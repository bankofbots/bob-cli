package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

var evmBalanceAt = evmNativeBalance
var evmSendNativeValue = evmSendNative

// chainConfig holds per-chain token addresses and fallback RPC URLs.
type chainConfig struct {
	USDCAddress common.Address
	FallbackRPC string
}

// supportedChains maps hex chain IDs to their configuration.
// Only Base is actively supported for lending; other chains are rejected.
var supportedChains = map[string]chainConfig{
	"0x2105": {
		USDCAddress: common.HexToAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
		FallbackRPC: "https://mainnet.base.org",
	},
}

// rpcURLForChain returns the RPC URL for a chain, preferring env override.
// Env: BOB_EVM_RPC_URL (applies to all chains).
func rpcURLForChain(chainIDHex string) (string, error) {
	if envRPC := os.Getenv("BOB_EVM_RPC_URL"); envRPC != "" {
		return envRPC, nil
	}
	cfg, ok := supportedChains[strings.ToLower(chainIDHex)]
	if !ok {
		return "", fmt.Errorf("unsupported chain %s — only Base (0x2105) is supported for loan repayment", chainIDHex)
	}
	return cfg.FallbackRPC, nil
}

// usdcAddressForChain returns the USDC contract address for the given chain.
func usdcAddressForChain(chainIDHex string) (common.Address, error) {
	cfg, ok := supportedChains[strings.ToLower(chainIDHex)]
	if !ok {
		return common.Address{}, fmt.Errorf("unsupported chain %s — no USDC address configured", chainIDHex)
	}
	return cfg.USDCAddress, nil
}

// evmRepayLoan sends USDC from the agent's wallet to the lender Safe.
//
// Primary path (EOA): the agent's key signs a direct USDC transfer.
// Fallback (Safe): if the borrower registered a Gnosis Safe as their wallet,
// the agent's key (as Safe owner) signs an execTransaction instead.
//
// Returns the confirmed transaction hash.
func evmRepayLoan(ctx context.Context, privKeyHex string, chainIDHex string, borrowerWallet common.Address, lenderSafe common.Address, amount *big.Int) (common.Hash, error) {
	rpcURL, err := rpcURLForChain(chainIDHex)
	if err != nil {
		return common.Hash{}, err
	}

	usdcAddr, err := usdcAddressForChain(chainIDHex)
	if err != nil {
		return common.Hash{}, err
	}

	privKeyBytes, err := hex.DecodeString(strings.TrimPrefix(privKeyHex, "0x"))
	if err != nil {
		return common.Hash{}, fmt.Errorf("decode private key: %w", err)
	}
	ecKey, err := ethcrypto.ToECDSA(privKeyBytes)
	if err != nil {
		return common.Hash{}, fmt.Errorf("parse private key: %w", err)
	}
	signerAddr := ethcrypto.PubkeyToAddress(ecKey.PublicKey)

	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return common.Hash{}, fmt.Errorf("connect to %s: %w", rpcURL, err)
	}
	defer client.Close()

	chainID, ok := new(big.Int).SetString(strings.TrimPrefix(chainIDHex, "0x"), 16)
	if !ok {
		return common.Hash{}, fmt.Errorf("parse chain ID: %s", chainIDHex)
	}

	// Default: direct ERC-20 transfer from the agent's EOA.
	callData := encodeERC20TransferCall(lenderSafe, amount)
	txTo := usdcAddr

	if signerAddr == borrowerWallet {
		// Common case: agent wallet IS the borrower wallet (EOA). Send directly.
	} else {
		// Agent key doesn't match borrower wallet — check if it's a Safe
		// where the agent is the owner (e.g. dashboard-deployed Safe).
		// Single call: getThreshold doubles as Safe detection (returns error/0 for non-Safes).
		threshold, threshErr := getSafeThreshold(ctx, client, borrowerWallet)
		if threshErr != nil || threshold <= 0 {
			return common.Hash{}, fmt.Errorf("borrower wallet %s does not match agent key %s and is not a Safe", borrowerWallet.Hex(), signerAddr.Hex())
		}
		if threshold != 1 {
			return common.Hash{}, fmt.Errorf("Safe %s has threshold %d — only threshold-1 Safes are supported for CLI repayment", borrowerWallet.Hex(), threshold)
		}

		// Verify signer is an owner.
		isOwner, ownerErr := isSafeOwner(ctx, client, borrowerWallet, signerAddr)
		if ownerErr != nil {
			return common.Hash{}, fmt.Errorf("check Safe ownership: %w", ownerErr)
		}
		if !isOwner {
			return common.Hash{}, fmt.Errorf("agent key %s is not an owner of Safe %s", signerAddr.Hex(), borrowerWallet.Hex())
		}

		innerData := encodeERC20TransferCall(lenderSafe, amount)
		callData, err = encodeSafeExecTransaction(usdcAddr, innerData, signerAddr)
		if err != nil {
			return common.Hash{}, fmt.Errorf("encode Safe execTransaction: %w", err)
		}
		txTo = borrowerWallet
	}

	return signAndSend(ctx, client, ecKey, chainID, txTo, callData)
}

// getSafeThreshold returns the threshold of a Gnosis Safe.
// Returns an error for non-Safe addresses (EOAs or other contracts).
func getSafeThreshold(ctx context.Context, client *ethclient.Client, safeAddr common.Address) (int, error) {
	data := common.Hex2Bytes("e75235b8") // getThreshold()
	msg := ethereum.CallMsg{To: &safeAddr, Data: data}
	result, err := client.CallContract(ctx, msg, nil)
	if err != nil {
		return 0, fmt.Errorf("getThreshold call failed: %w", err)
	}
	if len(result) < 32 {
		return 0, fmt.Errorf("unexpected getThreshold result length: %d", len(result))
	}
	return int(new(big.Int).SetBytes(result).Int64()), nil
}

// isSafeOwner checks if the given address is an owner of the Safe.
// Calls isOwner(address) on the Safe contract.
func isSafeOwner(ctx context.Context, client *ethclient.Client, safeAddr, owner common.Address) (bool, error) {
	// isOwner(address) selector = 0x2f54bf6e
	data := common.Hex2Bytes("2f54bf6e")
	data = append(data, common.LeftPadBytes(owner.Bytes(), 32)...)
	msg := ethereum.CallMsg{To: &safeAddr, Data: data}
	result, err := client.CallContract(ctx, msg, nil)
	if err != nil {
		return false, fmt.Errorf("isOwner call failed: %w", err)
	}
	if len(result) < 32 {
		return false, nil
	}
	return new(big.Int).SetBytes(result).Sign() > 0, nil
}

// encodeSafeExecTransaction encodes a Safe v1.3+ execTransaction call.
// Uses CALL operation (0), with the owner as the single signer.
func encodeSafeExecTransaction(to common.Address, data []byte, owner common.Address) ([]byte, error) {
	// For single-owner Safe: signature is r=owner (padded), s=0, v=1
	// This is the "pre-approved" signature format where the owner IS msg.sender.
	sig := make([]byte, 65)
	copy(sig[12:32], owner.Bytes()) // r = owner address, left-padded to 32 bytes
	sig[64] = 1                     // v = 1

	selector := common.Hex2Bytes("6a761202")

	// 10 fixed params, then dynamic data + signatures.
	params := make([]byte, 0, 1024)

	params = append(params, common.LeftPadBytes(to.Bytes(), 32)...)              // to
	params = append(params, common.LeftPadBytes(nil, 32)...)                     // value = 0
	params = append(params, common.LeftPadBytes(big.NewInt(320).Bytes(), 32)...) // data offset (10*32)
	params = append(params, common.LeftPadBytes(nil, 32)...)                     // operation = CALL
	params = append(params, common.LeftPadBytes(nil, 32)...)                     // safeTxGas = 0
	params = append(params, common.LeftPadBytes(nil, 32)...)                     // baseGas = 0
	params = append(params, common.LeftPadBytes(nil, 32)...)                     // gasPrice = 0
	params = append(params, common.LeftPadBytes(nil, 32)...)                     // gasToken = 0
	params = append(params, common.LeftPadBytes(nil, 32)...)                     // refundReceiver = 0

	dataPadded := padTo32(len(data))
	sigOffset := 320 + 32 + dataPadded
	params = append(params, common.LeftPadBytes(big.NewInt(int64(sigOffset)).Bytes(), 32)...) // signatures offset

	// Dynamic: data
	params = append(params, common.LeftPadBytes(big.NewInt(int64(len(data))).Bytes(), 32)...)
	params = append(params, data...)
	if pad := dataPadded - len(data); pad > 0 {
		params = append(params, make([]byte, pad)...)
	}

	// Dynamic: signatures
	params = append(params, common.LeftPadBytes(big.NewInt(int64(len(sig))).Bytes(), 32)...)
	params = append(params, sig...)
	if pad := padTo32(len(sig)) - len(sig); pad > 0 {
		params = append(params, make([]byte, pad)...)
	}

	result := make([]byte, 0, 4+len(params))
	result = append(result, selector...)
	result = append(result, params...)
	return result, nil
}

func padTo32(n int) int {
	if n%32 == 0 {
		return n
	}
	return n + (32 - n%32)
}

// encodeERC20TransferCall encodes an ERC-20 transfer(address,uint256) call.
func encodeERC20TransferCall(to common.Address, amount *big.Int) []byte {
	// transfer(address,uint256) selector = 0xa9059cbb
	data := common.Hex2Bytes("a9059cbb")
	data = append(data, common.LeftPadBytes(to.Bytes(), 32)...)
	data = append(data, common.LeftPadBytes(amount.Bytes(), 32)...)
	return data
}

// signAndSend builds, signs, broadcasts an EIP-1559 transaction, and waits
// for on-chain confirmation. Returns the tx hash only on success.
func signAndSend(ctx context.Context, client *ethclient.Client, key *ecdsa.PrivateKey, chainID *big.Int, to common.Address, data []byte) (common.Hash, error) {
	return signAndSendValue(ctx, client, key, chainID, to, big.NewInt(0), data)
}

func signAndSendValue(ctx context.Context, client *ethclient.Client, key *ecdsa.PrivateKey, chainID *big.Int, to common.Address, value *big.Int, data []byte) (common.Hash, error) {
	from := ethcrypto.PubkeyToAddress(key.PublicKey)

	nonce, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		return common.Hash{}, fmt.Errorf("get nonce: %w", err)
	}

	// Gas estimation with buffer.
	estimatedGas, err := client.EstimateGas(ctx, ethereum.CallMsg{
		From:  from,
		To:    &to,
		Value: value,
		Data:  data,
	})
	if err != nil {
		return common.Hash{}, fmt.Errorf("estimate gas (tx will likely revert): %w", err)
	}
	gasLimit := estimatedGas + estimatedGas/5 // +20% buffer

	// EIP-1559 fee parameters.
	gasTipCap, err := client.SuggestGasTipCap(ctx)
	if err != nil {
		return common.Hash{}, fmt.Errorf("get gas tip cap: %w", err)
	}
	head, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return common.Hash{}, fmt.Errorf("get latest block header: %w", err)
	}
	baseFee := head.BaseFee
	if baseFee == nil {
		return common.Hash{}, fmt.Errorf("chain does not support EIP-1559")
	}
	// maxFeePerGas = 2 * baseFee + tipCap
	gasFeeCap := new(big.Int).Add(new(big.Int).Mul(baseFee, big.NewInt(2)), gasTipCap)

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
		Gas:       gasLimit,
		To:        &to,
		Value:     value,
		Data:      data,
	})

	signer := types.LatestSignerForChainID(chainID)
	signedTx, err := types.SignTx(tx, signer, key)
	if err != nil {
		return common.Hash{}, fmt.Errorf("sign transaction: %w", err)
	}

	fmt.Fprintf(os.Stderr, "broadcasting tx %s...\n", signedTx.Hash().Hex())

	if err := client.SendTransaction(ctx, signedTx); err != nil {
		return common.Hash{}, fmt.Errorf("send transaction: %w", err)
	}

	txHash := signedTx.Hash()

	// Wait for confirmation (up to 90s).
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		receipt, err := client.TransactionReceipt(ctx, txHash)
		if err == nil {
			if receipt.Status == 0 {
				return txHash, fmt.Errorf("transaction reverted on-chain (tx: %s, gas used: %d)", txHash.Hex(), receipt.GasUsed)
			}
			fmt.Fprintf(os.Stderr, "confirmed in block %s (gas used: %d)\n", receipt.BlockNumber.String(), receipt.GasUsed)
			return txHash, nil
		}
		time.Sleep(2 * time.Second)
	}

	return common.Hash{}, fmt.Errorf("transaction broadcast but not confirmed within 90s (tx: %s) — do NOT retry, check block explorer first", txHash.Hex())
}

func evmNativeBalance(ctx context.Context, chainIDHex string, addr common.Address) (*big.Int, error) {
	rpcURL, err := rpcURLForChain(chainIDHex)
	if err != nil {
		return nil, err
	}
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", rpcURL, err)
	}
	defer client.Close()
	balance, err := client.BalanceAt(ctx, addr, nil)
	if err != nil {
		return nil, fmt.Errorf("read balance: %w", err)
	}
	return balance, nil
}

func evmSendNative(ctx context.Context, privKeyHex string, chainIDHex string, to common.Address, amountWei *big.Int) (common.Hash, error) {
	if amountWei == nil || amountWei.Sign() <= 0 {
		return common.Hash{}, fmt.Errorf("amountWei must be positive")
	}

	rpcURL, err := rpcURLForChain(chainIDHex)
	if err != nil {
		return common.Hash{}, err
	}
	privKeyBytes, err := hex.DecodeString(strings.TrimPrefix(privKeyHex, "0x"))
	if err != nil {
		return common.Hash{}, fmt.Errorf("decode private key: %w", err)
	}
	ecKey, err := ethcrypto.ToECDSA(privKeyBytes)
	if err != nil {
		return common.Hash{}, fmt.Errorf("parse private key: %w", err)
	}
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return common.Hash{}, fmt.Errorf("connect to %s: %w", rpcURL, err)
	}
	defer client.Close()

	chainID, ok := new(big.Int).SetString(strings.TrimPrefix(chainIDHex, "0x"), 16)
	if !ok {
		return common.Hash{}, fmt.Errorf("parse chain ID: %s", chainIDHex)
	}

	return signAndSendValue(ctx, client, ecKey, chainID, to, amountWei, nil)
}
