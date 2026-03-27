//go:build e2e

package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Anvil test harness
// ---------------------------------------------------------------------------

// Anvil deterministic accounts (from `anvil --accounts 10`):
//
//	Account 0: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
//	           key: ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
//	Account 1: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
//	           key: 59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
const (
	anvilRPC = "http://127.0.0.1:18545"

	// Agent (borrower) — Anvil account 0
	agentPrivKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	agentAddr    = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

	// Lender Safe stand-in — Anvil account 1 (just an EOA for receiving)
	lenderAddr = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

	// Chain ID for Anvil default
	anvilChainIDHex = "0x7a69" // 31337
)

var (
	mockUSDCAddr common.Address
	anvilCmd     *exec.Cmd
)

func TestMain(m *testing.M) {
	// Start Anvil.
	anvilCmd = exec.Command("anvil",
		"--port", "18545",
		"--accounts", "10",
		"--balance", "10000",
		"--silent",
	)
	anvilCmd.Stdout = os.Stderr
	anvilCmd.Stderr = os.Stderr

	if err := anvilCmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start anvil: %v\n", err)
		fmt.Fprintf(os.Stderr, "install foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup\n")
		os.Exit(1)
	}

	// Wait for Anvil to be ready.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var client *ethclient.Client
	var err error
	for {
		client, err = ethclient.DialContext(ctx, anvilRPC)
		if err == nil {
			if _, err := client.ChainID(ctx); err == nil {
				break
			}
		}
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "anvil did not start within 10s\n")
			anvilCmd.Process.Kill()
			os.Exit(1)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Deploy mock USDC (simple ERC-20).
	mockUSDCAddr, err = deployMockERC20(ctx, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to deploy mock USDC: %v\n", err)
		anvilCmd.Process.Kill()
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "mock USDC deployed at %s\n", mockUSDCAddr.Hex())

	// Mint USDC to the agent.
	err = mintMockERC20(ctx, client, mockUSDCAddr, common.HexToAddress(agentAddr), big.NewInt(100_000_000)) // 100 USDC
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to mint mock USDC: %v\n", err)
		anvilCmd.Process.Kill()
		os.Exit(1)
	}

	// Override supported chains to point to Anvil.
	supportedChains[anvilChainIDHex] = chainConfig{
		USDCAddress: mockUSDCAddr,
		FallbackRPC: anvilRPC,
	}

	client.Close()

	code := m.Run()

	anvilCmd.Process.Kill()
	anvilCmd.Wait()
	os.Exit(code)
}

// ---------------------------------------------------------------------------
// E2E: EOA repayment (primary path)
// ---------------------------------------------------------------------------

func TestE2E_EOARepayment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	borrower := common.HexToAddress(agentAddr)
	lender := common.HexToAddress(lenderAddr)
	amount := big.NewInt(2_000_000) // 2 USDC

	// Check initial balances.
	lenderBefore := balanceOf(t, ctx, mockUSDCAddr, lender)

	txHash, err := evmRepayLoan(ctx, agentPrivKey, anvilChainIDHex, borrower, lender, amount)
	require.NoError(t, err)
	assert.NotEqual(t, common.Hash{}, txHash)

	// Verify lender received the USDC.
	lenderAfter := balanceOf(t, ctx, mockUSDCAddr, lender)
	diff := new(big.Int).Sub(lenderAfter, lenderBefore)
	assert.Equal(t, amount.Int64(), diff.Int64(), "lender should have received 2 USDC")
}

func TestE2E_EOARepayment_InsufficientBalance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	borrower := common.HexToAddress(agentAddr)
	lender := common.HexToAddress(lenderAddr)
	// Try to repay more than the agent has.
	amount := big.NewInt(999_999_000_000) // 999,999 USDC

	_, err := evmRepayLoan(ctx, agentPrivKey, anvilChainIDHex, borrower, lender, amount)
	require.Error(t, err)
	// Should fail at gas estimation (transfer would revert).
	assert.Contains(t, err.Error(), "estimate gas")
}

func TestE2E_EOARepayment_WrongSigner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use account 1's key but claim borrower wallet is account 0.
	wrongKey := "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
	borrower := common.HexToAddress(agentAddr) // account 0
	lender := common.HexToAddress(lenderAddr)

	_, err := evmRepayLoan(ctx, wrongKey, anvilChainIDHex, borrower, lender, big.NewInt(1_000_000))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match agent key")
}

func TestE2E_UnsupportedChain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	borrower := common.HexToAddress(agentAddr)
	lender := common.HexToAddress(lenderAddr)

	_, err := evmRepayLoan(ctx, agentPrivKey, "0xdeadbeef", borrower, lender, big.NewInt(1_000_000))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported chain")
}

func TestE2E_MultipleRepayments(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	borrower := common.HexToAddress(agentAddr)
	lender := common.HexToAddress(lenderAddr)
	lenderBefore := balanceOf(t, ctx, mockUSDCAddr, lender)

	// Two sequential repayments.
	for i := 0; i < 2; i++ {
		_, err := evmRepayLoan(ctx, agentPrivKey, anvilChainIDHex, borrower, lender, big.NewInt(1_000_000))
		require.NoError(t, err, "repayment %d failed", i+1)
	}

	lenderAfter := balanceOf(t, ctx, mockUSDCAddr, lender)
	diff := new(big.Int).Sub(lenderAfter, lenderBefore)
	assert.Equal(t, int64(2_000_000), diff.Int64(), "lender should have received 2 USDC total")
}

// ---------------------------------------------------------------------------
// E2E: Non-Safe contract rejection
// ---------------------------------------------------------------------------

func TestE2E_NonSafeContractRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use the mock USDC address as the "borrower wallet" — it's a contract
	// but not a Safe. Agent key won't match, so it should probe and reject.
	lender := common.HexToAddress(lenderAddr)

	_, err := evmRepayLoan(ctx, agentPrivKey, anvilChainIDHex, mockUSDCAddr, lender, big.NewInt(1_000_000))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a Safe")
}

// ---------------------------------------------------------------------------
// Helpers: mock ERC-20 deployment
// ---------------------------------------------------------------------------

// Minimal ERC-20 bytecode with mint. This is a stripped-down Solidity contract:
//
//	mapping(address => uint256) public balanceOf;
//	function transfer(address to, uint256 amount) external returns (bool) {
//	    require(balanceOf[msg.sender] >= amount);
//	    balanceOf[msg.sender] -= amount;
//	    balanceOf[to] += amount;
//	    return true;
//	}
//	function mint(address to, uint256 amount) external {
//	    balanceOf[to] += amount;
//	}
//
// Compiled with solc 0.8.x, unoptimized. Bytecodes below are hex-encoded.
func deployMockERC20(ctx context.Context, client *ethclient.Client) (common.Address, error) {
	// Use Anvil's pre-funded account 9 as deployer (different from test accounts).
	deployerKey := "2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"
	privBytes, _ := hex.DecodeString(deployerKey)
	ecKey, _ := ethcrypto.ToECDSA(privBytes)
	deployer := ethcrypto.PubkeyToAddress(ecKey.PublicKey)

	nonce, err := client.PendingNonceAt(ctx, deployer)
	if err != nil {
		return common.Address{}, err
	}

	chainID, _ := client.ChainID(ctx)

	// Minimal ERC-20 init code (compiled from inline Yul/Solidity).
	// This deploys a contract that supports balanceOf, transfer, and mint.
	initCode := mustDecodeHex(mockERC20InitCode)

	gasPrice, _ := client.SuggestGasPrice(ctx)
	tx := types.NewContractCreation(nonce, big.NewInt(0), 3_000_000, gasPrice, initCode)
	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), ecKey)
	if err != nil {
		return common.Address{}, err
	}

	if err := client.SendTransaction(ctx, signedTx); err != nil {
		return common.Address{}, err
	}

	receipt, err := waitForReceipt(ctx, client, signedTx.Hash())
	if err != nil {
		return common.Address{}, err
	}
	if receipt.Status == 0 {
		return common.Address{}, fmt.Errorf("deploy reverted")
	}

	return receipt.ContractAddress, nil
}

func mintMockERC20(ctx context.Context, client *ethclient.Client, token, to common.Address, amount *big.Int) error {
	// mint(address,uint256) selector = 0x40c10f19
	data := common.Hex2Bytes("40c10f19")
	data = append(data, common.LeftPadBytes(to.Bytes(), 32)...)
	data = append(data, common.LeftPadBytes(amount.Bytes(), 32)...)

	// Use deployer account 9.
	deployerKey := "2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"
	privBytes, _ := hex.DecodeString(deployerKey)
	ecKey, _ := ethcrypto.ToECDSA(privBytes)
	deployer := ethcrypto.PubkeyToAddress(ecKey.PublicKey)

	nonce, err := client.PendingNonceAt(ctx, deployer)
	if err != nil {
		return err
	}
	chainID, _ := client.ChainID(ctx)
	gasPrice, _ := client.SuggestGasPrice(ctx)

	tx := types.NewTransaction(nonce, token, big.NewInt(0), 100_000, gasPrice, data)
	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), ecKey)
	if err != nil {
		return err
	}

	if err := client.SendTransaction(ctx, signedTx); err != nil {
		return err
	}

	receipt, err := waitForReceipt(ctx, client, signedTx.Hash())
	if err != nil {
		return err
	}
	if receipt.Status == 0 {
		return fmt.Errorf("mint reverted")
	}
	return nil
}

func balanceOf(t *testing.T, ctx context.Context, token, addr common.Address) *big.Int {
	t.Helper()
	client, err := ethclient.DialContext(ctx, anvilRPC)
	require.NoError(t, err)
	defer client.Close()

	// balanceOf(address) = 0x70a08231
	data := common.Hex2Bytes("70a08231")
	data = append(data, common.LeftPadBytes(addr.Bytes(), 32)...)

	result, err := client.CallContract(ctx, ethereum.CallMsg{To: &token, Data: data}, nil)
	require.NoError(t, err)
	if len(result) < 32 {
		return big.NewInt(0)
	}
	return new(big.Int).SetBytes(result)
}

func waitForReceipt(ctx context.Context, client *ethclient.Client, txHash common.Hash) (*types.Receipt, error) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		receipt, err := client.TransactionReceipt(ctx, txHash)
		if err == nil {
			return receipt, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("receipt timeout for %s", txHash.Hex())
}

func mustDecodeHex(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// loadAnvilKey loads a private key and returns the ecdsa key + address.
func loadAnvilKey(privHex string) (*ecdsa.PrivateKey, common.Address) {
	privBytes, _ := hex.DecodeString(privHex)
	ecKey, _ := ethcrypto.ToECDSA(privBytes)
	return ecKey, ethcrypto.PubkeyToAddress(ecKey.PublicKey)
}

// mockERC20InitCode is the compiled init bytecode for a minimal ERC-20
// with balanceOf(address), transfer(address,uint256), and mint(address,uint256).
//
// Solidity source (0.8.x):
//
//	pragma solidity ^0.8.0;
//	contract MockUSDC {
//	    mapping(address => uint256) public balanceOf;
//	    function transfer(address to, uint256 amount) external returns (bool) {
//	        require(balanceOf[msg.sender] >= amount, "insufficient");
//	        balanceOf[msg.sender] -= amount;
//	        balanceOf[to] += amount;
//	        return true;
//	    }
//	    function mint(address to, uint256 amount) external {
//	        balanceOf[to] += amount;
//	    }
//	}
//
// Compiled with: solc --bin --optimize MockUSDC.sol
const mockERC20InitCode = "6080604052348015600e575f5ffd5b506104ed8061001c5f395ff3fe608060405234801561000f575f5ffd5b506004361061003f575f3560e01c806340c10f191461004357806370a082311461005f578063a9059cbb1461008f575b5f5ffd5b61005d600480360381019061005891906102e8565b6100bf565b005b61007960048036038101906100749190610326565b610115565b6040516100869190610360565b60405180910390f35b6100a960048036038101906100a491906102e8565b610129565b6040516100b69190610393565b60405180910390f35b805f5f8473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f82825461010a91906103d9565b925050819055505050565b5f602052805f5260405f205f915090505481565b5f815f5f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205410156101a9576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101a090610466565b60405180910390fd5b815f5f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546101f49190610484565b92505081905550815f5f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f82825461024691906103d9565b925050819055506001905092915050565b5f5ffd5b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6102848261025b565b9050919050565b6102948161027a565b811461029e575f5ffd5b50565b5f813590506102af8161028b565b92915050565b5f819050919050565b6102c7816102b5565b81146102d1575f5ffd5b50565b5f813590506102e2816102be565b92915050565b5f5f604083850312156102fe576102fd610257565b5b5f61030b858286016102a1565b925050602061031c858286016102d4565b9150509250929050565b5f6020828403121561033b5761033a610257565b5b5f610348848285016102a1565b91505092915050565b61035a816102b5565b82525050565b5f6020820190506103735f830184610351565b92915050565b5f8115159050919050565b61038d81610379565b82525050565b5f6020820190506103a65f830184610384565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6103e3826102b5565b91506103ee836102b5565b9250828201905080821115610406576104056103ac565b5b92915050565b5f82825260208201905092915050565b7f696e73756666696369656e7400000000000000000000000000000000000000005f82015250565b5f610450600c8361040c565b915061045b8261041c565b602082019050919050565b5f6020820190508181035f83015261047d81610444565b9050919050565b5f61048e826102b5565b9150610499836102b5565b92508282039050818111156104b1576104b06103ac565b5b9291505056fea2646970667358221220d7b9ebf80c0c5915b356062e730e5ac03de0a997b0c5d60745620c57fb011f0064736f6c63430008210033"
