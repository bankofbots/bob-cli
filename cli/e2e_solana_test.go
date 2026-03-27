//go:build e2e_sol

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// solana-test-validator harness
// ---------------------------------------------------------------------------

const solTestRPC = "http://127.0.0.1:18899"

// Deterministic test keypair (32-byte seed).
const solTestSeed = "1111111111111111111111111111111111111111111111111111111111111111"

var (
	solValidatorCmd  *exec.Cmd
	solTestPubkey    string
	solTestMintPK    [32]byte // mint deployed on test validator
	solTestMintAddr  string   // base58 mint address (canonical, from deploy)
)

func TestMain(m *testing.M) {
	seedBytes, _ := hex.DecodeString(solTestSeed)
	privKey := ed25519.NewKeyFromSeed(seedBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)
	solTestPubkey = base58Encode(pubKey)

	solValidatorCmd = exec.Command("solana-test-validator",
		"--rpc-port", "18899",
		"--quiet",
		"--reset",
	)
	solValidatorCmd.Stdout = os.Stderr
	solValidatorCmd.Stderr = os.Stderr

	if err := solValidatorCmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start solana-test-validator: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	os.Setenv("BOB_SOL_RPC_URL", solTestRPC)

	for {
		_, err := solRPCCall(ctx, solTestRPC, "getHealth", []any{})
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "solana-test-validator did not start within 30s\n")
			solValidatorCmd.Process.Kill()
			os.Exit(1)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Airdrop SOL to test wallet.
	if err := solAirdrop(solTestPubkey, 10_000_000_000); err != nil {
		fmt.Fprintf(os.Stderr, "failed to airdrop SOL: %v\n", err)
		solValidatorCmd.Process.Kill()
		os.Exit(1)
	}

	// Deploy SPL token mint + mint tokens via raw transactions.
	mintPK, err := solDeployTestMint(ctx, seedBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to deploy test mint: %v\n", err)
		solValidatorCmd.Process.Kill()
		os.Exit(1)
	}
	solTestMintPK = mintPK
	solTestMintAddr = base58Encode(mintPK[:])

	fmt.Fprintf(os.Stderr, "test validator ready, pubkey=%s, mint=%s\n",
		solTestPubkey, solTestMintAddr)

	code := m.Run()

	solValidatorCmd.Process.Kill()
	solValidatorCmd.Wait()
	os.Exit(code)
}

// ---------------------------------------------------------------------------
// E2E Tests
// ---------------------------------------------------------------------------

func TestE2E_Sol_TransferUSDC_HappyPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	recipientSeed := make([]byte, 32)
	recipientSeed[0] = 0x42
	recipientKey := ed25519.NewKeyFromSeed(recipientSeed)
	recipientPub := base58Encode(recipientKey.Public().(ed25519.PublicKey))

	origMint := solUSDCMint
	solUSDCMint = mustBase58Decode(solTestMintAddr)
	defer func() { solUSDCMint = origMint }()

	sig, err := solTransferUSDC(ctx, solTestSeed, recipientPub, 1_000_000)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	// Verify the recipient received tokens by querying all their SPL token
	// accounts and finding the one for our test mint.
	balance, err := solGetTokenBalanceByProgram(ctx, solTestRPC, recipientPub, solTestMintAddr)
	require.NoError(t, err)
	assert.Equal(t, uint64(1_000_000), balance)
}

func TestE2E_Sol_TransferUSDC_InsufficientBalance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	recipientSeed := make([]byte, 32)
	recipientSeed[0] = 0x43
	recipientKey := ed25519.NewKeyFromSeed(recipientSeed)
	recipientPub := base58Encode(recipientKey.Public().(ed25519.PublicKey))

	origMint := solUSDCMint
	solUSDCMint = mustBase58Decode(solTestMintAddr)
	defer func() { solUSDCMint = origMint }()

	_, err := solTransferUSDC(ctx, solTestSeed, recipientPub, 999_999_000_000_000)
	require.Error(t, err)
}

func TestE2E_Sol_TransferUSDC_InvalidRecipient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := solTransferUSDC(ctx, solTestSeed, "not-a-valid-address", 1_000_000)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid recipient")
}

func TestE2E_Sol_TransferUSDC_MultipleTransfers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	recipientSeed := make([]byte, 32)
	recipientSeed[0] = 0x44
	recipientKey := ed25519.NewKeyFromSeed(recipientSeed)
	recipientPub := base58Encode(recipientKey.Public().(ed25519.PublicKey))

	origMint := solUSDCMint
	solUSDCMint = mustBase58Decode(solTestMintAddr)
	defer func() { solUSDCMint = origMint }()

	for i := 0; i < 2; i++ {
		sig, err := solTransferUSDC(ctx, solTestSeed, recipientPub, 500_000)
		require.NoError(t, err, "transfer %d failed", i+1)
		assert.NotEmpty(t, sig)
	}

	balance, err := solGetTokenBalanceByProgram(ctx, solTestRPC, recipientPub, solTestMintAddr)
	require.NoError(t, err)
	assert.Equal(t, uint64(1_000_000), balance)
}

func TestE2E_Sol_TransferUSDC_BadKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := solTransferUSDC(ctx, "not-hex", "11111111111111111111111111111111", 1_000_000)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode private key")
}

// ---------------------------------------------------------------------------
// Helpers: airdrop
// ---------------------------------------------------------------------------

func solAirdrop(pubkey string, lamports uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := solRPCCall(ctx, solTestRPC, "requestAirdrop", []any{pubkey, lamports})
	if err != nil {
		return err
	}
	var sig string
	json.Unmarshal(result, &sig)
	return solConfirmTransaction(ctx, solTestRPC, sig)
}

// ---------------------------------------------------------------------------
// Helpers: deploy SPL token mint via raw transactions
// ---------------------------------------------------------------------------

// solDeployTestMint creates a new SPL token mint with 6 decimals, creates an
// ATA for the payer, and mints 100_000_000 tokens (100 with 6 decimals).
// All done via raw Solana transactions — no spl-token CLI needed.
func solDeployTestMint(ctx context.Context, payerSeed []byte) ([32]byte, error) {
	payerKey := ed25519.NewKeyFromSeed(payerSeed)
	payerPub := toArr32(payerKey.Public().(ed25519.PublicKey))

	// Generate a new keypair for the mint account.
	mintSeed := make([]byte, 32)
	mintSeed[0] = 0xAA
	mintSeed[1] = 0xBB
	mintKey := ed25519.NewKeyFromSeed(mintSeed)
	mintPub := toArr32(mintKey.Public().(ed25519.PublicKey))

	tokenProgram := toArr32(solTokenProgramID)
	systemProgram := toArr32(solSystemProgram)

	// Step 1: Create mint account + InitializeMint in one tx.
	// Mint account needs 82 bytes of space, rent-exempt minimum.
	rentLamports := uint64(1_461_600) // Standard rent for 82-byte SPL mint account

	blockhash, err := solGetRecentBlockhash(ctx, solTestRPC)
	if err != nil {
		return [32]byte{}, fmt.Errorf("get blockhash: %w", err)
	}

	// CreateAccount instruction (System Program).
	createAcctData := make([]byte, 52)
	binary.LittleEndian.PutUint32(createAcctData[0:4], 0) // instruction: CreateAccount
	binary.LittleEndian.PutUint64(createAcctData[4:12], rentLamports)
	binary.LittleEndian.PutUint64(createAcctData[12:20], 82) // space
	copy(createAcctData[20:52], tokenProgram[:])              // owner = Token Program

	createAcctIx := solInstruction{
		programID: systemProgram,
		accounts: []solAccountMeta{
			{pubkey: payerPub, isSigner: true, isWritable: true},
			{pubkey: mintPub, isSigner: true, isWritable: true},
		},
		data: createAcctData,
	}

	// InitializeMint instruction (SPL Token Program).
	// Instruction index 0, decimals=6, mint_authority=payer, freeze_authority=None.
	initMintData := make([]byte, 67)
	initMintData[0] = 0 // InitializeMint instruction
	initMintData[1] = 6 // decimals
	copy(initMintData[2:34], payerPub[:])  // mint authority
	initMintData[34] = 0                   // COption: None for freeze authority
	// Remaining 32 bytes are zero (no freeze authority)

	sysvarRent := toArr32(mustBase58Decode("SysvarRent111111111111111111111111111111111"))

	initMintIx := solInstruction{
		programID: tokenProgram,
		accounts: []solAccountMeta{
			{pubkey: mintPub, isSigner: false, isWritable: true},
			{pubkey: sysvarRent, isSigner: false, isWritable: false},
		},
		data: initMintData,
	}

	msg1 := serializeSolMessage(blockhash, payerPub, []solInstruction{createAcctIx, initMintIx})

	// This tx needs TWO signatures: payer + mint account.
	sig1Payer := ed25519.Sign(payerKey, msg1)
	sig1Mint := ed25519.Sign(mintKey, msg1)
	signedTx1 := encodeSolMultiSigTx([][]byte{sig1Payer, sig1Mint}, msg1)

	txSig1, err := solSendTransaction(ctx, solTestRPC, signedTx1)
	if err != nil {
		return [32]byte{}, fmt.Errorf("create mint tx: %w", err)
	}
	if err := solConfirmTransaction(ctx, solTestRPC, txSig1); err != nil {
		return [32]byte{}, fmt.Errorf("confirm create mint: %w", err)
	}

	// Step 2: Create ATA for payer + MintTo.
	payerATA := deriveATA(payerPub, mintPub)

	blockhash2, err := solGetRecentBlockhash(ctx, solTestRPC)
	if err != nil {
		return [32]byte{}, fmt.Errorf("get blockhash 2: %w", err)
	}

	createATAIx := buildCreateATAIx(payerPub, payerPub, mintPub, payerATA)

	// MintTo instruction: index 7, amount 100_000_000 (100 tokens * 10^6).
	mintToData := make([]byte, 9)
	mintToData[0] = 7 // MintTo instruction
	binary.LittleEndian.PutUint64(mintToData[1:9], 100_000_000)

	mintToIx := solInstruction{
		programID: tokenProgram,
		accounts: []solAccountMeta{
			{pubkey: mintPub, isSigner: false, isWritable: true},    // mint
			{pubkey: payerATA, isSigner: false, isWritable: true},   // destination ATA
			{pubkey: payerPub, isSigner: true, isWritable: false},   // mint authority
		},
		data: mintToData,
	}

	msg2 := serializeSolMessage(blockhash2, payerPub, []solInstruction{createATAIx, mintToIx})
	sig2 := ed25519.Sign(payerKey, msg2)
	signedTx2 := encodeSolSignedTx(sig2, msg2)

	txSig2, err := solSendTransaction(ctx, solTestRPC, signedTx2)
	if err != nil {
		return [32]byte{}, fmt.Errorf("create ATA + mint tx: %w", err)
	}
	if err := solConfirmTransaction(ctx, solTestRPC, txSig2); err != nil {
		return [32]byte{}, fmt.Errorf("confirm ATA + mint: %w", err)
	}

	fmt.Fprintf(os.Stderr, "deployed mint %s, minted 100 tokens to %s\n",
		base58Encode(mintPub[:]), base58Encode(payerATA[:]))

	return mintPub, nil
}

// encodeSolMultiSigTx encodes a transaction with multiple signatures.
func encodeSolMultiSigTx(sigs [][]byte, message []byte) []byte {
	var buf []byte
	// Compact array of signatures.
	compactBuf := make([]byte, 0, 3)
	v := uint16(len(sigs))
	for {
		b := byte(v & 0x7F)
		v >>= 7
		if v > 0 {
			b |= 0x80
		}
		compactBuf = append(compactBuf, b)
		if v == 0 {
			break
		}
	}
	buf = append(buf, compactBuf...)
	for _, sig := range sigs {
		buf = append(buf, sig...)
	}
	buf = append(buf, message...)
	return buf
}

// solGetTokenAccountBalance queries a specific token account's balance.
func solGetTokenAccountBalance(ctx context.Context, rpcURL, ataAddress string) (uint64, error) {
	result, err := solRPCCall(ctx, rpcURL, "getTokenAccountBalance", []any{ataAddress})
	if err != nil {
		return 0, err
	}
	var parsed struct {
		Value struct {
			Amount string `json:"amount"`
		} `json:"value"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		return 0, err
	}
	var amount uint64
	fmt.Sscanf(parsed.Value.Amount, "%d", &amount)
	return amount, nil
}

// solGetTokenBalanceByProgram queries all SPL token accounts for an owner
// (filtered by Token Program) and returns the balance for the specified mint.
// This avoids the "could not find mint" error from getTokenAccountsByOwner
// with a mint filter on freshly-created mints.
func solGetTokenBalanceByProgram(ctx context.Context, rpcURL, owner, mint string) (uint64, error) {
	tokenProgramAddr := base58Encode(solTokenProgramID)
	result, err := solRPCCall(ctx, rpcURL, "getTokenAccountsByOwner", []any{
		owner,
		map[string]string{"programId": tokenProgramAddr},
		map[string]any{"encoding": "jsonParsed", "commitment": "confirmed"},
	})
	if err != nil {
		return 0, err
	}
	var parsed struct {
		Value []struct {
			Account struct {
				Data struct {
					Parsed struct {
						Info struct {
							Mint        string `json:"mint"`
							TokenAmount struct {
								Amount string `json:"amount"`
							} `json:"tokenAmount"`
						} `json:"info"`
					} `json:"parsed"`
				} `json:"data"`
			} `json:"account"`
		} `json:"value"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		return 0, err
	}
	for _, acct := range parsed.Value {
		if acct.Account.Data.Parsed.Info.Mint == mint {
			var amount uint64
			fmt.Sscanf(acct.Account.Data.Parsed.Info.TokenAmount.Amount, "%d", &amount)
			return amount, nil
		}
	}
	return 0, fmt.Errorf("no token account found for owner %s with mint %s", owner, mint)
}

// solGetTokenBalanceByOwner queries token accounts for an owner+mint and returns the balance.
// Uses getTokenAccountsByOwner RPC — doesn't require knowing the exact ATA address.
func solGetTokenBalanceByOwner(ctx context.Context, rpcURL, owner, mint string) (uint64, error) {
	result, err := solRPCCall(ctx, rpcURL, "getTokenAccountsByOwner", []any{
		owner,
		map[string]string{"mint": mint},
		map[string]string{"encoding": "jsonParsed"},
	})
	if err != nil {
		return 0, err
	}
	var parsed struct {
		Value []struct {
			Account struct {
				Data struct {
					Parsed struct {
						Info struct {
							TokenAmount struct {
								Amount string `json:"amount"`
							} `json:"tokenAmount"`
						} `json:"info"`
					} `json:"parsed"`
				} `json:"data"`
			} `json:"account"`
		} `json:"value"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		return 0, err
	}
	if len(parsed.Value) == 0 {
		return 0, fmt.Errorf("no token account found for owner %s mint %s", owner, mint)
	}
	var amount uint64
	fmt.Sscanf(parsed.Value[0].Account.Data.Parsed.Info.TokenAmount.Amount, "%d", &amount)
	return amount, nil
}
