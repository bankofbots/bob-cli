//go:build e2e_btc

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// bitcoind regtest harness
// ---------------------------------------------------------------------------

var (
	btcDataDir   string
	btcRPCPort   string
	btcRPCUser   = "test"
	btcRPCPass   = "test"
	btcMockURL   string
	btcTestPriv  string // hex-encoded secp256k1 private key (sender)
	btcTestAddr  string // bcrt1q... address of sender
)

// bitcoinCLI runs bitcoin-cli against our regtest node.
func bitcoinCLI(args ...string) (string, error) {
	base := []string{
		"-regtest",
		"-datadir=" + btcDataDir,
		"-rpcport=" + btcRPCPort,
		"-rpcuser=" + btcRPCUser,
		"-rpcpassword=" + btcRPCPass,
	}
	cmd := exec.Command("bitcoin-cli", append(base, args...)...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func TestMain(m *testing.M) {
	// Check if bitcoind is available.
	if _, err := exec.LookPath("bitcoind"); err != nil {
		fmt.Fprintf(os.Stderr, "bitcoind not found, skipping BTC e2e tests\n")
		os.Exit(0)
	}
	if _, err := exec.LookPath("bitcoin-cli"); err != nil {
		fmt.Fprintf(os.Stderr, "bitcoin-cli not found, skipping BTC e2e tests\n")
		os.Exit(0)
	}

	// Pick a random high port for RPC.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to find free port: %v\n", err)
		os.Exit(1)
	}
	btcRPCPort = strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	listener.Close()

	// Create temp data dir.
	btcDataDir, err = os.MkdirTemp("", "btc-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}

	// Start bitcoind in regtest mode.
	bitcoindCmd := exec.Command("bitcoind",
		"-regtest",
		"-daemon",
		"-txindex",
		"-datadir="+btcDataDir,
		"-rpcport="+btcRPCPort,
		"-rpcuser="+btcRPCUser,
		"-rpcpassword="+btcRPCPass,
		"-fallbackfee=0.00001",
		"-server",
		"-listen=0",
		"-listenonion=0",
	)
	bitcoindCmd.Stdout = os.Stderr
	bitcoindCmd.Stderr = os.Stderr

	if err := bitcoindCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start bitcoind: %v\n", err)
		os.RemoveAll(btcDataDir)
		os.Exit(1)
	}

	// Wait for bitcoind to be ready.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		if _, err := bitcoinCLI("getblockchaininfo"); err == nil {
			break
		}
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "bitcoind did not start within 30s\n")
			bitcoinCLI("stop")
			os.RemoveAll(btcDataDir)
			os.Exit(1)
		}
		time.Sleep(250 * time.Millisecond)
	}

	// Create a wallet.
	if _, err := bitcoinCLI("createwallet", "test"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create wallet: %v\n", err)
		bitcoinCLI("stop")
		os.RemoveAll(btcDataDir)
		os.Exit(1)
	}

	// Generate 101 blocks for coinbase maturity.
	if _, err := bitcoinCLI("-generate", "101"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate blocks: %v\n", err)
		bitcoinCLI("stop")
		os.RemoveAll(btcDataDir)
		os.Exit(1)
	}

	// Generate a secp256k1 key for the test sender.
	privKey, err := ethcrypto.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate key: %v\n", err)
		bitcoinCLI("stop")
		os.RemoveAll(btcDataDir)
		os.Exit(1)
	}
	btcTestPriv = hex.EncodeToString(ethcrypto.FromECDSA(privKey))
	pubCompressed := compressPublicKey(&privKey.PublicKey)
	pubKeyHash := hash160(pubCompressed)
	btcTestAddr, err = bech32Encode("bcrt", 0, pubKeyHash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode address: %v\n", err)
		bitcoinCLI("stop")
		os.RemoveAll(btcDataDir)
		os.Exit(1)
	}

	// Fund the test address with 2 BTC (enough for all tests).
	if _, err := bitcoinCLI("sendtoaddress", btcTestAddr, "2.0"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to fund test address: %v\n", err)
		bitcoinCLI("stop")
		os.RemoveAll(btcDataDir)
		os.Exit(1)
	}
	// Mine a block to confirm the funding tx.
	if _, err := bitcoinCLI("-generate", "1"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to mine block: %v\n", err)
		bitcoinCLI("stop")
		os.RemoveAll(btcDataDir)
		os.Exit(1)
	}

	// Start mock mempool server.
	mockServer := startMockMempoolServer()
	btcMockURL = mockServer.URL

	// Point btcSend at our mock mempool and set apiBase to localhost so
	// btcHRPFromNetwork() returns "bcrt".
	os.Setenv("BOB_BTC_MEMPOOL_URL", btcMockURL)
	apiBase = "http://localhost"

	// Start a background miner — regtest doesn't mine automatically, so the
	// confirmation poller in btcSend would time out without this.
	minerCtx, minerCancel := context.WithCancel(context.Background())
	go func() {
		for {
			select {
			case <-minerCtx.Done():
				return
			case <-time.After(2 * time.Second):
				bitcoinCLI("-generate", "1")
			}
		}
	}()

	fmt.Fprintf(os.Stderr, "bitcoind regtest ready (rpc port %s, sender %s, mock %s)\n",
		btcRPCPort, btcTestAddr, btcMockURL)

	code := m.Run()

	// Cleanup.
	minerCancel()
	mockServer.Close()
	bitcoinCLI("stop")
	// Give bitcoind a moment to shut down cleanly.
	time.Sleep(500 * time.Millisecond)
	os.RemoveAll(btcDataDir)
	os.Exit(code)
}

// ---------------------------------------------------------------------------
// Mock mempool.space server
// ---------------------------------------------------------------------------

func startMockMempoolServer() *httptest.Server {
	mux := http.NewServeMux()

	// GET /api/address/{addr}/utxo
	mux.HandleFunc("/api/address/", func(w http.ResponseWriter, r *http.Request) {
		// Path: /api/address/<addr>/utxo
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/address/"), "/")
		if len(parts) != 2 || parts[1] != "utxo" {
			http.NotFound(w, r)
			return
		}
		addr := parts[0]

		// Use scantxoutset to find UTXOs for external addresses (not in wallet).
		out, err := bitcoinCLI("scantxoutset", "start", fmt.Sprintf(`["addr(%s)"]`, addr))
		if err != nil {
			http.Error(w, "scantxoutset failed: "+err.Error(), 500)
			return
		}

		var scanResult struct {
			Unspents []struct {
				TxID   string  `json:"txid"`
				Vout   int     `json:"vout"`
				Amount float64 `json:"amount"`
				Height int     `json:"height"`
			} `json:"unspents"`
		}
		if err := json.Unmarshal([]byte(out), &scanResult); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("[]"))
			return
		}

		// Convert to mempool.space format.
		var result []map[string]any
		for _, u := range scanResult.Unspents {
			result = append(result, map[string]any{
				"txid":  u.TxID,
				"vout":  u.Vout,
				"value": int64(u.Amount * 1e8),
				"status": map[string]any{
					"confirmed": u.Height > 0,
				},
			})
		}
		if result == nil {
			result = []map[string]any{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	// GET /api/v1/fees/recommended
	mux.HandleFunc("/api/v1/fees/recommended", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"fastestFee":2,"halfHourFee":2,"hourFee":1,"minimumFee":1}`))
	})

	// GET /api/tx/{txid}/status — tx confirmation status
	mux.HandleFunc("/api/tx/", func(w http.ResponseWriter, r *http.Request) {
		handleTxGet(w, r)
	})

	// POST /api/tx — broadcast raw transaction
	mux.HandleFunc("/api/tx", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), 400)
			return
		}
		rawHex := strings.TrimSpace(string(body))

		txid, err := bitcoinCLI("sendrawtransaction", rawHex)
		if err != nil {
			http.Error(w, fmt.Sprintf("sendrawtransaction failed: %s (output: %s)", err, txid), 400)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(txid))
	})

	return httptest.NewServer(mux)
}

func handleTxGet(w http.ResponseWriter, r *http.Request) {
	// Parse: /api/tx/<txid> or /api/tx/<txid>/status
	path := strings.TrimPrefix(r.URL.Path, "/api/tx/")
	parts := strings.SplitN(path, "/", 2)
	txid := parts[0]

	if len(parts) == 2 && parts[1] == "status" {
		// Return confirmation status.
		out, err := bitcoinCLI("getrawtransaction", txid, "true")
		if err != nil {
			// Tx might be in mempool, not yet confirmed.
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"confirmed":false}`))
			return
		}
		var txInfo struct {
			Confirmations int `json:"confirmations"`
		}
		json.Unmarshal([]byte(out), &txInfo)
		confirmed := txInfo.Confirmations > 0
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"confirmed": confirmed})
		return
	}

	// Full tx info.
	out, err := bitcoinCLI("getrawtransaction", txid, "true")
	if err != nil {
		http.Error(w, "tx not found", 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(out))
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// generateRecipientAddress creates a new address from bitcoin-cli's wallet.
func generateRecipientAddress(t *testing.T) string {
	t.Helper()
	addr, err := bitcoinCLI("getnewaddress", "", "bech32")
	require.NoError(t, err, "getnewaddress failed: %s", addr)
	return addr
}

// mineBlock mines one block to confirm pending transactions.
func mineBlock(t *testing.T) {
	t.Helper()
	_, err := bitcoinCLI("-generate", "1")
	require.NoError(t, err)
}

// getReceivedByAddress returns the total BTC received by an address in satoshis.
func getReceivedByAddress(t *testing.T, addr string) int64 {
	t.Helper()
	out, err := bitcoinCLI("getreceivedbyaddress", addr, "0")
	require.NoError(t, err, "getreceivedbyaddress failed: %s", out)
	amount, err := strconv.ParseFloat(out, 64)
	require.NoError(t, err, "parse amount: %s", out)
	return int64(amount * 1e8)
}

// reFundSender sends additional BTC to the test sender and mines a block.
func reFundSender(t *testing.T, btcAmount string) {
	t.Helper()
	_, err := bitcoinCLI("sendtoaddress", btcTestAddr, btcAmount)
	require.NoError(t, err)
	mineBlock(t)
}

// ---------------------------------------------------------------------------
// E2E Tests
// ---------------------------------------------------------------------------

func TestE2E_BTC_BasicSend(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	recipient := generateRecipientAddress(t)

	txid, err := btcSend(ctx, btcTestPriv, recipient, 50000, 2)
	require.NoError(t, err)
	assert.NotEmpty(t, txid, "expected a txid")

	// Mine a block to confirm.
	mineBlock(t)

	// Verify the recipient received the funds.
	received := getReceivedByAddress(t, recipient)
	assert.Equal(t, int64(50000), received, "recipient should have received 50000 sats")
}

func TestE2E_BTC_SendWithChange(t *testing.T) {
	// Ensure the sender has a known UTXO by funding fresh.
	reFundSender(t, "0.5")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	recipient := generateRecipientAddress(t)

	// Send a small amount relative to the UTXO so change is generated.
	sendAmount := int64(100000) // 0.001 BTC
	txid, err := btcSend(ctx, btcTestPriv, recipient, sendAmount, 2)
	require.NoError(t, err)
	assert.NotEmpty(t, txid)

	// Mine a block.
	mineBlock(t)

	// Verify recipient got the amount.
	received := getReceivedByAddress(t, recipient)
	assert.Equal(t, sendAmount, received)

	// Verify the sender still has UTXOs (change was returned).
	// We do this by checking that the mock mempool lists UTXOs for the sender.
	utxos, err := fetchUTXOs(btcTestAddr)
	require.NoError(t, err)
	assert.NotEmpty(t, utxos, "sender should have change UTXOs")

	var totalRemaining int64
	for _, u := range utxos {
		totalRemaining += u.Value
	}
	// Sender should have gotten change back (original minus send minus fee).
	assert.Greater(t, totalRemaining, int64(0), "sender should have remaining balance")
}

func TestE2E_BTC_InsufficientFunds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	recipient := generateRecipientAddress(t)

	// Try to send way more than available (1000 BTC = 100B sats).
	_, err := btcSend(ctx, btcTestPriv, recipient, 100_000_000_000, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient funds")
}

func TestE2E_BTC_DustAmount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	recipient := generateRecipientAddress(t)

	// Try to send below the dust limit (546 sats).
	_, err := btcSend(ctx, btcTestPriv, recipient, 100, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dust limit")

	// Also try exactly at dust boundary minus one.
	_, err = btcSend(ctx, btcTestPriv, recipient, 545, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dust limit")
}

// ---------------------------------------------------------------------------
// Supplementary tests
// ---------------------------------------------------------------------------

func TestE2E_BTC_InvalidRecipient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := btcSend(ctx, btcTestPriv, "not-a-real-address", 50000, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid recipient address")
}

func TestE2E_BTC_BadPrivateKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	recipient := generateRecipientAddress(t)
	_, err := btcSend(ctx, "not-hex-at-all", recipient, 50000, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode private key")
}

func TestE2E_BTC_UnfundedKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate a fresh key with no funds.
	newKey, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	newPrivHex := hex.EncodeToString(ethcrypto.FromECDSA(newKey))

	recipient := generateRecipientAddress(t)
	_, err = btcSend(ctx, newPrivHex, recipient, 50000, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no confirmed UTXOs")
}

// ---------------------------------------------------------------------------
// Test that the mock mempool endpoints work correctly
// ---------------------------------------------------------------------------

func TestE2E_BTC_MockMempoolFees(t *testing.T) {
	feeRate, err := fetchFeeRate()
	require.NoError(t, err)
	assert.Equal(t, int64(2), feeRate, "mock should return halfHourFee=2")
}

func TestE2E_BTC_MockMempoolUTXOs(t *testing.T) {
	utxos, err := fetchUTXOs(btcTestAddr)
	require.NoError(t, err)
	assert.NotEmpty(t, utxos, "test address should have UTXOs")

	var total int64
	for _, u := range utxos {
		total += u.Value
		assert.True(t, u.Status.Confirmed, "UTXOs should be confirmed")
	}
	assert.Greater(t, total, int64(0))
}

// ---------------------------------------------------------------------------
// Test data dir cleanup helper (used by TestMain, verified here)
// ---------------------------------------------------------------------------

func TestE2E_BTC_DataDirExists(t *testing.T) {
	// Sanity check that our temp data dir exists during tests.
	info, err := os.Stat(btcDataDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	// Verify regtest subdir was created.
	regtestDir := filepath.Join(btcDataDir, "regtest")
	info, err = os.Stat(regtestDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}
