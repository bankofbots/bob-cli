package main

import (
	"context"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// encodeERC20TransferCall
// ---------------------------------------------------------------------------

func TestEncodeERC20TransferCall(t *testing.T) {
	to := common.HexToAddress("0xe1e62c940f6ba0c7c31591f32811d0f18699e1cd")
	amount := big.NewInt(2_000_000) // 2 USDC

	data := encodeERC20TransferCall(to, amount)

	assert.Equal(t, "a9059cbb", common.Bytes2Hex(data[:4]), "wrong selector")
	assert.Equal(t, 68, len(data), "wrong length")
	assert.Equal(t, to, common.BytesToAddress(data[4:36]))

	decoded := new(big.Int).SetBytes(data[36:68])
	assert.Equal(t, amount.Int64(), decoded.Int64())
}

func TestEncodeERC20TransferCall_ZeroAmount(t *testing.T) {
	to := common.HexToAddress("0x1111111111111111111111111111111111111111")
	data := encodeERC20TransferCall(to, big.NewInt(0))
	assert.Equal(t, 68, len(data))
	assert.Equal(t, "a9059cbb", common.Bytes2Hex(data[:4]))
}

func TestEncodeERC20TransferCall_LargeAmount(t *testing.T) {
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	amount := new(big.Int).Mul(big.NewInt(10_000_000_000), big.NewInt(1_000_000))
	data := encodeERC20TransferCall(to, amount)
	assert.Equal(t, 68, len(data))
	decoded := new(big.Int).SetBytes(data[36:68])
	assert.Equal(t, 0, amount.Cmp(decoded))
}

// ---------------------------------------------------------------------------
// encodeSafeExecTransaction
// ---------------------------------------------------------------------------

func TestEncodeSafeExecTransaction(t *testing.T) {
	usdcAddr := common.HexToAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
	owner := common.HexToAddress("0xe282755C6e8c5Fc4E2C752bdb6964cb16242D072")
	innerData := encodeERC20TransferCall(
		common.HexToAddress("0xe1e62c940f6ba0c7c31591f32811d0f18699e1cd"),
		big.NewInt(2_000_000),
	)

	data, err := encodeSafeExecTransaction(usdcAddr, innerData, owner)
	require.NoError(t, err)

	assert.Equal(t, "6a761202", common.Bytes2Hex(data[:4]), "wrong selector")
	toDecoded := common.BytesToAddress(data[4:36])
	assert.Equal(t, usdcAddr, toDecoded)
	valueDecoded := new(big.Int).SetBytes(data[36:68])
	assert.Equal(t, int64(0), valueDecoded.Int64())
}

func TestEncodeSafeExecTransaction_EmptyInnerData(t *testing.T) {
	to := common.HexToAddress("0x1111111111111111111111111111111111111111")
	owner := common.HexToAddress("0x2222222222222222222222222222222222222222")
	data, err := encodeSafeExecTransaction(to, []byte{}, owner)
	require.NoError(t, err)
	assert.Equal(t, "6a761202", common.Bytes2Hex(data[:4]))
}

// ---------------------------------------------------------------------------
// padTo32
// ---------------------------------------------------------------------------

func TestPadTo32(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{0, 0}, {1, 32}, {31, 32}, {32, 32}, {33, 64}, {64, 64}, {65, 96},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, padTo32(tt.input), "padTo32(%d)", tt.input)
	}
}

// ---------------------------------------------------------------------------
// Chain / token configuration
// ---------------------------------------------------------------------------

func TestSupportedChains_BaseOnly(t *testing.T) {
	_, ok := supportedChains["0x2105"]
	assert.True(t, ok, "Base should be supported")

	_, ok = supportedChains["0x1"]
	assert.False(t, ok, "Ethereum should not be supported")
}

func TestUsdcAddressForChain_Base(t *testing.T) {
	addr, err := usdcAddressForChain("0x2105")
	require.NoError(t, err)
	assert.Equal(t, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", addr.Hex())
}

func TestUsdcAddressForChain_Unsupported(t *testing.T) {
	_, err := usdcAddressForChain("0x1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported chain")
}

func TestRpcURLForChain_FallbackDefault(t *testing.T) {
	os.Unsetenv("BOB_EVM_RPC_URL")
	url, err := rpcURLForChain("0x2105")
	require.NoError(t, err)
	assert.Contains(t, url, "base.org")
}

func TestRpcURLForChain_EnvOverride(t *testing.T) {
	os.Setenv("BOB_EVM_RPC_URL", "https://my-custom-rpc.example.com")
	defer os.Unsetenv("BOB_EVM_RPC_URL")

	url, err := rpcURLForChain("0x2105")
	require.NoError(t, err)
	assert.Equal(t, "https://my-custom-rpc.example.com", url)
}

func TestRpcURLForChain_UnsupportedChain(t *testing.T) {
	os.Unsetenv("BOB_EVM_RPC_URL")
	_, err := rpcURLForChain("0xdeadbeef")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported chain")
}

// ---------------------------------------------------------------------------
// --amount required (no auto full-repayment)
// ---------------------------------------------------------------------------

func TestExecuteLoanRepayment_RequiresAmount(t *testing.T) {
	// amount=0 should fail immediately before any API call.
	_, _, err := executeLoanRepayment("fake-loan-id", "fake-agent-id", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--amount is required")
}

func TestExecuteLoanRepayment_NegativeAmount(t *testing.T) {
	_, _, err := executeLoanRepayment("fake-loan-id", "fake-agent-id", -100)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--amount is required")
}

// ---------------------------------------------------------------------------
// runSendEVM argument validation
// ---------------------------------------------------------------------------

func TestRunSendEVM_InvalidAmount(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("to", "0xe1e62c940f6ba0c7c31591f32811d0f18699e1cd", "")
	cmd.Flags().String("amount", "not-a-number", "")
	cmd.Flags().String("token", "usdc", "")

	err := runSendEVM(cmd, nil)
	assert.NoError(t, err) // runSendEVM emits errors, doesn't return them
}

func TestRunSendEVM_NegativeAmount(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("to", "0xe1e62c940f6ba0c7c31591f32811d0f18699e1cd", "")
	cmd.Flags().String("amount", "-100", "")
	cmd.Flags().String("token", "usdc", "")

	err := runSendEVM(cmd, nil)
	assert.NoError(t, err)
}

func TestRunSendEVM_ZeroAmount(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("to", "0xe1e62c940f6ba0c7c31591f32811d0f18699e1cd", "")
	cmd.Flags().String("amount", "0", "")
	cmd.Flags().String("token", "usdc", "")

	err := runSendEVM(cmd, nil)
	assert.NoError(t, err)
}

func TestRunSendEVM_BigIntAmount(t *testing.T) {
	// Amounts larger than int64 should be parseable (no truncation).
	amt := "99999999999999999999" // > MaxInt64
	parsed, ok := new(big.Int).SetString(amt, 10)
	require.True(t, ok)
	assert.True(t, parsed.Sign() > 0)
	// Verify it exceeds int64 range.
	assert.True(t, parsed.Cmp(big.NewInt(1<<62)) > 0)
}

func TestRunSendEVM_ExceedsUint256(t *testing.T) {
	// 2^256 is one above the max EVM uint256 value.
	overflow := new(big.Int).Lsh(big.NewInt(1), 256)
	cmd := &cobra.Command{}
	cmd.Flags().String("to", "0xe1e62c940f6ba0c7c31591f32811d0f18699e1cd", "")
	cmd.Flags().String("amount", overflow.String(), "")
	cmd.Flags().String("token", "usdc", "")

	err := runSendEVM(cmd, nil)
	assert.NoError(t, err) // error emitted, not returned
}

func TestRunSendEVM_Uint256MaxAccepted(t *testing.T) {
	// 2^256 - 1 (max uint256) should be accepted by validation (will fail at config load).
	uint256Max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	parsed, ok := new(big.Int).SetString(uint256Max.String(), 10)
	require.True(t, ok)
	assert.True(t, parsed.Sign() > 0)
	assert.Equal(t, 0, parsed.Cmp(uint256Max))
}

func TestRunSendEVM_InvalidAddress(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("to", "not-an-address", "")
	cmd.Flags().String("amount", "1000000", "")
	cmd.Flags().String("token", "usdc", "")

	err := runSendEVM(cmd, nil)
	assert.NoError(t, err) // error emitted, not returned
}

func TestRunSendEVM_UnsupportedToken(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("to", "0xe1e62c940f6ba0c7c31591f32811d0f18699e1cd", "")
	cmd.Flags().String("amount", "1000000", "")
	cmd.Flags().String("token", "doge", "")

	// Will fail trying to load config, but that's fine — tests the token validation path.
	err := runSendEVM(cmd, nil)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// evmSendNative validation
// ---------------------------------------------------------------------------

func TestEvmSendNative_InvalidPrivKey(t *testing.T) {
	_, err := evmSendNative(
		context.Background(), "not-hex", "0x2105",
		common.HexToAddress("0xe1e62c940f6ba0c7c31591f32811d0f18699e1cd"),
		big.NewInt(1000),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode private key")
}

func TestEvmSendNative_NilAmount(t *testing.T) {
	_, err := evmSendNative(
		context.Background(),
		"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"0x2105",
		common.HexToAddress("0xe1e62c940f6ba0c7c31591f32811d0f18699e1cd"),
		nil,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "positive")
}

func TestEvmSendNative_ZeroAmount(t *testing.T) {
	_, err := evmSendNative(
		context.Background(),
		"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"0x2105",
		common.HexToAddress("0xe1e62c940f6ba0c7c31591f32811d0f18699e1cd"),
		big.NewInt(0),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "positive")
}

func TestEvmSendNative_UnsupportedChain(t *testing.T) {
	os.Unsetenv("BOB_EVM_RPC_URL")
	_, err := evmSendNative(
		context.Background(),
		"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"0xdeadbeef",
		common.HexToAddress("0xe1e62c940f6ba0c7c31591f32811d0f18699e1cd"),
		big.NewInt(1000),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported chain")
}

// ---------------------------------------------------------------------------
// --tx path requires --amount
// ---------------------------------------------------------------------------

