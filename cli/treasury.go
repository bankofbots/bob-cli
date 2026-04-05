package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
)

type treasuryAccountsEnvelope struct {
	Accounts     []json.RawMessage `json:"accounts"`
	ControlFlags json.RawMessage   `json:"control_flags"`
}

type treasuryAccountStatusEnvelope struct {
	Status string `json:"status"`
}

type treasuryPrepareResponse struct {
	ReservationID     string `json:"reservation_id"`
	TreasuryAccountID string `json:"treasury_account_id"`
	ChainID           string `json:"chain_id"`
	SafeAddress       string `json:"safe_address"`
	SafeNonce         int64  `json:"safe_nonce"`
	SafeTxHash        string `json:"safe_tx_hash"`
	ContractAddress   string `json:"contract_address"`
	DataHex           string `json:"data_hex"`
	AssetAddress      string `json:"asset_address"`
	AmountAtomic      string `json:"amount_atomic"`
}

type treasuryTxRequestResponse struct {
	ID                string          `json:"id"`
	AgentID           string          `json:"agent_id"`
	OperatorID        string          `json:"operator_id"`
	TreasuryAccountID string          `json:"treasury_account_id"`
	PolicyVersionID   string          `json:"policy_version_id"`
	ChainID           string          `json:"chain_id"`
	SafeAddress       string          `json:"safe_address"`
	Kind              string          `json:"kind"`
	Status            string          `json:"status"`
	DecisionReason    string          `json:"decision_reason"`
	SafeTxHash        string          `json:"safe_tx_hash"`
	SafeNonce         int64           `json:"safe_nonce"`
	ToAddress         string          `json:"to_address"`
	ValueWei          string          `json:"value_wei"`
	DataHex           string          `json:"data_hex"`
	AssetAddress      string          `json:"asset_address"`
	AmountAtomic      string          `json:"amount_atomic"`
	ProposedByRole    string          `json:"proposed_by_role"`
	Request           json.RawMessage `json:"request"`
	Evaluation        json.RawMessage `json:"evaluation"`
	CreatedAt         string          `json:"created_at"`
	UpdatedAt         string          `json:"updated_at"`
}

func treasuryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "treasury",
		Short: "Use 2/2 treasury controls for spending-enabled agents",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob treasury",
				Data: map[string]any{
					"subcommands": []string{"status", "prepare", "sign", "submit", "transfer", "requests"},
				},
				NextActions: []NextAction{
					{Command: "bob treasury status", Description: "Show treasury accounts and active policy"},
					{Command: "bob treasury prepare --account-id <account-id> --to <address> --amount <atomic>", Description: "Reserve a nonce and build the canonical Safe tx"},
					{Command: "bob treasury transfer --account-id <account-id> --to <address> --amount <atomic>", Description: "Prepare, sign, and submit a treasury transfer"},
				},
			})
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show treasury accounts, control flags, and active policy",
		RunE:  runTreasuryStatus,
	}
	statusCmd.Flags().String("agent-id", "", "Agent ID")
	cmd.AddCommand(statusCmd)

	requestsCmd := &cobra.Command{
		Use:   "requests",
		Short: "List treasury transaction requests",
		RunE:  runTreasuryRequests,
	}
	requestsCmd.Flags().String("agent-id", "", "Agent ID")
	requestsCmd.Flags().Int("limit", 30, "Max results")
	requestsCmd.Flags().Int("offset", 0, "Offset")
	cmd.AddCommand(requestsCmd)

	prepareCmd := &cobra.Command{
		Use:   "prepare",
		Short: "Reserve a nonce and prepare a canonical treasury USDC transfer",
		RunE:  runTreasuryPrepare,
	}
	prepareCmd.Flags().String("agent-id", "", "Agent ID")
	prepareCmd.Flags().String("account-id", "", "Treasury account ID")
	prepareCmd.Flags().String("to", "", "Recipient EVM address")
	prepareCmd.Flags().String("amount", "", "USDC amount in atomic units (micro-USDC)")
	_ = prepareCmd.MarkFlagRequired("account-id")
	_ = prepareCmd.MarkFlagRequired("to")
	_ = prepareCmd.MarkFlagRequired("amount")
	cmd.AddCommand(prepareCmd)

	signCmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a prepared Safe tx hash with the local agent EVM key",
		RunE:  runTreasurySign,
	}
	signCmd.Flags().String("agent-id", "", "Agent ID")
	signCmd.Flags().String("safe-tx-hash", "", "Prepared Safe tx hash (0x...)")
	_ = signCmd.MarkFlagRequired("safe-tx-hash")
	cmd.AddCommand(signCmd)

	submitCmd := &cobra.Command{
		Use:   "submit",
		Short: "Submit a signed treasury transaction request for operator review",
		RunE:  runTreasurySubmit,
	}
	submitCmd.Flags().String("agent-id", "", "Agent ID")
	submitCmd.Flags().String("reservation-id", "", "Reserved treasury nonce ID")
	submitCmd.Flags().String("to", "", "Recipient EVM address")
	submitCmd.Flags().String("amount", "", "USDC amount in atomic units (micro-USDC)")
	submitCmd.Flags().String("signature", "", "Agent signature for safe_tx_hash (0x...)")
	submitCmd.Flags().String("request-json", `{"intent":"cli_treasury_transfer"}`, "Optional request metadata JSON object")
	_ = submitCmd.MarkFlagRequired("reservation-id")
	_ = submitCmd.MarkFlagRequired("to")
	_ = submitCmd.MarkFlagRequired("amount")
	_ = submitCmd.MarkFlagRequired("signature")
	cmd.AddCommand(submitCmd)

	transferCmd := &cobra.Command{
		Use:   "transfer",
		Short: "Prepare, sign, and submit a treasury transfer in one step",
		RunE:  runTreasuryTransfer,
	}
	transferCmd.Flags().String("agent-id", "", "Agent ID")
	transferCmd.Flags().String("account-id", "", "Treasury account ID")
	transferCmd.Flags().String("to", "", "Recipient EVM address")
	transferCmd.Flags().String("amount", "", "USDC amount in atomic units (micro-USDC)")
	transferCmd.Flags().String("request-json", `{"intent":"cli_treasury_transfer"}`, "Optional request metadata JSON object")
	_ = transferCmd.MarkFlagRequired("account-id")
	_ = transferCmd.MarkFlagRequired("to")
	_ = transferCmd.MarkFlagRequired("amount")
	cmd.AddCommand(transferCmd)

	return cmd
}

func runTreasuryStatus(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob treasury status", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	resp, err := apiGetFn(fmt.Sprintf("/agents/%s/treasury/accounts", url.PathEscape(agentID)))
	if err != nil {
		emitError("bob treasury status", err)
		return nil
	}
	var accounts treasuryAccountsEnvelope
	if err := json.Unmarshal(resp, &accounts); err != nil {
		emitError("bob treasury status", fmt.Errorf("failed to parse treasury accounts: %w", err))
		return nil
	}

	var policy any
	policyResp, err := apiGetFn(fmt.Sprintf("/agents/%s/treasury/policies/active", url.PathEscape(agentID)))
	if err == nil {
		if unmarshalErr := json.Unmarshal(policyResp, &policy); unmarshalErr != nil {
			emitError("bob treasury status", fmt.Errorf("failed to parse active policy: %w", unmarshalErr))
			return nil
		}
	} else if !isNotFoundError(err) {
		emitError("bob treasury status", err)
		return nil
	}
	activeAccountCount := countActiveTreasuryAccounts(accounts.Accounts)

	emit(Envelope{
		OK:      true,
		Command: "bob treasury status",
		Data: map[string]any{
			"agent_id":                       agentID,
			"accounts":                       accounts.Accounts,
			"control_flags":                  rawJSONToAny(accounts.ControlFlags),
			"active_policy":                  policy,
			"policy_present":                 policy != nil,
			"treasury_ready_for_spending":    activeAccountCount > 0 && policy != nil,
			"treasury_required_for_spending": true,
			"treasury_setup_guidance":        treasurySetupGuidance(activeAccountCount > 0, policy != nil),
		},
		NextActions: []NextAction{
			{Command: "bob treasury requests --agent-id " + agentID, Description: "List treasury transaction requests"},
			{Command: "bob treasury transfer --account-id <account-id> --to <address> --amount <atomic> --agent-id " + agentID, Description: "Submit a treasury transfer"},
		},
	})
	return nil
}

func treasurySetupGuidance(hasAccount bool, hasPolicy bool) string {
	switch {
	case !hasAccount && !hasPolicy:
		return "Treasury is not provisioned yet. For any agent that will spend autonomously, have your operator provision a 2-of-2 Safe and activate a treasury policy before funding it."
	case hasAccount && !hasPolicy:
		return "Treasury account exists but no active policy is attached. Spending should stay disabled until your operator activates a treasury policy."
	case !hasAccount && hasPolicy:
		return "Treasury policy exists but no treasury account is provisioned. Spending should stay disabled until the 2-of-2 Safe is created."
	default:
		return "Treasury is provisioned. Use treasury transfers for governed agent spending."
	}
}

func runTreasuryRequests(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob treasury requests", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}
	limit, _ := cmd.Flags().GetInt("limit")
	offset, _ := cmd.Flags().GetInt("offset")
	resp, err := apiGetFn(fmt.Sprintf("/agents/%s/treasury/tx-requests?limit=%d&offset=%d", url.PathEscape(agentID), limit, offset))
	if err != nil {
		emitError("bob treasury requests", err)
		return nil
	}
	var requests []json.RawMessage
	if err := json.Unmarshal(resp, &requests); err != nil {
		emitError("bob treasury requests", fmt.Errorf("failed to parse treasury requests: %w", err))
		return nil
	}
	emit(Envelope{
		OK:      true,
		Command: "bob treasury requests",
		Data: map[string]any{
			"agent_id": agentID,
			"requests": requests,
			"count":    len(requests),
		},
		NextActions: []NextAction{
			{Command: "bob treasury status --agent-id " + agentID, Description: "Show treasury account state"},
		},
	})
	return nil
}

func runTreasuryPrepare(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob treasury prepare", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}
	accountID, _ := cmd.Flags().GetString("account-id")
	toAddress, _ := cmd.Flags().GetString("to")
	amountAtomic, _ := cmd.Flags().GetString("amount")
	if err := validateTreasuryTransferInput(toAddress, amountAtomic); err != nil {
		emitError("bob treasury prepare", err)
		return nil
	}
	prepared, err := prepareTreasury(agentID, accountID, toAddress, amountAtomic)
	if err != nil {
		emitError("bob treasury prepare", err)
		return nil
	}
	emit(Envelope{
		OK:      true,
		Command: "bob treasury prepare",
		Data:    prepared,
		NextActions: []NextAction{
			{Command: "bob treasury sign --safe-tx-hash " + prepared.SafeTxHash + " --agent-id " + agentID, Description: "Sign the prepared Safe tx hash"},
			{Command: "bob treasury submit --reservation-id " + prepared.ReservationID + " --to " + toAddress + " --amount " + amountAtomic + " --signature <sig> --agent-id " + agentID, Description: "Submit the signed treasury request"},
		},
	})
	return nil
}

func runTreasurySign(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob treasury sign", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}
	safeTxHash, _ := cmd.Flags().GetString("safe-tx-hash")
	signature, signer, err := signTreasuryHashForAgent(agentID, safeTxHash)
	if err != nil {
		emitError("bob treasury sign", err)
		return nil
	}
	emit(Envelope{
		OK:      true,
		Command: "bob treasury sign",
		Data: map[string]any{
			"agent_id":       agentID,
			"signer_address": signer,
			"safe_tx_hash":   safeTxHash,
			"signature":      signature,
		},
		NextActions: []NextAction{
			{Command: "bob treasury submit --reservation-id <reservation-id> --to <address> --amount <atomic> --signature " + signature + " --agent-id " + agentID, Description: "Submit the signed treasury request"},
		},
	})
	return nil
}

func runTreasurySubmit(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob treasury submit", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}
	reservationID, _ := cmd.Flags().GetString("reservation-id")
	toAddress, _ := cmd.Flags().GetString("to")
	amountAtomic, _ := cmd.Flags().GetString("amount")
	signature, _ := cmd.Flags().GetString("signature")
	requestJSON, _ := cmd.Flags().GetString("request-json")
	if err := validateTreasuryTransferInput(toAddress, amountAtomic); err != nil {
		emitError("bob treasury submit", err)
		return nil
	}
	if err := validateSignatureHex(signature); err != nil {
		emitError("bob treasury submit", err)
		return nil
	}

	txReq, err := submitTreasury(agentID, reservationID, toAddress, amountAtomic, signature, requestJSON)
	if err != nil {
		emitError("bob treasury submit", err)
		return nil
	}
	emit(Envelope{
		OK:      true,
		Command: "bob treasury submit",
		Data:    txReq,
		NextActions: []NextAction{
			{Command: "bob treasury requests --agent-id " + agentID, Description: "Check request status"},
			{Command: "bob treasury status --agent-id " + agentID, Description: "Show treasury account state"},
		},
	})
	return nil
}

func runTreasuryTransfer(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob treasury transfer", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}
	accountID, _ := cmd.Flags().GetString("account-id")
	toAddress, _ := cmd.Flags().GetString("to")
	amountAtomic, _ := cmd.Flags().GetString("amount")
	requestJSON, _ := cmd.Flags().GetString("request-json")
	if err := validateTreasuryTransferInput(toAddress, amountAtomic); err != nil {
		emitError("bob treasury transfer", err)
		return nil
	}

	prepared, err := prepareTreasury(agentID, accountID, toAddress, amountAtomic)
	if err != nil {
		emitError("bob treasury transfer", err)
		return nil
	}
	signature, signer, err := signTreasuryHashForAgent(agentID, prepared.SafeTxHash)
	if err != nil {
		emitTreasuryFlowError("bob treasury transfer", err, prepared, toAddress, amountAtomic, agentID)
		return nil
	}
	txReq, err := submitTreasury(agentID, prepared.ReservationID, toAddress, amountAtomic, signature, requestJSON)
	if err != nil {
		emitTreasuryFlowError("bob treasury transfer", err, prepared, toAddress, amountAtomic, agentID)
		return nil
	}
	emit(Envelope{
		OK:      true,
		Command: "bob treasury transfer",
		Data: map[string]any{
			"prepared":       prepared,
			"signer_address": signer,
			"signature":      signature,
			"tx_request":     txReq,
		},
		NextActions: []NextAction{
			{Command: "bob treasury requests --agent-id " + agentID, Description: "Check operator review status"},
			{Command: "bob treasury status --agent-id " + agentID, Description: "Show treasury account state"},
		},
	})
	return nil
}

func prepareTreasury(agentID, accountID, toAddress, amountAtomic string) (*treasuryPrepareResponse, error) {
	resp, err := apiPostFn(fmt.Sprintf("/agents/%s/treasury/tx-requests/prepare", url.PathEscape(agentID)), map[string]any{
		"treasury_account_id": accountID,
		"to_address":          toAddress,
		"amount_atomic":       amountAtomic,
	})
	if err != nil {
		return nil, err
	}
	var prepared treasuryPrepareResponse
	if err := json.Unmarshal(resp, &prepared); err != nil {
		return nil, fmt.Errorf("failed to parse treasury prepare response: %w", err)
	}
	return &prepared, nil
}

func submitTreasury(agentID, reservationID, toAddress, amountAtomic, signature, requestJSON string) (*treasuryTxRequestResponse, error) {
	requestPayload, err := parseTreasuryRequestJSON(requestJSON)
	if err != nil {
		return nil, err
	}
	resp, err := apiPostFn(fmt.Sprintf("/agents/%s/treasury/tx-requests", url.PathEscape(agentID)), map[string]any{
		"reservation_id":  reservationID,
		"to_address":      toAddress,
		"amount_atomic":   amountAtomic,
		"agent_signature": signature,
		"request":         requestPayload,
	})
	if err != nil {
		return nil, err
	}
	var txReq treasuryTxRequestResponse
	if err := json.Unmarshal(resp, &txReq); err != nil {
		return nil, fmt.Errorf("failed to parse treasury tx request response: %w", err)
	}
	return &txReq, nil
}

func validateTreasuryTransferInput(toAddress, amountAtomic string) error {
	if !common.IsHexAddress(strings.TrimSpace(toAddress)) {
		return fmt.Errorf("invalid treasury recipient address %q", toAddress)
	}
	amount, ok := new(big.Int).SetString(strings.TrimSpace(amountAtomic), 10)
	if !ok {
		return fmt.Errorf("amount must be a positive integer (got %q)", amountAtomic)
	}
	if amount.Sign() <= 0 {
		return fmt.Errorf("amount must be greater than 0")
	}
	return nil
}

func emitTreasuryFlowError(command string, err error, prepared *treasuryPrepareResponse, toAddress, amountAtomic, agentID string) {
	if prepared == nil {
		emitError(command, err)
		return
	}
	emit(Envelope{
		OK:      false,
		Command: command,
		Data: map[string]any{
			"error":             err.Error(),
			"reservation_id":    prepared.ReservationID,
			"safe_tx_hash":      prepared.SafeTxHash,
			"treasury_account":  prepared.TreasuryAccountID,
			"safe_nonce":        prepared.SafeNonce,
			"to_address":        toAddress,
			"amount_atomic":     amountAtomic,
			"recovery_guidance": "reuse the existing reservation_id and safe_tx_hash to retry sign/submit instead of preparing a new transaction",
		},
		NextActions: []NextAction{
			{Command: "bob treasury sign --safe-tx-hash " + prepared.SafeTxHash + " --agent-id " + agentID, Description: "Re-sign the existing prepared Safe tx hash"},
			{Command: "bob treasury submit --reservation-id " + prepared.ReservationID + " --to " + toAddress + " --amount " + amountAtomic + " --signature <sig> --agent-id " + agentID, Description: "Submit the existing prepared treasury request without reserving a new nonce"},
		},
	})
}

// signTreasuryHashForAgent signs the raw 32-byte safeTxHash digest (no EIP-191 prefix).
// This matches Safe's eth_sign convention — the server-side verification must stay in sync.
func signTreasuryHashForAgent(agentID, safeTxHash string) (string, string, error) {
	cfg, err := loadCLIConfigFn()
	if err != nil {
		return "", "", fmt.Errorf("failed to load config: %w", err)
	}
	keys := cfg.walletKeysForAgent(agentID)
	if keys == nil || strings.TrimSpace(keys.EVMPrivateKey) == "" {
		return "", "", fmt.Errorf("no EVM wallet key found for agent %s — run 'bob init' for that agent first", agentID)
	}

	digestHex := strings.TrimPrefix(strings.TrimSpace(safeTxHash), "0x")
	digest, err := hex.DecodeString(digestHex)
	if err != nil {
		return "", "", fmt.Errorf("invalid safe_tx_hash: %w", err)
	}
	if len(digest) != 32 {
		return "", "", fmt.Errorf("safe_tx_hash must be 32 bytes")
	}

	privKeyBytes, err := hex.DecodeString(strings.TrimPrefix(keys.EVMPrivateKey, "0x"))
	if err != nil {
		return "", "", fmt.Errorf("decode EVM private key: %w", err)
	}
	defer func() {
		for i := range privKeyBytes {
			privKeyBytes[i] = 0
		}
	}()
	ecKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("parse EVM private key: %w", err)
	}
	signature, err := crypto.Sign(digest, ecKey)
	if err != nil {
		return "", "", fmt.Errorf("sign safe tx hash: %w", err)
	}
	if err := normalizeEthereumRecoveryID(signature); err != nil {
		return "", "", err
	}
	signer := crypto.PubkeyToAddress(ecKey.PublicKey).Hex()
	return "0x" + hex.EncodeToString(signature), signer, nil
}

func validateSignatureHex(sig string) error {
	trimmed := strings.TrimPrefix(strings.TrimSpace(sig), "0x")
	if trimmed == "" {
		return fmt.Errorf("signature is required")
	}
	sigBytes, err := hex.DecodeString(trimmed)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if len(sigBytes) != 65 {
		return fmt.Errorf("signature must be 65 bytes, got %d", len(sigBytes))
	}
	v := sigBytes[64]
	if v != 27 && v != 28 {
		return fmt.Errorf("invalid recovery ID %d (expected 27 or 28)", v)
	}
	return nil
}

func rawJSONToAny(raw json.RawMessage) any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return string(raw)
	}
	return out
}

func countActiveTreasuryAccounts(accounts []json.RawMessage) int {
	active := 0
	for _, raw := range accounts {
		var account treasuryAccountStatusEnvelope
		if err := json.Unmarshal(raw, &account); err != nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(account.Status)) {
		case "active":
			active++
		}
	}
	return active
}

func parseTreasuryRequestJSON(raw string) (any, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return map[string]any{}, nil
	}
	var out any
	if err := json.Unmarshal([]byte(trimmed), &out); err != nil {
		return nil, fmt.Errorf("request-json must be valid JSON: %w", err)
	}
	return out, nil
}
