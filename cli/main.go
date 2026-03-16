package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var apiBase = "http://localhost:8080/api/v1"
var apiKey string

func init() {
	if v := os.Getenv("BOB_API_URL"); v != "" {
		apiBase = v
	}
}

// --- Response envelope (HATEOAS) ---

type NextAction struct {
	Command     string           `json:"command"`
	Description string           `json:"description"`
	Params      map[string]Param `json:"params,omitempty"`
}

type Param struct {
	Value       string   `json:"value,omitempty"`
	Default     string   `json:"default,omitempty"`
	Enum        []string `json:"enum,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Description string   `json:"description"`
}

type Envelope struct {
	OK          bool         `json:"ok"`
	Command     string       `json:"command"`
	Data        any          `json:"data"`
	NextActions []NextAction `json:"next_actions"`
	Pagination  *Pagination  `json:"pagination,omitempty"`
}

type Pagination struct {
	Total     int  `json:"total"`
	Limit     int  `json:"limit"`
	Offset    int  `json:"offset"`
	HasMore   bool `json:"has_more"`
	Truncated bool `json:"truncated"`
}

func emit(env Envelope) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(env)
}

func emitError(command string, err error) {
	emit(Envelope{
		OK:      false,
		Command: command,
		Data:    map[string]string{"error": err.Error()},
	})
}

// redactKey shows only the prefix and last 4 characters of an API key.
func redactKey(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:8] + "..." + key[len(key)-4:]
}

// --- HTTP helpers ---

func newRequest(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, apiBase+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	return req, nil
}

func apiGet(path string) (json.RawMessage, error) {
	req, err := newRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("api error (%d): %s", resp.StatusCode, string(body))
	}
	return json.RawMessage(body), nil
}

func apiPost(path string, payload any) (json.RawMessage, error) {
	b, _ := json.Marshal(payload)
	req, err := newRequest(http.MethodPost, path, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusConflict {
		var apiErr struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &apiErr) == nil && apiErr.Error != "" {
			return nil, fmt.Errorf("conflict: %s", apiErr.Error)
		}
		return nil, fmt.Errorf("conflict: resource already exists")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("api error (%d): %s", resp.StatusCode, string(body))
	}
	return json.RawMessage(body), nil
}

func apiDelete(path string) (json.RawMessage, error) {
	req, err := newRequest(http.MethodDelete, path, nil)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("api error (%d): %s", resp.StatusCode, string(body))
	}
	return json.RawMessage(body), nil
}

// --- Command tree (Principle 3: Self-Documenting) ---

type CommandInfo struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Usage       string        `json:"usage,omitempty"`
	Flags       []FlagInfo    `json:"flags,omitempty"`
	Children    []CommandInfo `json:"children,omitempty"`
}

type FlagInfo struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Default     string `json:"default,omitempty"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

func commandTree() CommandInfo {
	return CommandInfo{
		Name:        "bob",
		Description: "Bank of Bots CLI — economic infrastructure for autonomous agents",
		Children: []CommandInfo{
			{
				Name:        "agent",
				Description: "Manage agents",
				Children: []CommandInfo{
					{
						Name:        "connect",
						Description: "Connect a new agent and provision rails",
						Usage:       "bob agent connect --name <name> [--operator <id>] [--budget <amount>] [--currency <code>] [--currencies <csv>] [--auto-approve]",
						Flags: []FlagInfo{
							{Name: "name", Type: "string", Required: true, Description: "Agent name"},
							{Name: "operator", Type: "string", Description: "Operator ID"},
							{Name: "budget", Type: "integer", Default: "0", Description: "Budget in smallest currency unit"},
							{Name: "currency", Type: "string", Default: "BTC", Description: "Primary currency"},
							{Name: "currencies", Type: "string", Description: "Comma-separated currencies to provision"},
							{Name: "auto-approve", Type: "boolean", Default: "false", Description: "Immediately approve agent after creation"},
						},
					},
					{
						Name:        "create",
						Description: "Create a new agent (alias for connect)",
						Usage:       "bob agent create --name <name> [--operator <id>] [--budget <amount>] [--currency <code>] [--currencies <csv>] [--auto-approve]",
						Flags: []FlagInfo{
							{Name: "name", Type: "string", Required: true, Description: "Agent name"},
							{Name: "operator", Type: "string", Description: "Operator ID"},
							{Name: "budget", Type: "integer", Default: "0", Description: "Budget in smallest currency unit"},
							{Name: "currency", Type: "string", Default: "BTC", Description: "Primary currency"},
							{Name: "currencies", Type: "string", Description: "Comma-separated currencies to provision"},
							{Name: "auto-approve", Type: "boolean", Default: "false", Description: "Immediately approve agent after creation"},
						},
					},
					{
						Name:        "list",
						Description: "List all agents",
						Usage:       "bob agent list [--limit <n>] [--offset <n>]",
						Flags: []FlagInfo{
							{Name: "limit", Type: "integer", Default: "30", Description: "Max results to return"},
							{Name: "offset", Type: "integer", Default: "0", Description: "Number of results to skip"},
						},
					},
					{
						Name:        "get",
						Description: "Get a single agent by ID",
						Usage:       "bob agent get <agent-id>",
					},
					{
						Name:        "approve",
						Description: "Approve and optionally seed an agent",
						Usage:       "bob agent approve <agent-id> [--seed-amount <n>] [--seed-currency <code>] [--seed-wallet-id <id>]",
						Flags: []FlagInfo{
							{Name: "seed-amount", Type: "integer", Default: "0", Description: "Optional starter balance amount"},
							{Name: "seed-currency", Type: "string", Description: "Currency for auto-selected seed wallet"},
							{Name: "seed-wallet-id", Type: "string", Description: "Explicit seed wallet override"},
						},
					},
					{
						Name:        "kill",
						Description: "Kill (deactivate) an agent",
						Usage:       "bob agent kill <agent-id>",
					},
				},
			},
			{
				Name:        "policy",
				Description: "Manage policies",
				Children: []CommandInfo{
					{
						Name:        "set",
						Description: "Set a spending policy for an agent",
						Usage:       "bob policy set <agent-id> [--spend-limit <n>] [--rate-limit <n>] [--time-window <s>] [--kill-switch]",
						Flags: []FlagInfo{
							{Name: "spend-limit", Type: "integer", Default: "0", Description: "Max spend per time window"},
							{Name: "rate-limit", Type: "integer", Default: "0", Description: "Max transactions per time window"},
							{Name: "time-window", Type: "integer", Default: "3600", Description: "Time window in seconds"},
							{Name: "kill-switch", Type: "boolean", Default: "false", Description: "Enable kill switch to block all transactions"},
						},
					},
					{
						Name:        "list",
						Description: "List policies for an agent",
						Usage:       "bob policy list <agent-id>",
					},
				},
			},
			{
				Name:        "spend",
				Description: "View spend summaries",
				Children: []CommandInfo{
					{
						Name:        "list",
						Description: "Show spend summary for an agent",
						Usage:       "bob spend list <agent-id>",
					},
				},
			},
			{
				Name:        "tx",
				Description: "Manage transactions",
				Children: []CommandInfo{
					{
						Name:        "record",
						Description: "Record a transaction for an agent",
						Usage:       "bob tx record <agent-id> --amount <n> [--currency <c>] [--execution-mode <auto|pinned>] [--rail <r|auto>] [--wallet-id <id>] [--endpoint <url>]",
						Flags: []FlagInfo{
							{Name: "amount", Type: "integer", Required: true, Description: "Transaction amount in smallest currency unit"},
							{Name: "currency", Type: "string", Default: "BTC", Description: "Currency code (BTC)"},
							{Name: "execution-mode", Type: "string", Default: "auto", Description: "Routing mode (auto or pinned)"},
							{Name: "rail", Type: "string", Default: "auto", Description: "Payment rail (auto, lightning, onchain)"},
							{Name: "wallet-id", Type: "string", Description: "Specific wallet override"},
							{Name: "endpoint", Type: "string", Description: "Target endpoint"},
						},
					},
					{
						Name:        "list",
						Description: "List transactions for an agent",
						Usage:       "bob tx list <agent-id> [--limit <n>] [--offset <n>] [--status <s>] [--direction <d>] [--since <rfc3339>] [--until <rfc3339>] [--sort-by <field>] [--order <dir>]",
						Flags: []FlagInfo{
							{Name: "limit", Type: "integer", Default: "30", Description: "Max results to return"},
							{Name: "offset", Type: "integer", Default: "0", Description: "Number of results to skip"},
							{Name: "status", Type: "string", Description: "Filter status (pending, complete, failed, denied)"},
							{Name: "direction", Type: "string", Description: "Filter direction (inbound, outbound)"},
							{Name: "since", Type: "string", Description: "Filter lower bound timestamp (RFC3339)"},
							{Name: "until", Type: "string", Description: "Filter upper bound timestamp (RFC3339)"},
							{Name: "sort-by", Type: "string", Default: "created_at", Description: "Sort field (created_at, amount)"},
							{Name: "order", Type: "string", Default: "desc", Description: "Sort direction (asc, desc)"},
						},
					},
					{
						Name:        "transfer",
						Description: "Create an agent-to-agent transfer",
						Usage:       "bob tx transfer <from-agent-id> --to-agent-id <id> --amount <n> [--currency <c>] [--from-wallet-id <id>] [--to-wallet-id <id>] [--description <text>]",
						Flags: []FlagInfo{
							{Name: "to-agent-id", Type: "string", Required: true, Description: "Destination agent ID"},
							{Name: "amount", Type: "integer", Required: true, Description: "Transfer amount in smallest currency unit"},
							{Name: "currency", Type: "string", Default: "BTC", Description: "Currency code (BTC)"},
							{Name: "from-wallet-id", Type: "string", Description: "Optional source wallet override"},
							{Name: "to-wallet-id", Type: "string", Description: "Optional destination wallet override"},
							{Name: "description", Type: "string", Description: "Optional transfer description"},
						},
					},
					{
						Name:        "transfers",
						Description: "List agent transfer history",
						Usage:       "bob tx transfers <agent-id> [--limit <n>] [--offset <n>] [--status <s>] [--direction <d>] [--since <rfc3339>] [--until <rfc3339>] [--sort-by <field>] [--order <dir>]",
						Flags: []FlagInfo{
							{Name: "limit", Type: "integer", Default: "30", Description: "Max results to return"},
							{Name: "offset", Type: "integer", Default: "0", Description: "Number of results to skip"},
							{Name: "status", Type: "string", Description: "Filter status (pending, complete, failed, denied)"},
							{Name: "direction", Type: "string", Description: "Filter direction (inbound, outbound)"},
							{Name: "since", Type: "string", Description: "Filter lower bound timestamp (RFC3339)"},
							{Name: "until", Type: "string", Description: "Filter upper bound timestamp (RFC3339)"},
							{Name: "sort-by", Type: "string", Default: "created_at", Description: "Sort field (created_at, amount)"},
							{Name: "order", Type: "string", Default: "desc", Description: "Sort direction (asc, desc)"},
						},
					},
				},
			},
		},
	}
}

func childCommandInfo(root CommandInfo, name string) CommandInfo {
	for _, c := range root.Children {
		if c.Name == name {
			return c
		}
	}
	return CommandInfo{Name: name}
}

func main() {
	root := &cobra.Command{
		Use:   "bob",
		Short: "Bank of Bots CLI",
		// Principle 3: root command emits the full command tree as JSON
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob",
				Data:    commandTree(),
				NextActions: []NextAction{
					{Command: "bob agent list", Description: "List all agents"},
					{Command: "bob agent connect --name <name>", Description: "Connect a new agent", Params: map[string]Param{
						"name": {Required: true, Description: "Agent name"},
					}},
				},
			})
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Persistent flag: --api-key (also reads BOB_API_KEY env)
	root.PersistentFlags().StringVar(&apiKey, "api-key", os.Getenv("BOB_API_KEY"), "API key for authentication (or set BOB_API_KEY)")

	root.AddCommand(agentCmd())
	root.AddCommand(policyCmd())
	root.AddCommand(spendCmd())
	root.AddCommand(txCmd())

	if err := root.Execute(); err != nil {
		emitError("bob", err)
		os.Exit(1)
	}
}

// --- Agent commands ---

func agentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Manage agents",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob agent",
				Data:    commandTree().Children[0],
				NextActions: []NextAction{
					{Command: "bob agent list", Description: "List all agents"},
					{Command: "bob agent connect --name <name>", Description: "Connect a new agent"},
				},
			})
			return nil
		},
	}

	// connect (primary)
	connectCmd := &cobra.Command{
		Use:   "connect",
		Short: "Connect a new agent and provision rails",
		RunE:  agentConnect,
	}
	connectCmd.Flags().String("name", "", "Agent name (required)")
	connectCmd.Flags().String("operator", "", "Operator ID")
	connectCmd.Flags().Int64("budget", 0, "Budget in smallest currency unit")
	connectCmd.Flags().String("currency", "BTC", "Primary currency (BTC)")
	connectCmd.Flags().StringSlice("currencies", nil, "Currencies to provision (overrides --currency)")
	connectCmd.Flags().Bool("auto-approve", false, "Immediately approve the agent")
	connectCmd.MarkFlagRequired("name")
	cmd.AddCommand(connectCmd)

	// create (alias for connect, backward compat)
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create an agent (alias for connect)",
		RunE:  agentConnect,
	}
	createCmd.Flags().String("name", "", "Agent name (required)")
	createCmd.Flags().String("operator", "", "Operator ID")
	createCmd.Flags().Int64("budget", 0, "Budget in smallest currency unit")
	createCmd.Flags().String("currency", "BTC", "Primary currency (BTC)")
	createCmd.Flags().StringSlice("currencies", nil, "Currencies to provision (overrides --currency)")
	createCmd.Flags().Bool("auto-approve", false, "Immediately approve the agent")
	createCmd.MarkFlagRequired("name")
	cmd.AddCommand(createCmd)

	// list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List agents",
		RunE:  agentList,
	}
	listCmd.Flags().Int("limit", 30, "Max results")
	listCmd.Flags().Int("offset", 0, "Results to skip")
	cmd.AddCommand(listCmd)

	// get
	cmd.AddCommand(&cobra.Command{
		Use:   "get [agent-id]",
		Short: "Get agent details",
		Args:  cobra.ExactArgs(1),
		RunE:  agentGet,
	})

	approveCmd := &cobra.Command{
		Use:   "approve [agent-id]",
		Short: "Approve and optionally seed an agent",
		Args:  cobra.ExactArgs(1),
		RunE:  agentApprove,
	}
	approveCmd.Flags().Int64("seed-amount", 0, "Optional starter balance amount")
	approveCmd.Flags().String("seed-currency", "", "Currency for auto-selected seed wallet")
	approveCmd.Flags().String("seed-wallet-id", "", "Explicit seed wallet override")
	cmd.AddCommand(approveCmd)

	// kill
	cmd.AddCommand(&cobra.Command{
		Use:   "kill [agent-id]",
		Short: "Kill (deactivate) an agent",
		Args:  cobra.ExactArgs(1),
		RunE:  agentKill,
	})

	return cmd
}

func agentConnect(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	operator, _ := cmd.Flags().GetString("operator")
	budget, _ := cmd.Flags().GetInt64("budget")
	autoApprove, _ := cmd.Flags().GetBool("auto-approve")
	primaryCurrency, _ := cmd.Flags().GetString("currency")
	currencies, _ := cmd.Flags().GetStringSlice("currencies")
	for i := range currencies {
		currencies[i] = strings.ToUpper(strings.TrimSpace(currencies[i]))
	}
	primaryCurrency = strings.ToUpper(strings.TrimSpace(primaryCurrency))
	if primaryCurrency == "" {
		primaryCurrency = "BTC"
	}
	if len(currencies) == 0 {
		currencies = []string{primaryCurrency}
	}

	data, err := apiPost("/agents", map[string]any{
		"name":         name,
		"operator_id":  operator,
		"budget":       budget,
		"currency":     primaryCurrency,
		"currencies":   currencies,
		"auto_approve": autoApprove,
	})
	if err != nil {
		emitError("bob agent connect", err)
		return nil
	}

	// Extract agent ID and API key for next_actions
	var agent map[string]any
	json.Unmarshal(data, &agent)
	agentID, _ := agent["id"].(string)
	agentAPIKey, _ := agent["api_key"].(string)
	apiKeyPending, _ := agent["api_key_pending"].(bool)

	nextActions := []NextAction{
		{
			Command:     fmt.Sprintf("bob policy set %s --spend-limit <limit>", agentID),
			Description: "Set a spending policy for this agent",
			Params: map[string]Param{
				"limit": {Description: "Max spend per time window", Required: true},
			},
		},
	}
	if agentAPIKey != "" {
		fmt.Fprintf(os.Stderr, "\n  *** Save this API key now — it will not be shown again ***\n  %s\n\n", agentAPIKey)
		nextActions = append(nextActions, NextAction{
			Command:     fmt.Sprintf("bob tx record %s --amount 1000", agentID),
			Description: "Test with a transaction",
		})
		nextActions = append([]NextAction{
			{
				Command:     fmt.Sprintf("export BOB_API_KEY=%s", redactKey(agentAPIKey)),
				Description: "Set API key in your environment (redacted — use full key from above)",
			},
			{
				Command:     fmt.Sprintf("bob agent get %s", agentID),
				Description: "View this agent's details",
			},
		}, nextActions...)
	} else if apiKeyPending {
		nextActions = append([]NextAction{
			{
				Command:     fmt.Sprintf("bob agent approve %s --seed-amount 10000", agentID),
				Description: "Approve the agent and seed starter balance",
			},
			{
				Command:     fmt.Sprintf("bob agent get %s", agentID),
				Description: "Check agent provisioning status and wallet readiness",
			},
		}, nextActions...)
	} else {
		nextActions = append([]NextAction{
			{
				Command:     fmt.Sprintf("bob agent get %s", agentID),
				Description: "View this agent's details",
			},
		}, nextActions...)
	}

	emit(Envelope{
		OK:          true,
		Command:     "bob agent connect",
		Data:        json.RawMessage(data),
		NextActions: nextActions,
	})
	return nil
}

func agentList(cmd *cobra.Command, args []string) error {
	limit, _ := cmd.Flags().GetInt("limit")
	offset, _ := cmd.Flags().GetInt("offset")

	data, err := apiGet(fmt.Sprintf("/agents?limit=%d&offset=%d", limit, offset))
	if err != nil {
		emitError("bob agent list", err)
		return nil
	}

	// Parse paginated response from API
	var paged struct {
		Data      json.RawMessage `json:"data"`
		Total     int             `json:"total"`
		Limit     int             `json:"limit"`
		Offset    int             `json:"offset"`
		HasMore   bool            `json:"has_more"`
		Truncated bool            `json:"truncated"`
	}
	json.Unmarshal(data, &paged)

	nextActions := []NextAction{
		{
			Command:     "bob agent connect --name <name>",
			Description: "Connect a new agent",
			Params:      map[string]Param{"name": {Required: true, Description: "Agent name"}},
		},
		{
			Command:     "bob agent get <agent-id>",
			Description: "Get details for a specific agent",
			Params:      map[string]Param{"agent-id": {Required: true, Description: "Agent UUID"}},
		},
	}

	if paged.HasMore {
		nextOffset := paged.Offset + paged.Limit
		nextActions = append(nextActions, NextAction{
			Command:     fmt.Sprintf("bob agent list --limit %d --offset %d", paged.Limit, nextOffset),
			Description: fmt.Sprintf("Next page (%d-%d of %d)", nextOffset+1, min(nextOffset+paged.Limit, paged.Total), paged.Total),
		})
	}

	emit(Envelope{
		OK:      true,
		Command: "bob agent list",
		Data:    paged.Data,
		Pagination: &Pagination{
			Total:     paged.Total,
			Limit:     paged.Limit,
			Offset:    paged.Offset,
			HasMore:   paged.HasMore,
			Truncated: paged.Truncated,
		},
		NextActions: nextActions,
	})
	return nil
}

func agentGet(cmd *cobra.Command, args []string) error {
	id := args[0]
	data, err := apiGet("/agents/" + id)
	if err != nil {
		emitError("bob agent get", err)
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob agent get",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: fmt.Sprintf("bob policy set %s --spend-limit <limit>", id), Description: "Set a spending policy"},
			{Command: fmt.Sprintf("bob policy list %s", id), Description: "View policies"},
			{Command: fmt.Sprintf("bob tx list %s", id), Description: "View transactions"},
			{Command: fmt.Sprintf("bob spend list %s", id), Description: "View spend summary"},
		},
	})
	return nil
}

func agentApprove(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	seedAmount, _ := cmd.Flags().GetInt64("seed-amount")
	seedCurrency, _ := cmd.Flags().GetString("seed-currency")
	seedWalletID, _ := cmd.Flags().GetString("seed-wallet-id")

	payload := map[string]any{}
	if seedAmount > 0 {
		payload["seed_amount"] = seedAmount
	}
	if seedCurrency != "" {
		payload["seed_currency"] = strings.ToUpper(strings.TrimSpace(seedCurrency))
	}
	if seedWalletID != "" {
		payload["seed_wallet_id"] = seedWalletID
	}

	data, err := apiPost("/agents/"+agentID+"/approve", payload)
	if err != nil {
		emitError("bob agent approve", err)
		return nil
	}

	var approved map[string]any
	_ = json.Unmarshal(data, &approved)
	agentAPIKey, _ := approved["api_key"].(string)
	apiKeyPending, _ := approved["api_key_pending"].(bool)

	nextActions := []NextAction{
		{Command: fmt.Sprintf("bob agent get %s", agentID), Description: "View updated agent status"},
	}
	if agentAPIKey != "" {
		fmt.Fprintf(os.Stderr, "\n  *** Save this API key now — it will not be shown again ***\n  %s\n\n", agentAPIKey)
		nextActions = append([]NextAction{
			{Command: fmt.Sprintf("export BOB_API_KEY=%s", redactKey(agentAPIKey)), Description: "Set API key in your environment (redacted — use full key from above)"},
			{Command: fmt.Sprintf("bob tx record %s --amount 1000", agentID), Description: "Run the first autonomous transaction"},
		}, nextActions...)
	} else if apiKeyPending {
		nextActions = append([]NextAction{
			{Command: fmt.Sprintf("bob agent get %s", agentID), Description: "Wait for a ready wallet, then retry approval"},
		}, nextActions...)
	}

	emit(Envelope{
		OK:          true,
		Command:     "bob agent approve",
		Data:        json.RawMessage(data),
		NextActions: nextActions,
	})
	return nil
}

func agentKill(cmd *cobra.Command, args []string) error {
	id := args[0]
	data, err := apiDelete("/agents/" + id)
	if err != nil {
		emitError("bob agent kill", err)
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob agent kill",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: "bob agent list", Description: "List remaining agents"},
			{Command: "bob agent connect --name <name>", Description: "Connect a replacement agent"},
		},
	})
	return nil
}

// --- Policy commands ---

func policyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage policies",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob policy",
				Data:    commandTree().Children[1],
			})
			return nil
		},
	}

	setCmd := &cobra.Command{
		Use:   "set [agent-id]",
		Short: "Set a policy for an agent",
		Args:  cobra.ExactArgs(1),
		RunE:  policySet,
	}
	setCmd.Flags().Int64("spend-limit", 0, "Spend limit per window")
	setCmd.Flags().Int("rate-limit", 0, "Max transactions per window")
	setCmd.Flags().Int("time-window", 3600, "Time window in seconds")
	setCmd.Flags().Bool("kill-switch", false, "Enable kill switch")
	cmd.AddCommand(setCmd)

	listCmd := &cobra.Command{
		Use:   "list [agent-id]",
		Short: "List policies for an agent",
		Args:  cobra.ExactArgs(1),
		RunE:  policyList,
	}
	cmd.AddCommand(listCmd)

	return cmd
}

func policySet(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	spendLimit, _ := cmd.Flags().GetInt64("spend-limit")
	rateLimit, _ := cmd.Flags().GetInt("rate-limit")
	timeWindow, _ := cmd.Flags().GetInt("time-window")
	killSwitch, _ := cmd.Flags().GetBool("kill-switch")

	data, err := apiPost("/agents/"+agentID+"/policies", map[string]any{
		"spend_limit": spendLimit,
		"rate_limit":  rateLimit,
		"time_window": timeWindow,
		"kill_switch": killSwitch,
	})
	if err != nil {
		emitError("bob policy set", err)
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob policy set",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: fmt.Sprintf("bob policy list %s", agentID), Description: "View all policies for this agent"},
			{Command: fmt.Sprintf("bob tx record %s --amount <amount>", agentID), Description: "Test with a transaction", Params: map[string]Param{
				"amount": {Required: true, Description: "Amount in smallest currency unit"},
			}},
			{Command: fmt.Sprintf("bob spend list %s", agentID), Description: "View current spend"},
		},
	})
	return nil
}

func policyList(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	data, err := apiGet("/agents/" + agentID + "/policies")
	if err != nil {
		emitError("bob policy list", err)
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob policy list",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: fmt.Sprintf("bob policy set %s --spend-limit <limit>", agentID), Description: "Set a new policy"},
			{Command: fmt.Sprintf("bob policy set %s --kill-switch", agentID), Description: "Emergency: enable kill switch"},
		},
	})
	return nil
}

// --- Spend commands ---

func spendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "spend",
		Short: "View spend summaries",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob spend",
				Data:    commandTree().Children[2],
			})
			return nil
		},
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list [agent-id]",
		Short: "Show spend summary for an agent",
		Args:  cobra.ExactArgs(1),
		RunE:  spendList,
	})

	return cmd
}

func spendList(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	data, err := apiGet("/agents/" + agentID + "/spend")
	if err != nil {
		emitError("bob spend list", err)
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob spend list",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: fmt.Sprintf("bob tx list %s", agentID), Description: "View transaction details"},
			{Command: fmt.Sprintf("bob policy list %s", agentID), Description: "View spending policies"},
		},
	})
	return nil
}

// --- Transaction commands ---

func txCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tx",
		Short: "Manage transactions",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob tx",
				Data:    childCommandInfo(commandTree(), "tx"),
			})
			return nil
		},
	}

	recordCmd := &cobra.Command{
		Use:   "record [agent-id]",
		Short: "Record a transaction",
		Args:  cobra.ExactArgs(1),
		RunE:  txRecord,
	}
	recordCmd.Flags().Int64("amount", 0, "Transaction amount (required)")
	recordCmd.Flags().String("currency", "BTC", "Currency (BTC)")
	recordCmd.Flags().String("execution-mode", "auto", "Routing mode (auto, pinned)")
	recordCmd.Flags().String("rail", "auto", "Payment rail (auto, lightning, onchain)")
	recordCmd.Flags().String("wallet-id", "", "Specific wallet override")
	recordCmd.Flags().String("endpoint", "", "Target endpoint")
	recordCmd.MarkFlagRequired("amount")
	cmd.AddCommand(recordCmd)

	listCmd := &cobra.Command{
		Use:   "list [agent-id]",
		Short: "List transactions for an agent",
		Args:  cobra.ExactArgs(1),
		RunE:  txList,
	}
	listCmd.Flags().Int("limit", 30, "Max results")
	listCmd.Flags().Int("offset", 0, "Results to skip")
	listCmd.Flags().String("status", "", "Filter status (pending, complete, failed, denied)")
	listCmd.Flags().String("direction", "", "Filter direction (inbound, outbound)")
	listCmd.Flags().String("since", "", "Filter lower bound timestamp (RFC3339)")
	listCmd.Flags().String("until", "", "Filter upper bound timestamp (RFC3339)")
	listCmd.Flags().String("sort-by", "created_at", "Sort field (created_at, amount)")
	listCmd.Flags().String("order", "desc", "Sort direction (asc, desc)")
	cmd.AddCommand(listCmd)

	transferCmd := &cobra.Command{
		Use:   "transfer [from-agent-id]",
		Short: "Create an agent-to-agent transfer",
		Args:  cobra.ExactArgs(1),
		RunE:  txTransfer,
	}
	transferCmd.Flags().String("to-agent-id", "", "Destination agent ID (required)")
	transferCmd.Flags().Int64("amount", 0, "Transfer amount in smallest currency unit (required)")
	transferCmd.Flags().String("currency", "BTC", "Currency (BTC)")
	transferCmd.Flags().String("from-wallet-id", "", "Optional source wallet override")
	transferCmd.Flags().String("to-wallet-id", "", "Optional destination wallet override")
	transferCmd.Flags().String("description", "", "Optional transfer description")
	transferCmd.MarkFlagRequired("to-agent-id")
	transferCmd.MarkFlagRequired("amount")
	cmd.AddCommand(transferCmd)

	transfersCmd := &cobra.Command{
		Use:   "transfers [agent-id]",
		Short: "List transfer history for an agent",
		Args:  cobra.ExactArgs(1),
		RunE:  txTransfers,
	}
	transfersCmd.Flags().Int("limit", 30, "Max results")
	transfersCmd.Flags().Int("offset", 0, "Results to skip")
	transfersCmd.Flags().String("status", "", "Filter status (pending, complete, failed, denied)")
	transfersCmd.Flags().String("direction", "", "Filter direction (inbound, outbound)")
	transfersCmd.Flags().String("since", "", "Filter lower bound timestamp (RFC3339)")
	transfersCmd.Flags().String("until", "", "Filter upper bound timestamp (RFC3339)")
	transfersCmd.Flags().String("sort-by", "created_at", "Sort field (created_at, amount)")
	transfersCmd.Flags().String("order", "desc", "Sort direction (asc, desc)")
	cmd.AddCommand(transfersCmd)

	return cmd
}

func txRecord(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	amount, _ := cmd.Flags().GetInt64("amount")
	currency, _ := cmd.Flags().GetString("currency")
	executionMode, _ := cmd.Flags().GetString("execution-mode")
	rail, _ := cmd.Flags().GetString("rail")
	walletID, _ := cmd.Flags().GetString("wallet-id")
	endpoint, _ := cmd.Flags().GetString("endpoint")

	executionMode = strings.ToLower(strings.TrimSpace(executionMode))
	if executionMode == "" {
		executionMode = "auto"
	}
	if executionMode != "auto" && executionMode != "pinned" {
		emitError("bob tx record", fmt.Errorf("execution-mode must be auto or pinned"))
		return nil
	}

	payload := map[string]any{
		"amount":         amount,
		"currency":       currency,
		"endpoint":       endpoint,
		"execution_mode": executionMode,
	}
	rail = strings.ToLower(strings.TrimSpace(rail))
	if rail != "" && rail != "auto" {
		if executionMode == "auto" {
			payload["execution_mode"] = "pinned"
		}
		payload["rail"] = rail
	}
	if walletID != "" {
		if payload["execution_mode"] == "auto" {
			payload["execution_mode"] = "pinned"
		}
		payload["wallet_id"] = walletID
	}
	if payload["execution_mode"] == "pinned" && rail == "auto" && walletID == "" {
		emitError("bob tx record", fmt.Errorf("pinned execution requires --rail or --wallet-id"))
		return nil
	}

	data, err := apiPost("/agents/"+agentID+"/transactions", payload)
	if err != nil {
		emitError("bob tx record", err)
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob tx record",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: fmt.Sprintf("bob spend list %s", agentID), Description: "View updated spend summary"},
			{Command: fmt.Sprintf("bob tx list %s", agentID), Description: "View all transactions"},
			{
				Command:     fmt.Sprintf("bob tx record %s --amount <amount>", agentID),
				Description: "Record another transaction",
				Params:      map[string]Param{"amount": {Required: true, Description: "Amount in smallest currency unit"}},
			},
		},
	})
	return nil
}

func txList(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	limit, _ := cmd.Flags().GetInt("limit")
	offset, _ := cmd.Flags().GetInt("offset")
	status, _ := cmd.Flags().GetString("status")
	direction, _ := cmd.Flags().GetString("direction")
	since, _ := cmd.Flags().GetString("since")
	until, _ := cmd.Flags().GetString("until")
	sortBy, _ := cmd.Flags().GetString("sort-by")
	order, _ := cmd.Flags().GetString("order")

	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", limit))
	params.Set("offset", fmt.Sprintf("%d", offset))
	if status != "" {
		params.Set("status", status)
	}
	if direction != "" {
		params.Set("direction", direction)
	}
	if since != "" {
		params.Set("since", since)
	}
	if until != "" {
		params.Set("until", until)
	}
	if sortBy != "" {
		params.Set("sort_by", sortBy)
	}
	if order != "" {
		params.Set("order", order)
	}

	data, err := apiGet(fmt.Sprintf("/agents/%s/transactions?%s", agentID, params.Encode()))
	if err != nil {
		emitError("bob tx list", err)
		return nil
	}

	var paged struct {
		Data      json.RawMessage `json:"data"`
		Total     int             `json:"total"`
		Limit     int             `json:"limit"`
		Offset    int             `json:"offset"`
		HasMore   bool            `json:"has_more"`
		Truncated bool            `json:"truncated"`
	}
	json.Unmarshal(data, &paged)

	nextActions := []NextAction{
		{Command: fmt.Sprintf("bob spend list %s", agentID), Description: "View spend summary"},
	}
	if paged.HasMore {
		nextOffset := paged.Offset + paged.Limit
		nextActions = append(nextActions, NextAction{
			Command:     fmt.Sprintf("bob tx list %s --limit %d --offset %d", agentID, paged.Limit, nextOffset),
			Description: fmt.Sprintf("Next page (%d-%d of %d)", nextOffset+1, min(nextOffset+paged.Limit, paged.Total), paged.Total),
		})
	}

	emit(Envelope{
		OK:      true,
		Command: "bob tx list",
		Data:    paged.Data,
		Pagination: &Pagination{
			Total:     paged.Total,
			Limit:     paged.Limit,
			Offset:    paged.Offset,
			HasMore:   paged.HasMore,
			Truncated: paged.Truncated,
		},
		NextActions: nextActions,
	})
	return nil
}

func txTransfer(cmd *cobra.Command, args []string) error {
	fromAgentID := args[0]
	toAgentID, _ := cmd.Flags().GetString("to-agent-id")
	amount, _ := cmd.Flags().GetInt64("amount")
	currency, _ := cmd.Flags().GetString("currency")
	fromWalletID, _ := cmd.Flags().GetString("from-wallet-id")
	toWalletID, _ := cmd.Flags().GetString("to-wallet-id")
	description, _ := cmd.Flags().GetString("description")

	if strings.TrimSpace(toAgentID) == "" {
		emitError("bob tx transfer", fmt.Errorf("--to-agent-id is required"))
		return nil
	}
	if amount <= 0 {
		emitError("bob tx transfer", fmt.Errorf("--amount must be positive"))
		return nil
	}

	payload := map[string]any{
		"to_agent_id": toAgentID,
		"amount":      amount,
		"currency":    currency,
	}
	if strings.TrimSpace(fromWalletID) != "" {
		payload["from_wallet_id"] = fromWalletID
	}
	if strings.TrimSpace(toWalletID) != "" {
		payload["to_wallet_id"] = toWalletID
	}
	if strings.TrimSpace(description) != "" {
		payload["description"] = description
	}

	data, err := apiPost("/agents/"+fromAgentID+"/transfers", payload)
	if err != nil {
		emitError("bob tx transfer", err)
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob tx transfer",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: fmt.Sprintf("bob tx transfers %s", fromAgentID), Description: "View source agent transfer history"},
			{Command: fmt.Sprintf("bob tx transfers %s", toAgentID), Description: "View destination agent transfer history"},
			{Command: fmt.Sprintf("bob tx list %s", fromAgentID), Description: "View source transaction ledger"},
		},
	})
	return nil
}

func txTransfers(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	limit, _ := cmd.Flags().GetInt("limit")
	offset, _ := cmd.Flags().GetInt("offset")
	status, _ := cmd.Flags().GetString("status")
	direction, _ := cmd.Flags().GetString("direction")
	since, _ := cmd.Flags().GetString("since")
	until, _ := cmd.Flags().GetString("until")
	sortBy, _ := cmd.Flags().GetString("sort-by")
	order, _ := cmd.Flags().GetString("order")

	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", limit))
	params.Set("offset", fmt.Sprintf("%d", offset))
	if status != "" {
		params.Set("status", status)
	}
	if direction != "" {
		params.Set("direction", direction)
	}
	if since != "" {
		params.Set("since", since)
	}
	if until != "" {
		params.Set("until", until)
	}
	if sortBy != "" {
		params.Set("sort_by", sortBy)
	}
	if order != "" {
		params.Set("order", order)
	}

	data, err := apiGet(fmt.Sprintf("/agents/%s/transfers?%s", agentID, params.Encode()))
	if err != nil {
		emitError("bob tx transfers", err)
		return nil
	}

	var paged struct {
		Data      json.RawMessage `json:"data"`
		Total     int             `json:"total"`
		Limit     int             `json:"limit"`
		Offset    int             `json:"offset"`
		HasMore   bool            `json:"has_more"`
		Truncated bool            `json:"truncated"`
	}
	json.Unmarshal(data, &paged)

	nextActions := []NextAction{
		{Command: fmt.Sprintf("bob tx list %s", agentID), Description: "View full transaction ledger"},
	}
	if paged.HasMore {
		nextOffset := paged.Offset + paged.Limit
		nextActions = append(nextActions, NextAction{
			Command:     fmt.Sprintf("bob tx transfers %s --limit %d --offset %d", agentID, paged.Limit, nextOffset),
			Description: fmt.Sprintf("Next page (%d-%d of %d)", nextOffset+1, min(nextOffset+paged.Limit, paged.Total), paged.Total),
		})
	}

	emit(Envelope{
		OK:      true,
		Command: "bob tx transfers",
		Data:    paged.Data,
		Pagination: &Pagination{
			Total:     paged.Total,
			Limit:     paged.Limit,
			Offset:    paged.Offset,
			HasMore:   paged.HasMore,
			Truncated: paged.Truncated,
		},
		NextActions: nextActions,
	})
	return nil
}

// --- Operator commands ---

