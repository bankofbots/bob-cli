package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func spendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "spend",
		Short: "Track and manage LLM spend for agents",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob spend",
				Data: map[string]any{
					"subcommands": []string{"track", "list", "summary", "budget", "sync"},
				},
				NextActions: []NextAction{
					{Command: "bob spend list", Description: "List recent LLM cost events"},
					{Command: "bob spend summary", Description: "Show spend analytics for the last 30 days"},
					{Command: "bob spend budget", Description: "View current budget configuration"},
				},
			})
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// track
	trackCmd := &cobra.Command{
		Use:   "track",
		Short: "Report an LLM cost event",
		RunE:  runSpendTrack,
	}
	trackCmd.Flags().String("agent-id", "", "Agent ID")
	trackCmd.Flags().String("provider", "", "LLM provider (e.g. openai, anthropic)")
	trackCmd.Flags().String("model", "", "Model name (e.g. gpt-4o, claude-sonnet-4-20250514)")
	trackCmd.Flags().Int64("tokens-in", 0, "Input/prompt tokens")
	trackCmd.Flags().Int64("tokens-out", 0, "Output/completion tokens")
	trackCmd.Flags().Float64("cost-usd", 0, "Cost in USD (e.g. 0.003)")
	trackCmd.Flags().String("session-id", "", "Optional session identifier")
	trackCmd.Flags().String("resource-url", "", "Optional resource URL (e.g. chat completion URL)")
	trackCmd.Flags().String("source", "agent_report", "Event source label")
	_ = trackCmd.MarkFlagRequired("provider")
	_ = trackCmd.MarkFlagRequired("model")
	_ = trackCmd.MarkFlagRequired("tokens-in")
	_ = trackCmd.MarkFlagRequired("tokens-out")
	_ = trackCmd.MarkFlagRequired("cost-usd")
	cmd.AddCommand(trackCmd)

	// list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List recent LLM cost events",
		RunE:  runSpendList,
	}
	listCmd.Flags().String("agent-id", "", "Agent ID")
	listCmd.Flags().Int("limit", 30, "Max results")
	listCmd.Flags().Int("offset", 0, "Offset")
	cmd.AddCommand(listCmd)

	// summary
	summaryCmd := &cobra.Command{
		Use:   "summary",
		Short: "Show spend analytics",
		RunE:  runSpendSummary,
	}
	summaryCmd.Flags().String("agent-id", "", "Agent ID")
	summaryCmd.Flags().String("since", "", "Start time in RFC3339 (default: 30 days ago)")
	cmd.AddCommand(summaryCmd)

	// budget
	budgetCmd := &cobra.Command{
		Use:   "budget",
		Short: "View or set spend budgets",
		RunE:  runSpendBudget,
	}
	budgetCmd.Flags().String("agent-id", "", "Agent ID")
	budgetCmd.Flags().Bool("set", false, "Create or update a budget")
	budgetCmd.Flags().String("window", "", "Budget window: daily, weekly, or monthly")
	budgetCmd.Flags().Float64("limit-usd", 0, "Budget limit in USD")
	budgetCmd.Flags().Int("alert-pct", 80, "Alert threshold percentage (0-100)")
	cmd.AddCommand(budgetCmd)

	// sync
	syncCmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync LLM usage from OpenClaw gateway",
		RunE:  runSpendSync,
	}
	syncCmd.Flags().String("agent-id", "", "Agent ID")
	syncCmd.Flags().Int("days", 1, "Number of days of usage to sync")
	cmd.AddCommand(syncCmd)

	return cmd
}

func runSpendTrack(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob spend track", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	provider, _ := cmd.Flags().GetString("provider")
	model, _ := cmd.Flags().GetString("model")
	tokensIn, _ := cmd.Flags().GetInt64("tokens-in")
	tokensOut, _ := cmd.Flags().GetInt64("tokens-out")
	costUSD, _ := cmd.Flags().GetFloat64("cost-usd")
	sessionID, _ := cmd.Flags().GetString("session-id")
	resourceURL, _ := cmd.Flags().GetString("resource-url")
	source, _ := cmd.Flags().GetString("source")

	if costUSD < 0 {
		emitError("bob spend track", fmt.Errorf("--cost-usd must not be negative"))
		return nil
	}
	if tokensIn < 0 || tokensOut < 0 {
		emitError("bob spend track", fmt.Errorf("--tokens-in and --tokens-out must not be negative"))
		return nil
	}

	costMicroUSD := int64(math.Round(costUSD * 1e6))

	event := map[string]any{
		"provider":      provider,
		"model":         model,
		"tokens_in":     tokensIn,
		"tokens_out":    tokensOut,
		"cost_micro_usd": costMicroUSD,
		"source":        source,
	}
	if sessionID != "" {
		event["session_id"] = sessionID
	}
	if resourceURL != "" {
		event["resource_url"] = resourceURL
	}

	resp, err := apiPostFn(
		fmt.Sprintf("/agents/%s/llm-costs", url.PathEscape(agentID)),
		map[string]any{"events": []any{event}},
	)
	if err != nil {
		emitError("bob spend track", err)
		return nil
	}
	var result json.RawMessage
	if err := json.Unmarshal(resp, &result); err != nil {
		emitError("bob spend track", fmt.Errorf("failed to parse response: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob spend track",
		Data: map[string]any{
			"agent_id":       agentID,
			"provider":       provider,
			"model":          model,
			"tokens_in":      tokensIn,
			"tokens_out":     tokensOut,
			"cost_usd":       costUSD,
			"cost_micro_usd": costMicroUSD,
			"result":         result,
		},
		NextActions: []NextAction{
			{Command: "bob spend list --agent-id " + agentID, Description: "List recent cost events"},
			{Command: "bob spend summary --agent-id " + agentID, Description: "Show spend analytics"},
		},
	})
	return nil
}

func runSpendList(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob spend list", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	limit, _ := cmd.Flags().GetInt("limit")
	offset, _ := cmd.Flags().GetInt("offset")

	resp, err := apiGetFn(fmt.Sprintf("/agents/%s/llm-costs?limit=%d&offset=%d",
		url.PathEscape(agentID), limit, offset))
	if err != nil {
		emitError("bob spend list", err)
		return nil
	}
	var events json.RawMessage
	if err := json.Unmarshal(resp, &events); err != nil {
		emitError("bob spend list", fmt.Errorf("failed to parse response: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob spend list",
		Data: map[string]any{
			"agent_id": agentID,
			"events":   events,
			"limit":    limit,
			"offset":   offset,
		},
		NextActions: []NextAction{
			{Command: "bob spend summary --agent-id " + agentID, Description: "Show spend analytics"},
			{Command: "bob spend list --agent-id " + agentID + " --offset " + strconv.Itoa(offset+limit), Description: "Next page"},
		},
	})
	return nil
}

func runSpendSummary(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob spend summary", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	since, _ := cmd.Flags().GetString("since")
	if since == "" {
		since = time.Now().UTC().AddDate(0, 0, -30).Format(time.RFC3339)
	}

	resp, err := apiGetFn(fmt.Sprintf("/agents/%s/llm-costs/summary?since=%s",
		url.PathEscape(agentID), url.QueryEscape(since)))
	if err != nil {
		emitError("bob spend summary", err)
		return nil
	}
	var summary json.RawMessage
	if err := json.Unmarshal(resp, &summary); err != nil {
		emitError("bob spend summary", fmt.Errorf("failed to parse response: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob spend summary",
		Data: map[string]any{
			"agent_id": agentID,
			"since":    since,
			"summary":  summary,
		},
		NextActions: []NextAction{
			{Command: "bob spend list --agent-id " + agentID, Description: "List individual cost events"},
			{Command: "bob spend budget --agent-id " + agentID, Description: "View budget configuration"},
		},
	})
	return nil
}

func runSpendBudget(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob spend budget", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	setMode, _ := cmd.Flags().GetBool("set")
	if setMode {
		return runSpendBudgetSet(cmd, agentID)
	}

	resp, err := apiGetFn(fmt.Sprintf("/agents/%s/llm-costs/budgets", url.PathEscape(agentID)))
	if err != nil {
		emitError("bob spend budget", err)
		return nil
	}
	var budgets json.RawMessage
	if err := json.Unmarshal(resp, &budgets); err != nil {
		emitError("bob spend budget", fmt.Errorf("failed to parse response: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob spend budget",
		Data: map[string]any{
			"agent_id": agentID,
			"budgets":  budgets,
		},
		NextActions: []NextAction{
			{Command: "bob spend budget --set --window daily --limit-usd 5.00 --agent-id " + agentID, Description: "Set a daily budget"},
			{Command: "bob spend summary --agent-id " + agentID, Description: "Show spend analytics"},
		},
	})
	return nil
}

func runSpendBudgetSet(cmd *cobra.Command, agentID string) error {
	window, _ := cmd.Flags().GetString("window")
	limitUSD, _ := cmd.Flags().GetFloat64("limit-usd")
	alertPct, _ := cmd.Flags().GetInt("alert-pct")

	if window == "" {
		emitError("bob spend budget", fmt.Errorf("--window is required when using --set (daily, weekly, or monthly)"))
		return nil
	}
	validWindows := map[string]bool{"daily": true, "weekly": true, "monthly": true}
	if !validWindows[window] {
		emitError("bob spend budget", fmt.Errorf("--window must be one of: daily, weekly, monthly"))
		return nil
	}
	if alertPct < 0 || alertPct > 100 {
		emitError("bob spend budget", fmt.Errorf("--alert-pct must be between 0 and 100"))
		return nil
	}
	if limitUSD <= 0 {
		emitError("bob spend budget", fmt.Errorf("--limit-usd must be greater than 0"))
		return nil
	}

	limitMicroUSD := int64(math.Round(limitUSD * 1e6))

	resp, err := apiPostFn(
		fmt.Sprintf("/agents/%s/llm-costs/budgets", url.PathEscape(agentID)),
		map[string]any{
			"window":              window,
			"limit_micro_usd":     limitMicroUSD,
			"alert_threshold_pct": alertPct,
		},
	)
	if err != nil {
		emitError("bob spend budget", err)
		return nil
	}
	var result json.RawMessage
	if err := json.Unmarshal(resp, &result); err != nil {
		emitError("bob spend budget", fmt.Errorf("failed to parse response: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob spend budget",
		Data: map[string]any{
			"agent_id":              agentID,
			"window":                window,
			"limit_usd":            limitUSD,
			"limit_micro_usd":      limitMicroUSD,
			"alert_threshold_pct":  alertPct,
			"result":               result,
		},
		NextActions: []NextAction{
			{Command: "bob spend budget --agent-id " + agentID, Description: "View updated budget configuration"},
			{Command: "bob spend summary --agent-id " + agentID, Description: "Show spend analytics"},
		},
	})
	return nil
}

func runSpendSync(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob spend sync", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	days, _ := cmd.Flags().GetInt("days")
	if days <= 0 {
		days = 1
	}

	// Load last sync time from local config
	cfg, err := loadCLIConfigFn()
	if err != nil {
		emitError("bob spend sync", fmt.Errorf("failed to load config: %w", err))
		return nil
	}

	// Shell out to openclaw usage-cost --json to get cost data.
	// The openclaw CLI handles WebSocket connection to the gateway internally.
	ocArgs := []string{"usage-cost", "--json", "--days", fmt.Sprintf("%d", days)}
	ocCmd := exec.Command("openclaw", ocArgs...)
	ocOutput, err := ocCmd.Output()
	if err != nil {
		emitError("bob spend sync", fmt.Errorf("openclaw usage-cost failed (is the gateway running?): %w", err))
		return nil
	}

	// Parse the OpenClaw usage-cost JSON output.
	// Structure: { totals: {...}, byModel: [...], byProvider: [...], sessions: [...] }
	var costSummary struct {
		Totals struct {
			Input      int64   `json:"input"`
			Output     int64   `json:"output"`
			CacheRead  int64   `json:"cacheRead"`
			CacheWrite int64   `json:"cacheWrite"`
			TotalCost  float64 `json:"totalCost"`
		} `json:"totals"`
		ByModel []struct {
			Model     string  `json:"model"`
			Provider  string  `json:"provider"`
			Input     int64   `json:"input"`
			Output    int64   `json:"output"`
			TotalCost float64 `json:"totalCost"`
		} `json:"byModel"`
	}
	if err := json.Unmarshal(ocOutput, &costSummary); err != nil {
		emitError("bob spend sync", fmt.Errorf("failed to parse openclaw output: %w", err))
		return nil
	}

	if len(costSummary.ByModel) == 0 {
		emit(Envelope{
			OK:      true,
			Command: "bob spend sync",
			Data: map[string]any{
				"agent_id": agentID,
				"synced":   0,
				"message":  "no usage data from openclaw gateway",
			},
		})
		return nil
	}

	// Transform per-model usage into LLM cost events.
	var events []any
	for _, m := range costSummary.ByModel {
		if m.TotalCost <= 0 {
			continue
		}
		// Derive provider from model name if not set
		provider := strings.ToLower(m.Provider)
		if provider == "" {
			if strings.Contains(strings.ToLower(m.Model), "claude") || strings.Contains(strings.ToLower(m.Model), "anthropic") {
				provider = "anthropic"
			} else if strings.Contains(strings.ToLower(m.Model), "gpt") || strings.Contains(strings.ToLower(m.Model), "openai") {
				provider = "openai"
			} else {
				provider = "unknown"
			}
		}
		costMicroUSD := int64(math.Round(m.TotalCost * 1e6))
		events = append(events, map[string]any{
			"provider":      provider,
			"model":         m.Model,
			"tokens_in":     m.Input,
			"tokens_out":    m.Output,
			"cost_usd":      m.TotalCost,
			"cost_micro_usd": costMicroUSD,
			"source":        "sync",
		})
	}

	if len(events) == 0 {
		emit(Envelope{
			OK:      true,
			Command: "bob spend sync",
			Data: map[string]any{
				"agent_id": agentID,
				"synced":   0,
				"message":  "no billable usage in openclaw data",
			},
		})
		return nil
	}

	_, err = apiPostFn(
		fmt.Sprintf("/agents/%s/llm-costs", url.PathEscape(agentID)),
		map[string]any{"events": events},
	)
	if err != nil {
		emitError("bob spend sync", err)
		return nil
	}

	syncTime := time.Now().UTC().Format(time.RFC3339)
	cfg.SpendSyncTimestamp = syncTime
	if saveErr := saveCLIConfig(cfg); saveErr != nil {
		emit(Envelope{
			OK:      true,
			Command: "bob spend sync",
			Data: map[string]any{
				"agent_id": agentID,
				"synced":   len(events),
				"warning":  "events synced but failed to save sync timestamp: " + saveErr.Error(),
			},
		})
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob spend sync",
		Data: map[string]any{
			"agent_id":       agentID,
			"synced":         len(events),
			"last_sync_time": syncTime,
			"days":           days,
		},
		NextActions: []NextAction{
			{Command: "bob spend list --agent-id " + agentID, Description: "List synced cost events"},
			{Command: "bob spend summary --agent-id " + agentID, Description: "Show spend analytics"},
		},
	})
	return nil
}
