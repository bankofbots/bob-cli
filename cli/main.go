package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const version = "0.1.0"

const defaultAPIBase = "http://localhost:8080/api/v1"

var apiBase = defaultAPIBase
var apiBaseSource = "default"
var defaultPlatform = "generic"
var httpClient = &http.Client{Timeout: 30 * time.Second}
var apiKey string
var configAPIKey string // loaded from config; used as flag default fallback
var identityRoleCache = "unknown"
var identityRoleSource = "default"

func init() {
	cfg, err := loadCLIConfig()
	if err == nil {
		if strings.TrimSpace(cfg.APIURL) != "" {
			apiBase = normalizeAPIBaseForEnv(cfg.APIURL)
			apiBaseSource = "config"
		}
		if validPlatform(cfg.Platform) {
			defaultPlatform = cfg.Platform
		}
		if strings.TrimSpace(cfg.APIKey) != "" {
			configAPIKey = strings.TrimSpace(cfg.APIKey)
		}
	}
	if v := strings.TrimSpace(os.Getenv("BOB_API_URL")); v != "" {
		apiBase = normalizeAPIBaseForEnv(v)
		apiBaseSource = "env"
	}
}

type cliConfig struct {
	APIURL   string `json:"api_url,omitempty"`
	Platform string `json:"platform,omitempty"`
	APIKey   string `json:"api_key,omitempty"`
	AgentID  string `json:"agent_id,omitempty"`
}

func validPlatform(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "generic", "openclaw", "claude":
		return true
	default:
		return false
	}
}

func cliConfigPath() string {
	if p := strings.TrimSpace(os.Getenv("BOB_CONFIG_FILE")); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ".bob-cli-config.json"
	}
	return filepath.Join(home, ".config", "bob", "config.json")
}

func fallbackCLIConfigPath() string {
	return ".bob-cli-config.json"
}

func activeCLIConfigPath() string {
	primary := cliConfigPath()
	if _, err := os.Stat(primary); err == nil {
		return primary
	}
	fallback := fallbackCLIConfigPath()
	if primary != fallback {
		if _, err := os.Stat(fallback); err == nil {
			return fallback
		}
	}
	return primary
}

func loadCLIConfig() (cliConfig, error) {
	candidatePaths := []string{cliConfigPath()}
	fallback := fallbackCLIConfigPath()
	if candidatePaths[0] != fallback {
		candidatePaths = append(candidatePaths, fallback)
	}
	for _, path := range candidatePaths {
		b, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if os.IsPermission(err) {
				continue
			}
			return cliConfig{}, err
		}
		var cfg cliConfig
		if err := json.Unmarshal(b, &cfg); err != nil {
			return cliConfig{}, err
		}
		return cfg, nil
	}
	return cliConfig{}, nil
}

func writeCLIConfig(path string, cfg cliConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	return os.WriteFile(path, payload, 0o600)
}

func saveCLIConfig(cfg cliConfig) error {
	primary := cliConfigPath()
	if err := writeCLIConfig(primary, cfg); err == nil {
		return nil
	}
	fallback := fallbackCLIConfigPath()
	if fallback != primary {
		return writeCLIConfig(fallback, cfg)
	}
	return writeCLIConfig(primary, cfg)
}

func persistCLIConfig(apiURL, platform string) error {
	cfg, err := loadCLIConfig()
	if err != nil {
		return err
	}
	if strings.TrimSpace(apiURL) != "" {
		cfg.APIURL = normalizeAPIBaseForEnv(apiURL)
	}
	if validPlatform(platform) {
		cfg.Platform = strings.ToLower(strings.TrimSpace(platform))
	}
	return saveCLIConfig(cfg)
}

func apiOriginFromBase(base string) string {
	normalized := normalizeAPIBaseForEnv(base)
	if strings.HasSuffix(normalized, "/api/v1") {
		return strings.TrimSuffix(normalized, "/api/v1")
	}
	return strings.TrimRight(normalized, "/")
}

func dashboardOriginFromAPIBase(base string) string {
	u, err := url.Parse(apiOriginFromBase(base))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	switch {
	case strings.HasPrefix(host, "api-"):
		// api-testnet.bobscore.ai → testnet.bobscore.ai (env-prefixed subdomain)
		host = strings.TrimPrefix(host, "api-")
	case host == "api.bobscore.ai":
		// api.bobscore.ai → bobscore.ai
		return u.Scheme + "://bobscore.ai"
	case strings.HasPrefix(host, "api."):
		host = "app." + strings.TrimPrefix(host, "api.")
	case host == "localhost" || host == "127.0.0.1":
		return u.Scheme + "://localhost:3000"
	}
	if host == "" {
		return ""
	}
	return u.Scheme + "://" + host
}

func extractAPIErrorMessage(err error) string {
	body := extractAPIErrorBody(err)
	if apiMsg, ok := body["error"].(string); ok && strings.TrimSpace(apiMsg) != "" {
		return strings.TrimSpace(apiMsg)
	}
	return strings.TrimSpace(err.Error())
}

func extractAPIErrorBody(err error) map[string]any {
	msg := strings.TrimSpace(err.Error())
	if idx := strings.Index(msg, "{"); idx >= 0 {
		var body map[string]any
		if unmarshalErr := json.Unmarshal([]byte(msg[idx:]), &body); unmarshalErr == nil {
			return body
		}
	}
	return map[string]any{}
}

func extractAPIErrorField(err error, field string) string {
	body := extractAPIErrorBody(err)
	value, _ := body[field].(string)
	return strings.TrimSpace(value)
}

func scopeNote(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "agent":
		return "AGENT scope: can record transactions, send payments, manage wallets, and view own policies. Cannot create agents, fund wallets, or access operator controls."
	case "operator":
		return "OPERATOR scope: can manage agents, fund wallets, configure policies, view treasury, and access all operator controls."
	default:
		return "scope unknown — run `bob auth me` to confirm your identity."
	}
}

func is403Error(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "api error (403)")
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
	OK          bool           `json:"ok"`
	Command     string         `json:"command"`
	Data        any            `json:"data"`
	NextActions []NextAction   `json:"next_actions"`
	Pagination  *Pagination    `json:"pagination,omitempty"`
	Context     map[string]any `json:"context,omitempty"`
}

type Pagination struct {
	Total     int  `json:"total"`
	Limit     int  `json:"limit"`
	Offset    int  `json:"offset"`
	HasMore   bool `json:"has_more"`
	Truncated bool `json:"truncated"`
}

func emit(env Envelope) {
	if env.Context == nil {
		env.Context = commandContext()
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(env)
}

func emitError(command string, err error) {
	if is403Error(err) {
		role := strings.TrimSpace(strings.ToLower(identityRoleCache))
		var roleNote string
		switch role {
		case "agent":
			roleNote = "you are authenticated with AGENT scope; this endpoint requires OPERATOR scope"
		case "operator":
			roleNote = "you have OPERATOR scope but lack permissions for this resource"
		default:
			roleNote = "unable to confirm scope; run `bob auth me` to verify your identity"
		}
		emitErrorWithActions(command, fmt.Errorf("forbidden (403): %s — %s", extractAPIErrorMessage(err), roleNote), []NextAction{
			{Command: "bob auth me", Description: "Verify current role and scope"},
			{Command: "export BOB_API_KEY=<operator-key>", Description: "Switch to an operator-scoped API key"},
		})
		return
	}
	emit(Envelope{
		OK:      false,
		Command: command,
		Data:    map[string]string{"error": err.Error()},
	})
}

func emitErrorWithActions(command string, err error, nextActions []NextAction) {
	emit(Envelope{
		OK:          false,
		Command:     command,
		Data:        map[string]string{"error": err.Error()},
		NextActions: nextActions,
	})
}

func roleHintFromAPIKey(raw string) (string, string) {
	key := strings.TrimSpace(raw)
	if key == "" {
		return "unauthenticated", "api_key_absent"
	}
	switch {
	case strings.HasPrefix(key, "bok_op_"):
		return "operator", "api_key_prefix"
	case strings.HasPrefix(key, "bok_"):
		return "agent_or_operator", "api_key_prefix"
	default:
		return "unknown", "api_key_format"
	}
}

func updateIdentityRoleCache(role, source string) {
	role = strings.TrimSpace(strings.ToLower(role))
	if role == "" {
		return
	}
	identityRoleCache = role
	if strings.TrimSpace(source) != "" {
		identityRoleSource = source
	}
}

func commandContext() map[string]any {
	role := strings.TrimSpace(identityRoleCache)
	roleSource := strings.TrimSpace(identityRoleSource)
	if role == "" || role == "unknown" {
		hintRole, hintSource := roleHintFromAPIKey(apiKey)
		role = hintRole
		roleSource = hintSource
	}

	return map[string]any{
		"api_url":        normalizeAPIBaseForEnv(apiBase),
		"api_url_source": apiBaseSource,
		"role":           role,
		"role_source":    roleSource,
	}
}

func resolveIdentityRoleForPreflight() (string, string, error) {
	role := strings.TrimSpace(strings.ToLower(identityRoleCache))
	if role == "agent" || role == "operator" {
		return role, strings.TrimSpace(identityRoleSource), nil
	}

	hintRole, hintSource := roleHintFromAPIKey(apiKey)
	if hintRole == "unauthenticated" {
		return hintRole, hintSource, nil
	}
	if hintRole == "operator" {
		updateIdentityRoleCache("operator", hintSource)
		return "operator", hintSource, nil
	}

	data, err := apiGet("/auth/me")
	if err != nil {
		return hintRole, hintSource, err
	}
	var identity map[string]any
	if err := json.Unmarshal(data, &identity); err != nil {
		return hintRole, hintSource, fmt.Errorf("failed to parse /auth/me response: %w", err)
	}
	roleVal, _ := identity["role"].(string)
	roleVal = strings.TrimSpace(strings.ToLower(roleVal))
	if roleVal != "agent" && roleVal != "operator" {
		if roleVal == "" {
			roleVal = hintRole
		}
	}
	updateIdentityRoleCache(roleVal, "auth_preflight")
	return roleVal, "auth_preflight", nil
}

func ensureOperatorScope(command string) bool {
	if strings.TrimSpace(command) == "" {
		command = "bob operator"
	}
	role, roleSource, err := resolveIdentityRoleForPreflight()
	nextActions := []NextAction{
		{Command: "bob config show", Description: "Show active API URL and local config source"},
		{Command: "bob auth me", Description: "Verify current role and identity"},
		{Command: "export BOB_API_KEY=<operator-key>", Description: "Switch to an operator-scoped API key"},
		{Command: command, Description: "Retry this command with operator scope"},
	}

	if err != nil {
		errMsg := extractAPIErrorMessage(err)
		emitErrorWithActions(command, fmt.Errorf("unable to verify operator scope with current credentials: %s", errMsg), nextActions)
		return false
	}

	switch role {
	case "operator":
		return true
	case "unauthenticated":
		emitErrorWithActions(command, fmt.Errorf("you are unauthenticated (no API key set). this command requires OPERATOR scope"), nextActions)
		return false
	case "agent":
		emitErrorWithActions(command, fmt.Errorf("you are authenticated as AGENT-scoped key (source=%s). this command requires OPERATOR scope", roleSource), nextActions)
		return false
	default:
		emitErrorWithActions(command, fmt.Errorf("unable to confirm operator scope (resolved role=%q from %s). this command requires OPERATOR scope", role, roleSource), nextActions)
		return false
	}
}

func operatorOnlyRunE(command string, fn func(*cobra.Command, []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(command) == "" {
			command = cmd.CommandPath()
		}
		if len(args) > 0 {
			command = strings.TrimSpace(command + " " + strings.Join(args, " "))
		}
		if !ensureOperatorScope(command) {
			return nil
		}
		return fn(cmd, args)
	}
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
	resp, err := httpClient.Do(req)
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
	resp, err := httpClient.Do(req)
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

func apiPatch(path string, payload any) (json.RawMessage, error) {
	b, _ := json.Marshal(payload)
	req, err := newRequest(http.MethodPatch, path, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	resp, err := httpClient.Do(req)
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

func apiPut(path string, payload any) (json.RawMessage, error) {
	b, _ := json.Marshal(payload)
	req, err := newRequest(http.MethodPut, path, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	resp, err := httpClient.Do(req)
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

func apiDelete(path string) (json.RawMessage, error) {
	req, err := newRequest(http.MethodDelete, path, nil)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	resp, err := httpClient.Do(req)
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

func newRequestNoAuth(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, apiBase+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func apiPostNoAuth(path string, payload any) (json.RawMessage, error) {
	b, _ := json.Marshal(payload)
	req, err := newRequestNoAuth(http.MethodPost, path, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	resp, err := httpClient.Do(req)
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

type systemRailCapability struct {
	Currency string `json:"currency"`
	Rail     string `json:"rail"`
	Provider string `json:"provider"`
	Enabled  bool   `json:"enabled"`
	Reason   string `json:"reason"`
}

type systemRailCapabilities struct {
	CustodyMode string `json:"custody_mode"`
	Unit        struct {
		Configured bool `json:"configured"`
	} `json:"unit"`
	BTC struct {
		Mode       string `json:"mode"`
		Configured bool   `json:"configured"`
		Enabled    bool   `json:"enabled"`
		Reason     string `json:"reason"`
	} `json:"btc"`
	Rails []systemRailCapability `json:"rails"`
}

func getSystemRailCapabilities() (*systemRailCapabilities, error) {
	data, err := apiGet("/system/rail-capabilities")
	if err != nil {
		return nil, err
	}
	var caps systemRailCapabilities
	if err := json.Unmarshal(data, &caps); err != nil {
		return nil, fmt.Errorf("failed to decode rail capabilities: %w", err)
	}
	return &caps, nil
}

func findRailCapability(caps *systemRailCapabilities, currency, rail string) *systemRailCapability {
	if caps == nil {
		return nil
	}
	currency = strings.ToUpper(strings.TrimSpace(currency))
	rail = strings.ToLower(strings.TrimSpace(rail))
	for i := range caps.Rails {
		rec := &caps.Rails[i]
		if strings.EqualFold(rec.Currency, currency) && strings.EqualFold(rec.Rail, rail) {
			return rec
		}
	}
	return nil
}

func enabledForDestination(caps *systemRailCapabilities, currency, destinationType string) []string {
	currency = strings.ToUpper(strings.TrimSpace(currency))
	destinationType = strings.ToLower(strings.TrimSpace(destinationType))
	var candidates []string
	switch destinationType {
	case "raw":
		candidates = []string{"lightning", "onchain"}
	case "bank_counterparty":
		candidates = []string{"ach", "wire"}
	case "unit_account":
		candidates = []string{"book"}
	case "bob_address":
		if currency == "BTC" {
			candidates = []string{"lightning", "onchain"}
		} else {
			candidates = []string{"book", "ach", "wire"}
		}
	default:
		return nil
	}
	enabled := make([]string, 0, len(candidates))
	for _, rail := range candidates {
		rec := findRailCapability(caps, currency, rail)
		if rec == nil || rec.Enabled {
			enabled = append(enabled, rail)
		}
	}
	return enabled
}

func ensureRailsAvailable(caps *systemRailCapabilities, currency, destinationType, pinnedRail string) error {
	if caps == nil {
		return nil
	}
	currency = strings.ToUpper(strings.TrimSpace(currency))
	destinationType = strings.ToLower(strings.TrimSpace(destinationType))
	pinnedRail = strings.ToLower(strings.TrimSpace(pinnedRail))

	if pinnedRail != "" && pinnedRail != "auto" {
		rec := findRailCapability(caps, currency, pinnedRail)
		if rec != nil && !rec.Enabled {
			reason := strings.TrimSpace(rec.Reason)
			if reason == "" {
				reason = "disabled in current backend environment"
			}
			return fmt.Errorf("pinned rail %s unavailable for %s: %s", pinnedRail, currency, reason)
		}
		return nil
	}

	enabled := enabledForDestination(caps, currency, destinationType)
	if len(enabled) > 0 {
		return nil
	}

	var candidates []string
	switch destinationType {
	case "raw":
		candidates = []string{"lightning", "onchain"}
	case "bank_counterparty":
		candidates = []string{"ach", "wire"}
	case "unit_account":
		candidates = []string{"book"}
	case "bob_address":
		if currency == "BTC" {
			candidates = []string{"lightning", "onchain"}
		} else {
			candidates = []string{"book", "ach", "wire"}
		}
	}
	reasons := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		rec := findRailCapability(caps, currency, candidate)
		if rec == nil {
			continue
		}
		if strings.TrimSpace(rec.Reason) != "" {
			reasons = append(reasons, fmt.Sprintf("%s: %s", candidate, rec.Reason))
		}
	}
	if len(reasons) == 0 {
		return fmt.Errorf("no backend rails available for %s %s destination", currency, destinationType)
	}
	return fmt.Errorf("no backend rails available for %s %s destination (%s)", currency, destinationType, strings.Join(reasons, " | "))
}

var creditTierMultipliers = map[string]float64{
	"trusted":  1.5,
	"growing":  1.2,
	"building": 1.0,
	"watch":    0.6,
}


func fetchOperatorCreditContext(agentID string) (map[string]any, error) {
	path := "/operators/me/credit?days=30"
	if strings.TrimSpace(agentID) != "" {
		path += "&agent_id=" + url.QueryEscape(strings.TrimSpace(agentID))
	}
	data, err := apiGet(path)
	if err != nil {
		return nil, err
	}
	var summary map[string]any
	if err := json.Unmarshal(data, &summary); err != nil {
		return nil, fmt.Errorf("failed to parse operator credit summary: %w", err)
	}
	tier := func(raw any) string {
		counts, ok := raw.(map[string]any)
		if !ok {
			return "building"
		}
		for _, t := range []string{"trusted", "growing", "building"} {
			if v, ok2 := counts[t]; ok2 {
				if n, ok3 := v.(float64); ok3 && n > 0 {
					return t
				}
			}
		}
		return "building"
	}(summary["tier_counts"])
	multiplier := creditTierMultipliers[tier]
	if multiplier == 0 {
		multiplier = 1.0
	}
	return map[string]any{
		"available":            true,
		"tier":                 tier,
		"multiplier":           multiplier,
		"average_score":        summary["average_score"],
		"events_30d":           summary["events_30d"],
		"last_credit_event_at": summary["last_credit_event_at"],
	}, nil
}

func creditContextOrUnavailable(agentID string) map[string]any {
	ctx, err := fetchOperatorCreditContext(agentID)
	if err == nil && ctx != nil {
		return ctx
	}
	return map[string]any{
		"available": false,
		"reason":    "operator credit context unavailable for current API key",
	}
}

func toInt64(raw any) int64 {
	switch n := raw.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	case float32:
		return int64(n)
	default:
		return 0
	}
}

func toFloat64(raw any) float64 {
	switch n := raw.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		return 0
	}
}

func toString(raw any) string {
	if s, ok := raw.(string); ok {
		return s
	}
	return ""
}

func humanQuoteRejectionReason(reason string) string {
	normalized := strings.ToLower(strings.TrimSpace(reason))
	switch normalized {
	case "wallet_not_ready":
		return "rail not ready"
	case "insufficient_wallet_balance":
		return "insufficient wallet balance"
	case "fee_above_max":
		return "estimated fee above max"
	case "settlement_after_deadline":
		return "settlement ETA misses deadline"
	case "":
		return "unknown"
	default:
		return normalized
	}
}

func buildQuoteRejectionSummary(result map[string]any) map[string]any {
	rows, ok := result["quotes"].([]any)
	if !ok {
		return map[string]any{}
	}
	total := 0
	rejected := 0
	candidates := 0
	rails := map[string]int{}
	rejectedByReason := map[string]int{}
	topCandidates := make([]map[string]any, 0, 3)
	selectedQuoteID := strings.TrimSpace(toString(result["selected_quote_id"]))
	var selected map[string]any
	if intent, ok := result["intent"].(map[string]any); ok {
		if selectedQuoteID == "" {
			selectedQuoteID = strings.TrimSpace(toString(intent["selected_quote_id"]))
		}
	}
	for _, row := range rows {
		q, ok := row.(map[string]any)
		if !ok {
			continue
		}
		total++
		status := strings.ToLower(strings.TrimSpace(toString(q["status"])))
		rail := strings.ToLower(strings.TrimSpace(toString(q["rail"])))
		if rail != "" {
			rails[rail]++
		}
		if status == "rejected" {
			rejected++
			reason := humanQuoteRejectionReason(toString(q["rejection_reason"]))
			rejectedByReason[reason]++
		} else {
			candidates++
			if len(topCandidates) < 3 {
				candidate := map[string]any{
					"id":                    strings.TrimSpace(toString(q["id"])),
					"rail":                  rail,
					"status":                status,
					"composite_score":       toFloat64(q["composite_score"]),
					"estimated_fee":         toInt64(q["estimated_fee"]),
					"settlement_seconds":    toInt64(q["estimated_settlement_seconds"]),
					"estimate_source":       strings.TrimSpace(toString(q["estimate_source"])),
					"priority_applied":      strings.TrimSpace(toString(q["priority_applied"])),
					"reliability_score":     0.0,
					"headroom_ratio":        0.0,
					"observed_success_rate": -1.0,
				}
				if explanation := strings.TrimSpace(toString(q["explanation"])); explanation != "" {
					var payload map[string]any
					if err := json.Unmarshal([]byte(explanation), &payload); err == nil {
						if scoreComponents, ok := payload["score_components"].(map[string]any); ok {
							candidate["reliability_score"] = toFloat64(scoreComponents["reliability_score"])
							candidate["headroom_ratio"] = toFloat64(scoreComponents["headroom_ratio"])
							if observed, ok := scoreComponents["observed_success_rate"]; ok {
								candidate["observed_success_rate"] = toFloat64(observed)
							}
						}
					}
				}
				topCandidates = append(topCandidates, candidate)
			}
		}
		if selected == nil && selectedQuoteID != "" && strings.TrimSpace(toString(q["id"])) == selectedQuoteID {
			selected = q
		}
	}
	if selected == nil {
		for _, row := range rows {
			q, ok := row.(map[string]any)
			if !ok {
				continue
			}
			if strings.ToLower(strings.TrimSpace(toString(q["status"]))) != "rejected" {
				selected = q
				break
			}
		}
	}
	summary := map[string]any{
		"total_quotes":          total,
		"candidate_quotes":      candidates,
		"rejected_quotes":       rejected,
		"rails_seen":            rails,
		"rejected_by_reason":    rejectedByReason,
		"selected_quote_id":     selectedQuoteID,
		"selected_quote_rail":   "",
		"selected_quote_status": "",
		"top_candidates":        topCandidates,
	}
	if selected != nil {
		summary["selected_quote_id"] = strings.TrimSpace(toString(selected["id"]))
		summary["selected_quote_rail"] = strings.TrimSpace(toString(selected["rail"]))
		summary["selected_quote_status"] = strings.TrimSpace(toString(selected["status"]))
		summary["selected_quote_fee"] = toInt64(selected["estimated_fee"])
		summary["selected_quote_settlement_seconds"] = toInt64(selected["estimated_settlement_seconds"])
	}
	return summary
}

func normalizeDestinationType(raw string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "" {
		return "", nil
	}
	switch normalized {
	case "raw", "bank_counterparty", "unit_account", "bob_address":
		return normalized, nil
	default:
		return "", fmt.Errorf("destination-type must be raw, bank_counterparty, unit_account, or bob_address")
	}
}

func validateDestinationCurrencyAndRail(currency, destinationType, rail string) error {
	normalizedCurrency := strings.ToUpper(strings.TrimSpace(currency))
	normalizedDestination := strings.ToLower(strings.TrimSpace(destinationType))
	normalizedRail := strings.ToLower(strings.TrimSpace(rail))

	switch normalizedDestination {
	case "raw":
		if normalizedCurrency != "BTC" {
			return fmt.Errorf("raw destinations currently support BTC only")
		}
		if normalizedRail != "" && normalizedRail != "auto" && normalizedRail != "lightning" && normalizedRail != "onchain" {
			return fmt.Errorf("raw destinations require lightning or onchain when pinning rail")
		}
	case "bank_counterparty":
		if normalizedCurrency != "USD" {
			return fmt.Errorf("bank_counterparty destinations currently support USD only")
		}
		if normalizedRail != "" && normalizedRail != "auto" && normalizedRail != "ach" && normalizedRail != "wire" {
			return fmt.Errorf("bank_counterparty destinations require ach or wire when pinning rail")
		}
	case "unit_account":
		if normalizedCurrency != "USD" {
			return fmt.Errorf("unit_account destinations currently support USD only")
		}
		if normalizedRail != "" && normalizedRail != "auto" && normalizedRail != "book" {
			return fmt.Errorf("unit_account destinations require book when pinning rail")
		}
	case "bob_address":
		switch normalizedCurrency {
		case "BTC":
			if normalizedRail != "" && normalizedRail != "auto" && normalizedRail != "lightning" && normalizedRail != "onchain" {
				return fmt.Errorf("bob_address with BTC requires lightning or onchain when pinning rail")
			}
		case "USD":
			if normalizedRail != "" && normalizedRail != "auto" && normalizedRail != "book" && normalizedRail != "ach" && normalizedRail != "wire" {
				return fmt.Errorf("bob_address with USD requires book, ach, or wire when pinning rail")
			}
		default:
			return fmt.Errorf("currency must be BTC or USD")
		}
	default:
		return fmt.Errorf("destination-type must be raw, bank_counterparty, unit_account, or bob_address")
	}
	return nil
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
		Description: "Bank of Bots CLI v" + version + " — economic infrastructure for autonomous agents",
		Children: []CommandInfo{
			{
				Name:        "init",
				Description: "Initialize local env vars for an agent session (supports setup token + claim-code exchange)",
				Usage:       "bob init [--token <setup-token> | --code <claim-code> | --agent-id <id> --api-key <key>] [--platform <generic|openclaw|claude>] [--api-url <url>]",
				Flags: []FlagInfo{
					{Name: "token", Type: "string", Description: "One-time setup token (`bos_...`)"},
					{Name: "code", Type: "string", Description: "One-time claim code (`BOB-XXXX-XXXX`)"},
					{Name: "agent-id", Type: "string", Description: "Agent ID (required if not using --token)"},
					{Name: "api-key", Type: "string", Description: "Agent API key (required if not using --token)"},
					{Name: "platform", Type: "string", Default: "generic", Description: "Output style hint (generic, openclaw, claude)"},
					{Name: "api-url", Type: "string", Description: "API base URL (accepts host or /api/v1 URL)"},
				},
				Children: []CommandInfo{
					{
						Name:        "switch-platform",
						Description: "Switch local platform preference without re-running setup token exchange",
						Usage:       "bob init switch-platform --platform <generic|openclaw|claude>",
						Flags: []FlagInfo{
							{Name: "platform", Type: "string", Required: true, Description: "Platform preference"},
						},
					},
				},
			},
			{
				Name:        "doctor",
				Description: "Show active CLI config and API/auth health checks",
				Usage:       "bob doctor",
			},
			{
				Name:        "auth",
				Description: "Authentication and identity",
				Children: []CommandInfo{
					{
						Name:        "me",
						Description: "Show current authenticated identity and role",
						Usage:       "bob auth me",
					},
					{
						Name:        "login",
						Description: "Authenticate interactively and store credentials",
						Usage:       "bob auth login [--email <email>] [--api-url <url>]",
						Flags: []FlagInfo{
							{Name: "email", Type: "string", Description: "Account email address"},
							{Name: "api-url", Type: "string", Description: "API base URL override"},
						},
					},
				},
			},
			{
				Name:        "config",
				Description: "Show or update CLI configuration",
				Children: []CommandInfo{
					{Name: "show", Description: "Print current CLI configuration", Usage: "bob config show"},
					{Name: "set", Description: "Update a single config value (api-url, platform)", Usage: "bob config set <key> <value>"},
				},
			},
			{
				Name:        "agent",
				Description: "Manage agents",
				Children: []CommandInfo{
					{
						Name:        "create",
						Description: "Create a new agent",
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
						Name:        "credit",
						Description: "Show agent credit score, tier, and effective policy limits",
						Usage:       "bob agent credit <agent-id>",
					},
					{
						Name:        "credit-events",
						Description: "List recent credit events for an agent",
						Usage:       "bob agent credit-events <agent-id> [--limit <n>] [--offset <n>]",
						Flags: []FlagInfo{
							{Name: "limit", Type: "integer", Default: "50", Description: "Max results to return"},
							{Name: "offset", Type: "integer", Default: "0", Description: "Number of results to skip"},
						},
					},
					{
						Name:        "credit-import",
						Description: "Import a historical BTC payment proof to build credit reputation",
						Usage:       "bob agent credit-import <agent-id> [--txid <txid> | --payment-hash <hash> | --proof-type <type> --proof-ref <ref>] --amount <sats>",
					},
					{
						Name:        "credit-imports",
						Description: "List historical BTC proof imports used for credit",
						Usage:       "bob agent credit-imports <agent-id> [--limit <n>] [--offset <n>]",
					},
				},
			},
			intentCommandInfo(),
			{
				Name:        "score",
				Description: "BOB Score — agent reputation and trust signals",
				Children: []CommandInfo{
					{Name: "me", Description: "View your agent's BOB Score and tier", Usage: "bob score me"},
					{Name: "composition", Description: "Breakdown of score components", Usage: "bob score composition <agent-id>"},
					{Name: "leaderboard", Description: "Top-ranked agents by BOB Score", Usage: "bob score leaderboard [--limit <n>]"},
					{Name: "signals", Description: "List trust signals contributing to score", Usage: "bob score signals <agent-id>"},
				},
			},
			{
				Name:        "binding",
				Description: "Bind Lightning/EVM node ownership to an agent",
				Children: []CommandInfo{
					{
						Name:        "lightning-challenge",
						Description: "Create a Lightning node ownership challenge",
						Usage:       "bob binding lightning-challenge <agent-id> [--wallet-id <id>]",
						Flags: []FlagInfo{
							{Name: "wallet-id", Type: "string", Description: "Optional wallet id to bind"},
						},
					},
					{
						Name:        "lightning-verify",
						Description: "Verify Lightning node ownership challenge with a node signature",
						Usage:       "bob binding lightning-verify <agent-id> --challenge-id <id> --signature <sig>",
						Flags: []FlagInfo{
							{Name: "challenge-id", Type: "string", Required: true, Description: "Ownership challenge id"},
							{Name: "signature", Type: "string", Required: true, Description: "Node signature over challenge.message"},
						},
					},
				},
			},
			{
				Name:        "webhook",
				Description: "Manage agent webhook subscribers",
				Children: []CommandInfo{
					{
						Name:        "create",
						Description: "Create an agent webhook subscriber",
						Usage:       "bob webhook create <agent-id> --url <url> [--events <event,...>]",
						Flags: []FlagInfo{
							{Name: "url", Type: "string", Required: true, Description: "Webhook URL"},
							{Name: "events", Type: "strings", Description: "Event filters (empty = all events)"},
						},
					},
					{Name: "list", Description: "List agent webhook subscribers", Usage: "bob webhook list <agent-id>"},
					{Name: "get", Description: "Get an agent webhook subscriber", Usage: "bob webhook get <agent-id> <webhook-id>"},
					{
						Name:        "update",
						Description: "Update an agent webhook subscriber",
						Usage:       "bob webhook update <agent-id> <webhook-id> [--url <url>] [--events <event,...>] [--active <true|false>]",
					},
					{Name: "delete", Description: "Delete an agent webhook subscriber", Usage: "bob webhook delete <agent-id> <webhook-id>"},
				},
			},
			{
				Name:        "inbox",
				Description: "Agent message inbox",
				Children: []CommandInfo{
					{
						Name:        "list",
						Description: "List inbox messages for an agent",
						Usage:       "bob inbox list <agent-id> [--limit <n>] [--offset <n>]",
					},
					{
						Name:        "ack",
						Description: "Acknowledge (mark read) an inbox message",
						Usage:       "bob inbox ack <agent-id> <message-id>",
					},
					{
						Name:        "events",
						Description: "List inbox event stream for an agent",
						Usage:       "bob inbox events <agent-id> [--limit <n>]",
					},
				},
			},
			{
				Name:        "api-key",
				Description: "Manage operator API keys",
				Children: []CommandInfo{
					{
						Name:        "list",
						Description: "List operator API keys",
						Usage:       "bob api-key list [--include-revoked] [--limit <n>]",
					},
					{
						Name:        "create",
						Description: "Create a new operator API key",
						Usage:       "bob api-key create [--name <name>] [--scope <scope>]",
					},
					{
						Name:        "revoke",
						Description: "Revoke an operator API key",
						Usage:       "bob api-key revoke <key-id>",
					},
				},
			},
		},
	}
}

func intentCommandInfo() CommandInfo {
	return CommandInfo{
		Name:        "intent",
		Description: "Quote and execute payment intents",
		Children: []CommandInfo{
			{
				Name:        "quote",
				Description: "Generate route quotes for a payment intent",
				Usage:       "bob intent quote <agent-id> --amount <n> [--currency <BTC|USD|USDC>] [--raw-destination <invoice|address>] [--destination-type <raw|bank_counterparty|unit_account|bob_address>] [--destination-ref <ref>]",
				Flags: []FlagInfo{
					{Name: "amount", Type: "integer", Required: true, Description: "Amount in smallest currency unit"},
					{Name: "currency", Type: "string", Default: "BTC", Description: "Currency code (BTC, USD, USDC)"},
					{Name: "raw-destination", Type: "string", Description: "BTC destination shortcut (Lightning invoice/LNURL/BTC address)"},
					{Name: "destination-type", Type: "string", Description: "raw, bank_counterparty, unit_account, or bob_address"},
					{Name: "destination-ref", Type: "string", Description: "Destination reference (invoice/address/account/counterparty id)"},
					{Name: "priority", Type: "string", Default: "balanced", Description: "Routing priority (cheapest, fastest, balanced)"},
					{Name: "max-fee", Type: "integer", Default: "0", Description: "Maximum acceptable fee"},
					{Name: "latest-settlement-by", Type: "string", Description: "Deadline for settlement (RFC3339)"},
					{Name: "execution-mode", Type: "string", Default: "auto", Description: "Execution mode (auto, pinned)"},
					{Name: "rail", Type: "string", Description: "Pin to a specific rail"},
					{Name: "wallet-id", Type: "string", Description: "Pin to a specific wallet"},
				},
			},
			{
				Name:        "execute",
				Description: "Execute a quoted payment intent",
				Usage:       "bob intent execute <agent-id> <intent-id> [--quote-id <id>] [--description <text>]",
				Flags: []FlagInfo{
					{Name: "quote-id", Type: "string", Description: "Specific quote to execute (best if omitted)"},
					{Name: "description", Type: "string", Description: "Payment description"},
				},
			},
			{
				Name:        "get",
				Description: "Get a payment intent with route quotes",
				Usage:       "bob intent get <agent-id> <intent-id>",
			},
			{
				Name:        "submit-proof",
				Description: "Submit non-custodial proof for a BTC payment intent",
				Usage:       "bob intent submit-proof <agent-id> <intent-id> [--proof-type <btc_onchain_tx|btc_lightning_payment_hash|btc_lightning_preimage>] [--proof-ref <value>] [--txid <txid>] [--payment-hash <hash>] [--preimage <hex>] --ownership-challenge-id <id> --ownership-signature <sig>",
				Flags: []FlagInfo{
					{Name: "proof-type", Type: "string", Description: "Proof type (btc_onchain_tx, btc_lightning_payment_hash, btc_lightning_preimage)"},
					{Name: "proof-ref", Type: "string", Description: "Proof reference value (txid or payment hash)"},
					{Name: "txid", Type: "string", Description: "Shortcut for --proof-type btc_onchain_tx"},
					{Name: "payment-hash", Type: "string", Description: "Shortcut for --proof-type btc_lightning_payment_hash"},
					{Name: "preimage", Type: "string", Description: "Shortcut for --proof-type btc_lightning_preimage"},
					{Name: "ownership-challenge-id", Type: "string", Description: "Ownership challenge id (required)"},
					{Name: "ownership-signature", Type: "string", Description: "Node signature over challenge message (required)"},
				},
			},
			{
				Name:        "proofs",
				Description: "List submitted proofs for a payment intent",
				Usage:       "bob intent proofs <agent-id> <intent-id>",
			},
			{
				Name:        "list",
				Description: "List payment intents for an agent",
				Usage:       "bob intent list <agent-id> [--limit <n>] [--offset <n>]",
				Flags: []FlagInfo{
					{Name: "limit", Type: "integer", Default: "30", Description: "Max results to return"},
					{Name: "offset", Type: "integer", Default: "0", Description: "Number of results to skip"},
				},
			},
		},
	}
}

func addressCommandInfo() CommandInfo { return CommandInfo{} }
func marketplaceCommandInfo() CommandInfo { return CommandInfo{} }


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
		Short: "Bank of Bots CLI v" + version,
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob",
				Data:    commandTree(),
				NextActions: []NextAction{
					{Command: "bob auth me", Description: "Check your identity and role"},
					{Command: "bob agent list", Description: "List all agents"},
					{Command: "bob agent create --name <name>", Description: "Create a new agent", Params: map[string]Param{
						"name": {Required: true, Description: "Agent name"},
					}},
					{Command: "bob intent quote <agent-id> --amount <n> --currency <BTC|USD|USDC> --destination-type <raw|bank_counterparty|unit_account|bob_address> --destination-ref <ref>", Description: "Quote a payment intent"},
					{Command: "bob score me", Description: "View your BOB Score"},
				},
			})
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Persistent flag: --api-key. Precedence: flag > BOB_API_KEY env > config file.
	apiKeyDefault := os.Getenv("BOB_API_KEY")
	if apiKeyDefault == "" {
		apiKeyDefault = configAPIKey
	}
	root.PersistentFlags().StringVar(&apiKey, "api-key", apiKeyDefault, "API key for authentication (or set BOB_API_KEY)")

	root.AddCommand(initCmd())
	root.AddCommand(doctorCmd())
	root.AddCommand(configCmd())
	root.AddCommand(authCmd())
	root.AddCommand(agentCmd())
	root.AddCommand(intentCmd())
	root.AddCommand(scoreCmd())
	root.AddCommand(bindingCmd())
	root.AddCommand(webhookCmd())
	root.AddCommand(inboxCmd())
	root.AddCommand(apiKeyCmd())

	if err := root.Execute(); err != nil {
		emitError("bob", err)
		os.Exit(1)
	}
}

func normalizeAPIBaseForEnv(raw string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(raw), "/")
	if trimmed == "" {
		trimmed = strings.TrimRight(defaultAPIBase, "/")
	}
	if strings.HasSuffix(trimmed, "/api/v1") {
		return trimmed
	}
	return trimmed + "/api/v1"
}

func initCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize local env vars for an agent session",
		RunE:  initSession,
	}
	cmd.Flags().String("token", "", "One-time setup token (`bos_...`) to exchange for API key")
	cmd.Flags().String("code", "", "One-time claim code (`BOB-XXXX-XXXX`) to redeem for API key")
	cmd.Flags().String("agent-id", "", "Agent ID (required if --token is not provided)")
	cmd.Flags().String("api-key", "", "Agent API key (required if --token is not provided)")
	cmd.Flags().String("platform", defaultPlatform, "Output style hint (generic, openclaw, claude)")
	cmd.Flags().String("api-url", apiBase, "API base URL (host root or /api/v1)")
	cmd.Flags().Bool("show-api-key", false, "Force-print plaintext API key even when not attached to a terminal")
	cmd.AddCommand(initSwitchPlatformCmd())
	return cmd
}

func initSwitchPlatformCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "switch-platform",
		Short: "Switch local platform preference without exchanging a new setup token",
		RunE:  initSwitchPlatform,
	}
	cmd.Flags().String("platform", "", "Platform preference (generic, openclaw, claude)")
	cmd.MarkFlagRequired("platform")
	return cmd
}

func initSwitchPlatform(cmd *cobra.Command, args []string) error {
	platform, _ := cmd.Flags().GetString("platform")
	platform = strings.ToLower(strings.TrimSpace(platform))
	if !validPlatform(platform) {
		emitError("bob init switch-platform", fmt.Errorf("--platform must be one of: generic, openclaw, claude"))
		return nil
	}
	if err := persistCLIConfig(apiBase, platform); err != nil {
		emitError("bob init switch-platform", fmt.Errorf("failed to persist local config: %w", err))
		return nil
	}
	emit(Envelope{
		OK:      true,
		Command: "bob init switch-platform",
		Data: map[string]any{
			"platform":       platform,
			"active_api_url": normalizeAPIBaseForEnv(apiBase),
			"config_file":    activeCLIConfigPath(),
		},
		NextActions: []NextAction{
			{Command: "bob doctor", Description: "Verify CLI config and connectivity"},
			{Command: "bob auth me", Description: "Verify current identity with active API URL"},
		},
	})
	return nil
}

func initSession(cmd *cobra.Command, args []string) error {
	token, _ := cmd.Flags().GetString("token")
	claimCode, _ := cmd.Flags().GetString("code")
	agentID, _ := cmd.Flags().GetString("agent-id")
	initAPIKey, _ := cmd.Flags().GetString("api-key")
	platform, _ := cmd.Flags().GetString("platform")
	apiURLFlag, _ := cmd.Flags().GetString("api-url")
	showAPIKey, _ := cmd.Flags().GetBool("show-api-key")

	platform = strings.ToLower(strings.TrimSpace(platform))
	if platform == "" {
		platform = "generic"
	}
	if !validPlatform(platform) {
		emitError("bob init", fmt.Errorf("--platform must be one of: generic, openclaw, claude"))
		return nil
	}

	normalizedAPIBase := normalizeAPIBaseForEnv(apiURLFlag)
	token = strings.TrimSpace(token)
	claimCode = strings.TrimSpace(claimCode)

	if token != "" && claimCode != "" {
		emitError("bob init", fmt.Errorf("use either --token or --code, not both"))
		return nil
	}

	if claimCode != "" && (strings.TrimSpace(agentID) != "" || strings.TrimSpace(initAPIKey) != "") {
		emitError("bob init", fmt.Errorf("--code cannot be combined with --agent-id or --api-key"))
		return nil
	}

	if token != "" {
		// Setup-token exchange does not use bearer auth.
		previousBase := apiBase
		apiBase = normalizedAPIBase
		defer func() { apiBase = previousBase }()

		resp, err := apiPostNoAuth("/setup-token/exchange", map[string]any{"token": token})
		if err != nil {
			parsedErr := extractAPIErrorMessage(err)
			if strings.Contains(strings.ToLower(parsedErr), "setup token already consumed or expired") {
				dashboardOrigin := dashboardOriginFromAPIBase(normalizedAPIBase)
				nextActions := []NextAction{
					{
						Command:     fmt.Sprintf("bob init --token <new-setup-token> --platform %s --api-url %s", platform, normalizedAPIBase),
						Description: "Retry init with a newly generated setup token",
					},
				}
				if dashboardOrigin != "" {
					nextActions = append([]NextAction{
						{
							Command:     dashboardOrigin + "/",
							Description: "Generate a new setup token from the dashboard",
						},
					}, nextActions...)
				}
				emitErrorWithActions("bob init", fmt.Errorf("setup token already consumed or expired"), nextActions)
				return nil
			}
			emitError("bob init", err)
			return nil
		}
		var exchange struct {
			APIKey  string `json:"api_key"`
			AgentID string `json:"agent_id"`
		}
		if err := json.Unmarshal(resp, &exchange); err != nil {
			return fmt.Errorf("failed to parse setup token exchange response: %w", err)
		}
		if strings.TrimSpace(exchange.APIKey) == "" || strings.TrimSpace(exchange.AgentID) == "" {
			emitError("bob init", fmt.Errorf("setup token exchange did not return api_key and agent_id"))
			return nil
		}
		initAPIKey = exchange.APIKey
		agentID = exchange.AgentID
	}

	if claimCode != "" {
		previousBase := apiBase
		apiBase = normalizedAPIBase
		defer func() { apiBase = previousBase }()

		resp, err := apiPostNoAuth("/claim-code/redeem", map[string]any{
			"code":     claimCode,
			"platform": platform,
		})
		if err != nil {
			parsedErr := extractAPIErrorMessage(err)
			if strings.Contains(strings.ToLower(parsedErr), "invalid or expired claim code") {
				emitErrorWithActions("bob init", fmt.Errorf("claim code is invalid or expired"), []NextAction{
					{Command: "Generate a fresh claim code from the dashboard", Description: "Claim codes are single-use and expire quickly"},
				})
				return nil
			}
			emitError("bob init", err)
			return nil
		}

		var redeemResp struct {
			APIKey  string `json:"api_key"`
			AgentID string `json:"agent_id"`
			APIURL  string `json:"api_url"`
			Data    struct {
				APIKey  string `json:"api_key"`
				AgentID string `json:"agent_id"`
				APIURL  string `json:"api_url"`
			} `json:"data"`
		}
		if err := json.Unmarshal(resp, &redeemResp); err != nil {
			return fmt.Errorf("failed to parse claim-code redeem response: %w", err)
		}

		resolvedAPIKey := strings.TrimSpace(redeemResp.APIKey)
		if resolvedAPIKey == "" {
			resolvedAPIKey = strings.TrimSpace(redeemResp.Data.APIKey)
		}
		resolvedAgentID := strings.TrimSpace(redeemResp.AgentID)
		if resolvedAgentID == "" {
			resolvedAgentID = strings.TrimSpace(redeemResp.Data.AgentID)
		}
		resolvedAPIURL := strings.TrimSpace(redeemResp.APIURL)
		if resolvedAPIURL == "" {
			resolvedAPIURL = strings.TrimSpace(redeemResp.Data.APIURL)
		}
		if resolvedAPIURL != "" {
			normalizedAPIBase = normalizeAPIBaseForEnv(resolvedAPIURL)
		}

		if resolvedAPIKey == "" || resolvedAgentID == "" {
			emitError("bob init", fmt.Errorf("claim code redeem did not return api_key and agent_id"))
			return nil
		}
		initAPIKey = resolvedAPIKey
		agentID = resolvedAgentID
	}

	agentID = strings.TrimSpace(agentID)
	initAPIKey = strings.TrimSpace(initAPIKey)
	if agentID == "" || initAPIKey == "" {
		emitError("bob init", fmt.Errorf("provide --token, --code, OR both --agent-id and --api-key"))
		return nil
	}

	shouldPrintAPIKey := showAPIKey || term.IsTerminal(int(os.Stderr.Fd()))
	if shouldPrintAPIKey {
		fmt.Fprintf(os.Stderr, "\n  *** Save this API key now — it will not be shown again ***\n  %s\n\n", initAPIKey)
	} else {
		fmt.Fprintln(os.Stderr, "\n  API key generated. Plaintext display is hidden by default to reduce accidental log leakage.")
		fmt.Fprintln(os.Stderr, "  Re-run in an interactive terminal or pass --show-api-key to reveal it once.")
		fmt.Fprintln(os.Stderr)
	}

	apiKeyEnvValue := "<paste_api_key_here>"
	if shouldPrintAPIKey {
		apiKeyEnvValue = initAPIKey
	}
	envCommands := []string{
		fmt.Sprintf("export BOB_API_KEY=%s", apiKeyEnvValue),
		fmt.Sprintf("export BOB_AGENT_ID=%s", agentID),
		fmt.Sprintf("export BOB_API_URL=%s", normalizedAPIBase),
	}

	warnings := []string{}
	switch platform {
	case "claude":
		warnings = append(warnings, "initialized as platform=claude. If you intended OpenClaw, run: bob init switch-platform --platform openclaw")
	case "openclaw":
		warnings = append(warnings, "initialized as platform=openclaw. If you intended Claude, run: bob init switch-platform --platform claude")
	}
	if err := persistCLIConfig(normalizedAPIBase, platform); err != nil {
		warnings = append(warnings, "failed to persist local CLI config: "+err.Error())
	}
	// Persist api_key and agent_id to primary config path only (never local fallback — gitignore risk).
	// This is the bootstrap credential store: each ./bob subprocess reads config fresh, so credentials
	// survive across OpenClaw tool invocations without requiring BOB_API_KEY to be set in the environment.
	if primaryPath := cliConfigPath(); primaryPath != fallbackCLIConfigPath() {
		if credCfg, loadErr := loadCLIConfig(); loadErr == nil {
			credCfg.APIKey = initAPIKey
			credCfg.AgentID = agentID
			if writeErr := writeCLIConfig(primaryPath, credCfg); writeErr != nil {
				warnings = append(warnings, "failed to persist credentials to config: "+writeErr.Error())
			}
		}
	}

	switchPlatformTarget := "openclaw"
	if platform == "openclaw" {
		switchPlatformTarget = "claude"
	}
	nextActions := []NextAction{
		{Command: fmt.Sprintf("bob init switch-platform --platform %s", switchPlatformTarget), Description: "Switch platform hint without regenerating credentials"},
		{Command: "bob auth me", Description: "Verify your key and role"},
		{Command: "bob doctor", Description: "Show active API URL + auth/config status"},
		{Command: fmt.Sprintf("bob agent get %s", agentID), Description: "Inspect agent details"},
		{Command: fmt.Sprintf("bob intent quote %s --amount 1000 --currency BTC --destination-type lightning --destination-ref <node-pubkey>", agentID), Description: "Get a payment quote"},
	}

	if platform == "claude" || platform == "openclaw" {
		nextActions = append([]NextAction{
			{Command: "mkdir -p .claude/skills/bankofbots", Description: "Ensure local Claude/OpenClaw skill directory exists"},
			{Command: "curl -fsSL \"$DASHBOARD_ORIGIN/api/skill/bankofbots?download=1\" -o .claude/skills/bankofbots/SKILL.md", Description: "Download the Bank of Bots skill file"},
		}, nextActions...)
	}

	emit(Envelope{
		OK:      true,
		Command: "bob init",
		Data: map[string]any{
			"platform":         platform,
			"initialized_as":   fmt.Sprintf("platform=%s", platform),
			"agent_id":         agentID,
			"api_key_redacted": redactKey(initAPIKey),
			"api_key_hidden":   !shouldPrintAPIKey,
			"api_url":          normalizedAPIBase,
			"config_file":      activeCLIConfigPath(),
			"warnings":         warnings,
			"env":              envCommands,
		},
		NextActions: nextActions,
	})
	return nil
}

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Show active CLI configuration and API/auth health checks",
		RunE:  runDoctor,
	}
}

func runDoctor(cmd *cobra.Command, args []string) error {
	activeAPIURL := normalizeAPIBaseForEnv(apiBase)
	activeOrigin := apiOriginFromBase(activeAPIURL)

	result := map[string]any{
		"api_url":         activeAPIURL,
		"api_url_source":  apiBaseSource,
		"api_key_present": strings.TrimSpace(apiKey) != "",
		"config_file":     activeCLIConfigPath(),
	}

	warnings := []string{}
	if apiBaseSource == "default" {
		warnings = append(warnings, "using default API URL (localhost). Set BOB_API_URL or run bob init --api-url <url> to target testnet/prod.")
	}

	healthURL := activeOrigin + "/health"
	healthReq, _ := http.NewRequest(http.MethodGet, healthURL, nil)
	healthResp, healthErr := httpClient.Do(healthReq)
	healthResult := map[string]any{
		"url": healthURL,
		"ok":  false,
	}
	if healthErr != nil {
		healthResult["error"] = healthErr.Error()
		warnings = append(warnings, "health endpoint unreachable; check API URL and network access")
	} else {
		defer healthResp.Body.Close()
		healthBody, _ := io.ReadAll(healthResp.Body)
		healthResult["status_code"] = healthResp.StatusCode
		if healthResp.StatusCode >= 200 && healthResp.StatusCode < 300 {
			healthResult["ok"] = true
			var parsed map[string]any
			if err := json.Unmarshal(healthBody, &parsed); err == nil {
				healthResult["response"] = parsed
			} else {
				healthResult["response"] = string(healthBody)
			}
		} else {
			healthResult["error"] = strings.TrimSpace(string(healthBody))
		}
	}
	result["health"] = healthResult

	authResult := map[string]any{"checked": false}
	if strings.TrimSpace(apiKey) != "" {
		authData, err := apiGet("/auth/me")
		authResult["checked"] = true
		if err != nil {
			authResult["ok"] = false
			authResult["error"] = extractAPIErrorMessage(err)
			warnings = append(warnings, "auth check failed with current API key")
		} else {
			authResult["ok"] = true
			var identity map[string]any
			if err := json.Unmarshal(authData, &identity); err == nil {
				authResult["identity"] = identity
				if role, ok := identity["role"].(string); ok {
					updateIdentityRoleCache(role, "doctor_auth_check")
				}
			} else {
				authResult["identity_raw"] = string(authData)
			}
		}
	} else {
		authResult["ok"] = false
		authResult["error"] = "BOB_API_KEY is not set"
		warnings = append(warnings, "set BOB_API_KEY (or use --api-key) to run authenticated checks")
	}
	result["auth"] = authResult
	result["warnings"] = warnings

	nextActions := []NextAction{
		{Command: "bob auth me", Description: "Verify authenticated identity"},
	}
	if strings.TrimSpace(apiKey) == "" {
		nextActions = append(nextActions, NextAction{Command: "export BOB_API_KEY=<your-key>", Description: "Set API key for authenticated commands"})
	}

	emit(Envelope{
		OK:          true,
		Command:     "bob doctor",
		Data:        result,
		NextActions: nextActions,
	})
	return nil
}

// --- Auth commands ---

func authCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authentication and identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob auth",
				Data:    childCommandInfo(commandTree(), "auth"),
				NextActions: []NextAction{
					{Command: "bob auth me", Description: "Check your identity and role"},
					{Command: "bob auth login", Description: "Authenticate interactively"},
				},
			})
			return nil
		},
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "me",
		Short: "Show current authenticated identity and role",
		RunE:  authMe,
	})

	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate interactively and store credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob auth login",
				Data: map[string]string{
					"status": "not_implemented",
					"hint":   "Use bob init --token <setup-token> or bob init --code <claim-code> to authenticate.",
				},
				NextActions: []NextAction{
					{Command: "bob init --token <setup-token>", Description: "Exchange a setup token for an API key"},
					{Command: "bob init --code <claim-code>", Description: "Redeem a claim code for credentials"},
					{Command: "bob auth me", Description: "Verify current credentials"},
				},
			})
			return nil
		},
	}
	loginCmd.Flags().String("email", "", "Account email address")
	loginCmd.Flags().String("api-url", "", "API base URL override")
	cmd.AddCommand(loginCmd)

	return cmd
}

func authMe(cmd *cobra.Command, args []string) error {
	data, err := apiGet("/auth/me")
	if err != nil {
		emitError("bob auth me", err)
		return nil
	}

	var identity map[string]any
	json.Unmarshal(data, &identity)
	role, _ := identity["role"].(string)
	updateIdentityRoleCache(role, "auth_me")

	// Enrich with scope clarity so agents and tools always know what they can do.
	identity["scope"] = role
	identity["scope_note"] = scopeNote(role)
	keyHint, _ := roleHintFromAPIKey(apiKey)
	identity["key_redacted"] = redactKey(apiKey)
	identity["key_role_hint"] = keyHint

	var nextActions []NextAction
	if role == "agent" {
		agentData, _ := identity["agent"].(map[string]any)
		agentID, _ := agentData["id"].(string)
		if agentID != "" {
			nextActions = []NextAction{
				{Command: fmt.Sprintf("bob agent get %s", agentID), Description: "View your agent details"},
				{Command: "bob score me", Description: "View your BOB Score and tier"},
				{Command: fmt.Sprintf("bob intent list %s", agentID), Description: "View payment intents"},
				{Command: fmt.Sprintf("bob agent credit %s", agentID), Description: "View credit score and tier"},
			}
		} else {
			nextActions = []NextAction{
				{Command: "bob agent list", Description: "List agents"},
			}
		}
	} else {
		nextActions = []NextAction{
			{Command: "bob agent list", Description: "List all agents"},
			{Command: "bob agent create --name <name>", Description: "Create a new agent"},
			{Command: "bob api-key list", Description: "List operator API keys"},
		}
	}

	emit(Envelope{
		OK:          true,
		Command:     "bob auth me",
		Data:        identity,
		NextActions: nextActions,
	})
	return nil
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
				Data:    childCommandInfo(commandTree(), "agent"),
				NextActions: []NextAction{
					{Command: "bob agent list", Description: "List all agents"},
					{Command: "bob agent create --name <name>", Description: "Create a new agent"},
				},
			})
			return nil
		},
	}

	// create
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new agent",
		RunE:  operatorOnlyRunE("bob agent create", agentConnect),
	}
	createCmd.Flags().String("name", "", "Agent name (required)")
	createCmd.Flags().String("operator", "", "Operator ID")
	createCmd.Flags().Int64("budget", 0, "Budget in smallest currency unit")
	createCmd.Flags().String("currency", "BTC", "Primary currency (BTC, USD, USDC)")
	createCmd.Flags().StringSlice("currencies", nil, "Currencies to provision (overrides --currency)")
	createCmd.Flags().Bool("auto-approve", false, "Immediately approve the agent")
	createCmd.MarkFlagRequired("name")
	cmd.AddCommand(createCmd)

	// list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List agents",
		RunE:  operatorOnlyRunE("bob agent list", agentList),
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

	// approve
	approveCmd := &cobra.Command{
		Use:   "approve [agent-id]",
		Short: "Approve and optionally seed an agent",
		Args:  cobra.ExactArgs(1),
		RunE:  operatorOnlyRunE("bob agent approve", agentApprove),
	}
	approveCmd.Flags().Int64("seed-amount", 0, "Optional starter balance amount")
	approveCmd.Flags().String("seed-currency", "", "Currency for auto-selected seed wallet")
	approveCmd.Flags().String("seed-wallet-id", "", "Explicit seed wallet override")
	cmd.AddCommand(approveCmd)

	// credit
	cmd.AddCommand(&cobra.Command{
		Use:   "credit [agent-id]",
		Short: "Show agent credit score, tier, and effective policy limits",
		Args:  cobra.ExactArgs(1),
		RunE:  agentCredit,
	})

	// credit-events
	creditEventsCmd := &cobra.Command{
		Use:   "credit-events [agent-id]",
		Short: "List recent credit events for an agent",
		Args:  cobra.ExactArgs(1),
		RunE:  agentCreditEvents,
	}
	creditEventsCmd.Flags().Int("limit", 50, "Max results")
	creditEventsCmd.Flags().Int("offset", 0, "Results to skip")
	cmd.AddCommand(creditEventsCmd)

	// credit-import
	creditImportCmd := &cobra.Command{
		Use:   "credit-import [agent-id]",
		Short: "Import a historical BTC payment proof to build credit reputation",
		Args:  cobra.ExactArgs(1),
		RunE:  agentCreditImport,
	}
	creditImportCmd.Flags().String("proof-type", "", "Proof type (btc_onchain_tx, btc_lightning_payment_hash, btc_lightning_preimage)")
	creditImportCmd.Flags().String("proof-ref", "", "Proof reference value (txid or payment hash)")
	creditImportCmd.Flags().String("txid", "", "Shortcut for --proof-type btc_onchain_tx")
	creditImportCmd.Flags().String("payment-hash", "", "Shortcut for --proof-type btc_lightning_payment_hash")
	creditImportCmd.Flags().String("preimage", "", "Shortcut for --proof-type btc_lightning_preimage")
	creditImportCmd.Flags().String("invoice", "", "Optional BOLT11 invoice to include in proof metadata")
	creditImportCmd.Flags().String("rail", "", "Rail (lightning or onchain)")
	creditImportCmd.Flags().String("currency", "BTC", "Currency (must be BTC)")
	creditImportCmd.Flags().Int64("amount", 0, "Amount in sats (required)")
	creditImportCmd.Flags().String("direction", "outbound", "Direction (outbound or inbound)")
	creditImportCmd.Flags().String("occurred-at", "", "Original payment timestamp (RFC3339)")
	creditImportCmd.Flags().String("counterparty-ref", "", "Optional counterparty descriptor")
	creditImportCmd.MarkFlagRequired("amount")
	cmd.AddCommand(creditImportCmd)

	// credit-imports
	creditImportsCmd := &cobra.Command{
		Use:   "credit-imports [agent-id]",
		Short: "List historical BTC proof imports used for credit",
		Args:  cobra.ExactArgs(1),
		RunE:  agentCreditImports,
	}
	creditImportsCmd.Flags().Int("limit", 50, "Max results")
	creditImportsCmd.Flags().Int("offset", 0, "Results to skip")
	cmd.AddCommand(creditImportsCmd)

	return cmd
}

func agentCredit(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	data, err := apiGet("/agents/" + url.PathEscape(agentID) + "/credit")
	if err != nil {
		emitError("bob agent credit", err)
		return nil
	}
	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("failed to parse credit response: %w", err)
	}
	emit(Envelope{
		OK:      true,
		Command: "bob agent credit",
		Data:    resp,
		NextActions: []NextAction{
			{Command: fmt.Sprintf("bob agent credit-events %s", agentID), Description: "View credit event history"},
		},
	})
	return nil
}


func agentCreditEvents(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	limit, _ := cmd.Flags().GetInt("limit")
	offset, _ := cmd.Flags().GetInt("offset")
	path := fmt.Sprintf("/agents/%s/credit/events?limit=%d&offset=%d", url.PathEscape(agentID), limit, offset)
	data, err := apiGet(path)
	if err != nil {
		emitError("bob agent credit-events", err)
		return nil
	}
	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("failed to parse credit events response: %w", err)
	}
	emit(Envelope{
		OK:      true,
		Command: "bob agent credit-events",
		Data:    resp,
	})
	return nil
}

func agentCreditImport(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	proofType, _ := cmd.Flags().GetString("proof-type")
	proofRef, _ := cmd.Flags().GetString("proof-ref")
	txid, _ := cmd.Flags().GetString("txid")
	paymentHash, _ := cmd.Flags().GetString("payment-hash")
	preimage, _ := cmd.Flags().GetString("preimage")
	invoice, _ := cmd.Flags().GetString("invoice")
	rail, _ := cmd.Flags().GetString("rail")
	currency, _ := cmd.Flags().GetString("currency")
	amount, _ := cmd.Flags().GetInt64("amount")
	direction, _ := cmd.Flags().GetString("direction")
	occurredAt, _ := cmd.Flags().GetString("occurred-at")
	counterpartyRef, _ := cmd.Flags().GetString("counterparty-ref")

	proofType = strings.ToLower(strings.TrimSpace(proofType))
	proofRef = strings.TrimSpace(proofRef)
	txid = strings.ToLower(strings.TrimSpace(txid))
	paymentHash = strings.ToLower(strings.TrimSpace(paymentHash))
	preimage = strings.TrimSpace(preimage)
	invoice = strings.TrimSpace(invoice)

	shortcuts := 0
	if txid != "" {
		shortcuts++
	}
	if paymentHash != "" {
		shortcuts++
	}
	if preimage != "" {
		shortcuts++
	}
	if shortcuts > 1 {
		emitError("bob agent credit-import", fmt.Errorf("set one shortcut: --txid, --payment-hash, or --preimage"))
		return nil
	}
	if txid != "" {
		if proofType != "" || proofRef != "" {
			emitError("bob agent credit-import", fmt.Errorf("use either shortcut flags or --proof-type/--proof-ref"))
			return nil
		}
		proofType = "btc_onchain_tx"
		proofRef = txid
	}
	if paymentHash != "" {
		if proofType != "" || proofRef != "" {
			emitError("bob agent credit-import", fmt.Errorf("use either shortcut flags or --proof-type/--proof-ref"))
			return nil
		}
		proofType = "btc_lightning_payment_hash"
		proofRef = paymentHash
	}
	if preimage != "" {
		if proofType != "" || proofRef != "" {
			emitError("bob agent credit-import", fmt.Errorf("use either shortcut flags or --proof-type/--proof-ref"))
			return nil
		}
		proofType = "btc_lightning_preimage"
		// proof_ref is the payment hash; user must also pass --proof-ref
	}
	if proofType == "" || (proofRef == "" && proofType != "btc_lightning_preimage") {
		emitError("bob agent credit-import", fmt.Errorf("proof is required: use --txid, --payment-hash, --preimage, or --proof-type + --proof-ref"))
		return nil
	}
	if proofType != "btc_onchain_tx" && proofType != "btc_lightning_payment_hash" && proofType != "btc_lightning_preimage" {
		emitError("bob agent credit-import", fmt.Errorf("proof-type must be btc_onchain_tx, btc_lightning_payment_hash, or btc_lightning_preimage"))
		return nil
	}
	rail = strings.ToLower(strings.TrimSpace(rail))
	if rail == "" {
		if proofType == "btc_onchain_tx" {
			rail = "onchain"
		} else {
			rail = "lightning"
		}
	}
	if rail != "onchain" && rail != "lightning" {
		emitError("bob agent credit-import", fmt.Errorf("rail must be lightning or onchain"))
		return nil
	}
	currency = strings.ToUpper(strings.TrimSpace(currency))
	if currency == "" {
		currency = "BTC"
	}
	if currency != "BTC" {
		emitError("bob agent credit-import", fmt.Errorf("currency must be BTC"))
		return nil
	}
	if amount <= 0 {
		emitError("bob agent credit-import", fmt.Errorf("amount must be greater than 0"))
		return nil
	}
	direction = strings.ToLower(strings.TrimSpace(direction))
	if direction == "" {
		direction = "outbound"
	}
	if direction != "outbound" && direction != "inbound" {
		emitError("bob agent credit-import", fmt.Errorf("direction must be outbound or inbound"))
		return nil
	}

	payload := map[string]any{
		"proof_type": proofType,
		"proof_ref":  proofRef,
		"rail":       rail,
		"currency":   currency,
		"amount":     amount,
		"direction":  direction,
	}
	if strings.TrimSpace(occurredAt) != "" {
		if _, err := time.Parse(time.RFC3339, strings.TrimSpace(occurredAt)); err != nil {
			emitError("bob agent credit-import", fmt.Errorf("--occurred-at must be RFC3339"))
			return nil
		}
		payload["occurred_at"] = strings.TrimSpace(occurredAt)
	}
	if strings.TrimSpace(counterpartyRef) != "" {
		payload["counterparty_ref"] = strings.TrimSpace(counterpartyRef)
	}
	if preimage != "" || invoice != "" {
		meta := map[string]any{}
		if preimage != "" {
			meta["preimage"] = preimage
		}
		if invoice != "" {
			meta["invoice"] = invoice
		}
		payload["metadata"] = meta
	}

	data, err := apiPost("/agents/"+url.PathEscape(agentID)+"/credit/imports/payment-proofs", payload)
	if err != nil {
		emitErrorWithActions("bob agent credit-import", err, []NextAction{
			{Command: fmt.Sprintf("bob agent credit-imports %s", agentID), Description: "List imported proofs"},
			{Command: fmt.Sprintf("bob agent credit-events %s", agentID), Description: "Inspect credit event timeline"},
		})
		return nil
	}
	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("failed to parse credit import response: %w", err)
	}
	creditData, _ := resp["credit"].(map[string]any)
	creditAwarded, _ := creditData["awarded"].(bool)
	creditReason, _ := creditData["reason"].(string)
	nextActions := []NextAction{
		{Command: fmt.Sprintf("bob agent credit-imports %s", agentID), Description: "List imported proofs"},
		{Command: fmt.Sprintf("bob agent credit-events %s", agentID), Description: "Check if credit increased"},
		{Command: fmt.Sprintf("bob agent credit %s", agentID), Description: "View updated score/tier"},
	}
	if !creditAwarded {
		switch creditReason {
		case "self_counterparty_blocked":
			nextActions = append(nextActions, NextAction{
				Command:     fmt.Sprintf("bob agent credit-import %s --proof-type <type> --proof-ref <ref> --rail <onchain|lightning> --currency BTC --amount <sats> --direction outbound --counterparty-ref <external-counterparty>", agentID),
				Description: "Re-import using a non-self counterparty reference",
			})
		case "amount_below_credit_floor":
			nextActions = append(nextActions, NextAction{
				Command:     fmt.Sprintf("bob agent credit-import %s --proof-type <type> --proof-ref <ref> --rail <onchain|lightning> --currency BTC --amount <at-least-1000-sats>", agentID),
				Description: "Re-import with an amount above the BTC credit floor",
			})
		}
	}
	emit(Envelope{
		OK:          true,
		Command:     "bob agent credit-import",
		Data:        resp,
		NextActions: nextActions,
	})
	return nil
}

func agentCreditImports(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	limit, _ := cmd.Flags().GetInt("limit")
	offset, _ := cmd.Flags().GetInt("offset")
	path := fmt.Sprintf("/agents/%s/credit/imports/payment-proofs?limit=%d&offset=%d", url.PathEscape(agentID), limit, offset)
	data, err := apiGet(path)
	if err != nil {
		emitError("bob agent credit-imports", err)
		return nil
	}
	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("failed to parse credit imports response: %w", err)
	}
	emit(Envelope{
		OK:      true,
		Command: "bob agent credit-imports",
		Data:    resp,
	})
	return nil
}


func agentWebhookCreate(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	urlFlag, _ := cmd.Flags().GetString("url")
	events, _ := cmd.Flags().GetStringSlice("events")
	data, err := apiPost("/agents/"+url.PathEscape(agentID)+"/webhooks", map[string]any{
		"url":    strings.TrimSpace(urlFlag),
		"events": events,
	})
	if err != nil {
		emitError("bob webhook create", err)
		return nil
	}
	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("failed to parse webhook response: %w", err)
	}
	emit(Envelope{OK: true, Command: "bob webhook create", Data: resp})
	return nil
}

func agentWebhookList(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	data, err := apiGet("/agents/" + url.PathEscape(agentID) + "/webhooks")
	if err != nil {
		emitError("bob webhook list", err)
		return nil
	}
	var resp any
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("failed to parse webhook list response: %w", err)
	}
	emit(Envelope{OK: true, Command: "bob webhook list", Data: resp})
	return nil
}

func agentWebhookGet(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	webhookID := args[1]
	data, err := apiGet("/agents/" + url.PathEscape(agentID) + "/webhooks/" + url.PathEscape(webhookID))
	if err != nil {
		emitError("bob webhook get", err)
		return nil
	}
	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("failed to parse webhook response: %w", err)
	}
	emit(Envelope{OK: true, Command: "bob webhook get", Data: resp})
	return nil
}

func agentWebhookUpdate(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	webhookID := args[1]
	urlFlag, _ := cmd.Flags().GetString("url")
	events, _ := cmd.Flags().GetStringSlice("events")
	active, _ := cmd.Flags().GetString("active")

	body := map[string]any{}
	if cmd.Flags().Changed("url") {
		body["url"] = strings.TrimSpace(urlFlag)
	}
	if cmd.Flags().Changed("events") {
		body["events"] = events
	}
	if cmd.Flags().Changed("active") {
		parsed, err := strconv.ParseBool(strings.TrimSpace(active))
		if err != nil {
			emitError("bob webhook update", fmt.Errorf("--active must be true or false"))
			return nil
		}
		body["active"] = parsed
	}
	if len(body) == 0 {
		emitError("bob webhook update", fmt.Errorf("provide at least one field to update"))
		return nil
	}

	data, err := apiPatch("/agents/"+url.PathEscape(agentID)+"/webhooks/"+url.PathEscape(webhookID), body)
	if err != nil {
		emitError("bob webhook update", err)
		return nil
	}
	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("failed to parse webhook response: %w", err)
	}
	emit(Envelope{OK: true, Command: "bob webhook update", Data: resp})
	return nil
}

func agentWebhookDelete(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	webhookID := args[1]
	data, err := apiDelete("/agents/" + url.PathEscape(agentID) + "/webhooks/" + url.PathEscape(webhookID))
	if err != nil {
		emitError("bob webhook delete", err)
		return nil
	}
	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("failed to parse webhook delete response: %w", err)
	}
	emit(Envelope{OK: true, Command: "bob webhook delete", Data: resp})
	return nil
}

func agentConnect(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	operator, _ := cmd.Flags().GetString("operator")
	budget, _ := cmd.Flags().GetInt64("budget")
	autoApprove, _ := cmd.Flags().GetBool("auto-approve")
	publicProfile, _ := cmd.Flags().GetBool("public-profile")
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
		"name":           name,
		"operator_id":    operator,
		"budget":         budget,
		"currency":       primaryCurrency,
		"currencies":     currencies,
		"auto_approve":   autoApprove,
		"public_profile": publicProfile,
	})
	if err != nil {
		emitErrorWithActions("bob agent connect", err, []NextAction{
			{Command: "bob auth me", Description: "Check your identity and role"},
			{Command: "bob operator kyc status", Description: "Check KYC verification status"},
		})
		return nil
	}

	// Extract agent ID and API key for next_actions
	var agent map[string]any
	json.Unmarshal(data, &agent)
	agentID, _ := agent["id"].(string)
	agentAPIKey, _ := agent["api_key"].(string)
	apiKeyPending, _ := agent["api_key_pending"].(bool)

	nextActions := []NextAction{
		{Command: fmt.Sprintf("bob agent get %s", agentID), Description: "View this agent's details"},
	}
	if agentAPIKey != "" {
		fmt.Fprintf(os.Stderr, "\n  *** Save this API key now — it will not be shown again ***\n  %s\n\n", agentAPIKey)
		nextActions = append([]NextAction{
			{Command: fmt.Sprintf("export BOB_API_KEY=%s", redactKey(agentAPIKey)), Description: "Set API key in your environment (redacted — use full key from above)"},
			{Command: fmt.Sprintf("bob agent credit %s", agentID), Description: "Check credit score and tier"},
		}, nextActions...)
	} else if apiKeyPending {
		nextActions = append([]NextAction{
			{Command: fmt.Sprintf("bob agent approve %s --seed-amount 10000", agentID), Description: "Approve the agent and seed starter balance"},
		}, nextActions...)
	}

	emit(Envelope{
		OK:          true,
		Command:     "bob agent create",
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
		emitErrorWithActions("bob agent get", err, []NextAction{
			{Command: "bob agent list", Description: "List all agents"},
			{Command: "bob auth me", Description: "Check your identity and role"},
		})
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob agent get",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: fmt.Sprintf("bob agent credit %s", id), Description: "View credit score and tier"},
			{Command: fmt.Sprintf("bob intent list %s", id), Description: "View payment intents"},
			{Command: "bob score me", Description: "View BOB Score"},
			{Command: fmt.Sprintf("bob webhook list %s", id), Description: "View webhook subscribers"},
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
		{Command: fmt.Sprintf("bob agent credit %s", agentID), Description: "View credit score and tier"},
	}
	if agentAPIKey != "" {
		fmt.Fprintf(os.Stderr, "\n  *** Save this API key now — it will not be shown again ***\n  %s\n\n", agentAPIKey)
		nextActions = append([]NextAction{
			{Command: fmt.Sprintf("export BOB_API_KEY=%s", redactKey(agentAPIKey)), Description: "Set API key in your environment (redacted — use full key from above)"},
		}, nextActions...)
	} else if apiKeyPending {
		nextActions = append([]NextAction{
			{Command: fmt.Sprintf("bob agent get %s", agentID), Description: "Wait for provisioning, then retry approval"},
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


// --- Intent commands ---

func intentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "intent",
		Short: "Quote and execute payment intents",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob intent",
				Data:    intentCommandInfo(),
				NextActions: []NextAction{
					{Command: "bob intent quote <agent-id> --amount <n> --currency <BTC|USD|USDC> --destination-type <raw|bank_counterparty|unit_account|bob_address> --destination-ref <ref>", Description: "Quote a payment intent"},
					{Command: "bob intent submit-proof <agent-id> <intent-id> --txid <txid> --ownership-challenge-id <challenge-id> --ownership-signature <signature>", Description: "Attach an ownership-attested on-chain proof to a BTC intent"},
					{Command: "bob intent list <agent-id>", Description: "List payment intents"},
				},
			})
			return nil
		},
	}

	quoteCmd := &cobra.Command{
		Use:   "quote [agent-id]",
		Short: "Generate route quotes for a payment intent",
		Args:  cobra.ExactArgs(1),
		RunE:  intentQuote,
	}
	quoteCmd.Flags().Int64("amount", 0, "Amount in smallest currency unit (required)")
	quoteCmd.Flags().String("currency", "BTC", "Currency code (BTC, USD, USDC)")
	quoteCmd.Flags().String("raw-destination", "", "BTC destination shortcut (Lightning invoice/LNURL/BTC address)")
	quoteCmd.Flags().String("destination-type", "", "raw, bank_counterparty, unit_account, or bob_address")
	quoteCmd.Flags().String("destination-ref", "", "Destination reference (invoice/address/account/counterparty id)")
	quoteCmd.Flags().String("priority", "balanced", "Routing priority (cheapest, fastest, balanced)")
	quoteCmd.Flags().Int64("max-fee", 0, "Maximum acceptable fee")
	quoteCmd.Flags().String("latest-settlement-by", "", "Deadline for settlement (RFC3339)")
	quoteCmd.Flags().String("execution-mode", "auto", "Execution mode (auto, pinned)")
	quoteCmd.Flags().String("rail", "", "Pin to a specific rail")
	quoteCmd.Flags().String("wallet-id", "", "Pin to a specific wallet")
	quoteCmd.MarkFlagRequired("amount")
	cmd.AddCommand(quoteCmd)

	executeCmd := &cobra.Command{
		Use:   "execute [agent-id] [intent-id]",
		Short: "Execute a quoted payment intent",
		Args:  cobra.ExactArgs(2),
		RunE:  intentExecute,
	}
	executeCmd.Flags().String("quote-id", "", "Specific quote to execute (best if omitted)")
	executeCmd.Flags().String("description", "", "Payment description")
	cmd.AddCommand(executeCmd)

	getCmd := &cobra.Command{
		Use:   "get [agent-id] [intent-id]",
		Short: "Get a payment intent with route quotes",
		Args:  cobra.ExactArgs(2),
		RunE:  intentGet,
	}
	cmd.AddCommand(getCmd)

	submitProofCmd := &cobra.Command{
		Use:   "submit-proof [agent-id] [intent-id]",
		Short: "Submit non-custodial proof for a BTC payment intent",
		Long: "Submit BTC non-custodial proof (txid/payment-hash/preimage) for intents with raw external destinations.\n" +
			"For bob_address intents, use execute flow and settlement status/webhooks instead of manual proof submission.",
		Args: cobra.ExactArgs(2),
		RunE: intentSubmitProof,
	}
	submitProofCmd.Flags().String("proof-type", "", "Proof type (btc_onchain_tx, btc_lightning_payment_hash, btc_lightning_preimage)")
	submitProofCmd.Flags().String("proof-ref", "", "Proof reference value (txid or payment hash)")
	submitProofCmd.Flags().String("txid", "", "Shortcut for --proof-type btc_onchain_tx")
	submitProofCmd.Flags().String("payment-hash", "", "Shortcut for --proof-type btc_lightning_payment_hash")
	submitProofCmd.Flags().String("preimage", "", "Shortcut for --proof-type btc_lightning_preimage (proof-ref = payment hash, preimage in metadata)")
	submitProofCmd.Flags().String("invoice", "", "Optional BOLT11 invoice to include in proof metadata")
	submitProofCmd.Flags().String("ownership-challenge-id", "", "Ownership challenge id from bob intent proof-challenge (required)")
	submitProofCmd.Flags().String("ownership-signature", "", "Node signature over ownership challenge message (required)")
	cmd.AddCommand(submitProofCmd)

	proofChallengeCmd := &cobra.Command{
		Use:   "proof-challenge [agent-id] [intent-id]",
		Short: "Create an ownership challenge bound to an intent proof",
		Args:  cobra.ExactArgs(2),
		RunE:  intentProofChallenge,
	}
	proofChallengeCmd.Flags().String("proof-type", "", "Proof type (btc_onchain_tx, btc_lightning_payment_hash, btc_lightning_preimage)")
	proofChallengeCmd.Flags().String("proof-ref", "", "Proof reference value (txid or payment hash)")
	proofChallengeCmd.Flags().String("txid", "", "Shortcut for --proof-type btc_onchain_tx")
	proofChallengeCmd.Flags().String("payment-hash", "", "Shortcut for --proof-type btc_lightning_payment_hash")
	cmd.AddCommand(proofChallengeCmd)

	proofsCmd := &cobra.Command{
		Use:   "proofs [agent-id] [intent-id]",
		Short: "List submitted proofs for a payment intent",
		Args:  cobra.ExactArgs(2),
		RunE:  intentProofs,
	}
	cmd.AddCommand(proofsCmd)

	listCmd := &cobra.Command{
		Use:   "list [agent-id]",
		Short: "List payment intents for an agent",
		Args:  cobra.ExactArgs(1),
		RunE:  intentList,
	}
	listCmd.Flags().Int("limit", 30, "Max results")
	listCmd.Flags().Int("offset", 0, "Results to skip")
	cmd.AddCommand(listCmd)

	return cmd
}

func intentQuote(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	amount, _ := cmd.Flags().GetInt64("amount")
	currency, _ := cmd.Flags().GetString("currency")
	currencyChanged := cmd.Flags().Changed("currency")
	rawDestination, _ := cmd.Flags().GetString("raw-destination")
	destType, _ := cmd.Flags().GetString("destination-type")
	destRef, _ := cmd.Flags().GetString("destination-ref")
	priority, _ := cmd.Flags().GetString("priority")
	maxFee, _ := cmd.Flags().GetInt64("max-fee")
	latestSettlementBy, _ := cmd.Flags().GetString("latest-settlement-by")
	executionMode, _ := cmd.Flags().GetString("execution-mode")
	rail, _ := cmd.Flags().GetString("rail")
	walletID, _ := cmd.Flags().GetString("wallet-id")
	caps, _ := getSystemRailCapabilities()

	if strings.TrimSpace(rawDestination) != "" {
		if strings.TrimSpace(destType) != "" || strings.TrimSpace(destRef) != "" {
			emitError("bob intent quote", fmt.Errorf("set one destination path: --raw-destination OR --destination-type/--destination-ref"))
			return nil
		}
		destType = "raw"
		destRef = strings.TrimSpace(rawDestination)
		if !currencyChanged {
			currency = "BTC"
		}
	}

	currency = strings.ToUpper(strings.TrimSpace(currency))
	if currency == "" {
		currency = "BTC"
	}
	if currency != "BTC" && currency != "USD" && currency != "USDC" {
		emitError("bob intent quote", fmt.Errorf("currency must be BTC, USD, or USDC"))
		return nil
	}
	destType, err := normalizeDestinationType(destType)
	if err != nil {
		emitError("bob intent quote", err)
		return nil
	}
	destRef = strings.TrimSpace(destRef)
	if destType == "" || destRef == "" {
		emitError("bob intent quote", fmt.Errorf("destination is required: use --raw-destination or --destination-type/--destination-ref"))
		return nil
	}
	priority = strings.ToLower(strings.TrimSpace(priority))
	if priority != "cheapest" && priority != "fastest" && priority != "balanced" {
		emitError("bob intent quote", fmt.Errorf("priority must be cheapest, fastest, or balanced"))
		return nil
	}
	executionMode = strings.ToLower(strings.TrimSpace(executionMode))
	if executionMode == "" {
		executionMode = "auto"
	}
	if executionMode != "auto" && executionMode != "pinned" {
		emitError("bob intent quote", fmt.Errorf("execution-mode must be auto or pinned"))
		return nil
	}
	rail = strings.ToLower(strings.TrimSpace(rail))
	if rail != "" && rail != "auto" && rail != "lightning" && rail != "onchain" && rail != "ach" && rail != "wire" && rail != "book" {
		emitError("bob intent quote", fmt.Errorf("rail must be auto, lightning, onchain, ach, wire, or book"))
		return nil
	}
	if err := validateDestinationCurrencyAndRail(currency, destType, rail); err != nil {
		emitError("bob intent quote", err)
		return nil
	}
	if err := ensureRailsAvailable(caps, currency, destType, rail); err != nil {
		emitError("bob intent quote", err)
		return nil
	}

	payload := map[string]any{
		"destination_type": destType,
		"destination_ref":  destRef,
		"amount":           amount,
		"currency":         currency,
		"auto_execute":     false,
		"priority":         priority,
	}
	if executionMode != "" {
		payload["execution_mode"] = executionMode
	}
	if strings.TrimSpace(rail) != "" {
		payload["pinned_rail"] = strings.TrimSpace(rail)
		if executionMode == "" || executionMode == "auto" {
			payload["execution_mode"] = "pinned"
		}
	}
	if strings.TrimSpace(walletID) != "" {
		payload["pinned_wallet_id"] = strings.TrimSpace(walletID)
		if executionMode == "" || executionMode == "auto" {
			payload["execution_mode"] = "pinned"
		}
	}
	if maxFee > 0 {
		payload["max_fee"] = maxFee
	}
	if strings.TrimSpace(latestSettlementBy) != "" {
		payload["latest_settlement_by"] = strings.TrimSpace(latestSettlementBy)
	}

	data, err := apiPost("/agents/"+agentID+"/payment-intents/quote", payload)
	if err != nil {
		emitErrorWithActions("bob intent quote", err, []NextAction{
			{Command: fmt.Sprintf("bob agent get %s", agentID), Description: "Check agent status"},
			{Command: "bob score me", Description: "Check agent credit score"},
		})
		return nil
	}

	var result map[string]any
	json.Unmarshal(data, &result)
	quoteSummary := buildQuoteRejectionSummary(result)
	result["quote_summary"] = quoteSummary
	result["credit_context"] = creditContextOrUnavailable(agentID)
	if enriched, err := json.Marshal(result); err == nil {
		data = enriched
	}
	intentData, _ := result["intent"].(map[string]any)
	intentID, _ := intentData["id"].(string)

	nextActions := []NextAction{
		{Command: fmt.Sprintf("bob intent execute %s %s", agentID, intentID), Description: "Execute the best route"},
		{Command: fmt.Sprintf("bob intent get %s %s", agentID, intentID), Description: "Inspect intent details"},
		{Command: "bob score me", Description: "Check current credit score and tier"},
	}
	if toInt64(quoteSummary["candidate_quotes"]) == 0 {
		nextActions = append([]NextAction{
			{Command: fmt.Sprintf("bob score signals %s", agentID), Description: "Review score signals for eligibility"},
			{Command: "Retry with lower amount, different rail pinning, or looser fee/deadline constraints", Description: "Generate executable route candidates"},
		}, nextActions...)
	}

	emit(Envelope{
		OK:          true,
		Command:     "bob intent quote",
		Data:        json.RawMessage(data),
		NextActions: nextActions,
	})
	return nil
}

func intentExecute(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	intentID := args[1]
	quoteID, _ := cmd.Flags().GetString("quote-id")
	description, _ := cmd.Flags().GetString("description")

	payload := map[string]any{}
	if strings.TrimSpace(quoteID) != "" {
		payload["quote_id"] = strings.TrimSpace(quoteID)
	}
	if strings.TrimSpace(description) != "" {
		payload["description"] = strings.TrimSpace(description)
	}

	data, err := apiPost(fmt.Sprintf("/agents/%s/payment-intents/%s/execute", agentID, intentID), payload)
	if err != nil {
		emitErrorWithActions("bob intent execute", err, []NextAction{
			{Command: fmt.Sprintf("bob intent get %s %s", agentID, intentID), Description: "Check intent status"},
		})
		return nil
	}

	var result map[string]any
	json.Unmarshal(data, &result)
	paymentData, _ := result["payment"].(map[string]any)
	paymentID, _ := paymentData["id"].(string)

	nextActions := []NextAction{
		{Command: fmt.Sprintf("bob intent get %s %s", agentID, intentID), Description: "Check intent status"},
	}
	if paymentID != "" {
		nextActions = append([]NextAction{
			{Command: fmt.Sprintf("bob intent get %s %s", agentID, intentID), Description: "Poll for payment settlement"},
		}, nextActions...)
	}

	emit(Envelope{
		OK:          true,
		Command:     "bob intent execute",
		Data:        json.RawMessage(data),
		NextActions: nextActions,
	})
	return nil
}

func intentGet(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	intentID := args[1]

	data, err := apiGet(fmt.Sprintf("/agents/%s/payment-intents/%s", agentID, intentID))
	if err != nil {
		emitError("bob intent get", err)
		return nil
	}

	var result map[string]any
	json.Unmarshal(data, &result)
	intentData, _ := result["intent"].(map[string]any)
	status, _ := intentData["status"].(string)

	nextActions := []NextAction{
		{Command: fmt.Sprintf("bob intent list %s", agentID), Description: "List all intents"},
	}
	if status == "quoted" {
		nextActions = append([]NextAction{
			{Command: fmt.Sprintf("bob intent execute %s %s", agentID, intentID), Description: "Execute the best route"},
		}, nextActions...)
	}
	if status != "complete" && status != "failed" && status != "canceled" {
		nextActions = append(nextActions, NextAction{
			Command:     fmt.Sprintf("bob intent get %s %s", agentID, intentID),
			Description: "Re-check intent status",
		})
	}

	emit(Envelope{
		OK:          true,
		Command:     "bob intent get",
		Data:        json.RawMessage(data),
		NextActions: nextActions,
	})
	return nil
}

func intentProofChallenge(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	intentID := args[1]
	proofType, _ := cmd.Flags().GetString("proof-type")
	proofRef, _ := cmd.Flags().GetString("proof-ref")
	txid, _ := cmd.Flags().GetString("txid")
	paymentHash, _ := cmd.Flags().GetString("payment-hash")

	proofType = strings.ToLower(strings.TrimSpace(proofType))
	proofRef = strings.TrimSpace(proofRef)
	txid = strings.ToLower(strings.TrimSpace(txid))
	paymentHash = strings.ToLower(strings.TrimSpace(paymentHash))

	shortcuts := 0
	if txid != "" {
		shortcuts++
	}
	if paymentHash != "" {
		shortcuts++
	}
	if shortcuts > 1 {
		emitError("bob intent proof-challenge", fmt.Errorf("set one shortcut: --txid or --payment-hash"))
		return nil
	}
	if txid != "" {
		if proofType != "" || proofRef != "" {
			emitError("bob intent proof-challenge", fmt.Errorf("use either shortcut flags or --proof-type/--proof-ref"))
			return nil
		}
		proofType = "btc_onchain_tx"
		proofRef = txid
	}
	if paymentHash != "" {
		if proofType != "" || proofRef != "" {
			emitError("bob intent proof-challenge", fmt.Errorf("use either shortcut flags or --proof-type/--proof-ref"))
			return nil
		}
		proofType = "btc_lightning_payment_hash"
		proofRef = paymentHash
	}
	if proofType == "" || proofRef == "" {
		emitError("bob intent proof-challenge", fmt.Errorf("proof is required: use --txid, --payment-hash, or --proof-type + --proof-ref"))
		return nil
	}
	if proofType != "btc_onchain_tx" && proofType != "btc_lightning_payment_hash" && proofType != "btc_lightning_preimage" {
		emitError("bob intent proof-challenge", fmt.Errorf("proof-type must be btc_onchain_tx, btc_lightning_payment_hash, or btc_lightning_preimage"))
		return nil
	}

	payload := map[string]any{
		"proof_type": proofType,
		"proof_ref":  proofRef,
	}
	data, err := apiPost(fmt.Sprintf("/agents/%s/payment-intents/%s/proof-ownership/challenge", agentID, intentID), payload)
	if err != nil {
		emitErrorWithActions("bob intent proof-challenge", err, []NextAction{
			{Command: fmt.Sprintf("bob intent get %s %s", agentID, intentID), Description: "Check intent status"},
			{Command: fmt.Sprintf("bob intent submit-proof %s %s --proof-type %s --proof-ref %s --ownership-challenge-id <challenge-id> --ownership-signature <signature>", agentID, intentID, proofType, proofRef), Description: "Submit proof with ownership attestation"},
		})
		return nil
	}

	nextActions := []NextAction{
		{Command: fmt.Sprintf("bob intent submit-proof %s %s --proof-type %s --proof-ref %s --ownership-challenge-id <challenge-id> --ownership-signature <signature>", agentID, intentID, proofType, proofRef), Description: "Submit proof using a node signature over challenge.message"},
		{Command: fmt.Sprintf("bob intent get %s %s", agentID, intentID), Description: "Check intent status"},
	}
	emit(Envelope{
		OK:          true,
		Command:     "bob intent proof-challenge",
		Data:        json.RawMessage(data),
		NextActions: nextActions,
	})
	return nil
}

func intentNodeBindChallenge(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	walletID, _ := cmd.Flags().GetString("wallet-id")
	walletID = strings.TrimSpace(walletID)

	payload := map[string]any{}
	if walletID != "" {
		payload["wallet_id"] = walletID
	}
	data, err := apiPost(fmt.Sprintf("/agents/%s/node-bindings/lightning/challenge", agentID), payload)
	if err != nil {
		emitErrorWithActions("bob binding lightning-challenge", err, []NextAction{
			{Command: fmt.Sprintf("bob agent get %s", agentID), Description: "Check agent status and ensure a ready BTC lightning wallet"},
			{Command: fmt.Sprintf("bob binding lightning-challenge %s --wallet-id <wallet-id>", agentID), Description: "Retry with an explicit wallet id"},
		})
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob binding lightning-challenge",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: fmt.Sprintf("bob binding lightning-verify %s --challenge-id <challenge-id> --signature <signature>", agentID), Description: "Verify challenge using node signature over challenge.message"},
		},
	})
	return nil
}

func intentNodeBindVerify(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	challengeID, _ := cmd.Flags().GetString("challenge-id")
	signature, _ := cmd.Flags().GetString("signature")
	challengeID = strings.TrimSpace(challengeID)
	signature = strings.TrimSpace(signature)
	if challengeID == "" || signature == "" {
		emitError("bob binding lightning-verify", fmt.Errorf("challenge-id and signature are required"))
		return nil
	}

	payload := map[string]any{
		"challenge_id": challengeID,
		"signature":    signature,
	}
	data, err := apiPost(fmt.Sprintf("/agents/%s/node-bindings/lightning/verify", agentID), payload)
	if err != nil {
		emitErrorWithActions("bob binding lightning-verify", err, []NextAction{
			{Command: fmt.Sprintf("bob binding lightning-challenge %s", agentID), Description: "Create a fresh challenge"},
		})
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob binding lightning-verify",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: fmt.Sprintf("bob intent proof-challenge %s <intent-id> --txid <txid>", agentID), Description: "Create a proof ownership challenge"},
		},
	})
	return nil
}

func intentSubmitProof(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	intentID := args[1]
	proofType, _ := cmd.Flags().GetString("proof-type")
	proofRef, _ := cmd.Flags().GetString("proof-ref")
	txid, _ := cmd.Flags().GetString("txid")
	paymentHash, _ := cmd.Flags().GetString("payment-hash")
	preimage, _ := cmd.Flags().GetString("preimage")
	invoice, _ := cmd.Flags().GetString("invoice")
	ownershipChallengeID, _ := cmd.Flags().GetString("ownership-challenge-id")
	ownershipSignature, _ := cmd.Flags().GetString("ownership-signature")

	proofType = strings.ToLower(strings.TrimSpace(proofType))
	proofRef = strings.TrimSpace(proofRef)
	txid = strings.ToLower(strings.TrimSpace(txid))
	paymentHash = strings.ToLower(strings.TrimSpace(paymentHash))
	preimage = strings.TrimSpace(preimage)
	invoice = strings.TrimSpace(invoice)
	ownershipChallengeID = strings.TrimSpace(ownershipChallengeID)
	ownershipSignature = strings.TrimSpace(ownershipSignature)

	shortcuts := 0
	if txid != "" {
		shortcuts++
	}
	if paymentHash != "" {
		shortcuts++
	}
	if preimage != "" {
		shortcuts++
	}
	if shortcuts > 1 {
		emitError("bob intent submit-proof", fmt.Errorf("set one shortcut: --txid, --payment-hash, or --preimage"))
		return nil
	}
	if txid != "" {
		if proofType != "" || proofRef != "" {
			emitError("bob intent submit-proof", fmt.Errorf("use either shortcut flags or --proof-type/--proof-ref"))
			return nil
		}
		proofType = "btc_onchain_tx"
		proofRef = txid
	}
	if paymentHash != "" {
		if proofType != "" || proofRef != "" {
			emitError("bob intent submit-proof", fmt.Errorf("use either shortcut flags or --proof-type/--proof-ref"))
			return nil
		}
		proofType = "btc_lightning_payment_hash"
		proofRef = paymentHash
	}
	if preimage != "" {
		if proofType != "" || proofRef != "" {
			emitError("bob intent submit-proof", fmt.Errorf("use either shortcut flags or --proof-type/--proof-ref"))
			return nil
		}
		proofType = "btc_lightning_preimage"
		// proof_ref (payment hash) should be set via --proof-ref or will use the intent's destination_ref
	}
	if proofType == "" || (proofRef == "" && proofType != "btc_lightning_preimage") {
		emitError("bob intent submit-proof", fmt.Errorf("proof is required: use --txid, --payment-hash, --preimage, or --proof-type + --proof-ref"))
		return nil
	}
	if ownershipChallengeID == "" || ownershipSignature == "" {
		emitError("bob intent submit-proof", fmt.Errorf("ownership attestation is required: set --ownership-challenge-id and --ownership-signature"))
		return nil
	}
	if proofType != "btc_onchain_tx" && proofType != "btc_lightning_payment_hash" && proofType != "btc_lightning_preimage" {
		emitError("bob intent submit-proof", fmt.Errorf("proof-type must be btc_onchain_tx, btc_lightning_payment_hash, or btc_lightning_preimage"))
		return nil
	}

	payload := map[string]any{
		"proof_type":             proofType,
		"proof_ref":              proofRef,
		"ownership_challenge_id": ownershipChallengeID,
		"ownership_signature":    ownershipSignature,
	}
	if proofType == "btc_lightning_preimage" || preimage != "" || invoice != "" {
		meta := map[string]any{}
		if preimage != "" {
			meta["preimage"] = preimage
		}
		if invoice != "" {
			meta["invoice"] = invoice
		}
		payload["metadata"] = meta
	}
	data, err := apiPost(fmt.Sprintf("/agents/%s/payment-intents/%s/proofs", agentID, intentID), payload)
	if err != nil {
		if extractAPIErrorField(err, "reason") == "proof_binding_requires_raw_destination" {
			emitErrorWithActions("bob intent submit-proof", fmt.Errorf("manual proof submission is only supported for raw external destinations; for bob_address intents use execute flow and await settlement"), []NextAction{
				{Command: fmt.Sprintf("bob intent get %s %s", agentID, intentID), Description: "Re-check current intent status"},
				{Command: fmt.Sprintf("bob intent execute %s %s", agentID, intentID), Description: "Execute intent for internal bob_address settlement"},
				{Command: fmt.Sprintf("bob intent quote %s --amount <sats> --currency BTC --destination-type raw --destination-ref <invoice-or-address>", agentID), Description: "Use raw destination for manual txid/payment-hash proof"},
			})
			return nil
		}
		emitErrorWithActions("bob intent submit-proof", err, []NextAction{
			{Command: fmt.Sprintf("bob intent get %s %s", agentID, intentID), Description: "Check intent status"},
			{Command: fmt.Sprintf("bob intent proofs %s %s", agentID, intentID), Description: "List existing proofs"},
		})
		return nil
	}

	var result map[string]any
	_ = json.Unmarshal(data, &result)
	proofData, _ := result["proof"].(map[string]any)
	intentData, _ := result["intent"].(map[string]any)
	creditData, _ := result["credit"].(map[string]any)
	verificationStatus, _ := proofData["verification_status"].(string)
	intentStatus, _ := intentData["status"].(string)
	creditAwarded, _ := creditData["awarded"].(bool)
	creditReason, _ := creditData["reason"].(string)

	nextActions := []NextAction{
		{Command: fmt.Sprintf("bob intent proofs %s %s", agentID, intentID), Description: "List submitted proofs"},
		{Command: fmt.Sprintf("bob intent get %s %s", agentID, intentID), Description: "Check intent status"},
	}
	if creditAwarded {
		nextActions = append(nextActions, NextAction{
			Command:     fmt.Sprintf("bob agent credit-events %s", agentID),
			Description: "Inspect proof credit event details",
		})
	}
	if verificationStatus != "verified" || (intentStatus != "complete" && intentStatus != "failed" && intentStatus != "canceled") {
		nextActions = append(nextActions, NextAction{
			Command:     fmt.Sprintf("bob intent submit-proof %s %s --proof-type %s --proof-ref %s --ownership-challenge-id <challenge-id> --ownership-signature <signature>", agentID, intentID, proofType, proofRef),
			Description: "Retry proof submission later if settlement is still pending",
		})
	} else if !creditAwarded && creditReason != "" {
		switch creditReason {
		case "amount_below_credit_floor":
			nextActions = append(nextActions, NextAction{
				Command:     fmt.Sprintf("bob intent quote %s --amount <at-least-1000-sats> --currency BTC --destination-type raw --destination-ref <invoice-or-address>", agentID),
				Description: "Use a larger BTC amount to qualify for proof credit",
			})
		case "unbound_or_unsettled_proof":
			nextActions = append(nextActions, NextAction{
				Command:     fmt.Sprintf("bob intent get %s %s", agentID, intentID),
				Description: "Confirm this proof is settlement-bound and destination-matched",
			})
		}
	}

	emit(Envelope{
		OK:          true,
		Command:     "bob intent submit-proof",
		Data:        json.RawMessage(data),
		NextActions: nextActions,
	})
	return nil
}

func intentProofs(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	intentID := args[1]

	data, err := apiGet(fmt.Sprintf("/agents/%s/payment-intents/%s/proofs", agentID, intentID))
	if err != nil {
		emitError("bob intent proofs", err)
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob intent proofs",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: fmt.Sprintf("bob intent get %s %s", agentID, intentID), Description: "Check intent status"},
			{Command: fmt.Sprintf("bob intent submit-proof %s %s --txid <txid> --ownership-challenge-id <challenge-id> --ownership-signature <signature>", agentID, intentID), Description: "Submit additional ownership-attested on-chain proof"},
		},
	})
	return nil
}

func intentList(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	limit, _ := cmd.Flags().GetInt("limit")
	offset, _ := cmd.Flags().GetInt("offset")

	data, err := apiGet(fmt.Sprintf("/agents/%s/payment-intents?limit=%d&offset=%d", agentID, limit, offset))
	if err != nil {
		emitError("bob intent list", err)
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
		{Command: fmt.Sprintf("bob intent quote %s --amount <n> --currency <BTC|USD|USDC> --destination-type <raw|bank_counterparty|unit_account|bob_address> --destination-ref <ref>", agentID), Description: "Quote a new payment intent"},
	}
	if paged.HasMore {
		nextOffset := paged.Offset + paged.Limit
		nextActions = append(nextActions, NextAction{
			Command:     fmt.Sprintf("bob intent list %s --limit %d --offset %d", agentID, paged.Limit, nextOffset),
			Description: fmt.Sprintf("Next page (%d-%d of %d)", nextOffset+1, min(nextOffset+paged.Limit, paged.Total), paged.Total),
		})
	}

	emit(Envelope{
		OK:      true,
		Command: "bob intent list",
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


// --- config commands ---

func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show or update CLI configuration",
		RunE:  configShow,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Print current CLI configuration",
		RunE:  configShow,
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "set <key> <value>",
		Short: "Update a single config value (api-url, platform)",
		Args:  cobra.ExactArgs(2),
		RunE:  configSet,
	})
	return cmd
}

func configShow(cmd *cobra.Command, args []string) error {
	cfg, _ := loadCLIConfig()
	result := map[string]any{
		"version":        version,
		"api_url":        apiBase,
		"api_url_source": apiBaseSource,
		"platform":       defaultPlatform,
		"config_file":    activeCLIConfigPath(),
		"stored":         cfg,
	}
	emit(Envelope{
		OK:      true,
		Command: "bob config show",
		Data:    result,
		NextActions: []NextAction{
			{Command: "bob config set api-url <url>", Description: "Update API base URL"},
			{Command: "bob config set platform <generic|openclaw|claude>", Description: "Update platform"},
			{Command: "bob doctor", Description: "Full health check including connectivity"},
		},
	})
	return nil
}

func configSet(cmd *cobra.Command, args []string) error {
	key := strings.ToLower(strings.TrimSpace(args[0]))
	value := strings.TrimSpace(args[1])

	cfg, err := loadCLIConfig()
	if err != nil {
		cfg = cliConfig{}
	}

	switch key {
	case "api-url", "api_url":
		if value == "" {
			emitError("bob config set", fmt.Errorf("api-url value cannot be empty"))
			return nil
		}
		cfg.APIURL = normalizeAPIBaseForEnv(value)
	case "platform":
		if !validPlatform(value) {
			emitError("bob config set", fmt.Errorf("platform must be generic, openclaw, or claude"))
			return nil
		}
		cfg.Platform = strings.ToLower(value)
	default:
		emitErrorWithActions("bob config set", fmt.Errorf("unknown config key %q — valid keys: api-url, platform", key), []NextAction{
			{Command: "bob config show", Description: "View current configuration"},
		})
		return nil
	}

	if err := saveCLIConfig(cfg); err != nil {
		emitError("bob config set", fmt.Errorf("failed to save config: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob config set",
		Data: map[string]any{
			"key":         key,
			"value":       value,
			"config_file": activeCLIConfigPath(),
		},
		NextActions: []NextAction{
			{Command: "bob config show", Description: "Verify updated configuration"},
			{Command: "bob doctor", Description: "Test connectivity with new settings"},
		},
	})
	return nil
}

// --- score command (v0 stub) ---

func scoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "score",
		Short: "BOB Score — agent reputation and trust signals",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob score",
				Data:    childCommandInfo(commandTree(), "score"),
				NextActions: []NextAction{
					{Command: "bob score me", Description: "View your BOB Score and tier"},
				},
			})
			return nil
		},
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "me",
		Short: "View your agent's BOB Score and tier",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := apiGet("/auth/me")
			if err != nil {
				emitError("bob score me", err)
				return nil
			}
			var identity map[string]any
			json.Unmarshal(data, &identity)
			agentData, _ := identity["agent"].(map[string]any)
			agentID, _ := agentData["id"].(string)
			if agentID == "" {
				emitError("bob score me", fmt.Errorf("no agent identity found — authenticate with an agent API key"))
				return nil
			}
			scoreData, err := apiGet("/agents/" + url.PathEscape(agentID) + "/credit")
			if err != nil {
				emitError("bob score me", err)
				return nil
			}
			var resp map[string]any
			json.Unmarshal(scoreData, &resp)
			emit(Envelope{
				OK:      true,
				Command: "bob score me",
				Data:    resp,
				NextActions: []NextAction{
					{Command: "bob score composition " + agentID, Description: "View score component breakdown"},
					{Command: "bob agent credit-events " + agentID, Description: "View credit event history"},
				},
			})
			return nil
		},
	})
	compositionCmd := &cobra.Command{
		Use:   "composition [agent-id]",
		Short: "Breakdown of score components",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			agentID := args[0]
			data, err := apiGet("/agents/" + url.PathEscape(agentID) + "/credit")
			if err != nil {
				emitError("bob score composition", err)
				return nil
			}
			var resp map[string]any
			json.Unmarshal(data, &resp)
			emit(Envelope{OK: true, Command: "bob score composition", Data: resp})
			return nil
		},
	}
	cmd.AddCommand(compositionCmd)
	leaderboardCmd := &cobra.Command{
		Use:   "leaderboard",
		Short: "Top-ranked agents by BOB Score",
		RunE: func(cmd *cobra.Command, args []string) error {
			limit, _ := cmd.Flags().GetInt("limit")
			data, err := apiGet(fmt.Sprintf("/score/leaderboard?limit=%d", limit))
			if err != nil {
				emitError("bob score leaderboard", err)
				return nil
			}
			var resp any
			json.Unmarshal(data, &resp)
			emit(Envelope{OK: true, Command: "bob score leaderboard", Data: resp})
			return nil
		},
	}
	leaderboardCmd.Flags().Int("limit", 20, "Max results")
	cmd.AddCommand(leaderboardCmd)
	signalsCmd := &cobra.Command{
		Use:   "signals [agent-id]",
		Short: "List trust signals contributing to score",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			agentID := args[0]
			data, err := apiGet("/agents/" + url.PathEscape(agentID) + "/score/signals")
			if err != nil {
				emitError("bob score signals", err)
				return nil
			}
			var resp any
			json.Unmarshal(data, &resp)
			emit(Envelope{OK: true, Command: "bob score signals", Data: resp})
			return nil
		},
	}
	cmd.AddCommand(signalsCmd)
	return cmd
}

// --- binding command ---

func bindingCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "binding",
		Short: "Bind Lightning/EVM node ownership to an agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob binding",
				Data:    childCommandInfo(commandTree(), "binding"),
				NextActions: []NextAction{
					{Command: "bob binding lightning-challenge <agent-id>", Description: "Create a Lightning node ownership challenge"},
				},
			})
			return nil
		},
	}

	challengeCmd := &cobra.Command{
		Use:   "lightning-challenge [agent-id]",
		Short: "Create a Lightning node ownership challenge",
		Args:  cobra.ExactArgs(1),
		RunE:  intentNodeBindChallenge,
	}
	challengeCmd.Flags().String("wallet-id", "", "Optional wallet id to bind")
	cmd.AddCommand(challengeCmd)

	verifyCmd := &cobra.Command{
		Use:   "lightning-verify [agent-id]",
		Short: "Verify Lightning node ownership challenge with a node signature",
		Args:  cobra.ExactArgs(1),
		RunE:  intentNodeBindVerify,
	}
	verifyCmd.Flags().String("challenge-id", "", "Ownership challenge id (required)")
	verifyCmd.Flags().String("signature", "", "Node signature over challenge.message (required)")
	cmd.AddCommand(verifyCmd)

	evmChallengeCmd := &cobra.Command{
		Use:   "evm-challenge",
		Short: "Create an EVM wallet ownership challenge",
		Args:  cobra.NoArgs,
		RunE:  operatorEVMBindChallenge,
	}
	evmChallengeCmd.Flags().String("address", "", "EVM wallet address (0x...) (required)")
	evmChallengeCmd.MarkFlagRequired("address")
	cmd.AddCommand(evmChallengeCmd)

	evmVerifyCmd := &cobra.Command{
		Use:   "evm-verify",
		Short: "Verify EVM wallet ownership challenge with a wallet signature",
		Args:  cobra.NoArgs,
		RunE:  operatorEVMBindVerify,
	}
	evmVerifyCmd.Flags().String("challenge-id", "", "Challenge id from evm-challenge (required)")
	evmVerifyCmd.Flags().String("address", "", "EVM wallet address (0x...) (required)")
	evmVerifyCmd.Flags().String("signature", "", "EIP-191 signature over challenge.message (required)")
	evmVerifyCmd.Flags().String("chain-id", "", "Optional hex chain id (e.g. 0x1 for Ethereum, 0x2105 for Base)")
	evmVerifyCmd.MarkFlagRequired("challenge-id")
	evmVerifyCmd.MarkFlagRequired("address")
	evmVerifyCmd.MarkFlagRequired("signature")
	cmd.AddCommand(evmVerifyCmd)

	return cmd
}

// --- EVM wallet binding handlers ---

func operatorEVMBindChallenge(cmd *cobra.Command, args []string) error {
	address, _ := cmd.Flags().GetString("address")
	address = strings.TrimSpace(address)

	payload := map[string]any{"address": address}
	data, err := apiPost("/operators/me/wallet-bindings/evm/challenge", payload)
	if err != nil {
		emitErrorWithActions("bob binding evm-challenge", err, []NextAction{
			{Command: "bob auth me", Description: "Verify operator credentials"},
		})
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob binding evm-challenge",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: "bob binding evm-verify --challenge-id <challenge-id> --address " + address + " --signature <sig>", Description: "Sign challenge.message with your wallet and submit the signature"},
		},
	})
	return nil
}

func operatorEVMBindVerify(cmd *cobra.Command, args []string) error {
	challengeID, _ := cmd.Flags().GetString("challenge-id")
	address, _ := cmd.Flags().GetString("address")
	signature, _ := cmd.Flags().GetString("signature")
	chainID, _ := cmd.Flags().GetString("chain-id")

	challengeID = strings.TrimSpace(challengeID)
	address = strings.TrimSpace(address)
	signature = strings.TrimSpace(signature)
	chainID = strings.TrimSpace(chainID)

	payload := map[string]any{
		"challenge_id": challengeID,
		"address":      address,
		"signature":    signature,
	}
	if chainID != "" {
		payload["chain_id"] = chainID
	}

	data, err := apiPost("/operators/me/wallet-bindings/evm/verify", payload)
	if err != nil {
		emitErrorWithActions("bob binding evm-verify", err, []NextAction{
			{Command: "bob binding evm-challenge --address " + address, Description: "Create a fresh challenge (current one may have expired)"},
		})
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob binding evm-verify",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: "bob score me", Description: "Check updated BOB Score with wallet binding signal"},
		},
	})
	return nil
}

// --- webhook command (top-level, reuses agentWebhook* handlers) ---

func webhookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "webhook",
		Short: "Manage agent webhook subscribers",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob webhook",
				Data:    childCommandInfo(commandTree(), "webhook"),
				NextActions: []NextAction{
					{Command: "bob webhook list <agent-id>", Description: "List webhook subscribers"},
					{Command: "bob webhook create <agent-id> --url <url>", Description: "Create a webhook subscriber"},
				},
			})
			return nil
		},
	}

	createCmd := &cobra.Command{
		Use:   "create [agent-id]",
		Short: "Create an agent webhook subscriber",
		Args:  cobra.ExactArgs(1),
		RunE:  agentWebhookCreate,
	}
	createCmd.Flags().String("url", "", "Webhook URL (required)")
	createCmd.Flags().StringSlice("events", nil, "Optional event filters (empty subscribes to all)")
	createCmd.MarkFlagRequired("url")
	cmd.AddCommand(createCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "list [agent-id]",
		Short: "List agent webhook subscribers",
		Args:  cobra.ExactArgs(1),
		RunE:  agentWebhookList,
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "get [agent-id] [webhook-id]",
		Short: "Get an agent webhook subscriber",
		Args:  cobra.ExactArgs(2),
		RunE:  agentWebhookGet,
	})

	updateCmd := &cobra.Command{
		Use:   "update [agent-id] [webhook-id]",
		Short: "Update an agent webhook subscriber",
		Args:  cobra.ExactArgs(2),
		RunE:  agentWebhookUpdate,
	}
	updateCmd.Flags().String("url", "", "Webhook URL")
	updateCmd.Flags().StringSlice("events", nil, "Replace event filters")
	updateCmd.Flags().String("active", "", "Set active state (true/false)")
	cmd.AddCommand(updateCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "delete [agent-id] [webhook-id]",
		Short: "Delete an agent webhook subscriber",
		Args:  cobra.ExactArgs(2),
		RunE:  agentWebhookDelete,
	})

	return cmd
}

// --- inbox command (v0 stub) ---

func inboxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inbox",
		Short: "Agent message inbox",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob inbox",
				Data:    childCommandInfo(commandTree(), "inbox"),
				NextActions: []NextAction{
					{Command: "bob inbox list <agent-id>", Description: "List inbox messages"},
				},
			})
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list [agent-id]",
		Short: "List inbox messages for an agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			agentID := args[0]
			limit, _ := cmd.Flags().GetInt("limit")
			offset, _ := cmd.Flags().GetInt("offset")
			data, err := apiGet(fmt.Sprintf("/agents/%s/inbox?limit=%d&offset=%d", url.PathEscape(agentID), limit, offset))
			if err != nil {
				emitError("bob inbox list", err)
				return nil
			}
			var resp any
			json.Unmarshal(data, &resp)
			emit(Envelope{
				OK:      true,
				Command: "bob inbox list",
				Data:    resp,
				NextActions: []NextAction{
					{Command: fmt.Sprintf("bob inbox ack %s <message-id>", agentID), Description: "Acknowledge a message"},
				},
			})
			return nil
		},
	}
	listCmd.Flags().Int("limit", 30, "Max results")
	listCmd.Flags().Int("offset", 0, "Results to skip")
	cmd.AddCommand(listCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "ack [agent-id] [message-id]",
		Short: "Acknowledge (mark read) an inbox message",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			agentID := args[0]
			messageID := args[1]
			data, err := apiPost(fmt.Sprintf("/agents/%s/inbox/%s/ack", url.PathEscape(agentID), url.PathEscape(messageID)), map[string]any{})
			if err != nil {
				emitError("bob inbox ack", err)
				return nil
			}
			var resp any
			json.Unmarshal(data, &resp)
			emit(Envelope{OK: true, Command: "bob inbox ack", Data: resp})
			return nil
		},
	})

	eventsCmd := &cobra.Command{
		Use:   "events [agent-id]",
		Short: "List inbox event stream for an agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			agentID := args[0]
			limit, _ := cmd.Flags().GetInt("limit")
			data, err := apiGet(fmt.Sprintf("/agents/%s/inbox/events?limit=%d", url.PathEscape(agentID), limit))
			if err != nil {
				emitError("bob inbox events", err)
				return nil
			}
			var resp any
			json.Unmarshal(data, &resp)
			emit(Envelope{OK: true, Command: "bob inbox events", Data: resp})
			return nil
		},
	}
	eventsCmd.Flags().Int("limit", 50, "Max results")
	cmd.AddCommand(eventsCmd)

	return cmd
}

// --- api-key command (operator API key management) ---

func apiKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "api-key",
		Short: "Manage operator API keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob api-key",
				Data:    childCommandInfo(commandTree(), "api-key"),
				NextActions: []NextAction{
					{Command: "bob api-key list", Description: "List operator API keys"},
					{Command: "bob api-key create --name <name>", Description: "Create a new operator API key"},
				},
			})
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List operator API keys",
		RunE:  operatorOnlyRunE("bob api-key list", operatorAPIKeyList),
	}
	listCmd.Flags().Bool("include-revoked", false, "Include revoked keys")
	listCmd.Flags().Int("limit", 50, "Maximum number of keys to return")
	cmd.AddCommand(listCmd)

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new operator API key",
		RunE:  operatorOnlyRunE("bob api-key create", operatorAPIKeyCreate),
	}
	createCmd.Flags().String("name", "", "Display name for the API key")
	createCmd.Flags().StringSlice("scope", nil, "Scope to grant (repeatable)")
	createCmd.Flags().String("scopes", "", "Comma-separated scopes to grant")
	cmd.AddCommand(createCmd)

	revokeCmd := &cobra.Command{
		Use:   "revoke <key-id>",
		Short: "Revoke an operator API key",
		Args:  cobra.ExactArgs(1),
		RunE:  operatorOnlyRunE("bob api-key revoke", operatorAPIKeyRevoke),
	}
	cmd.AddCommand(revokeCmd)

	return cmd
}

// --- operator API key handlers (reused by api-key command) ---

func operatorAPIKeyCreate(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	scopeFlags, _ := cmd.Flags().GetStringSlice("scope")
	scopesCSV, _ := cmd.Flags().GetString("scopes")

	scopes := make([]string, 0, len(scopeFlags)+2)
	for _, scope := range scopeFlags {
		trimmed := strings.ToLower(strings.TrimSpace(scope))
		if trimmed != "" {
			scopes = append(scopes, trimmed)
		}
	}
	if strings.TrimSpace(scopesCSV) != "" {
		for _, token := range strings.Split(scopesCSV, ",") {
			trimmed := strings.ToLower(strings.TrimSpace(token))
			if trimmed != "" {
				scopes = append(scopes, trimmed)
			}
		}
	}

	payload := map[string]any{}
	if strings.TrimSpace(name) != "" {
		payload["name"] = strings.TrimSpace(name)
	}
	if len(scopes) > 0 {
		payload["scopes"] = scopes
	}

	data, err := apiPost("/operators/me/api-keys", payload)
	if err != nil {
		emitError("bob api-key create", err)
		return nil
	}

	var body map[string]any
	_ = json.Unmarshal(data, &body)
	if k, _ := body["api_key"].(string); strings.TrimSpace(k) != "" {
		fmt.Fprintf(os.Stderr, "\n  *** Save this API key now — it will not be shown again ***\n  %s\n\n", k)
	}

	emit(Envelope{
		OK:      true,
		Command: "bob api-key create",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: "bob api-key list", Description: "List current operator keys"},
			{Command: "bob auth me", Description: "Verify active scopes on the current key"},
		},
	})
	return nil
}

func operatorAPIKeyList(cmd *cobra.Command, args []string) error {
	includeRevoked, _ := cmd.Flags().GetBool("include-revoked")
	limit, _ := cmd.Flags().GetInt("limit")
	if limit <= 0 {
		limit = 50
	}

	path := fmt.Sprintf("/operators/me/api-keys?limit=%d", limit)
	if includeRevoked {
		path += "&include_revoked=true"
	}

	data, err := apiGet(path)
	if err != nil {
		emitError("bob api-key list", err)
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob api-key list",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: "bob api-key create", Description: "Issue another operator key"},
			{Command: "bob auth me", Description: "Check current key identity and scopes"},
		},
	})
	return nil
}

func operatorAPIKeyRevoke(cmd *cobra.Command, args []string) error {
	keyID := strings.TrimSpace(args[0])
	if keyID == "" {
		emitError("bob api-key revoke", fmt.Errorf("key-id is required"))
		return nil
	}

	data, err := apiPost("/operators/me/api-keys/"+keyID+"/revoke", map[string]any{})
	if err != nil {
		emitError("bob api-key revoke", err)
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob api-key revoke",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: "bob api-key list --include-revoked", Description: "Verify key revocation status"},
		},
	})
	return nil
}
