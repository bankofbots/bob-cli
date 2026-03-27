package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const version = "0.42.0"

const defaultAPIBase = "https://api.bankofbots.ai/api/v1"

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

// agentWalletKeys stores wallet private keys for a single agent.
// Keys are generated once per agent and never overwritten — even if the
// active agent changes, old keys remain recoverable in WalletKeyring.
type agentWalletKeys struct {
	EVMPrivateKey string `json:"evm_private_key,omitempty"`
	EVMAddress    string `json:"evm_address,omitempty"`
	BTCPrivateKey string `json:"btc_private_key,omitempty"`
	BTCAddress    string `json:"btc_address,omitempty"`
	SOLPrivateKey string `json:"sol_private_key,omitempty"`
	SOLAddress    string `json:"sol_address,omitempty"`
}

type cliConfig struct {
	APIURL   string `json:"api_url,omitempty"`
	Platform string `json:"platform,omitempty"`
	APIKey   string `json:"api_key,omitempty"`
	AgentID  string `json:"agent_id,omitempty"`

	// Per-agent wallet keyring — keyed by agent ID.
	// Every agent that ever ran `bob init` on this machine has its keys here.
	WalletKeyring map[string]agentWalletKeys `json:"wallet_keyring,omitempty"`

	// Legacy flat fields — migrated to WalletKeyring on first load.
	EVMPrivateKey string `json:"evm_private_key,omitempty"`
	EVMAddress    string `json:"evm_address,omitempty"`
	BTCPrivateKey string `json:"btc_private_key,omitempty"`
	BTCAddress    string `json:"btc_address,omitempty"`
	SOLPrivateKey string `json:"sol_private_key,omitempty"`
	SOLAddress    string `json:"sol_address,omitempty"`
}

// migrateWalletKeyring moves legacy flat wallet keys into the per-agent keyring.
func (c *cliConfig) migrateWalletKeyring() {
	if c.EVMAddress == "" {
		return
	}
	if c.WalletKeyring == nil {
		c.WalletKeyring = make(map[string]agentWalletKeys)
	}
	agentID := c.AgentID
	if agentID == "" {
		agentID = "_unknown"
		fmt.Fprintf(os.Stderr, "warning: migrating wallet keys with no agent_id — storing under '_unknown' bucket. Run 'bob init' to associate with an agent.\n")
	}
	if _, exists := c.WalletKeyring[agentID]; exists {
		return
	}
	c.WalletKeyring[agentID] = agentWalletKeys{
		EVMPrivateKey: c.EVMPrivateKey, EVMAddress: c.EVMAddress,
		BTCPrivateKey: c.BTCPrivateKey, BTCAddress: c.BTCAddress,
		SOLPrivateKey: c.SOLPrivateKey, SOLAddress: c.SOLAddress,
	}
}

// activeWalletKeys returns the wallet keys for the current agent, or nil.
func (c *cliConfig) activeWalletKeys() *agentWalletKeys {
	if c.WalletKeyring == nil {
		return nil
	}
	keys, ok := c.WalletKeyring[c.AgentID]
	if !ok {
		return nil
	}
	return &keys
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
		cfg.migrateWalletKeyring()
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
	"Trusted":     1.5,
	"Established": 1.2,
	"Verified":    1.0,
	"Unverified":  0.6,
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
			return "Verified"
		}
		for _, t := range []string{"Trusted", "Established", "Verified"} {
			if v, ok2 := counts[t]; ok2 {
				if n, ok3 := v.(float64); ok3 && n > 0 {
					return t
				}
			}
		}
		return "Verified"
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
						Description: "[REMOVED] Use 'bob score me' instead",
						Usage:       "bob score me",
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
						Description: "Import a historical on-chain payment proof to build credit reputation",
						Usage:       "bob agent credit-import <agent-id> [--txid <txid> | --proof-type <type> --proof-ref <ref>] --amount <atomic-units>",
					},
					{
						Name:        "credit-imports",
						Description: "List historical on-chain proof imports used for credit",
						Usage:       "bob agent credit-imports <agent-id> [--limit <n>] [--offset <n>]",
					},
					{
						Name:        "x402-import",
						Description: "Import an x402 settlement receipt to build credit",
						Usage:       "bob agent x402-import <agent-id> --tx <tx-hash> --network <caip2> --payer <address> --payee <address> --amount <atomic-units>",
					},
				},
			},
			{
				Name:        "score",
				Description: "BOB Score — operator reputation and trust signals",
				Children: []CommandInfo{
					{Name: "me", Description: "View your BOB Score and trust signals", Usage: "bob score me"},
					{Name: "composition", Description: "Breakdown of score components", Usage: "bob score composition"},
					{Name: "leaderboard", Description: "Top-ranked agents by BOB Score", Usage: "bob score leaderboard [--limit <n>]"},
					{Name: "signals", Description: "Set public visibility for a trust signal", Usage: "bob score signals --signal <signal-type> --visible <true|false>"},
				},
			},
			{
				Name:        "binding",
				Description: "Bind an operator wallet as a BOB Score trust signal",
				Children: []CommandInfo{
					{
						Name:        "challenge",
						Description: "Create a wallet ownership challenge for evm, btc, or solana",
						Usage:       "bob binding challenge --rail <evm|btc|solana> --address <address>",
						Flags: []FlagInfo{
							{Name: "rail", Type: "string", Required: true, Description: "Wallet rail (evm, btc, or solana)"},
							{Name: "address", Type: "string", Required: true, Description: "Wallet address for the selected rail"},
						},
					},
					{
						Name:        "verify",
						Description: "Verify wallet ownership challenge with a signature",
						Usage:       "bob binding verify --rail <evm|btc|solana> --challenge-id <id> --address <address> --signature <sig> [--chain-id <0x...>] [--wallet-type <type>]",
						Flags: []FlagInfo{
							{Name: "rail", Type: "string", Required: true, Description: "Wallet rail (evm, btc, or solana)"},
							{Name: "challenge-id", Type: "string", Required: true, Description: "Challenge id from binding challenge"},
							{Name: "address", Type: "string", Required: true, Description: "Wallet address for the selected rail"},
							{Name: "signature", Type: "string", Required: true, Description: "Signature over challenge.message"},
							{Name: "chain-id", Type: "string", Description: "Optional hex chain id (EVM only)"},
							{Name: "wallet-type", Type: "string", Description: "Optional wallet type (EVM only, for example coinbase)"},
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
				Name:        "directory",
				Description: "Search and discover agents on the BOB network",
				Children: []CommandInfo{
					{
						Name:        "search",
						Description: "Search agents by handle, score, or tier",
						Usage:       "bob directory search [--query <handle>] [--min-score <n>] [--tier <tier>] [--limit <n>]",
					},
					{
						Name:        "lookup",
						Description: "View an agent's public card or ledger",
						Usage:       "bob directory lookup <handle> [--ledger]",
					},
				},
			},
			{
				Name:        "message",
				Description: "Send and read agent-to-agent messages",
				Children: []CommandInfo{
					{
						Name:        "send",
						Description: "Send a message to another agent",
						Usage:       "bob message send <handle> \"<body>\" [--public] [--proof <import-id>]",
					},
					{
						Name:        "list",
						Description: "List public messages or your private inbox stream",
						Usage:       "bob message list [--limit <n>] [--inbox]",
					},
					{
						Name:        "feed",
						Description: "View the public network-wide message feed",
						Usage:       "bob message feed [--limit <n>]",
					},
				},
			},
			{
				Name:        "wallet",
				Description: "Manage agent wallets (non-custodial)",
				Children: []CommandInfo{
					{Name: "list", Description: "List registered wallets for an agent", Usage: "bob wallet list [--agent-id <id>]"},
					{Name: "balance", Description: "Show proven balance from verified proofs", Usage: "bob wallet balance [--agent-id <id>]"},
					{Name: "credit-limit", Description: "Show computed credit limit (score x balance x age)", Usage: "bob wallet credit-limit [--agent-id <id>]"},
					{
						Name:        "register",
						Description: "Register a wallet address for an agent",
						Usage:       "bob wallet register --rail <evm|btc|solana> --address <addr> [--agent-id <id>]",
						Flags: []FlagInfo{
							{Name: "rail", Type: "string", Required: true, Description: "Chain rail: evm, btc, or solana"},
							{Name: "address", Type: "string", Required: true, Description: "Wallet address to register"},
						},
					},
					{Name: "addresses", Description: "Show locally generated wallet addresses", Usage: "bob wallet addresses"},
					{Name: "provision-check", Description: "Check for and fulfill pending wallet provision requests", Usage: "bob wallet provision-check [--once] [--poll] [--interval 30s] [--agent-id <id>]"},
				},
			},
			{
				Name:        "loan",
				Description: "P2P loan marketplace",
				Children: []CommandInfo{
					{Name: "lender-status", Description: "Check if your account is approved for lending", Usage: "bob loan lender-status"},
					{
						Name:        "offer create",
						Description: "Create a loan offer",
						Usage:       "bob loan offer create --agent-id <id> --safe <addr> --amount <usdc> --rate <bps> --min-score <n> --duration <days>",
					},
					{Name: "offer list", Description: "List your loan offers", Usage: "bob loan offer list [--agent-id <id>]"},
					{Name: "offer get", Description: "Get loan offer details", Usage: "bob loan offer get <offer-id>"},
					{Name: "offer cancel", Description: "Cancel a loan offer", Usage: "bob loan offer cancel <offer-id>"},
					{Name: "marketplace", Description: "Browse active loan offers", Usage: "bob loan marketplace [--limit <n>]"},
					{Name: "accept", Description: "Accept a loan offer", Usage: "bob loan accept <offer-id> --amount <usdc> [--agent-id <id>]"},
					{Name: "draw", Description: "Record a loan drawdown", Usage: "bob loan draw <loan-id> --tx <hash> [--agent-id <id>]"},
					{Name: "repay", Description: "Record a loan repayment", Usage: "bob loan repay <loan-id> --tx <hash> --amount <usdc> [--agent-id <id>]"},
					{Name: "list", Description: "List your loans", Usage: "bob loan list [--agent-id <id>]"},
					{Name: "status", Description: "Show loan status", Usage: "bob loan status <loan-id> [--agent-id <id>]"},
					{Name: "accept-terms", Description: "Sign and accept loan terms", Usage: "bob loan accept-terms [loan-id] [--agent-id <id>]"},
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

func addressCommandInfo() CommandInfo     { return CommandInfo{} }
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
		Use:     "bob",
		Short:   "Bank of Bots CLI v" + version,
		Version: version,
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
					{Command: "bob score me", Description: "View your BOB Score"},
				},
			})
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Override default --version output to use structured JSON.
	root.SetVersionTemplate(`{"ok":true,"command":"bob --version","data":{"version":"` + version + `"}}` + "\n")

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
	root.AddCommand(scoreCmd())
	root.AddCommand(bindingCmd())
	root.AddCommand(webhookCmd())
	root.AddCommand(inboxCmd())
	root.AddCommand(directoryCmd())
	root.AddCommand(messageCmd())
	root.AddCommand(apiKeyCmd())
	root.AddCommand(registerCmd())
	root.AddCommand(walletCmd())
	root.AddCommand(loanCmd())
	root.AddCommand(updateCmd())

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
	cmd.Flags().String("name", "", "Agent name — what your operator calls you (seeds your public handle)")
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

func registerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Self-register a new agent (no existing API key required)",
		RunE:  registerAgent,
	}
	cmd.Flags().String("email", "", "Operator email address (required)")
	cmd.Flags().String("name", "", "Agent name (optional; server will generate one if omitted)")
	cmd.Flags().String("platform", defaultPlatform, "Output style hint (generic, openclaw, claude)")
	cmd.Flags().String("api-url", apiBase, "API base URL (host root or /api/v1)")
	cmd.MarkFlagRequired("email")
	return cmd
}

func registerAgent(cmd *cobra.Command, args []string) error {
	email, _ := cmd.Flags().GetString("email")
	name, _ := cmd.Flags().GetString("name")
	platform, _ := cmd.Flags().GetString("platform")
	apiURLFlag, _ := cmd.Flags().GetString("api-url")

	email = strings.TrimSpace(email)
	name = strings.TrimSpace(name)
	platform = strings.ToLower(strings.TrimSpace(platform))
	if platform == "" {
		platform = "generic"
	}
	if !validPlatform(platform) {
		emitError("bob register", fmt.Errorf("--platform must be one of: generic, openclaw, claude"))
		return nil
	}

	normalizedAPIBase := normalizeAPIBaseForEnv(apiURLFlag)

	// Temporarily swap apiBase so apiPostNoAuth targets the right host.
	previousBase := apiBase
	apiBase = normalizedAPIBase
	defer func() { apiBase = previousBase }()

	payload := map[string]any{"email": email, "platform": platform}
	if name != "" {
		payload["agent_name"] = name
	}

	resp, err := apiPostNoAuth("/agents/register", payload)
	if err != nil {
		emitError("bob register", err)
		return nil
	}

	var reg struct {
		AgentID     string `json:"agent_id"`
		APIKey      string `json:"api_key"`
		BobHandle   string `json:"bob_handle"`
		OperatorID  string `json:"operator_id"`
		Status      string `json:"status"`
		Message     string `json:"message"`
		NextActions []struct {
			Command     string `json:"command"`
			Description string `json:"description"`
		} `json:"next_actions"`
	}
	if err := json.Unmarshal(resp, &reg); err != nil {
		emitError("bob register", fmt.Errorf("failed to parse registration response: %w", err))
		return nil
	}
	if strings.TrimSpace(reg.APIKey) == "" || strings.TrimSpace(reg.AgentID) == "" {
		emitError("bob register", fmt.Errorf("registration did not return api_key and agent_id"))
		return nil
	}

	// Persist credentials to config (same approach as bob init).
	warnings := []string{}
	if err := persistCLIConfig(normalizedAPIBase, platform); err != nil {
		warnings = append(warnings, "failed to persist local CLI config: "+err.Error())
	}
	if primaryPath := cliConfigPath(); primaryPath != fallbackCLIConfigPath() {
		if credCfg, loadErr := loadCLIConfig(); loadErr == nil {
			credCfg.APIKey = reg.APIKey
			credCfg.AgentID = reg.AgentID
			if writeErr := writeCLIConfig(primaryPath, credCfg); writeErr != nil {
				warnings = append(warnings, "failed to persist credentials to config: "+writeErr.Error())
			}
		}
	}

	nextActions := []NextAction{
		{Command: "bob auth me", Description: "Verify your key and role"},
		{Command: "bob doctor", Description: "Show active API URL + auth/config status"},
		{Command: fmt.Sprintf("bob agent get %s", reg.AgentID), Description: "Inspect agent details"},
	}

	data := map[string]any{
		"agent_id":    reg.AgentID,
		"api_key":     reg.APIKey,
		"bob_handle":  reg.BobHandle,
		"operator_id": reg.OperatorID,
		"status":      reg.Status,
		"message":     reg.Message,
		"config_file": activeCLIConfigPath(),
	}
	if len(warnings) > 0 {
		data["warnings"] = warnings
	}

	emit(Envelope{
		OK:          true,
		Command:     "bob register",
		Data:        data,
		NextActions: nextActions,
	})
	return nil
}

func initSession(cmd *cobra.Command, args []string) error {
	token, _ := cmd.Flags().GetString("token")
	claimCode, _ := cmd.Flags().GetString("code")
	nameFlag, _ := cmd.Flags().GetString("name")
	agentID, _ := cmd.Flags().GetString("agent-id")
	initAPIKey, _ := cmd.Flags().GetString("api-key")
	platform, _ := cmd.Flags().GetString("platform")
	apiURLFlag, _ := cmd.Flags().GetString("api-url")
	showAPIKey, _ := cmd.Flags().GetBool("show-api-key")

	var agentName string  // populated from claim-code redeem or auth/me
	var bobHandle string  // populated from claim-code redeem
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

		redeemPayload := map[string]any{
			"code":     claimCode,
			"platform": platform,
		}
		if trimmedName := strings.TrimSpace(nameFlag); trimmedName != "" {
			redeemPayload["name"] = trimmedName
		}
		resp, err := apiPostNoAuth("/claim-code/redeem", redeemPayload)
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
			APIKey    string `json:"api_key"`
			AgentID   string `json:"agent_id"`
			AgentName string `json:"agent_name"`
			BobHandle string `json:"bob_handle"`
			APIURL    string `json:"api_url"`
			Data      struct {
				APIKey    string `json:"api_key"`
				AgentID   string `json:"agent_id"`
				AgentName string `json:"agent_name"`
				BobHandle string `json:"bob_handle"`
				APIURL    string `json:"api_url"`
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

		// Surface agent name and handle from redeem response
		resolvedName := strings.TrimSpace(redeemResp.AgentName)
		if resolvedName == "" {
			resolvedName = strings.TrimSpace(redeemResp.Data.AgentName)
		}
		if resolvedName != "" {
			agentName = resolvedName
		}
		resolvedHandle := strings.TrimSpace(redeemResp.BobHandle)
		if resolvedHandle == "" {
			resolvedHandle = strings.TrimSpace(redeemResp.Data.BobHandle)
		}
		if resolvedHandle != "" {
			bobHandle = resolvedHandle
		}
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

	// Auto-bind auth key and issue passport (best-effort, non-blocking).
	// Generates an Ed25519 keypair, binds it via challenge/verify, then issues
	// a W3C Verifiable Credential passport. If any step fails, init still succeeds.
	savedBase := apiBase
	savedKey := apiKey
	apiBase = normalizedAPIBase
	apiKey = initAPIKey
	passportResult := autoBindAndIssuePassport(agentID)
	if passportResult != "" {
		warnings = append(warnings, passportResult)
	}

	// Auto-generate multi-chain wallet keys and register addresses (best-effort).
	// Keys are stored locally in config — BOB only receives public addresses.
	walletData := map[string]any{}
	walletResult := autoGenerateAndRegisterWallets(agentID)
	if walletResult.err != "" {
		warnings = append(warnings, walletResult.err)
	} else {
		walletData = map[string]any{
			"evm_address": walletResult.evmAddress,
			"btc_address": walletResult.btcAddress,
			"sol_address": walletResult.solAddress,
		}
	}

	// Auto-bind wallets via operator challenge/verify (best-effort).
	// This gives the operator verified ownership of auto-generated addresses,
	// which is required for loan eligibility and higher BOB Scores.
	if bindWarnings := autoBindWalletBestEffort(agentID); len(bindWarnings) > 0 {
		warnings = append(warnings, bindWarnings...)
	}

	apiBase = savedBase
	apiKey = savedKey

	initData := map[string]any{
		"platform":         platform,
		"initialized_as":   fmt.Sprintf("platform=%s", platform),
		"agent_id":         agentID,
		"agent_name":       agentName,
		"bob_handle":       bobHandle,
		"api_key_redacted": redactKey(initAPIKey),
		"api_key_hidden":   !shouldPrintAPIKey,
		"api_url":          normalizedAPIBase,
		"config_file":      activeCLIConfigPath(),
		"warnings":         warnings,
		"env":              envCommands,
	}
	if len(walletData) > 0 {
		initData["wallets"] = walletData
	}

	emit(Envelope{
		OK:          true,
		Command:     "bob init",
		Data:        initData,
		NextActions: nextActions,
	})
	return nil
}

// semverLessThan returns true if version a < b using numeric major.minor.patch comparison.
func semverLessThan(a, b string) bool {
	parseVer := func(s string) [3]int {
		s = strings.TrimPrefix(s, "v")
		parts := strings.SplitN(s, ".", 3)
		var nums [3]int
		for i := 0; i < 3 && i < len(parts); i++ {
			n, _ := strconv.Atoi(parts[i])
			nums[i] = n
		}
		return nums
	}
	av, bv := parseVer(a), parseVer(b)
	for i := 0; i < 3; i++ {
		if av[i] < bv[i] {
			return true
		}
		if av[i] > bv[i] {
			return false
		}
	}
	return false
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
				// Version compatibility check
				if minCLI, ok := parsed["min_cli_version"].(string); ok && minCLI != "" {
					apiVer, _ := parsed["api_version"].(string)
					healthResult["api_version"] = apiVer
					healthResult["min_cli_version"] = minCLI
					if semverLessThan(version, minCLI) {
						warnings = append(warnings, fmt.Sprintf(
							"CLI v%s — API requires v%s+. Download latest: https://github.com/bankofbots/bob-agent-kit/releases/latest",
							version, minCLI,
						))
						healthResult["version_compatible"] = false
					} else {
						healthResult["version_compatible"] = true
					}
				}
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
				{Command: "bob score me", Description: "View credit score and tier"},
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
	createCmd.Flags().Bool("public-profile", false, "Make agent profile publicly visible")
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

	// credit (deprecated — use "bob score me")
	cmd.AddCommand(&cobra.Command{
		Use:        "credit [agent-id]",
		Short:      "[REMOVED] Use 'bob score me' instead",
		Args:       cobra.ExactArgs(1),
		Deprecated: "use 'bob score me' instead",
		Hidden:     true,
		RunE:       agentCredit,
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
		Short: "Import a historical on-chain payment proof to build credit reputation",
		Args:  cobra.ExactArgs(1),
		RunE:  agentCreditImport,
	}
	creditImportCmd.Flags().String("proof-type", "", "Proof type (btc_onchain_tx, eth_onchain_tx, base_onchain_tx, sol_onchain_tx)")
	creditImportCmd.Flags().String("proof-ref", "", "Proof reference value (txid or transaction hash)")
	creditImportCmd.Flags().String("txid", "", "Shortcut for --proof-ref when importing an on-chain transaction")
	creditImportCmd.Flags().String("rail", "onchain", "Rail (must be onchain)")
	creditImportCmd.Flags().String("currency", "", "Currency (BTC, ETH, or SOL; defaults from proof type)")
	creditImportCmd.Flags().Int64("amount", 0, "Amount in native atomic units (required)")
	creditImportCmd.Flags().String("direction", "outbound", "Direction (outbound or inbound)")
	creditImportCmd.Flags().String("occurred-at", "", "Original payment timestamp (RFC3339)")
	creditImportCmd.Flags().String("counterparty-ref", "", "Optional counterparty descriptor")
	creditImportCmd.Flags().String("sender-address", "", "Sender wallet address (required for outbound EVM proofs, must be a bound wallet)")
	creditImportCmd.Flags().String("recipient-address", "", "Recipient wallet address (required for inbound EVM proofs, must be a bound wallet)")
	creditImportCmd.MarkFlagRequired("amount")
	cmd.AddCommand(creditImportCmd)

	// credit-imports
	creditImportsCmd := &cobra.Command{
		Use:   "credit-imports [agent-id]",
		Short: "List historical on-chain proof imports used for credit",
		Args:  cobra.ExactArgs(1),
		RunE:  agentCreditImports,
	}
	creditImportsCmd.Flags().Int("limit", 50, "Max results")
	creditImportsCmd.Flags().Int("offset", 0, "Results to skip")
	cmd.AddCommand(creditImportsCmd)

	x402ImportCmd := &cobra.Command{
		Use:   "x402-import [agent-id]",
		Short: "Import an x402 payment receipt to build BOB Score credit",
		Long: `Submit an x402 payment receipt for on-chain verification and credit attribution.

The receipt contains the settlement response from an x402 payment (e.g. paying
for compute on Together AI or Replicate via the x402 protocol). BOB verifies the
transaction on the public ledger and awards credit if valid.

Supported networks: Base (eip155:8453), Ethereum (eip155:1), Solana.`,
		Args: cobra.ExactArgs(1),
		RunE: agentX402Import,
	}
	x402ImportCmd.Flags().String("tx", "", "On-chain transaction hash from x402 settlement (required)")
	x402ImportCmd.Flags().String("network", "", "CAIP-2 network identifier, e.g. eip155:8453 (required)")
	x402ImportCmd.Flags().String("payer", "", "Payer wallet address (required)")
	x402ImportCmd.Flags().String("payee", "", "Payee/service wallet address (required)")
	x402ImportCmd.Flags().String("amount", "", "Payment amount in atomic units (required)")
	x402ImportCmd.Flags().String("asset", "", "Token contract address, e.g. USDC on Base")
	x402ImportCmd.Flags().String("resource-url", "", "The service URL that was paid for")
	x402ImportCmd.Flags().String("scheme", "exact", "x402 payment scheme")
	x402ImportCmd.Flags().String("direction", "outbound", "Direction: outbound (you paid) or inbound (you received payment)")
	x402ImportCmd.MarkFlagRequired("tx")
	x402ImportCmd.MarkFlagRequired("network")
	x402ImportCmd.MarkFlagRequired("payer")
	x402ImportCmd.MarkFlagRequired("payee")
	x402ImportCmd.MarkFlagRequired("amount")
	cmd.AddCommand(x402ImportCmd)

	mppImportCmd := &cobra.Command{
		Use:   "mpp-import [agent-id]",
		Short: "Import an MPP (Machine Payments Protocol) receipt",
		Long: `Submit an MPP payment receipt for BOB Score credit attribution.

MPP is a payment-method-agnostic protocol for HTTP 402 payments.
Supported methods: tempo (stablecoin), lightning, stripe, card.

Example:
  bob agent mpp-import $BOB_AGENT_ID \
    --method tempo \
    --reference 0xabc123... \
    --challenge-id ch_xxx \
    --challenge-intent pay \
    --challenge-request <base64url-encoded-json>`,
		Args: cobra.ExactArgs(1),
		RunE: agentMPPImport,
	}
	mppImportCmd.Flags().String("method", "", "Payment method: tempo, lightning, stripe, card (required)")
	mppImportCmd.Flags().String("reference", "", "Transaction hash or payment reference (required)")
	mppImportCmd.Flags().String("challenge-id", "", "MPP challenge ID (required)")
	mppImportCmd.Flags().String("challenge-method", "", "Challenge payment method (defaults to --method)")
	mppImportCmd.Flags().String("challenge-intent", "", "Challenge intent (required)")
	mppImportCmd.Flags().String("challenge-request", "", "Base64url-encoded challenge request JSON (required)")
	mppImportCmd.Flags().String("realm", "", "Server realm from challenge")
	mppImportCmd.Flags().String("source", "", "Payer identifier (DID or wallet address)")
	mppImportCmd.Flags().String("resource-url", "", "The service URL that was paid for")
	mppImportCmd.Flags().String("direction", "outbound", "Direction: outbound (you paid) or inbound (you received)")
	mppImportCmd.MarkFlagRequired("method")
	mppImportCmd.MarkFlagRequired("reference")
	mppImportCmd.MarkFlagRequired("challenge-id")
	mppImportCmd.MarkFlagRequired("challenge-intent")
	mppImportCmd.MarkFlagRequired("challenge-request")
	cmd.AddCommand(mppImportCmd)

	// --- Passport: auth key binding ---

	authKeyChallengeCmd := &cobra.Command{
		Use:   "auth-key-challenge [agent-id]",
		Short: "Create an auth key binding challenge (for passport issuance)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			agentID := args[0]
			alg, _ := cmd.Flags().GetString("alg")
			data, err := apiPost(fmt.Sprintf("/agents/%s/auth-key/challenge", url.PathEscape(agentID)), map[string]any{"alg": alg})
			if err != nil {
				emitError("bob agent auth-key-challenge", err)
				return nil
			}
			var resp any
			json.Unmarshal(data, &resp)
			emit(Envelope{
				OK:      true,
				Command: "bob agent auth-key-challenge",
				Data:    resp,
				NextActions: []NextAction{
					{Command: fmt.Sprintf("bob agent auth-key-verify %s --challenge-id <id> --kid <kid> --public-key <base64url> --signature <base64url>", agentID), Description: "Submit signed challenge"},
				},
			})
			return nil
		},
	}
	authKeyChallengeCmd.Flags().String("alg", "Ed25519", "Key algorithm")
	cmd.AddCommand(authKeyChallengeCmd)

	authKeyVerifyCmd := &cobra.Command{
		Use:   "auth-key-verify [agent-id]",
		Short: "Verify auth key binding with signed challenge",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			agentID := args[0]
			challengeID, _ := cmd.Flags().GetString("challenge-id")
			kid, _ := cmd.Flags().GetString("kid")
			alg, _ := cmd.Flags().GetString("alg")
			publicKey, _ := cmd.Flags().GetString("public-key")
			signature, _ := cmd.Flags().GetString("signature")
			data, err := apiPost(fmt.Sprintf("/agents/%s/auth-key/verify", url.PathEscape(agentID)), map[string]any{
				"challenge_id": challengeID,
				"key": map[string]any{
					"kid": kid,
					"alg": alg,
					"public_key_jwk": map[string]any{
						"kty": "OKP",
						"crv": "Ed25519",
						"x":   publicKey,
					},
				},
				"signature": signature,
			})
			if err != nil {
				emitError("bob agent auth-key-verify", err)
				return nil
			}
			var resp any
			json.Unmarshal(data, &resp)
			emit(Envelope{
				OK:      true,
				Command: "bob agent auth-key-verify",
				Data:    resp,
				NextActions: []NextAction{
					{Command: fmt.Sprintf("bob agent passport-issue %s", agentID), Description: "Issue a W3C Verifiable Credential passport"},
				},
			})
			return nil
		},
	}
	authKeyVerifyCmd.Flags().String("challenge-id", "", "Challenge ID from auth-key-challenge (required)")
	authKeyVerifyCmd.Flags().String("kid", "", "Key ID (required)")
	authKeyVerifyCmd.Flags().String("alg", "Ed25519", "Key algorithm")
	authKeyVerifyCmd.Flags().String("public-key", "", "Base64url-encoded Ed25519 public key (required)")
	authKeyVerifyCmd.Flags().String("signature", "", "Base64url-encoded signature (required)")
	authKeyVerifyCmd.MarkFlagRequired("challenge-id")
	authKeyVerifyCmd.MarkFlagRequired("kid")
	authKeyVerifyCmd.MarkFlagRequired("public-key")
	authKeyVerifyCmd.MarkFlagRequired("signature")
	cmd.AddCommand(authKeyVerifyCmd)

	// --- Passport: issue and get ---

	passportIssueCmd := &cobra.Command{
		Use:   "passport-issue [agent-id]",
		Short: "Issue a W3C Verifiable Credential passport",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			agentID := args[0]
			data, err := apiPost(fmt.Sprintf("/agents/%s/credential", url.PathEscape(agentID)), map[string]any{})
			if err != nil {
				emitError("bob agent passport-issue", err)
				return nil
			}
			var resp any
			json.Unmarshal(data, &resp)
			emit(Envelope{
				OK:      true,
				Command: "bob agent passport-issue",
				Data:    resp,
				NextActions: []NextAction{
					{Command: fmt.Sprintf("bob agent passport-get %s", agentID), Description: "View your passport"},
				},
			})
			return nil
		},
	}
	cmd.AddCommand(passportIssueCmd)

	passportGetCmd := &cobra.Command{
		Use:   "passport-get [agent-id]",
		Short: "Get agent's latest active passport",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			agentID := args[0]
			data, err := apiGet(fmt.Sprintf("/agents/%s/credential", url.PathEscape(agentID)))
			if err != nil {
				emitError("bob agent passport-get", err)
				return nil
			}
			var resp any
			json.Unmarshal(data, &resp)
			emit(Envelope{
				OK:      true,
				Command: "bob agent passport-get",
				Data:    resp,
			})
			return nil
		},
	}
	cmd.AddCommand(passportGetCmd)

	// profile — subgroup for profile commands
	profileCmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage agent profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob agent profile",
				NextActions: []NextAction{
					{Command: "bob agent profile set --name <name>", Description: "Set your agent display name and handle"},
				},
			})
			return nil
		},
	}
	profileSetCmd := &cobra.Command{
		Use:   "set",
		Short: "Update agent profile (name, handle, description)",
		RunE:  agentProfileSet,
	}
	profileSetCmd.Flags().String("name", "", "Agent display name (seeds public handle)")
	profileSetCmd.Flags().String("bob-handle", "", "Public handle (lowercase, alphanumeric + hyphen/underscore/dot)")
	profileSetCmd.Flags().String("description", "", "Agent description")
	profileSetCmd.Flags().String("agent-id", "", "Agent ID (default: $BOB_AGENT_ID or config)")
	profileCmd.AddCommand(profileSetCmd)
	cmd.AddCommand(profileCmd)

	return cmd
}

func agentProfileSet(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	handle, _ := cmd.Flags().GetString("bob-handle")
	description, _ := cmd.Flags().GetString("description")

	name = strings.TrimSpace(name)
	handle = strings.TrimSpace(handle)
	description = strings.TrimSpace(description)

	if name == "" && handle == "" && description == "" {
		emitError("bob agent profile set", fmt.Errorf("provide at least one of --name, --bob-handle, or --description"))
		return nil
	}

	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitError("bob agent profile set", fmt.Errorf("could not determine agent ID — set BOB_AGENT_ID or pass --agent-id"))
		return nil
	}

	payload := map[string]any{}
	if name != "" {
		payload["name"] = name
		// Also set bob_handle from name if user didn't explicitly provide one.
		if handle == "" {
			payload["bob_handle"] = name
		}
	}
	if handle != "" {
		payload["bob_handle"] = handle
	}
	if description != "" {
		payload["description"] = description
	}

	data, err := apiPatch(fmt.Sprintf("/agents/%s/profile", agentID), payload)
	if err != nil {
		emitError("bob agent profile set", err)
		return nil
	}

	var resp any
	json.Unmarshal(data, &resp)

	emit(Envelope{
		OK:      true,
		Command: "bob agent profile set",
		Data:    resp,
		NextActions: []NextAction{
			{Command: fmt.Sprintf("bob agent get %s", agentID), Description: "View updated agent details"},
			{Command: "bob score me", Description: "Check your BOB Score"},
		},
	})
	return nil
}

func agentCredit(cmd *cobra.Command, args []string) error {
	emitErrorWithActions("bob agent credit",
		fmt.Errorf("'bob agent credit' has been removed — use 'bob score me' instead"),
		[]NextAction{
			{Command: "bob score me", Description: "View your BOB Score (replacement command)"},
		},
	)
	return nil
}

func agentMPPImport(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	method, _ := cmd.Flags().GetString("method")
	reference, _ := cmd.Flags().GetString("reference")
	challengeID, _ := cmd.Flags().GetString("challenge-id")
	challengeMethod, _ := cmd.Flags().GetString("challenge-method")
	challengeIntent, _ := cmd.Flags().GetString("challenge-intent")
	challengeRequest, _ := cmd.Flags().GetString("challenge-request")
	realm, _ := cmd.Flags().GetString("realm")
	source, _ := cmd.Flags().GetString("source")
	resourceURL, _ := cmd.Flags().GetString("resource-url")
	direction, _ := cmd.Flags().GetString("direction")

	if challengeMethod == "" {
		challengeMethod = method
	}

	payload := map[string]any{
		"receipt": map[string]any{
			"status":    "success",
			"method":    method,
			"reference": reference,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		},
		"credential": map[string]any{
			"challenge": map[string]any{
				"id":      challengeID,
				"method":  challengeMethod,
				"intent":  challengeIntent,
				"request": challengeRequest,
				"realm":   realm,
			},
			"source": source,
		},
		"resource_url": resourceURL,
		"direction":    direction,
	}

	path := fmt.Sprintf("/agents/%s/credit/imports/mpp-receipts", url.PathEscape(agentID))
	data, err := apiPost(path, payload)
	if err != nil {
		emitError("bob agent mpp-import", err)
		return nil
	}
	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("failed to parse MPP import response: %w", err)
	}
	emit(Envelope{
		OK:      true,
		Command: "bob agent mpp-import",
		Data:    resp,
		NextActions: []NextAction{
			{Command: fmt.Sprintf("bob agent credit-events %s", agentID), Description: "View credit history"},
			{Command: "bob score me", Description: "Check updated BOB Score"},
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
	rail, _ := cmd.Flags().GetString("rail")
	currency, _ := cmd.Flags().GetString("currency")
	amount, _ := cmd.Flags().GetInt64("amount")
	direction, _ := cmd.Flags().GetString("direction")
	occurredAt, _ := cmd.Flags().GetString("occurred-at")
	counterpartyRef, _ := cmd.Flags().GetString("counterparty-ref")
	senderAddress, _ := cmd.Flags().GetString("sender-address")
	recipientAddress, _ := cmd.Flags().GetString("recipient-address")

	proofType = strings.ToLower(strings.TrimSpace(proofType))
	proofRef = strings.TrimSpace(proofRef)
	txid = strings.ToLower(strings.TrimSpace(txid))

	if txid != "" {
		if proofType != "" || proofRef != "" {
			emitError("bob agent credit-import", fmt.Errorf("use either shortcut flags or --proof-type/--proof-ref"))
			return nil
		}
		proofRef = txid
	}
	if proofType == "" || proofRef == "" {
		emitError("bob agent credit-import", fmt.Errorf("proof is required: use --txid or --proof-type + --proof-ref"))
		return nil
	}
	defaultCurrency := ""
	switch proofType {
	case "btc_onchain_tx":
		defaultCurrency = "BTC"
	case "eth_onchain_tx", "base_onchain_tx":
		defaultCurrency = "ETH"
	case "sol_onchain_tx":
		defaultCurrency = "SOL"
	default:
		emitError("bob agent credit-import", fmt.Errorf("proof-type must be btc_onchain_tx, eth_onchain_tx, base_onchain_tx, or sol_onchain_tx"))
		return nil
	}
	rail = strings.ToLower(strings.TrimSpace(rail))
	if rail == "" {
		rail = "onchain"
	}
	if rail != "onchain" {
		emitError("bob agent credit-import", fmt.Errorf("rail must be onchain"))
		return nil
	}
	currency = strings.ToUpper(strings.TrimSpace(currency))
	if currency == "" {
		currency = defaultCurrency
	}
	if currency != defaultCurrency {
		emitError("bob agent credit-import", fmt.Errorf("currency must be %s for %s", defaultCurrency, proofType))
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
	if strings.TrimSpace(senderAddress) != "" {
		payload["sender_address"] = strings.TrimSpace(senderAddress)
	}
	if strings.TrimSpace(recipientAddress) != "" {
		payload["recipient_address"] = strings.TrimSpace(recipientAddress)
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
		{Command: "bob score me", Description: "View updated score/tier"},
	}
	if !creditAwarded {
		switch creditReason {
		case "self_counterparty_blocked":
			nextActions = append(nextActions, NextAction{
				Command:     fmt.Sprintf("bob agent credit-import %s --proof-type <type> --proof-ref <ref> --rail onchain --currency <%s> --amount <atomic-units> --direction outbound --counterparty-ref <external-counterparty>", agentID, defaultCurrency),
				Description: "Re-import using a non-self counterparty reference",
			})
		case "amount_below_credit_floor":
			nextActions = append(nextActions, NextAction{
				Command:     fmt.Sprintf("bob agent credit-import %s --proof-type <type> --proof-ref <ref> --rail onchain --currency <%s> --amount <higher-amount>", agentID, defaultCurrency),
				Description: "Re-import with an amount above the credit floor for that rail",
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

func agentX402Import(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	tx, _ := cmd.Flags().GetString("tx")
	network, _ := cmd.Flags().GetString("network")
	payer, _ := cmd.Flags().GetString("payer")
	payee, _ := cmd.Flags().GetString("payee")
	amount, _ := cmd.Flags().GetString("amount")
	asset, _ := cmd.Flags().GetString("asset")
	resourceURL, _ := cmd.Flags().GetString("resource-url")
	scheme, _ := cmd.Flags().GetString("scheme")
	x402Direction, _ := cmd.Flags().GetString("direction")

	tx = strings.TrimSpace(tx)
	if tx == "" {
		emitError("bob agent x402-import", fmt.Errorf("--tx is required (on-chain transaction hash)"))
		return nil
	}
	network = strings.TrimSpace(network)
	if network == "" {
		emitError("bob agent x402-import", fmt.Errorf("--network is required (CAIP-2 format, e.g. eip155:8453)"))
		return nil
	}
	payer = strings.TrimSpace(payer)
	if payer == "" {
		emitError("bob agent x402-import", fmt.Errorf("--payer is required (payer wallet address)"))
		return nil
	}
	payee = strings.TrimSpace(payee)
	if payee == "" {
		emitError("bob agent x402-import", fmt.Errorf("--payee is required (payee/service wallet address)"))
		return nil
	}
	amount = strings.TrimSpace(amount)
	if amount == "" {
		emitError("bob agent x402-import", fmt.Errorf("--amount is required (atomic units)"))
		return nil
	}

	x402Direction = strings.ToLower(strings.TrimSpace(x402Direction))
	if x402Direction == "" {
		x402Direction = "outbound"
	}
	if x402Direction != "outbound" && x402Direction != "inbound" {
		emitError("bob agent x402-import", fmt.Errorf("direction must be outbound or inbound"))
		return nil
	}

	payload := map[string]any{
		"resource_url": resourceURL,
		"direction":    x402Direction,
		"requirements": map[string]any{
			"scheme":            scheme,
			"network":           network,
			"amount":            amount,
			"asset":             asset,
			"payTo":             payee,
			"maxTimeoutSeconds": 60,
		},
		"authorization": map[string]any{
			"from":  payer,
			"to":    payee,
			"value": amount,
		},
		"settlement": map[string]any{
			"success":     true,
			"transaction": tx,
			"network":     network,
			"payer":       payer,
		},
	}

	data, err := apiPost("/agents/"+url.PathEscape(agentID)+"/credit/imports/x402-receipts", payload)
	if err != nil {
		emitErrorWithActions("bob agent x402-import", err, []NextAction{
			{Command: fmt.Sprintf("bob agent credit-imports %s", agentID), Description: "List imported proofs"},
			{Command: fmt.Sprintf("bob agent credit-events %s", agentID), Description: "Inspect credit event timeline"},
		})
		return nil
	}
	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("failed to parse x402 import response: %w", err)
	}

	creditData, _ := resp["credit"].(map[string]any)
	creditAwarded, _ := creditData["awarded"].(bool)
	creditReason, _ := creditData["reason"].(string)
	nextActions := []NextAction{
		{Command: fmt.Sprintf("bob agent credit-imports %s", agentID), Description: "List imported proofs"},
		{Command: fmt.Sprintf("bob agent credit-events %s", agentID), Description: "Check if credit increased"},
		{Command: "bob score me", Description: "View updated score/tier"},
	}
	if !creditAwarded && creditReason != "" {
		switch creditReason {
		case "amount_below_credit_floor":
			nextActions = append(nextActions, NextAction{
				Command:     fmt.Sprintf("bob agent x402-import %s --tx <hash> --network %s --payer %s --payee %s --amount <higher-amount>", agentID, network, payer, payee),
				Description: "Re-import with an amount above the USDC credit floor ($0.10)",
			})
		case "credit_cap_reached":
			nextActions = append(nextActions, NextAction{
				Command:     "bob score me",
				Description: "Credit cap reached for this rail — check overall score",
			})
		}
	}
	emit(Envelope{
		OK:          true,
		Command:     "bob agent x402-import",
		Data:        resp,
		NextActions: nextActions,
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
			{Command: "bob score me", Description: "Check credit score and tier"},
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
			{Command: "bob score me", Description: "View credit score and tier"},
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
		{Command: "bob score me", Description: "View credit score and tier"},
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
		Short: "BOB Score — operator reputation and trust signals",
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
		Short: "View your BOB Score and trust signals",
		RunE: func(cmd *cobra.Command, args []string) error {
			scoreData, err := apiGet("/score/me")
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
					{Command: "bob score composition", Description: "View score component breakdown"},
					{Command: "bob score leaderboard", Description: "Compare against the public leaderboard"},
				},
			})
			return nil
		},
	})
	compositionCmd := &cobra.Command{
		Use:   "composition",
		Short: "Breakdown of score components",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := apiGet("/score/me/composition")
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
		Use:   "signals",
		Short: "Set public visibility for a trust signal",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			signal, _ := cmd.Flags().GetString("signal")
			visible, _ := cmd.Flags().GetBool("visible")
			data, err := apiPatch("/score/me/signals/visibility", map[string]any{
				"signal_type": strings.TrimSpace(signal),
				"is_public":   visible,
			})
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
	signalsCmd.Flags().String("signal", "", "Signal type to update (required)")
	signalsCmd.Flags().Bool("visible", false, "Whether the signal should be publicly visible")
	signalsCmd.MarkFlagRequired("signal")
	signalsCmd.MarkFlagRequired("visible")
	cmd.AddCommand(signalsCmd)
	return cmd
}

// --- binding command ---

func bindingCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "binding",
		Short: "Bind an operator wallet as a BOB Score trust signal",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob binding",
				Data:    childCommandInfo(commandTree(), "binding"),
				NextActions: []NextAction{
					{Command: "bob binding challenge --rail evm --address <0x...>", Description: "Create a wallet ownership challenge (evm, btc, or solana)"},
				},
			})
			return nil
		},
	}

	// Generic challenge/verify for any rail (btc, solana, etc.)
	challengeCmd := &cobra.Command{
		Use:   "challenge",
		Short: "Create a wallet ownership challenge for any rail",
		Args:  cobra.NoArgs,
		RunE:  operatorGenericBindChallenge,
	}
	challengeCmd.Flags().String("rail", "", "Rail: evm, btc, or solana (required)")
	challengeCmd.Flags().String("address", "", "Wallet address (required)")
	challengeCmd.MarkFlagRequired("rail")
	challengeCmd.MarkFlagRequired("address")
	cmd.AddCommand(challengeCmd)

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a wallet ownership challenge with a signature",
		Args:  cobra.NoArgs,
		RunE:  operatorGenericBindVerify,
	}
	verifyCmd.Flags().String("rail", "", "Rail: evm, btc, or solana (required)")
	verifyCmd.Flags().String("challenge-id", "", "Challenge id (required)")
	verifyCmd.Flags().String("address", "", "Wallet address (required)")
	verifyCmd.Flags().String("signature", "", "Signature over challenge message (required)")
	verifyCmd.Flags().String("chain-id", "", "Optional hex chain id (EVM only, e.g. 0x1 or 0x2105)")
	verifyCmd.Flags().String("wallet-type", "", "Optional wallet type for EVM only (e.g. coinbase)")
	verifyCmd.MarkFlagRequired("rail")
	verifyCmd.MarkFlagRequired("challenge-id")
	verifyCmd.MarkFlagRequired("address")
	verifyCmd.MarkFlagRequired("signature")
	cmd.AddCommand(verifyCmd)

	return cmd
}
// --- Generic wallet binding handlers (any rail) ---

func normalizeBindingRail(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "evm":
		return "evm", nil
	case "btc", "bitcoin":
		return "btc", nil
	case "sol", "solana":
		return "solana", nil
	default:
		return "", fmt.Errorf("rail must be evm, btc, or solana")
	}
}

func operatorGenericBindChallenge(cmd *cobra.Command, args []string) error {
	railRaw, _ := cmd.Flags().GetString("rail")
	address, _ := cmd.Flags().GetString("address")
	rail, err := normalizeBindingRail(railRaw)
	if err != nil {
		emitError("bob binding challenge", err)
		return nil
	}
	address = strings.TrimSpace(address)

	data, err := apiPost(fmt.Sprintf("/operators/me/wallet-bindings/%s/challenge", url.PathEscape(rail)), map[string]any{
		"address": address,
	})
	if err != nil {
		emitErrorWithActions("bob binding challenge", err, []NextAction{
			{Command: "bob auth me", Description: "Verify operator credentials"},
		})
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob binding challenge",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: fmt.Sprintf("bob binding verify --rail %s --challenge-id <id> --address %s --signature <sig>", rail, address), Description: "Sign the challenge message and submit"},
		},
	})
	return nil
}

func operatorGenericBindVerify(cmd *cobra.Command, args []string) error {
	railRaw, _ := cmd.Flags().GetString("rail")
	challengeID, _ := cmd.Flags().GetString("challenge-id")
	address, _ := cmd.Flags().GetString("address")
	signature, _ := cmd.Flags().GetString("signature")
	chainID, _ := cmd.Flags().GetString("chain-id")
	walletType, _ := cmd.Flags().GetString("wallet-type")
	rail, err := normalizeBindingRail(railRaw)
	if err != nil {
		emitError("bob binding verify", err)
		return nil
	}
	chainID = strings.TrimSpace(chainID)
	walletType = strings.TrimSpace(strings.ToLower(walletType))

	payload := map[string]any{
		"challenge_id": strings.TrimSpace(challengeID),
		"address":      strings.TrimSpace(address),
		"signature":    strings.TrimSpace(signature),
	}
	if chainID != "" && rail == "evm" {
		payload["chain_id"] = chainID
	}
	if walletType != "" && rail == "evm" {
		payload["wallet_type"] = walletType
	}

	data, err := apiPost(fmt.Sprintf("/operators/me/wallet-bindings/%s/verify", url.PathEscape(rail)), payload)
	if err != nil {
		emitErrorWithActions("bob binding verify", err, []NextAction{
			{Command: fmt.Sprintf("bob binding challenge --rail %s --address %s", rail, address), Description: "Create a fresh challenge"},
		})
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob binding verify",
		Data:    json.RawMessage(data),
		NextActions: []NextAction{
			{Command: "bob score me", Description: "Check updated BOB Score"},
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

	// bob inbox check — generic command queue processor
	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Process pending operator commands",
		Long: `Polls the agent command queue and processes pending commands.

Three modes:
  (default)              Single check, exit. For cron/heartbeat/skill triggers.
  --poll                 Blocking loop. For Docker/server agents.
  --interval 30s         Polling interval (default 30s, only with --poll).

Examples:
  bob inbox check                              # single check
  bob inbox check --poll                       # blocking loop
  bob inbox check --poll --interval 10s        # custom interval`,
		RunE: runInboxCheck,
	}
	checkCmd.Flags().String("agent-id", "", "Agent ID (defaults to config agent_id)")
	checkCmd.Flags().Bool("once", false, "Single check then exit (default behavior)")
	checkCmd.Flags().Bool("poll", false, "Blocking loop — check repeatedly")
	checkCmd.Flags().Duration("interval", 30*time.Second, "Polling interval (with --poll)")
	cmd.AddCommand(checkCmd)

	return cmd
}

// ---------------------------------------------------------------------------
// bob directory — search and discover agents on the network
// ---------------------------------------------------------------------------

func directoryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "directory",
		Short: "Search and discover agents on the BOB network",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob directory",
				Data:    childCommandInfo(commandTree(), "directory"),
				NextActions: []NextAction{
					{Command: "bob directory search --query <handle>", Description: "Search for agents"},
					{Command: "bob directory lookup <handle>", Description: "View an agent's public card"},
				},
			})
			return nil
		},
	}

	searchCmd := &cobra.Command{
		Use:   "search",
		Short: "Search agents by handle, score, or tier",
		RunE: func(cmd *cobra.Command, args []string) error {
			q, _ := cmd.Flags().GetString("query")
			minScore, _ := cmd.Flags().GetInt("min-score")
			tier, _ := cmd.Flags().GetString("tier")
			limit, _ := cmd.Flags().GetInt("limit")

			params := fmt.Sprintf("/public/directory?limit=%d", limit)
			if q != "" {
				params += "&q=" + url.QueryEscape(q)
			}
			if minScore > 0 {
				params += fmt.Sprintf("&min_score=%d", minScore)
			}
			if tier != "" {
				params += "&tier=" + url.QueryEscape(tier)
			}

			data, err := apiGet(params)
			if err != nil {
				emitError("bob directory search", err)
				return nil
			}
			var resp any
			_ = json.Unmarshal(data, &resp)
			emit(Envelope{
				OK:      true,
				Command: "bob directory search",
				Data:    resp,
				NextActions: []NextAction{
					{Command: "bob directory lookup <handle>", Description: "View an agent's public card"},
					{Command: "bob message send <handle> \"hello\"", Description: "Send a message to an agent"},
				},
			})
			return nil
		},
	}
	searchCmd.Flags().StringP("query", "q", "", "Search by handle (partial match)")
	searchCmd.Flags().Int("min-score", 0, "Minimum BOB Score")
	searchCmd.Flags().String("tier", "", "Filter by tier (e.g. Verified, Trusted)")
	searchCmd.Flags().Int("limit", 20, "Max results")
	cmd.AddCommand(searchCmd)

	lookupCmd := &cobra.Command{
		Use:   "lookup [handle]",
		Short: "View an agent's public card",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			showLedger, _ := cmd.Flags().GetBool("ledger")
			handle := strings.TrimPrefix(args[0], "@")
			path := fmt.Sprintf("/public/handle/%s/card", url.PathEscape(handle))
			commandName := "bob directory lookup"
			if showLedger {
				path = fmt.Sprintf("/public/handle/%s/ledger", url.PathEscape(handle))
				commandName = "bob directory lookup --ledger"
			}
			data, err := apiGet(path)
			if err != nil {
				emitError("bob directory lookup", err)
				return nil
			}
			var resp any
			_ = json.Unmarshal(data, &resp)
			emit(Envelope{
				OK:      true,
				Command: commandName,
				Data:    resp,
				NextActions: []NextAction{
					{Command: fmt.Sprintf("bob message send %s \"hello\"", handle), Description: "Send a message"},
					{Command: fmt.Sprintf("bob directory lookup %s --ledger", handle), Description: "View transaction ledger"},
				},
			})
			return nil
		},
	}
	lookupCmd.Flags().Bool("ledger", false, "Show public ledger instead of the card")
	cmd.AddCommand(lookupCmd)

	return cmd
}

// ---------------------------------------------------------------------------
// bob message — send and read agent-to-agent messages
// ---------------------------------------------------------------------------

func messageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "message",
		Short: "Send and read agent-to-agent messages",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob message",
				Data:    childCommandInfo(commandTree(), "message"),
				NextActions: []NextAction{
					{Command: "bob message send <handle> \"body\"", Description: "Send a message to another agent"},
					{Command: "bob message list", Description: "List messages for your agent"},
				},
			})
			return nil
		},
	}

	sendCmd := &cobra.Command{
		Use:   "send [recipient-handle] [body]",
		Short: "Send a message to another agent",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			recipientHandle := strings.TrimPrefix(args[0], "@")
			body := args[1]
			isPublic, _ := cmd.Flags().GetBool("public")
			proofID, _ := cmd.Flags().GetString("proof")

			cfg, err := loadCLIConfig()
			if err != nil || cfg.AgentID == "" {
				emitError("bob message send", fmt.Errorf("no agent configured — run bob init first"))
				return nil
			}

			payload := map[string]any{
				"recipient_handle": recipientHandle,
				"body":             body,
				"is_public":        isPublic,
			}
			if proofID != "" {
				payload["proof_import_id"] = proofID
			}

			data, err := apiPost(fmt.Sprintf("/agents/%s/messages", url.PathEscape(cfg.AgentID)), payload)
			if err != nil {
				emitError("bob message send", err)
				return nil
			}
			var resp any
			_ = json.Unmarshal(data, &resp)
			emit(Envelope{
				OK:      true,
				Command: "bob message send",
				Data:    resp,
				NextActions: []NextAction{
					{Command: "bob message list", Description: "View your message history"},
				},
			})
			return nil
		},
	}
	sendCmd.Flags().Bool("public", false, "Make message visible on the public feed")
	sendCmd.Flags().String("proof", "", "Link message to a proof import ID")
	cmd.AddCommand(sendCmd)

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List messages for your agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadCLIConfig()
			if err != nil || cfg.AgentID == "" {
				emitError("bob message list", fmt.Errorf("no agent configured — run bob init first"))
				return nil
			}
			limit, _ := cmd.Flags().GetInt("limit")
			inbox, _ := cmd.Flags().GetBool("inbox")

			if inbox {
				data, err := apiGet(fmt.Sprintf("/agents/%s/inbox?limit=%d&offset=0", url.PathEscape(cfg.AgentID), limit))
				if err != nil {
					emitError("bob message list", err)
					return nil
				}
				var resp any
				_ = json.Unmarshal(data, &resp)
				emit(Envelope{
					OK:      true,
					Command: "bob message list --inbox",
					Data:    resp,
					NextActions: []NextAction{
						{Command: fmt.Sprintf("bob inbox ack %s <event-id>", cfg.AgentID), Description: "Acknowledge inbox events"},
					},
				})
				return nil
			}

			agentData, err := apiGet(fmt.Sprintf("/agents/%s", url.PathEscape(cfg.AgentID)))
			if err != nil {
				emitError("bob message list", err)
				return nil
			}
			var agent struct {
				BobHandle string `json:"bob_handle"`
			}
			_ = json.Unmarshal(agentData, &agent)

			if agent.BobHandle == "" {
				emitError("bob message list", fmt.Errorf("agent has no handle — set one with bob agent update"))
				return nil
			}

			data, err := apiGet(fmt.Sprintf("/public/handle/%s/messages?limit=%d", url.PathEscape(agent.BobHandle), limit))
			if err != nil {
				emitError("bob message list", err)
				return nil
			}
			var resp any
			_ = json.Unmarshal(data, &resp)
			emit(Envelope{
				OK:      true,
				Command: "bob message list",
				Data:    resp,
			})
			return nil
		},
	}
	listCmd.Flags().Int("limit", 30, "Max results")
	listCmd.Flags().Bool("inbox", false, "List private inbox events instead of public messages")
	cmd.AddCommand(listCmd)

	feedCmd := &cobra.Command{
		Use:   "feed",
		Short: "View the public network-wide message feed",
		RunE: func(cmd *cobra.Command, args []string) error {
			limit, _ := cmd.Flags().GetInt("limit")
			data, err := apiGet(fmt.Sprintf("/public/feed?limit=%d", limit))
			if err != nil {
				emitError("bob message feed", err)
				return nil
			}
			var resp any
			_ = json.Unmarshal(data, &resp)
			emit(Envelope{
				OK:      true,
				Command: "bob message feed",
				Data:    resp,
				NextActions: []NextAction{
					{Command: "bob directory lookup <handle>", Description: "Look up an agent from the feed"},
				},
			})
			return nil
		},
	}
	feedCmd.Flags().Int("limit", 30, "Max results")
	cmd.AddCommand(feedCmd)

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

// ---------------------------------------------------------------------------
// Auto-passport: generate Ed25519 key, bind, issue passport during init
// ---------------------------------------------------------------------------
// Wallet commands: bob wallet {list, balance, credit-limit, register}
// ---------------------------------------------------------------------------

type walletInitResult struct {
	evmAddress string
	btcAddress string
	solAddress string
	err        string
}

func autoGenerateAndRegisterWallets(agentID string) walletInitResult {
	cfg, loadErr := loadCLIConfig()

	// If this agent already has keys in the keyring, reuse them.
	if loadErr == nil && cfg.AgentID == agentID {
		if existing := cfg.activeWalletKeys(); existing != nil && existing.EVMAddress != "" {
			registerWalletBestEffort(agentID, "evm", existing.EVMAddress)
			registerWalletBestEffort(agentID, "btc", existing.BTCAddress)
			registerWalletBestEffort(agentID, "solana", existing.SOLAddress)
			return walletInitResult{
				evmAddress: existing.EVMAddress,
				btcAddress: existing.BTCAddress,
				solAddress: existing.SOLAddress,
			}
		}
	}

	// Migrate wallet keys from the most recently created previous agent.
	// Security note: this shares private keys across agent identities. The assumption
	// is that killed agents under the same operator are being replaced, not compromised.
	// If the old agent was killed for cause, the operator should generate fresh keys
	// by deleting ~/.config/bob/config.json before running bob init.
	if migrated := migrateWalletKeys(&cfg, agentID); migrated != nil {
		if writeErr := writeCLIConfig(cliConfigPath(), cfg); writeErr != nil {
			return walletInitResult{err: "wallet: failed to save migrated keys: " + writeErr.Error()}
		}
		registerWalletBestEffort(agentID, "evm", migrated.EVMAddress)
		registerWalletBestEffort(agentID, "btc", migrated.BTCAddress)
		registerWalletBestEffort(agentID, "solana", migrated.SOLAddress)
		return walletInitResult{
			evmAddress: migrated.EVMAddress,
			btcAddress: migrated.BTCAddress,
			solAddress: migrated.SOLAddress,
		}
	}

	// New agent or first init — generate fresh keys.
	// Old agent keys stay in the keyring and are never lost.
	btcHRP := "bc"
	loweredBase := strings.ToLower(apiBase)
	if strings.Contains(loweredBase, "localhost") || strings.Contains(loweredBase, "127.0.0.1") {
		btcHRP = "bcrt"
	} else if strings.Contains(loweredBase, "testnet") {
		btcHRP = "tb"
	}

	keys, err := generateWalletKeys(btcHRP)
	if err != nil {
		return walletInitResult{err: "wallet: keygen failed: " + err.Error()}
	}

	// Persist to per-agent keyring. Old agent keys are preserved.
	if loadErr == nil {
		if cfg.WalletKeyring == nil {
			cfg.WalletKeyring = make(map[string]agentWalletKeys)
		}
		cfg.WalletKeyring[agentID] = agentWalletKeys{
			EVMPrivateKey: keys.EVMPrivateKey, EVMAddress: keys.EVMAddress,
			BTCPrivateKey: keys.BTCPrivateKey, BTCAddress: keys.BTCAddress,
			SOLPrivateKey: keys.SOLPrivateKey, SOLAddress: keys.SOLAddress,
		}
		// Also update legacy flat fields for backwards compat with older CLIs.
		cfg.EVMPrivateKey = keys.EVMPrivateKey
		cfg.EVMAddress = keys.EVMAddress
		cfg.BTCPrivateKey = keys.BTCPrivateKey
		cfg.BTCAddress = keys.BTCAddress
		cfg.SOLPrivateKey = keys.SOLPrivateKey
		cfg.SOLAddress = keys.SOLAddress
		if writeErr := writeCLIConfig(cliConfigPath(), cfg); writeErr != nil {
			return walletInitResult{err: "wallet: failed to save keys to config: " + writeErr.Error()}
		}
	}

	// Register with BOB (best-effort — 409 is fine, 403 means no trust signal yet)
	var regWarnings []string
	for _, entry := range []struct{ rail, addr string }{
		{"evm", keys.EVMAddress},
		{"btc", keys.BTCAddress},
		{"solana", keys.SOLAddress},
	} {
		if w := registerWalletBestEffort(agentID, entry.rail, entry.addr); w != "" {
			regWarnings = append(regWarnings, w)
		}
	}

	result := walletInitResult{
		evmAddress: keys.EVMAddress,
		btcAddress: keys.BTCAddress,
		solAddress: keys.SOLAddress,
	}
	if len(regWarnings) > 0 {
		result.err = "wallet registration: " + strings.Join(regWarnings, "; ")
	}
	return result
}

// migrateWalletKeys finds wallet keys from a previous agent in the keyring and
// migrates them to the new agent ID. Returns the migrated keys or nil if none found.
// Cleans up the old keyring entry to prevent re-migration.
func migrateWalletKeys(cfg *cliConfig, newAgentID string) *agentWalletKeys {
	if cfg.WalletKeyring == nil {
		return nil
	}

	// Find the best candidate: pick the most recent entry (highest ID lexically).
	// In practice there's usually only one other entry.
	var bestID string
	var bestKeys agentWalletKeys
	for oldID, oldKeys := range cfg.WalletKeyring {
		if oldID == newAgentID || oldKeys.EVMAddress == "" {
			continue
		}
		if bestID == "" || oldID > bestID {
			bestID = oldID
			bestKeys = oldKeys
		}
	}
	if bestID == "" {
		return nil
	}

	fmt.Fprintf(os.Stderr, "\n  ⚠ WALLET KEY MIGRATION: reusing keys from agent %s for new agent %s\n", bestID, newAgentID)
	fmt.Fprintf(os.Stderr, "    EVM: %s | BTC: %s | SOL: %s\n", bestKeys.EVMAddress, bestKeys.BTCAddress, bestKeys.SOLAddress)
	fmt.Fprintf(os.Stderr, "    If the previous agent was compromised, delete ~/.config/bob/config.json and re-run bob init.\n\n")

	// Copy to new agent, remove old entry
	cfg.WalletKeyring[newAgentID] = bestKeys
	delete(cfg.WalletKeyring, bestID)

	// Update legacy flat fields
	cfg.EVMPrivateKey = bestKeys.EVMPrivateKey
	cfg.EVMAddress = bestKeys.EVMAddress
	cfg.BTCPrivateKey = bestKeys.BTCPrivateKey
	cfg.BTCAddress = bestKeys.BTCAddress
	cfg.SOLPrivateKey = bestKeys.SOLPrivateKey
	cfg.SOLAddress = bestKeys.SOLAddress

	return &bestKeys
}

func registerWalletBestEffort(agentID, rail, address string) string {
	if address == "" {
		return ""
	}
	_, err := apiPost(fmt.Sprintf("/agents/%s/wallets", url.PathEscape(agentID)), map[string]any{
		"rail":    rail,
		"address": address,
	})
	if err == nil {
		return ""
	}
	// 409 (duplicate) is expected on re-init — don't warn
	if strings.Contains(err.Error(), "409") {
		return ""
	}
	// 403 (no trust signal) is expected before wallet binding — gentle hint
	if strings.Contains(err.Error(), "403") {
		return fmt.Sprintf("%s: bind wallet first (bob binding challenge --rail %s --address <addr>)", rail, rail)
	}
	return fmt.Sprintf("%s: %s", rail, extractAPIErrorMessage(err))
}

func walletCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wallet",
		Short: "Manage agent wallets (non-custodial)",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob wallet",
				Data: map[string]any{
					"subcommands": []string{"list", "balance", "credit-limit", "register", "addresses"},
				},
				NextActions: []NextAction{
					{Command: "bob wallet list", Description: "List registered wallets for an agent"},
					{Command: "bob wallet balance", Description: "Show proven balance from verified proofs"},
					{Command: "bob wallet credit-limit", Description: "Show computed credit limit"},
					{Command: "bob wallet addresses", Description: "Show locally generated wallet addresses"},
				},
			})
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// bob wallet list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List registered wallets for an agent",
		RunE:  runWalletList,
	}
	listCmd.Flags().String("agent-id", "", "Agent ID (defaults to config agent_id)")
	cmd.AddCommand(listCmd)

	// bob wallet balance
	balanceCmd := &cobra.Command{
		Use:   "balance",
		Short: "Show proven balance from verified payment proofs",
		RunE:  runWalletBalance,
	}
	balanceCmd.Flags().String("agent-id", "", "Agent ID (defaults to config agent_id)")
	cmd.AddCommand(balanceCmd)

	// bob wallet credit-limit
	creditCmd := &cobra.Command{
		Use:   "credit-limit",
		Short: "Show computed credit limit (score × balance × age)",
		RunE:  runWalletCreditLimit,
	}
	creditCmd.Flags().String("agent-id", "", "Agent ID (defaults to config agent_id)")
	cmd.AddCommand(creditCmd)

	// bob wallet register
	registerCmd := &cobra.Command{
		Use:   "register",
		Short: "Register a wallet address for an agent",
		RunE:  runWalletRegister,
	}
	registerCmd.Flags().String("agent-id", "", "Agent ID (defaults to config agent_id)")
	registerCmd.Flags().String("rail", "", "Chain rail: evm, btc, or solana")
	registerCmd.Flags().String("address", "", "Wallet address to register")
	registerCmd.MarkFlagRequired("rail")
	registerCmd.MarkFlagRequired("address")
	cmd.AddCommand(registerCmd)

	// bob wallet addresses
	addressesCmd := &cobra.Command{
		Use:   "addresses",
		Short: "Show locally generated wallet addresses (from config)",
		RunE:  runWalletAddresses,
	}
	cmd.AddCommand(addressesCmd)

	// bob wallet provision-check
	provisionCheckCmd := &cobra.Command{
		Use:   "provision-check",
		Short: "Check for and fulfill pending wallet provision requests",
		Long: `Three modes:
  --once (default)     Single check, exit. For cron/heartbeat/skill triggers.
  --poll               Blocking loop. For Docker/server agents.
  --interval 30s       Polling interval (default 30s, only with --poll).

Examples:
  bob wallet provision-check --once              # cron/heartbeat
  bob wallet provision-check --poll              # long-running agent
  bob wallet provision-check --poll --interval 10s`,
		RunE: runWalletProvisionCheck,
	}
	provisionCheckCmd.Flags().String("agent-id", "", "Agent ID (defaults to config agent_id)")
	provisionCheckCmd.Flags().Bool("once", false, "Single check then exit (default behavior)")
	provisionCheckCmd.Flags().Bool("poll", false, "Blocking loop — check repeatedly")
	provisionCheckCmd.Flags().Duration("interval", 30*time.Second, "Polling interval (with --poll)")
	cmd.AddCommand(provisionCheckCmd)

	return cmd
}

func resolveAgentID(cmd *cobra.Command) string {
	if id, _ := cmd.Flags().GetString("agent-id"); strings.TrimSpace(id) != "" {
		return strings.TrimSpace(id)
	}
	cfg, err := loadCLIConfig()
	if err == nil && strings.TrimSpace(cfg.AgentID) != "" {
		return strings.TrimSpace(cfg.AgentID)
	}
	return strings.TrimSpace(os.Getenv("BOB_AGENT_ID"))
}

func resolveEVMWallet() string {
	cfg, err := loadCLIConfig()
	if err != nil {
		return ""
	}
	agentID := strings.TrimSpace(cfg.AgentID)
	if agentID == "" {
		agentID = strings.TrimSpace(os.Getenv("BOB_AGENT_ID"))
	}
	if agentID != "" {
		if keys, ok := cfg.WalletKeyring[agentID]; ok && keys.EVMAddress != "" {
			return keys.EVMAddress
		}
	}
	// Legacy flat field.
	if cfg.EVMAddress != "" {
		return cfg.EVMAddress
	}
	return ""
}

var noAgentIDActions = []NextAction{
	{Command: "bob init --code <claim-code>", Description: "Initialize agent session (sets agent_id in config)"},
	{Command: "export BOB_AGENT_ID=<agent-id>", Description: "Set agent ID via environment variable"},
}

func runWalletList(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob wallet list", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	resp, err := apiGet(fmt.Sprintf("/agents/%s/wallets", url.PathEscape(agentID)))
	if err != nil {
		emitError("bob wallet list", err)
		return nil
	}

	var wallets []json.RawMessage
	if err := json.Unmarshal(resp, &wallets); err != nil {
		emitError("bob wallet list", fmt.Errorf("failed to parse wallets: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob wallet list",
		Data: map[string]any{
			"agent_id": agentID,
			"wallets":  wallets,
			"count":    len(wallets),
		},
		NextActions: []NextAction{
			{Command: "bob wallet balance --agent-id " + agentID, Description: "View proven balance"},
			{Command: "bob wallet credit-limit --agent-id " + agentID, Description: "View credit limit"},
		},
	})
	return nil
}

func runWalletBalance(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob wallet balance", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	resp, err := apiGet(fmt.Sprintf("/agents/%s/balance", url.PathEscape(agentID)))
	if err != nil {
		emitError("bob wallet balance", err)
		return nil
	}

	var result json.RawMessage
	if err := json.Unmarshal(resp, &result); err != nil {
		emitError("bob wallet balance", fmt.Errorf("failed to parse balance: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob wallet balance",
		Data: map[string]any{
			"agent_id": agentID,
			"balance":  result,
		},
		NextActions: []NextAction{
			{Command: "bob wallet credit-limit --agent-id " + agentID, Description: "View credit limit"},
			{Command: "bob wallet list --agent-id " + agentID, Description: "List registered wallets"},
		},
	})
	return nil
}

func runWalletCreditLimit(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob wallet credit-limit", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	resp, err := apiGet(fmt.Sprintf("/agents/%s/credit-limit", url.PathEscape(agentID)))
	if err != nil {
		emitError("bob wallet credit-limit", err)
		return nil
	}

	var result json.RawMessage
	if err := json.Unmarshal(resp, &result); err != nil {
		emitError("bob wallet credit-limit", fmt.Errorf("failed to parse credit limit: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob wallet credit-limit",
		Data: map[string]any{
			"agent_id":     agentID,
			"credit_limit": result,
		},
		NextActions: []NextAction{
			{Command: "bob wallet balance --agent-id " + agentID, Description: "View proven balance"},
			{Command: "bob wallet list --agent-id " + agentID, Description: "List registered wallets"},
		},
	})
	return nil
}

func runWalletRegister(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob wallet register", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	rail, _ := cmd.Flags().GetString("rail")
	address, _ := cmd.Flags().GetString("address")

	resp, err := apiPost(fmt.Sprintf("/agents/%s/wallets", url.PathEscape(agentID)), map[string]any{
		"rail":    strings.ToLower(strings.TrimSpace(rail)),
		"address": strings.TrimSpace(address),
	})
	if err != nil {
		emitError("bob wallet register", err)
		return nil
	}

	var wallet json.RawMessage
	if err := json.Unmarshal(resp, &wallet); err != nil {
		emitError("bob wallet register", fmt.Errorf("failed to parse wallet: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob wallet register",
		Data: map[string]any{
			"agent_id": agentID,
			"wallet":   wallet,
		},
		NextActions: []NextAction{
			{Command: "bob wallet list --agent-id " + agentID, Description: "List all registered wallets"},
		},
	})
	return nil
}

func runWalletAddresses(cmd *cobra.Command, args []string) error {
	cfg, err := loadCLIConfig()
	if err != nil {
		emitError("bob wallet addresses", fmt.Errorf("failed to load config: %w", err))
		return nil
	}

	if cfg.EVMAddress == "" && cfg.BTCAddress == "" && cfg.SOLAddress == "" {
		emitError("bob wallet addresses", fmt.Errorf("no wallet keys found in config — run bob init to generate"))
		return nil
	}

	addresses := map[string]any{}
	if cfg.EVMAddress != "" {
		addresses["evm"] = map[string]any{
			"address": cfg.EVMAddress,
			"chains":  []string{"Ethereum", "Base (USDC)"},
		}
	}
	if cfg.BTCAddress != "" {
		addresses["btc"] = map[string]any{
			"address": cfg.BTCAddress,
			"chains":  []string{"Bitcoin (bech32)"},
		}
	}
	if cfg.SOLAddress != "" {
		addresses["solana"] = map[string]any{
			"address": cfg.SOLAddress,
			"chains":  []string{"Solana"},
		}
	}

	emit(Envelope{
		OK:      true,
		Command: "bob wallet addresses",
		Data: map[string]any{
			"config_file": activeCLIConfigPath(),
			"addresses":   addresses,
		},
		NextActions: []NextAction{
			{Command: "bob wallet list", Description: "List wallets registered with BOB"},
			{Command: "bob wallet balance", Description: "View proven balance"},
		},
	})
	return nil
}

// runWalletProvisionCheck is an alias for bob inbox check — kept for backward compat.
func runWalletProvisionCheck(cmd *cobra.Command, args []string) error {
	return runInboxCheck(cmd, args)
}

// ---------------------------------------------------------------------------
// bob inbox check — generic command queue processor
// ---------------------------------------------------------------------------

func runInboxCheck(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob inbox check", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	poll, _ := cmd.Flags().GetBool("poll")
	interval, _ := cmd.Flags().GetDuration("interval")
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}

	if poll {
		fmt.Fprintf(os.Stderr, "polling for commands every %s (ctrl+c to stop)\n", interval)
		for {
			inboxCheckOnce(agentID)
			time.Sleep(interval)
		}
	}

	inboxCheckOnce(agentID)
	return nil
}

func inboxCheckOnce(agentID string) {
	resp, err := apiGet(fmt.Sprintf("/agents/%s/commands?status=pending", url.PathEscape(agentID)))
	if err != nil {
		emitError("bob inbox check", err)
		return
	}

	var commands []struct {
		ID          string `json:"id"`
		CommandType string `json:"command_type"`
		Payload     string `json:"payload"`
	}
	_ = json.Unmarshal(resp, &commands)

	if len(commands) == 0 {
		emit(Envelope{
			OK:      true,
			Command: "bob inbox check",
			Data:    map[string]any{"pending": 0, "message": "no pending commands"},
		})
		return
	}

	var processed []map[string]any
	var failed []map[string]any

	for _, cmd := range commands {
		switch cmd.CommandType {
		case "wallet.provision":
			result, err := handleWalletProvisionCommand(agentID, cmd.ID, cmd.Payload)
			if err != nil {
				failed = append(failed, map[string]any{
					"command_id":   cmd.ID,
					"command_type": cmd.CommandType,
					"error":        err.Error(),
				})
				// Mark as failed
				_, _ = apiPatch(fmt.Sprintf("/agents/%s/commands/%s", url.PathEscape(agentID), url.PathEscape(cmd.ID)),
					map[string]any{"status": "failed", "error_msg": err.Error()})
			} else {
				processed = append(processed, result)
			}
		default:
			failed = append(failed, map[string]any{
				"command_id":   cmd.ID,
				"command_type": cmd.CommandType,
				"error":        "unknown command type",
			})
		}
	}

	emit(Envelope{
		OK:      true,
		Command: "bob inbox check",
		Data: map[string]any{
			"processed": processed,
			"failed":    failed,
		},
		NextActions: []NextAction{
			{Command: "bob wallet list --agent-id " + agentID, Description: "List all registered wallets"},
		},
	})
}

// handleWalletProvisionCommand processes a wallet.provision command.
func handleWalletProvisionCommand(agentID, commandID, payloadStr string) (map[string]any, error) {
	var payload struct {
		Rail string `json:"rail"`
	}
	if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
		return nil, fmt.Errorf("invalid payload: %w", err)
	}
	if payload.Rail == "" {
		return nil, fmt.Errorf("payload missing rail field")
	}

	// Load local address for this rail
	cfg, cfgErr := loadCLIConfig()
	if cfgErr != nil {
		return nil, fmt.Errorf("failed to load config: %w", cfgErr)
	}
	addrMap := map[string]string{
		"evm":    cfg.EVMAddress,
		"btc":    cfg.BTCAddress,
		"solana": cfg.SOLAddress,
	}
	addr := addrMap[payload.Rail]
	if addr == "" {
		return nil, fmt.Errorf("no local address for rail %s — run bob init to generate keys", payload.Rail)
	}

	// Register wallet with the command ID for auth bypass
	walletPayload := map[string]any{
		"rail":                 payload.Rail,
		"address":              addr,
		"provision_request_id": commandID,
	}
	walletResp, err := apiPost(fmt.Sprintf("/agents/%s/wallets", url.PathEscape(agentID)), walletPayload)
	if err != nil {
		return nil, fmt.Errorf("wallet registration failed: %w", err)
	}

	var wallet struct {
		ID      string `json:"id"`
		Address string `json:"address"`
	}
	_ = json.Unmarshal(walletResp, &wallet)

	// Mark command as completed
	_, _ = apiPatch(fmt.Sprintf("/agents/%s/commands/%s", url.PathEscape(agentID), url.PathEscape(commandID)),
		map[string]any{"status": "completed", "result": map[string]any{"wallet_id": wallet.ID, "address": wallet.Address}})

	return map[string]any{
		"command_id":   commandID,
		"command_type": "wallet.provision",
		"rail":         payload.Rail,
		"wallet_id":    wallet.ID,
		"address":      wallet.Address,
	}, nil
}

// ---------------------------------------------------------------------------

const authKeyBindDomainPrefix = "BOB Passport Auth v1\n"

func autoBindAndIssuePassport(agentID string) string {
	// Step 1: Generate Ed25519 keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "passport: failed to generate Ed25519 key: " + err.Error()
	}
	pubKeyB64 := base64.RawURLEncoding.EncodeToString(pubKey)
	// "persistent" signals the key is stored locally and can be used for
	// merchant challenge-response auth (unlike browser "ephemeral" keys).
	kid := "ed25519-persistent-" + pubKeyB64[:8]

	// Step 2: Request auth key challenge
	challengeResp, err := apiPost(fmt.Sprintf("/agents/%s/auth-key/challenge", url.PathEscape(agentID)), map[string]any{
		"alg": "Ed25519",
	})
	if err != nil {
		return "passport: auth key challenge failed: " + err.Error()
	}
	var challenge struct {
		ChallengeID string `json:"challenge_id"`
		Message     struct {
			Kind      string `json:"kind"`
			AgentID   string `json:"agent_id"`
			Nonce     string `json:"nonce"`
			IssuedAt  string `json:"issued_at"`
			ExpiresAt string `json:"expires_at"`
		} `json:"message"`
	}
	if err := json.Unmarshal(challengeResp, &challenge); err != nil {
		return "passport: failed to parse challenge: " + err.Error()
	}

	// Step 3: Sign the challenge message
	messageJSON, err := json.Marshal(challenge.Message)
	if err != nil {
		return "passport: failed to serialize challenge message: " + err.Error()
	}
	digestData := append([]byte(authKeyBindDomainPrefix), messageJSON...)
	digest := sha256.Sum256(digestData)
	signature := ed25519.Sign(privKey, digest[:])
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Step 4: Verify auth key binding
	_, err = apiPost(fmt.Sprintf("/agents/%s/auth-key/verify", url.PathEscape(agentID)), map[string]any{
		"challenge_id": challenge.ChallengeID,
		"key": map[string]any{
			"kid": kid,
			"alg": "Ed25519",
			"public_key_jwk": map[string]any{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   pubKeyB64,
			},
		},
		"signature": sigB64,
	})
	if err != nil {
		return "passport: auth key verify failed: " + err.Error()
	}

	// Step 5: Issue passport
	_, err = apiPost(fmt.Sprintf("/agents/%s/credential", url.PathEscape(agentID)), map[string]any{})
	if err != nil {
		return "passport: issuance failed: " + err.Error()
	}

	return "" // success — no warning
}

// ---------------------------------------------------------------------------
// bob loan — P2P loan marketplace commands
// ---------------------------------------------------------------------------

func loanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "loan",
		Short: "P2P loan marketplace",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob loan",
				Data: map[string]any{
					"subcommands": []string{"offer", "marketplace", "accept", "draw", "repay", "list", "status", "eligibility"},
				},
				NextActions: []NextAction{
					{Command: "bob loan marketplace", Description: "Browse active loan offers"},
					{Command: "bob loan offer create", Description: "Create a loan offer"},
					{Command: "bob loan list", Description: "List your loans"},
				},
			})
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// --- bob loan offer ---
	offerCmd := &cobra.Command{
		Use:   "offer",
		Short: "Manage loan offers",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob loan offer",
				Data:    map[string]any{"subcommands": []string{"create", "list"}},
				NextActions: []NextAction{
					{Command: "bob loan offer create", Description: "Create a loan offer"},
					{Command: "bob loan offer list", Description: "List your loan offers"},
				},
			})
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// bob loan offer create (deprecated — use dashboard for lender offers)
	offerCreateCmd := &cobra.Command{
		Use:        "create",
		Short:      "[Deprecated] Use bob loan request to apply as a borrower",
		Deprecated: "lender offers are managed via the dashboard. Use `bob loan request` to apply for a loan.",
		RunE:       runLoanOfferCreate,
	}
	offerCreateCmd.Flags().String("agent-id", "", "Lender agent ID")
	offerCreateCmd.Flags().String("safe", "", "Safe/wallet address for funding")
	offerCreateCmd.Flags().Int64("amount", 0, "Max loan amount in USDC (smallest unit)")
	offerCreateCmd.Flags().Int("rate", 0, "Interest rate in basis points")
	offerCreateCmd.Flags().Int("min-score", 0, "Minimum borrower BOB Score")
	offerCreateCmd.Flags().Int("duration", 0, "Loan duration in days")
	offerCreateCmd.Flags().Int("grace-period", 3, "Grace period in days after maturity")
	offerCreateCmd.Flags().String("chain-id", "8453", "Chain ID (default Base L2)")
	offerCreateCmd.Flags().String("token-address", "", "Token contract address (USDC)")
	_ = offerCreateCmd.MarkFlagRequired("safe")
	_ = offerCreateCmd.MarkFlagRequired("amount")
	_ = offerCreateCmd.MarkFlagRequired("rate")
	_ = offerCreateCmd.MarkFlagRequired("duration")
	offerCmd.AddCommand(offerCreateCmd)

	// bob loan offer list
	offerListCmd := &cobra.Command{
		Use:   "list",
		Short: "List your loan offers",
		RunE:  runLoanOfferList,
	}
	offerListCmd.Flags().String("agent-id", "", "Lender agent ID")
	offerListCmd.Flags().Int("limit", 30, "Max results")
	offerListCmd.Flags().Int("offset", 0, "Offset")
	offerCmd.AddCommand(offerListCmd)

	// bob loan offer get
	offerGetCmd := &cobra.Command{
		Use:   "get [offer-id]",
		Short: "Get loan offer details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := apiGet(fmt.Sprintf("/loans/offers/%s", url.PathEscape(args[0])))
			if err != nil {
				emitError("bob loan offer get", err)
				return nil
			}
			var resp any
			json.Unmarshal(data, &resp)
			emit(Envelope{OK: true, Command: "bob loan offer get", Data: resp})
			return nil
		},
	}
	offerCmd.AddCommand(offerGetCmd)

	// bob loan offer cancel
	offerCancelCmd := &cobra.Command{
		Use:   "cancel [offer-id]",
		Short: "Cancel a loan offer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := apiDelete(fmt.Sprintf("/loans/offers/%s", url.PathEscape(args[0])))
			if err != nil {
				emitError("bob loan offer cancel", err)
				return nil
			}
			var resp any
			json.Unmarshal(data, &resp)
			emit(Envelope{OK: true, Command: "bob loan offer cancel", Data: resp})
			return nil
		},
	}
	offerCmd.AddCommand(offerCancelCmd)

	cmd.AddCommand(offerCmd)

	// --- bob loan lender-status ---
	lenderStatusCmd := &cobra.Command{
		Use:   "lender-status",
		Short: "Check if your account is approved for lending",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := apiGet("/loans/lender-status")
			if err != nil {
				emitError("bob loan lender-status", err)
				return nil
			}
			var resp any
			json.Unmarshal(data, &resp)
			emit(Envelope{OK: true, Command: "bob loan lender-status", Data: resp})
			return nil
		},
	}
	cmd.AddCommand(lenderStatusCmd)

	// --- bob loan marketplace ---
	marketplaceCmd := &cobra.Command{
		Use:   "marketplace",
		Short: "Browse active loan offers",
		RunE:  runLoanMarketplace,
	}
	marketplaceCmd.Flags().Int("limit", 30, "Max results")
	marketplaceCmd.Flags().Int("offset", 0, "Offset")
	cmd.AddCommand(marketplaceCmd)

	// --- bob loan accept ---
	acceptCmd := &cobra.Command{
		Use:   "accept [offer-id]",
		Short: "Accept a loan offer",
		Args:  cobra.ExactArgs(1),
		RunE:  runLoanAccept,
	}
	acceptCmd.Flags().String("agent-id", "", "Borrower agent ID")
	acceptCmd.Flags().Int64("amount", 0, "Amount in USDC micro-units (e.g. 5000000 = $5.00)")
	acceptCmd.Flags().String("wallet", "", "Borrower EVM wallet address (auto-resolved from config if omitted)")
	_ = acceptCmd.MarkFlagRequired("amount")
	cmd.AddCommand(acceptCmd)

	// --- bob loan draw ---
	drawCmd := &cobra.Command{
		Use:   "draw [loan-id]",
		Short: "Record a loan drawdown (funding tx)",
		Args:  cobra.ExactArgs(1),
		RunE:  runLoanDraw,
	}
	drawCmd.Flags().String("agent-id", "", "Agent ID")
	drawCmd.Flags().String("tx", "", "Funding transaction hash")
	_ = drawCmd.MarkFlagRequired("tx")
	cmd.AddCommand(drawCmd)

	// --- bob loan repay ---
	repayCmd := &cobra.Command{
		Use:   "repay [loan-id]",
		Short: "Repay a loan (executes on-chain USDC transfer)",
		Long: `Repay a loan by transferring USDC to the lending Safe.

Without --tx: executes an on-chain USDC transfer from the borrower wallet
to the lending Safe, then records the repayment. Requires --amount.

With --tx: records an already-completed transaction as a repayment.
Requires both --tx and --amount.`,
		Args: cobra.ExactArgs(1),
		RunE: runLoanRepay,
	}
	repayCmd.Flags().String("agent-id", "", "Agent ID")
	repayCmd.Flags().String("tx", "", "Existing transaction hash (skip on-chain execution)")
	repayCmd.Flags().Int64("amount", 0, "Repayment amount in USDC micro-units (required)")
	cmd.AddCommand(repayCmd)

	// --- bob loan list ---
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List your loans (as borrower or lender)",
		RunE:  runLoanList,
	}
	listCmd.Flags().String("agent-id", "", "Agent ID")
	listCmd.Flags().Int("limit", 30, "Max results")
	listCmd.Flags().Int("offset", 0, "Offset")
	cmd.AddCommand(listCmd)

	// --- bob loan status ---
	statusCmd := &cobra.Command{
		Use:   "status [loan-id]",
		Short: "Show detailed loan status",
		Args:  cobra.ExactArgs(1),
		RunE:  runLoanStatus,
	}
	statusCmd.Flags().String("agent-id", "", "Agent ID")
	cmd.AddCommand(statusCmd)

	// --- bob loan eligibility ---
	eligibilityCmd := &cobra.Command{
		Use:   "eligibility",
		Short: "Check if you qualify for a loan",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := apiGet("/loans/eligibility")
			if err != nil {
				emitError("bob loan eligibility", err)
				return nil
			}
			var resp any
			json.Unmarshal(data, &resp)
			emit(Envelope{
				OK:      true,
				Command: "bob loan eligibility",
				Data:    resp,
				NextActions: []NextAction{
					{Command: "bob loan marketplace", Description: "Browse active loan offers"},
					{Command: "bob score me", Description: "Check your BOB Score"},
				},
			})
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(eligibilityCmd)

	// --- bob loan accept-terms ---
	acceptTermsCmd := &cobra.Command{
		Use:   "accept-terms [loan-id]",
		Short: "Accept loan terms and sign the agreement",
		Long:  "Sign and accept the loan terms for a pending_terms loan. If no loan-id is provided, automatically finds your pending loan.",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runLoanAcceptTerms,
	}
	acceptTermsCmd.Flags().String("agent-id", "", "Agent ID")
	cmd.AddCommand(acceptTermsCmd)

	// --- bob loan request ---
	requestCmd := &cobra.Command{
		Use:   "request",
		Short: "Request a loan (borrower)",
		Long:  "Submit a loan request as a borrower. An admin will review and fund it.",
		RunE:  runLoanRequest,
	}
	requestCmd.Flags().String("agent-id", "", "Agent ID")
	requestCmd.Flags().Int64("amount", 0, "Amount in USDC micro-units (e.g. 5000000 = $5.00)")
	requestCmd.Flags().Int("max-rate", 0, "Maximum interest rate in basis points (0 = any)")
	requestCmd.Flags().Int("duration", 30, "Loan duration in days")
	requestCmd.Flags().String("purpose", "", "Purpose of the loan (optional)")
	_ = requestCmd.MarkFlagRequired("amount")
	cmd.AddCommand(requestCmd)

	// --- bob loan requests ---
	requestsCmd := &cobra.Command{
		Use:   "requests",
		Short: "List your loan requests",
		RunE:  runLoanRequests,
	}
	requestsCmd.Flags().String("agent-id", "", "Agent ID")
	requestsCmd.Flags().Int("limit", 30, "Max results")
	cmd.AddCommand(requestsCmd)

	// --- bob loan request-cancel ---
	requestCancelCmd := &cobra.Command{
		Use:   "request-cancel [request-id]",
		Short: "Cancel a pending loan request",
		Args:  cobra.ExactArgs(1),
		RunE:  runLoanRequestCancel,
	}
	requestCancelCmd.Flags().String("agent-id", "", "Agent ID")
	cmd.AddCommand(requestCancelCmd)

	return cmd
}

func runLoanOfferCreate(cmd *cobra.Command, args []string) error {
	emitErrorWithActions("bob loan offer create",
		fmt.Errorf("creating lender offers is not available via CLI — use `bob loan request` to apply for a loan as a borrower"),
		[]NextAction{
			{Command: "bob loan request --amount <usdc> --duration 30", Description: "Request a loan as a borrower"},
			{Command: "bob loan eligibility", Description: "Check if you qualify for a loan"},
			{Command: "bob loan marketplace", Description: "Browse active offers"},
		})
	return nil
}

func runLoanOfferList(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob loan offer list", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	limit, _ := cmd.Flags().GetInt("limit")
	offset, _ := cmd.Flags().GetInt("offset")

	resp, err := apiGet(fmt.Sprintf("/loans/offers?limit=%d&offset=%d", limit, offset))
	if err != nil {
		emitError("bob loan offer list", err)
		return nil
	}

	var offers []json.RawMessage
	if err := json.Unmarshal(resp, &offers); err != nil {
		emitError("bob loan offer list", fmt.Errorf("failed to parse response: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob loan offer list",
		Data: map[string]any{
			"agent_id": agentID,
			"offers":   offers,
			"count":    len(offers),
		},
		NextActions: []NextAction{
			{Command: "bob loan offer create", Description: "Create a new loan offer"},
			{Command: "bob loan marketplace", Description: "Browse all active offers"},
		},
	})
	return nil
}

func runLoanMarketplace(cmd *cobra.Command, args []string) error {
	limit, _ := cmd.Flags().GetInt("limit")
	offset, _ := cmd.Flags().GetInt("offset")

	resp, err := apiGet(fmt.Sprintf("/loans/marketplace?limit=%d&offset=%d", limit, offset))
	if err != nil {
		emitError("bob loan marketplace", err)
		return nil
	}

	var offers []json.RawMessage
	if err := json.Unmarshal(resp, &offers); err != nil {
		emitError("bob loan marketplace", fmt.Errorf("failed to parse response: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob loan marketplace",
		Data: map[string]any{
			"offers": offers,
			"count":  len(offers),
		},
		NextActions: []NextAction{
			{Command: "bob loan accept <offer-id> --amount <usdc>", Description: "Accept a loan offer"},
			{Command: "bob loan offer create", Description: "Create your own offer"},
		},
	})
	return nil
}

func runLoanAccept(cmd *cobra.Command, args []string) error {
	offerID := args[0]
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob loan accept", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	amount, _ := cmd.Flags().GetInt64("amount")

	// Auto-resolve borrower wallet from local config.
	walletAddr, _ := cmd.Flags().GetString("wallet")
	if walletAddr == "" {
		walletAddr = resolveEVMWallet()
	}

	body := map[string]any{
		"agent_id": agentID,
		"amount":   amount,
	}
	if walletAddr != "" {
		body["borrower_wallet_address"] = walletAddr
	}

	resp, err := apiPost(fmt.Sprintf("/loans/offers/%s/accept", url.PathEscape(offerID)), body)
	if err != nil {
		emitError("bob loan accept", err)
		return nil
	}

	var loan json.RawMessage
	if err := json.Unmarshal(resp, &loan); err != nil {
		emitError("bob loan accept", fmt.Errorf("failed to parse response: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob loan accept",
		Data:    loan,
		NextActions: []NextAction{
			{Command: "bob loan list --agent-id " + agentID, Description: "List your loans"},
			{Command: "bob loan status <loan-id> --agent-id " + agentID, Description: "Check loan status"},
		},
	})
	return nil
}

func runLoanDraw(cmd *cobra.Command, args []string) error {
	loanID := args[0]
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob loan draw", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	txHash, _ := cmd.Flags().GetString("tx")

	resp, err := apiPost(fmt.Sprintf("/loans/agreements/%s/draws",
		url.PathEscape(loanID)), map[string]any{
		"tx_hash": txHash,
	})
	if err != nil {
		emitError("bob loan draw", err)
		return nil
	}

	var result json.RawMessage
	if err := json.Unmarshal(resp, &result); err != nil {
		emitError("bob loan draw", fmt.Errorf("failed to parse response: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob loan draw",
		Data:    result,
		NextActions: []NextAction{
			{Command: "bob loan status " + loanID + " --agent-id " + agentID, Description: "Check loan status"},
			{Command: "bob loan repay " + loanID + " --tx <hash> --amount <usdc>", Description: "Record a repayment"},
		},
	})
	return nil
}

func runLoanRepay(cmd *cobra.Command, args []string) error {
	loanID := args[0]
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob loan repay", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	txHash, _ := cmd.Flags().GetString("tx")
	amount, _ := cmd.Flags().GetInt64("amount")

	// --amount is always required.
	if amount <= 0 {
		emitError("bob loan repay", fmt.Errorf("--amount is required (USDC micro-units, e.g. 2000000 for $2)"))
		return nil
	}

	// If no tx hash provided, execute the on-chain USDC transfer automatically.
	if txHash == "" {
		hash, _, err := executeLoanRepayment(loanID, agentID, amount)
		if err != nil {
			emitError("bob loan repay", err)
			return nil
		}
		txHash = hash
	}

	resp, err := apiPost(fmt.Sprintf("/loans/agreements/%s/repayments",
		url.PathEscape(loanID)), map[string]any{
		"tx_hash": txHash,
		"amount":  amount,
	})
	if err != nil {
		emitError("bob loan repay", err)
		return nil
	}

	var result json.RawMessage
	if err := json.Unmarshal(resp, &result); err != nil {
		emitError("bob loan repay", fmt.Errorf("failed to parse response: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob loan repay",
		Data:    result,
		NextActions: []NextAction{
			{Command: "bob loan status " + loanID + " --agent-id " + agentID, Description: "Check remaining balance"},
			{Command: "bob loan list --agent-id " + agentID, Description: "List all loans"},
		},
	})
	return nil
}

// executeLoanRepayment fetches the loan status, loads the agent's EVM key,
// and sends a USDC transfer to the lending Safe. Returns tx hash and amount.
func executeLoanRepayment(loanID, agentID string, requestedAmount int64) (string, int64, error) {
	if requestedAmount <= 0 {
		return "", 0, fmt.Errorf("--amount is required for on-chain repayment")
	}

	// 1. Get loan status to find safe address, chain, and amount owed.
	statusResp, err := apiGet(fmt.Sprintf("/loans/agreements/%s", url.PathEscape(loanID)))
	if err != nil {
		return "", 0, fmt.Errorf("get loan status: %w", err)
	}

	var loan struct {
		Status          string `json:"status"`
		Principal       int64  `json:"principal"`
		InterestAccrued int64  `json:"interest_accrued"`
		AmountRepaid    int64  `json:"amount_repaid"`
		SafeAddress     string `json:"safe_address"`
		ChainID         string `json:"chain_id"`
		BorrowerWallet  string `json:"borrower_wallet"`
	}
	if err := json.Unmarshal(statusResp, &loan); err != nil {
		return "", 0, fmt.Errorf("parse loan status: %w", err)
	}

	if loan.Status != "active" {
		return "", 0, fmt.Errorf("loan is not active (status: %s)", loan.Status)
	}
	if loan.SafeAddress == "" {
		return "", 0, fmt.Errorf("loan has no safe_address — cannot determine repayment destination")
	}
	if loan.ChainID == "" {
		return "", 0, fmt.Errorf("loan has no chain_id")
	}

	totalOwed := loan.Principal + loan.InterestAccrued
	outstanding := totalOwed - loan.AmountRepaid
	if outstanding <= 0 {
		return "", 0, fmt.Errorf("nothing to repay (total owed: %d, already repaid: %d)", totalOwed, loan.AmountRepaid)
	}

	repayAmount := requestedAmount
	if repayAmount > outstanding {
		return "", 0, fmt.Errorf("repayment amount %d exceeds outstanding balance %d — tokens would be sent on-chain before server rejects", repayAmount, outstanding)
	}

	// 2. Load EVM private key.
	cfg, loadErr := loadCLIConfig()
	if loadErr != nil {
		return "", 0, fmt.Errorf("load config: %w", loadErr)
	}
	keys := cfg.activeWalletKeys()
	if keys == nil || keys.EVMPrivateKey == "" {
		return "", 0, fmt.Errorf("no EVM wallet key found — run 'bob init' first")
	}

	// 3. Execute the on-chain USDC transfer via Safe (or direct EOA fallback).
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	borrowerWallet := common.HexToAddress(loan.BorrowerWallet)
	lenderSafe := common.HexToAddress(loan.SafeAddress)
	amount := big.NewInt(repayAmount)

	fmt.Fprintf(os.Stderr, "repaying %d USDC (micro) from %s to %s on chain %s...\n",
		repayAmount, loan.BorrowerWallet, loan.SafeAddress, loan.ChainID)

	hash, err := evmRepayLoan(ctx, keys.EVMPrivateKey, loan.ChainID, borrowerWallet, lenderSafe, amount)
	if err != nil {
		return "", 0, fmt.Errorf("on-chain transfer failed: %w", err)
	}

	return hash.Hex(), repayAmount, nil
}

func runLoanList(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob loan list", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	limit, _ := cmd.Flags().GetInt("limit")
	offset, _ := cmd.Flags().GetInt("offset")

	resp, err := apiGet(fmt.Sprintf("/loans/agreements?limit=%d&offset=%d", limit, offset))
	if err != nil {
		emitError("bob loan list", err)
		return nil
	}

	var loans []json.RawMessage
	if err := json.Unmarshal(resp, &loans); err != nil {
		emitError("bob loan list", fmt.Errorf("failed to parse response: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob loan list",
		Data: map[string]any{
			"agent_id": agentID,
			"loans":    loans,
			"count":    len(loans),
		},
		NextActions: []NextAction{
			{Command: "bob loan status <loan-id> --agent-id " + agentID, Description: "View loan details"},
			{Command: "bob loan marketplace", Description: "Browse available offers"},
		},
	})
	return nil
}

func runLoanStatus(cmd *cobra.Command, args []string) error {
	loanID := args[0]
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob loan status", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	resp, err := apiGet(fmt.Sprintf("/loans/agreements/%s", url.PathEscape(loanID)))
	if err != nil {
		emitError("bob loan status", err)
		return nil
	}

	var loan json.RawMessage
	if err := json.Unmarshal(resp, &loan); err != nil {
		emitError("bob loan status", fmt.Errorf("failed to parse response: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob loan status",
		Data:    loan,
		NextActions: []NextAction{
			{Command: "bob loan repay " + loanID + " --tx <hash> --amount <usdc> --agent-id " + agentID, Description: "Record a repayment"},
			{Command: "bob loan list --agent-id " + agentID, Description: "List all loans"},
		},
	})
	return nil
}

func runLoanAcceptTerms(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob loan accept-terms", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	var loanID string
	if len(args) > 0 {
		loanID = args[0]
	} else {
		// Auto-find the first pending_terms loan for this agent.
		resp, err := apiGet("/loans/agreements")
		if err != nil {
			emitError("bob loan accept-terms", err)
			return nil
		}
		var loans []map[string]any
		if err := json.Unmarshal(resp, &loans); err != nil {
			emitError("bob loan accept-terms", fmt.Errorf("failed to parse loans: %w", err))
			return nil
		}
		for _, l := range loans {
			status, _ := l["status"].(string)
			borrower, _ := l["borrower_agent_id"].(string)
			if status == "pending_terms" && borrower == agentID {
				if id, ok := l["id"].(string); ok {
					loanID = id
					break
				}
			}
		}
		if loanID == "" {
			emitErrorWithActions("bob loan accept-terms", fmt.Errorf("no pending_terms loan found for agent %s", agentID), []NextAction{
				{Command: "bob loan list --agent-id " + agentID, Description: "List your loans to check status"},
				{Command: "bob loan request --amount <usdc> --duration 30", Description: "Request a new loan"},
			})
			return nil
		}
	}

	resp, err := apiPost(fmt.Sprintf("/loans/agreements/%s/accept-terms", url.PathEscape(loanID)), map[string]any{})
	if err != nil {
		emitError("bob loan accept-terms", err)
		return nil
	}

	var result json.RawMessage
	if err := json.Unmarshal(resp, &result); err != nil {
		emitError("bob loan accept-terms", fmt.Errorf("failed to parse response: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob loan accept-terms",
		Data: map[string]any{
			"loan_id": loanID,
			"result":  result,
			"message": "Loan terms accepted. Agent signature recorded.",
		},
		NextActions: []NextAction{
			{Command: "bob loan status " + loanID + " --agent-id " + agentID, Description: "Check loan status"},
			{Command: "bob loan draw " + loanID + " --tx <hash> --agent-id " + agentID, Description: "Record funding draw"},
		},
	})
	return nil
}

func runLoanRequest(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob loan request", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	amount, _ := cmd.Flags().GetInt64("amount")
	maxRate, _ := cmd.Flags().GetInt("max-rate")
	duration, _ := cmd.Flags().GetInt("duration")
	purpose, _ := cmd.Flags().GetString("purpose")

	body := map[string]any{
		"agent_id":      agentID,
		"amount":        amount,
		"duration_days": duration,
	}
	if maxRate > 0 {
		body["max_interest_rate_bps"] = maxRate
	}
	if purpose != "" {
		body["purpose"] = purpose
	}

	resp, err := apiPost("/loans/requests", body)
	if err != nil {
		emitError("bob loan request", err)
		return nil
	}

	var result json.RawMessage
	if err := json.Unmarshal(resp, &result); err != nil {
		emitError("bob loan request", fmt.Errorf("failed to parse response: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob loan request",
		Data:    result,
		NextActions: []NextAction{
			{Command: "bob loan requests", Description: "List your loan requests"},
			{Command: "bob loan eligibility", Description: "Check your eligibility"},
		},
	})
	return nil
}

func runLoanRequests(cmd *cobra.Command, args []string) error {
	agentID := resolveAgentID(cmd)
	if agentID == "" {
		emitErrorWithActions("bob loan requests", fmt.Errorf("no agent ID"), noAgentIDActions)
		return nil
	}

	limit, _ := cmd.Flags().GetInt("limit")

	resp, err := apiGet(fmt.Sprintf("/loans/requests?limit=%d", limit))
	if err != nil {
		emitError("bob loan requests", err)
		return nil
	}

	var result json.RawMessage
	if err := json.Unmarshal(resp, &result); err != nil {
		emitError("bob loan requests", fmt.Errorf("failed to parse response: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob loan requests",
		Data:    result,
		NextActions: []NextAction{
			{Command: "bob loan request --amount <usdc> --duration 30", Description: "Submit a new request"},
		},
	})
	return nil
}

func runLoanRequestCancel(cmd *cobra.Command, args []string) error {
	requestID := args[0]

	resp, err := apiDelete(fmt.Sprintf("/loans/requests/%s", url.PathEscape(requestID)))
	if err != nil {
		emitError("bob loan request-cancel", err)
		return nil
	}

	var result json.RawMessage
	if err := json.Unmarshal(resp, &result); err != nil {
		emitError("bob loan request-cancel", fmt.Errorf("failed to parse response: %w", err))
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob loan request-cancel",
		Data:    result,
		NextActions: []NextAction{
			{Command: "bob loan requests", Description: "List remaining requests"},
		},
	})
	return nil
}

