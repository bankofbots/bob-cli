package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var updateHTTPClient = &http.Client{Timeout: 60 * time.Second}

func updateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Self-update the bob CLI to the latest version",
		Args:  cobra.NoArgs,
		RunE:  runUpdate,
	}
	cmd.Flags().String("version", "", "Update to a specific version (e.g. 0.28.0) instead of latest")
	return cmd
}

func runUpdate(cmd *cobra.Command, args []string) error {
	plat := runtime.GOOS
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		emitError("bob update", fmt.Errorf("unsupported architecture: %s", arch))
		return nil
	}

	targetVersion, _ := cmd.Flags().GetString("version")

	// Resolve target binary path early so we can report it
	currentBin, err := os.Executable()
	if err != nil {
		emitError("bob update", fmt.Errorf("cannot determine current binary path: %w", err))
		return nil
	}
	currentBin, _ = filepath.EvalSymlinks(currentBin)

	// Check if writable
	if f, err := os.OpenFile(currentBin, os.O_WRONLY, 0); err != nil {
		emitErrorWithActions("bob update",
			fmt.Errorf("binary at %s is not writable: %w", currentBin, err),
			[]NextAction{
				{Command: "Download the latest bob binary from https://github.com/bankofbots/bob-cli/releases/latest", Description: "Install a fresh binary from GitHub Releases"},
				{Command: "bob --version", Description: "Verify which bob binary is on your PATH"},
			})
		return nil
	} else {
		f.Close()
	}

	// Fetch release info from GitHub API
	apiURL := "https://api.github.com/repos/bankofbots/bob-cli/releases/latest"
	if targetVersion != "" {
		targetVersion = strings.TrimPrefix(targetVersion, "v")
		apiURL = fmt.Sprintf("https://api.github.com/repos/bankofbots/bob-cli/releases/tags/v%s", targetVersion)
	}

	resp, err := updateHTTPClient.Get(apiURL)
	if err != nil {
		emitError("bob update", fmt.Errorf("failed to check for updates: %w", err))
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 && targetVersion != "" {
		emitError("bob update", fmt.Errorf("version v%s not found", targetVersion))
		return nil
	}
	if resp.StatusCode != 200 {
		emitError("bob update", fmt.Errorf("GitHub API returned %d", resp.StatusCode))
		return nil
	}

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		emitError("bob update", fmt.Errorf("failed to parse release info: %w", err))
		return nil
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	if latestVersion == version && targetVersion == "" {
		emit(Envelope{
			OK:      true,
			Command: "bob update",
			Data: map[string]any{
				"current_version": version,
				"latest_version":  latestVersion,
				"binary_path":     currentBin,
				"status":          "up_to_date",
			},
		})
		return nil
	}

	// Find the right asset and its checksum
	wantName := fmt.Sprintf("bob-%s-%s-%s.tar.gz", release.TagName, plat, arch)
	checksumName := wantName + ".sha256"
	var downloadURL, checksumURL string
	for _, a := range release.Assets {
		if a.Name == wantName {
			downloadURL = a.BrowserDownloadURL
		}
		if a.Name == checksumName {
			checksumURL = a.BrowserDownloadURL
		}
	}
	if downloadURL == "" {
		emitError("bob update", fmt.Errorf("no binary found for %s/%s in release %s", plat, arch, release.TagName))
		return nil
	}

	// Checksum is required — fail closed if missing
	if checksumURL == "" {
		emitError("bob update", fmt.Errorf("no checksum file found for %s in release %s — refusing to update without integrity verification", wantName, release.TagName))
		return nil
	}

	// Download checksum first
	csResp, err := updateHTTPClient.Get(checksumURL)
	if err != nil {
		emitError("bob update", fmt.Errorf("failed to download checksum: %w", err))
		return nil
	}
	csBody, _ := io.ReadAll(csResp.Body)
	csResp.Body.Close()
	if csResp.StatusCode != 200 {
		emitError("bob update", fmt.Errorf("checksum download returned %d — refusing to update without integrity verification", csResp.StatusCode))
		return nil
	}
	parts := strings.Fields(string(csBody))
	if len(parts) < 1 {
		emitError("bob update", fmt.Errorf("checksum file is empty or malformed"))
		return nil
	}
	expectedHash := parts[0]

	// Download binary
	dlResp, err := updateHTTPClient.Get(downloadURL)
	if err != nil {
		emitError("bob update", fmt.Errorf("download failed: %w", err))
		return nil
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode != 200 {
		emitError("bob update", fmt.Errorf("download returned %d", dlResp.StatusCode))
		return nil
	}

	tmpDir, err := os.MkdirTemp("", "bob-update-")
	if err != nil {
		emitError("bob update", fmt.Errorf("failed to create temp dir: %w", err))
		return nil
	}
	defer os.RemoveAll(tmpDir)

	tarPath := filepath.Join(tmpDir, wantName)
	f, err := os.Create(tarPath)
	if err != nil {
		emitError("bob update", fmt.Errorf("failed to create temp file: %w", err))
		return nil
	}

	// Download and compute SHA256 simultaneously
	hasher := sha256.New()
	tee := io.TeeReader(dlResp.Body, hasher)
	if _, err := io.Copy(f, tee); err != nil {
		f.Close()
		emitError("bob update", fmt.Errorf("download write failed: %w", err))
		return nil
	}
	f.Close()
	gotHash := hex.EncodeToString(hasher.Sum(nil))

	// Verify checksum — fail closed
	if !strings.EqualFold(gotHash, expectedHash) {
		emitError("bob update", fmt.Errorf("checksum mismatch: got %s, expected %s — download may be corrupted or tampered with", gotHash, expectedHash))
		return nil
	}

	// Extract
	tarCmd := exec.Command("tar", "-xzf", tarPath, "-C", tmpDir)
	if out, err := tarCmd.CombinedOutput(); err != nil {
		emitError("bob update", fmt.Errorf("extract failed: %s: %w", string(out), err))
		return nil
	}

	// Find extracted binary
	extractedDir := strings.TrimSuffix(wantName, ".tar.gz")
	binName := "bob"
	if plat == "windows" {
		binName = "bob.exe"
	}
	newBin := filepath.Join(tmpDir, extractedDir, binName)
	if _, err := os.Stat(newBin); err != nil {
		newBin = filepath.Join(tmpDir, binName)
		if _, err := os.Stat(newBin); err != nil {
			emitError("bob update", fmt.Errorf("extracted binary not found"))
			return nil
		}
	}

	// Atomic replace: rename old → .old, copy new → current, remove .old
	oldBin := currentBin + ".old"
	if err := os.Rename(currentBin, oldBin); err != nil {
		emitErrorWithActions("bob update",
			fmt.Errorf("cannot rename binary at %s: %w", currentBin, err),
			[]NextAction{
				{Command: "Download the latest bob binary from https://github.com/bankofbots/bob-cli/releases/latest", Description: "Replace the binary manually"},
			})
		return nil
	}

	src, err := os.Open(newBin)
	if err != nil {
		os.Rename(oldBin, currentBin)
		emitError("bob update", fmt.Errorf("cannot open new binary: %w", err))
		return nil
	}
	dst, err := os.OpenFile(currentBin, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		src.Close()
		os.Rename(oldBin, currentBin)
		emitErrorWithActions("bob update",
			fmt.Errorf("cannot write to %s: %w", currentBin, err),
			[]NextAction{
				{Command: "Download the latest bob binary from https://github.com/bankofbots/bob-cli/releases/latest", Description: "Replace the binary manually"},
			})
		return nil
	}
	if _, err := io.Copy(dst, src); err != nil {
		src.Close()
		dst.Close()
		os.Rename(oldBin, currentBin)
		emitError("bob update", fmt.Errorf("copy failed: %w", err))
		return nil
	}
	src.Close()
	dst.Close()
	os.Remove(oldBin)

	emit(Envelope{
		OK:      true,
		Command: "bob update",
		Data: map[string]any{
			"previous_version":  version,
			"new_version":       latestVersion,
			"binary_path":       currentBin,
			"checksum_verified": true,
			"sha256":            gotHash,
			"status":            "updated",
		},
		NextActions: []NextAction{
			{Command: "bob --version", Description: "Verify the update"},
			{Command: "bob doctor", Description: "Run diagnostics"},
		},
	})
	return nil
}
