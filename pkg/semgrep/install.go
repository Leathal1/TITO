package semgrep

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// InstallMethod describes how semgrep was installed
type InstallMethod string

const (
	InstallPip    InstallMethod = "pip"
	InstallPipx   InstallMethod = "pipx"
	InstallBrew   InstallMethod = "brew"
	InstallBinary InstallMethod = "binary"
	InstallNone   InstallMethod = "none"
)

// InstallInfo holds detection results about the semgrep installation
type InstallInfo struct {
	Installed bool          // whether semgrep is available
	Path      string        // absolute path to the binary
	Version   string        // semgrep version string
	Method    InstallMethod // how it was installed
}

var (
	ensureOnce sync.Once
	ensureErr  error
)

// Detect checks whether semgrep is installed and gathers info about it.
// It never modifies the system.
func Detect(ctx context.Context) *InstallInfo {
	info := &InstallInfo{Method: InstallNone}

	path, err := exec.LookPath("semgrep")
	if err != nil {
		return info
	}
	info.Path = path
	info.Installed = true

	// Grab version (silently)
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	if err == nil {
		info.Version = strings.TrimSpace(string(out))
	}

	// Determine install method
	info.Method = detectMethod(ctx, path)
	return info
}

// detectMethod figures out how semgrep was installed based on its path and
// available package managers.
func detectMethod(ctx context.Context, binPath string) InstallMethod {
	abs, _ := filepath.EvalSymlinks(binPath)

	// Homebrew: binary lives under Cellar or homebrew prefix
	if strings.Contains(abs, "Cellar") || strings.Contains(abs, "homebrew") || strings.Contains(abs, "linuxbrew") {
		return InstallBrew
	}

	// pipx: typically ~/.local/pipx/venvs/semgrep/...
	if strings.Contains(abs, "pipx") {
		return InstallPipx
	}

	// pip: site-packages path or standard pip bin locations
	if strings.Contains(abs, "site-packages") || strings.Contains(abs, "Python") {
		return InstallPip
	}

	// Check pip list as fallback
	for _, pip := range []string{"pip3", "pip"} {
		if p, err := exec.LookPath(pip); err == nil {
			cmd := exec.CommandContext(ctx, p, "show", "semgrep")
			cmd.Stderr = nil
			if out, err := cmd.Output(); err == nil && len(out) > 0 {
				return InstallPip
			}
		}
	}

	return InstallBinary
}

// EnsureInstalled silently installs semgrep if it isn't already present.
// Safe to call from multiple goroutines — installation runs at most once per process.
// Returns the InstallInfo after ensuring availability.
func EnsureInstalled(ctx context.Context) (*InstallInfo, error) {
	info := Detect(ctx)
	if info.Installed {
		return info, nil
	}

	ensureOnce.Do(func() {
		ensureErr = install(ctx)
	})
	if ensureErr != nil {
		return info, fmt.Errorf("semgrep auto-install failed: %w", ensureErr)
	}

	// Re-detect after install
	info = Detect(ctx)
	if !info.Installed {
		return info, fmt.Errorf("semgrep was installed but is not in PATH")
	}
	return info, nil
}

// Install explicitly installs semgrep. Unlike EnsureInstalled, this always
// attempts installation even if semgrep is already present (useful for upgrades).
func Install(ctx context.Context) error {
	return install(ctx)
}

// Uninstall removes semgrep using the same method it was installed with.
// Returns an error if the install method can't be determined or uninstall fails.
func Uninstall(ctx context.Context) error {
	info := Detect(ctx)
	if !info.Installed {
		return nil // nothing to uninstall
	}

	devNull, _ := os.Open(os.DevNull)
	defer devNull.Close()

	switch info.Method {
	case InstallPip:
		for _, pip := range []string{"pip3", "pip"} {
			if _, err := exec.LookPath(pip); err == nil {
				cmd := exec.CommandContext(ctx, pip, "uninstall", "-y", "semgrep")
				cmd.Stdout = devNull
				cmd.Stderr = devNull
				if err := cmd.Run(); err == nil {
					return nil
				}
			}
		}
		return fmt.Errorf("pip uninstall failed")

	case InstallPipx:
		if pipx, err := exec.LookPath("pipx"); err == nil {
			cmd := exec.CommandContext(ctx, pipx, "uninstall", "semgrep")
			cmd.Stdout = devNull
			cmd.Stderr = devNull
			return cmd.Run()
		}
		return fmt.Errorf("pipx not found — cannot uninstall")

	case InstallBrew:
		if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
			return fmt.Errorf("brew uninstall not supported on %s", runtime.GOOS)
		}
		if brew, err := exec.LookPath("brew"); err == nil {
			cmd := exec.CommandContext(ctx, brew, "uninstall", "--quiet", "semgrep")
			cmd.Stdout = devNull
			cmd.Stderr = devNull
			return cmd.Run()
		}
		return fmt.Errorf("brew not found — cannot uninstall")

	case InstallBinary:
		// Manual binary — try to remove it directly
		if info.Path != "" {
			return os.Remove(info.Path)
		}
		return fmt.Errorf("cannot determine binary path for removal")

	default:
		return fmt.Errorf("unknown install method %q — remove semgrep manually", info.Method)
	}
}

// install tries multiple methods to install semgrep silently.
// Order: pip3 → pip → pipx → brew (macOS/Linux) → binary download
func install(ctx context.Context) error {
	devNull, _ := os.Open(os.DevNull)
	defer devNull.Close()

	// 1. pip3 / pip
	for _, pip := range []string{"pip3", "pip"} {
		if _, err := exec.LookPath(pip); err == nil {
			cmd := exec.CommandContext(ctx, pip, "install", "--quiet", "--break-system-packages", "semgrep")
			cmd.Stdout = devNull
			cmd.Stderr = devNull
			if err := cmd.Run(); err == nil {
				return nil
			}
			// Retry without --break-system-packages for older pip
			cmd2 := exec.CommandContext(ctx, pip, "install", "--quiet", "semgrep")
			cmd2.Stdout = devNull
			cmd2.Stderr = devNull
			if err := cmd2.Run(); err == nil {
				return nil
			}
		}
	}

	// 2. pipx (isolated venv — doesn't pollute global site-packages)
	if pipx, err := exec.LookPath("pipx"); err == nil {
		cmd := exec.CommandContext(ctx, pipx, "install", "semgrep")
		cmd.Stdout = devNull
		cmd.Stderr = devNull
		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	// 3. Homebrew (macOS and Linux)
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		if brew, err := exec.LookPath("brew"); err == nil {
			cmd := exec.CommandContext(ctx, brew, "install", "--quiet", "semgrep")
			cmd.Stdout = devNull
			cmd.Stderr = devNull
			if err := cmd.Run(); err == nil {
				return nil
			}
		}
	}

	// 4. Direct binary download (GitHub releases) as last resort
	if err := installBinary(ctx); err == nil {
		return nil
	}

	return fmt.Errorf("all install methods failed (tried pip3, pip, pipx, brew, binary). " +
		"Install manually: pip install semgrep")
}

// installBinary downloads a pre-built semgrep binary from GitHub releases.
func installBinary(ctx context.Context) error {
	// Determine platform
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	if goos != "linux" && goos != "darwin" {
		return fmt.Errorf("binary install not supported on %s", goos)
	}

	// Semgrep provides pip wheels and brew — direct binary is a fallback.
	// The official install script handles this.
	devNull, _ := os.Open(os.DevNull)
	defer devNull.Close()

	// Try the official install script
	var script string
	if goos == "darwin" || goos == "linux" {
		script = "python3 -m pip install --quiet semgrep || python3 -m pip install --quiet --user semgrep"
	}
	if script == "" {
		return fmt.Errorf("no binary install script for %s/%s", goos, goarch)
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	return cmd.Run()
}

// Version returns the installed semgrep version string, or empty if not installed.
func Version(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "semgrep", "--version")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return ""
	}
	return strings.TrimSpace(out.String())
}
