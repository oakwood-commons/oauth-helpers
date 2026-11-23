// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"

	osDarwin  = "darwin"
	osLinux   = "linux"
	osWindows = "windows"

	cmdOpen              = "open"
	cmdXdgOpen           = "xdg-open"
	cmdRundll32          = "rundll32"
	rundll32URLHandler   = "url.dll,FileProtocolHandler"
	macOSOpenAppFlag     = "-a"
	macOSAppBundleSuffix = ".app"
	windowsExeSuffix     = ".exe"

	prefDefault = "default"
	prefSystem  = "system"

	envBrowser         = "BROWSER"
	envProgramFiles    = "ProgramFiles"
	envProgramFilesX86 = "ProgramFiles(x86)"
	envLocalAppData    = "LocalAppData"
	envWSLDistroName   = "WSL_DISTRO_NAME"
	envWSLInterop      = "WSL_INTEROP"

	asciiSpace = 0x20
	asciiDEL   = 0x7f
)

type browserFamily int

const (
	familyUnknown browserFamily = iota
	familyEdge
	familyChrome
	familyChromium
	familyFirefox
	familyBrave
	familySafari
)

// BrowserOption configures optional behavior for OpenBrowserWithPreference.
type BrowserOption func(*browserConfig)

type browserConfig struct {
	warnHandler func(string)
	ops         *browserOps
}

func (c *browserConfig) emitWarning(msg string) {
	if c.warnHandler != nil {
		c.warnHandler(msg)
	}
}

// WithWarningHandler registers a callback invoked with a warning message when
// an explicit browser preference or $BROWSER environment variable cannot be
// found or fails to start before falling back to the system default browser.
func WithWarningHandler(fn func(string)) BrowserOption {
	return func(c *browserConfig) {
		c.warnHandler = fn
	}
}

// browserOps abstracts OS discovery and process execution so unit tests can
// exercise darwin, linux, windows, and WSL paths deterministically without
// launching a real browser.
type browserOps struct {
	goos            string
	getenv          func(string) string
	lookPath        func(string) (string, error)
	stat            func(string) (os.FileInfo, error)
	startCmd        func(name string, args ...string) error
	startDefaultCmd func(name string, args ...string) error
	runCmd          func(ctx context.Context, name string, args ...string) error
}

func withBrowserOps(ops *browserOps) BrowserOption {
	return func(c *browserConfig) {
		c.ops = ops
	}
}

func defaultBrowserOps() browserOps {
	return browserOps{
		goos:            runtime.GOOS,
		getenv:          os.Getenv,
		lookPath:        exec.LookPath,
		stat:            os.Stat,
		startCmd:        startDetachedProcess,
		startDefaultCmd: startSystemDefaultProcess,
		runCmd:          runProcess,
	}
}

func startDetachedProcess(name string, args ...string) error {
	return startDetachedProcessWithEnv(nil, name, args...)
}

func startSystemDefaultProcess(name string, args ...string) error {
	// Strip BROWSER from the child environment when launching the OS default
	// browser so Linux xdg-open does not re-read a broken, shell-Unsafe, or
	// explicitly bypassed ("default"/"system") $BROWSER variable.
	return startDetachedProcessWithEnv(stripBrowserEnv(os.Environ()), name, args...)
}

func startDetachedProcessWithEnv(env []string, name string, args ...string) error {
	// Intentionally avoid exec.CommandContext: when launching a browser binary
	// directly, the spawned process may be the user's browser session itself.
	// Binding it to the OAuth login context would send SIGKILL / TerminateProcess
	// to the browser as soon as Login(ctx) finishes and cancels ctx.
	cmd := exec.Command(name, args...) //nolint:gosec,noctx // URL is validated; child browser must survive login ctx cancellation
	if env != nil {
		cmd.Env = env
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		_ = cmd.Wait()
	}()
	return nil
}

func stripBrowserEnv(environ []string) []string {
	found := false
	for _, kv := range environ {
		k, _, hasEq := strings.Cut(kv, "=")
		if hasEq && strings.EqualFold(k, envBrowser) {
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	filtered := make([]string, 0, len(environ)-1)
	for _, kv := range environ {
		k, _, hasEq := strings.Cut(kv, "=")
		if hasEq && strings.EqualFold(k, envBrowser) {
			continue
		}
		filtered = append(filtered, kv)
	}
	return filtered
}

func runProcess(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // URL and launcher arguments are validated
	return cmd.Run()
}

// OpenBrowser opens rawURL in the user's browser, honoring the $BROWSER
// environment variable when set and falling back to the OS default browser.
//
// Only valid http:// and https:// URLs with a non-empty host and no control
// characters or whitespace are allowed. The browser process runs detached from
// ctx after startup so canceling ctx does not terminate the browser session.
func OpenBrowser(ctx context.Context, rawURL string) error {
	return OpenBrowserWithPreference(ctx, rawURL, "")
}

// OpenBrowserWithPreference opens rawURL using the following priority chain:
//  1. Explicit preference (e.g. "msedge", "edge", "chrome", "google-chrome",
//     "chromium", "firefox", "brave", "safari", "default"/"system", or an
//     executable name/path). "default" and "system" bypass $BROWSER and open
//     the OS default browser directly.
//  2. $BROWSER environment variable when preference is empty (supporting
//     colon-separated fallback entries on Unix and semicolon-separated entries
//     or single executable paths on Windows, without invoking a shell).
//  3. OS default browser ("open" on darwin, "xdg-open" on linux,
//     "rundll32 url.dll,FileProtocolHandler" on windows).
//
// If a configured preference or $BROWSER cannot be found or fails to start, a
// warning is emitted via WithWarningHandler (if provided) and OpenBrowserWithPreference
// falls back to the OS default browser, returning an error only if the OS
// default fallback also fails (or if ctx or URL validation fails up front).
func OpenBrowserWithPreference(ctx context.Context, rawURL, preference string, opts ...BrowserOption) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("browser launch canceled: %w", err)
	}
	normalizedURL, err := validateBrowserURL(rawURL)
	if err != nil {
		return err
	}

	var cfg browserConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	ops := defaultBrowserOps()
	if cfg.ops != nil {
		ops = *cfg.ops
	}

	pref := cleanBrowserToken(preference)
	if pref != "" {
		if isSystemDefaultPreference(pref) {
			return launchSystemDefaultBrowser(&ops, normalizedURL)
		}
		launchErr := launchPreferredBrowser(ctx, &ops, pref, normalizedURL)
		if launchErr == nil {
			return nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("browser launch canceled: %w", ctxErr)
		}
		cfg.emitWarning(fmt.Sprintf("configured browser %q could not be launched (%v); falling back to system default browser", pref, launchErr))
		if fallbackErr := launchSystemDefaultBrowser(&ops, normalizedURL); fallbackErr != nil {
			return fmt.Errorf("failed to open system default browser after %q failed: %w", pref, fallbackErr)
		}
		return nil
	}

	rawBrowserEnv := ""
	if ops.getenv != nil {
		rawBrowserEnv = strings.TrimSpace(ops.getenv(envBrowser))
	}
	if rawBrowserEnv != "" {
		entries := splitBrowserEnv(ops.goos, rawBrowserEnv)
		if len(entries) == 1 && isSystemDefaultPreference(entries[0]) {
			return launchSystemDefaultBrowser(&ops, normalizedURL)
		}
		if len(entries) > 0 {
			var lastErr error
			for _, entry := range entries {
				var entryErr error
				if isSystemDefaultPreference(entry) {
					entryErr = launchSystemDefaultBrowser(&ops, normalizedURL)
				} else {
					entryErr = launchPreferredBrowser(ctx, &ops, entry, normalizedURL)
				}
				if entryErr == nil {
					return nil
				}
				if ctxErr := ctx.Err(); ctxErr != nil {
					return fmt.Errorf("browser launch canceled: %w", ctxErr)
				}
				lastErr = entryErr
			}
			cfg.emitWarning(fmt.Sprintf("$BROWSER (%q) could not be launched (%v); falling back to system default browser", rawBrowserEnv, lastErr))
			if fallbackErr := launchSystemDefaultBrowser(&ops, normalizedURL); fallbackErr != nil {
				return fmt.Errorf("failed to open system default browser after $BROWSER (%q) failed: %w", rawBrowserEnv, fallbackErr)
			}
			return nil
		}
	}

	return launchSystemDefaultBrowser(&ops, normalizedURL)
}

func validateBrowserURL(rawURL string) (string, error) {
	if !utf8.ValidString(rawURL) {
		return "", fmt.Errorf("refusing to open URL containing invalid UTF-8: %q", rawURL)
	}
	for _, r := range rawURL {
		if r <= asciiSpace || r == asciiDEL || unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", fmt.Errorf("refusing to open URL containing control characters or whitespace: %q", rawURL)
		}
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid browser URL %q: %w", rawURL, err)
	}

	if !strings.EqualFold(parsed.Scheme, schemeHTTP) && !strings.EqualFold(parsed.Scheme, schemeHTTPS) {
		return "", fmt.Errorf("refusing to open URL with non-HTTP scheme: %q", rawURL)
	}

	if parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		return "", fmt.Errorf("refusing to open URL with empty host: %q", rawURL)
	}

	// Normalize uppercase HTTP/HTTPS scheme prefixes so OS launchers (such as
	// Linux xdg-mime x-scheme-handler lookups) match lowercase scheme handlers
	// without re-encoding query parameters.
	if !strings.HasPrefix(rawURL, parsed.Scheme) {
		rawURL = parsed.Scheme + rawURL[len(parsed.Scheme):]
	}

	return rawURL, nil
}

func cleanBrowserToken(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

func validateBrowserToken(token string) error {
	if token == "" {
		return errors.New("empty browser specification")
	}
	if strings.HasPrefix(token, "-") {
		return fmt.Errorf("browser specification %q must not start with '-'", token)
	}
	if !utf8.ValidString(token) {
		return fmt.Errorf("browser specification %q contains invalid UTF-8", token)
	}
	for _, r := range token {
		if r < asciiSpace || r == asciiDEL || unicode.IsControl(r) {
			return fmt.Errorf("browser specification %q contains control characters", token)
		}
	}
	return nil
}

func isSystemDefaultPreference(token string) bool {
	return strings.EqualFold(token, prefDefault) || strings.EqualFold(token, prefSystem)
}

func splitBrowserEnv(goos, raw string) []string {
	sep := ":"
	if goos == osWindows {
		sep = ";"
	}
	parts := strings.Split(raw, sep)
	entries := make([]string, 0, len(parts))
	for _, part := range parts {
		cleaned := cleanBrowserToken(part)
		if cleaned != "" {
			entries = append(entries, cleaned)
		}
	}
	return entries
}

func resolveBrowserFamily(token string) browserFamily {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "msedge", "edge", "microsoft-edge", "microsoft-edge-stable", "microsoft edge", "msedge.exe":
		return familyEdge
	case "chrome", "google-chrome", "google-chrome-stable", "google chrome", "chrome.exe":
		return familyChrome
	case "chromium", "chromium-browser", "chromium.exe":
		return familyChromium
	case "firefox", "mozilla-firefox", "firefox.exe":
		return familyFirefox
	case "brave", "brave-browser", "brave browser", "brave.exe":
		return familyBrave
	case "safari":
		return familySafari
	default:
		return familyUnknown
	}
}

func launchSystemDefaultBrowser(ops *browserOps, rawURL string) error {
	var cmd string
	var args []string

	switch ops.goos {
	case osDarwin:
		cmd = cmdOpen
		args = []string{rawURL}
	case osLinux:
		cmd = cmdXdgOpen
		args = []string{rawURL}
	case osWindows:
		cmd = cmdRundll32
		args = []string{rundll32URLHandler, rawURL}
	default:
		return fmt.Errorf("unsupported platform: %s", ops.goos)
	}

	starter := ops.startDefaultCmd
	if starter == nil {
		starter = ops.startCmd
	}
	if err := starter(cmd, args...); err != nil {
		return fmt.Errorf("starting default browser %q: %w", cmd, err)
	}
	return nil
}

func launchPreferredBrowser(ctx context.Context, ops *browserOps, token, rawURL string) error {
	if err := validateBrowserToken(token); err != nil {
		return err
	}

	family := resolveBrowserFamily(token)

	switch ops.goos {
	case osDarwin:
		return launchPreferredDarwin(ctx, ops, family, token, rawURL)
	case osWindows:
		return launchPreferredWindows(ops, family, token, rawURL)
	case osLinux:
		return launchPreferredLinux(ops, family, token, rawURL)
	default:
		return fmt.Errorf("unsupported platform: %s", ops.goos)
	}
}

func launchPreferredDarwin(ctx context.Context, ops *browserOps, family browserFamily, token, rawURL string) error {
	if appName, ok := darwinAppName(family); ok {
		if err := ops.runCmd(ctx, cmdOpen, macOSOpenAppFlag, appName, rawURL); err != nil {
			return fmt.Errorf("launching macOS application %q: %w", appName, err)
		}
		return nil
	}

	if strings.HasSuffix(strings.ToLower(token), macOSAppBundleSuffix) {
		if strings.Contains(token, "/") {
			if err := requireAppBundle(ops.stat, token); err != nil {
				return err
			}
		}
		if err := ops.runCmd(ctx, cmdOpen, macOSOpenAppFlag, token, rawURL); err != nil {
			return fmt.Errorf("launching macOS application %q: %w", token, err)
		}
		return nil
	}

	if strings.Contains(token, "/") {
		if err := requireRegularFile(ops.stat, token); err != nil {
			return err
		}
		if err := ops.startCmd(token, rawURL); err != nil {
			return fmt.Errorf("starting browser executable %q: %w", token, err)
		}
		return nil
	}

	if bin, lookErr := ops.lookPath(token); lookErr == nil && bin != "" {
		if err := ops.startCmd(bin, rawURL); err != nil {
			return fmt.Errorf("starting browser %q: %w", bin, err)
		}
		return nil
	}

	if err := ops.runCmd(ctx, cmdOpen, macOSOpenAppFlag, token, rawURL); err != nil {
		return fmt.Errorf("launching browser %q on macOS: %w", token, err)
	}
	return nil
}

func darwinAppName(family browserFamily) (string, bool) {
	switch family {
	case familyEdge:
		return "Microsoft Edge", true
	case familyChrome:
		return "Google Chrome", true
	case familyChromium:
		return "Chromium", true
	case familyFirefox:
		return "Firefox", true
	case familyBrave:
		return "Brave Browser", true
	case familySafari:
		return "Safari", true
	case familyUnknown:
		// Unknown tokens are resolved via PATH / bundle lookup by the caller.
	}
	return "", false
}

func launchPreferredWindows(ops *browserOps, family browserFamily, token, rawURL string) error {
	if family == familySafari {
		return errors.New("safari is not supported on windows")
	}

	if exeNames, relPaths, ok := windowsCandidates(family); ok {
		for _, name := range exeNames {
			if bin, err := ops.lookPath(name); err == nil && bin != "" {
				if startErr := ops.startCmd(bin, rawURL); startErr != nil {
					return fmt.Errorf("starting browser %q: %w", bin, startErr)
				}
				return nil
			}
		}

		for _, envKey := range []string{envProgramFiles, envProgramFilesX86, envLocalAppData} {
			root := ""
			if ops.getenv != nil {
				root = strings.TrimSpace(ops.getenv(envKey))
			}
			if root == "" {
				continue
			}
			for _, rel := range relPaths {
				candidate := joinWindowsPath(root, rel...)
				if fileExists(ops.stat, candidate) {
					if startErr := ops.startCmd(candidate, rawURL); startErr != nil {
						return fmt.Errorf("starting browser %q: %w", candidate, startErr)
					}
					return nil
				}
			}
		}

		return fmt.Errorf("browser %q not found on PATH or in standard Windows install locations", token)
	}

	if strings.ContainsAny(token, `\/`) || hasWindowsDrivePrefix(token) {
		if err := requireRegularFile(ops.stat, token); err != nil {
			return err
		}
		if err := ops.startCmd(token, rawURL); err != nil {
			return fmt.Errorf("starting browser executable %q: %w", token, err)
		}
		return nil
	}

	candidates := []string{token}
	if !strings.HasSuffix(strings.ToLower(token), windowsExeSuffix) {
		candidates = append(candidates, token+windowsExeSuffix)
	}
	for _, cand := range candidates {
		if bin, err := ops.lookPath(cand); err == nil && bin != "" {
			if startErr := ops.startCmd(bin, rawURL); startErr != nil {
				return fmt.Errorf("starting browser %q: %w", bin, startErr)
			}
			return nil
		}
	}

	return fmt.Errorf("browser %q not found on PATH", token)
}

func windowsCandidates(family browserFamily) ([]string, [][]string, bool) {
	switch family {
	case familyEdge:
		return []string{"msedge.exe", "msedge"},
			[][]string{{"Microsoft", "Edge", "Application", "msedge.exe"}},
			true
	case familyChrome:
		return []string{"chrome.exe", "chrome", "google-chrome"},
			[][]string{{"Google", "Chrome", "Application", "chrome.exe"}},
			true
	case familyChromium:
		return []string{"chromium.exe", "chromium"},
			[][]string{
				{"Chromium", "Application", "chrome.exe"},
				{"Chromium", "Application", "chromium.exe"},
			},
			true
	case familyFirefox:
		return []string{"firefox.exe", "firefox"},
			[][]string{{"Mozilla Firefox", "firefox.exe"}},
			true
	case familyBrave:
		return []string{"brave.exe", "brave"},
			[][]string{{"BraveSoftware", "Brave-Browser", "Application", "brave.exe"}},
			true
	case familySafari, familyUnknown:
		// Handled by caller outside standard Windows family lookup.
	}
	return nil, nil, false
}

func launchPreferredLinux(ops *browserOps, family browserFamily, token, rawURL string) error {
	if family == familySafari {
		return errors.New("safari is not supported on linux")
	}

	if binNames, wslExeNames, wslPaths, ok := linuxCandidates(family); ok {
		for _, name := range binNames {
			if bin, err := ops.lookPath(name); err == nil && bin != "" {
				if startErr := ops.startCmd(bin, rawURL); startErr != nil {
					return fmt.Errorf("starting browser %q: %w", bin, startErr)
				}
				return nil
			}
		}

		wsl := isWSL(ops.getenv)
		if wsl || strings.HasSuffix(strings.ToLower(token), windowsExeSuffix) {
			for _, exeName := range wslExeNames {
				if bin, err := ops.lookPath(exeName); err == nil && bin != "" {
					if startErr := ops.startCmd(bin, rawURL); startErr != nil {
						return fmt.Errorf("starting WSL browser %q: %w", bin, startErr)
					}
					return nil
				}
			}
		}

		if wsl {
			for _, wslPath := range wslPaths {
				if fileExists(ops.stat, wslPath) {
					if startErr := ops.startCmd(wslPath, rawURL); startErr != nil {
						return fmt.Errorf("starting WSL browser %q: %w", wslPath, startErr)
					}
					return nil
				}
			}
		}

		return fmt.Errorf("browser %q not found on PATH", token)
	}

	if strings.Contains(token, "/") {
		if err := requireRegularFile(ops.stat, token); err != nil {
			return err
		}
		if err := ops.startCmd(token, rawURL); err != nil {
			return fmt.Errorf("starting browser executable %q: %w", token, err)
		}
		return nil
	}

	bin, err := ops.lookPath(token)
	if err != nil {
		return fmt.Errorf("browser %q not found on PATH: %w", token, err)
	}
	if startErr := ops.startCmd(bin, rawURL); startErr != nil {
		return fmt.Errorf("starting browser %q: %w", bin, startErr)
	}
	return nil
}

func linuxCandidates(family browserFamily) ([]string, []string, []string, bool) {
	switch family {
	case familyEdge:
		return []string{"microsoft-edge", "microsoft-edge-stable", "msedge"},
			[]string{"msedge.exe"},
			[]string{
				"/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
				"/mnt/c/Program Files/Microsoft/Edge/Application/msedge.exe",
			},
			true
	case familyChrome:
		return []string{"google-chrome", "google-chrome-stable", "chrome"},
			[]string{"chrome.exe"},
			[]string{
				"/mnt/c/Program Files/Google/Chrome/Application/chrome.exe",
				"/mnt/c/Program Files (x86)/Google/Chrome/Application/chrome.exe",
			},
			true
	case familyChromium:
		return []string{"chromium", "chromium-browser"},
			[]string{"chromium.exe"},
			[]string{
				"/mnt/c/Program Files/Chromium/Application/chrome.exe",
				"/mnt/c/Program Files (x86)/Chromium/Application/chrome.exe",
			},
			true
	case familyFirefox:
		return []string{"firefox", "mozilla-firefox"},
			[]string{"firefox.exe"},
			[]string{
				"/mnt/c/Program Files/Mozilla Firefox/firefox.exe",
				"/mnt/c/Program Files (x86)/Mozilla Firefox/firefox.exe",
			},
			true
	case familyBrave:
		return []string{"brave-browser", "brave"},
			[]string{"brave.exe"},
			[]string{
				"/mnt/c/Program Files/BraveSoftware/Brave-Browser/Application/brave.exe",
				"/mnt/c/Program Files (x86)/BraveSoftware/Brave-Browser/Application/brave.exe",
			},
			true
	case familySafari, familyUnknown:
		// Handled by caller outside standard Linux family lookup.
	}
	return nil, nil, nil, false
}

func isWSL(getenv func(string) string) bool {
	if getenv == nil {
		return false
	}
	return getenv(envWSLDistroName) != "" || getenv(envWSLInterop) != ""
}

func fileExists(statFn func(string) (os.FileInfo, error), path string) bool {
	if statFn == nil {
		return false
	}
	info, err := statFn(path)
	return err == nil && info.Mode().IsRegular()
}

func requireAppBundle(statFn func(string) (os.FileInfo, error), path string) error {
	if statFn == nil {
		return fmt.Errorf("macOS application bundle %q cannot be verified", path)
	}
	if _, err := statFn(path); err != nil {
		return fmt.Errorf("macOS application bundle %q not found: %w", path, err)
	}
	return nil
}

func requireRegularFile(statFn func(string) (os.FileInfo, error), path string) error {
	if statFn == nil {
		return fmt.Errorf("browser executable %q cannot be verified", path)
	}
	info, err := statFn(path)
	if err != nil {
		return fmt.Errorf("browser executable %q not found: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("browser executable %q is a directory", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("browser executable %q is not a regular file", path)
	}
	return nil
}

func joinWindowsPath(base string, elems ...string) string {
	out := strings.TrimRight(base, `\/`)
	for _, elem := range elems {
		trimmed := strings.Trim(elem, `\/`)
		if trimmed == "" {
			continue
		}
		out += `\` + trimmed
	}
	return out
}

func hasWindowsDrivePrefix(path string) bool {
	if len(path) < 2 || path[1] != ':' {
		return false
	}
	c := path[0]
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}
