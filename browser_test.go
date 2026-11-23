// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordedCall struct {
	kind string // "start", "start_default", or "run"
	name string
	args []string
}

type fakeFileInfo struct {
	name  string
	isDir bool
	mode  os.FileMode
}

func (f fakeFileInfo) Name() string { return f.name }
func (f fakeFileInfo) Size() int64  { return 0 }
func (f fakeFileInfo) Mode() os.FileMode {
	if f.mode != 0 {
		return f.mode
	}
	if f.isDir {
		return os.ModeDir | 0o755
	}
	return 0o755
}
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.isDir }
func (f fakeFileInfo) Sys() any           { return nil }

type mockBrowserEnv struct {
	goos     string
	env      map[string]string
	pathBins map[string]string
	files    map[string]fakeFileInfo
	startErr map[string]error
	runErr   map[string]error
	calls    []recordedCall
}

func newMockBrowserEnv(goos string) *mockBrowserEnv {
	return &mockBrowserEnv{
		goos:     goos,
		env:      make(map[string]string),
		pathBins: make(map[string]string),
		files:    make(map[string]fakeFileInfo),
		startErr: make(map[string]error),
		runErr:   make(map[string]error),
	}
}

func (m *mockBrowserEnv) ops() *browserOps {
	return &browserOps{
		goos: m.goos,
		getenv: func(key string) string {
			return m.env[key]
		},
		lookPath: func(file string) (string, error) {
			if resolved, ok := m.pathBins[file]; ok {
				return resolved, nil
			}
			return "", errors.New("executable file not found in PATH: " + file)
		},
		stat: func(path string) (os.FileInfo, error) {
			if info, ok := m.files[path]; ok {
				return info, nil
			}
			return nil, os.ErrNotExist
		},
		startCmd: func(name string, args ...string) error {
			m.calls = append(m.calls, recordedCall{
				kind: "start",
				name: name,
				args: append([]string(nil), args...),
			})
			if err, ok := m.startErr[name]; ok {
				return err
			}
			return nil
		},
		startDefaultCmd: func(name string, args ...string) error {
			m.calls = append(m.calls, recordedCall{
				kind: "start_default",
				name: name,
				args: append([]string(nil), args...),
			})
			if err, ok := m.startErr[name]; ok {
				return err
			}
			return nil
		},
		runCmd: func(ctx context.Context, name string, args ...string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			m.calls = append(m.calls, recordedCall{
				kind: "run",
				name: name,
				args: append([]string(nil), args...),
			})
			key := name
			if len(args) >= 2 && args[0] == "-a" {
				key = name + ":" + args[1]
			}
			if err, ok := m.runErr[key]; ok {
				return err
			}
			if err, ok := m.runErr[name]; ok {
				return err
			}
			return nil
		},
	}
}

func TestOpenBrowserWithPreference_URLValidation(t *testing.T) {
	tests := []struct {
		name        string
		rawURL      string
		wantURL     string
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid https OAuth URL with ampersands",
			rawURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8400%2Fcallback&state=xyz123",
			wantURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8400%2Fcallback&state=xyz123",
			wantErr: false,
		},
		{
			name:    "valid http loopback URL",
			rawURL:  "http://127.0.0.1:54321/auth/callback?code=1&state=2",
			wantURL: "http://127.0.0.1:54321/auth/callback?code=1&state=2",
			wantErr: false,
		},
		{
			name:    "valid uppercase HTTPS scheme normalized to lowercase",
			rawURL:  "HTTPS://idp.example.com/authorize?client_id=1&state=2",
			wantURL: "https://idp.example.com/authorize?client_id=1&state=2",
			wantErr: false,
		},
		{
			name:    "valid uppercase HTTP IPv6 loopback normalized to lowercase",
			rawURL:  "HTTP://[::1]:8080/callback?state=ok",
			wantURL: "http://[::1]:8080/callback?state=ok",
			wantErr: false,
		},
		{
			name:        "empty URL rejected",
			rawURL:      "",
			wantErr:     true,
			errContains: "non-HTTP scheme",
		},
		{
			name:        "javascript scheme rejected",
			rawURL:      "javascript:alert(1)",
			wantErr:     true,
			errContains: "non-HTTP scheme",
		},
		{
			name:        "file scheme rejected",
			rawURL:      "file:///etc/passwd",
			wantErr:     true,
			errContains: "non-HTTP scheme",
		},
		{
			name:        "ftp scheme rejected",
			rawURL:      "ftp://example.com/resource",
			wantErr:     true,
			errContains: "non-HTTP scheme",
		},
		{
			name:        "http missing host rejected",
			rawURL:      "http:///callback",
			wantErr:     true,
			errContains: "empty host",
		},
		{
			name:        "https port only empty hostname rejected",
			rawURL:      "https://:8443/callback",
			wantErr:     true,
			errContains: "empty host",
		},
		{
			name:        "http opaque URL without double slash rejected",
			rawURL:      "http:example.com/login",
			wantErr:     true,
			errContains: "empty host",
		},
		{
			name:        "space in URL rejected",
			rawURL:      "https://example.com/auth?scope=openid profile",
			wantErr:     true,
			errContains: "control characters or whitespace",
		},
		{
			name:        "newline in URL rejected",
			rawURL:      "https://example.com/auth\n--evil",
			wantErr:     true,
			errContains: "control characters or whitespace",
		},
		{
			name:        "carriage return in URL rejected",
			rawURL:      "https://example.com/auth\r",
			wantErr:     true,
			errContains: "control characters or whitespace",
		},
		{
			name:        "tab in URL rejected",
			rawURL:      "https://example.com/auth\tfoo",
			wantErr:     true,
			errContains: "control characters or whitespace",
		},
		{
			name:        "NUL byte in URL rejected",
			rawURL:      "https://example.com/auth\x00",
			wantErr:     true,
			errContains: "control characters or whitespace",
		},
		{
			name:        "DEL byte in URL rejected",
			rawURL:      "https://example.com/auth\x7f",
			wantErr:     true,
			errContains: "control characters or whitespace",
		},
		{
			name:        "C1 control rune in URL rejected",
			rawURL:      "https://example.com/auth\u0085",
			wantErr:     true,
			errContains: "control characters or whitespace",
		},
		{
			name:        "invalid UTF-8 in URL rejected",
			rawURL:      "https://example.com/\xff",
			wantErr:     true,
			errContains: "invalid UTF-8",
		},
		{
			name:        "malformed bracketed IPv6 URL rejected",
			rawURL:      "https://[::1:bad/callback",
			wantErr:     true,
			errContains: "invalid browser URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockBrowserEnv(osLinux)
			err := OpenBrowserWithPreference(context.Background(), tt.rawURL, "", withBrowserOps(mock.ops()))
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Empty(t, mock.calls, "invalid URL must never invoke launcher")
				return
			}
			require.NoError(t, err)
			require.Len(t, mock.calls, 1)
			assert.Equal(t, recordedCall{
				kind: "start_default",
				name: "xdg-open",
				args: []string{tt.wantURL},
			}, mock.calls[0])
		})
	}
}

func TestOpenBrowserWithPreference_PreCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mock := newMockBrowserEnv(osLinux)
	mock.pathBins["firefox"] = "/usr/bin/firefox"

	var warnings []string
	err := OpenBrowserWithPreference(
		ctx,
		"https://idp.example.com/authorize?client_id=1&state=2",
		"firefox",
		WithWarningHandler(func(msg string) { warnings = append(warnings, msg) }),
		withBrowserOps(mock.ops()),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, mock.calls)
	assert.Empty(t, warnings)
}

func TestOpenBrowserWithPreference_NilContextAllowed(t *testing.T) {
	mock := newMockBrowserEnv(osLinux)
	err := OpenBrowserWithPreference(nil, "https://idp.example.com/authorize", "", withBrowserOps(mock.ops())) //nolint:staticcheck // intentionally testing nil ctx guard
	require.NoError(t, err)
	require.Len(t, mock.calls, 1)
	assert.Equal(t, "xdg-open", mock.calls[0].name)
}

func TestOpenBrowserWithPreference_SystemDefaultBypassesEnv(t *testing.T) {
	const authURL = "https://idp.example.com/authorize?a=1&b=2"

	tests := []struct {
		name     string
		goos     string
		pref     string
		wantName string
		wantArgs []string
	}{
		{
			name:     "linux default bypasses BROWSER",
			goos:     osLinux,
			pref:     "default",
			wantName: "xdg-open",
			wantArgs: []string{authURL},
		},
		{
			name:     "darwin system bypasses BROWSER",
			goos:     osDarwin,
			pref:     "system",
			wantName: "open",
			wantArgs: []string{authURL},
		},
		{
			name:     "windows DEFAULT case-insensitive bypasses BROWSER",
			goos:     osWindows,
			pref:     " DEFAULT ",
			wantName: "rundll32",
			wantArgs: []string{"url.dll,FileProtocolHandler", authURL},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockBrowserEnv(tt.goos)
			mock.env["BROWSER"] = "firefox"
			mock.pathBins["firefox"] = "/usr/bin/firefox"

			var warnings []string
			err := OpenBrowserWithPreference(
				context.Background(),
				authURL,
				tt.pref,
				WithWarningHandler(func(msg string) { warnings = append(warnings, msg) }),
				withBrowserOps(mock.ops()),
			)
			require.NoError(t, err)
			assert.Empty(t, warnings)
			require.Len(t, mock.calls, 1)
			assert.Equal(t, recordedCall{
				kind: "start_default",
				name: tt.wantName,
				args: tt.wantArgs,
			}, mock.calls[0])
		})
	}
}

func TestOpenBrowserWithPreference_DarwinAliasesAndFallback(t *testing.T) {
	const authURL = "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?client_id=1&state=abc"

	aliases := []struct {
		pref    string
		wantApp string
	}{
		{"msedge", "Microsoft Edge"},
		{"edge", "Microsoft Edge"},
		{"Microsoft Edge", "Microsoft Edge"},
		{"chrome", "Google Chrome"},
		{"google-chrome", "Google Chrome"},
		{"chromium", "Chromium"},
		{"firefox", "Firefox"},
		{"brave", "Brave Browser"},
		{"brave-browser", "Brave Browser"},
		{"safari", "Safari"},
	}

	for _, tt := range aliases {
		t.Run("alias_"+tt.pref, func(t *testing.T) {
			mock := newMockBrowserEnv(osDarwin)
			err := OpenBrowserWithPreference(context.Background(), authURL, tt.pref, withBrowserOps(mock.ops()))
			require.NoError(t, err)
			require.Len(t, mock.calls, 1)
			assert.Equal(t, recordedCall{
				kind: "run",
				name: "open",
				args: []string{"-a", tt.wantApp, authURL},
			}, mock.calls[0])
		})
	}

	t.Run("missing macOS app warns and falls back to open", func(t *testing.T) {
		mock := newMockBrowserEnv(osDarwin)
		mock.runErr["open:Microsoft Edge"] = errors.New("Unable to find application named 'Microsoft Edge'")

		var warnings []string
		err := OpenBrowserWithPreference(
			context.Background(),
			authURL,
			"msedge",
			WithWarningHandler(func(msg string) { warnings = append(warnings, msg) }),
			withBrowserOps(mock.ops()),
		)
		require.NoError(t, err)
		require.Len(t, warnings, 1)
		assert.Contains(t, warnings[0], "msedge")
		assert.Contains(t, warnings[0], "falling back to system default browser")
		require.Len(t, mock.calls, 2)
		assert.Equal(t, recordedCall{
			kind: "run",
			name: "open",
			args: []string{"-a", "Microsoft Edge", authURL},
		}, mock.calls[0])
		assert.Equal(t, recordedCall{
			kind: "start_default",
			name: "open",
			args: []string{authURL},
		}, mock.calls[1])
	})

	t.Run("custom .app bundle path on darwin", func(t *testing.T) {
		mock := newMockBrowserEnv(osDarwin)
		mock.files["/Applications/Arc.app"] = fakeFileInfo{name: "Arc.app", isDir: true}

		err := OpenBrowserWithPreference(context.Background(), authURL, "/Applications/Arc.app", withBrowserOps(mock.ops()))
		require.NoError(t, err)
		require.Len(t, mock.calls, 1)
		assert.Equal(t, recordedCall{
			kind: "run",
			name: "open",
			args: []string{"-a", "/Applications/Arc.app", authURL},
		}, mock.calls[0])
	})

	t.Run("custom executable path on darwin", func(t *testing.T) {
		mock := newMockBrowserEnv(osDarwin)
		mock.files["/opt/homebrew/bin/custom-browser"] = fakeFileInfo{name: "custom-browser"}

		err := OpenBrowserWithPreference(context.Background(), authURL, "/opt/homebrew/bin/custom-browser", withBrowserOps(mock.ops()))
		require.NoError(t, err)
		require.Len(t, mock.calls, 1)
		assert.Equal(t, recordedCall{
			kind: "start",
			name: "/opt/homebrew/bin/custom-browser",
			args: []string{authURL},
		}, mock.calls[0])
	})

	t.Run("custom bare binary on PATH on darwin", func(t *testing.T) {
		mock := newMockBrowserEnv(osDarwin)
		mock.pathBins["qutebrowser"] = "/opt/homebrew/bin/qutebrowser"

		err := OpenBrowserWithPreference(context.Background(), authURL, "qutebrowser", withBrowserOps(mock.ops()))
		require.NoError(t, err)
		require.Len(t, mock.calls, 1)
		assert.Equal(t, recordedCall{
			kind: "start",
			name: "/opt/homebrew/bin/qutebrowser",
			args: []string{authURL},
		}, mock.calls[0])
	})

	t.Run("custom macOS app name not on PATH uses open -a", func(t *testing.T) {
		mock := newMockBrowserEnv(osDarwin)

		err := OpenBrowserWithPreference(context.Background(), authURL, "Arc", withBrowserOps(mock.ops()))
		require.NoError(t, err)
		require.Len(t, mock.calls, 1)
		assert.Equal(t, recordedCall{
			kind: "run",
			name: "open",
			args: []string{"-a", "Arc", authURL},
		}, mock.calls[0])
	})
}

func TestOpenBrowserWithPreference_WindowsDiscoveryAndAmpersandSafety(t *testing.T) {
	// URL intentionally includes multiple '&' query parameters that cmd.exe /c start
	// would truncate or treat as command separators if a shell were ever used.
	const authURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=cid&response_type=code&scope=openid&state=st123"

	t.Run("resolves msedge via LookPath", func(t *testing.T) {
		mock := newMockBrowserEnv(osWindows)
		mock.pathBins["msedge.exe"] = `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`

		err := OpenBrowserWithPreference(context.Background(), authURL, "msedge", withBrowserOps(mock.ops()))
		require.NoError(t, err)
		require.Len(t, mock.calls, 1)
		assert.Equal(t, recordedCall{
			kind: "start",
			name: `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
			args: []string{authURL},
		}, mock.calls[0])
	})

	installTests := []struct {
		name     string
		pref     string
		envKey   string
		envVal   string
		filePath string
	}{
		{
			name:     "edge via ProgramFiles(x86)",
			pref:     "edge",
			envKey:   "ProgramFiles(x86)",
			envVal:   `C:\Program Files (x86)`,
			filePath: `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		},
		{
			name:     "chrome via ProgramFiles",
			pref:     "chrome",
			envKey:   "ProgramFiles",
			envVal:   `C:\Program Files`,
			filePath: `C:\Program Files\Google\Chrome\Application\chrome.exe`,
		},
		{
			name:     "chromium via LocalAppData",
			pref:     "chromium",
			envKey:   "LocalAppData",
			envVal:   `C:\Users\alice\AppData\Local`,
			filePath: `C:\Users\alice\AppData\Local\Chromium\Application\chrome.exe`,
		},
		{
			name:     "firefox via ProgramFiles",
			pref:     "firefox",
			envKey:   "ProgramFiles",
			envVal:   `C:\Program Files`,
			filePath: `C:\Program Files\Mozilla Firefox\firefox.exe`,
		},
		{
			name:     "brave via LocalAppData",
			pref:     "brave",
			envKey:   "LocalAppData",
			envVal:   `C:\Users\alice\AppData\Local`,
			filePath: `C:\Users\alice\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe`,
		},
	}

	for _, tt := range installTests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockBrowserEnv(osWindows)
			mock.env[tt.envKey] = tt.envVal
			mock.files[tt.filePath] = fakeFileInfo{name: "browser.exe"}

			err := OpenBrowserWithPreference(context.Background(), authURL, tt.pref, withBrowserOps(mock.ops()))
			require.NoError(t, err)
			require.Len(t, mock.calls, 1)
			assert.Equal(t, recordedCall{
				kind: "start",
				name: tt.filePath,
				args: []string{authURL},
			}, mock.calls[0])
		})
	}

	t.Run("safari on windows warns and falls back to rundll32", func(t *testing.T) {
		mock := newMockBrowserEnv(osWindows)
		var warnings []string
		err := OpenBrowserWithPreference(
			context.Background(),
			authURL,
			"safari",
			WithWarningHandler(func(msg string) { warnings = append(warnings, msg) }),
			withBrowserOps(mock.ops()),
		)
		require.NoError(t, err)
		require.Len(t, warnings, 1)
		assert.Contains(t, warnings[0], "safari")
		require.Len(t, mock.calls, 1)
		assert.Equal(t, recordedCall{
			kind: "start_default",
			name: "rundll32",
			args: []string{"url.dll,FileProtocolHandler", authURL},
		}, mock.calls[0])
	})

	t.Run("BROWSER env on windows preserves drive-letter colon path", func(t *testing.T) {
		mock := newMockBrowserEnv(osWindows)
		exePath := `C:\Program Files\Mozilla Firefox\firefox.exe`
		mock.env["BROWSER"] = `"` + exePath + `"`
		mock.files[exePath] = fakeFileInfo{name: "firefox.exe"}

		err := OpenBrowserWithPreference(context.Background(), authURL, "", withBrowserOps(mock.ops()))
		require.NoError(t, err)
		require.Len(t, mock.calls, 1)
		assert.Equal(t, recordedCall{
			kind: "start",
			name: exePath,
			args: []string{authURL},
		}, mock.calls[0])
	})

	t.Run("bare custom executable appends .exe on windows", func(t *testing.T) {
		mock := newMockBrowserEnv(osWindows)
		mock.pathBins["vivaldi.exe"] = `C:\Users\alice\AppData\Local\Vivaldi\Application\vivaldi.exe`

		err := OpenBrowserWithPreference(context.Background(), authURL, "vivaldi", withBrowserOps(mock.ops()))
		require.NoError(t, err)
		require.Len(t, mock.calls, 1)
		assert.Equal(t, `C:\Users\alice\AppData\Local\Vivaldi\Application\vivaldi.exe`, mock.calls[0].name)
	})
}

func TestOpenBrowserWithPreference_LinuxAndWSL(t *testing.T) {
	const authURL = "https://idp.example.com/oauth2/authorize?client_id=abc&state=def"

	linuxTests := []struct {
		pref    string
		binName string
		binPath string
	}{
		{"msedge", "microsoft-edge-stable", "/usr/bin/microsoft-edge-stable"},
		{"edge", "microsoft-edge", "/usr/bin/microsoft-edge"},
		{"chrome", "google-chrome-stable", "/usr/bin/google-chrome-stable"},
		{"google-chrome", "google-chrome", "/usr/bin/google-chrome"},
		{"chromium", "chromium-browser", "/usr/bin/chromium-browser"},
		{"firefox", "firefox", "/usr/bin/firefox"},
		{"brave", "brave-browser", "/usr/bin/brave-browser"},
	}

	for _, tt := range linuxTests {
		t.Run("linux_"+tt.pref+"_"+tt.binName, func(t *testing.T) {
			mock := newMockBrowserEnv(osLinux)
			mock.pathBins[tt.binName] = tt.binPath

			err := OpenBrowserWithPreference(context.Background(), authURL, tt.pref, withBrowserOps(mock.ops()))
			require.NoError(t, err)
			require.Len(t, mock.calls, 1)
			assert.Equal(t, recordedCall{
				kind: "start",
				name: tt.binPath,
				args: []string{authURL},
			}, mock.calls[0])
		})
	}

	t.Run("WSL resolves per-user LocalAppData .exe on PATH before /mnt/c Program Files", func(t *testing.T) {
		mock := newMockBrowserEnv(osLinux)
		mock.env["WSL_DISTRO_NAME"] = "Ubuntu"
		localAppChrome := "/mnt/c/Users/alice/AppData/Local/Google/Chrome/Application/chrome.exe"
		mock.pathBins["chrome.exe"] = localAppChrome

		err := OpenBrowserWithPreference(context.Background(), authURL, "chrome", withBrowserOps(mock.ops()))
		require.NoError(t, err)
		require.Len(t, mock.calls, 1)
		assert.Equal(t, recordedCall{
			kind: "start",
			name: localAppChrome,
			args: []string{authURL},
		}, mock.calls[0])
	})

	t.Run("WSL falls back to /mnt/c msedge.exe only when file exists via stat", func(t *testing.T) {
		mock := newMockBrowserEnv(osLinux)
		mock.env["WSL_DISTRO_NAME"] = "Ubuntu"
		wslEdge := "/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
		mock.files[wslEdge] = fakeFileInfo{name: "msedge.exe"}

		err := OpenBrowserWithPreference(context.Background(), authURL, "msedge", withBrowserOps(mock.ops()))
		require.NoError(t, err)
		require.Len(t, mock.calls, 1)
		assert.Equal(t, recordedCall{
			kind: "start",
			name: wslEdge,
			args: []string{authURL},
		}, mock.calls[0])
	})

	t.Run("non-WSL linux ignores /mnt/c binaries and falls back to xdg-open", func(t *testing.T) {
		mock := newMockBrowserEnv(osLinux)
		wslEdge := "/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
		mock.files[wslEdge] = fakeFileInfo{name: "msedge.exe"}

		var warnings []string
		err := OpenBrowserWithPreference(
			context.Background(),
			authURL,
			"msedge",
			WithWarningHandler(func(msg string) { warnings = append(warnings, msg) }),
			withBrowserOps(mock.ops()),
		)
		require.NoError(t, err)
		require.Len(t, warnings, 1)
		require.Len(t, mock.calls, 1)
		assert.Equal(t, "xdg-open", mock.calls[0].name)
	})

	t.Run("safari on linux warns and falls back to xdg-open", func(t *testing.T) {
		mock := newMockBrowserEnv(osLinux)
		var warnings []string
		err := OpenBrowserWithPreference(
			context.Background(),
			authURL,
			"safari",
			WithWarningHandler(func(msg string) { warnings = append(warnings, msg) }),
			withBrowserOps(mock.ops()),
		)
		require.NoError(t, err)
		require.Len(t, warnings, 1)
		assert.Contains(t, warnings[0], "safari")
		require.Len(t, mock.calls, 1)
		assert.Equal(t, "xdg-open", mock.calls[0].name)
	})

	t.Run("explicit executable path on linux", func(t *testing.T) {
		mock := newMockBrowserEnv(osLinux)
		mock.files["/opt/browsers/custom-firefox"] = fakeFileInfo{name: "custom-firefox"}

		err := OpenBrowserWithPreference(context.Background(), authURL, "/opt/browsers/custom-firefox", withBrowserOps(mock.ops()))
		require.NoError(t, err)
		require.Len(t, mock.calls, 1)
		assert.Equal(t, "/opt/browsers/custom-firefox", mock.calls[0].name)
	})

	t.Run("directory path rejected with warning and fallback", func(t *testing.T) {
		mock := newMockBrowserEnv(osLinux)
		mock.files["/opt/browsers"] = fakeFileInfo{name: "browsers", isDir: true}

		var warnings []string
		err := OpenBrowserWithPreference(
			context.Background(),
			authURL,
			"/opt/browsers",
			WithWarningHandler(func(msg string) { warnings = append(warnings, msg) }),
			withBrowserOps(mock.ops()),
		)
		require.NoError(t, err)
		require.Len(t, warnings, 1)
		assert.Contains(t, warnings[0], "is a directory")
		require.Len(t, mock.calls, 1)
		assert.Equal(t, "xdg-open", mock.calls[0].name)
	})

	t.Run("dash-prefixed preference rejected to prevent flag injection", func(t *testing.T) {
		mock := newMockBrowserEnv(osLinux)
		var warnings []string
		err := OpenBrowserWithPreference(
			context.Background(),
			authURL,
			"--evil-flag",
			WithWarningHandler(func(msg string) { warnings = append(warnings, msg) }),
			withBrowserOps(mock.ops()),
		)
		require.NoError(t, err)
		require.Len(t, warnings, 1)
		assert.Contains(t, warnings[0], "must not start with '-'")
		require.Len(t, mock.calls, 1)
		assert.Equal(t, "xdg-open", mock.calls[0].name)
	})
}

func TestOpenBrowserWithPreference_BrowserEnvColonChainAndFallback(t *testing.T) {
	const authURL = "https://idp.example.com/authorize?state=123"

	t.Run("colon-separated BROWSER uses second candidate when first missing", func(t *testing.T) {
		mock := newMockBrowserEnv(osLinux)
		mock.env["BROWSER"] = "missing-browser:chromium:firefox"
		mock.pathBins["chromium"] = "/usr/bin/chromium"
		mock.pathBins["firefox"] = "/usr/bin/firefox"

		var warnings []string
		err := OpenBrowserWithPreference(
			context.Background(),
			authURL,
			"",
			WithWarningHandler(func(msg string) { warnings = append(warnings, msg) }),
			withBrowserOps(mock.ops()),
		)
		require.NoError(t, err)
		assert.Empty(t, warnings)
		require.Len(t, mock.calls, 1)
		assert.Equal(t, "/usr/bin/chromium", mock.calls[0].name)
	})

	t.Run("all BROWSER entries failing warns and falls back to OS default", func(t *testing.T) {
		mock := newMockBrowserEnv(osLinux)
		mock.env["BROWSER"] = "missing-one:missing-two"

		var warnings []string
		err := OpenBrowserWithPreference(
			context.Background(),
			authURL,
			"",
			WithWarningHandler(func(msg string) { warnings = append(warnings, msg) }),
			withBrowserOps(mock.ops()),
		)
		require.NoError(t, err)
		require.Len(t, warnings, 1)
		assert.Contains(t, warnings[0], "$BROWSER")
		assert.Contains(t, warnings[0], "missing-one:missing-two")
		require.Len(t, mock.calls, 1)
		assert.Equal(t, "xdg-open", mock.calls[0].name)
	})

	t.Run("explicit preference takes priority over BROWSER", func(t *testing.T) {
		mock := newMockBrowserEnv(osLinux)
		mock.env["BROWSER"] = "firefox"
		mock.pathBins["firefox"] = "/usr/bin/firefox"
		mock.pathBins["microsoft-edge"] = "/usr/bin/microsoft-edge"

		err := OpenBrowserWithPreference(context.Background(), authURL, "msedge", withBrowserOps(mock.ops()))
		require.NoError(t, err)
		require.Len(t, mock.calls, 1)
		assert.Equal(t, "/usr/bin/microsoft-edge", mock.calls[0].name)
	})

	t.Run("error returned only when both preference and OS default fail", func(t *testing.T) {
		mock := newMockBrowserEnv(osLinux)
		mock.startErr["xdg-open"] = errors.New("xdg-open not installed")

		var warnings []string
		err := OpenBrowserWithPreference(
			context.Background(),
			authURL,
			"msedge",
			WithWarningHandler(func(msg string) { warnings = append(warnings, msg) }),
			withBrowserOps(mock.ops()),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "xdg-open not installed")
		require.Len(t, warnings, 1)
	})

	t.Run("unsupported platform returns error", func(t *testing.T) {
		mock := newMockBrowserEnv("plan9")
		err := OpenBrowserWithPreference(context.Background(), authURL, "", withBrowserOps(mock.ops()))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported platform: plan9")
	})

	t.Run("unsupported platform with preference warns and returns fallback error", func(t *testing.T) {
		mock := newMockBrowserEnv("plan9")
		var warnings []string
		err := OpenBrowserWithPreference(
			context.Background(),
			authURL,
			"firefox",
			WithWarningHandler(func(msg string) { warnings = append(warnings, msg) }),
			withBrowserOps(mock.ops()),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported platform: plan9")
		require.Len(t, warnings, 1)
	})

	t.Run("BROWSER set to system uses OS default directly", func(t *testing.T) {
		mock := newMockBrowserEnv(osLinux)
		mock.env["BROWSER"] = "system"
		err := OpenBrowserWithPreference(context.Background(), authURL, "", withBrowserOps(mock.ops()))
		require.NoError(t, err)
		require.Len(t, mock.calls, 1)
		assert.Equal(t, "start_default", mock.calls[0].kind)
		assert.Equal(t, "xdg-open", mock.calls[0].name)
	})

	t.Run("BROWSER default:firefox falls through to firefox when OS default fails", func(t *testing.T) {
		mock := newMockBrowserEnv(osLinux)
		mock.env["BROWSER"] = "default:firefox"
		mock.startErr["xdg-open"] = errors.New("xdg-open missing")
		mock.pathBins["firefox"] = "/usr/bin/firefox"

		var warnings []string
		err := OpenBrowserWithPreference(
			context.Background(),
			authURL,
			"",
			WithWarningHandler(func(msg string) { warnings = append(warnings, msg) }),
			withBrowserOps(mock.ops()),
		)
		require.NoError(t, err)
		assert.Empty(t, warnings)
		require.Len(t, mock.calls, 2)
		assert.Equal(t, "xdg-open", mock.calls[0].name)
		assert.Equal(t, "/usr/bin/firefox", mock.calls[1].name)
	})

	t.Run("BROWSER failure plus OS default failure returns error", func(t *testing.T) {
		mock := newMockBrowserEnv(osLinux)
		mock.env["BROWSER"] = "missing"
		mock.startErr["xdg-open"] = errors.New("no display")

		err := OpenBrowserWithPreference(context.Background(), authURL, "", withBrowserOps(mock.ops()))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no display")
	})

	t.Run("OpenBrowser backward compatibility rejects invalid URL and canceled ctx", func(t *testing.T) {
		err := OpenBrowser(context.Background(), "ftp://example.com")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "non-HTTP scheme")

		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		err = OpenBrowser(canceled, authURL)
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestOpenBrowserWithPreference_ErrorPathsAndTokenValidation(t *testing.T) {
	const authURL = "https://idp.example.com/authorize?state=errpaths"

	t.Run("control char and invalid UTF-8 browser tokens warn and fall back", func(t *testing.T) {
		for _, badPref := range []string{"firefox\x00", "firefox\x7f", "firefox\xff"} {
			mock := newMockBrowserEnv(osLinux)
			var warnings []string
			err := OpenBrowserWithPreference(
				context.Background(),
				authURL,
				badPref,
				WithWarningHandler(func(msg string) { warnings = append(warnings, msg) }),
				withBrowserOps(mock.ops()),
			)
			require.NoError(t, err)
			require.Len(t, warnings, 1)
			require.Len(t, mock.calls, 1)
			assert.Equal(t, "xdg-open", mock.calls[0].name)
		}
		assert.Error(t, validateBrowserToken(""))
	})

	t.Run("darwin error paths fall back cleanly", func(t *testing.T) {
		// Missing .app path
		mock := newMockBrowserEnv(osDarwin)
		err := OpenBrowserWithPreference(context.Background(), authURL, "/Applications/Missing.app", withBrowserOps(mock.ops()))
		require.NoError(t, err)
		assert.Equal(t, "open", mock.calls[len(mock.calls)-1].name)

		// Existing .app path whose open -a fails
		mock = newMockBrowserEnv(osDarwin)
		mock.files["/Applications/Broken.app"] = fakeFileInfo{name: "Broken.app", isDir: true}
		mock.runErr["open:/Applications/Broken.app"] = errors.New("launch failed")
		err = OpenBrowserWithPreference(context.Background(), authURL, "/Applications/Broken.app", withBrowserOps(mock.ops()))
		require.NoError(t, err)

		// Missing explicit binary path and start failure on existing binary path
		mock = newMockBrowserEnv(osDarwin)
		err = OpenBrowserWithPreference(context.Background(), authURL, "/opt/missing/browser", withBrowserOps(mock.ops()))
		require.NoError(t, err)

		mock = newMockBrowserEnv(osDarwin)
		mock.files["/opt/broken/browser"] = fakeFileInfo{name: "browser"}
		mock.startErr["/opt/broken/browser"] = errors.New("exec format error")
		err = OpenBrowserWithPreference(context.Background(), authURL, "/opt/broken/browser", withBrowserOps(mock.ops()))
		require.NoError(t, err)

		// Bare binary on PATH failing to start, and bare unknown app failing open -a
		mock = newMockBrowserEnv(osDarwin)
		mock.pathBins["broken-cli"] = "/usr/local/bin/broken-cli"
		mock.startErr["/usr/local/bin/broken-cli"] = errors.New("boom")
		err = OpenBrowserWithPreference(context.Background(), authURL, "broken-cli", withBrowserOps(mock.ops()))
		require.NoError(t, err)

		mock = newMockBrowserEnv(osDarwin)
		mock.runErr["open:UnknownApp"] = errors.New("not found")
		err = OpenBrowserWithPreference(context.Background(), authURL, "UnknownApp", withBrowserOps(mock.ops()))
		require.NoError(t, err)
	})

	t.Run("darwin mid-launch context cancellation aborts without fallback", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		mock := newMockBrowserEnv(osDarwin)
		ops := mock.ops()
		ops.runCmd = func(_ context.Context, _ string, _ ...string) error {
			cancel()
			return context.Canceled
		}
		err := OpenBrowserWithPreference(ctx, authURL, "msedge", withBrowserOps(ops))
		require.ErrorIs(t, err, context.Canceled)
		assert.Empty(t, mock.calls, "must not launch OS default after ctx cancel")
	})

	t.Run("windows error paths fall back cleanly", func(t *testing.T) {
		// LookPath hit fails startCmd
		mock := newMockBrowserEnv(osWindows)
		mock.pathBins["msedge.exe"] = `C:\Edge\msedge.exe`
		mock.startErr[`C:\Edge\msedge.exe`] = errors.New("access denied")
		require.NoError(t, OpenBrowserWithPreference(context.Background(), authURL, "msedge", withBrowserOps(mock.ops())))

		// Install-dir hit fails startCmd
		mock = newMockBrowserEnv(osWindows)
		mock.env["ProgramFiles"] = `C:\Program Files`
		exe := `C:\Program Files\Google\Chrome\Application\chrome.exe`
		mock.files[exe] = fakeFileInfo{name: "chrome.exe"}
		mock.startErr[exe] = errors.New("access denied")
		require.NoError(t, OpenBrowserWithPreference(context.Background(), authURL, "chrome", withBrowserOps(mock.ops())))

		// Explicit drive path missing and failing startCmd
		mock = newMockBrowserEnv(osWindows)
		require.NoError(t, OpenBrowserWithPreference(context.Background(), authURL, `C:\Missing\browser.exe`, withBrowserOps(mock.ops())))

		mock = newMockBrowserEnv(osWindows)
		mock.files[`d:\Apps\browser.exe`] = fakeFileInfo{name: "browser.exe"}
		mock.startErr[`d:\Apps\browser.exe`] = errors.New("bad image")
		require.NoError(t, OpenBrowserWithPreference(context.Background(), authURL, `d:\Apps\browser.exe`, withBrowserOps(mock.ops())))

		// Bare custom command missing or failing startCmd
		mock = newMockBrowserEnv(osWindows)
		require.NoError(t, OpenBrowserWithPreference(context.Background(), authURL, "nonexistent", withBrowserOps(mock.ops())))

		mock = newMockBrowserEnv(osWindows)
		mock.pathBins["vivaldi"] = `C:\Vivaldi\vivaldi.exe`
		mock.startErr[`C:\Vivaldi\vivaldi.exe`] = errors.New("fail")
		require.NoError(t, OpenBrowserWithPreference(context.Background(), authURL, "vivaldi", withBrowserOps(mock.ops())))
	})

	t.Run("linux and WSL error paths fall back cleanly", func(t *testing.T) {
		// LookPath hit fails startCmd
		mock := newMockBrowserEnv(osLinux)
		mock.pathBins["firefox"] = "/usr/bin/firefox"
		mock.startErr["/usr/bin/firefox"] = errors.New("perm denied")
		require.NoError(t, OpenBrowserWithPreference(context.Background(), authURL, "firefox", withBrowserOps(mock.ops())))

		// WSL_INTEROP path hit fails startCmd (and covers chrome/chromium/firefox/brave WSL candidates)
		for _, pref := range []string{"chrome", "chromium", "firefox", "brave"} {
			mock = newMockBrowserEnv(osLinux)
			mock.env["WSL_INTEROP"] = "/run/WSL/1_interop"
			require.NoError(t, OpenBrowserWithPreference(context.Background(), authURL, pref, withBrowserOps(mock.ops())))
		}

		mock = newMockBrowserEnv(osLinux)
		mock.env["WSL_INTEROP"] = "/run/WSL/1_interop"
		wslChrome := "/mnt/c/Program Files/Google/Chrome/Application/chrome.exe"
		mock.files[wslChrome] = fakeFileInfo{name: "chrome.exe"}
		mock.startErr[wslChrome] = errors.New("wsl interop disabled")
		require.NoError(t, OpenBrowserWithPreference(context.Background(), authURL, "chrome", withBrowserOps(mock.ops())))

		// Explicit path startCmd error & bare command startCmd error
		mock = newMockBrowserEnv(osLinux)
		mock.files["/opt/custom"] = fakeFileInfo{name: "custom"}
		mock.startErr["/opt/custom"] = errors.New("exec error")
		require.NoError(t, OpenBrowserWithPreference(context.Background(), authURL, "/opt/custom", withBrowserOps(mock.ops())))

		mock = newMockBrowserEnv(osLinux)
		mock.pathBins["epiphany"] = "/usr/bin/epiphany"
		mock.startErr["/usr/bin/epiphany"] = errors.New("exec error")
		require.NoError(t, OpenBrowserWithPreference(context.Background(), authURL, "epiphany", withBrowserOps(mock.ops())))
	})

	t.Run("startDetachedProcess returns error when binary missing", func(t *testing.T) {
		err := startDetachedProcess(filepath.Join(t.TempDir(), "does-not-exist"))
		require.Error(t, err)
	})

	t.Run("helper nil guards and stripEnvKey", func(t *testing.T) {
		assert.False(t, isWSL(nil))
		assert.False(t, fileExists(nil, "/tmp"))
		assert.Error(t, requireAppBundle(nil, "/Applications/Test.app"))
		assert.Error(t, requireRegularFile(nil, "/tmp/x"))
		fifoStats := func(string) (os.FileInfo, error) {
			return fakeFileInfo{name: "pipe", mode: os.ModeNamedPipe | 0o600}, nil
		}
		assert.ErrorContains(t, requireRegularFile(fifoStats, "/tmp/pipe"), "not a regular file")
		assert.Equal(t, `C:\Program Files\App\bin.exe`, joinWindowsPath(`C:\Program Files\`, "", `\App\`, "bin.exe"))
		assert.False(t, hasWindowsDrivePrefix("x"))
		assert.False(t, hasWindowsDrivePrefix("1:/foo"))
		assert.Nil(t, stripBrowserEnv([]string{"PATH=/usr/bin", "HOME=/tmp"}))
		stripped := stripBrowserEnv([]string{"PATH=/usr/bin", "BROWSER=firefox", "browser=chrome"})
		assert.Equal(t, []string{"PATH=/usr/bin"}, stripped)
		onlyBrowser := stripBrowserEnv([]string{"BROWSER=firefox"})
		require.NotNil(t, onlyBrowser)
		assert.Empty(t, onlyBrowser)
	})
}

func TestOpenBrowserWithPreference_DetachedProcessSurvivesContextCancel(t *testing.T) {
	// Exercise the real startDetachedProcess, startSystemDefaultProcess, and
	// runProcess helpers using the current test binary as a harmless helper
	// subprocess (never opening a real browser). Verifies that canceling ctx
	// immediately after launch does NOT kill the spawned process before it
	// completes its post-cancel marker write, and that startSystemDefaultProcess
	// strips BROWSER from the child environment.
	markerPath := filepath.Join(t.TempDir(), "survived.txt")
	t.Setenv("GO_WANT_OAUTH_BROWSER_HELPER", "1")
	t.Setenv("GO_OAUTH_BROWSER_MARKER_FILE", markerPath)
	t.Setenv("BROWSER", "")

	exePath, err := os.Executable()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	realOps := defaultBrowserOps()
	ops := &browserOps{
		goos:     realOps.goos,
		getenv:   func(string) string { return "" },
		lookPath: realOps.lookPath,
		stat:     realOps.stat,
		startCmd: func(name string, args ...string) error {
			if name != exePath {
				return fmt.Errorf("unexpected binary %q", name)
			}
			helperArgs := append([]string{"-test.run=^TestBrowserHelperProcess$", "--"}, args...)
			return realOps.startCmd(name, helperArgs...)
		},
		startDefaultCmd: func(name string, args ...string) error {
			return fmt.Errorf("unexpected fallback to system default %q", name)
		},
		runCmd: realOps.runCmd,
	}

	var warnings []string
	err = OpenBrowserWithPreference(
		ctx,
		"https://idp.example.com/authorize?state=survive",
		exePath,
		WithWarningHandler(func(msg string) { warnings = append(warnings, msg) }),
		withBrowserOps(ops),
	)
	require.NoError(t, err)
	assert.Empty(t, warnings)

	// Immediately cancel the login context (simulating Login(ctx) completing).
	cancel()

	require.Eventually(t, func() bool {
		data, readErr := os.ReadFile(markerPath)
		return readErr == nil && string(data) == "https://idp.example.com/authorize?state=survive|"
	}, 3*time.Second, 20*time.Millisecond, "detached browser process must survive login ctx cancellation")

	// Verify startSystemDefaultProcess strips $BROWSER from the child process env.
	defaultMarker := filepath.Join(t.TempDir(), "default-no-browser.txt")
	t.Setenv("GO_OAUTH_BROWSER_MARKER_FILE", defaultMarker)
	t.Setenv("BROWSER", "should-be-stripped")
	err = realOps.startDefaultCmd(exePath, "-test.run=^TestBrowserHelperProcess$", "--", "https://idp.example.com/default")
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		data, readErr := os.ReadFile(defaultMarker)
		return readErr == nil && string(data) == "https://idp.example.com/default|"
	}, 3*time.Second, 20*time.Millisecond, "startSystemDefaultProcess must strip BROWSER from child env")

	// Also exercise realOps.runCmd with the same harmless helper process.
	runMarker := filepath.Join(t.TempDir(), "run-ok.txt")
	t.Setenv("GO_OAUTH_BROWSER_MARKER_FILE", runMarker)
	err = realOps.runCmd(context.Background(), exePath, "-test.run=^TestBrowserHelperProcess$", "--", "https://idp.example.com/run")
	require.NoError(t, err)
	data, err := os.ReadFile(runMarker)
	require.NoError(t, err)
	assert.Equal(t, "https://idp.example.com/run|should-be-stripped", string(data))
}

func TestBrowserHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_OAUTH_BROWSER_HELPER") != "1" {
		return
	}
	var targetURL string
	for i, arg := range os.Args {
		if arg == "--" && i+1 < len(os.Args) {
			targetURL = os.Args[i+1]
			break
		}
	}
	// Sleep briefly so the parent test has already canceled ctx before we write
	// the survival marker.
	time.Sleep(120 * time.Millisecond)
	if marker := os.Getenv("GO_OAUTH_BROWSER_MARKER_FILE"); marker != "" {
		payload := targetURL + "|" + os.Getenv("BROWSER")
		_ = os.WriteFile(marker, []byte(payload), 0o600)
	}
	os.Exit(0)
}
