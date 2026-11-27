// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testDeviceToken struct {
	AccessToken string
}

type stubTimeoutError struct {
	msg     string
	timeout bool
}

func (e stubTimeoutError) Error() string { return e.msg }
func (e stubTimeoutError) Timeout() bool { return e.timeout }

// virtualPollClock records sleep durations and advances a deterministic virtual
// clock across both Sleep calls and simulated HTTP exchange round-trips without
// performing any real time.Sleep.
type virtualPollClock struct {
	now          time.Duration
	sleeps       []time.Duration
	pollStartsAt []time.Duration
}

func (c *virtualPollClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.sleeps = append(c.sleeps, d)
	c.now += d
	return nil
}

func TestPollDeviceToken_PostResponseSpacing(t *testing.T) {
	clock := &virtualPollClock{}
	const exchangeLatency = 200 * time.Millisecond

	attempt := 0
	tok, err := PollDeviceToken(
		context.Background(),
		DevicePollConfig{
			Interval: 5 * time.Second,
			Sleep:    clock.sleep,
		},
		func(_ context.Context) (*testDeviceToken, *DevicePollError, error) {
			clock.pollStartsAt = append(clock.pollStartsAt, clock.now)
			// Simulate a 200ms HTTP round-trip on every poll attempt.
			clock.now += exchangeLatency
			attempt++
			if attempt < 3 {
				return nil, &DevicePollError{Code: "authorization_pending"}, nil
			}
			return &testDeviceToken{AccessToken: "tok-123"}, nil, nil
		},
	)

	require.NoError(t, err)
	require.NotNil(t, tok)
	assert.Equal(t, "tok-123", tok.AccessToken)

	// Every wait must be a full 5s + 1s = 6s AFTER the previous 200ms exchange
	// finished rather than subtracting exchange latency on a fixed-rate ticker.
	assert.Equal(t, []time.Duration{
		6 * time.Second,
		6 * time.Second,
		6 * time.Second,
	}, clock.sleeps)
	assert.Equal(t, []time.Duration{
		6 * time.Second,
		12*time.Second + 200*time.Millisecond,
		18*time.Second + 400*time.Millisecond,
	}, clock.pollStartsAt)
}

func TestPollDeviceToken_Cases(t *testing.T) {
	customAADSTSErr := errors.New("AADSTS700016: application not found in tenant")
	transientNetErr := errors.New("dial tcp: temporary network unreachable")
	wrappedTimeoutErr := &url.Error{
		Op:  "Post",
		URL: "https://example.com/oauth/token",
		Err: fmt.Errorf("transport read: %w", stubTimeoutError{msg: "i/o timeout", timeout: true}),
	}
	wrappedNonTimeoutErr := &url.Error{
		Op:  "Post",
		URL: "https://example.com/oauth/token",
		Err: stubTimeoutError{msg: "connection reset", timeout: false},
	}
	untrustedLongCause := errors.New("\x1b[31mprovider raw error\x07\r\n" + strings.Repeat("z", 700))

	type step struct {
		token   *testDeviceToken
		pollErr *DevicePollError
		err     error
		cancel  bool
	}

	tests := []struct {
		name               string
		cfg                DevicePollConfig
		steps              []step
		wantToken          string
		wantErrIs          []error
		wantErrSame        error
		wantPollErrCode    string
		wantErrContains    string
		wantNoControlRunes bool
		wantMaxErrRunes    int
		wantSleeps         []time.Duration
		wantSlowDowns      []time.Duration
		wantTransientCount int
	}{
		{
			name: "defaults use 5s interval plus 1s safety margin",
			cfg:  DevicePollConfig{},
			steps: []step{
				{pollErr: &DevicePollError{Code: "authorization_pending"}},
				{token: &testDeviceToken{AccessToken: "default-ok"}},
			},
			wantToken:  "default-ok",
			wantSleeps: []time.Duration{6 * time.Second, 6 * time.Second},
		},
		{
			name: "server interval below MinInterval is clamped up",
			cfg: DevicePollConfig{
				Interval:    2 * time.Second,
				MinInterval: 5 * time.Second,
			},
			steps: []step{
				{token: &testDeviceToken{AccessToken: "clamped-ok"}},
			},
			wantToken:  "clamped-ok",
			wantSleeps: []time.Duration{6 * time.Second},
		},
		{
			name: "server interval above MinInterval is honored",
			cfg: DevicePollConfig{
				Interval:     10 * time.Second,
				SafetyMargin: 2 * time.Second,
			},
			steps: []step{
				{token: &testDeviceToken{AccessToken: "custom-interval"}},
			},
			wantToken:  "custom-interval",
			wantSleeps: []time.Duration{12 * time.Second},
		},
		{
			name: "DisableSafetyMargin allows exact zero margin",
			cfg: DevicePollConfig{
				Interval:            5 * time.Second,
				SafetyMargin:        3 * time.Second,
				DisableSafetyMargin: true,
			},
			steps: []step{
				{token: &testDeviceToken{AccessToken: "zero-margin"}},
			},
			wantToken:  "zero-margin",
			wantSleeps: []time.Duration{5 * time.Second},
		},
		{
			name: "negative config durations fall back to safe defaults",
			cfg: DevicePollConfig{
				Interval:          -3 * time.Second,
				MinInterval:       -1 * time.Second,
				SafetyMargin:      -2 * time.Second,
				SlowDownIncrement: -5 * time.Second,
			},
			steps: []step{
				{pollErr: &DevicePollError{Code: "slow_down", Interval: -10}},
				{token: &testDeviceToken{AccessToken: "neg-safe"}},
			},
			wantToken:     "neg-safe",
			wantSleeps:    []time.Duration{6 * time.Second, 11 * time.Second},
			wantSlowDowns: []time.Duration{10 * time.Second},
		},
		{
			name: "positive SlowDownIncrement below 5s is clamped up to 5s",
			cfg: DevicePollConfig{
				Interval:          5 * time.Second,
				SlowDownIncrement: time.Second,
			},
			steps: []step{
				{pollErr: &DevicePollError{Code: "slow_down"}},
				{token: &testDeviceToken{AccessToken: "clamped-slowdown"}},
			},
			wantToken:     "clamped-slowdown",
			wantSleeps:    []time.Duration{6 * time.Second, 11 * time.Second},
			wantSlowDowns: []time.Duration{10 * time.Second},
		},
		{
			name: "SlowDownIncrement above 5s is honored",
			cfg: DevicePollConfig{
				Interval:          5 * time.Second,
				SlowDownIncrement: 8 * time.Second,
			},
			steps: []step{
				{pollErr: &DevicePollError{Code: "slow_down"}},
				{token: &testDeviceToken{AccessToken: "custom-slowdown"}},
			},
			wantToken:     "custom-slowdown",
			wantSleeps:    []time.Duration{6 * time.Second, 14 * time.Second},
			wantSlowDowns: []time.Duration{13 * time.Second},
		},
		{
			name: "slow_down adds default 5s increment cumulatively",
			cfg: DevicePollConfig{
				Interval: 5 * time.Second,
			},
			steps: []step{
				{pollErr: &DevicePollError{Code: "slow_down"}},
				{pollErr: &DevicePollError{Code: "slow_down", Interval: 12}},
				{token: &testDeviceToken{AccessToken: "slowed-ok"}},
			},
			wantToken: "slowed-ok",
			wantSleeps: []time.Duration{
				6 * time.Second,
				11 * time.Second,
				16 * time.Second,
			},
			wantSlowDowns: []time.Duration{10 * time.Second, 15 * time.Second},
		},
		{
			name: "slow_down honors larger server-supplied Interval",
			cfg: DevicePollConfig{
				Interval: 5 * time.Second,
			},
			steps: []step{
				{pollErr: &DevicePollError{Code: "slow_down", Interval: 15}},
				{pollErr: &DevicePollError{Code: "authorization_pending"}},
				{token: &testDeviceToken{AccessToken: "srv-interval-ok"}},
			},
			wantToken: "srv-interval-ok",
			wantSleeps: []time.Duration{
				6 * time.Second,
				16 * time.Second,
				16 * time.Second,
			},
			wantSlowDowns: []time.Duration{15 * time.Second},
		},
		{
			name: "expired_token wraps ErrDeviceCodeExpired and DevicePollError with description",
			cfg:  DevicePollConfig{},
			steps: []step{
				{pollErr: &DevicePollError{Code: "expired_token", Description: "The device code has expired."}},
			},
			wantErrIs:       []error{ErrDeviceCodeExpired},
			wantPollErrCode: "expired_token",
			wantErrContains: "The device code has expired.",
			wantSleeps:      []time.Duration{6 * time.Second},
		},
		{
			name: "expired_token without description wraps ErrDeviceCodeExpired, DevicePollError, and Cause",
			cfg:  DevicePollConfig{},
			steps: []step{
				{pollErr: &DevicePollError{Code: "expired_token", Cause: transientNetErr}},
			},
			wantErrIs:       []error{ErrDeviceCodeExpired, transientNetErr},
			wantPollErrCode: "expired_token",
			wantErrContains: "expired_token",
			wantSleeps:      []time.Duration{6 * time.Second},
		},
		{
			name: "access_denied wraps ErrDeviceAccessDenied, sanitizes description, and preserves Cause",
			cfg:  DevicePollConfig{},
			steps: []step{
				{pollErr: &DevicePollError{
					Code:        "access_denied",
					Description: "\x1b[31mEnd-user denied authorization\x07",
					Cause:       transientNetErr,
				}},
			},
			wantErrIs:          []error{ErrDeviceAccessDenied, transientNetErr},
			wantPollErrCode:    "access_denied",
			wantErrContains:    "End-user denied authorization",
			wantNoControlRunes: true,
			wantSleeps:         []time.Duration{6 * time.Second},
		},
		{
			name: "expired_token without description sanitizes and caps Cause while preserving Unwrap",
			cfg:  DevicePollConfig{},
			steps: []step{
				{pollErr: &DevicePollError{Code: "expired_token", Cause: untrustedLongCause}},
			},
			wantErrIs:          []error{ErrDeviceCodeExpired, untrustedLongCause},
			wantPollErrCode:    "expired_token",
			wantErrContains:    "provider raw error",
			wantNoControlRunes: true,
			wantMaxErrRunes:    len("device code expired (expired_token): ") + maxOAuthErrorDescRunes,
			wantSleeps:         []time.Duration{6 * time.Second},
		},
		{
			name: "access_denied with description and untrusted Cause sanitizes and caps both while preserving Unwrap",
			cfg:  DevicePollConfig{},
			steps: []step{
				{pollErr: &DevicePollError{
					Code:        "access_denied",
					Description: "\x1b[31mEnd-user denied authorization\x07 " + strings.Repeat("d", 700),
					Cause:       untrustedLongCause,
				}},
			},
			wantErrIs:          []error{ErrDeviceAccessDenied, untrustedLongCause},
			wantPollErrCode:    "access_denied",
			wantErrContains:    "provider raw error",
			wantNoControlRunes: true,
			wantMaxErrRunes:    len("device authorization denied: : ") + 2*maxOAuthErrorDescRunes,
			wantSleeps:         []time.Duration{6 * time.Second},
		},
		{
			name: "authorization_declined wraps ErrDeviceAccessDenied and DevicePollError",
			cfg:  DevicePollConfig{},
			steps: []step{
				{pollErr: &DevicePollError{Code: "authorization_declined"}},
			},
			wantErrIs:       []error{ErrDeviceAccessDenied},
			wantPollErrCode: "authorization_declined",
			wantErrContains: "authorization_declined",
			wantSleeps:      []time.Duration{6 * time.Second},
		},
		{
			name: "unrecognized error returns Cause directly when present",
			cfg:  DevicePollConfig{},
			steps: []step{
				{pollErr: &DevicePollError{
					Code:        "invalid_client",
					Description: "AADSTS700016",
					Cause:       customAADSTSErr,
				}},
			},
			wantErrSame: customAADSTSErr,
			wantSleeps:  []time.Duration{6 * time.Second},
		},
		{
			name: "unrecognized error without Cause returns DevicePollError",
			cfg:  DevicePollConfig{},
			steps: []step{
				{pollErr: &DevicePollError{
					Code:        "bad_verification_code",
					Description: "The code passed is incorrect or expired.",
				}},
			},
			wantPollErrCode: "bad_verification_code",
			wantErrContains: "bad_verification_code: The code passed is incorrect or expired.",
			wantSleeps:      []time.Duration{6 * time.Second},
		},
		{
			name: "RetryTransientErrors false fails fast without extra sleep",
			cfg: DevicePollConfig{
				RetryTransientErrors: false,
			},
			steps: []step{
				{err: transientNetErr},
			},
			wantErrSame:        transientNetErr,
			wantSleeps:         []time.Duration{6 * time.Second},
			wantTransientCount: 0,
		},
		{
			name: "RetryTransientErrors true sleeps full interval plus margin before retrying",
			cfg: DevicePollConfig{
				Interval:             5 * time.Second,
				RetryTransientErrors: true,
			},
			steps: []step{
				{err: transientNetErr},
				{err: wrappedNonTimeoutErr},
				{token: &testDeviceToken{AccessToken: "recovered-tok"}},
			},
			wantToken: "recovered-tok",
			wantSleeps: []time.Duration{
				6 * time.Second,
				6 * time.Second,
				6 * time.Second,
			},
			wantTransientCount: 2,
		},
		{
			name: "RetryTransientErrors true doubles base interval on wrapped timeout errors",
			cfg: DevicePollConfig{
				Interval:             5 * time.Second,
				RetryTransientErrors: true,
			},
			steps: []step{
				{err: wrappedTimeoutErr},
				{err: fmt.Errorf("request timed out: %w", os.ErrDeadlineExceeded)},
				{err: transientNetErr},
				{token: &testDeviceToken{AccessToken: "timeout-recovered"}},
			},
			wantToken: "timeout-recovered",
			wantSleeps: []time.Duration{
				6 * time.Second,
				11 * time.Second,
				21 * time.Second,
				21 * time.Second,
			},
			wantTransientCount: 3,
		},
		{
			name: "RetryTransientErrors true backs off on per-request context deadline and joined timeout errors",
			cfg: DevicePollConfig{
				Interval:             5 * time.Second,
				RetryTransientErrors: true,
			},
			steps: []step{
				{err: fmt.Errorf("per-request timeout: %w", context.DeadlineExceeded)},
				{err: errors.Join(stubTimeoutError{msg: "reset", timeout: false}, stubTimeoutError{msg: "read timeout", timeout: true})},
				{token: &testDeviceToken{AccessToken: "deadline-recovered"}},
			},
			wantToken: "deadline-recovered",
			wantSleeps: []time.Duration{
				6 * time.Second,
				11 * time.Second,
				21 * time.Second,
			},
			wantTransientCount: 2,
		},
		{
			name: "context canceled during exchange with RetryTransientErrors true stops immediately",
			cfg: DevicePollConfig{
				Interval:             5 * time.Second,
				RetryTransientErrors: true,
			},
			steps: []step{
				{err: transientNetErr, cancel: true},
			},
			wantErrIs:          []error{context.Canceled},
			wantSleeps:         []time.Duration{6 * time.Second},
			wantTransientCount: 0,
		},
		{
			name: "nil token without error is rejected defensively",
			cfg:  DevicePollConfig{},
			steps: []step{
				{},
			},
			wantErrContains: "nil token",
			wantSleeps:      []time.Duration{6 * time.Second},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			clock := &virtualPollClock{}
			var slowDowns []time.Duration
			var transientErrs []error

			cfg := tt.cfg
			cfg.Sleep = clock.sleep
			cfg.OnSlowDown = func(d time.Duration) {
				slowDowns = append(slowDowns, d)
			}
			cfg.OnTransientError = func(err error) {
				transientErrs = append(transientErrs, err)
			}

			idx := 0
			tok, err := PollDeviceToken(ctx, cfg, func(_ context.Context) (*testDeviceToken, *DevicePollError, error) {
				require.Less(t, idx, len(tt.steps), "unexpected extra poll attempt")
				s := tt.steps[idx]
				idx++
				if s.cancel {
					cancel()
				}
				return s.token, s.pollErr, s.err
			})

			assert.Equal(t, tt.wantSleeps, clock.sleeps)
			assert.Equal(t, tt.wantSlowDowns, slowDowns)
			assert.Len(t, transientErrs, tt.wantTransientCount)

			if tt.wantToken != "" {
				require.NoError(t, err)
				require.NotNil(t, tok)
				assert.Equal(t, tt.wantToken, tok.AccessToken)
				return
			}

			require.Error(t, err)
			assert.Nil(t, tok)
			for _, target := range tt.wantErrIs {
				assert.ErrorIs(t, err, target)
			}
			if tt.wantErrSame != nil {
				assert.Same(t, tt.wantErrSame, err)
			}
			if tt.wantPollErrCode != "" {
				var pe *DevicePollError
				require.ErrorAs(t, err, &pe)
				assert.Equal(t, tt.wantPollErrCode, pe.Code)
			}
			if tt.wantErrContains != "" {
				assert.Contains(t, err.Error(), tt.wantErrContains)
			}
			if tt.wantNoControlRunes {
				assert.NotContains(t, err.Error(), "\x1b")
				for _, r := range err.Error() {
					assert.False(t, unicode.IsControl(r), "control rune %U must not appear in %q", r, err.Error())
				}
			}
			if tt.wantMaxErrRunes > 0 {
				assert.LessOrEqual(t, utf8.RuneCountInString(err.Error()), tt.wantMaxErrRunes)
			}
		})
	}
}

func TestPollDeviceToken_ContextCancellationAndValidation(t *testing.T) {
	t.Run("nil context rejected", func(t *testing.T) {
		var nilCtx context.Context
		tok, err := PollDeviceToken(nilCtx, DevicePollConfig{}, func(context.Context) (*testDeviceToken, *DevicePollError, error) {
			t.Fatal("exchange must not be called")
			return nil, nil, nil
		})
		require.Error(t, err)
		assert.Nil(t, tok)
		assert.Contains(t, err.Error(), "context")
	})

	t.Run("nil exchange rejected without sleeping", func(t *testing.T) {
		slept := false
		tok, err := PollDeviceToken[testDeviceToken](
			context.Background(),
			DevicePollConfig{
				Sleep: func(context.Context, time.Duration) error {
					slept = true
					return nil
				},
			},
			nil,
		)
		require.Error(t, err)
		assert.Nil(t, tok)
		assert.False(t, slept)
		assert.Contains(t, err.Error(), "exchange")
	})

	t.Run("pre-canceled context returns before Sleep", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		slept := false
		tok, err := PollDeviceToken(ctx, DevicePollConfig{
			Sleep: func(context.Context, time.Duration) error {
				slept = true
				return nil
			},
		}, func(context.Context) (*testDeviceToken, *DevicePollError, error) {
			t.Fatal("exchange must not be called")
			return nil, nil, nil
		})
		require.ErrorIs(t, err, context.Canceled)
		assert.Nil(t, tok)
		assert.False(t, slept)
	})

	t.Run("deadline exceeded during Sleep returns context.DeadlineExceeded", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		tok, err := PollDeviceToken(ctx, DevicePollConfig{
			Sleep: func(sleepCtx context.Context, _ time.Duration) error {
				<-sleepCtx.Done()
				return errors.New("sleep interrupted")
			},
		}, func(context.Context) (*testDeviceToken, *DevicePollError, error) {
			t.Fatal("exchange must not be called after deadline-expired Sleep")
			return nil, nil, nil
		})
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Nil(t, tok)
	})

	t.Run("context canceled during Sleep returning nil still aborts before exchange", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		tok, err := PollDeviceToken(ctx, DevicePollConfig{
			Sleep: func(_ context.Context, _ time.Duration) error {
				cancel()
				return nil
			},
		}, func(context.Context) (*testDeviceToken, *DevicePollError, error) {
			t.Fatal("exchange must not be called after context cancel in Sleep")
			return nil, nil, nil
		})
		require.ErrorIs(t, err, context.Canceled)
		assert.Nil(t, tok)
	})

	t.Run("custom Sleep returning non-context error surfaces error", func(t *testing.T) {
		clockErr := errors.New("clock fault")
		tok, err := PollDeviceToken(context.Background(), DevicePollConfig{
			Sleep: func(context.Context, time.Duration) error {
				return clockErr
			},
		}, func(context.Context) (*testDeviceToken, *DevicePollError, error) {
			t.Fatal("exchange must not be called")
			return nil, nil, nil
		})
		require.ErrorIs(t, err, clockErr)
		assert.Nil(t, tok)
	})

	t.Run("default timer Sleep interrupts 10s wait immediately on cancel", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
		defer cancel()

		start := time.Now()
		tok, err := PollDeviceToken(ctx, DevicePollConfig{
			Interval: 10 * time.Second,
		}, func(context.Context) (*testDeviceToken, *DevicePollError, error) {
			t.Fatal("exchange must not run before 10s wait expires")
			return nil, nil, nil
		})
		elapsed := time.Since(start)

		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Nil(t, tok)
		assert.Less(t, elapsed, 2*time.Second, "timer wait must abort promptly on deadline")
	})

	t.Run("default timer Sleep succeeds on short interval", func(t *testing.T) {
		tok, err := PollDeviceToken(context.Background(), DevicePollConfig{
			Interval:            time.Millisecond,
			MinInterval:         time.Millisecond,
			DisableSafetyMargin: true,
		}, func(context.Context) (*testDeviceToken, *DevicePollError, error) {
			return &testDeviceToken{AccessToken: "timer-ok"}, nil, nil
		})
		require.NoError(t, err)
		require.NotNil(t, tok)
		assert.Equal(t, "timer-ok", tok.AccessToken)
		assert.NoError(t, defaultDeviceSleep(context.Background(), 0))
	})
}

func TestPollDeviceToken_OverflowHardening(t *testing.T) {
	// Architecture-independent duration addition saturation check.
	addClock := &virtualPollClock{}
	tok, err := PollDeviceToken(context.Background(), DevicePollConfig{
		Interval:     time.Duration(math.MaxInt64) - 2*time.Second,
		SafetyMargin: 5 * time.Second,
		Sleep:        addClock.sleep,
	}, func(context.Context) (*testDeviceToken, *DevicePollError, error) {
		return &testDeviceToken{AccessToken: "saturated-add"}, nil, nil
	})
	require.NoError(t, err)
	require.NotNil(t, tok)
	require.Equal(t, []time.Duration{time.Duration(math.MaxInt64)}, addClock.sleeps)

	// Timeout backoff near MaxInt64 must saturate rather than wrap negative.
	timeoutClock := &virtualPollClock{}
	timeoutCalls := 0
	nearHalfMax := time.Duration(math.MaxInt64)/2 + 10*time.Second
	tok, err = PollDeviceToken(context.Background(), DevicePollConfig{
		Interval:             nearHalfMax,
		DisableSafetyMargin:  true,
		RetryTransientErrors: true,
		Sleep:                timeoutClock.sleep,
	}, func(context.Context) (*testDeviceToken, *DevicePollError, error) {
		timeoutCalls++
		if timeoutCalls == 1 {
			return nil, nil, stubTimeoutError{msg: "timeout", timeout: true}
		}
		return &testDeviceToken{AccessToken: "saturated-timeout"}, nil, nil
	})
	require.NoError(t, err)
	require.NotNil(t, tok)
	assert.Equal(t, []time.Duration{
		nearHalfMax,
		time.Duration(math.MaxInt64),
	}, timeoutClock.sleeps)

	if int64(math.MaxInt) > math.MaxInt64/int64(time.Second) {
		clock := &virtualPollClock{}
		calls := 0
		tok, err = PollDeviceToken(context.Background(), DevicePollConfig{
			Interval: 5 * time.Second,
			Sleep:    clock.sleep,
		}, func(context.Context) (*testDeviceToken, *DevicePollError, error) {
			calls++
			if calls == 1 {
				return nil, &DevicePollError{Code: "slow_down", Interval: math.MaxInt}, nil
			}
			return &testDeviceToken{AccessToken: "clamped-overflow"}, nil, nil
		})
		require.NoError(t, err)
		require.NotNil(t, tok)
		require.Len(t, clock.sleeps, 2)
		assert.Equal(t, time.Duration(math.MaxInt64), clock.sleeps[1], "overflowing server Interval must saturate rather than wrap negative")
	}
}

func TestDevicePollError_FormattingAndSanitization(t *testing.T) {
	var nilErr *DevicePollError
	assert.Equal(t, "", nilErr.Error())
	assert.NoError(t, nilErr.Unwrap())

	underlying := errors.New("underlying cause")
	controlOnlyCause := errors.New("\x1b\x07")
	tests := []struct {
		name string
		err  *DevicePollError
		want string
	}{
		{
			name: "code and description",
			err:  &DevicePollError{Code: "invalid_grant", Description: "Bad verification code"},
			want: "OAuth device error: invalid_grant: Bad verification code",
		},
		{
			name: "code only",
			err:  &DevicePollError{Code: "invalid_client"},
			want: "OAuth device error: invalid_client",
		},
		{
			name: "description only",
			err:  &DevicePollError{Description: "Server temporarily unavailable"},
			want: "OAuth device error: Server temporarily unavailable",
		},
		{
			name: "cause only",
			err:  &DevicePollError{Cause: underlying},
			want: "underlying cause",
		},
		{
			name: "control-only cause falls back to unknown_error",
			err:  &DevicePollError{Cause: controlOnlyCause},
			want: "OAuth device error: unknown_error",
		},
		{
			name: "all empty",
			err:  &DevicePollError{},
			want: "OAuth device error: unknown_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
		})
	}

	withCause := &DevicePollError{Code: "invalid_client", Cause: underlying}
	assert.ErrorIs(t, withCause, underlying)
	assert.ErrorIs(t, &DevicePollError{Cause: controlOnlyCause}, controlOnlyCause)

	// Control characters and overlong untrusted descriptions and causes must be
	// sanitized and capped while preserving Unwrap.
	untrusted := &DevicePollError{
		Code:        "\x1b[31maccess_denied\x7f",
		Description: "\x1b]52;c;ZXY=\x07FAKE\r\nLINE2 " + strings.Repeat("x", 700),
	}
	formatted := untrusted.Error()
	assert.True(t, utf8.ValidString(formatted))
	assert.NotContains(t, formatted, "\x1b")
	for _, r := range formatted {
		assert.False(t, unicode.IsControl(r), "control rune %U must not appear in %q", r, formatted)
	}

	untrustedCause := errors.New("\x1b]52;c;ZXY=\x07CAUSE\r\nLINE2 " + strings.Repeat("c", 700))
	causeErr := &DevicePollError{Cause: untrustedCause}
	formattedCause := causeErr.Error()
	assert.True(t, utf8.ValidString(formattedCause))
	assert.Contains(t, formattedCause, "CAUSE LINE2")
	assert.NotContains(t, formattedCause, "\x1b")
	assert.LessOrEqual(t, utf8.RuneCountInString(formattedCause), maxOAuthErrorDescRunes)
	for _, r := range formattedCause {
		assert.False(t, unicode.IsControl(r), "control rune %U must not appear in %q", r, formattedCause)
	}
	assert.ErrorIs(t, causeErr, untrustedCause)
}
