// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"time"
)

const (
	// DefaultDevicePollInterval is the default minimum interval between
	// device-authorization token poll attempts per RFC 8628 Section 3.2.
	DefaultDevicePollInterval = 5 * time.Second

	// DefaultDevicePollSafetyMargin is the default post-response buffer added to
	// each poll wait so clock skew or sub-second rounding never clips a server's
	// whole-second rate-limit ceiling.
	DefaultDevicePollSafetyMargin = time.Second

	// DefaultDeviceSlowDownIncrement is the default duration added to the poll
	// interval when the authorization server returns "slow_down" per RFC 8628
	// Section 3.5.
	DefaultDeviceSlowDownIncrement = 5 * time.Second

	deviceErrAuthorizationPending  = "authorization_pending"
	deviceErrSlowDown              = "slow_down"
	deviceErrExpiredToken          = "expired_token"
	deviceErrAccessDenied          = "access_denied"
	deviceErrAuthorizationDeclined = "authorization_declined"
)

var (
	// ErrDeviceCodeExpired indicates the device code expired before the user
	// completed authorization (RFC 8628 "expired_token").
	ErrDeviceCodeExpired = errors.New("device code expired")

	// ErrDeviceAccessDenied indicates the authorization request was denied by
	// the user or authorization server (RFC 8628 "access_denied" or
	// "authorization_declined").
	ErrDeviceAccessDenied = errors.New("device authorization denied")
)

// DevicePollError represents an OAuth 2.0 device-authorization token endpoint
// error response (RFC 8628 Section 3.5) or a caller-supplied terminal error.
type DevicePollError struct {
	// Code is the OAuth 2.0 "error" code (for example, "authorization_pending",
	// "slow_down", "expired_token", "access_denied", or "authorization_declined").
	Code string
	// Description is the optional human-readable "error_description" returned by
	// the authorization server. Control characters are sanitized and length is
	// capped when formatting error strings.
	Description string
	// Interval is the optional server-supplied minimum polling interval in
	// whole seconds returned alongside a "slow_down" response.
	Interval int
	// Cause is an optional underlying error exposed via Unwrap and returned
	// directly by PollDeviceToken when Code is not one of the standard polling
	// or sentinel error codes. When formatted via DevicePollError.Error or a
	// sentinel-wrapped error, Cause.Error() is sanitized and length-capped while
	// Unwrap preserves the original Cause unchanged.
	Cause error
}

// Error formats the device polling error with terminal-safe sanitized fields.
func (e *DevicePollError) Error() string {
	if e == nil {
		return ""
	}
	code := sanitizeOAuthError(e.Code, maxOAuthErrorRunes)
	desc := sanitizeOAuthError(e.Description, maxOAuthErrorDescRunes)
	var cause string
	if e.Cause != nil {
		cause = sanitizeOAuthError(e.Cause.Error(), maxOAuthErrorDescRunes)
	}
	switch {
	case code != "" && desc != "":
		return fmt.Sprintf("OAuth device error: %s: %s", code, desc)
	case code != "":
		return fmt.Sprintf("OAuth device error: %s", code)
	case desc != "":
		return fmt.Sprintf("OAuth device error: %s", desc)
	case cause != "":
		return cause
	default:
		return "OAuth device error: unknown_error"
	}
}

// Unwrap returns the underlying Cause error, if any.
func (e *DevicePollError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// DevicePollConfig configures RFC 8628 device-authorization token polling.
type DevicePollConfig struct {
	// Interval is the server-requested polling interval. Values below
	// MinInterval are clamped up to MinInterval.
	Interval time.Duration
	// MinInterval is the minimum base polling interval. Defaults to
	// DefaultDevicePollInterval (5s) when <= 0.
	MinInterval time.Duration
	// SafetyMargin is added to each post-response wait to avoid clipping
	// whole-second server rate-limit windows due to clock skew or rounding.
	// Defaults to DefaultDevicePollSafetyMargin (1s) when <= 0 and
	// DisableSafetyMargin is false.
	SafetyMargin time.Duration
	// DisableSafetyMargin sets the post-response safety margin to 0s when true.
	DisableSafetyMargin bool
	// SlowDownIncrement is added to the current polling interval on each
	// "slow_down" response unless the server supplies a larger Interval.
	// Values below DefaultDeviceSlowDownIncrement (5s) are clamped up to
	// DefaultDeviceSlowDownIncrement per RFC 8628 Section 3.5.
	SlowDownIncrement time.Duration
	// RetryTransientErrors controls whether transport/exchange errors returned
	// as the third return value of exchange are retried after waiting
	// Interval + SafetyMargin (true) or returned immediately (false). When true,
	// timeout errors double the base polling interval (clamped on overflow)
	// before the retry wait per RFC 8628 Section 3.5, while non-timeout
	// transient errors keep the current polling interval unchanged.
	RetryTransientErrors bool
	// Sleep waits for d or until ctx is done. Defaults to a timer-backed wait
	// that stops its timer immediately on context cancellation. Callers may
	// supply a fake clock hook in tests to avoid real sleeps.
	Sleep func(ctx context.Context, d time.Duration) error
	// OnSlowDown is an optional hook invoked with the updated base polling
	// interval (excluding SafetyMargin) whenever "slow_down" increases it.
	OnSlowDown func(newInterval time.Duration)
	// OnTransientError is an optional hook invoked whenever exchange returns a
	// retryable error and RetryTransientErrors is true.
	OnTransientError func(err error)
}

// PollDeviceToken polls an OAuth 2.0 device-authorization token endpoint per
// RFC 8628 until authorization succeeds, a terminal OAuth error occurs, or ctx
// is canceled.
//
// Each wait of interval + safetyMargin happens before the first poll attempt
// and after each completed "authorization_pending", "slow_down", or retried
// transient-error attempt rather than on a fixed-rate ticker, ensuring exchange
// round-trip latency never shortens the server's required wait window.
//
// The exchange callback performs a single token request:
//   - Return (token, nil, nil) when an access token has been issued.
//   - Return (nil, pollErr, nil) when the server returned an OAuth error body
//     (or a non-retryable failure wrapped in pollErr.Cause).
//   - Return (nil, nil, err) on transport/network failure; PollDeviceToken
//     returns err immediately when cfg.RetryTransientErrors is false, or waits
//     interval + safetyMargin before retrying when cfg.RetryTransientErrors is
//     true (doubling the base interval with overflow-safe backoff on timeout
//     errors per RFC 8628 Section 3.5, unless ctx is already done).
func PollDeviceToken[T any](
	ctx context.Context,
	cfg DevicePollConfig,
	exchange func(ctx context.Context) (*T, *DevicePollError, error),
) (*T, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}
	if exchange == nil {
		return nil, errors.New("device token exchange function must not be nil")
	}

	minInterval := cfg.MinInterval
	if minInterval <= 0 {
		minInterval = DefaultDevicePollInterval
	}

	interval := cfg.Interval
	if interval < minInterval {
		interval = minInterval
	}

	var safetyMargin time.Duration
	if !cfg.DisableSafetyMargin {
		safetyMargin = cfg.SafetyMargin
		if safetyMargin <= 0 {
			safetyMargin = DefaultDevicePollSafetyMargin
		}
	}

	slowDownIncr := cfg.SlowDownIncrement
	if slowDownIncr < DefaultDeviceSlowDownIncrement {
		slowDownIncr = DefaultDeviceSlowDownIncrement
	}

	sleepFn := cfg.Sleep
	if sleepFn == nil {
		sleepFn = defaultDeviceSleep
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		wait := addDurationClamped(interval, safetyMargin)
		if err := sleepFn(ctx, wait); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, err
		}

		if err := ctx.Err(); err != nil {
			return nil, err
		}

		tok, pollErr, err := exchange(ctx)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			if !cfg.RetryTransientErrors {
				return nil, err
			}
			if isTimeoutError(err) {
				interval = addDurationClamped(interval, interval)
			}
			if cfg.OnTransientError != nil {
				cfg.OnTransientError(err)
			}
			continue
		}

		if pollErr != nil {
			switch strings.TrimSpace(pollErr.Code) {
			case deviceErrAuthorizationPending:
				continue
			case deviceErrSlowDown:
				next := addDurationClamped(interval, slowDownIncr)
				if srv := secondsToDurationClamped(pollErr.Interval); srv > next {
					next = srv
				}
				interval = next
				if cfg.OnSlowDown != nil {
					cfg.OnSlowDown(interval)
				}
				continue
			case deviceErrExpiredToken:
				return nil, wrapSentinelPollError(ErrDeviceCodeExpired, pollErr)
			case deviceErrAccessDenied, deviceErrAuthorizationDeclined:
				return nil, wrapSentinelPollError(ErrDeviceAccessDenied, pollErr)
			default:
				if pollErr.Cause != nil {
					return nil, pollErr.Cause
				}
				return nil, pollErr
			}
		}

		if tok == nil {
			return nil, errors.New("device token exchange returned nil token without error")
		}
		return tok, nil
	}
}

func defaultDeviceSleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type sentinelDevicePollError struct {
	msg      string
	sentinel error
	pollErr  *DevicePollError
}

func (e *sentinelDevicePollError) Error() string {
	return e.msg
}

func (e *sentinelDevicePollError) Unwrap() []error {
	return []error{e.sentinel, e.pollErr}
}

func wrapSentinelPollError(sentinel error, pollErr *DevicePollError) error {
	desc := sanitizeOAuthError(pollErr.Description, maxOAuthErrorDescRunes)
	code := sanitizeOAuthError(pollErr.Code, maxOAuthErrorRunes)
	var cause string
	if pollErr.Cause != nil {
		cause = sanitizeOAuthError(pollErr.Cause.Error(), maxOAuthErrorDescRunes)
	}
	var msg string
	switch {
	case desc != "" && cause != "":
		msg = fmt.Sprintf("%s: %s: %s", sentinel.Error(), desc, cause)
	case desc != "":
		msg = fmt.Sprintf("%s: %s", sentinel.Error(), desc)
	case cause != "":
		msg = fmt.Sprintf("%s (%s): %s", sentinel.Error(), code, cause)
	default:
		msg = fmt.Sprintf("%s (%s)", sentinel.Error(), code)
	}
	return &sentinelDevicePollError{
		msg:      msg,
		sentinel: sentinel,
		pollErr:  pollErr,
	}
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	return hasTimeoutFlag(err)
}

func hasTimeoutFlag(err error) bool {
	if err == nil {
		return false
	}
	if te, ok := err.(interface{ Timeout() bool }); ok && te.Timeout() {
		return true
	}
	if sub := errors.Unwrap(err); sub != nil {
		return hasTimeoutFlag(sub)
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, sub := range joined.Unwrap() {
			if hasTimeoutFlag(sub) {
				return true
			}
		}
	}
	return false
}

func addDurationClamped(a, b time.Duration) time.Duration {
	if b > 0 && a > time.Duration(math.MaxInt64)-b {
		return time.Duration(math.MaxInt64)
	}
	return a + b
}

func secondsToDurationClamped(seconds int) time.Duration {
	if seconds <= 0 {
		return 0
	}
	const maxSeconds = math.MaxInt64 / int64(time.Second)
	if int64(seconds) > maxSeconds {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(int64(seconds) * int64(time.Second))
}
