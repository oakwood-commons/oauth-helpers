// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"testing"
	"time"
)

func BenchmarkPollDeviceToken_ImmediateSuccess(b *testing.B) {
	ctx := context.Background()
	tok := &testDeviceToken{AccessToken: "bench-token"}
	cfg := DevicePollConfig{
		Interval: 5 * time.Second,
		Sleep:    func(context.Context, time.Duration) error { return nil },
	}
	exchange := func(context.Context) (*testDeviceToken, *DevicePollError, error) {
		return tok, nil, nil
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		got, err := PollDeviceToken(ctx, cfg, exchange)
		if err != nil || got == nil {
			b.Fatalf("unexpected result: tok=%v err=%v", got, err)
		}
	}
}

func BenchmarkPollDeviceToken_PendingAndSlowDown(b *testing.B) {
	ctx := context.Background()
	tok := &testDeviceToken{AccessToken: "bench-token"}
	pendingErr := &DevicePollError{Code: "authorization_pending"}
	slowDownErr := &DevicePollError{Code: "slow_down", Interval: 10}
	cfg := DevicePollConfig{
		Interval: 5 * time.Second,
		Sleep:    func(context.Context, time.Duration) error { return nil },
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		attempt := 0
		got, err := PollDeviceToken(ctx, cfg, func(context.Context) (*testDeviceToken, *DevicePollError, error) {
			attempt++
			switch attempt {
			case 1:
				return nil, pendingErr, nil
			case 2:
				return nil, slowDownErr, nil
			default:
				return tok, nil, nil
			}
		})
		if err != nil || got == nil {
			b.Fatalf("unexpected result: tok=%v err=%v", got, err)
		}
	}
}
