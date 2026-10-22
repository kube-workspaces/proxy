package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// ErrCredentialRevoked marks a credential that must no longer authorise work.
// Long-lived connections end as soon as revalidation reports it.
var ErrCredentialRevoked = errors.New("credential revoked")

// RevalidateCredential re-checks a credential against live account state.
//
// It returns nil while the credential is still usable, ErrCredentialRevoked once
// the account or credential is revoked, disabled, replaced or restricted, and a
// plain error when the state could not be verified. Callers must distinguish the
// two failure kinds: a revoked credential ends the connection immediately,
// while an unverifiable state is retried.
//
// The check reads live cluster state rather than a per-replica cache, so a
// revocation performed against one proxy replica is observed by every replica
// that holds a connection for the same account.
func (p *ConfigProvider) RevalidateCredential(ctx context.Context, token *SessionToken) error {
	if p == nil || token == nil {
		return nil
	}
	cfg, err := p.GetConfig(ctx)
	if err != nil {
		return err
	}
	if !cfg.Enabled {
		return nil
	}
	if time.Now().Unix() >= token.ExpiresAt {
		return fmt.Errorf("%w: credential expired", ErrCredentialRevoked)
	}
	if token.Type == "device" {
		if err := p.ValidateDevice(ctx, token); err != nil {
			if credentialStateUnavailable(err) {
				return err
			}
			return fmt.Errorf("%w: %v", ErrCredentialRevoked, err)
		}
	}
	if token.UserUID == "" || token.CredentialVersion == "" {
		return fmt.Errorf("%w: credential is not method bound", ErrCredentialRevoked)
	}
	user, err := p.GetUserByEmail(ctx, token.Email)
	if err != nil {
		if credentialStateUnavailable(err) {
			return err
		}
		return fmt.Errorf("%w: current user account unavailable", ErrCredentialRevoked)
	}
	if token.UserUID != user.UID {
		return fmt.Errorf("%w: session user identity no longer matches", ErrCredentialRevoked)
	}
	restricted, err := p.ValidateProvenance(ctx, token, user)
	if err != nil {
		if credentialStateUnavailable(err) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrCredentialRevoked, err)
	}
	if restricted {
		return fmt.Errorf("%w: credential is restricted", ErrCredentialRevoked)
	}
	return nil
}

// Missing objects are revocations; transport and API-server failures are not.
func credentialStateUnavailable(err error) bool {
	var status apierrors.APIStatus
	var transport net.Error
	return (errors.As(err, &status) && !apierrors.IsNotFound(err)) || errors.As(err, &transport) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

const (
	// DefaultRevalidateInterval is how often an open connection revalidates the
	// credential that authorised it.
	DefaultRevalidateInterval = 5 * time.Second
	// maxRevalidateFailures is how many consecutive verification failures are
	// tolerated before a connection is ended. A verification failure is not a
	// revocation: the account state may simply be momentarily unavailable.
	maxRevalidateFailures = 3
)

// WatchCredentialRevocation revalidates a credential on an interval and calls
// onRevoked once the credential is no longer usable. The returned function
// stops the watcher.
//
// A revoked credential ends the connection immediately. A verification failure
// is retried, because the account state may only be momentarily unavailable;
// after repeated failures the connection is ended rather than left open on
// unverified state.
func WatchCredentialRevocation(ctx context.Context, revalidate func(context.Context) error, interval time.Duration, onRevoked func(reason string)) func() {
	if revalidate == nil || onRevoked == nil {
		return func() {}
	}
	if interval <= 0 {
		interval = DefaultRevalidateInterval
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := make(chan struct{})
	go func() {
		defer cancel()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		failures := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-ticker.C:
			}
			checkCtx, checkCancel := context.WithTimeout(ctx, 5*time.Second)
			err := revalidate(checkCtx)
			checkCancel()
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				failures = 0
				continue
			}
			if errors.Is(err, ErrCredentialRevoked) {
				onRevoked("credential revoked")
				return
			}
			failures++
			if failures >= maxRevalidateFailures {
				onRevoked("credential could not be verified")
				return
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { cancel(); close(stop) }) }
}
