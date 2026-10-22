package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestRevalidateCredentialRevokesDeviceAndExpiry(t *testing.T) {
	ctx := context.Background()
	device := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": "Secret",
		"metadata":   map[string]interface{}{"name": "kw-device-device-id", "namespace": deviceNamespace},
		"stringData": map[string]interface{}{"email": "user@example.com", "revoked": "false", "expiresAt": strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)},
	}}
	client := newFakeDynamic(currentUser(), currentPassword(), device)
	p := NewConfigProvider(client)
	p.config, p.lastFetch = &AuthConfig{Enabled: true, SigningKey: []byte("test-key")}, time.Now()
	token := &SessionToken{UserUID: "current-uid", Email: "user@example.com", Type: "device", JTI: "device-id", ExpiresAt: time.Now().Add(time.Hour).Unix(), AuthMethod: "local", CredentialVersion: localCredentialVersion("current-uid", "password", "passwordHash", "test-hash")}
	if err := p.RevalidateCredential(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err := client.Resource(secretGVR).Namespace(deviceNamespace).Delete(ctx, device.GetName(), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := p.RevalidateCredential(ctx, token); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("deleted device still valid: %v", err)
	}
	token.Type, token.JTI, token.ExpiresAt = "", "", time.Now().Add(-time.Second).Unix()
	if err := p.RevalidateCredential(ctx, token); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("expired credential still valid: %v", err)
	}
}

func TestRevalidateCredentialFollowsLiveAccountState(t *testing.T) {
	ctx := context.Background()
	u := currentUser()
	secret := currentPassword()
	client := newFakeDynamic(u, secret)
	p := NewConfigProvider(client)
	p.config, p.lastFetch = &AuthConfig{Enabled: true, SigningKey: []byte("test-key")}, time.Now()

	token := &SessionToken{
		UserUID:           "current-uid",
		Email:             "user@example.com",
		Role:              "editor",
		ExpiresAt:         time.Now().Add(time.Hour).Unix(),
		AuthMethod:        "local",
		CredentialVersion: localCredentialVersion("current-uid", "password", "passwordHash", "test-hash"),
	}

	if err := p.RevalidateCredential(ctx, token); err != nil {
		t.Fatalf("live credential reported as revoked: %v", err)
	}

	// A replaced password rotates the revision and revokes the credential.
	_ = unstructured.SetNestedField(secret.Object, base64.StdEncoding.EncodeToString([]byte("rotated-hash")), "data", "passwordHash")
	if _, err := client.Resource(secretGVR).Namespace(deviceNamespace).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := p.RevalidateCredential(ctx, token); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("expected revocation after the password was replaced, got %v", err)
	}

	// The rotated credential is accepted again.
	token.CredentialVersion = localCredentialVersion("current-uid", "password", "passwordHash", "rotated-hash")
	if err := p.RevalidateCredential(ctx, token); err != nil {
		t.Fatalf("rotated credential reported as revoked: %v", err)
	}

	// A disabled account revokes the credential.
	_ = unstructured.SetNestedField(u.Object, true, "spec", "disabled")
	if _, err := client.Resource(userGVR).Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := p.RevalidateCredential(ctx, token); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("expected revocation for a disabled account, got %v", err)
	}
}

func TestRevalidateCredentialRejectsUnboundCredentials(t *testing.T) {
	ctx := context.Background()
	p := NewConfigProvider(newFakeDynamic(currentUser(), currentPassword()))
	p.config, p.lastFetch = &AuthConfig{Enabled: true, SigningKey: []byte("test-key")}, time.Now()

	token := &SessionToken{Email: "user@example.com", Role: "editor", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	if err := p.RevalidateCredential(ctx, token); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("expected a methodless credential to be revoked, got %v", err)
	}
}

func TestWatchCredentialRevocationEndsConnection(t *testing.T) {
	revoked := make(chan string, 1)
	stop := WatchCredentialRevocation(context.Background(), func(context.Context) error {
		return ErrCredentialRevoked
	}, 10*time.Millisecond, func(reason string) { revoked <- reason })
	defer stop()

	select {
	case <-revoked:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not report the revocation")
	}
}

func TestWatchCredentialRevocationToleratesTransientFailures(t *testing.T) {
	var attempts int
	revoked := make(chan string, 1)
	stop := WatchCredentialRevocation(context.Background(), func(context.Context) error {
		attempts++
		if attempts < 3 {
			return errors.New("temporarily unavailable")
		}
		return ErrCredentialRevoked
	}, 10*time.Millisecond, func(reason string) { revoked <- reason })
	defer stop()

	select {
	case <-revoked:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not report the revocation")
	}
	if attempts != 3 {
		t.Fatalf("expected the transient failures to be retried, got %d attempts", attempts)
	}
}
