package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestMethodSessionsAtProxy(t *testing.T) {
	ctx := context.Background()
	key := []byte("test-key")
	u := currentUser()
	_ = unstructured.SetNestedField(u.Object, true, "spec", "localAuth", "mustChangePassword")
	_ = unstructured.SetNestedSlice(u.Object, []interface{}{map[string]interface{}{"issuer": "https://idp.example.com", "subject": "subject"}}, "spec", "externalIdentities")
	payload, _ := json.Marshal(map[string]string{"issuer": "https://idp.example.com", "subject": "subject"})
	sum := sha256.Sum256(payload)
	claim := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": "Secret", "metadata": map[string]interface{}{"name": "kw-identity-" + hex.EncodeToString(sum[:]), "namespace": deviceNamespace,
			"annotations": map[string]interface{}{"kubeworkspaces.io/issuer": "https://idp.example.com", "kubeworkspaces.io/subject": "subject", "kubeworkspaces.io/user-name": "user", "kubeworkspaces.io/user-uid": "current-uid", "kubeworkspaces.io/credential-version": "oidc-revision"}},
	}}
	secret := currentPassword()
	client := newFakeDynamic(u, secret, claim)
	p := NewConfigProvider(client)
	p.config, p.lastFetch = &AuthConfig{Enabled: true, SigningKey: key, AdminEmails: []string{"user@example.com"}}, time.Now()
	local := SessionToken{UserUID: "current-uid", Email: "user@example.com", Role: "admin", ExpiresAt: time.Now().Add(time.Hour).Unix(), AuthMethod: "local", CredentialVersion: localCredentialVersion("current-uid", "password", "passwordHash", "test-hash")}
	oidc := local
	oidc.AuthMethod, oidc.CredentialVersion, oidc.Issuer, oidc.Subject = "oidc", "oidc-revision", "https://idp.example.com", "subject"
	check := func(token SessionToken, want int) {
		t.Helper()
		if got := doRequest(t, p, "/proxy/personal/ws/", "Bearer "+signPayload(key, token)); got != want {
			t.Fatalf("method=%s status=%d want=%d", token.AuthMethod, got, want)
		}
	}
	check(local, 403) // even a configured admin cannot bypass local restrictions
	check(oidc, 200)
	_ = unstructured.SetNestedField(u.Object, false, "spec", "localAuth", "mustChangePassword")
	if _, err := client.Resource(userGVR).Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedField(secret.Object, base64.StdEncoding.EncodeToString([]byte("reset-hash")), "data", "passwordHash")
	_ = unstructured.SetNestedField(secret.Object, base64.StdEncoding.EncodeToString([]byte("true")), "data", "mustChangePassword")
	if _, err := client.Resource(secretGVR).Namespace(deviceNamespace).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	check(local, 401)
	check(oidc, 200)
	local.CredentialVersion = localCredentialVersion("current-uid", "password", "passwordHash", "reset-hash")
	check(local, 403) // Secret policy cannot be bypassed by clearing the User flag
	_ = unstructured.SetNestedField(secret.Object, base64.StdEncoding.EncodeToString([]byte("false")), "data", "mustChangePassword")
	if _, err := client.Resource(secretGVR).Namespace(deviceNamespace).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	check(local, 200)
	a := claim.GetAnnotations()
	a["kubeworkspaces.io/credential-version"] = "rotated"
	claim.SetAnnotations(a)
	if _, err := client.Resource(secretGVR).Namespace(deviceNamespace).Update(ctx, claim, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	check(oidc, 401)
	check(local, 200)
	oidc.CredentialVersion = "rotated"
	check(oidc, 200)
	_ = unstructured.SetNestedSlice(u.Object, []interface{}{}, "spec", "externalIdentities")
	if _, err := client.Resource(userGVR).Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	check(oidc, 401)
	check(local, 200)
}

// Fixed cross-repo wire vector: also exercised in API provenance tests. It
// catches JSON naming, revision construction and HMAC-envelope drift.
func TestMethodSessionWireVector(t *testing.T) {
	const raw = "eyJ1c2VyX3VpZCI6ImN1cnJlbnQtdWlkIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIiwicm9sZSI6ImFkbWluIiwiYXV0aF9tZXRob2QiOiJsb2NhbCIsImNyZWRlbnRpYWxfdmVyc2lvbiI6IjhkZmM2ZThhY2I5YjAzY2U5NzE2ODcwNTliYTNhY2NiODUyOTIzOTBiOTg4ODVkNzM2NzJkMjcwYzVmZDllNGYiLCJpYXQiOjEsImV4cCI6NDEwMjQ0NDgwMH0.BeGHg4QRcZdN-x2S9Vh1VxJwZBX8sFBcdMSC1NM81f0"
	token, err := ValidateSessionToken(raw, []byte("wire-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	if token.AuthMethod != "local" || token.CredentialVersion != "8dfc6e8acb9b03ce971687059ba3accb85292390b98885d73672d270c5fd9e4f" {
		t.Fatal("method/session wire contract changed")
	}
	if token.CredentialVersion != localCredentialVersion("current-uid", "password", "passwordHash", "test-hash") {
		t.Fatal("local revision wire construction changed")
	}
	p := NewConfigProvider(newFakeDynamic(currentUser(), currentPassword()))
	p.config, p.lastFetch = &AuthConfig{Enabled: true, SigningKey: []byte("wire-test-key")}, time.Now()
	if got := doRequest(t, p, "/proxy/personal/ws/", "Bearer "+raw); got != 200 {
		t.Fatalf("wire fixture denied: %d", got)
	}
}
