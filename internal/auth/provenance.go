package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func localCredentialVersion(uid, name, key, hash string) string {
	payload, _ := json.Marshal([]string{uid, name, key, hash})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func secretDataValue(secret *unstructured.Unstructured, key string) (string, bool, error) {
	data, found, err := unstructured.NestedStringMap(secret.Object, "data")
	if err != nil {
		return "", false, err
	}
	if found {
		value, present := data[key]
		if !present {
			return "", false, nil
		}
		decoded, err := base64.StdEncoding.DecodeString(value)
		return string(decoded), true, err
	}
	data, _, err = unstructured.NestedStringMap(secret.Object, "stringData")
	value, present := data[key]
	return value, present, err
}

// ValidateProvenance mirrors API method/revision validation and never contacts
// the identity provider. Each request uses current account and credential state.
func (p *ConfigProvider) ValidateProvenance(ctx context.Context, token *SessionToken, user *UserInfo) (bool, error) {
	if user.record == nil || token.UserUID == "" || token.UserUID != user.UID || token.CredentialVersion == "" {
		return false, fmt.Errorf("credential identity unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	switch token.AuthMethod {
	case "local":
		if token.Issuer != "" || token.Subject != "" {
			return false, fmt.Errorf("invalid local provenance")
		}
		enabled, _, err := unstructured.NestedBool(user.record.Object, "spec", "localAuth", "enabled")
		if err != nil || !enabled {
			return false, fmt.Errorf("local credential disabled")
		}
		name, _, err := unstructured.NestedString(user.record.Object, "spec", "localAuth", "passwordSecretRef", "name")
		if err != nil || name == "" {
			return false, fmt.Errorf("password reference unavailable")
		}
		key, _, err := unstructured.NestedString(user.record.Object, "spec", "localAuth", "passwordSecretRef", "key")
		if err != nil {
			return false, err
		}
		if key == "" {
			key = "passwordHash"
		}
		secret, err := p.dynamicClient.Resource(secretGVR).Namespace(deviceNamespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if secret.GetDeletionTimestamp() != nil {
			return false, fmt.Errorf("password credential deleting")
		}
		if uid := secret.GetAnnotations()["kubeworkspaces.io/user-uid"]; uid != "" && uid != user.UID {
			return false, fmt.Errorf("password credential belongs to a different User UID")
		}
		for _, owner := range secret.GetOwnerReferences() {
			if owner.Kind == "User" && (string(owner.UID) != user.UID || owner.Name != user.record.GetName() || owner.APIVersion != "kubeworkspaces.io/v1alpha1") {
				return false, fmt.Errorf("password credential owner reference mismatch")
			}
		}
		hash, found, err := secretDataValue(secret, key)
		if err != nil || !found || hash == "" || token.CredentialVersion != localCredentialVersion(user.UID, name, key, hash) {
			return false, fmt.Errorf("local credential revoked")
		}
		restricted, _, err := unstructured.NestedBool(user.record.Object, "spec", "localAuth", "mustChangePassword")
		if err != nil {
			return false, err
		}
		policy, present, err := secretDataValue(secret, "mustChangePassword")
		if err != nil {
			return false, err
		}
		if present {
			if policy != "true" && policy != "false" {
				return false, fmt.Errorf("invalid password policy")
			}
			restricted = restricted || policy == "true"
		}
		return restricted, nil
	case "oidc":
		if token.Issuer == "" || token.Subject == "" {
			return false, fmt.Errorf("invalid OIDC provenance")
		}
		identity := struct {
			Issuer  string `json:"issuer"`
			Subject string `json:"subject"`
		}{token.Issuer, token.Subject}
		payload, _ := json.Marshal(identity)
		sum := sha256.Sum256(payload)
		claim, err := p.dynamicClient.Resource(secretGVR).Namespace(deviceNamespace).Get(ctx, "kw-identity-"+hex.EncodeToString(sum[:]), metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		a := claim.GetAnnotations()
		if claim.GetDeletionTimestamp() != nil || a["kubeworkspaces.io/issuer"] != token.Issuer || a["kubeworkspaces.io/subject"] != token.Subject || a["kubeworkspaces.io/user-name"] != user.record.GetName() || a["kubeworkspaces.io/user-uid"] != user.UID {
			return false, fmt.Errorf("identity ownership conflict")
		}
		version := a["kubeworkspaces.io/credential-version"]
		if version == "" && claim.GetUID() != "" {
			version = "uid:" + string(claim.GetUID())
		}
		if version == "" || version != token.CredentialVersion {
			return false, fmt.Errorf("OIDC credential revoked")
		}
		users, err := p.dynamicClient.Resource(userGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		matches := 0
		for _, candidate := range users.Items {
			bindings, _, err := unstructured.NestedSlice(candidate.Object, "spec", "externalIdentities")
			if err != nil {
				return false, err
			}
			for _, binding := range bindings {
				m, ok := binding.(map[string]interface{})
				if !ok {
					return false, fmt.Errorf("invalid identity binding")
				}
				if m["issuer"] == token.Issuer && m["subject"] == token.Subject {
					if candidate.GetUID() != user.record.GetUID() || candidate.GetName() != user.record.GetName() {
						return false, fmt.Errorf("identity ownership conflict")
					}
					matches++
				}
			}
		}
		if matches != 1 {
			return false, fmt.Errorf("identity binding unavailable or ambiguous")
		}
		return false, nil
	default:
		return false, fmt.Errorf("fresh sign-in required")
	}
}
