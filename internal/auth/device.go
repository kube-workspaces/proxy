package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Device registrations share API's fixed storage namespace, independently of
// the installation namespace used for session signing keys.
const deviceNamespace = "kube-workspaces-system"

// ValidateDevice checks the same backing registration used by API revocation.
// Never cache this lookup: deleting a registration must deny the next request.
func (p *ConfigProvider) ValidateDevice(ctx context.Context, token *SessionToken) error {
	if token.JTI == "" || p.dynamicClient == nil {
		return fmt.Errorf("device registration unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	obj, err := p.dynamicClient.Resource(secretGVR).Namespace(deviceNamespace).Get(ctx, "kw-device-"+token.JTI, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("device registration unavailable: %w", err)
	}
	if obj.GetDeletionTimestamp() != nil {
		return fmt.Errorf("device registration is being deleted")
	}
	owner := obj.GetAnnotations()["kubeworkspaces.io/device-email"]
	if owner != "" && !strings.EqualFold(owner, token.Email) {
		return fmt.Errorf("device owner does not match")
	}
	data, found, err := unstructured.NestedStringMap(obj.Object, "data")
	if err != nil {
		return fmt.Errorf("invalid device registration")
	}
	if found {
		for key, value := range data {
			decoded, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return fmt.Errorf("invalid device registration")
			}
			data[key] = string(decoded)
		}
	} else {
		// Fake dynamic clients do not convert stringData on write.
		data, _, err = unstructured.NestedStringMap(obj.Object, "stringData")
		if err != nil {
			return fmt.Errorf("invalid device registration")
		}
	}
	if data["email"] != "" {
		if !strings.EqualFold(data["email"], token.Email) {
			return fmt.Errorf("device owner does not match")
		}
		owner = data["email"]
	}
	expires, err := strconv.ParseInt(data["expiresAt"], 10, 64)
	if owner == "" || data["revoked"] != "false" || err != nil || time.Now().Unix() >= expires {
		return fmt.Errorf("device registration is invalid, expired or revoked")
	}
	return nil
}
