package k8s

import (
	"context"
	"errors"
	"net"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ResolveAgentOwner restricts premium peer hops to pods in this proxy's own
// namespace, release and service account. Lease metadata is not a dial address.
func (c *Client) ResolveAgentOwner(ctx context.Context, ns, self, owner, port string) (string, error) {
	pods := c.dynamic.Resource(schema.GroupVersionResource{Version: "v1", Resource: "pods"}).Namespace(ns)
	me, err := pods.Get(ctx, self, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	peer, err := pods.Get(ctx, owner, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	instance := me.GetLabels()["app.kubernetes.io/instance"]
	mySA, _, _ := unstructured.NestedString(me.Object, "spec", "serviceAccountName")
	peerSA, _, _ := unstructured.NestedString(peer.Object, "spec", "serviceAccountName")
	ip, _, _ := unstructured.NestedString(peer.Object, "status", "podIP")
	if peer.GetLabels()["app.kubernetes.io/instance"] != instance || peer.GetLabels()["app.kubernetes.io/name"] != me.GetLabels()["app.kubernetes.io/name"] || peer.GetLabels()["app.kubernetes.io/component"] != "proxy" || mySA == "" || mySA != peerSA || net.ParseIP(ip) == nil || peer.GetDeletionTimestamp() != nil {
		return "", errors.New("agent owner is not a live proxy peer")
	}
	return net.JoinHostPort(ip, port), nil
}
