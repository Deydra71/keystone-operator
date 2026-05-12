package controller

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	keystonev1 "github.com/openstack-k8s-operators/keystone-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	oko_secret "github.com/openstack-k8s-operators/lib-common/modules/common/secret"
	edpm "github.com/openstack-k8s-operators/lib-common/modules/edpm"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(keystonev1.AddToScheme(s))
	return s
}

func newTestRESTMapper() meta.RESTMapper {
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{
		{Group: "dataplane.openstack.org", Version: "v1beta1"},
	})
	mapper.Add(edpm.NodeSetGVK, meta.RESTScopeNamespace)
	return mapper
}

func makeNodeSet(name, namespace string, secretHashes map[string]string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(edpm.NodeSetGVK)
	obj.SetName(name)
	obj.SetNamespace(namespace)
	if len(secretHashes) > 0 {
		hashes := map[string]interface{}{}
		for k, v := range secretHashes {
			hashes[k] = v
		}
		obj.Object["status"] = map[string]interface{}{
			"secretHashes": hashes,
		}
	}
	return obj
}

func makeACSecret(name, namespace, serviceName string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"application-credentials":        "true",
				"application-credential-service": serviceName,
			},
			Finalizers: []string{acSecretFinalizer},
		},
		Data: map[string][]byte{
			keystonev1.ACIDSecretKey:     {},
			keystonev1.ACSecretSecretKey: []byte("fake-secret"),
		},
	}
}

func TestCleanupUnusedRotatedSecrets_BlockedByStaleNodeSet(t *testing.T) {
	ns := "test-blocking"
	serviceName := "nova"
	configSecretName := "nova-config"

	configSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: configSecretName, Namespace: ns},
		Data:       map[string][]byte{"config": []byte("new-config-data")},
	}
	configHash, err := oko_secret.Hash(configSecret)
	if err != nil {
		t.Fatalf("failed to hash config secret: %v", err)
	}

	// NodeSet reports a stale hash — EDPM has NOT been redeployed yet
	nodeset := makeNodeSet("edpm-compute", ns, map[string]string{
		configSecretName: configHash + "-stale",
	})

	acSecret := makeACSecret("ac-nova-old-secret", ns, serviceName)

	s := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithRESTMapper(newTestRESTMapper()).
		WithObjects(configSecret, acSecret).
		WithStatusSubresource(&keystonev1.KeystoneApplicationCredential{}).
		WithObjects(nodeset).
		Build()

	instance := &keystonev1.KeystoneApplicationCredential{
		ObjectMeta: metav1.ObjectMeta{Name: "ac-" + serviceName, Namespace: ns},
		Status: keystonev1.KeystoneApplicationCredentialStatus{
			SecretName:         "ac-nova-current-secret",
			PreviousSecretName: "ac-nova-previous-secret",
		},
	}

	kclient := k8sfake.NewSimpleClientset(acSecret)
	helperObj, err := helper.NewHelper(instance, c, kclient, s, logr.Discard())
	if err != nil {
		t.Fatalf("failed to create helper: %v", err)
	}

	reconciler := &ApplicationCredentialReconciler{
		Client: c,
		Scheme: s,
		Log:    logr.Discard(),
	}

	err = reconciler.cleanupUnusedRotatedSecrets(context.Background(), instance, helperObj, nil, "")
	if err != nil {
		t.Fatalf("cleanupUnusedRotatedSecrets returned error: %v", err)
	}

	// The AC secret must still exist — cleanup was blocked by stale NodeSet
	preserved := &corev1.Secret{}
	err = c.Get(context.Background(), types.NamespacedName{Name: acSecret.Name, Namespace: ns}, preserved)
	if err != nil {
		t.Fatalf("AC secret was deleted but should have been preserved (EDPM out of sync): %v", err)
	}
	if len(preserved.Finalizers) == 0 || preserved.Finalizers[0] != acSecretFinalizer {
		t.Errorf("AC secret finalizer was modified; expected %s, got %v", acSecretFinalizer, preserved.Finalizers)
	}
}

func TestCleanupUnusedRotatedSecrets_ProceedsWithoutNodeSets(t *testing.T) {
	ns := "test-no-nodesets"
	serviceName := "nova"

	// AC secret with empty ACID so Keystone revocation is skipped
	acSecret := makeACSecret("ac-nova-old-secret", ns, serviceName)

	s := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithRESTMapper(newTestRESTMapper()).
		WithObjects(acSecret).
		WithStatusSubresource(&keystonev1.KeystoneApplicationCredential{}).
		Build()

	instance := &keystonev1.KeystoneApplicationCredential{
		ObjectMeta: metav1.ObjectMeta{Name: "ac-" + serviceName, Namespace: ns},
		Status: keystonev1.KeystoneApplicationCredentialStatus{
			SecretName:         "ac-nova-current-secret",
			PreviousSecretName: "ac-nova-previous-secret",
		},
	}

	kclient := k8sfake.NewSimpleClientset(acSecret)
	helperObj, err := helper.NewHelper(instance, c, kclient, s, logr.Discard())
	if err != nil {
		t.Fatalf("failed to create helper: %v", err)
	}

	reconciler := &ApplicationCredentialReconciler{
		Client: c,
		Scheme: s,
		Log:    logr.Discard(),
	}

	err = reconciler.cleanupUnusedRotatedSecrets(context.Background(), instance, helperObj, nil, "")
	if err != nil {
		t.Fatalf("cleanupUnusedRotatedSecrets returned error: %v", err)
	}

	// The AC secret should be deleted — no NodeSets means hashes are in sync
	deleted := &corev1.Secret{}
	err = c.Get(context.Background(), types.NamespacedName{Name: acSecret.Name, Namespace: ns}, deleted)
	if err == nil {
		t.Fatalf("AC secret still exists but should have been deleted (no NodeSets, cleanup should proceed)")
	}
	if client.IgnoreNotFound(err) != nil {
		t.Fatalf("unexpected error checking for deleted secret: %v", err)
	}
}
