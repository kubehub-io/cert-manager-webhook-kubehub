package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd/server"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

var log = logf.Log.WithName("kubehub")
var GroupName = os.Getenv("GROUP_NAME")

const (
	configMapName      = "kubehub-dns01-challenge"
	configMapNamespace = "cert-manager"

	challengeGroup    = "gateway.kubehub.io"
	challengeVersion  = "v1alpha1"
	challengeResource = "dns01challenges"
	challengeKind     = "DNS01Challenge"

	processedCondition = "Processed"

	crdPollInterval = 2 * time.Second
	crdWaitTimeout  = 2 * time.Minute
)

var dns01ChallengeGVR = schema.GroupVersionResource{
	Group:    challengeGroup,
	Version:  challengeVersion,
	Resource: challengeResource,
}

type kubehubDNSProviderSolver struct {
	client        kubernetes.Interface
	dynamicClient dynamic.Interface
	useCRD        bool
	mu            sync.Mutex
}

func main() {
	if GroupName == "" {
		klog.Fatal("GROUP_NAME environment variable must be set")
	}

	logs.InitLogs()
	defer logs.FlushLogs()
	ctrl.SetLogger(logf.Log)

	solver := &kubehubDNSProviderSolver{}
	ctx := logf.NewContext(ctrl.SetupSignalHandler(), logf.Log, "acme-dns-webhook")

	command := server.NewCommandStartWebhookServer(ctx, GroupName, solver)
	command.Flags().BoolVar(&solver.useCRD, "crd", false, "Track DNS01 challenges with DNS01Challenge custom resources instead of a ConfigMap")

	if err := command.ExecuteContext(ctx); err != nil {
		logf.Log.Error(err, "error executing command")
		os.Exit(1)
	}
}

func (s *kubehubDNSProviderSolver) Name() string {
	return "default"
}

func (s *kubehubDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	log.Info("got request DNSName=%s, UID=%s", ch.DNSName, ch.UID)
	if s.useCRD {
		return s.processChallengeCR(ch, v1alpha1.ChallengeActionPresent)
	}
	return s.appendToConfigMap("Present", ch)
}

func (s *kubehubDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	log.Info("got request DNSName=%s, UID=%s", ch.DNSName, ch.UID)
	if s.useCRD {
		return s.processChallengeCR(ch, v1alpha1.ChallengeActionCleanUp)
	}
	return s.appendToConfigMap("Cleanup", ch)
}

func (s *kubehubDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	client, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		log.Error(err, "failed to create kubernetes client: %s", err)
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(kubeClientConfig)
	if err != nil {
		log.Error(err, "failed to create dynamic client: %s", err)
		return fmt.Errorf("failed to create dynamic client: %w", err)
	}

	s.client = client
	s.dynamicClient = dynamicClient
	return nil
}

// processChallengeCR keeps one DNS01Challenge for the lifetime of a
// certificate request. Present leaves the CR in place; CleanUp reuses it,
// waits for the controller to confirm the record is removed, and then deletes
// the CR.
func (s *kubehubDNSProviderSolver) processChallengeCR(ch *v1alpha1.ChallengeRequest, action v1alpha1.ChallengeAction) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	name := challengeCRName(ch)
	resource := s.dynamicClient.Resource(dns01ChallengeGVR).Namespace(configMapNamespace)

	spec := map[string]interface{}{
		"action":            string(action),
		"dnsName":           ch.DNSName,
		"key":               ch.Key,
		"resolvedFQDN":      ch.ResolvedFQDN,
		"resolvedZone":      ch.ResolvedZone,
		"resourceNamespace": ch.ResourceNamespace,
		"uid":               string(ch.UID),
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": challengeGroup + "/" + challengeVersion,
			"kind":       challengeKind,
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": configMapNamespace,
			},
			"spec": spec,
		},
	}

	var generation int64
	existing, err := resource.Get(ctx, name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		created, err := resource.Create(ctx, obj, metav1.CreateOptions{})
		if err != nil {
			log.Error(err, "failed to create DNS01Challenge", "name", name)
			return fmt.Errorf("failed to create DNS01Challenge %q: %w", name, err)
		}
		generation = created.GetGeneration()
	case err != nil:
		log.Error(err, "failed to get DNS01Challenge", "name", name)
		return fmt.Errorf("failed to get DNS01Challenge %q: %w", name, err)
	case existing.GetDeletionTimestamp() != nil:
		// The previous lifecycle is still being deleted. Wait for it to go
		// away before creating a fresh object.
		if err := s.waitForChallengeDeletion(ctx, name); err != nil {
			return err
		}
		created, err := resource.Create(ctx, obj, metav1.CreateOptions{})
		if err != nil {
			log.Error(err, "failed to create DNS01Challenge", "name", name)
			return fmt.Errorf("failed to create DNS01Challenge %q: %w", name, err)
		}
		generation = created.GetGeneration()
	default:
		existingSpec, _, err := unstructured.NestedStringMap(existing.Object, "spec")
		if err != nil {
			return fmt.Errorf("failed to read spec of DNS01Challenge %q: %w", name, err)
		}
		if reflect.DeepEqual(existingSpec, toStringMap(spec)) {
			generation = existing.GetGeneration()
			break
		}

		existing.Object["spec"] = spec
		updated, err := resource.Update(ctx, existing, metav1.UpdateOptions{})
		if err != nil {
			log.Error(err, "failed to update DNS01Challenge", "name", name)
			return fmt.Errorf("failed to update DNS01Challenge %q: %w", name, err)
		}
		generation = updated.GetGeneration()
	}

	completed, waitErr := s.waitForChallengeProcessed(ctx, name, generation)
	if waitErr != nil {
		// A terminal failure means this phase will not complete. Drop the CR
		// so the next cert-manager retry starts with a clean object.
		// On a timeout the CR is kept so the retry can observe the eventual
		// result instead of racing the controller.
		if completed {
			if deleteErr := s.deleteChallengeCR(ctx, name); deleteErr != nil {
				log.Error(deleteErr, "failed to delete DNS01Challenge", "name", name)
			}
		}
		return waitErr
	}

	if action == v1alpha1.ChallengeActionCleanUp {
		// CleanUp is the end of the lifecycle, so the CR can be removed once
		// the controller confirms the TXT record is gone.
		if err := s.deleteChallengeCR(ctx, name); err != nil {
			return err
		}
		log.Info("DNS01Challenge cleaned up", "name", name)
		return nil
	}

	log.Info("DNS01Challenge presented", "name", name)
	return nil
}

func (s *kubehubDNSProviderSolver) deleteChallengeCR(ctx context.Context, name string) error {
	resource := s.dynamicClient.Resource(dns01ChallengeGVR).Namespace(configMapNamespace)
	if err := resource.Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete DNS01Challenge %q: %w", name, err)
	}
	return nil
}

// waitForChallengeProcessed waits for a terminal Processed condition that was
// observed at the given CR generation. The returned bool reports whether a
// terminal condition was observed; when it is false the caller should keep the
// CR for a later retry.
func (s *kubehubDNSProviderSolver) waitForChallengeProcessed(ctx context.Context, name string, generation int64) (bool, error) {
	resource := s.dynamicClient.Resource(dns01ChallengeGVR).Namespace(configMapNamespace)

	waitCtx, cancel := context.WithTimeout(ctx, crdWaitTimeout)
	defer cancel()

	var lastErr error
	var completed bool
	err := wait.PollUntilContextTimeout(waitCtx, crdPollInterval, crdWaitTimeout, true, func(ctx context.Context) (bool, error) {
		obj, err := resource.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return false, fmt.Errorf("DNS01Challenge %q disappeared before it was processed", name)
			}
			lastErr = err
			return false, nil
		}

		status, message, observedGeneration, found := challengeCondition(obj, processedCondition)
		if !found {
			return false, nil
		}

		// spec.action changes bump metadata.generation. Ignore a Processed
		// condition left over from the previous phase until the controller
		// reports that it observed the current generation. Prefer the
		// condition's own observedGeneration; fall back to the top-level
		// status field when the condition does not set it.
		if observedGeneration == 0 {
			observedGeneration = nestedInt64(obj.Object, "status", "observedGeneration")
		}
		if observedGeneration < generation {
			return false, nil
		}

		switch status {
		case string(metav1.ConditionTrue):
			completed = true
			return true, nil
		case string(metav1.ConditionFalse):
			completed = true
			if message == "" {
				message = "controller reported the challenge as not processed"
			}
			return false, fmt.Errorf("DNS01Challenge %q was not processed: %s", name, message)
		default:
			return false, nil
		}
	})
	if err != nil {
		if completed {
			return true, err
		}
		if lastErr != nil {
			return false, fmt.Errorf("failed to wait for DNS01Challenge %q: %w", name, lastErr)
		}
		return false, fmt.Errorf("failed to wait for DNS01Challenge %q to be processed: %w", name, err)
	}

	log.Info("DNS01Challenge processed", "name", name, "generation", generation)
	return true, nil
}

func (s *kubehubDNSProviderSolver) waitForChallengeDeletion(ctx context.Context, name string) error {
	resource := s.dynamicClient.Resource(dns01ChallengeGVR).Namespace(configMapNamespace)

	waitCtx, cancel := context.WithTimeout(ctx, crdWaitTimeout)
	defer cancel()

	err := wait.PollUntilContextTimeout(waitCtx, crdPollInterval, crdWaitTimeout, true, func(ctx context.Context) (bool, error) {
		_, err := resource.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("failed to wait for DNS01Challenge %q to be deleted: %w", name, err)
	}
	return nil
}

func challengeCondition(obj *unstructured.Unstructured, conditionType string) (status, message string, observedGeneration int64, found bool) {
	conditions, ok, err := unstructured.NestedSlice(obj.Object, "status", "conditions")
	if err != nil || !ok {
		return "", "", 0, false
	}

	for _, raw := range conditions {
		condition, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		typ, _, _ := unstructured.NestedString(condition, "type")
		if typ != conditionType {
			continue
		}
		status, _, _ = unstructured.NestedString(condition, "status")
		message, _, _ = unstructured.NestedString(condition, "message")
		observedGeneration = nestedInt64(condition, "observedGeneration")
		return status, message, observedGeneration, true
	}

	return "", "", 0, false
}

func nestedInt64(obj map[string]interface{}, fields ...string) int64 {
	value, found, err := unstructured.NestedFieldNoCopy(obj, fields...)
	if err != nil || !found {
		return 0
	}

	switch v := value.(type) {
	case int64:
		return v
	case int32:
		return int64(v)
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case json.Number:
		n, err := v.Int64()
		if err == nil {
			return n
		}
	}

	return 0
}

var invalidChallengeNameChars = regexp.MustCompile(`[^a-z0-9.-]+`)

func challengeCRName(ch *v1alpha1.ChallengeRequest) string {
	// ChallengeRequest does not carry a Certificate name, so the DNS name is
	// the only stable, human-readable identifier available here.
	name := strings.ToLower(strings.TrimSuffix(ch.DNSName, "."))
	name = strings.ReplaceAll(name, "*", "wildcard")
	name = invalidChallengeNameChars.ReplaceAllString(name, "-")
	name = strings.Trim(name, "-.")
	if name == "" {
		return "dns01-challenge"
	}
	if len(name) > 253 {
		name = strings.Trim(name[:253], "-.")
	}

	return name
}

func toStringMap(in map[string]interface{}) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

func (s *kubehubDNSProviderSolver) appendToConfigMap(field string, ch *v1alpha1.ChallengeRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cm, err := s.client.CoreV1().ConfigMaps(configMapNamespace).Get(context.Background(), configMapName, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "failed to get configmap: %s", err)
			return fmt.Errorf("failed to get configmap: %w", err)
		}
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      configMapName,
				Namespace: configMapNamespace,
			},
			Data: map[string]string{
				"Present": "{}",
				"Cleanup": "{}",
			},
		}
		cm, err = s.client.CoreV1().ConfigMaps(configMapNamespace).Create(context.Background(), cm, metav1.CreateOptions{})
		if err != nil {
			log.Error(err, "failed to create configmap: %s", err)
			return fmt.Errorf("failed to create configmap: %w", err)
		}
	}

	entries := map[string]json.RawMessage{}
	if data, ok := cm.Data[field]; ok && data != "" {
		if err := json.Unmarshal([]byte(data), &entries); err != nil {
			log.Error(err, "failed to unmarshal %q field: %s", field, err)
			return fmt.Errorf("failed to unmarshal %q field: %w", field, err)
		}
	}

	chBytes, err := json.Marshal(ch)
	log.Info("requestPayload=%s, UID=%s", ch.UID, string(chBytes))
	if err != nil {
		log.Error(err, "failed to marshal challenge request: %s", err)
		return fmt.Errorf("failed to marshal challenge request: %w", err)
	}

	existingRaw, exists := entries[ch.DNSName]
	if exists {
		needsUpdate := false
		if field == "Present" {
			needsUpdate = string(existingRaw) != string(chBytes)
		} else {
			var existingReq v1alpha1.ChallengeRequest
			if err := json.Unmarshal(existingRaw, &existingReq); err == nil {
				needsUpdate = existingReq.DNSName != ch.DNSName || existingReq.ResolvedFQDN != ch.ResolvedFQDN
			} else {
				needsUpdate = true
			}
		}
		if !needsUpdate {
			log.Info("Skipping update for %s key=%s, entry already up to date", field, ch.DNSName)
			return nil
		}
	}

	entries[ch.DNSName] = json.RawMessage(chBytes)

	data, err := json.Marshal(entries)
	if err != nil {
		log.Error(err, "failed to marshal entries: %s", err)
		return fmt.Errorf("failed to marshal entries: %w", err)
	}

	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}
	cm.Data[field] = string(data)

	_, err = s.client.CoreV1().ConfigMaps(configMapNamespace).Update(context.Background(), cm, metav1.UpdateOptions{})
	if err != nil {
		log.Error(err, "failed to update configmap: %s", err)
		return fmt.Errorf("failed to update configmap: %w", err)
	}

	return nil
}
