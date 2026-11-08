package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd/server"
	"github.com/go-logr/logr"
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
	ctrl "sigs.k8s.io/controller-runtime"
)

var logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
var groupName = os.Getenv("GROUP_NAME")

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
	if groupName == "" {
		logger.Error("GROUP_NAME environment variable must be set")
		os.Exit(1)
	}
	logs.InitLogs()
	defer logs.FlushLogs()
	ctrl.SetLogger(logr.Discard())

	solver := &kubehubDNSProviderSolver{}
	ctx := ctrl.SetupSignalHandler()

	command := server.NewCommandStartWebhookServer(ctx, groupName, solver)
	command.Flags().BoolVar(&solver.useCRD, "crd", false, "Track DNS01 challenges with DNS01Challenge custom resources instead of a ConfigMap")

	if err := command.ExecuteContext(ctx); err != nil {
		logger.Error("error executing webhook server", "error", err)
		os.Exit(1)
	}
}

func (s *kubehubDNSProviderSolver) Name() string {
	return "default"
}

func (s *kubehubDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	logger.Info("received challenge request", challengeLogAttrs(ch)...)
	if s.useCRD {
		return s.processChallengeCR(ch, v1alpha1.ChallengeActionPresent)
	}
	return s.appendToConfigMap("Present", ch)
}

func (s *kubehubDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	logger.Info("received challenge request", challengeLogAttrs(ch)...)
	if s.useCRD {
		return s.processChallengeCR(ch, v1alpha1.ChallengeActionCleanUp)
	}
	return s.appendToConfigMap("Cleanup", ch)
}

func challengeLogAttrs(ch *v1alpha1.ChallengeRequest) []any {
	return []any{
		"uid", ch.UID,
		"action", ch.Action,
		"type", ch.Type,
		"dns_name", ch.DNSName,
		"key", ch.Key,
		"resource_namespace", ch.ResourceNamespace,
		"resolved_fqdn", ch.ResolvedFQDN,
		"resolved_zone", ch.ResolvedZone,
		"allow_ambient_credentials", ch.AllowAmbientCredentials,
		"config", ch.Config,
	}
}

func (s *kubehubDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	client, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		logger.Error("failed to create kubernetes client", "error", err)
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(kubeClientConfig)
	if err != nil {
		logger.Error("failed to create dynamic client", "error", err)
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
	logger.Info("starting DNS01Challenge operation", "name", challengeCRName(ch), "action", action, "dns_name", ch.DNSName, "uid", ch.UID)
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
		logger.Info("DNS01Challenge not found; creating", "name", name, "action", action)
		created, err := resource.Create(ctx, obj, metav1.CreateOptions{})
		if err != nil {
			logger.Error("failed to create DNS01Challenge", "error", err, "name", name)
			return fmt.Errorf("failed to create DNS01Challenge %q: %w", name, err)
		}
		generation = created.GetGeneration()
		logger.Info("created DNS01Challenge", "name", name, "generation", generation, "action", action)
	case err != nil:
		logger.Error("failed to get DNS01Challenge", "error", err, "name", name)
		return fmt.Errorf("failed to get DNS01Challenge %q: %w", name, err)
	case existing.GetDeletionTimestamp() != nil:
		logger.Info("DNS01Challenge is pending deletion; waiting before recreating", "name", name, "action", action)
		// The previous lifecycle is still being deleted. Wait for it to go
		// away before creating a fresh object.
		if err := s.waitForChallengeDeletion(ctx, name); err != nil {
			return err
		}
		created, err := resource.Create(ctx, obj, metav1.CreateOptions{})
		if err != nil {
			logger.Error("failed to create DNS01Challenge", "error", err, "name", name)
			return fmt.Errorf("failed to create DNS01Challenge %q: %w", name, err)
		}
		generation = created.GetGeneration()
		logger.Info("recreated DNS01Challenge", "name", name, "generation", generation, "action", action)
	default:
		logger.Info("found existing DNS01Challenge", "name", name, "generation", existing.GetGeneration(), "action", action)
		existingSpec, _, err := unstructured.NestedStringMap(existing.Object, "spec")
		if err != nil {
			return fmt.Errorf("failed to read spec of DNS01Challenge %q: %w", name, err)
		}
		if reflect.DeepEqual(existingSpec, toStringMap(spec)) {
			generation = existing.GetGeneration()
			logger.Info("DNS01Challenge spec already matches; skipping update", "name", name, "generation", generation, "action", action)
			break
		}

		existing.Object["spec"] = spec
		updated, err := resource.Update(ctx, existing, metav1.UpdateOptions{})
		if err != nil {
			logger.Error("failed to update DNS01Challenge", "error", err, "name", name)
			return fmt.Errorf("failed to update DNS01Challenge %q: %w", name, err)
		}
		generation = updated.GetGeneration()
		logger.Info("updated DNS01Challenge spec", "name", name, "generation", generation, "action", action)
	}

	logger.Info("waiting for DNS01Challenge to be processed", "name", name, "generation", generation, "action", action)
	completed, waitErr := s.waitForChallengeProcessed(ctx, name, generation)
	if waitErr != nil {
		// A terminal failure means this phase will not complete. Drop the CR
		// so the next cert-manager retry starts with a clean object.
		// On a timeout the CR is kept so the retry can observe the eventual
		// result instead of racing the controller.
		if completed {
			logger.Info("processed DNS01Challenge failed; deleting completed object", "name", name, "action", action)
			if deleteErr := s.deleteChallengeCR(ctx, name); deleteErr != nil {
				logger.Error("failed to delete DNS01Challenge", "error", deleteErr, "name", name)
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
		logger.Info("deleted DNS01Challenge after cleanup", "name", name, "action", action)
		logger.Info("DNS01Challenge cleaned up", "name", name, "action", action, "uid", ch.UID)
		return nil
	}

	logger.Info("DNS01Challenge presented", "name", name, "action", action, "uid", ch.UID)
	return nil
}

func (s *kubehubDNSProviderSolver) deleteChallengeCR(ctx context.Context, name string) error {
	logger.Info("deleting DNS01Challenge", "name", name)
	resource := s.dynamicClient.Resource(dns01ChallengeGVR).Namespace(configMapNamespace)
	if err := resource.Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete DNS01Challenge %q: %w", name, err)
	}
	logger.Info("DNS01Challenge deletion requested", "name", name)
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
	logger.Info("polling DNS01Challenge status", "name", name, "generation", generation, "poll_interval", crdPollInterval, "timeout", crdWaitTimeout)
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
			logger.Info("ignoring stale DNS01Challenge condition", "name", name, "generation", generation, "observed_generation", observedGeneration, "status", status)
			return false, nil
		}
		logger.Info("observed DNS01Challenge condition", "name", name, "generation", generation, "observed_generation", observedGeneration, "status", status, "message", message)

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

	logger.Info("DNS01Challenge processed", "name", name, "generation", generation)
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
	logger.Info("updating challenge state", "field", field, "dns_name", ch.DNSName, "uid", ch.UID)
	s.mu.Lock()
	defer s.mu.Unlock()

	cm, err := s.client.CoreV1().ConfigMaps(configMapNamespace).Get(context.Background(), configMapName, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			logger.Error("failed to get configmap", "error", err, "name", configMapName, "namespace", configMapNamespace)
			return fmt.Errorf("failed to get configmap: %w", err)
		}
		logger.Info("challenge state ConfigMap does not exist; creating it", "name", configMapName, "namespace", configMapNamespace)
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
			logger.Error("failed to create configmap", "error", err, "name", configMapName, "namespace", configMapNamespace)
			return fmt.Errorf("failed to create configmap: %w", err)
		}
	}

	entries := map[string]json.RawMessage{}
	if data, ok := cm.Data[field]; ok && data != "" {
		if err := json.Unmarshal([]byte(data), &entries); err != nil {
			logger.Error("failed to unmarshal ConfigMap field", "error", err, "field", field)
			return fmt.Errorf("failed to unmarshal %q field: %w", field, err)
		}
	}
	logger.Info("loaded challenge state", "field", field, "entry_count", len(entries))

	chBytes, err := json.Marshal(ch)
	if err != nil {
		logger.Error("failed to marshal challenge request", "error", err, "uid", ch.UID)
		return fmt.Errorf("failed to marshal challenge request: %w", err)
	}
	logger.Info("challenge request payload", "field", field, "uid", ch.UID, "payload", string(chBytes))

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
			logger.Info("skipping ConfigMap update; challenge state is already up to date", "field", field, "dns_name", ch.DNSName, "uid", ch.UID)
			return nil
		}
		logger.Info("existing challenge state differs; replacing it", "field", field, "dns_name", ch.DNSName, "uid", ch.UID)
	}

	entries[ch.DNSName] = json.RawMessage(chBytes)

	data, err := json.Marshal(entries)
	if err != nil {
		logger.Error("failed to marshal challenge entries", "error", err, "field", field)
		return fmt.Errorf("failed to marshal entries: %w", err)
	}

	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}
	cm.Data[field] = string(data)

	_, err = s.client.CoreV1().ConfigMaps(configMapNamespace).Update(context.Background(), cm, metav1.UpdateOptions{})
	if err != nil {
		logger.Error("failed to update challenge state ConfigMap", "error", err, "field", field, "dns_name", ch.DNSName)
		return fmt.Errorf("failed to update configmap: %w", err)
	}
	logger.Info("updated challenge state ConfigMap", "field", field, "dns_name", ch.DNSName, "uid", ch.UID)

	return nil
}
