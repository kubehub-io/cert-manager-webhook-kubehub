package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
var groupName = os.Getenv("GROUP_NAME")

const (
	configMapName      = "kubehub-dns01-challenge"
	configMapNamespace = "cert-manager"
)

type kubehubDNSProviderSolver struct {
	client kubernetes.Interface
	mu     sync.Mutex
}

func main() {
	if groupName == "" {
		logger.Error("GROUP_NAME environment variable must be set")
		os.Exit(1)
	}
	cmd.RunWebhookServer(groupName, &kubehubDNSProviderSolver{})
}

func (s *kubehubDNSProviderSolver) Name() string {
	return "default"
}

func (s *kubehubDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	logger.Info("received challenge request", challengeLogAttrs(ch)...)
	return s.appendToConfigMap("Present", ch)
}

func (s *kubehubDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	logger.Info("received challenge request", challengeLogAttrs(ch)...)
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
	s.client = client
	return nil
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
