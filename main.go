package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

var log = logf.Log.WithName("kubehub")
var GroupName = os.Getenv("GROUP_NAME")

const (
	configMapName      = "kubehub-dns01-challenge"
	configMapNamespace = "cert-manager"
)

type kubehubDNSProviderSolver struct {
	client kubernetes.Interface
	mu     sync.Mutex
}

func main() {
	if GroupName == "" {
		klog.Fatal("GROUP_NAME environment variable must be set")
	}
	cmd.RunWebhookServer(GroupName, &kubehubDNSProviderSolver{})
}

func (s *kubehubDNSProviderSolver) Name() string {
	return "default"
}

func (s *kubehubDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	log.Info("got request DNSName=%s, UID=%s", ch.DNSName, ch.UID)
	return s.appendToConfigMap("Present", ch)
}

func (s *kubehubDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	log.Info("got request DNSName=%s, UID=%s", ch.DNSName, ch.UID)
	return s.appendToConfigMap("Cleanup", ch)
}

func (s *kubehubDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	client, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		log.Error(err, "failed to create kubernetes client: %s", err)
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	s.client = client
	return nil
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
