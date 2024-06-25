/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package keyhub provides a KeyHub provider for External Secrets.
package keyhub

import (
	"context"
	"sync"

	ctrl "sigs.k8s.io/controller-runtime"
	kubeClient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/external-secrets/external-secrets/pkg/cache"
	"github.com/external-secrets/external-secrets/pkg/provider/keyhub/util"
)

var (
	logger = ctrl.Log.WithName("provider").WithName("keyhub")

	// Create a single Keyhub client per store.
	useMu       = sync.Mutex{}
	clientCache *cache.Cache[*client]
)

type Provider struct {
}

// Capabilities returns the provider Capabilities (Read, Write, ReadWrite).
func (p *Provider) Capabilities() esv1beta1.SecretStoreCapabilities {
	return esv1beta1.SecretStoreReadOnly
}

// NewClient creates a new KeyHub client.
func (p *Provider) NewClient(ctx context.Context, store esv1beta1.GenericStore, kube kubeClient.Client, namespace string) (esv1beta1.SecretsClient, error) {
	cfg, err := util.GetKeyHubProvider(store)
	if err != nil {
		return nil, err
	}

	return p.newClient(ctx, store, cfg, kube, namespace)
}

func (p *Provider) newClient(ctx context.Context, store esv1beta1.GenericStore, cfg *esv1beta1.KeyHubProvider, kube kubeClient.Client, namespace string) (esv1beta1.SecretsClient, error) {
	key := cache.Key{
		Name:      store.GetObjectMeta().Name,
		Namespace: store.GetObjectMeta().Namespace,
		Kind:      store.GetTypeMeta().Kind,
	}

	client, ok := clientCache.Get(store.GetObjectMeta().ResourceVersion, key)
	if ok {
		return client, nil
	}

	useMu.Lock()
	defer useMu.Unlock()

	client, ok = clientCache.Get(store.GetObjectMeta().ResourceVersion, key)
	if ok {
		return client, nil
	}

	client, err := NewClient(ctx, cfg, kube, store.GetTypeMeta().Kind, namespace)
	if err != nil {
		return nil, err
	}

	clientCache.Add(store.GetObjectMeta().ResourceVersion, key, client)

	return client, nil
}

func init() {
	// TODO: make cache size configurable (for large clusters with alot of unique clients)
	clientCache = cache.Must[*client](256, nil)

	esv1beta1.Register(&Provider{}, &esv1beta1.SecretStoreProvider{
		KeyHub: &esv1beta1.KeyHubProvider{},
	})
}
