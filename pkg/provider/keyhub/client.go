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
	"errors"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/keymutex"
	kubeClient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/external-secrets/external-secrets/pkg/cache"
	khClient "github.com/external-secrets/external-secrets/pkg/provider/keyhub/client"
	"github.com/external-secrets/external-secrets/pkg/provider/keyhub/util"
	keyhubmodels "github.com/topicuskeyhub/sdk-go/models"
)

var (
	_ esv1beta1.SecretsClient = &client{}
)

type client struct {
	client *khClient.KeyHubClient

	useMu       keymutex.KeyMutex
	recordCache *cache.Cache[keyhubmodels.VaultVaultRecordable]
}

func NewClient(ctx context.Context, cfg *esv1beta1.KeyHubProvider, kube kubeClient.Client, storeKind, namespace string) (*client, error) {
	logger.Info("creating KeyHub client", "issuer", cfg.Issuer)
	clientID, clientSecret, err := util.GetKeyHubAuth(ctx, cfg.Auth, kube, storeKind, namespace)
	if err != nil {
		return nil, err
	}

	khClient, err := khClient.NewKeyHubClient(cfg.Issuer, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	// TODO: make mutex and cache size configurable
	return &client{
		client:      khClient,
		useMu:       keymutex.NewHashed(16),
		recordCache: cache.Must[keyhubmodels.VaultVaultRecordable](2048, nil),
	}, nil
}

func (c *client) GetSecret(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) ([]byte, error) {
	logger.V(1).Info("fetching secret", "key", ref.Key, "property", ref.Property)

	record, err := c.getVaultRecord(ctx, ref)
	if err != nil {
		return nil, err
	}

	secret := record.GetAdditionalObjects().GetSecret()
	audit := record.GetAdditionalObjects().GetAudit()

	switch ref.Property {
	case "name":
		return []byte(*record.GetName()), nil
	case "color":
		return []byte(record.GetColor().String()), nil
	case "link":
		return []byte(*record.GetUrl()), nil
	case "username":
		return []byte(*record.GetUsername()), nil
	case "filename":
		return []byte(*record.GetFilename()), nil
	case "file":
		return []byte(*secret.GetFile()), nil
	case "enddate":
		return []byte(record.GetEndDate().String()), nil
	case "comment":
		return []byte(*secret.GetComment()), nil
	case "lastModifiedAt":
		return []byte(audit.GetLastModifiedAt().UTC().Format(time.RFC3339)), nil
	default:
		return []byte(*secret.GetPassword()), nil
	}
}

func (c *client) PushSecret(_ context.Context, _ *corev1.Secret, _ esv1beta1.PushSecretData) error {
	return errors.New("not implemented")
}

func (c *client) DeleteSecret(_ context.Context, _ esv1beta1.PushSecretRemoteRef) error {
	return errors.New("not implemented")
}

func (c *client) SecretExists(_ context.Context, _ esv1beta1.PushSecretRemoteRef) (bool, error) {
	return false, errors.New("not implemented")
}

func (c *client) Validate() (esv1beta1.ValidationResult, error) {
	return esv1beta1.ValidationResultReady, nil
}

func (c *client) GetSecretMap(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	return nil, errors.New("not implemented")
}

func (c *client) GetAllSecrets(_ context.Context, _ esv1beta1.ExternalSecretFind) (map[string][]byte, error) {
	// TODO (maybe):
	//   - path: <group uuid>
	//   - name: <regex obv vault record name>
	//   - tags
	//       group: <group uuid> (of via path?)
	//       color: <color> (alle secrets met kleurtje x, nuttig???)

	return nil, errors.New("not implemented")
}

func (c *client) Close(context.Context) error {
	return nil
}

// getVaultRecord retrieves the vault record referenced by ref from the KeyHub API.
func (c *client) getVaultRecord(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) (keyhubmodels.VaultVaultRecordable, error) {
	if ref.Version != "" {
		return nil, errors.New("specifying a version is not supported by KeyHub")
	}

	key := cache.Key{
		Name:      ref.Key,
		Namespace: "",
		Kind:      "",
	}

	// Only check 'version' (KeyHub lastModifiedAt field) if key exists in cache
	ok := c.recordCache.Contains(key)
	if ok {
		lastModifiedAt, err := c.client.GetVaultRecordLastModifiedAt(ctx, ref.Key)
		if err != nil {
			return nil, err
		}

		logger.V(1).Info("lookup secret from cache", "key", ref.Key, "lastModifiedAt", lastModifiedAt.String())
		record, ok := c.recordCache.Get(strconv.FormatInt(lastModifiedAt.Unix(), 10), key)
		if ok {
			return record, nil
		}
	}

	c.useMu.LockKey(ref.Key)
	defer func() {
		_ = c.useMu.UnlockKey(ref.Key)
	}()

	ok = c.recordCache.Contains(key)
	if ok {
		lastModifiedAt, err := c.client.GetVaultRecordLastModifiedAt(ctx, ref.Key)
		if err != nil {
			return nil, err
		}

		logger.V(1).Info("lookup secret from cache", "key", ref.Key, "lastModifiedAt", lastModifiedAt.String())
		record, ok := c.recordCache.Get(strconv.FormatInt(lastModifiedAt.Unix(), 10), key)
		if ok {
			return record, nil
		}
	}

	record, err := c.client.GetVaultRecord(ctx, ref.Key)
	if err != nil {
		return nil, err
	}
	logger.V(1).Info("caching version", "key", ref.Key, "lastModifiedAt", record.GetAdditionalObjects().GetAudit().GetLastModifiedAt())
	c.recordCache.Add(strconv.FormatInt(record.GetAdditionalObjects().GetAudit().GetLastModifiedAt().Unix(), 10), key, record)
	return record, nil
}
