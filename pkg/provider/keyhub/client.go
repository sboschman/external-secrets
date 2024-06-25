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
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	keyhubmodels "github.com/topicuskeyhub/sdk-go/models"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/keymutex"
	kubeClient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/cache"
	"github.com/external-secrets/external-secrets/pkg/find"
	khClient "github.com/external-secrets/external-secrets/pkg/provider/keyhub/client"
	"github.com/external-secrets/external-secrets/pkg/provider/keyhub/util"
)

const (
	errInvalidProperty        = "invalid property '%s'"
	errUnexpectedFindOperator = "unexpected find operator"
)

var (
	_ esv1.SecretsClient = &client{}
)

type client struct {
	client *khClient.KeyHubClient

	useMu       keymutex.KeyMutex
	recordCache *cache.Cache[keyhubmodels.VaultVaultRecordable]
}

func NewClient(ctx context.Context, cfg *esv1.KeyHubProvider, kube kubeClient.Client, storeKind, namespace string) (*client, error) {
	clientID, clientSecret, err := util.GetKeyHubAuth(ctx, cfg.Auth, kube, storeKind, namespace)
	if err != nil {
		return nil, err
	}
	logger.V(1).Info("creating KeyHub client", "issuer", cfg.Issuer, "client", clientID)

	khClient, err := khClient.NewKeyHubClient(cfg.Issuer, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	info, err := khClient.GetInfo(ctx)
	if err != nil {
		return nil, err
	}
	logger.Info("KeyHub connection validated", "issuer", cfg.Issuer, "client", clientID, "KeyHub version", info.GetKeyHubVersion())

	// TODO: make mutex and cache size configurable
	return &client{
		client:      khClient,
		useMu:       keymutex.NewHashed(16),
		recordCache: cache.Must[keyhubmodels.VaultVaultRecordable](2048, nil),
	}, nil
}

func (c *client) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	if ref.Version != "" {
		return nil, errors.New("specifying a version is not supported by KeyHub")
	}

	property := ref.Property
	if property == "" {
		property = "password"
	}

	logger.V(1).Info("fetching secret", "key", ref.Key, "property", property)

	record, err := c.getVaultRecord(ctx, ref.Key)
	if err != nil {
		return nil, err
	}

	values, err := c.getVaultRecordProperties(record, property)
	if err != nil {
		return nil, err
	}

	return values[property], nil
}

func (c *client) PushSecret(_ context.Context, _ *corev1.Secret, _ esv1.PushSecretData) error {
	return errors.New("not implemented")
}

func (c *client) DeleteSecret(_ context.Context, _ esv1.PushSecretRemoteRef) error {
	return errors.New("not implemented")
}

func (c *client) SecretExists(_ context.Context, _ esv1.PushSecretRemoteRef) (bool, error) {
	return false, errors.New("not implemented")
}

func (c *client) Validate() (esv1.ValidationResult, error) {
	_, err := c.client.GetInfo(context.TODO())
	if err != nil {
		return esv1.ValidationResultError, err
	}
	return esv1.ValidationResultReady, nil
}

func (c *client) GetSecretMap(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	if ref.Version != "" {
		return nil, errors.New("specifying a version is not supported by KeyHub")
	}

	logger.V(1).Info("fetching property map for secret", "key", ref.Key, "property", ref.Property)

	record, err := c.getVaultRecord(ctx, ref.Key)
	if err != nil {
		return nil, err
	}

	return c.getVaultRecordProperties(record, ref.Property)
}

func (c *client) GetAllSecrets(ctx context.Context, ref esv1.ExternalSecretFind) (map[string][]byte, error) {
	secrets, err := c.listSecrets(ctx, c.newVaultRecordFilter(ref))
	if err != nil {
		return nil, err
	}

	secretData := make(map[string][]byte, len(secrets)*2)
	for _, s := range secrets {
		record, err := c.getVaultRecord(ctx, *s.GetUuid())
		if err != nil {
			return nil, err
		}

		recordProperties, err := c.getVaultRecordProperties(record, "")
		if err != nil {
			return nil, err
		}

		isSingleProperty := len(recordProperties) == 1
		for propertyName, property := range recordProperties {
			key := *record.GetName()
			if !isSingleProperty {
				key = fmt.Sprintf("%s/%s", key, propertyName)
			}
			secretData[key] = property
		}
	}

	return secretData, nil
}

func (c *client) newVaultRecordFilter(ref esv1.ExternalSecretFind) khClient.VaultRecordFilter {
	filter := khClient.VaultRecordFilter{}

	if ref.Path != nil {
		filter.Group = *ref.Path
	}

	if ref.Name != nil {
		filter.Name = ref.Name
	}

	// TODO: map tags to VaultRecordFilter
	// for k, v := range ref.Tags {
	// }

	return filter
}

func (c *client) listSecrets(ctx context.Context, filter khClient.VaultRecordFilter) ([]keyhubmodels.VaultVaultRecordable, error) {
	potentialSecrets, err := c.client.GetVaultRecordMetadata(ctx, filter)
	if err != nil {
		return nil, err
	}

	if filter.Name != nil {
		return c.filterSecretsByName(potentialSecrets, *filter.Name)
	}

	return potentialSecrets, nil
}

func (c *client) filterSecretsByName(secrets []keyhubmodels.VaultVaultRecordable, name esv1.FindName) ([]keyhubmodels.VaultVaultRecordable, error) {
	matcher, err := find.New(name)
	if err != nil {
		return nil, err
	}

	filtered := make([]keyhubmodels.VaultVaultRecordable, 0, len(secrets))
	for _, r := range secrets {
		if matcher.MatchName(*r.GetName()) {
			filtered = append(filtered, r)
		}
	}

	return filtered, nil
}

func (c *client) Close(context.Context) error {
	return nil
}

// getVaultRecord retrieves the vault record referenced by ref from the KeyHub API.
func (c *client) getVaultRecord(ctx context.Context, uuid string) (keyhubmodels.VaultVaultRecordable, error) {
	key := cache.Key{
		Name:      uuid,
		Namespace: "",
		Kind:      "",
	}

	// Only check 'version' (KeyHub lastModifiedAt field) if key exists in cache
	ok := c.recordCache.Contains(key)
	if ok {
		lastModifiedAt, err := c.client.GetVaultRecordLastModifiedAt(ctx, uuid)
		if err != nil {
			return nil, err
		}

		logger.V(1).Info("lookup secret from cache", "key", uuid, "lastModifiedAt", lastModifiedAt.String())
		record, ok := c.recordCache.Get(strconv.FormatInt(lastModifiedAt.Unix(), 10), key)
		if ok {
			return record, nil
		}
	}

	c.useMu.LockKey(uuid)
	defer func() {
		_ = c.useMu.UnlockKey(uuid)
	}()

	ok = c.recordCache.Contains(key)
	if ok {
		lastModifiedAt, err := c.client.GetVaultRecordLastModifiedAt(ctx, uuid)
		if err != nil {
			return nil, err
		}

		logger.V(1).Info("lookup secret from cache", "key", uuid, "lastModifiedAt", lastModifiedAt.String())
		record, ok := c.recordCache.Get(strconv.FormatInt(lastModifiedAt.Unix(), 10), key)
		if ok {
			return record, nil
		}
	}

	record, err := c.client.GetVaultRecord(ctx, uuid)
	if err != nil {
		return nil, err
	}
	logger.V(1).Info("caching version", "key", uuid, "lastModifiedAt", record.GetAdditionalObjects().GetAudit().GetLastModifiedAt())
	c.recordCache.Add(strconv.FormatInt(record.GetAdditionalObjects().GetAudit().GetLastModifiedAt().Unix(), 10), key, record)
	return record, nil
}

func (c *client) getVaultRecordProperties(record keyhubmodels.VaultVaultRecordable, property string) (map[string][]byte, error) {
	data := make(map[string][]byte, 12)

	fetchAll := property == ""
	secret := record.GetAdditionalObjects().GetSecret()
	audit := record.GetAdditionalObjects().GetAudit()

	if property == "name" {
		data["name"] = []byte(*record.GetName())
	}
	if property == "color" {
		if record.GetColor() != nil {
			data["color"] = []byte(record.GetColor().String())
		} else {
			data["color"] = []byte("")
		}
	}
	if fetchAll || property == "link" {
		if record.GetUrl() != nil {
			data["link"] = []byte(*record.GetUrl())
		} else if !fetchAll {
			data["link"] = []byte("")
		}
	}
	if fetchAll || property == "username" {
		if record.GetUsername() != nil {
			data["username"] = []byte(*record.GetUsername())
		} else if !fetchAll {
			data["username"] = []byte("")
		}
	}
	if fetchAll || property == "password" {
		if secret.GetPassword() != nil {
			data["password"] = []byte(*secret.GetPassword())
		} else if !fetchAll {
			data["password"] = []byte("")
		}
	}
	if property == "filename" {
		if record.GetFilename() != nil {
			data["filename"] = []byte(*record.GetFilename())
		} else {
			data["filename"] = []byte("")
		}
	}
	if (fetchAll || property == "file") && secret.GetFile() != nil {
		value, err := base64.StdEncoding.DecodeString(*secret.GetFile())
		if err != nil {
			return nil, err
		}
		data["file"] = value
	}

	if (property == "enddate") && record.GetEndDate() != nil {
		data["enddate"] = []byte(record.GetEndDate().String())
	}
	if (property == "comment") && secret.GetComment() != nil {
		data["comment"] = []byte(*secret.GetComment())
	}
	if (property == "lastModifiedBy") && audit.GetLastModifiedBy() != nil {
		data["lastModifiedBy"] = []byte(*audit.GetLastModifiedBy())
	}
	if (property == "lastModifiedAt") && audit.GetLastModifiedAt() != nil {
		data["lastModifiedAt"] = []byte(audit.GetLastModifiedAt().UTC().Format(time.RFC3339))
	}
	if len(data) == 0 {
		return nil, fmt.Errorf(errInvalidProperty, property)
	}

	return data, nil
}
