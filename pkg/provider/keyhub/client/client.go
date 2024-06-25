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

package client

import (
	"context"
	"fmt"
	"net/http"
	"time"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	keyhub "github.com/topicuskeyhub/sdk-go"
	keyhubreqi "github.com/topicuskeyhub/sdk-go/info"
	keyhubmodels "github.com/topicuskeyhub/sdk-go/models"
	keyhubreq "github.com/topicuskeyhub/sdk-go/vaultrecord"
	ctrl "sigs.k8s.io/controller-runtime"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

var logger = ctrl.Log.WithName("provider").WithName("keyhub")

type KeyHubClient struct {
	client *keyhub.KeyHubClient
}

type VaultRecordFilter struct {
	UUID    string
	Name    *esv1.FindName
	Group   string
	Color   []string
	Type    []string
	IsValid *bool
}

func NewKeyHubClient(issuer, clientID, clientSecret string) (*KeyHubClient, error) {
	adapter, err := keyhub.NewKeyHubRequestAdapter(&http.Client{}, issuer, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	return &KeyHubClient{
		client: keyhub.NewKeyHubClient(adapter),
	}, nil
}

func (c *KeyHubClient) GetInfo(ctx context.Context) (keyhubmodels.SimpleVersionInfoable, error) {
	return c.client.Info().Get(ctx, &keyhubreqi.InfoRequestBuilderGetRequestConfiguration{})
}

func (c *KeyHubClient) GetVaultRecordLastModifiedAt(ctx context.Context, uuid string) (*time.Time, error) {
	logger.V(1).Info("fetching lastModifiedAt of vault record", "uuid", uuid)
	records, err := c.GetVaultRecordMetadata(ctx, VaultRecordFilter{UUID: uuid})
	if err != nil || len(records) == 0 {
		return nil, esv1.NoSecretErr
	}

	return records[0].GetAdditionalObjects().GetAudit().GetLastModifiedAt(), nil
}

func (c *KeyHubClient) GetVaultRecordMetadata(ctx context.Context, filter VaultRecordFilter) ([]keyhubmodels.VaultVaultRecordable, error) {
	queryParams := &keyhubreq.VaultrecordRequestBuilderGetQueryParameters{
		AdditionalAsGetAdditionalQueryParameterType: []keyhubreq.GetAdditionalQueryParameterType{
			keyhubreq.AUDIT_GETADDITIONALQUERYPARAMETERTYPE,
		},
	}

	if filter.UUID != "" {
		queryParams.Uuid = []string{filter.UUID}
	}
	if filter.Group != "" {
		queryParams.Q = []string{fmt.Sprintf("group.uuid='%s'", filter.Group)}
	}

	// 	queryParams.Q
	// 	q=group.uuid='xyz'
	// 	q=secret.type=''
	// 	queryParams.HasValidPolicy
	// 	queryParams.HasValidPolicy
	// 	queryParams.Secret

	result := make([]keyhubmodels.VaultVaultRecordable, 0, 20)
	err := c.iterateVaultRecords(ctx, queryParams, func(records []keyhubmodels.VaultVaultRecordable) {
		result = append(result, records...)
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *KeyHubClient) iterateVaultRecords(ctx context.Context, queryParams *keyhubreq.VaultrecordRequestBuilderGetQueryParameters, cb func(records []keyhubmodels.VaultVaultRecordable)) error {
	const batchSize = 100
	offset := 0
	headers := abstractions.NewRequestHeaders()
	var wrapper keyhubmodels.VaultVaultRecordLinkableWrapperable
	for ok := true; ok; ok = wrapper != nil && len(wrapper.GetItems()) < batchSize {
		headers.Add("Range", fmt.Sprintf("items=%d-%d", offset*batchSize, (offset*batchSize)+batchSize-1))
		wrapper, err := c.client.Vaultrecord().Get(ctx, &keyhubreq.VaultrecordRequestBuilderGetRequestConfiguration{
			Headers:         nil,
			QueryParameters: queryParams,
		})
		if err != nil {
			return err
		}

		cb(wrapper.GetItems())

		headers.Clear()
		offset++
	}
	return nil
}

func (c *KeyHubClient) GetVaultRecord(ctx context.Context, uuid string) (keyhubmodels.VaultVaultRecordable, error) {
	logger.V(1).Info("fetching vault record", "uuid", uuid)
	wrapper, err := c.client.Vaultrecord().Get(ctx, &keyhubreq.VaultrecordRequestBuilderGetRequestConfiguration{
		QueryParameters: &keyhubreq.VaultrecordRequestBuilderGetQueryParameters{
			Uuid: []string{uuid},
			AdditionalAsGetAdditionalQueryParameterType: []keyhubreq.GetAdditionalQueryParameterType{
				keyhubreq.AUDIT_GETADDITIONALQUERYPARAMETERTYPE,
				keyhubreq.SECRET_GETADDITIONALQUERYPARAMETERTYPE,
			},
		},
	})
	if err != nil || len(wrapper.GetItems()) == 0 {
		return nil, esv1.NoSecretErr
	}

	return wrapper.GetItems()[0], nil
}
