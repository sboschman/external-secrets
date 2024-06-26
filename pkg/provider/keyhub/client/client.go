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
	"net/http"
	"time"

	keyhub "github.com/topicuskeyhub/sdk-go"
	keyhubreqi "github.com/topicuskeyhub/sdk-go/info"
	keyhubmodels "github.com/topicuskeyhub/sdk-go/models"
	keyhubreq "github.com/topicuskeyhub/sdk-go/vaultrecord"
	ctrl "sigs.k8s.io/controller-runtime"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
)

var logger = ctrl.Log.WithName("provider").WithName("keyhub")

type KeyHubClient struct {
	client *keyhub.KeyHubClient
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
	record, err := c.getVaultRecord(ctx, uuid, false)
	if err != nil {
		return nil, err
	}

	return record.GetAdditionalObjects().GetAudit().GetLastModifiedAt(), nil
}

func (c *KeyHubClient) GetVaultRecord(ctx context.Context, uuid string) (keyhubmodels.VaultVaultRecordable, error) {
	logger.V(1).Info("fetching vault record", "uuid", uuid)
	return c.getVaultRecord(ctx, uuid, true)
}

func (c *KeyHubClient) getVaultRecord(ctx context.Context, uuid string, fetchSecretData bool) (keyhubmodels.VaultVaultRecordable, error) {
	additionalParams := []keyhubreq.GetAdditionalQueryParameterType{
		keyhubreq.AUDIT_GETADDITIONALQUERYPARAMETERTYPE,
	}
	if fetchSecretData {
		additionalParams = append(additionalParams, keyhubreq.SECRET_GETADDITIONALQUERYPARAMETERTYPE)
	}

	wrapper, err := c.client.Vaultrecord().Get(ctx, &keyhubreq.VaultrecordRequestBuilderGetRequestConfiguration{
		QueryParameters: &keyhubreq.VaultrecordRequestBuilderGetQueryParameters{
			Uuid: []string{uuid},
			AdditionalAsGetAdditionalQueryParameterType: additionalParams,
		},
	})

	if err != nil || len(wrapper.GetItems()) == 0 {
		return nil, esv1beta1.NoSecretErr
	}

	return wrapper.GetItems()[0], nil
}
