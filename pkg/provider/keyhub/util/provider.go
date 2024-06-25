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

package util

import (
	"context"
	"fmt"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/external-secrets/external-secrets/pkg/utils/resolvers"
	kubeClient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	errNilStore         = "found nil store"
	errMissingStoreSpec = "store is missing spec"
	errMissingProvider  = "storeSpec is missing provider"
	errInvalidProvider  = "invalid provider spec. Missing KeyHub field in store %s"
)

// GetKeyHubProvider does the necessary nil checks on the generic store
// it returns the KeyHub provider config or an error.
func GetKeyHubProvider(store esv1beta1.GenericStore) (*esv1beta1.KeyHubProvider, error) {
	if store == nil {
		return nil, fmt.Errorf(errNilStore)
	}
	spec := store.GetSpec()
	if spec == nil {
		return nil, fmt.Errorf(errMissingStoreSpec)
	}
	if spec.Provider == nil {
		return nil, fmt.Errorf(errMissingProvider)
	}

	if spec.Provider.KeyHub == nil {
		return nil, fmt.Errorf(errMissingProvider)
	}

	prov := spec.Provider.KeyHub
	if prov == nil {
		return nil, fmt.Errorf(errInvalidProvider, store.GetObjectMeta().String())
	}
	return prov, nil
}

// GetKeyHubAuth retrieves the OIDC clientId and clientSecret from the K8S Secret ref.
func GetKeyHubAuth(ctx context.Context, auth esv1beta1.KeyHubAuth, kube kubeClient.Client, storeKind, namespace string) (string, string, error) {
	clientIDRef := auth.SecretRef.DeepCopy()
	clientIDRef.Key = "clientId"
	clientID, err := resolvers.SecretKeyRef(
		ctx,
		kube,
		storeKind,
		namespace,
		clientIDRef)
	if err != nil {
		return "", "", err
	}

	clientSecretRef := auth.SecretRef.DeepCopy()
	clientSecretRef.Key = "clientSecret"
	clientSecret, err := resolvers.SecretKeyRef(
		ctx,
		kube,
		storeKind,
		namespace,
		clientSecretRef)
	if err != nil {
		return "", "", err
	}

	return clientID, clientSecret, nil
}
