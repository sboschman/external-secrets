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
	"errors"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/esutils"
	"github.com/external-secrets/external-secrets/pkg/provider/keyhub/util"
)

// ValidateStore validates the store.
func (p *Provider) ValidateStore(store esv1.GenericStore) (admission.Warnings, error) {
	storeSpec, err := util.GetKeyHubProvider(store)
	if err != nil {
		return nil, err
	}

	if storeSpec.Issuer == "" {
		return nil, errors.New("KeyHub issuer cannot be empty")
	}

	if err := esutils.ValidateSecretSelector(store, storeSpec.Auth.SecretRef); err != nil {
		return nil, fmt.Errorf("invalid store '%s': %w", store.GetName(), err)
	}

	return nil, nil
}
