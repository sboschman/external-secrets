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
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/external-secrets/external-secrets/pkg/provider/keyhub/util"
	"github.com/external-secrets/external-secrets/pkg/utils"
)

// ValidateStore validates the store.
func (p *Provider) ValidateStore(store esv1beta1.GenericStore) (admission.Warnings, error) {
	storeSpec, err := util.GetKeyHubProvider(store)
	if err != nil {
		return nil, err
	}

	if storeSpec.Issuer == "" {
		return nil, fmt.Errorf("KeyHub issuer cannot be empty")
	}

	if err := utils.ValidateSecretSelector(store, storeSpec.Auth.SecretRef); err != nil {
		return nil, fmt.Errorf("invalid store '%s': %s", store.GetName(), err)
	}

	return nil, nil
}
