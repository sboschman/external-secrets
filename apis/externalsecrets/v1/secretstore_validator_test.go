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

package v1

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// ValidationProvider is a simple provider that we can use without cyclic import.
type ValidationProvider struct {
	Provider
}

func (v *ValidationProvider) ValidateStore(_ GenericStore) (admission.Warnings, error) {
	return nil, nil
}

func TestValidateSecretStore(t *testing.T) {
	tests := []struct {
		name        string
		obj         *SecretStore
		mock        func()
		assertWarns func(t *testing.T, warns admission.Warnings)
		assertErr   func(t *testing.T, err error)
	}{
		{
			name: "valid regex",
			obj: &SecretStore{
				Spec: SecretStoreSpec{
					Conditions: []ClusterSecretStoreCondition{
						{
							NamespaceRegexes: []string{`.*`},
						},
					},
					Provider: &SecretStoreProvider{
						AWS: &AWSProvider{},
					},
				},
			},
			mock: func() {
				ForceRegister(&ValidationProvider{}, &SecretStoreProvider{
					AWS: &AWSProvider{},
				}, MaintenanceStatusMaintained)
			},
			assertErr: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
			assertWarns: func(t *testing.T, warns admission.Warnings) {
				require.Equal(t, 0, len(warns))
			},
		},
		{
			name: "invalid regex",
			obj: &SecretStore{
				Spec: SecretStoreSpec{
					Conditions: []ClusterSecretStoreCondition{
						{
							NamespaceRegexes: []string{`\1`},
						},
					},
					Provider: &SecretStoreProvider{
						AWS: &AWSProvider{},
					},
				},
			},
			mock: func() {
				ForceRegister(&ValidationProvider{}, &SecretStoreProvider{
					AWS: &AWSProvider{},
				}, MaintenanceStatusMaintained)
			},
			assertErr: func(t *testing.T, err error) {
				assert.EqualError(t, err, "failed to compile 0th namespace regex in 0th condition: error parsing regexp: invalid escape sequence: `\\1`")
			},
			assertWarns: func(t *testing.T, warns admission.Warnings) {
				require.Equal(t, 0, len(warns))
			},
		},
		{
			name: "multiple errors",
			obj: &SecretStore{
				Spec: SecretStoreSpec{
					Conditions: []ClusterSecretStoreCondition{
						{
							NamespaceRegexes: []string{`\1`, `\2`},
						},
					},
					Provider: &SecretStoreProvider{
						AWS: &AWSProvider{},
					},
				},
			},
			assertWarns: func(t *testing.T, warns admission.Warnings) {
				require.Equal(t, 0, len(warns))
			},

			mock: func() {
				ForceRegister(&ValidationProvider{}, &SecretStoreProvider{
					AWS: &AWSProvider{},
				}, MaintenanceStatusMaintained)
			},
			assertErr: func(t *testing.T, err error) {
				assert.EqualError(t, err, "failed to compile 0th namespace regex in 0th condition: error parsing regexp: invalid escape sequence: `\\1`\nfailed to compile 1th namespace regex in 0th condition: error parsing regexp: invalid escape sequence: `\\2`")
			},
		},
		{
			name: "secret store must have only a single backend",
			obj: &SecretStore{
				Spec: SecretStoreSpec{
					Provider: &SecretStoreProvider{
						AWS:   &AWSProvider{},
						GCPSM: &GCPSMProvider{},
					},
				},
			},
			assertErr: func(t *testing.T, err error) {
				assert.EqualError(t, err, "store error for : secret stores must only have exactly one backend specified, found 2")
			},
			assertWarns: func(t *testing.T, warns admission.Warnings) {
				require.Equal(t, 0, len(warns))
			},
		},
		{
			name: "no registered store backend",
			obj: &SecretStore{
				Spec: SecretStoreSpec{
					Conditions: []ClusterSecretStoreCondition{
						{
							Namespaces: []string{"default"},
						},
					},
				},
			},
			assertErr: func(t *testing.T, err error) {
				assert.EqualError(t, err, "store error for : secret stores must only have exactly one backend specified, found 0")
			},
			assertWarns: func(t *testing.T, warns admission.Warnings) {
				require.Equal(t, 0, len(warns))
			},
		},
		{
			name: "unmaintained warning",
			obj: &SecretStore{
				Spec: SecretStoreSpec{
					Conditions: []ClusterSecretStoreCondition{
						{
							NamespaceRegexes: []string{`.*`},
						},
					},
					Provider: &SecretStoreProvider{
						AWS: &AWSProvider{},
					},
				},
			},
			mock: func() {
				ForceRegister(&ValidationProvider{}, &SecretStoreProvider{
					AWS: &AWSProvider{},
				}, MaintenanceStatusNotMaintained)
			},
			assertErr: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
			assertWarns: func(t *testing.T, warns admission.Warnings) {
				require.Equal(t, 1, len(warns))
				assert.Equal(t, warns[0], fmt.Sprintf(warnStoreUnmaintained, ""))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mock != nil {
				tt.mock()
			}

			warns, err := validateStore(tt.obj)
			tt.assertErr(t, err)
			tt.assertWarns(t, warns)
		})
	}
}
