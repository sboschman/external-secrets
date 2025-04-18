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
	"context"
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type ExternalSecretValidator struct{}

func (esv *ExternalSecretValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	return validateExternalSecret(obj)
}

func (esv *ExternalSecretValidator) ValidateUpdate(_ context.Context, _, newObj runtime.Object) (admission.Warnings, error) {
	return validateExternalSecret(newObj)
}

func (esv *ExternalSecretValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

func validateExternalSecret(obj runtime.Object) (admission.Warnings, error) {
	es, ok := obj.(*ExternalSecret)
	if !ok {
		return nil, errors.New("unexpected type")
	}

	var errs error
	if err := validatePolicies(es); err != nil {
		errs = errors.Join(errs, err)
	}

	if len(es.Spec.Data) == 0 && len(es.Spec.DataFrom) == 0 {
		errs = errors.Join(errs, errors.New("either data or dataFrom should be specified"))
	}

	for _, ref := range es.Spec.DataFrom {
		if err := validateExtractFindGenerator(ref); err != nil {
			errs = errors.Join(errs, err)
		}

		if err := validateFindExtractSourceRef(ref); err != nil {
			errs = errors.Join(errs, err)
		}

		if err := validateSourceRef(ref); err != nil {
			errs = errors.Join(errs, err)
		}
	}

	errs = validateDuplicateKeys(es, errs)
	return nil, errs
}

func validateSourceRef(ref ExternalSecretDataFromRemoteRef) error {
	if ref.SourceRef != nil && ref.SourceRef.GeneratorRef == nil && ref.SourceRef.SecretStoreRef == nil {
		return errors.New("generatorRef or storeRef must be set when using sourceRef in dataFrom")
	}

	return nil
}

func validateFindExtractSourceRef(ref ExternalSecretDataFromRemoteRef) error {
	if ref.Find == nil && ref.Extract == nil && ref.SourceRef == nil {
		return errors.New("either extract, find, or sourceRef must be set to dataFrom")
	}

	return nil
}

func validateExtractFindGenerator(ref ExternalSecretDataFromRemoteRef) error {
	generatorRef := ref.SourceRef != nil && ref.SourceRef.GeneratorRef != nil
	if (ref.Find != nil && (ref.Extract != nil || generatorRef)) || (ref.Extract != nil && (ref.Find != nil || generatorRef)) || (generatorRef && (ref.Find != nil || ref.Extract != nil)) {
		return errors.New("extract, find, or generatorRef cannot be set at the same time")
	}

	return nil
}

func validatePolicies(es *ExternalSecret) error {
	var errs error
	if (es.Spec.Target.DeletionPolicy == DeletionPolicyDelete && es.Spec.Target.CreationPolicy == CreatePolicyMerge) ||
		(es.Spec.Target.DeletionPolicy == DeletionPolicyDelete && es.Spec.Target.CreationPolicy == CreatePolicyNone) {
		errs = errors.Join(errs, errors.New("deletionPolicy=Delete must not be used when the controller doesn't own the secret. Please set creationPolicy=Owner"))
	}

	if es.Spec.Target.DeletionPolicy == DeletionPolicyMerge && es.Spec.Target.CreationPolicy == CreatePolicyNone {
		errs = errors.Join(errs, errors.New("deletionPolicy=Merge must not be used with creationPolicy=None. There is no Secret to merge with"))
	}

	return errs
}

func validateDuplicateKeys(es *ExternalSecret, errs error) error {
	if es.Spec.Target.DeletionPolicy == DeletionPolicyRetain {
		seenKeys := make(map[string]struct{})
		for _, data := range es.Spec.Data {
			secretKey := data.SecretKey
			if _, exists := seenKeys[secretKey]; exists {
				errs = errors.Join(errs, fmt.Errorf("duplicate secretKey found: %s", secretKey))
			}
			seenKeys[secretKey] = struct{}{}
		}
	}
	return errs
}
