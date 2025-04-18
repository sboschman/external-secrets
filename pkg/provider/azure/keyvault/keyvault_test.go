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

package keyvault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/date"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	pointer "k8s.io/utils/ptr"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	v1 "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/external-secrets/external-secrets/pkg/provider/azure/keyvault/fake"
	testingfake "github.com/external-secrets/external-secrets/pkg/provider/testing/fake"
	"github.com/external-secrets/external-secrets/pkg/utils"
	"github.com/external-secrets/external-secrets/pkg/utils/metadata"
)

type secretManagerTestCase struct {
	mockClient              *fake.AzureMockClient
	secretName              string
	secretVersion           string
	serviceURL              string
	ref                     *esv1.ExternalSecretDataRemoteRef
	refFind                 *esv1.ExternalSecretFind
	apiErr                  error
	setErr                  error
	deleteErr               error
	pushData                esv1.PushSecretData
	secretOutput            keyvault.SecretBundle
	setSecretOutput         keyvault.SecretBundle
	keyOutput               keyvault.KeyBundle
	createKeyOutput         keyvault.KeyBundle
	certOutput              keyvault.CertificateBundle
	importOutput            keyvault.CertificateBundle
	listOutput              keyvault.SecretListResultIterator
	deleteKeyOutput         keyvault.DeletedKeyBundle
	deleteCertificateOutput keyvault.DeletedCertificateBundle
	deleteSecretOutput      keyvault.DeletedSecretBundle

	expectError    string
	setValue       []byte
	expectedSecret string
	// for testing secretmap
	expectedData      map[string][]byte
	expectedExistence bool
	// for testing pushing multi-key k8s secrets
	secret *corev1.Secret
	// for testing changes in expiration date for akv secrets
	newExpiry *date.UnixTime
}

func makeValidSecretManagerTestCase() *secretManagerTestCase {
	secretString := "Hello World!"
	smtc := secretManagerTestCase{
		mockClient:     &fake.AzureMockClient{},
		secretName:     "MySecret",
		secretVersion:  "",
		ref:            makeValidRef(),
		refFind:        makeValidFind(),
		secretOutput:   keyvault.SecretBundle{Value: &secretString},
		serviceURL:     "",
		apiErr:         nil,
		expectError:    "",
		expectedSecret: secretString,
		expectedData:   map[string][]byte{},
	}

	smtc.mockClient.WithValue(smtc.serviceURL, smtc.secretName, smtc.secretVersion, smtc.secretOutput, smtc.apiErr)

	return &smtc
}

func makeValidSecretManagerTestCaseCustom(tweaks ...func(smtc *secretManagerTestCase)) *secretManagerTestCase {
	smtc := makeValidSecretManagerTestCase()
	for _, fn := range tweaks {
		fn(smtc)
	}

	smtc.mockClient.WithValue(smtc.serviceURL, smtc.secretName, smtc.secretVersion, smtc.secretOutput, smtc.apiErr)
	smtc.mockClient.WithKey(smtc.serviceURL, smtc.secretName, smtc.secretVersion, smtc.keyOutput, smtc.apiErr)
	smtc.mockClient.WithCertificate(smtc.serviceURL, smtc.secretName, smtc.secretVersion, smtc.certOutput, smtc.apiErr)
	smtc.mockClient.WithList(smtc.serviceURL, smtc.listOutput, smtc.apiErr)
	smtc.mockClient.WithImportCertificate(smtc.importOutput, smtc.setErr)
	smtc.mockClient.WithImportKey(smtc.createKeyOutput, smtc.setErr)
	smtc.mockClient.WithSetSecret(smtc.setSecretOutput, smtc.setErr)
	smtc.mockClient.WithDeleteCertificate(smtc.deleteCertificateOutput, smtc.deleteErr)
	smtc.mockClient.WithDeleteKey(smtc.deleteKeyOutput, smtc.deleteErr)
	smtc.mockClient.WithDeleteSecret(smtc.deleteSecretOutput, smtc.deleteErr)
	return smtc
}

const (
	jwkPubRSA            = `{"kid":"ex","kty":"RSA","key_ops":["sign","verify","wrapKey","unwrapKey","encrypt","decrypt"],"n":"p2VQo8qCfWAZmdWBVaYuYb-a-tWWm78K6Sr9poCvNcmv8rUPSLACxitQWR8gZaSH1DklVkqz-Ed8Cdlf8lkDg4Ex5tkB64jRdC1Uvn4CDpOH6cp-N2s8hTFLqy9_YaDmyQS7HiqthOi9oVjil1VMeWfaAbClGtFt6UnKD0Vb_DvLoWYQSqlhgBArFJi966b4E1pOq5Ad02K8pHBDThlIIx7unibLehhDU6q3DCwNH_OOLx6bgNtmvGYJDd1cywpkLQ3YzNCUPWnfMBJRP3iQP_WI21uP6cvo0DqBPBM4wvVzHbCT0vnIflwkbgEWkq1FprqAitZlop9KjLqzjp9vyQ","e":"AQAB"}`
	jwkPubEC             = `{"kid":"https://example.vault.azure.net/keys/ec-p-521/e3d0e9c179b54988860c69c6ae172c65","kty":"EC","key_ops":["sign","verify"],"crv":"P-521","x":"AedOAtb7H7Oz1C_cPKI_R4CN_eai5nteY6KFW07FOoaqgQfVCSkQDK22fCOiMT_28c8LZYJRsiIFz_IIbQUW7bXj","y":"AOnchHnmBphIWXvanmMAmcCDkaED6ycW8GsAl9fQ43BMVZTqcTkJYn6vGnhn7MObizmkNSmgZYTwG-vZkIg03HHs"}`
	jsonTestString       = `{"Name": "External", "LastName": "Secret", "Address": { "Street": "Myroad st.", "CP": "J4K4T4" } }`
	jsonSingleTestString = `{"Name": "External", "LastName": "Secret" }`
	jsonTagTestString    = `{"tagname":"tagvalue","tagname2":"tagvalue2"}`
	keyName              = "key/keyname"
	certName             = "cert/certname"
	secretString         = "changedvalue"
	unexpectedError      = "[%d] unexpected error: %s, expected: '%s'"
	unexpectedSecretData = "[%d] unexpected secret data: expected %#v, got %#v"
	errorNoTag           = "tag something does not exist"
	errNotManaged        = "not managed by external-secrets"
	errNoPermission      = "No Permissions"
	errAPI               = "unexpected api error"
	something            = "something"
	tagname              = "tagname"
	tagname2             = "tagname2"
	tagvalue             = "tagvalue"
	tagvalue2            = "tagvalue2"
	secretName           = "example-1"
	testsecret           = "test-secret"
	fakeURL              = "noop"
	foo                  = "foo"
	bar                  = "bar"
	errStore             = "Azure.ValidateStore() error = %v, wantErr %v"
	externalSecrets      = "external-secrets"
	notFoundMessage      = "Not Found"
	forbiddenMessage     = "Forbidden"
)

func getTagMap() map[string]*string {
	tag1 := "tagname"
	tag2 := "tagname2"
	value1 := "tagvalue"
	value2 := "tagvalue2"
	tagMap := make(map[string]*string)
	tagMap[tag1] = &value1
	tagMap[tag2] = &value2
	return tagMap
}

func newKVJWK(b []byte) *keyvault.JSONWebKey {
	var key keyvault.JSONWebKey
	err := json.Unmarshal(b, &key)
	if err != nil {
		panic(err)
	}
	return &key
}

func TestAzureKeyVaultDeleteSecret(t *testing.T) {
	unsupportedType := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: "yadayada/foo",
		}
		smtc.expectError = "secret type 'yadayada' is not supported"
	}

	secretSuccess := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: secretName,
		}
		smtc.secretOutput = keyvault.SecretBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
			Value: pointer.To("foo"),
		}
		smtc.deleteSecretOutput = keyvault.DeletedSecretBundle{}
	}

	secretNotFound := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: secretName,
		}
		smtc.apiErr = autorest.DetailedError{StatusCode: 404, Method: "GET", Message: notFoundMessage}
		smtc.deleteErr = autorest.DetailedError{StatusCode: 404, Method: "DELETE", Message: notFoundMessage}
	}

	secretNotManaged := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: secretName,
		}
		smtc.secretOutput = keyvault.SecretBundle{
			Value: pointer.To("foo"),
		}
		smtc.expectError = errNotManaged
		smtc.deleteErr = autorest.DetailedError{StatusCode: 500, Method: "DELETE", Message: "Shouldnt happen"}
	}

	secretUnexpectedError := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: secretName,
		}
		smtc.expectError = "boom"
		smtc.apiErr = errors.New("boom")
	}

	secretNoDeletePermissions := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: secretName,
		}
		smtc.secretOutput = keyvault.SecretBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
			Value: pointer.To("foo"),
		}
		smtc.expectError = errNoPermission
		smtc.deleteErr = autorest.DetailedError{StatusCode: 403, Method: "DELETE", Message: errNoPermission}
	}

	secretNoGetPermissions := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: secretName,
		}
		smtc.expectError = errNoPermission
		smtc.apiErr = autorest.DetailedError{StatusCode: 403, Method: "GET", Message: errNoPermission}
	}

	certificateSuccess := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: certName,
		}
		smtc.certOutput = keyvault.CertificateBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
		}
		smtc.deleteCertificateOutput = keyvault.DeletedCertificateBundle{}
	}
	certNotFound := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: certName,
		}
		smtc.apiErr = autorest.DetailedError{StatusCode: 404, Method: "GET", Message: "Certificate Not Found"}
		smtc.deleteErr = autorest.DetailedError{StatusCode: 404, Method: "DELETE", Message: notFoundMessage}
	}

	certNotManaged := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: certName,
		}
		smtc.certOutput = keyvault.CertificateBundle{}
		smtc.expectError = errNotManaged
		smtc.deleteErr = autorest.DetailedError{StatusCode: 500, Method: "DELETE", Message: "Shouldnt happen"}
	}

	certUnexpectedError := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: certName,
		}
		smtc.expectError = "crash"
		smtc.apiErr = errors.New("crash")
	}

	certNoDeletePermissions := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: certName,
		}
		smtc.certOutput = keyvault.CertificateBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
		}
		smtc.expectError = "No certificate delete Permissions"
		smtc.deleteErr = autorest.DetailedError{StatusCode: 403, Method: "DELETE", Message: "No certificate delete Permissions"}
	}

	certNoGetPermissions := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: certName,
		}
		smtc.expectError = "No certificate get Permissions"
		smtc.apiErr = autorest.DetailedError{StatusCode: 403, Method: "GET", Message: "No certificate get Permissions"}
	}

	keySuccess := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: keyName,
		}
		smtc.keyOutput = keyvault.KeyBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
		}
		smtc.deleteKeyOutput = keyvault.DeletedKeyBundle{}
	}
	keyNotFound := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: keyName,
		}
		smtc.apiErr = autorest.DetailedError{StatusCode: 404, Method: "GET", Message: notFoundMessage}
		smtc.deleteErr = autorest.DetailedError{StatusCode: 404, Method: "DELETE", Message: notFoundMessage}
	}

	keyNotManaged := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: keyName,
		}
		smtc.keyOutput = keyvault.KeyBundle{}
		smtc.expectError = errNotManaged
		smtc.deleteErr = autorest.DetailedError{StatusCode: 500, Method: "DELETE", Message: "Shouldnt happen"}
	}

	keyUnexpectedError := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: keyName,
		}
		smtc.expectError = "tls timeout"
		smtc.apiErr = errors.New("tls timeout")
	}

	keyNoDeletePermissions := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: keyName,
		}
		smtc.keyOutput = keyvault.KeyBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
		}
		smtc.expectError = errNoPermission
		smtc.deleteErr = autorest.DetailedError{StatusCode: 403, Method: "DELETE", Message: errNoPermission}
	}

	keyNoGetPermissions := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: keyName,
		}
		smtc.expectError = errNoPermission
		smtc.apiErr = autorest.DetailedError{StatusCode: 403, Method: "GET", Message: errNoPermission}
	}

	successCases := []*secretManagerTestCase{
		makeValidSecretManagerTestCaseCustom(unsupportedType),
		makeValidSecretManagerTestCaseCustom(secretSuccess),
		makeValidSecretManagerTestCaseCustom(secretNotFound),
		makeValidSecretManagerTestCaseCustom(secretNotManaged),
		makeValidSecretManagerTestCaseCustom(secretUnexpectedError),
		makeValidSecretManagerTestCaseCustom(secretNoDeletePermissions),
		makeValidSecretManagerTestCaseCustom(secretNoGetPermissions),
		makeValidSecretManagerTestCaseCustom(certificateSuccess),
		makeValidSecretManagerTestCaseCustom(certNotFound),
		makeValidSecretManagerTestCaseCustom(certNotManaged),
		makeValidSecretManagerTestCaseCustom(certUnexpectedError),
		makeValidSecretManagerTestCaseCustom(certNoDeletePermissions),
		makeValidSecretManagerTestCaseCustom(certNoGetPermissions),
		makeValidSecretManagerTestCaseCustom(keySuccess),
		makeValidSecretManagerTestCaseCustom(keyNotFound),
		makeValidSecretManagerTestCaseCustom(keyNotManaged),
		makeValidSecretManagerTestCaseCustom(keyUnexpectedError),
		makeValidSecretManagerTestCaseCustom(keyNoDeletePermissions),
		makeValidSecretManagerTestCaseCustom(keyNoGetPermissions),
	}

	sm := Azure{
		provider: &esv1.AzureKVProvider{VaultURL: pointer.To(fakeURL)},
	}
	for k, v := range successCases {
		sm.baseClient = v.mockClient
		err := sm.DeleteSecret(context.Background(), v.pushData)
		if !utils.ErrorContains(err, v.expectError) {
			if err == nil {
				t.Errorf("[%d] unexpected error: <nil>, expected: '%s'", k, v.expectError)
			} else {
				t.Errorf("[%d] unexpected error: '%s', expected: '%s'", k, err.Error(), v.expectError)
			}
		}
	}
}
func TestAzureKeyVaultPushSecret(t *testing.T) {
	p12Cert, _ := base64.StdEncoding.DecodeString("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")
	p12CertChainLegacy, _ := base64.StdEncoding.DecodeString("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")
	p12CertChainModern, _ := base64.StdEncoding.DecodeString("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")
	goodKey, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUpRZ0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQ1N3d2dna29BZ0VBQW9JQ0FRQ1pITzRvNkpteU9aZGYKQXQ3RFdqR2tHdzdENVVIU1BHZXQyTjg2cnBGWXcrZThnL3dSeDBnZDBzRk9pelBBREdjcnpmdWE5Z3ZFcDRWcwpXb2FHbmN3UXhqdnMrZ1orWmQ2UkVPNHRLNzRURmYxaWZibmowUHE2OENlQlFpaG8xbDNwM2UwQy8yemVJMjNiCnZWRHZlMm13VXE5aDY4UTFFUmdWMU1LaWJHU1Naak5DQzdkRGFQWmpKazViMFlWVFdxREViemREVnh2ZVVMNVIKcUZnL0RKQTMzVnE2VFQzQ2U5RjBIcEorb3graSs4cUxmWU5qZExSUDZlbEtLTU5naVhhNTFvdnQ5MjF4UkVGdgpYRXYvTUtqWTlhNkppNndIRSs0NmdvbFY4V2puK2xMRkRKVHh6WEFEN2p2NzVzaHY0WEczdFlaQ2J4cTMzZ2JtCm96c0VQZ3lTRGtCMm5zc0tIUEFhSVNPaWpjNDhiSXhwbDVocFJPWUZFblJDWnhablhQNjdLZVF1VWZXQkpoVWcKYWltc0JRK3p6cFB6ZjVUbjRnVExkWll2NU41V1V2djJJdUF5Qktha0ZhR1ZYTzFpZ2FDeVQvUTNBcEE2ZGx4Sgo1VW44SzY4dS9KSGFmWWZ5engwVnVoZk5zbmtiWkxWSEZsR2Rxd3JrU0tCWSs1eS9WWlpkeC9hSHNWWndVN3ZECmNlaGxlWlFNNGV2cm5tMUY3dk5xSHBUK3BHSnpNVWVUNGZMVFpabTBra1Y3ZXl5RGRMMDFEWXRXQk1TM2NEb1EKdU5vWElBMCtDeFZPOHcxcC9wbXF2UFQ3cmpad2pwYkVMUkp3MWs4R3ozU2FKb2VqaFBzWC9xNzNGWWdBc09PRApwTXJuK3ZpU2U0ZnJmR0VmZlEvYXJUVE5qK1BUb3dJREFRQUJBb0lDQUM3ek1CUmJQc1huNHdLL1hvK0ltTEE1Cm04MTEvemo0VE5LQ0xmRlFsa0VoMFcxOUMwNW9UVFRYNjI2cVFMUWpHWC9WS2RIYW9NRXNuVDBjaFNQQ1AxRGwKZUhxeU1FdVI4UzJLZzM1V2EzSnV5OFBueVppUi9GQldVOGJQQXBVakpxa1A1QjJITlZyb2drZGZSZklwWmI4cgptNXZyTDc4Vi9zeXk4UHZkUVBtalhSUmpnMDZvWU9VR1dnRE52cFJRdGZ1R0h1d0hTZ1JodmZwTUpNTXdsd2lLClY4Zkk1NmM3VUg3SzRTRHo1RCtWOWdYUDl2b0lUMEl4OTlkRnFLTnhnM1o0MDIrazcycE1BOFNpQ0t1M3dBN0gKUnozbUZsb1ZRbmV1ajI1TEdHQUo0bGVLQkNJaFhMZlgxWXpvdDQyWEU4ZkJZZW45SjdRNTRPUFlLY0NqUmpjSgp1M2NkamtIbmFWVFc1dDdLTDFuYVAxRmF0S0ZxSjY1V1Y0c3pxWDhPVkpzbWhLalNsNUhqTk1VeERuaFUraWRTCmsxaGNaa00zOWd2RGR1ekRHeHF0L2hHMWNJS3VtamxZb01WNDV4VWFoVHdhTjZnamlrTUxNdFgrb2c0MVAxU3cKa09hZTZ4enJFQmU1eXhqSnVDWFJzK2FFOXZhTmpIWmpnSTNKREJ0enNjeCtvRFZBMXoxWVBpR2t1NXBNYmxYUQpFMWlRQnlJOVRjeHMrazN0NWdIQ0d3Z2lOcXVnOVZJaXY1cTQ2R2VGRVdnQS8wZ2hEZ0hIRnNRSDJ4VEpGU2d6ClluTkRVNlZtQ1RYZEQ0QU5jS085Z0loQzdxYk9iazlUeS9zZkZIQjBrYUdCVjFFZGZ3a0R4LytYdXRacHNUN3IKdkl6SUVDd2JPTEUzZCtLb1grUUJBb0lCQVFESG9SVU42U1VmQ3I4Z2FsOFM3UDhscU1kZnhsQVNRcWRqOHY2WAp3V1o1MFJKVE9TRmxqN3dlb2FnTStDT3pEUHpoU3pMbE4vcVdnK2h1RFJGcXBWb08xTmlrZVdvZEVwajFyZG5qCmlLeFlEVUJKNjFCMk5GT3R6Qm9CZUgyOFpDR3dRUW93clZSNUh5dUlqOTRhTzBiRlNUWEJTdWx2d3NQeDZhR2cKaTV2Q0VITHB6ODZKV1BzcjYwSmxVSDk2Z2U3NXJNZEFuRTJ1UE5JVlRnR2grMHpOenZ2a21yZHRYRVR4QXpFZwo5d0RaNVFZTUNYTGVjV0RxaWtmQUpoaUFJTjdVWEtvajN0b1ZMMzh6Sm95WmNWT3ZLaVRIQXY1MCtyNGhVTzhiCjJmL1J2VllKMngybnJuSVR4L0s2Y2N3UUttb1dFNmJRdmg4SXJGTEI3aWN2cVJzUEFvSUJBUURFV1VGemRyRHgKN2w4VGg2bVV5ZlBIWWtOUU0vdDBqM3l3RDROQ2JuSlEvZGd2OGNqMVhGWTNkOWptdWZreGtrQ01WVC8rcVNrOQp1cm1JVVJDeGo5ZDJZcUtMYXZVcUVFWCtNVStIZ0VDOW4yTHluN0xXdVNyK2dFWVdkNllXUVNSVXpoS0xaN2RUCnliTnhmcnNtczNFSVJEZTkwcFV4ZGJ0eWpJSTlZd1NaRDdMUHVOQmc1cWNaTW1xWG9vSnQxdnJld1JINncwam8KM1pxTWMrVGFtNGxYc0xmU0pqTlAzd2IzZEE0ZDFvWWFIb29WWTVyK0dER1F5YnVKYllQZSt6d01NTkJhZ2dTVQpCL3J5NlBldVBTWVJnby9kTlR2TERDamJjbytXdFpncjRJaWxCVmpCbmwycEhzakVHYjZDV2Q2bXZCdlk3SWM5ClM3cXJLUGQrWE00dEFvSUJBR08wRkN2cWNkdmJKakl1Ym1XcGNKV0NnbkZYUHM2Zjg3Sjd2cVJVdDdYSHNmdFcKNFZNMFFxU1o0TEQ1amZyelZhbkFRUjh5b2psaWtFZkd4eGdZbGE0cXFEa2RXdDVDVjVyOHhZSmExSmoxcFZKRgo4TjNZcktKMCtkZ2FNZEpSd0hHalNrK2RnajhzVGpYYWhQZGMrNisxTE4vcFprV25aTzRCM2ZPdFJwSGFYVXBoCnU2bmxneTBnUnYwTEEyQlFYT2JlWUhYb212T1c5T1luRzdHbkxXanRJK205VERlV2llaEZ5OWZIQmVuTjlRTTIKQk9VTWczY2dzVTFLdVpuazBPWUhrZ0p3WDBPTmdWNHV0ckk4WTZ0c3hRbVFlVDQ3clpJK05lNFhKeW0rQXFiUgpoVEltY2x0bTFkaEExY2FOS0liMk1hNjRCZy95NFRKeW02ZTJNZ2tDZ2dFQkFKTGt5NmljVllqSjh1dGpoU1ZCCmFWWHpWN1M3RHhhRytwdWxIMmdseFBSKzFLd1owV1J1N2ptVk9mcHppOURnUDlZOU9TRkdZUXBEbGVZNzc2ZEgKbThSL3ltZFBYNWRXa1dhNGNXMUlNQ2N0QlJQTEVqcStVVUlScVYzSnFjSGdmbFBMeitmbmNpb0hMbTVzaDR0TwpsL085Ulk2SDZ3SVR1R2JjWTl1VkpxMTBKeXhzY2NqdEJubzlVNjJaOE1aSUhXdGxPaFJHNFZjRjQwZk10Snd2CjNMSjBEVEgxVGxJazRzdGlVZVZVeHdMbmNocktaL3hORVZmbTlKeStCL2hjTVBKVjJxcTd0cjBnczBmanJ0ajEKK25NRElLbzMxMEh6R09ZRWNSUXBTMjBZRUdLVSsyL3ZFTmNqcHNPL0Z0M2lha2FIV0xZVFRxSTI4N0oxZGFOZAp2d2tDZ2dFQUNqWTJIc0ErSlQvWlU1Q0k1NlFRNmlMTkdJeFNUYkxUMGJNbGNWTDJraGFFNTRMVGtld0I5enFTCk5xNVFacUhxbGk2anZiKzM4Q1FPUWxPWmd6clVtZlhIemNWQ1FwMUk1RjRmSGkyWUVVa3FJL2dWdlVGMUxCNUUKZE1KR1FZa3Jick83Qjc0eE50RUV3Mmh3UFUwcTRmby92eFZXV0pFdTNoMGpSL0llMDA3UGtPZ0p1K1R5ZWZBNwpQVkM4OFlQbmsyZ3ArUFpRdDljanhOL0V4enRweDZ4cUJzT0MvQWZIYU5BdFA0azM5MVc5NjN3eHVwbUE5SkdiCk4yM0NCRmVIZDJmTUViTWJuWDk1Q1NYNjNJVWNaNVRhZTdwQS9OZ094YkdzaGRSMHdFZldTMGNyT1VTdGt6aE0KT3lCekNZSk53d3Bld3cyOFpIMGgybHh6VVRHWStRPT0KLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=")
	goodSecret := "old"
	secretKey := "fakeSecretKey"
	tagKey := "fakeTagKey"
	tagValue := "fakeTagValue"
	mdataWithTag := &metadata.PushSecretMetadata[PushSecretMetadataSpec]{
		APIVersion: metadata.APIVersion,
		Kind:       metadata.Kind,
		Spec: PushSecretMetadataSpec{
			Tags: map[string]string{
				tagKey: tagValue,
			},
		},
	}
	mdataWithTagRaw, _ := yaml.Marshal(mdataWithTag)
	typeNotSupported := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: "badtype/secret",
		}
		smtc.expectError = "secret type badtype not supported"
	}
	secretSuccess := func(smtc *secretManagerTestCase) {
		smtc.setValue = []byte("secret")
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: secretName,
		}
		smtc.secretOutput = keyvault.SecretBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
			Value: &goodSecret,
		}
	}
	secretNoChange := func(smtc *secretManagerTestCase) {
		smtc.setValue = []byte(goodSecret)
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: secretName,
		}
		smtc.secretOutput = keyvault.SecretBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
			Value: &goodSecret,
		}
	}
	secretExpiryChange := func(smtc *secretManagerTestCase) {
		newExpiry := date.UnixTime(time.Now().Add(24 * time.Hour))
		oldExpiry := date.UnixTime(time.Now().Add(-1 * time.Hour))
		mdata := &metadata.PushSecretMetadata[PushSecretMetadataSpec]{
			APIVersion: metadata.APIVersion,
			Kind:       metadata.Kind,
			Spec: PushSecretMetadataSpec{
				ExpirationDate: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			},
		}
		metadataRaw, _ := yaml.Marshal(mdata)
		smtc.newExpiry = &newExpiry
		smtc.setValue = []byte(goodSecret)
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: secretName,
			Metadata: &apiextensionsv1.JSON{
				Raw: metadataRaw,
			},
		}
		smtc.secretOutput = keyvault.SecretBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
			Value: &goodSecret,
			Attributes: &keyvault.SecretAttributes{
				Expires: &oldExpiry,
			},
		}
		smtc.setSecretOutput = keyvault.SecretBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
			Value: &goodSecret,
			Attributes: &keyvault.SecretAttributes{
				Expires: smtc.newExpiry,
			},
		}
	}
	secretWrongTags := func(smtc *secretManagerTestCase) {
		smtc.setValue = []byte(goodSecret)
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: secretName,
		}
		smtc.secretOutput = keyvault.SecretBundle{
			Tags: map[string]*string{
				managedBy: pointer.To("nope"),
			},
			Value: &goodSecret,
		}
		smtc.expectError = errNotManaged
	}
	secretWithTags := func(smtc *secretManagerTestCase) {
		smtc.setValue = []byte(goodSecret)
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: secretName,
			Metadata: &apiextensionsv1.JSON{
				Raw: mdataWithTagRaw,
			},
		}
		smtc.secretOutput = keyvault.SecretBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
				tagKey:    pointer.To(tagValue),
			},
			Value: &goodSecret,
		}
	}
	wholeSecretNoKey := func(smtc *secretManagerTestCase) {
		wholeSecretMap := map[string][]byte{"key1": []byte(`value1`), "key2": []byte(`value2`)}
		wholeSecretString := `{"key1": "value1", "key2": "value2" }`
		wholeSecret := &corev1.Secret{Data: wholeSecretMap}
		smtc.secret = wholeSecret
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: secretName,
		}
		smtc.secretOutput = keyvault.SecretBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
			Value: &wholeSecretString,
		}

		smtc.expectedData = wholeSecretMap
	}

	secretNoTags := func(smtc *secretManagerTestCase) {
		smtc.setValue = []byte(goodSecret)
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: secretName,
		}
		smtc.secretOutput = keyvault.SecretBundle{
			Tags:  map[string]*string{},
			Value: &goodSecret,
		}
		smtc.expectError = errNotManaged
	}
	secretNotFound := func(smtc *secretManagerTestCase) {
		smtc.setValue = []byte(goodSecret)
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: secretName,
		}
		smtc.apiErr = autorest.DetailedError{StatusCode: 404, Method: "GET", Message: notFoundMessage}
	}
	failedGetSecret := func(smtc *secretManagerTestCase) {
		smtc.setValue = []byte(goodSecret)
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: secretName,
		}
		smtc.apiErr = autorest.DetailedError{StatusCode: 403, Method: "GET", Message: forbiddenMessage}
		smtc.expectError = errAPI
	}
	failedNotParseableError := func(smtc *secretManagerTestCase) {
		smtc.setValue = []byte(goodSecret)
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: secretName,
		}
		smtc.apiErr = errors.New("crash")
		smtc.expectError = "crash"
	}
	failedSetSecret := func(smtc *secretManagerTestCase) {
		smtc.setValue = []byte(goodSecret)
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: secretName,
		}
		smtc.apiErr = autorest.DetailedError{StatusCode: 404, Method: "GET", Message: notFoundMessage}
		smtc.setErr = autorest.DetailedError{StatusCode: 403, Method: "POST", Message: forbiddenMessage}
		smtc.expectError = "could not set secret example-1: #POST: Forbidden: StatusCode=403"
	}
	keySuccess := func(smtc *secretManagerTestCase) {
		smtc.setValue = goodKey
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: keyName,
		}
		smtc.keyOutput = keyvault.KeyBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(managerLabel),
			},
			Key: &keyvault.JSONWebKey{},
		}
	}
	symmetricKeySuccess := func(smtc *secretManagerTestCase) {
		smtc.setValue = []byte("secret")
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: keyName,
		}
		smtc.keyOutput = keyvault.KeyBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(managerLabel),
			},
			Key: &keyvault.JSONWebKey{},
		}
	}
	RSAKeySuccess := func(smtc *secretManagerTestCase) {
		smtc.setValue, _ = base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlKS1FJQkFBS0NBZ0VBdmIxYjM2YlpyaFNFYm5YWGtRL1pjR3VLY05HMDBGa2U1SkVOaWU4UzFHTG1uK1N0CndmdittVFRUN2xyVkdpVkplV3ZhQnRkMUVLRll0aWdlVlhJQjA0MllzeHRmMlM5WkNzNlUxaFZDWFZQc3BobEUKOUVyOHNHa0Ewa1lKdmxWejR2eFA2NTNzNjFGYTBpclRvUGlJTFZwMU1jdGRxVnB0VnJFV1JadzQ2NEF4MzhNNgpCMjFvN2NaUmlZN3VGZTA4UEllbEd3VGc0cHJRdEg2VXVuK09BV3MrNFNDTU5xT2xDRkNzSDBLK0NZZUMyZmpXClplaURsbjBTUDdkZ3puMmJsbk9VQzZ0Z3VtQ3grdW1ISVdmV1hzUDVQR0hoWFBwYlpGbDA4ZktaelNqbytCOWkKVzVsbWhrRE1HM0dsU0JPMmEvcEtjck1uTFVWbE15OVdWLy9LUmw3ZWFtdmJ5dWFzSnZHbVJ4L3d1NXlpYVhwSwprZG4xL0E2VFhBRnVvbU4xb3NvaGVyMjR2MHZ0YzBGZmxJM3h4WVpVTXIwazhLV0VlM1Nhdk83NkdrZTJhbEppCnVtZ20wTmhtK2pqNmlXajl1V1ZzV215MmFDMHc0aTRDS1d2YU56K0NDek5kWk8vcFpPTmlmTzVSSUZpZ2RzTVgKUHgvWU5nSkVKdmEyUVZ2MU9kcWZTdW1CMS8zRldFYmg5V2tFYXRGOElJRDI5TS9qVktiRm9BaktYeVZhUTI5eQpOOFRWR3Axc2pzOW5sSWdjN0JRUFhBZTVPQUExdnc5SWV4N09QZjhPZENBbDluQzlEaDdaK3MyV2lOVlRxb2dwCk1VbE1GUWxGVXpMWGVCUmp0ay9rL3lWT20yWkhBT2RuR1k4bSthRWlTV0ExYXhpa0RYMG9HWjhjbHFzQ0F3RUEKQVFLQ0FnRUFwZDZBRG9pQ0M1aU1IVFNQZXBUc2RVYk9BOHFQMHdQVjZlS1VmMXlzalZiWVhqYy9Yekc0Wko2MgpGc3o1TnA0YUdUZWJwaGQ4azBrNWtDU0tRQkFtWUphTVF5ZFBKMElwQ1RXSEQ1QU9NQ0JKNVBwNk9VWEVtVU55CklHQng3QjR2N09LOXl6Q0lDVDlac2hrV1lNWmo1YUlLaWJsSzY5M05iOWZuckhyaGw1NjkrdXRrTTFJR1JMYjIKV05iR2RBeXNlQTNzM0Mzcm1xM1VmYldhdDE4QytXS1QyYUxtY0cybXZCb3FIam51Zjg0aktnSkxDMU8wbFQ1SgpVY0l4c3RKRHpjYkVTVjlNZENKTDlSbHB0RjVlSFFJZFJCZ2ROM2IxcGtnOTM3VkJsd1NJaFVDS2I2RXU2M2FCCitBdmxmWmtlQkU4Ti9pOTN0Qy9TUkdqQmhyUnFVcEVOOVYrOHBJczVxTE5keC9RanF4TEpMMUtwMXQ0L0hVTkEKOVVTZVNrVDZTZ09OZ1NnQktCemFCYzUyTXRoWWYrZDk2YTJkN0N0dCt1amJBT0JKTkdKMytGenJoc3pzUTMzWQpkalBWTGQxSzBQSHZ0WDNrSWRKbFNWSmYxS3d5bDVKVm1Cck1wb2ZDQ2dsNnhyR0puYVJPb1A3bDZNb1BFZ21hClNRWWFIQVIvVGIzM2lBeTNLdlBuUkNMQlM2MEJCYitIcVd3c0RhczM0Uk9WUE05bUI2ZldkTUo0TG5kZmVpZm0KTGZ3Sy9GMXpRdFRaczNpYUYyMGEvY0EvdjRENWJCUldYSEQvTDA3Mks5TGxoMGNRRFVZY1V1ZUdwRWUycEZHRApxa1pCL08wSXNBOXAyTnNCekdvRWl1eHJwd0JBaXpiOUdCcU9DZUlGS1hKeU5heGU3YUVDZ2dFQkFOeG9zQ2cyCngwTWQzajRtWVhvWVpMMVBOUklwNlpuN2VLbThzK0tIRFdMUTlXWmtFbUwyODNXNzJFd2dDbmc2VjdsUHVYVlEKVTJXR0xjNDNvUU95U3JlNEZXbnZhTVhnWk42Wis2T0wvQ1J2VHZSbFhVNXJlYVNCT2tyZUJYK1g2dFo2Q1dORgpLWjkxTERvVVR5TlJVTTFUL3lwbS85SlE4MTJ1VUxnYUlQZGl5cCtPYmRoZWdBUE5CS0lxR3Nva0tKRlpjRDNyCjRwSVdHT0U3RVJrbU14MnFZMk54VGtuUGxOVUJzR01jS25qeTdycER5WmpDR0U3eldoRE5XRGdMUkJOc1liaHIKa0p4ZlNVVlBOb2RLaE8xVHQ3bDJRMnplcWxlV05pcktRbWdMY3JJRU9MRUdYcEY3U250eEx3N1pvYWlQU0FWWApQMTVqNXNkZlUzV1ZOdzhDZ2dFQkFOeGcyOGw5TllHUmwwU1JCZFJEakJhV21IK0pWYWdpdG0zNnorcnB1MWdZClZ4dFJ0N0FGTzF1QVphTys1aWd1d0JKcFhSUWJXVmZUcWppaTM1bUV2UENkZjhPcTZBQVlzeXg5WXVmUUdOUnEKZG1VNlcvdWhCMnVURDBrL0dQdjVFb2hBTlRjQmkyS1ROS2p0S1Z2bHFtbWZ4Tis5YTl4NjVEdWRHWUFRNGplNwpGaHZJSlU5WFA5VnRUc0ZGL1dqbE54enJNQURqSzNJekRvQTMwaU1XQXZkeTFjUDgxUzJzeGtwa0ZoL1QrNVVFCjYwZkNOSGFFemtQWWhKUmxYaUZtWXpqc3AyWjZpUERyMllHd1FWbURoMFFGeFVqZnoxdk1ONFdnVlVVeDlmNnUKR3QxeDdHblZFSGhzQ0VjQlFCUkhFbzJRcXY0VDVXbmNTNUVTN2hqK1JxVUNnZ0VBRDVUVEJ6VEFKMjJBSFpLbgpCM09jQTRvSzdXckxHZGllTWhtbCtkaWtTSjBQREJyODljUVJkL3c4a1QwZW9GczNnbUV4Y2lxb2lwL09zeXBaCmxxSlBCK2ZhazYrYUQ0c0tkbllhUlBpTGJhUDB4L0EyaFdteG9zQ0Q5M0Qwb0kyRHkzKzdGQ3A2Zzh4THdSdFkKY04yNXdab3ppckxYV08zaUZuaFJPb0tXWEFhKzNrSzZYelpuQkYzRSt4WFE2UU5mWHM4YzBUUFF3NVVPVXpYUwp3cDFodGJJcTdvZS9DaGJEcGI5RjBldlcwTkFUc2xWQ2Rpc2FmdEpUUnFiTm1zQ3BJbHBpR2lCNGk2VnN6NXFHCjkwOThVQzYvNlR1RURyazYvNUFkNmk1OFBWQzUzZjNRYUN0VUdpTEdKQzNmTHNTUjJoR3UvTG1yUUNmOTA1QlkKblJKY1h3S0NBUUVBbjJkQUV5SUtEY3B0akI4S0JGdEhmUjg0OXljeldnYWh4ak5oS1I0ZmNMMUtaR3hiWFdxcgpZS2dpM0tvOGVGdzRlaGpVUnJMeGtPRjlnckhzNG5KczUrNUVlQmVxOEVidGN3VFBBYlkzLzQxeVRnNUVjbUlyCnA5Z2Jlbk8xY3F6YWhzdEtzcHJmWTFIdkNURmlkU0pPZlZBZmEyYnNHZkthRzdTcXVVTjlIYXFwZHpieUpjMksKVXFwYUNOckRUWmhlb1FCTkhKYzAyY21zZDNubytZLzJYVjRtMlRpTVNobHE1R3c0eEpUa3FRbUIxY25YZ05MWApENlFSWWZWZ2ZQQStYUEp3czJOMm9pMDJpdVFlb016T2pwbE45a1JOREsxT2k4MUpZRitlKzdTYm9nbkJZMXZHCktoU2FlQ0dqWkFkMG1BbElaYmVtZlVmbk1PeHNaSStvTVFLQ0FRQmdETzBkTEt2Z3k0OFFwNzdzU3FkeGRRdTEKb2pqYm9rMGY4VVo5ZDJZWWl1WHMwb0k2WFQ4cmpESmJYUGZSUmFVUU1JYWRrL1VZOWxRdHZRRThHbW9aR2ozbgpXYTVXWGVkcUR3YUR4aHpmVnZQUzFMVm1VdkhsbllPWVBVT0JPc1ZUaU4yWXk1L0Y5WEpxMWRlVW0xVnVOZCs1ClVuK3d0YWVHVGR5K1pyQjF2RUFRT3M3R1REVFI2MjgwV1BPZ1JsenVRejhkYllYR29iajJrd3N1empCa0EvSjAKc2dkeEF0dExBWmIzQlVSQ2NmenkrdHJCd0Y3S1ZYek5EQnhmcit3MklRR0hINXR5NmNvcExTVDNXb2Y4WVRuTQpMdHBCVDNZTmgwTm5hS25HTlRGc3pZRldIRlJqSjRZU1BrcW85TkdWa0tiblZyOTllMDFjLys1VjBYY00KLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0K")
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: keyName,
		}
		smtc.keyOutput = keyvault.KeyBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(managerLabel),
			},
			Key: &keyvault.JSONWebKey{},
		}
	}
	ECKeySuccess := func(smtc *secretManagerTestCase) {
		smtc.setValue, _ = base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1JR2tBZ0VCQkRBWTk0L0NYOGo4UDNBakZXUkZYR0pWMFNWT1ErU1ZpV01nd0VFdy9rV2ZXcHF1OGtidllVTnAKVTQyN1Fubk5NV3VnQndZRks0RUVBQ0toWkFOaUFBU1FyOXAvcytDWHpFY2RUZ2t0aVFhTkxuVzJnNmQ1QkF4cQpBQXNaQms2UW11WngrZTZMUUdra080Uit0SVVaZCtWTGJlV3pLeEl3dk9xSVA3bkp0QldtTjZ4N3JsMjJibnhNCm5QWVQyNy9wSXM1RTk1L2dPV2RhOGMyUStHQTd5RTQ9Ci0tLS0tRU5EIEVDIFBSSVZBVEUgS0VZLS0tLS0K")
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: keyName,
		}
		smtc.keyOutput = keyvault.KeyBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(managerLabel),
			},
			Key: &keyvault.JSONWebKey{},
		}
	}
	invalidKey := func(smtc *secretManagerTestCase) {
		smtc.setValue, _ = base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZhekNDQTFPZ0F3SUJBZ0lVUHZKZ21wcTBKUWVRNkJuL0hmVTcvUDhRTFlFd0RRWUpLb1pJaHZjTkFRRUwKQlFBd1JURUxNQWtHQTFVRUJoTUNRVlV4RXpBUkJnTlZCQWdNQ2xOdmJXVXRVM1JoZEdVeElUQWZCZ05WQkFvTQpHRWx1ZEdWeWJtVjBJRmRwWkdkcGRITWdVSFI1SUV4MFpEQWVGdzB5TWpBMk1UY3lNREEwTWpSYUZ3MHlNekEyCk1UY3lNREEwTWpSYU1FVXhDekFKQmdOVkJBWVRBa0ZWTVJNd0VRWURWUVFJREFwVGIyMWxMVk4wWVhSbE1TRXcKSHdZRFZRUUtEQmhKYm5SbGNtNWxkQ0JYYVdSbmFYUnpJRkIwZVNCTWRHUXdnZ0lpTUEwR0NTcUdTSWIzRFFFQgpBUVVBQTRJQ0R3QXdnZ0lLQW9JQ0FRRGlEditEVENBL0xaZjZiNnlVYnliQUxlSUViOHh0aHd1dnRFZk5aZ1dOClN3ZWNMZXY0QXF1N3lSUWRidlQ1cnRKOGs3TnJ0TUE0RDNVN1BQamkwOXVpdjFnSGRockY0VlloTjhiRFllc1UKaEpxZXZSVFBVQ0hRek9xMmNhT3ViRnBUN3JxN3lsMVFTQTFlbkptMUQxNnc0UnlJcEtTLzhvVDNQaGtXM1YydwpkWmFjblZSV1RXZE5MTy9iVWdseDd1YzJMS0wwd2pIMzNSbkZiWUUrTTdiZFVDUXlsSXFwcDM2ZWNvL0Y1Ym1xCjdRdzJ2VkRENENGY0g5aUp4N1FDYjc4Skp5WWlMNzRycjJNVXVzMzR5RlhpMUk5RDR0ajdtQTM2VmNHRk9OZUsKdEtLMnlOYWNrWm1VeTlLQUdGWnIxU2c0ODZTcWw2Y2VpTlAvVGpsb3dQaDNMOTFHOEUxaGJSM3dDS2J6MUR1bQpmaEZOSUdNZmNERkNRcXpEUlU4OEpuUlcyYnF2bGpGanFla0NkcncyeHcrOWp1K1NieXkxeVlrN3ZSM015ZHovCmJ1YUY1S29YUlVzUzhxOHIwSEg1TVAzR3ZYVVY3eXU4bE5kUUtzMXhnVVpmL2JYM0ZjS2xjazhNU3ZZbjNMQWoKbDNRNHMwMXZQY1JnaUMyTUZmajlzV0pueW16YVhYUk1qNFpaY0RuVHlFUmhOcHpXSmNMelh3bFcydTVKdkpVTQpRVEdxUlpXYkErMHF5Y0dBOENBTHRRTXc2ZU5sLzI0Mlo5ZnZ0U0JPc3VkWTdEWTFXckFTWTNhbVV1WWU4RjFBCjhNMlg2N0xBc1lGNkY5YW9JNk00S2dVSXdHYm81OGFVTU1qdzJibGkzdHZIaVNSSjduejFXU1VGOHZnZThIYkEKcFFJREFRQUJvMU13VVRBZEJnTlZIUTRFRmdRVWd0Y0xTUXpaUkRmQkFsSWh5b2pJTHNLYXBwc3dId1lEVlIwagpCQmd3Rm9BVWd0Y0xTUXpaUkRmQkFsSWh5b2pJTHNLYXBwc3dEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU5CZ2txCmhraUc5dzBCQVFzRkFBT0NBZ0VBcy96OWNOT1ZSUzZFMmJVZm9GZS9lQW5OZlJjTmNaaW05VkdCWUFtRjc0MDgKSVEvVjhDK3g3cEloR1NGZ2VFNncxS1BRVXF0Z3dldUxFK0psOVhEYlAvMUdhcmgvN0xDWTVBUXk5eEdTVTNkcAp5VWs3SWE2a0wxRENkS3M0dXdGZ24wVjE1SytSM01Ud2FsemhVb1NVS2tDYVVSeU4vNTZXYk9OanhzRUhUbFhnClBBTEVYKzZVNDMzdktkYnNZdTJXZ2hXSmNwMytSZkI2MU90VmdvYTJYaThhL2pSbFpKVUJ1ZURESGEwVTE0L2EKaFRKcVdQWElROFlTY1BCbndsTzFyRjJkaEtMU0hiczZBd3d6VEVHUE5SUVpGRXF4YTJlb3VvV0NWUmxHTGVueQpMcWxnb1FSQ1pGRTdNNnBJazE5b0ZwV2tTSmNXYjFRMjJRWE03SFdKNjNtM2VBRjBUNThXcE45UzBsYXFNbnZCClZxNVpueUs1YVNDNjV3MGp1YzJteWM2K1RyUmNQSmM0UHJCY3VSZ0gvS1M1bkQvVFlKSStOSVBjU0NVZ2VKWFgKR003THNZanVuY1pCQmJkbFByRXJJN3pkYVNGdVJJbWYrSmh3T2p4OThSZjg3WkQ3d05pRmtzd1ZQYWZFQzFXQQoxc3ZMZDI0Nk0vR3I0RFVDK2Y2MUx4eFNKUkRWMDNySmdsZnY2cWlrL3hjaVlKU2lDdkZzR0hqYzBJaEtyTXBNCnFKRW03dWQxK3VTM3NHWTR6SkVUMUhleEJudjJ4RVlESjZhbGErV3FsNDdZTllSNm4yNlAvUWpNYjdSSGE1ZWMKUEhPMW5HaTY5L1U1dmVMRVlmZmtIV01qSTlKa1dhQzFiREcrMDl0clpSdXNUQWJCZHhqbWxzZ3o0UUFDeFd3PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==")
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: keyName,
		}
		smtc.keyOutput = keyvault.KeyBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(managerLabel),
			},
			Key: &keyvault.JSONWebKey{},
		}
		smtc.expectError = "could not load private key keyname: key type CERTIFICATE is not supported"
	}

	noTags := func(smtc *secretManagerTestCase) {
		smtc.setValue = goodKey
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: keyName,
		}
		smtc.keyOutput = keyvault.KeyBundle{
			Tags: map[string]*string{},
			Key:  &keyvault.JSONWebKey{},
		}
		smtc.expectError = errNotManaged
	}
	wrongTags := func(smtc *secretManagerTestCase) {
		smtc.setValue = goodKey
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: keyName,
		}
		smtc.keyOutput = keyvault.KeyBundle{
			Tags: map[string]*string{
				managedBy: pointer.To("internal-secrets"),
			},
			Key: &keyvault.JSONWebKey{},
		}
		smtc.expectError = errNotManaged
	}
	keyWithTags := func(smtc *secretManagerTestCase) {
		smtc.setValue = goodKey
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: keyName,
			Metadata: &apiextensionsv1.JSON{
				Raw: mdataWithTagRaw,
			},
		}
		smtc.keyOutput = keyvault.KeyBundle{
			Tags: map[string]*string{
				managedBy: pointer.To(managerLabel),
				tagKey:    pointer.To(tagValue),
			},
			Key: &keyvault.JSONWebKey{},
		}
	}
	errorGetKey := func(smtc *secretManagerTestCase) {
		smtc.setValue = goodKey
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: keyName,
		}
		smtc.apiErr = autorest.DetailedError{StatusCode: 403, Method: "GET", Message: forbiddenMessage}
		smtc.expectError = errAPI
	}
	keyNotFound := func(smtc *secretManagerTestCase) {
		smtc.setValue = goodKey
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: keyName,
		}
		smtc.apiErr = autorest.DetailedError{StatusCode: 404, Method: "GET", Message: notFoundMessage}
		smtc.expectError = ""
	}
	importKeyFailed := func(smtc *secretManagerTestCase) {
		smtc.setValue = goodKey
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: keyName,
		}
		smtc.apiErr = autorest.DetailedError{StatusCode: 404, Method: "GET", Message: notFoundMessage}
		smtc.setErr = autorest.DetailedError{StatusCode: 403, Method: "POST", Message: forbiddenMessage}
		smtc.expectError = "could not import key keyname: #POST: Forbidden: StatusCode=403"
	}
	certP12Success := func(smtc *secretManagerTestCase) {
		smtc.setValue = p12Cert
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: certName,
		}
		smtc.certOutput = keyvault.CertificateBundle{
			X509Thumbprint: pointer.To("123"),
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
		}
	}
	certP12ChainLegacySuccess := func(smtc *secretManagerTestCase) {
		smtc.setValue = p12CertChainLegacy
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: certName,
		}
		smtc.certOutput = keyvault.CertificateBundle{
			X509Thumbprint: pointer.To("123"),
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
		}
	}
	certP12ChainModernSuccess := func(smtc *secretManagerTestCase) {
		smtc.setValue = p12CertChainModern
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: certName,
		}
		smtc.certOutput = keyvault.CertificateBundle{
			X509Thumbprint: pointer.To("123"),
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
		}
	}
	certPEMSuccess := func(smtc *secretManagerTestCase) {
		pemCert, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZwekNDQTQrZ0F3SUJBZ0lVTUhhVDZtZG8vd2Urbit0NFB2R0JZaUdDSXE0d0RRWUpLb1pJaHZjTkFRRUwKQlFBd1l6RUxNQWtHQTFVRUJoTUNRVlV4RXpBUkJnTlZCQWdNQ2xOdmJXVXRVM1JoZEdVeElUQWZCZ05WQkFvTQpHRWx1ZEdWeWJtVjBJRmRwWkdkcGRITWdVSFI1SUV4MFpERWNNQm9HQTFVRUF3d1RZVzV2ZEdobGNpMW1iMjh0ClltRnlMbU52YlRBZUZ3MHlNakEyTURreE56UTFNelphRncweU16QTJNRGt4TnpRMU16WmFNR014Q3pBSkJnTlYKQkFZVEFrRlZNUk13RVFZRFZRUUlEQXBUYjIxbExWTjBZWFJsTVNFd0h3WURWUVFLREJoSmJuUmxjbTVsZENCWAphV1JuYVhSeklGQjBlU0JNZEdReEhEQWFCZ05WQkFNTUUyRnViM1JvWlhJdFptOXZMV0poY2k1amIyMHdnZ0lpCk1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQ0R3QXdnZ0lLQW9JQ0FRQ1pITzRvNkpteU9aZGZBdDdEV2pHa0d3N0QKNVVIU1BHZXQyTjg2cnBGWXcrZThnL3dSeDBnZDBzRk9pelBBREdjcnpmdWE5Z3ZFcDRWc1dvYUduY3dReGp2cworZ1orWmQ2UkVPNHRLNzRURmYxaWZibmowUHE2OENlQlFpaG8xbDNwM2UwQy8yemVJMjNidlZEdmUybXdVcTloCjY4UTFFUmdWMU1LaWJHU1Naak5DQzdkRGFQWmpKazViMFlWVFdxREViemREVnh2ZVVMNVJxRmcvREpBMzNWcTYKVFQzQ2U5RjBIcEorb3graSs4cUxmWU5qZExSUDZlbEtLTU5naVhhNTFvdnQ5MjF4UkVGdlhFdi9NS2pZOWE2SgppNndIRSs0NmdvbFY4V2puK2xMRkRKVHh6WEFEN2p2NzVzaHY0WEczdFlaQ2J4cTMzZ2Jtb3pzRVBneVNEa0IyCm5zc0tIUEFhSVNPaWpjNDhiSXhwbDVocFJPWUZFblJDWnhablhQNjdLZVF1VWZXQkpoVWdhaW1zQlErenpwUHoKZjVUbjRnVExkWll2NU41V1V2djJJdUF5Qktha0ZhR1ZYTzFpZ2FDeVQvUTNBcEE2ZGx4SjVVbjhLNjh1L0pIYQpmWWZ5engwVnVoZk5zbmtiWkxWSEZsR2Rxd3JrU0tCWSs1eS9WWlpkeC9hSHNWWndVN3ZEY2VobGVaUU00ZXZyCm5tMUY3dk5xSHBUK3BHSnpNVWVUNGZMVFpabTBra1Y3ZXl5RGRMMDFEWXRXQk1TM2NEb1F1Tm9YSUEwK0N4Vk8KOHcxcC9wbXF2UFQ3cmpad2pwYkVMUkp3MWs4R3ozU2FKb2VqaFBzWC9xNzNGWWdBc09PRHBNcm4rdmlTZTRmcgpmR0VmZlEvYXJUVE5qK1BUb3dJREFRQUJvMU13VVRBZEJnTlZIUTRFRmdRVWJPQk14azJ5UkNkR1N4eEZGMzBUCkZORFhHS3N3SHdZRFZSMGpCQmd3Rm9BVWJPQk14azJ5UkNkR1N4eEZGMzBURk5EWEdLc3dEd1lEVlIwVEFRSC8KQkFVd0F3RUIvekFOQmdrcWhraUc5dzBCQVFzRkFBT0NBZ0VBQXdudUtxOThOQ2hUMlUzU2RSNEFVem1MTjFCVwowNHIwMTA3TjlKdW9LbzJycjhoZ21mRmd0MDgrdFNDYzR5ajZSNStyY1hudXpqeEZLaWJVYnFncFpvd0pSSGEyCjF0NUJicEwxeWcybGZyZnhIb3YvRjh0VnNTbUE4d3loNlVpV1J3RTlrdlBXUm5LblR1a3Y1enpzcVNsTlNpbG0KNDl6UTdTV05sK0lBRnkvc3dacnRKUTEwVlQ5czRuUGVHM29XUU1vdE9QUCtsbFNpeW5LTFpxUTRnU0tSaTNmZQpQTGlXcHQ5WGZYb0dVQ0VqN3E1cGhibExQZ2RLVUNyaEdQMW4yalltWHNjV0xNeWtBbmEyMGNobHJxVlluQ2E4CkpVcDRMZnRGRHA4OVlUb1hPRkhuRm1uTkN2Y0lyRGZGeURmaGw0VU1GcEswT1VLcVRUeFdhSzl1cU9JcGFySXMKS1l3c3ArZkxlV0xiUTZrR2Ztbk81aURSZCtvT2hyTllvb1RaVks5ZlFSNXJEMmU0QitlYTByelFGWEFBVWpKNQpPWGFieGJEclErT01landjNEhxcXN4enRKZ0QyYVAyZUsyL0w1UFdQdWcwRSsxZzhBQlpmVmJvaC9NM01IZ2J6ClBnYVRxZ3V6R0Zka0czRVh1K09oR2JVMC8rNzdWTW5aaTJJUVpuL2F3R1VhN1grTVAwQkR2alZZNWtWcE1aMWgKYzJDbERqZ3hOc0xHdGlrTzRjV2I1c1FSUjJHWU0zZE1rNTBWUWN0SjVScXNSczZwT0NYRFhFM1JlVlFqNGhOQgplV3ZhRFdRMktteU9haTU1ZGJEcmxKK251ODNPbUNwNTlSelA1azU4WmFEWG5sQzM4VXdUdDBxMUQ3K3pGMHRzCjFHOTMydUVCSFdZSHVPQT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=")
		smtc.setValue = pemCert
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: certName,
		}
		smtc.certOutput = keyvault.CertificateBundle{
			X509Thumbprint: pointer.To("123"),
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
		}
	}

	certPEMWithGarbageSuccess := func(smtc *secretManagerTestCase) {
		pemCert, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBNWNXTTdWYnd2dGtxWXVLd1lrVUhlSXRMQnd2eUd2ekhzODQwbDZpT00rZXZneEVXCmcydFAvb3NYeG1Rb1ZOdDJLUXRScEwweTh4K3JhWHhRRm5VTlJEc3pHSEkyWTdmWnVVRWd0M2FQQVhmUUlMNm0KazdJaWQ0VmZUdlpLTFhNbnB6dEduNVlaTVBxak0yU3k3ZWY5ZjJMNkxuamNwRkRNZFBqN25vd0pxcTdMb3kxcAo2aU1xeHNyRGY1RXloRHdGUVhiZHRQM0pPNmpjSDY4UUVsVkE0eVR5RHR4WXpxSS9mb0pIM2tGZStHSmJwS0FNCnlNQXRwVkphS2F6VGVnTCtWZnc1MFV2czFLT3A3L1ZxZXVCd2FpZDhtWkhYWDFRUE44RE9VUmJRbkhoVUp1Y3UKZlIyNVdlbHhqWUtOMGdGWFE1bHo5MXY1TmVlTnhQWkhRbkZ2NVFJREFRQUJBb0lCQUNQR2FuYlp2b280amR6dgpwcjdtT0krUVFKSk1UZG5kMmNvcEpROG44MXdwaXE1Qmp0dlBiWmtZVnc5UXNPYmxkTFJYU3RMM2ttTkFYeFFCCmd3YThHdUN3eHZmYmNKUitINncwYzcrYytnOGtkSWRrcDlML1BWYVdzWXc5MUxiVzR5bXFsUWhyK21naDNoODIKWXBXZ05Wd01NUi9qT1pkcjdTbVpTclFZNGJodFN6eFlDOE5Vc0hwL1JaR3FqejdILzRyR1B5dEpTMjFVYVMzegpabXBLdHcrRm81ZVF5UW5lUVUyL2dmNkxTV3JUZjI5Y3NXSEVlMUpRWHZzYlA1enAxbGEzRjBXczEvOUNyT0VNCnFsbUNWNFRXWXR1Nno1a2k2Y1c1enkybEVLSnpCYTVqT0ZqRGtqREFzRm1IZmNydXlMbVVqZUU2MWlPZjAycXQKV1Z5MkZZRUNnWUVBNmRRdFgxTDNmaVpKdFUzd0lkVytxVkZSeEFwMUd6RG5TaEJBQmg0SDA5eHFhMzc2RXovSgpYUmdrV0xLZTU0VUdnZi9ZTzJDTkRkSzVGZmw1MHNrN1hDeGJPRzZITTNSRytxZjQ0MXUzQWd6L0ppa3QyOFBMCmZ2dUJYRG91a1hQUUVvWHR1cHNHaFJLRUxleWhZTHNJSzZNWndJQnFBQThGV200cWc1b2RPazBDZ1lFQSs0N2sKaXNHMWRxaFdnUk1Fc1ZBVG9SeW9ITDBXYVFpbkhXUWQ4ZFBDZ1BDNzJqbmZQdmZ2THZnUEVEeEMxTk41VEJNUQpwOHliS2EvOEZOVzV0VkpQdXdsSGlveURKdHZVVFQ1UVZtVmtOa21LZllZR1h0dVlqQUVtaVJWL0JSRVZQSG0yCnYvTjBLRHA2YVRTQXAxdm10czZoQ0I0ZGNSeXkyNnNTdG5XcUova0NnWUEwRHlBMjYrTGNQQ3dHNko1QStqU2oKdjg0amhteUNMRVlpVURIZzZzaTFXNHA1K21BMDd1dW5CVnY2UDNKdmUwZHlwQUtCWGNLcHhET2U5OWN1bmN6UQpmYk9sZ2I0cUw0WXFBa0hBWk1mKzllUE1uRGh3aUV3RExuMmppZlNhUDUyZ3NoNjJnQk5ZaDBIVWM2Mk9PclhiCitVa2ZlYmVmNGJoQVpPeWtOaWl4dFFLQmdFNm1MRm9kbWlpUkZRcWg4Wk9tWDV5OW91bnBUSHBtVkNsaVJlSjMKdkpZbnJmUGFxQ3U5eExCQXFpVC9VajNNS0Y1YWo1aUc1ZlF3cTNXd0pMSEdIRnR6MlVRK0RqczErN2h5eFJkZAo5K2pwTVQxeGk4aFlpK2NwN094ckpoMWxhK2hPZlk2aUJTMFdxM0w5RVVSQi9XNG1TRDZMZTlVRGpnQVVDbk8xCmNnK3hBb0dCQU9YVktjTzFpS3UrZWNCZUxFMVV0M2JUcUFCL2tCcFRkdVZZbTh3Mld0b1BUQ2tqUTZNc2o5ZWcKRjJ0R0pwbUV0djZ6NnMzbmo1TmhSWlYyWDh0WjMxWHViVkdVQUt4aGprSnlPQnBuczk3bTlxZUMxRHlFcDlMaQp6RnFpQ1VMWVp1c1JObzVTWVRCcHBCbmFPN1ArODhFMnFmV3Fob0h6b1dYNWk1a2dpK0tXCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlGcHpDQ0E0K2dBd0lCQWdJVU1IYVQ2bWRvL3dlK24rdDRQdkdCWWlHQ0lxNHdEUVlKS29aSWh2Y05BUUVMCkJRQXdZekVMTUFrR0ExVUVCaE1DUVZVeEV6QVJCZ05WQkFnTUNsTnZiV1V0VTNSaGRHVXhJVEFmQmdOVkJBb00KR0VsdWRHVnlibVYwSUZkcFpHZHBkSE1nVUhSNUlFeDBaREVjTUJvR0ExVUVBd3dUWVc1dmRHaGxjaTFtYjI4dApZbUZ5TG1OdmJUQWVGdzB5TWpBMk1Ea3hOelExTXpaYUZ3MHlNekEyTURreE56UTFNelphTUdNeEN6QUpCZ05WCkJBWVRBa0ZWTVJNd0VRWURWUVFJREFwVGIyMWxMVk4wWVhSbE1TRXdId1lEVlFRS0RCaEpiblJsY201bGRDQlgKYVdSbmFYUnpJRkIwZVNCTWRHUXhIREFhQmdOVkJBTU1FMkZ1YjNSb1pYSXRabTl2TFdKaGNpNWpiMjB3Z2dJaQpNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUNEd0F3Z2dJS0FvSUNBUUNaSE80bzZKbXlPWmRmQXQ3RFdqR2tHdzdECjVVSFNQR2V0Mk44NnJwRll3K2U4Zy93UngwZ2Qwc0ZPaXpQQURHY3J6ZnVhOWd2RXA0VnNXb2FHbmN3UXhqdnMKK2daK1pkNlJFTzR0Szc0VEZmMWlmYm5qMFBxNjhDZUJRaWhvMWwzcDNlMEMvMnplSTIzYnZWRHZlMm13VXE5aAo2OFExRVJnVjFNS2liR1NTWmpOQ0M3ZERhUFpqSms1YjBZVlRXcURFYnpkRFZ4dmVVTDVScUZnL0RKQTMzVnE2ClRUM0NlOUYwSHBKK294K2krOHFMZllOamRMUlA2ZWxLS01OZ2lYYTUxb3Z0OTIxeFJFRnZYRXYvTUtqWTlhNkoKaTZ3SEUrNDZnb2xWOFdqbitsTEZESlR4elhBRDdqdjc1c2h2NFhHM3RZWkNieHEzM2dibW96c0VQZ3lTRGtCMgpuc3NLSFBBYUlTT2lqYzQ4Ykl4cGw1aHBST1lGRW5SQ1p4Wm5YUDY3S2VRdVVmV0JKaFVnYWltc0JRK3p6cFB6CmY1VG40Z1RMZFpZdjVONVdVdnYySXVBeUJLYWtGYUdWWE8xaWdhQ3lUL1EzQXBBNmRseEo1VW44SzY4dS9KSGEKZllmeXp4MFZ1aGZOc25rYlpMVkhGbEdkcXdya1NLQlkrNXkvVlpaZHgvYUhzVlp3VTd2RGNlaGxlWlFNNGV2cgpubTFGN3ZOcUhwVCtwR0p6TVVlVDRmTFRaWm0wa2tWN2V5eURkTDAxRFl0V0JNUzNjRG9RdU5vWElBMCtDeFZPCjh3MXAvcG1xdlBUN3JqWndqcGJFTFJKdzFrOEd6M1NhSm9lamhQc1gvcTczRllnQXNPT0RwTXJuK3ZpU2U0ZnIKZkdFZmZRL2FyVFROaitQVG93SURBUUFCbzFNd1VUQWRCZ05WSFE0RUZnUVViT0JNeGsyeVJDZEdTeHhGRjMwVApGTkRYR0tzd0h3WURWUjBqQkJnd0ZvQVViT0JNeGsyeVJDZEdTeHhGRjMwVEZORFhHS3N3RHdZRFZSMFRBUUgvCkJBVXdBd0VCL3pBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQWdFQUF3bnVLcTk4TkNoVDJVM1NkUjRBVXptTE4xQlcKMDRyMDEwN045SnVvS28ycnI4aGdtZkZndDA4K3RTQ2M0eWo2UjUrcmNYbnV6anhGS2liVWJxZ3Bab3dKUkhhMgoxdDVCYnBMMXlnMmxmcmZ4SG92L0Y4dFZzU21BOHd5aDZVaVdSd0U5a3ZQV1JuS25UdWt2NXp6c3FTbE5TaWxtCjQ5elE3U1dObCtJQUZ5L3N3WnJ0SlExMFZUOXM0blBlRzNvV1FNb3RPUFArbGxTaXluS0xacVE0Z1NLUmkzZmUKUExpV3B0OVhmWG9HVUNFajdxNXBoYmxMUGdkS1VDcmhHUDFuMmpZbVhzY1dMTXlrQW5hMjBjaGxycVZZbkNhOApKVXA0TGZ0RkRwODlZVG9YT0ZIbkZtbk5DdmNJckRmRnlEZmhsNFVNRnBLME9VS3FUVHhXYUs5dXFPSXBhcklzCktZd3NwK2ZMZVdMYlE2a0dmbW5PNWlEUmQrb09ock5Zb29UWlZLOWZRUjVyRDJlNEIrZWEwcnpRRlhBQVVqSjUKT1hhYnhiRHJRK09NZWp3YzRIcXFzeHp0SmdEMmFQMmVLMi9MNVBXUHVnMEUrMWc4QUJaZlZib2gvTTNNSGdiegpQZ2FUcWd1ekdGZGtHM0VYdStPaEdiVTAvKzc3Vk1uWmkySVFabi9hd0dVYTdYK01QMEJEdmpWWTVrVnBNWjFoCmMyQ2xEamd4TnNMR3Rpa080Y1diNXNRUlIyR1lNM2RNazUwVlFjdEo1UnFzUnM2cE9DWERYRTNSZVZRajRoTkIKZVd2YURXUTJLbXlPYWk1NWRiRHJsSitudTgzT21DcDU5UnpQNWs1OFphRFhubEMzOFV3VHQwcTFENyt6RjB0cwoxRzkzMnVFQkhXWUh1T0E9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K")
		smtc.setValue = pemCert
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: certName,
		}
		smtc.certOutput = keyvault.CertificateBundle{
			X509Thumbprint: pointer.To("123"),
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
		}
	}

	certDERSuccess := func(smtc *secretManagerTestCase) {
		derCert, _ := base64.StdEncoding.DecodeString("MIIFpzCCA4+gAwIBAgIUMHaT6mdo/we+n+t4PvGBYiGCIq4wDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEcMBoGA1UEAwwTYW5vdGhlci1mb28tYmFyLmNvbTAeFw0yMjA2MDkxNzQ1MzZaFw0yMzA2MDkxNzQ1MzZaMGMxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxHDAaBgNVBAMME2Fub3RoZXItZm9vLWJhci5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCZHO4o6JmyOZdfAt7DWjGkGw7D5UHSPGet2N86rpFYw+e8g/wRx0gd0sFOizPADGcrzfua9gvEp4VsWoaGncwQxjvs+gZ+Zd6REO4tK74TFf1ifbnj0Pq68CeBQiho1l3p3e0C/2zeI23bvVDve2mwUq9h68Q1ERgV1MKibGSSZjNCC7dDaPZjJk5b0YVTWqDEbzdDVxveUL5RqFg/DJA33Vq6TT3Ce9F0HpJ+ox+i+8qLfYNjdLRP6elKKMNgiXa51ovt921xREFvXEv/MKjY9a6Ji6wHE+46golV8Wjn+lLFDJTxzXAD7jv75shv4XG3tYZCbxq33gbmozsEPgySDkB2nssKHPAaISOijc48bIxpl5hpROYFEnRCZxZnXP67KeQuUfWBJhUgaimsBQ+zzpPzf5Tn4gTLdZYv5N5WUvv2IuAyBKakFaGVXO1igaCyT/Q3ApA6dlxJ5Un8K68u/JHafYfyzx0VuhfNsnkbZLVHFlGdqwrkSKBY+5y/VZZdx/aHsVZwU7vDcehleZQM4evrnm1F7vNqHpT+pGJzMUeT4fLTZZm0kkV7eyyDdL01DYtWBMS3cDoQuNoXIA0+CxVO8w1p/pmqvPT7rjZwjpbELRJw1k8Gz3SaJoejhPsX/q73FYgAsOODpMrn+viSe4frfGEffQ/arTTNj+PTowIDAQABo1MwUTAdBgNVHQ4EFgQUbOBMxk2yRCdGSxxFF30TFNDXGKswHwYDVR0jBBgwFoAUbOBMxk2yRCdGSxxFF30TFNDXGKswDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAAwnuKq98NChT2U3SdR4AUzmLN1BW04r0107N9JuoKo2rr8hgmfFgt08+tSCc4yj6R5+rcXnuzjxFKibUbqgpZowJRHa21t5BbpL1yg2lfrfxHov/F8tVsSmA8wyh6UiWRwE9kvPWRnKnTukv5zzsqSlNSilm49zQ7SWNl+IAFy/swZrtJQ10VT9s4nPeG3oWQMotOPP+llSiynKLZqQ4gSKRi3fePLiWpt9XfXoGUCEj7q5phblLPgdKUCrhGP1n2jYmXscWLMykAna20chlrqVYnCa8JUp4LftFDp89YToXOFHnFmnNCvcIrDfFyDfhl4UMFpK0OUKqTTxWaK9uqOIparIsKYwsp+fLeWLbQ6kGfmnO5iDRd+oOhrNYooTZVK9fQR5rD2e4B+ea0rzQFXAAUjJ5OXabxbDrQ+OMejwc4HqqsxztJgD2aP2eK2/L5PWPug0E+1g8ABZfVboh/M3MHgbzPgaTqguzGFdkG3EXu+OhGbU0/+77VMnZi2IQZn/awGUa7X+MP0BDvjVY5kVpMZ1hc2ClDjgxNsLGtikO4cWb5sQRR2GYM3dMk50VQctJ5RqsRs6pOCXDXE3ReVQj4hNBeWvaDWQ2KmyOai55dbDrlJ+nu83OmCp59RzP5k58ZaDXnlC38UwTt0q1D7+zF0ts1G932uEBHWYHuOA=")
		smtc.setValue = derCert
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: certName,
		}
		smtc.certOutput = keyvault.CertificateBundle{
			X509Thumbprint: pointer.To("123"),
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
		}
	}

	certImportCertificateError := func(smtc *secretManagerTestCase) {
		smtc.setErr = errors.New("error")
		smtc.setValue = p12Cert
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: certName,
		}
		smtc.certOutput = keyvault.CertificateBundle{
			X509Thumbprint: pointer.To("123"),
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
		}
		smtc.expectError = "could not import certificate certname: error"
	}

	certFingerprintMatches := func(smtc *secretManagerTestCase) {
		smtc.setErr = errors.New("error")
		cert, _ := base64.StdEncoding.DecodeString("MIIFpzCCA4+gAwIBAgIUMHaT6mdo/we+n+t4PvGBYiGCIq4wDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEcMBoGA1UEAwwTYW5vdGhlci1mb28tYmFyLmNvbTAeFw0yMjA2MDkxNzQ1MzZaFw0yMzA2MDkxNzQ1MzZaMGMxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxHDAaBgNVBAMME2Fub3RoZXItZm9vLWJhci5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCZHO4o6JmyOZdfAt7DWjGkGw7D5UHSPGet2N86rpFYw+e8g/wRx0gd0sFOizPADGcrzfua9gvEp4VsWoaGncwQxjvs+gZ+Zd6REO4tK74TFf1ifbnj0Pq68CeBQiho1l3p3e0C/2zeI23bvVDve2mwUq9h68Q1ERgV1MKibGSSZjNCC7dDaPZjJk5b0YVTWqDEbzdDVxveUL5RqFg/DJA33Vq6TT3Ce9F0HpJ+ox+i+8qLfYNjdLRP6elKKMNgiXa51ovt921xREFvXEv/MKjY9a6Ji6wHE+46golV8Wjn+lLFDJTxzXAD7jv75shv4XG3tYZCbxq33gbmozsEPgySDkB2nssKHPAaISOijc48bIxpl5hpROYFEnRCZxZnXP67KeQuUfWBJhUgaimsBQ+zzpPzf5Tn4gTLdZYv5N5WUvv2IuAyBKakFaGVXO1igaCyT/Q3ApA6dlxJ5Un8K68u/JHafYfyzx0VuhfNsnkbZLVHFlGdqwrkSKBY+5y/VZZdx/aHsVZwU7vDcehleZQM4evrnm1F7vNqHpT+pGJzMUeT4fLTZZm0kkV7eyyDdL01DYtWBMS3cDoQuNoXIA0+CxVO8w1p/pmqvPT7rjZwjpbELRJw1k8Gz3SaJoejhPsX/q73FYgAsOODpMrn+viSe4frfGEffQ/arTTNj+PTowIDAQABo1MwUTAdBgNVHQ4EFgQUbOBMxk2yRCdGSxxFF30TFNDXGKswHwYDVR0jBBgwFoAUbOBMxk2yRCdGSxxFF30TFNDXGKswDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAAwnuKq98NChT2U3SdR4AUzmLN1BW04r0107N9JuoKo2rr8hgmfFgt08+tSCc4yj6R5+rcXnuzjxFKibUbqgpZowJRHa21t5BbpL1yg2lfrfxHov/F8tVsSmA8wyh6UiWRwE9kvPWRnKnTukv5zzsqSlNSilm49zQ7SWNl+IAFy/swZrtJQ10VT9s4nPeG3oWQMotOPP+llSiynKLZqQ4gSKRi3fePLiWpt9XfXoGUCEj7q5phblLPgdKUCrhGP1n2jYmXscWLMykAna20chlrqVYnCa8JUp4LftFDp89YToXOFHnFmnNCvcIrDfFyDfhl4UMFpK0OUKqTTxWaK9uqOIparIsKYwsp+fLeWLbQ6kGfmnO5iDRd+oOhrNYooTZVK9fQR5rD2e4B+ea0rzQFXAAUjJ5OXabxbDrQ+OMejwc4HqqsxztJgD2aP2eK2/L5PWPug0E+1g8ABZfVboh/M3MHgbzPgaTqguzGFdkG3EXu+OhGbU0/+77VMnZi2IQZn/awGUa7X+MP0BDvjVY5kVpMZ1hc2ClDjgxNsLGtikO4cWb5sQRR2GYM3dMk50VQctJ5RqsRs6pOCXDXE3ReVQj4hNBeWvaDWQ2KmyOai55dbDrlJ+nu83OmCp59RzP5k58ZaDXnlC38UwTt0q1D7+zF0ts1G932uEBHWYHuOA=")
		smtc.setValue = p12Cert
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: certName,
		}
		smtc.certOutput = keyvault.CertificateBundle{
			Cer: &cert,
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
			},
		}
	}

	certNotManagedByES := func(smtc *secretManagerTestCase) {
		smtc.setValue = p12Cert
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: certName,
		}
		smtc.certOutput = keyvault.CertificateBundle{
			X509Thumbprint: pointer.To("123"),
			Tags: map[string]*string{
				managedBy: pointer.To("foobar"),
			},
		}
		smtc.expectError = "certificate certname: not managed by external-secrets"
	}

	certNoManagerTags := func(smtc *secretManagerTestCase) {
		smtc.setValue = p12Cert
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: certName,
		}
		smtc.certOutput = keyvault.CertificateBundle{
			X509Thumbprint: pointer.To("123"),
		}
		smtc.expectError = "certificate certname: not managed by external-secrets"
	}

	certWithTags := func(smtc *secretManagerTestCase) {
		smtc.setValue = p12CertChainLegacy
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: certName,
			Metadata: &apiextensionsv1.JSON{
				Raw: mdataWithTagRaw,
			},
		}
		smtc.certOutput = keyvault.CertificateBundle{
			X509Thumbprint: pointer.To("123"),
			Tags: map[string]*string{
				managedBy: pointer.To(externalSecrets),
				tagKey:    pointer.To(tagValue),
			},
		}
	}

	certNotACertificate := func(smtc *secretManagerTestCase) {
		smtc.setValue = []byte("foobar")
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: certName,
		}
		smtc.certOutput = keyvault.CertificateBundle{
			X509Thumbprint: pointer.To("123"),
		}
		smtc.expectError = "value from secret is not a valid certificate: could not parse certificate value as PKCS#12, DER or PEM"
	}

	certNoPermissions := func(smtc *secretManagerTestCase) {
		smtc.apiErr = autorest.DetailedError{
			StatusCode: 403,
			Method:     "GET",
			Message:    "Insufficient Permissions",
		}
		smtc.setValue = p12Cert
		smtc.pushData = testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: certName,
		}
		smtc.certOutput = keyvault.CertificateBundle{
			X509Thumbprint: pointer.To("123"),
		}
		smtc.expectError = errAPI
	}

	successCases := []*secretManagerTestCase{
		makeValidSecretManagerTestCaseCustom(certP12Success),
		makeValidSecretManagerTestCaseCustom(certP12ChainLegacySuccess),
		makeValidSecretManagerTestCaseCustom(certP12ChainModernSuccess),
		makeValidSecretManagerTestCaseCustom(certPEMSuccess),
		makeValidSecretManagerTestCaseCustom(certPEMWithGarbageSuccess),
		makeValidSecretManagerTestCaseCustom(certDERSuccess),
		makeValidSecretManagerTestCaseCustom(certImportCertificateError),
		makeValidSecretManagerTestCaseCustom(certFingerprintMatches),
		makeValidSecretManagerTestCaseCustom(certNotManagedByES),
		makeValidSecretManagerTestCaseCustom(certNoManagerTags),
		makeValidSecretManagerTestCaseCustom(certNotACertificate),
		makeValidSecretManagerTestCaseCustom(certNoPermissions),
		makeValidSecretManagerTestCaseCustom(keySuccess),
		makeValidSecretManagerTestCaseCustom(symmetricKeySuccess),
		makeValidSecretManagerTestCaseCustom(RSAKeySuccess),
		makeValidSecretManagerTestCaseCustom(ECKeySuccess),
		makeValidSecretManagerTestCaseCustom(invalidKey),
		makeValidSecretManagerTestCaseCustom(errorGetKey),
		makeValidSecretManagerTestCaseCustom(keyNotFound),
		makeValidSecretManagerTestCaseCustom(importKeyFailed),
		makeValidSecretManagerTestCaseCustom(noTags),
		makeValidSecretManagerTestCaseCustom(wrongTags),
		makeValidSecretManagerTestCaseCustom(secretSuccess),
		makeValidSecretManagerTestCaseCustom(secretNoChange),
		makeValidSecretManagerTestCaseCustom(secretExpiryChange),
		makeValidSecretManagerTestCaseCustom(secretWrongTags),
		makeValidSecretManagerTestCaseCustom(secretNoTags),
		makeValidSecretManagerTestCaseCustom(secretNotFound),
		makeValidSecretManagerTestCaseCustom(failedGetSecret),
		makeValidSecretManagerTestCaseCustom(failedNotParseableError),
		makeValidSecretManagerTestCaseCustom(failedSetSecret),
		makeValidSecretManagerTestCaseCustom(typeNotSupported),
		makeValidSecretManagerTestCaseCustom(wholeSecretNoKey),
		makeValidSecretManagerTestCaseCustom(secretWithTags),
		makeValidSecretManagerTestCaseCustom(certWithTags),
		makeValidSecretManagerTestCaseCustom(keyWithTags),
	}

	sm := Azure{
		provider: &esv1.AzureKVProvider{VaultURL: pointer.To(fakeURL)},
	}
	for k, v := range successCases {
		sm.baseClient = v.mockClient
		if v.secret == nil {
			v.secret = &corev1.Secret{
				Data: map[string][]byte{
					secretKey: v.setValue,
				},
			}
		}
		err := sm.PushSecret(context.Background(), v.secret, v.pushData)
		if !utils.ErrorContains(err, v.expectError) {
			if err == nil {
				t.Errorf("[%d] unexpected error: <nil>, expected: '%s'", k, v.expectError)
			} else {
				t.Errorf(unexpectedError, k, err.Error(), v.expectError)
			}
		}
		if len(v.expectedData) > 0 {
			sm.baseClient = v.mockClient
			out, err := sm.GetSecretMap(context.Background(), *v.ref)
			if !utils.ErrorContains(err, v.expectError) {
				t.Errorf(unexpectedError, k, err.Error(), v.expectError)
			}
			if err == nil && !reflect.DeepEqual(out, v.expectedData) {
				t.Errorf(unexpectedSecretData, k, v.expectedData, out)
			}
		}
	}
}

// test the sm<->azurekv interface
// make sure correct values are passed and errors are handled accordingly.
func TestAzureKeyVaultSecretManagerGetSecret(t *testing.T) {
	secretString := "changedvalue"
	secretCertificate := "certificate_value"
	tagMap := getTagMap()

	// good case
	setSecretString := func(smtc *secretManagerTestCase) {
		smtc.expectedSecret = secretString
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &secretString,
		}
	}
	// good case
	secretNotFound := func(smtc *secretManagerTestCase) {
		smtc.expectedSecret = ""
		smtc.apiErr = autorest.DetailedError{StatusCode: 404}
		smtc.expectError = esv1.NoSecretError{}.Error()
	}

	certNotFound := func(smtc *secretManagerTestCase) {
		smtc.expectedSecret = ""
		smtc.secretName = certName
		smtc.apiErr = autorest.DetailedError{StatusCode: 404}
		smtc.expectError = esv1.NoSecretError{}.Error()
	}

	keyNotFound := func(smtc *secretManagerTestCase) {
		smtc.expectedSecret = ""
		smtc.secretName = keyName
		smtc.apiErr = autorest.DetailedError{StatusCode: 404}
		smtc.expectError = esv1.NoSecretError{}.Error()
	}

	setSecretStringWithVersion := func(smtc *secretManagerTestCase) {
		smtc.expectedSecret = secretString
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &secretString,
		}
		smtc.ref.Version = "v1"
		smtc.secretVersion = smtc.ref.Version
	}

	setSecretWithProperty := func(smtc *secretManagerTestCase) {
		jsonString := jsonTestString
		smtc.expectedSecret = "External"
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &jsonString,
		}
		smtc.ref.Property = "Name"
	}

	badSecretWithProperty := func(smtc *secretManagerTestCase) {
		jsonString := jsonTestString
		smtc.expectedSecret = ""
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &jsonString,
		}
		smtc.ref.Property = "Age"
		smtc.expectError = fmt.Sprintf("property %s does not exist in key %s", smtc.ref.Property, smtc.ref.Key)
		smtc.apiErr = errors.New(smtc.expectError)
	}

	// // good case: key set
	setPubRSAKey := func(smtc *secretManagerTestCase) {
		smtc.secretName = keyName
		smtc.expectedSecret = jwkPubRSA
		smtc.keyOutput = keyvault.KeyBundle{
			Key: newKVJWK([]byte(jwkPubRSA)),
		}
		smtc.ref.Key = smtc.secretName
	}

	// // good case: key set
	setPubECKey := func(smtc *secretManagerTestCase) {
		smtc.secretName = keyName
		smtc.expectedSecret = jwkPubEC
		smtc.keyOutput = keyvault.KeyBundle{
			Key: newKVJWK([]byte(jwkPubEC)),
		}
		smtc.ref.Key = smtc.secretName
	}

	// // good case: key set
	setCertificate := func(smtc *secretManagerTestCase) {
		byteArrString := []byte(secretCertificate)
		smtc.secretName = certName
		smtc.expectedSecret = secretCertificate
		smtc.certOutput = keyvault.CertificateBundle{
			Cer: &byteArrString,
		}
		smtc.ref.Key = smtc.secretName
	}

	badSecretType := func(smtc *secretManagerTestCase) {
		smtc.secretName = "name"
		smtc.expectedSecret = ""
		smtc.expectError = fmt.Sprintf("unknown Azure Keyvault object Type for %s", smtc.secretName)
		smtc.ref.Key = fmt.Sprintf("example/%s", smtc.secretName)
	}

	setSecretWithTag := func(smtc *secretManagerTestCase) {
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		smtc.ref.Property = tagname
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &secretString, Tags: tagMap,
		}
		smtc.expectedSecret = tagvalue
	}

	badSecretWithTag := func(smtc *secretManagerTestCase) {
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		smtc.ref.Property = something
		smtc.expectedSecret = ""
		smtc.expectError = errorNoTag
		smtc.apiErr = errors.New(smtc.expectError)
	}

	setSecretWithNoSpecificTag := func(smtc *secretManagerTestCase) {
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &secretString, Tags: tagMap,
		}
		smtc.expectedSecret = jsonTagTestString
	}

	setSecretWithNoTags := func(smtc *secretManagerTestCase) {
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		smtc.secretOutput = keyvault.SecretBundle{}
		smtc.expectedSecret = "{}"
	}

	setCertWithTag := func(smtc *secretManagerTestCase) {
		byteArrString := []byte(secretCertificate)
		smtc.secretName = certName
		smtc.certOutput = keyvault.CertificateBundle{
			Cer: &byteArrString, Tags: tagMap,
		}
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		smtc.ref.Property = tagname
		smtc.expectedSecret = tagvalue
		smtc.ref.Key = smtc.secretName
	}

	badCertWithTag := func(smtc *secretManagerTestCase) {
		byteArrString := []byte(secretCertificate)
		smtc.secretName = certName
		smtc.ref.Key = smtc.secretName
		smtc.certOutput = keyvault.CertificateBundle{
			Cer: &byteArrString,
		}
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		smtc.ref.Property = something
		smtc.expectedSecret = ""
		smtc.expectError = errorNoTag
		smtc.apiErr = errors.New(smtc.expectError)
	}

	setCertWithNoSpecificTag := func(smtc *secretManagerTestCase) {
		byteArrString := []byte(secretCertificate)
		smtc.secretName = certName
		smtc.ref.Key = smtc.secretName
		smtc.certOutput = keyvault.CertificateBundle{
			Cer: &byteArrString, Tags: tagMap,
		}
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		smtc.expectedSecret = jsonTagTestString
	}

	setCertWithNoTags := func(smtc *secretManagerTestCase) {
		byteArrString := []byte(secretCertificate)
		smtc.secretName = certName
		smtc.ref.Key = smtc.secretName
		smtc.certOutput = keyvault.CertificateBundle{
			Cer: &byteArrString,
		}
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		smtc.expectedSecret = "{}"
	}

	setKeyWithTag := func(smtc *secretManagerTestCase) {
		smtc.secretName = keyName
		smtc.keyOutput = keyvault.KeyBundle{
			Key: newKVJWK([]byte(jwkPubRSA)), Tags: tagMap,
		}
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		smtc.ref.Property = tagname
		smtc.expectedSecret = tagvalue
		smtc.ref.Key = smtc.secretName
	}

	badKeyWithTag := func(smtc *secretManagerTestCase) {
		smtc.secretName = keyName
		smtc.ref.Key = smtc.secretName
		smtc.keyOutput = keyvault.KeyBundle{
			Key: newKVJWK([]byte(jwkPubRSA)), Tags: tagMap,
		}
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		smtc.ref.Property = something
		smtc.expectedSecret = ""
		smtc.expectError = errorNoTag
		smtc.apiErr = errors.New(smtc.expectError)
	}

	setKeyWithNoSpecificTag := func(smtc *secretManagerTestCase) {
		smtc.secretName = keyName
		smtc.ref.Key = smtc.secretName
		smtc.keyOutput = keyvault.KeyBundle{
			Key: newKVJWK([]byte(jwkPubRSA)), Tags: tagMap,
		}
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		smtc.expectedSecret = jsonTagTestString
	}

	setKeyWithNoTags := func(smtc *secretManagerTestCase) {
		smtc.secretName = keyName
		smtc.ref.Key = smtc.secretName
		smtc.keyOutput = keyvault.KeyBundle{
			Key: newKVJWK([]byte(jwkPubRSA)),
		}
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		smtc.expectedSecret = "{}"
	}

	badPropertyTag := func(smtc *secretManagerTestCase) {
		smtc.ref.Property = tagname
		smtc.expectedSecret = ""
		smtc.expectError = "property tagname does not exist in key test-secret"
		smtc.apiErr = errors.New(smtc.expectError)
	}

	fetchSingleTag := func(smtc *secretManagerTestCase) {
		jsonString := jsonTestString
		smtc.expectedSecret = bar
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		secretTags := map[string]*string{}
		tagValue := bar
		secretTags[foo] = &tagValue
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &jsonString,
			Tags:  secretTags,
		}
		smtc.ref.Property = foo
	}

	fetchJSONTag := func(smtc *secretManagerTestCase) {
		jsonString := jsonTestString
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		secretTags := map[string]*string{}
		tagValue := "{\"key\":\"value\"}"
		secretTags[foo] = &tagValue
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &jsonString,
			Tags:  secretTags,
		}
		smtc.ref.Property = foo
		smtc.expectedSecret = tagValue
	}

	fetchDottedJSONTag := func(smtc *secretManagerTestCase) {
		jsonString := jsonTestString
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		secretTags := map[string]*string{}
		tagValue := "{\"key\":\"value\"}"
		secretTags[foo] = &tagValue
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &jsonString,
			Tags:  secretTags,
		}
		smtc.ref.Property = "foo.key"
		smtc.expectedSecret = "value"
	}

	fetchNestedJSONTag := func(smtc *secretManagerTestCase) {
		jsonString := jsonTestString
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		secretTags := map[string]*string{}
		tagValue := "{\"key\":\"value\", \"nested\": {\"foo\":\"bar\"}}"
		secretTags["foo"] = &tagValue
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &jsonString,
			Tags:  secretTags,
		}
		smtc.ref.Property = "foo.nested"
		smtc.expectedSecret = "{\"foo\":\"bar\"}"
	}

	fetchNestedDottedJSONTag := func(smtc *secretManagerTestCase) {
		jsonString := jsonTestString
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		secretTags := map[string]*string{}
		tagValue := "{\"key\":\"value\", \"nested\": {\"foo\":\"bar\"}}"
		secretTags[foo] = &tagValue
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &jsonString,
			Tags:  secretTags,
		}
		smtc.ref.Property = "foo.nested.foo"
		smtc.expectedSecret = bar
	}

	fetchDottedKeyJSONTag := func(smtc *secretManagerTestCase) {
		jsonString := jsonTestString
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		secretTags := map[string]*string{}
		tagValue := "{\"foo.json\":\"bar\"}"
		secretTags[foo] = &tagValue
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &jsonString,
			Tags:  secretTags,
		}
		smtc.ref.Property = "foo.foo.json"
		smtc.expectedSecret = bar
	}

	fetchDottedSecretJSONTag := func(smtc *secretManagerTestCase) {
		jsonString := "{\"foo.json\":\"bar\"}"
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &jsonString,
		}
		smtc.ref.Property = "foo.json"
		smtc.expectedSecret = bar
	}

	successCases := []*secretManagerTestCase{
		makeValidSecretManagerTestCase(),
		makeValidSecretManagerTestCaseCustom(setSecretString),
		makeValidSecretManagerTestCaseCustom(setSecretStringWithVersion),
		makeValidSecretManagerTestCaseCustom(setSecretWithProperty),
		makeValidSecretManagerTestCaseCustom(badSecretWithProperty),
		makeValidSecretManagerTestCaseCustom(setPubRSAKey),
		makeValidSecretManagerTestCaseCustom(setPubECKey),
		makeValidSecretManagerTestCaseCustom(secretNotFound),
		makeValidSecretManagerTestCaseCustom(certNotFound),
		makeValidSecretManagerTestCaseCustom(keyNotFound),
		makeValidSecretManagerTestCaseCustom(setCertificate),
		makeValidSecretManagerTestCaseCustom(badSecretType),
		makeValidSecretManagerTestCaseCustom(setSecretWithTag),
		makeValidSecretManagerTestCaseCustom(badSecretWithTag),
		makeValidSecretManagerTestCaseCustom(setSecretWithNoSpecificTag),
		makeValidSecretManagerTestCaseCustom(setSecretWithNoTags),
		makeValidSecretManagerTestCaseCustom(setCertWithTag),
		makeValidSecretManagerTestCaseCustom(badCertWithTag),
		makeValidSecretManagerTestCaseCustom(setCertWithNoSpecificTag),
		makeValidSecretManagerTestCaseCustom(setCertWithNoTags),
		makeValidSecretManagerTestCaseCustom(setKeyWithTag),
		makeValidSecretManagerTestCaseCustom(badKeyWithTag),
		makeValidSecretManagerTestCaseCustom(setKeyWithNoSpecificTag),
		makeValidSecretManagerTestCaseCustom(setKeyWithNoTags),
		makeValidSecretManagerTestCaseCustom(badPropertyTag),
		makeValidSecretManagerTestCaseCustom(fetchSingleTag),
		makeValidSecretManagerTestCaseCustom(fetchJSONTag),
		makeValidSecretManagerTestCaseCustom(fetchDottedJSONTag),
		makeValidSecretManagerTestCaseCustom(fetchNestedJSONTag),
		makeValidSecretManagerTestCaseCustom(fetchNestedDottedJSONTag),
		makeValidSecretManagerTestCaseCustom(fetchDottedKeyJSONTag),
		makeValidSecretManagerTestCaseCustom(fetchDottedSecretJSONTag),
	}

	sm := Azure{
		provider: &esv1.AzureKVProvider{VaultURL: pointer.To(fakeURL)},
	}
	for k, v := range successCases {
		sm.baseClient = v.mockClient
		out, err := sm.GetSecret(context.Background(), *v.ref)
		if !utils.ErrorContains(err, v.expectError) {
			t.Errorf(unexpectedError, k, err.Error(), v.expectError)
		}
		if string(out) != v.expectedSecret {
			t.Errorf("[%d] unexpected secret: expected %s, got %s", k, v.expectedSecret, string(out))
		}
	}
}

func TestAzureKeyVaultSecretManagerGetSecretMap(t *testing.T) {
	secretString := "changedvalue"
	secretCertificate := "certificate_value"
	tagMap := getTagMap()

	badSecretString := func(smtc *secretManagerTestCase) {
		smtc.expectedSecret = secretString
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &secretString,
		}
		smtc.expectError = "error unmarshalling json data: invalid character 'c' looking for beginning of value"
	}

	setSecretJSON := func(smtc *secretManagerTestCase) {
		jsonString := jsonSingleTestString
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &jsonString,
		}
		smtc.expectedData["Name"] = []byte("External")
		smtc.expectedData["LastName"] = []byte("Secret")
	}

	setSecretJSONWithProperty := func(smtc *secretManagerTestCase) {
		jsonString := jsonTestString
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &jsonString,
		}
		smtc.ref.Property = "Address"

		smtc.expectedData["Street"] = []byte("Myroad st.")
		smtc.expectedData["CP"] = []byte("J4K4T4")
	}

	badSecretWithProperty := func(smtc *secretManagerTestCase) {
		jsonString := jsonTestString
		smtc.expectedSecret = ""
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &jsonString,
		}
		smtc.ref.Property = "Age"
		smtc.expectError = fmt.Sprintf("property %s does not exist in key %s", smtc.ref.Property, smtc.ref.Key)
		smtc.apiErr = errors.New(smtc.expectError)
	}

	badPubRSAKey := func(smtc *secretManagerTestCase) {
		smtc.secretName = keyName
		smtc.expectedSecret = jwkPubRSA
		smtc.keyOutput = keyvault.KeyBundle{
			Key: newKVJWK([]byte(jwkPubRSA)),
		}
		smtc.ref.Key = smtc.secretName
		smtc.expectError = "cannot get use dataFrom to get key secret"
	}

	badCertificate := func(smtc *secretManagerTestCase) {
		byteArrString := []byte(secretCertificate)
		smtc.secretName = certName
		smtc.expectedSecret = secretCertificate
		smtc.certOutput = keyvault.CertificateBundle{
			Cer: &byteArrString,
		}
		smtc.ref.Key = smtc.secretName
		smtc.expectError = "cannot get use dataFrom to get certificate secret"
	}

	badSecretType := func(smtc *secretManagerTestCase) {
		smtc.secretName = "name"
		smtc.expectedSecret = ""
		smtc.expectError = fmt.Sprintf("unknown Azure Keyvault object Type for %s", smtc.secretName)
		smtc.ref.Key = fmt.Sprintf("example/%s", smtc.secretName)
	}

	setSecretTags := func(smtc *secretManagerTestCase) {
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		smtc.secretOutput = keyvault.SecretBundle{
			Tags: tagMap,
		}
		smtc.expectedData[testsecret+"_"+tagname] = []byte(tagvalue)
		smtc.expectedData[testsecret+"_"+tagname2] = []byte(tagvalue2)
	}

	setSecretWithJSONTag := func(smtc *secretManagerTestCase) {
		tagJSONMap := make(map[string]*string)
		tagJSONData := `{"keyname":"keyvalue","x":"y"}`
		tagJSONMap["json"] = &tagJSONData
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &secretString, Tags: tagJSONMap,
		}
		smtc.expectedData[testsecret+"_json_keyname"] = []byte("keyvalue")
		smtc.expectedData[testsecret+"_json_x"] = []byte("y")
	}

	setSecretWithNoTags := func(smtc *secretManagerTestCase) {
		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		tagMapTestEmpty := make(map[string]*string)
		smtc.secretOutput = keyvault.SecretBundle{
			Tags: tagMapTestEmpty,
		}
		smtc.expectedSecret = ""
	}

	nestedJSONNoProperty := func(smtc *secretManagerTestCase) {
		jsonString := jsonTestString
		smtc.expectedSecret = ""
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &jsonString,
		}
		smtc.ref.Property = ""
		smtc.expectedData["Name"] = []byte("External")
		smtc.expectedData["LastName"] = []byte("Secret")
		smtc.expectedData["Address"] = []byte(`{ "Street": "Myroad st.", "CP": "J4K4T4" }`)
	}

	setNestedJSONTag := func(smtc *secretManagerTestCase) {
		secretTags := map[string]*string{}
		tagValue := `{"foo":"bar","nested.tag":{"foo":"bar"}}`
		bug := "1137"
		secretTags["dev"] = &tagValue
		secretTags["bug"] = &bug

		smtc.ref.MetadataPolicy = esv1.ExternalSecretMetadataPolicyFetch
		smtc.secretOutput = keyvault.SecretBundle{
			Tags: secretTags,
		}
		smtc.ref.Property = "dev"
		smtc.expectedData[testsecret+"_dev"] = []byte(tagValue)
	}

	successCases := []*secretManagerTestCase{
		makeValidSecretManagerTestCaseCustom(badSecretString),
		makeValidSecretManagerTestCaseCustom(setSecretJSON),
		makeValidSecretManagerTestCaseCustom(setSecretJSONWithProperty),
		makeValidSecretManagerTestCaseCustom(badSecretWithProperty),
		makeValidSecretManagerTestCaseCustom(badPubRSAKey),
		makeValidSecretManagerTestCaseCustom(badCertificate),
		makeValidSecretManagerTestCaseCustom(badSecretType),
		makeValidSecretManagerTestCaseCustom(setSecretTags),
		makeValidSecretManagerTestCaseCustom(setSecretWithJSONTag),
		makeValidSecretManagerTestCaseCustom(setSecretWithNoTags),
		makeValidSecretManagerTestCaseCustom(nestedJSONNoProperty),
		makeValidSecretManagerTestCaseCustom(setNestedJSONTag),
	}

	sm := Azure{
		provider: &esv1.AzureKVProvider{VaultURL: pointer.To(fakeURL)},
	}
	for k, v := range successCases {
		sm.baseClient = v.mockClient
		out, err := sm.GetSecretMap(context.Background(), *v.ref)
		if !utils.ErrorContains(err, v.expectError) {
			t.Errorf(unexpectedError, k, err.Error(), v.expectError)
		}
		if err == nil && !reflect.DeepEqual(out, v.expectedData) {
			t.Errorf(unexpectedSecretData, k, v.expectedData, out)
		}
	}
}

func TestAzureKeyVaultSecretManagerGetAllSecrets(t *testing.T) {
	secretString := secretString
	secretName := secretName
	wrongName := "not-valid"
	environment := "dev"
	author := "seb"
	enabled := true

	getNextPage := func(ctx context.Context, list keyvault.SecretListResult) (result keyvault.SecretListResult, err error) {
		return keyvault.SecretListResult{
			Value:    nil,
			NextLink: nil,
		}, nil
	}

	setOneSecretByName := func(smtc *secretManagerTestCase) {
		enabledAtt := keyvault.SecretAttributes{
			Enabled: &enabled,
		}
		secretItem := keyvault.SecretItem{
			ID:         &secretName,
			Attributes: &enabledAtt,
		}

		list := keyvault.SecretListResult{
			Value: &[]keyvault.SecretItem{secretItem},
		}

		resultPage := keyvault.NewSecretListResultPage(list, getNextPage)
		smtc.listOutput = keyvault.NewSecretListResultIterator(resultPage)

		smtc.expectedSecret = secretString
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &secretString,
		}

		smtc.expectedData[secretName] = []byte(secretString)
	}

	setTwoSecretsByName := func(smtc *secretManagerTestCase) {
		enabledAtt := keyvault.SecretAttributes{
			Enabled: &enabled,
		}
		secretItemOne := keyvault.SecretItem{
			ID:         &secretName,
			Attributes: &enabledAtt,
		}

		secretItemTwo := keyvault.SecretItem{
			ID:         &wrongName,
			Attributes: &enabledAtt,
		}

		list := keyvault.SecretListResult{
			Value: &[]keyvault.SecretItem{secretItemOne, secretItemTwo},
		}

		resultPage := keyvault.NewSecretListResultPage(list, getNextPage)
		smtc.listOutput = keyvault.NewSecretListResultIterator(resultPage)

		smtc.expectedSecret = secretString
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &secretString,
		}

		smtc.expectedData[secretName] = []byte(secretString)
	}

	setOneSecretByTag := func(smtc *secretManagerTestCase) {
		enabledAtt := keyvault.SecretAttributes{
			Enabled: &enabled,
		}
		secretItem := keyvault.SecretItem{
			ID:         &secretName,
			Attributes: &enabledAtt,
			Tags:       map[string]*string{"environment": &environment},
		}

		list := keyvault.SecretListResult{
			Value: &[]keyvault.SecretItem{secretItem},
		}

		resultPage := keyvault.NewSecretListResultPage(list, getNextPage)
		smtc.listOutput = keyvault.NewSecretListResultIterator(resultPage)

		smtc.expectedSecret = secretString
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &secretString,
		}
		smtc.refFind.Tags = map[string]string{"environment": environment}

		smtc.expectedData[secretName] = []byte(secretString)
	}

	setTwoSecretsByTag := func(smtc *secretManagerTestCase) {
		enabled := true
		enabledAtt := keyvault.SecretAttributes{
			Enabled: &enabled,
		}
		secretItem := keyvault.SecretItem{
			ID:         &secretName,
			Attributes: &enabledAtt,
			Tags:       map[string]*string{"environment": &environment, "author": &author},
		}

		list := keyvault.SecretListResult{
			Value: &[]keyvault.SecretItem{secretItem},
		}

		resultPage := keyvault.NewSecretListResultPage(list, getNextPage)
		smtc.listOutput = keyvault.NewSecretListResultIterator(resultPage)

		smtc.expectedSecret = secretString
		smtc.secretOutput = keyvault.SecretBundle{
			Value: &secretString,
		}
		smtc.refFind.Tags = map[string]string{"environment": environment, "author": author}

		smtc.expectedData[secretName] = []byte(secretString)
	}

	successCases := []*secretManagerTestCase{
		makeValidSecretManagerTestCaseCustom(setOneSecretByName),
		makeValidSecretManagerTestCaseCustom(setTwoSecretsByName),
		makeValidSecretManagerTestCaseCustom(setOneSecretByTag),
		makeValidSecretManagerTestCaseCustom(setTwoSecretsByTag),
	}

	sm := Azure{
		provider: &esv1.AzureKVProvider{VaultURL: pointer.To(fakeURL)},
	}
	for k, v := range successCases {
		sm.baseClient = v.mockClient
		out, err := sm.GetAllSecrets(context.Background(), *v.refFind)
		if !utils.ErrorContains(err, v.expectError) {
			t.Errorf(unexpectedError, k, err.Error(), v.expectError)
		}
		if err == nil && !reflect.DeepEqual(out, v.expectedData) {
			t.Errorf(unexpectedSecretData, k, v.expectedData, out)
		}
	}
}

func makeValidRef() *esv1.ExternalSecretDataRemoteRef {
	return &esv1.ExternalSecretDataRemoteRef{
		Key:      "test-secret",
		Version:  "default",
		Property: "",
	}
}

func makeValidFind() *esv1.ExternalSecretFind {
	return &esv1.ExternalSecretFind{
		Name: &esv1.FindName{
			RegExp: "^example",
		},
		Tags: map[string]string{},
	}
}

func TestValidateStore(t *testing.T) {
	type args struct {
		store *esv1.SecretStore
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "storeIsNil",
			wantErr: true,
		},
		{
			name:    "specIsNil",
			wantErr: true,
			args: args{
				store: &esv1.SecretStore{},
			},
		},
		{
			name:    "providerIsNil",
			wantErr: true,
			args: args{
				store: &esv1.SecretStore{
					Spec: esv1.SecretStoreSpec{},
				},
			},
		},
		{
			name:    "azureKVIsNil",
			wantErr: true,
			args: args{
				store: &esv1.SecretStore{
					Spec: esv1.SecretStoreSpec{
						Provider: &esv1.SecretStoreProvider{},
					},
				},
			},
		},
		{
			name:    "empty auth",
			wantErr: false,
			args: args{
				store: &esv1.SecretStore{
					Spec: esv1.SecretStoreSpec{
						Provider: &esv1.SecretStoreProvider{
							AzureKV: &esv1.AzureKVProvider{},
						},
					},
				},
			},
		},
		{
			name:    "empty client id",
			wantErr: false,
			args: args{
				store: &esv1.SecretStore{
					Spec: esv1.SecretStoreSpec{
						Provider: &esv1.SecretStoreProvider{
							AzureKV: &esv1.AzureKVProvider{
								AuthSecretRef: &esv1.AzureKVAuth{},
							},
						},
					},
				},
			},
		},
		{
			name:    "invalid client id",
			wantErr: true,
			args: args{
				store: &esv1.SecretStore{
					Spec: esv1.SecretStoreSpec{
						Provider: &esv1.SecretStoreProvider{
							AzureKV: &esv1.AzureKVProvider{
								AuthSecretRef: &esv1.AzureKVAuth{
									ClientID: &v1.SecretKeySelector{
										Namespace: pointer.To("invalid"),
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:    "invalid client secret",
			wantErr: true,
			args: args{
				store: &esv1.SecretStore{
					Spec: esv1.SecretStoreSpec{
						Provider: &esv1.SecretStoreProvider{
							AzureKV: &esv1.AzureKVProvider{
								AuthSecretRef: &esv1.AzureKVAuth{
									ClientSecret: &v1.SecretKeySelector{
										Namespace: pointer.To("invalid"),
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Azure{}
			if tt.name == "storeIsNil" {
				if _, err := a.ValidateStore(nil); (err != nil) != tt.wantErr {
					t.Errorf(errStore, err, tt.wantErr)
				}
			} else if _, err := a.ValidateStore(tt.args.store); (err != nil) != tt.wantErr {
				t.Errorf(errStore, err, tt.wantErr)
			}
		})
	}
}

func TestAzureKeyVaultSecretExists(t *testing.T) {
	unsupportedType := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: "yadayada/foo",
		}
		smtc.expectError = "secret type 'yadayada' is not supported"
	}

	secretFound := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: secretName,
		}
		smtc.secretOutput = keyvault.SecretBundle{
			Tags: map[string]*string{
				"managed-by": pointer.To(externalSecrets),
			},
			Value: pointer.To("foo"),
		}
		smtc.expectedExistence = true
	}

	secretFoundNoUsefulTags := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: secretName,
		}
		smtc.secretOutput = keyvault.SecretBundle{
			Tags: map[string]*string{
				"someTag": pointer.To("someUselessValue"),
			},
			Value: pointer.To("foo"),
		}
		smtc.expectedExistence = true
	}

	secretNotFound := func(smtc *secretManagerTestCase) {
		smtc.pushData = testingfake.PushSecretData{
			RemoteKey: secretName,
		}
		smtc.apiErr = autorest.DetailedError{StatusCode: 404, Method: "GET", Message: notFoundMessage}
		smtc.expectedExistence = false
	}

	testCases := []*secretManagerTestCase{
		makeValidSecretManagerTestCaseCustom(unsupportedType),
		makeValidSecretManagerTestCaseCustom(secretFound),
		makeValidSecretManagerTestCaseCustom(secretFoundNoUsefulTags),
		makeValidSecretManagerTestCaseCustom(secretNotFound),
	}

	sm := Azure{
		provider: &esv1.AzureKVProvider{VaultURL: pointer.To(fakeURL)},
	}

	for k, tc := range testCases {
		sm.baseClient = tc.mockClient
		exists, err := sm.SecretExists(context.Background(), tc.pushData)

		if !utils.ErrorContains(err, tc.expectError) {
			if err == nil {
				t.Errorf("[%d] unexpected error: <nil>, expected: '%s'", k, tc.expectError)
			} else {
				t.Errorf("[%d] unexpected error: '%s', expected: '%s'", k, err.Error(), tc.expectError)
			}
		}

		if exists != tc.expectedExistence {
			t.Errorf("[%d] unexpected existence result: expected %t, got %t", k, tc.expectedExistence, exists)
		}
	}
}
