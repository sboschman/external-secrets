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

package ecr

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecr/ecriface"
	"github.com/aws/aws-sdk-go/service/ecrpublic"
	"github.com/aws/aws-sdk-go/service/ecrpublic/ecrpubliciface"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	genv1alpha1 "github.com/external-secrets/external-secrets/apis/generators/v1alpha1"
	awsauth "github.com/external-secrets/external-secrets/pkg/provider/aws/auth"
)

type Generator struct{}

const (
	errNoSpec          = "no config spec provided"
	errParseSpec       = "unable to parse spec: %w"
	errCreateSess      = "unable to create aws session: %w"
	errGetPrivateToken = "unable to get authorization token: %w"
	errGetPublicToken  = "unable to get public authorization token: %w"
)

func (g *Generator) Generate(ctx context.Context, jsonSpec *apiextensions.JSON, kube client.Client, namespace string) (map[string][]byte, genv1alpha1.GeneratorProviderState, error) {
	return g.generate(ctx, jsonSpec, kube, namespace, ecrPrivateFactory, ecrPublicFactory)
}

func (g *Generator) Cleanup(ctx context.Context, jsonSpec *apiextensions.JSON, _ genv1alpha1.GeneratorProviderState, crClient client.Client, namespace string) error {
	return nil
}

func (g *Generator) generate(
	ctx context.Context,
	jsonSpec *apiextensions.JSON,
	kube client.Client,
	namespace string,
	ecrPrivateFunc ecrPrivateFactoryFunc,
	ecrPublicFunc ecrPublicFactoryFunc,
) (map[string][]byte, genv1alpha1.GeneratorProviderState, error) {
	if jsonSpec == nil {
		return nil, nil, errors.New(errNoSpec)
	}
	res, err := parseSpec(jsonSpec.Raw)
	if err != nil {
		return nil, nil, fmt.Errorf(errParseSpec, err)
	}
	sess, err := awsauth.NewGeneratorSession(
		ctx,
		esv1.AWSAuth{
			SecretRef: (*esv1.AWSAuthSecretRef)(res.Spec.Auth.SecretRef),
			JWTAuth:   (*esv1.AWSJWTAuth)(res.Spec.Auth.JWTAuth),
		},
		res.Spec.Role,
		res.Spec.Region,
		kube,
		namespace,
		awsauth.DefaultSTSProvider,
		awsauth.DefaultJWTProvider)
	if err != nil {
		return nil, nil, fmt.Errorf(errCreateSess, err)
	}

	if res.Spec.Scope == "public" {
		return fetchECRPublicToken(sess, ecrPublicFunc)
	}

	return fetchECRPrivateToken(sess, ecrPrivateFunc)
}

func fetchECRPrivateToken(sess *session.Session, ecrPrivateFunc ecrPrivateFactoryFunc) (map[string][]byte, genv1alpha1.GeneratorProviderState, error) {
	client := ecrPrivateFunc(sess)
	out, err := client.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, nil, fmt.Errorf(errGetPrivateToken, err)
	}
	if len(out.AuthorizationData) != 1 {
		return nil, nil, fmt.Errorf("unexpected number of authorization tokens. expected 1, found %d", len(out.AuthorizationData))
	}

	// AuthorizationToken is base64 encoded {username}:{password} string
	decodedToken, err := base64.StdEncoding.DecodeString(*out.AuthorizationData[0].AuthorizationToken)
	if err != nil {
		return nil, nil, err
	}
	parts := strings.Split(string(decodedToken), ":")
	if len(parts) != 2 {
		return nil, nil, errors.New("unexpected token format")
	}

	exp := out.AuthorizationData[0].ExpiresAt.UTC().Unix()
	return map[string][]byte{
		"username":       []byte(parts[0]),
		"password":       []byte(parts[1]),
		"proxy_endpoint": []byte(*out.AuthorizationData[0].ProxyEndpoint),
		"expires_at":     []byte(strconv.FormatInt(exp, 10)),
	}, nil, nil
}

func fetchECRPublicToken(sess *session.Session, ecrPublicFunc ecrPublicFactoryFunc) (map[string][]byte, genv1alpha1.GeneratorProviderState, error) {
	client := ecrPublicFunc(sess)
	out, err := client.GetAuthorizationToken(&ecrpublic.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, nil, fmt.Errorf(errGetPublicToken, err)
	}

	decodedToken, err := base64.StdEncoding.DecodeString(*out.AuthorizationData.AuthorizationToken)
	if err != nil {
		return nil, nil, err
	}
	parts := strings.Split(string(decodedToken), ":")
	if len(parts) != 2 {
		return nil, nil, errors.New("unexpected token format")
	}

	exp := out.AuthorizationData.ExpiresAt.UTC().Unix()
	return map[string][]byte{
		"username":   []byte(parts[0]),
		"password":   []byte(parts[1]),
		"expires_at": []byte(strconv.FormatInt(exp, 10)),
	}, nil, nil
}

type ecrPrivateFactoryFunc func(aws *session.Session) ecriface.ECRAPI
type ecrPublicFactoryFunc func(aws *session.Session) ecrpubliciface.ECRPublicAPI

func ecrPrivateFactory(aws *session.Session) ecriface.ECRAPI {
	return ecr.New(aws)
}

func ecrPublicFactory(aws *session.Session) ecrpubliciface.ECRPublicAPI {
	return ecrpublic.New(aws)
}

func parseSpec(data []byte) (*genv1alpha1.ECRAuthorizationToken, error) {
	var spec genv1alpha1.ECRAuthorizationToken
	err := yaml.Unmarshal(data, &spec)
	return &spec, err
}

func init() {
	genv1alpha1.Register(genv1alpha1.ECRAuthorizationTokenKind, &Generator{})
}
