External Secrets Operator integrates with [Topicus KeyHub](https://www.topicus-keyhub.com/en/) to sync KeyHub vault records into a Kubernetes cluster.

## Creating a SecretStore

To connect to Topicus KeyHub an OAuth2/OIDC application (use the `Server-side web application` profile) has to be created. Grant the application the `Groups - Access the vault of a group` permission to every group/vault you want to sync secrets with.

Create a `Secret` with the client identifier and secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: keyhub-client-credentials
stringData:
  clientId: <CLIENT_ID>
  clientSecret: <CLIENT_SECRET>
```

Next, you can create a `ClusterSecretStore` (or `SecretStore`):

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: keyhub
spec:
  provider:
    keyhub:
      issuer: <YOUR_TOPICUS_KEYHUB_URL>
      auth:
        secretRef:
          name: keyhub-client-credentials
          namespace: default
```

## Referencing Secrets

Secrets can be referenced by their vault record UUID and optionally a property. If no property is specified the `password` property is returned. See the section [supported properties](#supported-properties) for all available properties.

```yaml
data:
- secretKey: password
  remoteRef:
    key: <VAULT_RECORD_UUID>
    property: password
```

**NOTE:** Specifying a `version` is not supported.

### Fetching all properties

To fetch multiple properties of a single vault record use the `extract` option, e.g.:

```yaml
dataFrom:
- extract:
    key: <VAULT_RECORD_UUID>
```

The `property` field can be used as well to return just a single property, e.g.:

```yaml
dataFrom:
- extract:
    key: <VAULT_RECORD_UUID>
    property: password
```

**NOTE:** Specifying a `version` is not supported.

### Find by Path or Name

Instead of retrieving secrets by their vault record UUID you can also use `dataFrom` to search for secrets by vault UUID or name. To only search within a specific vault, the `path` can be set to the UUID of the vault.

```yaml
dataFrom:
- find:
    path: <VAULT_UUID>
    name:
      regexp: ".*"
```

In case multiple secrets are returned, the keys for the individual properties are as follows `<vault record name>/<property>`, e.g. `My API key/password`.
If only a single secret matches the find query the keys are simply the property name. See the section [supported properties](#supported-properties) for the properties returned this way.

**NOTE:** Finding secrets by tag is not supported.

### Supported properties

The following table lists the KeyHub vault record properties supported by this provider:

| Property | With `spec.data` | With `spec.dataFrom`</br>(single property) | With `spec.dataFrom`</br>(all properties) |
| --- | :-------: | :-------: | :-------: |
| name | x | x | |
| color | x | x | |
| link | x | x | x |
| username | x | x | x |
| password | x | x | x |
| filename | x | x | |
| file | x | x | x |
| enddate | x | x | |
| comment | x | x | |
| lastModifiedBy | x | x | |
| lastModifiedAt | x | x | |

**NOTE:** Using `dataFrom` only non-empty properties are returned, using `data` an empty value is returned in case the specified property is empty in KeyHub.

## Examples

### Basic authentication Secret

You can create a Secret of type `kubernetes.io/basic-auth`, using `spec.template` as a blueprint, mapping
the KeyHub vault record properties `username` and `password` using `spec.data`.

``` yaml
{% include "keyhub-basic-auth-1.yaml" %}
```

Alternatively, if the KeyHub vault record only defines the `username` and `password` properties, the `spec.dataFrom` field can be used to include the relevant KeyHub vault record properties.

``` yaml
{% include "keyhub-basic-auth-2.yaml" %}
```
