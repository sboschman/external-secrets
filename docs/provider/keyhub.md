intro

## Creating a SecretStore

auth stuff

## Referencing Secrets

info

### Examples

examples

#### Basic authentication Secret

You can create a Secret of type `kubernetes.io/basic-auth`, using `spec.template` as a blueprint, mapping
the KeyHub vault record fields `username` and `password` using `spec.data`.

``` yaml
{% include "keyhub-basic-auth-1.yaml" %}
```

Alternatively, if the KeyHub vault record only defines the `username` and `password` fields (as fields marked for inclusion when fetching 'all' properties), the `spec.dataFrom` field can be used to include the relevant KeyHub vault record fields.

``` yaml
{% include "keyhub-basic-auth-2.yaml" %}
```
