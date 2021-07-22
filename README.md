# Vault Secrets Plugin for GCP OIDC and JWTAccess Tokens


Fork of [vault-plugin-secrets-gcp](https://github.com/hashicorp/vault-plugin-secrets-gcp)
with experimental support for

* [Google OIDC tokens](https://github.com/salrashid123/salrashid123.github.io/tree/master/google_id_token)
  [https://github.com/hashicorp/vault-plugin-secrets-gcp/issues/46](https://github.com/hashicorp/vault-plugin-secrets-gcp/issues/46)

* [JwtAccessToken](https://medium.com/google-cloud/faster-serviceaccount-authentication-for-google-cloud-platform-apis-f1355abc14b2)
  [https://github.com/hashicorp/vault-plugin-secrets-gcp/issues/47](https://github.com/hashicorp/vault-plugin-secrets-gcp/issues/47)

>> This repo is NOT supported by google!


Reference:
- [https://github.com/salrashid123/vault_gcp](https://github.com/salrashid123/vault_gcp)

was looking at this for a diff reason today and decided to update it with HEAD.  attached are the modifications and the working usage for `id_token` and `jwt_access_token`.  The id_token capability shoudl work for iap if you set the audience value correctly

if there is interest in having additional secret types based on the existing way to get access and service account jwt, the files attached to this issue at the bottom could be used as working start point (i'd submit it fully but don't know how to writeup the testcases at all)


1. Compile

```bash
export GOBIN=`pwd`/bin
make fmt
make dev

vault server -dev -dev-plugin-dir=./bin --log-level=debug
```


2. New window

load plugin

```bash
export VAULT_ADDR='http://localhost:8200'

export SHASUM=$(shasum -a 256 "bin/vault-plugin-secrets-gcp" | cut -d " " -f1)

vault plugin register \
    -sha256="${SHASUM}" \
    -command="vault-plugin-secrets-gcp" \
    secret vault-plugin-secrets-gcp

vault secrets enable --plugin-name='vault-plugin-secrets-gcp' --path="gcp" plugin
```


### OIDC Token


Create Roleset

```bash
vault write gcp/roleset/my-idtoken-roleset    \
   project="pubsub-msg"   \
   secret_type="id_token"  \
   audience="https://foo.bar"   \
   bindings=-<<EOF
resource "//cloudresourcemanager.googleapis.com/projects/pubsub-msg" {
    roles = []  
}
EOF
```


Create VAULT_TOKEN with policy

```bash
vault policy write idtoken-policy -<<EOF
path "gcp/idtoken/my-idtoken-roleset" {
    capabilities = ["read"]
}
EOF

vault token create -policy=idtoken-policy
```

Copy VAULT_TOKEN to new window and access secret

```bash
export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN=s.gSREOoTDI5vGZwHQKW1w43Fl
vault read gcp/idtoken/my-idtoken-roleset
```

Gives:

```bash
vault read gcp/idtoken/my-idtoken-roleset
Key                   Value
---                   -----
expires_at_seconds    1626814203
id_token              eyJhbGciOiJSUzI1NiIsImtpZCI6IjdmNTQ4ZjY3MDg2OTBjMjExMjBiMGFiNjY4Y2FhMDc5YWNiYzJiMmYiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJhenAiOiJ2YXVsdG15LWlkdG9rZW4tcm9sLTE2MjY4MTAyMjZAcHVic3ViLW1zZy5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbSIsImVtYWlsIjoidmF1bHRteS1pZHRva2VuLXJvbC0xNjI2ODEwMjI2QHB1YnN1Yi1tc2cuaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZXhwIjoxNjI2ODE0MjAzLCJpYXQiOjE2MjY4MTA2MDMsImlzcyI6Imh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbSIsInN1YiI6IjExNDQ2ODQ5MDY4NDEwMzk1MjMzNCJ9.kXAtujjYBfheS2-kNytjHVnn4s0-xtS2FtRGcZXlhbv54zastjKmVQTa0BeH3F4MJd2JPbT30J9ioucf0c5y516DvX3ot70ktcbq9b4-93jYnK9sotJX-1iucSk108kzplcKESTcxUAO_I5EAhvUkQfiFbsseF6eoPK7jN3SKD5KiZYgKKHgVHyuUcwLcHoo5-RTa3RguhBrLVugw9LTHZkcS7EFhR08d0VS2gdrTQGAjMS7uB-lRHdz7VQVXxVeX-teYbk8ln5XCh6OTozFRg5ENwp6EL3IH8flZUi7GHCkfXjGcMNqJR8vaN5yN68coZJJuiEh4S6waCrj4cnBhQ
token_ttl             59m59s
```

gives an id_token with 
```json
{
  "aud": "https://foo.bar",
  "azp": "vaultmy-idtoken-rol-1626810226@pubsub-msg.iam.gserviceaccount.com",
  "email": "vaultmy-idtoken-rol-1626810226@pubsub-msg.iam.gserviceaccount.com",
  "email_verified": true,
  "exp": 1626814203,
  "iat": 1626810603,
  "iss": "https://accounts.google.com",
  "sub": "114468490684103952334"
}
```

---

## JWTAccessToken

```bash
vault write gcp/roleset/my-jwttoken-roleset    \
   project="pubsub-msg"   \
   secret_type="jwt_access_token"  \
   audience="https://pubsub.googleapis.com/google.pubsub.v1.Publisher"   \
   bindings=-<<EOF
resource "projects/pubsub-msg" {
    roles = ["roles/pubsub.admin"]  
}
EOF


vault policy write jwttoken-policy -<<EOF
path "gcp/jwtaccess/my-jwttoken-roleset" {
    capabilities = ["read"]
}
EOF

vault token create -policy=jwttoken-policy
```

copy `VAULT_TOKEN` to new window

```bash
export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN=s.W73ewt7HJ8JEClRUYkx4UxaW


$ vault read gcp/jwtaccess/my-jwttoken-roleset
Key                   Value
---                   -----
expires_at_seconds    1626814668
jwt_access_token      eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjZkZTBlZDI0Mzc5MmQ2MjVmNjM2MzllMzU0Njg4NDIyM2JmZGUxZmUifQ.eyJpc3MiOiJ2YXVsdG15LWp3dHRva2VuLXJvLTE2MjY4MTA3NTJAcHVic3ViLW1zZy5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbSIsImF1ZCI6Imh0dHBzOi8vZm9vLmJhciIsImV4cCI6MTYyNjgxNDY2OCwiaWF0IjoxNjI2ODExMDY4LCJzdWIiOiJ2YXVsdG15LWp3dHRva2VuLXJvLTE2MjY4MTA3NTJAcHVic3ViLW1zZy5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbSJ9.euCJI5w0_nwBICRCoyQZvKc03CxaXXbRdcLH0I_uJJj8oLsLIUITLOlkHkvZiPgcwvY5OELaWt4i04MkaY3ou6ObSp7UcxIeYqVBtPc-4gIX6sm-wHHFRT5EXHXkEX4wD8FXhxiBDduLYtoZP_Njx1IV0B1que5njN8hqgPsn917KwzuWH_7GZA1UcYxkX5Gq3O13UMk9H8-O-djM-mIaF75juiVAo77EiWfcdiDuHzgyrSWNZ0NeusGrhc9V8ZGTs28reFotnrMjMiH0Nygdd1syTJBKdgoNpN_9VOoLViXv5pGrDf5-GUXUjTyDwEUaNBJ1BV7vbLNXLvG5HsHfQ
token_ttl             59m59s
```

gives JWTAccessToken of form 

```json
{
  "iss": "vaultmy-jwttoken-ro-1626810752@pubsub-msg.iam.gserviceaccount.com",
  "aud": "https://pubsub.googleapis.com/google.pubsub.v1.Publisher",
  "exp": 1626814668,
  "iat": 1626811068,
  "sub": "vaultmy-jwttoken-ro-1626810752@pubsub-msg.iam.gserviceaccount.com"
}
```
### DELETE

```bash
vault delete gcp/roleset/my-jwttoken-roleset

vault delete gcp/roleset/my-idtoken-roleset
```