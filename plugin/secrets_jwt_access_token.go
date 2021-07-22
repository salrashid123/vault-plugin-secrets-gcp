package gcpsecrets

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jws"
)

func pathSecretJwtAccessToken(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("jwtaccess/%s", framework.GenericNameRegex("roleset")),
		Fields: map[string]*framework.FieldSchema{
			"roleset": {
				Type:        framework.TypeString,
				Description: "Required. Name of the role set.",
			},
		},
		ExistenceCheck: b.pathRoleSetExistenceCheck("roleset"),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathJwtAccessToken,
			logical.UpdateOperation: b.pathJwtAccessToken,
		},
		HelpSynopsis:    pathJwtAccessTokenHelpSyn,
		HelpDescription: pathJwtAccessTokenHelpDesc,
	}
}

func (b *backend) pathJwtAccessToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	rsName := d.Get("roleset").(string)

	rs, err := getRoleSet(rsName, ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if rs == nil {
		return logical.ErrorResponse("role set '%s' does not exists", rsName), nil
	}

	if rs.SecretType != SecretTypeJwtAccessToken {
		return logical.ErrorResponse("role set '%s' cannot generate jwt (has secret type %s)", rsName, rs.SecretType), nil
	}

	return b.secretJwtAccessTokenResponse(ctx, req.Storage, rs)
}

func (b *backend) secretJwtAccessTokenResponse(ctx context.Context, s logical.Storage, rs *RoleSet) (*logical.Response, error) {
	if rs.TokenGen == nil || rs.TokenGen.KeyName == "" {
		return logical.ErrorResponse("invalid role set has no service account key, must be updated (path roleset/%s/rotate-key) before generating new secrets", rs.Name), nil
	}

	token, err := rs.TokenGen.getJwtAccessToken(ctx)
	if err != nil {
		return logical.ErrorResponse("unable to generate token - make sure your roleset service account and key are still valid: %v", err), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"jwt_access_token":   token.AccessToken,
			"token_ttl":          token.Expiry.UTC().Sub(time.Now().UTC()) / (time.Second),
			"expires_at_seconds": token.Expiry.Unix(),
		},
	}, nil
}

func (tg *TokenGenerator) getJwtAccessToken(ctx context.Context) (*oauth2.Token, error) {

	jsonBytes, err := base64.StdEncoding.DecodeString(tg.B64KeyJSON)
	if err != nil {
		return nil, errwrap.Wrapf("could not b64-decode key data: {{err}}", err)
	}

	conf, err := google.JWTConfigFromJSON(jsonBytes, "")
	if err != nil {
		return nil, errwrap.Wrapf("could not generate token JWT config: {{err}}", err)
	}

	header := &jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
		KeyID:     conf.PrivateKeyID,
	}

	iat := time.Now()
	exp := iat.Add(time.Hour)

	payload := &jws.ClaimSet{
		Iss: conf.Email,
		Iat: iat.Unix(),
		Exp: exp.Unix(),
		Aud: tg.Audience,
		Sub: conf.Email,
	}

	key := conf.PrivateKey
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(key)
		if err != nil {
			return nil, errwrap.Wrapf("id_token: PrivateKey is invalid: {{err}}", err)
		}
	}
	parsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errwrap.Wrapf("id_token: PrivateKey is invalid: {{err}}", err)
	}

	idToken, err := jws.Encode(header, payload, parsed)
	if err != nil {
		return nil, errwrap.Wrapf("could not generate token JWT config: {{err}}", err)
	}

	tkn := &oauth2.Token{
		AccessToken: idToken,
		Expiry:      exp,
	}

	return tkn, err
}

const jwtdeprecationWarning = `
This endpoint no longer generates leases due to limitations of the GCP API, as OAuth2 tokens belonging to Service
Accounts cannot be revoked. This access_token and lease were created by a previous version of the GCP secrets
engine and will be cleaned up now. Note that there is the chance that this access_token, if not already expired,
will still be valid up to one hour.
`

const pathJwtAccessTokenHelpSyn = `Generate an OAuth2 access token under a specific role set.`
const pathJwtAccessTokenHelpDesc = `
This path will generate a new OAuth2 access token for accessing GCP APIs.
A role set, binding IAM roles to specific GCP resources, will be specified
by name - for example, if this backend is mounted at "gcp",
then "gcp/token/deploy" would generate tokens for the "deploy" role set.

On the backend, each roleset is associated with a service account.
The token will be associated with this service account. Tokens have a
short-term lease (1-hour) associated with them but cannot be renewed.

Please see backend documentation for more information:
https://www.vaultproject.io/docs/secrets/gcp/index.html
`

// EVERYTHING USING THIS SECRET TYPE IS CURRENTLY DEPRECATED.
// We keep it to allow for clean up of access_token secrets/leases that may have be left over
// by older versions of Vault.
const SecretTypeJwtAccessToken = "jwt_access_token"

func secretJwtAccessToken(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: SecretTypeJwtAccessToken,
		Fields: map[string]*framework.FieldSchema{
			"jwtaccess": {
				Type:        framework.TypeString,
				Description: "JwtAccess token",
			},
		},
		Renew:  b.secretJwtAccessTokenRenew,
		Revoke: b.secretJwtAccessTokenRevoke,
	}
}

// Renewal will still return an error, but return the warning in case as well.
func (b *backend) secretJwtAccessTokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := logical.ErrorResponse("short-term access tokens cannot be renewed - request new access token instead")
	resp.AddWarning(jwtdeprecationWarning)
	return resp, nil
}

// Revoke will no-op and pass but warn the user. This is mostly to clean up old leases.
// Any associated secret (access_token) has already expired and thus doesn't need to
// actually be revoked,  or will expire within an hour and currently can't actually be revoked anyways.
func (b *backend) secretJwtAccessTokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{}
	resp.AddWarning(jwtdeprecationWarning)
	return resp, nil
}
