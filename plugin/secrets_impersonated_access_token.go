package gcpsecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/oauth2"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

func pathSecretImpersonatedAccessToken(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("impersonatedtoken/%s", framework.GenericNameRegex("roleset")),
		Fields: map[string]*framework.FieldSchema{
			"roleset": {
				Type:        framework.TypeString,
				Description: "Required. Name of the role set.",
			},
		},
		ExistenceCheck: b.pathRoleSetExistenceCheck("roleset"),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathImpersonatedAccessToken,
			logical.UpdateOperation: b.pathImpersonatedAccessToken,
		},
		HelpSynopsis:    pathJwtAccessTokenHelpSyn,
		HelpDescription: pathJwtAccessTokenHelpDesc,
	}
}

func (b *backend) pathImpersonatedAccessToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	rsName := d.Get("roleset").(string)

	rs, err := getRoleSet(rsName, ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if rs == nil {
		return logical.ErrorResponse("role set '%s' does not exists", rsName), nil
	}

	if rs.SecretType != SecretTypeImpersonatedAccessToken {
		return logical.ErrorResponse("role set '%s' cannot generate Impersonated (has secret type %s)", rsName, rs.SecretType), nil
	}

	return b.secretImpersonatedAccessTokenResponse(ctx, req.Storage, rs, d)
}

func (b *backend) secretImpersonatedAccessTokenResponse(ctx context.Context, s logical.Storage, rs *RoleSet, d *framework.FieldData) (*logical.Response, error) {

	creds, err := b.GetCredentials(s)
	if err != nil {
		return logical.ErrorResponse("Error generating Impersonated Credentials %v", err), nil
	}

	// del := d.Get("impersonation_target").(string)
	del := rs.TokenGen.TargetServiceAccount
	ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: del,
		Scopes:          rs.TokenGen.Scopes,
		Delegates:       rs.TokenGen.Delegates,
		Lifetime:        rs.TokenGen.Lifetime,
	}, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}

	tok, err := ts.Token()
	if err != nil {
		return logical.ErrorResponse("Error generating Impersonated Token %v", err), nil
	}
	token := &oauth2.Token{
		AccessToken: tok.AccessToken,
		Expiry:      tok.Expiry,
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"impersonated_access_token": token.AccessToken,
			"token_ttl":                 token.Expiry.UTC().Sub(time.Now().UTC()) / (time.Second),
			"expires_at_seconds":        token.Expiry.Unix(),
		},
	}, nil
}

const impersonateddeprecationWarning = `
This endpoint no longer generates leases due to limitations of the GCP API, as OAuth2 tokens belonging to Service
Accounts cannot be revoked. This access_token and lease were created by a previous version of the GCP secrets
engine and will be cleaned up now. Note that there is the chance that this access_token, if not already expired,
will still be valid up to one hour.
`

const pathImpersonatedAccessTokenHelpSyn = `Generate an Impersonated OAuth2 access token.`
const pathImpersonatedAccessTokenHelpDesc = `
This path will generate a new impersonated access token.  For more information,see

https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials
`

// EVERYTHING USING THIS SECRET TYPE IS CURRENTLY DEPRECATED.
// We keep it to allow for clean up of access_token secrets/leases that may have be left over
// by older versions of Vault.
const SecretTypeImpersonatedAccessToken = "impersonated_access_token"

func secretImpersonatedAccessToken(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: SecretTypeImpersonatedAccessToken,
		Fields: map[string]*framework.FieldSchema{
			"impersonated_access_token": {
				Type:        framework.TypeString,
				Description: "Impersonated token",
			},
		},
		Renew:  b.secretImpersonatedAccessTokenRenew,
		Revoke: b.secretImpersonatedAccessTokenRevoke,
	}
}

// Renewal will still return an error, but return the warning in case as well.
func (b *backend) secretImpersonatedAccessTokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := logical.ErrorResponse("short-term access tokens cannot be renewed - request new access token instead")
	resp.AddWarning(impersonateddeprecationWarning)
	return resp, nil
}

// Revoke will no-op and pass but warn the user. This is mostly to clean up old leases.
// Any associated secret (access_token) has already expired and thus doesn't need to
// actually be revoked,  or will expire within an hour and currently can't actually be revoked anyways.
func (b *backend) secretImpersonatedAccessTokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{}
	resp.AddWarning(impersonateddeprecationWarning)
	return resp, nil
}
