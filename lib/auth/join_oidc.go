package auth

import (
	"context"

	"github.com/coreos/go-oidc"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
)

// example jwks endpoint
// https://www.googleapis.com/oauth2/v3/certs

type gcpIDToken struct {
	Sub    string `json:"sub"`
	Google struct {
		ComputeEngine struct {
			ProjectID     string `json:"project_id"`
			ProjectNumber int    `json:"project_number"`
			InstanceID    string `json:"instance_id"`
			InstanceName  string `json:"instance_name"`
		} `json:"compute_engine"`
	} `json:"google"`
}

func (a *Server) checkOIDCJoinRequest(ctx context.Context, req *types.RegisterUsingTokenRequest) error {
	if req.OIDCJWT == "" {
		return trace.BadParameter("Request must contain OIDCJWT value when using OIDC based joining.")
	}
	_, err := a.GetToken(ctx, req.Token)
	if err != nil {
		return trace.Wrap(err)
	}

	// TODO:
	// Instantiating this provider hits the issuer's well-known endpoint
	// and configures a cache for the JWKs, because of this, we probably
	// actually want to instantiate this elsewhere and inject this, rather than
	// instantiating this for every validation.
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return trace.Wrap(err)
	}

	clusterName, err := a.GetClusterName()
	if err != nil {
		return trace.Wrap(err)
	}

	v := provider.Verifier(&oidc.Config{
		// Expect the audience of the token to be the name of the cluster.
		// This reduces the risk that a JWT leaked by another application can
		// be used against Teleport.
		ClientID:             clusterName.GetClusterName(),
		SupportedSigningAlgs: []string{oidc.RS256, oidc.RS384, oidc.RS512},
	})

	verifiedToken, err := v.Verify(ctx, req.OIDCJWT)
	if err != nil {
		return trace.Wrap(err)
	}

	var parsedClaims gcpIDToken
	if err := verifiedToken.Claims(&parsedClaims); err != nil {
		return trace.Wrap(err)
	}

	return nil
}
