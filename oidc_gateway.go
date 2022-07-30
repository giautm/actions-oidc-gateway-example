package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

type GatewayContext struct {
	jwks *keyfunc.JWKS
}

func (gc *GatewayContext) validateTokenCameFromGitHub(oidcTokenString string) (jwt.MapClaims, error) {
	// Attempt to validate JWT with JWKS
	t, err := jwt.Parse(string(oidcTokenString), gc.jwks.Keyfunc)
	if err != nil || !t.Valid {
		return nil, fmt.Errorf("gateway: unable to validate JWT")
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("gateway: unable to map JWT claims")
	}

	return claims, nil
}

func (gc *GatewayContext) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodConnect && req.RequestURI != "/apiExample" {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	// Check that the OIDC token verifies as a valid token from GitHub
	//
	// This only means the OIDC token came from any GitHub Actions workflow,
	// we *must* check claims specific to our use case below
	oidcTokenString := string(req.Header.Get("Gateway-Authorization"))

	claims, err := gc.validateTokenCameFromGitHub(oidcTokenString)
	if err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// Token is valid, but we *must* check some claim specific to our use case
	//
	// For examples of other claims you could check, see:
	// https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#configuring-the-oidc-trust-with-the-cloud
	//
	// Here we check the same claims for all requests, but you could customize
	// the claims you check per handler below
	if claims["repository"] != "octo-org/octo-repo" {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// You can customize the audience when you request an Actions OIDC token.
	//
	// This is a good idea to prevent a token being accidentally leaked by a
	// service from being used in another service.
	//
	// The example in the README.md requests this specific custom audience.
	if claims["aud"] != "api://ActionsOIDCGateway" {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return

	}

	// Now that claims have been verified, we can service the request
	if req.Method == http.MethodConnect {
		handleProxyRequest(w, req)
	} else if req.RequestURI == "/apiExample" {
		handleApiRequest(w)
	}
}

func main() {
	fmt.Println("starting up")

	jwks, err := keyfunc.Get("https://token.actions.githubusercontent.com/.well-known/jwks", keyfunc.Options{
		RefreshInterval: time.Minute,
	})
	if err != nil {
		panic(err)
	}

	server := http.Server{
		Addr:         ":8000",
		Handler:      &GatewayContext{jwks: jwks},
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	server.ListenAndServe()
}
