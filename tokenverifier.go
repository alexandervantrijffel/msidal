package msidal

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Azure/go-autorest/autorest"
	oidc "github.com/coreos/go-oidc"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"golang.org/x/oauth2"
)

func VerifyToken(settings *AzureSettings, rawIDToken string) (*oidc.IDToken, error) {
	provider, err := newAzureProvider(settings)
	if err != nil {
		return nil, err
	}
	trimmedIDToken := strings.TrimPrefix(rawIDToken, "Bearer ")
	return provider.oidcVerifier.Verify(context.Background(), trimmedIDToken)
}

type AzureSettings struct {
	TenantID                string
	ClientID                string
	ActiveDirectoryEndpoint string
}

var authorizerLifetime = 30 * time.Minute

type azureProvider struct {
	oidcVerifier         *oidc.IDTokenVerifier
	settings             *AzureSettings
	httpClient           *http.Client
	authorizer           autorest.Authorizer
	authorizerExpiration time.Time
	lock                 sync.RWMutex
}

type oidcDiscoveryInfo struct {
	Issuer  string `json:"issuer"`
	JWKSURL string `json:"jwks_uri"`
}

// copied from https://github.com/hashicorp/vault-plugin-auth-azure/blob/4c0b46069a2293d5a6ca7506c8d3e0c4a92f3dbc/azure.go#L58
func newAzureProvider(settings *AzureSettings) (*azureProvider, error) {
	httpClient := cleanhttp.DefaultClient()

	// In many OIDC providers, the discovery endpoint matches the issuer. For Azure AD, the discovery
	// endpoint is the AD endpoint which does not match the issuer defined in the discovery payload. This
	// makes a request to the discovery URL to determine the issuer and key set information to configure
	// the OIDC verifier
	discoveryURL := fmt.Sprintf("%s%s/v2.0/.well-known/openid-configuration", settings.ActiveDirectoryEndpoint, settings.TenantID)
	req, err := http.NewRequest("GET", discoveryURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent())

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}
	var discoveryInfo oidcDiscoveryInfo
	if err := json.Unmarshal(body, &discoveryInfo); err != nil {
		return nil, fmt.Errorf("unable to unmarshal discovery url: %w", err)
	}

	fmt.Printf("Found discoveryInfo %+v", discoveryInfo)

	// Create a remote key set from the discovery endpoint
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
	remoteKeySet := oidc.NewRemoteKeySet(ctx, discoveryInfo.JWKSURL)

	verifierConfig := &oidc.Config{
		ClientID:             settings.ClientID,
		SupportedSigningAlgs: []string{oidc.RS256},
	}
	oidcVerifier := oidc.NewVerifier(discoveryInfo.Issuer, remoteKeySet, verifierConfig)

	return &azureProvider{
		settings:     settings,
		oidcVerifier: oidcVerifier,
		httpClient:   httpClient,
	}, nil
}

func userAgent() string {
	// latest chrome on linux
	return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36"
}
