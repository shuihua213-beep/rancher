package genericoidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rancher/norman/types"
	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	apiv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/accessor"
	"github.com/rancher/rancher/pkg/auth/providers/oidc"
	baseoidc "github.com/rancher/rancher/pkg/auth/providers/oidc"
	client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	userMocks "github.com/rancher/rancher/pkg/user/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGenOIDCProvider_GetPrincipal(t *testing.T) {
	tests := []struct {
		name        string
		principalID string
		token       apiv3.Token
		want        apiv3.Principal
		wantErr     bool
	}{
		{
			name:        "fetch principal for current user",
			principalID: "genericoidc_user://1234567",
			token: apiv3.Token{
				UserPrincipal: apiv3.Principal{
					ObjectMeta: metav1.ObjectMeta{
						Name: "genericoidc_user://1234567",
					},
					DisplayName:   "Test User",
					LoginName:     "1234567",
					PrincipalType: "user",
					Me:            true,
				},
			},
			want: apiv3.Principal{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_user://1234567",
				},
				DisplayName:   "Test User",
				LoginName:     "1234567",
				PrincipalType: "user",
				Me:            true,
				Provider:      Name,
			},
			wantErr: false,
		},
		{
			name:        "fetch principal for user other than self",
			principalID: "genericoidc_user://9876543",
			token: apiv3.Token{
				UserPrincipal: apiv3.Principal{
					ObjectMeta: metav1.ObjectMeta{
						Name: "genericoidc_user://1234567",
					},
					DisplayName:   "Test User",
					LoginName:     "1234567",
					PrincipalType: "user",
					Me:            false,
				},
			},
			want: apiv3.Principal{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_user://9876543",
				},
				DisplayName:   "9876543",
				LoginName:     "9876543",
				PrincipalType: "user",
				Me:            false,
				Provider:      Name,
			},
			wantErr: false,
		},
		{
			name:        "fetch principal token is nil",
			principalID: "genericoidc_user://9876543",
			want: apiv3.Principal{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_user://9876543",
				},
				DisplayName:   "9876543",
				LoginName:     "9876543",
				PrincipalType: "user",
				Me:            false,
				Provider:      Name,
			},
			wantErr: false,
		},
		{
			name:        "fetch principal called with empty principal",
			principalID: "",
			want:        apiv3.Principal{},
			wantErr:     true,
		},
	}
	for _, test := range tests {
		test := test
		g := &GenOIDCProvider{
			oidc.OpenIDCProvider{
				Name: Name,
				Type: client.GenericOIDCConfigType,
			},
		}
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := g.GetPrincipal(test.principalID, &test.token)
			if (err != nil) != test.wantErr {
				t.Errorf("GetPrincipal() error = %v, wantErr %v", err, test.wantErr)
				return
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("GetPrincipal() got = %v, want %v", got, test.want)
			}
		})
	}
}

func TestGenOIDCProvider_GetPrincipalExt(t *testing.T) {
	tests := []struct {
		name        string
		principalID string
		token       ext.Token
		want        apiv3.Principal
		wantErr     bool
	}{
		{
			name:        "fetch principal",
			principalID: "genericoidc_user://1234567",
			token: ext.Token{
				Spec: ext.TokenSpec{
					UserPrincipal: ext.TokenPrincipal{
						Name:          "genericoidc_user://1234567",
						Provider:      Name,
						DisplayName:   "Test User",
						LoginName:     "1234567",
						PrincipalType: "user",
					},
				},
			},
			want: apiv3.Principal{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_user://1234567",
				},
				DisplayName:   "Test User",
				LoginName:     "1234567",
				PrincipalType: "user",
				Provider:      Name,
				Me:            true,
			},
			wantErr: false,
		},
		{
			name:        "fetch principal token is nil",
			principalID: "genericoidc_user://9876543",
			want: apiv3.Principal{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_user://9876543",
				},
				DisplayName:   "9876543",
				LoginName:     "9876543",
				PrincipalType: "user",
				Me:            false,
				Provider:      Name,
			},
			wantErr: false,
		},
		{
			name:        "fetch principal called with empty principal",
			principalID: "",
			want:        apiv3.Principal{},
			wantErr:     true,
		},
	}
	for _, test := range tests {
		test := test
		g := &GenOIDCProvider{
			oidc.OpenIDCProvider{
				Name: Name,
				Type: client.GenericOIDCConfigType,
			},
		}
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := g.GetPrincipal(test.principalID, &test.token)
			assert.Equal(t, test.wantErr, err != nil)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestGenOIDCProvider_SearchPrincipals(t *testing.T) {
	tests := []struct {
		name          string
		searchValue   string
		principalType string
		expected      []apiv3.Principal
	}{
		{
			name:          "test search for user principal",
			searchValue:   "user1",
			principalType: UserType,
			expected: []apiv3.Principal{
				{
					ObjectMeta:    metav1.ObjectMeta{Name: "genericoidc_user://user1"},
					DisplayName:   "user1",
					LoginName:     "user1",
					PrincipalType: UserType,
					Provider:      Name,
				},
			},
		},
		{
			name:        "test search for user principal with empty principaltype",
			searchValue: "user1",
			expected: []apiv3.Principal{
				{
					ObjectMeta:    metav1.ObjectMeta{Name: "genericoidc_user://user1"},
					DisplayName:   "user1",
					LoginName:     "user1",
					PrincipalType: UserType,
					Provider:      Name,
				},
				{
					ObjectMeta:    metav1.ObjectMeta{Name: "genericoidc_group://user1"},
					DisplayName:   "user1",
					PrincipalType: GroupType,
					Provider:      Name,
				},
			},
		},
		{
			name: "test search for user principal with empty principaltype and searchval",
			expected: []apiv3.Principal{
				{
					ObjectMeta:    metav1.ObjectMeta{Name: "genericoidc_user://"},
					PrincipalType: UserType,
					Provider:      Name,
				},
				{
					ObjectMeta:    metav1.ObjectMeta{Name: "genericoidc_group://"},
					PrincipalType: GroupType,
					Provider:      Name,
				},
			},
		},
		{
			name:          "test search for group principal",
			searchValue:   "group1",
			principalType: GroupType,
			expected: []apiv3.Principal{
				{
					ObjectMeta:    metav1.ObjectMeta{Name: "genericoidc_group://group1"},
					DisplayName:   "group1",
					PrincipalType: GroupType,
					Provider:      Name,
				},
			},
		},
		{
			name:          "test search for group principal with empty searchval",
			principalType: GroupType,
			expected: []apiv3.Principal{
				{
					ObjectMeta:    metav1.ObjectMeta{Name: "genericoidc_group://"},
					PrincipalType: GroupType,
					Provider:      Name,
				},
			},
		},
	}

	g := &GenOIDCProvider{
		oidc.OpenIDCProvider{
			Name: Name,
			Type: client.GenericOIDCConfigType,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := g.SearchPrincipals(test.searchValue, test.principalType, &apiv3.Token{})
			if err != nil {
				t.Errorf("SearchPrincipals() returned an error: %v", err)
			}

			if !reflect.DeepEqual(result, test.expected) {
				t.Errorf("SearchPrincipals() returned %+v, expected %+v", result, test.expected)
			}
		})

		t.Run(test.name+", ext", func(t *testing.T) {
			t.Parallel()
			result, err := g.SearchPrincipals(test.searchValue, test.principalType, &ext.Token{})
			if err != nil {
				t.Errorf("SearchPrincipals() returned an error: %v", err)
			}

			if !reflect.DeepEqual(result, test.expected) {
				t.Errorf("SearchPrincipals() returned %+v, expected %+v", result, test.expected)
			}
		})
	}
}

func TestGenOIDCProvider_TransformToAuthProvider(t *testing.T) {
	tests := []struct {
		name       string
		authConfig map[string]any
		expected   map[string]any
	}{
		{
			name: "Test with valid authConfig",
			authConfig: map[string]any{
				"metadata":     map[string]any{"name": "genericoidc"},
				"clientId":     "client123",
				"rancherUrl":   "https://example.com/callback",
				"scope":        "openid profile email",
				"issuer":       "https://ranchertest.io/issuer",
				"authEndpoint": "https://ranchertest.io/auth",
			},
			expected: map[string]any{
				"id":                 "genericoidc",
				"redirectUrl":        "https://ranchertest.io/auth?client_id=client123&response_type=code&redirect_uri=https://example.com/callback",
				"scopes":             "openid profile email",
				"logoutAllSupported": false,
				"logoutAllEnabled":   false,
				"logoutAllForced":    false,
			},
		},
		{
			name: "When configuration has acrValue",
			authConfig: map[string]any{
				"metadata":     map[string]any{"name": "genericoidc"},
				"clientId":     "client123",
				"rancherUrl":   "https://example.com/callback",
				"scope":        "openid profile email",
				"issuer":       "https://ranchertest.io/issuer",
				"authEndpoint": "https://ranchertest.io/auth",
				"acrValue":     "testing",
			},
			expected: map[string]any{
				"id":                 "genericoidc",
				"redirectUrl":        "https://ranchertest.io/auth?client_id=client123&response_type=code&redirect_uri=https://example.com/callback&acr_values=testing",
				"scopes":             "openid profile email",
				"logoutAllSupported": false,
				"logoutAllEnabled":   false,
				"logoutAllForced":    false,
			},
		},
	}

	provider := &GenOIDCProvider{
		baseoidc.OpenIDCProvider{},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := provider.TransformToAuthProvider(test.authConfig)
			assert.NoError(t, err)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGenOIDCProvider_LoginUser_ErrorScenarios(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := map[string]struct {
		config                func(string) *apiv3.OIDCConfig
		oidcProviderResponses func(string) genericOIDCResponses
		setupUserManager      func(*userMocks.MockManager)
		expectedError         string
	}{
		"invalid issuer": {
			config: func(_ string) *apiv3.OIDCConfig {
				return &apiv3.OIDCConfig{
					Issuer:   "://invalid",
					ClientID: "test",
				}
			},
			oidcProviderResponses: func(port string) genericOIDCResponses {
				return newGenericOIDCResponses(privateKey, port)
			},
			setupUserManager: func(*userMocks.MockManager) {},
			expectedError:    "missing protocol scheme",
		},
		"missing subject in user info": {
			config: func(port string) *apiv3.OIDCConfig {
				return newGenericOIDCConfig(port)
			},
			oidcProviderResponses: func(port string) genericOIDCResponses {
				resp := newGenericOIDCResponses(privateKey, port)
				resp.user = `{"email":"test@example.com"}`
				return resp
			},
			setupUserManager: func(userManager *userMocks.MockManager) {
				userManager.EXPECT().CheckAccess(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)
			},
			expectedError: "missing subject",
		},
		"missing configured name claim": {
			config: func(port string) *apiv3.OIDCConfig {
				cfg := newGenericOIDCConfig(port)
				cfg.NameClaim = "display_name"
				return cfg
			},
			oidcProviderResponses: func(port string) genericOIDCResponses {
				return newGenericOIDCResponses(privateKey, port)
			},
			setupUserManager: func(userManager *userMocks.MockManager) {
				userManager.EXPECT().CheckAccess(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)
			},
			expectedError: "missing display_name claim",
		},
		"missing configured email claim": {
			config: func(port string) *apiv3.OIDCConfig {
				cfg := newGenericOIDCConfig(port)
				cfg.EmailClaim = "public_email"
				return cfg
			},
			oidcProviderResponses: func(port string) genericOIDCResponses {
				return newGenericOIDCResponses(privateKey, port)
			},
			setupUserManager: func(userManager *userMocks.MockManager) {
				userManager.EXPECT().CheckAccess(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)
			},
			expectedError: "missing public_email claim",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			listener, err := net.Listen("tcp", ":0")
			require.NoError(t, err)
			port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
			server := mockGenericOIDCServer(listener, test.oidcProviderResponses(port))
			defer server.Shutdown(context.TODO())

			userManager := userMocks.NewMockManager(ctrl)
			test.setupUserManager(userManager)

			provider := &GenOIDCProvider{
				oidc.OpenIDCProvider{
					Name:     Name,
					Type:     client.GenericOIDCConfigType,
					TokenMgr: &testGenericOIDCTokenManager{},
					UserMGR:  userManager,
				},
			}

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "https://localhost:"+port, nil)

			_, _, _, _, err = provider.LoginUser(recorder, request, &apiv3.OIDCLogin{Code: "test-code"}, test.config(port))
			require.Error(t, err)
			assert.ErrorContains(t, err, test.expectedError)
		})
	}
}

type testGenericOIDCTokenManager struct{}

func (t *testGenericOIDCTokenManager) UpdateSecret(userID, provider, secret string) error {
	return nil
}

func (t *testGenericOIDCTokenManager) CreateTokenAndSetCookie(userID string, userPrincipal apiv3.Principal, groupPrincipals []apiv3.Principal, providerToken string, ttl int, description string, request *types.APIContext) error {
	return nil
}

func (t *testGenericOIDCTokenManager) CreateSecret(userID, provider, secret string) error {
	return nil
}

func (t *testGenericOIDCTokenManager) GetSecret(userID string, provider string, fallbackTokens []accessor.TokenAccessor) (string, error) {
	return "", nil
}

func mockGenericOIDCServer(listener net.Listener, resp genericOIDCResponses) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp.config)
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp.jwks)
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(resp.user))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp.token)
	})

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()
	return server
}

type genericOIDCResponses struct {
	user   string
	config genericProviderJSON
	jwks   genericJSONWebKeySet
	token  *genericToken
}

type genericToken struct {
	oauth2.Token
	IDToken string `json:"id_token"`
}

func newGenericOIDCResponses(privateKey *rsa.PrivateKey, port string) genericOIDCResponses {
	tokenJWT := jwt.New(jwt.SigningMethodRS256)
	tokenJWT.Claims = jwt.MapClaims{
		"aud":   "test",
		"email": "test@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iss":   "http://localhost:" + port,
	}
	tokenStr, err := tokenJWT.SignedString(privateKey)
	if err != nil {
		panic(err)
	}

	return genericOIDCResponses{
		user: `{
			"sub": "a8d0d2c4-6543-4546-8f1a-73e1d7dffcbd",
			"email": "test@example.com",
			"groups": ["admingroup"],
			"full_group_path": ["/admingroup"],
			"roles": ["adminrole"]
		}`,
		config: genericProviderJSON{
			Issuer:      "http://localhost:" + port,
			UserInfoURL: "http://localhost:" + port + "/user",
			JWKSURL:     "http://localhost:" + port + "/.well-known/jwks.json",
			AuthURL:     "http://localhost:" + port + "/auth",
			TokenURL:    "http://localhost:" + port + "/token",
		},
		token: &genericToken{
			Token: oauth2.Token{
				AccessToken:  tokenStr,
				Expiry:       time.Now().Add(5 * time.Minute),
				RefreshToken: tokenStr,
			},
			IDToken: tokenStr,
		},
		jwks: genericJSONWebKeySet{
			Keys: []genericJSONWebKey{
				{
					Kty: "RSA",
					Kid: "example-key-id",
					Use: "sig",
					Alg: "RS256",
					N:   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
					E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
				},
			},
		},
	}
}

func newGenericOIDCConfig(port string) *apiv3.OIDCConfig {
	return &apiv3.OIDCConfig{
		Issuer:           "http://localhost:" + port,
		ClientID:         "test",
		JWKSUrl:          "http://localhost:" + port + "/.well-known/jwks.json",
		AuthEndpoint:     "http://localhost:" + port + "/auth",
		TokenEndpoint:    "http://localhost:" + port + "/token",
		UserInfoEndpoint: "http://localhost:" + port + "/user",
	}
}

type genericJSONWebKeySet struct {
	Keys []genericJSONWebKey `json:"keys"`
}

type genericJSONWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type genericProviderJSON struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	JWKSURL     string `json:"jwks_uri"`
	UserInfoURL string `json:"userinfo_endpoint"`
}
