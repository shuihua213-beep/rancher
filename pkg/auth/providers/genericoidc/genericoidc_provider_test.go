package genericoidc

import (
	"reflect"
	"testing"

	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	apiv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/providers/oidc"
	baseoidc "github.com/rancher/rancher/pkg/auth/providers/oidc"
	client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		// Note: ext tokens do not have `Me` information. current/other not distinguishable.
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

		// And same behaviour for ext tokens
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

func TestGenOIDCProvider_LoginUser_Exceptions(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	type testCase struct {
		name        string
		setupServer func(serverURL string) *httptest.Server
		wantErr     string
	}

	jwksHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": "test-key-id",
					"use": "sig",
					"alg": "RS256",
					"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
				},
			},
		})
	}

	tests := []testCase{
		{
			name: "error - issuer not valid", // issuer 不合法
			setupServer: func(serverURL string) *httptest.Server {
				mux := http.NewServeMux()
				mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]string{
						"issuer":                 serverURL,
						"authorization_endpoint": serverURL + "/auth",
						"token_endpoint":         serverURL + "/token",
						"jwks_uri":               serverURL + "/.well-known/jwks.json",
						"userinfo_endpoint":      serverURL + "/user",
					})
				})
				mux.HandleFunc("/.well-known/jwks.json", jwksHandler)
				mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					jwtToken := jwt.New(jwt.SigningMethodRS256)
					jwtToken.Claims = jwt.RegisteredClaims{
						Audience:  []string{"test-client"},
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
						Issuer:    "http://invalid-issuer", // Invalid issuer
					}
					jwtStr, _ := jwtToken.SignedString(privateKey)
					json.NewEncoder(w).Encode(map[string]any{
						"access_token": jwtStr,
						"id_token":     jwtStr,
						"token_type":   "Bearer",
						"expires_in":   300,
					})
				})
				return httptest.NewServer(mux)
			},
			wantErr: "oidc: id token issued by a different provider",
		},
		{
			name: "error - missing user info", // 用户信息缺失
			setupServer: func(serverURL string) *httptest.Server {
				mux := http.NewServeMux()
				mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]string{
						"issuer":                 serverURL,
						"authorization_endpoint": serverURL + "/auth",
						"token_endpoint":         serverURL + "/token",
						"jwks_uri":               serverURL + "/.well-known/jwks.json",
						"userinfo_endpoint":      serverURL + "/user",
					})
				})
				mux.HandleFunc("/.well-known/jwks.json", jwksHandler)
				mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					jwtToken := jwt.New(jwt.SigningMethodRS256)
					jwtToken.Claims = jwt.RegisteredClaims{
						Audience:  []string{"test-client"},
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
						Issuer:    serverURL,
						Subject:   "test-user",
					}
					jwtStr, _ := jwtToken.SignedString(privateKey)
					json.NewEncoder(w).Encode(map[string]any{
						"access_token": jwtStr,
						"id_token":     jwtStr,
						"token_type":   "Bearer",
						"expires_in":   300,
					})
				})
				mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{}`)) // Missing user info
				})
				return httptest.NewServer(mux)
			},
			wantErr: "failed to decode userinfo: unexpected end of JSON input",
		},
		{
			name: "error - missing critical claim in token", // token 中缺少关键 claim
			setupServer: func(serverURL string) *httptest.Server {
				mux := http.NewServeMux()
				mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]string{
						"issuer":                 serverURL,
						"authorization_endpoint": serverURL + "/auth",
						"token_endpoint":         serverURL + "/token",
						"jwks_uri":               serverURL + "/.well-known/jwks.json",
						"userinfo_endpoint":      serverURL + "/user",
					})
				})
				mux.HandleFunc("/.well-known/jwks.json", jwksHandler)
				mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					jwtToken := jwt.New(jwt.SigningMethodRS256)
					jwtToken.Claims = jwt.MapClaims{
						"aud": "test-client",
						"exp": time.Now().Add(5 * time.Minute).Unix(),
						"iss": serverURL,
						// "sub" is omitted
					}
					jwtStr, _ := jwtToken.SignedString(privateKey)
					json.NewEncoder(w).Encode(map[string]any{
						"access_token": jwtStr,
						"id_token":     jwtStr,
						"token_type":   "Bearer",
						"expires_in":   300,
					})
				})
				return httptest.NewServer(mux)
			},
			wantErr: "oidc: missing sub claim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
			serverURL := "http://127.0.0.1:" + port

			server := tt.setupServer(serverURL)
			// override listener
			server.Listener.Close()
			server.Listener = listener
			server.Start()
			defer server.Close()

			config := &apiv3.OIDCConfig{
				Issuer:           serverURL,
				ClientID:         "test-client",
				JWKSUrl:          serverURL + "/.well-known/jwks.json",
				AuthEndpoint:     serverURL + "/auth",
				TokenEndpoint:    serverURL + "/token",
				UserInfoEndpoint: serverURL + "/user",
			}

			g := &GenOIDCProvider{
				baseoidc.OpenIDCProvider{
					Name: Name,
					Type: client.GenericOIDCConfigType,
					CTX:  context.Background(),
				},
			}

			req := httptest.NewRequest(http.MethodGet, "/login", nil)
			w := httptest.NewRecorder()

			loginInfo := &apiv3.OIDCLogin{
				Code: "dummy-code",
			}

			_, _, _, _, err = g.LoginUser(w, req, loginInfo, config)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
