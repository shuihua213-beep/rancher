package genericoidc

import (
	"reflect"
	"testing"

	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	apiv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/providers/oidc"
	baseoidc "github.com/rancher/rancher/pkg/auth/providers/oidc"
	client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	"github.com/stretchr/testify/assert"
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
		{
			name:        "invalid principal format - missing :// separator",
			principalID: "genericoidc_user1234567",
			want:        apiv3.Principal{},
			wantErr:     true,
		},
		{
			name:        "invalid principal format - missing underscore separator",
			principalID: "genericoidc://user123",
			want:        apiv3.Principal{},
			wantErr:     true,
		},
		{
			name:        "invalid principal type - not user or group",
			principalID: "genericoidc_invalid://123456",
			want:        apiv3.Principal{},
			wantErr:     true,
		},
		{
			name:        "empty external id but valid type",
			principalID: "genericoidc_user://",
			want: apiv3.Principal{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_user://",
				},
				DisplayName:   "",
				LoginName:     "",
				PrincipalType: "user",
				Me:            false,
				Provider:      Name,
			},
			wantErr: false,
		},
		{
			name:        "fetch group principal with nil token",
			principalID: "genericoidc_group://engineering-team",
			want: apiv3.Principal{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_group://engineering-team",
				},
				DisplayName:   "engineering-team",
				PrincipalType: "group",
				Me:            false,
				Provider:      Name,
			},
			wantErr: false,
		},
		{
			name:        "fetch group principal with empty group name",
			principalID: "genericoidc_group://",
			want: apiv3.Principal{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_group://",
				},
				DisplayName:   "",
				PrincipalType: "group",
				Me:            false,
				Provider:      Name,
			},
			wantErr: false,
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
		{
			name:        "invalid principal format - missing :// separator",
			principalID: "genericoidc_user1234567",
			want:        apiv3.Principal{},
			wantErr:     true,
		},
		{
			name:        "invalid principal format - missing underscore separator",
			principalID: "genericoidc://user123",
			want:        apiv3.Principal{},
			wantErr:     true,
		},
		{
			name:        "invalid principal type - not user or group",
			principalID: "genericoidc_invalid://123456",
			want:        apiv3.Principal{},
			wantErr:     true,
		},
		{
			name:        "empty external id but valid type",
			principalID: "genericoidc_user://",
			want: apiv3.Principal{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_user://",
				},
				DisplayName:   "",
				LoginName:     "",
				PrincipalType: "user",
				Provider:      Name,
				Me:            false,
			},
			wantErr: false,
		},
		{
			name:        "fetch group principal with nil token",
			principalID: "genericoidc_group://engineering-team",
			want: apiv3.Principal{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_group://engineering-team",
				},
				DisplayName:   "engineering-team",
				PrincipalType: "group",
				Me:            false,
				Provider:      Name,
			},
			wantErr: false,
		},
		{
			name:        "fetch group principal with empty group name",
			principalID: "genericoidc_group://",
			want: apiv3.Principal{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_group://",
				},
				DisplayName:   "",
				PrincipalType: "group",
				Me:            false,
				Provider:      Name,
			},
			wantErr: false,
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
		wantErr    bool
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
			wantErr: false,
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
			wantErr: false,
		},
		{
			name: "missing both authEndpoint and issuer - should return error",
			authConfig: map[string]any{
				"metadata":   map[string]any{"name": "genericoidc"},
				"clientId":   "client123",
				"rancherUrl": "https://example.com/callback",
				"scope":      "openid profile email",
			},
			expected: nil,
			wantErr:  true,
		},
		{
			name: "invalid issuer URL format when discovery needed - should return error",
			authConfig: map[string]any{
				"metadata":   map[string]any{"name": "genericoidc"},
				"clientId":   "client123",
				"rancherUrl": "https://example.com/callback",
				"scope":      "openid profile email",
				"issuer":     "://invalid-url",
			},
			expected: nil,
			wantErr:  true,
		},
		{
			name: "missing clientId - should still work but redirect URL will be incomplete",
			authConfig: map[string]any{
				"metadata":     map[string]any{"name": "genericoidc"},
				"rancherUrl":   "https://example.com/callback",
				"scope":        "openid profile email",
				"issuer":       "https://ranchertest.io/issuer",
				"authEndpoint": "https://ranchertest.io/auth",
			},
			expected: map[string]any{
				"id":                 "genericoidc",
				"redirectUrl":        "https://ranchertest.io/auth?client_id=%3Cnil%3E&response_type=code&redirect_uri=https://example.com/callback",
				"scopes":             "openid profile email",
				"logoutAllSupported": false,
				"logoutAllEnabled":   false,
				"logoutAllForced":    false,
			},
			wantErr: false,
		},
		{
			name: "missing rancherUrl - should still work but redirect URL will be incomplete",
			authConfig: map[string]any{
				"metadata":     map[string]any{"name": "genericoidc"},
				"clientId":     "client123",
				"scope":        "openid profile email",
				"issuer":       "https://ranchertest.io/issuer",
				"authEndpoint": "https://ranchertest.io/auth",
			},
			expected: map[string]any{
				"id":                 "genericoidc",
				"redirectUrl":        "https://ranchertest.io/auth?client_id=client123&response_type=code&redirect_uri=%3Cnil%3E",
				"scopes":             "openid profile email",
				"logoutAllSupported": false,
				"logoutAllEnabled":   false,
				"logoutAllForced":    false,
			},
			wantErr: false,
		},
		{
			name: "with rancherApiHost configured - should return correct redirect URL",
			authConfig: map[string]any{
				"metadata":       map[string]any{"name": "genericoidc"},
				"clientId":       "client123",
				"rancherUrl":     "https://example.com/callback",
				"rancherApiHost": "https://api.example.com",
				"scope":          "openid profile email",
				"issuer":         "https://ranchertest.io/issuer",
			},
			expected: map[string]any{
				"id":                 "genericoidc",
				"redirectUrl":        "https://api.example.com/v1-oidc/genericoidc",
				"scopes":             "openid profile email",
				"logoutAllSupported": false,
				"logoutAllEnabled":   false,
				"logoutAllForced":    false,
			},
			wantErr: false,
		},
	}

	provider := &GenOIDCProvider{
		baseoidc.OpenIDCProvider{},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := provider.TransformToAuthProvider(test.authConfig)
			if test.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, result)
			}
		})
	}
}
