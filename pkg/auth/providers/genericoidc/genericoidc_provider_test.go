package genericoidc

import (
	"reflect"
	"testing"

	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	apiv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/providers/oidc"
	baseoidc "github.com/rancher/rancher/pkg/auth/providers/oidc"
	client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	usermocks "github.com/rancher/rancher/pkg/user/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
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

func TestGenOIDCProvider_GetPrincipal_InvalidPrincipalID(t *testing.T) {
	tests := []struct {
		name        string
		principalID string
		wantErr     bool
		errContains string
	}{
		{
			name:        "principal id without separator scheme",
			principalID: "nounderscore://123",
			wantErr:     true,
			errContains: "invalid principal scheme",
		},
		{
			name:        "principal id with invalid type",
			principalID: "genericoidc_admin://123",
			wantErr:     true,
			errContains: "invalid principal type",
		},
		{
			name:        "principal id with empty external id and empty type",
			principalID: "genericoidc_://",
			wantErr:     true,
			errContains: "invalid id",
		},
		{
			name:        "principal id with only separator no provider",
			principalID: "_user://123",
			wantErr:     false,
		},
		{
			name:        "principal id with missing provider prefix",
			principalID: "user://123",
			wantErr:     true,
			errContains: "invalid principal scheme",
		},
		{
			name:        "principal id with empty external id for user type",
			principalID: "genericoidc_user://",
			wantErr:     false,
		},
		{
			name:        "principal id with empty external id for group type",
			principalID: "genericoidc_group://",
			wantErr:     false,
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
			_, err := g.GetPrincipal(test.principalID, nil)
			if test.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.errContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGenOIDCProvider_GetPrincipal_MissingUserInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockUserMGR := usermocks.NewMockManager(ctrl)
	mockUserMGR.EXPECT().IsMemberOf(gomock.Any(), gomock.Any()).Return(false).AnyTimes()

	tests := []struct {
		name        string
		principalID string
		token       apiv3.Token
		want        apiv3.Principal
	}{
		{
			name:        "token with empty user principal display name and login name",
			principalID: "genericoidc_user://1234567",
			token: apiv3.Token{
				UserPrincipal: apiv3.Principal{
					ObjectMeta: metav1.ObjectMeta{
						Name: "genericoidc_user://1234567",
					},
					DisplayName:   "",
					LoginName:     "",
					PrincipalType: "user",
					Me:            true,
				},
			},
			want: apiv3.Principal{
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_user://1234567",
				},
				DisplayName:   "",
				LoginName:     "",
				PrincipalType: "user",
				Me:            true,
				Provider:      Name,
			},
		},
		{
			name:        "token with empty user principal object meta name",
			principalID: "genericoidc_user://1234567",
			token: apiv3.Token{
				UserPrincipal: apiv3.Principal{
					ObjectMeta: metav1.ObjectMeta{
						Name: "",
					},
					DisplayName:   "",
					LoginName:     "",
					PrincipalType: "user",
					Me:            false,
				},
			},
			want: apiv3.Principal{
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_user://1234567",
				},
				DisplayName:   "1234567",
				LoginName:     "1234567",
				PrincipalType: "user",
				Me:            false,
				Provider:      Name,
			},
		},
		{
			name:        "group principal with token",
			principalID: "genericoidc_group://mygroup",
			token: apiv3.Token{
				UserPrincipal: apiv3.Principal{
					ObjectMeta: metav1.ObjectMeta{
						Name: "genericoidc_user://1234567",
					},
					DisplayName:   "Test User",
					LoginName:     "1234567",
					PrincipalType: "user",
				},
			},
			want: apiv3.Principal{
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_group://mygroup",
				},
				DisplayName:   "mygroup",
				PrincipalType: "group",
				Provider:      Name,
				Me:            false,
				MemberOf:      false,
			},
		},
		{
			name:        "group principal with nil token",
			principalID: "genericoidc_group://mygroup",
			want: apiv3.Principal{
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_group://mygroup",
				},
				DisplayName:   "mygroup",
				PrincipalType: "group",
				Provider:      Name,
				Me:            false,
			},
		},
	}

	for _, test := range tests {
		test := test
		g := &GenOIDCProvider{
			oidc.OpenIDCProvider{
				Name:    Name,
				Type:    client.GenericOIDCConfigType,
				UserMGR: mockUserMGR,
			},
		}
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := g.GetPrincipal(test.principalID, &test.token)
			assert.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestGenOIDCProvider_GetPrincipal_MissingTokenClaims(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockUserMGR := usermocks.NewMockManager(ctrl)
	mockUserMGR.EXPECT().IsMemberOf(gomock.Any(), gomock.Any()).Return(false).AnyTimes()

	tests := []struct {
		name        string
		principalID string
		token       apiv3.Token
		want        apiv3.Principal
	}{
		{
			name:        "token missing user principal provider info",
			principalID: "genericoidc_user://1234567",
			token: apiv3.Token{
				UserPrincipal: apiv3.Principal{
					ObjectMeta: metav1.ObjectMeta{
						Name: "genericoidc_user://1234567",
					},
					PrincipalType: "user",
					Me:            true,
				},
			},
			want: apiv3.Principal{
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_user://1234567",
				},
				DisplayName:   "",
				LoginName:     "",
				PrincipalType: "user",
				Me:            true,
				Provider:      Name,
			},
		},
		{
			name:        "token with mismatched principal name should not be me",
			principalID: "genericoidc_user://different_user",
			token: apiv3.Token{
				UserPrincipal: apiv3.Principal{
					ObjectMeta: metav1.ObjectMeta{
						Name: "genericoidc_user://1234567",
					},
					DisplayName:   "Original User",
					LoginName:     "1234567",
					PrincipalType: "user",
					Me:            false,
				},
			},
			want: apiv3.Principal{
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_user://different_user",
				},
				DisplayName:   "different_user",
				LoginName:     "different_user",
				PrincipalType: "user",
				Me:            false,
				Provider:      Name,
			},
		},
		{
			name:        "token with group principal missing group claims",
			principalID: "genericoidc_group://emptygroup",
			token: apiv3.Token{
				UserPrincipal: apiv3.Principal{
					ObjectMeta: metav1.ObjectMeta{
						Name: "genericoidc_user://1234567",
					},
					DisplayName:   "Test User",
					LoginName:     "1234567",
					PrincipalType: "user",
				},
				GroupPrincipals: []apiv3.Principal{},
			},
			want: apiv3.Principal{
				ObjectMeta: metav1.ObjectMeta{
					Name: "genericoidc_group://emptygroup",
				},
				DisplayName:   "emptygroup",
				PrincipalType: "group",
				Provider:      Name,
				Me:            false,
				MemberOf:      false,
			},
		},
	}

	for _, test := range tests {
		test := test
		g := &GenOIDCProvider{
			oidc.OpenIDCProvider{
				Name:    Name,
				Type:    client.GenericOIDCConfigType,
				UserMGR: mockUserMGR,
			},
		}
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := g.GetPrincipal(test.principalID, &test.token)
			assert.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestGenOIDCProvider_TransformToAuthProvider_InvalidIssuer(t *testing.T) {
	tests := []struct {
		name       string
		authConfig map[string]any
		wantErr    bool
	}{
		{
			name: "missing issuer and authEndpoint",
			authConfig: map[string]any{
				"metadata":   map[string]any{"name": "genericoidc"},
				"clientId":   "client123",
				"rancherUrl": "https://example.com/callback",
				"scope":      "openid profile email",
			},
			wantErr: true,
		},
		{
			name: "invalid issuer url",
			authConfig: map[string]any{
				"metadata":     map[string]any{"name": "genericoidc"},
				"clientId":     "client123",
				"rancherUrl":   "https://example.com/callback",
				"scope":        "openid profile email",
				"issuer":       "://invalid-issuer",
				"authEndpoint": "https://ranchertest.io/auth",
			},
			wantErr: false,
		},
		{
			name: "missing scope in authConfig",
			authConfig: map[string]any{
				"metadata":     map[string]any{"name": "genericoidc"},
				"clientId":     "client123",
				"rancherUrl":   "https://example.com/callback",
				"issuer":       "https://ranchertest.io/issuer",
				"authEndpoint": "https://ranchertest.io/auth",
			},
			wantErr: false,
		},
		{
			name: "missing metadata name",
			authConfig: map[string]any{
				"metadata":     map[string]any{},
				"clientId":     "client123",
				"rancherUrl":   "https://example.com/callback",
				"scope":        "openid profile email",
				"issuer":       "https://ranchertest.io/issuer",
				"authEndpoint": "https://ranchertest.io/auth",
			},
			wantErr: true,
		},
		{
			name: "empty issuer url",
			authConfig: map[string]any{
				"metadata":     map[string]any{"name": "genericoidc"},
				"clientId":     "client123",
				"rancherUrl":   "https://example.com/callback",
				"scope":        "openid profile email",
				"issuer":       "",
				"authEndpoint": "https://ranchertest.io/auth",
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
				if _, ok := test.authConfig["scope"]; !ok {
					assert.Nil(t, result["scopes"])
				}
			}
		})
	}
}

func TestGenOIDCProvider_RefetchGroupPrincipals(t *testing.T) {
	g := &GenOIDCProvider{
		oidc.OpenIDCProvider{
			Name: Name,
			Type: client.GenericOIDCConfigType,
		},
	}

	result, err := g.RefetchGroupPrincipals("genericoidc_user://123", "secret")
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Equal(t, "Not implemented", err.Error())
}

func TestGenOIDCProvider_UsesUserSecrets(t *testing.T) {
	g := &GenOIDCProvider{}
	assert.False(t, g.UsesUserSecrets())
}

func TestGenOIDCProvider_CanRefreshPrincipals(t *testing.T) {
	g := &GenOIDCProvider{}
	assert.False(t, g.CanRefreshPrincipals())
}
