package genericoidc

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	apiv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/accessor"
	"github.com/rancher/rancher/pkg/auth/providers/common"
	baseoidc "github.com/rancher/rancher/pkg/auth/providers/oidc"
	"github.com/rancher/rancher/pkg/auth/tokens"
	client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	publicclient "github.com/rancher/rancher/pkg/client/generated/management/v3public"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/rancher/rancher/pkg/user"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type GenOIDCProvider struct {
	baseoidc.OpenIDCProvider
}

const (
	Name      = "genericoidc"
	UserType  = "user"
	GroupType = "group"
)

func Configure(ctx context.Context, mgmtCtx *config.ScaledContext, userMGR user.Manager, tokenMGR *tokens.Manager) common.AuthProvider {
	p := &GenOIDCProvider{
		baseoidc.OpenIDCProvider{
			Name:        Name,
			Type:        client.GenericOIDCConfigType,
			CTX:         ctx,
			AuthConfigs: mgmtCtx.Management.AuthConfigs(""),
			Secrets:     mgmtCtx.Wrangler.Core.Secret(),
			UserMGR:     userMGR,
			TokenMgr:    tokenMGR,
		},
	}
	p.GetConfig = p.GetOIDCConfig
	return p
}

func (g *GenOIDCProvider) GetName() string {
	return Name
}

func (g *GenOIDCProvider) SearchPrincipals(searchValue, principalType string, _ accessor.TokenAccessor) ([]apiv3.Principal, error) {
	var principals []apiv3.Principal

	if principalType != GroupType {
		p := apiv3.Principal{
			ObjectMeta:    metav1.ObjectMeta{Name: g.Name + "_" + UserType + "://" + searchValue},
			DisplayName:   searchValue,
			LoginName:     searchValue,
			PrincipalType: UserType,
			Provider:      g.Name,
		}
		principals = append(principals, p)
	}

	if principalType != UserType {
		gp := apiv3.Principal{
			ObjectMeta:    metav1.ObjectMeta{Name: g.Name + "_" + GroupType + "://" + searchValue},
			DisplayName:   searchValue,
			PrincipalType: GroupType,
			Provider:      g.Name,
		}
		principals = append(principals, gp)
	}
	return principals, nil
}

func (g *GenOIDCProvider) GetPrincipal(principalID string, token accessor.TokenAccessor) (apiv3.Principal, error) {
	var p apiv3.Principal

	principalScheme, externalID, found := strings.Cut(principalID, "://")
	if !found {
		return p, fmt.Errorf("invalid principal id: %s", principalID)
	}
	provider, principalType, found := strings.Cut(principalScheme, "_")
	if !found {
		return p, fmt.Errorf("invalid principal scheme: %s", principalScheme)
	}

	if externalID == "" && principalType == "" {
		return p, fmt.Errorf("invalid id %v", principalID)
	}
	if principalType != UserType && principalType != GroupType {
		return p, fmt.Errorf("invalid principal type: %s", principalType)
	}
	if principalType == UserType {
		p = apiv3.Principal{
			ObjectMeta:    metav1.ObjectMeta{Name: provider + "_" + principalType + "://" + externalID},
			DisplayName:   externalID,
			LoginName:     externalID,
			PrincipalType: UserType,
			Provider:      g.Name,
		}
	} else {
		p = g.groupToPrincipal(externalID)
	}
	p = g.toPrincipalFromToken(principalType, p, token)
	return p, nil
}

func (g *GenOIDCProvider) LoginUser(w http.ResponseWriter, req *http.Request, oauthLoginInfo *apiv3.OIDCLogin, config *apiv3.OIDCConfig) (apiv3.Principal, []apiv3.Principal, string, baseoidc.ClaimInfo, error) {
	var err error
	if config == nil {
		config, err = g.GetConfig()
		if err != nil {
			return apiv3.Principal{}, nil, "", baseoidc.ClaimInfo{}, err
		}
	}

	userPrincipal, groupPrincipals, providerToken, claimInfo, err := g.OpenIDCProvider.LoginUser(w, req, oauthLoginInfo, config)
	if err != nil {
		return apiv3.Principal{}, nil, "", baseoidc.ClaimInfo{}, err
	}

	if userPrincipal.LoginName == "" && claimInfo.Email != "" {
		userPrincipal.LoginName = claimInfo.Email
	}
	if userPrincipal.DisplayName == "" {
		switch {
		case claimInfo.Name != "":
			userPrincipal.DisplayName = claimInfo.Name
		case userPrincipal.LoginName != "":
			userPrincipal.DisplayName = userPrincipal.LoginName
		}
	}

	if err := g.validateLoginUserResult(userPrincipal, claimInfo, config); err != nil {
		return apiv3.Principal{}, nil, "", baseoidc.ClaimInfo{}, err
	}

	return userPrincipal, groupPrincipals, providerToken, claimInfo, nil
}

func (g *GenOIDCProvider) validateLoginUserResult(userPrincipal apiv3.Principal, claimInfo baseoidc.ClaimInfo, config *apiv3.OIDCConfig) error {
	if userPrincipal.PrincipalType == UserType && strings.HasSuffix(userPrincipal.Name, "://") {
		return fmt.Errorf("invalid user info response: missing subject")
	}
	if config == nil {
		return nil
	}
	if config.NameClaim != "" && claimInfo.Name == "" {
		return fmt.Errorf("invalid token claims: missing %s claim", config.NameClaim)
	}
	if config.EmailClaim != "" && claimInfo.Email == "" {
		return fmt.Errorf("invalid token claims: missing %s claim", config.EmailClaim)
	}
	return nil
}

func (g *GenOIDCProvider) TransformToAuthProvider(authConfig map[string]any) (map[string]any, error) {
	p, err := g.OpenIDCProvider.TransformToAuthProvider(authConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to transform auth config: %w", err)
	}

	if authConfig["acrValue"] != nil {
		redirectURL := p[publicclient.GenericOIDCProviderFieldRedirectURL].(string)
		p[publicclient.GenericOIDCProviderFieldRedirectURL] = redirectURL + fmt.Sprintf("&acr_values=%s", authConfig["acrValue"])
	}

	p[publicclient.GenericOIDCProviderFieldScopes] = authConfig["scope"]

	return p, nil
}

func (g *GenOIDCProvider) RefetchGroupPrincipals(principalID string, secret string) ([]apiv3.Principal, error) {
	return nil, errors.New("Not implemented")
}

func (g *GenOIDCProvider) UsesUserSecrets() bool      { return false }
func (g *GenOIDCProvider) CanRefreshPrincipals() bool { return false }

func (g *GenOIDCProvider) groupToPrincipal(groupName string) apiv3.Principal {
	return apiv3.Principal{
		ObjectMeta:    metav1.ObjectMeta{Name: g.Name + "_" + GroupType + "://" + groupName},
		DisplayName:   groupName,
		Provider:      g.Name,
		PrincipalType: GroupType,
		Me:            false,
	}
}

func (g *GenOIDCProvider) toPrincipalFromToken(principalType string, princ apiv3.Principal, token accessor.TokenAccessor) apiv3.Principal {
	if principalType == UserType {
		princ.PrincipalType = UserType
		if token != nil {
			princ.Me = g.IsThisUserMe(token.GetUserPrincipal(), princ)
			if princ.Me {
				tokenPrincipal := token.GetUserPrincipal()
				princ.LoginName = tokenPrincipal.LoginName
				princ.DisplayName = tokenPrincipal.DisplayName
			}
		}
	} else {
		princ.PrincipalType = GroupType
		if token != nil {
			princ.MemberOf = g.UserMGR.IsMemberOf(token, princ)
		}
	}
	return princ
}
