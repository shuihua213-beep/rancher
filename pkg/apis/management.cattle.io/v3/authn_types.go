package v3

import (
	"strings"
	"time"

	"github.com/rancher/norman/condition"
	"github.com/rancher/norman/types"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	UserConditionInitialRolesPopulated condition.Cond = "InitialRolesPopulated"
	AuthConfigConditionSecretsMigrated condition.Cond = "SecretsMigrated"
	// AuthConfigConditionShibbolethSecretFixed is applied to an AuthConfig when the
	// incorrect name for the shibboleth OpenLDAP secret has been fixed.
	AuthConfigConditionShibbolethSecretFixed condition.Cond = "ShibbolethSecretFixed"

	// AuthConfigOKTAPasswordMigrated is applied when an Okta password has been
	// moved to a Secret.
	AuthConfigOKTAPasswordMigrated condition.Cond = "OktaPasswordMigrated"
)

// +genclient
// +kubebuilder:skipversion
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Token struct {
	metav1.TypeMeta    `json:",inline"`
	metav1.ObjectMeta  `json:"metadata,omitempty"`
	Token              string            `json:"token" norman:"writeOnly,noupdate"`
	UserPrincipal      Principal         `json:"userPrincipal" norman:"type=reference[principal]"`
	GroupPrincipals    []Principal       `json:"groupPrincipals,omitempty" norman:"type=array[reference[principal]]"`
	ProviderInfo       map[string]string `json:"providerInfo,omitempty"`
	UserID             string            `json:"userId" norman:"type=reference[user]"`
	AuthProvider       string            `json:"authProvider"`
	TTLMillis          int64             `json:"ttl"`
	LastUsedAt         *metav1.Time      `json:"lastUsedAt,omitempty"`
	ActivityLastSeenAt *metav1.Time      `json:"activityLastSeenAt,omitempty"`
	IsDerived          bool              `json:"isDerived"`
	Description        string            `json:"description"`
	Expired            bool              `json:"expired"`
	ExpiresAt          string            `json:"expiresAt"`
	Current            bool              `json:"current"`
	ClusterName        string            `json:"clusterName,omitempty" norman:"noupdate,type=reference[cluster]"`
	Enabled            *bool             `json:"enabled,omitempty" norman:"default=true"`
}

// Implement the TokenAccessor interface

func (t *Token) GetName() string {
	return t.ObjectMeta.Name
}

func (t *Token) GetIsEnabled() bool {
	return t.Enabled == nil || *t.Enabled
}

func (t *Token) GetIsDerived() bool {
	return t.IsDerived
}

func (t *Token) GetAuthProvider() string {
	return t.AuthProvider
}

func (t *Token) GetUserID() string {
	return t.UserID
}

func (t *Token) ObjClusterName() string {
	return t.ClusterName
}

func (t *Token) GetUserPrincipal() Principal {
	return t.UserPrincipal
}

func (t *Token) GetGroupPrincipals() []Principal {
	return t.GroupPrincipals
}

func (t *Token) GetProviderInfo() map[string]string {
	return t.ProviderInfo
}

func (t *Token) GetLastUsedAt() *metav1.Time {
	return t.LastUsedAt
}

func (t *Token) GetLastActivitySeen() *metav1.Time {
	return t.ActivityLastSeenAt
}

func (t *Token) GetCreationTime() metav1.Time {
	return t.CreationTimestamp
}

func (t *Token) GetExpiresAt() string {
	return t.ExpiresAt
}

func (t *Token) GetIsExpired() bool {
	if t.TTLMillis == 0 {
		return false
	}

	created := t.ObjectMeta.CreationTimestamp.Time
	durationElapsed := time.Since(created)

	ttlDuration := time.Duration(t.TTLMillis) * time.Millisecond
	return durationElapsed.Seconds() >= ttlDuration.Seconds()
}

// +genclient
// +genclient:nonNamespaced
// +kubebuilder:resource:scope=Cluster
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// User represents a user in Rancher
type User struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// DisplayName is the user friendly name shown in the UI.
	// +optional
	DisplayName string `json:"displayName,omitempty"`
	// Description provides a brief summary about the user.
	// +optional
	Description string `json:"description"`
	// Username is the unique login identifier for the user.
	// +optional
	Username string `json:"username,omitempty"`
	// Deprecated. Password are stored in secrets in the cattle-local-user-passwords namespace.
	// +optional
	Password string `json:"password,omitempty" norman:"writeOnly,noupdate"`
	// MustChangePassword is a flag that, if true, forces the user to change their
	// password upon their next login.
	// +optional
	MustChangePassword bool `json:"mustChangePassword,omitempty"`
	// PrincipalIDs lists the authentication provider identities (e.g. GitHub, Keycloak or Active Directory)
	// that are associated with this user account.
	// +optional
	PrincipalIDs []string `json:"principalIds,omitempty" norman:"type=array[reference[principal]]"`
	// Deprecated. Only used by /v3 Rancher API.
	// +optional
	Me bool `json:"me,omitempty" norman:"nocreate,noupdate"`
	// Enabled indicates whether the user account is active.
	// +optional
	Enabled *bool `json:"enabled,omitempty" norman:"default=true"`
	// Status contains the most recent observed state of the user.
	// +optional
	Status UserStatus `json:"status"`
}

// IsSystem returns true if the user is a system user.
func (u *User) IsSystem() bool {
	for _, principalID := range u.PrincipalIDs {
		if strings.HasPrefix(principalID, "system:") {
			return true
		}
	}

	return false
}

// IsDefaultAdmin returns true if the user is the default admin user.
func (u *User) IsDefaultAdmin() bool {
	return u.Username == "admin"
}

// GetEnabled returns true if the user is enabled.
func (u *User) GetEnabled() bool {
	if u.Enabled == nil {
		return true
	}

	return *u.Enabled
}

type UserStatus struct {
	// +optional
	Conditions []UserCondition `json:"conditions"`
}

type UserCondition struct {
	// Type of user condition.
	Type string `json:"type"`
	// Status of the condition, one of True, False, Unknown.
	Status v1.ConditionStatus `json:"status"`
	// The last time this condition was updated.
	LastUpdateTime string `json:"lastUpdateTime,omitempty"`
	// Last time the condition transitioned from one status to another.
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
	// The reason for the condition's last transition.
	Reason string `json:"reason,omitempty"`
	// Human-readable message indicating details about last transition
	Message string `json:"message,omitempty"`
}

// +genclient
// +kubebuilder:skipversion
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// UserAttribute will have a CRD (and controller) generated for it, but will not be exposed in the API.
type UserAttribute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	UserName        string
	GroupPrincipals map[string]Principals
	LastRefresh     string
	NeedsRefresh    bool
	ExtraByProvider map[string]map[string][]string
	LastLogin       *metav1.Time     `json:"lastLogin,omitempty"`
	DisableAfter    *metav1.Duration `json:"disableAfter,omitempty"`
	DeleteAfter     *metav1.Duration `json:"deleteAfter,omitempty"`
}

type Principals struct {
	Items []Principal
}

// +genclient
// +kubebuilder:skipversion
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Group identifies an identity provider's group that is provisioned via SCIM.
type Group struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	DisplayName string `json:"displayName,omitempty"`
	Provider    string `json:"provider,omitempty"`
	ExternalID  string `json:"externalId,omitempty"`
}

// +genclient
// +kubebuilder:skipversion
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type GroupMember struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	GroupName   string `json:"groupName,omitempty" norman:"type=reference[group]"`
	PrincipalID string `json:"principalId,omitempty" norman:"type=reference[principal]"`
}

// +genclient
// +kubebuilder:skipversion
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Principal struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	DisplayName    string            `json:"displayName,omitempty"`
	LoginName      string            `json:"loginName,omitempty"`
	ProfilePicture string            `json:"profilePicture,omitempty"`
	ProfileURL     string            `json:"profileURL,omitempty"`
	PrincipalType  string            `json:"principalType,omitempty"`
	Me             bool              `json:"me,omitempty"`
	MemberOf       bool              `json:"memberOf,omitempty"`
	Provider       string            `json:"provider,omitempty"`
	ExtraInfo      map[string]string `json:"extraInfo,omitempty"`
}

type SearchPrincipalsInput struct {
	Name          string `json:"name" norman:"type=string,required,notnullable"`
	PrincipalType string `json:"principalType,omitempty" norman:"type=enum,options=user|group"`
	Page          int    `json:"page,omitempty" norman:"type=int"`
	PageSize      int    `json:"pageSize,omitempty" norman:"type=int"`
}

type ChangePasswordInput struct {
	CurrentPassword string `json:"currentPassword" norman:"type=string,required"`
	NewPassword     string `json:"newPassword" norman:"type=string,required"`
}

type SetPasswordInput struct {
	NewPassword string `json:"newPassword" norman:"type=string,required"`
}

// +genclient
// +kubebuilder:skipversion
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type AuthConfig struct {
	metav1.TypeMeta   `json:",inline" mapstructure:",squash"`
	metav1.ObjectMeta `json:"metadata,omitempty" mapstructure:"metadata"`

	Type                string   `json:"type" norman:"noupdate"`
	Enabled             bool     `json:"enabled,omitempty"`
	AccessMode          string   `json:"accessMode,omitempty" norman:"required,notnullable,type=enum,options=required|restricted|unrestricted"`
	AllowedPrincipalIDs []string `json:"allowedPrincipalIds,omitempty" norman:"type=array[reference[principal]]"`

	LogoutAllSupported bool `json:"logoutAllSupported,omitempty"`

	Status AuthConfigStatus `json:"status"`
}

type AuthConfigStatus struct {
	Conditions []AuthConfigConditions `json:"conditions"`
}

type AuthConfigConditions struct {
	Type condition.Cond `json:"type"`
	Status v1.ConditionStatus `json:"status"`
	LastUpdateTime string `json:"lastUpdateTime,omitempty"`
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
	Reason string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// +genclient
// +kubebuilder:skipversion
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type SamlToken struct {
	types.Namespaced
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Token             string `json:"token"`
	RedirectTo        string `json:"redirectTo"`
	CreatedAt         string `json:"createdAt"`
	Expired           bool   `json:"expired"`
	AuthProvider      string `json:"authProvider,omitempty"`
}
