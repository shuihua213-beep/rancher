package cluster

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/types"
	"github.com/rancher/norman/types/convert"
	apimgmtv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/accessor"
	v3 "github.com/rancher/rancher/pkg/client/generated/management/v3"
	"github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3/fakes"
	managementSchema "github.com/rancher/rancher/pkg/schemas/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/rancher/pkg/user"
	userMocks "github.com/rancher/rancher/pkg/user/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	testClusterName = "test-cluster"
	fakeHost        = "fake-request-host.fake"
	testUser        = "test-user"
	errUserName     = "err-user"
)

func TestGenerateKubeconfigActionHandler(t *testing.T) {
	tests := []struct {
		name          string
		hostname      string
		generateToken string
	}{
		{
			name:          "no token generation",
			generateToken: "false",
		},
		{
			name:          "token generation",
			generateToken: "true",
		},
		{
			name:          "token generation with hostname set",
			hostname:      "https://set-hostname.fake",
			generateToken: "true",
		},
		{
			name:          "no token generation with hostname set",
			hostname:      "https://set-hostname.fake",
			generateToken: "false",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			userManager := userMocks.NewMockManager(ctrl)
			userManager.EXPECT().GetUser(gomock.Any()).Return(testUser).AnyTimes()

			err := settings.KubeconfigGenerateToken.Set(test.generateToken)
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, settings.KubeconfigGenerateToken.Set(""))
			})

			err = settings.ServerURL.Set(test.hostname)
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, settings.ServerURL.Set(""))
			})

			apiContext, recorder := newTestAPIContext(&fakeClusterStore{
				cluster: v3.Cluster{
					Name: testClusterName,
				},
			}, nil)

			handler := newTestActionHandler(userManager, &fakeTokenManager{}, nil)
			err = handler.GenerateKubeconfigActionHandler("not-used", nil, apiContext)
			require.NoError(t, err)
			require.Len(t, recorder.Responses, 1)

			response := recorder.Responses[0]
			assert.Equal(t, http.StatusOK, response.Code)

			data, ok := response.Data.(map[string]interface{})
			require.True(t, ok)

			kubeconfig, ok := data["config"].(string)
			require.True(t, ok)
			assert.Equal(t, "generateKubeconfigOutput", data["type"])

			if test.generateToken == "true" {
				assert.Contains(t, kubeconfig, fmt.Sprintf("kubeconfig-%s:", testUser))
			}
			if test.hostname == "" {
				assert.Contains(t, kubeconfig, fakeHost)
			} else {
				assert.Contains(t, kubeconfig, test.hostname)
			}
		})
	}
}

func TestGenerateKubeconfigActionHandler_ErrorPaths(t *testing.T) {
	t.Run("cluster not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		userManager := userMocks.NewMockManager(ctrl)
		userManager.EXPECT().GetUser(gomock.Any()).Return(testUser).AnyTimes()

		apiContext, recorder := newTestAPIContext(&fakeClusterStore{
			err: httperror.NewAPIError(httperror.NotFound, ""),
		}, nil)

		handler := newTestActionHandler(userManager, &fakeTokenManager{}, nil)
		err := handler.GenerateKubeconfigActionHandler("not-used", nil, apiContext)
		assertAPIError(t, err, httperror.NewAPIError(httperror.NotFound, ""))
		assert.Empty(t, recorder.Responses)
	})

	t.Run("permission denied", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		userManager := userMocks.NewMockManager(ctrl)
		userManager.EXPECT().GetUser(gomock.Any()).Return(testUser).AnyTimes()

		permissionDeniedErr := httperror.NewAPIError(httperror.PermissionDenied, "can not get cluster ")
		apiContext, recorder := newTestAPIContext(&fakeClusterStore{
			cluster: v3.Cluster{
				Name: testClusterName,
			},
		}, &stubAccessControl{err: permissionDeniedErr})

		handler := newTestActionHandler(userManager, &fakeTokenManager{}, nil)
		err := handler.GenerateKubeconfigActionHandler("not-used", nil, apiContext)
		assertAPIError(t, err, permissionDeniedErr)
		assert.Empty(t, recorder.Responses)
	})

	t.Run("kubeconfig generation failure", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		userManager := userMocks.NewMockManager(ctrl)
		userManager.EXPECT().GetUser(gomock.Any()).Return(testUser).AnyTimes()

		originalForTokenBased := forTokenBased
		forTokenBased = func(clusterName, clusterID, host, token string) (string, error) {
			return "", errors.New("failed to generate kubeconfig")
		}
		t.Cleanup(func() {
			forTokenBased = originalForTokenBased
		})

		apiContext, recorder := newTestAPIContext(&fakeClusterStore{
			cluster: v3.Cluster{
				Name: testClusterName,
			},
		}, nil)

		handler := newTestActionHandler(userManager, &fakeTokenManager{}, nil)
		err := handler.GenerateKubeconfigActionHandler("not-used", nil, apiContext)
		require.EqualError(t, err, "failed to generate kubeconfig")
		assert.Empty(t, recorder.Responses)
	})
}

func newTestAPIContext(store types.Store, accessControl types.AccessControl) (*types.APIContext, *normanRecorder) {
	testSchemas := types.NewSchemas().AddSchemas(managementSchema.Schemas)
	clusterSchema := testSchemas.Schema(&managementSchema.Version, v3.ClusterType)
	clusterSchema.Store = store

	recorder := &normanRecorder{}
	apiContext := &types.APIContext{
		ID:             testClusterName,
		Version:        &managementSchema.Version,
		Type:           v3.ClusterType,
		ResponseWriter: recorder,
		Schemas:        testSchemas,
		Request:        &http.Request{Host: fakeHost},
		AccessControl:  accessControl,
	}

	return apiContext, recorder
}

func newTestActionHandler(userManager userManager, tokenManager tokenManager, nodeListerErr error) ActionHandler {
	return ActionHandler{
		NodeLister: &fakes.NodeListerMock{
			GetFunc: func(namespace string, name string) (*apimgmtv3.Node, error) {
				return nil, nil
			},
			ListFunc: func(namespace string, selector labels.Selector) ([]*apimgmtv3.Node, error) {
				return nil, nodeListerErr
			},
		},
		UserMgr:   userManager,
		TokenMgr:  tokenManager,
		AuthToken: newFakeAuthToken(testUser),
	}
}

func newFakeAuthToken(userName string) *fakeAuthToken {
	return &fakeAuthToken{
		token: apimgmtv3.Token{
			AuthProvider: "local",
			UserPrincipal: apimgmtv3.Principal{
				Provider: "local",
				ObjectMeta: metav1.ObjectMeta{
					Name: userName,
				},
			},
		},
	}
}

func assertAPIError(t *testing.T, err error, want *httperror.APIError) {
	t.Helper()
	require.Error(t, err)

	var apiErr *httperror.APIError
	require.True(t, errors.As(err, &apiErr), "expected httperror.APIError, got %T", err)
	assert.Equal(t, want.Code.Status, apiErr.Code.Status)
	assert.Equal(t, want.Message, apiErr.Message)
}

type stubAccessControl struct {
	err error
}

func (s *stubAccessControl) CanCreate(apiContext *types.APIContext, schema *types.Schema) error {
	return s.err
}

func (s *stubAccessControl) CanList(apiContext *types.APIContext, schema *types.Schema) error {
	return s.err
}

func (s *stubAccessControl) CanGet(apiContext *types.APIContext, schema *types.Schema) error {
	return s.err
}

func (s *stubAccessControl) CanUpdate(apiContext *types.APIContext, obj map[string]interface{}, schema *types.Schema) error {
	return s.err
}

func (s *stubAccessControl) CanDelete(apiContext *types.APIContext, obj map[string]interface{}, schema *types.Schema) error {
	return s.err
}

func (s *stubAccessControl) CanDo(apiGroup, resource, verb string, apiContext *types.APIContext, obj map[string]interface{}, schema *types.Schema) error {
	return s.err
}

func (s *stubAccessControl) Filter(apiContext *types.APIContext, schema *types.Schema, obj map[string]interface{}, context map[string]string) map[string]interface{} {
	if s.err != nil {
		return nil
	}
	return obj
}

func (s *stubAccessControl) FilterList(apiContext *types.APIContext, schema *types.Schema, objs []map[string]interface{}, context map[string]string) []map[string]interface{} {
	if s.err != nil {
		return nil
	}
	return objs
}

type fakeClusterStore struct {
	err     error
	cluster v3.Cluster
}

func (f *fakeClusterStore) ByID(apiContext *types.APIContext, schema *types.Schema, id string) (map[string]interface{}, error) {
	if f.err != nil {
		return nil, f.err
	}
	return convert.EncodeToMap(f.cluster)
}

func (f *fakeClusterStore) Context() types.StorageContext { return "" }
func (f *fakeClusterStore) List(apiContext *types.APIContext, schema *types.Schema, opt *types.QueryOptions) ([]map[string]interface{}, error) {
	return nil, nil
}
func (f *fakeClusterStore) Create(apiContext *types.APIContext, schema *types.Schema, data map[string]interface{}) (map[string]interface{}, error) {
	return nil, nil
}
func (f *fakeClusterStore) Update(apiContext *types.APIContext, schema *types.Schema, data map[string]interface{}, id string) (map[string]interface{}, error) {
	return nil, nil
}
func (f *fakeClusterStore) Delete(apiContext *types.APIContext, schema *types.Schema, id string) (map[string]interface{}, error) {
	return nil, nil
}
func (f *fakeClusterStore) Watch(apiContext *types.APIContext, schema *types.Schema, opt *types.QueryOptions) (chan map[string]interface{}, error) {
	return nil, nil
}

type normanRecorder struct {
	Responses []struct {
		Code int
		Data interface{}
	}
}

func (n *normanRecorder) Write(apiContext *types.APIContext, code int, obj interface{}) {
	if n.Responses == nil {
		n.Responses = []struct {
			Code int
			Data interface{}
		}{}
	}
	n.Responses = append(n.Responses, struct {
		Code int
		Data interface{}
	}{
		Code: code,
		Data: obj,
	})
}

type fakeAuthToken struct {
	token apimgmtv3.Token
	err   error
}

func (f *fakeAuthToken) TokenFromRequest(req *http.Request) (accessor.TokenAccessor, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &f.token, nil
}

type fakeTokenManager struct{}

func (f *fakeTokenManager) EnsureToken(input user.TokenInput) (string, runtime.Object, error) {
	if input.UserName == errUserName {
		return "", nil, fmt.Errorf("can't generate token for err user")
	}
	return input.TokenName + ":" + "tokenvalue", nil, nil
}

func (f *fakeTokenManager) EnsureClusterToken(clusterName string, input user.TokenInput) (string, runtime.Object, error) {
	if input.UserName == errUserName {
		return "", nil, fmt.Errorf("can't generate token for err user")
	}
	return input.TokenName + ":" + "tokenvalue", nil, nil
}
