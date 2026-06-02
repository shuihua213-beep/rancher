package clients

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAzureMSGraphClient_listGroupPrincipals_CoalescesConcurrentRequests(t *testing.T) {
	setupTestCache(t)

	const callers = 32
	userID := "user-1"
	groupID := "group-1"
	displayName := "test-group"
	securityEnabled := true
	want := []v3.Principal{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "azuread_group://group-1"},
			DisplayName:   displayName,
			PrincipalType: "group",
			Provider:      Name,
			MemberOf:      true,
		},
	}

	var membershipCalls atomic.Int32
	client := AzureMSGraphClient{
		GroupRequestKey: t.Name(),
		listGroupMembershipsFunc: func(ctx context.Context, requestedUserID string, filter string, f func(*models.Group)) error {
			if requestedUserID != userID {
				return assert.AnError
			}

			membershipCalls.Add(1)
			time.Sleep(50 * time.Millisecond)

			group := models.NewGroup()
			group.SetId(&groupID)
			group.SetDisplayName(&displayName)
			group.SetSecurityEnabled(&securityEnabled)
			f(group)
			return nil
		},
	}
	userPrincipal := v3.Principal{ObjectMeta: metav1.ObjectMeta{Name: Name + "_user://" + userID}}

	start := make(chan struct{})
	results := make(chan []v3.Principal, callers)
	errs := make(chan error, callers)

	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			principals, err := client.listGroupPrincipals(context.Background(), userPrincipal, "")
			if err != nil {
				errs <- err
				return
			}
			results <- principals
		}()
	}

	close(start)
	wg.Wait()
	close(errs)
	close(results)

	for err := range errs {
		require.NoError(t, err)
	}
	for principals := range results {
		assert.Equal(t, want, principals)
	}
	assert.EqualValues(t, 1, membershipCalls.Load())

	cachedGroup, ok := cachedGroupPrincipal(groupID)
	require.True(t, ok)
	assert.Equal(t, want[0], cachedGroup)
}
