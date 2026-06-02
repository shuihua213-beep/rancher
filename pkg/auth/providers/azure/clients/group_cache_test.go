package clients

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func TestUserGroupsToPrincipals(t *testing.T) {
	setupTestCache(t)
	testGUID := "0f8fad5b-d9cb-469f-a165-70867728950e"

	fc := &fakePrincipalsClient{
		groups: map[string]fakeGroup{
			testGUID: {id: ptr.To(testGUID)},
		},
	}
	principals, err := UserGroupsToPrincipals(fc, []string{testGUID})
	require.NoError(t, err)

	want := []v3.Principal{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "azuread_group://0f8fad5b-d9cb-469f-a165-70867728950e",
			},
			PrincipalType: "group",
			MemberOf:      true,
			Provider:      "azuread",
		},
	}
	assert.Equal(t, want, principals)
}

func TestUserGroupsToPrincipals_CoalescesConcurrentCacheMisses(t *testing.T) {
	setupTestCache(t)
	testGUID := "0f8fad5b-d9cb-469f-a165-70867728950e"
	want := []v3.Principal{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "azuread_group://0f8fad5b-d9cb-469f-a165-70867728950e",
			},
			PrincipalType: "group",
			MemberOf:      true,
			Provider:      "azuread",
		},
	}

	fc := &fakePrincipalsClient{
		delay: 50 * time.Millisecond,
		groups: map[string]fakeGroup{
			testGUID: {id: ptr.To(testGUID)},
		},
	}

	const callers = 32
	start := make(chan struct{})
	results := make(chan []v3.Principal, callers)
	errs := make(chan error, callers)

	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			principals, err := UserGroupsToPrincipals(fc, []string{testGUID})
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
	assert.EqualValues(t, 1, fc.calls.Load())
}

type fakePrincipalsClient struct {
	groups map[string]fakeGroup
	delay  time.Duration
	calls  atomic.Int32
}

func (f *fakePrincipalsClient) GetGroup(id string) (v3.Principal, error) {
	f.calls.Add(1)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	return groupToPrincipal(f.groups[id]), nil
}

type fakeGroup struct {
	id          *string
	displayName *string
}

func (f fakeGroup) GetId() *string {
	return f.id
}

func (f fakeGroup) GetDisplayName() *string {
	return f.displayName
}

func setupTestCache(t *testing.T) {
	t.Helper()
	oldGroupCache := GroupCache
	t.Cleanup(func() {
		GroupCache = oldGroupCache
	})
	gc, err := lru.New(10)
	require.NoError(t, err)
	GroupCache = gc
}
