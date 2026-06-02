package clients

import (
	"sync"
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
			testGUID: fakeGroup{id: ptr.To(testGUID)},
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

func TestUserGroupsToPrincipals_Concurrency(t *testing.T) {
	setupTestCache(t)
	testGUID := "0f8fad5b-d9cb-469f-a165-70867728950e"

	fc := &fakePrincipalsClient{
		groups: map[string]fakeGroup{
			testGUID: {id: ptr.To(testGUID)},
		},
		delay: 50 * time.Millisecond,
	}

	var wg sync.WaitGroup
	numWorkers := 10
	wg.Add(numWorkers)

	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			principals, err := UserGroupsToPrincipals(fc, []string{testGUID})
			require.NoError(t, err)
			require.Len(t, principals, 1)
			assert.Equal(t, "azuread_group://"+testGUID, principals[0].Name)
		}()
	}

	wg.Wait()

	// Should only be called once due to singleflight
	assert.Equal(t, 1, fc.callCount, "expected GetGroup to be called exactly once")
}

type fakePrincipalsClient struct {
	groups    map[string]fakeGroup
	callCount int
	mu        sync.Mutex
	delay     time.Duration
}

func (f *fakePrincipalsClient) GetGroup(id string) (v3.Principal, error) {
	f.mu.Lock()
	f.callCount++
	f.mu.Unlock()
	
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
