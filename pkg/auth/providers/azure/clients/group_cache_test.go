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

func TestUserGroupsToPrincipals_ConcurrentRequestsDeduplication(t *testing.T) {
	setupTestCache(t)
	testGUID := "0f8fad5b-d9cb-469f-a165-70867728950e"

	// Create a fake client that tracks how many times GetGroup is called
	fc := &countingFakePrincipalsClient{
		groups: map[string]fakeGroup{
			testGUID: fakeGroup{id: ptr.To(testGUID)},
		},
		delay: 100 * time.Millisecond, // Add some delay to simulate real API
	}

	const concurrentRequests = 100

	// Launch multiple concurrent requests for the same group
	var wg sync.WaitGroup
	results := make([][]v3.Principal, concurrentRequests)
	errors := make([]error, concurrentRequests)

	for i := 0; i < concurrentRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			principals, err := UserGroupsToPrincipals(fc, []string{testGUID})
			results[idx] = principals
			errors[idx] = err
		}(i)
	}

	wg.Wait()

	// Verify all requests succeeded
	for i := 0; i < concurrentRequests; i++ {
		require.NoError(t, errors[i])
		require.Len(t, results[i], 1)
		assert.Equal(t, "azuread_group://"+testGUID, results[i][0].Name)
	}

	// Verify GetGroup was called only once
	assert.Equal(t, 1, fc.getCallCount(), "Expected GetGroup to be called only once, but got %d calls", fc.getCallCount())
}

type fakePrincipalsClient struct {
	groups map[string]fakeGroup
}

func (f *fakePrincipalsClient) GetGroup(id string) (v3.Principal, error) {
	return groupToPrincipal(f.groups[id]), nil
}

type countingFakePrincipalsClient struct {
	groups    map[string]fakeGroup
	callCount int
	mu        sync.Mutex
	delay     time.Duration
}

func (f *countingFakePrincipalsClient) GetGroup(id string) (v3.Principal, error) {
	f.mu.Lock()
	f.callCount++
	f.mu.Unlock()

	// Simulate API delay
	if f.delay > 0 {
		time.Sleep(f.delay)
	}

	return groupToPrincipal(f.groups[id]), nil
}

func (f *countingFakePrincipalsClient) getCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callCount
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
