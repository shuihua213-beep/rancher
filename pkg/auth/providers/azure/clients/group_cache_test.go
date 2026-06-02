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
	"golang.org/x/sync/singleflight"
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

type fakePrincipalsClient struct {
	groups    map[string]fakeGroup
	callCount int64
	delay     time.Duration
	mu        sync.Mutex
}

func (f *fakePrincipalsClient) GetGroup(id string) (v3.Principal, error) {
	atomic.AddInt64(&f.callCount, 1)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	f.mu.Lock()
	g := f.groups[id]
	f.mu.Unlock()
	return groupToPrincipal(g), nil
}

func (f *fakePrincipalsClient) getCallCount() int64 {
	return atomic.LoadInt64(&f.callCount)
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
	oldFlight := groupCacheFlight
	t.Cleanup(func() {
		GroupCache = oldGroupCache
		groupCacheFlight = oldFlight
	})
	gc, err := lru.New(10)
	require.NoError(t, err)
	GroupCache = gc
	groupCacheFlight = singleflight.Group{}
}

func TestUserGroupsToPrincipals_ConcurrentDedup(t *testing.T) {
	setupTestCache(t)
	testGUID := "0f8fad5b-d9cb-469f-a165-70867728950e"

	fc := &fakePrincipalsClient{
		groups: map[string]fakeGroup{
			testGUID: {id: ptr.To(testGUID)},
		},
		delay: 50 * time.Millisecond,
	}

	const concurrency = 20
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			principals, err := UserGroupsToPrincipals(fc, []string{testGUID})
			require.NoError(t, err)
			require.Len(t, principals, 1)
			assert.True(t, principals[0].MemberOf)
			assert.Equal(t, "azuread_group://"+testGUID, principals[0].Name)
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(1), fc.getCallCount(), "GetGroup should only be called once despite %d concurrent requests", concurrency)
}

func TestUserGroupsToPrincipals_ConcurrentMultipleGroups(t *testing.T) {
	setupTestCache(t)

	groupA := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	groupB := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	fc := &fakePrincipalsClient{
		groups: map[string]fakeGroup{
			groupA: {id: ptr.To(groupA)},
			groupB: {id: ptr.To(groupB)},
		},
		delay: 50 * time.Millisecond,
	}

	const concurrency = 10
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			principals, err := UserGroupsToPrincipals(fc, []string{groupA, groupB})
			require.NoError(t, err)
			require.Len(t, principals, 2)
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(2), fc.getCallCount(), "GetGroup should be called once per unique group, not per concurrent request")
}
