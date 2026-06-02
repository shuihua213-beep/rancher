package clients

import (
	"sync"
	"sync/atomic"
	"testing"

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

func TestUserGroupsToPrincipals_DuplicateIDs(t *testing.T) {
	setupTestCache(t)
	testGUID := "0f8fad5b-d9cb-469f-a165-70867728950e"

	cc := &countingFakePrincipalsClient{
		count:  make(map[string]int32),
		groups: map[string]fakeGroup{
			testGUID: fakeGroup{id: ptr.To(testGUID)},
		},
	}

	principals, err := UserGroupsToPrincipals(cc, []string{testGUID, testGUID, testGUID})
	require.NoError(t, err)

	assert.Len(t, principals, 3)
	for _, p := range principals {
		assert.Equal(t, "azuread_group://0f8fad5b-d9cb-469f-a165-70867728950e", p.Name)
		assert.Equal(t, "group", p.PrincipalType)
		assert.True(t, p.MemberOf)
	}

	assert.Equal(t, int32(1), atomic.LoadInt32(&cc.count[testGUID]),
		"only one remote request should be made for duplicate group IDs in a single call")
}

func TestUserGroupsToPrincipals_ConcurrentDedup(t *testing.T) {
	setupTestCache(t)
	testGUID := "0f8fad5b-d9cb-469f-a165-70867728950e"

	cc := &countingFakePrincipalsClient{
		count:  make(map[string]int32),
		groups: map[string]fakeGroup{
			testGUID: fakeGroup{id: ptr.To(testGUID)},
		},
	}

	const concurrency = 20
	var wg sync.WaitGroup
	errs := make(chan error, concurrency)

	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := UserGroupsToPrincipals(cc, []string{testGUID})
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatal(err)
	}

	assert.Equal(t, int32(1), atomic.LoadInt32(&cc.count[testGUID]),
		"concurrent requests for the same group should trigger only one remote call")
}

func TestUserGroupsToPrincipals_MixedGroups(t *testing.T) {
	setupTestCache(t)
	guidA := "0f8fad5b-d9cb-469f-a165-70867728950e"
	guidB := "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

	cc := &countingFakePrincipalsClient{
		count: make(map[string]int32),
		groups: map[string]fakeGroup{
			guidA: fakeGroup{id: ptr.To(guidA)},
			guidB: fakeGroup{id: ptr.To(guidB)},
		},
	}

	principals, err := UserGroupsToPrincipals(cc, []string{guidA, guidB, guidA, guidB, guidA, guidB})
	require.NoError(t, err)
	assert.Len(t, principals, 6)

	assert.Equal(t, int32(1), atomic.LoadInt32(&cc.count[guidA]),
		"group A should be fetched only once")
	assert.Equal(t, int32(1), atomic.LoadInt32(&cc.count[guidB]),
		"group B should be fetched only once")
}

type fakePrincipalsClient struct {
	groups map[string]fakeGroup
}

func (f *fakePrincipalsClient) GetGroup(id string) (v3.Principal, error) {
	return groupToPrincipal(f.groups[id]), nil
}

type countingFakePrincipalsClient struct {
	count  map[string]int32
	groups map[string]fakeGroup
}

func (f *countingFakePrincipalsClient) GetGroup(id string) (v3.Principal, error) {
	atomic.AddInt32(&f.count[id], 1)
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
	oldSingleFlight := groupCacheSingleFlight
	t.Cleanup(func() {
		GroupCache = oldGroupCache
		groupCacheSingleFlight = oldSingleFlight
	})
	gc, err := lru.New(10)
	require.NoError(t, err)
	GroupCache = gc
	groupCacheSingleFlight = singleflight.Group{}
}
