package clients

import (
	"fmt"
	"time"

	lru "github.com/hashicorp/golang-lru"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

// GroupCache is an in-memory cache of group principals.
var GroupCache *lru.Cache

var groupLookupGroup singleflight.Group

type userPrincipalsClient interface {
	GetGroup(id string) (v3.Principal, error)
}

func cachedGroupPrincipal(groupID string) (v3.Principal, bool) {
	if GroupCache == nil {
		return v3.Principal{}, false
	}

	principal, ok := GroupCache.Get(groupID)
	if !ok {
		return v3.Principal{}, false
	}

	p, ok := principal.(v3.Principal)
	if !ok {
		logrus.Errorf("failed to convert a cached group to principal")
		return v3.Principal{}, false
	}

	return p, true
}

func cacheGroupPrincipal(groupID string, principal v3.Principal) {
	if GroupCache == nil {
		return
	}

	GroupCache.Add(groupID, principal)
}

func getGroupPrincipal(azureClient userPrincipalsClient, groupID string) (v3.Principal, error) {
	if principal, ok := cachedGroupPrincipal(groupID); ok {
		return principal, nil
	}

	principal, err, _ := groupLookupGroup.Do(groupID, func() (interface{}, error) {
		if cachedPrincipal, ok := cachedGroupPrincipal(groupID); ok {
			return cachedPrincipal, nil
		}

		groupObj, err := azureClient.GetGroup(groupID)
		if err != nil {
			return v3.Principal{}, err
		}
		groupObj.MemberOf = true
		cacheGroupPrincipal(groupID, groupObj)
		return groupObj, nil
	})
	if err != nil {
		return v3.Principal{}, err
	}

	groupPrincipal, ok := principal.(v3.Principal)
	if !ok {
		return v3.Principal{}, fmt.Errorf("failed to convert a fetched group to principal")
	}

	return groupPrincipal, nil
}

// UserGroupsToPrincipals attempts to convert a value representing a collection of groups to a slice of principal values.
// It also stores group values in an in-memory cache for faster subsequent access.
func UserGroupsToPrincipals(azureClient userPrincipalsClient, groupNames []string) ([]v3.Principal, error) {
	var tasksManager errgroup.Group
	groupPrincipals := make([]v3.Principal, len(groupNames))

	start := time.Now()
	logrus.Debug("[AZURE_PROVIDER] Started gathering users groups")

	for i, id := range groupNames {
		if id == "" {
			continue
		}

		j := i
		groupID := id

		if principal, ok := cachedGroupPrincipal(groupID); ok {
			groupPrincipals[j] = principal
			continue
		}

		tasksManager.Go(func() error {
			groupObj, err := getGroupPrincipal(azureClient, groupID)
			if err != nil {
				logrus.Errorf("[AZURE_PROVIDER] Error getting group: %v", err)
				return err
			}

			groupPrincipals[j] = groupObj
			return nil
		})
	}
	if err := tasksManager.Wait(); err != nil {
		return nil, err
	}
	logrus.Debugf("[AZURE_PROVIDER] Completed gathering users groups, took %v, keys in cache:%v", time.Since(start), GroupCache.Len())
	return groupPrincipals, nil
}
