package clients

import (
	"time"

	lru "github.com/hashicorp/golang-lru"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

// GroupCache is an in-memory cache of group principals.
var GroupCache *lru.Cache

var groupFetchGroup singleflight.Group

type userPrincipalsClient interface {
	GetGroup(id string) (v3.Principal, error)
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

		if principal, ok := GroupCache.Get(groupID); ok {
			p, ok := principal.(v3.Principal)
			if !ok {
				logrus.Errorf("failed to convert a cached group to principal")
				continue
			}
			groupPrincipals[j] = p
			continue
		}

		tasksManager.Go(func() error {
			// This is inefficient for a collection of msgraph.Group. This is temporary - until support for Azure AD Graph is removed.
			// The SDK for Microsoft Graph returns actual groups when queried for a user's group memberships.
			// The SDK for Azure AD Graph returns group names as strings.
			// The common interface that abstracts the Graph operations returns group names as strings.
			// So Microsoft Graph groups are effectively fetched twice. But this happens only once - before the groups are added to the cache.
			v, err, _ := groupFetchGroup.Do(groupID, func() (interface{}, error) {
				// Re-check the cache inside the singleflight to avoid duplicate network requests
				// if another goroutine has just fetched and cached the group.
				if principal, ok := GroupCache.Get(groupID); ok {
					if p, ok := principal.(v3.Principal); ok {
						return p, nil
					}
				}

				groupObj, err := azureClient.GetGroup(groupID)
				if err != nil {
					logrus.Errorf("[AZURE_PROVIDER] Error getting group: %v", err)
					return nil, err
				}
				groupObj.MemberOf = true

				GroupCache.Add(groupID, groupObj)
				return groupObj, nil
			})

			if err != nil {
				return err
			}
			
			groupPrincipals[j] = v.(v3.Principal)
			return nil
		})
	}
	if err := tasksManager.Wait(); err != nil {
		return nil, err
	}
	logrus.Debugf("[AZURE_PROVIDER] Completed gathering users groups, took %v, keys in cache:%v", time.Since(start), GroupCache.Len())
	return groupPrincipals, nil
}
