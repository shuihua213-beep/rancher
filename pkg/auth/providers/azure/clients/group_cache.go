package clients

import (
	"time"

	lru "github.com/hashicorp/golang-lru"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

var GroupCache *lru.Cache

var groupCacheFlight singleflight.Group

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
			v, err, _ := groupCacheFlight.Do("sf:"+groupID, func() (interface{}, error) {
				if principal, ok := GroupCache.Get(groupID); ok {
					p, ok := principal.(v3.Principal)
					if !ok {
						logrus.Errorf("failed to convert a cached group to principal")
						return nil, nil
					}
					return p, nil
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
			if v == nil {
				return nil
			}
			p, ok := v.(v3.Principal)
			if !ok {
				logrus.Errorf("failed to convert a singleflight result to principal")
				return nil
			}
			groupPrincipals[j] = p
			return nil
		})
	}
	if err := tasksManager.Wait(); err != nil {
		return nil, err
	}
	logrus.Debugf("[AZURE_PROVIDER] Completed gathering users groups, took %v, keys in cache:%v", time.Since(start), GroupCache.Len())
	return groupPrincipals, nil
}
