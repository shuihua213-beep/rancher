package settings

import (
	"github.com/rancher/apiserver/pkg/types"
	schema2 "github.com/rancher/steve/pkg/schema"
	steve "github.com/rancher/steve/pkg/server"
)

func Register(server *steve.Server) {
	server.SchemaFactory.AddTemplate(schema2.Template{
		Group: "management.cattle.io",
		Kind:  "Setting",
		StoreFactory: func(innerStore types.Store) types.Store {
			return &store{
				Store: innerStore,
			}
		},
	})
}
