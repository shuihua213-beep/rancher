package settings

import (
	"github.com/rancher/apiserver/pkg/types"
	"github.com/rancher/rancher/pkg/settings"
	schema2 "github.com/rancher/steve/pkg/schema"
	steve "github.com/rancher/steve/pkg/server"
)

func Register(server *steve.Server) {
	server.SchemaFactory.AddTemplate(schema2.Template{
		Group: "management.cattle.io",
		Kind:  "Setting",
		StoreFactory: func(innerStore types.Store) types.Store {
			return &store{Store: innerStore}
		},
		Formatter: func(request *types.APIRequest, resource *types.RawResource) {
			data := resource.APIObject.Data()
			if data.String("value") == "" {
				data.Set("value", resolveSettingValue(resource.ID, "", data.String("default"), nil))
			}
		},
	})
}

type store struct {
	types.Store
}

func (s *store) ByID(apiOp *types.APIRequest, schema *types.APISchema, id string) (types.APIObject, error) {
	result, err := s.Store.ByID(apiOp, schema, id)
	if err != nil {
		return result, err
	}

	applySettingValue(&result, settings.GetValues(id))
	return result, nil
}

func (s *store) List(apiOp *types.APIRequest, schema *types.APISchema) (types.APIObjectList, error) {
	result, err := s.Store.List(apiOp, schema)
	if err != nil {
		return result, err
	}

	values := settings.GetValues(missingSettingNames(result.Objects)...)
	for i := range result.Objects {
		applySettingValue(&result.Objects[i], values)
	}

	return result, nil
}

func missingSettingNames(objects []types.APIObject) []string {
	names := make([]string, 0, len(objects))
	seen := map[string]struct{}{}
	for i := range objects {
		if objects[i].Data().String("value") != "" {
			continue
		}
		if _, ok := seen[objects[i].ID]; ok {
			continue
		}
		seen[objects[i].ID] = struct{}{}
		names = append(names, objects[i].ID)
	}
	return names
}

func applySettingValue(obj *types.APIObject, values map[string]string) {
	data := obj.Data()
	if data.String("value") != "" {
		return
	}
	data.Set("value", resolveSettingValue(obj.ID, "", data.String("default"), values))
}

func resolveSettingValue(name, value, defaultValue string, values map[string]string) string {
	if value != "" {
		return value
	}
	if values != nil {
		if resolved, ok := values[name]; ok && resolved != "" {
			return resolved
		}
	}
	return defaultValue
}
