package settings

import (
	"github.com/rancher/apiserver/pkg/types"
)

type store struct {
	types.Store
}

func (s *store) List(apiOp *types.APIRequest, schema *types.APISchema) (types.APIObjectList, error) {
	result, err := s.Store.List(apiOp, schema)
	if err != nil {
		return result, err
	}
	for i := range result.Objects {
		applyDefaultIfEmpty(result.Objects[i])
	}
	return result, nil
}

func (s *store) ByID(apiOp *types.APIRequest, schema *types.APISchema, id string) (types.APIObject, error) {
	result, err := s.Store.ByID(apiOp, schema, id)
	if err != nil {
		return result, err
	}
	applyDefaultIfEmpty(result)
	return result, nil
}

func applyDefaultIfEmpty(obj types.APIObject) {
	data := obj.Data()
	if data.String("value") == "" {
		data.Set("value", data.String("default"))
	}
}
