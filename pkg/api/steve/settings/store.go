package settings

import (
	"github.com/rancher/apiserver/pkg/types"
)

type store struct {
	types.Store
}

func (s *store) ByID(apiOp *types.APIRequest, schema *types.APISchema, id string) (types.APIObject, error) {
	result, err := s.Store.ByID(apiOp, schema, id)
	if err != nil {
		return result, err
	}
	applyDefault(result)
	return result, nil
}

func (s *store) List(apiOp *types.APIRequest, schema *types.APISchema) (types.APIObjectList, error) {
	result, err := s.Store.List(apiOp, schema)
	if err != nil {
		return result, err
	}
	for i := range result.Objects {
		applyDefault(result.Objects[i])
	}
	return result, nil
}

func (s *store) Watch(apiOp *types.APIRequest, schema *types.APISchema, wr types.WatchRequest) (chan types.APIEvent, error) {
	result, err := s.Store.Watch(apiOp, schema, wr)
	if err != nil {
		return result, err
	}

	newResult := make(chan types.APIEvent, 1)
	go func() {
		defer close(newResult)
		for event := range result {
			applyDefault(event.Object)
			newResult <- event
		}
	}()

	return newResult, nil
}

func applyDefault(obj types.APIObject) {
	data := obj.Data()
	if data.String("value") == "" {
		data.Set("value", data.String("default"))
	}
}