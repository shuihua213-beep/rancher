package settings

import (
	"testing"

	"github.com/rancher/apiserver/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestFormat(t *testing.T) {
	tests := []struct {
		name          string
		input         map[string]interface{}
		expectedValue string
	}{
		{
			name: "value is empty, use default",
			input: map[string]interface{}{
				"value":   "",
				"default": "my-default",
			},
			expectedValue: "my-default",
		},
		{
			name: "value is not empty, keep value",
			input: map[string]interface{}{
				"value":   "my-value",
				"default": "my-default",
			},
			expectedValue: "my-value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := &types.RawResource{
				APIObject: types.APIObject{
					Object: tt.input,
				},
			}
			format(resource)

			d := resource.APIObject.Data()
			assert.Equal(t, tt.expectedValue, d.String("value"))
		})
	}
}

func TestCollectionFormatter(t *testing.T) {
	collection := &types.GenericCollection{
		Data: []types.RawResource{
			{
				APIObject: types.APIObject{
					Object: map[string]interface{}{
						"value":   "",
						"default": "default-1",
					},
				},
			},
			{
				APIObject: types.APIObject{
					Object: map[string]interface{}{
						"value":   "value-2",
						"default": "default-2",
					},
				},
			},
		},
	}

	collectionFormatter(nil, collection)

	d1 := collection.Data[0].APIObject.Data()
	assert.Equal(t, "default-1", d1.String("value"))

	d2 := collection.Data[1].APIObject.Data()
	assert.Equal(t, "value-2", d2.String("value"))
}
