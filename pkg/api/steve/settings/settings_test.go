package settings

import "testing"

func TestResolveSettingValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		settingName  string
		value        string
		defaultValue string
		batchValues  map[string]string
		want         string
	}{
		{
			name:         "keeps explicit value",
			settingName:  "server-url",
			value:        "https://configured.example.com",
			defaultValue: "https://default.example.com",
			batchValues: map[string]string{
				"server-url": "https://batch.example.com",
			},
			want: "https://configured.example.com",
		},
		{
			name:         "uses batch value when setting is empty",
			settingName:  "server-url",
			defaultValue: "https://default.example.com",
			batchValues: map[string]string{
				"server-url": "https://batch.example.com",
			},
			want: "https://batch.example.com",
		},
		{
			name:         "falls back to default to preserve response shape",
			settingName:  "server-url",
			defaultValue: "https://default.example.com",
			batchValues:  map[string]string{},
			want:         "https://default.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := resolveSettingValue(tt.settingName, tt.value, tt.defaultValue, tt.batchValues)
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
