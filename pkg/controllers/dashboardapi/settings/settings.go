// Package settings registers the settings provider which acts as a client for setting and provides functions for
// maintaining settings in k8s on startup. This maintenance includes configuring setting to match any corresponding
// env variables that are set or updating their default values.
package settings

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	managementcontrollers "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/settings"
)

func Register(settingController managementcontrollers.SettingController) error {
	sp := &settingsProvider{
		settings:     settingController,
		settingCache: settingController.Cache(),
	}

	return settings.SetProvider(sp)
}

type settingsProvider struct {
	settings     managementcontrollers.SettingClient
	settingCache managementcontrollers.SettingCache
	fallback     map[string]string
}

func (s *settingsProvider) Get(name string) string {
	value := os.Getenv(settings.GetEnvKey(name))
	if value != "" {
		return value
	}

	var (
		obj *v3.Setting
		err error
	)
	if s.settingCache != nil {
		obj, err = s.settingCache.Get(name)
	}
	if err != nil || obj == nil {
		val, getErr := s.settings.Get(name, metav1.GetOptions{})
		if getErr != nil {
			return s.fallback[name]
		}
		obj = val
	}

	return effectiveValue(obj, s.fallback[name])
}

func (s *settingsProvider) GetAll(names ...string) map[string]string {
	values := make(map[string]string, len(names))
	if len(names) == 0 {
		return values
	}

	remaining := make([]string, 0, len(names))
	seen := map[string]struct{}{}
	for _, name := range names {
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		key := settings.GetEnvKey(name)
		if value, ok := os.LookupEnv(key); ok {
			values[name] = value
			continue
		}
		remaining = append(remaining, name)
	}

	if len(remaining) == 0 {
		return values
	}

	stored, err := s.listSettings()
	if err != nil {
		for _, name := range remaining {
			values[name] = s.fallback[name]
		}
		return values
	}

	for _, name := range remaining {
		obj, ok := stored[name]
		if !ok {
			values[name] = s.fallback[name]
			continue
		}
		values[name] = effectiveValue(obj, s.fallback[name])
	}

	return values
}

func (s *settingsProvider) listSettings() (map[string]*v3.Setting, error) {
	if s.settingCache != nil {
		items, err := s.settingCache.List(labels.Everything())
		if err == nil {
			result := make(map[string]*v3.Setting, len(items))
			for _, item := range items {
				result[item.Name] = item
			}
			return result, nil
		}
	}

	list, err := s.settings.List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	result := make(map[string]*v3.Setting, len(list.Items))
	for i := range list.Items {
		item := &list.Items[i]
		result[item.Name] = item
	}
	return result, nil
}

func effectiveValue(obj *v3.Setting, fallback string) string {
	if obj == nil {
		return fallback
	}
	if obj.Value != "" {
		return obj.Value
	}
	if obj.Default != "" {
		return obj.Default
	}
	return fallback
}

func (s *settingsProvider) Set(name, value string) error {
	envValue := os.Getenv(settings.GetEnvKey(name))
	if envValue != "" {
		return fmt.Errorf("setting %s can not be set because it is from environment variable", name)
	}
	obj, err := s.settings.Get(name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	obj.Value = value
	_, err = s.settings.Update(obj)
	return err
}

func (s *settingsProvider) SetIfUnset(name, value string) error {
	obj, err := s.settings.Get(name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if obj.Value != "" {
		return nil
	}

	obj.Value = value
	_, err = s.settings.Update(obj)
	return err
}

// SetAll iterates through a map of settings.Setting and updates corresponding settings in k8s
// to match any values set for them via their respective CATTLE_<setting-name> env var, their
// source to "env" if configured by an env var, and their default to match the setting in the map.
// NOTE: All settings not provided in settingsMap will be marked as unknown, and may be removed in the future.
func (s *settingsProvider) SetAll(settingsMap map[string]settings.Setting) error {
	anyInstalled, err := s.anySettingsInstalled()
	if err != nil {
		return fmt.Errorf("failed to check if any settings are installed: %w", err)
	}
	fallback := map[string]string{}

	for name, setting := range settingsMap {
		key := settings.GetEnvKey(name)
		envValue, envOk := os.LookupEnv(key)

		obj, err := s.settings.Get(setting.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			newSetting := &v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.Name,
				},
				Default: setting.Default,
			}
			if anyInstalled && setting.DefaultOnUpgrade != "" {
				newSetting.Default = setting.DefaultOnUpgrade
			}
			if envOk {
				newSetting.Source = "env"
				newSetting.Value = envValue
			}
			if newSetting.Value == "" {
				fallback[newSetting.Name] = newSetting.Default
			} else {
				fallback[newSetting.Name] = newSetting.Value
			}
			_, err := s.settings.Create(newSetting)
			// Rancher will race in an HA setup to try and create the settings
			// so if it exists just move on.
			if err != nil && !apierrors.IsAlreadyExists(err) {
				return err
			}
		} else if err != nil {
			return err
		} else {
			update := false
			if obj.Default != setting.Default {
				if setting.DefaultOnUpgrade != "" {
					obj.Default = setting.DefaultOnUpgrade
				} else {
					obj.Default = setting.Default
				}
				update = true
			}
			if envOk && obj.Source != "env" {
				obj.Source = "env"
				update = true
			}
			if !envOk && obj.Source == "env" {
				obj.Source = ""
				update = true
			}
			if envOk && obj.Value != envValue {
				obj.Value = envValue
				update = true
			}
			if obj.Value == "" {
				fallback[obj.Name] = obj.Default
			} else {
				fallback[obj.Name] = obj.Value
			}
			if update {
				_, err := s.settings.Update(obj)
				if err != nil {
					return err
				}
			}
		}
	}

	s.fallback = fallback

	if err := s.cleanupUnknownSettings(settingsMap); err != nil {
		logrus.Errorf("Error cleaning up unknown settings: %v", err)
	}

	return nil
}

// cleanupUnknownSettings lists all settings in the cluster and deletes all unknown (e.g. deprecated) settings.
func (s *settingsProvider) cleanupUnknownSettings(settingsMap map[string]settings.Setting) error {
	// The settings cache is not yet available at this point, thus using the client directly.
	list, err := s.settings.List(metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, setting := range list.Items {
		if _, ok := settingsMap[setting.Name]; ok {
			continue
		}

		err = s.settings.Delete(setting.Name, &metav1.DeleteOptions{})
		if err != nil {
			logrus.Errorf("Error deleting unknown setting %s: %v", setting.Name, err)
			continue
		}

		logrus.Warnf("Deleted unknown setting %s", setting.Name)
	}

	return nil
}

// anySettingsInstalled tries to find out if at least one setting is installed as a resource in the cluster.
// It is used as a way to know if Rancher has been started for the first time.
func (s *settingsProvider) anySettingsInstalled() (bool, error) {
	list, err := s.settings.List(metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	return len(list.Items) > 0, nil
}
