// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package ibmcloud

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// The Pod VM settings that can change without restarting the adaptor. When
// Config.PodVMConfigDir is set, each is read from a file of the same name in it,
// the layout of a mounted ConfigMap, and its environment variable and flag are
// ignored. A change only affects Pod VMs created after it.
const (
	podVMImageIDKey     = "IBMCLOUD_PODVM_IMAGE_ID"
	podVMProfileNameKey = "IBMCLOUD_PODVM_INSTANCE_PROFILE_NAME"
	podVMProfileListKey = "IBMCLOUD_PODVM_INSTANCE_PROFILE_LIST"
	podVMDisableCVMKey  = "DISABLECVM"
)

var podVMConfigKeys = []string{podVMImageIDKey, podVMProfileNameKey, podVMProfileListKey, podVMDisableCVMKey}

// kubelet takes up to a minute or more to update a ConfigMap volume, so a
// shorter interval gains little
const podVMConfigPollInterval = 30 * time.Second

// podVMConfig maps each of podVMConfigKeys to its value, "" when its file is missing
type podVMConfig map[string]string

var errPodVMConfigChanged = errors.New("changed while it was read")

// readPodVMConfig reads the settings in dir, retrying when kubelet updates the
// volume part way through
func readPodVMConfig(dir string) (podVMConfig, error) {
	for range 3 {
		cfg, err := readPodVMConfigVersion(dir)
		if !errors.Is(err, errPodVMConfigChanged) {
			return cfg, err
		}
	}
	return nil, fmt.Errorf("%s %w on every attempt", dir, errPodVMConfigChanged)
}

// readPodVMConfigVersion reads every key from the directory that dir/..data
// points to, or from dir when there is no ..data. kubelet updates a ConfigMap
// volume by pointing ..data at a new directory, so following it once per key
// could mix two versions of the ConfigMap.
func readPodVMConfigVersion(dir string) (podVMConfig, error) {
	// otherwise a missing directory reads as every key being unset
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}
	version := dir
	if resolved, err := filepath.EvalSymlinks(filepath.Join(dir, "..data")); err == nil {
		version = resolved
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	cfg := make(podVMConfig, len(podVMConfigKeys))
	for _, key := range podVMConfigKeys {
		data, err := os.ReadFile(filepath.Join(version, key))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		cfg[key] = strings.TrimSpace(string(data))
	}

	// kubelet deletes a version one file at a time, and only once ..data points
	// at the next one, so with ..data unchanged no key read as unset because it
	// was being deleted
	if version != dir {
		if now, err := filepath.EvalSymlinks(filepath.Join(dir, "..data")); err != nil || now != version {
			return nil, errPodVMConfigChanged
		}
	}
	return cfg, nil
}

// loadPodVMConfig sets the Pod VM settings in config from Config.PodVMConfigDir
// and returns what it read
func loadPodVMConfig(config *Config) (podVMConfig, error) {
	cfg, err := readPodVMConfig(config.PodVMConfigDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read Pod VM config: %w", err)
	}
	if err := setPodVMConfig(config, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// setPodVMConfig sets the Pod VM settings in config to those in cfg. A missing
// setting takes the default the adaptor uses when its environment variable is
// unset.
func setPodVMConfig(config *Config, cfg podVMConfig) error {
	config.Images = nil
	if err := config.Images.Set(cfg[podVMImageIDKey]); err != nil {
		return fmt.Errorf("invalid %s: %w", podVMImageIDKey, err)
	}
	config.InstanceProfiles = nil
	if err := config.InstanceProfiles.Set(cfg[podVMProfileListKey]); err != nil {
		return fmt.Errorf("invalid %s: %w", podVMProfileListKey, err)
	}
	config.ProfileName = cfg[podVMProfileNameKey]
	config.DisableCVM = true
	if v := strings.ToLower(cfg[podVMDisableCVMKey]); v != "" {
		config.DisableCVM = v == "1" || v == "true"
	}
	return nil
}

// withPodVMConfig returns a copy of base that uses the settings in cfg, after
// looking up its instance profiles and images
func (p *ibmcloudVPCProvider) withPodVMConfig(ctx context.Context, base *Config, cfg podVMConfig) (*Config, error) {
	next := *base
	if err := setPodVMConfig(&next, cfg); err != nil {
		return nil, err
	}

	resolver := &ibmcloudVPCProvider{vpc: p.vpc, serviceConfig: &next}
	if err := resolver.updateInstanceProfileSpecList(); err != nil {
		return nil, err
	}
	if err := resolver.checkDefaultProfile(); err != nil {
		return nil, err
	}
	if err := resolver.updateImageList(ctx); err != nil {
		return nil, err
	}
	return &next, nil
}

// checkDefaultProfile looks up the default instance profile, which
// updateInstanceProfileSpecList skips when there is a profile list. Pods that
// do not ask for a size otherwise fail to create their Pod VM.
func (p *ibmcloudVPCProvider) checkDefaultProfile() error {
	if len(p.serviceConfig.InstanceProfiles) == 0 || slices.Contains(p.serviceConfig.InstanceProfiles, p.serviceConfig.ProfileName) {
		return nil
	}
	_, _, _, err := p.getProfileNameInformation(p.serviceConfig.ProfileName)
	return err
}

// allImagesFound reports whether config has every image in cfg.
// updateImageList drops the images it cannot look up, and may fail to look one
// up only for the moment.
func allImagesFound(config *Config, cfg podVMConfig) bool {
	var want Images
	_ = want.Set(cfg[podVMImageIDKey])
	return len(config.Images) == len(want)
}

// startPodVMConfigReload polls Config.PodVMConfigDir for changes to applied,
// the settings serviceConfig was loaded with
func (p *ibmcloudVPCProvider) startPodVMConfigReload(applied podVMConfig) {
	if !allImagesFound(p.serviceConfig, applied) {
		applied = nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.reloaded = &atomic.Pointer[Config]{}
	p.reloaded.Store(p.serviceConfig)
	p.stopReload = cancel
	go p.reloadPodVMConfig(ctx, p.serviceConfig.PodVMConfigDir, applied)
}

// reloadPodVMConfig polls dir until ctx is done. A change that names an
// instance profile the VPC API cannot find, or no image it can find, is logged
// and retried on every poll, and new Pod VMs keep the previous settings until
// it is fixed. A change where only some images are found is used, and the
// others are retried on every poll.
func (p *ibmcloudVPCProvider) reloadPodVMConfig(ctx context.Context, dir string, applied podVMConfig) {
	ticker := time.NewTicker(podVMConfigPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		cfg, err := readPodVMConfig(dir)
		switch {
		case err != nil:
			logger.Printf("failed to read Pod VM config: %v", err)
		case !maps.Equal(cfg, applied):
			next, err := p.withPodVMConfig(ctx, p.reloaded.Load(), cfg)
			if err != nil {
				logger.Printf("keeping the previous Pod VM config, the one in %s is not usable: %v", dir, err)
				break
			}
			p.reloaded.Store(next)
			// a partial config is not applied, so that any later change,
			// including back to the previous config, is reloaded
			applied = nil
			if allImagesFound(next, cfg) {
				applied = cfg
			}
			logger.Printf("reloaded Pod VM config from %s: images %s, instance profile %q, instance profiles %v, disable CVM %t",
				dir, next.Images.String(), next.ProfileName, next.InstanceProfiles, next.DisableCVM)
		}
	}
}

// current returns p with the Pod VM settings last loaded from
// Config.PodVMConfigDir. CreateInstance reads them through one call to current
// so that a reload part way through cannot mix two configs in one Pod VM.
func (p *ibmcloudVPCProvider) current() *ibmcloudVPCProvider {
	if p.reloaded == nil {
		return p
	}
	c := *p
	c.serviceConfig = p.reloaded.Load()
	return &c
}
