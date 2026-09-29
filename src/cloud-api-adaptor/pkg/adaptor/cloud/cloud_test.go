// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	cri "github.com/containerd/containerd/pkg/cri/annotations"
	pb "github.com/kata-containers/kata-containers/src/runtime/protocols/hypervisor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/adaptor/proxy"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/adaptor/state"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/forwarder"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/podnetwork"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/podnetwork/tunneler"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/util/tlsutil"
	provider "github.com/confidential-containers/cloud-api-adaptor/src/cloud-providers"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-providers/util/cloudinit"
)

type mockProvider struct{}

func (p *mockProvider) CreateInstance(ctx context.Context, podName, sandboxID string, cloudConfig cloudinit.CloudConfigGenerator, spec provider.InstanceTypeSpec) (*provider.Instance, error) {
	return &provider.Instance{
		Name: "abc",
		ID:   fmt.Sprintf("%s-%.8s", podName, sandboxID),
		IPs: []netip.Addr{
			netip.MustParseAddr("127.0.0.1"),
		},
	}, nil
}

func (p *mockProvider) DeleteInstance(ctx context.Context, instanceID string) error {
	return nil
}

func (p *mockProvider) Teardown() error {
	return nil
}

func (p *mockProvider) ConfigVerifier() error {
	return nil
}

func (p *mockProvider) SelectInstanceType(ctx context.Context, vCPU int64, memory int64) (instanceType string, err error) {
	return "", nil
}

type mockProxy struct {
	readyCh    chan struct{}
	stopCh     chan struct{}
	socketPath string
}

func (p *mockProxy) Start(ctx context.Context, serverURL *url.URL) error {
	close(p.readyCh)
	<-p.stopCh
	return nil
}

func (p *mockProxy) Ready() chan struct{} {
	return p.readyCh
}

func (p *mockProxy) Shutdown() error {
	close(p.stopCh)
	return nil
}

func (p *mockProxy) ClientCA() (certPEM []byte) {
	return nil
}

func (p *mockProxy) CAService() tlsutil.CAService {
	return nil
}

type mockProxyFactory struct {
	podsDir string
}

func (f *mockProxyFactory) New(serverName, socketPath string) proxy.AgentProxy {
	return &mockProxy{
		socketPath: socketPath,
		readyCh:    make(chan struct{}),
		stopCh:     make(chan struct{}),
	}
}

type mockWorkerNode struct{}

func (n mockWorkerNode) Inspect(nsPath string) (*tunneler.Config, error) {
	return &tunneler.Config{
		TunnelType:          podnetwork.DefaultTunnelType,
		Index:               0,
		ExternalNetViaPodVM: false,
	}, nil
}

func (n *mockWorkerNode) Setup(nsPath string, podNodeIPs []netip.Addr, config *tunneler.Config) error {
	return nil
}

func (n *mockWorkerNode) Teardown(nsPath string, config *tunneler.Config) error {
	return nil
}

func TestCloudService(t *testing.T) {

	ctx := context.Background()
	dir := t.TempDir()

	proxyFactory := &mockProxyFactory{
		podsDir: dir,
	}

	cfg := &ServerConfig{
		PodsDir:       dir,
		ForwarderPort: forwarder.DefaultListenPort,
	}

	// false, "", "", "", "", "", dir, forwarder.DefaultListenPort, ""
	s := NewService(&mockProvider{}, proxyFactory, &mockWorkerNode{}, cfg)

	assert.NotNil(t, s)

	sandboxID := "123"
	sandboxNS := "default"
	sandboxName := "mypod"

	req := &pb.CreateVMRequest{
		Id: sandboxID,
		Annotations: map[string]string{
			cri.SandboxNamespace: sandboxNS,
			cri.SandboxName:      sandboxName,
		},
	}

	res1, err := s.CreateVM(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, res1)
	assert.Contains(t, res1.AgentSocketPath, dir)

	m := state.NewManager(dir)
	_, err = m.TryLock(sandboxID)
	assert.ErrorIs(t, err, state.ErrLocked, "expect sandbox locked until it is running")

	res2, err := s.StartVM(ctx, &pb.StartVMRequest{Id: sandboxID})

	assert.NoError(t, err)
	assert.NotNil(t, res2)

	lock, err := m.TryLock(sandboxID)
	require.NoError(t, err, "expect sandbox unlocked once running")
	require.NoError(t, lock.Close())

	res3, err := s.StopVM(ctx, &pb.StopVMRequest{Id: sandboxID})

	assert.NoError(t, err)
	assert.NotNil(t, res3)
}

func TestRecoverSandboxes(t *testing.T) {
	const sandboxID = "123"

	ctx := context.Background()

	// saveStartingSandbox persists state as CreateVM leaves it before StartVM
	// marks the sandbox running
	saveStartingSandbox := func(t *testing.T) (*ServerConfig, *state.Manager) {
		t.Helper()
		dir := t.TempDir()
		netNSPath := filepath.Join(t.TempDir(), "netns")
		require.NoError(t, os.WriteFile(netNSPath, nil, 0o644))
		require.NoError(t, os.MkdirAll(filepath.Join(dir, sandboxID), 0o755))

		m := state.NewManager(dir)
		require.NoError(t, m.Save(&state.SandboxState{
			Version:      1,
			SandboxID:    sandboxID,
			PodName:      "mypod",
			PodNamespace: "default",
			NetNSPath:    netNSPath,
			InstanceIPs:  []string{"127.0.0.1"},
			ServerName:   "podvm",
		}))

		return &ServerConfig{PodsDir: dir, ForwarderPort: forwarder.DefaultListenPort}, m
	}

	newService := func(cfg *ServerConfig) Service {
		return NewService(&mockProvider{}, &mockProxyFactory{podsDir: cfg.PodsDir}, &mockWorkerNode{}, cfg)
	}

	t.Run("cleans up a sandbox abandoned mid-start", func(t *testing.T) {
		cfg, m := saveStartingSandbox(t)

		newService(cfg)

		_, err := m.Load(sandboxID)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("adopts a sandbox once another process finishes starting it", func(t *testing.T) {
		cfg, m := saveStartingSandbox(t)
		lock, err := m.TryLock(sandboxID)
		require.NoError(t, err)

		s := newService(cfg)

		_, err = m.Load(sandboxID)
		require.NoError(t, err, "expect state kept while another process is starting the sandbox")

		require.NoError(t, m.SetReady(sandboxID, nil))
		require.NoError(t, lock.Close())

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			_, err := s.StopVM(ctx, &pb.StopVMRequest{Id: sandboxID})
			assert.NoError(c, err)
		}, 5*time.Second, 100*time.Millisecond)
	})

	t.Run("cleans up a sandbox whose starter exits before it is running", func(t *testing.T) {
		cfg, m := saveStartingSandbox(t)
		lock, err := m.TryLock(sandboxID)
		require.NoError(t, err)

		newService(cfg)

		_, err = m.Load(sandboxID)
		require.NoError(t, err, "expect state kept while another process is starting the sandbox")

		require.NoError(t, lock.Close())

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			_, err := m.Load(sandboxID)
			assert.ErrorIs(c, err, os.ErrNotExist)
		}, 5*time.Second, 100*time.Millisecond)
	})
}

func TestCreateVMTLSProfilePropagation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	proxyFactory := &mockProxyFactory{podsDir: dir}

	t.Run("TLS profile written to apf.json when TLSConfig is set", func(t *testing.T) {
		cfg := &ServerConfig{
			PodsDir:       dir,
			ForwarderPort: forwarder.DefaultListenPort,
			TLSConfig: &tlsutil.TLSConfig{
				MinTLSVersion: "VersionTLS13",
				CipherSuites:  []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			},
		}

		s := NewService(&mockProvider{}, proxyFactory, &mockWorkerNode{}, cfg)

		req := &pb.CreateVMRequest{
			Id: "tls-test-sandbox",
			Annotations: map[string]string{
				cri.SandboxNamespace: "default",
				cri.SandboxName:      "tls-test-pod",
			},
		}

		_, err := s.CreateVM(ctx, req)
		require.NoError(t, err)

		apfPath := filepath.Join(dir, "tls-test-sandbox", "apf.json")
		data, err := os.ReadFile(apfPath)
		require.NoError(t, err)

		var daemonCfg forwarder.Config
		require.NoError(t, json.Unmarshal(data, &daemonCfg))

		assert.Equal(t, "VersionTLS13", daemonCfg.MinTLSVersion)
		assert.Equal(t, []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}, daemonCfg.CipherSuites)
	})

	t.Run("TLS profile fields absent from apf.json when TLSConfig is nil", func(t *testing.T) {
		cfg := &ServerConfig{
			PodsDir:       dir,
			ForwarderPort: forwarder.DefaultListenPort,
			TLSConfig:     nil,
		}

		s := NewService(&mockProvider{}, proxyFactory, &mockWorkerNode{}, cfg)

		req := &pb.CreateVMRequest{
			Id: "notls-test-sandbox",
			Annotations: map[string]string{
				cri.SandboxNamespace: "default",
				cri.SandboxName:      "notls-test-pod",
			},
		}

		_, err := s.CreateVM(ctx, req)
		require.NoError(t, err)

		apfPath := filepath.Join(dir, "notls-test-sandbox", "apf.json")
		data, err := os.ReadFile(apfPath)
		require.NoError(t, err)

		var daemonCfg forwarder.Config
		require.NoError(t, json.Unmarshal(data, &daemonCfg))

		assert.Empty(t, daemonCfg.MinTLSVersion)
		assert.Empty(t, daemonCfg.CipherSuites)
	})
}
