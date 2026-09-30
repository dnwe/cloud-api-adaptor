// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package adaptor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/adaptor/cloud"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/adaptor/proxy"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/podnetwork/tunneler"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/util/tlsutil"
	provider "github.com/confidential-containers/cloud-api-adaptor/src/cloud-providers"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-providers/util/cloudinit"
	"github.com/containerd/containerd/pkg/cri/annotations"
	"github.com/containerd/ttrpc"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/kata-containers/kata-containers/src/runtime/protocols/hypervisor"
	agent "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols/grpc"
)

func TestServerStartAndShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s, dir, socketPath, client, serverErrCh := testServerStart(t, ctx, &mockProvider{})
	defer testServerShutdown(t, s, socketPath, dir, serverErrCh)
	if _, err := client.Version(context.Background(), &pb.VersionRequest{}); err != nil {
		t.Error(err)
	}
}

func TestShutdownDuringStartVM(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &mockProvider{creating: make(chan struct{}), release: make(chan struct{})}
	_, _, _, client, serverErrCh := testServerStart(t, ctx, p)

	id := uuid.New().String()
	_, err := client.CreateVM(context.Background(), &pb.CreateVMRequest{
		Id: id,
		Annotations: map[string]string{
			annotations.SandboxName:      "test",
			annotations.SandboxNamespace: "test",
		},
	})
	require.NoError(t, err)

	startErr := make(chan error, 1)
	go func() {
		_, err := client.StartVM(context.Background(), &pb.StartVMRequest{Id: id})
		startErr <- err
	}()
	<-p.creating

	// SIGTERM cancels the context passed to Start
	cancel()
	close(p.release)

	assert.NoError(t, <-startErr, "expect in-flight StartVM to finish during shutdown")
	assert.NoError(t, <-serverErrCh)
}

func TestBuildAgentFactory(t *testing.T) {
	build := func(t *testing.T, tlsConfig *tlsutil.TLSConfig, materialPath string) proxy.AgentProxy {
		t.Helper()
		factory, err := buildAgentFactory(&cloud.ServerConfig{TLSConfig: tlsConfig, TLSMaterialPath: materialPath})
		require.NoError(t, err)
		return factory.New("podvm", filepath.Join(t.TempDir(), "agent.ttrpc"))
	}

	t.Run("reuses persisted material across restarts", func(t *testing.T) {
		materialPath := filepath.Join(t.TempDir(), "tls-material.json")

		first := &tlsutil.TLSConfig{}
		firstProxy := build(t, first, materialPath)
		second := &tlsutil.TLSConfig{}
		secondProxy := build(t, second, materialPath)

		require.NotEmpty(t, first.CAData)
		assert.Equal(t, first.CAData, second.CAData)
		assert.Equal(t, first.CertData, second.CertData)
		assert.Equal(t, firstProxy.CAService().RootCertificate(), secondProxy.CAService().RootCertificate())
	})

	t.Run("keeps configured certificate files", func(t *testing.T) {
		tlsConfig := &tlsutil.TLSConfig{CAFile: "/etc/certificates/ca.crt", CertFile: "/etc/certificates/client.crt", KeyFile: "/etc/certificates/client.key"}

		agentProxy := build(t, tlsConfig, filepath.Join(t.TempDir(), "tls-material.json"))

		assert.Nil(t, tlsConfig.CAData)
		assert.Nil(t, tlsConfig.CertData)
		assert.Nil(t, tlsConfig.KeyData)
		assert.Nil(t, agentProxy.CAService())
	})

	t.Run("persists only the CA when the client certificate is configured", func(t *testing.T) {
		tlsConfig := &tlsutil.TLSConfig{CertFile: "/etc/certificates/client.crt", KeyFile: "/etc/certificates/client.key"}

		agentProxy := build(t, tlsConfig, filepath.Join(t.TempDir(), "tls-material.json"))

		assert.Nil(t, tlsConfig.CertData)
		assert.Nil(t, tlsConfig.KeyData)
		require.NotNil(t, agentProxy.CAService())
		assert.Equal(t, agentProxy.CAService().RootCertificate(), tlsConfig.CAData)
	})
}

func TestCreateStartAndStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s, dir, socketPath, client, serverErrCh := testServerStart(t, ctx, &mockProvider{})
	defer testServerShutdown(t, s, socketPath, dir, serverErrCh)
	id := uuid.New().String()
	if _, err := client.CreateVM(
		context.Background(),
		&pb.CreateVMRequest{
			Id: id,
			Annotations: map[string]string{
				annotations.SandboxName:      "test",
				annotations.SandboxNamespace: "test",
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := client.StartVM(context.Background(), &pb.StartVMRequest{Id: id}); err != nil {
		t.Fatal(err)
	}

	forwarderSocket := filepath.Join(dir, "pods", id, proxy.SocketName)
	conn, err := net.Dial("unix", forwarderSocket)
	if err != nil {
		t.Fatal(err)
	}

	ttrpcClient := ttrpc.NewClient(conn)
	defer ttrpcClient.Close()

	agentClient := agent.NewAgentServiceClient(ttrpcClient)

	if _, err := agentClient.GetGuestDetails(ctx, &agent.GuestDetailsRequest{}); err != nil {
		t.Fatal(err)
	}

	if _, err := client.StopVM(context.Background(), &pb.StopVMRequest{Id: id}); err != nil {
		t.Fatal(err)
	}
}

func testServerStart(t *testing.T, ctx context.Context, provider *mockProvider) (Server, string, string, pb.HypervisorService, chan error) {

	dir := t.TempDir()

	socketPath := filepath.Join(dir, "hypervisor.sock")
	s := newServer(t, socketPath, filepath.Join(dir, "pods"), provider)

	serverErrCh := make(chan error)
	go func() {
		defer close(serverErrCh)
		if err := s.Start(ctx); err != nil {
			serverErrCh <- err
		}
	}()

	<-s.Ready()

	select {
	case err := <-serverErrCh:
		t.Fatal(err)
	default:
	}
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	client := pb.NewHypervisorClient(ttrpc.NewClient(conn))
	return s, dir, socketPath, client, serverErrCh
}

func startAgentServer(t *testing.T) string {

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Expect no error, got %q", err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	ttrpcServer, err := ttrpc.NewServer()
	if err != nil {
		t.Fatal(err)
	}

	agent.RegisterAgentServiceService(ttrpcServer, newAgentService())
	agent.RegisterHealthService(ttrpcServer, &healthService{})

	ctx := context.Background()

	go func() {
		if err := ttrpcServer.Serve(ctx, listener); err != nil {
			if !errors.Is(err, ttrpc.ErrServerClosed) {
				t.Error(err)
			}
		}
	}()
	t.Cleanup(func() {
		if err := ttrpcServer.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})

	return port
}

func newServer(t *testing.T, socketPath, podsDir string, provider *mockProvider) Server {

	port := startAgentServer(t)
	serverConfig := &cloud.ServerConfig{
		SocketPath:              socketPath,
		PodsDir:                 podsDir,
		ForwarderPort:           port,
		ProxyTimeout:            5 * time.Second,
		EnableCloudConfigVerify: false,
		PeerPodsLimitPerNode:    -1,
	}
	srv, err := NewServer(provider, serverConfig, &mockWorkerNode{})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func testServerShutdown(t *testing.T, s Server, socketPath, dir string, serverErrCh chan error) {

	if err := s.Shutdown(); err != nil {
		t.Error(err)
	}
	if err := <-serverErrCh; err != nil {
		t.Error(err)
	}
	if _, err := os.Stat(socketPath); err == nil {
		t.Errorf("Unix domain socket %s still remains\n", socketPath)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Error(err)
	}
}

type mockWorkerNode struct{}

func (n *mockWorkerNode) Inspect(nsPath string) (*tunneler.Config, error) {
	return &tunneler.Config{}, nil
}

func (n *mockWorkerNode) Setup(nsPath string, podNodeIPs []netip.Addr, config *tunneler.Config) error {
	return nil
}

func (n *mockWorkerNode) Teardown(nsPath string, config *tunneler.Config) error {
	return nil
}

type mockProvider struct {
	primaryIP   string
	secondaryIP string

	// when set, CreateInstance closes creating and waits for release
	creating chan struct{}
	release  chan struct{}
}

func (p *mockProvider) CreateInstance(ctx context.Context, podName, sandboxID string, cloudConfig cloudinit.CloudConfigGenerator, spec provider.InstanceTypeSpec) (*provider.Instance, error) {
	if p.release != nil {
		close(p.creating)
		<-p.release
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	primaryIP := p.primaryIP
	if primaryIP == "" {
		primaryIP = "127.0.0.1"
	}

	secondaryIP := p.secondaryIP
	if secondaryIP == "" {
		secondaryIP = "127.0.0.1"
	}

	ips := make([]netip.Addr, 2)
	ips[0] = netip.MustParseAddr(primaryIP)
	ips[1] = netip.MustParseAddr(secondaryIP)

	instance := &provider.Instance{
		ID:   "mock",
		Name: "mock",
		IPs:  ips,
	}

	return instance, nil
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
