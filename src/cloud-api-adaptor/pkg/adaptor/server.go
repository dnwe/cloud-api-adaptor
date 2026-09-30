// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package adaptor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/containerd/ttrpc"
	pbHypervisor "github.com/kata-containers/kata-containers/src/runtime/protocols/hypervisor"

	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/adaptor/cloud"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/adaptor/k8sops"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/adaptor/proxy"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/adaptor/vminfo"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/podnetwork"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/util/tlsutil"
	pbPodVMInfo "github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/proto/podvminfo"
	provider "github.com/confidential-containers/cloud-api-adaptor/src/cloud-providers"
)

var logger = log.New(log.Writer(), "[adaptor] ", log.LstdFlags|log.Lmsgprefix)

const (
	DefaultSocketPath = "/run/peerpod/hypervisor.sock"
	DefaultPodsDir    = "/run/peerpod/pods"

	// hypervisorShutdownTimeout bounds how long Shutdown waits for in-flight
	// calls such as StartVM. When the new CAA only starts after this one exits,
	// running pods have no agent proxy meanwhile, and their shims stop retrying
	// after a few minutes.
	hypervisorShutdownTimeout = 2 * time.Minute
)

type Server interface {
	Start(ctx context.Context) error
	Shutdown() error
	Ready() chan struct{}
}

type server struct {
	cloudService            cloud.Service
	vmInfoService           pbPodVMInfo.PodVMInfoService
	workerNode              podnetwork.WorkerNode
	ttRPC                   *ttrpc.Server
	readyCh                 chan struct{}
	stopCh                  chan struct{}
	socketPath              string
	stopOnce                sync.Once
	enableCloudConfigVerify bool
	PeerPodsLimitPerNode    int
	ownerUID                string
	isOwner                 bool
	calls                   *callTracker
}

// callTracker counts in-flight hypervisor calls so Shutdown can wait for
// them. ttrpc.Server.Shutdown cannot: it treats a connection as idle until its
// first response, so it closes the per-call connections the kata shim opens
// and cancels their requests.
type callTracker struct {
	mu      sync.Mutex
	active  int
	closing bool
	drained chan struct{}
}

func newCallTracker() *callTracker {
	return &callTracker{drained: make(chan struct{})}
}

func (c *callTracker) intercept(ctx context.Context, unmarshal ttrpc.Unmarshaler, info *ttrpc.UnaryServerInfo, method ttrpc.Method) (interface{}, error) {
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return nil, fmt.Errorf("cloud-api-adaptor is shutting down, rejecting %s", info.FullMethod)
	}
	c.active++
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.active--
		if c.closing && c.active == 0 {
			close(c.drained)
		}
	}()
	return method(ctx, unmarshal)
}

// close rejects new calls and returns a channel that is closed once the
// in-flight calls have returned.
func (c *callTracker) close() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closing {
		c.closing = true
		if c.active == 0 {
			close(c.drained)
		}
	}
	return c.drained
}

// buildAgentFactory constructs a proxy.Factory, using persistent TLS material
// when configured, falling back to ephemeral material otherwise. Persistent
// material only stands in for the client certificate and CA that
// proxy.NewFactory would otherwise generate; configured files are kept.
func buildAgentFactory(cfg *cloud.ServerConfig) (proxy.Factory, error) {
	tlsConfig := cfg.TLSConfig
	if tlsConfig == nil || cfg.TLSMaterialPath == "" || (tlsConfig.HasCertAuth() && tlsConfig.HasCA()) {
		return proxy.NewFactory(cfg.PauseImage, tlsConfig, cfg.ProxyTimeout), nil
	}

	persistedCA, clientCertPEM, clientKeyPEM, err := tlsutil.LoadOrCreateTLSMaterial(cfg.TLSMaterialPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load/create TLS material from %s: %w", cfg.TLSMaterialPath, err)
	}
	logger.Printf("using persistent TLS material from %s", cfg.TLSMaterialPath)

	if !tlsConfig.HasCertAuth() {
		tlsConfig.CertData = clientCertPEM
		tlsConfig.KeyData = clientKeyPEM
	}
	var caService tlsutil.CAService
	if !tlsConfig.HasCA() {
		caService = persistedCA
		tlsConfig.CAData = caService.RootCertificate()
	}
	return proxy.NewFactoryWithCAService(cfg.PauseImage, tlsConfig, cfg.ProxyTimeout, caService), nil
}

func NewServer(provider provider.Provider, cfg *cloud.ServerConfig, workerNode podnetwork.WorkerNode) (Server, error) {
	logger.Printf("server config: %#v", cfg)

	agentFactory, err := buildAgentFactory(cfg)
	if err != nil {
		return nil, err
	}
	cloudService := cloud.NewService(provider, agentFactory, workerNode, cfg)
	vmInfoService := vminfo.NewService(cloudService)

	return &server{
		socketPath:              cfg.SocketPath,
		cloudService:            cloudService,
		vmInfoService:           vmInfoService,
		workerNode:              workerNode,
		readyCh:                 make(chan struct{}),
		stopCh:                  make(chan struct{}),
		enableCloudConfigVerify: cfg.EnableCloudConfigVerify,
		PeerPodsLimitPerNode:    cfg.PeerPodsLimitPerNode,
		ownerUID:                os.Getenv("POD_UID"),
		calls:                   newCallTracker(),
	}, nil
}

func (s *server) Start(ctx context.Context) (err error) {
	if s.enableCloudConfigVerify {
		verifierErr := s.cloudService.ConfigVerifier()
		if verifierErr != nil {
			return err
		}
	}
	// Advertise node resources
	if k8sops.IsKubernetesEnvironment() {
		err = k8sops.AdvertiseExtendedResources(s.PeerPodsLimitPerNode, s.ownerUID)
		if err != nil {
			return err
		}
	}

	ttRPC, err := ttrpc.NewServer(ttrpc.WithUnaryServerInterceptor(s.calls.intercept))
	if err != nil {
		return err
	}
	s.ttRPC = ttRPC
	if err := os.MkdirAll(filepath.Dir(s.socketPath), os.ModePerm); err != nil {
		return err
	}
	if err := os.RemoveAll(s.socketPath); err != nil { // just in case socket wasn't cleaned
		return err
	}
	pbHypervisor.RegisterHypervisorService(s.ttRPC, s.cloudService)
	pbPodVMInfo.RegisterPodVMInfoService(s.ttRPC, s.vmInfoService)

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return err
	}
	if ul, ok := listener.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}

	ttRPCErr := make(chan error)
	go func() {
		defer close(ttRPCErr)
		// request contexts derive from this one; keep them alive on SIGTERM
		// so Shutdown can let in-flight calls finish
		if err := s.ttRPC.Serve(context.WithoutCancel(ctx), listener); err != nil && !errors.Is(err, ttrpc.ErrServerClosed) {
			ttRPCErr <- err
		}
	}()
	// Declared before the ttrpc shutdown defer so it runs after (defers are LIFO).
	// Removes the socket only when this instance is still the current owner — skipped
	// during rolling restarts where the new pod has already taken ownership, but runs
	// on clean shutdown and uninstall so the file is not left on the node indefinitely.
	defer func() {
		if !k8sops.IsKubernetesEnvironment() || s.isOwner {
			os.Remove(s.socketPath)
		}
	}()
	defer func() {
		ttRPCShutdownErr := s.ttRPC.Shutdown(context.Background())
		if ttRPCShutdownErr != nil && err == nil {
			err = ttRPCShutdownErr
		}
	}()

	close(s.readyCh)

	logger.Printf("server started")

	select {
	case <-ctx.Done():
		shutdownErr := s.Shutdown()
		if shutdownErr != nil && err == nil {
			err = shutdownErr
		}
	case <-s.stopCh:
	case err = <-ttRPCErr:
		shutdownErr := s.Shutdown()
		if shutdownErr != nil && err == nil {
			err = shutdownErr
		}
	}
	return err
}

func (s *server) Shutdown() error {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})

	// let in-flight calls finish before draining the agent proxies (otherwise
	// a StartVM in progress fails and the pod being created is retried)
	select {
	case <-s.calls.close():
	case <-time.After(hypervisorShutdownTimeout):
		logger.Printf("in-flight hypervisor calls did not finish within %v, cancelling them", hypervisorShutdownTimeout)
		select {
		case <-s.readyCh:
			if err := s.ttRPC.Close(); err != nil {
				logger.Printf("closing hypervisor service: %v", err)
			}
		default:
		}
	}

	if k8sops.IsKubernetesEnvironment() {
		isOwner, err := k8sops.RemoveExtendedResources(s.ownerUID)
		if err != nil {
			return err
		}
		s.isOwner = isOwner
	}

	return s.cloudService.Teardown()
}

func (s *server) Ready() chan struct{} {
	return s.readyCh
}
