/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package containerutil

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/pkg/netns"
	"github.com/containerd/nerdctl/pkg/api/types"
	"github.com/containerd/nerdctl/pkg/clientutil"
	"github.com/containerd/nerdctl/pkg/dnsutil/hostsstore"
	"github.com/containerd/nerdctl/pkg/idutil/containerwalker"
	"github.com/containerd/nerdctl/pkg/mountutil"
	"github.com/containerd/nerdctl/pkg/netutil/nettype"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func withCustomResolvConf(src string) func(context.Context, oci.Client, *containers.Container, *oci.Spec) error {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		s.Mounts = append(s.Mounts, specs.Mount{
			Destination: "/etc/resolv.conf",
			Type:        "bind",
			Source:      src,
			Options:     []string{"bind", mountutil.DefaultPropagationMode}, // writable
		})
		return nil
	}
}

func withCustomEtcHostname(src string) func(context.Context, oci.Client, *containers.Container, *oci.Spec) error {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		s.Mounts = append(s.Mounts, specs.Mount{
			Destination: "/etc/hostname",
			Type:        "bind",
			Source:      src,
			Options:     []string{"bind", mountutil.DefaultPropagationMode}, // writable
		})
		return nil
	}
}

func withCustomHosts(src string) func(context.Context, oci.Client, *containers.Container, *oci.Spec) error {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		s.Mounts = append(s.Mounts, specs.Mount{
			Destination: "/etc/hosts",
			Type:        "bind",
			Source:      src,
			Options:     []string{"bind", mountutil.DefaultPropagationMode}, // writable
		})
		return nil
	}
}

// types.NetworkOptionsManager is an interface for reading/setting networking
// options for containers based on the provided command flags.
type NetworkOptionsManager interface {
	// Returns a copy of the internal types.NetworkOptions.
	GetNetworkOptions() types.NetworkOptions

	// Verifies that the internal network settings are correct.
	VerifyNetworkOptions(context.Context) error

	// Performs setup actions required for the container with the given ID.
	SetupNetworking(context.Context, string) error

	// Performs any required cleanup actions for the container with the given ID.
	// Should only be called to revert any setup steps performed in SetupNetworking.
	CleanupNetworking(context.Context, string) error

	// Returns the set of NetworkingOptions which should be set as labels on the container.
	//
	// These options can potentially differ from the actual networking options
	// that the NetworkOptionsManager was initially instantiated with.
	// E.g: in container networking mode, the label will be normalized to an ID:
	// `--net=container:myContainer` => `--net=container:<ID of myContainer>`.
	GetInternalNetworkingOptionLabels(context.Context) (types.NetworkOptions, error)

	// Returns a slice of `oci.SpecOpts` and `containerd.NewContainerOpts` which represent
	// the network specs which need to be applied to the container with the given ID.
	GetContainerNetworkingOpts(context.Context, string) ([]oci.SpecOpts, []containerd.NewContainerOpts, error)
}

// Returns a types.NetworkOptionsManager based on the provided command's flags.
func NewNetworkingOptionsManager(globalOptions types.GlobalCommandOptions, netOpts types.NetworkOptions) (NetworkOptionsManager, error) {
	netType, err := nettype.Detect(netOpts.NetworkSlice)
	if err != nil {
		return nil, err
	}

	var manager NetworkOptionsManager
	switch netType {
	case nettype.None:
		manager = &noneNetworkManager{globalOptions, netOpts}
	case nettype.Host:
		manager = &hostNetworkManager{globalOptions, netOpts}
	case nettype.Container:
		manager = &containerNetworkManager{globalOptions, netOpts}
	case nettype.CNI:
		manager = &cniNetworkManager{globalOptions, netOpts, nil}
	default:
		return nil, fmt.Errorf("unexpected container networking type: %q", netType)
	}

	return manager, nil
}

// No-op types.NetworkOptionsManager for network-less containers.
type noneNetworkManager struct {
	globalOptions types.GlobalCommandOptions
	netOpts       types.NetworkOptions
}

// Returns a copy of the internal types.NetworkOptions.
func (m *noneNetworkManager) GetNetworkOptions() types.NetworkOptions {
	return m.netOpts
}

// Verifies that the internal network settings are correct.
func (m *noneNetworkManager) VerifyNetworkOptions(_ context.Context) error {
	// No options to verify if no network settings are provided.
	return nil
}

// Performs setup actions required for the container with the given ID.
func (m *noneNetworkManager) SetupNetworking(_ context.Context, _ string) error {
	return nil
}

// Performs any required cleanup actions for the container with the given ID.
// Should only be called to revert any setup steps performed in SetupNetworking.
func (m *noneNetworkManager) CleanupNetworking(_ context.Context, _ string) error {
	return nil
}

// Returns the set of NetworkingOptions which should be set as labels on the container.
func (m *noneNetworkManager) GetInternalNetworkingOptionLabels(_ context.Context) (types.NetworkOptions, error) {
	return m.netOpts, nil
}

// Returns a slice of `oci.SpecOpts` and `containerd.NewContainerOpts` which represent
// the network specs which need to be applied to the container with the given ID.
func (m *noneNetworkManager) GetContainerNetworkingOpts(_ context.Context, _ string) ([]oci.SpecOpts, []containerd.NewContainerOpts, error) {
	// No options to return if no network settings are provided.
	return []oci.SpecOpts{}, []containerd.NewContainerOpts{}, nil
}

// types.NetworkOptionsManager implementation for container networking settings.
type containerNetworkManager struct {
	globalOptions types.GlobalCommandOptions
	netOpts       types.NetworkOptions
}

// Returns a copy of the internal types.NetworkOptions.
func (m *containerNetworkManager) GetNetworkOptions() types.NetworkOptions {
	return m.netOpts
}

// Verifies that the internal network settings are correct.
func (m *containerNetworkManager) VerifyNetworkOptions(_ context.Context) error {
	// TODO: check host OS, not client-side OS.
	if runtime.GOOS != "linux" {
		return errors.New("container networking mode is currently only supported on Linux")
	}

	if m.netOpts.NetworkSlice != nil && len(m.netOpts.NetworkSlice) > 1 {
		return errors.New("conflicting options: only one network specification is allowed when using '--network=container:<container>'")
	}

	if m.netOpts.MACAddress != "" {
		return errors.New("conflicting options: mac-address and the network mode")
	}

	if m.netOpts.PortMappings != nil && len(m.netOpts.PortMappings) != 0 {
		return errors.New("conflicting options: cannot publish ports in container network mode")
	}

	if m.netOpts.Hostname != "" {
		return errors.New("conflicting options: cannot set hostname in container network mode")
	}

	if m.netOpts.DNSServers != nil && len(m.netOpts.DNSServers) != 0 {
		return errors.New("conflicting options: cannot set DNS servers in container network mode")
	}

	if m.netOpts.AddHost != nil && len(m.netOpts.AddHost) != 0 {
		return errors.New("conflicting options: custom host-to-IP mapping cannot be used in container network mode")
	}

	return nil
}

// Returns the relevant paths of the `hostname`, `resolv.conf`, and `hosts` files
// in the datastore of the container with the given ID.
func (m *containerNetworkManager) getContainerNetworkFilePaths(containerID string) (string, string, string, error) {
	dataStore, err := clientutil.DataStore(m.globalOptions.DataRoot, m.globalOptions.Address)
	if err != nil {
		return "", "", "", err
	}
	conStateDir, err := getContainerStateDirPath(m.globalOptions, dataStore, containerID)
	if err != nil {
		return "", "", "", err
	}

	hostnamePath := filepath.Join(conStateDir, "hostname")
	resolvConfPath := filepath.Join(conStateDir, "resolv.conf")
	etcHostsPath := hostsstore.HostsPath(dataStore, m.globalOptions.Namespace, containerID)

	return hostnamePath, resolvConfPath, etcHostsPath, nil
}

// Performs setup actions required for the container with the given ID.
func (m *containerNetworkManager) SetupNetworking(_ context.Context, _ string) error {
	// NOTE: container networking simply reuses network config files from the
	// bridged container so there are no setup/teardown steps required.
	return nil
}

// Performs any required cleanup actions for the container with the given ID.
// Should only be called to revert any setup steps performed in SetupNetworking.
func (m *containerNetworkManager) CleanupNetworking(_ context.Context, _ string) error {
	// NOTE: container networking simply reuses network config files from the
	// bridged container so there are no setup/teardown steps required.
	return nil
}

// Searches for and returns the networking container for the given network argument.
func (m *containerNetworkManager) getNetworkingContainerForArgument(ctx context.Context, containerNetArg string) (containerd.Container, error) {
	netItems := strings.Split(containerNetArg, ":")
	if len(netItems) < 2 {
		return nil, fmt.Errorf("container networking argument format must be 'container:<id|name>', got: %q", containerNetArg)
	}
	containerName := netItems[1]

	client, ctxt, cancel, err := clientutil.NewClient(ctx, m.globalOptions.Namespace, m.globalOptions.Address)
	if err != nil {
		return nil, err
	}
	defer cancel()

	var foundContainer containerd.Container
	walker := &containerwalker.ContainerWalker{
		Client: client,
		OnFound: func(ctx context.Context, found containerwalker.Found) error {
			if found.MatchCount > 1 {
				return fmt.Errorf("container networking: multiple containers found with prefix: %s", containerName)
			}
			foundContainer = found.Container
			return nil
		},
	}
	n, err := walker.Walk(ctxt, containerName)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, fmt.Errorf("container networking: could not find container: %s", containerName)
	}

	return foundContainer, nil
}

// Returns the set of NetworkingOptions which should be set as labels on the container.
func (m *containerNetworkManager) GetInternalNetworkingOptionLabels(ctx context.Context) (types.NetworkOptions, error) {
	opts := m.netOpts
	if m.netOpts.NetworkSlice == nil || len(m.netOpts.NetworkSlice) != 1 {
		return opts, fmt.Errorf("conflicting options: exactly one network specification is allowed when using '--network=container:<container>'")
	}

	container, err := m.getNetworkingContainerForArgument(ctx, m.netOpts.NetworkSlice[0])
	if err != nil {
		return opts, err
	}
	containerID := container.ID()
	opts.NetworkSlice = []string{fmt.Sprintf("container:%s", containerID)}
	return opts, nil
}

// Returns a slice of `oci.SpecOpts` and `containerd.NewContainerOpts` which represent
// the network specs which need to be applied to the container with the given ID.
func (m *containerNetworkManager) GetContainerNetworkingOpts(ctx context.Context, _ string) ([]oci.SpecOpts, []containerd.NewContainerOpts, error) {
	opts := []oci.SpecOpts{}
	cOpts := []containerd.NewContainerOpts{}

	container, err := m.getNetworkingContainerForArgument(ctx, m.netOpts.NetworkSlice[0])
	if err != nil {
		return nil, nil, err
	}
	containerID := container.ID()

	s, err := container.Spec(ctx)
	if err != nil {
		return nil, nil, err
	}
	hostname := s.Hostname

	netNSPath, err := ContainerNetNSPath(ctx, container)
	if err != nil {
		return nil, nil, err
	}

	hostnamePath, resolvConfPath, etcHostsPath, err := m.getContainerNetworkFilePaths(containerID)
	if err != nil {
		return nil, nil, err
	}

	opts = append(opts,
		oci.WithLinuxNamespace(specs.LinuxNamespace{
			Type: specs.NetworkNamespace,
			Path: netNSPath,
		}),
		withCustomResolvConf(resolvConfPath),
		withCustomHosts(etcHostsPath),
		oci.WithHostname(hostname),
		withCustomEtcHostname(hostnamePath),
	)

	return opts, cOpts, nil
}

// types.NetworkOptionsManager implementation for host networking settings.
type hostNetworkManager struct {
	globalOptions types.GlobalCommandOptions
	netOpts       types.NetworkOptions
}

// Returns a copy of the internal types.NetworkOptions.
func (m *hostNetworkManager) GetNetworkOptions() types.NetworkOptions {
	return m.netOpts
}

// Verifies that the internal network settings are correct.
func (m *hostNetworkManager) VerifyNetworkOptions(_ context.Context) error {
	// TODO: check host OS, not client-side OS.
	if runtime.GOOS == "windows" {
		return errors.New("cannot use host networking on Windows")
	}

	if m.netOpts.MACAddress != "" {
		return errors.New("conflicting options: mac-address and the network mode")
	}

	return nil
}

// Performs setup actions required for the container with the given ID.
func (m *hostNetworkManager) SetupNetworking(_ context.Context, _ string) error {
	// NOTE: there are no setup steps required for host networking.
	return nil
}

// Performs any required cleanup actions for the container with the given ID.
// Should only be called to revert any setup steps performed in SetupNetworking.
func (m *hostNetworkManager) CleanupNetworking(_ context.Context, _ string) error {
	// NOTE: there are no setup steps required for host networking.
	return nil
}

// Returns the set of NetworkingOptions which should be set as labels on the container.
func (m *hostNetworkManager) GetInternalNetworkingOptionLabels(_ context.Context) (types.NetworkOptions, error) {
	opts := m.netOpts
	// Cannot have a MAC address in host networking mode.
	opts.MACAddress = ""
	return opts, nil
}

// Returns a slice of `oci.SpecOpts` and `containerd.NewContainerOpts` which represent
// the network specs which need to be applied to the container with the given ID.
func (m *hostNetworkManager) GetContainerNetworkingOpts(_ context.Context, _ string) ([]oci.SpecOpts, []containerd.NewContainerOpts, error) {
	specs := []oci.SpecOpts{
		oci.WithHostNamespace(specs.NetworkNamespace),
		oci.WithHostHostsFile,
		oci.WithHostResolvconf}
	cOpts := []containerd.NewContainerOpts{}
	return specs, cOpts, nil
}

// types.NetworkOptionsManager implementation for CNI networking settings.
// This is a more specialized and OS-dependendant networking model so this
// struct provides different implementations on different platforms.
type cniNetworkManager struct {
	globalOptions types.GlobalCommandOptions
	netOpts       types.NetworkOptions
	netNs         *netns.NetNS
}

// Returns a copy of the internal types.NetworkOptions.
func (m *cniNetworkManager) GetNetworkOptions() types.NetworkOptions {
	return m.netOpts
}
