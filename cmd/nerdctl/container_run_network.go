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

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/pkg/netns"
	gocni "github.com/containerd/go-cni"
	"github.com/containerd/nerdctl/pkg/api/types"
	"github.com/containerd/nerdctl/pkg/clientutil"
	"github.com/containerd/nerdctl/pkg/containerutil"
	"github.com/containerd/nerdctl/pkg/dnsutil/hostsstore"
	"github.com/containerd/nerdctl/pkg/idutil/containerwalker"
	"github.com/containerd/nerdctl/pkg/mountutil"
	"github.com/containerd/nerdctl/pkg/netutil/nettype"
	"github.com/containerd/nerdctl/pkg/portutil"
	"github.com/containerd/nerdctl/pkg/strutil"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/spf13/cobra"
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

// Struct defining networking-related options.
type networkOptions struct {
	// --net/--network=<net name> ...
	networkSlice []string

	// --mac-address=<MAC>
	macAddress string

	// --ip=<container static IP>
	ipAddress string

	// -h/--hostname=<container hostname>
	hostname string

	// --dns=<DNS host> ...
	dnsServers []string

	// --dns-opt/--dns-option=<resolv.conf line> ...
	dnsResolvConfOptions []string

	// --dns-search=<domain name> ...
	dnsSearchDomains []string

	// --add-host=<host:IP> ...
	addHost []string

	// -p/--publish=127.0.0.1:80:8080/tcp ...
	portMappings []gocni.PortMapping
}

// Returns an internalLabels struct with the networking fields which map 1:1 set in it.
func (nopts networkOptions) toInternalLabels() internalLabels {
	return internalLabels{
		hostname:   nopts.hostname,
		networks:   nopts.networkSlice,
		ipAddress:  nopts.ipAddress,
		ports:      nopts.portMappings,
		macAddress: nopts.macAddress,
	}
}

func loadNetworkFlags(cmd *cobra.Command) (networkOptions, error) {
	nopts := networkOptions{}

	// --net/--network=<net name> ...
	var netSlice = []string{}
	var networkSet = false
	if cmd.Flags().Lookup("network").Changed {
		network, err := cmd.Flags().GetStringSlice("network")
		if err != nil {
			return nopts, err
		}
		netSlice = append(netSlice, network...)
		networkSet = true
	}
	if cmd.Flags().Lookup("net").Changed {
		net, err := cmd.Flags().GetStringSlice("net")
		if err != nil {
			return nopts, err
		}
		netSlice = append(netSlice, net...)
		networkSet = true
	}

	if !networkSet {
		network, err := cmd.Flags().GetStringSlice("network")
		if err != nil {
			return nopts, err
		}
		netSlice = append(netSlice, network...)
	}
	nopts.networkSlice = strutil.DedupeStrSlice(netSlice)

	// --mac-address=<MAC>
	macAddress, err := cmd.Flags().GetString("mac-address")
	if err != nil {
		return nopts, err
	}
	if macAddress != "" {
		if _, err := net.ParseMAC(macAddress); err != nil {
			return nopts, err
		}
	}
	nopts.macAddress = macAddress

	// --ip=<container static IP>
	ipAddress, err := cmd.Flags().GetString("ip")
	if err != nil {
		return nopts, err
	}
	nopts.ipAddress = ipAddress

	// -h/--hostname=<container hostname>
	hostName, err := cmd.Flags().GetString("hostname")
	if err != nil {
		return nopts, err
	}
	nopts.hostname = hostName

	// --dns=<DNS host> ...
	dnsSlice, err := cmd.Flags().GetStringSlice("dns")
	if err != nil {
		return nopts, err
	}
	nopts.dnsServers = strutil.DedupeStrSlice(dnsSlice)

	// --dns-search=<domain name> ...
	dnsSearchSlice, err := cmd.Flags().GetStringSlice("dns-search")
	if err != nil {
		return nopts, err
	}
	nopts.dnsSearchDomains = strutil.DedupeStrSlice(dnsSearchSlice)

	// --dns-opt/--dns-option=<resolv.conf line> ...
	dnsOptions := []string{}

	dnsOptFlags, err := cmd.Flags().GetStringSlice("dns-opt")
	if err != nil {
		return nopts, err
	}
	dnsOptions = append(dnsOptions, dnsOptFlags...)

	dnsOptionFlags, err := cmd.Flags().GetStringSlice("dns-option")
	if err != nil {
		return nopts, err
	}
	dnsOptions = append(dnsOptions, dnsOptionFlags...)

	nopts.dnsResolvConfOptions = strutil.DedupeStrSlice(dnsOptions)

	// --add-host=<host:IP> ...
	addHostFlags, err := cmd.Flags().GetStringSlice("add-host")
	if err != nil {
		return nopts, err
	}
	nopts.addHost = addHostFlags

	// -p/--publish=127.0.0.1:80:8080/tcp ...
	portSlice, err := cmd.Flags().GetStringSlice("publish")
	if err != nil {
		return nopts, err
	}
	portSlice = strutil.DedupeStrSlice(portSlice)
	portMappings := []gocni.PortMapping{}
	for _, p := range portSlice {
		pm, err := portutil.ParseFlagP(p)
		if err != nil {
			return nopts, err
		}
		portMappings = append(portMappings, pm...)
	}
	nopts.portMappings = portMappings

	return nopts, nil
}

// networkOptionsManager is an interface for reading/setting networking
// options for containers based on the provided command flags.
type networkOptionsManager interface {
	// Returns a copy of the internal NetworkOptions.
	getNetworkOptions() networkOptions

	// Verifies that the internal network settings are correct.
	verifyNetworkOptions() error

	// Performs setup actions required for the container with the given ID.
	setupNetworking(string) error

	// Performs any required cleanup actions for the container with the given ID.
	// Should only be called to revert any setup steps performed in setupNetworking.
	cleanupNetworking(string) error

	// Returns a struct with the internal networking labels for the internal
	// network settings which should be set of the container.
	getInternalNetworkingLabels() (internalLabels, error)

	// Returns a slice of `oci.SpecOpts` and `containerd.NewContainerOpts` which represent
	// the network specs which need to be applied to the container with the given ID.
	getContainerNetworkingOpts(string) ([]oci.SpecOpts, []containerd.NewContainerOpts, error)
}

// Returns a NetworkOptionsManager based on the provided command's flags.
func newNetworkingOptionsManager(cmd *cobra.Command) (networkOptionsManager, error) {
	globalOptions, err := processRootCmdFlags(cmd)
	if err != nil {
		return nil, err
	}

	nopts, err := loadNetworkFlags(cmd)
	if err != nil {
		return nil, err
	}

	netType, err := nettype.Detect(nopts.networkSlice)
	if err != nil {
		return nil, err
	}

	var manager networkOptionsManager
	switch netType {
	case nettype.None:
		manager = &noneNetworkManager{globalOptions, nopts}
	case nettype.Host:
		manager = &hostNetworkManager{globalOptions, nopts}
	case nettype.Container:
		manager = &containerNetworkManager{cmd.Context(), globalOptions, nopts}
	case nettype.CNI:
		manager = &cniNetworkManager{cmd.Context(), globalOptions, nopts, nil}
	default:
		return nil, fmt.Errorf("unexpected container networking type: %q", netType)
	}

	if err := manager.verifyNetworkOptions(); err != nil {
		return nil, fmt.Errorf("failed to verify networking options: %s", err)
	}

	return manager, nil
}

// No-op NetworkOptionsManager for network-less containers.
type noneNetworkManager struct {
	globalOptions types.GlobalCommandOptions
	netOpts       networkOptions
}

// Returns a copy of the internal NetworkOptions.
func (m *noneNetworkManager) getNetworkOptions() networkOptions {
	return m.netOpts
}

// Verifies that the internal network settings are correct.
func (m *noneNetworkManager) verifyNetworkOptions() error {
	// No options to verify if no network settings are provided.
	return nil
}

// Performs setup actions required for the container with the given ID.
func (m *noneNetworkManager) setupNetworking(_ string) error {
	return nil
}

// Performs any required cleanup actions for the container with the given ID.
// Should only be called to revert any setup steps performed in setupNetworking.
func (m *noneNetworkManager) cleanupNetworking(_ string) error {
	return nil
}

// Returns a struct with the internal networking labels for the internal
// network settings which should be set of the container.
func (m *noneNetworkManager) getInternalNetworkingLabels() (internalLabels, error) {
	return m.netOpts.toInternalLabels(), nil
}

// Returns a slice of `oci.SpecOpts` and `containerd.NewContainerOpts` which represent
// the network specs which need to be applied to the container with the given ID.
func (m *noneNetworkManager) getContainerNetworkingOpts(_ string) ([]oci.SpecOpts, []containerd.NewContainerOpts, error) {
	// No options to return if no network settings are provided.
	return []oci.SpecOpts{}, []containerd.NewContainerOpts{}, nil
}

// NetworkOptionsManager implementation for container networking settings.
type containerNetworkManager struct {
	commandContext context.Context
	globalOptions  types.GlobalCommandOptions
	netOpts        networkOptions
}

// Returns a copy of the internal NetworkOptions.
func (m *containerNetworkManager) getNetworkOptions() networkOptions {
	return m.netOpts
}

// Verifies that the internal network settings are correct.
func (m *containerNetworkManager) verifyNetworkOptions() error {
	// TODO: check host OS, not client-side OS.
	if runtime.GOOS != "linux" {
		return errors.New("container networking mode is currently only supported on Linux")
	}

	if m.netOpts.networkSlice != nil && len(m.netOpts.networkSlice) > 1 {
		return errors.New("conflicting options: only one network specification is allowed when using '--network=container:<container>'")
	}

	if m.netOpts.macAddress != "" {
		return errors.New("conflicting options: mac-address and the network mode")
	}

	if m.netOpts.portMappings != nil && len(m.netOpts.portMappings) != 0 {
		return errors.New("conflicting options: cannot publish ports in container network mode")
	}

	if m.netOpts.hostname != "" {
		return errors.New("conflicting options: cannot set hostname in container network mode")
	}

	if m.netOpts.dnsServers != nil && len(m.netOpts.dnsServers) != 0 {
		return errors.New("conflicting options: cannot set DNS servers in container network mode")
	}

	if m.netOpts.addHost != nil && len(m.netOpts.addHost) != 0 {
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
func (m *containerNetworkManager) setupNetworking(_ string) error {
	// NOTE: container networking simply reuses network config files from the
	// bridged container so there are no setup/teardown steps required.
	return nil
}

// Performs any required cleanup actions for the container with the given ID.
// Should only be called to revert any setup steps performed in setupNetworking.
func (m *containerNetworkManager) cleanupNetworking(_ string) error {
	// NOTE: container networking simply reuses network config files from the
	// bridged container so there are no setup/teardown steps required.
	return nil
}

// Searches for and returns the networking container for the given network argument.
func (m *containerNetworkManager) getNetworkingContainerForArgument(containerNetArg string) (containerd.Container, error) {
	netItems := strings.Split(containerNetArg, ":")
	if len(netItems) < 2 {
		return nil, fmt.Errorf("container networking argument format must be 'container:<id|name>', got: %q", containerNetArg)
	}
	containerName := netItems[1]

	client, ctxt, cancel, err := clientutil.NewClient(m.commandContext, m.globalOptions.Namespace, m.globalOptions.Address)
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

// Returns a struct with the internal networking labels for the internal
// network settings which should be set of the container.
func (m *containerNetworkManager) getInternalNetworkingLabels() (internalLabels, error) {
	labels := m.netOpts.toInternalLabels()
	if m.netOpts.networkSlice == nil || len(m.netOpts.networkSlice) != 1 {
		return labels, fmt.Errorf("conflicting options: exactly one network specification is allowed when using '--network=container:<container>'")
	}

	container, err := m.getNetworkingContainerForArgument(m.netOpts.networkSlice[0])
	if err != nil {
		return labels, err
	}
	containerID := container.ID()
	labels.networks = []string{fmt.Sprintf("container:%s", containerID)}
	return labels, nil
}

// Returns a slice of `oci.SpecOpts` and `containerd.NewContainerOpts` which represent
// the network specs which need to be applied to the container with the given ID.
func (m *containerNetworkManager) getContainerNetworkingOpts(_ string) ([]oci.SpecOpts, []containerd.NewContainerOpts, error) {
	opts := []oci.SpecOpts{}
	cOpts := []containerd.NewContainerOpts{}

	container, err := m.getNetworkingContainerForArgument(m.netOpts.networkSlice[0])
	if err != nil {
		return nil, nil, err
	}
	containerID := container.ID()

	s, err := container.Spec(m.commandContext)
	if err != nil {
		return nil, nil, err
	}
	hostname := s.Hostname

	netNSPath, err := containerutil.ContainerNetNSPath(m.commandContext, container)
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

// NetworkOptionsManager implementation for host networking settings.
type hostNetworkManager struct {
	globalOptions types.GlobalCommandOptions
	netOpts       networkOptions
}

// Returns a copy of the internal NetworkOptions.
func (m *hostNetworkManager) getNetworkOptions() networkOptions {
	return m.netOpts
}

// Verifies that the internal network settings are correct.
func (m *hostNetworkManager) verifyNetworkOptions() error {
	// TODO: check host OS, not client-side OS.
	if runtime.GOOS == "windows" {
		return errors.New("cannot use host networking on Windows")
	}

	if m.netOpts.macAddress != "" {
		return errors.New("conflicting options: mac-address and the network mode")
	}

	return nil
}

// Performs setup actions required for the container with the given ID.
func (m *hostNetworkManager) setupNetworking(_ string) error {
	// NOTE: there are no setup steps required for host networking.
	return nil
}

// Performs any required cleanup actions for the container with the given ID.
// Should only be called to revert any setup steps performed in setupNetworking.
func (m *hostNetworkManager) cleanupNetworking(_ string) error {
	// NOTE: there are no setup steps required for host networking.
	return nil
}

// Returns a struct with the internal networking labels for the internal
// network settings which should be set of the container.
func (m *hostNetworkManager) getInternalNetworkingLabels() (internalLabels, error) {
	labels := m.netOpts.toInternalLabels()
	// Cannot have a MAC address in host networking mode.
	labels.macAddress = ""
	return labels, nil
}

// Returns a slice of `oci.SpecOpts` and `containerd.NewContainerOpts` which represent
// the network specs which need to be applied to the container with the given ID.
func (m *hostNetworkManager) getContainerNetworkingOpts(_ string) ([]oci.SpecOpts, []containerd.NewContainerOpts, error) {
	specs := []oci.SpecOpts{
		oci.WithHostNamespace(specs.NetworkNamespace),
		oci.WithHostHostsFile,
		oci.WithHostResolvconf}
	cOpts := []containerd.NewContainerOpts{}
	return specs, cOpts, nil
}

// NetworkOptionsManager implementation for CNI networking settings.
// This is a more specialized and OS-dependendant networking model so this
// struct provides different implementations on different platforms.
type cniNetworkManager struct {
	commandContext context.Context
	globalOptions  types.GlobalCommandOptions
	netOpts        networkOptions
	netNs          *netns.NetNS
}

// Returns a copy of the internal NetworkOptions.
func (m *cniNetworkManager) getNetworkOptions() networkOptions {
	return m.netOpts
}
