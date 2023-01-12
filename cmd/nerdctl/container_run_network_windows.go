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
	"fmt"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/pkg/netns"
	gocni "github.com/containerd/go-cni"
	"github.com/containerd/nerdctl/pkg/netutil"
	"github.com/containerd/nerdctl/pkg/strutil"
)

// Verifies that the internal network settings are correct.
func (m *cniNetworkManager) verifyNetworkOptions() error {
	e, err := netutil.NewCNIEnv(m.globalOptions.CNIPath, m.globalOptions.CNINetConfPath, netutil.WithDefaultNetwork())
	if err != nil {
		return err
	}
	validNetworkTypes := []string{"nat"}
	netMap, err := e.NetworkMap()
	if err != nil {
		return err
	}
	for _, netstr := range m.netOpts.networkSlice {
		netConfig, ok := netMap[netstr]
		if !ok {
			return fmt.Errorf("network %s not found", netstr)
		}
		netType := netConfig.Plugins[0].Network.Type
		if !strutil.InStringSlice(validNetworkTypes, netType) {
			return fmt.Errorf("network %s of type %q is not supported, must be one of: %v", netType, netstr, validNetworkTypes)
		}
	}
	return nil
}

// Performs setup actions required for the container with the given ID.
func (m *cniNetworkManager) setupNetworking(containerID string) error {
	network, err := gocni.New(gocni.WithDefaultConf)
	if err != nil {
		return err
	}

	netNs, err := m.setupNetNs()
	if err != nil {
		return err
	}

	_, err = network.Setup(m.commandContext, containerID, netNs.GetPath())
	return err
}

// Performs any required cleanup actions for the container with the given ID.
// Should only be called to revert any setup steps performed in setupNetworking.
func (m *cniNetworkManager) cleanupNetworking(containerID string) error {
	// NOTE: we must use `gocni.New` since nerdctl/pkg/netutil doesn't support
	// loading CNI configs < v1.0.0, and Windows only supports <= 0.4.0.
	network, err := gocni.New(gocni.WithDefaultConf)
	if err != nil {
		return err
	}

	netNs, err := m.setupNetNs()
	if err != nil {
		return err
	}

	return network.Remove(m.commandContext, containerID, netNs.GetPath())
}

// Returns a struct with the internal networking labels for the internal
// network settings which should be set of the container.
func (m *cniNetworkManager) getInternalNetworkingLabels() (internalLabels, error) {
	return m.netOpts.toInternalLabels(), nil
}

// Returns a slice of `oci.SpecOpts` and `containerd.NewContainerOpts` which represent
// the network specs which need to be applied to the container with the given ID.
func (m *cniNetworkManager) getContainerNetworkingOpts(containerID string) ([]oci.SpecOpts, []containerd.NewContainerOpts, error) {
	cOpts := []containerd.NewContainerOpts{}

	ns, err := m.setupNetNs()
	if err != nil {
		return nil, nil, err
	}

	opts := []oci.SpecOpts{
		oci.WithWindowNetworksAllowUnqualifiedDNSQuery(),
		oci.WithWindowsNetworkNamespace(ns.GetPath()),
	}

	return opts, cOpts, nil
}

// Returns the string path to a network namespace.
func (m *cniNetworkManager) setupNetNs() (*netns.NetNS, error) {
	if m.netNs != nil {
		return m.netNs, nil
	}

	ns, err := netns.NewNetNS("")
	if err != nil {
		return nil, err
	}

	m.netNs = ns
	return ns, err
}
