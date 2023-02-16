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
	"fmt"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/pkg/netns"
	gocni "github.com/containerd/go-cni"

	"github.com/containerd/nerdctl/pkg/api/types"
	"github.com/containerd/nerdctl/pkg/netutil"
	"github.com/containerd/nerdctl/pkg/ocihook"
)

// Verifies that the internal network settings are correct.
func (m *cniNetworkManager) VerifyNetworkOptions(_ context.Context) error {
	e, err := netutil.NewCNIEnv(m.globalOptions.CNIPath, m.globalOptions.CNINetConfPath, netutil.WithDefaultNetwork())
	if err != nil {
		return err
	}

	// NOTE: only currently supported network type on Windows is nat:
	validNetworkTypes := []string{"nat"}
	if _, err := verifyNetworkTypes(e, m.netOpts.NetworkSlice, validNetworkTypes); err != nil {
		return err
	}

	if m.netOpts.UTSNamespace != "" {
		return fmt.Errorf("--uts is not supported on Windows")
	}

	return nil
}

func (m *cniNetworkManager) getCNI() (gocni.CNI, error) {
	e, err := netutil.NewCNIEnv(m.globalOptions.CNIPath, m.globalOptions.CNINetConfPath, netutil.WithDefaultNetwork())
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate CNI env: %s", err)
	}

	cniOpts := []gocni.Opt{
		gocni.WithPluginDir([]string{m.globalOptions.CNIPath}),
		gocni.WithPluginConfDir(m.globalOptions.CNINetConfPath),
	}

	if netMap, err := verifyNetworkTypes(e, m.netOpts.NetworkSlice, nil); err == nil {
		for _, netConf := range netMap {
			cniOpts = append(cniOpts, gocni.WithConfListFile(netConf.File))
		}
	} else {
		return nil, err
	}

	return gocni.New(cniOpts...)
}

// Performs setup actions required for the container with the given ID.
func (m *cniNetworkManager) SetupNetworking(ctx context.Context, containerID string) error {
	cni, err := m.getCNI()
	if err != nil {
		return fmt.Errorf("failed to get container networking for cleanup: %s", err)
	}

	netNs, err := m.setupNetNs()
	if err != nil {
		return err
	}

	namespaceOpts := []gocni.NamespaceOpts{}
	if m.netOpts.PortMappings != nil {
		namespaceOpts = append(namespaceOpts, gocni.WithCapabilityPortMap(m.netOpts.PortMappings))
	}

	_, err = cni.Setup(ctx, containerID, netNs.GetPath(), namespaceOpts...)
	return err
}

// Performs any required cleanup actions for the container with the given ID.
// Should only be called to revert any setup steps performed in setupNetworking.
func (m *cniNetworkManager) CleanupNetworking(ctx context.Context, containerID string) error {
	cni, err := m.getCNI()
	if err != nil {
		return fmt.Errorf("failed to get container networking for cleanup: %s", err)
	}

	netNs, err := m.setupNetNs()
	if err != nil {
		return err
	}

	namespaceOpts := []gocni.NamespaceOpts{}
	if m.netOpts.PortMappings != nil {
		namespaceOpts = append(namespaceOpts, gocni.WithCapabilityPortMap(m.netOpts.PortMappings))
	}

	return cni.Remove(ctx, containerID, netNs.GetPath(), namespaceOpts...)
}

// Returns the set of NetworkingOptions which should be set as labels on the container.
func (m *cniNetworkManager) GetInternalNetworkingOptionLabels(_ context.Context) (types.NetworkOptions, error) {
	return m.netOpts, nil
}

// Returns a slice of `oci.SpecOpts` and `containerd.NewContainerOpts` which represent
// the network specs which need to be applied to the container with the given ID.
func (m *cniNetworkManager) GetContainerNetworkingOpts(_ context.Context, containerID string) ([]oci.SpecOpts, []containerd.NewContainerOpts, error) {
	ns, err := m.setupNetNs()
	if err != nil {
		return nil, nil, err
	}

	opts := []oci.SpecOpts{
		oci.WithWindowNetworksAllowUnqualifiedDNSQuery(),
		oci.WithWindowsNetworkNamespace(ns.GetPath()),
	}

	cOpts := []containerd.NewContainerOpts{
		containerd.WithAdditionalContainerLabels(
			map[string]string{
				ocihook.NetworkNamespace: ns.GetPath(),
			},
		),
	}

	return opts, cOpts, nil
}

// Returns the string path to a network namespace.
func (m *cniNetworkManager) setupNetNs() (*netns.NetNS, error) {
	if m.netNs != nil {
		return m.netNs, nil
	}

	// NOTE: the baseDir argument to NewNetNS is ignored on Windows.
	ns, err := netns.NewNetNS("")
	if err != nil {
		return nil, err
	}

	m.netNs = ns
	return ns, err
}
