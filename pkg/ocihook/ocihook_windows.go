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

package ocihook

import (
	"fmt"

	gocni "github.com/containerd/go-cni"
	"github.com/containerd/nerdctl/pkg/netutil"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func loadAppArmor() {
	//noop
	return
}

func loadCNIEnv(cniPath string, cniNetconfPath string, networkList []string) (gocni.CNI, []string, error) {
	//// TODO: remove limitation in case multiple names of type="nat" (not name="nat"!)
	//// are supported by HCS:
	//if len(networkList) > 1 {
	//    return nil, nil, fmt.Errorf("only one network attachment allowed on Windows")
	//}

	//// NOTE: we must use `gocni.New` since nerdctl/pkg/netutil doesn't support
	//// loading CNI configs < v1.0.0, and Windows only supports <= 0.4.0.
	//network, err := gocni.New(gocni.WithDefaultConf)
	//if err != nil {
	//    return nil, nil, err
	//}

	e, err := netutil.NewCNIEnv(cniPath, cniNetconfPath, netutil.WithDefaultNetwork())
	if err != nil {
		return nil, nil, err
	}
	cniOpts := []gocni.Opt{
		gocni.WithPluginDir([]string{cniPath}),
	}
	netMap, err := e.NetworkMap()
	if err != nil {
		return nil, nil, err
	}

	cniNames := []string{}
	for _, netstr := range networkList {
		net, ok := netMap[netstr]
		if !ok {
			return nil, nil, fmt.Errorf("no such network: %q", netstr)
		}
		cniOpts = append(cniOpts, gocni.WithConfListBytes(net.Bytes))
		cniNames = append(cniNames, netstr)
	}

	cni, err := gocni.New(cniOpts...)
	if err != nil {
		return nil, nil, err
	}

	return cni, cniNames, nil
}

func getNetNSPath(state *specs.State) (string, error) {
	// If we have a network-namespace annotation we use it over the passed Pid.
	if netNsPath, netNsFound := state.Annotations[NetworkNamespace]; netNsFound {
		if netNsPath == "" {
			return "", fmt.Errorf("a Windows network namespace annotation must be set")
		}
		return netNsPath, nil
	}

	return "", fmt.Errorf("a Windows network namespace annottion is required, not %q annotation in: %+v", NetworkNamespace, state.Annotations)
}

func onCreateRuntime(_ *handlerOpts) error {
	return nil
}

func onCreateContainer(opts *handlerOpts) error {
	// NOTE: on Windows, the network setup actions taken in `commonPostCreateSetup`
	// must be performed within the container's namespace, not the runtime's.
	return commonPostCreateSetup(opts)
}
