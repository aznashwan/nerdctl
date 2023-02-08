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
	"errors"
	"fmt"
	"os"

	gocni "github.com/containerd/go-cni"
	"github.com/containerd/nerdctl/pkg/netutil"

	"github.com/opencontainers/runtime-spec/specs-go"
)

func loadAppArmor() {
	//noop
	return
}

func loadCNIEnv(cniPath string, cniNetconfPath string, networkList []string) (gocni.CNI, []string, error) {
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
	netNsPath, netNsFound := state.Annotations[NetworkNamespace]
	if netNsFound {
		if _, err := os.Stat(netNsPath); err != nil {
			return "", err
		}

		return netNsPath, nil
	}

	if state.Pid == 0 && !netNsFound {
		return "", errors.New("both state.Pid and the netNs annotation are unset")
	}

	// We dont't have a networking namespace annotation, but we have a PID.
	s := fmt.Sprintf("/proc/%d/ns/net", state.Pid)
	if _, err := os.Stat(s); err != nil {
		return "", err
	}
	return s, nil
}

func onCreateRuntime(opts *handlerOpts) error {
	// NOTE: on BSDs, the network setup actions taken in `commonPostCreateSetup`
	// must be performed within the runtime's namespace, not the container's.
	return commonPostCreateSetup(opts)
}

func onCreateContainer(_ *handlerOpts) error {
	return nil
}
