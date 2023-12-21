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

package netutil

import "fmt"

const (
	PluginNat       = "nat"
	PluginSDNBridge = "sdnbridge"
	PluginOverlay   = "sdnoverlay"
)

var windowsDriverToPluginMap = map[string]string{
	DriverNat:      PluginNat,
	DriverL2Bridge: PluginSDNBridge,
	DriverOverlay:  PluginOverlay,
}

type pluginConfig struct {
	PluginType string                 `json:"type"`
	IPAM       map[string]interface{} `json:"ipam"`
}

func (conf *pluginConfig) GetPluginType() string {
	return conf.PluginType
}

func newPlugin(driverName string) (*pluginConfig, error) {
	pluginType, ok := windowsDriverToPluginMap[driverName]
	if !ok {
		return nil, fmt.Errorf("unsupported CNI driver %q", driverName)
	}

	return &pluginConfig{
		PluginType: pluginType,
	}, nil
}

// https://github.com/microsoft/windows-container-networking/blob/v0.2.0/cni/cni.go#L55-L63
type windowsIpamConfig struct {
	Type          string      `json:"type"`
	Environment   string      `json:"environment,omitempty"`
	AddrSpace     string      `json:"addressSpace,omitempty"`
	Subnet        string      `json:"subnet,omitempty"`
	Address       string      `json:"ipAddress,omitempty"`
	QueryInterval string      `json:"queryInterval,omitempty"`
	Routes        []IPAMRoute `json:"routes,omitempty"`
}

func newWindowsIPAMConfig() *windowsIpamConfig {
	return &windowsIpamConfig{}
}
