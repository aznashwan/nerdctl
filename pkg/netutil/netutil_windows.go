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

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/mitchellh/mapstructure"
)

const (
	DefaultNetworkName = "nat"
	DefaultCIDR        = "10.4.0.0/24"

	// When creating non-default network without passing in `--subnet` option,
	// nerdctl assigns subnet address for the creation starting from `StartingCIDR`
	// This prevents subnet address overlapping with `DefaultCIDR` used by the default networkß
	StartingCIDR = "10.4.1.0/24"

	DriverNat         = "nat"
	DriverL2Bridge    = "l2bridge"
	DriverOverlay     = "overlay"
	DriverTransparent = "transparent"
)

func (n *NetworkConfig) subnets() ([]*net.IPNet, error) {
	var plugin pluginConfig
	if err := json.Unmarshal(n.Plugins[0].Bytes, &plugin); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON for plugin %q: %s", n.Plugins[0].Network.Type, err)
	}
	var ipam windowsIpamConfig
	if err := mapstructure.Decode(plugin.IPAM, &ipam); err != nil {
		return nil, fmt.Errorf("failed to decode IPAM for plugin %q: %s", n.Plugins[0].Network.Type, err)
	}
	_, subnet, err := net.ParseCIDR(ipam.Subnet)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CIDRs plugin %q: %s", n.Plugins[0].Network.Type, err)
	}
	subnets := []*net.IPNet{subnet}
	return subnets, nil
}

func (n *NetworkConfig) clean() error {
	return nil
}

func (e *CNIEnv) generateCNIPlugins(driver string, name string, ipam map[string]interface{}, opts map[string]string, ipv6 bool) ([]CNIPlugin, error) {
	plugin, err := newPlugin(driver)
	if err != nil {
		return nil, err
	}
	plugin.IPAM = ipam

	return []CNIPlugin{plugin}, nil
}

func (e *CNIEnv) generateIPAM(driver string, subnets []string, gatewayStr, ipRangeStr string, opts map[string]string, ipv6 bool) (map[string]interface{}, error) {
	switch driver {
	case "default":
	default:
		return nil, fmt.Errorf("unsupported ipam driver %q", driver)
	}

	ipamConfig := newWindowsIPAMConfig()
	subnet, err := e.parseSubnet(subnets[0])
	if err != nil {
		return nil, err
	}
	ipamRange, err := parseIPAMRange(subnet, gatewayStr, ipRangeStr)
	if err != nil {
		return nil, err
	}
	ipamConfig.Subnet = ipamRange.Subnet
	ipamConfig.Routes = append(ipamConfig.Routes, IPAMRoute{Gateway: ipamRange.Gateway})
	ipam, err := structToMap(ipamConfig)
	if err != nil {
		return nil, err
	}
	return ipam, nil
}
