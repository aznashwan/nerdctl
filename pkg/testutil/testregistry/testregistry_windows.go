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

package testregistry

import (
	"fmt"
	"net"

	"github.com/containerd/nerdctl/pkg/testutil"
	"github.com/containerd/nerdctl/pkg/testutil/nettestutil"

	"gotest.tools/v3/assert"
)

type TestRegistry struct {
	IP         net.IP
	ListenIP   net.IP
	ListenPort int
	HostsDir   string // contains "<HostIP>:<ListenPort>/hosts.toml"
	Cleanup    func()
	Logs       func()
}

func NewPlainHTTP(base *testutil.Base, port int) *TestRegistry {
	hostIP, err := nettestutil.NonLoopbackIPv4()
	assert.NilError(base.T, err)
	// listen on 0.0.0.0 to enable 127.0.0.1
	listenIP := net.ParseIP("0.0.0.0")
	listenPort := port
	base.T.Logf("hostIP=%q, listenIP=%q, listenPort=%d", hostIP, listenIP, listenPort)

	registryContainerName := "reg-" + testutil.Identifier(base.T)
	cmd := base.Cmd("run",
		"-d",
		"-p", fmt.Sprintf("%s:%d:5000", listenIP, listenPort),
		"--name", registryContainerName,
		testutil.RegistryImage)
	cmd.AssertOK()
	if _, err = nettestutil.HTTPGet(fmt.Sprintf("http://%s:%d/v2", hostIP.String(), listenPort), 30, false); err != nil {
		base.Cmd("rm", "-f", registryContainerName).Run()
		base.T.Fatal(err)
	}
	return &TestRegistry{
		IP:         hostIP,
		ListenIP:   listenIP,
		ListenPort: listenPort,
		Cleanup:    func() { base.Cmd("rm", "-f", registryContainerName).AssertOK() },
	}
}
