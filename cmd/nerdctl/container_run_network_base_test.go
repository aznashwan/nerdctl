//go:build linux || windows

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
	"io"
	"net"
	"regexp"
	"strings"
	"testing"

	"github.com/containerd/nerdctl/pkg/testutil"
	"github.com/containerd/nerdctl/pkg/testutil/nettestutil"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/icmd"
)

func baseTestRunPortWithNoHostPort(t *testing.T) {
	type testCase struct {
		containerPort    string
		runShouldSuccess bool
	}
	testCases := []testCase{
		{
			containerPort:    "80",
			runShouldSuccess: true,
		},
		{
			containerPort:    "80-81",
			runShouldSuccess: true,
		},
		{
			containerPort:    "80-81/tcp",
			runShouldSuccess: true,
		},
	}
	tID := testutil.Identifier(t)
	for i, tc := range testCases {
		i := i
		tc := tc
		tcName := fmt.Sprintf("%+v", tc)
		t.Run(tcName, func(t *testing.T) {
			testContainerName := fmt.Sprintf("%s-%d", tID, i)
			base := testutil.NewBase(t)
			defer base.Cmd("rm", "-f", testContainerName).Run()
			pFlag := tc.containerPort
			cmd := base.Cmd("run", "-d",
				"--name", testContainerName,
				"-p", pFlag,
				testutil.NginxAlpineImage)
			var result *icmd.Result
			stdoutContent := ""
			if tc.runShouldSuccess {
				cmd.AssertOK()
			} else {
				cmd.AssertFail()
				return
			}
			portCmd := base.Cmd("port", testContainerName)
			portCmd.Base.T.Helper()
			result = portCmd.Run()
			stdoutContent = result.Stdout() + result.Stderr()
			assert.Assert(cmd.Base.T, result.ExitCode == 0, stdoutContent)
			regexExpression := regexp.MustCompile(`80\/tcp.*?->.*?0.0.0.0:(?P<portNumber>\d{1,5}).*?`)
			match := regexExpression.FindStringSubmatch(stdoutContent)
			paramsMap := make(map[string]string)
			for i, name := range regexExpression.SubexpNames() {
				if i > 0 && i <= len(match) {
					paramsMap[name] = match[i]
				}
			}
			if _, ok := paramsMap["portNumber"]; !ok {
				t.Fail()
				return
			}
			connectURL := fmt.Sprintf("http://%s:%s", "127.0.0.1", paramsMap["portNumber"])
			resp, err := nettestutil.HTTPGet(connectURL, 30, false)
			assert.NilError(t, err)
			respBody, err := io.ReadAll(resp.Body)
			assert.NilError(t, err)
			assert.Assert(t, strings.Contains(string(respBody), testutil.NginxAlpineIndexHTMLSnippet))
		})
	}
}

func baseTestRunPort(t *testing.T) {
	hostIP, err := nettestutil.NonLoopbackIPv4()
	assert.NilError(t, err)
	type testCase struct {
		listenIP         net.IP
		connectIP        net.IP
		hostPort         string
		containerPort    string
		connectURLPort   int
		runShouldSuccess bool
		err              string
	}
	lo := net.ParseIP("127.0.0.1")
	zeroIP := net.ParseIP("0.0.0.0")
	testCases := []testCase{
		{
			listenIP:         lo,
			connectIP:        lo,
			hostPort:         "8080",
			containerPort:    "80",
			connectURLPort:   8080,
			runShouldSuccess: true,
		},
		{
			// for https://github.com/containerd/nerdctl/issues/88
			listenIP:         hostIP,
			connectIP:        hostIP,
			hostPort:         "8080",
			containerPort:    "80",
			connectURLPort:   8080,
			runShouldSuccess: true,
		},
		{
			listenIP:         hostIP,
			connectIP:        lo,
			hostPort:         "8080",
			containerPort:    "80",
			connectURLPort:   8080,
			err:              "connection refused",
			runShouldSuccess: true,
		},
		{
			listenIP:         lo,
			connectIP:        hostIP,
			hostPort:         "8080",
			containerPort:    "80",
			connectURLPort:   8080,
			err:              "connection refused",
			runShouldSuccess: true,
		},
		{
			listenIP:         zeroIP,
			connectIP:        lo,
			hostPort:         "8080",
			containerPort:    "80",
			connectURLPort:   8080,
			runShouldSuccess: true,
		},
		{
			listenIP:         zeroIP,
			connectIP:        hostIP,
			hostPort:         "8080",
			containerPort:    "80",
			connectURLPort:   8080,
			runShouldSuccess: true,
		},
		{
			listenIP:         lo,
			connectIP:        lo,
			hostPort:         "7000-7005",
			containerPort:    "79-84",
			connectURLPort:   7001,
			runShouldSuccess: true,
		},
		{
			listenIP:         hostIP,
			connectIP:        hostIP,
			hostPort:         "7000-7005",
			containerPort:    "79-84",
			connectURLPort:   7001,
			runShouldSuccess: true,
		},
		{
			listenIP:         hostIP,
			connectIP:        lo,
			hostPort:         "7000-7005",
			containerPort:    "79-84",
			connectURLPort:   7001,
			err:              "connection refused",
			runShouldSuccess: true,
		},
		{
			listenIP:         lo,
			connectIP:        hostIP,
			hostPort:         "7000-7005",
			containerPort:    "79-84",
			connectURLPort:   7001,
			err:              "connection refused",
			runShouldSuccess: true,
		},
		{
			listenIP:         zeroIP,
			connectIP:        hostIP,
			hostPort:         "7000-7005",
			containerPort:    "79-84",
			connectURLPort:   7001,
			runShouldSuccess: true,
		},
		{
			listenIP:         zeroIP,
			connectIP:        lo,
			hostPort:         "7000-7005",
			containerPort:    "80-85",
			connectURLPort:   7001,
			err:              "error after 30 attempts",
			runShouldSuccess: true,
		},
		{
			listenIP:         zeroIP,
			connectIP:        lo,
			hostPort:         "7000-7005",
			containerPort:    "80",
			connectURLPort:   7000,
			runShouldSuccess: true,
		},
		{
			listenIP:         zeroIP,
			connectIP:        lo,
			hostPort:         "7000-7005",
			containerPort:    "80",
			connectURLPort:   7005,
			err:              "connection refused",
			runShouldSuccess: true,
		},
		{
			listenIP:         zeroIP,
			connectIP:        lo,
			hostPort:         "7000-7005",
			containerPort:    "79-85",
			connectURLPort:   7005,
			err:              "invalid ranges specified for container and host Ports",
			runShouldSuccess: false,
		},
	}

	tID := testutil.Identifier(t)
	for i, tc := range testCases {
		i := i
		tc := tc
		tcName := fmt.Sprintf("%+v", tc)
		t.Run(tcName, func(t *testing.T) {
			testContainerName := fmt.Sprintf("%s-%d", tID, i)
			base := testutil.NewBase(t)
			defer base.Cmd("rm", "-f", testContainerName).Run()
			pFlag := fmt.Sprintf("%s:%s:%s", tc.listenIP.String(), tc.hostPort, tc.containerPort)
			connectURL := fmt.Sprintf("http://%s:%d", tc.connectIP.String(), tc.connectURLPort)
			t.Logf("pFlag=%q, connectURL=%q", pFlag, connectURL)
			cmd := base.Cmd("run", "-d",
				"--name", testContainerName,
				"-p", pFlag,
				testutil.NginxAlpineImage)
			if tc.runShouldSuccess {
				cmd.AssertOK()
			} else {
				cmd.AssertFail()
				return
			}

			resp, err := nettestutil.HTTPGet(connectURL, 30, false)
			if tc.err != "" {
				assert.ErrorContains(t, err, tc.err)
				return
			}
			assert.NilError(t, err)
			respBody, err := io.ReadAll(resp.Body)
			assert.NilError(t, err)
			assert.Assert(t, strings.Contains(string(respBody), testutil.NginxAlpineIndexHTMLSnippet))
		})
	}

}

func baseTestRunDNS(t *testing.T) {
	base := testutil.NewBase(t)

	base.Cmd("run", "--rm", "--dns", "8.8.8.8", testutil.CommonImage,
		"cat", "/etc/resolv.conf").AssertOutContains("nameserver 8.8.8.8\n")
	base.Cmd("run", "--rm", "--dns-search", "test", testutil.CommonImage,
		"cat", "/etc/resolv.conf").AssertOutContains("search test\n")
	base.Cmd("run", "--rm", "--dns-search", "test", "--dns-search", "test1", testutil.CommonImage,
		"cat", "/etc/resolv.conf").AssertOutContains("search test test1\n")
	base.Cmd("run", "--rm", "--dns-opt", "no-tld-query", "--dns-option", "attempts:10", testutil.CommonImage,
		"cat", "/etc/resolv.conf").AssertOutContains("options no-tld-query attempts:10\n")
	cmd := base.Cmd("run", "--rm", "--dns", "8.8.8.8", "--dns-search", "test", "--dns-option", "attempts:10", testutil.CommonImage,
		"cat", "/etc/resolv.conf")
	cmd.AssertOutContains("nameserver 8.8.8.8\n")
	cmd.AssertOutContains("search test\n")
	cmd.AssertOutContains("options attempts:10\n")
}
