//go:build darwin || freebsd || netbsd || openbsd

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
	"runtime"

	"github.com/containerd/containerd/oci"
)

// Verifies that the internal network settings are correct.
func (m *cniNetworkManager) verifyNetworkOptions() error {
	return fmt.Errorf("CNI networking currently unsupported on %s", runtime.GOOS)
}

// Performs setup actions required for the container with the given ID.
func (m *cniNetworkManager) setupNetworking(_ string) error {
	return nil
}

// Performs any required cleanup actions for the container with the given ID.
// Should only be called to revert any setup steps performed in setupNetworking.
func (m *cniNetworkManager) cleanupNetworking(_ string) error {
	return nil
}

// Returns a struct with the internal networking labels for the internal
// network settings which should be set of the container.
func (m *cniNetworkManager) getInternalNetworkingLabels() (internalLabels, error) {
	return internalLabels{}, fmt.Errorf("CNI networking currently unsupported on %s", runtime.GOOS)
}

// Returns a slice of `oci.SpecOpts` which represent the network specs
// which need to be applied to the container with the given ID.
func (m *cniNetworkManager) getContainerNetworkingSpecOpts(_ string) ([]oci.SpecOpts, error) {
	return []oci.SpecOpts{}, fmt.Errorf("CNI networking currently unsupported on %s", runtime.GOOS)
}
