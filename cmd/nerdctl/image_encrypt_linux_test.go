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
	"testing"

	"github.com/containerd/nerdctl/pkg/testutil"
)

// Returns the list of shell commands to be run for generating public/private RSA keys
// with the given filepaths to be used during the encryption/decryption tests
func keyGenCmdsF(prvPath string, pubPath string) [][]string {
	// Exec openssl commands to ensure that nerdctl is compatible with the output of openssl commands.
	// Do NOT refactor this function to use "crypto/rsa" stdlib.
	return [][]string{
		{"openssl", "genrsa", "-out", prvPath},
		{"openssl", "rsa", "-in", prvPath, "-pubout", "-out", pubPath},
	}
}

func TestImageEncryptJWE(t *testing.T) {
	keyPair := newJWEKeyPair(t, keyGenCmdsF)
	testImageEncryptJWE(t, testutil.CommonImage, keyPair)
}
