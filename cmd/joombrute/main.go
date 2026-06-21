// joombrute - Joomla 3/4/5 credential attack toolkit.
//
// Title  : joombrute - Joomla 3/4/5 credential attack toolkit
// Author : Ravindu Wickramasinghe | rvz (@rvzsec)
// Link   : https://github.com/rvzsec/joombrute
// Website: www.zyenra.com
//
// CVE coverage:
//   CVE-2023-23752  unauthenticated API user + DB credential disclosure
//                   (Joomla 4.0.0 - 4.2.7, CISA KEV)
//   CVE-2023-23755  no rate limit on captive MFA screen, 6-digit TOTP brute
//                   (Joomla 4.2.0 - 4.3.1)
//   CVE-2025-25227  MFA captive-gate bypass via view=methods
//                   (Joomla 4.0.0 - 4.4.12, 5.0.0 - 5.2.5)
//
// DISCLAIMER:
//
// This tool is provided for authorized security testing and research
// only. Run it only against systems you have explicit written
// permission to test. Generates traffic that any IDS will catch. The
// author disclaims all liability for misuse. Compliance with local
// law is the user's responsibility.
package main

import (
	"fmt"
	"os"
)

// version is stamped at build time via:
//
//	go build -ldflags "-X main.version=v1.2.3" ./cmd/joombrute
//
// The release workflow sets it from the git tag. Dev builds leave it
// as "dev" so `joombrute --version` prints something sensible.
var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
