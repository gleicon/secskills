package main

import (
	"flag"
	"fmt"

	"github.com/gleicon/secskills/internal/report"
	"github.com/gleicon/secskills/internal/workspace"
)

// cmdAttest signs or verifies a run's attestation envelope.
func cmdAttest(args []string) error {
	fs := flag.NewFlagSet("attest", flag.ContinueOnError)
	sign := fs.String("sign", "", "target: sign its latest run attestation")
	verify := fs.String("verify", "", "target: verify its run attestation signature")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *sign != "":
		wd, err := workspace.Workdir(*sign)
		if err != nil {
			return err
		}
		out, err := report.SignRunManifest(wd)
		if err != nil {
			return err
		}
		fmt.Printf("signed: %s\n", out)
		return nil
	case *verify != "":
		wd, err := workspace.Workdir(*verify)
		if err != nil {
			return err
		}
		if err := report.VerifyRunManifest(wd); err != nil {
			return err
		}
		if err := report.VerifyEvidenceChain(wd); err != nil {
			return err
		}
		fmt.Println("signature OK — run attestation + evidence chain are authentic and unmodified")
		return nil
	}
	return fmt.Errorf("usage: secskills attest --sign <target> | --verify <target>")
}
