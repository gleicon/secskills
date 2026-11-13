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
		out, err := report.SignRunManifest(workspace.Workdir(*sign))
		if err != nil {
			return err
		}
		fmt.Printf("signed: %s\n", out)
		return nil
	case *verify != "":
		if err := report.VerifyRunManifest(workspace.Workdir(*verify)); err != nil {
			return err
		}
		if err := report.VerifyEvidenceChain(workspace.Workdir(*verify)); err != nil {
			return err
		}
		fmt.Println("signature OK — run attestation + evidence chain are authentic and unmodified")
		return nil
	}
	return fmt.Errorf("usage: secskills attest --sign <target> | --verify <target>")
}
