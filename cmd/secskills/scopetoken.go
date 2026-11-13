package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/gleicon/secskills/internal/scope"
)

func cmdToken(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secskills token <sign|verify> --file <token.json>")
	}
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	file := fs.String("file", "", "token JSON file")
	ip := fs.String("ip", "", "verify: also check this IP is authorized")
	class := fs.String("class", "cve", "verify: check class for the --ip test")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("--file is required")
	}
	key, err := scope.TokenKey()
	if err != nil {
		return err
	}
	b, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	var tok scope.ScopeToken
	if err := json.Unmarshal(b, &tok); err != nil {
		return err
	}

	switch args[0] {
	case "sign":
		signed, err := tok.Sign(key)
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(signed, "", "  ")
		fmt.Println(string(out))
		return nil
	case "verify":
		if err := tok.Verify(key); err != nil {
			return fmt.Errorf("REJECT: %w", err)
		}
		fmt.Printf("signature OK — tenant %s, AS%d, %d prefixes, window %s..%s, classes %v, intrusive=%v\n",
			tok.Tenant, tok.ASN, len(tok.Prefixes), tok.NotBefore, tok.NotAfter, tok.AllowedClasses, tok.Intrusive)
		if *ip != "" {
			ok, why := tok.Authorizes(net.ParseIP(*ip), *class, time.Now())
			fmt.Printf("authorizes %s (%s): %v — %s\n", *ip, *class, ok, why)
		}
		return nil
	default:
		return fmt.Errorf("unknown token subcommand %q (want sign|verify)", args[0])
	}
}
