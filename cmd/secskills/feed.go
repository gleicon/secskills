package main

import (
	"fmt"

	"github.com/gleicon/secskills/internal/exposure"
)

func cmdFeed(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secskills feed <kev|epss> ...")
	}
	switch args[0] {
	case "kev":
		return exposure.FeedKEV(args[1:])
	case "epss":
		return exposure.FeedEPSS(args[1:])
	case "nvd":
		return exposure.FeedNVD(args[1:])
	default:
		return fmt.Errorf("unknown feed source %q (want kev|epss|nvd)", args[0])
	}
}
