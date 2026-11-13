package main

import (
	"testing"
)

func TestSelftest(t *testing.T) {
	if err := cmdSelftest(nil); err != nil {
		t.Fatalf("end-to-end selftest failed: %v", err)
	}
}
