package tooling

import (
	"io"
	"os"
)

// Passthrough copies the input file (or stdin) to stdout unchanged; used when
// tldt is not installed.
func Passthrough(inFile string) error {
	if inFile == "" {
		_, err := io.Copy(os.Stdout, os.Stdin)
		return err
	}
	b, err := os.ReadFile(inFile)
	if err != nil {
		return err
	}
	os.Stdout.Write(b)
	return nil
}
