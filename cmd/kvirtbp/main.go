package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/phenixblue/kvirtbp/internal/cli"
)

func main() {
	if err := cli.NewRootCmd().Execute(); err != nil {
		var exitErr *cli.ExitCodeError
		if errors.As(err, &exitErr) {
			fmt.Fprintln(os.Stderr, exitErr.Error())
			os.Exit(exitErr.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
