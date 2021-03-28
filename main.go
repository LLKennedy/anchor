package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var commands = []string{
	"init",
	"sign",
}

func main() {
	cmd := &cobra.Command{
		Use: fmt.Sprintf("anchor %s", strings.Join(commands, " | ")),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf(("unimplemented"))
		},
	}
	err := cmd.RunE(cmd, os.Args)
	if err != nil {
		log.Fatalln(err)
	}
}
