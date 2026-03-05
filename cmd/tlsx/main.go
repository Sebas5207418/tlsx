package main

import (
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tlsx/internal/runner"
	"github.com/projectdiscovery/tlsx/pkg/output"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/openssl"
	"github.com/projectdiscovery/utils/errkit"
	errorutils "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
)

var (
	cfgFile string
	options = &clients.Options{}
)

func main() {
	if err := process(); err != nil {
		gologger.Fatal().Msgf("%s", err)
	}
}

func process() error {
	if err := readFlags(os.Args[1:]...); err != nil {
		return errkit.Wrapf(err, "could not read flags")
	}

	// Initialize output coordinator if output file is specified
	var coord *output.AsyncOutputCoordinator
	if options.OutputFile != "" {
		var err error
		coord, err = output.NewAsyncOutputCoordinator(options.OutputFile, 10000, 1*time.Second)
		if err != nil {
			return errkit.Wrapf(err, "could not initialize output coordinator")
		}
		options.AsyncOutputCoordinator = coord
		coord.HandleSignals()

		defer func() {
			if err := coord.GracefulShutdown(); err != nil {
				gologger.Warning().Msgf("Error during graceful shutdown: %v", err)
			}
		}()
	}

	runner, err := runner.New(options)
	if err != nil {
		return errkit.Wrapf(err, "could not create runner")
	}
	if runner == nil {
		return nil
	}
	if err := runner.Execute(); err != nil {
		return errkit.Wrapf(err, "could not execute runner")
	}
	if err := runner.Close(); err != nil {
		return errkit.Wrapf(err, "could not close runner")
	}
	return nil
}

func readFlags(args ...string) error {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`TLSX is a tls data gathering and analysis toolkit.`)

	// [Tutte le flag groups rimangono identiche al codice originale...]
	// [Inclusi tutti i gruppi: input, scan-mode, probes, ctlogs, ecc...]

	err := flagSet.Parse(args...)
	if err != nil {
		return errkit.Wrapf(err, "could not parse flags")
	}

	hasStdin := fileutil.HasStdin()

	// Validation: CT logs mode and input mode cannot be used together
	if options.CTLogs && (len(options.Inputs) > 0 || options.InputList != "" || hasStdin) {
		return errorutils.NewWithTag("flags", "CT logs mode (-ctl) and input mode (-u/-l/stdin) cannot be used together.")
	}

	// Enable CT logs mode by default if no input is provided
	if len(options.Inputs) == 0 && options.InputList == "" && !hasStdin {
		options.CTLogs = true
	}

	// Enable SAN by default when CT logs mode is active
	if options.CTLogs {
		options.SAN = true
	}

	if options.HealthCheck {
		gologger.Print().Msgf("%s\n", runner.DoHealthCheck(flagSet))
		os.Exit(0)
	}

	if cfgFile != "" {
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			return errkit.Wrapf(err, "could not read config file")
		}
	}
	return nil
}

func init() {
	// Feature: Debug Mode
	if os.Getenv("DEBUG") != "" {
		errkit.EnableTrace = true
	}
}
