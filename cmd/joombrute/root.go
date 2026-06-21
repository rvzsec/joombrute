package main

import (
	"io"
	"os"

	"github.com/rvzsec/joombrute/internal/output"
	"github.com/spf13/cobra"
)

// Global flags shared by every subcommand. Bound on the root and read by
// the individual command builders so we don't repeat boilerplate.
type globalFlags struct {
	URL         string
	Proxy       string
	UserAgent   string
	InsecureTLS bool
	JSONLOutput bool
	OutputFile  string
	Debug       bool
}

var gflags globalFlags

// banner is the figlet "smslant" rendering of "joombrute" plus a tight
// 3-line metadata block. Printed by --help, -h, and bare invocation.
// Slanted italic glyphs telegraph the speed angle, 5 lines tall, ~46
// columns wide, fits any 80-col terminal without wrap.
//
// The version line is interpolated lazily via bannerString() so a build
// stamped with -ldflags -X main.version=v1.2.3 shows the real tag.
const bannerArt = `      _                 __            __     
     (_)__  ___  __ _  / /  ______ __/ /____ 
    / / _ \/ _ \/  ' \/ _ \/ __/ // / __/ -_)
 __/ /\___/\___/_/_/_/_.__/_/  \_,_/\__/\__/ 
|___/                                        `

const (
	ansiRed   = "\033[31m"
	ansiBold  = "\033[1m"
	ansiDim   = "\033[2m"
	ansiReset = "\033[0m"
)

func bannerString() string {
	return ansiRed + ansiBold + bannerArt + ansiReset + "\n" +
		ansiDim +
		"  joombrute " + version + " · CVE-2023-23752 · CVE-2023-23755 · CVE-2025-25227\n" +
		"  Joomla 3/4/5 credential attack toolkit\n" +
		"  Ravindu Wickramasinghe | rvz (@rvzsec) · www.zyenra.com\n" +
		"  github.com/rvzsec/joombrute · Authorized use only.\n" +
		ansiReset
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "joombrute",
		Short:         "Joomla 3/4/5 credential attack toolkit",
		Long:          bannerString(),
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: false,
		// Bare invocation with no subcommand prints help instead of
		// the cobra default "Error: required flag(s) not set" noise.
		// Operators who type just `joombrute` get the menu they expect.
		Run: func(c *cobra.Command, _ []string) { _ = c.Help() },
	}
	// Cobra's default version template is "{{.Use}} version {{.Version}}".
	// Override so the output is just "joombrute v1.2.3" (or "joombrute dev"
	// when running an un-stamped build) which is friendlier for shell
	// pipelines like `joombrute --version | awk '{print $2}'`.
	cmd.SetVersionTemplate("joombrute {{.Version}}\n")

	pf := cmd.PersistentFlags()
	pf.StringVarP(&gflags.URL, "url", "u", "", "Joomla target base URL (e.g. http://target/)")
	pf.StringVarP(&gflags.Proxy, "proxy", "p", "", "HTTP/HTTPS/SOCKS5 proxy (e.g. http://127.0.0.1:8080)")
	pf.StringVar(&gflags.UserAgent, "ua", "", "Override User-Agent header")
	pf.BoolVarP(&gflags.InsecureTLS, "insecure", "k", false, "Skip TLS verification")
	pf.BoolVar(&gflags.JSONLOutput, "json", false, "Emit findings as JSONL (one object per line)")
	pf.StringVarP(&gflags.OutputFile, "output", "o", "", "Write findings to file in addition to stdout")
	pf.BoolVar(&gflags.Debug, "debug", false, "Verbose debug logging")

	cmd.AddCommand(newDetectCmd())
	cmd.AddCommand(newEnumCmd())
	cmd.AddCommand(newBruteCmd())
	cmd.AddCommand(newMFABruteCmd())
	cmd.AddCommand(newMFABypassCmd())
	cmd.AddCommand(newChainCmd())

	return cmd
}

// buildSink returns the configured output sink based on global flags.
// If --output is set we tee to file. JSONL vs console is controlled by --json.
func buildSink() (output.Sink, func()) {
	var stdoutSink output.Sink
	if gflags.JSONLOutput {
		stdoutSink = output.NewJSONLSink(os.Stdout, gflags.Debug)
	} else {
		stdoutSink = output.NewConsoleSink(os.Stdout, gflags.Debug)
	}

	if gflags.OutputFile == "" {
		return stdoutSink, func() {}
	}

	f, err := os.OpenFile(gflags.OutputFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		stdoutSink.Errorf("could not open output file %q: %v (continuing without file sink)", gflags.OutputFile, err)
		return stdoutSink, func() {}
	}

	fileSink := output.NewJSONLSink(f, gflags.Debug)
	tee := &teeSink{a: stdoutSink, b: fileSink}
	return tee, func() { _ = f.Close() }
}

// teeSink fans every event out to two underlying sinks. Used when --output
// is set: stdout gets human/JSONL, file always gets JSONL for replay.
type teeSink struct {
	a, b output.Sink
}

func (t *teeSink) Hit(h output.Hit) {
	t.a.Hit(h)
	t.b.Hit(h)
}
func (t *teeSink) Infof(f string, args ...any)  { t.a.Infof(f, args...); t.b.Infof(f, args...) }
func (t *teeSink) Warnf(f string, args ...any)  { t.a.Warnf(f, args...); t.b.Warnf(f, args...) }
func (t *teeSink) Errorf(f string, args ...any) { t.a.Errorf(f, args...); t.b.Errorf(f, args...) }
func (t *teeSink) Debugf(f string, args ...any) { t.a.Debugf(f, args...); t.b.Debugf(f, args...) }

// _ tiny guard to keep io imported if a future tee variant needs it.
var _ io.Writer = (*os.File)(nil)
