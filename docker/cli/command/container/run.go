package container

import (
	"fmt"
	"io"
	"net/http/httputil"
	"os"
	"runtime"
	"strings"
	"syscall"
	"log"
	"net"
	"bufio"
	
	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/docker/docker/pkg/promise"
	"github.com/docker/docker/pkg/signal"
	"github.com/docker/libnetwork/resolvconf/dns"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/net/context"
	"github.com/mbndr/logo"
)

var (
	whitelist = vulnerabilitiesWhitelist{}
	logger    *logo.Logger
)

type runOptions struct {
	detach     bool
	sigProxy   bool
	name       string
	detachKeys string
}

// GetIntranetIP get ip to Clair
func GetIntranetIP() string {
	addrs, err := net.InterfaceAddrs()

	var ip []string

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, address := range addrs {

		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				fmt.Println("ip:", ipnet.IP.String())
				ip = append(ip, ipnet.IP.String())
			}
		}
	}
	//fmt.Println(ip[0])
	return ip[0]
}

// updatedockerfile create update image
func updatedockerfile() {

	deldockerfile := os.Remove("dockerfile")
	if deldockerfile != nil {
		fmt.Println(deldockerfile)
	}

	createupdatedockerfile, error := os.Create("dockerfile")
	if error != nil {
		fmt.Println(error)
	}
	fmt.Println(createupdatedockerfile)
	createupdatedockerfile.Close()

	outputFile, outputError := os.OpenFile("dockerfile", os.O_WRONLY|os.O_CREATE, 0666)
	if outputError != nil {
		fmt.Printf("An error occurred with file opening or creation\n")
		return
	}
	defer outputFile.Close()

	outputWriter := bufio.NewWriter(outputFile)
	outputString := "FROM ubuntu\n" + "RUN apt-get update && apt-get upgrade\n"

	outputWriter.WriteString(outputString)
	outputWriter.Flush()
	return
}

// NewRunCommand create a new `docker run` command
func NewRunCommand(dockerCli *command.DockerCli) *cobra.Command {
	var opts runOptions
	var copts *containerOptions

	cmd := &cobra.Command{
		Use:   "run [OPTIONS] IMAGE [COMMAND] [ARG...]",
		Short: "Run a command in a new container",
		Args:  cli.RequiresMinArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			copts.Image = args[0]
			if len(args) > 1 {
				copts.Args = args[1:]
			}
			return runRun(dockerCli, cmd.Flags(), &opts, copts)
		},
	}

	flags := cmd.Flags()
	flags.SetInterspersed(false)

	// These are flags not stored in Config/HostConfig
	flags.BoolVarP(&opts.detach, "detach", "d", false, "Run container in background and print container ID")
	flags.BoolVar(&opts.sigProxy, "sig-proxy", true, "Proxy received signals to the process")
	flags.StringVar(&opts.name, "name", "", "Assign a name to the container")
	flags.StringVar(&opts.detachKeys, "detach-keys", "", "Override the key sequence for detaching a container")

	// Add an explicit help that doesn't have a `-h` to prevent the conflict
	// with hostname
	flags.Bool("help", false, "Print usage")

	command.AddTrustVerificationFlags(flags)
	copts = addFlags(flags)
	return cmd
}

func warnOnOomKillDisable(hostConfig container.HostConfig, stderr io.Writer) {
	if hostConfig.OomKillDisable != nil && *hostConfig.OomKillDisable && hostConfig.Memory == 0 {
		fmt.Fprintln(stderr, "WARNING: Disabling the OOM killer on containers without setting a '-m/--memory' limit may be dangerous.")
	}
}

// check the DNS settings passed via --dns against localhost regexp to warn if
// they are trying to set a DNS to a localhost address
func warnOnLocalhostDNS(hostConfig container.HostConfig, stderr io.Writer) {
	for _, dnsIP := range hostConfig.DNS {
		if dns.IsLocalhost(dnsIP) {
			fmt.Fprintf(stderr, "WARNING: Localhost DNS setting (--dns=%s) may fail in containers.\n", dnsIP)
			return
		}
	}
}


// detectmain detect image vulnerability
func detectmain(image string,currentip string ){
	var (
		whitelistFile      = ""
		whitelistThreshold = "Unknown"
		clair              = "http://127.0.0.1:6060"
		//ip                 = "172.17.0.4"
		ip = currentip
		logFile            = ""
		reportAll          = true
		reportFile         = ""
		imageName          = image
	)

	initializeLogger(logFile)
	if whitelistFile != "" {
		whitelist = parseWhitelistFile(whitelistFile)
	}
	validateThreshold(whitelistThreshold)

	logger.Info("Start clair-scanner")

	go listenForSignal(func(s os.Signal) {
		log.Fatalf("Application interrupted [%v]", s)
	})

	result := scan(scannerConfig{
		imageName,
		whitelist,
		clair,
		ip,
		reportFile,
		whitelistThreshold,
		reportAll,
	})
	if len(result) > 0 {
	fmt.Println(result)
	updatedockerfile()
	}else{
	fmt.Println("OK")
}
}

func initializeLogger(logFile string) {
	cliRec := logo.NewReceiver(os.Stderr, "")
	cliRec.Color = true

	if logFile != "" {
		file, err := logo.Open(logFile)
		if err != nil {
			fmt.Printf("Could not initialize logging file %v", err)
			os.Exit(1)
		}

		fileRec := logo.NewReceiver(file, "")
		logger = logo.NewLogger(cliRec, fileRec)
	} else {
		logger = logo.NewLogger(cliRec)
	}
}


func runRun(dockerCli *command.DockerCli, flags *pflag.FlagSet, opts *runOptions, copts *containerOptions) error {
	containerConfig, err := parse(flags, copts)
	// just in case the parse does not exit
	if err != nil {
		reportError(dockerCli.Err(), "run", err.Error(), true)
		return cli.StatusError{StatusCode: 125}
	}
	return runContainer(dockerCli, opts, copts, containerConfig)
}

func runContainer(dockerCli *command.DockerCli, opts *runOptions, copts *containerOptions, containerConfig *containerConfig) error {
	
	config := containerConfig.Config
	hostConfig := containerConfig.HostConfig
	stdout, stderr := dockerCli.Out(), dockerCli.Err()
	client := dockerCli.Client()

	fmt.Println(config.Image)
	currentip := GetIntranetIP()
	fmt.Println(currentip)
	if config.Image == "ubuntu" {
	detectmain(config.Image,currentip)
}
	// TODO: pass this as an argument
	cmdPath := "run"

	warnOnOomKillDisable(*hostConfig, stderr)
	warnOnLocalhostDNS(*hostConfig, stderr)

	config.ArgsEscaped = false

	if !opts.detach {
		if err := dockerCli.In().CheckTty(config.AttachStdin, config.Tty); err != nil {
			return err
		}
	} else {
		if copts.attach.Len() != 0 {
			return errors.New("Conflicting options: -a and -d")
		}

		config.AttachStdin = false
		config.AttachStdout = false
		config.AttachStderr = false
		config.StdinOnce = false
	}

	// Disable sigProxy when in TTY mode
	if config.Tty {
		opts.sigProxy = false
	}

	// Telling the Windows daemon the initial size of the tty during start makes
	// a far better user experience rather than relying on subsequent resizes
	// to cause things to catch up.
	if runtime.GOOS == "windows" {
		hostConfig.ConsoleSize[0], hostConfig.ConsoleSize[1] = dockerCli.Out().GetTtySize()
	}

	ctx, cancelFun := context.WithCancel(context.Background())

	createResponse, err := createContainer(ctx, dockerCli, containerConfig, opts.name)
	if err != nil {
		reportError(stderr, cmdPath, err.Error(), true)
		return runStartContainerErr(err)
	}
	if opts.sigProxy {
		sigc := ForwardAllSignals(ctx, dockerCli, createResponse.ID)
		defer signal.StopCatch(sigc)
	}
	var (
		waitDisplayID chan struct{}
		errCh         chan error
	)
	if !config.AttachStdout && !config.AttachStderr {
		// Make this asynchronous to allow the client to write to stdin before having to read the ID
		waitDisplayID = make(chan struct{})
		go func() {
			defer close(waitDisplayID)
			fmt.Fprintln(stdout, createResponse.ID)
		}()
	}
	attach := config.AttachStdin || config.AttachStdout || config.AttachStderr
	if attach {
		if opts.detachKeys != "" {
			dockerCli.ConfigFile().DetachKeys = opts.detachKeys
		}

		close, err := attachContainer(ctx, dockerCli, &errCh, config, createResponse.ID)
		defer close()
		if err != nil {
			return err
		}
	}

	statusChan := waitExitOrRemoved(ctx, dockerCli, createResponse.ID, copts.autoRemove)

	//start the container
	if err := client.ContainerStart(ctx, createResponse.ID, types.ContainerStartOptions{}); err != nil {
		// If we have holdHijackedConnection, we should notify
		// holdHijackedConnection we are going to exit and wait
		// to avoid the terminal are not restored.
		if attach {
			cancelFun()
			<-errCh
		}

		reportError(stderr, cmdPath, err.Error(), false)
		if copts.autoRemove {
			// wait container to be removed
			<-statusChan
		}
		return runStartContainerErr(err)
	}

	if (config.AttachStdin || config.AttachStdout || config.AttachStderr) && config.Tty && dockerCli.Out().IsTerminal() {
		if err := MonitorTtySize(ctx, dockerCli, createResponse.ID, false); err != nil {
			fmt.Fprintln(stderr, "Error monitoring TTY size:", err)
		}
	}

	if errCh != nil {
		if err := <-errCh; err != nil {
			logrus.Debugf("Error hijack: %s", err)
			return err
		}
	}

	// Detached mode: wait for the id to be displayed and return.
	if !config.AttachStdout && !config.AttachStderr {
		// Detached mode
		<-waitDisplayID
		return nil
	}

	status := <-statusChan
	if status != 0 {
		return cli.StatusError{StatusCode: status}
	}
	return nil
}

func attachContainer(
	ctx context.Context,
	dockerCli *command.DockerCli,
	errCh *chan error,
	config *container.Config,
	containerID string,
) (func(), error) {
	stdout, stderr := dockerCli.Out(), dockerCli.Err()
	var (
		out, cerr io.Writer
		in        io.ReadCloser
	)
	if config.AttachStdin {
		in = dockerCli.In()
	}
	if config.AttachStdout {
		out = stdout
	}
	if config.AttachStderr {
		if config.Tty {
			cerr = stdout
		} else {
			cerr = stderr
		}
	}

	options := types.ContainerAttachOptions{
		Stream:     true,
		Stdin:      config.AttachStdin,
		Stdout:     config.AttachStdout,
		Stderr:     config.AttachStderr,
		DetachKeys: dockerCli.ConfigFile().DetachKeys,
	}

	resp, errAttach := dockerCli.Client().ContainerAttach(ctx, containerID, options)
	if errAttach != nil && errAttach != httputil.ErrPersistEOF {
		// ContainerAttach returns an ErrPersistEOF (connection closed)
		// means server met an error and put it in Hijacked connection
		// keep the error and read detailed error message from hijacked connection later
		return nil, errAttach
	}

	*errCh = promise.Go(func() error {
		if errHijack := holdHijackedConnection(ctx, dockerCli, config.Tty, in, out, cerr, resp); errHijack != nil {
			return errHijack
		}
		return errAttach
	})
	return resp.Close, nil
}

// reportError is a utility method that prints a user-friendly message
// containing the error that occurred during parsing and a suggestion to get help
func reportError(stderr io.Writer, name string, str string, withHelp bool) {
	str = strings.TrimSuffix(str, ".") + "."
	if withHelp {
		str += "\nSee '" + os.Args[0] + " " + name + " --help'."
	}
	fmt.Fprintf(stderr, "%s: %s\n", os.Args[0], str)
}

// if container start fails with 'not found'/'no such' error, return 127
// if container start fails with 'permission denied' error, return 126
// return 125 for generic docker daemon failures
func runStartContainerErr(err error) error {
	trimmedErr := strings.TrimPrefix(err.Error(), "Error response from daemon: ")
	statusError := cli.StatusError{StatusCode: 125}
	if strings.Contains(trimmedErr, "executable file not found") ||
		strings.Contains(trimmedErr, "no such file or directory") ||
		strings.Contains(trimmedErr, "system cannot find the file specified") {
		statusError = cli.StatusError{StatusCode: 127}
	} else if strings.Contains(trimmedErr, syscall.EACCES.Error()) {
		statusError = cli.StatusError{StatusCode: 126}
	}

	return statusError
}
