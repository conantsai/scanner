package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/mbndr/logo"
)

var (
	whitelist = vulnerabilitiesWhitelist{}
	logger    *logo.Logger
)

func main() {

	var (
		/*whitelistFile      = app.StringOpt("w whitelist", "", "Path to the whitelist file")
		whitelistThreshold = app.StringOpt("t threshold", "Unknown", "CVE severity threshold. Valid values; 'Defcon1', 'Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'")
		clair              = app.StringOpt("c clair", "http://127.0.0.1:6060", "Clair URL")
		ip                 = app.StringOpt("ip", "localhost", "IP address where clair-scanner is running on")
		logFile            = app.StringOpt("l log", "", "Log to a file")
		reportAll          = app.BoolOpt("all reportAll", true, "Display all vulnerabilities, even if they are approved")
		reportFile         = app.StringOpt("r report", "", "Report output file, as JSON")
		imageName          = app.StringArg("IMAGE", "", "Name of the Docker image to scan")*/

		whitelistFile      = ""
		whitelistThreshold = "Unknown"
		clair              = "http://127.0.0.1:6060"
		//ip                 = "192.168.253.142"
		ip          = GetIntranetIP()
		logFile     = ""
		reportAll   = true
		reportFile  = ""
		imageName   = "ubuntu:latest"
		updatereply = ""
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
		logger.Info("Do you want to update the vulnerable image?")
		fmt.Scanln(&updatereply)
		if updatereply == "YES" || updatereply == "yes" {
			fmt.Println("YES")
		} else if updatereply == "NO" || updatereply == "no" {
			fmt.Println("NO")
		}
		os.Exit(1)
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

// GetIntranetIP get ip to Clair
func GetIntranetIP() string {
	addrs, err := net.InterfaceAddrs()

	var ip []string

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, address := range addrs {

		// 检查ip地址判断是否回环地址
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				fmt.Println("ip:", ipnet.IP.String())
				ip = append(ip, ipnet.IP.String())
			}

		}
	}
	fmt.Println(ip[0])
	return ip[0]
}
