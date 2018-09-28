/*package main

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"time"
)

func main() {
	date := currentdate()
	fmt.Println(date)
	//cmd = exec.Command("docker", `/usr/bin/`)
	//cmd := exec.Command("/usr/bin/docker")
	//cmd = exec.Command("/bin/sh", "-c", `/sbin/ifconfig en0 | grep -E 'inet ' |  awk '{print $2}'`)
	command := "/usr/bin/docker"
	//command += date
	fmt.Println(command)
	params := []string{"ps -a"}
	execCommand(command, params)
}

func execCommand(commandName string, params []string) bool {
	cmd := exec.Command(commandName, params...)

	//显示运行的命令
	fmt.Println(cmd.Args)

	stdout, err := cmd.StdoutPipe()

	if err != nil {
		fmt.Println(err)
		return false
	}

	cmd.Start()

	reader := bufio.NewReader(stdout)

	//实时循环读取输出流中的一行内容
	for {
		line, err2 := reader.ReadString('\n')
		if err2 != nil || io.EOF == err2 {
			break
		}
		fmt.Println(line)
	}

	cmd.Wait()
	return true
}*/

package main

import (
	/*"fmt"
	"os"*/
	"fmt"
	"os"
	"os/exec"
	"time"
)

func main() {
	var whoami []byte
	var err error
	var cmd *exec.Cmd

	cmd = exec.Command("/usr/bin/docker", "build", "-t=ubuntu:update", "/home/conan/go/ExeCommand")
	//cmd = exec.Command("/usr/bin/docker", "version")

	if whoami, err = cmd.Output(); err != nil {
		fmt.Println(err)
		fmt.Println("error")
		os.Exit(1)
	}
	// 默认输出有一个换行
	fmt.Println(string(whoami))
	os.Exit(1)

}

func currentdate() string {
	t := time.Now()
	date := t.Format("2006-01-02")
	return date
}
