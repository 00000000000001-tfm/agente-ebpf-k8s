package main

import (
	"fmt"
	"io"
	"net"
	"os"
)

func main() {
	port := "4444"
	fmt.Printf("[*] Listener escuchando en :%s\n", port)

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()

	fmt.Println("[*] Esperando conexión...")
	conn, err := ln.Accept()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Accept error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Conexión recibida de %s\n", conn.RemoteAddr())
	go io.Copy(conn, os.Stdin)
	io.Copy(os.Stdout, conn)
}
