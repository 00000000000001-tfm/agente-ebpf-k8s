package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// AF_ALG socket structures
const (
	AF_ALG        = 38
	SOL_ALG       = 279
	ALG_SET_KEY   = 1
)

type SockaddrALG struct {
	Family uint16
	Type   [14]byte
	Feat   uint32
	Mask   uint32
	Name   [64]byte
}

func main() {
	fmt.Println("[*] CVE-2026-31431 Copy Fail PoC")
	fmt.Println("[*] Paso 1: socket(AF_ALG, SOCK_SEQPACKET, 0)")

	// Paso 1 — abrir socket AF_ALG
	fd, _, errno := syscall.RawSyscall(syscall.SYS_SOCKET, AF_ALG, syscall.SOCK_SEQPACKET, 0)
	if errno != 0 {
		fmt.Fprintf(os.Stderr, "[-] socket() falló: %v\n", errno)
		os.Exit(1)
	}
	fmt.Printf("[+] Socket AF_ALG abierto fd=%d\n", fd)

	fmt.Println("[*] Paso 2: bind() con algoritmo skcipher/cbc(aes)")

	// Paso 2 — bind con algoritmo AEAD
	sa := SockaddrALG{Family: AF_ALG}
	copy(sa.Type[:], "skcipher")
	copy(sa.Name[:], "cbc(aes)")

	_, _, errno = syscall.RawSyscall(syscall.SYS_BIND, fd,
		uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa))
	if errno != 0 {
		fmt.Fprintf(os.Stderr, "[-] bind() falló: %v\n", errno)
		// Continuar — el agente ya debería haber detectado el socket
	} else {
		fmt.Println("[+] bind() completado — algoritmo skcipher configurado")
	}

	fmt.Println("[*] Paso 3: sendmsg() — escritura en page cache")

	// Paso 3 — sendmsg simulando escritura en page cache
	msg := []byte("COPYFAIL_PAYLOAD_PAGECACHE_WRITE")
	iov := syscall.Iovec{
		Base: &msg[0],
		Len:  uint64(len(msg)),
	}
	msghdr := syscall.Msghdr{
		Iov:    &iov,
		Iovlen: 1,
	}
	_, _, errno = syscall.RawSyscall(syscall.SYS_SENDMSG, fd,
		uintptr(unsafe.Pointer(&msghdr)), 0)
	if errno != 0 {
		fmt.Printf("[+] sendmsg() retornó error esperado: %v\n", errno)
		fmt.Println("[+] Secuencia completa — el agente debería haber detectado CF score>=21")
	} else {
		fmt.Println("[+] sendmsg() completado")
	}

	syscall.Close(int(fd))
	fmt.Println("[*] PoC completado")
}
