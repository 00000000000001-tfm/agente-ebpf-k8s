// miner-poc.c — PoC mínimo y aislado para el sensor cryptominer.
// Solo abre un socket y conecta a un puerto stratum conocido (3333).
// No hace dup2/exec de shell, para no contaminar el sensor de reverse-shell
// y permitir validar el sensor cryptominer de forma aislada.
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    printf("[*] Cryptominer PoC (nombre de proceso: xmrig)\n");
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(3333); // puerto stratum XMR
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    printf("[*] Conectando a pool stratum 127.0.0.1:3333...\n");
    connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    close(fd);
    printf("[+] PoC completado\n");
    return 0;
}
