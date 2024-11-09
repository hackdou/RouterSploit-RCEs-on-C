// "ZTE F460, ZTE F660

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 80 // Порт для HTTP
#define BUFFER_SIZE 1024

void scan_target(const char *target_ip) {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];

    // Создание сокета
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return;
    }

    // Установка адреса и порта
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    // Попытка подключения
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("Connection to %s failed\n", target_ip);
    } else {
        printf("Connected to %s\n", target_ip);
        // Здесь можно добавить код для выполнения атаки или сканирования
        // Например, отправка HTTP-запроса
        const char *http_request = "GET / HTTP/1.1\r\nHost: ";
        send(sock, http_request, strlen(http_request), 0);
        send(sock, target_ip, strlen(target_ip), 0);
        send(sock, "\r\n\r\n", 4, 0);

        // Чтение ответа
        int bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0'; // Завершение строки
            printf("Response:\n%s\n", buffer);
        }
    }

    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <target_ip>\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    scan_target(target_ip);

    return 0;
}
