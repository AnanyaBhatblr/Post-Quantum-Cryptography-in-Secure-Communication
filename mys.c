// Compile: gcc insecure_server.c -o insecure_server
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define MSG_LEN 1024

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    char buffer[MSG_LEN] = {0};

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 1);
    printf("[Server] Listening on port %d...\n", PORT);
    client_fd = accept(server_fd, NULL, NULL);
    printf("[Server] Client connected!\n");

    while (1) {
        memset(buffer, 0, MSG_LEN);
        int bytes = read(client_fd, buffer, MSG_LEN);
        if (bytes <= 0) break;
        printf("[Client]: %s\n", buffer);
    }

    close(client_fd);
    close(server_fd);
    return 0;
}

