// Compile: gcc insecure_client.c -o insecure_client
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8081
#define MSG_LEN 1024

int main() {
    int sock;
    struct sockaddr_in serv_addr;
    char msg[MSG_LEN];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    printf("[Client] Connected to server.\n");

    while (1) {
        printf("You: ");
        fgets(msg, MSG_LEN, stdin);
        msg[strcspn(msg, "\n")] = 0;
        write(sock, msg, strlen(msg));
    }

    close(sock);
    return 0;
}

