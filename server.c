#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define PORT 8888
#define BACKLOG 10
#define MAXDATASIZE 2048
int main(int argc, char *argv[])
{
    struct sockaddr_in serveraddr, peeraddr;
    socklen_t peer_len = sizeof(peeraddr);
    int listenfd;
    int ret = -1;

    listenfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    printf("listenfd=%d\n", listenfd);
    if (listenfd < 0) {
        printf("socket init failed! Aborting...");
        return -1;
    }
    bzero(&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(PORT);  //把端口转化为网络字节序，即大端模式
    serveraddr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(listenfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    if (ret < 0) {
        printf("bind failed! Aborting...");
        return -1;
    }
    ret = listen(listenfd, BACKLOG);
    if (ret < 0) {
        printf("listen failed! Aborting...");
        return -1;
    }
    printf("======bind success, waiting for client's request======\n");

    int connfd;
    while (1) {
        connfd = accept(listenfd, (struct sockaddr *)&peeraddr, &peer_len);
        printf("\n========== client connected ==========\n");
        printf("IP = %s:%d\n", inet_ntoa(peeraddr.sin_addr),
               ntohs(peeraddr.sin_port));
        char buf[MAXDATASIZE];
        while (1) {
            memset(buf, '\0', MAXDATASIZE / sizeof(char));
            int recv_length = recv(connfd, buf, MAXDATASIZE / sizeof(char), 0);
            if (recv_length == 0) {
                printf("client has closed!\n");
                break;
            }
            printf("client says: ");
            fputs(buf, stdout);
            memset(buf, '\0', MAXDATASIZE / sizeof(char));
            printf("input: ");
            fgets(buf, sizeof(buf), stdin);
            send(connfd, buf, recv_length, 0);
        }
        close(connfd);
        close(listenfd);
        return 0;
    }
}