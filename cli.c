#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PORT 8888
#define MAXDATASIZE 2048

int main(int argc, char *argv[])
{
    struct sockaddr_in serveraddr;
    const char *server_ip = "127.0.0.1";  //从命令行获取输入的ip地址
    int sockfd;
    int ret = -1;

    if (argc > 1) {
        server_ip = argv[1];
    }
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TTCP);
    if (sockfd < 0) {
        printf("socket init failed! Aborting...");
        return -1;
    }
    bzero(&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(PORT);
    inet_pton(AF_INET, server_ip, &serveraddr.sin_addr);
    printf("Connecting..\n");
    ret = connect(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    printf("conn: %d\n", ret);
    printf("========= Server connected =========\n");
    char buf[MAXDATASIZE];
    memset(buf, 0, sizeof(buf));
    printf("input: ");
    while (fgets(buf, sizeof(buf), stdin) != NULL && (strcmp(buf, "quit"))) {
        send(sockfd, buf, sizeof(buf), 0);
        memset(buf, 0, sizeof(buf));
        recv(sockfd, buf, sizeof(buf), 0);
        printf("server say: ");
        fputs(buf, stdout);
        memset(buf, 0, sizeof(buf));
        printf("input: ");
    }
    printf("client will be closed, see you next time.\n");
    close(sockfd);
    return 0;
}
