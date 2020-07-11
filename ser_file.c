#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAXLINE 4096

int main(int argc, char **argv)
{
    int listenfd, connfd;
    struct sockaddr_in servaddr;
    char buff[MAXLINE];
    FILE *fp;
    int n;

    if ((listenfd = socket(AF_INET, SOCK_STREAM, IPPORTO_TTCP)) < 0) {
        printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
        return 0;
    }
    printf("----init socket----\n");

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(6666);
    //设置端口可重用
    int contain;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &contain, sizeof(int));

    if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        printf("bind socket error: %s(errno: %d)\n", strerror(errno), errno);
        return 0;
    }
    printf("----bind sucess----\n");

    if (listen(listenfd, 10) < 0) {
        printf("listen socket error: %s(errno: %d)\n", strerror(errno), errno);
        return 0;
    }
    if ((fp = fopen("./file2", "ab")) == NULL) {
        printf("File.\n");
        close(listenfd);
        exit(1);
    }

    printf("======waiting for client's request======\n");
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t size = sizeof(client_addr);
        if ((connfd = accept(listenfd, (struct sockaddr *)&client_addr,
                             &size)) < 0) {
            printf("accept socket error: %s(errno: %d)", strerror(errno),
                   errno);
            continue;
        }
        while (1) {
            n = read(connfd, buff, MAXLINE);
            if (n == 0)
                break;
            fwrite(buff, 1, n, fp);
        }
        buff[n] = '\0';
        printf("recv msg from client: %s\n", buff);
        close(connfd);
        fclose(fp);
    }
    close(listenfd);
    return 0;
}