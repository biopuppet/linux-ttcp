#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
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
    int sockfd, len;
    char buffer[MAXLINE];
    struct sockaddr_in servaddr;
    FILE *fq;
    const char *ip = "127.0.0.1";  //从命令行获取输入的ip地址

    if (argc > 1) {
        ip = argv[1];
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TTCP)) < 0) {
        printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
        return 0;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(6666);
    if (inet_pton(AF_INET, ip, &servaddr.sin_addr) <= 0) {
        printf("inet_pton error for %s\n", ip);
        return 0;
    }

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        printf("connect error: %s(errno: %d)\n", strerror(errno), errno);
        return 0;
    }
    if ((fq = fopen("./file1", "rb")) == NULL) {
        printf("Cannot open file.\n");
        close(sockfd);
        exit(1);
    }

    bzero(buffer, sizeof(buffer));
    while (!feof(fq)) {
        len = fread(buffer, 1, sizeof(buffer), fq);
        if (len != write(sockfd, buffer, len)) {
            printf("write %d.\n", len);
            break;
        }
    }
    close(sockfd);
    fclose(fq);

    return 0;
}