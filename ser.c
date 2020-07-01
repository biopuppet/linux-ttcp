#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define PORT 8888
#define MAXDATASIZE 2048
#define BACKLOG 10
int main(int argc, char *argv[])
{
    int sockfd;
    struct sockaddr_in serveraddr, peeraddr;
    socklen_t peer_len = sizeof(peeraddr);
    int ret = -1;
    int n;
    int prot = IPPROTO_TTCP;
    if (argc > 1) {
	prot = IPPROTO_TCP;
    }
    sockfd = socket(AF_INET, SOCK_STREAM, prot);
    printf("IPPROTO: %d\nsockfd=%d\n", prot, sockfd);
    if (sockfd < 0) {
        printf("socket init failed! Aborting...\n");
        return -1;
    }
    bzero((char *)&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = INADDR_ANY;
    serveraddr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
	perror("Error on binding\n");
	return -1;
    }
    ret = listen(sockfd, BACKLOG);
    if (ret) {
        perror("Error on listening.\n");
	return -1;
    }
    printf("======bind success, listening======\n");

    int connfd;
    while (1) {
        connfd = accept(sockfd, (struct sockaddr *)&peeraddr, &peer_len);
        printf("\n========== client connected ==========\n");
        printf("IP = %d\n", ntohs(peeraddr.sin_port));
	
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
        close(sockfd);
        return 0;
    }
}
