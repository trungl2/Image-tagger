/* A simple client program for server.c

   To compile: gcc client.c -o client

   To run: start the server, then the client */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <math.h>

int main(int argc, char ** argv)
{
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent * server;

    char buffer[256];

    if (argc < 4)
    {
        fprintf(stderr, "usage %s hostname port\n", argv[0]);
        exit(0);
    }

    portno = atoi(argv[2]);


    /* Translate host name into peer's IP address ;
     * This is name translation service by the operating system
     */
    server = gethostbyname(argv[1]);

    if (server == NULL)
    {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }

    /* Building data structures for socket */

    bzero((char *)&serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;

    bcopy(server->h_addr_list[0], (char *)&serv_addr.sin_addr.s_addr, server->h_length);

    serv_addr.sin_port = htons(portno);

    /* Create TCP socket -- active open
    * Preliminary steps: Setup: creation of active open socket
    */

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        perror("ERROR opening socket");
        exit(0);
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("ERROR connecting");
        exit(0);
    }

    /* Do processing
    */
    
    int round = 1;

    int gamodp;
    char snum[5];
    char *gbmodp_str = argv[3];
    int gbmodp = atoi(argv[3]);
    int b = atoi(argv[4]);
    int gabmodp;
    

    while(1) {
    	
    	//send name
		bzero(buffer, 256);
		strncpy(buffer, "trungl2\n", 255);
		n = write(sockfd, buffer, strlen(buffer));
	
		if (n < 0)
		{
			perror("ERROR writing to socket");
			exit(0);
		} else {
			printf("sent name\n");
		}
		

		//puts g^bmodp into the buffer and adds a new line character
		bzero(buffer, 256);
		int gbmodp_len = strlen(gbmodp_str);
		strncpy(buffer, gbmodp_str, gbmodp_len);
		buffer[gbmodp_len] = '\n';
		
		//send g^b(modp)
		n = write(sockfd, buffer, strlen(buffer));
	
		if (n < 0)
		{
			perror("ERROR writing to socket");
			exit(0);
		} else {
			printf("sent g^b(modp)\n");
		}

		//read g^a(modp)
		bzero(buffer, 256);
		n = read(sockfd, buffer, 255);
		if (n < 0)
		{
			perror("ERROR reading from socket");
			exit(0);
		}
		gamodp = atoi(buffer);
		printf("got gamodp: %d\n", gamodp);
		
		//calculate and send g^ab(modp)
		//gabmodp = (gbmodp * gamodp) % 97;
		gabmodp = gamodp;
		for(int i=0; i<b-1; i++) {
			gabmodp = (gabmodp * gamodp) % 97;
			printf("%d  : %d\n", i, gabmodp);
		}
		
		sprintf(snum, "%d", gabmodp);
		printf("gab(modp): %s\n", snum);
		strncpy(buffer, snum , strlen(snum)); 
		buffer[strlen(snum)] = '\n';
		
		
		n = write(sockfd, buffer, strlen(buffer));
		if (n < 0)
		{
			perror("ERROR writing to socket");
			exit(0);
		} else {
			printf("g^ab(modp) sent: %s\n", buffer);
		}
		
		//read status report
		bzero(buffer, 256);
		n = read(sockfd, buffer, 255);
		if (n < 0)
		{
			perror("ERROR reading from socket");
			exit(0);
		}
		printf("%s\n", buffer);
		
		break;
		
    }

    return 0;
}
