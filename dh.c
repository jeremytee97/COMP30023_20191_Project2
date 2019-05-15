/*
    Computer System - Project 2 (Password Cracker)
    Author: Jeremy Tee (856782)
    Purpose: Perform a reponse protocol based on Deffie-Hellman Key exchange with the server, 
             Note: value of b is the first byte of (openssl sha256 dh.c)
             Once both client and server have the same secret code, pwd6sha256 is available to download
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

#define G  15
#define P  97
#define PORT 7800
#define ADDRESS "172.26.37.44"

void calculateAndWrite(int b, unsigned char* buffer);
int compute(int g, int a, int p);

int main(int argc, char ** argv)
{
    //response buffer
    unsigned char buffer[256];

    //encrypt the dh.c
    const char* cmndStr = "openssl sha256 dh.c";
    FILE* pipe = popen(cmndStr, "r");

    //read in the first 32 byte of the sha256 of dh.c
    if(pipe != NULL){
        int read = 0;
        fread(buffer, 32, 1, pipe);
    }

    //locate the start of the hexa value for sha256 of dh.c
    char* startPtr = strstr(buffer, "= ");
    if(startPtr != NULL){
        //shift pointer 2 position ahead
        startPtr += 2;
    }

    //store the two characters of the hexa into a string
    char hexString[3] = {startPtr[0], startPtr[1], '\0'};

    //convert 1st byte of hex string into int
    int b = (int)strtol(hexString, NULL, 16);

    //handles all calculation and exchanging with the server
    calculateAndWrite(b, buffer); 
    return 0;
}


void calculateAndWrite(int b,  unsigned char* buffer){
    int sockfd, n, portno;
    struct sockaddr_in serv_addr;
    struct hostent * server;

    portno = PORT;

    /* Translate host name into peer's IP address ;
     * This is name translation service by the operating system
     */
    server = gethostbyname(ADDRESS);

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

    bzero(buffer, 256);

    //copy my username
    strcpy(buffer, "teej1\n");

    //caluclate gbmodp
    int gbmodp = compute(G, b, P);

    //print for checking
    //printf("B = %d\n", b);

    char str[10];
    sprintf(str, "%d", gbmodp);
    strcat(buffer, str);
    strcat(buffer, "\n");

    //write username and gbmodp to server
    n = write(sockfd, buffer, strlen(buffer));

    if (n < 0)
    {
        perror("ERROR writing to socket");
        exit(0);
    }

    printf("Send username and gbmodp =\n%s", buffer);


    bzero(buffer, 256);

    //read gamodp from server
    n = read(sockfd, buffer, 255);

    if (n < 0)
    {
        perror("ERROR reading from socket");
        exit(0);
    }
    printf("g^a mod p from server = %s\n", buffer);

    //convert it to int
    int gamodp = (int)strtol(buffer, NULL, 10);

    //compute secret key
    int secret = compute(gamodp, b, P);
    bzero(buffer, 256);
    
    char secretkey[20] = {0};
    sprintf(secretkey, "%d", secret);
    strcpy(buffer, secretkey);
    strcat(buffer, "\n");

    printf("Secret buffer send = %s\n", buffer);

    //write secret key back to server
    //printf("buffer length = %ld", strlen(buffer));
    n = write(sockfd, buffer, strlen(buffer));

    if (n < 0)
    {
        perror("ERROR writing to socket");
        exit(0);
    }

    bzero(buffer, 256);

    //read response from server (SUCCESS OR FAILURE)
    n = read(sockfd, buffer, 255);

    if (n < 0)
    {
        perror("ERROR reading from socket");
        exit(0);
    }

    printf("REPLY: %s\n", buffer);
}

// Function to compute g^a mod p
//source from https://www.techiedelight.com/c-program-demonstrate-diffie-hellman-algorithm/
int compute(int g, int a, int p)
{
	int r;
	int y = 1;

	while (a > 0)
	{
		r = a % 2;

		// fast exponention 
		if (r == 1)
			y = (y*g) % p;
		g = g*g % p;

		a = a / 2;
	}

	return y;
}