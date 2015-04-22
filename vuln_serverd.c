/* vuln_serverd.c - Basic web server vulnerable to stack-based buffer overflow.
 *
 * Useful for demonstrating binary exploitation and remote code execution.
 *
 * Based on tinyhttpd by J. David Blackstone and tinyweb.c by Jon Erickson.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define WEBROOT "./"
#define PORT 6789


void accept_request(int client);
void handle_conn(int sockfd, struct sockaddr_in *client_addr_ptr);
int recv_line(int sock, char *buf, int size);

int main(void) {
	struct sockaddr_in host_addr, client_addr;
	socklen_t sin_size;
	int recv_length = 1, yes = 1;
	int sockfd, new_sockfd;
	
	/* Set up the socket, PF_INET -> IPv4 and SOCK_STREAM -> TCP. */
	sockfd = socket(PF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
		exit(1); // fatal
	}

	/* Set socket options, SO_REUSEADDR -> allows reusing the port for binding. */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
		perror("setsockopt");
		exit(1); // fatal
	}

	/* Set the host structure for use in the bind call. */
	memset(&host_addr, '\0', sizeof(struct sockaddr_in)); // zero out struct
	host_addr.sin_family = AF_INET; // host byte order
	host_addr.sin_port = htons(PORT); // short, network byte order
	host_addr.sin_addr.s_addr = 0; // automatically fill ip

	/* Bind the socket to the current ip address on the selected port. */
	if (bind(sockfd, (struct sockaddr *)&host_addr, sizeof(struct sockaddr)) < 0) {
		perror("bind");
		exit(1); // fatal
	}

	/* Tell the socket to listen for incoming connections. */
	if (listen(sockfd, 5) == -1) {
		perror("listen");
		exit(1); // fatal
	}

	printf("HTTP web server accepting requests on port %d\n", PORT);

	/* Accept incoming connections. */
	while (1) {
		sin_size = sizeof(struct sockaddr_in);
		new_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &sin_size);

		if (new_sockfd < 0) {
			perror("accepting connection");
			exit(1);
		}

		printf("+ server: got connection from %s:%d\n",
			inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

		handle_conn(new_sockfd, &client_addr);		
	}

	return 0;
}

void handle_conn(int sockfd, struct sockaddr_in *client_addr_ptr) {
	unsigned char *ptr, resource[255], request[1024];
	int fd, length;

	length = recv_line(sockfd, request, sizeof(request));

	ptr = strstr(request, " HTTP/"); // look for valid HTTP request
	if (ptr == NULL) {
		printf("\tOther, not HTTP.\n");
	} else {
		*ptr = '\0'; // terminate buffer at url
		ptr = NULL; // used to flag for an invalid request

		if (strncmp(request, "GET", 3) == 0)
			ptr = request+4; // ptr -> url
		if (strncmp(request, "HEAD", 4) == 0)
			ptr = request+5; // ptr -> url

		if (ptr == NULL) {
			printf("\tUnknown request.\n");
		} else {
			if (ptr[strlen(ptr) - 1] == '/') // url ends with '/'?
				strcat(ptr, "index.html"); // add 'index.html' to it
			strcpy(resource, WEBROOT); // begin resource with web root path
			strcat(resource, ptr); // join it with the resource path

			fd = open(resource, O_RDONLY, 0); // try opening file
			printf("\tOpening \'%s\'.\n", resource);
			if (fd == -1) {
				printf("\t404 File not found.\n");

				send_string(sockfd, "HTTP/1.0 404 NOT FOUND\r\n");
				send_string(sockfd, "Server: vuln_serverd\r\n\r\n");
				send_string(sockfd, "<html><head><title>404 Not Found</title></head>");
				send_string(sockfd, "<body><h1>URL not found</h1></body></html>\r\n");
			} else {
				printf("\t200 OK\n");

				send_string(sockfd, "HTTP/1.0 200 OK\r\n");
				send_string(sockfd, "Server: vuln_serverd\r\n\r\n");

				if (ptr == request + 4) {
					if ((length = get_file_size(fd)) == -1) {
						perror("getting resource file size");
						exit(1); // fatal
					}
					if ((ptr = (unsigned char *) malloc(length)) == NULL) {
						perror("allocating memory for reading resource");
						exit(1); // fatal
					}

					read(fd, ptr, length); // read file into memory

					send(sockfd, ptr, length, 0); // send to socket

					free(ptr); // free file memory
				}

				close(fd); // close file
			}
		}
	}

	shutdown(sockfd, SHUT_RDWR); // close the socket gracefully
}

/* Reads a line from a socket and terminates it. */
int recv_line(int sock, char *buf, int size) {
	int n, i = 0;
	char c = '\0';

	while ((i < size - 1) && (c != '\n')) {
		n = recv(sock, &c, 1, 0);

		if (n > 0) {
			if (c == '\r') {
				n = recv(sock, &c, 1, MSG_PEEK);

				if ((n > 0) && (c == '\n'))
					recv(sock, &c, 1, 0);
				else
					c = '\n';
			}
			buf[i] = c;
			i++;
		} else {
			c = '\n';
		}
		buf[i] = '\0';
	}

	return i;
}

/* Sends a buffer (string) over a socket to a client. */
int send_string(int sockfd, unsigned char *buffer) {
	int complete, next;
	next = strlen(buffer);

	while (next > 0) {
		complete = send(sockfd, buffer, next, 0);

		if (complete == -1)
			return -1; // return -1 on send error

		next -= complete;
		buffer += complete;
	}

	return 0; // return 0 on success
}

/* Returns the size of a file based on an already open file descriptor. */
int get_file_size(int fd) {
	struct stat stat_struct;

	if (fstat(fd, &stat_struct) == -1)
		return -1;

	return (int) stat_struct.st_size;
}