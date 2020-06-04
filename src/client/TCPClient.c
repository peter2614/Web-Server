// client from class
#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include<algorithm>
#include <unistd.h>

#include "Practical.h"

using namespace std;


/* Given a sockaddr struct, return it as a string (from D&C book) */
char * get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen);

/* for reading in the test file */
class FileNotFoundException : public exception { };
string readFile(string filename);

/* a.out host port input_file */
int main(int argc, char *argv[]) {
	if (argc != 4) {
		DieWithUserMessage("Parameter(s)", "request");
	}

	/* creating the socket */
	const char * host = argv[1];
	const char * port = argv[2];
	const char * request = argv[3];

	struct addrinfo hints, *servinfo, *p;
	int rv, sock;

	fprintf(stderr, "Connecting to %s:%s\n", host, port);

	memset(&hints, 0, sizeof(hints)); // prepare/clear out the addrinfo data structure
	hints.ai_family = AF_UNSPEC;     // either IPv6 or IPV4 OK
	hints.ai_socktype = SOCK_STREAM; // use tcp

	// dns to address lookup, servinfo gets a linked list of potential candidates we can connect to
	if ((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
		DieWithUserMessage("getaddrinfo", gai_strerror(rv));
	}

	// loop through the results and try to connect to each of them until we succeed
	for (p = servinfo; p != NULL; p = p->ai_next) {
		// create the socket
		if ((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("socket");
			continue;
		}
		// connect to the socket
		if (connect(sock, p->ai_addr, p->ai_addrlen) == -1) {
			perror("connect");
			close(sock);
			continue;
		}
		break;
	}

	if (p == NULL) {
		DieWithUserMessage("socket", "Didn't find an address to connect to");
	}
	freeaddrinfo(servinfo);

	char addrbuf[128];
	get_ip_str(p->ai_addr, addrbuf, 128);
	fprintf(stderr, "Connected to %s!\r\n", addrbuf);

	std::ifstream ifs(request);
	std::string content( (std::istreambuf_iterator<char>(ifs) ),
						(std::istreambuf_iterator<char>()    ) );

	if (!ifs.is_open()) {
		DieWithUserMessage("Bad request", "Couldn't open request.");
	}

	fprintf(stderr, "============================== SENDING ==============================");
	fprintf(stderr, "\n%s", content.c_str());
  	if (send(sock, content.c_str(), content.length() , 0) == -1) {
		DieWithSystemMessage("FAILED TO SEND");
	}

  	// Receive the response
	ssize_t numBytes;
	std::string responseBuffer;
	
	auto responseEnd = std::string::npos;
	unsigned int alreadySearched = 0;
	int contentLength;
	bool foundCompleteResponse = false;
	int responseNum = 0;
	char buffer[BUFSIZE] = ""; // I/O buffer
	do {
		memset(&buffer[0], 0, sizeof(buffer));
		numBytes = recv(sock, buffer, BUFSIZE - 1, 0); // receive

		if (numBytes < 0)
			DieWithSystemMessage("recv() failed");
		else if (numBytes == 0)
			break;
		else {
			
			// add the receive buffer to the string buffer
			responseBuffer.append(buffer); 
			
			// while there are complete processes in the string buffer
			while ((responseEnd = responseBuffer.find("\r\n\r\n", alreadySearched)) != std::string::npos && !foundCompleteResponse) {
				if(!foundCompleteResponse && responseEnd != std::string::npos) {
					// handle content-length for content-body
					boost::regex reg("(content-length: [0-9]+)",  boost::regex::icase);
					boost::smatch matches;
					std::vector<std::string> result;
					if (boost::regex_search(responseBuffer, matches, reg)) {
						std::string matched = matches[1].str();
						boost::split(result, matched, boost::is_any_of(" "));
						contentLength = stoi(result[1]);
					} else {
						contentLength = 0;
					}

					// we've found \r\n\r\n and we've extracted the length of the optional body, don't need to calculate again
					foundCompleteResponse = true;
				}

				// if we've found \r\n\r\n, but haven't received the entire optional body yet, continue receiving data
				if (foundCompleteResponse && (responseBuffer.length() < (responseEnd + 4 + contentLength))) {
					break;
				}

				// we have the complete response, go ahead and process it
				if (foundCompleteResponse) {
					foundCompleteResponse = false;
					responseNum++;
					fprintf(stderr, "============== Start Response %d ==============\n", responseNum);
					fprintf(stderr, (responseBuffer.substr(0, responseEnd + contentLength + 4)).c_str());
					fprintf(stderr, "============== End Response %d ==============\n", responseNum);
					responseBuffer.erase(0, responseEnd + contentLength + 4);
					alreadySearched = 0; // just took off a complete response, should start searching for a complete response from the beginning of the string again
				}
			} // while 
			
			// if we didn't find \r\n\r\n, then \r\n\r\n must not exist from characters 0 to responseBuffer.length-4
			if (responseBuffer.length() > 3) {
				alreadySearched = responseBuffer.length()-4;
			}
			
		} // else

	} while (numBytes > 0);
	//fprintf(stderr, "\n============================== SERVER RESPONSE ==============================\n");
	//fprintf(stderr, responseBuffer.c_str());
	close(sock);	// close the socket
	fprintf(stderr, "Closed the socket!\n");
	exit(0);
}

char * get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                s, maxlen);
                break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                s, maxlen);
                break;

        default:
            strncpy(s, "Unknown AF", maxlen);
            return NULL;
    }

    return s;
}