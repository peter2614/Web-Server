#include <sysexits.h>

#include "logger.hpp"
#include "HttpdServer.hpp"

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h> // to prevent crashing on many pipelined requests

#include <limits.h> // for realpath() parsing
#include <iostream> // for cout and printing

// for blocking/unblocking
#include <sys/time.h>
#include <unistd.h>

// for threading
#include <thread>

// for string parsing
#include <sstream>
#include <istream>
#include <cstdlib>
#include <regex>
#include <fstream>
#include <algorithm>

// for sending files back to client
//#include <sys/types.h>
//#include <sys/stat.h>
#include <sys/sendfile.h>

// === for error logging ===
#include <stdio.h>
#include <stdlib.h>
#define BACKLOG 20
#define BUFFERSIZE 1000 // max number of bytes we can get at once in recv
#define TIMEOUT 5


void DieWithSystemMessage(const char *msg) {
  perror(msg);
  exit(1);
} 


HttpdServer::HttpdServer(INIReader& t_config) : config(t_config) {
	auto log = logger();

	string pstr = config.Get("httpd", "port", "");
	if (pstr == "") {
		log->error("port was not in the config file");
		exit(EX_CONFIG);
	}
	port = pstr;

	string dr = config.Get("httpd", "doc_root", "");
	if (dr == "") {
		log->error("doc_root was not in the config file");
		exit(EX_CONFIG);
	}
	doc_root = dr;

	string mime = config.Get("httpd", "mime_types", "");
	if (dr == "") {
		log->error("mime_types was not in the config file");
		exit(EX_CONFIG);
	}
	mime_types = mime;
}


void HttpdServer::launch() {
	auto log = logger();

	log->info("Launching web server");
	log->info("Port: {}", port);
	log->info("doc_root: {}", doc_root);
	std::ifstream file(mime_types);
	std::string line;
	//std::vector<std::string> splitString;
	while(std::getline(file, line)) {
		//boost::split(splitString, line, boost::is_any_of(" "));
		//mimeTypesMap[splitString[0]]=splitString[1];
        int firstSpace = line.find(" ");
        string key = line.substr(0,firstSpace);
        line.erase(0, firstSpace + 1); // line is now just the value
        mimeTypesMap[key] = line;
	}

	signal(SIGPIPE, SIG_IGN); // call to prevent pipeline breaking and silent crash

	// get the server info for the host and port
	int status;
	struct addrinfo hints; 	   // addr info has fields ai_flags, ai_family, ai_socktype, ai_protocol, ai_addrlen, *ai_addr, *ai_canonname, *ai_next
	struct addrinfo *servinfo; // pointer to linked list of results

	memset(&hints, 0, sizeof hints); 	// make sure struct is empty
	hints.ai_family = AF_UNSPEC;		// don't care if IPv4 or IPv6, use AF_INET or AF_INET6 to specify
	hints.ai_socktype = SOCK_STREAM;	// tcp
	hints.ai_flags = AI_PASSIVE; 		// fill in IP for me, tells getaddrinfo() to assign the address of my local host to the socket structures rather than hardcoding
	if ((status = getaddrinfo(NULL, port.c_str(), &hints, &servinfo)) != 0) {
		log->info("FAILED TO GET ADDR INFO: {}", gai_strerror(status));
		DieWithSystemMessage("Couldn't connect to port. :(");			  // kill server
	}
	
	// loop through the linked list until we can successfully connect
	int sock_fd;
	struct addrinfo *p;
	int yes = 1;
	for (p = servinfo; p != NULL; p = p->ai_next) {

		// === for printing out the ip version and ip, can remove this entire block ===
        void *addr;
		string ipver;
		char ipstr[INET6_ADDRSTRLEN];
        // get the pointer to the address itself,
        // different fields in IPv4 and IPv6:
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }
        // convert the IP to a string and print it:
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        log-> info("  {}: {}", ipver, ipstr);
		// ============================================================================

    	// create the socket
		if ((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			log->info("FAILED TO CREATE SOCKET");
			continue;
		}

		// free socket if in use
		if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) == -1) {
			log->info("FAILED TO FREE SOCKET");
			continue;
		} 

		// connect to the socket
		if (bind(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
			log->info("FAILED TO BIND TO SOCKET");
			close(sock_fd);
			continue;
		}
		break;
	}

	log->info("Connected to port", port);
	// free up the linked list of results we got from getaddrinfo
	freeaddrinfo(servinfo);

	// listen for incoming connections
	if (listen(sock_fd, BACKLOG) == -1) { // hardcoded the backlog to 5, might want to move this
			log->info("FAILED TO LISTEN");
	}

	// accept incoming connections and obtain their socket file descriptor
	// will want to spawn a new thread each time
	struct sockaddr_storage incoming_addr;
	socklen_t addr_size;

	// ================= MAIN ACCEPT LOOP =================
	// fcntl(sockfd, F_SETFL, O_NONBLOCK) unblocks a socket, but don't use it. 
	while(1) {
		// ======== ACCEPT ========
		int new_fd;
		addr_size = sizeof incoming_addr;
		if ((new_fd = accept(sock_fd, (struct sockaddr *) &incoming_addr, &addr_size)) == -1) {
			log->info("FAILED TO ACCEPT INCOMING CONNECTION");	
			continue;
		}

		// ready to communicate on socket descriptor "new_fd"
		// create a new thread to handle its own connection
		std::thread newThread(&HttpdServer::handleConnection, this, new_fd);
		newThread.detach(); // detach thread, allows execution to continue indepedently
	}
}


// handles a new connection from a client
int HttpdServer::handleConnection(int new_fd) {
	auto log = logger();		// logger
	struct timeval timeout;		// timeout struct
	timeout.tv_sec = TIMEOUT;	// seconds
	timeout.tv_usec = 0;		// microseconds

	log->info(" ==== NEW CONNECTION {} ==== ", new_fd);

	// set timeouts on recv and send for new socket
	if (setsockopt(new_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) == -1) {
		log->info("TIMEOUT");
	}
	if (setsockopt(new_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) == -1) {
		log->info("TIMEOUT");
	}

	// ======== RECV ========
	ssize_t numBytes;
	auto requestEnd = std::string::npos;
	unsigned int alreadySearched = 0;
	char buffer[BUFFERSIZE] = ""; // I/O buffer
	std::string requestBuffer = ""; // dynamic buffer
	do {
		memset(&buffer[0], 0, sizeof(buffer)); // clear buffer
		numBytes = recv(new_fd, buffer, BUFFERSIZE - 1, 0); // receive

		if (numBytes < 0)  {
			// receive failed, possibly due to timeout
			// if there's a partial request in the buffer, send a 400, else just close the connection
			if (requestBuffer.length() > 0) {
				log->info("TIMEOUT"); 
				std::string response400 = "HTTP/1.1 400 CLIENT ERROR\r\nServer: APH-Server 1.0\r\nConnection: close\r\n\r\n";
				if (sendall(new_fd, response400, response400.length()) == -1) {
					log->info("FAILED TO SEND 400");
				}
			}
			close(new_fd);
			return 0;
		}
		else if (numBytes == 0) {
			break;
		} 
		else {	
			// frame incoming bytes by reading bytes from the socket into dynamically resizing buffer (string)
			requestBuffer.append(buffer); 

			// while we have complete requests in the string buffer
			while ( (requestEnd = requestBuffer.find("\r\n\r\n", alreadySearched)) != std::string::npos) {
				log->info(" == COMPLETE REQUEST FOUND == ");
				// once we've found a complete request, remove it from our dynamic buffer and process it
				if (processRequest(new_fd, requestBuffer.substr(0, requestEnd + 4)) == -1) {
					return 0;
				}
				requestBuffer.erase(0, requestEnd + 4);	
				alreadySearched = 0; // after removing a request, should start looking for \r\n\r\n from the beginning
			}

			// we've searched for \r\n\r\n up to the end of requestBuffer
			if (requestBuffer.length() > 3) {
				alreadySearched = requestBuffer.length()-4;
			}
		}

	} while (numBytes > 0);	// if we still have bytes to read from request

	close(new_fd);

	return 0;
}


int HttpdServer::processRequest(int new_fd, string request) {
	auto log = logger();	// logger
	
	std::istringstream requestStream(request);
	std::vector<std::string> requestParts;
	std::string readline;
	while(std::getline(requestStream, readline)) {
		requestParts.push_back(readline);
		log->info(readline);
	}

	log->info(" == END OF REQUEST == ");

	// start processing the request line by line
	std::string path;	// this variable will get filled with the requested file path after processRequestLine is done
	unsigned int lineCounter = 0;
	bool closeConnection = false; 	
	bool hasHostValue = false;
	// last line in a request should just be \r after removing a \n
	if (requestParts.back() == "\r") {
		requestParts.pop_back(); // remove it the \r from the end
		for(std::vector<std::string>::iterator it = requestParts.begin(); it != requestParts.end(); it++) {
			//log->info("PROCESS LINE: {}", *it);
			int result = processRequestLine(path, *it, lineCounter);
			if (result == 400) {
				log->info("		Malformed Request");
				std::string response400 = "HTTP/1.1 400 CLIENT ERROR\r\nServer: APH-Server 1.0\r\nConnection: close\r\n\r\n";
				if (sendall(new_fd, response400, response400.length()) == -1) {
					log->info("FAILED TO SEND 400");
				}
				close(new_fd);
				return -1;
			} else if (result == 1) {
				closeConnection = true;
			} else if (result == 2) {
				hasHostValue = true;
			}
			lineCounter++;
		}
	}

	if (hasHostValue == false) {
		log->info("		Missing Host: <value> Request header");
		std::string response400 = "HTTP/1.1 400 CLIENT ERROR\r\nServer: APH-Server 1.0\r\nConnection: close\r\n\r\n";
		if (sendall(new_fd, response400, response400.length()) == -1) {
			log->info("FAILED TO SEND 400");
		}
		close(new_fd);
		return -1;
	}

	// ======== SEND ========
	sendResponse(new_fd, path, closeConnection);

	// close connection is Connection: close header was found
	if (closeConnection) {
		log->info("CONNECTION CLOSED");
		close(new_fd);
		return -1;
	}

	return 0;
}


int HttpdServer::processRequestLine(std::string &path, std::string requestLine, unsigned int lineCounter) {
	auto log = logger();

	// first line
	if (lineCounter == 0) {
       
        //find get
        int firstSpace = requestLine.find(" ");
        string get = requestLine.substr(0, firstSpace);
        std::transform(get.begin(), get.end(), get.begin(), ::tolower);
        if(get != "get"){
			log->info("		GET malformed or missing");
            return 400;
        }
        requestLine.erase(0, firstSpace + 1); // remove everything up until the path
        int secondSpace = requestLine.find(" ");
        path = doc_root;
        string requestPath = requestLine.substr(0, secondSpace);
		if (requestPath[0] != '/') {
			log->info("		Path does not begin with '/'");
			return 400;
		}
        path.append(requestPath);
        if(requestPath == "/"){
            path.append("index.html");
        }
        requestLine.erase(0, secondSpace + 1);
        std::transform(requestLine.begin(), requestLine.end(), requestLine.begin(), ::tolower);
        if(requestLine != "http/1.1\r"){
			log->info("		HTTP/1.1 malformed or missing");
            return 400;
        }
	} 
	// if the line is a key-value line: key: value
	else {

		auto colonSpace = std::string::npos;
        if( (colonSpace = requestLine.find(": ")) == std::string::npos){
			log->info("		Missing <colon><space> in key-value");
			return 400;
		}
        string key = requestLine.substr(0,colonSpace);
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        requestLine.erase(0, colonSpace + 1); //erase : and space
        if(key == "host"){
            return 2;
        }
        if(key == "connection"){
            std::transform(requestLine.begin(), requestLine.end(), requestLine.begin(), ::tolower);
            if(requestLine.find("close") != string::npos){
                return 1;
            }
        }
	}

	return -1;	
}


void HttpdServer::sendResponse(int new_fd, std::string path, bool closeConnection) {
	auto log = logger();

	// 404 response: not found
	std::string response404 = "HTTP/1.1 404 NOT FOUND\r\nServer: APH-Server 1.0\r\n";
	if (closeConnection) {
		response404.append("Connection: close\r\n");
	}
	response404.append("\r\n");

	// 403 response: permission denied
	std::string response403 = "HTTP/1.1 403 PERMISSION DENIED\r\nServer: APH-Server 1.0\r\n";
	if (closeConnection) {
		response403.append("Connection: close\r\n");
	}
	response403.append("\r\n");

	// convert relative path to absolute path
	char absolute_path[PATH_MAX + 1];
	char *result = realpath(path.c_str(), absolute_path);	// get absolute path to requested file
	if (result) {
		log->info("		Path leads to {}", absolute_path);
	} else {
		// couldn't find the path/file, send 404
		log->info("		Couldn't find {}", absolute_path);
		if (sendall(new_fd, response404, response404.length()) == -1) {
			log->info("FAILED TO SEND 404");
		}
		return;
	}

	// check if absolute document root path is a prefix of the absolute path of requested file
	char absolute_doc_root[PATH_MAX + 1];
	realpath(doc_root.c_str(), absolute_doc_root); // get absolute path to document root
	string abs_doc = absolute_doc_root; // make string so we can use it with std::equal
	string abs_path = absolute_path;
	if(!std::equal(abs_doc.begin(), abs_doc.end(), abs_path.begin())){
		log->info("		Path escapes document root");
		if (sendall(new_fd, response404, response404.length()) == -1) {
			log->info("FAILED TO SEND 404");
		}
		return;
	}

	// if couldn't open file, send 404
	int file_fd;
	if((file_fd = open(abs_path.c_str(), O_RDONLY)) < 0) {
		log->info("		ERROR IN OPENING FILE, FILE DOESN'T EXIST?");
		if (sendall(new_fd, response404, response404.length()) == -1) {
			log->info("FAILED TO SEND 404");
		}
		return;
	}

	// check if file is world readable, if not send 403
	struct stat file_stats;
	stat(abs_path.c_str(), &file_stats); 
	if ((file_stats.st_mode & S_IROTH) == 4) {
		log->info("		File is world readable!");
	} else {
		log->info("		File is not set to world readable.");
		if (sendall(new_fd, response403, response403.length()) == -1) {
			log->info("FAILED TO SEND 403");
		}
		return;
	}

	// if we haven't failed up to this point, then we should be good to send response code 200
	log->info("		Good Request");
	std::string response200 = "HTTP/1.1 200 OK\r\nServer: APH-Server 1.0\r\n";
	// last modified
	time_t time_stat = file_stats.st_mtime;
	struct tm localt;
	localtime_r(&time_stat, &localt); // convert to local time
	char timeBuffer[256];
	strftime(timeBuffer, sizeof(timeBuffer), "%a, %d %b %y %T %z", &localt); // format time
	response200.append("Last-Modified: ");
	response200.append(timeBuffer); // Last-Modified
	response200.append("\r\n");

	// content length
	response200.append("Content-Length: ");
	response200.append(std::to_string(file_stats.st_size)); // content length
	response200.append("\r\n");

	// content type
	//std::vector<std::string> splitString;
	//boost::split(splitString, abs_path, boost::is_any_of("."));
    int fristdot = abs_path.find(".");
    abs_path.erase(0, fristdot + 1);
	string fileType = ".";
	//fileType.append(splitString.back()); // get file extension off end of request path
    fileType.append(abs_path);
	string contentType;
	if (mimeTypesMap.find(fileType) == mimeTypesMap.end()) {
		// didn't find in map, set to default
		contentType = "application/octet-stream";
	} else {
		// found in map
		contentType = mimeTypesMap[fileType];
	}

	response200.append("Content-Type: ");
	response200.append(contentType); // content type
	response200.append("\r\n");

	if (closeConnection) {
		response200.append("Connection: close\r\n");
	}
	response200.append("\r\n"); // end of response 

	// Send out response, TODO: put send in a loop later to make sure everything sends
	
	if (sendall(new_fd, response200.c_str(), response200.length()) == -1) {
		log->info("FAILED TO SEND 200");
	}
	
	// send the file that was requested
	sendfile(new_fd, file_fd, 0, file_stats.st_size);
	
	log->info("SENT RESPONSE 200");
}


int HttpdServer::sendall(int new_fd, std::string sendString, int len) {
	char * sendStringPointer = new char[sendString.length()];
	std::copy(sendString.begin(), sendString.end(), sendStringPointer);
	int total = 0;          // how many bytes we've sent
	int bytesleft = len;   // how many we have left to send
	int n;

	while(total < len) {
		n = send(new_fd, sendStringPointer+total, bytesleft, 0);
		if (n == -1) { break; }
		total += n;
		bytesleft -= n;
	}

	delete[] sendStringPointer; //deallocate temporary char buffer
	return n == 1 ? -1 : 0;   // return -1 on failure, 0 on success
}
