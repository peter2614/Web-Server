#ifndef HTTPDSERVER_HPP
#define HTTPDSERVER_HPP

#include "inih/INIReader.h"
#include "logger.hpp"
#include <regex> 

using namespace std;

class HttpdServer {
public:
	HttpdServer(INIReader& t_config);

	void launch();
	int handleConnection(int new_fd);
	int processRequest(int new_fd, string request);
	int processRequestLine(std::string &path, std::string requestLine, unsigned int lineCounter);
 	void sendResponse(int new_fd, std::string path, bool connectionClose);
	int sendall(int new_fd, std::string sendString, int len);

protected:
	INIReader& config;
	string port;
	string doc_root;
	string mime_types;
	map<string,string> mimeTypesMap;
};

#endif // HTTPDSERVER_HPP
