#include <iostream>
#include <cstring> // memset
#include <sys/socket.h> // socket, sendto
#include <netinet/in.h> // sockaddr_in
#include <arpa/inet.h> // inet_pton
#include <unistd.h> // close
#include <vector>


void send_to_collector(const std::string& collector_ip, int collector_port, const std::vector<Flow>& flows);
