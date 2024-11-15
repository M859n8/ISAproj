#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

void send_to_collector(const std::string& collector_ip, int collector_port, const char* data, size_t data_size);
