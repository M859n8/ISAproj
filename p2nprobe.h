#include <pcap.h>
#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>    // для IP заголовків
#include <netinet/tcp.h>   // для TCP заголовків
#include <arpa/inet.h>     // для функції inet_ntoa()

#include <stdio.h>
#include <cstring>

#define PCAP_ERRBUF_SIZE 256
//#define INET_ADDRSTRLEN

//struct for input arguments
typedef struct {
    char* addr;
    int port;
    char* file_path;
    int act_timeout;
    int inact_timeout;
} Arguments;

struct flow {
    // Struktura reprezentující tok
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint32_t packets;
    uint32_t bytes;
    struct timeval start_time;
    struct timeval last_time;
};

// Hashovací tabulka pro ukládání toků
std::unordered_map<std::string, struct flow> flow_table;


char *get_host_by_name(char *hostname);
int input_parse(int argc, char *argv[], Arguments *value);