#ifndef P2NPROBE_H
#define P2NPROBE_H

#include <pcap.h>
#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>    // для IP заголовків
#include <netinet/tcp.h>   // для TCP заголовків
#include <arpa/inet.h>     // для функції inet_ntoa()
#include <unordered_map>

#include <stdio.h>
#include <cstring> // memset
#include <sys/socket.h> // socket, sendto
#include <unistd.h> // close
#include <vector>
#include <sys/time.h>
//#include "sendUDP.h"

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

struct Flow {
    // Struktura reprezentující tok
    std::string src_ip; //char* ??
    std::string dst_ip;
    int src_port;
    int dst_port;
    int packet_count;
    int byte_count;
    struct timeval first_packet_time;
    struct timeval last_packet_time;

    bool send;

//    std::chrono::system_clock::time_point first_packet_time;
//    std::chrono::system_clock::time_point last_packet_time;
};




// Hashovací tabulka pro ukládání toků
extern std::unordered_map<std::string, struct Flow> flow_table;
extern Arguments input_val;

//test only
extern int amount ;

char *get_host_by_name(char *hostname);
int input_parse(int argc, char *argv[], Arguments *value);
Flow create_flow(const std::string& src_ip, const std::string& dst_ip, int src_port, int dst_port, int bytes,  struct timeval packet_time);
std::string create_hash_key(const std::string& src_ip, const std::string& dst_ip, uint16_t src_port, uint16_t dst_port);
void print_flows();
void check_timers(struct timeval current_time);
long time_diff_in_seconds(const struct timeval& start, const struct timeval& end);
void prepare_to_send();
void send_remains();

void send_to_collector(const std::string& collector_ip, int collector_port, const std::vector<Flow>& flows);
int prepare_flow_data(const Flow& flow, char* buffer) ;

#endif //P2NPROBE_H