//Author : Maryna Kucher , xkuche01

#ifndef P2NPROBE_H
#define P2NPROBE_H

#include <pcap.h>
#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unordered_map>

#include <stdio.h>
#include <cstring> //memset
#include <sys/socket.h> //socket, sendto
#include <unistd.h> //close
#include <vector>
#include <sys/time.h>

#define PCAP_ERRBUF_SIZE 256

//struct for input arguments
typedef struct {
    char* addr;
    int port;
    char* file_path;
    int act_timeout;
    int inact_timeout;

    int sequence_flow ;
} Arguments;
//struct for flow
struct Flow {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t packet_count;
    uint32_t byte_count;
    struct timeval first_packet_time;
    struct timeval last_packet_time;
    uint8_t tcp_flags;
    uint8_t tos; //type of Service

    uint8_t flow_num;


};


extern std::unordered_map<std::string, struct Flow> flow_table; //hash table for flows
extern Arguments input_val;
extern std::vector<Flow> flows_to_send;
extern struct timeval boot_time; //start of the program time

//function that calculate ip address by name
char *get_host_by_name(char *hostname);
//parse input arguments
int input_parse(int argc, char *argv[], Arguments *value);
//function for packet processing
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pcap_head, const u_char *packet);
//function that creates hash key from src/dst ip, src/dst port
std::string create_hash_key(const std::string& src_ip, const std::string& dst_ip, uint16_t src_port, uint16_t dst_port);
//function that creates flow
Flow create_flow(const std::string& src_ip, const std::string& dst_ip, int src_port,
                 int dst_port, int bytes,  struct timeval time, uint8_t tos, uint8_t tcp_flags);
//function that checks timers expiration
void check_timers(struct timeval current_time);
//function that exports flows
void export_flows();
//function that exports remaining flows after processing all packets from a file
void send_remains();

//sendUDP.cpp
uint32_t get_time_diff(struct timeval start_time, struct timeval end_time);
void send_to_collector(const std::string& collector_ip, int collector_port, const std::vector<Flow>& flows);
void prepare_header(int amount_of_flows, char* buffer, int flow_seq);
void prepare_body(const Flow& flow, char *buffer);
void send_to_collector(const std::string& collector_ip, int port, const std::vector<Flow>& flows);

#endif //P2NPROBE_H