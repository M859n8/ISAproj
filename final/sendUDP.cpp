//Author : Maryna Kucher , xkuche01
#include "p2nprobe.h"

const int MAX_FLOWS_PER_PACKET = 30;
const int HEADER_SIZE = 24;
const int RECORD_SIZE = 48;

//function that calculates time difference
uint32_t get_time_diff(struct timeval start_time, struct timeval end_time){
    //get time diff in microseconds
    uint32_t time_diff_us  =(end_time.tv_sec - start_time.tv_sec) * 1000000ULL +
                            (end_time.tv_usec - start_time.tv_usec);
    //convert to milliseconds
    uint32_t time_diff = time_diff_us / 1000;
    //covert into big endian
    uint32_t time_diff_endian = htonl(time_diff);
    return time_diff_endian;
}
//function that prepares header
void prepare_header(int amount_of_flows, char* buffer, int flow_seq){

    uint16_t version = htons(5);
    uint16_t count = htons(amount_of_flows);
    //get current time and compare it with boot time
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    uint32_t sys_uptime = get_time_diff(boot_time, current_time);

    uint32_t unix_secs = htonl(current_time.tv_sec);
    uint32_t unix_nsecs = htonl(current_time.tv_usec * 1000);
    uint32_t flow_sequence = htonl(flow_seq);
    uint8_t engine_type = 0;
    uint8_t engine_id = 0;
    uint16_t sampling_interval = htons(0);

    memcpy(buffer, &version, 2);
    memcpy(buffer + 2, &count, 2);
    memcpy(buffer + 4, &sys_uptime, 4);
    memcpy(buffer + 8, &unix_secs, 4);
    memcpy(buffer + 12, &unix_nsecs, 4);
    memcpy(buffer + 16, &flow_sequence, 4);
    memcpy(buffer + 20, &engine_type, 1);
    memcpy(buffer + 21, &engine_id, 1);
    memcpy(buffer + 22, &sampling_interval, 2);

}

//function that prepares body for every flow
void prepare_body(const Flow& flow, char *buffer){

    struct in_addr src, dst;
    inet_pton(AF_INET, flow.src_ip.c_str(), &src);
    inet_pton(AF_INET, flow.dst_ip.c_str(), &dst);
    memcpy(buffer, &src, 4);
    memcpy(buffer + 4, &dst, 4);

    memset(buffer + 8, 0, 4);
    memset(buffer + 12, 0, 2);
    memset(buffer + 14, 0, 2);

    uint32_t packet_count = htonl(flow.packet_count);
    uint32_t byte_count = htonl(flow.byte_count);
    memcpy(buffer + 16, &packet_count, 4);
    memcpy(buffer + 20, &byte_count, 4);


    uint32_t start_time = get_time_diff(boot_time, flow.first_packet_time);
    uint32_t end_time = get_time_diff(boot_time, flow.last_packet_time);
    memcpy(buffer + 24, &start_time, 4);
    memcpy(buffer + 28, &end_time, 4);

    uint16_t src_port = htons(flow.src_port);
    uint16_t dst_port = htons(flow.dst_port);
    memcpy(buffer + 32, &src_port, 2);
    memcpy(buffer + 34, &dst_port, 2);

    memset(buffer + 36, 0, 1);

    uint8_t tcp_flags = flow.tcp_flags;
    memcpy(buffer + 37, &tcp_flags, 1);
    uint8_t protocol = 6;  //tcp protocol
    memcpy(buffer + 38, &protocol, 1);
    uint8_t tos = flow.tos;
    memcpy(buffer + 39, &tos, 1);

    memset(buffer + 40, 0, 8); //rest is unknown
}

//function that sends packets to collector
void send_to_collector(const std::string& collector_ip, int port, const std::vector<Flow>& flows) {
    //create socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr,"Err: Socket creation failed");
        exit(1);
    }

    //setup collector addr
    struct sockaddr_in collector_addr{};
    memset(&collector_addr, 0, sizeof(collector_addr));
    collector_addr.sin_family = AF_INET;
    collector_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, collector_ip.c_str(), &collector_addr.sin_addr) <= 0) {
        fprintf(stderr,"Invalid collector IP address");
        close(sock);
        exit(1);
    }

    int flow_count = flows.size();
    //max 30 flows in packet
    for (int i = 0; i < flow_count; i += MAX_FLOWS_PER_PACKET) {
        //save amount of flows
        int current_count = std::min(MAX_FLOWS_PER_PACKET, flow_count - i);
        char buffer[HEADER_SIZE + RECORD_SIZE * current_count] = {0};
        //save sequence number
        const Flow &first_flow = flows[i];
        int sequence = first_flow.flow_num;

        //add header to buffer
        char header[HEADER_SIZE];
        prepare_header(flow_count, header, sequence);
        memcpy(buffer , header, HEADER_SIZE);
        //process all body for each flow in this packet
        for (int j = 0; j < current_count; ++j) {
            const Flow &flow = flows[i + j];
            char record[RECORD_SIZE];
            prepare_body(flow, record);
            memcpy(buffer + HEADER_SIZE + j * RECORD_SIZE, record, RECORD_SIZE);
        }
        //send packet
        sendto(sock, buffer, HEADER_SIZE + RECORD_SIZE * current_count, 0, (struct sockaddr *) &collector_addr,sizeof(collector_addr));

    }
    close(sock);
}
