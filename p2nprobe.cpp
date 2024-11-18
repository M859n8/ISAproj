//Author : Maryna Kucher , xkuche01

#include "p2nprobe.h"

// Визначення змінних
std::unordered_map<std::string, struct Flow> flow_table;
Arguments input_val;
std::vector<Flow> flows_to_send;
struct timeval boot_time;
//test only
int amount = 0;
int packets = 0;
int bytes_count = 0;

//function that calculate ip address by name
//the function is taken from my IPK project
char *get_host_by_name(char *hostname) {
    //helping strucutres
    struct addrinfo hints, *result, *p;
    //max size for IPv4
    char ip_address[INET_ADDRSTRLEN];
    //set memory for structure hints
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; //IPv4
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0) {
        fprintf(stderr, "ERR: can't get ip.\n");
        exit(1);
    }
    //go through the list of addresses
    for (p = result; p != NULL; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            //convert network address to string
            inet_ntop(AF_INET, &(ipv4->sin_addr), ip_address, INET_ADDRSTRLEN);
            break; //get first IPv4 adress -> break
        }
    }

    freeaddrinfo(result);
    return strdup(ip_address);
}

//parse input arguments
int input_parse(int argc, char *argv[], Arguments *value){
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            value->act_timeout = std::stoi(argv[++i]); //convert into int
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            value->inact_timeout = std::stoi(argv[++i]);
        } else if (strchr(argv[i], ':') != nullptr) {  //if argument include ":"
            char* port_str = strchr(argv[i], ':'); //get pos of :
            *port_str = '\0'; //change ':' to '\0'
            value->addr = argv[i]; //now argv[i] contains only port (it was before \0)
            value->port = std::stoi(port_str + 1); //port is after \0
        } else if (strcmp(argv[i], "-h") == 0) { //help output
            fprintf(stdout, "Start program with"
            " ./p2nprobe <host>:<port> <pcap_file_path> [-a <active_timeout> -i <inactive_timeout>]\n");
            exit(0);
        } else { //otherwise we save argument as pcap file
            value->file_path = argv[i];
        }

    }
    //check mandatory arguments
    if(!value->port || !value->addr || !value->file_path){
        return -1;
    }
    //resolve hostname
    value->addr = get_host_by_name(value->addr);
    return 0;
}

//function for packet processing
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pcap_head, const u_char *packet) {
    //get packet type
    struct ether_header *ether_head = (struct ether_header *) packet;
    int etherType = ntohs(ether_head->ether_type);
    //check if it is IPv4
    if (etherType != 0x0800) {
        return;
    }
    //get ip4 header
    struct ip *ip_head = (struct ip *) (packet + sizeof(struct ether_header));
    //check if it is TCP
    if (ip_head->ip_p != IPPROTO_TCP) { //
        return;
    }
    uint8_t tos = ip_head->ip_tos;//get tos
    // get tcp head
    struct tcphdr* tcp_head = (struct tcphdr*)(packet + sizeof(struct ether_header)  + ip_head->ip_hl * 4);
    //get packet time and check the flows expiration
    struct timeval time = pcap_head->ts;
    check_timers(time);
    //export expired flows
    export_flows();
    //get basic information about packet
    uint16_t src_port = ntohs(tcp_head->source);
    uint16_t dst_port = ntohs(tcp_head->dest);

    std::string src_ip = inet_ntoa(ip_head->ip_src);
    std::string dst_ip = inet_ntoa(ip_head->ip_dst);
    int bytes = pcap_head->len - 14; //we need length without ip header
    uint8_t tcp_flags = tcp_head->th_flags;
    //create hash key based on information that distinguishes flows
    std::string key = create_hash_key(src_ip, dst_ip, src_port, dst_port);

    //id there is suitable flow add packet
    if ((flow_table.find(key) != flow_table.end()) ) {
        //update flow info
        Flow& flow = flow_table[key];
        flow.packet_count += 1;
        flow.byte_count += bytes;
        flow.last_packet_time = time;
        flow.tos = tos;
        flow.tcp_flags = tcp_flags;

    } else {
        //otherwise create a new flow
        Flow new_flow = create_flow(src_ip, dst_ip, src_port, dst_port, bytes, time, tos, tcp_flags);
        flow_table[key] = new_flow;
    }
}
//function that creates hash key from src/dst ip, src/dst port
std::string create_hash_key(const std::string& src_ip, const std::string& dst_ip, uint16_t src_port, uint16_t dst_port) {
    return src_ip + ":" + std::to_string(src_port) + "to" + dst_ip + ":" + std::to_string(dst_port);
}
//function that creates flow
Flow create_flow(const std::string& src_ip, const std::string& dst_ip, int src_port,
                 int dst_port, int bytes,  struct timeval time, uint8_t tos, uint8_t tcp_flags){
    Flow new_flow;
    new_flow.src_ip = src_ip;
    new_flow.dst_ip = dst_ip;
    new_flow.src_port = src_port;
    new_flow.dst_port = dst_port;
    new_flow.packet_count = 1;
    new_flow.byte_count = bytes;
    new_flow.first_packet_time = time;
    new_flow.last_packet_time = time;
    new_flow.tos = tos;
    new_flow.tcp_flags = tcp_flags;
    new_flow.flow_num = 0;

    return new_flow;
}

//function that checks timers expiration
void check_timers(struct timeval current_time) {
    for (auto itr = flow_table.begin(); itr != flow_table.end();  ) {
        Flow& flow = itr->second; //get the flow value
        //current time - time that we got from packet
        //get the time difference in microseconds for accurate estimation
        long active_diff_usec = (current_time.tv_sec - flow.first_packet_time.tv_sec) * 1000000L
                                + (current_time.tv_usec - flow.first_packet_time.tv_usec);

        long inactive_diff_usec = (current_time.tv_sec - flow.last_packet_time.tv_sec) * 1000000L
                                  + (current_time.tv_usec - flow.last_packet_time.tv_usec);

        //convert timeouts from seconds to nanoseconds
        long act_timeout_usec = input_val.act_timeout * 1000000L;
        long inact_timeout_usec = input_val.inact_timeout * 1000000L;

        if (active_diff_usec > act_timeout_usec || inactive_diff_usec > inact_timeout_usec) {
            //delete expired flow and add to send list
            itr->second.flow_num = input_val.sequence_flow++;
            flows_to_send.push_back(itr->second);
            itr = flow_table.erase(itr);
        }else {
            ++itr; //go to the next

        }
    }
}

//function that exports flows
void export_flows() {
    if (!flows_to_send.empty()) {
        send_to_collector(input_val.addr, input_val.port, flows_to_send);
        flows_to_send.clear();
    }
}

//function that exports remaining flows after processing all packets from a file
void send_remains(){
    for (auto itr = flow_table.begin(); itr != flow_table.end();  ) {
        itr->second.flow_num = input_val.sequence_flow++;
        flows_to_send.push_back(itr->second);
        itr = flow_table.erase(itr);
    }
    export_flows();
}

int main(int argc, char *argv[]) {
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    //get time when program starts
    gettimeofday(&boot_time, NULL);

    //set input arguments default values
    input_val.addr = nullptr;
    input_val.port = 0;
    input_val.file_path = nullptr;
    input_val.act_timeout = 60;
    input_val.inact_timeout = 60;
    input_val.sequence_flow = 0;

    if(input_parse(argc, argv, &input_val) == -1){
        fprintf(stderr, "ERR: Input arguments .\n");
        return 1;
    }

    //open pcap file
    pcap = pcap_open_offline(input_val.file_path, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "ERR: Can not open pcap file: %s\n", errbuf);
        return 1;
    }

    //loop through packets of the pcap file
    if (pcap_loop(pcap, 0, packet_handler, nullptr) < 0) {
        std::cerr << "ERR: reading packers" << pcap_geterr(pcap) << "\n";
        return 1;
    }
    //send packets that were not exported by the timer
    send_remains();

    pcap_close(pcap);

    return 0;
}