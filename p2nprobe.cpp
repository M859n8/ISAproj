#include "p2nprobe.h"

//copied from my ipk project
//function that calculate ip address by name
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
        return NULL;
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

int input_parse(int argc, char *argv[], Arguments *value){
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            value->act_timeout = std::stoi(argv[++i]);//переводимо рядок в число
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            value->inact_timeout = std::stoi(argv[++i]);
        } else if (strchr(argv[i], ':') != nullptr) {  // Якщо аргумент має формат <host>:<port>
            char* port_str = strchr(argv[i], ':');//шукаємо перше входження двокрапки
            *port_str = '\0';
            value->addr = argv[i];
            value->port = std::stoi(port_str + 1);
        } else {
            value->file_path = argv[i];  // Вважаємо, що це шлях до PCAP-файлу
        }

    }
    //перевіряємо чи наставлено обовязкові змінні
    if(!value->port || !value->addr || !value->file_path){
        return -1;
    }
    value->addr = get_host_by_name(value->addr);
    return 0;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    //get packet type
    struct ether_header *ether_head = (struct ether_header *) packet;
    int etherType = ntohs(ether_head->ether_type);
    //Мже не треба перевіряти на іпв4? може тільки перевірку на тцп залишити ??
    if (etherType != 0x0800) { //if not  IPv4
        return;
    }
    //get ip4 header
    struct ip *ip_head = (struct ip *) (packet + sizeof(struct ether_header));
    // Вказівник на IP заголовок
    //struct ip* ipHeader = (struct ip*)(packet + 14);  // Ethernet заголовок має розмір 14 байт
    // Якщо це не IP-пакет, виходимо
    if (ip_head->ip_p != IPPROTO_TCP) {
        fprintf(stdout, "not tcp ret\n");
        return;
    }

    // Вказівник на TCP заголовок (після IP заголовка)
    struct tcphdr* tcp_head = (struct tcphdr*)(packet + sizeof(struct ether_header)  + ip_head->ip_hl * 4);
    // Виведення базової інформації про TCP пакет
    std::cout << "Source IP: " << inet_ntoa(ip_head->ip_src) << "\n";
    std::cout << "Destination IP: " << inet_ntoa(ip_head->ip_dst) << "\n";
    std::cout << "Source Port: " << ntohs(tcp_head->th_sport) << "\n";
    std::cout << "Destination Port: " << ntohs(tcp_head->th_dport) << "\n";
    std::cout << "-------------------------------------------\n";
}

//std::string hash_key(const std::string& src_ip, const std::string& dst_ip, uint16_t src_port, uint16_t dst_port) {
//    return src_ip + ":" + std::to_string(src_port) + "to" + dst_ip + ":" + std::to_string(dst_port);
//}


int main(int argc, char *argv[]) {
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];

    Arguments input_val;
    input_val.addr = nullptr;
    input_val.port = 0;
    input_val.file_path = nullptr;
    input_val.act_timeout = 60;
    input_val.inact_timeout = 60;
    if(input_parse(argc, argv, &input_val) == -1){
        fprintf(stderr, "ERR: Input arguments .\n");
        return 1;
    }

    // Otevření PCAP souboru
    pcap = pcap_open_offline(input_val.file_path, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "Nemohu otevřít PCAP soubor: %s\n", errbuf);
        return 1;
    }
    // Iterace přes pakety v PCAP souboru
    //pcap_loop(pcap, 0, packet_handler, NULL);
    // Запуск обробки кожного пакета
    if (pcap_loop(pcap, 0, packet_handler, nullptr) < 0) {
        std::cerr << "Error reading packets: " << pcap_geterr(pcap) << "\n";
        return 1;
    }

    // Otevření PCAP souboru a inicializace socketu pro komunikaci s kolektorem

    // Nastavení časovačů pro aktivní a neaktivní timeouty

    // Zpracování PCAP souboru pomocí pcap_loop nebo pcap_next_ex

    // Při detekci toku nebo po timeoutu odeslání dat na kolektor

    // Uvolnění zdrojů a ukončení programu




    //для перевірки змінних
    std::cout << "Host: " << input_val.addr << "\n";
    std::cout << "Port: " << input_val.port << "\n";
    std::cout << "PCAP file: " << input_val.file_path << "\n";
    std::cout << "Active timeout: " << input_val.act_timeout << " seconds\n";
    std::cout << "Inactive timeout: " << input_val.inact_timeout << " seconds\n";

    // Zavření souboru
    pcap_close(pcap);

    return 0;
}