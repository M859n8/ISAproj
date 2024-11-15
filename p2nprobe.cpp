#include "p2nprobe.h"

// Визначення змінних
std::unordered_map<std::string, struct Flow> flow_table;
Arguments input_val;
//test only
int amount = 0;

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

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pcap_head, const u_char *packet) {
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
        return;
    }

    // Вказівник на TCP заголовок (після IP заголовка)
    struct tcphdr* tcp_head = (struct tcphdr*)(packet + sizeof(struct ether_header)  + ip_head->ip_hl * 4);

//    // Виведення базової інформації про TCP пакет
//    std::cout << "Source IP: " << inet_ntoa(ip_head->ip_src) << "\n";
//    std::cout << "Destination IP: " << inet_ntoa(ip_head->ip_dst) << "\n";
//    std::cout << "Source Port: " << ntohs(tcp_head->th_sport) << "\n";
//    std::cout << "Destination Port: " << ntohs(tcp_head->th_dport) << "\n";
//
    struct timeval time = pcap_head->ts;
    check_timers(time);
    uint16_t src_port = ntohs(tcp_head->source);
    uint16_t dst_port = ntohs(tcp_head->dest);

    // Отримання IP-адрес
    std::string src_ip = inet_ntoa(ip_head->ip_src);
    std::string dst_ip = inet_ntoa(ip_head->ip_dst);
    int bytes = pcap_head->len;
    // Створюємо ключ для хеш-таблиці
    std::string key = create_hash_key(src_ip, dst_ip, src_port, dst_port);
    // Якщо флоу вже є у таблиці, оновлюємо його
    if ((flow_table.find(key) != flow_table.end()) && flow_table[key].send == false) {
        Flow& flow = flow_table[key];

//        std::cout << "old flow" << amount << "\n";

        flow.packet_count += 1;
        flow.byte_count += bytes;
        flow.last_packet_time = time;
        //fprintf(stdout, "   update\n");
    } else {
//        std::cout << "new flow" << amount << "\n";

        // Інакше створюємо новий флоу
        Flow new_flow = create_flow(src_ip, dst_ip, src_port, dst_port, bytes, time);
        flow_table[key] = new_flow;
        //fprintf(stdout, "   create\n");
    }
}

// Функція для обчислення різниці між timeval у секундах
long time_diff_in_seconds(const struct timeval& start, const struct timeval& end) {
//    fprintf(stdout, "   entered time diff func\n");

    return (end.tv_sec - start.tv_sec);
}

void check_timers(struct timeval current_time) {
//    fprintf(stdout, "entered check timer func\n");

    for (auto itr = flow_table.begin(); itr != flow_table.end();  ) {
        Flow& flow = itr->second; // Доступ до значення (Flow)
        if(flow.send == true ){
            ++itr; // Переходимо до наступного елемента
            continue;
        }

        long active_diff = time_diff_in_seconds(flow.first_packet_time, current_time);
        long inactive_diff = time_diff_in_seconds(flow.last_packet_time, current_time);

        if (active_diff > input_val.act_timeout || inactive_diff > input_val.inact_timeout) {
            // Тут має бути експорт і видалення потоку
//            send_to_collector(input_val.addr, input_val.port, flow.dst_ip.data(), sizeof(flow));
//
//            itr = flow_table.erase(itr); // Видаляємо потік і отримуємо новий ітератор
//            fprintf(stdout, "   erase\n");
            flow.send = true;

            amount++; //test only

        } else {
            ++itr; // Переходимо до наступного елемента

        }
    }
}

// Вибір флоу з send == true і надсилання їх на колектор
void prepare_to_send() {
    std::vector<Flow> flows_to_send;
    for (auto itr = flow_table.begin(); itr != flow_table.end();) {
        if (itr->second.send) {
            flows_to_send.push_back(itr->second);
            itr = flow_table.erase(itr); // Видалення флоу після вибору
        } else {
            ++itr;
        }

        // Якщо зібрано 30 флоу, відправляємо їх
        if (flows_to_send.size() == 30) {
            send_to_collector(input_val.addr, input_val.port, flows_to_send);
            flows_to_send.clear();
        }
    }

    // Надсилаємо залишок, якщо є
    if (!flows_to_send.empty()) {
        send_to_collector(input_val.addr, input_val.port, flows_to_send);
    }
}


std::string create_hash_key(const std::string& src_ip, const std::string& dst_ip, uint16_t src_port, uint16_t dst_port) {
    return src_ip + ":" + std::to_string(src_port) + "to" + dst_ip + ":" + std::to_string(dst_port);
}

Flow create_flow(const std::string& src_ip, const std::string& dst_ip, int src_port, int dst_port, int bytes,  struct timeval time){
    Flow new_flow;
    new_flow.src_ip = src_ip;
    new_flow.dst_ip = dst_ip;
    new_flow.src_port = src_port;
    new_flow.dst_port = dst_port;
    new_flow.packet_count = 1;
    new_flow.byte_count = bytes;
    new_flow.first_packet_time = time;
    new_flow.last_packet_time = time;
    new_flow.send = false;
    return new_flow;

}

// Функція для виведення флоу на stdout
void print_flows() {
//    fprintf(stdout, "entered print func\n");
    for (const auto& entry : flow_table) {
        amount++;
//        const Flow& flow = entry.second;
//        std::cout << "Flow: " << flow.src_ip << ":" << flow.src_port << " -> "
//                  << flow.dst_ip << ":" << flow.dst_port << "\n"
//                  << "Packets ount: " << flow.packet_count << ", Bytes: " << flow.byte_count << "\n";
//        time_t packet_time_sec = flow.first_packet_time.tv_sec; // секунди
//        suseconds_t packet_time_usec = flow.first_packet_time.tv_usec; // мікросекунди
//
//        // Конвертуємо час у формат, зручний для читання
//        struct tm *tm_info = localtime(&packet_time_sec);
//        char time_buffer[64];
//        strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);
//
//        std::cout << "Час пакету: " << time_buffer << "." << packet_time_usec << std::endl;
//
//        std::cout << "-------------------------------------------\n";
    }
    fprintf(stdout, "Amount of flows : %d\n", amount);


}


int main(int argc, char *argv[]) {
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];

//    Arguments input_val;
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
    prepare_to_send();

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

    print_flows();
    // Zavření souboru
    pcap_close(pcap);

    return 0;
}