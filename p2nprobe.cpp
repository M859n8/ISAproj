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
    uint8_t tos = ip_head->ip_tos; // Získání TOS z hlavičky IP
    // Вказівник на TCP заголовок (після IP заголовка)
    struct tcphdr* tcp_head = (struct tcphdr*)(packet + sizeof(struct ether_header)  + ip_head->ip_hl * 4);

    struct timeval time = pcap_head->ts;
    check_timers(time);
    //prepare_to_send();

    uint16_t src_port = ntohs(tcp_head->source);
    uint16_t dst_port = ntohs(tcp_head->dest);
    // Отримання IP-адрес
    std::string src_ip = inet_ntoa(ip_head->ip_src);
    std::string dst_ip = inet_ntoa(ip_head->ip_dst);
    int bytes = pcap_head->len - 14; // без айпі заголовку
    uint8_t tcp_flags = tcp_head->th_flags;
    // Створюємо ключ для хеш-таблиці
    std::string key = create_hash_key(src_ip, dst_ip, src_port, dst_port);

    // Якщо флоу вже є у таблиці, оновлюємо його
    if ((flow_table.find(key) != flow_table.end()) ) {
//if ((flow_table.find(key) != flow_table.end()) && flow_table[key].send == false ) {

        packets++; //test only


        Flow& flow = flow_table[key];
        flow.packet_count += 1;
        flow.byte_count += bytes;
        flow.last_packet_time = time;
        flow.tos = tos;
        flow.tcp_flags = tcp_flags;

        bytes_count +=bytes; //test only

//        std::cout << "upd flow" <<  flow_table[key].packet_count << " packet numb " << packets << "\n";

    } else {
        packets++;//test only

        // Інакше створюємо новий флоу
        Flow new_flow = create_flow(src_ip, dst_ip, src_port, dst_port, bytes, time, tos, tcp_flags);
        flow_table[key] = new_flow;

//        std::cout << "  new flow" << amount << " packet numb " << packets << "\n";

    }


}

// Функція для обчислення різниці між timeval у секундах
//long time_diff_in_seconds(const struct timeval& start, const struct timeval& end) {
//    // Обчислення різниці в секундах
//    long sec_diff = end.tv_sec - start.tv_sec;
//
//    // Якщо секунди однакові, обчислюємо різницю в мікросекундах
//    if (sec_diff == 0) {
//        long usec_diff = end.tv_usec - start.tv_usec;
//        if (usec_diff > 0) {
////            fprintf(stdout, "Difference in microseconds: %ld µs\n", usec_diff);
//            return 0; // Різниця в секундах нульова, тільки мікросекунди
//        } else {
////            fprintf(stdout, "End time is earlier in microseconds\n");
//            return -1; // Сигналізуємо, що `end` раніше `start`
//        }
//    }
//
//    // Якщо секунди різні, обчислюємо результат як різницю секунд
//    return sec_diff;
//}

void check_timers(struct timeval current_time) {
//    fprintf(stdout, "entered check timer func\n");

    for (auto itr = flow_table.begin(); itr != flow_table.end();  ) {
        Flow& flow = itr->second; // Доступ до значення (Flow)
        if(flow.send == true ){
            ++itr; // Переходимо до наступного елемента
            continue;
        }

//        long active_diff = time_diff_in_seconds(flow.first_packet_time, current_time);
//        long inactive_diff = time_diff_in_seconds(flow.last_packet_time, current_time);
        long active_diff_usec = (current_time.tv_sec - flow.first_packet_time.tv_sec) * 1000000L
                                + (current_time.tv_usec - flow.first_packet_time.tv_usec);

        long inactive_diff_usec = (current_time.tv_sec - flow.last_packet_time.tv_sec) * 1000000L
                                  + (current_time.tv_usec - flow.last_packet_time.tv_usec);

// Перетворюємо таймаути з секунд у мікросекунди
        long act_timeout_usec = input_val.act_timeout * 1000000L;
        long inact_timeout_usec = input_val.inact_timeout * 1000000L;

// Перевірка таймаутів
        if (active_diff_usec > act_timeout_usec || inactive_diff_usec > inact_timeout_usec) {
            // Експорт і видалення потоку
            flows_to_send.push_back(itr->second);
            itr = flow_table.erase(itr); // Видалення флоу після вибору
            flow.send = true; //maybe do not nedd this now
        }
        else {
            ++itr; // Переходимо до наступного елемента

        }
    }
}

// Вибір флоу з send == true і надсилання їх на колектор
void prepare_to_send() {
//    std::cout << "entered prepare to send \n " ;
//    std::vector<Flow> flows_to_send;
    //test only
//    std::cout << "flows table size :  " << flow_table.size()  << " \n " ;

    for (auto itr = flow_table.begin(); itr != flow_table.end();) {
        if (itr->second.send) {
            flows_to_send.push_back(itr->second);
            itr = flow_table.erase(itr); // Видалення флоу після вибору
        } else {
            ++itr;
        }

//        std::cout << "  flows count  " << flows_to_send.size() << "\n";

        // Якщо зібрано 30 флоу, відправляємо їх
//        if (flows_to_send.size() == 30) {
//            std::cout << "reach count 30 \n " ;
//
//            send_to_collector(input_val.addr, input_val.port, flows_to_send);
//            flows_to_send.clear();
//        }
    }
//    std::cout << "send remaining flows \n " ;
//
//    // Надсилаємо залишок, якщо є
    if (!flows_to_send.empty()) {
//        std::cout << "Sending ... " << amount << " \n " ;
//        std::cout << "flows to sent size :  " << flows_to_send.size() << " \n " ;

        send_to_collector(input_val.addr, input_val.port, flows_to_send);
    }
}

void send_remains(){
//    std::vector<Flow> flows_to_send;

    for (auto itr = flow_table.begin(); itr != flow_table.end();  ) {
        flows_to_send.push_back(itr->second);
        itr = flow_table.erase(itr);
    }
    if (!flows_to_send.empty()) {
//        std::cout << "Sending ... " << amount << " \n " ;
//        std::cout << "flows to sent size :  " << flows_to_send.size() << " \n " ;

        send_to_collector(input_val.addr, input_val.port, flows_to_send);
    }

}

std::string create_hash_key(const std::string& src_ip, const std::string& dst_ip, uint16_t src_port, uint16_t dst_port) {
    return src_ip + ":" + std::to_string(src_port) + "to" + dst_ip + ":" + std::to_string(dst_port);
}

Flow create_flow(const std::string& src_ip, const std::string& dst_ip, int src_port,
                 int dst_port, int bytes,  struct timeval time, uint8_t tos, uint8_t tcp_flags){

    amount++;//test only

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

    new_flow.send = false;

    bytes_count +=bytes; //test only


    return new_flow;

}

// Функція для виведення флоу на stdout
void print_flows() {
//    fprintf(stdout, "entered print func\n");
    int remains = 0;
    for (const auto& entry : flow_table) {

        const Flow& flow = entry.second;
        std::cout << "Flow: " << flow.src_ip << ":" << flow.src_port << " -> "
                  << flow.dst_ip << ":" << flow.dst_port << "\n"
                  << "Packets count: " << flow.packet_count << ", Bytes: " << flow.byte_count << "\n";
        time_t packet_time_sec = flow.first_packet_time.tv_sec; // секунди
        suseconds_t packet_time_usec = flow.first_packet_time.tv_usec; // мікросекунди

        // Конвертуємо час у формат, зручний для читання
        struct tm *tm_info = localtime(&packet_time_sec);
        char time_buffer[64];
        strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);

        std::cout << "Час пакету: " << time_buffer << "." << packet_time_usec << std::endl;

        std::cout << "-------------------------------------------\n";
    remains++;
    }
    fprintf(stdout, "Amount of flows : %d\n", amount);
    fprintf(stdout, "Remains of flows : %d\n", remains);
    fprintf(stdout, "Packets : %d and bytes count %d\n", packets, bytes_count);



}


int main(int argc, char *argv[]) {
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];

    gettimeofday(&boot_time, NULL);

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
//    prepare_to_send();
    send_remains();
    // Otevření PCAP souboru a inicializace socketu pro komunikaci s kolektorem

    // Nastavení časovačů pro aktivní a neaktivní timeouty

    // Zpracování PCAP souboru pomocí pcap_loop nebo pcap_next_ex

    // Při detekci toku nebo po timeoutu odeslání dat na kolektor

    // Uvolnění zdrojů a ukončení programu


    print_flows();
    // Zavření souboru
    pcap_close(pcap);

    return 0;
}