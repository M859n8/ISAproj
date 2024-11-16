//#include "sendUDP.h"
#include "p2nprobe.h"

const int MAX_FLOWS_PER_PACKET = 30; // Максимальна кількість флоу в пакеті
const int HEADER_SIZE = 24;
const int RECORD_SIZE = 48;
//test only
int amount1 = 0;
// Підготовка даних для одного флоу
int prepare_flow_data(const Flow& flow, char* buffer) {
    // Підготовка даних для передачі флоу
    // Наприклад: перетворення атрибутів флоу в послідовність байтів
    // Повертаємо довжину підготовлених даних
    return snprintf(buffer, 1024, "Flow data");
}

void prepare_header(int amount_of_flows, char* buffer){
    // Заповнюємо заголовок
    uint16_t version = htons(5);
    uint16_t count = htons(amount_of_flows);
    //хіба там не інший час ????????? час старту програми(стрім)? час пакету(гітхаб) ?
    uint32_t sys_uptime = htonl(0); // Заглушка
    uint32_t unix_secs = htonl(time(nullptr)); // Поточний час
    uint32_t unix_nsecs = htonl(0); // Заглушка
    //хіба тут не має бути якесь число флоу ?????
    uint32_t flow_sequence = htonl(0); // Заглушка
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
void prepare_body(const Flow& flow, char *buffer){
    struct in_addr src, dst;
    inet_pton(AF_INET, flow.src_ip.c_str(), &src);
    inet_pton(AF_INET, flow.dst_ip.c_str(), &dst);

    memcpy(buffer, &src, 4);
    memcpy(buffer + 4, &dst, 4);
    memset(buffer + 8, 0, 4); // NextHop
    memset(buffer + 12, 0, 2); // Input
    memset(buffer + 14, 0, 2); // Output
    uint32_t packet_count = htonl(flow.packet_count);
    uint32_t byte_count = htonl(flow.byte_count);
    memcpy(buffer + 16, &packet_count, 4);
    memcpy(buffer + 20, &byte_count, 4);

    uint32_t start_time = htonl(flow.first_packet_time.tv_sec);
    uint32_t end_time = htonl(flow.last_packet_time.tv_sec);
    memcpy(buffer + 24, &start_time, 4);
    memcpy(buffer + 28, &end_time, 4);

    uint16_t src_port = htons(flow.src_port);
    uint16_t dst_port = htons(flow.dst_port);
    memcpy(buffer + 32, &src_port, 2);
    memcpy(buffer + 34, &dst_port, 2);

    //ДОПОВНИТИ ТЕ ЩО ЛИШИЛОСЬ 0 ?? ЧИ МОЖЕ ТАЙП ОФ СЕРВІС НЕ НУЛЬ ?? МАСКА 32?? (зі стріму)

//test only
amount1++;
}

void send_to_collector(const std::string& collector_ip, int port, const std::vector<Flow>& flows) {
    std::cout << "entered send to collector\n " ;

    // Створення UDP сокету
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }

    // Налаштування адреси колектора
    struct sockaddr_in collector_addr{};
    memset(&collector_addr, 0, sizeof(collector_addr));
    collector_addr.sin_family = AF_INET;
    collector_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, collector_ip.c_str(), &collector_addr.sin_addr) <= 0) {
        perror("Invalid collector IP address");
        close(sock);
        return;
    }

    // Розбиваємо потоки на пакети
    int flow_count = flows.size();
    for (int i = 0; i < flow_count; i += MAX_FLOWS_PER_PACKET) {
        int current_count = std::min(MAX_FLOWS_PER_PACKET, flow_count - i);
        char buffer[HEADER_SIZE + RECORD_SIZE * current_count] = {0};
//
        char header[HEADER_SIZE];
        prepare_header(flow_count, header);
        memcpy(buffer , header, HEADER_SIZE);
//
//        // Заповнюємо body
        for (int j = 0; j < current_count; ++j) {
            const Flow &flow = flows[i + j];
            char record[RECORD_SIZE];
            prepare_body(flow, record);
            memcpy(buffer + HEADER_SIZE + j * RECORD_SIZE, record, RECORD_SIZE);
        }
        // Відправляємо пакет
        sendto(sock, buffer, HEADER_SIZE + RECORD_SIZE * current_count, 0, (struct sockaddr *) &collector_addr,sizeof(collector_addr));
        std::cout << "sent packets number " << amount1 << "\n " ;

    }
    close(sock);
}


//int main() {
//    // Дані для відправки
//    char example_data[] = "Example NetFlow data"; // Замініть на ваш NetFlow пакет
//    std::string collector_ip = "192.168.1.100";   // IP-адреса колектора
//    int collector_port = 2055;                   // Порт колектора
//
//    send_to_collector(collector_ip, collector_port, example_data, sizeof(example_data));
//    return 0;
//}
