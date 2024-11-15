//#include "sendUDP.h"
#include "p2nprobe.h"

// Підготовка даних для одного флоу
int prepare_flow_data(const Flow& flow, char* buffer) {
    // Підготовка даних для передачі флоу
    // Наприклад: перетворення атрибутів флоу в послідовність байтів
    // Повертаємо довжину підготовлених даних
    return snprintf(buffer, 1024, "Flow data");
}

void send_to_collector(const std::string& collector_ip, int port, const std::vector<Flow>& flows) {
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

    for (const auto& flow : flows) {
        char buffer[1024];
        int length = prepare_flow_data(flow, buffer); // Підготовка даних для відправлення
        if(sendto(sock, buffer, length, 0, (struct sockaddr*)&collector_addr, sizeof(collector_addr)) <0 ){
            perror("Failed to send data");

        }
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
