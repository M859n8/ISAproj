#include "sendUDP.h"

void send_to_collector(const std::string& collector_ip, int collector_port, const char* data, size_t data_size) {
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
    collector_addr.sin_port = htons(collector_port);
    if (inet_pton(AF_INET, collector_ip.c_str(), &collector_addr.sin_addr) <= 0) {
        perror("Invalid collector IP address");
        close(sock);
        return;
    }

    // Відправка даних
    if (sendto(sock, data, data_size, 0, (struct sockaddr*)&collector_addr, sizeof(collector_addr)) < 0) {
        perror("Failed to send data");
    } else {
        std::cout << "Packet sent to collector " << collector_ip << ":" << collector_port << std::endl;
    }

    // Закриття сокету
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
