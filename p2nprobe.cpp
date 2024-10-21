#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <cstring>

//struct for input arguments
typedef struct {
    char* addr;
    int port;
    char* file_path;
    int act_timeout;
    int inact_timeout;
} Arguments;

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

int main(int argc, char *argv[]) {
    //std::cout << "Hello World!";
    fprintf(stdout, "Hello World!\n");

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


    //дял перевірки змінних
    std::cout << "Host: " << input_val.addr << "\n";
    std::cout << "Port: " << input_val.port << "\n";
    std::cout << "PCAP file: " << input_val.file_path << "\n";
    std::cout << "Active timeout: " << input_val.act_timeout << " seconds\n";
    std::cout << "Inactive timeout: " << input_val.inact_timeout << " seconds\n";


    return 0;
}