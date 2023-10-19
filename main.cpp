#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <iostream>

#define PORT_MAX 65535

// class for parsing arguments and storing to config
class Configuration{
public:
    bool recursion;
    bool reverse;
    bool aaaa;
    const char* server;
    int port;
    const char* adress;

    Configuration(){
        recursion = false;
        reverse = false;
        aaaa = false;
        server = nullptr;
        port = 53;  // default port for DNS
        adress = nullptr;
    }

    bool ParseArgs(int argc, char* argv[]){
        if (argc > 20){
            std::cerr << "Too many arguments! " << argc << std::endl;
            return false;
        }

        for (int i = 1; i < argc; ++i) {
            if (!strcmp(argv[i], "-r")){
                reverse = true;
            } else if (!strcmp(argv[i], "-x")){
                recursion = true;
            } else if (!strcmp(argv[i], "-6")){
                aaaa = true;
            } else if (!strcmp(argv[i], "-s")){

                if (++i < argc){
                    server = argv[i];
                } else {
                    std::cerr << "Missing value of -s argument!" << std::endl;
                    return false;
                }

            } else if (!strcmp(argv[i], "-p")){

                if (++i < argc){
                    port = atoi(argv[i]);
                    if (port < 1 || port > PORT_MAX){
                        std::cerr << "Invalid port number!" << std::endl;
                    }
                } else {
                    std::cerr << "Missing value of -p argument!" << std::endl;
                    return false;
                }

            } else if (adress == nullptr) {
                adress = argv[i];
            } else {
                std::cerr << "Unknown argument: " << argv[i] << std::endl;
                return false;
            }
        }

        if (server == nullptr || adress == nullptr){ // required args
            std::cerr << "Missing server or question adress!"  << std::endl;
            return false;
        }

        return true;
    }
};


bool udpSend(const char *msg){
    
}

struct DNSHeader {
    uint16_t ID;            // DNS Query Identifier
    uint16_t Flags;         // Flags
    uint16_t QDCount;       // Number of Questions
    uint16_t ANCount;       // Number of Answers
    uint16_t NSCount;       // Number of Name Server (Authority) Resource Records
    uint16_t ARCount;       // Number of Additional Resource Records
};

void SetDNSHeader(DNSHeader* header){
    header->ID = htons(45);
    header->Flags = htons(0b0000000100000000);
    header->QDCount = htons(1);
    header->ANCount = htons(0);
    header-> NSCount = htons(0);
    header->ARCount = htons(0);
}


void SetDNSQuestion(uint8_t* query, const char* domain){
    int position = 0;
    int length = 0;
    while (domain[position]){
        if (domain[position] != '.'){
            query[position + 1] = domain[position];
            length++;
        } else {
            query[position - length] = length;
            length = 0;
        }

        position++;
    }
    query[position - length] = length;
    position++;
    query[position] = 0;
    position++;

    uint16_t queryType = htons(1); // A record type
    memcpy(&query[position], &queryType, sizeof(queryType));
    position += sizeof(queryType);

    uint16_t queryClass = htons(1); // IN class
    memcpy(&query[position], &queryClass, sizeof(queryClass));
    position += sizeof(queryClass);

}


int main(int argc, char* argv[]) {
    std::cout << "Hello, World!" << std::endl;

    Configuration config;
    if (!config.ParseArgs(argc, argv)){
        std::cout << "Usage: dns [-r] [-x] [-6] -s server [-p port] adresa" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << config.adress << std::endl;
    std::cout << config.port << std::endl;
    std::cout << config.server << std::endl;
    std::cout << config.aaaa << std::endl;
    std::cout << config.recursion << std::endl;
    std::cout << config.reverse << std::endl;

    return 0;

    uint8_t  query[200];
    DNSHeader header;

    SetDNSHeader(&header);
    SetDNSQuestion(query, "www.github.com");

    uint8_t msg[256];
    memcpy(msg, &header, sizeof(header));
    memcpy(&msg[sizeof(header)], query, sizeof(query));

    int sock;                        // socket descriptor
    int i;
    struct sockaddr_in server, from; // address structures of the server and the client

    socklen_t len, fromlen;

    memset(&server,0,sizeof(server)); // erase the server structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("1.1.1.1");
    server.sin_port = htons(53);

    if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1){  //create a client socket
        // error
    }

    len = sizeof(server);
    fromlen = sizeof(from);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1){
        // error
    }

    i = send(sock,msg,256,0);
    if (i == -1){
        // err
    }

    getsockname(sock,(struct sockaddr *) &from, &len);

    uint8_t answer[512];
    i = recv(sock,answer, 512,0);
    printf("ahoj");
    std::cout << "Formatted DNS Request Packet:" << std::endl;
    for (int i = 0; i < 256; i++) {
        printf("%02X ", answer[i]);
        if ((i + 1) % 16 == 0)
            std::cout << std::endl;
    }
    std::cout << std::endl;
    return 0;
}
