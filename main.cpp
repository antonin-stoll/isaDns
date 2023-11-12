#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <iostream>

#define PORT_MAX 65535
#define QUERY_LENGTH 200
#define MSG_LENGTH 256
#define INVERSEBIT      0b0000100000000000
#define TRUNCATIONBIT   0b0000001000000000
#define RECURSIONBIT    0b0000000100000000

// class for parsing arguments and storing to config
class Configuration{
public:
    bool recursion;
    bool inverse;
    bool aaaa;
    const char* server;
    int port;
    const char* adress;

    Configuration(){
        recursion = false;
        inverse = false;
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
                recursion = true;
            } else if (!strcmp(argv[i], "-x")){
                inverse = true;
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

struct DNSHeader {
    uint16_t ID;            // DNS Query Identifier
    uint16_t Flags;         // Flags
    uint16_t QDCount;       // Number of Questions
    uint16_t ANCount;       // Number of Answers
    uint16_t NSCount;       // Number of Name Server (Authority) Resource Records
    uint16_t ARCount;       // Number of Additional Resource Records
};

class Resolver{
public:
    DNSHeader header = DNSHeader();
    uint8_t  query[QUERY_LENGTH]{};
    Configuration config;

    explicit Resolver(Configuration conf){
        config = conf;
        SetDNSHeader();
        SetDNSQuestion();
    }

    // setting dns header
    void SetDNSHeader(){
        header.ID = htons(45);

        uint16_t flags = 0;
        if (config.inverse){
            flags |= INVERSEBIT;
        }
        if (config.recursion){
            flags |= RECURSIONBIT;
        }

        header.Flags = htons(flags);
        header.QDCount = htons(1);
        header.ANCount = htons(0);
        header. NSCount = htons(0);
        header.ARCount = htons(0);
    }

    // setting dns question
    void SetDNSQuestion(){
        int position = EncodeLabel(config.adress, query);

        uint16_t queryType = htons(config.aaaa ? 28 : 1); // A or AAAA record type
        memcpy(&query[position], &queryType, sizeof(queryType));
        position += sizeof(queryType);

        uint16_t queryClass = htons(1); // IN class
        memcpy(&query[position], &queryClass, sizeof(queryClass));
    }

    void SendQuestion(){
        // combining header and question
        uint8_t msg[MSG_LENGTH];
        memcpy(msg, &header, sizeof(header));
        memcpy(&msg[sizeof(header)], query, sizeof(query));

        std::cout << "Formatted DNS Request Packet:" << std::endl;
        for (int i = 0; i < 256; i++) {
            printf("%02X ", msg[i]);
            if ((i + 1) % 16 == 0)
                std::cout << std::endl;
        }
        std::cout << "-----------------------" << std::endl;


        int sock;                        // socket descriptor
        int i;
        struct sockaddr_in server, from; // address structures of the server and the client

        socklen_t len, fromlen;

        memset(&server,0,sizeof(server)); // erase the server structure
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = inet_addr(config.server);
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
    }

    static int EncodeLabel(const char *src, uint8_t *dst){
        int position = 0;
        int length = 0;
        while (src[position]){
            if (src[position] != '.'){
                dst[position + 1] = src[position];
                length++;
            } else {
                dst[position - length] = length;
                length = 0;
            }
            position++;
        }

        dst[position - length] = length;
        position++;
        dst[position] = 0;
        position++;

        return position;
    }

    void DecodeLabel(){

    }
};

int main(int argc, char* argv[]) {
    // parsing command line arguments
    Configuration config;
    if (!config.ParseArgs(argc, argv)){
        std::cout << "Usage: dns [-r] [-x] [-6] -s server [-p port] adresa" << std::endl;
        return EXIT_FAILURE;
    }

    auto resolver = Resolver(config);
    resolver.SendQuestion();

    return 0;
}
