#include <cstdio>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>

#define PORT_MAX 65535
#define QUERY_LENGTH 200
#define MSG_LENGTH 2048
#define AABIT           0b0000010000000000
#define TRUNCATIONBIT   0b0000001000000000
#define RECURSIONBIT    0b0000000100000000
#define LABELPOINER     0b11000000

// class for parsing arguments and storing to config
class Configuration{
public:
    bool recursion;
    bool inverse;
    bool aaaa;
    char* server;
    int port;
    char* address;

    Configuration(){
        recursion = false;
        inverse = false;
        aaaa = false;
        server = nullptr;
        port = 53;  // default port for DNS
        address = nullptr;
    }

    /**
     * Parsing commandline arguments
     * @param argc argc
     * @param argv argv
     * @return True on success
     */
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

            } else if (address == nullptr) {
                address = argv[i];
            } else {
                std::cerr << "Unknown argument: " << argv[i] << std::endl;
                return false;
            }
        }

        if (server == nullptr || address == nullptr){ // required args
            std::cerr << "Missing server or question address!"  << std::endl;
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
    enum QType : int {
        A = 1,      // a host address
        NS = 2,     // an authoritative name server
        MD = 3,     // a mail destination (Obsolete - use MX)
        MF = 4,     // a mail forwarder (Obsolete - use MX)
        CNAME = 5,  // the canonical name for an alias
        SOA = 6,    // marks the start of a zone of authority
        MB = 7,     // a mailbox domain name (EXPERIMENTAL)
        MG = 8,     // a mail group member (EXPERIMENTAL)
        MR = 9,     // a mail rename domain name (EXPERIMENTAL)
        NULL_RR = 10,  // a null RR (EXPERIMENTAL)
        WKS = 11,   // a well-known service description
        PTR = 12,   // a domain name pointer
        HINFO = 13, // host information
        MINFO = 14, // mailbox or mail list information
        MX = 15,    // mail exchange
        TXT = 16,   // text strings
        AAAA = 28,  // ipv6 host address
        XFR = 252,  // a request for a transfer of an entire zone
        MAILB = 253, // a request for mailbox-related records (MB, MG, or MR)
        MAILA = 254, // a request for mail agent RRs (Obsolete - see MX)
        ALL = 255   // a request for all records
    };

    enum QClass : int {
        IN = 1, // the Internet
        CS = 2, // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
        CH = 3, // the CHAOS class
        HS = 4,  // Hesiod [Dyer 87]
        ANY = 255 // any class
    };

    DNSHeader header = DNSHeader();
    uint8_t  query[QUERY_LENGTH]{};
    int queryLen;
    Configuration config;
    uint8_t *answer;
    int answerLen;
    char ip[16]{};

    Resolver(){
        queryLen = 0;
        answer = nullptr;
        answerLen = 0;
        memset(ip, 0 ,sizeof(ip));
    }

    ~Resolver(){
        delete answer;
    }

    void Configure(Configuration conf){
        config = conf;
        SetDNSHeader();
        SetDNSQuestion();
    }

    /**
     * Constructs header of the question
     */
    void SetDNSHeader(){
        header.ID = htons(45);

        uint16_t flags = 0;
        if (config.recursion){
            flags |= RECURSIONBIT;
        }

        header.Flags = htons(flags);
        header.QDCount = htons(1);
        header.ANCount = htons(0);
        header. NSCount = htons(0);
        header.ARCount = htons(0);
    }

    /**
     * Constructs question to be sent
     */
    void SetDNSQuestion(){
        int position;
        if (config.inverse){
            position = EncodeIP(config.address, query);
        } else{
            // domain into labels
            position = EncodeLabel(config.address, query);
        }

        // query type PTR, AAAA or A record type
        uint16_t queryType = htons(config.inverse ? QType::PTR : (config.aaaa ? QType::AAAA : QType::A));
        memcpy(&query[position], &queryType, sizeof(queryType));
        position += sizeof(queryType);

        // query class
        uint16_t queryClass = htons(1); // IN class
        memcpy(&query[position], &queryClass, sizeof(queryClass));
        position += sizeof(queryClass);
        queryLen = position;
    }

    /**
     * Sends DNS packet via UDP
     */
    void SendQuestion(){
        // combining header and question
        uint8_t msg[sizeof(header) + queryLen];
        memcpy(msg, &header, sizeof(header));
        memcpy(&msg[sizeof(header)], query, queryLen);

        int sock;                           // socket descriptor
        int i;
        sockaddr_in server{};                 // ipv4 address structures of the server and the client
        sockaddr_in6 serverV6{};              // ipv6 address structures of the server and the client

        memset(&server,0,sizeof(server)); // erase the server structure
        memset(&serverV6,0,sizeof(serverV6)); // erase the server structure

        struct in_addr ipBuffer;
        struct in6_addr ipv6Buffer;

        bool ipv6 = false;
        if (inet_pton(AF_INET6, config.server, &ipv6Buffer) == 1){
            serverV6.sin6_addr = ipv6Buffer;
            serverV6.sin6_family = AF_INET6;
            serverV6.sin6_port = htons(config.port);
            ipv6 = true;
        } else if (inet_pton(AF_INET, config.server, &ipBuffer) == 1){
            server.sin_addr = ipBuffer;
            server.sin_family = AF_INET;
            server.sin_port = htons(config.port);
            ipv6 = false;
        } else {
            std::cerr << "Failed parsing IP!" << std::endl;
            exit(EXIT_FAILURE);
        }

        if (ipv6){
            if ((sock = socket(AF_INET6 , SOCK_DGRAM , 0)) == -1){  //create a client socket
                std::cerr << "Failed creating socket!" << std::endl;
                exit(EXIT_FAILURE);
            }
        } else {
            if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1){  //create a client socket
                std::cerr << "Failed creating socket!" << std::endl;
                exit(EXIT_FAILURE);
            }
        }

        if (ipv6){
            if (connect(sock, (struct sockaddr *)&serverV6, sizeof(serverV6))  == -1){
                std::cerr << "Failed connecting to peer!" << std::endl;
                exit(EXIT_FAILURE);
            }
        } else {
            if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1){
                std::cerr << "Failed connecting to peer!" << std::endl;
                exit(EXIT_FAILURE);
            }
        }

        i = send(sock,msg, sizeof(msg),0);
        if (i == -1){
            std::cerr << "Failed sending the packet!" << std::endl;
            exit(EXIT_FAILURE);
        }

        uint8_t buffer[MSG_LENGTH];
        answerLen = (int) recv(sock,buffer, MSG_LENGTH,0);
        answer = new uint8_t[answerLen];
        memcpy(answer, buffer, answerLen);
    }

    /**
     * Decodes answer and writes it to std::cout if print is true
     * @param print bool deciding if answer should be printed
     */
    void ParseAnswer(bool print){
        DNSHeader answerHeader = DNSHeader();
        uint8_t answerBody[answerLen - sizeof(header)];
        int position = 0;
        char buffer[MSG_LENGTH];
        uint16_t tmp = 0;

        memcpy(&answerHeader, answer, sizeof(header));
        memcpy(answerBody, &answer[sizeof(header)], sizeof(answerBody));

        // print header
        if (print){
            std::cout << "Authoritative: " << (ntohs(answerHeader.Flags) & AABIT ? "Yes" : "No") << ", "
            << "Recursive: " << (ntohs(answerHeader.Flags) & RECURSIONBIT ? "Yes" : "No") << ", "
            << "Truncated: " << (ntohs(answerHeader.Flags) & TRUNCATIONBIT ? "Yes" : "No") << std::endl;
        }

        // print question section
        uint16_t questionCount = ntohs(answerHeader.QDCount);
        if (print){
            std::cout << "Question section (" << questionCount << ")" << std::endl;
        }
        for (int i = 0; i < questionCount; ++i) {
            position += DecodeLabel(answerBody, buffer, answer);     // question
            if (print){
                std::cout << "\t" << buffer << ", ";
            }

            memcpy(&tmp, &answerBody[position], sizeof(uint16_t));
            if (print){
                printQType(static_cast<QType>(ntohs(tmp)));                 // QTYPE
            }
            position += sizeof(uint16_t);

            if (print){
                std::cout << ", ";
            }

            memcpy(&tmp, &answerBody[position], sizeof(uint16_t));
            if (print){
                printQClass(static_cast<QClass>(ntohs(tmp)));             // QCLASS
            }
            position += sizeof(uint16_t);

            if (print){
                std::cout << std::endl;
            }
        }

        // print answer section
        uint16_t answerCount = ntohs(answerHeader.ANCount);
        if (print){
            std::cout << "Answer section (" << answerCount << ")" << std::endl;
        }
        parseRR(answerBody, &position, buffer, answerCount, print);

        // print authority section
        uint16_t authorityCount = ntohs(answerHeader.NSCount);
        if (print){
            std::cout << "Authority section (" << authorityCount << ")" << std::endl;
        }
        parseRR(answerBody, &position, buffer, authorityCount, print);

        // print additional section
        uint16_t additionalCount = ntohs(answerHeader.ARCount);
        if (print){
            std::cout << "Additional section (" << additionalCount << ")" << std::endl;
        }
        parseRR(answerBody, &position, buffer, additionalCount, print);
    }

    /**
     * Decodes records and prints them if print is true
     * @param answerBody array to be decoded
     * @param position position of next RR
     * @param buffer destination of decoded line
     * @param rrCount how many RRs is in answerBody
     * @param print bool deciding if answer should be printed
     */
    void parseRR(const uint8_t *answerBody, int *position, char *buffer, uint16_t rrCount, bool print){
        uint16_t tmp = 0;
        for (int i = 0; i < rrCount; ++i) {
            *position += DecodeLabel(&answerBody[*position], buffer, answer);
            if (print){
                std::cout << "\t" << buffer << ", ";                                            // NAME
            }

            memcpy(&tmp, &answerBody[*position], sizeof(uint16_t));
            QType qtype = static_cast<QType>(ntohs(tmp));
            if (print){
                printQType(qtype);                                                 // QTYPE
            }
            *position += sizeof(uint16_t);

            if (print){
                std::cout << ", ";
            }

            memcpy(&tmp, &answerBody[*position], sizeof(uint16_t));
            if (print){
                printQClass(static_cast<QClass>(ntohs(tmp)));            // QCLASS
            }
            *position += sizeof(uint16_t);

            if (print){
                std::cout << ", ";
            }

            uint32_t ttl = 0;
            memcpy(&ttl, &answerBody[*position], sizeof(uint32_t));
            if (print){
                std::cout << ntohl(ttl) << ", ";                                // TTL
            }
            *position += sizeof(uint32_t);

            *position += sizeof(uint16_t);                                          // skipping RDLENGTH
            switch (qtype) {
                case A:
                    for (int j = 0, k = 0; j < 4; ++j) {
                        if (print){
                            std::cout << (int) answerBody[*position] << (j < 3 ? "." : "");
                        }
                        k += snprintf(&ip[k], 4, "%d", (int) answerBody[*position]);
                        if (j < 3){
                            ip[k++] = '.';
                        }
                        (*position)++;
                    }
                    break;
                case CNAME:
                case NS:
                case PTR:
                    *position += DecodeLabel(&answerBody[*position], buffer, answer);
                    if (print){
                        std::cout << buffer;
                    }
                    break;
                case AAAA:
                    for (int j = 0; j < 16; j++) {
                        if (print){
                            printf("%02X", answerBody[*position]);
                            if (j % 2 == 1 && j < 14){
                                std::cout << ":";
                            }
                        }
                        (*position)++;
                    }
                    break;
                default:
                    if (print){
                        std::cout << "Not implemented, data: ";
                    }
                    memcpy(&tmp, &answerBody[*position - 2], sizeof(uint16_t));
                    for (int j = 0; j < ((int) ntohs(tmp)); j++) {
                        if (print){
                            printf("%02X ", answerBody[*position]);
                        }
                        (*position)++;
                    }
                    break;
            }

            if (print){
                std::cout << std::endl;
            }
        }
    }

    /**
     * Encodes IP to labels (for reversed query use)
     * @param src IP string to be encoded
     * @param dst destination of encoded labels
     * @return number of used bytes from src
     */
    int EncodeIP(const char *src, uint8_t *dst){
        struct in6_addr ipv6Buffer{};
        if (inet_pton(AF_INET6, src, &ipv6Buffer) == 1){
            // making full length ipv6
            uint8_t addr[16];
            inet_pton(AF_INET6, src, addr);
            char addrStr[33];
            memset(addrStr, 0, sizeof(addrStr));
            for (int i = 0; i < (sizeof(addr)/2); ++i) {
                sprintf(&addrStr[i*4], "%04X", htons(*((uint16_t *)&addr[2*i]))); // trochu nechutné :(
            }

            // reversing and adding dots
            char reversedAddrStr[64 + sizeof(".ip6.arpa") + 1];
            memset(reversedAddrStr, 0, sizeof(reversedAddrStr));
            for (int i = 0; i < (sizeof(addrStr) - 1); ++i) {
                reversedAddrStr[2*i] = addrStr[sizeof(addrStr)-i-2];
                reversedAddrStr[2*i + 1] = '.';
            }

            strcpy(&reversedAddrStr[strlen(reversedAddrStr)], "ip6.arpa");
            return EncodeLabel(reversedAddrStr, dst);
        } else {
            uint8_t addr[4];
            uint8_t reversedAddr[4];
            inet_pton(AF_INET, src, addr);
            for (int i = 0; i < sizeof(addr); ++i) {
                reversedAddr[i] = addr[3-i];
            }

            char reversedAddrStr[16 + sizeof(".in-addr.arpa") + 1];
            memset(reversedAddrStr, 0, sizeof(reversedAddrStr));
            inet_ntop(AF_INET, reversedAddr, reversedAddrStr, sizeof(reversedAddrStr));

            strcpy(&reversedAddrStr[strlen(reversedAddrStr)], ".in-addr.arpa");
            return EncodeLabel(reversedAddrStr, dst);
        }
    }

    /**
     * Encodes domain name into labels
     * @param src domain name string to be encoded
     * @param dst destination of encoded labels
     * @return number of used bytes in dst
     */
    static int EncodeLabel(char *src, uint8_t *dst){
        if (src[strlen(src)-1] == '.'){
            src[strlen(src)-1] = '\0';
        }
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

    /**
     * Decodes sequence of labels into readable string
     * @param src labels to be decoded
     * @param dst destination of final string
     * @param wholeSrc complete query
     * @return number of used bytes from src
     */
    static int DecodeLabel(const uint8_t *src, char *dst, const uint8_t *wholeSrc){
        int positionSrc = 0;
        int positionDst = 0;
        int returnedPosition = 0;

        while (src[positionSrc] != 0){
            if (src[positionSrc] & LABELPOINER){
                uint16_t tmp;
                memcpy(&tmp, &src[positionSrc], sizeof(uint16_t));
                src = wholeSrc;
                returnedPosition = positionSrc + (int) sizeof(uint16_t);
                positionSrc = ntohs(tmp) - 0xC000;
            }

            int charCount = src[positionSrc];
            for (int i = 0; i < charCount; i++) {
                positionSrc++;

                dst[positionDst] = (char) src[positionSrc];
                positionDst++;
            }

            positionSrc++;
            dst[positionDst] = '.';
            positionDst++;

        }

        positionSrc++;
        dst[positionDst] = 0;

        if (returnedPosition != 0){
            return returnedPosition;
        }
        return positionSrc;
    }

    /**
     * Prints string representation of QType to std::cout
     * @param type
     */
    static void printQType(QType type) {
        switch (type) {
            case QType::A:
                std::cout << "A";
                break;
            case QType::NS:
                std::cout << "NS";
                break;
            case QType::MD:
                std::cout << "MD";
                break;
            case QType::MF:
                std::cout << "MF";
                break;
            case QType::CNAME:
                std::cout << "CNAME";
                break;
            case QType::SOA:
                std::cout << "SOA";
                break;
            case QType::MB:
                std::cout << "MB";
                break;
            case QType::MG:
                std::cout << "MG";
                break;
            case QType::MR:
                std::cout << "MR";
                break;
            case QType::NULL_RR:
                std::cout << "NULL";
                break;
            case QType::WKS:
                std::cout << "WKS";
                break;
            case QType::PTR:
                std::cout << "PTR";
                break;
            case QType::HINFO:
                std::cout << "HINFO";
                break;
            case QType::MINFO:
                std::cout << "MINFO";
                break;
            case QType::MX:
                std::cout << "MX";
                break;
            case QType::TXT:
                std::cout << "TXT";
                break;
            case QType::AAAA:
                std::cout << "AAAA";
                break;
            case QType::XFR:
                std::cout << "XFR";
                break;
            case QType::MAILB:
                std::cout << " MAILB";
                break;
            case QType::MAILA:
                std::cout << "MAILA";
                break;
            case QType::ALL:
                std::cout << "*";
                break;
            default:
                std::cout << "Unknown DNS type";
        }
    }

    /**
     * Prints string representation of QClass to std::cout
     * @param qClass
     */
    static void printQClass(QClass qClass) {
        switch (qClass) {
            case QClass::IN:
                std::cout << "IN";
                break;
            case QClass::CS:
                std::cout << "CS";
                break;
            case QClass::CH:
                std::cout << "CH";
                break;
            case QClass::HS:
                std::cout << "HS";
                break;
            case QClass::ANY:
                std::cout << "*";
                break;
            default:
                std::cout << "Unknown DNS class";
        }
    }
};

int main(int argc, char* argv[]) {
    // parsing command line arguments
    Configuration config;
    if (!config.ParseArgs(argc, argv)){
        std::cout << "Usage: dns [-r] [-x] [-6] -s server [-p port] adresa" << std::endl;
        return EXIT_FAILURE;
    }

    struct in_addr ipBuffer{};
    struct in6_addr ipv6Buffer{};
    if (inet_pton(AF_INET, config.server, &ipBuffer) != 1 && inet_pton(AF_INET6, config.server, &ipv6Buffer) != 1){       // server is not ip address
        Configuration serverConf = Configuration();
        serverConf.server = "1.1.1.1";
        serverConf.address = config.server;
        serverConf.recursion = true;

        Resolver serverResolver = Resolver();
        serverResolver.Configure(serverConf);
        serverResolver.SendQuestion();
        serverResolver.ParseAnswer(false);
        config.server = new char[16];
        strcpy(config.server, serverResolver.ip);
    }

    // resolving user query
    Resolver resolver = Resolver();
    resolver.Configure(config);
    resolver.SendQuestion();
    resolver.ParseAnswer(true);

    return 0;
}
