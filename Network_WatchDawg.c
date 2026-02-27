#define _GNU_SOURCE
#define RED "\x1B[31m"    // ANSI escape codes used to add red color in printing statement or you can say in terminal
#define GRN "\x1B[32m"    // ANSI escape codes used to add green color in printing statement or you can say in terminal
#define CYN "\x1B[36m"    // ANSI escape codes used to add cyan color in printing statement or you can say in terminal
#define RESET "\x1B[0m"   // ANSI escape codes used to reset the color back to the normal
#include <stdio.h>        //used to print
#include <stdlib.h>       //used to exit
#include <string.h>       //usin to do some string functions
#include <pcap.h>         //used to do all the boss stuff
#include <net/ethernet.h> // used to sort the header of 16 bytes which conatins source and dest mac and protocol
#include <netinet/ip.h>   // used to retreave te ip eader which is just next to the eth header
#include <arpa/inet.h>    // this header is used to fixx the printing of ip and port
#include <netinet/tcp.h>  // used to get the tcp header
#include <netinet/udp.h>  // used to get the udp header
#include <ctype.h>

int main()
{
    system("clear");
    printf("%s", GRN);
    printf("==================================================================\n");
    printf("||                   NETWORK-WATCHDAWG v1.0                     ||\n");
    printf("||           Custom Network Analysis & Security Suite           ||\n");
    printf("==================================================================\n");
    printf("|| [Status]: SYSTEM_READY                                       ||\n");
    printf("|| [Mode]  : PROMISCUOUS_SNIFFING                               ||\n");
    printf("|| [User]  : ROOT_ACCESS_GRANTED                                ||\n");
    printf("==================================================================\n");
    printf("%s\n\n", RESET);

    char error_buffer[PCAP_ERRBUF_SIZE]; // this will help to print the error

    pcap_if_t *alldev; // it points to the head of the list
    pcap_if_t *d;      // it will help to iterate the loop

    if (pcap_findalldevs(&alldev, error_buffer) == -1) // it will help to check if all the interface cards are live and if not then whats the error message
    {
        printf("\n%s[!] FATAL ERROR:%s \n>> Reason: %s\n", error_buffer, RED, RESET);
    }

    printf("%s", GRN);
    printf("==================================================================\n");
    printf("||                 AVAILABLE NETWORK INTERFACES                 ||\n");
    printf("==================================================================\n%s", RESET);
    int count = 1;
    for (d = alldev; d != NULL; d = d->next)
    {
        printf("  [%s%d%s] Device: %-15s | Desc: %s\n", GRN, count, RESET, d->name, (d->description) ? d->description : "No description");
        count++;
    }

    printf("\n\n");
    d = alldev;

    int choice;
    printf("\n%s[?]%s SELECT INTERFACE NUMBER -> ", GRN, RESET);
    scanf("%d", &choice);

    for (int i = 0; i < choice - 1; i++)
    {
        d = d->next;
    }

    printf("\n%s[+ Successfully Initialized]%s\n", GRN, RESET);
    printf("Target Interface: %s[%s]%s\n", RED, d->name, RESET);
    printf("%s------------------------------------------------------------------%s\n\n", GRN, RESET);

    pcap_t *handle; // creating a remote to network card so that we dont need to call it again and again to make the program slower we can use its functions using this remote
    // it acts as a mediator to connect your program using open live to network card

    handle = pcap_open_live(d->name, 65535, 1, 1000, error_buffer); // by pairing pcapt with this our remote is ready to to handle like catch packets, set filters or close the session
    // basically it is used to open live session and then sniff packets

    if (handle == NULL)
    {
        printf("\n%s[!] FATAL ERROR:%s Failed to initialize handle\n", RED, RESET);
        printf(">> Reason: %s\n", error_buffer);
        exit(1); // good practice to exit if the handle fails
    }
    else
    {
        printf("%s[+ LINK ESTABLISHED]%s\n", GRN, RESET);
        printf("Session started on device: %s%s%s\n", GRN, d->name, RESET);
        printf("Status: %sMonitoring Live Traffic...%s\n", GRN, RESET);
    }
    printf("\n%s------------------------------------------------------------------%s\n", GRN, RESET);
    pcap_freealldevs(alldev); // free the memory delete the list and gives memory back to the OS

    struct bpf_program fp; // this struct helps us to cumminacate to kernal and telling it to filter the packets  using the strings it convert our strings to hardware understanding bytecodes so that kernal can filter packets directly

    if (pcap_compile(handle, &fp, "ip", 1, PCAP_NETMASK_UNKNOWN) == -1) // parse the type of filter that i want to apply to kernal
    {
        printf("\n%s[!] KERNAL_FILTER_ERROR:%s Unable to parse BPF string\n", RED, RESET);
        printf(">> Detail: %s\n", pcap_geterr(handle));
    }

    if (pcap_setfilter(handle, &fp) == -1) // set the filter
    {
        printf("%s[!] KERNAL_APPLY_ERROR:%s Failed to push filter to handle\n", RED, RESET);
        printf(">> Detail: %s\n", pcap_geterr(handle));
    }

    pcap_freecode(&fp);

    struct pcap_pkthdr header; // creating a header variable which contains all the info of packet passed by OS header.len, header.caplen, header.ts
    const __u_char *packet;    // an unsigned const char because unsigned is perfect way for look at a byte and const because memory where it contains is pcap buffer so accidentally it didnt get changed

    int option;
    printf("\n%s+------------------------------------------------------------+%s\n", GRN, RESET);
    printf("| %s[ SELECT ANALYSIS MODULE ]%s                               |\n", GRN, RESET);
    printf("+------------------------------------------------------------+\n");
    printf("| %s[1]%s DNS / UDP PORT 53  - %s(Targeted Game Detection)%s       |\n", GRN, RESET, RED, RESET);
    printf("| %s[2]%s TCP/UDP STACK      - %s(Full Protocol Analysis)%s        |\n", GRN, RESET, RED, RESET);
    printf("| %s[3]%s LAYER-2 DISCOVERY  - %s(MAC & IP Mapping)%s              |\n", GRN, RESET, RED, RESET);
    printf("+------------------------------------------------------------+\n");
    printf("\n%s[?]%s MODULE_ID -> ", GRN, RESET);
    scanf("%d", &option);

    system("clear"); // clearing screen again for a clean "Live Sniffer" view
    printf("%s[+ INITIALIZING ENGINE...]%s\n", GRN, RESET);
    printf("%s[*]%s Mode: %s\n", GRN, RESET, (option == 1 ? "UDP-53 Sniffer" : (option == 2 ? "TCP/UDP Sniffer" : "Network Mapping")));
    printf("%s[*]%s Status: %sLIVE_DETECTION_ACTIVE%s\n", GRN, RESET, RED, RESET);
    printf("%s------------------------------------------------------------%s\n", GRN, RESET);
    printf("Press %s[Ctrl+C]%s to terminate the session and exit safely.\n\n", RED, RESET);
    while (1)
    {

        packet = pcap_next(handle, &header); // this bridges your handle to the code and checks for packet on your interface card

        if (packet == NULL)
        {
            printf("%s[WAITING]%s Listening for traffic on %s...", RED, RESET, d->name);
            continue;
        }

        struct ethhdr *eth;            // used to sort the starting 16 bytes of packet to get the header
        eth = (struct ethhdr *)packet; // here we are doin typecasting to make our packet read and retrieve the header

        struct iphdr *ip; // ip header functions structure
        ip = ((struct iphdr *)(packet + 14));
        int ip_header_len = ip->ihl * 4;

        if (option == 1)
        {

            if (ip->protocol == 17) // protocol 17 means udp
            {

                char source_ip[16];
                strcpy(source_ip, inet_ntoa(*(struct in_addr *)&ip->saddr)); //  we are copying the source addr in this string so that we can print both the ip's in single printf statement cuz inet_ntoa uses static buffer which can store one string at a time if we use 2 inet_ntoa in sinle printf it will just give you the same string twice

                struct udphdr *udp; // this struct contains the functions like uh_source and uh_dest
                udp = (struct udphdr *)((unsigned char *)packet + 14 + ip_header_len);

                printf("\r%s[!] TRAFFIC_DETECTED%s\n", RED, RESET);

                printf("%s+------------------------------------------------------------------+%s\n", RED, RESET);
                printf("| %sPROTOCOL: UDP%s | %sLEN: %-4d%s | %sTIMESTAMP: %ld%s               |\n",
                       RED, RESET, RED, header.len, RESET, RED, header.ts.tv_sec, RESET);
                printf("+------------------------------------------------------------------+\n");
                printf("| %-15s : %-5d  %s>>>%s  %-15s : %-5d |\n",
                       source_ip, ntohs(udp->uh_sport), RED, RESET,
                       inet_ntoa(*(struct in_addr *)&ip->daddr), ntohs(udp->uh_dport));
                printf("+------------------------------------------------------------------+\n");

                int payload_len;
                const unsigned char *payload;

                payload_len = header.len - (14 + ip_header_len + 8);
                payload = (unsigned char *)(packet + 14 + ip_header_len + 8);

                printf("%s[PAYLOAD DATA]:%s\n", RED, RESET);
                printf("--------------------------------------------------------------------\n");

                for (int i = 0; i < payload_len; i++)
                {
                    // Print in blocks of 32 for better readability on standard terminals
                    if (isprint(payload[i])) //used to print human readable format only 
                    {
                        printf("%c", payload[i]);
                    }
                    else
                    {
                        printf("%s.%s", RED, RESET); // Make non-printable dots red for style
                    }

                    if ((i + 1) % 64 == 0)
                    {
                        printf("\n");
                    }
                }

                printf("\n--------------------------------------------------------------------\n\n");
            }
        }
        else if (option == 2)
        {
            if (ip->protocol == 6) // protocol 6 means tcp
            {

                if (packet != NULL)
                {
                    printf("\r%s[+] TCP_STREAM_INTERCEPTED%s\n", GRN, RESET);
                }

                char source_ip[16];
                strcpy(source_ip, inet_ntoa(*(struct in_addr *)&ip->saddr)); //  we are copying the source addr in this string so that we can print both the ip's in single printf statement cuz inet_ntoa uses static buffer which can store one string at a time if we use 2 inet_ntoa in sinle printf it will just give you the same string twice

                struct tcphdr *tcp; // this struct contains the functions like source and dest
                tcp = (struct tcphdr *)((unsigned char *)packet + 14 + ip_header_len);

                printf("%s+------------------------------------------------------------------+%s\n", GRN, RESET);
                printf("| %sPROTOCOL: TCP%s | %sLEN: %-4d%s | %sFLAGS: [ACK/PSH]%s                 |\n",
                       GRN, RESET, GRN, header.len, RESET, GRN, RESET);
                printf("+------------------------------------------------------------------+\n");
                printf("| %-15s : %-5d  %s==>%s  %-15s : %-5d |\n",
                       source_ip, ntohs(tcp->source), GRN, RESET,
                       inet_ntoa(*(struct in_addr *)&ip->daddr), ntohs(tcp->dest));
                printf("+------------------------------------------------------------------+\n");

                int tcp_header_len = tcp->doff * 4;
                int payload_len;
                const unsigned char *payload;

                payload_len = header.len - (14 + ip_header_len + tcp_header_len);
                payload = (unsigned char *)(packet + 14 + ip_header_len + tcp_header_len);

                printf("%s[DATA STREAM]:%s\n", GRN, RESET);
                printf("--------------------------------------------------------------------\n");

                for (int i = 0; i < payload_len; i++)
                {
                    if (isprint(payload[i]))
                    {
                        printf("%c", payload[i]);
                    }
                    else
                    {
                        printf("%s.%s", GRN, RESET); // Subtle green dots for non-printables
                    }

                    // Keep the line width consistent at 64 characters
                    if ((i + 1) % 64 == 0)
                    {
                        printf("\n");
                    }
                }
                printf("\n--------------------------------------------------------------------\n\n");
            }
            if (ip->protocol == 17) // protocol 17 means udp
            {

                if (packet != NULL)
                {
                    printf("\r%s[!] UDP_DATAGRAM_INTERCEPTED%s\n", RED, RESET);
                }

                char source_ip[16];
                strcpy(source_ip, inet_ntoa(*(struct in_addr *)&ip->saddr)); //  we are copying the source addr in this string so that we can print both the ip's in single printf statement cuz inet_ntoa uses static buffer which can store one string at a time if we use 2 inet_ntoa in sinle printf it will just give you the same string twice

                struct udphdr *udp; // this struct contains the functions like uh_source and uh_dest
                udp = (struct udphdr *)((unsigned char *)packet + 14 + ip_header_len);

                printf("%s+------------------------------------------------------------------+%s\n", RED, RESET);
                printf("| %sPROTOCOL: UDP%s | %sLEN: %-4d%s | %sTYPE: USER_DATA%s                  |\n",
                       RED, RESET, RED, header.len, RESET, RED, RESET);
                printf("+------------------------------------------------------------------+\n");
                printf("| %-15s : %-5d  %s>>>%s  %-15s : %-5d |\n",
                       source_ip, ntohs(udp->uh_sport), RED, RESET,
                       inet_ntoa(*(struct in_addr *)&ip->daddr), ntohs(udp->uh_dport));
                printf("+------------------------------------------------------------------+\n");

                int payload_len;
                const unsigned char *payload;

                payload_len = header.len - (14 + ip_header_len + 8);
                payload = (unsigned char *)(packet + 14 + ip_header_len + 8);

                printf("%s[DATA PAYLOAD]:%s\n", RED, RESET);
                printf("--------------------------------------------------------------------\n");

                for (int i = 0; i < payload_len; i++)
                {
                    if (isprint(payload[i]))
                    {
                        printf("%c", payload[i]);
                    }
                    else
                    {
                        printf("%s.%s", RED, RESET); // Red dots for binary/non-printable data
                    }

                    if ((i + 1) % 64 == 0)
                    {
                        printf("\n");
                    }
                }
                printf("\n--------------------------------------------------------------------\n\n");
            }
        }
        else if (option == 3)
        {
            // We use Cyan for discovery/mapping
            printf("\n%s[!] DEVICE_FINGERPRINT_EXTRACTED%s\n", CYN, RESET);
            printf("%s+------------------------------------------------------------+%s\n", CYN, RESET);
            printf("|  %s[ LAYER 2 - ETHERNET ]%s                                    |\n", CYN, RESET);

            // Fixed: Added %s and %s to actually apply the colors
            printf("|  %sSource MAC%s      : ", CYN, RESET);
            for (int i = 0; i < 6; i++)
            {
                printf("%02x%s", eth->h_source[i], i == 5 ? "" : ":");
            }
            printf("                       |\n"); // Fixed padding to keep the box aligned

            printf("|  %sDestination MAC%s : ", CYN, RESET);
            for (int i = 0; i < 6; i++)
            {
                printf("%02x%s", eth->h_dest[i], i == 5 ? "" : ":");
            }
            printf("                       |\n");

            printf("|  Eth-Protocol    : 0x%04x                                  |\n", ntohs(eth->h_proto));
            printf("+------------------------------------------------------------+\n");
            printf("|  %s[ LAYER 3 - INTERNET ]%s                                    |\n", CYN, RESET);
            printf("|  Source IP       : %-15s                         |\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
            printf("|  Destination IP  : %-15s                         |\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
            printf("|  IP-Protocol     : %-3d                                     |\n", ip->protocol);
            printf("+------------------------------------------------------------+%s\n\n", RESET);
        }
    }
    return 0;
}