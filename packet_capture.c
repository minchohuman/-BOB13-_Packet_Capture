// 송수신되는 packet을 capture하여 중요 정보를 출력하는 C/C++ 기반 프로그램을 작성하라.

//1. Ethernet Header의 src mac / dst mac
//2. IP Header의 src ip / dst ip
//3. TCP Header의 src port / dst port
//4. Payload(Data)의 hexadecimal value(최대 20바이트까지만)

//**** Digital Forensics 김도현(2226), of BOB 13th ****
// MUST INSTALL -> sudo apt-get install libpcap-dev

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <string.h>

// Ethernet addresses are 6 bytes
#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14

// Ethernet header
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; // Destination host address
    u_char ether_shost[ETHER_ADDR_LEN]; // Source host address
    u_short ether_type; // IP? ARP? RARP? etc
};

// IP header
struct sniff_ip {
    u_char ip_vhl; // version << 4 | header length >> 2
    u_char ip_tos; // type of service
    u_short ip_len; // total length
    u_short ip_id; // identification
    u_short ip_off; // fragment offset field
    u_char ip_ttl; // time to live
    u_char ip_p; // protocol
    u_short ip_sum; // checksum
    struct in_addr ip_src, ip_dst; // source and dest address
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)

// TCP header
struct sniff_tcp {
    u_short th_sport; // source port
    u_short th_dport; // destination port
    u_int32_t th_seq; // sequence number
    u_int32_t th_ack; // acknowledgement number
    u_char th_offx2; // data offset, rsvd
    #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
    u_short th_win; // window
    u_short th_sum; // checksum
    u_short th_urp; // urgent pointer
};

// Callback function that is called each time a packet is captured
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct sniff_ethernet *ethernet; // The ethernet header
    const struct sniff_ip *ip; // The IP header
    const struct sniff_tcp *tcp; // The TCP header
    const char *payload; // Packet payload

    int size_ip;
    int size_tcp;
    int size_payload;

    // Define ethernet header
    ethernet = (struct sniff_ethernet*)(packet);

    // Define/compute IP header offset
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    // Define/compute TCP header offset
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        printf("Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    // Define/compute payload offset
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    // Compute payload size
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    // Print source and destination MAC addresses
    printf("Ethernet Header\n");
    printf("   Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet->ether_shost[0],
           ethernet->ether_shost[1],
           ethernet->ether_shost[2],
           ethernet->ether_shost[3],
           ethernet->ether_shost[4],
           ethernet->ether_shost[5]);
    printf("   Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet->ether_dhost[0],
           ethernet->ether_dhost[1],
           ethernet->ether_dhost[2],
           ethernet->ether_dhost[3],
           ethernet->ether_dhost[4],
           ethernet->ether_dhost[5]);

    // Print source and destination IP addresses
    printf("IP Header\n");
    printf("   Src IP: %s\n", inet_ntoa(ip->ip_src));
    printf("   Dst IP: %s\n", inet_ntoa(ip->ip_dst));

    // Print source and destination ports
    printf("TCP Header\n");
    printf("   Src Port: %d\n", ntohs(tcp->th_sport));
    printf("   Dst Port: %d\n", ntohs(tcp->th_dport));

    // Print payload in hexadecimal
    printf("Payload\n");
    if (size_payload > 0) {
        int len = size_payload < 20 ? size_payload : 20;
        for (int i = 0; i < len; i++) {
            printf("%02x ", (unsigned char)payload[i]);
        }
        printf("\n");
    }
}

// Main function
int main(int argc, char *argv[]) {
    char *dev = NULL; // capture device name
    char errbuf[PCAP_ERRBUF_SIZE]; // error buffer
    pcap_t *handle; // packet capture handle

    // Define the device
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 2;
    }
    printf("Device: %s\n", dev);

    // Open the session in promiscuous mode
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // Compile and apply the filter
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    // Close the session
    pcap_close(handle);
    return 0;
}

