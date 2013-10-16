#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // close()
#include <string.h> // strcpy, memset(), and memcpy()
#include <netdb.h> // struct addrinfo
#include <sys/types.h> // needed for socket()
#include <sys/socket.h> // needed for socket()
#include <netinet/in.h> // IPPROTO_RAW
#include <netinet/ip.h> // IP_MAXPACKET (which is 65535)
#include <arpa/inet.h> // inet_pton() and inet_ntop()
#include <sys/ioctl.h> // macro ioctl is defined
#include <bits/ioctls.h> // defines values for argument "request" of ioctl.
#include <net/if.h> // struct ifreq
#include <linux/if_ether.h> // ETH_P_ARP = 0x0806
#include <linux/if_packet.h> // struct sockaddr_ll
#include <net/ethernet.h>
#include <errno.h> // errno, perror()

#include <time.h>

/**Configure these**/
#define SOURCE_ADDRESS "192.168.1.116" // This computer's IP Address
#define INTERFACE "eth0" // Output device
#define ONLY_ARP_REQ_LOCAL 1 // Only send ARP requests for IPs in 192.168.*.* range

#define ARP_HDRLEN 28 // ARP header length
#define ARPOP_REQUEST 1 // OpCode for ARP Request

#define CHECK_MEM_ERR(ptr) if (ptr == NULL) {fprintf(stderr, "Fatal: Memory Allocation Error\n"); exit(-1);}

time_t timer;

char **ip_table = NULL;
int ip_table_size = 1;
int ip_table_count = 0;

// Globals to store the MAC address found in an ARP Reply message
char ARP_MAC_address[1024];
int ARP_is_reply = 0;

typedef enum {
    UNKNOWN,
    TCP,
    ARP,
    IP,
    IP6,
} packet_t;

struct arp_hdr {
    unsigned short htype;
    unsigned short ptype;
    unsigned char hlen;
    unsigned char plen;
    unsigned short opcode;
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
};

int seen_ip(char *ip) {
    int i;
    for (i = 0; i < ip_table_count; i++) {
        if (strcmp(ip, ip_table[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

int add_ip(char *ip) {
    if (seen_ip(ip)) return 0;

    if (ip_table_count >= ip_table_size) {
        ip_table_size = ip_table_count * 2;
        ip_table = (char**) realloc((void*) ip_table, sizeof(char*) * ip_table_size);
        CHECK_MEM_ERR(ip_table);
    }
    ip_table[ip_table_count] = ip;
    ip_table_count++;
    return 1;
}

void init_ip_table() {
    ip_table = (char**) malloc(sizeof(char*) * ip_table_size);
    CHECK_MEM_ERR(ip_table);
}

void arp_request(char *ip) {
    if (!add_ip(ip)) {
        free(ip);
        return;
    }
    printf("Sending ARP Request for: %s\n", ip);

    // Send ARP Request for new IP Address
    char *interface, *src_ip, *dest_ip;
    int sockfd, status, frame_length, bytes;
    struct ifreq *ifr;
    unsigned char *src_mac, *dest_mac, *ether_frame;
    struct sockaddr_ll *device;
    struct addrinfo *hints, *result;
    struct sockaddr_in *ipv4;
    struct arp_hdr *arp_hdr;
    
    // Use calloc to automatically zero out stuff for sockets (I don't trust that stuff)
    interface = (char*) calloc(40, sizeof(char));
    CHECK_MEM_ERR(interface);
    strcpy(interface, INTERFACE);
    
    ifr = (struct ifreq*) calloc(1, sizeof(struct ifreq));
    CHECK_MEM_ERR(ifr);
    
    src_mac = (unsigned char*) calloc(6, sizeof(unsigned char));
    CHECK_MEM_ERR(src_mac);
    
    dest_mac = (unsigned char*) calloc(6, sizeof(unsigned char));
    CHECK_MEM_ERR(dest_mac);
    memset(dest_mac, 0xff, 6); // set to broadcast address
    
    device = (struct sockaddr_ll*) calloc(1, sizeof(struct sockaddr_ll));
    CHECK_MEM_ERR(device);
    
    src_ip = (char*) calloc(16, sizeof(char));
    CHECK_MEM_ERR(src_ip);
    strcpy(src_ip, SOURCE_ADDRESS);
    
    dest_ip = (char*) calloc(40, sizeof(char));
    CHECK_MEM_ERR(dest_ip);
    strncpy(dest_ip, ip, 40);
    
    hints = (struct addrinfo*) calloc(1, sizeof(struct addrinfo));
    CHECK_MEM_ERR(hints);
    
    arp_hdr = (struct arp_hdr*) calloc(1, sizeof(struct arp_hdr));
    CHECK_MEM_ERR(arp_hdr);
    
    ether_frame = (unsigned char*) calloc(IP_MAXPACKET, sizeof(unsigned char));
    CHECK_MEM_ERR(ether_frame);
    
    // Open a socket to look up MAC Address of the interface
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket() failed");
        exit(-1);
    }
    
    // Get source MAC address
    snprintf(ifr->ifr_name, sizeof(ifr->ifr_name), "%s", interface);
    if (ioctl(sockfd, SIOCGIFHWADDR, ifr) < 0) {
        perror("ioctl() failed to obtain source MAC address");
        exit(-1);
    }
    close(sockfd);

    // Copy in source MAC address
    memcpy(src_mac, ifr->ifr_hwaddr.sa_data, 6);
    
    // Find interface index from interface name
    if ((device->sll_ifindex = if_nametoindex (interface)) == 0) {
        perror("if_nametoindex() failed to obtain interface index");
        exit(-1);
    }
    
    // Fill out hints for getaddrinfo
    hints->ai_family = AF_INET;
    hints->ai_socktype = SOCK_STREAM;
    hints->ai_flags = hints->ai_flags | AI_CANONNAME;
    
    // Resolve source
    if ((status = getaddrinfo(src_ip, NULL, hints, &result)) != 0) {
        fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(status));
        exit(-1);
    }
    ipv4 = (struct sockaddr_in*) result->ai_addr;
    memcpy(&(arp_hdr->sender_ip), &(ipv4->sin_addr), 4);
    freeaddrinfo(result);
    
    memset(ipv4, 0, sizeof(*ipv4));

    // Resolve destination
    if ((status = getaddrinfo(dest_ip, NULL, hints, &result)) != 0) {
        fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(status));
        exit(-1);
    }
    ipv4 = (struct sockaddr_in*) result->ai_addr;
    memcpy(&(arp_hdr->target_ip), &(ipv4->sin_addr), 4);
    freeaddrinfo(result);

    // Fill out sockaddr_ll
    device->sll_family = AF_PACKET;
    memcpy(device->sll_addr, src_mac, 6);
    device->sll_halen = htons(6);
    
    /*
     ARP header
    */
    
    // Hardware type (ethernet)
    arp_hdr->htype = htons(1);
    // Protocol type (IP)
    arp_hdr->ptype = htons(ETH_P_IP);
    // Hardware address length (6 bytes for MAC address)
    arp_hdr->hlen = 6;
    // Protocol address length (4 bytes for IPv4)
    arp_hdr->plen = 4;
    // OpCode (1 for ARP request)
    arp_hdr->opcode = htons(ARPOP_REQUEST);
    // Sender hardware address (MAC address)
    memcpy(&arp_hdr->sender_mac, src_mac, 6);
    // Target hardware address (0 for unknown)
    memset(&arp_hdr->target_mac, 0, 6);
    
    /*
     Ethernet frame
    */
    
    // Ethernet frame header (length = MAC + MAC + ethernet_type + ethernet_data
    frame_length = 6 + 6 + 2 + ARP_HDRLEN;
    // Destination and source MAC addresses
    memcpy(ether_frame, dest_mac, 6);
    memcpy(ether_frame + 6, src_mac, 6);
    // Ethernet type code (ETH_P_ARP for ARP)
    ether_frame[12] = ETH_P_ARP / 256;
    ether_frame[13] = ETH_P_ARP % 256;
    // ARP header
    memcpy(ether_frame+14, arp_hdr, ARP_HDRLEN);
    
    /*
     Send ethernet frame
    */
    if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket() for ethernet packet failed");
        exit(-1);
    }
    if ((bytes = sendto(sockfd, ether_frame, frame_length, 0,
            (struct sockaddr*) device, sizeof(*device))) <= 0) {
        perror("sendto() failed");
        exit(-1);
    }
    
    // Cleanup
    close(sockfd);
    free(interface);
    free(src_ip);
    free(dest_ip);
    free(ifr);
    free(src_mac);
    free(dest_mac);
    free(ether_frame);
    free(device);
    free(hints);
    free(arp_hdr);    
    
    // Update current time
    time(&timer);
    return;
}

char** parse_TCP(char *pkt, int *count) {
    // Don't know what these look like, just treat as error for now
    return NULL;
}

#define ARP_PKT_COUNT 2
char** parse_ARP(char *pkt, int *count) {
    // Parse an ARP packet for IPs
    int i;
    char **IPs = (char**) malloc(sizeof(char*) * ARP_PKT_COUNT);
    CHECK_MEM_ERR(IPs);

    if (strncmp(pkt, "Request", strlen("Request")) == 0) {
        // Allocate room for 2 IPs
        for (i = 0; i < ARP_PKT_COUNT; i++) {
            IPs[i] = (char*) malloc(sizeof(char) * 1024);
            CHECK_MEM_ERR(IPs[i]);
        }

        // Try and parse the IPs
        if (sscanf(pkt, "Request who-has %1023s tell %1023[^,]s, ", IPs[0], IPs[1]) != 2) {
            // Format did not match?
            fprintf(stderr, "Error parsing ARP Request packet: ");
            for (i = 0; i < ARP_PKT_COUNT; i++) {
                free(IPs[i]);
            }
            free(IPs);
            return NULL;
        }
        *count = 2;
        return IPs;
    } else if (strncmp(pkt, "Reply", strlen("Reply")) == 0) {
        // Allocate room for 1 IP
        IPs[0] = (char*) malloc(sizeof(char) * 1024);
        CHECK_MEM_ERR(IPs);
        if (sscanf(pkt, "Reply %1023s is-at %1023[^,]s, ", IPs[0], ARP_MAC_address) != 2) {
            // Format did not match?
            fprintf(stderr, "Error parsing ARP Reply packet: ");
            free(IPs[0]);
            free(IPs);
            return NULL;
        }
        ARP_is_reply = 1;
        *count = 1;
        return IPs;
    }
    fprintf(stderr, "Error parsing ARP packet: ");
    free(IPs);
    return NULL;
}

#define IP_PKT_COUNT 2
char** parse_IP(char *pkt, int *count) {
    // Parse an IP packet for IPs
    int i;
    char **IPs = (char**) malloc(sizeof(char*) * IP_PKT_COUNT);
    CHECK_MEM_ERR(IPs);

    for (i = 0; i < IP_PKT_COUNT; i++) {
        IPs[i] = (char*) malloc(sizeof(char) * 1024);
        CHECK_MEM_ERR(IPs[i]);
    }

    // Parse IP line for src and dest address (throw away rest)
    if (sscanf(pkt, "%1023s > %1023[^:]s ", IPs[0], IPs[1]) != 2) {
        fprintf(stderr, "Error parsing IP packet: ");
        for (i = 0; i < IP_PKT_COUNT; i++) {
            free(IPs[i]);
        }
        free(IPs);
        return NULL;
    }
    *count = IP_PKT_COUNT;
    return IPs;
}

char** parse_IP6(char *pkt, int *count) {
    // Parse an IP6 packet for IPs
    
    // Not currently supported
    *count = 0;
    return NULL;
}

void handle_line(char *ln) {
    /*
        Parse the given line for IP Addresses,
        then send ARP requests for any new/unrecognized IP Addresses
    */
    int i;
    char line[1024];
    strncpy(line, ln, 1024);
    
    packet_t type = UNKNOWN;
    char timestamp[1024];
    char pkt_type[1024];
    char rest[1024];
    
    // partially parse the packet for timestamp and type
    if (sscanf(line, "%1023s %1023s %1023[^\n]", timestamp, pkt_type, rest) != 3) {
        fprintf(stderr, "Unable to parse string:\n%s\n", ln);
        return;
    }
    
    // We don't care about the timestamp; get packet type
    if (strcmp(pkt_type, "TCP") == 0) {
        type = TCP;
    } else if (strcmp(pkt_type, "ARP,") == 0) {
        type = ARP;
    } else if (strcmp(pkt_type, "IP") == 0) {
        type = IP;
    } else if (strcmp(pkt_type, "IP6") == 0) {
        type = IP6;
    }

    // Parse the packet for IP Addresses
    char **IPs;
    int IP_count = -1;
    switch(type) {
    case TCP:
        IPs = parse_TCP(rest, &IP_count);
        break;
    case ARP:
        IPs = parse_ARP(rest, &IP_count);
        break;
    case IP:
        IPs = parse_IP(rest, &IP_count);
        break;
    case IP6:
        IPs = parse_IP6(rest, &IP_count);
        break;
    case UNKNOWN: // fall through
    default:
        fprintf(stderr, "Unknown packet type: %s\n\t%s\n", pkt_type, ln);
        return;
    }

    if (IP_count == -1) {
        fprintf(stderr, "%s\n", ln);
        return;
    }
    
    // filter nonlocal IP addresses and send ARP request for new addresses
    for (i = 0; i < IP_count; i++) {
        int a, b, c, d;

        // Parse first four numbers
        // This is because some packets are logged with port number,
        // e.g. 192.168.0.1.80
        if (sscanf(IPs[i], "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
            fprintf(stderr, "Error parsing IP %s received from packet %s\n", IPs[i], ln);
            free(IPs);
            return;
        }

        // Check to see if this address is 192.168.*.*
        if (ONLY_ARP_REQ_LOCAL && (a != 192 || b != 168)) continue;

        // Turn address back into string for sending an arp request
        char *ip = (char*) malloc(sizeof(char) * 1024);
        CHECK_MEM_ERR(ip);
        sprintf(ip, "%d.%d.%d.%d", a, b, c, d);

        // Send arp request (will automatically check if address is new)
        arp_request(ip);
    }
    // Free addresses that we are no longer using
    free(IPs);
}

int main(int argc, char **argv) {
    int i;
    char line[1024];

    init_ip_table();
    
    // Start timer
    time(&timer);
    while(1) {
        // Read line from stdin
        gets(line);

        // Quit when we reach end of file
        if (feof(stdin)) break;
        
        // Quit when 5 minutes have passed
        if (difftime(timer, time(NULL)) > 60 * 5) break;

        // Reset ARP reply flag
        ARP_is_reply = 0;
        
        // Parse and handle line
        handle_line(line);
    }
    
    // Free up memory (to make valgrind happy)
    for (i = 0; i < ip_table_count; i++) {
        free(ip_table[i]);
    }
    free(ip_table);
    return 0;
}
