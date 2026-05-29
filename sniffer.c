#include <stdio.h>
#include <sys/socket.h> //for socket creation.
#include <unistd.h> //for closing the file descriptor
#include <string.h> //strncpy and strcat functions
#include <linux/if_ether.h> //ethernet structures.
#include <arpa/inet.h> //used to format network addresses to human readable format (ASCII).
#include <netinet/in.h> //contains htons/l and ntohs/l for swapping internet/host bytes.
#include <netinet/ip.h> //contains ip header structure.
#include <net/if.h> //contains the ifreq form for filling the name of the network interface card through which the communication will take place and setting the kernel to promiscous mode.
#include <sys/ioctl.h> //input output control for promiscous mode.
#include <netinet/tcp.h> //used for tcp header structure.
#include <ctype.h> //used for isprint command.


int main(){
    int fd; //file descriptor.
    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); //raw socket domain(AF_PACKET) allows for every packet on the card, SOCK_RAW for the raw communication desired, and ETH_P_ALL for every protocol to pass through, nothing to be left behind.
    if(fd < 0){
        perror("Socket not created!");
        return -1;
    }
    else printf("Socket created!\n");

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr)); //initialising form to empty.
    strncpy(ifr.ifr_name, "eth", IF_NAMESIZE-1); //replace eth with your ip network interface card name.
    //PUTTING THE TERMINAL IN PROMISCOUS MODE:
    if(ioctl(fd, SIOCGIFFLAGS, &ifr) < 0){ //Socket Input Output Can Get InterFace FLAGS.
        perror("ioctl");
        close(fd);
        return -1;
    }

    ifr.ifr_flags |= IFF_PROMISC; //setting 0 to 1.

    if(ioctl(fd, SIOCSIFFLAGS, &ifr) < 0){ //Socket Input Output Can Set InterFace FLAGS.
        perror("ioctl");
        close(fd);
        return -1;
    }

    unsigned char buffer[65536]; //array which stores the data packet's data.

    while(1){
        ssize_t data_size = read(fd, buffer, 65536); //size of the data packet.

        if(data_size < 0){
            perror("read error");
            break;
        }

        if(data_size < 34) continue; 

        struct ethhdr* eth = (struct ethhdr*)buffer; //eth header
        struct iphdr* ip = (struct iphdr*)(buffer + sizeof(struct ethhdr)); //ip header

        if(ntohs(eth->h_proto) != ETH_P_IP) continue; //if protocol is not ip

        unsigned char *mac_src, *mac_dest;

        char ip_src[INET_ADDRSTRLEN], ip_dest[INET_ADDRSTRLEN];

        mac_src = (unsigned char*)eth->h_source;
        mac_dest = (unsigned char*)eth->h_dest;

        int ip_hdr_len = ip->ihl * 4; //ihl is internet header length which gives us the number of 32 bit words in the ip header.
        //FILTERED OUT ICMP AND UDP PACKETS ONLY TCP PACKETS WERE SNIFFED.
        if(ip->protocol == IPPROTO_UDP || ip->protocol == IPPROTO_ICMP) continue;

        inet_ntop(AF_INET, &(ip->saddr), ip_src, INET_ADDRSTRLEN); //assigning the source address of the data packet to ip_src.
        inet_ntop(AF_INET, &(ip->daddr), ip_dest, INET_ADDRSTRLEN); //assigning the dest address of the data packet to ip_dest.

        struct tcphdr *tcp = (struct tcphdr*)((char*)ip + ip_hdr_len); //tcp header

        uint16_t src_prt = ntohs(tcp->source); //source port byte exchanging.
        uint16_t dest_prt = ntohs(tcp->dest); //dest port byte exchanging.
        //TCP flags for syn ack.
        char flags_str[64] = "";

        if(tcp->syn) strcat(flags_str, "SYN ");
        if(tcp->ack) strcat(flags_str, "ACK ");
        if(tcp->fin) strcat(flags_str, "FIN ");
        if(tcp->rst) strcat(flags_str, "RST ");
        if(tcp->urg) strcat(flags_str, "URG ");
        if(tcp->psh) strcat(flags_str, "PSH ");

        //printf("[TCP]: %s %d -> %s %d [%s]\n", ip_src, src_prt, ip_dest, dest_prt, flags_str); //can print this to see handshakes in real time.

        int tcp_hdr_len = tcp->doff * 4; //tcp header length.
        char *payload = buffer + 14 + (ip_hdr_len) + (tcp_hdr_len); //payload pointer.
        int payload_len = ntohs(ip->tot_len) - ((ip_hdr_len) + (tcp_hdr_len)); //payload length.
        //Hex dump loop:
        if(payload_len > 0){
            for(int i = 0; i < payload_len; i += 16){
                printf("%04x    ", i); //Printing the order of 16 byte lines.
                for(int j = 0; j < 16; j++){ //HEXADECIMAL LOOP
                    if((i + j) >= payload_len) printf("   "); //To prevent uneven formatting and overflowing.
                    else printf("%02x ", (unsigned char)payload[i + j]); //unsigned char in order to prevent ffffff78 printing format.
                }
                printf("    ");
                for (int k = 0; k < 16; k++) //ASCII LOOP
                {
                    if (i + k < payload_len)
                    {
                        char c = payload[i + k];
                        if (isprint((unsigned char)c)) //checking if the byte is printable in ASCII.
                        {
                            printf("%c", c);
                        }
                        else
                        {
                            printf("."); //if not printable
                        }
                    }
                    else
                    {
                        printf(" "); // Print blank padding space if past payload length
                    }
                }
                printf("\n");
            }
        }
        //printf("[Packet Size: %ld] | MAC: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x | IP: %s -> %s | [IP Header Size: %d]\n", data_size, mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5], mac_dest[0], mac_dest[1], mac_dest[2], mac_dest[3], mac_dest[4], mac_dest[5], ip_src, ip_dest, ip_hdr_len);
    }
    close(fd);
    return 0;
}