all : send_arp

send_arp: arp_spoofing.o
	g++ -g -o send_arp arp_spoofing.o -lpcap

arp_spoofing.o:
	g++ -g -c -o arp_spoofing.o arp_spoofing.cpp

clean:
	rm -f send_arp
	rm -f *.o

