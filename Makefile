all: arp_spoofing

arp_spoofing: main.o
	g++ -o arp_spoofing main.o -lpcap

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f *.o
	rm -f arp_spoofing
