HEADER_LOCATIONS=-I/home/kenny/CLibs/STC/include -I/usr/local/include -I/usr/include
HEADER_FILES=FFXIVSniffer.h
all:
	clang -o pcap_interfacing main.c -lpcap ${HEADER_LOCATIONS}

clean:
	rm pcap_interfacing
