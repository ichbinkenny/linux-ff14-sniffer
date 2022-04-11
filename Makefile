HEADER_LOCATIONS=-I/usr/local/include -I/usr/include
HEADER_FILES=FFXIVSniffer.h
all:
	clang -o linux-ff14-sniffer main.c -lpcap ${HEADER_LOCATIONS}
	echo "On linux, you will need to run sudo setcap cap_net_raw,cap_net_admin+eip linux-ff14-sniffer to properly use the binary. This command simply allows a normal user to access the system network interfaces for creating and using the sniffer."

clean:
	rm linux-ff14-sniffer
