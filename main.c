#include "FFXIVDataframe.h"
#include "FFXIVPacket.h"
#include "FFXIVSniffer.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>

struct FFXIVSniffer sniffer;

void callback(unsigned char *args, const struct pcap_pkthdr *header,
              const unsigned char *packet) {
  // Packet contains ALL the data, including headers for each layer.
  struct ether_header *eth_header = (struct ether_header *)packet;
  struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
  struct tcphdr *tcp_hdr =
      (struct tcphdr *)(packet + sizeof(struct ether_header) +
                        sizeof(struct iphdr));
  const unsigned char *payload = packet + sizeof(struct ether_header) +
                                 (ip_hdr->ihl * 4) + (tcp_hdr->doff * 4);
  struct FFXIVPacket ffxiv_packet = FFXIVPacket_from_data(payload);
  if (ffxiv_packet.is_valid_packet == FFXIV_PACKET_VALID) {
    struct FFXIVDataframe ffxiv_dataframe =
        createFFXIVDataframe(ffxiv_packet.data);
    printf("FFXIV Action type: 0x%x\n",
           ffxiv_dataframe.dataframe_header.action);
  }
}

int main(void) {
  sniffer.callback = &callback;
  // try to start sniffer with no specs
  printf("Starting ffxiv sniffer status: %d\n", FFXIVSniffer_start(&sniffer));
  printf("Pcap is using interface: %s\n", sniffer.sniffing_interface->name);
  return EXIT_SUCCESS;
}
