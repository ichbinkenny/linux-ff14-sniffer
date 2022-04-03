#ifndef __FFXIVSNIFFER_H__
#define __FFXIVSNIFFER_H__

#include "FFXIVDataframe.h"
#include "FFXIVEventSubscriber.h"
#include "FFXIVPacket.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <string.h>

#define MAX_SNIFFER_BUFFER_SIZE 1024
#ifdef __APPLE__
#define FFXIV_SNIFFER_TIMEOUT 0
#endif
#ifdef __linux__
#define FFXIV_SNIFFER_TIMEOUT -1
#endif

#define FFXIV_MAX_NUM_SUBSCRIBERS 100

const char *FFXIV_FILTERS = "host 204.2.229.0/24";

enum SniffingStatus { Stopped, Running, Closed };

struct FFXIVSniffer {
  pcap_if_t *sniffing_interface;
  pcap_t *live_device;
  enum SniffingStatus sniffing_status;
  pcap_handler callback;
  struct bpf_program bpf_prog;
  bpf_u_int32 ip_addr;
  int current_index;
  u_char *current_packet;
  u_char *packet_buffer[MAX_SNIFFER_BUFFER_SIZE];
  unsigned int num_subscribers;
  const struct FFXIVEventSubscriber *subscribers[FFXIV_MAX_NUM_SUBSCRIBERS];
};

struct FFXIVSniffer ffxiv_sniffer;

/**
 * Default sniffing function for FFXIV. This queues up each message into a
 *buffer, and then alerts all subscribers that are registered to handle a
 *specific message type.
 *
 * For example: if a subscriber is registered to handle movement events (0x169),
 * it's handler function will be called anytime a packet is read with the 0x169
 *header.
 **/
void callback(unsigned char *args, const struct pcap_pkthdr *header,
              const unsigned char *packet) {
  // Packet contains ALL the data, including headers for each layer.
  struct ether_header *eth_header = (struct ether_header *)packet;

  struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
  struct tcphdr *tcp_hdr =
      (struct tcphdr *)(packet + sizeof(struct ether_header) +
                        (ip_hdr->ip_hl * 4));
  const unsigned char *payload = packet + sizeof(struct ether_header) +
                                 (ip_hdr->ip_hl * 4) + (tcp_hdr->th_off * 4);

  struct FFXIVPacket ffxiv_packet = FFXIVPacket_from_data(payload);
  if (ffxiv_packet.is_valid_packet == FFXIV_PACKET_VALID) {
    // TODO extract segment type
    struct FFXIVDataframe dataframe = createFFXIVDataframe(ffxiv_packet.data);
    for (int i = 0; i < ffxiv_sniffer.num_subscribers; ++i) {
      FFXIVEventSubscriber_call(ffxiv_sniffer.subscribers[i],
                                dataframe.dataframe_header.action, &dataframe);
    }
    // TODO alert subscribers belonging to action type
  }
}

/***
 * Starts a sniffing process. If no interface name is set in the FFXIVSniffer,
 * then the interface will be set to the first available device.
 *
 * If the device is not already sniffing, it will start.
 *
 * Returns 0 if the device was opened, -1 on error.
 */
int FFXIVSniffer_start(struct FFXIVSniffer *sniffer) {
  pcap_if_t *all_interfaces[PCAP_BUF_SIZE];
  char error[BUFSIZ];
  int status_code = 0;
  if (NULL == sniffer->sniffing_interface) {
    pcap_findalldevs(all_interfaces, error);
    if (NULL == all_interfaces[0]) {
      status_code = -1;
    } else {
      printf("Setting live device to first available one!\n");
      sniffer->sniffing_interface = all_interfaces[0];
      sniffer->live_device =
          pcap_open_live(sniffer->sniffing_interface->name, BUFSIZ, 0,
                         FFXIV_SNIFFER_TIMEOUT, error);
      if (NULL == sniffer->live_device) {
        status_code = -1;
        printf("Err: failed to start FFXIVSniffer: %s\n", error);
      } else {
        // Compile the filters
        pcap_compile(sniffer->live_device, &sniffer->bpf_prog, FFXIV_FILTERS, 0,
                     sniffer->ip_addr);
        pcap_setfilter(sniffer->live_device, &sniffer->bpf_prog);
        if (sniffer->callback != NULL) {
          pcap_loop(sniffer->live_device, -1, sniffer->callback, NULL);
        } else {
          pcap_loop(sniffer->live_device, -1, &callback, NULL);
        }
      }
    }
  }
  return status_code;
}

/***
 * Stops a sniffing process and closes the live device.
 * returns 0 if the device was found and closed, -1 otherwise.
 ***/
int FFXIVSniffer_stop(struct FFXIVSniffer *sniffer) {
  int status_code = -1;
  if (NULL != sniffer->live_device) {
    pcap_close(sniffer->live_device);
    status_code = 0;
  }
  return status_code;
}

/***
 * Sets the function called on a packet received to the provided callback.
 ***/
void FFXIVSniffer_set_cb(struct FFXIVSniffer *sniffer, pcap_handler cb_func) {
  sniffer->callback = cb_func;
}

/***
 * Attempts to add a new event subscriber to the sniffer collection.
 * Returns 0 on success, and -1 if the subscribers list is full.
 **/
int FFXIVSniffer_add_subscriber(struct FFXIVSniffer *sniffer,
                                const struct FFXIVEventSubscriber *subscriber) {
  if (sniffer->num_subscribers >= FFXIV_MAX_NUM_SUBSCRIBERS) {
    return -1;
  }
  sniffer->subscribers[sniffer->num_subscribers] = subscriber;
  sniffer->num_subscribers++;
  return 0;
}

#endif
