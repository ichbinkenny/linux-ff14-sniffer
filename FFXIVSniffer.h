#ifndef __FFXIVSNIFFER_H__
#define __FFXIVSNIFFER_H__

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <string.h>

#define MAX_SNIFFER_BUFFER_SIZE 1024
#define FFXIV_SNIFFER_TIMEOUT -1

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
};

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
      } else if (sniffer->callback != NULL) {
        // Compile the filters
        pcap_compile(sniffer->live_device, &sniffer->bpf_prog, FFXIV_FILTERS, 0,
                     sniffer->ip_addr);
        pcap_setfilter(sniffer->live_device, &sniffer->bpf_prog);
        pcap_loop(sniffer->live_device, -1, sniffer->callback, NULL);
      } else {
        printf(
            "Err: no callback has been set. Please set one, and then retry.\n");
        status_code = -1;
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

#endif
