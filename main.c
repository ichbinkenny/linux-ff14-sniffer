#include "FFXIVActions.h"
#include "FFXIVDataframe.h"
#include "FFXIVEvent.h"
#include "FFXIVEventSubscriber.h"
#include "FFXIVSniffer.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

struct FFXIVEventSubscriber movement_subscriber;

void movement_handler(const struct FFXIVDataframe *dataframe) {
  printf("MOVEMENT DETECTED!!!\n");
}

void setup_movement_sub() {
  movement_subscriber.name = "Movement Subscriber";
  FFXIVEventSubscriber_subscribe(&movement_subscriber, FFXIV_ACTION_MOVEMENT,
                                 movement_handler);
}

void interrupt_handler(int signal_code) {
  printf("Killing ffxiv sniffer...\n");
  FFXIVSniffer_stop(&ffxiv_sniffer);
  exit(0);
}

int main(void) {
  // handle ctrl-c event to clean up
  signal(SIGINT, interrupt_handler);
  // try to start sniffer with no specs
  setup_movement_sub();
  FFXIVSniffer_add_subscriber(&ffxiv_sniffer, &movement_subscriber);
  printf("Starting ffxiv sniffer status: %d\n",
         FFXIVSniffer_start(&ffxiv_sniffer));
  printf("Pcap is using interface: %s\n",
         ffxiv_sniffer.sniffing_interface->name);
  return EXIT_SUCCESS;
}
