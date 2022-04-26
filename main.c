#include "FFXIVActions.h"
#include "FFXIVDataframe.h"
#include "FFXIVEvent.h"
#include "FFXIVEventSubscriber.h"
#include "FFXIVSniffer.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

struct FFXIVEventSubscriber movement_subscriber;
struct FFXIVEventSubscriber unhandled_code_classifier;

uint8_t alerted_codes[65535] = {};

void movement_handler(const struct FFXIVDataframe *dataframe) {
  printf("MOVEMENT DETECTED!!!\n");
}

void unknown_classifier_handler(const struct FFXIVDataframe *dataframe) {
  // This classifier handles packets with information not specified that are
  // zone types.
  if (alerted_codes[dataframe->dataframe_header.action] == 0) {
	printf("Unknown code: 0x%x\n", dataframe->dataframe_header.action);
	alerted_codes[dataframe->dataframe_header.action] = 1;
  }
  if (dataframe->segment_type == FFXIV_SEGMENT_TYPE_ZONE) {
    printf("packet actor id: 0x%x\n", dataframe->actor_id);
    printf("packet target id: 0x%x\n", dataframe->target_id);
  }
}

void setup_movement_sub() {
  movement_subscriber.name = "Movement Subscriber";
  FFXIVEventSubscriber_subscribe(&movement_subscriber, FFXIV_ACTION_MOVEMENT,
                                 movement_handler);
}

void setup_default_subscriber() {
  unhandled_code_classifier.name = "Default Subscriber";
  FFXIVEventSubscriber_subscribe(&unhandled_code_classifier, FFXIV_ACTION_ANY,
                                 unknown_classifier_handler);
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
  setup_default_subscriber();
  FFXIVSniffer_add_subscriber(&ffxiv_sniffer, &movement_subscriber);
  FFXIVSniffer_add_subscriber(&ffxiv_sniffer, &unhandled_code_classifier);
  printf("Starting ffxiv sniffer status: %d\n",
         FFXIVSniffer_start(&ffxiv_sniffer));
  printf("Pcap is using interface: %s\n",
         ffxiv_sniffer.sniffing_interface->name);
  return EXIT_SUCCESS;
}
