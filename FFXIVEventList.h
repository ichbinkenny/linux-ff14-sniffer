#ifndef __H_FFXIVEVENTLIST__
#define __H_FFXIVEVENTLIST__

#include "FFXIVDataframe.h"
#include "FFXIVEvent.h"
#include <stdio.h>
#include <stdlib.h>

#define MAX_EVENT_HANDLERS 100

struct FFXIVEventList {
  unsigned int num_entries;
  ffxiv_event_handler_t events[MAX_EVENT_HANDLERS];
};

struct FFXIVEventList createFFXIVEventList() {
  struct FFXIVEventList list;
  return list;
}

/**
 * Attempts to add an event handler to this event list.
 * If the event is added, a 0 is returned.
 * If an error occurs, or the list has a maximum number of entries
 * then a status of -1 is returned.
 **/
int FFXIVEventList_add_event(struct FFXIVEventList *list,
                             const ffxiv_event_handler_t event) {
  printf("Trying to add event to event list %p\n", list);
  if (list->num_entries >= MAX_EVENT_HANDLERS) {
    printf("List is full!\n");
    return -1; // there are already too many events registered in this list.
  }
  printf("Adding event at %p to list!\n", event);
  list->events[list->num_entries] = event;
  list->num_entries++;
  return 0;
}

/***
 * Executes all events in a specified event list with a provided dataframe.
 **/
void FFXIVEventList_call(const struct FFXIVEventList *list,
                         const struct FFXIVDataframe *dataframe) {
  int i;
  // TODO make this multithread to improve performance?
  for (i = 0; i < list->num_entries; ++i) {
    list->events[i](dataframe);
  }
}

#endif
