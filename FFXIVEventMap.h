#ifndef __H_FFXIVEVENTMAP__
#define __H_FFXIVEVENTMAP__

/***
 * This class implements a hashmap that allows FFXIVEvents to
 * be linked to a specific method handler
 ***/

#include "FFXIVDataframe.h"
#include "FFXIVEvent.h"
#include "FFXIVEventList.h"
#include <stdio.h>
#include <stdlib.h>

#define MAX_FFXIV_EVENT_COUNT 0xffff

struct FFXIVEventMap {
  struct FFXIVEventList *values[MAX_FFXIV_EVENT_COUNT];
  unsigned int num_entries[MAX_FFXIV_EVENT_COUNT];
};

void FFXIVEventMap_call_events(const struct FFXIVEventMap *event_map,
                               const unsigned int event_code,
                               const struct FFXIVDataframe *dataframe) {
  if (event_map->values[event_code] != NULL) {
    int i;
    for (i = 0; i < event_map->values[event_code]->num_entries; ++i) {
      event_map->values[event_code]->events[i](dataframe);
    }
  }
}

void FFXIVEventMap_insert(struct FFXIVEventMap *event_map,
                          const unsigned int event_code,
                          const ffxiv_event_handler_t event_handler) {
  if (event_map->values[event_code] == NULL) {
    struct FFXIVEventList list = createFFXIVEventList();
    list.num_entries = 0;
    event_map->values[event_code] = &list;
  }
  int status =
      FFXIVEventList_add_event(event_map->values[event_code], event_handler);
}

#endif
