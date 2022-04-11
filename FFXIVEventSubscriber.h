#ifndef __H_FFXIVEVENTSUBSCRIBER__
#define __H_FFXIVEVENTSUBSCRIBER__

#include "FFXIVDataframe.h"

#include "FFXIVEvent.h"
#include "FFXIVEventMap.h"
#include "FFXIVPacket.h"

struct FFXIVEventSubscriber {
  const char *name;
  struct FFXIVEventMap events;
};

void FFXIVEventSubscriber_subscribe(struct FFXIVEventSubscriber *subscriber,
                                    const unsigned int event_code,
                                    const ffxiv_event_handler_t handler) {
  FFXIVEventMap_insert(&subscriber->events, event_code, handler);
}

void FFXIVEventSubscriber_call(const struct FFXIVEventSubscriber *subscriber,
                               const unsigned int event_code,
                               const struct FFXIVDataframe *payload) {
  // Call events registered to ANY action first.
  FFXIVEventMap_call_events(&subscriber->events, FFXIV_EVENT_ANY, payload);
  FFXIVEventMap_call_events(&subscriber->events, event_code, payload);
}

#endif
