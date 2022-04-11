#ifndef __H_FFXIVEVENT__
#define __H_FFXIVEVENT__

#include "FFXIVDataframe.h"

typedef void (*ffxiv_event_handler_t)(const struct FFXIVDataframe *dataframe);

enum FFXIVEvents {
  FFXIV_EVENT_ANY = 0,
};

#endif
