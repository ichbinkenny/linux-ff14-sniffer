#ifndef __H_FFXIVDATAFRAME__
#define __H_FFXIVDATAFRAME__

#include "FFXIVConversions.h"

struct FFXIVDataframeHeader {
  const unsigned short action;
  const unsigned short server_id;
  const unsigned int timestamp;
};

struct FFXIVDataframe {
  const unsigned int size;
  const unsigned int actor_id;
  const unsigned int target_id;
  const unsigned short segment_type;
  const struct FFXIVDataframeHeader dataframe_header;
  const unsigned char *data;
};

struct FFXIVDataframeHeader
createFFXIVDataframeHeader(const unsigned char *data) {
  struct FFXIVDataframeHeader header = {
      .action = U16FromBytesLE(&data[2]),
      .server_id = U16FromBytesLE(&data[6]),
      .timestamp = U32FromBytesLE(&data[8], 4),
  };
  return header;
}

struct FFXIVDataframe createFFXIVDataframe(const unsigned char *data) {
  struct FFXIVDataframe dataframe = {
      .size = U32FromBytesLE(&data[0], 4),
      .actor_id = U32FromBytesLE(&data[4], 4),
      .target_id = U32FromBytesLE(&data[8], 4),
      .segment_type = U16FromBytesLE(&data[12]),
      .dataframe_header = createFFXIVDataframeHeader(&data[16]),
      .data = &data[32],
  };

  return dataframe;
}

#endif
