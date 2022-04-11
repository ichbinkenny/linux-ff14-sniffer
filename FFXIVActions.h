#ifndef __H_FFXIVACTIONS__
#define __H_FFXIVACTIONS__

enum FFXIVActions {
  FFXIV_ACTION_ANY =
      0, // Note: ANY is a special value that is ALWAYS called. Use wisely.
  FFXIV_ACTION_MOVEMENT = 0x169,
};

enum FFXIVSegment_types {
  FFXIV_SEGMENT_TYPE_LOBBY = 0,
  FFXIV_SEGMENT_TYPE_ZONE = 1,
  FFXIV_SEGMENT_TYPE_CHAT = 2,
};

#endif
