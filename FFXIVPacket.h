#ifndef __H_FFXIVPACKET__
#define __H_FFXIVPACKET__

#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>

#include "FFXIVConversions.h"
#include "FFXIVWorldInfo.h"

#define FFXIV_ENCRYPTED 1
#define FFXIV_UNENCRYPTED 0

const unsigned char FFXIV_PACKET_IDENTIFIER[8] = {0x52, 0x52, 0xa0, 0x41,
                                                  0xff, 0x5d, 0x46, 0xe2};

enum FFXIVPacketStatus {
  FFXIV_PACKET_INVALID = 0x3f,
  FFXIV_PACKET_VALID = 0xae,
};

const unsigned char FFXIV_MIN_PACKET_LEN = 40;

struct FFXIVPacket {
  unsigned char magic[16];
  unsigned long epoch_time; // this is unsigned as the server time wil // always
                            // be ahead of epoch
  unsigned int length;
  unsigned short connection_type;
  unsigned short segment_count;
  unsigned char is_compressed;
  unsigned char *data;
  unsigned char is_valid_packet;
};

const unsigned char FFXIVPacket_validate(const unsigned char *packet_data) {
  int i;
  for (i = 0; i < sizeof(FFXIV_PACKET_IDENTIFIER); ++i) {
    if (packet_data[i] != FFXIV_PACKET_IDENTIFIER[i]) {
      return FFXIV_PACKET_INVALID;
    }
  }
  return FFXIV_PACKET_VALID;
}

const char *FFXIVPacket_get_server_name(const uint32_t server_address) {
  return FFXIVWorld_get_name_from_IP(server_address);
}

struct FFXIVPacket FFXIVPacket_from_data(const unsigned char *packet_data) {
  struct FFXIVPacket ffxiv_packet = {
      .magic = {packet_data[0], packet_data[1], packet_data[2], packet_data[3],
                packet_data[4], packet_data[5], packet_data[6], packet_data[7],
                packet_data[8], packet_data[9], packet_data[10],
                packet_data[11], packet_data[12], packet_data[13],
                packet_data[14], packet_data[15]},
      .epoch_time = toFFXIVServerTime(&packet_data[16]),
      .length = packet_data[24],
      .connection_type = U16FromBytesLE(&packet_data[28]),
      .segment_count = U16FromBytesLE(&packet_data[30]),
      .is_compressed = packet_data[33] == FFXIV_ENCRYPTED,
      .data = (unsigned char *)&packet_data[40],
      .is_valid_packet = FFXIVPacket_validate(packet_data),
  };
  return ffxiv_packet;
}

#endif
