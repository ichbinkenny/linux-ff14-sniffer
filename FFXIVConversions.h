#ifndef __H_FFXIVCONVERSIONS__
#define __H_FFXIVCONVERSIONS__

#define FFXIV_TIME_SIZE 8

#include <arpa/inet.h>

/**
 * This header includes methods to assist with converting FFXIV
 * packet data (in char[] format) to more meaningful structures.
 **/

/**
 * Converts a char array of LE bytes to an unsigned short.
 **/
unsigned short U16FromBytesLE(const unsigned char *data) {
  return data[1] << 8 | data[0];
}

/**
 * Returns a u32 from a little endian character array
 **/
unsigned int U32FromBytesLE(const unsigned char *data,
                            const unsigned char num_bytes) {
  int i;
  unsigned int u32_val = 0;
  for (i = 0; i < num_bytes; i++) {
    u32_val |= data[i] << (i * 8);
  }
  return u32_val;
}

/**
 * Converts a char array of LE bytes to a uint64 (unsigned long)
 * WARNING: this function expects 8 bytes. Behavior for any other
 * number of bytes is undefined!
 **/
unsigned long U64FromBytesLE(const unsigned char *data,
                             const unsigned char num_bytes) {
  return U32FromBytesLE(&data[4], num_bytes - 4) << 32 |
         U32FromBytesLE(&data[0], 4);
}

/**
 * Converts a character array into its respective Epoch time.
 * If no valid time is passed, or data is empty, a default
 * value of 0 is returned.
 **/
unsigned long toFFXIVServerTime(const unsigned char *data) {
  if (sizeof(data) < FFXIV_TIME_SIZE) {
    return 0;
  }
  unsigned long time = U64FromBytesLE(&data[0], FFXIV_TIME_SIZE);
  return time;
}

/**
 *
 **/

#endif
