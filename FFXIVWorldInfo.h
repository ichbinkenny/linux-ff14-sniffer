#ifndef __H_FFXIVWORLDINFO__
#define __H_FFXIVWORLDINFO__

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *FFXIVWorld_get_name_from_IP(const uint32_t ipaddr) {
  char address[16];
  inet_ntop(AF_INET, &ipaddr, address, 16);
  if (strcmp(address, "204.2.229.84") == 0) {
    return "Cactuar";
  }
  return "UNKNOWN";
}

#endif
