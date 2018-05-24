#ifndef __ACCESS_CONF_ENTRY_H__
#define __ACCESS_CONF_ENTRY_H__

#include <stdbool.h>
#include <stdint.h>

typedef enum host_specifier_type {
  HST_ALL=1,
  HST_HOSTNAME,
  HST_IPV4_ADDRESS,
  HST_IPV4_NETWORK
} host_specifier_type_t;

typedef struct access_conf_host_specifier {
  char* hostname;
  uint8_t ipv4_len;
  uint32_t ipv4_network;
  uint8_t ipv6_len;
  uint8_t ipv6_network[128];
  struct access_conf_host_specifier* next;
  host_specifier_type_t type;
} access_conf_host_specifier_t;

typedef struct access_conf_entry {
  bool group;
  access_conf_host_specifier_t* hspec;
  struct access_conf_entry* next;
  bool permit;
  char* uspec;
} access_conf_entry_t;

#endif /* __ACCESS_CONF_ENTRY_H__ */

