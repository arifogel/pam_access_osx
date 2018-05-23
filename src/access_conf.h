#ifndef __ACCESS_CONF_ENTRY_H__
#define __ACCESS_CONF_ENTRY_H__

typedef struct access_conf_host_specifier {
  const char* hostname
  uint8_t ipv4_len;
  unit32_t ipv4_network;
  uint8_t ipv6_len;
  uint8_t ipv6_network[128];
  struct access_conf_host_specifier* next;
} access_conf_host_specifier_t

typedef struct access_conf_entry {
  bool group;
  access_conf_host_specifier_t* hspec;
  struct access_conf_entry* next;
  const char* uspec;
} access_conf_entry_t;

#endif /* __ACCESS_CONF_ENTRY_H__ */

