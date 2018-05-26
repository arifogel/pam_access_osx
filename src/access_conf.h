#ifndef __ACCESS_CONF_ENTRY_H__
#define __ACCESS_CONF_ENTRY_H__

#include <arpa/inet.h>
#include <ip_util.h>
#include <stdbool.h>
#include <stdint.h>

typedef enum host_specifier_type {
  HST_ALL = 1,
  HST_HOSTNAME,
  HST_IPV4_NETWORK,
  HST_IPV6_NETWORK
} host_specifier_type_t;

typedef union host_info_id {
  char* hostname;
  ipv4_addr_t ip4;
  ipv6_addr_t ip6;
} host_info_id_t;

typedef struct host_info {
  host_info_id_t id;
  host_specifier_type_t type;
} host_info_t;

typedef struct access_conf_host_specifier {
  char* hostname;
  ip_network_t network;
  struct access_conf_host_specifier* next;
  host_specifier_type_t type;
} access_conf_host_specifier_t;

typedef struct access_conf_user_specifier {
  bool all;
  bool group;
  char* ug;
} access_conf_user_specifier_t;

typedef struct access_conf_entry {
  access_conf_host_specifier_t* hspec;
  struct access_conf_entry* next;
  bool permit;
  access_conf_user_specifier_t uspec;
} access_conf_entry_t;

access_conf_entry_t*
access_conf_entry_match(
  access_conf_entry_t* entry,
  const char* ug_str,
  const host_info_t hinfo);

bool
access_conf_permit(
  access_conf_entry_t* entry,
  const char* ug_str,
  const host_info_t hinfo);

access_conf_host_specifier_t*
entry_hspec_match(
  access_conf_host_specifier_t* hspec,
  const host_info_t hinfo);

bool
entry_match(
  access_conf_entry_t* entry,
  const char* ug_str,
  const host_info_t hinfo);

host_info_t
get_hinfo(
  char* host_str);

bool
hspec_match(
  const access_conf_host_specifier_t* hspec,
  const host_info_t hinfo);

bool
uspec_match(
  access_conf_user_specifier_t uspec,
  const char* ug_str);

#endif /* __ACCESS_CONF_ENTRY_H__ */

