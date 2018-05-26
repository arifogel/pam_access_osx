#include <string.h>

#include "access_conf.h"

host_info_t
get_hinfo(
  char* host_str) {
  ipv4_addr_t addr4;
  if (inet_pton(AF_INET, host_str, &addr4) > 0) {
     host_info_t hinfo = {.id = {.ip4 = addr4}, .type = HST_IPV4_NETWORK};
     return hinfo;
  }
  ipv6_addr_t addr6;
  if (inet_pton(AF_INET6, host_str, &addr6) > 0) {
    host_info_t hinfo = {.id = {.ip6 = addr6}, .type = HST_IPV6_NETWORK};
    return hinfo;
  }
  host_info_t hinfo = {.id = {.hostname = host_str}, .type = HST_HOSTNAME};
  return hinfo;
}

bool
hspec_match(
  const access_conf_host_specifier_t* hspec,
  const host_info_t hinfo) {
  if (hspec->type == HST_ALL) {
    return true;
  }
  if (hspec->type != hinfo.type) {
    return false;
  }
  switch (hspec->type) {
    case HST_HOSTNAME:
      return !strcmp(hspec->hostname, hinfo.id.hostname);

    case HST_IPV4_NETWORK:
      return ipv4_network_contains(hspec->network.net4, hinfo.id.ip4);

    case HST_IPV6_NETWORK:
      return ipv6_network_contains(hspec->network.net6, hinfo.id.ip6);

    default: /* should not happen */
      return false;
  }
}

bool
entry_match(
  const access_conf_entry_t* entry,
  const char* ug_str,
  const host_info_t hinfo) {
  return false;
}

bool
uspec_match(
  access_conf_user_specifier_t uspec,
  const char* ug_str) {
  if (uspec.group) {
    /* not currently supported */
    return false;
  }
  return !strcmp(uspec.ug, ug_str);
}
