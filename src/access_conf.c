#include <string.h>

#include "access_conf.h"

access_conf_entry_t*
access_conf_entry_match(
  access_conf_entry_t* entry,
  const char* ug_str,
  const host_info_t hinfo) {
  access_conf_entry_t* cur_entry;
  for (cur_entry = entry; cur_entry != NULL; cur_entry = cur_entry->next) {
    if (uspec_match(cur_entry->uspec, ug_str) && entry_hspec_match(cur_entry->hspec, hinfo)) {
      return cur_entry;
    }
  }
  return NULL;
}

bool
access_conf_permit(
  access_conf_entry_t* entry,
  const char* ug_str,
  const host_info_t hinfo) {
  access_conf_entry_t* matching_entry = access_conf_entry_match(entry, ug_str, hinfo);
  return matching_entry == NULL || matching_entry->permit;
}

access_conf_host_specifier_t*
entry_hspec_match(
  access_conf_host_specifier_t* hspec,
  const host_info_t hinfo) {
  access_conf_host_specifier_t* cur_hspec;
  for (cur_hspec = hspec; cur_hspec != NULL; cur_hspec = cur_hspec->next) {
    if (hspec_match(cur_hspec, hinfo)) {
      return cur_hspec;
    }
  }
  return NULL;
}

bool
entry_match(
  access_conf_entry_t* entry,
  const char* ug_str,
  const host_info_t hinfo) {
  return uspec_match(entry->uspec, ug_str) && entry_hspec_match(entry->hspec, hinfo);
}

host_info_t
get_hinfo(
  char* host_str) {
  ipv4_addr_t addr4;
  if (inet_pton(AF_INET, host_str, &addr4) > 0) {
    host_info_t hinfo = { .id = { .ip4 = addr4 }, .type = HST_IPV4_NETWORK };
    return hinfo;
  }
  ipv6_addr_t addr6;
  if (inet_pton(AF_INET6, host_str, &addr6) > 0) {
    host_info_t hinfo = { .id = { .ip6 = addr6 }, .type = HST_IPV6_NETWORK };
    return hinfo;
  }
  host_info_t hinfo = { .id = { .hostname = host_str }, .type = HST_HOSTNAME };
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
uspec_match(
  access_conf_user_specifier_t uspec,
  const char* ug_str) {
  if (uspec.all) {
    return true;
  }
  if (uspec.group) {
    /* not currently supported */
    return false;
  }
  return !strcmp(uspec.ug, ug_str);
}
