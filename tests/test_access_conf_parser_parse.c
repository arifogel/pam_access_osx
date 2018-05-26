#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "access_conf.h"
#include "access_conf_parser.h"
#include "pam_access_osx.h"

#define TEST_ACCESS_CONF ("tests/resources/etc/access.conf")

int
main(
  void) {
  pam_access_osx_log_level = LOG_INFO;
  access_conf_entry_t* first_entry = parse_file(TEST_ACCESS_CONF);

  // Leading entry should be returned
  assert(first_entry != NULL);

  // Should have allocated corresponding # of entry, hostname, hspec, uspec
  assert(pam_exec_osx_allocated_entry_count == 8);
  assert(pam_exec_osx_allocated_hostname_count == 11);
  assert(pam_exec_osx_allocated_hspec_count == 11);
  assert(pam_exec_osx_allocated_uspec_count == 8);

  // Should have corresponding counts for hspec types
  assert(pam_exec_osx_hspec_all_count == 1);
  assert(pam_exec_osx_hspec_ipv4_address_count == 2);
  assert(pam_exec_osx_hspec_ipv4_network_count == 3);
  assert(pam_exec_osx_hspec_ipv6_address_count == 1);
  assert(pam_exec_osx_hspec_ipv6_network_count == 3);
  assert(pam_exec_osx_hspec_hostname_count == 1);

  // alice
  access_conf_entry_t* cur_entry = first_entry;
  assert(cur_entry->permit);
  assert(!cur_entry->uspec.all);
  assert(!cur_entry->uspec.group);
  assert(!strcmp(cur_entry->uspec.ug, "alice"));
  assert(cur_entry->hspec->type = HST_IPV4_NETWORK);
  assert(!strcmp(cur_entry->hspec->hostname, "127.0.0.1"));
  assert(cur_entry->hspec->network.net4.length == 32);
  assert(!cur_entry->hspec->next);
  assert(cur_entry->next);

  // alice 2
  cur_entry = cur_entry->next;
  assert(cur_entry->permit);
  assert(!cur_entry->uspec.all);
  assert(!cur_entry->uspec.group);
  assert(!strcmp(cur_entry->uspec.ug, "alice"));
  assert(cur_entry->hspec->type = HST_IPV4_NETWORK);
  assert(!strcmp(cur_entry->hspec->hostname, "1.2.3.4"));
  assert(cur_entry->hspec->network.net4.length == 32);
  assert(!cur_entry->hspec->next);
  assert(cur_entry->next);

  // bob
  cur_entry = cur_entry->next;
  assert(cur_entry->permit);
  assert(!cur_entry->uspec.all);
  assert(!cur_entry->uspec.group);
  assert(!strcmp(cur_entry->uspec.ug, "bob"));
  assert(cur_entry->hspec->type = HST_IPV4_NETWORK);
  assert(!strcmp(cur_entry->hspec->hostname, "192.168.0.0/24"));
  assert(cur_entry->hspec->network.net4.length == 24);
  assert(!cur_entry->hspec->next);
  assert(cur_entry->next);

  // chunming
  cur_entry = cur_entry->next;
  assert(cur_entry->permit);
  assert(!cur_entry->uspec.all);
  assert(!cur_entry->uspec.group);
  assert(!strcmp(cur_entry->uspec.ug, "chunming"));
  assert(cur_entry->hspec->type = HST_IPV4_NETWORK);
  assert(!strcmp(cur_entry->hspec->hostname, "172.16.0.0/16"));
  assert(cur_entry->hspec->network.net4.length == 16);
  assert(cur_entry->hspec->next);
  assert(cur_entry->hspec->next->type = HST_IPV4_NETWORK);
  assert(!strcmp(cur_entry->hspec->next->hostname, "10.0.0.0/8"));
  assert(cur_entry->hspec->next->network.net4.length == 8);
  assert(!cur_entry->hspec->next->next);
  assert(cur_entry->next);

  // david
  cur_entry = cur_entry->next;
  assert(cur_entry->permit);
  assert(!cur_entry->uspec.all);
  assert(!cur_entry->uspec.group);
  assert(!strcmp(cur_entry->uspec.ug, "david"));
  assert(cur_entry->hspec->type = HST_IPV6_NETWORK);
  assert(!strcmp(cur_entry->hspec->hostname, "::1"));
  assert(cur_entry->hspec->network.net6.length == 128);
  assert(!cur_entry->hspec->next);
  assert(cur_entry->next);

  // edwina
  cur_entry = cur_entry->next;
  assert(cur_entry->permit);
  assert(!cur_entry->uspec.all);
  assert(!cur_entry->uspec.group);
  assert(!strcmp(cur_entry->uspec.ug, "edwina"));
  assert(cur_entry->hspec->type = HST_IPV6_NETWORK);
  assert(!strcmp(cur_entry->hspec->hostname, "ff00::/8"));
  assert(cur_entry->hspec->network.net6.length == 8);
  assert(cur_entry->hspec->next);
  assert(cur_entry->hspec->next->type = HST_IPV6_NETWORK);
  assert(!strcmp(cur_entry->hspec->next->hostname, "1:2:3:4::/64"));
  assert(cur_entry->hspec->next->network.net6.length == 64);
  assert(cur_entry->hspec->next->next);
  assert(cur_entry->hspec->next->next->type = HST_IPV6_NETWORK);
  assert(!strcmp(cur_entry->hspec->next->next->hostname, "5:6:7:8:9:a:b::/112"));
  assert(cur_entry->hspec->next->next->network.net6.length == 112);
  assert(!cur_entry->hspec->next->next->next);
  assert(cur_entry->next);

  // fatima
  cur_entry = cur_entry->next;
  assert(cur_entry->permit);
  assert(!cur_entry->uspec.all);
  assert(!cur_entry->uspec.group);
  assert(!strcmp(cur_entry->uspec.ug, "fatima"));
  assert(cur_entry->hspec->type = HST_HOSTNAME);
  assert(!strcmp(cur_entry->hspec->hostname, "example.com"));
  assert(!cur_entry->hspec->next);
  assert(cur_entry->next);

  // EXPLICIT DENY
  cur_entry = cur_entry->next;
  assert(!cur_entry->permit);
  assert(cur_entry->uspec.all);
  assert(!cur_entry->uspec.group);
  assert(!strcmp(cur_entry->uspec.ug, "ALL"));
  assert(cur_entry->hspec->type = HST_ALL);
  assert(!strcmp(cur_entry->hspec->hostname, "ALL"));
  assert(!cur_entry->hspec->next);
  assert(!cur_entry->next);

  destroy_entry(first_entry);

  // All items should be deallocated
  assert(pam_exec_osx_allocated_entry_count == 0);
  assert(pam_exec_osx_allocated_hostname_count == 0);
  assert(pam_exec_osx_allocated_hspec_count == 0);
  assert(pam_exec_osx_allocated_uspec_count == 0);
  exit(0);
}

