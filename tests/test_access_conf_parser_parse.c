#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

#include "access_conf.h"
#include "access_conf_parser.h"
#include "pam_access_osx.h"

#define TEST_ACCESS_CONF ("tests/resources/etc/access.conf")

int main(void) {
  pam_access_osx_log_level = LOG_INFO;
  access_conf_entry_t* first_entry = parse_file(TEST_ACCESS_CONF);

  // Leading entry should be returned
  assert(first_entry != NULL);

  // Should have allocated corresponding # of entry, hostname, hspec, uspec
  assert(pam_exec_osx_allocated_entry_count == 7);
  assert(pam_exec_osx_allocated_hostname_count == 8);
  assert(pam_exec_osx_allocated_hspec_count == 8);
  assert(pam_exec_osx_allocated_uspec_count == 7);

  // Should have corresponding counts for hspec types
  assert(pam_exec_osx_hspec_all_count == 1);
  assert(pam_exec_osx_hspec_ipv4_address_count == 1);
  assert(pam_exec_osx_hspec_ipv4_network_count == 3);
  assert(pam_exec_osx_hspec_ipv6_address_count == 1);
  assert(pam_exec_osx_hspec_ipv6_network_count == 1);
  assert(pam_exec_osx_hspec_hostname_count == 1);

  destroy_entry(first_entry);

  // All items should be deallocated
  assert(pam_exec_osx_allocated_entry_count == 0);
  assert(pam_exec_osx_allocated_hostname_count == 0);
  assert(pam_exec_osx_allocated_hspec_count == 0);
  assert(pam_exec_osx_allocated_uspec_count == 0);
  exit(0);
}

