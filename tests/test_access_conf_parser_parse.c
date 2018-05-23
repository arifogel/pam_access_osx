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
  assert(first_entry != NULL);
  assert(pam_exec_osx_allocated_entry_count > 0);
  assert(pam_exec_osx_allocated_hspec_count > 0);
  destroy_entry(first_entry);
  assert(pam_exec_osx_allocated_entry_count == 0);
  assert(pam_exec_osx_allocated_hspec_count == 0);
  exit(0);
}

