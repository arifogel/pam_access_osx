#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "access_conf_parser.h"
#include "pam_access_osx.h"

#define TEST_BAD_ACCESS_CONF ("tests/resources/etc/bad-access.conf")

int
main(
  void) {
  pam_access_osx_log_level = LOG_EMERG;
  if (validate_file(TEST_BAD_ACCESS_CONF)) {
    fprintf(stderr, "Improperly validated: '%s'\n", TEST_BAD_ACCESS_CONF);
    exit(1);
  }
  exit(0);
}

