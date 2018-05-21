#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

#include "access_conf_parser.h"
#include "pam_access_osx.h"

#define TEST_ACCESS_CONF ("tests/resources/etc/access.conf")
#define TEST_BAD_ACCESS_CONF ("tests/resources/etc/bad-access.conf")

int main(void) {
  if (validate(TEST_ACCESS_CONF)) {
    exit(1);
  }
  exit(!validate(TEST_BAD_ACCESS_CONF));
}

