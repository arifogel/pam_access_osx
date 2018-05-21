#include <stdio.h>

#include "access_conf_parser.h"

int
validate(const char* path) {
  FILE* input_file = fopen(path, "r");
  if (input_file == NULL) {
    pam_access_osx_syslog(
  }
  return 0;
}

