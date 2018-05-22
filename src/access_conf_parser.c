#include <stdio.h>
#include <string.h>
#include <sys/errno.h>

#include "pam_access_osx.h"
#include "access_conf_parser.h"

int
validate(const char* path) {
  FILE* input_file = fopen(path, "r");
  if (input_file == NULL) {
    pam_access_osx_syslog(LOG_ERR, "Could not open configuration file: '%s': %s\n", path, strerror(errno));
    return 1;
  }
  int validation_result = validate_file(input_file);
  if (fclose(input_file) == EOF) {
    pam_access_osx_syslog(LOG_ERR, "Could not close configuration file: '%s': %s\n", path, strerror(errno));
    return 1;
  }
  return validation_result;
}

int
validate_file(FILE* input_file) {
  return 0;
}

