#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

#include "access_conf_parser.h"
#include "pam_access_osx.h"

int main(void) {
  exit(validate(NULL));
}

