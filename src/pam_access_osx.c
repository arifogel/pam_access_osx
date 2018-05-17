#include <inttypes.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include "pam_access_osx.h"

int
pam_access_osx_init_pam_info(
  pam_handle_t* pamh,
  const char** pam_rhost,
  const char** pam_user) {
  // Get PAM_RHOST
  if (pam_get_item(pamh, PAM_RHOST, (const void**) pam_rhost) != PAM_SUCCESS) {
    pam_access_osx_syslog(LOG_ERR, "Could not retrieve PAM_RHOST\n");
    return (PAM_AUTH_ERR);
  }
  pam_access_osx_syslog(LOG_DEBUG, "PAM_RHOST: %s\n", *pam_rhost);

  // Get PAM user
  if (pam_get_user(pamh, pam_user, NULL) != PAM_SUCCESS || (pam_user == NULL)) {
    pam_access_osx_syslog(LOG_ERR, "Could not retrieve PAM user\n");
    return (PAM_AUTH_ERR);
  }
  pam_access_osx_syslog(LOG_DEBUG, "PAM user: %s\n", *pam_user);

  return (PAM_SUCCESS);
}

void
pam_access_osx_syslog(
  int priority,
  const char* format,
  ...) {
  if (priority > PAM_ACCESS_OSX_LOG_LEVEL) {
    return;
  }
  va_list args;
  va_start(args, format);
  openlog(PAM_ACCESS_OSX_IDENT, 0, LOG_AUTH);
  vsyslog(priority, format, args);
  closelog();
}

PAM_EXTERN
int
pam_sm_authenticate(
  pam_handle_t* pamh,
  int flags,
  int argc,
  const char** argv) {
  const char* pam_user = NULL;
  const char* pam_rhost = NULL;
  if (pam_access_osx_init_pam_info(pamh, &pam_rhost, &pam_user) != 0) {
    pam_access_osx_syslog(LOG_ERR, "Error retrieving PAM variables\n");
    return (PAM_AUTH_ERR);
  }
  return (PAM_SUCCESS);
}

PAM_EXTERN
int
pam_sm_acct_mgmt(
  pam_handle_t* pamh,
  int flags,
  int argc,
  const char** argv) {
  return (PAM_SUCCESS);
}

PAM_EXTERN
int
pam_sm_chauthtok(
  pam_handle_t* pamh,
  int flags,
  int argc,
  const char** argv) {
  return (PAM_SUCCESS);
}

PAM_EXTERN
int
pam_sm_close_session(
  pam_handle_t* pamh,
  int flags,
  int argc,
  const char** argv) {
  return (PAM_SUCCESS);
}

PAM_EXTERN
int
pam_sm_open_session(
  pam_handle_t* pamh,
  int flags,
  int argc,
  const char** argv) {
  return (PAM_SUCCESS);
}

PAM_EXTERN
int
pam_sm_setcred(
  pam_handle_t* pamh,
  int flags,
  int argc,
  const char** argv) {
  return (PAM_SUCCESS);
}

PAM_MODULE_ENTRY(PAM_ACCESS_OSX_MODULE_ENTRY);

