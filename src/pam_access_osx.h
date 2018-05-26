#ifndef __PAM_ACCESS_OSX_H__
#define __PAM_ACCESS_OSX_H__

#include <security/pam_appl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>

#include "pam_access_osx_config.h"

#define PAM_ACCESS_OSX_DEFAULT_ACCESS_CONF_PATH ("/etc/security/access.conf")

#define PAM_ACCESS_OSX_CHILD_DENY (1)
#define PAM_ACCESS_OSX_CHILD_ERR (-1)
#define PAM_ACCESS_OSX_CHILD_PERMIT (0)

#define PAM_ACCESS_OSX_IDENT ("pam_access_osx")

#define PAM_ACCESS_OSX_MODULE_ENTRY ("pam_access_osx")

#define PAM_ACCESS_OSX_ENV_USER ("PAM_ACCESS_OSX_USER")
#define PAM_ACCESS_OSX_ENV_RHOST ("PAM_ACCESS_OSX_RHOST")

extern char* pam_access_osx_access_conf_path;

extern int pam_access_osx_log_level;

/**
 * Child process entry point in which command specified by argc and argv executes. This command is responsible
 * for authenticating, and runs in an environment in which variables PAM_ACCESS_OSX_USER and PAM_ACCESS_OSX_RHOST are
 * with pam_user and pam_rhost respectively.
 * Exits with:
 * - PAM_ACCESS_OSX_CHILD_PERMIT, if command successfully authenticates pam
 */
void
pam_access_osx_child(
  int argc,
  const char** argv,
  const char* pam_rhost,
  const char* pam_user);

/**
 *  Populates pam_user and pam_rhost via pamh.
 */
int
pam_access_osx_init_pam_info(
  pam_handle_t* pamh,
  const char** pam_rhost,
  const char** pam_user);

/**
 * Parent process continuation point after forking child with PID child_pid.
 * Returns:
 * - PAM_AUTH_ERR if child process exits with PAM_ACCESS_OSX_CHILD_DENY or PAM_ACCESS_OSX_CHILD
 * - PAM_SUCESS if child process exits with PAM_ACCESS_OSX_CHILD_PERMIT
 */
int
pam_access_osx_parent(
  pid_t child_pid,
  const char* pam_rhost,
  const char* pam_user);

/**
 * Write format string to syslog facility LOG_AUTH with specified priority.
 */
void
pam_access_osx_syslog(
  int priority,
  const char* format,
  ...);

/**
 * Write format string to syslog facility LOG_AUTH with specified priority.
 */
void
pam_access_osx_vsyslog(
  int priority,
  const char* format,
  va_list args);

#endif /*__PAM_ACCESS_OSX_H__*/

