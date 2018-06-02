#include <errno.h>
#include <grp.h>
#include <membership.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "pam_access_osx.h"
#include "access_conf.h"

access_conf_entry_t*
access_conf_entry_match(
  access_conf_entry_t* entry,
  access_conf_user_info_t uinfo,
  const host_info_t hinfo) {
  access_conf_entry_t* cur_entry;
  for (cur_entry = entry; cur_entry != NULL; cur_entry = cur_entry->next) {
    if (uspec_match(cur_entry->uspec, uinfo) && entry_hspec_match(cur_entry->hspec, hinfo)) {
      return cur_entry;
    }
  }
  return NULL;
}

bool
access_conf_permit(
  access_conf_entry_t* entry,
  const char* username,
  const host_info_t hinfo) {
  access_conf_user_info_t uinfo;
  if (!init_uinfo(&uinfo, username)) {
    return false;
  }
  return access_conf_permit_uinfo(entry, uinfo, hinfo);
}

bool
access_conf_permit_uinfo(
  access_conf_entry_t* entry,
  access_conf_user_info_t uinfo,
  const host_info_t hinfo) {
  access_conf_entry_t* matching_entry = access_conf_entry_match(entry, uinfo, hinfo);
  return matching_entry == NULL || matching_entry->permit;
}

access_conf_host_specifier_t*
entry_hspec_match(
  access_conf_host_specifier_t* hspec,
  const host_info_t hinfo) {
  access_conf_host_specifier_t* cur_hspec;
  for (cur_hspec = hspec; cur_hspec != NULL; cur_hspec = cur_hspec->next) {
    if (hspec_match(cur_hspec, hinfo)) {
      return cur_hspec;
    }
  }
  return NULL;
}

bool
entry_match(
  access_conf_entry_t* entry,
  access_conf_user_info_t uinfo,
  const host_info_t hinfo) {
  return uspec_match(entry->uspec, uinfo) && entry_hspec_match(entry->hspec, hinfo);
}

host_info_t
get_hinfo(
  const char* host_str) {
  ipv4_addr_t addr4;
  if (inet_pton(AF_INET, host_str, &addr4) > 0) {
    host_info_t hinfo = { .id = { .ip4 = addr4 }, .type = HST_IPV4_NETWORK };
    return hinfo;
  }
  ipv6_addr_t addr6;
  if (inet_pton(AF_INET6, host_str, &addr6) > 0) {
    host_info_t hinfo = { .id = { .ip6 = addr6 }, .type = HST_IPV6_NETWORK };
    return hinfo;
  }
  host_info_t hinfo = { .id = { .hostname = host_str }, .type = HST_HOSTNAME };
  return hinfo;
}

bool
hspec_match(
  const access_conf_host_specifier_t* hspec,
  const host_info_t hinfo) {
  if (hspec->type == HST_ALL) {
    return true;
  }
  if (hspec->type != hinfo.type) {
    return false;
  }
  switch (hspec->type) {
    case HST_HOSTNAME:
      return !strcmp(hspec->hostname, hinfo.id.hostname);

    case HST_IPV4_NETWORK:
      return ipv4_network_contains(hspec->network.net4, hinfo.id.ip4);

    case HST_IPV6_NETWORK:
      return ipv6_network_contains(hspec->network.net6, hinfo.id.ip6);

    default: /* should not happen */
      return false;
  }
}

bool
init_uinfo(
  access_conf_user_info_t* uinfo,
  const char* username) {
  char* buffer;
  struct passwd pwd;
  struct passwd* u_result;
  long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (bufsize == -1) {
    pam_access_osx_syslog(
    LOG_ERR, "Could not get recommended size for getpwnam_r buffer: %s", strerror(errno));
    return false;
  }
  buffer = calloc(bufsize, 1);
  if (buffer == NULL) {
    pam_access_osx_syslog(
      LOG_ERR,
      "Unable to allocate buffer of size %dl for getpwnam_r buffer: %s",
      bufsize,
      strerror(errno));
    return false;
  }
  if (getpwnam_r(username, &pwd, buffer, bufsize, &u_result)) {
    pam_access_osx_syslog(LOG_ERR, "Error calling getpwnam_r for user '%s'", username);
    return false;
  }
  if (u_result == NULL) {
    pam_access_osx_syslog(LOG_INFO, "user '%s' does not exist", username);
    return false;
  }
  uid_t uid = pwd.pw_uid;
  free(buffer);
  int err = mbr_uid_to_uuid(uid, uinfo->uuid);
  if (err != 0) {
    pam_access_osx_syslog(LOG_ERR, "Error calling mbr_uid_to_uuid: %s", strerror(err));
    return false;
  }
  uinfo->uid = uid;
  uinfo->username = username;
  return true;
}

bool
uspec_match(
  access_conf_user_specifier_t uspec,
  access_conf_user_info_t uinfo) {
  if (uspec.all) {
    return true;
  }
  if (uspec.group) {
    char* buffer;
    struct group grp;
    struct group* g_result;
    long bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (bufsize == -1) {
      pam_access_osx_syslog(
      LOG_ERR, "Could not get recommended size for getgrnam_r buffer: %s", strerror(errno));
      return false;
    }
    buffer = calloc(bufsize, 1);
    if (buffer == NULL) {
      pam_access_osx_syslog(
        LOG_ERR,
        "Unable to allocate buffer of size %dl for getgrnam_r buffer: %s",
        bufsize,
        strerror(errno));
      return false;
    }
    if (getgrnam_r(uspec.ug + 1, &grp, buffer, bufsize, &g_result)) {
      pam_access_osx_syslog(LOG_ERR, "Error calling getgrnam_r for group '%s'", uspec.ug + 1);
      return false;
    }
    if (g_result == NULL) {
      pam_access_osx_syslog(LOG_WARNING, "group '%s' does not exist", uspec.ug + 1);
      return false;
    }
    gid_t gid = grp.gr_gid;
    free(buffer);
    uuid_t group_uuid;
    int err = mbr_gid_to_uuid(gid, group_uuid);
    if (err != 0) {
      pam_access_osx_syslog(LOG_ERR, "Error calling mbr_gid_to_uuid: %s", strerror(err));
      return false;
    }
    int ismember;
    err = mbr_check_membership(uinfo.uuid, group_uuid, &ismember);
    if (err != 0) {
      pam_access_osx_syslog(LOG_ERR, "Error calling mbr_check_membership: %s", strerror(err));
      return false;
    }
    return ismember;
  }
  // uspec contains username
  return !strcmp(uspec.ug, uinfo.username);
}
