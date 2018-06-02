#include <assert.h>
#include <grp.h>
#include <membership.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "access_conf.h"

static
void
get_test_user_and_group(
  char** username,
  char** groupname) {
  long bufsize;
  char* buffer;

  assert((bufsize = sysconf(_SC_GETPW_R_SIZE_MAX)) != -1);
  assert((buffer = calloc(bufsize,1)) != NULL);
  struct passwd pwd;
  struct passwd* u_result;
  assert(!getpwuid_r(getuid(), &pwd, buffer, bufsize, &u_result));
  assert((*username = calloc(bufsize,1)) != NULL);
  strcpy(*username, pwd.pw_name);
  free(buffer);

  struct group grp;
  struct group* g_result;
  assert((bufsize = sysconf(_SC_GETGR_R_SIZE_MAX)) != -1);
  assert((buffer = calloc(bufsize,1)) != NULL);
  assert(!getgrgid_r(getgid(), &grp, buffer, bufsize, &g_result));
  assert((*groupname = calloc(bufsize+1,1)) != NULL); // extra byte for '@'
  char* gn = *groupname;
  strcpy(gn + 1, grp.gr_name);
  gn[0] = '@';
  free(buffer);
}

int
main(
  void) {
  // user specifier - user
  access_conf_user_specifier_t uspec1 = { .group = false, .ug = "user1" };

  access_conf_user_info_t uinfo_user1 = { .username = "user1" };
  assert(uspec_match(uspec1, uinfo_user1));
  access_conf_user_info_t uinfo_user2 = { .username = "user2" };
  assert(!uspec_match(uspec1, uinfo_user2));

  // user specifier - group
  char* username;
  char* groupname;
  get_test_user_and_group(&username, &groupname);
  access_conf_user_specifier_t uspec_group = { .group = true, .ug = groupname };
  access_conf_user_info_t uinfo_group;
  assert(init_uinfo(&uinfo_group, username));
  assert(uspec_match(uspec_group, uinfo_group));

  // user specifier - ALL
  access_conf_user_specifier_t uspec_all = { .group = false, .all = true };
  access_conf_user_info_t uinfo_all = { .username = "user3" };
  assert(uspec_match(uspec_all, uinfo_all));

  // host specifier - hostname
  access_conf_host_specifier_t hspec_hostname = { .hostname = "example.com", .type = HST_HOSTNAME };

  assert(hspec_match(&hspec_hostname, get_hinfo("example.com")));
  assert(!hspec_match(&hspec_hostname, get_hinfo("some-other-host")));
  assert(!hspec_match(&hspec_hostname, get_hinfo("1.2.3.4")));
  assert(!hspec_match(&hspec_hostname, get_hinfo("::1")));

  // host specifier - ipv4 address
  access_conf_host_specifier_t hspec_ipv4_address = { .network = { .net4 = { .address = inet_addr(
    "1.2.3.4"), .length = 32 } }, .type = HST_IPV4_NETWORK };

  assert(hspec_match(&hspec_ipv4_address, get_hinfo("1.2.3.4")));
  assert(!hspec_match(&hspec_ipv4_address, get_hinfo("1.2.3.5")));

  // host specifier - ipv4 network
  access_conf_host_specifier_t hspec_ipv4_network = { .network = { .net4 = { .address = inet_addr(
    "1.2.3.4"), .length = 24 } }, .type = HST_IPV4_NETWORK };

  assert(hspec_match(&hspec_ipv4_network, get_hinfo("1.2.3.3")));
  assert(!hspec_match(&hspec_ipv4_network, get_hinfo("1.2.4.3")));
  assert(!hspec_match(&hspec_ipv4_network, get_hinfo("example.com")));
  assert(!hspec_match(&hspec_ipv4_network, get_hinfo("some-other-host")));
  assert(!hspec_match(&hspec_ipv4_network, get_hinfo("1::1")));

  // host specifier - ipv6 address
  access_conf_host_specifier_t hspec_ipv6_address = { .network = { .net6 = {
      .address = __ip6("::1"), .length = 128 } }, .type = HST_IPV6_NETWORK };

  assert(hspec_match(&hspec_ipv6_address, get_hinfo("0:0:0:0:0:0:0:1")));
  assert(!hspec_match(&hspec_ipv6_address, get_hinfo("1:2:3:4:5:6:7:8")));

  // host specifier - ipv6 network
  access_conf_host_specifier_t hspec_ipv6_network = { .network = { .net6 = {
      .address = __ip6("1::"), .length = 64 } }, .type = HST_IPV6_NETWORK };

  assert(hspec_match(&hspec_ipv6_network, get_hinfo("1::1")));
  assert(!hspec_match(&hspec_ipv6_network, get_hinfo("2::1")));
  assert(!hspec_match(&hspec_ipv6_network, get_hinfo("example.com")));
  assert(!hspec_match(&hspec_ipv6_network, get_hinfo("some-other-host")));
  assert(!hspec_match(&hspec_ipv6_network, get_hinfo("1.2.3.4")));

  // host specifier - ALL
  access_conf_host_specifier_t hspec_all = { .type = HST_ALL };

  assert(hspec_match(&hspec_all, get_hinfo("example.com")));
  assert(hspec_match(&hspec_all, get_hinfo("some-other-host")));
  assert(hspec_match(&hspec_all, get_hinfo("1.2.3.4")));
  assert(hspec_match(&hspec_all, get_hinfo("::1")));

  // entry - single hspec
  access_conf_host_specifier_t single_hspec = { .hostname = "example.com", .type = HST_HOSTNAME };
  access_conf_entry_t entry_single_hspec = { .hspec = &single_hspec, .permit = true, .uspec = {
      .ug = "user1", .group = false } };

  assert(entry_match(&entry_single_hspec, uinfo_user1, get_hinfo("example.com")));
  assert(!entry_match(&entry_single_hspec, uinfo_user2, get_hinfo("example.com")));
  assert(!entry_match(&entry_single_hspec, uinfo_user1, get_hinfo("foo")));

  // entry - dual hspec
  access_conf_host_specifier_t dual_hspec_second =
      { .hostname = "example.com", .type = HST_HOSTNAME };
  access_conf_host_specifier_t dual_hspec_first = { .hostname = "example.org", .type = HST_HOSTNAME,
      .next = &dual_hspec_second };

  access_conf_entry_t entry_dual_hspec = { .hspec = &dual_hspec_first, .permit = true, .uspec = {
      .ug = "user1", .group = false } };

  assert(entry_match(&entry_dual_hspec, uinfo_user1, get_hinfo("example.com")));
  assert(entry_match(&entry_dual_hspec, uinfo_user1, get_hinfo("example.org")));
  assert(!entry_match(&entry_dual_hspec, uinfo_user2, get_hinfo("example.net")));

  // dual entry
  access_conf_host_specifier_t dual_entry_hspec_second = { .hostname = "example.sh", .type =
      HST_HOSTNAME };
  access_conf_host_specifier_t dual_entry_hspec_first = { .hostname = "example.biz", .type =
      HST_HOSTNAME };
  access_conf_entry_t dual_entry_second = { .hspec = &dual_entry_hspec_second, .permit = true,
      .uspec = { .ug = "user1", .group = false } };
  access_conf_entry_t dual_entry_first = { .hspec = &dual_entry_hspec_first, .permit = true,
      .uspec = { .ug = "user1", .group = false }, .next = &dual_entry_second };

  assert(access_conf_entry_match(&dual_entry_first, uinfo_user1, get_hinfo("example.biz")));
  assert(access_conf_entry_match(&dual_entry_first, uinfo_user1, get_hinfo("example.sh")));
  assert(!access_conf_entry_match(&dual_entry_first, uinfo_user1, get_hinfo("example.dev")));

  access_conf_host_specifier_t entry_action_hspec_permit = { .hostname = "example.co.uk", .type =
      HST_HOSTNAME };
  access_conf_host_specifier_t entry_action_hspec_deny = { .hostname = "example.ca", .type =
      HST_HOSTNAME };
  access_conf_entry_t entry_action_deny = { .hspec = &entry_action_hspec_deny, .permit = false,
      .uspec = { .ug = "user1", .group = false } };
  access_conf_entry_t entry_action_permit = { .hspec = &entry_action_hspec_permit, .permit = true,
      .uspec = { .ug = "user1", .group = false }, .next = &entry_action_deny };

  assert(
    access_conf_entry_match(&entry_action_permit, uinfo_user1, get_hinfo("example.co.uk"))
        == &entry_action_permit);
  assert(access_conf_permit_uinfo(&entry_action_permit, uinfo_user1, get_hinfo("example.co.uk")));
  assert(
    access_conf_entry_match(&entry_action_permit, uinfo_user1, get_hinfo("example.ca"))
        == &entry_action_deny);
  assert(!access_conf_permit_uinfo(&entry_action_permit, uinfo_user1, get_hinfo("example.ca")));
  assert(
    access_conf_entry_match(&entry_action_permit, uinfo_user1, get_hinfo("example.foo")) == NULL);
  assert(access_conf_permit_uinfo(&entry_action_permit, uinfo_user1, get_hinfo("example.foo")));

  return 0;
}
