#include <assert.h>

#include "access_conf.h"
#include "access_conf_parser.h"
#include "ip_util.h"
#include "pam_access_osx.h"

#define TEST_ACCESS_CONF ("tests/resources/etc/access.conf")

int main(void) {
  pam_access_osx_log_level = LOG_INFO;
  access_conf_entry_t* first_entry = parse_file(TEST_ACCESS_CONF);

  assert(access_conf_permit(first_entry, "alice", get_hinfo("127.0.0.1")));
  assert(access_conf_permit(first_entry, "bob", get_hinfo("192.168.0.33")));
  assert(access_conf_permit(first_entry, "chunming", get_hinfo("172.16.5.6")));
  assert(access_conf_permit(first_entry, "chunming", get_hinfo("10.2.3.4")));
  assert(access_conf_permit(first_entry, "david", get_hinfo("::1")));
  assert(access_conf_permit(first_entry, "edwina", get_hinfo("ff00:2:3:4:5:6:7:8")));
  assert(access_conf_permit(first_entry, "edwina", get_hinfo("1:2:3:4:5:6:7:8")));
  assert(access_conf_permit(first_entry, "edwina", get_hinfo("5:6:7:8:9:a:b:c")));
  assert(access_conf_permit(first_entry, "fatima", get_hinfo("example.com")));
  assert(!access_conf_permit(first_entry, "alice", get_hinfo("example.com")));

  destroy_entry(first_entry);

  return 0;
}
