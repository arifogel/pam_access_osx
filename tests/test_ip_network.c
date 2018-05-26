#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>

#include "ip_util.h"

int
main(
  void) {
  // ipv4_network tests
  ipv4_network_t n4_1 = { .address = inet_addr("192.168.0.0"), .length = 24 };

  ipv4_addr_t addr_in_1 = inet_addr("192.168.0.1");
  ipv4_addr_t addr_out_1 = inet_addr("192.168.1.1");

  assert(ipv4_network_contains(n4_1, addr_in_1));
  assert(!ipv4_network_contains(n4_1, addr_out_1));

  // length not divisible by 8
  ipv4_network_t n4_2 = { .address = inet_addr("1.2.3.4"), .length = 30 };

  ipv4_addr_t addr_in_2 = inet_addr("1.2.3.5");
  ipv4_addr_t addr_out_2 = inet_addr("1.2.3.0");

  assert(ipv4_network_contains(n4_2, addr_in_2));
  assert(!ipv4_network_contains(n4_2, addr_out_2));

  // ipv6_network tests
  ipv6_network_t n6_1 = {.address = __ip6("3::"), .length = 64 };

  ipv6_addr_t addr6_in_1 = __ip6("3::1");
  ipv6_addr_t addr6_out_1 = __ip6("3:1::1");

  assert(ipv6_network_contains(n6_1, addr6_in_1));
  assert(!ipv6_network_contains(n6_1, addr6_out_1));

  // length not divisible by 8
  ipv6_network_t n6_2 = {.address = __ip6("1:2:3:4:5:6:7:4"), .length = 126 };

  ipv6_addr_t addr6_in_2 = __ip6("1:2:3:4:5:6:7:5");
  ipv6_addr_t addr6_out_2 = __ip6("1:2:3:4:5:6:7:0");

  assert(ipv6_network_contains(n6_2, addr6_in_2));
  assert(!ipv6_network_contains(n6_2, addr6_out_2));

  return 0;
}
