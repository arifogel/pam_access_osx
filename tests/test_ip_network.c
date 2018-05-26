#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>

#include "ip_util.h"

int
main(
  void) {
  // ipv4_network tests
  ipv4_network_t n4 = { .address = __ip("192.168.0.0"), .length = 24 };

  ipv4_addr_t addr_in = __ip("192.168.0.1");
  ipv4_addr_t addr_out = __ip("192.168.1.1");

  assert(ipv4_network_contains(n4, addr_in));
  assert(!ipv4_network_contains(n4, addr_out));

  // ipv6_network tests
  ipv6_network_t n6 = {.address = __ip6("3::"), .length = 64 };

  ipv6_addr_t addr6_in = __ip6("3::1");
  ipv6_addr_t addr6_out = __ip6("3:1::1");

  assert(ipv6_network_contains(n6, addr6_in));
  assert(!ipv6_network_contains(n6, addr6_out));
}
