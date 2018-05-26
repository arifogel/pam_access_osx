#include <string.h>

#include "ip_util.h"

struct in6_addr
__ip6(
  const char* addr_str) {
  ipv6_addr_t addr;
  inet_pton(AF_INET6, addr_str, &addr);
  return addr;
}

bool
ipv4_network_contains(
  ipv4_network_t network,
  ipv4_addr_t address) {
  ipv4_addr_t mask;
  netmask4(network.length, &mask);
  ipv4_addr_t masked_network = network.address & mask;
  ipv4_addr_t masked_address = address & mask;
  return masked_network == masked_address;
}

bool
ipv6_network_contains(
  ipv6_network_t network,
  ipv6_addr_t address) {
  ipv6_addr_t mask;
  netmask6(network.length, &mask);
  ipv6_addr_t masked_network = network.address;
  ((uint64_t*) &masked_network)[0] &= ((uint64_t*) &mask)[0];
  ((uint64_t*) &masked_network)[1] &= ((uint64_t*) &mask)[1];
  ipv6_addr_t masked_address = address;
  ((uint64_t*) &masked_address)[0] &= ((uint64_t*) &mask)[0];
  ((uint64_t*) &masked_address)[1] &= ((uint64_t*) &mask)[1];
  return ((uint64_t*) &masked_network)[0] == ((uint64_t*) &masked_address)[0]
      && ((uint64_t*) &masked_network)[1] == ((uint64_t*) &masked_address)[1];
}

bool
netmask4(
  uint8_t length,
  ipv4_addr_t* mask) {
  if (length > 32) {
    return false;
  }
  int shift = 32 - length;
  *mask = htonl(~((ipv4_addr_t )0) >> shift << shift);
  return true;
}

bool
netmask6(
  uint8_t length,
  ipv6_addr_t* mask) {
  if (length > 128) {
    return false;
  }
  uint8_t* bytes = (uint8_t*) mask;
  int full_bytes = length / 8;
  int remaining_bits = length % 8;
  memset(bytes, 0xFF, full_bytes);
  memset(bytes + full_bytes, 0x00, 16 - full_bytes);
  if (remaining_bits) {
    int shift = 8 - remaining_bits;
    bytes[full_bytes] = ((uint8_t) 0xFF) >> shift << shift;
  }
  return true;
}
