#include <ip_util.h>

uint32_t __ip(const char* addr_str) {
  uint32_t ip_network_order;
  inet_pton(AF_INET, addr_str, &ip_network_order);
  return ntohl(ip_network_order);
}

struct in6_addr __ip6(const char* addr_str) {
  struct in6_addr  ip_network_order;
  inet_pton(AF_INET6, addr_str, &ip_network_order);
  int i;
  struct in6_addr output;
  uint8_t* output_bytes_network_order = (uint8_t*)&ip_network_order;
  uint8_t* output_bytes = (uint8_t*)&output;
  for (i = 0; i < 128; i++) {
    output_bytes[i] = output_bytes_network_order[127-i];
  }
  return output;
}

bool
ipv4_network_contains(
  ipv4_network_t network,
  uint32_t address) {
  uint32_t mask;
  netmask4(network.length, &mask);
  uint32_t masked_network = network.address & mask;
  uint32_t masked_address = address & mask;
  return masked_network == masked_address;
}

//bool
//ipv6_network_contains(
//  ipv6_network_t network,
//  struct in6_addr address){
//
//}

bool
netmask4(uint8_t length, uint32_t* mask) {
  if (length > 32) {
    return false;
  }
  int shift = 32 - length;
  *mask = ~'0' >> shift << shift;
  return true;
}

