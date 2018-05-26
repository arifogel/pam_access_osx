#ifndef __ip_util_h__
#define __ip_util_h__

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>

typedef uint32_t ipv4_addr_t;
typedef struct in6_addr ipv6_addr_t;

typedef struct ipv4_network {
  ipv4_addr_t address;
  uint8_t length;
} ipv4_network_t;

typedef struct ipv6_network {
  ipv6_addr_t address;
  uint8_t length;
} ipv6_network_t;

typedef union ip_network {
  ipv4_network_t net4;
  ipv6_network_t net6;
} ip_network_t;

ipv6_addr_t
__ip6(
  const char* addr_str);

bool
ipv4_network_contains(
  ipv4_network_t network,
  ipv4_addr_t address);

bool
ipv6_network_contains(
  ipv6_network_t network,
  ipv6_addr_t address);

bool
netmask4(
  uint8_t length,
  ipv4_addr_t* mask);

bool
netmask6(
  uint8_t length,
  ipv6_addr_t* mask);

#endif /* __ip_util_h__ */
