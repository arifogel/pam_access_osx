#include <assert.h>

#include "access_conf.h"

int main(void) {
  // user specifier
  access_conf_user_specifier_t uspec1 = {.group = false, .ug = "user1"};

  assert(uspec_match(uspec1, "user1"));
  assert(!uspec_match(uspec1, "user2"));

  // host specifier - hostname
  access_conf_host_specifier_t hspec_hostname = {.hostname = "example.com", .type = HST_HOSTNAME};

  assert(hspec_match(&hspec_hostname, get_hinfo("example.com")));
  assert(!hspec_match(&hspec_hostname, get_hinfo("some-other-host")));

  // host specifier - ipv4 address
  access_conf_host_specifier_t hspec_ipv4_address = { .network = { .net4 = {
      .address = inet_addr("1.2.3.4"), .length = 32}}, .type = HST_IPV4_NETWORK};

  assert(hspec_match(&hspec_ipv4_address, get_hinfo("1.2.3.4")));
  assert(!hspec_match(&hspec_ipv4_address, get_hinfo("1.2.3.5")));

  // host specifier - ipv4 network
  access_conf_host_specifier_t hspec_ipv4_network = { .network = { .net4 = {
      .address = inet_addr("1.2.3.4"), .length = 24}}, .type = HST_IPV4_NETWORK};

  assert(hspec_match(&hspec_ipv4_network, get_hinfo("1.2.3.3")));
  assert(!hspec_match(&hspec_ipv4_network, get_hinfo("1.2.4.3")));

  // host specifier - ipv6 address
  access_conf_host_specifier_t hspec_ipv6_address = { .network = { .net6 = {
      .address = __ip6("::1"), .length = 128}}, .type = HST_IPV6_NETWORK};

  assert(hspec_match(&hspec_ipv6_address, get_hinfo("0:0:0:0:0:0:0:1")));
  assert(!hspec_match(&hspec_ipv6_address, get_hinfo("1:2:3:4:5:6:7:8")));

  // host specifier - ipv6 network
  access_conf_host_specifier_t hspec_ipv6_network = { .network = { .net6 = {
      .address = __ip6("1::"), .length = 64}}, .type = HST_IPV6_NETWORK};

  assert(hspec_match(&hspec_ipv6_network, get_hinfo("1::1")));
  assert(!hspec_match(&hspec_ipv6_network, get_hinfo("2::1")));

}
