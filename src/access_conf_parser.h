#ifndef __ACCESS_CONF_PARSER_H__
#define __ACCESS_CONF_PARSER_H__

#include <stdbool.h>

#include "access_conf.h"

#define ADDR_STR_MAX_LEN (16)
#define ADDR6_STR_MAX_LEN (48)

extern size_t pam_exec_osx_allocated_entry_count;

extern size_t pam_exec_osx_allocated_hostname_count;

extern size_t pam_exec_osx_allocated_hspec_count;

extern size_t pam_exec_osx_allocated_uspec_count;

extern size_t pam_exec_osx_hspec_all_count;

extern size_t pam_exec_osx_hspec_hostname_count;

extern size_t pam_exec_osx_hspec_ipv4_address_count;

extern size_t pam_exec_osx_hspec_ipv4_network_count;

extern size_t pam_exec_osx_hspec_ipv6_address_count;

extern size_t pam_exec_osx_hspec_ipv6_network_count;

typedef struct parser_state {
  const char* buf;
  off_t col;
  bool eof;
  bool err;
  int fd;
  access_conf_entry_t* first_entry;
  access_conf_host_specifier_t* cur_hspec;
  char last;
  access_conf_entry_t* last_entry;
  off_t len;
  off_t line;
  const char* path;
  off_t pos;
  void* start;
} parser_state_t;

void
destroy_entry(
  access_conf_entry_t* entry);

void
destroy_hspec(
  access_conf_host_specifier_t* hspec);

void
destroy_uspec(
  char* uspec);

/**
 * Consume a colon (':') character.
 * Sets state->err if at EOF or error occurs.
 * Returns true iff successful.
 */
bool
expect_colon(
  parser_state_t* state);

/**
 * Returns true iff ch is a valid char in a host-specifier.
 */
bool
host_char(
  char ch);

bool
init_file(
  const char* path,
  parser_state_t* state);

/**
 * Set initial values for parser state.
 */
void
init_state(
  parser_state_t* state);

/**
 * Writes the next char in the stream to state->last
 * Sets state->err if at EOF.
 * Returns true iff no error occurred.
 */
bool
next_char(
  parser_state_t* state);

access_conf_entry_t*
parse(
  parser_state_t* state);

/**
 * Consume an action, represented as either '+' or '-' (unquoted).
 * Sets state->err if at EOF or error occurs.
 * Returns true iff successful.
 */
bool
parse_action(
  parser_state_t* state,
  access_conf_entry_t* entry);

/**
 * Print parse error to error log, prefixed by current line and column.
 */
void
parse_error(
  parser_state_t* state,
  const char* format,
  ...);

access_conf_entry_t*
parse_file(
  const char* path);

/**
 * Consume a host specifier:
 * - IPv4 address
 * - IPv4 network
 * - IPv6 address
 * - IPv6 network
 * - hostname
 *
 * Sets state->err if at EOF or error occurs.
 * Returns true iff successful.
 */
bool
parse_host_specifier(
  parser_state_t* state,
  bool required,
  access_conf_entry_t* entry);

bool
parse_line(
  parser_state_t* state);

/**
 * Consume a username.
 * Sets state->err if at EOF or error occurs.
 * Returns true iff successful.
 */
bool
parse_user(
  parser_state_t* state,
  access_conf_entry_t* entry);

/**
 * Writes the next char in the stream to nc without advancing the stream.
 * Behavior is undefined if state->eof is true.
 */
char
peek_char(
  parser_state_t* state);

/**
 * Consume a comment (#.*$) if available.
 * Returns true iff comment consumed.
 */
bool
skip_comment(
  parser_state_t* state);

/**
 * Consume a newline '\n' character if available.
 * Returns true iff newline consumed.
 */
bool
skip_newline(
  parser_state_t* state);

/**
 * Consumes whitespace if available.
 * Returns true iff whitespace consumed.
 */
bool
skip_whitespace(
  parser_state_t* state);

bool
sp_all(
  parser_state_t* state,
  const char* hostname,
  access_conf_host_specifier_t* hspec);

bool
sp_ipv4_address(
  parser_state_t* state,
  const char* hostname,
  access_conf_host_specifier_t* hspec);

bool
sp_ipv4_network(
  parser_state_t* state,
  const char* hostname,
  access_conf_host_specifier_t* hspec);

bool
sp_ipv6_address(
  parser_state_t* state,
  const char* hostname,
  access_conf_host_specifier_t* hspec);

bool
sp_ipv6_network(
  parser_state_t* state,
  const char* hostname,
  access_conf_host_specifier_t* hspec);

bool
specialize_hspec(
  parser_state_t* state,
  const char* hostname,
  access_conf_host_specifier_t* hspec);

/**
 * Set state->eof if all characters have been consumed
 */
void
update_eof(
  parser_state_t* state);

/**
 * Returns true iff ch is a valid char in a username.
 */
bool
user_char(
  char ch);

/**
 * Returns true iff ch is a whitespace character (' ' or '\t')
 */
bool
whitespace(
  char ch);

#endif /* __ACCESS_CONF_PARSER_H__ */

