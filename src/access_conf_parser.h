#ifndef __ACCESS_CONF_PARSER_H__
#define __ACCESS_CONF_PARSER_H__

#define PARSER_ERROR (-1)
#define PARSER_SUCCESS (0)

typedef struct parser_state {
  const char* buf;
  off_t col;
  bool err;
  bool eof;
  int fd;
  char last;
  off_t len;
  off_t line;
  const char* path;
  off_t pos;
  void* start;
} parser_state_t;

/**
 * Consume an action, represented as either '+' or '-' (unquoted).
 * Sets state->err if at EOF or error occurs.
 * Returns true iff successful.
 */
bool
expect_action(
  parser_state_t* state);

/**
 * Consume a colon (':') character.
 * Sets state->err if at EOF or error occurs.
 * Returns true iff successful.
 */
bool
expect_colon(
  parser_state_t* state);

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
expect_host_specifier(
  parser_state_t* state);

/**
 * Consume a username.
 * Sets state->err if at EOF or error occurs.
 * Returns true iff successful.
 */
bool
expect_user(
  parser_state_t* state);

/**
 * Returns true iff ch is a valid char in a host-specifier.
 */
bool
host_char(
  char ch);

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

/**
 * Print parse error to error log, prefixed by current line and column.
 */
void
parse_error(
  parser_state_t* state,
  const char* format,
  ...);

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
 * Consume a host specifier if available:
 * - IPv4 address
 * - IPv4 network
 * - IPv6 address
 * - IPv6 network
 * - hostname
 *
 * Sets state->err if at EOF or error occurs.
 * Returns true iff host specifier consumed.
 */
bool
skip_host_specifier(
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

/**
 * Set state->eof if all characters have been consumed
 */
void
update_eof(parser_state_t* state); 

/**
 * Returns true iff ch is a valid char in a username.
 */
bool
user_char(
  char ch);

/**
 * Validate the format of the access.conf file located at supplied path.
 * Returns true iff successful.
 */
bool
validate(
  const char* path
);

/**
 * Validate the format of the access.conf represented as state..
 * Returns true iff successful.
 */
bool
validate_file(
  parser_state_t* state
);

/**
 * Validate the format of the next line in the access.conf file
 * Returns true iff successful.
 */
bool
validate_line(
  parser_state_t* state
);

/**
 * Returns true iff ch is a whitespace character (' ' or '\t')
 */
bool
whitespace(
  char ch);

#endif /* __ACCESS_CONF_PARSER_H__ */

