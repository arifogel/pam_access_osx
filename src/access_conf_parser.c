#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/mman.h>

#include "pam_access_osx.h"
#include "access_conf_parser.h"

void
clean_state(parser_state_t* state) {
  if (state->start != NULL) {
    if (munmap(state->start, state->len) < 0) {
      pam_access_osx_syslog(LOG_ERR, "Could not unmap configuration file: '%s': %s\n", state->path, strerror(errno));
    }
    state->start = NULL;
  }
  if (state->fd >= 0) {
    if (close(state->fd) < 0) {
      pam_access_osx_syslog(LOG_ERR, "Could not close configuration file: '%s': %s\n", state->path, strerror(errno));
    }
    state->fd = -1;
  }
}

bool
digit(char ch) {
  return '0' <= ch && ch <= '9';
}

bool
expect_action(parser_state_t* state) {
  pam_access_osx_syslog(LOG_DEBUG, "Entered expect_action\n");
  if (!next_char(state)) {
    return false;
  }
  if (!(state->last == '+' || state->last == '-')) {
    parse_error(state, "Expected '+' or '-'\n");
    return false;
  }
  return true;
}

bool
expect_colon(parser_state_t* state) {
  pam_access_osx_syslog(LOG_DEBUG, "Entered expect_colon\n");
  if (!next_char(state)) {
    return false;
  }
  if (state->last != ':') {
    parse_error(state, "Expected ':'\n");
    return false;
  }
  return true;;
}

bool
expect_host_specifier(parser_state_t* state) {
  pam_access_osx_syslog(LOG_DEBUG, "Entered expect_host_specifier\n");
  if (!next_char(state)) {
    return false;
  }
  if (!host_char(state->last)) {
    parse_error(state, "Expected host-specifier\n");
    return false;
  }
  while (!state->eof && host_char(peek_char(state))) {
    next_char(state);
  }
  return true;
}

bool
expect_user(parser_state_t* state) {
  pam_access_osx_syslog(LOG_DEBUG, "Entered expect_user\n");
  if (!next_char(state)) {
    return false;
  }
  if (!user_char(state->last)) {
    parse_error(state, "Expected user\n");
    return false;
  }
  while (!state->eof && user_char(peek_char(state))) {
    next_char(state);
  }
  return true;
}

bool
host_char(char ch) {
  return ch != '\n' && ch != '#' && ch != ' ' && ch != '\t';
}

void
init_state(parser_state_t* state) {
  state->buf = NULL;
  state->col = 0;
  state->eof = false;
  state->err = false;
  state->fd = -1;
  state->len = 0;
  state->line = 1;
  state->pos = 0;
  state->start = NULL;
}

bool
lower(char ch) {
  return 'a' <= ch && ch <= 'z';
}

bool
next_char(parser_state_t* state) {
  pam_access_osx_syslog(LOG_DEBUG, "Entered next_char\n");
  if (state->eof) {
    state->err = true;
    return false;
  } else {
    if (state->last == '\n') {
      state->line++;
      state->col = 0;
    } else {
      state->col++;
    }
    state->last = state->buf[state->pos++];
    update_eof(state);
  }
  char chstr[3] = {0};
  switch(state->last) {
    case '\n':
      chstr[0] = '\\';
      chstr[1] = 'n';
      break;
    case '\t':
      chstr[0] = '\\';
      chstr[1] = 't';
      break;
    default:
      chstr[0] = state->last;
  }
  pam_access_osx_syslog(LOG_DEBUG, "%d:%d: Consumed '%s'\n", state->line, state->col, chstr);
  return true;
}

void
parse_error(parser_state_t* state, const char* format, ...) {
  pam_access_osx_syslog(LOG_DEBUG, "Entered parse_error\n");
  state->err = true;
  va_list args;
  va_start(args, format);
  pam_access_osx_syslog(LOG_ERR, "%d:%d: PARSE ERROR: ", state->line, state->col);
  pam_access_osx_vsyslog(LOG_ERR, format, args);
}

char
peek_char(parser_state_t* state) {
  pam_access_osx_syslog(LOG_DEBUG, "Entered peek_char\n");
  return state->buf[state->pos];
}

bool
skip_comment(parser_state_t* state) {
  pam_access_osx_syslog(LOG_DEBUG, "Entered skip_comment\n");
  bool consumed = false;
  if (!state->eof && peek_char(state) == '#') {
    // Skip '#'
    next_char(state);
    consumed = true;
    while (!state->eof && peek_char(state) != '\n') {
      // Skip non-newline
      next_char(state);
    }
  }
  return consumed;
}

bool
skip_host_specifier(parser_state_t* state) {
  pam_access_osx_syslog(LOG_DEBUG, "Entered skip_host_specifier\n");
  bool consumed = false;
  while (!state->eof && host_char(peek_char(state))) {
    next_char(state);
    consumed = true;
  }
  return consumed;

}

bool
skip_newline(parser_state_t* state) {
  pam_access_osx_syslog(LOG_DEBUG, "Entered skip_newline\n");
  bool consumed = false;
  if (!state->eof && peek_char(state) == '\n') {
    next_char(state);
    consumed = true;
  }
  return consumed;
}

bool
skip_whitespace(parser_state_t* state) {
  pam_access_osx_syslog(LOG_DEBUG, "Entered skip_whitespace\n");
  bool consumed = false;
  while (!state->eof && whitespace(peek_char(state))) {
    next_char(state);
    consumed = true;
  }
  return consumed;
}

void
update_eof(parser_state_t* state) {
  pam_access_osx_syslog(LOG_DEBUG, "Entered update_eof\n");
  if (state->pos >= state->len) {
    state->eof = true;
  }
}

bool
upper(char ch) {
  return 'A' <= ch && ch <= 'Z';
}

bool
user_char(char ch) {
  return ch != '\n' && ch != ':' && ch != '#' && ch != ' ' && ch != '\t';
}

bool
validate(const char* path) {
  pam_access_osx_syslog(LOG_DEBUG, "Entered validate\n");
  parser_state_t state;
  init_state(&state);
  state.fd = open(path, O_RDONLY);
  if (state.fd == -1) {
    pam_access_osx_syslog(LOG_ERR, "Could not open configuration file: '%s': %s\n", path, strerror(errno));
    clean_state(&state);
    return false;
  }
  state.len = lseek(state.fd, 0, SEEK_END);
  if (state.len < 0) {
    pam_access_osx_syslog(LOG_ERR, "Could not get length of configuration file: '%s': %s\n", path, strerror(errno));
    clean_state(&state);
    return false;
  }
  if (lseek(state.fd, 0, SEEK_SET) < 0) {
    pam_access_osx_syslog(LOG_ERR, "Could not seek to beginning of configuration file after fetching length: '%s': %s\n", path, strerror(errno));
    clean_state(&state);
    return false;
  }
  state.start = mmap(0, state.len, PROT_READ, MAP_FILE | MAP_PRIVATE, state.fd, 0);
  if (state.start == MAP_FAILED) {
    pam_access_osx_syslog(LOG_ERR, "Could not mmap configuration file: '%s': %s\n", path, strerror(errno));
    clean_state(&state);
    return false;
  }
  state.buf = state.start;
  pam_access_osx_syslog(LOG_DEBUG, "Beginning validation of configuration file: '%s'\n", path);
  bool valid = validate_file(&state);
  clean_state(&state);
  return valid;
}

bool
validate_file(parser_state_t* state) {
  pam_access_osx_syslog(LOG_DEBUG, "Entered validate_file\n");
  while (skip_comment(state) || skip_newline(state) || skip_whitespace(state)) {}
  while (!state->eof && !state->err) {
    validate_line(state);
  }
  return !state->err;
}

bool
validate_line(parser_state_t* state) {
  pam_access_osx_syslog(LOG_DEBUG, "Entered validate_line\n");
  skip_whitespace(state);
  // Action
  if (!expect_action(state)) {
    return false;
  }
  skip_whitespace(state);
  // :
  if (!expect_colon(state)) {
    return false;
  }
  skip_whitespace(state);
  // User
  if (!expect_user(state)) {
    return false;
  }
  skip_whitespace(state);
  // :
  if (!expect_colon(state)) {
    return false;
  }
  skip_whitespace(state);
  // HS1
  if (!expect_host_specifier(state)) {
    return false;
  }
  // HS2-
  while (skip_whitespace(state) || skip_host_specifier(state)) {}
  // #.*\n
  while (skip_comment(state) || skip_newline(state) || skip_whitespace(state)) {}
  return true;
}

bool
word_char(char ch) {
  return ch != '\n' && ch != ' ' && ch != '\t' && ch != '#';
}

bool
whitespace(char ch) {
  return ch == ' ' || ch == '\t';
}

