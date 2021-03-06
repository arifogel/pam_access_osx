AUTOMAKE_OPTIONS = subdir-objects serial-tests
ACLOCAL_AMFLAGS=-I m4

### Module and test library

pam_access_osxdir = $(libdir)/security

PAM_ACCESS_OSX_DOC = man/pam_access_osx.8 man/access.conf.5

dist_man_MANS = $(PAM_ACCESS_OSX_DOC)

pam_access_osx_LTLIBRARIES = pam_access_osx.la

MODULE_SRC = \
   src/pam_access_osx.h src/pam_access_osx.c \
	 src/access_conf_parser.h src/access_conf_parser.c \
	 src/access_conf.h src/access_conf.c \
	 src/ip_util.h src/ip_util.c

pam_access_osx_la_LDFLAGS = $(AM_LDFLAGS) -avoid-version -export-dynamic -module -shared -export-symbols-regex "pam_sm_authenticate"
pam_access_osx_la_LIBADD = -lpam
pam_access_osx_la_SOURCES = $(MODULE_SRC)

### Tests
TEST_NAMES = \
	test_access_exports \
	test_access_conf \
	test_access_conf_parser_failure \
	test_access_conf_parser_parse \
	test_ip_network \
	test_end_to_end

TESTS = $(TEST_NAMES)

check_PROGRAMS = $(TEST_NAMES)

TEST_CFLAGS = $(AM_CFLAGS) -DPAM_ACCESS_OSX_TEST
TEST_LDFLAGS = -lpam

### Exports test
test_access_exports_CPPFLAGS = -I$(top_srcdir)/src
test_access_exports_SOURCES = tests/test_access_exports.c

### Other tests

# Test template
#test_access_<CHANGEME>_CPPFLAGS = -I$(top_srcdir)/src
#test_access_<CHANGEME>_LDADD = $(TEST_LDFLAGS)
#test_access_<CHANGEME>_SOURCES = tests/test_access_<CHANGEME>.c $(MODULE_SRC)

test_access_conf_CFLAGS = $(TEST_CFLAGS)
test_access_conf_CPPFLAGS = -I$(top_srcdir)/src
test_access_conf_LDADD = $(TEST_LDFLAGS)
test_access_conf_SOURCES = tests/test_access_conf.c $(MODULE_SRC)

test_access_conf_parser_parse_CFLAGS = $(TEST_CFLAGS)
test_access_conf_parser_parse_CPPFLAGS = -I$(top_srcdir)/src
test_access_conf_parser_parse_LDADD = $(TEST_LDFLAGS)
test_access_conf_parser_parse_SOURCES = tests/test_access_conf_parser_parse.c $(MODULE_SRC)

test_access_conf_parser_failure_CFLAGS = $(TEST_CFLAGS)
test_access_conf_parser_failure_CPPFLAGS = -I$(top_srcdir)/src
test_access_conf_parser_failure_LDADD = $(TEST_LDFLAGS)
test_access_conf_parser_failure_SOURCES = tests/test_access_conf_parser_failure.c $(MODULE_SRC)

test_ip_network_CFLAGS = $(TEST_CFLAGS)
test_ip_network_CPPFLAGS = -I$(top_srcdir)/src
test_ip_network_LDADD = $(TEST_LDFLAGS)
test_ip_network_SOURCES = tests/test_ip_network.c $(MODULE_SRC)

test_end_to_end_CFLAGS = $(TEST_CFLAGS)
test_end_to_end_CPPFLAGS = -I$(top_srcdir)/src
test_end_to_end_LDADD = $(TEST_LDFLAGS)
test_end_to_end_SOURCES = tests/test_end_to_end.c $(MODULE_SRC)

.PHONY: doc

doc: $(PAM_ACCESS_OSX_DOC)

man/pam_access_osx.8: man/pam_access_osx.8.md
	pandoc --standalone --to man man/pam_access_osx.8.md > man/pam_access_osx.8

man/access.conf.5: man/access.conf.5.md
	pandoc --standalone --to man man/access.conf.5.md > man/access.conf.5

