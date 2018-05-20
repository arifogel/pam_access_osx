AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS=-I m4

### Module and test library

pam_access_osxdir = $(libdir)/security

pam_access_osx_LTLIBRARIES = pam_access_osx.la

MODULE_SRC = src/pam_access_osx.h src/pam_access_osx.c \
						 src/access_conf_parser.h src/access_conf_parser.c

pam_access_osx_la_LDFLAGS = $(AM_LDFLAGS) -avoid-version -export-dynamic -module -shared -export-symbols-regex "pam_sm_authenticate"
pam_access_osx_la_LIBADD = -lpam
pam_access_osx_la_SOURCES = $(MODULE_SRC)

### Tests
TEST_NAMES = \
	test_access_exports \
	test_access_parser

TESTS = $(TEST_NAMES)

check_PROGRAMS = $(TEST_NAMES)

TEST_LDFLAGS = -lpam

### Exports test
test_access_exports_CPPFLAGS = -I$(top_srcdir)/src
test_access_exports_SOURCES = tests/test_access_exports.c

### Other tests

# Test template
#test_access_<CHANGEME>_CPPFLAGS = -I$(top_srcdir)/src
#test_access_<CHANGEME>_LDADD = $(TEST_LDFLAGS)
#test_access_<CHANGEME>_SOURCES = tests/test_access_<CHANGEME>.c $(MODULE_SRC)

test_access_parser_CPPFLAGS = -I$(top_srcdir)/src
test_access_parser_LDADD = $(TEST_LDFLAGS)
test_access_parser_SOURCES = tests/test_access_parser.c $(MODULE_SRC)

