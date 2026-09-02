PACKAGE_NAME = kisa-cce-linux-scanner

prefix ?= /usr/local
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin
libdir ?= $(exec_prefix)/lib
pkglibdir ?= $(libdir)/$(PACKAGE_NAME)
datarootdir ?= $(prefix)/share
datadir ?= $(datarootdir)/$(PACKAGE_NAME)
mandir ?= $(datarootdir)/man
man8dir ?= $(mandir)/man8

INSTALL ?= install
INSTALL_PROGRAM = $(INSTALL) -m 0755
INSTALL_DATA = $(INSTALL) -m 0644

LIBRARY_FILES = \
	lib/checks_account_file.sh \
	lib/checks_service.sh \
	lib/checks_system.sh \
	lib/core.sh \
	lib/kisa-cce-scan-main.sh \
	lib/resolvers.sh

MANPAGE_FILES = man/kisa-cce-scan.8

.PHONY: all check install lint

all:

check:
	/bin/sh -n bin/kisa-cce-scan
	/bin/bash -n $(LIBRARY_FILES) tests/run.sh
	./tests/run.sh

lint:
	shellcheck -x bin/kisa-cce-scan $(LIBRARY_FILES) tests/run.sh

install:
	$(INSTALL) -d \
		"$(DESTDIR)$(bindir)" \
		"$(DESTDIR)$(pkglibdir)" \
		"$(DESTDIR)$(datadir)" \
		"$(DESTDIR)$(man8dir)"
	$(INSTALL_PROGRAM) bin/kisa-cce-scan "$(DESTDIR)$(bindir)/kisa-cce-scan"
	$(INSTALL_DATA) $(LIBRARY_FILES) "$(DESTDIR)$(pkglibdir)"
	$(INSTALL_DATA) data/criteria.tsv data/VERSION "$(DESTDIR)$(datadir)"
	$(INSTALL_DATA) $(MANPAGE_FILES) "$(DESTDIR)$(man8dir)"
