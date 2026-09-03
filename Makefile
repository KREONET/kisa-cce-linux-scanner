# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

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
	lib/evidence.sh \
	lib/i18n.sh \
	lib/kisa-cce-collect-main.sh \
	lib/kisa-cce-scan-main.sh \
	lib/policy.sh \
	lib/scan_epoch.sh \
	lib/resolvers.sh

PROGRAM_FILES = bin/kisa-cce-collect bin/kisa-cce-scan

MANPAGE_FILES = man/kisa-cce-collect.8 man/kisa-cce-scan.8

TEST_FILES = \
	tests/documentation_links.sh \
	tests/evidence_bundle_v2.sh \
	tests/pam_cache.sh \
	tests/performance_cache.sh \
	tests/run.sh \
	tests/scan_epoch.sh \
	tests/runtime_cache.sh \
	tests/system_checks.sh \
	tests/typed_policy.sh \
	tests/u67_numeric_uid.sh

.PHONY: all check install lint

all:

check:
	/bin/sh -n $(PROGRAM_FILES)
	/bin/bash -n $(LIBRARY_FILES) $(TEST_FILES) tests/benchmark.sh
	./tests/documentation_links.sh
	./tests/run.sh
	./tests/evidence_bundle_v2.sh
	./tests/performance_cache.sh
	./tests/pam_cache.sh
	./tests/scan_epoch.sh
	./tests/runtime_cache.sh
	./tests/system_checks.sh
	./tests/typed_policy.sh
	./tests/u67_numeric_uid.sh

lint:
	shellcheck --severity=warning -x $(PROGRAM_FILES) $(LIBRARY_FILES) $(TEST_FILES) tests/benchmark.sh

install:
	$(INSTALL) -d \
		"$(DESTDIR)$(bindir)" \
		"$(DESTDIR)$(pkglibdir)" \
		"$(DESTDIR)$(datadir)" \
		"$(DESTDIR)$(datadir)/locale/en/LC_MESSAGES" \
		"$(DESTDIR)$(datadir)/locale/ko/LC_MESSAGES" \
		"$(DESTDIR)$(man8dir)"
	$(INSTALL_PROGRAM) $(PROGRAM_FILES) "$(DESTDIR)$(bindir)"
	$(INSTALL_DATA) $(LIBRARY_FILES) "$(DESTDIR)$(pkglibdir)"
	$(INSTALL_DATA) data/criteria.tsv data/VERSION "$(DESTDIR)$(datadir)"
	$(INSTALL_DATA) share/kisa-cce-linux-scanner/locale/en/LC_MESSAGES/kisa-cce-linux-scanner.po \
		"$(DESTDIR)$(datadir)/locale/en/LC_MESSAGES"
	$(INSTALL_DATA) share/kisa-cce-linux-scanner/locale/ko/LC_MESSAGES/kisa-cce-linux-scanner.po \
		"$(DESTDIR)$(datadir)/locale/ko/LC_MESSAGES"
	$(INSTALL_DATA) $(MANPAGE_FILES) "$(DESTDIR)$(man8dir)"
