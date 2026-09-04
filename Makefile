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
sysconfdir ?= /etc
scannerconfdir ?= $(sysconfdir)/kisa-cce-scanner
policydir ?= $(scannerconfdir)/policy.d

INSTALL ?= install
INSTALL_PROGRAM = $(INSTALL) -m 0755
INSTALL_DATA = $(INSTALL) -m 0644
INSTALL_POLICY_DATA = $(INSTALL) -m 0600

CHECK_LIBRARY_FILES = \
	lib/kisa-cce-checks/_account-file.sh \
	lib/kisa-cce-checks/_service.sh \
	lib/kisa-cce-checks/_system.sh

CLI_LIBRARY_FILES = \
	lib/kisa-cce-cli/_collect-main.sh \
	lib/kisa-cce-cli/_policy-compile-main.sh \
	lib/kisa-cce-cli/_scan-main.sh

CORE_LIBRARY_FILES = \
	lib/kisa-cce-core/_core.sh \
	lib/kisa-cce-core/_i18n.sh \
	lib/kisa-cce-core/_scan-epoch.sh

POLICY_LIBRARY_FILES = \
	lib/kisa-cce-policy/_policy.sh \
	lib/kisa-cce-policy/_policy-yaml.sh

RESOLVER_LIBRARY_FILES = lib/kisa-cce-resolvers/_resolvers.sh

RUNTIME_LIBRARY_FILES = \
	lib/kisa-cce-runtime/_evidence.sh \
	lib/kisa-cce-runtime/_runtime-fallback.sh

LIBRARY_FILES = \
	$(CHECK_LIBRARY_FILES) \
	$(CLI_LIBRARY_FILES) \
	$(CORE_LIBRARY_FILES) \
	$(POLICY_LIBRARY_FILES) \
	$(RESOLVER_LIBRARY_FILES) \
	$(RUNTIME_LIBRARY_FILES)

PROGRAM_FILES = bin/kisa-cce-collect bin/kisa-cce-policy-compile bin/kisa-cce-scan

MANPAGE_FILES = man/kisa-cce-collect.8 man/kisa-cce-policy-compile.8 man/kisa-cce-scan.8

POLICY_FILES = etc/kisa-cce-scanner/policy.d/00-default.tsv

TEST_FILES = \
	tests/account_manual_reductions.sh \
	tests/automation_mode.sh \
	tests/default_policy.sh \
	tests/policy_compile.sh \
	tests/documentation_links.sh \
	tests/evidence_bundle_v2.sh \
	tests/non_systemd_runtime.sh \
	tests/pam_cache.sh \
	tests/performance_cache.sh \
	tests/redaction_paths.sh \
	tests/report_readability.sh \
	tests/runtime_fallback.sh \
	tests/run.sh \
	tests/scan_epoch.sh \
	tests/service_evidence_quality.sh \
	tests/runtime_cache.sh \
	tests/system_checks.sh \
	tests/typed_policy.sh \
	tests/u28_evidence_state.sh \
	tests/u30_comment_sources.sh \
	tests/u67_numeric_uid.sh

.PHONY: all check install lint

all:

check:
	/bin/sh -n $(PROGRAM_FILES)
	/bin/bash -n $(LIBRARY_FILES) $(TEST_FILES) tests/benchmark.sh
	./tests/account_manual_reductions.sh
	./tests/automation_mode.sh
	./tests/default_policy.sh
	./tests/policy_compile.sh
	./tests/documentation_links.sh
	./tests/run.sh
	./tests/evidence_bundle_v2.sh
	./tests/non_systemd_runtime.sh
	./tests/performance_cache.sh
	./tests/pam_cache.sh
	./tests/redaction_paths.sh
	./tests/report_readability.sh
	./tests/runtime_fallback.sh
	./tests/scan_epoch.sh
	./tests/service_evidence_quality.sh
	./tests/runtime_cache.sh
	./tests/system_checks.sh
	./tests/typed_policy.sh
	./tests/u28_evidence_state.sh
	./tests/u30_comment_sources.sh
	./tests/u67_numeric_uid.sh

lint:
	shellcheck --severity=warning -x $(PROGRAM_FILES) $(LIBRARY_FILES) $(TEST_FILES) tests/benchmark.sh

install:
	$(INSTALL) -d \
		"$(DESTDIR)$(bindir)" \
		"$(DESTDIR)$(pkglibdir)/kisa-cce-checks" \
		"$(DESTDIR)$(pkglibdir)/kisa-cce-cli" \
		"$(DESTDIR)$(pkglibdir)/kisa-cce-core" \
		"$(DESTDIR)$(pkglibdir)/kisa-cce-policy" \
		"$(DESTDIR)$(pkglibdir)/kisa-cce-resolvers" \
		"$(DESTDIR)$(pkglibdir)/kisa-cce-runtime" \
		"$(DESTDIR)$(datadir)" \
		"$(DESTDIR)$(datadir)/locale/en/LC_MESSAGES" \
		"$(DESTDIR)$(datadir)/locale/ko/LC_MESSAGES" \
		"$(DESTDIR)$(man8dir)"
	$(INSTALL) -d -m 0700 "$(DESTDIR)$(policydir)"
	$(INSTALL_PROGRAM) $(PROGRAM_FILES) "$(DESTDIR)$(bindir)"
	$(INSTALL_DATA) $(CHECK_LIBRARY_FILES) "$(DESTDIR)$(pkglibdir)/kisa-cce-checks"
	$(INSTALL_DATA) $(CLI_LIBRARY_FILES) "$(DESTDIR)$(pkglibdir)/kisa-cce-cli"
	$(INSTALL_DATA) $(CORE_LIBRARY_FILES) "$(DESTDIR)$(pkglibdir)/kisa-cce-core"
	$(INSTALL_DATA) $(POLICY_LIBRARY_FILES) "$(DESTDIR)$(pkglibdir)/kisa-cce-policy"
	$(INSTALL_DATA) $(RESOLVER_LIBRARY_FILES) "$(DESTDIR)$(pkglibdir)/kisa-cce-resolvers"
	$(INSTALL_DATA) $(RUNTIME_LIBRARY_FILES) "$(DESTDIR)$(pkglibdir)/kisa-cce-runtime"
	$(INSTALL_DATA) data/criteria.tsv data/VERSION "$(DESTDIR)$(datadir)"
	$(INSTALL_DATA) share/kisa-cce-linux-scanner/locale/en/LC_MESSAGES/kisa-cce-linux-scanner.po \
		"$(DESTDIR)$(datadir)/locale/en/LC_MESSAGES"
	$(INSTALL_DATA) share/kisa-cce-linux-scanner/locale/ko/LC_MESSAGES/kisa-cce-linux-scanner.po \
		"$(DESTDIR)$(datadir)/locale/ko/LC_MESSAGES"
	$(INSTALL_DATA) $(MANPAGE_FILES) "$(DESTDIR)$(man8dir)"
	@if [ ! -e "$(DESTDIR)$(policydir)/00-default.tsv" ] && \
		[ ! -L "$(DESTDIR)$(policydir)/00-default.tsv" ]; then \
		$(INSTALL_POLICY_DATA) $(POLICY_FILES) "$(DESTDIR)$(policydir)/00-default.tsv"; \
	fi
