################################################################################
#
# linuxptp
#
################################################################################

PTPUTIL_VERSION = 2.0
PTPUTIL_SOURCE = linuxptp-$(PTPUTIL_VERSION).tgz
PTPUTIL_SITE = http://downloads.sourceforge.net/linuxptp
PTPUTIL_LICENSE = GPL-2.0+
PTPUTIL_LICENSE_FILES = COPYING


define PTPUTIL_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 644 $(PTPUTIL_PKGDIR)/def.cfg \
		$(TARGET_DIR)/root/def.cfg

	$(INSTALL) -D -m 644 $(PTPUTIL_PKGDIR)/gptp_test.cfg \
		$(TARGET_DIR)/root/gptp_test.cfg

	$(INSTALL) -D -m 644 $(PTPUTIL_PKGDIR)/jira_tl30.cfg \
		$(TARGET_DIR)/root/jira_tl30.cfg

	$(INSTALL) -D -m 777 $(PTPUTIL_PKGDIR)/tc_exec.sh \
		$(TARGET_DIR)/root/tc_exec.sh
endef

$(eval $(generic-package))
