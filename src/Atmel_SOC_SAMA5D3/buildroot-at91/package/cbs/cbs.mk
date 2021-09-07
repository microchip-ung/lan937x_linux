################################################################################
#
# cbs
#
################################################################################

CBS_VERSION = 1.0
CBS_SITE = ./package/cbs/src
CBS_SITE_METHOD = local

define CBS_BUILD_CMDS
    $(MAKE) CC="$(TARGET_CC)" LD="$(TARGET_LD)" -C $(@D)
endef

define CBS_INSTALL_TARGET_CMDS
    $(INSTALL) -D -m 0755 $(@D)/tsn_talker $(TARGET_DIR)/usr/bin
    $(INSTALL) -D -m 0755 $(@D)/tsn_listener $(TARGET_DIR)/usr/bin
    $(INSTALL) -D -m 0755 $(@D)/pkt_io $(TARGET_DIR)/usr/bin
    $(INSTALL) -D -m 0755 $(@D)/dsa_ver $(TARGET_DIR)/root
    $(INSTALL) -D -m 777 $(CBS_PKGDIR)/jira_tl30.cfg $(TARGET_DIR)/root
endef

$(eval $(generic-package))
