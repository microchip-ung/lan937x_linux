################################################################################
#
# cbs
#
################################################################################

LAN937X_TC_VERSION = 1.0
LAN937X_TC_SITE = ./package/microchip/lan937x_tc/src
LAN937X_TC_SITE_METHOD = local

define LAN937X_TC_BUILD_CMDS
    $(MAKE) CC="$(TARGET_CC)" LD="$(TARGET_LD)" -C $(@D)
endef

define LAN937X_TC_INSTALL_TARGET_CMDS
    $(INSTALL) -D -m 0755 $(@D)/tsn_talker $(TARGET_DIR)/root
    $(INSTALL) -D -m 0755 $(@D)/tsn_listener $(TARGET_DIR)/root
    $(INSTALL) -D -m 0755 $(@D)/dsa_ver $(TARGET_DIR)/root
endef

$(eval $(generic-package))
