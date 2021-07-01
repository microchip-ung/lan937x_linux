################################################################################
#
# Custom Scripts
#
################################################################################

CUSTOM_SCRIPTS_VERSION = 0.1
CUSTOM_SCRIPTS_DEV_DIR = ../scripts/
CUSTOM_SCRIPTS_SITE = ../scripts
CUSTOM_SCRIPTS_SITE_METHOD = local
CUSTOM_SCRIPTS_INSTALL_TARGET = YES

SCRIPTS_TARGET_DIR=$(TARGET_DIR)/scripts

define CUSTOM_SCRIPTS_INSTALL_TARGET_CMDS
	rm -rf $(TARGET_DIR)/scripts/*
	rsync -av $(CUSTOM_SCRIPTS_DEV_DIR) $(TARGET_DIR)/scripts/
endef


$(eval $(generic-package))
