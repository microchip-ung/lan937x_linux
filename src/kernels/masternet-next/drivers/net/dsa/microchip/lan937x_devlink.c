// SPDX-License-Identifier: GPL-2.0
/* Microchip LAN937X devlink implementation
 * Copyright (C) 2021 Microchip Technology Inc.
 */

#include "ksz_common.h"
#include "lan937x_reg.h"
#include "lan937x_dev.h"
#include "lan937x_devlink.h"

static int lan937x_cut_through_get(struct ksz_device *dev, u8 *value)
{
	*value = dev->cut_through_enable;

	return 0;
}

/* Each bit in value correspond to one port.
 * For example, if bit 0 is 1, then it enable the cut through for port 0
 * otherwise disable.
 */
static int lan937x_cut_through_set(struct ksz_device *dev, u8 value)
{
	struct dsa_switch *ds = dev->ds;
	bool enable;
	int port;
	int ret;

	dev->cut_through_enable = value;

	for (port = 0; port < ds->num_ports; port++) {
		if (!dsa_is_user_port(ds, port))
			continue;

		if(value & (1<<port))
			enable = 1;
		else
			enable = 0;

		ret = lan937x_port_cfg(dev, port, REG_PORT_TAS_CTL__1,
				       TAS_CUT_THROUGH, enable);
		if (ret)
			break;
	}

	return ret;
}

enum lan937x_devlink_param_id {
	LAN937X_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
	LAN937X_DEVLINK_PARAM_ID_CUT_THROUGH,
};

int lan937x_devlink_param_get(struct dsa_switch *ds, u32 id,
			      struct devlink_param_gset_ctx *ctx)
{
	struct ksz_device *dev = ds->priv;
	int ret;

	switch (id) {
	case LAN937X_DEVLINK_PARAM_ID_CUT_THROUGH:
		ret = lan937x_cut_through_get(dev, &ctx->val.vu8);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

int lan937x_devlink_param_set(struct dsa_switch *ds, u32 id,
			      struct devlink_param_gset_ctx *ctx)
{
	struct ksz_device *dev = ds->priv;
	int ret;

	switch (id) {
	case LAN937X_DEVLINK_PARAM_ID_CUT_THROUGH:
		ret = lan937x_cut_through_set(dev, ctx->val.vu8);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

static const struct devlink_param lan937x_devlink_params[] = {
	DSA_DEVLINK_PARAM_DRIVER(LAN937X_DEVLINK_PARAM_ID_CUT_THROUGH,
				 "cut_through", DEVLINK_PARAM_TYPE_U8,
				 BIT(DEVLINK_PARAM_CMODE_RUNTIME)),
};

static int lan937x_init_devlink_params(struct dsa_switch *ds)
{
	return dsa_devlink_params_register(ds, lan937x_devlink_params,
					   ARRAY_SIZE(lan937x_devlink_params));
}

static void lan937x_exit_devlink_params(struct dsa_switch *ds)
{
	dsa_devlink_params_unregister(ds, lan937x_devlink_params,
				      ARRAY_SIZE(lan937x_devlink_params));
}

int lan937x_devlink_info_get(struct dsa_switch *ds,
			     struct devlink_info_req *req,
			     struct netlink_ext_ack *extack)
{
	int ret;

	ret = devlink_info_driver_name_put(req, "lan937x");
	if (ret)
		return ret;

	ret = devlink_info_version_fixed_put(
		req, DEVLINK_INFO_VERSION_GENERIC_ASIC_ID, "lan937x");
	return ret;
}

int lan937x_devlink_init(struct dsa_switch *ds)
{
	int ret;

	ret = lan937x_init_devlink_params(ds);
	if (ret)
		return ret;

	return 0;
}

void lan937x_devlink_exit(struct dsa_switch *ds)
{
	lan937x_exit_devlink_params(ds);
}
