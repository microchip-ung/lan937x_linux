// SPDX-License-Identifier: GPL-2.0
/* Microchip LAN937X devlink implementation
 * Copyright (C) 2021 Microchip Technology Inc.
 */

#include "ksz_common.h"
#include "lan937x_reg.h"
#include "lan937x_dev.h"
#include "lan937x_devlink.h"

static int lan937x_cut_through_get(struct ksz_device *dev, u16 *value)
{
	*value = dev->cut_through_enable;

	return 0;
}

/* Devlink param is not accepting the hex decimal number. So as of now
 * 1000, 2000, is used to differentiate the lan1, 2 and so on.
 * Bit 0 to 7 corresponds to each queue. So if 1255 then for lan1 all the
 * queues are cut-through enabled.
 */
static int lan937x_cut_through_set(struct ksz_device *dev, u16 value)
{
	struct dsa_switch *ds = dev->ds;
	u8 queue = (value % 1000);
	u8 port = (value / 1000);
	u8 tas_gate_ctl;
	bool enable;
	int ret;
	u8 i;

	if ((port == 0) || (port > ds->num_ports)) {
		dev_err(dev->dev, "Port number should be from 1 to %d",
			ds->num_ports);
		return -EINVAL;
	}

	//Port starts from value 0
	port = port - 1;

	if (!dsa_is_user_port(ds, port)) {
		dev_err(dev->dev, "Port is not a user port");
		return -EINVAL;
	}

	ret = lan937x_pread8(dev, port, REG_PORT_TAS_GATE_CTRL__1,
			     &tas_gate_ctl);
	if (ret)
		return ret;

	if (!(tas_gate_ctl & TAS_GATE_ENABLE)) {
		dev_err(dev->dev, "TAS should be enabled before cut-through");
		return -EINVAL;
	}

	for (i = 0; i < ds->num_tx_queues; i++) {
		ret = lan937x_pwrite32(dev, port, REG_PORT_MTI_QUEUE_INDEX__4,
				       i);
		if (ret)
			return ret;

		if (queue & (1<<i))
			enable = 1;
		else
			enable = 0;

		ret = lan937x_port_cfg(dev, port, REG_PORT_TAS_CTL__1,
				       TAS_CUT_THROUGH, enable);
		if (ret)
			return ret;
	}

	dev->cut_through_enable = value;

	return 0;
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
		ret = lan937x_cut_through_get(dev, &ctx->val.vu16);
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
		ret = lan937x_cut_through_set(dev, ctx->val.vu16);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

static const struct devlink_param lan937x_devlink_params[] = {
	DSA_DEVLINK_PARAM_DRIVER(LAN937X_DEVLINK_PARAM_ID_CUT_THROUGH,
				 "cut_through", DEVLINK_PARAM_TYPE_U16,
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
