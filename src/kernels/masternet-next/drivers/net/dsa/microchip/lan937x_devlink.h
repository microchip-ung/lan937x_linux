// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 Microchip Technology Inc.
 */

#ifndef _LAN937x_DEVLINK_H
#define _LAN937x_DEVLINK_H


int lan937x_devlink_init(struct dsa_switch *ds);
void lan937x_devlink_exit(struct dsa_switch *ds);
int lan937x_devlink_param_get(struct dsa_switch *ds, u32 id,
			      struct devlink_param_gset_ctx *ctx);
int lan937x_devlink_param_set(struct dsa_switch *ds, u32 id,
			      struct devlink_param_gset_ctx *ctx);
int lan937x_devlink_info_get(struct dsa_switch *ds,
			     struct devlink_info_req *req,
			     struct netlink_ext_ack *extack);

#endif
