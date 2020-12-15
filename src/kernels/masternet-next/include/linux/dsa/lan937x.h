/* SPDX-License-Identifier: GPL-2.0 */
/* Microchip LAN937X extended port information
 * Copyright (C) 2019-2020 Microchip Technology Inc.
 */
#ifndef _NET_DSA_LAN937X_H
#define _NET_DSA_LAN937X_H

#include <net/dsa.h>
/* Lan937x port extended information which is used to refer
 * logical port number when accessing the registers
 */
struct lan937x_port_ext {
	u8 lp_num; /*logical port number*/
	u8 tx_phy_log_prt; /*tx phy port number in the device*/
	struct dsa_port *dp;
	struct ksz_device_ptp_shared *ptp_dev;
};

#endif/* _NET_DSA_LAN937X_H */
