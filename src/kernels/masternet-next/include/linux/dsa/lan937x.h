/* SPDX-License-Identifier: GPL-2.0 */
/* Microchip LAN937X extended port information
 * Copyright (C) 2019-2020 Microchip Technology Inc.
 */
#ifndef _NET_DSA_LAN937X_H
#define _NET_DSA_LAN937X_H

#include <net/dsa.h>

struct ksz_port_ext {
	u8 lp_num;
	u8 tx_phy_log_prt;
	struct dsa_port *dp;
};

#endif/* _NET_DSA_LAN937X_H */
