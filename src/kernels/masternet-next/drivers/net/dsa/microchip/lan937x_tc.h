/* SPDX-License-Identifier: GPL-2.0 */
/* Microchip LAN937X TC Implementation
 * Copyright (C) 2021 Microchip Technology Inc.
 */

#ifndef _NET_DSA_DRIVERS_LAN937X_TC_H
#define _NET_DSA_DRIVERS_LAN937X_TC_H

#include <net/pkt_cls.h>

#define LAN937X_NUM_TC 8

void lan937x_tc_queue_init(struct dsa_switch *ds);

int lan937x_setup_tc(struct dsa_switch *ds, int port, enum tc_setup_type type,
		     void *type_data);
#endif
