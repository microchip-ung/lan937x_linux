// SPDX-License-Identifier: GPL-2.0
/* Microchip lan937x dev ops functions
 * Copyright (C) 2021 Microchip Technology Inc.
 */
#ifndef _LAN937x_TAS_H
#define _LAN937x_TAS_H

#if IS_ENABLED(CONFIG_NET_DSA_MICROCHIP_LAN937X_TAS)

int lan937x_setup_tc_taprio(struct dsa_switch *ds, int port,
			    struct tc_taprio_qopt_offload *admin);
#else

static inline int lan937x_setup_tc_taprio(struct dsa_switch *ds, int port,
					  struct tc_taprio_qopt_offload *admin)
{
	return -EOPNOTSUPP;
}
#endif

#endif
