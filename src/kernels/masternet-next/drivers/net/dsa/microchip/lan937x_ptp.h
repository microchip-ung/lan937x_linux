/* SPDX-License-Identifier: GPL-2.0 */
/* Microchip LAN937X PTP Implementation
 * Copyright (C) 2021 Microchip Technology Inc.
 */

#ifndef _NET_DSA_DRIVERS_LAN937X_PTP_H
#define _NET_DSA_DRIVERS_LAN937X_PTP_H

#include <linux/irqreturn.h>
#include <linux/types.h>
#include "ksz_common.h"

#if IS_ENABLED(CONFIG_NET_DSA_MICROCHIP_LAN937X_PTP)

#include <linux/ptp_clock_kernel.h>

int lan937x_get_ts_info(struct dsa_switch *ds, int port,
			struct ethtool_ts_info *ts);
int lan937x_hwtstamp_get(struct dsa_switch *ds, int port, struct ifreq *ifr);
int lan937x_hwtstamp_set(struct dsa_switch *ds, int port, struct ifreq *ifr);
void lan937x_port_txtstamp(struct dsa_switch *ds, int port,
			   struct sk_buff *skb);
irqreturn_t lan937x_ptp_port_interrupt(struct ksz_device *dev, int port);
int lan937x_ptp_init(struct ksz_device *dev);
void lan937x_ptp_deinit(struct ksz_device *dev);
int lan937x_ptp_gettime(struct ptp_clock_info *ptp, struct timespec64 *ts);

#else

struct lan937x_ptp_data {
	struct mutex lock; //dummy data
};

static inline irqreturn_t lan937x_ptp_port_interrupt(struct ksz_device *dev,
						     int port)
{
	return IRQ_NONE;
}

static inline int lan937x_ptp_init(struct ksz_device *dev)
{
	return 0;
}

static inline void lan937x_ptp_deinit(struct ksz_device *dev)
{
}

static inline int lan937x_get_ts_info(struct dsa_switch *ds, int port,
				      struct ethtool_ts_info *ts)
{
	return -EOPNOTSUPP;
}

static inline int lan937x_hwtstamp_get(struct dsa_switch *ds, int port,
				       struct ifreq *ifr)
{
	return -EOPNOTSUPP;
}

static inline int lan937x_hwtstamp_set(struct dsa_switch *ds, int port,
				       struct ifreq *ifr)
{
	return -EOPNOTSUPP;
}

static inline void lan937x_port_txtstamp(struct dsa_switch *ds, int port,
					 struct sk_buff *skb)
{
}

#endif /* End of CONFIG_NET_DSA_MICROCHIOP_LAN937X_PTP */

#endif
