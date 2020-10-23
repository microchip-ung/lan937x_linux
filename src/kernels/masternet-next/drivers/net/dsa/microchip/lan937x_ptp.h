#ifndef _NET_DSA_DRIVERS_LAN937X_PTP_H
#define _NET_DSA_DRIVERS_LAN937X_PTP_H

#if IS_ENABLED(CONFIG_NET_DSA_MICROCHIP_LAN937X_PTP)

#include <linux/ptp_clock_kernel.h>

struct lan937x_ptp_data
{
	struct ptp_clock_info caps;
	struct ptp_clock *clock;
};

int lan937x_get_ts_info(struct dsa_switch *ds, int port, struct ethtool_ts_info *ts);
int lan937x_hwtstamp_get(struct dsa_switch *ds, int port, struct ifreq *ifr);
int lan937x_hwtstamp_set(struct dsa_switch *ds, int port, struct ifreq *ifr);
int lan937x_ptp_clock_register(struct dsa_switch *ds);

#else

struct lan937x_ptp_data
{
	struct mutex lock;
};

static inline int lan937x_ptp_clock_register(struct dsa_switch *ds)
{
	return 0;
}

static inline int lan937x_get_ts_info(struct dsa_switch *ds, int port, struct ethtool_ts_info *ts)
{
	return -EOPNOTSUPP;
}

static inline int lan937x_hwtstamp_get(struct dsa_switch *ds, int port, struct ifreq *ifr)
{
	return -EOPNOTSUPP;
}

static inline int lan937x_hwtstamp_set(struct dsa_switch *ds, int port, struct ifreq *ifr)
{
	return -EOPNOTSUPP;
}

#endif  /* End of CONFIG_NET_DSA_MICROCHIOP_LAN937X_PTP */

#endif
