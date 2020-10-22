#ifndef NET_DSA_DRIVERS_LAN937X_PTP_H
#define NET_DSA_DRIVERS_LAN937X_PTP_H

#if IS_ENABLED(CONFIG_NET_DSA_MICROCHIP_LAN937X_PTP)
int lan937x_get_ts_info(struct dsa_switch *ds, int port, struct ethtool_ts_info *ts);
int lan937x_hwtstamp_get(struct dsa_switch *ds, int port, struct ifreq *ifr);
int lan937x_hwtstamp_set(struct dsa_switch *ds, int port, struct ifreq *ifr);
#else

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
