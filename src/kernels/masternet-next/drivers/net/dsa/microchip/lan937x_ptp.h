#ifndef NET_DSA_DRIVERS_LAN937X_PTP_H
#define NET_DSA_DRIVERS_LAN937X_PTP_H

int lan937x_get_ts_info(struct dsa_switch *ds, int port, struct ethtool_ts_info *ts);
int lan937x_hwtstamp_get(struct dsa_switch *ds, int port, struct ifreq *ifr);
int lan937x_hwtstamp_set(struct dsa_switch *ds, int port, struct ifreq *ifr);

#endif
