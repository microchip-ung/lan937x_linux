#ifndef _NET_DSA_DRIVERS_LAN937X_PTP_H
#define _NET_DSA_DRIVERS_LAN937X_PTP_H

#if IS_ENABLED(CONFIG_NET_DSA_MICROCHIP_LAN937X_PTP)

#include <linux/ptp_clock_kernel.h>

/* state flags for _port_hwtstamp::state */
enum {
	LAN937X_HWTSTAMP_ENABLED,
	LAN937X_HWTSTAMP_TX_IN_PROGRESS,
};

struct lan937x_ptp_data
{
	struct ptp_clock_info caps;
	struct ptp_clock *clock;
	struct mutex lock;  //to serialize the activity in the phc
};

int lan937x_get_ts_info(struct dsa_switch *ds, int port, struct ethtool_ts_info *ts);
int lan937x_hwtstamp_get(struct dsa_switch *ds, int port, struct ifreq *ifr);
int lan937x_hwtstamp_set(struct dsa_switch *ds, int port, struct ifreq *ifr);
bool lan937x_port_rxtstamp(struct dsa_switch *ds, int port,
			     struct sk_buff *clone, unsigned int type);
bool lan937x_port_txtstamp(struct dsa_switch *ds, int port,
			     struct sk_buff *clone, unsigned int type);

int lan937x_ptp_clock_register(struct dsa_switch *ds);
void lan937x_ptp_clock_unregister(struct dsa_switch *ds);

#else

struct lan937x_ptp_data
{
	struct mutex lock;
};

static inline int lan937x_ptp_clock_register(struct dsa_switch *ds)
{
	return 0;
}

static inline void lan937x_ptp_clock_unregister(struct dsa_switch *ds){}

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


static inline bool lan937x_port_rxtstamp(struct dsa_switch *ds, int port,
					   struct sk_buff *clone,
					   unsigned int type)
{
	return false;
}

static inline bool lan937x_port_txtstamp(struct dsa_switch *ds, int port,
					   struct sk_buff *clone,
					   unsigned int type)
{
	return false;
}


#endif  /* End of CONFIG_NET_DSA_MICROCHIOP_LAN937X_PTP */

#endif
