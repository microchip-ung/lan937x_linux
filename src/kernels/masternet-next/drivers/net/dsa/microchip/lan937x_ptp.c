#include "lan937x_reg.h"
#include "ksz_common.h"
#include "lan937x_ptp.h"


int lan937x_get_ts_info(struct dsa_switch *ds, int port, struct ethtool_ts_info *ts)
{

	//todo - insert the clock index

	ts->so_timestamping = SOF_TIMESTAMPING_TX_HARDWARE |
		              SOF_TIMESTAMPING_RX_HARDWARE |
			      SOF_TIMESTAMPING_RAW_HARDWARE;

	ts->tx_types = (1 << HWTSTAMP_TX_OFF) |
		       (1 << HWTSTAMP_TX_ON);

	ts->rx_filters = (1 << HWTSTAMP_FILTER_NONE) |
		         (1 << HWTSTAMP_FILTER_PTP_V2_L2_EVENT);

	return 0;
}


int lan937x_hwtstamp_get(struct dsa_switch *ds, int port, struct ifreq *ifr)
{


	return 0;
}

int lan937x_hwtstamp_set(struct dsa_switch *ds, int port, struct ifreq *ifr)
{

	return 0;
}
