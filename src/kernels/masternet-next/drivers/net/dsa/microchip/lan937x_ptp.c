#include "lan937x_reg.h"
#include "ksz_common.h"

/* The function is return back the capability of timestamping feature when requested
   through ethtool -T <interface> utility
   */
int lan937x_get_ts_info(struct dsa_switch *ds, int port, struct ethtool_ts_info *ts)
{
	struct ksz_device *dev  = ds->priv;
	struct lan937x_ptp_data *ptp_data = &dev->ptp_data;

	ts->so_timestamping = SOF_TIMESTAMPING_TX_HARDWARE |
		              SOF_TIMESTAMPING_RX_HARDWARE |
			      SOF_TIMESTAMPING_RAW_HARDWARE;

	ts->tx_types = (1 << HWTSTAMP_TX_OFF) |
		       (1 << HWTSTAMP_TX_ON);

	ts->rx_filters = (1 << HWTSTAMP_FILTER_NONE)  |
		         (1 << HWTSTAMP_FILTER_PTP_V2_L2_EVENT);
	
	ts->phc_index = ptp_clock_index(ptp_data->clock);

	return 0;
}


int lan937x_hwtstamp_get(struct dsa_switch *ds, int port, struct ifreq *ifr)
{
	struct ksz_device *dev  = ds->priv;
	struct hwtstamp_config *port_tconfig = &dev->ports[port].tstamp_config;


	return copy_to_user(ifr->ifr_data, port_tconfig, sizeof(struct hwtstamp_config)) ?  
	        -EFAULT : 0;
}

int lan937x_hwtstamp_set(struct dsa_switch *ds, int port, struct ifreq *ifr)
{
	struct ksz_device *dev  = ds->priv;
	struct hwtstamp_config *port_tconfig = &dev->ports[port].tstamp_config;
	struct hwtstamp_config config;

	if(copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;
	
	//save the configuration in the ksz_port
	memcpy(port_tconfig, &config, sizeof(config));
	

	return copy_to_user(ifr->ifr_data, &config, sizeof(config)) ?  
	        -EFAULT : 0;
}

int lan937x_ptp_clock_register(struct dsa_switch *ds)
{
	struct ksz_device *dev  = ds->priv;
	struct lan937x_ptp_data *ptp_data = &dev->ptp_data;
	
	ptp_data->caps = (struct ptp_clock_info) {
		.owner		= THIS_MODULE,
		.name		= "LAN937X PHC"
	};

	ptp_data->clock = ptp_clock_register(&ptp_data->caps, ds->dev);
	if (IS_ERR_OR_NULL(ptp_data->clock))
		return PTR_ERR(ptp_data->clock);
	
	return 0;
}	
