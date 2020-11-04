/*
*
*/
#include "lan937x_reg.h"
#include "ksz_common.h"
#include <linux/ptp_classify.h>


#define ptp_caps_to_data(d) \
		container_of((d), struct lan937x_ptp_data, caps)
#define ptp_data_to_lan937x(d) \
		container_of((d), struct ksz_device, ptp_data)

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

static int lan937x_set_hwtstamp_config(struct ksz_device *dev, int port,
					 struct hwtstamp_config *config)
{
	struct ksz_port *prt = &dev->ports[port];
	bool tstamp_enable = false;

	/* Prevent the TX/RX paths from trying to interact with the
	 * timestamp hardware while we reconfigure it.
	 */
	clear_bit_unlock(LAN937X_HWTSTAMP_ENABLED, &prt->tstamp_state);
	
	/* reserved for future extensions */
	if (config->flags)
		return -EINVAL;

	switch (config->tx_type) {
	case HWTSTAMP_TX_OFF:
		tstamp_enable = false;
		break;
	case HWTSTAMP_TX_ON:
		tstamp_enable = true;
		break;
	default:
		return -ERANGE;
	}

	//Todo: insert the switch statement for rx_filter

	/* Once hardware has been configured, enable timestamp checks
	 * in the RX/TX paths.
	 */
	if (tstamp_enable)
		set_bit(LAN937X_HWTSTAMP_ENABLED, &prt->tstamp_state);

	return 0;
}

int lan937x_hwtstamp_set(struct dsa_switch *ds, int port, struct ifreq *ifr)
{
	struct ksz_device *dev  = ds->priv;
	struct hwtstamp_config *port_tconfig = &dev->ports[port].tstamp_config;
	struct hwtstamp_config config;
	int err;	

	if(copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;
	
	err = lan937x_set_hwtstamp_config(dev, port, &config);
	if (err)
		return err;

	/* Save the chosen configuration to be returned later. */
	memcpy(port_tconfig, &config, sizeof(config));
	

	return copy_to_user(ifr->ifr_data, &config, sizeof(config)) ?  
	        -EFAULT : 0;
}

/* Returns a pointer to the PTP header if the caller should time stamp,
 * or NULL if the caller should not.
 */
static struct ptp_header *lan937x_ptp_should_tstamp(struct ksz_port *port, struct sk_buff *skb,
		unsigned int type) 
{
	if (!test_bit(LAN937X_HWTSTAMP_ENABLED, &port->tstamp_state))
		return NULL;

	return ptp_parse_header(skb, type); 
}


bool lan937x_port_txtstamp(struct dsa_switch *ds, int port,
			     struct sk_buff *clone, unsigned int type)
{
	struct ksz_device *dev  = ds->priv;
	struct ksz_port *prt = &dev->ports[port];
	struct ptp_header *hdr;

	//if (!(skb_shinfo(clone)->tx_flags & SKBTX_HW_TSTAMP))
	//	return false;

	hdr = lan937x_ptp_should_tstamp(prt, clone, type);
	if (!hdr)
		return false;

	if (test_and_set_bit_lock(LAN937X_HWTSTAMP_TX_IN_PROGRESS, 
				&prt->tstamp_state))
		return false;

//	ps->tx_skb = clone;
//	ps->tx_tstamp_start = jiffies;
//	ps->tx_seq_id = be16_to_cpu(hdr->sequence_id);

//	ptp_schedule_worker(chip->ptp_clock, 0);
	return true;
}

bool lan937x_port_rxtstamp(struct dsa_switch *ds, int port,
			     struct sk_buff *clone, unsigned int type)
{

	return true;
}

//These are function releated to the ptp clock info

static int lan937x_ptp_enable(struct ptp_clock_info *ptp,
		struct ptp_clock_request *req, int on)
{
	struct lan937x_ptp_data *ptp_data = ptp_caps_to_data(ptp);
	struct ksz_device *priv = ptp_data_to_lan937x(ptp_data);
	int rc = -EOPNOTSUPP;

	if (req->type == PTP_CLK_REQ_PPS)
		rc = 0;  //todo: add code here
	else if (req->type == PTP_CLK_REQ_EXTTS)
		rc = 0;  //todo: add code here

	return rc; 
}


static int lan937x_ptp_gettime(struct ptp_clock_info *ptp,
		struct timespec64 *ts)
{
	struct lan937x_ptp_data *ptp_data = ptp_caps_to_data(ptp);
	struct ksz_device *priv = ptp_data_to_lan937x(ptp_data);

	mutex_lock(&ptp_data->lock);

	mutex_unlock(&ptp_data->lock);

	return 0; //Todo: change it.
}

static int lan937x_ptp_settime(struct ptp_clock_info *ptp,
		const struct timespec64 *ts)
{
	struct lan937x_ptp_data *ptp_data = ptp_caps_to_data(ptp);
	struct ksz_device *priv = ptp_data_to_lan937x(ptp_data);

	mutex_lock(&ptp_data->lock);

	mutex_unlock(&ptp_data->lock);

	return 0;  //Todo: change it now.

}


static int lan937x_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct lan937x_ptp_data *ptp_data = ptp_caps_to_data(ptp);
	struct ksz_device *priv = ptp_data_to_lan937x(ptp_data);

	mutex_lock(&ptp_data->lock);

	mutex_unlock(&ptp_data->lock);

	return 0; //Todo: change it
}


static int lan937x_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct lan937x_ptp_data *ptp_data = ptp_caps_to_data(ptp);
	struct ksz_device *priv = ptp_data_to_lan937x(ptp_data);

	mutex_lock(&ptp_data->lock);

	mutex_unlock(&ptp_data->lock);

	return 0;
}



int lan937x_ptp_clock_register(struct dsa_switch *ds)
{
	struct ksz_device *dev  = ds->priv;
	struct lan937x_ptp_data *ptp_data = &dev->ptp_data;

	ptp_data->caps = (struct ptp_clock_info) {
		.owner		= THIS_MODULE,
			.name		= "Microchip Clock",
			.enable		= lan937x_ptp_enable,
			.gettime64	= lan937x_ptp_gettime,
			.settime64	= lan937x_ptp_settime,
			.adjfine	= lan937x_ptp_adjfine,
			.adjtime	= lan937x_ptp_adjtime

	};

	ptp_data->clock = ptp_clock_register(&ptp_data->caps, ds->dev);
	if (IS_ERR_OR_NULL(ptp_data->clock))
		return PTR_ERR(ptp_data->clock);

	return 0;
}	


void lan937x_ptp_clock_unregister(struct dsa_switch *ds)
{
	struct ksz_device *dev  = ds->priv;
	struct lan937x_ptp_data *ptp_data = &dev->ptp_data;

	if (IS_ERR_OR_NULL(ptp_data->clock))
		return;

	ptp_clock_unregister(ptp_data->clock);
	ptp_data->clock = NULL;
}
