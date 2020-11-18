/*
*
*/
#include "lan937x_reg.h"
#include "ksz_common.h"
#include <linux/ptp_classify.h>

#define ptp_clock_info_to_dev(d) \
		container_of((d), struct ksz_device, ptp_caps)

#define MAX_DRIFT_CORR 6250000

#define KSZ_PTP_INC_NS 40  /* HW clock is incremented every 40 ns (by 40) */
#define KSZ_PTP_SUBNS_BITS 32  /* Number of bits in sub-nanoseconds counter */

/* The function is return back the capability of timestamping feature when requested
   through ethtool -T <interface> utility
   */
int lan937x_get_ts_info(struct dsa_switch *ds, int port, struct ethtool_ts_info *ts)
{
	struct ksz_device *dev  = ds->priv;

	ts->so_timestamping = SOF_TIMESTAMPING_TX_HARDWARE |
		              SOF_TIMESTAMPING_RX_HARDWARE |
			      SOF_TIMESTAMPING_RAW_HARDWARE;

	ts->tx_types = (1 << HWTSTAMP_TX_OFF) |
		       (1 << HWTSTAMP_TX_ON);

	ts->rx_filters = (1 << HWTSTAMP_FILTER_NONE)  |
		         (1 << HWTSTAMP_FILTER_PTP_V2_L2_EVENT);
	
	ts->phc_index = ptp_clock_index(dev->ptp_clock);

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
			//case HWTSTAMP_TX_ONESTEP_SYNC:   //todo: check for this. it is need for onestep sync
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

	if (!(skb_shinfo(clone)->tx_flags & SKBTX_HW_TSTAMP))
		return false;

	hdr = lan937x_ptp_should_tstamp(prt, clone, type);
	if (!hdr)
		return false;


	if (test_and_set_bit_lock(LAN937X_HWTSTAMP_TX_IN_PROGRESS, 
				&prt->tstamp_state))
		return false;

	prt->tx_skb = clone;
	prt->tx_tstamp_start = jiffies;
	prt->tx_seq_id = be16_to_cpu(hdr->sequence_id);

	ptp_schedule_worker(dev->ptp_clock, 0);
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
/*	struct lan937x_ptp_data *ptp_data = ptp_caps_to_data(ptp);
	struct ksz_device *priv = ptp_data_to_lan937x(ptp_data);
	int rc = -EOPNOTSUPP;

	if (req->type == PTP_CLK_REQ_PPS)
		rc = 0;  //todo: add code here
	else if (req->type == PTP_CLK_REQ_EXTTS)
		rc = 0;  //todo: add code here

	return rc; 
	*/
	return -ENOTTY;
}

/*
 * Function is pointer to the do_aux_work in the ptp_clock capability.
 * It is called by application, by polling method to read the timestamp
 * If timestamp is ready, it post using skb_complete api and return -1.
 * else it returns 1 for restart the polling to get timestamp.
 */
long lan937x_ptp_hwtstamp_work(struct ptp_clock_info *ptp)
{
	struct ksz_device *dev = ptp_clock_info_to_dev(ptp);
	struct dsa_switch *ds = dev->ds;
	struct ksz_port *prt = &dev->ports[0];  //todo: change the 1 to number of the port. 
	struct sk_buff *tmp_skb;
	struct skb_shared_hwtstamps shhwtstamps;
	u32 tstamp_raw;

	
	memset(&shhwtstamps, 0, sizeof(struct skb_shared_hwtstamps));

	//Read the timestamp from the hardware
	tstamp_raw = 1234;	//todo get the timestamp from the hardware. just a placeholder now
	shhwtstamps.hwtstamp = lan937x_tstamp_to_clock(dev, tstamp_raw, prt->tstamp_tx_latency_ns);
	
	/* skb_complete_tx_timestamp() will free up the client to make
	 * another timestamp-able transmit. We have to be ready for it
	 * -- by clearing the ps->tx_skb "flag" -- beforehand.
	 */

	tmp_skb = prt->tx_skb;
	prt->tx_skb = NULL;
	clear_bit_unlock(LAN937X_HWTSTAMP_TX_IN_PROGRESS, &prt->tstamp_state);
	skb_complete_tx_timestamp(tmp_skb, &shhwtstamps);
	
	return -1; //as of now, setting -1 for not to restart. 1 means to restart the poll
}

static int _lan937x_ptp_gettime(struct ksz_device *dev, struct timespec64 *ts)
{
	u32 nanoseconds;
	u32 seconds;
	u16 data16;
	u8 phase;
	int ret;

	/* Copy current PTP clock into shadow registers */
	ret = ksz_read16(dev, REG_PTP_CLK_CTRL, &data16);
	if (ret)
		return ret;

	data16 |= PTP_READ_TIME;

	ret = ksz_write16(dev, REG_PTP_CLK_CTRL, data16);
	if (ret)
		return ret;

	/* Read from shadow registers */
	ret = ksz_read8(dev, REG_PTP_RTC_SUB_NANOSEC__2, &phase);
	if (ret)
		return ret;
	ret = ksz_read32(dev, REG_PTP_RTC_NANOSEC, &nanoseconds);
	if (ret)
		return ret;
	ret = ksz_read32(dev, REG_PTP_RTC_SEC, &seconds);
	if (ret)
		return ret;

	ts->tv_sec = seconds;
	ts->tv_nsec = nanoseconds + phase * 8;

	return 0;
}

static int lan937x_ptp_gettime(struct ptp_clock_info *ptp,
		struct timespec64 *ts)
{
	struct ksz_device *dev = ptp_clock_info_to_dev(ptp);
	int ret;

	mutex_lock(&dev->ptp_mutex);
	ret = _lan937x_ptp_gettime(dev, ts);
	mutex_unlock(&dev->ptp_mutex);

	return ret; 
}

static int lan937x_ptp_settime(struct ptp_clock_info *ptp,
		const struct timespec64 *ts)
{
	struct ksz_device *dev = ptp_clock_info_to_dev(ptp);
	u16 data16;
	unsigned long flags;
	int ret;

	mutex_lock(&dev->ptp_mutex);

	/* Write to shadow registers */

	/* clock phase */
	ret = ksz_read16(dev, REG_PTP_RTC_SUB_NANOSEC__2, &data16);
	if (ret)
		goto error_return;

	data16 &= ~PTP_RTC_SUB_NANOSEC_M;

	ret = ksz_write16(dev, REG_PTP_RTC_SUB_NANOSEC__2, data16);
	if (ret)
		goto error_return;

	/* nanoseconds */
	ret = ksz_write32(dev, REG_PTP_RTC_NANOSEC, ts->tv_nsec);
	if (ret)
		goto error_return;

	/* seconds */
	ret = ksz_write32(dev, REG_PTP_RTC_SEC, ts->tv_sec);
	if (ret)
		goto error_return;

	/* Load PTP clock from shadow registers */
	ret = ksz_read16(dev, REG_PTP_CLK_CTRL, &data16);
	if (ret)
		goto error_return;

	data16 |= PTP_LOAD_TIME;

	ret = ksz_write16(dev, REG_PTP_CLK_CTRL, data16);
	if (ret)
		goto error_return;

	spin_lock_irqsave(&dev->ptp_clock_lock, flags);
	dev->ptp_clock_time = *ts;
	spin_unlock_irqrestore(&dev->ptp_clock_lock, flags);

error_return:
	mutex_unlock(&dev->ptp_mutex);

	return ret;  

}


static int lan937x_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct ksz_device *dev = ptp_clock_info_to_dev(ptp);
	u16 data16;
	int ret;

	if (scaled_ppm) {
		/* basic calculation:
		 * s32 ppb = scaled_ppm_to_ppb(scaled_ppm);
		 * s64 adj = div_s64(((s64)ppb * KSZ_PTP_INC_NS) << KSZ_PTP_SUBNS_BITS,
		 *                   NSEC_PER_SEC);
		 */

		/* more precise calculation (avoids shifting out precision) */
		s64 ppb, adj;
		u32 data32;

		/* see scaled_ppm_to_ppb() in ptp_clock.c for details */
		ppb = 1 + scaled_ppm;
		ppb *= 125;
		ppb *= KSZ_PTP_INC_NS;
		ppb <<= KSZ_PTP_SUBNS_BITS - 13;
		adj = div_s64(ppb, NSEC_PER_SEC);

		data32 = abs(adj);
		data32 &= BIT_MASK(30) - 1;
		if (adj >= 0)
			data32 |= PTP_RATE_DIR;

		ret = ksz_write32(dev, REG_PTP_SUBNANOSEC_RATE, data32);
		if (ret)
			return ret;
	}

	ret = ksz_read16(dev, REG_PTP_CLK_CTRL, &data16);
	if (ret)
		return ret;

	if (scaled_ppm)
		data16 |= PTP_CLK_ADJ_ENABLE;
	else
		data16 &= ~PTP_CLK_ADJ_ENABLE;

	ret = ksz_write16(dev, REG_PTP_CLK_CTRL, data16);
	if (ret)
		return ret;

	return 0; 
}


static int lan937x_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct ksz_device *dev = ptp_clock_info_to_dev(ptp);
	struct timespec64 delta64 = ns_to_timespec64(delta);
	int ret;
	s32 sec, nsec;
	u16 data16;
	unsigned long flags;

	mutex_lock(&dev->ptp_mutex);

	/* do not use ns_to_timespec64(), both sec and nsec are subtracted by hw */
	sec = div_s64_rem(delta, NSEC_PER_SEC, &nsec);

	ret = ksz_write32(dev, REG_PTP_RTC_NANOSEC, abs(nsec));
	if (ret)
		goto error_return;

	/* contradictory to the data sheet, seconds are also considered */
	ret = ksz_write32(dev, REG_PTP_RTC_SEC, abs(sec));
	if (ret)
		goto error_return;

	ret = ksz_read16(dev, REG_PTP_CLK_CTRL, &data16);
	if (ret)
		goto error_return;

	data16 |= PTP_STEP_ADJ;
	if (delta < 0)
		data16 &= ~PTP_STEP_DIR;  /* 0: subtract */
	else
		data16 |= PTP_STEP_DIR;   /* 1: add */

	ret = ksz_write16(dev, REG_PTP_CLK_CTRL, data16);
	if (ret)
		goto error_return;

	spin_lock_irqsave(&dev->ptp_clock_lock, flags);
	dev->ptp_clock_time = timespec64_add(dev->ptp_clock_time, delta64);
	spin_unlock_irqrestore(&dev->ptp_clock_lock, flags);

error_return:
	mutex_unlock(&dev->ptp_mutex);
	return ret;
}


static int lan937x_ptp_start_clock(struct ksz_device *dev)
{
	u16 data;
	unsigned long flags;
	int ret;

	ret = ksz_read16(dev, REG_PTP_CLK_CTRL, &data);
	if (ret)
		return ret;

	/* Perform PTP clock reset */
	data |= PTP_CLK_RESET;
	ret = ksz_write16(dev, REG_PTP_CLK_CTRL, data);
	if (ret)
		return ret;
	data &= ~PTP_CLK_RESET;

	/* Enable PTP clock */
	data |= PTP_CLK_ENABLE;
	ret = ksz_write16(dev, REG_PTP_CLK_CTRL, data);
	if (ret)
		return ret;

	spin_lock_irqsave(&dev->ptp_clock_lock, flags);
	dev->ptp_clock_time.tv_sec = 0;
	dev->ptp_clock_time.tv_nsec = 0;
	spin_unlock_irqrestore(&dev->ptp_clock_lock, flags);
	
	return 0;
}

static int lan937x_ptp_stop_clock(struct ksz_device *dev)
{
	u16 data;
	int ret;

	ret = ksz_read16(dev, REG_PTP_CLK_CTRL, &data);
	if (ret)
		return ret;

	/* Disable PTP clock */
	data &= ~PTP_CLK_ENABLE;
	ret = ksz_write16(dev, REG_PTP_CLK_CTRL, data);
	if (ret)
		return ret;

	return 0;
}

/*Time Stamping support - accessing the register */
static int lan937x_ptp_enable_mode(struct ksz_device *dev) {
       u16 data;
       int ret;

       ret = ksz_read16(dev, REG_PTP_MSG_CONF1, &data);
       if (ret)
               return ret;

       /* Enable PTP mode */
       data |= PTP_ENABLE;
       ret = ksz_write16(dev, REG_PTP_MSG_CONF1, data);
       if (ret)
               return ret;

       return 0;
}

static int lan937x_ptp_disable_mode(struct ksz_device *dev) {
       u16 data;
       int ret;

       ret = ksz_read16(dev, REG_PTP_MSG_CONF1, &data);
       if (ret)
               return ret;

       /* Disable PTP mode */
       data &= ~PTP_ENABLE;
       ret = ksz_write16(dev, REG_PTP_MSG_CONF1, data);
       if (ret)
               return ret;

       return 0;
}

static int lan937x_ptp_enable_port_ptp_interrupts(struct ksz_device *dev, int port)
{
	u32 addr = PORT_CTRL_ADDR(port, REG_PORT_INT_MASK);
	u8 data;
	int ret;

	ret = ksz_read8(dev, addr, &data);
	if (ret)
		return ret;

	/* Enable port PTP interrupt (0 means enabled) */
	data &= ~PORT_PTP_INT;
	ret = ksz_write8(dev, addr, data);
	if (ret)
		return ret;

	return 0;
}

static int lan937x_ptp_disable_port_ptp_interrupts(struct ksz_device *dev, int port)
{
	u32 addr = PORT_CTRL_ADDR(port, REG_PORT_INT_MASK);
	u8 data;
	int ret;

	ret = ksz_read8(dev, addr, &data);
	if (ret)
		return ret;

	/* Enable port PTP interrupt (1 means disabled) */
	data |= PORT_PTP_INT;
	ret = ksz_write8(dev, addr, data);
	if (ret)
		return ret;

	return 0;
}

static int lan937x_ptp_enable_port_egress_interrupts(struct ksz_device *dev, int port)
{
	u32 addr = PORT_CTRL_ADDR(port, REG_PTP_PORT_TX_INT_ENABLE__2);
	u16 data;
	int ret;

	ret = ksz_read16(dev, addr, &data);
	if (ret)
		return ret;

	/* Enable port xdelay egress timestamp interrupt (1 means enabled) */
	data |= PTP_PORT_XDELAY_REQ_INT;
	ret = ksz_write16(dev, addr, data);
	if (ret)
		return ret;

	return 0;
}

static int lan937x_ptp_disable_port_egress_interrupts(struct ksz_device *dev, int port)
{
	u32 addr = PORT_CTRL_ADDR(port, REG_PTP_PORT_TX_INT_ENABLE__2);
	u16 data;
	int ret;

	ret = ksz_read16(dev, addr, &data);
	if (ret)
		return ret;

	/* Disable port xdelay egress timestamp interrupts (0 means disabled) */
	data &= PTP_PORT_XDELAY_REQ_INT;
	ret = ksz_write16(dev, addr, data);
	if (ret)
		return ret;

	return 0;
}

static int lan937x_ptp_port_init(struct ksz_device *dev, int port)
{
	struct ksz_port *prt = &dev->ports[port];
	int ret;

	/* Read rx and tx delay from port registers */
	ret = ksz_read16(dev, PORT_CTRL_ADDR(port, REG_PTP_PORT_RX_DELAY__2),
			 &prt->tstamp_rx_latency_ns);
	if (ret)
		return ret;

	ret = ksz_read16(dev, PORT_CTRL_ADDR(port, REG_PTP_PORT_TX_DELAY__2),
			 &prt->tstamp_tx_latency_ns);
	if (ret)
		return ret;

	if (port != dev->cpu_port) {
		ret = lan937x_ptp_enable_port_ptp_interrupts(dev, port);
		if (ret)
			return ret;

		ret = lan937x_ptp_enable_port_egress_interrupts(dev, port);
		if (ret)
			goto error_disable_port_ptp_interrupts;
	}

	return 0;

error_disable_port_ptp_interrupts:
	if (port != dev->cpu_port)
		lan937x_ptp_disable_port_ptp_interrupts(dev, port);
	return ret;
}

static void lan937x_ptp_port_deinit(struct ksz_device *dev, int port)
{
	if (port != dev->cpu_port) {
		lan937x_ptp_disable_port_egress_interrupts(dev, port);
		lan937x_ptp_disable_port_ptp_interrupts(dev, port);
	}
}

static int lan937x_ptp_ports_init(struct ksz_device *dev)
{
	int port;
	int ret;

	for (port = 0; port < dev->port_cnt; port++) {
		ret = lan937x_ptp_port_init(dev, port);
		if (ret)
			goto error_deinit;
	}

	return 0;

error_deinit:
	for (--port; port >= 0; --port)
		lan937x_ptp_port_deinit(dev, port);
	return ret;
}

static void lan937x_ptp_ports_deinit(struct ksz_device *dev)
{
	int port;

	for (port = dev->port_cnt - 1; port >= 0; --port)
		lan937x_ptp_port_deinit(dev, port);
}

int lan937x_ptp_init(struct dsa_switch *ds)
{
	struct ksz_device *dev  = ds->priv;
	int ret;

	dev->ptp_caps = (struct ptp_clock_info) {
		.owner		= THIS_MODULE,
		.name		= "Microchip Clock",
		.max_adj  	= MAX_DRIFT_CORR,
		.enable		= lan937x_ptp_enable,
		.gettime64	= lan937x_ptp_gettime,
		.settime64	= lan937x_ptp_settime,
		.adjfine	= lan937x_ptp_adjfine,
		.adjtime	= lan937x_ptp_adjtime,
		.do_aux_work	= lan937x_ptp_hwtstamp_work,
		.n_alarm        = 0,
		.n_ext_ts       = 0,  /* currently not implemented */
		.n_per_out      = 0,
		.pps            = 0
	};

	/* Start hardware counter (will overflow after 136 years) */
	ret = lan937x_ptp_start_clock(dev);
	if (ret)
		return ret;

	dev->ptp_clock = ptp_clock_register(&dev->ptp_caps, ds->dev);
	if (IS_ERR_OR_NULL(dev->ptp_clock))
	{
		ret = PTR_ERR(dev->ptp_clock);
		goto error_stop_clock;
	}

	/* Enable PTP mode (will affect tail tagging format) */
	ret = lan937x_ptp_enable_mode(dev);
	if (ret)
		goto error_unregister_clock;

	/* Init switch ports */
	ret = lan937x_ptp_ports_init(dev);
	if (ret)
		goto error_disable_mode;


	/* Schedule cyclic call of ptp_do_aux_work() */
	ret = ptp_schedule_worker(dev->ptp_clock, 0);
	if (ret)
		goto error_ports_deinit;

 	return 0;
 
error_ports_deinit:
	lan937x_ptp_ports_deinit(dev);
error_disable_mode:
	lan937x_ptp_disable_mode(dev);
error_unregister_clock:
	ptp_clock_unregister(dev->ptp_clock);
error_stop_clock:
	lan937x_ptp_stop_clock(dev);
	return ret;
}	

void lan937x_ptp_deinit(struct dsa_switch *ds)
{
	struct ksz_device *dev  = ds->priv;

	if (IS_ERR_OR_NULL(dev->ptp_clock))
		return;

	ptp_clock_unregister(dev->ptp_clock);
	dev->ptp_clock = NULL;
	lan937x_ptp_stop_clock(dev);
}

