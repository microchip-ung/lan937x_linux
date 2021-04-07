// SPDX-License-Identifier: GPL-2.0
/* Microchip LAN937X PTP Implementation
 * Copyright (C) 2019-2020 Microchip Technology Inc.
 */

#include "lan937x_reg.h"
#include "ksz_common.h"
#include <linux/ptp_classify.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/irqreturn.h>

#define ptp_clock_info_to_dev(d) \
	container_of((d), struct ksz_device, ptp_caps)
#define sync_to_port(work) \
		container_of((work), struct lan937x_port_ptp_shared, sync_work)
#define pdelayreq_to_port(work) \
	   container_of((work), struct lan937x_port_ptp_shared, pdelayreq_work)
#define pdelayrsp_to_port(work) \
	   container_of((work), struct lan937x_port_ptp_shared, pdelayrsp_work)
#define ptp_shared_to_ksz_port(t) \
		container_of((t), struct ksz_port, ptp_shared)
#define ptp_shared_to_ksz_device(t) \
		container_of((t), struct ksz_device, ptp_shared)

#define MAX_DRIFT_CORR 6250000

#define KSZ_PTP_INC_NS 40  /* HW clock is incremented every 40 ns (by 40) */
#define KSZ_PTP_SUBNS_BITS 32  /* Number of bits in sub-nanoseconds counter */

static int _lan937x_ptp_gettime(struct ksz_device *dev, struct timespec64 *ts);

/* PPS Support */
#define PPS_LED_1       0
#define PPS_LED_2       1

#define LAN937x_PPS_TOU 2   /* currently fixed to trigger output unit 2 */

static int ksz_reg_setbits(struct ksz_device *dev, u32 reg, u32 val)
{
        u32 data;
        int ret;

	ret = ksz_read32(dev, reg, &data);
	if (ret)
		return ret;

	data |= val;

	ret = ksz_write32(dev, reg, data);
	if (ret)
		return ret;

        return 0; 
}

static int ksz_reg_clearbits(struct ksz_device *dev, u32 reg, u32 val)
{
        u32 data;
        int ret;

	ret = ksz_read32(dev, reg, &data);
	if (ret)
		return ret;

	data &= ~val;

	ret = ksz_write32(dev, reg, data);
	if (ret)
		return ret;

        return 0; 
}

static int lan937x_ptp_tou_index(struct ksz_device *dev, u8 index,
                                 u32 pps_led_index)
{
        u32 data;
        int ret;

	data = ((index << PTP_TOU_INDEX_S) | (pps_led_index << PTP_GPIO_INDEX_S));

        ret = ksz_reg_setbits(dev ,REG_PTP_UNIT_INDEX__4, data);
        
        return ret; 
}
 
static int lan937x_ptp_tou_reset(struct ksz_device *dev)
{
	int ret;

	/* Reset trigger unit */
        ret = ksz_reg_setbits(dev, REG_PTP_CTRL_STAT__4, TRIG_RESET);
	if (ret)
		return ret;

        /* Clear reset */
        ret = ksz_reg_clearbits(dev, REG_PTP_CTRL_STAT__4, (TRIG_RESET | TRIG_ENABLE));
	if (ret)
		return ret;

	return 0;
}

static int lan937x_ptp_tou_cycle_count_set(struct ksz_device *dev, u16 count)
{
	u32 data;
	int ret;

	ret = ksz_read32(dev, REG_TRIG_CYCLE_CNT, &data);
	if (ret)
		return ret;

	data &= ~(TRIG_CYCLE_CNT_M << TRIG_CYCLE_CNT_S);
	data |= (count & TRIG_CYCLE_CNT_M) << TRIG_CYCLE_CNT_S;

	ret = ksz_write32(dev, REG_TRIG_CYCLE_CNT, data);
	if (ret)
		return ret;

	return 0;
}

static int lan937x_set_tou_target_time(struct ksz_device *dev)
{
	struct timespec64 now, pps_start, diff;
        int ret; 

	/* Read current time */
	ret = _lan937x_ptp_gettime(dev, &now);
	if (ret)
		return ret;

	/* Determine and write start time of PPS */
	pps_start.tv_sec = now.tv_sec + 1;
	pps_start.tv_nsec = 0;
	diff = timespec64_sub(pps_start, now);

	/* Reserve at least 1ms for programming and activating */
	if (diff.tv_nsec < 1000000)
		pps_start.tv_sec++;

        ret = ksz_write32(dev, REG_TRIG_TARGET_NANOSEC, pps_start.tv_nsec);
	if (ret)
		return ret;

	ret = ksz_write32(dev, REG_TRIG_TARGET_SEC, pps_start.tv_sec);
	if (ret)
		return ret;
        
        return 0;
}

static int lan937x_ptp_tou_gpio(struct ksz_device *dev, u32 pps_led_index)
{
        u32 data;
        int ret;

        /* Set the Led Override register */
	ret = ksz_read32(dev, REG_SW_GLOBAL_LED_OVR__4, &data);
	if (ret)
		return ret;

        if(pps_led_index == PPS_LED_2)
                data |= LED_OVR_2;
        else
                data |= LED_OVR_1;

	ret = ksz_write32(dev, REG_SW_GLOBAL_LED_OVR__4, data);
	if (ret)
		return ret;

        /* Set the Led Source register */
	ret = ksz_read32(dev, REG_SW_GLOBAL_LED_SRC__4, &data);
	if (ret)
		return ret;

        if(pps_led_index == PPS_LED_2)
                data |= LED_SRC_PTP_GPIO_2;
        else
                data |= LED_SRC_PTP_GPIO_1;

	ret = ksz_write32(dev, REG_SW_GLOBAL_LED_SRC__4, data);
	if (ret)
		return ret;

        return 0;
}

static int lan937x_ptp_enable_pps(struct ksz_device *dev, int on)
{
        u32 pps_led_index = 0;
	u32 data;
	int ret;

	if (dev->ptp_tou_mode != KSZ_PTP_TOU_PPS && dev->ptp_tou_mode != KSZ_PTP_TOU_IDLE)
		return -EBUSY;

        //get the pps led no, numbering is -1 from dts tree
        if(of_property_read_u32(dev->dev->of_node, "pps_led_index", &pps_led_index))
        {
                dev_err(dev->dev, "pps_led_index not defined in dts tree");
                return -EINVAL;
        }
        else
        {
                if((pps_led_index == 1) || (pps_led_index == 2))
                        pps_led_index -= 1;
                else
                        return -EINVAL;
        }

        /* Set the tou index register */
        ret = lan937x_ptp_tou_index(dev, LAN937x_PPS_TOU, pps_led_index);
        if(ret)
                return ret;

	/* Reset trigger unit  */
	ret = lan937x_ptp_tou_reset(dev);
	if (ret)
		return ret;

	if (!on) {
		dev->ptp_tou_mode = KSZ_PTP_TOU_IDLE;
		return 0;  /* success */
	}

	/* set periodic pulse pattern */
	data = (TRIG_POS_PERIOD << TRIG_PATTERN_S) | (pps_led_index << TRIG_GPO_S);
	ret = ksz_write32(dev, REG_TRIG_CTRL__4, data);
	if (ret)
		return ret;

	/* Set cycle width (1 s) */
        ret = ksz_write32(dev, REG_TRIG_CYCLE_WIDTH, NSEC_PER_SEC);
	if (ret)
		return ret;

	/* Set cycle count (infinite) */
	ret = lan937x_ptp_tou_cycle_count_set(dev, 0);
	if (ret)
		return ret;

	/* Set pulse with (20 ms / 8 ns) */
        data = (20000000/8);
        ret = ksz_write32(dev, REG_TRIG_PULSE_WIDTH__4, data);
	if (ret)
		return ret;
        
        /* Set target time */
        ret = lan937x_set_tou_target_time(dev);
        if(ret)
                return ret;

        /* Configure GPIO pins */
        ret = lan937x_ptp_tou_gpio(dev, pps_led_index);
        if(ret)
                return ret;

	/* Activate trigger unit */
        ret = ksz_reg_setbits(dev, REG_PTP_CTRL_STAT__4, (GPIO_OUT | TRIG_ENABLE));
	if (ret)
		return ret;

	dev->ptp_tou_mode = KSZ_PTP_TOU_PPS;
	return 0;
}

/*Time Stamping support - accessing the register */
static int lan937x_ptp_enable_mode(struct ksz_device *dev, bool enable)
{
	u16 data;
	int ret;

	ret = ksz_read16(dev, REG_PTP_MSG_CONF1, &data);
	if (ret)
		return ret;

	/* Enable PTP mode */
	if (enable)
		data |= PTP_ENABLE;
	else
		data &= ~PTP_ENABLE;

	ret = ksz_write16(dev, REG_PTP_MSG_CONF1, data);
	if (ret)
		return ret;

	if (enable) {
		/* Schedule cyclic call of ksz_ptp_do_aux_work() */
		ret = ptp_schedule_worker(dev->ptp_clock, 0);
		if (ret)
			goto error_disable_mode;
	} else {
		ptp_cancel_worker_sync(dev->ptp_clock);
	}

	return 0;

error_disable_mode:
	ksz_write16(dev, REG_PTP_MSG_CONF1, data & ~PTP_ENABLE);
	return ret;
}

/* The function is return back the capability of timestamping feature when
 * requested through ethtool -T <interface> utility
 */
int lan937x_get_ts_info(struct dsa_switch *ds, int port,
			struct ethtool_ts_info *ts)
{
	struct ksz_device *dev	= ds->priv;

	ts->so_timestamping = SOF_TIMESTAMPING_TX_HARDWARE |
			      SOF_TIMESTAMPING_RX_HARDWARE |
			      SOF_TIMESTAMPING_RAW_HARDWARE;

	ts->tx_types = (1 << HWTSTAMP_TX_OFF) |
		       (1 << HWTSTAMP_TX_ON);

	ts->rx_filters = (1 << HWTSTAMP_FILTER_NONE)  |
			 (1 << HWTSTAMP_FILTER_ALL);

	ts->phc_index = ptp_clock_index(dev->ptp_clock);

	return 0;
}

int lan937x_hwtstamp_get(struct dsa_switch *ds, int port, struct ifreq *ifr)
{
	struct ksz_device *dev	= ds->priv;
	struct hwtstamp_config config;

	config.flags = 0;

	if (dev->ports[port].hwts_tx_en)
		config.tx_type = HWTSTAMP_TX_ON;
	else
		config.tx_type = HWTSTAMP_TX_OFF;

	if (test_bit(LAN937X_HWTS_EN, &dev->ptp_shared.state))
		config.rx_filter = HWTSTAMP_FILTER_ALL;
	else
		config.rx_filter = HWTSTAMP_FILTER_NONE;

	return copy_to_user(ifr->ifr_data, &config,
			sizeof(struct hwtstamp_config)) ? -EFAULT : 0;
}

static int lan937x_set_hwtstamp_config(struct ksz_device *dev, int port,
				       struct hwtstamp_config *config)
{
	struct ksz_device_ptp_shared *ptp_shared = &dev->ptp_shared;
        struct ksz_port *prt = &dev->ports[port];
	bool rx_on;

	/* reserved for future extensions */
	if (config->flags)
		return -EINVAL;

	switch (config->tx_type) {
	case HWTSTAMP_TX_OFF:
		prt->hwts_tx_en = false;
		break;
	case HWTSTAMP_TX_ON:
		prt->hwts_tx_en = true;
		break;
	default:
		return -ERANGE;
	}

	switch (config->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		rx_on = false;
		break;
	default:
		rx_on = true;
		break;
	}

	if (rx_on != test_bit(LAN937X_HWTS_EN, &ptp_shared->state)) {
		int ret;

		clear_bit(LAN937X_HWTS_EN, &dev->ptp_shared.state);

		ret = lan937x_ptp_enable_mode(dev, rx_on);
		if (ret)
			return ret;

		if (rx_on)
			set_bit(LAN937X_HWTS_EN, &ptp_shared->state);
	}

	return 0;
}

int lan937x_hwtstamp_set(struct dsa_switch *ds, int port, struct ifreq *ifr)
{
	struct ksz_device *dev	= ds->priv;
	struct hwtstamp_config config;
	int ret;

	mutex_lock(&dev->ptp_mutex);

	ret = copy_from_user(&config, ifr->ifr_data, sizeof(config));
        if (ret)
                goto error_return;

	ret = lan937x_set_hwtstamp_config(dev, port, &config);
	if (ret)
                goto error_return;

	/* Save the chosen configuration to be returned later. */
	ret = copy_to_user(ifr->ifr_data, &config, sizeof(config));

 error_return:
	mutex_unlock(&dev->ptp_mutex);
        return ret;
}

bool lan937x_port_txtstamp(struct dsa_switch *ds, int port,
			   struct sk_buff *clone, unsigned int type)
{
	struct ksz_device *dev	= ds->priv;
        struct ksz_port *prt = &dev->ports[port];
	struct ptp_header *hdr;
	u8 ptp_msg_type;

	if (!(skb_shinfo(clone)->tx_flags & SKBTX_HW_TSTAMP))
		return false;

	if (!prt->hwts_tx_en)
		return false;

	hdr = ptp_parse_header(clone, type);
	if (!hdr)
		return false;

	ptp_msg_type = ptp_get_msgtype(hdr, type);

	switch (ptp_msg_type) {
	case PTP_MSGTYPE_PDELAY_REQ:
	case PTP_MSGTYPE_PDELAY_RESP:
	case PTP_MSGTYPE_SYNC:
		break;

	default:
		return false;  /* free cloned skb */
	}

	KSZ_SKB_CB(clone)->ptp_type = type;
	KSZ_SKB_CB(clone)->ptp_msg_type = ptp_msg_type;

	return true;
}

//These are function related to the ptp clock info
static int lan937x_ptp_enable(struct ptp_clock_info *ptp,
			      struct ptp_clock_request *req, int on)
{
	struct ksz_device *dev = ptp_clock_info_to_dev(ptp);
	int ret;

        switch(req->type) {
        case PTP_CLK_REQ_PPS:
	        mutex_lock(&dev->ptp_mutex);
	        ret = lan937x_ptp_enable_pps(dev, on);
	        mutex_unlock(&dev->ptp_mutex);
                break;

        default:
                ret = -EINVAL;
                break;
        }

        return ret;
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
	struct ksz_device *dev = container_of(ptp, struct ksz_device, ptp_caps);
	struct ksz_device_ptp_shared *ptp_shared = &dev->ptp_shared;
	u16 data16;
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

        switch(dev->ptp_tou_mode) {
        case KSZ_PTP_TOU_IDLE:
                break;

        case KSZ_PTP_TOU_PPS:
                ret = lan937x_ptp_enable_pps(dev, true);
                if(ret)
                        goto error_return;
                break;
        }

	spin_lock_bh(&ptp_shared->ptp_clock_lock);
	ptp_shared->ptp_clock_time = *ts;
	spin_unlock_bh(&ptp_shared->ptp_clock_lock);

error_return:
	mutex_unlock(&dev->ptp_mutex);

	return ret;
}

static int lan937x_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct ksz_device *dev = ptp_clock_info_to_dev(ptp);
	u16 data16;
	int ret;

	mutex_lock(&dev->ptp_mutex);

	if (scaled_ppm) {
		/* basic calculation:
		 * s32 ppb = scaled_ppm_to_ppb(scaled_ppm);
		 * s64 adj = div_s64(((s64)ppb * KSZ_PTP_INC_NS) << KSZ_PTP_SUBNS_BITS,
		 * NSEC_PER_SEC);
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
			goto error_return;
	}

	ret = ksz_read16(dev, REG_PTP_CLK_CTRL, &data16);
	if (ret)
		goto error_return;

	if (scaled_ppm)
		data16 |= PTP_CLK_ADJ_ENABLE;
	else
		data16 &= ~PTP_CLK_ADJ_ENABLE;

	ret = ksz_write16(dev, REG_PTP_CLK_CTRL, data16);
	if (ret)
		goto error_return;

error_return:
	mutex_unlock(&dev->ptp_mutex);
	return ret;
}

static int lan937x_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct ksz_device *dev = container_of(ptp, struct ksz_device, ptp_caps);
	struct ksz_device_ptp_shared *ptp_shared = &dev->ptp_shared;
	struct timespec64 delta64 = ns_to_timespec64(delta);
	s32 sec, nsec;
	u16 data16;
	int ret;

	mutex_lock(&dev->ptp_mutex);

	/* do not use ns_to_timespec64(),
	 * both sec and nsec are subtracted by hw
	 */
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

        switch(dev->ptp_tou_mode) {
        case KSZ_PTP_TOU_IDLE:
                break;

        case KSZ_PTP_TOU_PPS:
                ret = lan937x_ptp_enable_pps(dev, true);
                if(ret)
                        goto error_return;
                break;
        }

	spin_lock_bh(&ptp_shared->ptp_clock_lock);
	ptp_shared->ptp_clock_time = timespec64_add(ptp_shared->ptp_clock_time, delta64);
	spin_unlock_bh(&ptp_shared->ptp_clock_lock);

error_return:
	mutex_unlock(&dev->ptp_mutex);
	return ret;
}

/*  Function is pointer to the do_aux_work in the ptp_clock capability */
static long lan937x_ptp_do_aux_work(struct ptp_clock_info *ptp)
{
	struct ksz_device *dev = container_of(ptp, struct ksz_device, ptp_caps);
	struct ksz_device_ptp_shared *ptp_shared = &dev->ptp_shared;
	struct timespec64 ts;

	mutex_lock(&dev->ptp_mutex);
	_lan937x_ptp_gettime(dev, &ts);
	mutex_unlock(&dev->ptp_mutex);

	spin_lock_bh(&ptp_shared->ptp_clock_lock);
	ptp_shared->ptp_clock_time = ts;
	spin_unlock_bh(&ptp_shared->ptp_clock_lock);

	return HZ;  /* reschedule in 1 second */
}

static int lan937x_ptp_start_clock(struct ksz_device *dev)
{
	struct ksz_device_ptp_shared *ptp_shared = &dev->ptp_shared;
	u16 data;
	int ret;

	ret = ksz_read16(dev, REG_PTP_CLK_CTRL, &data);
	if (ret)
		return ret;

	/* Enable PTP clock */
	data |= PTP_CLK_ENABLE;
	ret = ksz_write16(dev, REG_PTP_CLK_CTRL, data);
	if (ret)
		return ret;

	spin_lock_bh(&ptp_shared->ptp_clock_lock);
	ptp_shared->ptp_clock_time.tv_sec = 0;
	ptp_shared->ptp_clock_time.tv_nsec = 0;
	spin_unlock_bh(&ptp_shared->ptp_clock_lock);

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

static int lan937x_ptp_8021as(struct ksz_device *dev,
				  bool enable)
{
	u16 data;
	int ret;

	ret = ksz_read16(dev, REG_PTP_MSG_CONF1, &data);
	if (ret)
		return ret;

	if (enable)
		data |= PTP_802_1AS;
	else
		data &= ~PTP_802_1AS;

	return ksz_write16(dev, REG_PTP_MSG_CONF1, data);
}

/* Function to enable/disable Port PTP interrupt */
static int lan937x_ptp_enable_ptp_int(struct ksz_device *dev,
					     int port, bool enable)
{
	u32 addr = PORT_CTRL_ADDR(port, REG_PORT_INT_MASK);
	u8 data;
	int ret;

	ret = ksz_read8(dev, addr, &data);
	if (ret)
		return ret;

	/* PORT_PTP_INT bit is active low */
	if (enable)
		data &= ~PORT_PTP_INT;
	else
		data |= PORT_PTP_INT;

	return ksz_write8(dev, addr, data);
}

/* Function to enable/disable Individual message interrupt */
static int lan937x_ptp_enable_msg_int(struct ksz_device *dev,
			              int port, u16 mask, bool enable)
{
	u32 addr = PORT_CTRL_ADDR(port, REG_PTP_PORT_TX_INT_ENABLE__2);
	u16 data;
	int ret;

	ret = ksz_read16(dev, addr, &data);
	if (ret)
		return ret;

	/* PTP msg interrupts are active high (1 means enabled)*/
	if (enable)
		data |= mask;
	else
		data &= ~mask;

	return ksz_write16(dev, addr, data);
}

static void lan937x_sync_txtstamp_skb(struct ksz_device *dev,
				      struct ksz_port *prt, struct sk_buff *skb)
{
	struct skb_shared_hwtstamps hwtstamps = {};
	int ret;

	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;

	/* timeout must include tstamp latency, IRQ latency and time for
	 * reading the time stamp.
	 */
	ret = wait_for_completion_timeout(&prt->tstamp_sync_comp,
					  msecs_to_jiffies(100));
	if (!ret)
		return;

	hwtstamps.hwtstamp = prt->tstamp_sync;
	skb_complete_tx_timestamp(skb, &hwtstamps);
}

static void lan937x_pdelayreq_txtstamp_skb(struct ksz_device *dev,
					   struct ksz_port *prt,
					   struct sk_buff *skb)
{
	struct skb_shared_hwtstamps hwtstamps = {};
	int ret;

	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;

	/* timeout must include tstamp latency, IRQ latency and time for
	 * reading the time stamp.
	 */
	ret = wait_for_completion_timeout(&prt->tstamp_pdelayreq_comp,
					  msecs_to_jiffies(100));
	if (!ret)
		return;

	hwtstamps.hwtstamp = prt->tstamp_pdelayreq;
	skb_complete_tx_timestamp(skb, &hwtstamps);
}

static void lan937x_pdelayrsp_txtstamp_skb(struct ksz_device *dev,
					   struct ksz_port *prt,
					   struct sk_buff *skb)
{
	struct skb_shared_hwtstamps hwtstamps = {};
	int ret;

	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;

	/* timeout must include tstamp latency, IRQ latency and time for
	 * reading the time stamp.
	 */
	ret = wait_for_completion_timeout(&prt->tstamp_pdelayrsp_comp,
					  msecs_to_jiffies(100));
	if (!ret)
		return;

	hwtstamps.hwtstamp = prt->tstamp_pdelayrsp;
	skb_complete_tx_timestamp(skb, &hwtstamps);
}


/* Deferred work is necessary for time stamped messages. This cannot
 * be done from atomic context as we have to wait for the hardware interrupt.
 */
static void lan937x_sync_deferred_xmit(struct kthread_work *work)
{
	struct lan937x_port_ptp_shared *prt_ptp_shared = sync_to_port(work);
        struct ksz_port *prt = ptp_shared_to_ksz_port(prt_ptp_shared);
	struct ksz_device_ptp_shared *ptp_shared = prt_ptp_shared->dev;
	struct ksz_device *dev = ptp_shared_to_ksz_device(ptp_shared);
	int port = prt - dev->ports;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&prt_ptp_shared->sync_queue)) != NULL) {
		struct sk_buff *clone = DSA_SKB_CB(skb)->clone;

		reinit_completion(&prt->tstamp_sync_comp);

		/* Transfer skb to the host port. */
		dsa_enqueue_skb(skb, dsa_to_port(dev->ds, port)->slave);

		lan937x_sync_txtstamp_skb(dev, prt, clone);
	}
}

static void lan937x_pdelayreq_deferred_xmit(struct kthread_work *work)
{
	struct lan937x_port_ptp_shared *prt_ptp_shared = pdelayreq_to_port(work);
        struct ksz_port *prt = ptp_shared_to_ksz_port(prt_ptp_shared);
	struct ksz_device_ptp_shared *ptp_shared = prt_ptp_shared->dev;
	struct ksz_device *dev = ptp_shared_to_ksz_device(ptp_shared);
	int port = prt - dev->ports;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&prt_ptp_shared->pdelayreq_queue)) != NULL) {
		struct sk_buff *clone = DSA_SKB_CB(skb)->clone;

		reinit_completion(&prt->tstamp_pdelayreq_comp);

		/* Transfer skb to the host port. */
		dsa_enqueue_skb(skb, dsa_to_port(dev->ds, port)->slave);

		lan937x_pdelayreq_txtstamp_skb(dev, prt, clone);
	}
}

static void lan937x_pdelayrsp_deferred_xmit(struct kthread_work *work)
{
	struct lan937x_port_ptp_shared *prt_ptp_shared = pdelayrsp_to_port(work);
        struct ksz_port *prt = ptp_shared_to_ksz_port(prt_ptp_shared);
	struct ksz_device_ptp_shared *ptp_shared = prt_ptp_shared->dev;
	struct ksz_device *dev = ptp_shared_to_ksz_device(ptp_shared);
	int port = prt - dev->ports;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&prt_ptp_shared->pdelayrsp_queue)) != NULL) {
		struct sk_buff *clone = DSA_SKB_CB(skb)->clone;

		reinit_completion(&prt->tstamp_pdelayrsp_comp);

		/* Transfer skb to the host port. */
		dsa_enqueue_skb(skb, dsa_to_port(dev->ds, port)->slave);

		lan937x_pdelayrsp_txtstamp_skb(dev, prt, clone);
	}
}


/* Function is to  enable the Message Interrupt and intialize the worker queue
 * for processing the Interrupt routine
 */
static int lan937x_ptp_sync_msg_en(struct ksz_device *dev, int port)
{
	struct ksz_port *prt = &dev->ports[port];
	struct lan937x_port_ptp_shared *ptp_shared = &prt->ptp_shared;
	struct dsa_port *dp = dsa_to_port(dev->ds, port);
        int ret;
        
	ret = lan937x_ptp_enable_msg_int(dev, port, PTP_PORT_SYNC_INT,	true);
	if (ret)
		return ret;

	init_completion(&prt->tstamp_sync_comp);
	skb_queue_head_init(&ptp_shared->sync_queue);
	kthread_init_work(&ptp_shared->sync_work,
			  lan937x_sync_deferred_xmit);
	ptp_shared->sync_worker = kthread_create_worker(0, "%s_sync",
							dp->slave->name);
       
       if (IS_ERR(ptp_shared->sync_worker)) {
		ret = PTR_ERR(ptp_shared->sync_worker);
		goto error_disable_interrupt;
	} 

        return 0;

error_disable_interrupt:
        lan937x_ptp_enable_msg_int(dev, port, PTP_PORT_SYNC_INT, false);
        return ret;
}

static int lan937x_ptp_xdelayreq_msg_en(struct ksz_device *dev, int port)
{
	struct ksz_port *prt = &dev->ports[port];
	struct lan937x_port_ptp_shared *ptp_shared = &prt->ptp_shared;
	struct dsa_port *dp = dsa_to_port(dev->ds, port);
        int ret;
        
	ret = lan937x_ptp_enable_msg_int(dev, port, PTP_PORT_XDELAY_REQ_INT, true);
	if (ret)
		return ret;


	init_completion(&prt->tstamp_pdelayreq_comp);
	skb_queue_head_init(&ptp_shared->pdelayreq_queue);
	kthread_init_work(&ptp_shared->pdelayreq_work,
			  lan937x_pdelayreq_deferred_xmit);

	ptp_shared->pdelayreq_worker = kthread_create_worker(0, "%s_req_xmit",
							     dp->slave->name);

       if (IS_ERR(ptp_shared->pdelayreq_worker)) {
		ret = PTR_ERR(ptp_shared->pdelayreq_worker);
		goto error_disable_interrupt;
	} 

        return 0;

error_disable_interrupt:
        lan937x_ptp_enable_msg_int(dev, port, PTP_PORT_XDELAY_REQ_INT, false);
        return ret;
}

static int lan937x_ptp_pdelayresp_msg_en(struct ksz_device *dev, int port)
{
	struct ksz_port *prt = &dev->ports[port];
	struct lan937x_port_ptp_shared *ptp_shared = &prt->ptp_shared;
	struct dsa_port *dp = dsa_to_port(dev->ds, port);
        int ret;

	ret = lan937x_ptp_enable_msg_int(dev, port, PTP_PORT_PDELAY_RESP_INT, true);
	if (ret)
	        return ret;

	init_completion(&prt->tstamp_pdelayrsp_comp);
	skb_queue_head_init(&ptp_shared->pdelayrsp_queue);
	kthread_init_work(&ptp_shared->pdelayrsp_work,
			  lan937x_pdelayrsp_deferred_xmit);

	ptp_shared->pdelayrsp_worker = kthread_create_worker(0, "%s_rsp_xmit",
							     dp->slave->name);

       if (IS_ERR(ptp_shared->pdelayrsp_worker)) {
		ret = PTR_ERR(ptp_shared->pdelayrsp_worker);
		goto error_disable_interrupt;
	} 

        return 0;

error_disable_interrupt:
        lan937x_ptp_enable_msg_int(dev, port, PTP_PORT_PDELAY_RESP_INT, false);
        return ret;
}

static int lan937x_ptp_port_init(struct ksz_device *dev, int port)
{
	struct dsa_port *dp = dsa_to_port(dev->ds, port);
	struct lan937x_port_ptp_shared *ptp_shared;
	struct ksz_port *prt = &dev->ports[port];
	int ret;

        ptp_shared = &prt->ptp_shared;
        
	if (port == dev->cpu_port)
		return 0;

	/* Set rx and tx latency to 0 (will be handled by user space) */
	ret = ksz_write16(dev, PORT_CTRL_ADDR(port, REG_PTP_PORT_RX_DELAY__2),
			  0);
	if (ret)
		return ret;

	ret = ksz_write16(dev, PORT_CTRL_ADDR(port, REG_PTP_PORT_TX_DELAY__2),
			  0);
	if (ret)
		return ret;

	ret = lan937x_ptp_enable_ptp_int(dev, port, true);
	if (ret)
		return ret;

	/* ksz_port::ptp_shared is used in tagging driver */
	ptp_shared->dev = &dev->ptp_shared;
        dp->priv = ptp_shared;

        ret = lan937x_ptp_sync_msg_en(dev, port);
        if(ret)
                goto error_disable_ptp_int;

        ret = lan937x_ptp_xdelayreq_msg_en(dev, port);
        if(ret)
                goto error_disable_ptp_int;

        ret = lan937x_ptp_pdelayresp_msg_en(dev, port);
        if(ret)
                goto error_disable_ptp_int;

	return 0;

error_disable_ptp_int:
	lan937x_ptp_enable_ptp_int(dev, port, false);
	return ret;
}

static void lan937x_ptp_port_deinit(struct ksz_device *dev, int port)
{
        struct lan937x_port_ptp_shared *ptp_shared = &dev->ports[port].ptp_shared;

	if (port == dev->cpu_port)
		return;

	kthread_destroy_worker(ptp_shared->sync_worker);
	kthread_destroy_worker(ptp_shared->pdelayreq_worker);
	kthread_destroy_worker(ptp_shared->pdelayrsp_worker);

	lan937x_ptp_enable_msg_int(dev, port, PTP_PORT_PDELAY_RESP_INT, false);
	lan937x_ptp_enable_msg_int(dev, port, PTP_PORT_XDELAY_REQ_INT, false);
	lan937x_ptp_enable_msg_int(dev, port, PTP_PORT_SYNC_INT, false);
	lan937x_ptp_enable_ptp_int(dev, port, false);
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
	while (port-- > 0)
		lan937x_ptp_port_deinit(dev, port);
	return ret;
}

static void lan937x_ptp_ports_deinit(struct ksz_device *dev)
{
	int port;

	for (port = 0; port < dev->port_cnt; port++)
		lan937x_ptp_port_deinit(dev, port);
}

int lan937x_ptp_init(struct ksz_device *dev)
{
	int ret;

	mutex_init(&dev->ptp_mutex);
	spin_lock_init(&dev->ptp_shared.ptp_clock_lock);

	dev->ptp_caps = (struct ptp_clock_info) {
		.owner		= THIS_MODULE,
		.name		= "Microchip Clock",
		.max_adj	= MAX_DRIFT_CORR,
		.enable		= lan937x_ptp_enable,
		.gettime64	= lan937x_ptp_gettime,
		.settime64	= lan937x_ptp_settime,
		.adjfine	= lan937x_ptp_adjfine,
		.adjtime	= lan937x_ptp_adjtime,
		.do_aux_work	= lan937x_ptp_do_aux_work,
		.n_alarm	= 0,
		.n_ext_ts	= 0,
		.n_per_out	= 0,
		.pps		= 1
	};

	/* Start hardware counter (will overflow after 136 years) */
	ret = lan937x_ptp_start_clock(dev);
	if (ret)
		return ret;

        /* Register the PTP Clock */
	dev->ptp_clock = ptp_clock_register(&dev->ptp_caps, dev->dev);
	if (IS_ERR_OR_NULL(dev->ptp_clock)) {
		ret = PTR_ERR(dev->ptp_clock);
		goto error_stop_clock;
	}

	/* Init switch ports */
	ret = lan937x_ptp_ports_init(dev);
	if (ret)
		goto error_unregister_clock;

        /*Enable 802.1as mode */
	ret = lan937x_ptp_8021as(dev, true);
        if(ret)
                goto error_ports_deinit;

	return 0;

error_ports_deinit:
	lan937x_ptp_ports_deinit(dev);
error_unregister_clock:
	ptp_clock_unregister(dev->ptp_clock);
error_stop_clock:
	lan937x_ptp_stop_clock(dev);
	return ret;
}

void lan937x_ptp_deinit(struct ksz_device *dev)
{
	lan937x_ptp_ports_deinit(dev);
	lan937x_ptp_enable_mode(dev, false);
	ptp_clock_unregister(dev->ptp_clock);
	lan937x_ptp_stop_clock(dev);
}

/* Interrupt Service Routine for PTP
 * It reads the 32 bit timestamp value from the register and reconstruct it to 
 * timestamp and post the complete signal 
 */  
irqreturn_t lan937x_ptp_port_interrupt(struct ksz_device *dev, int port)
{
	u32 addr = PORT_CTRL_ADDR(port, REG_PTP_PORT_TX_INT_STATUS__2);
        struct ksz_port *prt = &dev->ports[port];
	u32 tstamp_raw;
	ktime_t tstamp;
	u32 regaddr;
	u16 data;
	int ret;

	ret = ksz_read16(dev, addr, &data);
	if (ret)
		return IRQ_NONE;

	if (data & PTP_PORT_XDELAY_REQ_INT) {
		regaddr = PORT_CTRL_ADDR(port, REG_PTP_PORT_XDELAY_TS);

		ret = ksz_read32(dev, regaddr, &tstamp_raw);
		if (ret)
			return IRQ_NONE;

		tstamp = ksz_decode_tstamp(tstamp_raw);

		prt->tstamp_pdelayreq = ksz_tstamp_reconstruct(&dev->ptp_shared, tstamp);
		complete(&prt->tstamp_pdelayreq_comp);
	}

	if (data & PTP_PORT_PDELAY_RESP_INT) {
		regaddr = PORT_CTRL_ADDR(port, REG_PTP_PORT_PDRESP_TS);

		ret = ksz_read32(dev, regaddr, &tstamp_raw);
		if (ret)
			return IRQ_NONE;

		tstamp = ksz_decode_tstamp(tstamp_raw);

		prt->tstamp_pdelayrsp = ksz_tstamp_reconstruct(&dev->ptp_shared, tstamp);
		complete(&prt->tstamp_pdelayrsp_comp);
	}

	if (data & PTP_PORT_SYNC_INT) {
		regaddr = PORT_CTRL_ADDR(port, REG_PTP_PORT_SYNC_TS);

		ret = ksz_read32(dev, regaddr, &tstamp_raw);
		if (ret)
			return IRQ_NONE;

		tstamp = ksz_decode_tstamp(tstamp_raw);

		prt->tstamp_sync = ksz_tstamp_reconstruct(&dev->ptp_shared, tstamp);
		complete(&prt->tstamp_sync_comp);
	}

	//Clear the interrupts W1C
	ret = ksz_write16(dev, addr, data);
	if (ret)
		return IRQ_NONE;

	return IRQ_HANDLED;
}
