// SPDX-License-Identifier: GPL-2.0
/* Microchip LAN937X PTP Implementation 
* Copyright (C) 2019-2020 Microchip Technology Inc.
 */

#include "lan937x_reg.h"
#include "ksz_common.h"
#include <linux/ptp_classify.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/irqreturn.h>
#include <linux/dsa/lan937x.h>

#define ptp_clock_info_to_dev(d) \
        container_of((d), struct ksz_device, ptp_caps)

#define MAX_DRIFT_CORR 6250000

#define KSZ_PTP_INC_NS 40  /* HW clock is incremented every 40 ns (by 40) */
#define KSZ_PTP_SUBNS_BITS 32  /* Number of bits in sub-nanoseconds counter */


/*Time Stamping support - accessing the register */
static int lan937x_ptp_enable_mode(struct ksz_device *dev, bool enable) {
        u16 data;
        int ret;

        ret = ksz_read16(dev, REG_PTP_MSG_CONF1, &data);
        if (ret)
                return ret;

        /* Enable PTP mode */
        if(enable)
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
        struct ksz_device *dev  = ds->priv;

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
        struct ksz_device *dev  = ds->priv;
        struct hwtstamp_config config;

        config.flags = 0;

        if (dev->prts_ext[port].hwts_tx_en)
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
        struct lan937x_port_ext *prt = &dev->prts_ext[port];
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
                int ret = 0;

                clear_bit(LAN937X_HWTS_EN, &dev->ptp_shared.state);

                ret = lan937x_ptp_enable_mode(dev, rx_on);
                if (ret) {
                        return ret;
                }
                if (rx_on)
                        set_bit(LAN937X_HWTS_EN, &ptp_shared->state);
        }

        return 0;
}

int lan937x_hwtstamp_set(struct dsa_switch *ds, int port, struct ifreq *ifr)
{
        struct ksz_device *dev  = ds->priv;
        struct hwtstamp_config config;
        unsigned long bytes_copied;
        int err;	

        mutex_lock(&dev->ptp_mutex);

        if(copy_from_user(&config, ifr->ifr_data, sizeof(config)))
                return -EFAULT;

        err = lan937x_set_hwtstamp_config(dev, port, &config);
        if (err)
                return err;

        /* Save the chosen configuration to be returned later. */
        bytes_copied = copy_to_user(ifr->ifr_data, &config, sizeof(config)); 

        mutex_unlock(&dev->ptp_mutex);

        return bytes_copied ?  -EFAULT : 0;
}


bool lan937x_port_txtstamp(struct dsa_switch *ds, int port,
                struct sk_buff *clone, unsigned int type)
{
        struct ksz_device *dev  = ds->priv;
        struct lan937x_port_ext *prt;
        struct ptp_header *hdr;
        u8 ptp_msg_type;

        prt =  &dev->prts_ext[port];

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


//These are function releated to the ptp clock info

static int lan937x_ptp_enable(struct ptp_clock_info *ptp,
                struct ptp_clock_request *req, int on)
{
        return -ENOTTY;
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
         * both sec and nsec are subtracted by hw */
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

        spin_lock_bh(&ptp_shared->ptp_clock_lock);
        ptp_shared->ptp_clock_time = timespec64_add(ptp_shared->ptp_clock_time, delta64);
        spin_unlock_bh(&ptp_shared->ptp_clock_lock);

error_return:
        mutex_unlock(&dev->ptp_mutex);
        return ret;
}

/*
* Function is pointer to the do_aux_work in the ptp_clock capability.
 */
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

        /* Perform PTP clock reset */
        /*	data |= PTP_CLK_RESET;
                ret = ksz_write16(dev, REG_PTP_CLK_CTRL, data);
                if (ret)
                return ret;
                data &= ~PTP_CLK_RESET;
         */
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

static int lan937x_ptp_enable_ptp_interrupts(struct ksz_device *dev,
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

static int lan937x_ptp_enable_sync_interrupts(struct ksz_device *dev, 
                                              int port, bool enable)
{
        u32 addr = PORT_CTRL_ADDR(port, REG_PTP_PORT_TX_INT_ENABLE__2);
        u16 data;
        int ret;

        ret = ksz_read16(dev, addr, &data);
        if (ret)
                return ret;

        /* Enable port sync timestamp interrupt (1 means enabled) */
        if(enable)
                data |= PTP_PORT_SYNC_INT;
        else
                data &= ~PTP_PORT_SYNC_INT;
        
        return ksz_write16(dev, addr, data);
}

static int lan937x_ptp_enable_xdelayreq_interrupts(struct ksz_device *dev,
						     int port, bool enable)
{
	u32 addr = PORT_CTRL_ADDR(port, REG_PTP_PORT_TX_INT_ENABLE__2);
	u16 data;
	int ret;

	ret = ksz_read16(dev, addr, &data);
	if (ret)
		return ret;

	/* PTP_PORT_XDELAY_REQ_INT is high active */
	if (enable)
		data |= PTP_PORT_XDELAY_REQ_INT;
	else
		data &= ~PTP_PORT_XDELAY_REQ_INT;

	return ksz_write16(dev, addr, data);
}

static int lan937x_ptp_enable_xdelayrsp_interrupts(struct ksz_device *dev,
                                                   int port, bool enable)
{
        u32 addr = PORT_CTRL_ADDR(port, REG_PTP_PORT_TX_INT_ENABLE__2);
        u16 data;
        int ret;

        ret = ksz_read16(dev, addr, &data);
        if (ret)
                return ret;

        /* Enable port xdelay resp timestamp interrupt (1 means enabled) */
        if(enable)
                data |= PTP_PORT_PDELAY_RESP_INT;
        else
                data &= ~PTP_PORT_PDELAY_RESP_INT;

        return ksz_write16(dev, addr, data);
}


static void lan937x_sync_txtstamp_skb(struct ksz_device *dev,
	              struct lan937x_port_ext *prt_ext, struct sk_buff *skb)
{
	struct skb_shared_hwtstamps hwtstamps = {};
	int ret;

	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;

	/* timeout must include tstamp latency, IRQ latency and time for
	 * reading the time stamp.
	 */
	ret = wait_for_completion_timeout(&prt_ext->tstamp_sync_comp,
					  msecs_to_jiffies(100));
	if (!ret) {
		return;
	}

	hwtstamps.hwtstamp = prt_ext->tstamp_sync;
	skb_complete_tx_timestamp(skb, &hwtstamps);
}

static void lan937x_pdelayreq_txtstamp_skb(struct ksz_device *dev,
		         struct lan937x_port_ext *prt_ext, struct sk_buff *skb)
{
	struct skb_shared_hwtstamps hwtstamps = {};
	int ret;

	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;

	/* timeout must include tstamp latency, IRQ latency and time for
	 * reading the time stamp.
	 */
	ret = wait_for_completion_timeout(&prt_ext->tstamp_pdelayreq_comp,
					  msecs_to_jiffies(100));
	if (!ret) {
		return;
	}
	hwtstamps.hwtstamp = prt_ext->tstamp_pdelayreq;
	skb_complete_tx_timestamp(skb, &hwtstamps);
}

static void lan937x_pdelayrsp_txtstamp_skb(struct ksz_device *dev,
		         struct lan937x_port_ext *prt_ext, struct sk_buff *skb)
{
	struct skb_shared_hwtstamps hwtstamps = {};
	int ret;

	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;

	/* timeout must include tstamp latency, IRQ latency and time for
	 * reading the time stamp.
	 */
	ret = wait_for_completion_timeout(&prt_ext->tstamp_pdelayrsp_comp,
					  msecs_to_jiffies(100));
	if (!ret) {
		return;
	}
	hwtstamps.hwtstamp = prt_ext->tstamp_pdelayrsp;
	skb_complete_tx_timestamp(skb, &hwtstamps);
}

#define sync_to_port(work) \
		container_of((work), struct lan937x_port_ptp_shared, sync_work)
#define pdelayreq_to_port(work) \
		container_of((work), struct lan937x_port_ptp_shared, pdelayreq_work)
#define pdelayrsp_to_port(work) \
		container_of((work), struct lan937x_port_ptp_shared, pdelayrsp_work)
#define ptp_shared_to_port_ext(t) \
		container_of((t), struct lan937x_port_ext, ptp_shared)
#define ptp_shared_to_ksz_device(t) \
		container_of((t), struct ksz_device, ptp_shared)

/* Deferred work is necessary for time stamped PDelay_Req messages. This cannot
 * be done from atomic context as we have to wait for the hardware interrupt.
 */
static void lan937x_sync_deferred_xmit(struct kthread_work *work)
{
	struct lan937x_port_ptp_shared *prt_ptp_shared = sync_to_port(work);
	struct lan937x_port_ext *prt_ext = ptp_shared_to_port_ext(prt_ptp_shared);
	struct ksz_device_ptp_shared *ptp_shared = prt_ptp_shared->dev;
	struct ksz_device *dev = ptp_shared_to_ksz_device(ptp_shared);
	int port = prt_ext - dev->prts_ext;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&prt_ptp_shared->sync_queue)) != NULL) {
		struct sk_buff *clone = DSA_SKB_CB(skb)->clone;

		reinit_completion(&prt_ext->tstamp_sync_comp);

		/* Transfer skb to the host port. */
		dsa_enqueue_skb(skb, dsa_to_port(dev->ds, port)->slave);

		lan937x_sync_txtstamp_skb(dev, prt_ext, clone);
	}
}


static void lan937x_pdelayreq_deferred_xmit(struct kthread_work *work)
{
	struct lan937x_port_ptp_shared *prt_ptp_shared = pdelayreq_to_port(work);
	struct lan937x_port_ext *prt_ext = ptp_shared_to_port_ext(prt_ptp_shared);
	struct ksz_device_ptp_shared *ptp_shared = prt_ptp_shared->dev;
	struct ksz_device *dev = ptp_shared_to_ksz_device(ptp_shared);
	int port = prt_ext - dev->prts_ext;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&prt_ptp_shared->pdelayreq_queue)) != NULL) {
		struct sk_buff *clone = DSA_SKB_CB(skb)->clone;

		reinit_completion(&prt_ext->tstamp_pdelayreq_comp);

		/* Transfer skb to the host port. */
		dsa_enqueue_skb(skb, dsa_to_port(dev->ds, port)->slave);

		lan937x_pdelayreq_txtstamp_skb(dev, prt_ext, clone);
	}
}

static void lan937x_pdelayrsp_deferred_xmit(struct kthread_work *work)
{
	struct lan937x_port_ptp_shared *prt_ptp_shared = pdelayrsp_to_port(work);
	struct lan937x_port_ext *prt_ext = ptp_shared_to_port_ext(prt_ptp_shared);
	struct ksz_device_ptp_shared *ptp_shared = prt_ptp_shared->dev;
	struct ksz_device *dev = ptp_shared_to_ksz_device(ptp_shared);
	int port = prt_ext - dev->prts_ext;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&prt_ptp_shared->pdelayrsp_queue)) != NULL) {
		struct sk_buff *clone = DSA_SKB_CB(skb)->clone;

		reinit_completion(&prt_ext->tstamp_pdelayrsp_comp);

		/* Transfer skb to the host port. */
		dsa_enqueue_skb(skb, dsa_to_port(dev->ds, port)->slave);

		lan937x_pdelayrsp_txtstamp_skb(dev, prt_ext, clone);
	}
}

static int lan937x_ptp_port_init(struct ksz_device *dev, int port)
{
        struct lan937x_port_ext *prt_ext = &dev->prts_ext[port];
	struct lan937x_port_ptp_shared *ptp_shared = &prt_ext->ptp_shared;
	struct dsa_port *dp = dsa_to_port(dev->ds, port);
        int ret;

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

        ret = lan937x_ptp_enable_ptp_interrupts(dev, port, true);
        if (ret)
                return ret;

        ret = lan937x_ptp_enable_sync_interrupts(dev, port, true);
        if (ret)
                goto error_disable_ptp_interrupts;

        ret = lan937x_ptp_enable_xdelayreq_interrupts(dev, port, true);
        if (ret)
                goto error_disable_sync_interrupts;

        ret = lan937x_ptp_enable_xdelayrsp_interrupts(dev, port, true);
        if(ret)
                goto error_disable_xdelayreq_interrupts;

	/* ksz_port::ptp_shared is used in tagging driver */
	ptp_shared->dev = &dev->ptp_shared;

	init_completion(&prt_ext->tstamp_sync_comp);
	kthread_init_work(&ptp_shared->sync_work,
			  lan937x_sync_deferred_xmit);

	init_completion(&prt_ext->tstamp_pdelayreq_comp);
	kthread_init_work(&ptp_shared->pdelayreq_work,
			  lan937x_pdelayreq_deferred_xmit);

	init_completion(&prt_ext->tstamp_pdelayrsp_comp);
	kthread_init_work(&ptp_shared->pdelayrsp_work,
			  lan937x_pdelayrsp_deferred_xmit);

	ptp_shared->sync_worker = kthread_create_worker(0, "%s_xmit",
							dp->slave->name);
	ptp_shared->pdelayreq_worker = kthread_create_worker(0, "%s_req_xmit",
							dp->slave->name);
	ptp_shared->pdelayrsp_worker = kthread_create_worker(0, "%s_rsp_xmit",
							dp->slave->name);
	if (IS_ERR(ptp_shared->sync_worker)) 
		goto error_disable_xdelayreq_interrupts;
	
	skb_queue_head_init(&ptp_shared->sync_queue);
	skb_queue_head_init(&ptp_shared->pdelayreq_queue);
	skb_queue_head_init(&ptp_shared->pdelayrsp_queue);

        return 0;

error_disable_xdelayreq_interrupts:
	lan937x_ptp_enable_xdelayreq_interrupts(dev, port, false);
error_disable_sync_interrupts:
        lan937x_ptp_enable_sync_interrupts(dev, port, false);
error_disable_ptp_interrupts:
        lan937x_ptp_enable_ptp_interrupts(dev, port, false);
        return ret;
}

static void lan937x_ptp_port_deinit(struct ksz_device *dev, int port)
{
        struct lan937x_port_ext *prt_ext = &dev->prts_ext[port];
	struct lan937x_port_ptp_shared *ptp_shared = &prt_ext->ptp_shared;

        if (port == dev->cpu_port) 
                return;

        kthread_destroy_worker(ptp_shared->sync_worker);
        kthread_destroy_worker(ptp_shared->pdelayreq_worker);
        kthread_destroy_worker(ptp_shared->pdelayrsp_worker);

        lan937x_ptp_enable_xdelayrsp_interrupts(dev, port, false);
        lan937x_ptp_enable_xdelayreq_interrupts(dev, port, false);
        lan937x_ptp_enable_sync_interrupts(dev, port, false);
        lan937x_ptp_enable_ptp_interrupts(dev, port, false);
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

enum lan937x_ptp_tcmode {
        LAN937x_PTP_TCMODE_E2E,
        LAN937x_PTP_TCMODE_P2P,
};

static int lan937x_ptp_tcmode_set(struct ksz_device *dev,
                                 enum lan937x_ptp_tcmode tcmode)
{
        u16 data;
        int ret;

        ret = ksz_read16(dev, REG_PTP_MSG_CONF1, &data);
        if (ret)
                return ret;

        if (tcmode == LAN937x_PTP_TCMODE_P2P)
                data |= PTP_TC_P2P;
        else
                data &= ~PTP_TC_P2P;

        return ksz_write16(dev, REG_PTP_MSG_CONF1, data);
}

enum lan937x_ptp_ocmode {
        LAN937x_PTP_OCMODE_SLAVE,
        LAN937x_PTP_OCMODE_MASTER,
};

static int lan937x_ptp_ocmode_set(struct ksz_device *dev,
                enum lan937x_ptp_ocmode ocmode)
{
        u16 data;
        int ret;

        ret = ksz_read16(dev, REG_PTP_MSG_CONF1, &data);
        if (ret)
                return ret;

        if (ocmode == LAN937x_PTP_OCMODE_MASTER)
                data |= PTP_INITIATOR;
        else
                data &= ~PTP_INITIATOR;

        return ksz_write16(dev, REG_PTP_MSG_CONF1, data);
}

static int lan937x_ptp_twostep_set(struct ksz_device *dev,
                                   bool val)
{
        u16 data;
        int ret;

        ret = ksz_read16(dev, REG_PTP_MSG_CONF1, &data);
        if (ret)
                return ret;

        if (val == 1)
                data &= ~PTP_1STEP;		
        else
                data |= PTP_1STEP;		

        return ksz_write16(dev, REG_PTP_MSG_CONF1, data);
}

static int lan937x_ptp_8021as_set(struct ksz_device *dev,
                bool val)
{
        u16 data;
        int ret;

        ret = ksz_read16(dev, REG_PTP_MSG_CONF1, &data);
        if (ret)
                return ret;

        if (val == 1)
                data |= PTP_802_1AS;
        else
                data &= ~PTP_802_1AS;		

        return ksz_write16(dev, REG_PTP_MSG_CONF1, data);
}

int lan937x_ptp_init(struct dsa_switch *ds)
{
        struct ksz_device *dev  = ds->priv;
        int ret;

        mutex_init(&dev->ptp_mutex);
        spin_lock_init(&dev->ptp_shared.ptp_clock_lock);

        dev->ptp_caps = (struct ptp_clock_info) {
                .owner		= THIS_MODULE,
                        .name		= "Microchip Clock",
                        .max_adj  	= MAX_DRIFT_CORR,
                        .enable		= lan937x_ptp_enable,
                        .gettime64	= lan937x_ptp_gettime,
                        .settime64	= lan937x_ptp_settime,
                        .adjfine	= lan937x_ptp_adjfine,
                        .adjtime	= lan937x_ptp_adjtime,
                        .do_aux_work	= lan937x_ptp_do_aux_work,
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

        /* Init switch ports */
        ret = lan937x_ptp_ports_init(dev);
        if (ret)
                goto error_unregister_clock;

        //lan937x_ptp_tcmode_set(dev, LAN937x_PTP_TCMODE_P2P);
        lan937x_ptp_8021as_set(dev, 1);
        //	lan937x_ptp_ocmode_set(dev, LAN937x_PTP_OCMODE_MASTER);
        //	lan937x_ptp_twostep_set(dev, 1);


        return 0;

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

        dev->ptp_clock = NULL;
        lan937x_ptp_ports_deinit(dev);
        lan937x_ptp_enable_mode(dev, false);
        ptp_clock_unregister(dev->ptp_clock);
        lan937x_ptp_stop_clock(dev);
}

irqreturn_t lan937x_ptp_port_interrupt(struct ksz_device *dev, int port)
{
        u32 addr = PORT_CTRL_ADDR(port, REG_PTP_PORT_TX_INT_STATUS__2);
        struct lan937x_port_ext *prt_ext = &dev->prts_ext[port - 1];
        u32 tstamp_raw;
        ktime_t tstamp;
        u32 regaddr;
        u16 data;
        int ret;

        ret = ksz_read16(dev, addr, &data);
        if (ret)
                return IRQ_NONE;

        if(data & PTP_PORT_XDELAY_REQ_INT)
        {
                regaddr = PORT_CTRL_ADDR(port, REG_PTP_PORT_XDELAY_TS);

                ret = ksz_read32(dev, regaddr, &tstamp_raw);
                if (ret)
                        return IRQ_NONE;

                tstamp = ksz_decode_tstamp(tstamp_raw);

                prt_ext->tstamp_pdelayreq = ksz_tstamp_reconstruct(&dev->ptp_shared, tstamp);
                complete(&prt_ext->tstamp_pdelayreq_comp);
        }

        if(data & PTP_PORT_PDELAY_RESP_INT)
        {
                regaddr = PORT_CTRL_ADDR(port, REG_PTP_PORT_PDRESP_TS);

                ret = ksz_read32(dev, regaddr, &tstamp_raw);
                if (ret)
                        return IRQ_NONE;

                tstamp = ksz_decode_tstamp(tstamp_raw);

                prt_ext->tstamp_pdelayrsp = ksz_tstamp_reconstruct(&dev->ptp_shared, tstamp);
                complete(&prt_ext->tstamp_pdelayrsp_comp);
        }

        if(data & PTP_PORT_SYNC_INT)
        {
                regaddr = PORT_CTRL_ADDR(port, REG_PTP_PORT_SYNC_TS);

                ret = ksz_read32(dev, regaddr, &tstamp_raw);
                if (ret)
                        return IRQ_NONE;

                tstamp = ksz_decode_tstamp(tstamp_raw);

                prt_ext->tstamp_sync = ksz_tstamp_reconstruct(&dev->ptp_shared, tstamp);
                complete(&prt_ext->tstamp_sync_comp);
        }

        //Clear the interrupts W1C
        ret = ksz_write16(dev, addr, data);
        if (ret)
                return IRQ_NONE;


        return IRQ_HANDLED;
}
