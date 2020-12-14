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

#define MAX_DRIFT_CORR 6250000

#define KSZ_PTP_INC_NS 40  /* HW clock is incremented every 40 ns (by 40) */
#define KSZ_PTP_SUBNS_BITS 32  /* Number of bits in sub-nanoseconds counter */

/* state flags for _port_hwtstamp::state */
enum {
        LAN937X_HWTSTAMP_ENABLED,
        LAN937X_HWTSTAMP_TX_XDELAY_IN_PROGRESS,
        LAN937X_HWTSTAMP_TX_XDELAY_RSP_IN_PROGRESS,
        LAN937X_HWTSTAMP_TX_SYNC_IN_PROGRESS
};

enum ksz9477_ptp_event_messages {
        PTP_Event_Message_Sync        = 0x0,
        PTP_Event_Message_Delay_Req   = 0x1,
        PTP_Event_Message_Pdelay_Req  = 0x2,
        PTP_Event_Message_Pdelay_Resp = 0x3, };


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

        return 0;

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

        return copy_to_user(ifr->ifr_data, &config, sizeof(struct hwtstamp_config)) ?  
                -EFAULT : 0;
}

static int lan937x_set_hwtstamp_config(struct ksz_device *dev, int port,
                struct hwtstamp_config *config)
{
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

        if (rx_on != test_bit(LAN937X_HWTS_EN, &dev->ptp_shared.state)) {
                int ret = 0;

                clear_bit(LAN937X_HWTS_EN, &dev->ptp_shared.state);

                ret = lan937x_ptp_enable_mode(dev, rx_on);
                if (ret) {
                        return ret;
                }
                if (rx_on)
                        set_bit(LAN937X_HWTS_EN, &dev->ptp_shared.state);
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
        memcpy(&dev->tstamp_config, &config, sizeof(config));
        bytes_copied = copy_to_user(ifr->ifr_data, &config, sizeof(config)); 

        mutex_unlock(&dev->ptp_mutex);

        return bytes_copied ?  -EFAULT : 0;
}


bool lan937x_port_txtstamp(struct dsa_switch *ds, int port,
                struct sk_buff *clone, unsigned int type)
{
        struct ksz_device *dev  = ds->priv;
        struct ksz_port *prt = &dev->ports[port];
        struct ptp_header *hdr;
        enum ksz9477_ptp_event_messages msg_type;
        struct skb_shared_hwtstamps shhwtstamps;

        if (!(skb_shinfo(clone)->tx_flags & SKBTX_HW_TSTAMP))
                return false;

        if (!prt->hwts_tx_en)
                return false;

        hdr = ptp_parse_header(clone, type);
        if (!hdr)
                return false;

        msg_type = ptp_get_msgtype(hdr, type);

        switch (msg_type) {
                /* As the KSZ9563 always performs one step time stamping, only the time
                * stamp for Delay_Req and Pdelay_Req are reported to the application
                * via socket error queue. Time stamps for Sync and Pdelay_resp will be
                * applied directly to the outgoing message (e.g. correction field), but
                * will NOT be reported to the socket.
                 */
                case PTP_Event_Message_Pdelay_Req:
                        if (test_and_set_bit_lock(LAN937X_HWTSTAMP_TX_XDELAY_IN_PROGRESS,
                                                &prt->tstamp_state))
                                return false;  /* free cloned skb */

                        prt->tstamp_tx_xdelay_skb = clone;
                        break;

                case PTP_Event_Message_Pdelay_Resp:
                        if (test_and_set_bit_lock(LAN937X_HWTSTAMP_TX_XDELAY_RSP_IN_PROGRESS,
                                                &prt->tstamp_state))
                                return false;  /* free cloned skb */

                        prt->tstamp_tx_xdelay_rsp_skb = clone;
                        break;



                case PTP_Event_Message_Sync:
                        if (test_and_set_bit_lock(LAN937X_HWTSTAMP_TX_SYNC_IN_PROGRESS,
                                                &prt->tstamp_state))
                                return false;  /* free cloned skb */

                        prt->tstamp_tx_sync_skb = clone;
                        //	shhwtstamps.hwtstamp = lan937x_tstamp_reconstruct(dev, 0x1234);
                        //	skb_complete_tx_timestamp(clone, &shhwtstamps);
                        break;

                default:
                        return false;  /* free cloned skb */
        }

        prt->tx_tstamp_start = jiffies;
        prt->tx_seq_id = be16_to_cpu(hdr->sequence_id);

        //ptp_schedule_worker(dev->ptp_clock, 0);
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

        ret = ksz_write16(dev, REG_PTP_CLK_CTRL, data16)
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
        struct ksz_device_ptp_shared *ptp_shared = &dev->ptp_shared;
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
        struct ksz_device *dev = ptp_clock_info_to_dev(ptp);
        struct ksz_device_ptp_shared *ptp_shared = &dev->ptp_shared;
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
        {
                data16 &= ~PTP_STEP_DIR;  /* 0: subtract */
        }
        else
        {
                data16 |= PTP_STEP_DIR;   /* 1: add */
        }

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
        struct ksz_device *dev = ptp_clock_info_to_dev(ptp);
        struct ksz_device_ptp_shared *ptp_shared = &dev->ptp_shared;
        struct timespec64 ts;
        unsigned long flags;

        mutex_lock(&dev->ptp_mutex);
        _lan937x_ptp_gettime(dev, &ts);
        mutex_unlock(&dev->ptp_mutex);

        spin_lock_bh(&ptp_shared->ptp_clock_lock);
        ptp_shared->ptp_clock_time = ts;
        spin_unlock_bh(&ptp_shared->ptp_clock_lock);

        return 1; //HZ;  /* reschedule in 1 second */
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

static int lan937x_ptp_enable_port_ptp_interrupts(struct ksz_device *dev,
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

static int lan937x_ptp_enable_port_sync_interrupts(struct ksz_device *dev, 
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

static int lan937x_ptp_enable_port_xdelayreq_interrupts(struct ksz_device *dev,
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

static int lan937x_ptp_enable_port_xdelayrsp_interrupts(struct ksz_device *dev,
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

static int lan937x_ptp_disable_port_xDelayRsp_interrupts(struct ksz_device *dev, int port)
{
        u32 addr = PORT_CTRL_ADDR(port, REG_PTP_PORT_TX_INT_ENABLE__2);
        u16 data;
        int ret;

        ret = ksz_read16(dev, addr, &data);
        if (ret)
                return ret;

        /* Disable port xdelay egress timestamp interrupts (0 means disabled) */
        data &= PTP_PORT_PDELAY_RESP_INT;
        ret = ksz_write16(dev, addr, data);
        if (ret)
                return ret;

        return 0;
}
static int lan937x_ptp_port_init(struct ksz_device *dev, int port)
{
        struct ksz_port *prt = &dev->ports[port];
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

        ret = lan937x_ptp_enable_port_ptp_interrupts(dev, port, true);
        if (ret)
                return ret;

        ret = lan937x_ptp_enable_port_sync_interrupts(dev, port, true);
        if (ret)
                goto error_disable_port_ptp_interrupts;

        ret = lan937x_ptp_enable_port_xdelayreq_interrupts(dev, port, true);
        if (ret)
                goto error_disable_port_sync_interrupts;

        ret = lan937x_ptp_enable_port_xdelayrsp_interrupts(dev, port, true);
        if(ret)
                goto error_disable_port_xdelayreq_interrupts;

        return 0;

error_disable_port_xdelayreq_interrupts:
	lan937x_ptp_enable_port_xdelayreq_interrupts(dev, port, false);
error_disable_port_sync_interrupts:
        lan937x_ptp_enable_port_sync_interrupts(dev, port, false);
error_disable_port_ptp_interrupts:
        lan937x_ptp_enable_port_ptp_interrupts(dev, port, false);
        return ret;
}

static void lan937x_ptp_port_deinit(struct ksz_device *dev, int port)
{
        if (port == dev->cpu_port) 
                return;

        lan937x_ptp_enable_port_xdelayrsp_interrupts(dev, port, false);
        lan937x_ptp_enable_port_xdelayreq_interrupts(dev, port, false);
        lan937x_ptp_enable_port_sync_interrupts(dev, port, false);
        lan937x_ptp_enable_port_ptp_interrupts(dev, port, false);
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

enum ksz9477_ptp_tcmode {
        KSZ9477_PTP_TCMODE_E2E,
        KSZ9477_PTP_TCMODE_P2P,
};

static int ksz9477_ptp_tcmode_set(struct ksz_device *dev,
                enum ksz9477_ptp_tcmode tcmode)
{
        u16 data;
        int ret;

        ret = ksz_read16(dev, REG_PTP_MSG_CONF1, &data);
        if (ret)
                return ret;

        if (tcmode == KSZ9477_PTP_TCMODE_P2P)
                data |= PTP_TC_P2P;
        else
                data &= ~PTP_TC_P2P;

        return ksz_write16(dev, REG_PTP_MSG_CONF1, data);
}
enum lan937x_ptp_ocmode {
        KSZ9477_PTP_OCMODE_SLAVE,
        KSZ9477_PTP_OCMODE_MASTER,
};

static int lan937x_ptp_ocmode_set(struct ksz_device *dev,
                enum lan937x_ptp_ocmode ocmode)
{
        u16 data;
        int ret;

        ret = ksz_read16(dev, REG_PTP_MSG_CONF1, &data);
        if (ret)
                return ret;

        if (ocmode == KSZ9477_PTP_OCMODE_MASTER)
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

        /* Enable PTP mode (will affect tail tagging format) */
        ret = lan937x_ptp_enable_mode(dev, true);
        if (ret)
                goto error_unregister_clock;

        /* Init switch ports */
        ret = lan937x_ptp_ports_init(dev);
        if (ret)
                goto error_disable_mode;

        //ksz9477_ptp_tcmode_set(dev, KSZ9477_PTP_TCMODE_P2P);
        lan937x_ptp_8021as_set(dev, 1);
        //	lan937x_ptp_ocmode_set(dev, KSZ9477_PTP_OCMODE_MASTER);
        //	lan937x_ptp_twostep_set(dev, 1);


        return 0;

error_disable_mode:
        lan937x_ptp_enable_mode(dev, false);
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
        u32 enable_addr = PORT_CTRL_ADDR(port, REG_PTP_PORT_TX_INT_ENABLE__2);
        struct ksz_port *prt = &dev->ports[port - 1];
        u16 data;
        int ret;


        ret = ksz_read16(dev, addr, &data);
        if (ret)
                return IRQ_NONE;


        //	if (((data & PTP_PORT_XDELAY_REQ_INT) || (data & PTP_PORT_SYNC_INT)) && prt->tstamp_tx_xdelay_skb) {
        if ((data & PTP_PORT_XDELAY_REQ_INT) || (data & PTP_PORT_SYNC_INT)|| (data & PTP_PORT_PDELAY_RESP_INT)) {
                /* Timestamp for Pdelay_Req / Delay_Req */
                u32 tstamp_raw;
                ktime_t tstamp;
                struct skb_shared_hwtstamps shhwtstamps;
                struct sk_buff *tmp_skb;
                u32 regaddr;
                u16 portInt;

                if(data & PTP_PORT_XDELAY_REQ_INT)
                {
                        regaddr = PORT_CTRL_ADDR(port, REG_PTP_PORT_XDELAY_TS);
                        portInt = PTP_PORT_XDELAY_REQ_INT;
                }
                else if(data & PTP_PORT_PDELAY_RESP_INT)
                {
                        regaddr = PORT_CTRL_ADDR(port, REG_PTP_PORT_PDRESP_TS);
                        portInt = PTP_PORT_PDELAY_RESP_INT;

                }
                else if(data & PTP_PORT_SYNC_INT)
                {
                        regaddr = PORT_CTRL_ADDR(port, REG_PTP_PORT_SYNC_TS);
                        portInt = PTP_PORT_SYNC_INT;
                }
                else
                {

                }

                /* In contrast to the KSZ9563R data sheet, the format of the
                * port time stamp registers is also 2 bit seconds + 30 bit
                * nanoseconds (same as in the tail tags).
                 */
                ret = ksz_read32(dev, regaddr, &tstamp_raw);
                if (ret)
                        return IRQ_NONE;

                tstamp = ksz9477_decode_tstamp(tstamp_raw);
                memset(&shhwtstamps, 0, sizeof(shhwtstamps));
                shhwtstamps.hwtstamp = lan937x_tstamp_reconstruct(&dev->ptp_shared, tstamp);

                /* skb_complete_tx_timestamp() will free up the client to make
                * another timestamp-able transmit. We have to be ready for it
                * -- by clearing the ps->tx_skb "flag" -- beforehand.
                 */

                if(data & PTP_PORT_XDELAY_REQ_INT)
                {
                        tmp_skb = prt->tstamp_tx_xdelay_skb;
                        prt->tstamp_tx_xdelay_skb = NULL;
                        clear_bit_unlock(LAN937X_HWTSTAMP_TX_XDELAY_IN_PROGRESS, &prt->tstamp_state);
                }
                else if(data & PTP_PORT_PDELAY_RESP_INT)
                {
                        tmp_skb = prt->tstamp_tx_xdelay_rsp_skb;
                        prt->tstamp_tx_xdelay_rsp_skb = NULL;
                        clear_bit_unlock(LAN937X_HWTSTAMP_TX_XDELAY_RSP_IN_PROGRESS, &prt->tstamp_state);

                }
                else if(data & PTP_PORT_SYNC_INT)
                {
                        tmp_skb = prt->tstamp_tx_sync_skb;
                        prt->tstamp_tx_sync_skb = NULL;
                        clear_bit_unlock(LAN937X_HWTSTAMP_TX_SYNC_IN_PROGRESS, &prt->tstamp_state);

                }
                skb_complete_tx_timestamp(tmp_skb, &shhwtstamps);

                /* Clear interrupt(s) (W1C) */
                ret = ksz_write16(dev, addr, portInt);
                if (ret)
                        return IRQ_NONE;
        }

        return IRQ_HANDLED;
}
