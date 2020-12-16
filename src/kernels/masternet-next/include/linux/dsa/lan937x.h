/* SPDX-License-Identifier: GPL-2.0 */
/* Microchip LAN937X extended port information
 * Copyright (C) 2019-2020 Microchip Technology Inc.
 */
#ifndef _NET_DSA_LAN937X_H
#define _NET_DSA_LAN937X_H

#include <net/dsa.h>

struct lan937x_port_ptp_shared{
	struct ksz_device_ptp_shared *dev;
        struct kthread_worker *xmit_sync_worker;
        struct kthread_worker *xmit_pdelayreq_worker;
        struct kthread_worker *xmit_pdelayrsp_worker;
	struct kthread_work xmit_sync_work;
	struct sk_buff_head xmit_sync_queue;
	struct kthread_work xmit_pdelayreq_work;
	struct sk_buff_head xmit_pdelayreq_queue;
	struct kthread_work xmit_pdelayrsp_work;
	struct sk_buff_head xmit_pdelayrsp_queue;
};

/* Lan937x port extended information which is used to refer
 * logical port number when accessing the registers
 */
struct lan937x_port_ext {
	u8 lp_num; /*logical port number*/
	u8 tx_phy_log_prt; /*tx phy port number in the device*/
	struct dsa_port *dp;
        struct lan937x_port_ptp_shared ptp_shared;
        ktime_t tstamp_sync;
	struct completion tstamp_sync_comp;	
        ktime_t tstamp_pdelayreq;
	struct completion tstamp_pdelayreq_comp;	
        ktime_t tstamp_pdelayrsp;
	struct completion tstamp_pdelayrsp_comp;	
};

#endif/* _NET_DSA_LAN937X_H */
