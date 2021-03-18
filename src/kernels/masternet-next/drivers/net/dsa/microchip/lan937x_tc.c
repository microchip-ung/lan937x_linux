// SPDX-License-Identifier: GPL-2.0
/* Microchip lan937x dev ops functions
 * Copyright (C) 2019-2020 Microchip Technology Inc.
 */
#include <net/dsa.h>
#include <net/switchdev.h>
#include "lan937x_reg.h"
#include "ksz_common.h"
#include "lan937x_dev.h"
#include "lan937x_tc.h"

static int lan937x_setup_tc_mqprio(struct dsa_switch *ds, int port,
		            struct tc_mqprio_qopt_offload *m)
{
        m->qopt.hw = TC_MQPRIO_HW_OFFLOAD_TCS;

        if(m->qopt.num_tc != LAN937X_NUM_TC)
                return -EINVAL;

        return 0;
}


static int cinc_cal(s32 idleSlope, s32 sendSlope)
{
        int cinc = 0;
        u32 txrate;
        u32 rate;
        u8 temp;
        u8 i;

        txrate = idleSlope - sendSlope;

	//Scaling factor 1.5 is applicable only for A0 silicon
        rate = idleSlope * 3;

        txrate *= 2;

        for(i=0; i<6; i++)  //24 bit register
        {
                rate = rate * 16;

                temp = rate / txrate;

                rate %= txrate;

                cinc = ((cinc <<4) | temp);
        }

        if(cinc > 0x00ffffff)
                cinc = 0x00ffffff;

        return cinc;
}


static int lan937x_setup_tc_cbs(struct dsa_switch *ds, int port,
				struct tc_cbs_qopt_offload *qopt)
{
        struct ksz_device *dev = ds->priv;
        u32 bw;

	if(qopt->queue > LAN937X_NUM_TC)
		return -EINVAL;

        lan937x_pwrite32(dev, port, REG_PORT_MTI_QUEUE_INDEX__4, qopt->queue); //queue index register

        if(!qopt->enable)
        {
                lan937x_pwrite8(dev, port, REG_PORT_MTI_QUEUE_CTRL_0,
		       ((MTI_SCHEDULE_WRR<<MTI_SCHEDULE_MODE_S)|(MTI_SHAPING_OFF<<MTI_SHAPING_S))); //schdular
                return 0;
        }
                
        bw = cinc_cal(qopt->idleslope, qopt->sendslope);

        lan937x_pwrite8(dev, port, REG_PORT_MTI_QUEUE_CTRL_0, 
		       ((MTI_SCHEDULE_STRICT_PRIO<<MTI_SCHEDULE_MODE_S)|(MTI_SHAPING_SRP<<MTI_SHAPING_S))); //schdular

        lan937x_pwrite16(dev, port, REG_PORT_MTI_HI_WATER_MARK, qopt->hicredit); //high credit
	
        lan937x_pwrite16(dev, port, REG_PORT_MTI_LO_WATER_MARK, qopt->locredit); //low credit

        lan937x_pwrite16(dev, port, REG_PORT_MTI_CREDIT_INCREMENT, ((bw & 0x00ffff00)>>8)); //credit incr

        lan937x_pwrite8(dev, port, (REG_PORT_MTI_CREDIT_INCREMENT + 2), (bw & 0x000000ff)); //credit incr

        return 0;
}

int lan937x_setup_tc(struct dsa_switch *ds, int port,
				   enum tc_setup_type type, void *type_data)
{
        switch (type) {
	case TC_SETUP_QDISC_MQPRIO:
		return lan937x_setup_tc_mqprio(ds, port, type_data);
	case TC_SETUP_QDISC_CBS:
		return lan937x_setup_tc_cbs(ds, port, type_data);
	default:
		return -EOPNOTSUPP;
	}
}

void lan937x_tc_queue_init(struct dsa_switch *ds)
{
	struct ksz_device *dev = ds->priv;
	int port;

	ds->num_tx_queues = LAN937X_NUM_TC;

	for (port = 0; port < dev->port_cnt; port++) {
		 lan937x_port_cfg(dev, port, REG_PORT_CTRL_0,
		                  PORT_QUEUE_SPLIT_ENABLE, true);
	}
}
