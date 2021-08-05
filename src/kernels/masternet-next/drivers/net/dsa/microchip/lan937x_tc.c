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
#include "lan937x_ptp.h"

#define LAN937X_CBS_ENABLE ((MTI_SCHEDULE_STRICT_PRIO << MTI_SCHEDULE_MODE_S) | \
			    (MTI_SHAPING_SRP << MTI_SHAPING_S))
#define LAN937X_CBS_DISABLE ((MTI_SCHEDULE_WRR << MTI_SCHEDULE_MODE_S) |\
			     (MTI_SHAPING_OFF << MTI_SHAPING_S))

/* Bandwidth is calculated by idle slope/transmission speed. Then the Bandwidth
 * is converted to Hex-decimal using the successive multiplication method. On
 * every step, integer part is taken and decimal part is carry forwarded.
 */
static int cinc_cal(s32 idle_slope, s32 send_slope)
{
	int cinc = 0;
	u32 txrate;
	u32 rate;
	u8 temp;
	u8 i;

	txrate = idle_slope - send_slope;

	rate = idle_slope;

	/* 24 bit register */
	for (i = 0; i < 6; i++) {
		rate = rate * 16;

		temp = rate / txrate;

		rate %= txrate;

		cinc = ((cinc << 4) | temp);
	}

	return cinc;
}

static int lan937x_setup_tc_cbs(struct dsa_switch *ds, int port,
				struct tc_cbs_qopt_offload *qopt)
{
	struct ksz_device *dev = ds->priv;
	int ret;
	u32 bw;

	if (qopt->queue > LAN937X_NUM_TC)
		return -EINVAL;

	/* Queue Selection */
	ret = lan937x_pwrite32(dev, port, REG_PORT_MTI_QUEUE_INDEX__4,
			       qopt->queue);
	if(ret)
		return ret;

	if (!qopt->enable) {
		lan937x_pwrite8(dev, port, REG_PORT_MTI_QUEUE_CTRL_0,
				LAN937X_CBS_DISABLE);
		return 0;
	}

	ret = lan937x_pwrite8(dev, port, REG_PORT_MTI_QUEUE_CTRL_0,
			      LAN937X_CBS_ENABLE);
	if(ret)
		return ret;

	/* High Credit */
	ret = lan937x_pwrite16(dev, port, REG_PORT_MTI_HI_WATER_MARK,
			       qopt->hicredit);
	if(ret)
		return ret;


	/* Low Credit */
	ret = lan937x_pwrite16(dev, port, REG_PORT_MTI_LO_WATER_MARK,
			       qopt->locredit);
	if(ret)
		return ret;

	/* Credit Increment Register */
	bw = cinc_cal(qopt->idleslope, qopt->sendslope);

	return lan937x_pwrite32(dev, port, REG_PORT_MTI_CREDIT_INCREMENT, bw);
}

static bool lan937x_tas_validate_gcl(struct tc_taprio_qopt_offload *qopt)
{
	u8 i;

	/* cycle time can only be 32bit */
	if (qopt->cycle_time > (u32)-1)
		return -EOPNOTSUPP;

	/* Only set command is supported */
	for (i = 0; i < qopt->num_entries; ++i)
		if (qopt->entries[i].command != TC_TAPRIO_CMD_SET_GATES)
			return -EOPNOTSUPP;

	return 0;
}

static void lan937x_tas_set_basetime(struct ksz_device *dev, ktime_t base_time,
				     u32 cycle_time,
				     struct timespec64 *new_base_ts)
{
	ktime_t new_base_time;
	ktime_t current_time;
	struct timespec64 ts;

	lan937x_ptp_gettime(&dev->ptp_caps, &ts);

	current_time = timespec64_to_ktime(ts);
	new_base_time = base_time;

	if (base_time < current_time) {
		u64 nr_of_cycles = current_time - base_time;
		u32 add_cycles = 1;

		/*Reserve 1ms for programming and activating */
		if(cycle_time < 1000000)
			add_cycles = DIV_ROUND_UP(1000000, cycle_time);

		do_div(nr_of_cycles, cycle_time);
		new_base_time += cycle_time * (nr_of_cycles + add_cycles);
	}

	*new_base_ts = ktime_to_timespec64(new_base_time);
}

static int lan937x_setup_tc_taprio(struct dsa_switch *ds, int port,
				   struct tc_taprio_qopt_offload *qopt)
{
	struct ksz_device *dev = ds->priv;
	struct timespec64 base_ts;
	u32 cycle_cnt;
	int ret = 0;
	u32 event;
	u8 i;

	if (!qopt->enable)
	{
		ret =  lan937x_port_cfg(dev, port, REG_PORT_TAS_GATE_CTRL__1,
					TAS_GATE_ENABLE, false);
		return ret;
	}

	/* Validate GCL */
	ret = lan937x_tas_validate_gcl(qopt);
	if (ret)
		return ret;

	/* Enable Gating */
	ret =  lan937x_port_cfg(dev, port, REG_PORT_TAS_GATE_CTRL__1,
				TAS_GATE_ENABLE, true);
	if (ret)
		return ret;

	/* Schedule entry */
	for (i = 0; i < qopt->num_entries; i++) {
		ret = lan937x_pwrite8(dev, port, REG_PORT_TAS_EVENT_INDEX__1,
				      i);
		if (ret)
			return ret;

		/*1 Cycle count equals 12ns. 1/83.3Mhz*/
		event = qopt->entries[i].gate_mask << TAS_GATE_CMD_S;
		cycle_cnt = qopt->entries[i].interval / 12;
		event |= (cycle_cnt & TAS_GATE_CYCLE_M);

		pr_err("event value %x", event);

		ret = lan937x_pwrite32(dev, port, REG_PORT_TAS_EVENT__4, event);
		if (ret)
			return ret;
	}

	/* Last schedule entry */
	ret = lan937x_pwrite16(dev, port, REG_PORT_TAS_GCL_LAST_INDEX__2,
			       qopt->num_entries -1);
	if (ret)
		return ret;

	/*PTP Cycle time*/
	ret = lan937x_pwrite32(dev, port, REG_PORT_TAS_CYCLE_TIME__4,
			       qopt->cycle_time);
	if (ret)
		return ret;

	/*PTP Base time */
	lan937x_tas_set_basetime(dev, qopt->base_time, qopt->cycle_time,
				 &base_ts);

	ret = lan937x_pwrite32(dev, port, REG_PORT_TAS_TRIG_SEC__4,
			       base_ts.tv_sec);
	if (ret)
		return ret;

	ret = lan937x_pwrite32(dev, port, REG_PORT_TAS_TRIG_NSEC__4,
			       base_ts.tv_nsec);
	if (ret)
		return ret;

	/*Set the config change bit */
	return lan937x_port_cfg(dev, port, REG_PORT_TAS_GATE_CTRL__1,
				TAS_CFG_CHANGE, true);
}

int lan937x_setup_tc(struct dsa_switch *ds, int port,
		     enum tc_setup_type type, void *type_data)
{
	switch (type) {
	case TC_SETUP_QDISC_CBS:
		return lan937x_setup_tc_cbs(ds, port, type_data);
	case TC_SETUP_QDISC_TAPRIO:
		return lan937x_setup_tc_taprio(ds, port, type_data);
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
