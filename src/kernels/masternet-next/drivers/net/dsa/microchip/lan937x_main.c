// SPDX-License-Identifier: GPL-2.0
/* Microchip LAN937X switch driver main logic
 * Copyright (C) 2019-2020 Microchip Technology Inc.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/iopoll.h>
#include <linux/phy.h>
#include <linux/if_bridge.h>
#include <net/dsa.h>
#include <net/switchdev.h>
#include "lan937x_reg.h"
#include "lan937x_ptp.h"
#include "ksz_common.h"
#include "lan937x_dev.h"

static int lan937x_wait_vlan_ctrl_ready(struct ksz_device *dev)
{
	unsigned int val;

	return regmap_read_poll_timeout(dev->regmap[0], REG_SW_VLAN_CTRL,
					val, !(val & VLAN_START), 10, 1000);
}

static int lan937x_get_vlan_table(struct ksz_device *dev, u16 vid,
				  u32 *vlan_table)
{
	int ret;

	mutex_lock(&dev->vlan_mutex);

	ksz_write16(dev, REG_SW_VLAN_ENTRY_INDEX__2, vid & VLAN_INDEX_M);
	ksz_write8(dev, REG_SW_VLAN_CTRL, VLAN_READ | VLAN_START);

	/* wait to be cleared */
	ret = lan937x_wait_vlan_ctrl_ready(dev);
	if (ret)
		goto exit;

	ksz_read32(dev, REG_SW_VLAN_ENTRY__4, &vlan_table[0]);
	ksz_read32(dev, REG_SW_VLAN_ENTRY_UNTAG__4, &vlan_table[1]);
	ksz_read32(dev, REG_SW_VLAN_ENTRY_PORTS__4, &vlan_table[2]);

	ksz_write8(dev, REG_SW_VLAN_CTRL, 0);

exit:
	mutex_unlock(&dev->vlan_mutex);

	return ret;
}

static int lan937x_set_vlan_table(struct ksz_device *dev, u16 vid,
				  u32 *vlan_table)
{
	int ret;

	mutex_lock(&dev->vlan_mutex);

	ksz_write32(dev, REG_SW_VLAN_ENTRY__4, vlan_table[0]);
	ksz_write32(dev, REG_SW_VLAN_ENTRY_UNTAG__4, vlan_table[1]);
	ksz_write32(dev, REG_SW_VLAN_ENTRY_PORTS__4, vlan_table[2]);

	ksz_write16(dev, REG_SW_VLAN_ENTRY_INDEX__2, vid & VLAN_INDEX_M);
	ksz_write8(dev, REG_SW_VLAN_CTRL, VLAN_START | VLAN_WRITE);

	/* wait to be cleared */
	ret = lan937x_wait_vlan_ctrl_ready(dev);
	if (ret)
		goto exit;

	ksz_write8(dev, REG_SW_VLAN_CTRL, 0);

	/* update vlan cache table */
	dev->vlan_cache[vid].table[0] = vlan_table[0];
	dev->vlan_cache[vid].table[1] = vlan_table[1];
	dev->vlan_cache[vid].table[2] = vlan_table[2];

exit:
	mutex_unlock(&dev->vlan_mutex);

	return ret;
}

static void lan937x_read_table(struct ksz_device *dev, u32 *table)
{
	/* read alu table */
	ksz_read32(dev, REG_SW_ALU_VAL_A, &table[0]);
	ksz_read32(dev, REG_SW_ALU_VAL_B, &table[1]);
	ksz_read32(dev, REG_SW_ALU_VAL_C, &table[2]);
	ksz_read32(dev, REG_SW_ALU_VAL_D, &table[3]);
}

static void lan937x_write_table(struct ksz_device *dev, u32 *table)
{
	/* write alu table */
	ksz_write32(dev, REG_SW_ALU_VAL_A, table[0]);
	ksz_write32(dev, REG_SW_ALU_VAL_B, table[1]);
	ksz_write32(dev, REG_SW_ALU_VAL_C, table[2]);
	ksz_write32(dev, REG_SW_ALU_VAL_D, table[3]);
}

static int lan937x_wait_alu_ready(int alu, struct ksz_device *dev)
{
	unsigned int val;

	return regmap_read_poll_timeout(dev->regmap[2], REG_SW_ALU_CTRL(alu),
					val, !(val & ALU_START), 10, 1000);
}

static int lan937x_wait_alu_sta_ready(struct ksz_device *dev)
{
	unsigned int val;

	return regmap_read_poll_timeout(dev->regmap[2],
					REG_SW_ALU_STAT_CTRL__4,
					val, !(val & ALU_STAT_START),
					10, 1000);
}

static enum dsa_tag_protocol lan937x_get_tag_protocol(struct dsa_switch *ds,
						      int port,
						      enum dsa_tag_protocol mp)
{
	return DSA_TAG_PROTO_LAN937X_VALUE;
}

static int lan937x_get_link_status(struct ksz_device *dev, int port)
{
	u16 val1, val2;

	lan937x_t1_tx_phy_read(dev, port, REG_PORT_T1_PHY_M_STATUS,
			       &val1);

	lan937x_t1_tx_phy_read(dev, port, REG_PORT_T1_MODE_STAT, &val2);

	if (val1 & (PORT_T1_LOCAL_RX_OK | PORT_T1_REMOTE_RX_OK) &&
	    val2 & (T1_PORT_DSCR_LOCK_STATUS_MSK | T1_PORT_LINK_UP_MSK))
		return PHY_LINK_UP;

	return PHY_LINK_DOWN;
}

static int lan937x_phy_read16(struct dsa_switch *ds, int addr, int reg)
{
	struct ksz_device *dev = ds->priv;
	u16 val;

	lan937x_t1_tx_phy_read(dev, addr, reg, &val);

	if (reg == MII_BMSR && lan937x_is_internal_t1_phy_port(dev, addr)) {
		/* T1 PHY supports only 100 Mb FD, report through BMSR_100FULL bit*/
		val |= BMSR_100FULL;

		/* T1 Phy link is based on REG_PORT_T1_PHY_M_STATUS & REG_PORT_T1
		 * _MODE_STAT registers for LAN937x, get the link status
		 * and report through BMSR_LSTATUS bit
		 */
		if (lan937x_get_link_status(dev, addr) == PHY_LINK_UP)
			val |= BMSR_LSTATUS;
		else
			val &= ~BMSR_LSTATUS;
	}

	return val;
}

static int lan937x_phy_write16(struct dsa_switch *ds, int addr, int reg,
			       u16 val)
{
	struct ksz_device *dev = ds->priv;

	return lan937x_t1_tx_phy_write(dev, addr, reg, val);
}

static void lan937x_get_strings(struct dsa_switch *ds, int port,
				u32 stringset, uint8_t *buf)
{
	struct ksz_device *dev = ds->priv;
	int i;

	if (stringset != ETH_SS_STATS)
		return;

	for (i = 0; i < dev->mib_cnt; i++) {
		memcpy(buf + i * ETH_GSTRING_LEN, lan937x_mib_names[i].string,
		       ETH_GSTRING_LEN);
	}
}

static void lan937x_port_stp_state_set(struct dsa_switch *ds, int port,
				       u8 state)
{
	struct ksz_device *dev = ds->priv;
	struct ksz_port *p = &dev->ports[port];
	int forward = dev->member;
	int member = -1;
	u8 data;

	lan937x_pread8(dev, port, P_STP_CTRL, &data);
	data &= ~(PORT_TX_ENABLE | PORT_RX_ENABLE | PORT_LEARN_DISABLE);

	switch (state) {
	case BR_STATE_DISABLED:
		data |= PORT_LEARN_DISABLE;
		if (port != dev->cpu_port)
			member = 0;
		break;
	case BR_STATE_LISTENING:
		data |= (PORT_RX_ENABLE | PORT_LEARN_DISABLE);
		if (port != dev->cpu_port &&
		    p->stp_state == BR_STATE_DISABLED)
			member = dev->host_mask | p->vid_member;
		break;
	case BR_STATE_LEARNING:
		data |= PORT_RX_ENABLE;
		break;
	case BR_STATE_FORWARDING:
		data |= (PORT_TX_ENABLE | PORT_RX_ENABLE);

		/* This function is also used internally. */
		if (port == dev->cpu_port)
			break;

		member = dev->host_mask | p->vid_member;
		mutex_lock(&dev->dev_mutex);

		/* Port is a member of a bridge. */
		if (dev->br_member & (1 << port)) {
			dev->member |= (1 << port);
			member = dev->member;
		}
		mutex_unlock(&dev->dev_mutex);
		break;
	case BR_STATE_BLOCKING:
		data |= PORT_LEARN_DISABLE;
		if (port != dev->cpu_port &&
		    p->stp_state == BR_STATE_DISABLED)
			member = dev->host_mask | p->vid_member;
		break;
	default:
		dev_err(ds->dev, "invalid STP state: %d\n", state);
		return;
	}

	lan937x_pwrite8(dev, port, P_STP_CTRL, data);

	p->stp_state = state;
	mutex_lock(&dev->dev_mutex);

	/* Port membership may share register with STP state. */
	if (member >= 0 && member != p->member)
		lan937x_cfg_port_member(dev, port, (u8)member);

	/* Check if forwarding needs to be updated. */
	if (state != BR_STATE_FORWARDING) {
		if (dev->br_member & (1 << port))
			dev->member &= ~(1 << port);
	}

	/* When topology has changed the function ksz_update_port_member
	 * should be called to modify port forwarding behavior.
	 */
	if (forward != dev->member)
		ksz_update_port_member(dev, port);
	mutex_unlock(&dev->dev_mutex);
}

static int lan937x_port_vlan_filtering(struct dsa_switch *ds, int port,
				       bool flag)
{
	struct ksz_device *dev = ds->priv;

	if (flag) {
		lan937x_port_cfg(dev, port, REG_PORT_LUE_CTRL,
				 PORT_VLAN_LOOKUP_VID_0, true);
		lan937x_cfg(dev, REG_SW_LUE_CTRL_0, SW_VLAN_ENABLE, true);
	} else {
		lan937x_cfg(dev, REG_SW_LUE_CTRL_0, SW_VLAN_ENABLE, false);
		lan937x_port_cfg(dev, port, REG_PORT_LUE_CTRL,
				 PORT_VLAN_LOOKUP_VID_0, false);
	}

	return 0;
}

static int lan937x_port_vlan_add(struct dsa_switch *ds, int port,
				  const struct switchdev_obj_port_vlan *vlan)
{
	bool untagged = vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED;
	struct ksz_device *dev = ds->priv;
	u32 vlan_table[3];
	int err;

	err = lan937x_get_vlan_table(dev, vlan->vid, vlan_table);
	if (err) {
		dev_err(dev->dev, "Failed to get vlan table\n");
		return err;
	}

	vlan_table[0] = VLAN_VALID | (vlan->vid & VLAN_FID_M);

	/* set/clear switch port when updating vlan table
	* registers
	*/
	if (untagged)
		vlan_table[1] |= BIT(port);
	else
		vlan_table[1] &= ~BIT(port);
	vlan_table[1] &= ~(BIT(dev->cpu_port));

	vlan_table[2] |= BIT(port) |
					BIT(dev->cpu_port);

	err = lan937x_set_vlan_table(dev, vlan->vid, vlan_table);
	if (err) {
		dev_err(dev->dev, "Failed to set vlan table\n");
		return err;
	}

	/* change PVID */
	if (vlan->flags & BRIDGE_VLAN_INFO_PVID)
		lan937x_pwrite16(dev, port, REG_PORT_DEFAULT_VID, vlan->vid);
	
	return 0;
}

static int lan937x_port_vlan_del(struct dsa_switch *ds, int port,
				 const struct switchdev_obj_port_vlan *vlan)
{
	bool untagged = vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED;
	struct ksz_device *dev = ds->priv;
	u32 vlan_table[3];
	u16 pvid;

	lan937x_pread16(dev, port, REG_PORT_DEFAULT_VID, &pvid);
	pvid = pvid & 0xFFF;

	if (lan937x_get_vlan_table(dev, vlan->vid, vlan_table)) {
		dev_err(dev->dev, "Failed to get vlan table\n");
		return -ETIMEDOUT;
	}
	/* clear switch port number */
	vlan_table[2] &= ~BIT(port);

	if (pvid == vlan->vid)
		pvid = 1;

	if (untagged)
		vlan_table[1] &= ~BIT(port);

	if (lan937x_set_vlan_table(dev, vlan->vid, vlan_table)) {
		dev_err(dev->dev, "Failed to set vlan table\n");
		return -ETIMEDOUT;
	}

	lan937x_pwrite16(dev, port, REG_PORT_DEFAULT_VID, pvid);

	return 0;
}

static u8 lan937x_get_fid(u16 vid)
{
	if (vid > ALU_FID_SIZE)
		return LAN937X_GET_FID(vid);
	else
		return vid;
}

static int lan937x_port_fdb_add(struct dsa_switch *ds, int port,
				const unsigned char *addr, u16 vid)
{
	struct ksz_device *dev = ds->priv;
	u8 fid = lan937x_get_fid(vid);
	u32 alu_table[4];
	int ret, i;
	u32 data;
	u8 val;

	mutex_lock(&dev->alu_mutex);

	for (i = 0; i < ALU_STA_DYN_CNT; i++) {
		/* find any entry with mac & fid */
		data = fid << ALU_FID_INDEX_S;
		data |= ((addr[0] << 8) | addr[1]);
		ksz_write32(dev, REG_SW_ALU_INDEX_0, data);

		data = ((addr[2] << 24) | (addr[3] << 16));
		data |= ((addr[4] << 8) | addr[5]);
		ksz_write32(dev, REG_SW_ALU_INDEX_1, data);

		/* start read operation */
		ksz_write32(dev, REG_SW_ALU_CTRL(i), ALU_READ | ALU_START);

		/* wait to be finished */
		ret = lan937x_wait_alu_ready(i, dev);
		if (ret) {
			dev_err(dev->dev, "Failed to read ALU\n");
			goto exit;
		}

		/* read ALU entry */
		lan937x_read_table(dev, alu_table);

		/* update ALU entry */
		alu_table[0] = ALU_V_STATIC_VALID;

		/* update port number */
		alu_table[1] |= BIT(port);

		if (fid)
			alu_table[1] |= ALU_V_USE_FID;
		alu_table[2] = (fid << ALU_V_FID_S);
		alu_table[2] |= ((addr[0] << 8) | addr[1]);
		alu_table[3] = ((addr[2] << 24) | (addr[3] << 16));
		alu_table[3] |= ((addr[4] << 8) | addr[5]);

		lan937x_write_table(dev, alu_table);

		ksz_write32(dev, REG_SW_ALU_CTRL(i), ALU_WRITE | ALU_START);

		/* wait to be finished */
		ret = lan937x_wait_alu_ready(i, dev);

		if (ret)
			dev_err(dev->dev, "Failed to write ALU\n");

		ksz_read8(dev, REG_SW_LUE_INT_STATUS__1, &val);

		/* ALU write failed */
		if (val & WRITE_FAIL_INT && i == 1)
			dev_err(dev->dev, "Failed to write ALU\n");

		/* ALU1 write failed and attempt to write ALU2, otherwise exit*/
		if (val & WRITE_FAIL_INT)
			val = WRITE_FAIL_INT;
		else
			goto exit;
	}

exit:
	mutex_unlock(&dev->alu_mutex);

	return ret;
}

static int lan937x_port_fdb_del(struct dsa_switch *ds, int port,
				const unsigned char *addr, u16 vid)
{
	struct ksz_device *dev = ds->priv;
	u8 fid = lan937x_get_fid(vid);
	u32 alu_table[4];
	int ret, i;
	u32 data;

	mutex_lock(&dev->alu_mutex);

	for (i = 0; i < ALU_STA_DYN_CNT; i++) {
		/* read any entry with mac & fid */
		data = fid << ALU_FID_INDEX_S;
		data |= ((addr[0] << 8) | addr[1]);
		ksz_write32(dev, REG_SW_ALU_INDEX_0, data);

		data = ((addr[2] << 24) | (addr[3] << 16));
		data |= ((addr[4] << 8) | addr[5]);
		ksz_write32(dev, REG_SW_ALU_INDEX_1, data);

		/* start read operation */
		ksz_write32(dev, REG_SW_ALU_CTRL(i), ALU_READ | ALU_START);

		/* wait to be finished */
		ret = lan937x_wait_alu_ready(i, dev);
		if (ret) {
			dev_err(dev->dev, "Failed to read ALU\n");
			goto exit;
		}

		ksz_read32(dev, REG_SW_ALU_VAL_A, &alu_table[0]);
		if (alu_table[0] & ALU_V_STATIC_VALID) {
			ksz_read32(dev, REG_SW_ALU_VAL_B, &alu_table[1]);
			ksz_read32(dev, REG_SW_ALU_VAL_C, &alu_table[2]);
			ksz_read32(dev, REG_SW_ALU_VAL_D, &alu_table[3]);

			/* clear forwarding port */
			alu_table[1] &= ~BIT(port);

			/* if there is no port to forward, clear table */
			if ((alu_table[1] & ALU_V_PORT_MAP) == 0) {
				alu_table[0] = 0;
				alu_table[1] = 0;
				alu_table[2] = 0;
				alu_table[3] = 0;
			}
		} else {
			alu_table[0] = 0;
			alu_table[1] = 0;
			alu_table[2] = 0;
			alu_table[3] = 0;
		}

		lan937x_write_table(dev, alu_table);

		ksz_write32(dev, REG_SW_ALU_CTRL(i), ALU_WRITE | ALU_START);

		/* wait to be finished */
		ret = lan937x_wait_alu_ready(i, dev);
		if (ret)
			dev_err(dev->dev, "Failed to write ALU\n");
	}

exit:
	mutex_unlock(&dev->alu_mutex);

	return ret;
}

static void lan937x_convert_alu(struct lan_alu_struct *alu, u32 *alu_table)
{
	alu->is_static = !!(alu_table[0] & ALU_V_STATIC_VALID);
	alu->is_src_filter = !!(alu_table[0] & ALU_V_SRC_FILTER);
	alu->is_dst_filter = !!(alu_table[0] & ALU_V_DST_FILTER);
	alu->prio_age = (alu_table[0] >> ALU_V_PRIO_AGE_CNT_S) &
			ALU_V_PRIO_AGE_CNT_M;
	alu->mstp = alu_table[0] & ALU_V_MSTP_M;

	alu->is_override = !!(alu_table[1] & ALU_V_OVERRIDE);
	alu->is_use_fid = !!(alu_table[1] & ALU_V_USE_FID);
	alu->port_forward = alu_table[1] & ALU_V_PORT_MAP;

	alu->fid = (alu_table[2] >> ALU_V_FID_S) & ALU_V_FID_M;

	alu->mac[0] = (alu_table[2] >> 8) & 0xFF;
	alu->mac[1] = alu_table[2] & 0xFF;
	alu->mac[2] = (alu_table[3] >> 24) & 0xFF;
	alu->mac[3] = (alu_table[3] >> 16) & 0xFF;
	alu->mac[4] = (alu_table[3] >> 8) & 0xFF;
	alu->mac[5] = alu_table[3] & 0xFF;
}

static int lan937x_port_fdb_dump(struct dsa_switch *ds, int port,
				 dsa_fdb_dump_cb_t *cb, void *data)
{
	struct ksz_device *dev = ds->priv;
	struct lan_alu_struct alu;
	u32 lan937x_data;
	u32 alu_table[4];
	int ret, i;
	int timeout;

	mutex_lock(&dev->alu_mutex);

	for (i = 0; i < ALU_STA_DYN_CNT; i++) {
		/* start ALU search */
		ksz_write32(dev, REG_SW_ALU_CTRL(i), ALU_START | ALU_SEARCH);

		do {
			timeout = 1000;
			do {
				ksz_read32(dev, REG_SW_ALU_CTRL(i), &lan937x_data);
				if ((lan937x_data & ALU_VALID) || !(lan937x_data & ALU_START))
					break;
				usleep_range(1, 10);
			} while (timeout-- > 0);

			if (!timeout) {
				dev_err(dev->dev, "Failed to search ALU\n");
				ret = -ETIMEDOUT;
				goto exit;
			}

			/* read ALU table */
			lan937x_read_table(dev, alu_table);

			lan937x_convert_alu(&alu, alu_table);

			if (alu.port_forward & BIT(port)) {
				ret = cb(alu.mac, alu.fid, alu.is_static, data);
				if (ret)
					goto exit;
			}
		} while (lan937x_data & ALU_START);

exit:
			/* stop ALU search & continue to next ALU if available */
			ksz_write32(dev, REG_SW_ALU_CTRL(i), 0);
	}

	mutex_unlock(&dev->alu_mutex);

	return ret;
}

static int lan937x_port_mdb_add(struct dsa_switch *ds, int port,
				 const struct switchdev_obj_port_mdb *mdb)
{
	struct ksz_device *dev = ds->priv;
	u8 fid = lan937x_get_fid(mdb->vid);
	u32 static_table[4];
	u32 mac_hi, mac_lo;
	int err = 0;
	int index;
	u32 data;

	mac_hi = ((mdb->addr[0] << 8) | mdb->addr[1]);
	mac_lo = ((mdb->addr[2] << 24) | (mdb->addr[3] << 16));
	mac_lo |= ((mdb->addr[4] << 8) | mdb->addr[5]);

	mutex_lock(&dev->alu_mutex);

	for (index = 0; index < dev->num_statics; index++) {
		/* find empty slot first */
		data = (index << ALU_STAT_INDEX_S) |
			ALU_STAT_READ | ALU_STAT_START;
		ksz_write32(dev, REG_SW_ALU_STAT_CTRL__4, data);

		/* wait to be finished */
		err = lan937x_wait_alu_sta_ready(dev);
		if (err) {
			dev_err(dev->dev, "Failed to read ALU STATIC\n");
			goto exit;
		}

		/* read ALU static table */
		lan937x_read_table(dev, static_table);

		if (static_table[0] & ALU_V_STATIC_VALID) {
			/* check this has same fid & mac address */
			if (((static_table[2] >> ALU_V_FID_S) == fid) &&
			    ((static_table[2] & ALU_V_MAC_ADDR_HI) == mac_hi) &&
			    static_table[3] == mac_lo) {
				/* found matching one */
				break;
			}
		} else {
			/* found empty one */
			break;
		}
	}

	/* no available entry */
	if (index == dev->num_statics) {
		err = -ENOSPC;
		goto exit;
	}

	/* add entry */
	static_table[0] = ALU_V_STATIC_VALID;

	static_table[1] |= BIT(port);
	if (fid)
		static_table[1] |= ALU_V_USE_FID;
	static_table[2] = (fid << ALU_V_FID_S);
	static_table[2] |= mac_hi;
	static_table[3] = mac_lo;

	lan937x_write_table(dev, static_table);

	data = (index << ALU_STAT_INDEX_S) | ALU_STAT_START;
	ksz_write32(dev, REG_SW_ALU_STAT_CTRL__4, data);

	/* wait to be finished */
	if (lan937x_wait_alu_sta_ready(dev))
		dev_err(dev->dev, "Failed to read ALU STATIC\n");

exit:
	mutex_unlock(&dev->alu_mutex);
	return err;
}

static int lan937x_port_mdb_del(struct dsa_switch *ds, int port,
				const struct switchdev_obj_port_mdb *mdb)
{
	struct ksz_device *dev = ds->priv;
	u8 fid = lan937x_get_fid(mdb->vid);
	u32 static_table[4];
	u32 mac_hi, mac_lo;
	int index, ret;
	u32 data;

	mac_hi = ((mdb->addr[0] << 8) | mdb->addr[1]);
	mac_lo = ((mdb->addr[2] << 24) | (mdb->addr[3] << 16));
	mac_lo |= ((mdb->addr[4] << 8) | mdb->addr[5]);

	mutex_lock(&dev->alu_mutex);

	for (index = 0; index < dev->num_statics; index++) {
		/* find empty slot first */
		data = (index << ALU_STAT_INDEX_S) |
			ALU_STAT_READ | ALU_STAT_START;
		ksz_write32(dev, REG_SW_ALU_STAT_CTRL__4, data);

		/* wait to be finished */
		ret = lan937x_wait_alu_sta_ready(dev);
		if (ret) {
			dev_err(dev->dev, "Failed to read ALU STATIC\n");
			goto exit;
		}

		/* read ALU static table */
		lan937x_read_table(dev, static_table);

		if (static_table[0] & ALU_V_STATIC_VALID) {
			/* check this has same fid & mac address */

			if (((static_table[2] >> ALU_V_FID_S) == fid) &&
			    ((static_table[2] & ALU_V_MAC_ADDR_HI) == mac_hi) &&
			    static_table[3] == mac_lo) {
				/* found matching one */
				break;
			}
		}
	}

	/* no available entry */
	if (index == dev->num_statics)
		goto exit;

	/* clear port based on port arg */
	static_table[1] &= ~BIT(port);

	if ((static_table[1] & ALU_V_PORT_MAP) == 0) {
		/* delete entry */
		static_table[0] = 0;
		static_table[1] = 0;
		static_table[2] = 0;
		static_table[3] = 0;
	}

	lan937x_write_table(dev, static_table);

	data = (index << ALU_STAT_INDEX_S) | ALU_STAT_START;
	ksz_write32(dev, REG_SW_ALU_STAT_CTRL__4, data);

	/* wait to be finished */
	ret = lan937x_wait_alu_sta_ready(dev);
	if (ret)
		dev_err(dev->dev, "Failed to read ALU STATIC\n");

exit:
	mutex_unlock(&dev->alu_mutex);

	return ret;
}

static int lan937x_port_mirror_add(struct dsa_switch *ds, int port,
				   struct dsa_mall_mirror_tc_entry *mirror,
				   bool ingress)
{
	struct ksz_device *dev = ds->priv;

	if (ingress)
		lan937x_port_cfg(dev, port, P_MIRROR_CTRL, PORT_MIRROR_RX, true);
	else
		lan937x_port_cfg(dev, port, P_MIRROR_CTRL, PORT_MIRROR_TX, true);

	lan937x_port_cfg(dev, port, P_MIRROR_CTRL, PORT_MIRROR_SNIFFER, false);

	/* configure mirror port */
	lan937x_port_cfg(dev, mirror->to_local_port, P_MIRROR_CTRL,
			 PORT_MIRROR_SNIFFER, true);

	lan937x_cfg(dev, S_MIRROR_CTRL, SW_MIRROR_RX_TX, false);

	return 0;
}

static void lan937x_port_mirror_del(struct dsa_switch *ds, int port,
				    struct dsa_mall_mirror_tc_entry *mirror)
{
	struct ksz_device *dev = ds->priv;
	u8 data;

	if (mirror->ingress)
		lan937x_port_cfg(dev, port, P_MIRROR_CTRL, PORT_MIRROR_RX, false);
	else
		lan937x_port_cfg(dev, port, P_MIRROR_CTRL, PORT_MIRROR_TX, false);

	lan937x_pread8(dev, port, P_MIRROR_CTRL, &data);

	if (!(data & (PORT_MIRROR_RX | PORT_MIRROR_TX)))
		lan937x_port_cfg(dev, mirror->to_local_port, P_MIRROR_CTRL,
				 PORT_MIRROR_SNIFFER, false);
}

static phy_interface_t lan937x_get_interface(struct ksz_device *dev, int port)
{
	phy_interface_t interface;
	bool gbit;
	u8 data8;

	if (lan937x_is_internal_phy_port(dev, port))
		return PHY_INTERFACE_MODE_NA;

	/* read interface from REG_PORT_XMII_CTRL_1 register */
	lan937x_pread8(dev, port, REG_PORT_XMII_CTRL_1, &data8);

	/* get interface speed */
	gbit = !(data8 & PORT_MII_NOT_1GBIT);

	switch (data8 & PORT_MII_SEL_M) {
	case PORT_RMII_SEL:
		interface = PHY_INTERFACE_MODE_RMII;
		break;
	case PORT_RGMII_SEL:
		interface = PHY_INTERFACE_MODE_RGMII;
		if (data8 & PORT_RGMII_ID_EG_ENABLE)
			interface = PHY_INTERFACE_MODE_RGMII_TXID;
		if (data8 & PORT_RGMII_ID_IG_ENABLE) {
			interface = PHY_INTERFACE_MODE_RGMII_RXID;
			if (data8 & PORT_RGMII_ID_EG_ENABLE)
				interface = PHY_INTERFACE_MODE_RGMII_ID;
		}
		break;
	case PORT_MII_SEL:
	default:
		/* Interface is MII */
		interface = PHY_INTERFACE_MODE_MII;
		break;
	}
	return interface;
}

static void lan937x_config_cpu_port(struct dsa_switch *ds)
{
	struct ksz_device *dev = ds->priv;
	struct ksz_port *p;
	int i;

	ds->num_ports = dev->port_cnt;

	for (i = 0; i < dev->port_cnt; i++) {
		if (dsa_is_cpu_port(ds, i) && (dev->cpu_ports & (1 << i))) {
			phy_interface_t interface;
			const char *prev_msg;
			const char *prev_mode;

			dev->cpu_port = i;
			dev->host_mask = (1 << dev->cpu_port);
			dev->port_mask |= dev->host_mask;
			p = &dev->ports[i];

			/* Read from XMII register to determine host port
			 * interface.  If set specifically in device tree
			 * note the difference to help debugging.
			 */
			interface = lan937x_get_interface(dev, i);
			if (!p->interface) {
				if (dev->compat_interface) {
					dev_warn(dev->dev,
						 "Using legacy switch \"phy-mode\" property, because it is missing on port %d node. Please update your device tree.\n",
						 i);
					p->interface = dev->compat_interface;
				} else {
					p->interface = interface;
				}
			}
			if (interface && interface != p->interface) {
				prev_msg = " instead of ";
				prev_mode = phy_modes(interface);
			} else {
				prev_msg = "";
				prev_mode = "";
			}
			dev_info(dev->dev,
				 "Port%d: using phy mode %s%s%s\n",
				 i,
				 phy_modes(p->interface),
				 prev_msg,
				 prev_mode);

			/* enable cpu port */
			lan937x_port_setup(dev, i, true);
			p->vid_member = dev->port_mask;
		}
	}

	dev->member = dev->host_mask;

	for (i = 0; i < dev->port_cnt; i++) {
		if (i == dev->cpu_port)
			continue;
		p = &dev->ports[i];

		/* Initialize to non-zero so that lan937x_cfg_port_member() will
		 * be called.
		 */
		p->vid_member = (1 << i);
		p->member = dev->port_mask;
		lan937x_port_stp_state_set(ds, i, BR_STATE_DISABLED);
	}
}

static int lan937x_setup(struct dsa_switch *ds)
{
	struct ksz_device *dev = ds->priv;
	int ret = 0;

	dev->vlan_cache = devm_kcalloc(dev->dev, sizeof(struct vlan_table),
				       dev->num_vlans, GFP_KERNEL);
	if (!dev->vlan_cache)
		return -ENOMEM;

	/* Required for port partitioning. */
	lan937x_cfg32(dev, REG_SW_QM_CTRL__4, UNICAST_VLAN_BOUNDARY,
		      true);

	lan937x_config_cpu_port(ds);

	ds->configure_vlan_while_not_filtering = true;

	/* Enable aggressive back off & UNH */
	lan937x_cfg(dev, REG_SW_MAC_CTRL_0, SW_PAUSE_UNH_MODE | SW_NEW_BACKOFF |
						SW_AGGR_BACKOFF, true);

	lan937x_cfg(dev, REG_SW_MAC_CTRL_1, (MULTICAST_STORM_DISABLE
							| NO_EXC_COLLISION_DROP), true);

	/* queue based egress rate limit */
	lan937x_cfg(dev, REG_SW_MAC_CTRL_5, SW_OUT_RATE_LIMIT_QUEUE_BASED, true);

	lan937x_cfg(dev, REG_SW_LUE_CTRL_0, SW_RESV_MCAST_ENABLE, true);

	/* enable global MIB counter freeze function */
	lan937x_cfg(dev, REG_SW_MAC_CTRL_6, SW_MIB_COUNTER_FREEZE, true);

	ret = lan937x_ptp_init(ds);
	if (ret < 0) {
		dev_err(ds->dev, "Failed to register PTP clock: %d\n", ret);
		return ret;
	}

	ret = lan937x_ptp_init(dev);
        if(ret)
                goto error_ptp_deinit;

	/* start switch */
	lan937x_cfg(dev, REG_SW_OPERATION, SW_START, true);

	ksz_init_mib_timer(dev);

	return 0;

error_ptp_deinit:
        lan937x_ptp_deinit(dev);
        return ret;
}

static int lan937x_change_mtu(struct dsa_switch *ds, int port, int mtu)
{
	struct ksz_device *dev = ds->priv;
	u16 max_size;

	if (mtu >= FR_MIN_SIZE) {
		lan937x_port_cfg(dev, port, REG_PORT_MAC_CTRL_0, PORT_JUMBO_EN, true);
		max_size = FR_MAX_SIZE;
	} else {
		lan937x_port_cfg(dev, port, REG_PORT_MAC_CTRL_0, PORT_JUMBO_EN, false);
		max_size = FR_MIN_SIZE;
	}
	/* Write the frame size in PORT_MAX_FR_SIZE register */
	lan937x_pwrite16(dev, port, PORT_MAX_FR_SIZE, max_size);
	return 0;
}

static int lan937x_get_max_mtu(struct dsa_switch *ds, int port)
{
	/* Frame size is 9000 (= 0x2328) if
	 * jumbo frame support is enabled, PORT_JUMBO_EN bit will be enabled
	 * based on mtu in lan937x_change_mtu() API
	 */
	return FR_MAX_SIZE;
}

static void lan937x_phylink_validate(struct dsa_switch *ds, int port,
				     unsigned long *supported,
			  struct phylink_link_state *state)
{
	struct ksz_device *dev = ds->priv;
	__ETHTOOL_DECLARE_LINK_MODE_MASK(mask) = { 0, };

	if (phy_interface_mode_is_rgmii(state->interface) ||
	    state->interface == PHY_INTERFACE_MODE_SGMII ||
		state->interface == PHY_INTERFACE_MODE_RMII ||
		state->interface == PHY_INTERFACE_MODE_MII ||
		lan937x_is_internal_tx_phy_port(dev, port)) {
		phylink_set(mask, 10baseT_Half);
		phylink_set(mask, 10baseT_Full);
		phylink_set(mask, 100baseT_Half);
		phylink_set(mask, 100baseT_Full);
		phylink_set(mask, Autoneg);
		phylink_set_port_modes(mask);
		phylink_set(mask, Pause);
		phylink_set(mask, Asym_Pause);
	}
	/*  For RGMII & SGMII interfaces */
	if (phy_interface_mode_is_rgmii(state->interface) ||
	    state->interface == PHY_INTERFACE_MODE_SGMII) {
		phylink_set(mask, 1000baseT_Full);
	}
	/* For T1 PHY */
	if (lan937x_is_internal_t1_phy_port(dev, port)) {
		phylink_set(mask, 100baseT_Full);
		phylink_set_port_modes(mask);
	}

	bitmap_and(supported, supported, mask,
		   __ETHTOOL_LINK_MODE_MASK_NBITS);
	bitmap_and(state->advertising, state->advertising, mask,
		   __ETHTOOL_LINK_MODE_MASK_NBITS);
}

const struct dsa_switch_ops lan937x_switch_ops = {
	.get_tag_protocol	= lan937x_get_tag_protocol,
	.setup			= lan937x_setup,
	.phy_read		= lan937x_phy_read16,
	.phy_write		= lan937x_phy_write16,
	.port_enable		= ksz_enable_port,
	.get_strings		= lan937x_get_strings,
	.get_ethtool_stats	= ksz_get_ethtool_stats,
	.get_sset_count		= ksz_sset_count,
	.port_bridge_join	= ksz_port_bridge_join,
	.port_bridge_leave	= ksz_port_bridge_leave,
	.port_stp_state_set	= lan937x_port_stp_state_set,
	.port_fast_age		= ksz_port_fast_age,
	.port_vlan_filtering	= lan937x_port_vlan_filtering,
	.port_vlan_add		= lan937x_port_vlan_add,
	.port_vlan_del		= lan937x_port_vlan_del,
	.port_fdb_dump		= lan937x_port_fdb_dump,
	.port_fdb_add		= lan937x_port_fdb_add,
	.port_fdb_del		= lan937x_port_fdb_del,
	.port_mdb_add           = lan937x_port_mdb_add,
	.port_mdb_del           = lan937x_port_mdb_del,
	.port_mirror_add	= lan937x_port_mirror_add,
	.port_mirror_del	= lan937x_port_mirror_del,
	.port_max_mtu		= lan937x_get_max_mtu,
	.port_change_mtu	= lan937x_change_mtu,
	.phylink_validate	= lan937x_phylink_validate,
	.phylink_mac_link_down	= ksz_mac_link_down,
	.port_hwtstamp_get      = lan937x_hwtstamp_get,
	.port_hwtstamp_set      = lan937x_hwtstamp_set,
        /* never defer rx delivery, tstamping is done via tail tagging */
	.port_rxtstamp		= NULL, 
	.port_txtstamp		= lan937x_port_txtstamp,
	.get_ts_info            = lan937x_get_ts_info
};


int lan937x_switch_register(struct ksz_device *dev)
{
	return ksz_switch_register(dev, &lan937x_dev_ops);
}
EXPORT_SYMBOL(lan937x_switch_register);

MODULE_AUTHOR("Prasanna Vengateshan Varadharajan " \
			  "Prasanna.Vengateshan@microchip.com>");
MODULE_DESCRIPTION("Microchip LAN937x Series Switch DSA Driver");
MODULE_LICENSE("GPL");
