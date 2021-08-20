// SPDX-License-Identifier: GPL-2.0
/* Microchip LAN937X switch driver main logic
 * Copyright (C) 2019-2021 Microchip Technology Inc.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/iopoll.h>
#include <linux/phy.h>
#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
#include <net/dsa.h>
#include <net/switchdev.h>

#include "lan937x_reg.h"
#include "ksz_common.h"
#include "lan937x_dev.h"

static int lan937x_wait_vlan_ctrl_ready(struct ksz_device *dev)
{
	unsigned int val;

	return regmap_read_poll_timeout(dev->regmap[0], REG_SW_VLAN_CTRL, val,
					!(val & VLAN_START), 10, 1000);
}

static u8 lan937x_get_fid(u16 vid)
{
	if (vid > ALU_FID_SIZE)
		return LAN937X_GET_FID(vid);
	else
		return vid;
}

static int lan937x_get_vlan_table(struct ksz_device *dev, u16 vid,
				  struct lan937x_vlan *vlan_entry)
{
	u32 data;
	int ret;

	mutex_lock(&dev->vlan_mutex);

	ret = ksz_write16(dev, REG_SW_VLAN_ENTRY_INDEX__2, vid & VLAN_INDEX_M);
	if (ret < 0)
		goto exit;

	ret = ksz_write8(dev, REG_SW_VLAN_CTRL, VLAN_READ | VLAN_START);
	if (ret < 0)
		goto exit;

	/* wait to be cleared */
	ret = lan937x_wait_vlan_ctrl_ready(dev);
	if (ret < 0)
		goto exit;

	ret = ksz_read32(dev, REG_SW_VLAN_ENTRY__4, &data);
	if (ret < 0)
		goto exit;

	vlan_entry->valid = !!(data & VLAN_VALID);
	vlan_entry->fid	= data & VLAN_FID_M;

	ret = ksz_read32(dev, REG_SW_VLAN_ENTRY_UNTAG__4,
			 &vlan_entry->untag_prtmap);
	if (ret < 0)
		goto exit;

	ret = ksz_read32(dev, REG_SW_VLAN_ENTRY_PORTS__4,
			 &vlan_entry->fwd_map);
	if (ret < 0)
		goto exit;

	ret = ksz_write8(dev, REG_SW_VLAN_CTRL, 0);
	if (ret < 0)
		goto exit;

exit:
	mutex_unlock(&dev->vlan_mutex);

	return ret;
}

static int lan937x_set_vlan_table(struct ksz_device *dev, u16 vid,
				  struct lan937x_vlan *vlan_entry)
{
	u32 data;
	int ret;

	mutex_lock(&dev->vlan_mutex);

	data = vlan_entry->valid ? VLAN_VALID : 0;
	data |= vlan_entry->fid;

	ret = ksz_write32(dev, REG_SW_VLAN_ENTRY__4, data);
	if (ret < 0)
		goto exit;

	ret = ksz_write32(dev, REG_SW_VLAN_ENTRY_UNTAG__4,
			  vlan_entry->untag_prtmap);
	if (ret < 0)
		goto exit;

	ret = ksz_write32(dev, REG_SW_VLAN_ENTRY_PORTS__4, vlan_entry->fwd_map);
	if (ret < 0)
		goto exit;

	ret = ksz_write16(dev, REG_SW_VLAN_ENTRY_INDEX__2, vid & VLAN_INDEX_M);
	if (ret < 0)
		goto exit;

	ret = ksz_write8(dev, REG_SW_VLAN_CTRL, VLAN_START | VLAN_WRITE);
	if (ret < 0)
		goto exit;

	/* wait to be cleared */
	ret = lan937x_wait_vlan_ctrl_ready(dev);
	if (ret < 0)
		goto exit;

exit:
	mutex_unlock(&dev->vlan_mutex);

	return ret;
}

static int lan937x_read_table(struct ksz_device *dev, u32 *table)
{
	int ret;

	/* read alu table */
	ret = ksz_read32(dev, REG_SW_ALU_VAL_A, &table[0]);
	if (ret < 0)
		return ret;

	ret = ksz_read32(dev, REG_SW_ALU_VAL_B, &table[1]);
	if (ret < 0)
		return ret;

	ret = ksz_read32(dev, REG_SW_ALU_VAL_C, &table[2]);
	if (ret < 0)
		return ret;

	ret = ksz_read32(dev, REG_SW_ALU_VAL_D, &table[3]);

	return ret;
}

static int lan937x_write_table(struct ksz_device *dev, u32 *table)
{
	int ret;

	/* write alu table */
	ret = ksz_write32(dev, REG_SW_ALU_VAL_A, table[0]);
	if (ret < 0)
		return ret;

	ret = ksz_write32(dev, REG_SW_ALU_VAL_B, table[1]);
	if (ret < 0)
		return ret;

	ret = ksz_write32(dev, REG_SW_ALU_VAL_C, table[2]);
	if (ret < 0)
		return ret;

	ret = ksz_write32(dev, REG_SW_ALU_VAL_D, table[3]);

	return ret;
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

	return regmap_read_poll_timeout(dev->regmap[2], REG_SW_ALU_STAT_CTRL__4,
					val, !(val & ALU_STAT_START), 10, 1000);
}

static enum dsa_tag_protocol lan937x_get_tag_protocol(struct dsa_switch *ds,
						      int port,
						      enum dsa_tag_protocol mp)
{
	return DSA_TAG_PROTO_LAN937X_VALUE;
}

static int lan937x_phy_read16(struct dsa_switch *ds, int addr, int reg)
{
	struct ksz_device *dev = ds->priv;
	u16 val;
	int ret;

	ret = lan937x_internal_phy_read(dev, addr, reg, &val);
	if (ret < 0)
		return ret;

	return val;
}

static int lan937x_phy_write16(struct dsa_switch *ds, int addr, int reg,
			       u16 val)
{
	struct ksz_device *dev = ds->priv;

	return lan937x_internal_phy_write(dev, addr, reg, val);
}

static void lan937x_get_strings(struct dsa_switch *ds, int port, u32 stringset,
				uint8_t *buf)
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
		break;
	case BR_STATE_LISTENING:
		data |= (PORT_RX_ENABLE | PORT_LEARN_DISABLE);
		if (p->stp_state == BR_STATE_DISABLED)
			member = dev->host_mask | p->vid_member;
		break;
	case BR_STATE_LEARNING:
		data |= PORT_RX_ENABLE;
		break;
	case BR_STATE_FORWARDING:
		data |= (PORT_TX_ENABLE | PORT_RX_ENABLE);
		member = dev->host_mask | p->vid_member;

		/* Port is a member of a bridge. */
		if (dev->br_member & (1 << port)) {
			dev->member |= (1 << port);
			member = dev->member;
		}
		break;
	case BR_STATE_BLOCKING:
		data |= PORT_LEARN_DISABLE;
		if (p->stp_state == BR_STATE_DISABLED)
			member = dev->host_mask | p->vid_member;
		break;
	default:
		dev_err(ds->dev, "invalid STP state: %d\n", state);
		return;
	}

	lan937x_pwrite8(dev, port, P_STP_CTRL, data);

	p->stp_state = state;

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
}

static int lan937x_port_vlan_filtering(struct dsa_switch *ds, int port,
				       bool flag,
				       struct netlink_ext_ack *extack)
{
	struct ksz_device *dev = ds->priv;
	int ret;

	ret = lan937x_cfg(dev, REG_SW_LUE_CTRL_0, SW_VLAN_ENABLE,
			  flag);

	return ret;
}

static int lan937x_port_vlan_add(struct dsa_switch *ds, int port,
				 const struct switchdev_obj_port_vlan *vlan,
				 struct netlink_ext_ack *extack)
{
	bool untagged = vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED;
	struct ksz_device *dev = ds->priv;
	struct lan937x_vlan vlan_entry;
	int ret;

	ret = lan937x_get_vlan_table(dev, vlan->vid, &vlan_entry);
	if (ret < 0) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to get vlan table\n");
		return ret;
	}

	vlan_entry.fid = lan937x_get_fid(vlan->vid);
	vlan_entry.valid = true;

	/* set/clear switch port when updating vlan table registers */
	if (untagged)
		vlan_entry.untag_prtmap |= BIT(port);
	else
		vlan_entry.untag_prtmap &= ~BIT(port);

	vlan_entry.fwd_map |= BIT(port);

	ret = lan937x_set_vlan_table(dev, vlan->vid, &vlan_entry);
	if (ret < 0) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to set vlan table\n");
		return ret;
	}

	/* change PVID */
	if (vlan->flags & BRIDGE_VLAN_INFO_PVID) {
		ret = lan937x_pwrite16(dev, port, REG_PORT_DEFAULT_VID,
				       vlan->vid);
		if (ret < 0) {
			NL_SET_ERR_MSG_MOD(extack, "Failed to set pvid\n");
			return ret;
		}
	}

	return 0;
}

static int lan937x_port_vlan_del(struct dsa_switch *ds, int port,
				 const struct switchdev_obj_port_vlan *vlan)
{
	bool untagged = vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED;
	struct ksz_device *dev = ds->priv;
	struct lan937x_vlan vlan_entry;
	u16 pvid;
	int ret;

	lan937x_pread16(dev, port, REG_PORT_DEFAULT_VID, &pvid);
	pvid &= 0xFFF;

	ret = lan937x_get_vlan_table(dev, vlan->vid, &vlan_entry);
	if (ret < 0) {
		dev_err(dev->dev, "Failed to get vlan table\n");
		return ret;
	}
	/* clear port fwd map */
	vlan_entry.fwd_map &= ~BIT(port);

	if (untagged)
		vlan_entry.untag_prtmap &= ~BIT(port);

	ret = lan937x_set_vlan_table(dev, vlan->vid, &vlan_entry);
	if (ret < 0) {
		dev_err(dev->dev, "Failed to set vlan table\n");
		return ret;
	}

	ret = lan937x_pwrite16(dev, port, REG_PORT_DEFAULT_VID, pvid);
	if (ret < 0) {
		dev_err(dev->dev, "Failed to set pvid\n");
		return ret;
	}

	return 0;
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

	/* Accessing two ALU tables through loop */
	for (i = 0; i < ALU_STA_DYN_CNT; i++) {
		/* find any entry with mac & fid */
		data = fid << ALU_FID_INDEX_S;
		data |= ((addr[0] << 8) | addr[1]);

		ret = ksz_write32(dev, REG_SW_ALU_INDEX_0, data);
		if (ret < 0)
			break;

		data = ((addr[2] << 24) | (addr[3] << 16));
		data |= ((addr[4] << 8) | addr[5]);

		ret = ksz_write32(dev, REG_SW_ALU_INDEX_1, data);
		if (ret < 0)
			break;

		/* start read operation */
		ret = ksz_write32(dev, REG_SW_ALU_CTRL(i),
				  ALU_READ | ALU_START);
		if (ret < 0)
			break;

		/* wait to be finished */
		ret = lan937x_wait_alu_ready(i, dev);
		if (ret < 0) {
			dev_err(dev->dev, "Failed to read ALU\n");
			break;
		}

		/* read ALU entry */
		ret = lan937x_read_table(dev, alu_table);
		if (ret < 0) {
			dev_err(dev->dev, "Failed to read ALU\n");
			break;
		}

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

		ret = lan937x_write_table(dev, alu_table);
		if (ret < 0)
			break;

		ret = ksz_write32(dev, REG_SW_ALU_CTRL(i),
				  (ALU_WRITE | ALU_START));
		if (ret < 0)
			break;

		/* wait to be finished */
		ret = lan937x_wait_alu_ready(i, dev);
		if (ret < 0) {
			dev_err(dev->dev, "Failed to write ALU\n");
			break;
		}

		ret = ksz_read8(dev, REG_SW_LUE_INT_STATUS__1, &val);
		if (ret < 0)
			break;

		/* ALU2 write failed */
		if (val & WRITE_FAIL_INT && i == 1)
			dev_err(dev->dev, "Failed to write ALU\n");

		/* if ALU1 write is failed and attempt to write ALU2,
		 * otherwise exit. Clear Write fail for both ALU1 & ALU2
		 */
		if (val & WRITE_FAIL_INT) {
			/* Write to clear the Write Fail */
			ret = ksz_write8(dev, REG_SW_LUE_INT_STATUS__1,
					 WRITE_FAIL_INT);
			if (ret < 0)
				break;
		} else {
			break;
		}
	}

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

	/* Accessing two ALU tables through loop */
	for (i = 0; i < ALU_STA_DYN_CNT; i++) {
		/* read any entry with mac & fid */
		data = fid << ALU_FID_INDEX_S;
		data |= ((addr[0] << 8) | addr[1]);
		ret = ksz_write32(dev, REG_SW_ALU_INDEX_0, data);
		if (ret < 0)
			break;

		data = ((addr[2] << 24) | (addr[3] << 16));
		data |= ((addr[4] << 8) | addr[5]);
		ret = ksz_write32(dev, REG_SW_ALU_INDEX_1, data);
		if (ret < 0)
			break;

		/* start read operation */
		ret = ksz_write32(dev, REG_SW_ALU_CTRL(i),
				  (ALU_READ | ALU_START));
		if (ret < 0)
			break;

		/* wait to be finished */
		ret = lan937x_wait_alu_ready(i, dev);
		if (ret < 0) {
			dev_err(dev->dev, "Failed to read ALU\n");
			break;
		}

		ret = ksz_read32(dev, REG_SW_ALU_VAL_A, &alu_table[0]);
		if (ret < 0)
			break;

		if (alu_table[0] & ALU_V_STATIC_VALID) {
			/* read ALU entry */
			ret = lan937x_read_table(dev, alu_table);
			if (ret < 0) {
				dev_err(dev->dev, "Failed to read ALU table\n");
				break;
			}

			/* clear forwarding port */
			alu_table[1] &= ~BIT(port);

			/* if there is no port to forward, clear table */
			if ((alu_table[1] & ALU_V_PORT_MAP) == 0) {
				memset(&alu_table, 0, sizeof(alu_table));
			}
		} else {
			memset(&alu_table, 0, sizeof(alu_table));
		}

		ret = lan937x_write_table(dev, alu_table);
		if (ret < 0)
			break;

		ret = ksz_write32(dev, REG_SW_ALU_CTRL(i),
				  (ALU_WRITE | ALU_START));
		if (ret < 0)
			break;

		/* wait to be finished */
		ret = lan937x_wait_alu_ready(i, dev);
		if (ret < 0) {
			dev_err(dev->dev, "Failed to delete ALU Entries\n");
			break;
		}
	}

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
	int timeout;
	int ret, i;

	mutex_lock(&dev->alu_mutex);

	/* Accessing two ALU tables through loop */
	for (i = 0; i < ALU_STA_DYN_CNT; i++) {
		/* start ALU search */
		ret = ksz_write32(dev, REG_SW_ALU_CTRL(i),
				  (ALU_START | ALU_SEARCH));
		if (ret < 0)
			goto exit;

		do {
			timeout = 1000;
			do {
				ret = ksz_read32(dev, REG_SW_ALU_CTRL(i),
						 &lan937x_data);
				if (ret < 0)
					goto exit;

				if ((lan937x_data & ALU_VALID) ||
				    !(lan937x_data & ALU_START))
					break;
				usleep_range(1, 10);
			} while (timeout-- > 0);

			if (!timeout) {
				dev_err(dev->dev, "Failed to search ALU\n");
				ret = -ETIMEDOUT;
				goto exit;
			}

			/* read ALU table */
			ret = lan937x_read_table(dev, alu_table);
			if (ret < 0)
				goto exit;

			lan937x_convert_alu(&alu, alu_table);

			if (alu.port_forward & BIT(port)) {
				ret = cb(alu.mac, alu.fid, alu.is_static, data);
				if (ret)
					goto exit;
			}
		} while (lan937x_data & ALU_START);

exit:
		/* stop ALU search & continue to next ALU if available */
		ret = ksz_write32(dev, REG_SW_ALU_CTRL(i), 0);
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
	int index, ret;
	u32 data;

	mac_hi = ((mdb->addr[0] << 8) | mdb->addr[1]);
	mac_lo = ((mdb->addr[2] << 24) | (mdb->addr[3] << 16));
	mac_lo |= ((mdb->addr[4] << 8) | mdb->addr[5]);

	mutex_lock(&dev->alu_mutex);

	/* Access the entries in the table */
	for (index = 0; index < dev->num_statics; index++) {
		/* find empty slot first */
		data = (index << ALU_STAT_INDEX_S) |
			ALU_STAT_READ | ALU_STAT_START;

		ret = ksz_write32(dev, REG_SW_ALU_STAT_CTRL__4, data);
		if (ret < 0)
			goto exit;

		/* wait to be finished */
		ret = lan937x_wait_alu_sta_ready(dev);
		if (ret < 0) {
			dev_err(dev->dev, "Failed to read ALU STATIC\n");
			goto exit;
		}

		/* read ALU static table */
		ret = lan937x_read_table(dev, static_table);
		if (ret < 0)
			goto exit;

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
		ret = -ENOSPC;
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

	ret = lan937x_write_table(dev, static_table);
	if (ret < 0)
		goto exit;

	data = (index << ALU_STAT_INDEX_S) | ALU_STAT_START;
	ret = ksz_write32(dev, REG_SW_ALU_STAT_CTRL__4, data);
	if (ret < 0)
		goto exit;

	/* wait to be finished */
	ret = lan937x_wait_alu_sta_ready(dev);
	if (ret < 0)
		dev_err(dev->dev, "Failed to read ALU STATIC\n");

exit:
	mutex_unlock(&dev->alu_mutex);
	return ret;
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

	/* Access the entries in the table */
	for (index = 0; index < dev->num_statics; index++) {
		data = (index << ALU_STAT_INDEX_S) |
			ALU_STAT_READ | ALU_STAT_START;
		ret = ksz_write32(dev, REG_SW_ALU_STAT_CTRL__4, data);
		if (ret < 0)
			goto exit;

		/* wait to be finished */
		ret = lan937x_wait_alu_sta_ready(dev);
		if (ret < 0) {
			dev_err(dev->dev, "Failed to read ALU STATIC\n");
			goto exit;
		}

		/* read ALU static table */
		ret = lan937x_read_table(dev, static_table);
		if (ret < 0)
			goto exit;

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
		memset(&static_table, 0, sizeof(static_table));
	}

	ret = lan937x_write_table(dev, static_table);
	if (ret < 0)
		goto exit;

	data = (index << ALU_STAT_INDEX_S) | ALU_STAT_START;
	ret = ksz_write32(dev, REG_SW_ALU_STAT_CTRL__4, data);
	if (ret < 0)
		goto exit;

	/* wait to be finished */
	ret = lan937x_wait_alu_sta_ready(dev);
	if (ret < 0)
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
	int ret, p;
	u8 data;

	/* Configure ingress/egress mirroring*/
	if (ingress)
		ret = lan937x_port_cfg(dev, port, P_MIRROR_CTRL, PORT_MIRROR_RX,
				       true);
	else
		ret = lan937x_port_cfg(dev, port, P_MIRROR_CTRL, PORT_MIRROR_TX,
				       true);
	if (ret < 0)
		return ret;

	/* Configure sniffer port meanwhile limit to one sniffer port
	 * Check if any of the port is already set for sniffing
	 * If yes, instruct the user to remove the previous entry & exit
	 */
	for (p = 0; p < dev->port_cnt; p++) {
		/* Skip the current sniffing port */
		if (p == mirror->to_local_port)
			continue;

		ret = lan937x_pread8(dev, p, P_MIRROR_CTRL, &data);
		if (ret < 0)
			return ret;

		if (data & PORT_MIRROR_SNIFFER) {
			dev_err(dev->dev,
				"Delete existing rules towards %s & try\n",
				dsa_to_port(ds, p)->name);
			return -EBUSY;
		}
	}

	ret = lan937x_port_cfg(dev, mirror->to_local_port, P_MIRROR_CTRL,
			       PORT_MIRROR_SNIFFER, true);
	if (ret < 0)
		return ret;

	ret = lan937x_cfg(dev, S_MIRROR_CTRL, SW_MIRROR_RX_TX, false);

	return ret;
}

static void lan937x_port_mirror_del(struct dsa_switch *ds, int port,
				    struct dsa_mall_mirror_tc_entry *mirror)
{
	struct ksz_device *dev = ds->priv;
	bool in_use = false;
	u8 data;
	int p;

	/* clear ingress/egress mirroring port */
	if (mirror->ingress)
		lan937x_port_cfg(dev, port, P_MIRROR_CTRL, PORT_MIRROR_RX,
				 false);
	else
		lan937x_port_cfg(dev, port, P_MIRROR_CTRL, PORT_MIRROR_TX,
				 false);

	/* Check if any of the port is still referring to sniffer port */
	for (p = 0; p < dev->port_cnt; p++) {
		lan937x_pread8(dev, p, P_MIRROR_CTRL, &data);

		if ((data & (PORT_MIRROR_RX | PORT_MIRROR_TX))) {
			in_use = true;
			break;
		}
	}

	/* delete sniffing if there are no other mirroring rule exist */
	if (!in_use)
		lan937x_port_cfg(dev, mirror->to_local_port, P_MIRROR_CTRL,
				 PORT_MIRROR_SNIFFER, false);
}

static phy_interface_t lan937x_get_interface(struct ksz_device *dev, int port)
{
	phy_interface_t interface;
	u8 data8;
	int ret;

	if (lan937x_is_internal_phy_port(dev, port))
		return PHY_INTERFACE_MODE_NA;

	/* read interface from REG_PORT_XMII_CTRL_1 register */
	ret = lan937x_pread8(dev, port, REG_PORT_XMII_CTRL_1, &data8);
	if (ret < 0)
		return PHY_INTERFACE_MODE_NA;

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

			dev->cpu_port = i;
			dev->host_mask = (1 << dev->cpu_port);
			dev->port_mask |= dev->host_mask;
			p = &dev->ports[i];

			/* Check if the device tree have specific interface
			 * setting otherwise read & assign from XMII register
			 * for host port interface
			 */
			interface = lan937x_get_interface(dev, i);
			if (!p->interface)
				p->interface = interface;

			dev_info(dev->dev,
				 "Port%d: using phy mode %s\n",
				 i,
				 phy_modes(p->interface));

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
	int ret;

	ret = lan937x_reset_switch(dev);
	if (ret < 0) {
		dev_err(ds->dev, "failed to reset switch\n");
		return ret;
	}
	/* The VLAN aware is a global setting. Mixed vlan
	 * filterings are not supported.
	 */
	ds->vlan_filtering_is_global = true;

	/* Configure cpu port */
	lan937x_config_cpu_port(ds);

	/* Enable aggressive back off for half duplex & UNH mode */
	lan937x_cfg(dev, REG_SW_MAC_CTRL_0,
		    (SW_PAUSE_UNH_MODE | SW_NEW_BACKOFF | SW_AGGR_BACKOFF),
		    true);

	/* If NO_EXC_COLLISION_DROP bit is set, the switch will not drop
	 * packets when 16 or more collisions occur
	 */
	lan937x_cfg(dev, REG_SW_MAC_CTRL_1, NO_EXC_COLLISION_DROP, true);

	/* Enable reserved multicast table */
	lan937x_cfg(dev, REG_SW_LUE_CTRL_0, SW_RESV_MCAST_ENABLE, true);

	/* enable global MIB counter freeze function */
	lan937x_cfg(dev, REG_SW_MAC_CTRL_6, SW_MIB_COUNTER_FREEZE, true);

	/* disable CLK125 & CLK25, 1: disable, 0: enable */
	lan937x_cfg(dev, REG_SW_GLOBAL_OUTPUT_CTRL__1,
		    (SW_CLK125_ENB | SW_CLK25_ENB), true);

	lan937x_enable_spi_indirect_access(dev);

	/* start switch */
	lan937x_cfg(dev, REG_SW_OPERATION, SW_START, true);

	ksz_init_mib_timer(dev);

	return 0;
}

static int lan937x_change_mtu(struct dsa_switch *ds, int port, int new_mtu)
{
	struct ksz_device *dev = ds->priv;
	int ret;

	new_mtu += VLAN_ETH_HLEN + ETH_FCS_LEN;

	if (dsa_is_cpu_port(ds, port))
		new_mtu += LAN937X_TAG_LEN;

	if (new_mtu >= FR_MIN_SIZE)
		ret = lan937x_port_cfg(dev, port, REG_PORT_MAC_CTRL_0,
				       PORT_JUMBO_EN, true);
	else
		ret = lan937x_port_cfg(dev, port, REG_PORT_MAC_CTRL_0,
				       PORT_JUMBO_EN, false);
	if (ret < 0) {
		dev_err(ds->dev, "failed to enable jumbo\n");
		return ret;
	}

	/* Write the frame size in PORT_MAX_FR_SIZE register */
	ret = lan937x_pwrite16(dev, port, PORT_MAX_FR_SIZE, new_mtu);
	if (ret < 0) {
		dev_err(ds->dev, "failed to change the mtu\n");
		return ret;
	}

	return 0;
}

static int lan937x_get_max_mtu(struct dsa_switch *ds, int port)
{
	/* Frame max size is 9000 (= 0x2328) if
	 * jumbo frame support is enabled, PORT_JUMBO_EN bit will be enabled
	 * based on mtu in lan937x_change_mtu() API
	 */
	return (FR_MAX_SIZE - VLAN_ETH_HLEN - ETH_FCS_LEN);
}

static void lan937x_phylink_mac_config(struct dsa_switch *ds, int port,
				       unsigned int mode,
				       const struct phylink_link_state *state)
{
	struct ksz_device *dev = ds->priv;

	/* Internal PHYs */
	if (lan937x_is_internal_phy_port(dev, port))
		return;

	if (phylink_autoneg_inband(mode)) {
		dev_err(ds->dev, "In-band AN not supported!\n");
		return;
	}
	lan937x_mac_config(dev, port, state->interface);
}

static void lan937x_phylink_mac_link_up(struct dsa_switch *ds, int port,
					unsigned int mode,
					phy_interface_t interface,
					struct phy_device *phydev,
					int speed, int duplex,
					bool tx_pause, bool rx_pause)
{
	struct ksz_device *dev = ds->priv;

	/* Internal PHYs */
	if (lan937x_is_internal_phy_port(dev, port))
		return;

	if (phylink_autoneg_inband(mode)) {
		dev_err(ds->dev, "In-band AN not supported!\n");
		return;
	}
	lan937x_config_interface(dev, port, speed, duplex,
				 tx_pause, rx_pause);
}

static void lan937x_phylink_validate(struct dsa_switch *ds, int port,
				     unsigned long *supported,
				     struct phylink_link_state *state)
{
	struct ksz_device *dev = ds->priv;
	__ETHTOOL_DECLARE_LINK_MODE_MASK(mask) = { 0, };

	/* Check for unsupported interfaces */
	if (!phy_interface_mode_is_rgmii(state->interface) &&
	    state->interface != PHY_INTERFACE_MODE_RMII &&
	    state->interface != PHY_INTERFACE_MODE_MII &&
	    state->interface != PHY_INTERFACE_MODE_INTERNAL) {
		bitmap_zero(supported, __ETHTOOL_LINK_MODE_MASK_NBITS);
		dev_err(ds->dev, "Unsupported interface '%s' for port %d\n",
			phy_modes(state->interface), port);
		return;
	}

	/* For RGMII, RMII, MII and internal TX phy port */
	if (phy_interface_mode_is_rgmii(state->interface) ||
	    state->interface == PHY_INTERFACE_MODE_RMII ||
	    state->interface == PHY_INTERFACE_MODE_MII ||
	    lan937x_is_internal_100BTX_phy_port(dev, port)) {
		phylink_set(mask, 10baseT_Half);
		phylink_set(mask, 10baseT_Full);
		phylink_set(mask, 100baseT_Half);
		phylink_set(mask, 100baseT_Full);
		phylink_set(mask, Autoneg);
		phylink_set_port_modes(mask);
		phylink_set(mask, Pause);
		phylink_set(mask, Asym_Pause);
	}

	/* For RGMII interface */
	if (phy_interface_mode_is_rgmii(state->interface))
		phylink_set(mask, 1000baseT_Full);

	/* For T1 PHY */
	if (lan937x_is_internal_t1_phy_port(dev, port)) {
		phylink_set(mask, 100baseT1_Full);
		phylink_set_port_modes(mask);
	}

	bitmap_and(supported, supported, mask, __ETHTOOL_LINK_MODE_MASK_NBITS);
	bitmap_and(state->advertising, state->advertising, mask,
		   __ETHTOOL_LINK_MODE_MASK_NBITS);
}

const struct dsa_switch_ops lan937x_switch_ops = {
	.get_tag_protocol = lan937x_get_tag_protocol,
	.setup = lan937x_setup,
	.phy_read = lan937x_phy_read16,
	.phy_write = lan937x_phy_write16,
	.port_enable = ksz_enable_port,
	.get_strings = lan937x_get_strings,
	.get_ethtool_stats = ksz_get_ethtool_stats,
	.get_sset_count = ksz_sset_count,
	.port_bridge_join = ksz_port_bridge_join,
	.port_bridge_leave = ksz_port_bridge_leave,
	.port_stp_state_set = lan937x_port_stp_state_set,
	.port_fast_age = ksz_port_fast_age,
	.port_vlan_filtering = lan937x_port_vlan_filtering,
	.port_vlan_add = lan937x_port_vlan_add,
	.port_vlan_del = lan937x_port_vlan_del,
	.port_fdb_dump = lan937x_port_fdb_dump,
	.port_fdb_add = lan937x_port_fdb_add,
	.port_fdb_del = lan937x_port_fdb_del,
	.port_mdb_add = lan937x_port_mdb_add,
	.port_mdb_del = lan937x_port_mdb_del,
	.port_mirror_add = lan937x_port_mirror_add,
	.port_mirror_del = lan937x_port_mirror_del,
	.port_max_mtu = lan937x_get_max_mtu,
	.port_change_mtu = lan937x_change_mtu,
	.phylink_validate = lan937x_phylink_validate,
	.phylink_mac_link_down = ksz_mac_link_down,
	.phylink_mac_config = lan937x_phylink_mac_config,
	.phylink_mac_link_up = lan937x_phylink_mac_link_up,
};

int lan937x_switch_register(struct ksz_device *dev)
{
	return ksz_switch_register(dev, &lan937x_dev_ops);
}
EXPORT_SYMBOL(lan937x_switch_register);

MODULE_AUTHOR("Prasanna Vengateshan Varadharajan <Prasanna.Vengateshan@microchip.com>");
MODULE_DESCRIPTION("Microchip LAN937x Series Switch DSA Driver");
MODULE_LICENSE("GPL");
