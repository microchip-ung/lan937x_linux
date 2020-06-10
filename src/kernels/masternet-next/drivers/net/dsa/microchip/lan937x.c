// SPDX-License-Identifier: GPL-2.0
/*
 * Microchip KSZ9477 switch driver main logic
 *
 * Copyright (C) 2017-2019 Microchip Technology Inc.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/iopoll.h>
#include <linux/platform_data/microchip-ksz.h>
#include <linux/phy.h>
#include <linux/if_bridge.h>
#include <net/dsa.h>
#include <net/switchdev.h>

#include "lan937x_reg.h"
#include "ksz_common.h"

/* Used with variable features to indicate capabilities. */
#define GBIT_SUPPORT			BIT(0)
#define NEW_XMII			BIT(1)
#define IS_9893				BIT(2)

static const struct {
	int index;
	char string[ETH_GSTRING_LEN];
} lan937x_mib_names[TOTAL_SWITCH_COUNTER_NUM] = {
	{ 0x00, "rx_hi" },
	{ 0x01, "rx_undersize" },
	{ 0x02, "rx_fragments" },
	{ 0x03, "rx_oversize" },
	{ 0x04, "rx_jabbers" },
	{ 0x05, "rx_symbol_err" },
	{ 0x06, "rx_crc_err" },
	{ 0x07, "rx_align_err" },
	{ 0x08, "rx_mac_ctrl" },
	{ 0x09, "rx_pause" },
	{ 0x0A, "rx_bcast" },
	{ 0x0B, "rx_mcast" },
	{ 0x0C, "rx_ucast" },
	{ 0x0D, "rx_64_or_less" },
	{ 0x0E, "rx_65_127" },
	{ 0x0F, "rx_128_255" },
	{ 0x10, "rx_256_511" },
	{ 0x11, "rx_512_1023" },
	{ 0x12, "rx_1024_1522" },
	{ 0x13, "rx_1523_2000" },
	{ 0x14, "rx_2001" },
	{ 0x15, "tx_hi" },
	{ 0x16, "tx_late_col" },
	{ 0x17, "tx_pause" },
	{ 0x18, "tx_bcast" },
	{ 0x19, "tx_mcast" },
	{ 0x1A, "tx_ucast" },
	{ 0x1B, "tx_deferred" },
	{ 0x1C, "tx_total_col" },
	{ 0x1D, "tx_exc_col" },
	{ 0x1E, "tx_single_col" },
	{ 0x1F, "tx_mult_col" },
	{ 0x80, "rx_total" },
	{ 0x81, "tx_total" },
	{ 0x82, "rx_discards" },
	{ 0x83, "tx_discards" },
};

static void lan937x_cfg(struct ksz_device *dev, u32 addr, u8 bits, bool set)
{
	regmap_update_bits(dev->regmap[0], addr, bits, set ? bits : 0);
}

static void lan937x_port_cfg(struct ksz_device *dev, int port, int offset, u8 bits,
			 bool set)
{
	//Get the logical to physical PHY mapping
	int logical_port = dev->logical_port_map[port];

	regmap_update_bits(dev->regmap[0], PORT_CTRL_ADDR(logical_port, offset),
			   bits, set ? bits : 0);
}

static void lan937x_cfg32(struct ksz_device *dev, u32 addr, u32 bits, bool set)
{
	regmap_update_bits(dev->regmap[2], addr, bits, set ? bits : 0);
}
static inline void lan937x_pread8(struct ksz_device *dev, int port, int offset,
			      u8 *data)
{
	//Get the logical to physical PHY mapping
	int logical_port = dev->logical_port_map[port];

	ksz_read8(dev, dev->dev_ops->get_port_addr(logical_port, offset), data);
}

static inline void lan937x_pread16(struct ksz_device *dev, int port, int offset,
			       u16 *data)
{
	//Get the logical to physical PHY mapping
	int logical_port = dev->logical_port_map[port];

	ksz_read16(dev, dev->dev_ops->get_port_addr(logical_port, offset), data);
}

static inline void lan937x_pread32(struct ksz_device *dev, int port, int offset,
			       u32 *data)
{
	//Get the logical to physical PHY mapping
	int logical_port = dev->logical_port_map[port];

	ksz_read32(dev, dev->dev_ops->get_port_addr(logical_port, offset), data);
}

static inline void lan937x_pwrite8(struct ksz_device *dev, int port, int offset,
			       u8 data)
{
	//Get the logical to physical PHY mapping
	int logical_port = dev->logical_port_map[port];

	ksz_write8(dev, dev->dev_ops->get_port_addr(logical_port, offset), data);
}

static inline void lan937x_pwrite16(struct ksz_device *dev, int port, int offset,
				u16 data)
{
	//Get the logical to physical PHY mapping
	int logical_port = dev->logical_port_map[port];

	ksz_write16(dev, dev->dev_ops->get_port_addr(logical_port, offset), data);
}

static inline void lan937x_pwrite32(struct ksz_device *dev, int port, int offset,
				u32 data)
{
	//Get the logical to physical PHY mapping
	int logical_port = dev->logical_port_map[port];

	ksz_write32(dev, dev->dev_ops->get_port_addr(logical_port, offset), data);
}

static void lan937x_port_cfg32(struct ksz_device *dev, int port, int offset,
			       u32 bits, bool set)
{
	//Get the logical to physical PHY mapping
	int logical_port = dev->logical_port_map[port];

	regmap_update_bits(dev->regmap[2], PORT_CTRL_ADDR(logical_port, offset),
			   bits, set ? bits : 0);
}

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
	if (ret) {
		dev_dbg(dev->dev, "Failed to read vlan table\n");
		goto exit;
	}

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
	if (ret) {
		dev_dbg(dev->dev, "Failed to write vlan table\n");
		goto exit;
	}

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
	ksz_read32(dev, REG_SW_ALU_VAL_A, &table[0]);
	ksz_read32(dev, REG_SW_ALU_VAL_B, &table[1]);
	ksz_read32(dev, REG_SW_ALU_VAL_C, &table[2]);
	ksz_read32(dev, REG_SW_ALU_VAL_D, &table[3]);
}

static void lan937x_write_table(struct ksz_device *dev, u32 *table)
{
	ksz_write32(dev, REG_SW_ALU_VAL_A, table[0]);
	ksz_write32(dev, REG_SW_ALU_VAL_B, table[1]);
	ksz_write32(dev, REG_SW_ALU_VAL_C, table[2]);
	ksz_write32(dev, REG_SW_ALU_VAL_D, table[3]);
}

static int lan937x_wait_alu_ready(struct ksz_device *dev)
{
	unsigned int val;

	return regmap_read_poll_timeout(dev->regmap[2], REG_SW_ALU_CTRL__4,
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

static int lan937x_reset_switch(struct ksz_device *dev)
{
	u8 data8;
	u32 data32;

	/* reset switch */
	lan937x_cfg(dev, REG_SW_OPERATION, SW_RESET, true);

	/* turn off SPI DO Edge select */
	regmap_update_bits(dev->regmap[0], REG_SW_GLOBAL_SERIAL_CTRL_0,
			   SPI_AUTO_EDGE_DETECTION, 0);
			   


	/* default configuration */
	ksz_read8(dev, REG_SW_LUE_CTRL_1, &data8);
	data8 = SW_AGING_ENABLE | SW_LINK_AUTO_AGING |
	      SW_SRC_ADDR_FILTER | SW_FLUSH_STP_TABLE | SW_FLUSH_MSTP_TABLE;
	ksz_write8(dev, REG_SW_LUE_CTRL_1, data8);

	/* disable interrupts */
	ksz_write32(dev, REG_SW_INT_MASK__4, SWITCH_INT_MASK);
	ksz_write32(dev, REG_SW_PORT_INT_MASK__4, 0x7F);
	ksz_read32(dev, REG_SW_PORT_INT_STATUS__4, &data32);

	/* set broadcast storm protection 10% rate */
	regmap_update_bits(dev->regmap[1], REG_SW_MAC_CTRL_2,
			   BROADCAST_STORM_RATE,
			   (BROADCAST_STORM_VALUE *
			   BROADCAST_STORM_PROT_RATE) / 100);

	if (dev->synclko_125)
		ksz_write8(dev, REG_SW_GLOBAL_OUTPUT_CTRL__1,
			   SW_ENABLE_REFCLKO | SW_REFCLKO_IS_125MHZ);

	return 0;
}

static void lan937x_r_mib_cnt(struct ksz_device *dev, int port, u16 addr,
			      u64 *cnt)
{
	struct ksz_port *p = &dev->ports[port];
	unsigned int val;
	u32 data;
	int ret;

	/* retain the flush/freeze bit */
	data = p->freeze ? MIB_COUNTER_FLUSH_FREEZE : 0;
	data |= MIB_COUNTER_READ;
	data |= (addr << MIB_COUNTER_INDEX_S);
	lan937x_pwrite32(dev, port, REG_PORT_MIB_CTRL_STAT__4, data);

	ret = regmap_read_poll_timeout(dev->regmap[2],
			PORT_CTRL_ADDR(port, REG_PORT_MIB_CTRL_STAT__4),
			val, !(val & MIB_COUNTER_READ), 10, 1000);
	/* failed to read MIB. get out of loop */
	if (ret) {
		dev_dbg(dev->dev, "Failed to get MIB\n");
		return;
	}

	/* count resets upon read */
	lan937x_pread32(dev, port, REG_PORT_MIB_DATA, &data);
	*cnt += data;
}

static void lan937x_r_mib_pkt(struct ksz_device *dev, int port, u16 addr,
			      u64 *dropped, u64 *cnt)
{
	addr = lan937x_mib_names[addr].index;
	lan937x_r_mib_cnt(dev, port, addr, cnt);
}

static void lan937x_freeze_mib(struct ksz_device *dev, int port, bool freeze)
{
	u32 val = freeze ? MIB_COUNTER_FLUSH_FREEZE : 0;
	struct ksz_port *p = &dev->ports[port];

	/* enable/disable the port for flush/freeze function */
	mutex_lock(&p->mib.cnt_mutex);
	lan937x_pwrite32(dev, port, REG_PORT_MIB_CTRL_STAT__4, val);

	/* used by MIB counter reading code to know freeze is enabled */
	p->freeze = freeze;
	mutex_unlock(&p->mib.cnt_mutex);
}

static void lan937x_port_init_cnt(struct ksz_device *dev, int port)
{
	struct ksz_port_mib *mib = &dev->ports[port].mib;

	/* flush all enabled port MIB counters */
	mutex_lock(&mib->cnt_mutex);
	lan937x_pwrite32(dev, port, REG_PORT_MIB_CTRL_STAT__4,
		     MIB_COUNTER_FLUSH_FREEZE);
	ksz_write8(dev, REG_SW_MAC_CTRL_6, SW_MIB_COUNTER_FLUSH);
	lan937x_pwrite32(dev, port, REG_PORT_MIB_CTRL_STAT__4, 0);
	mutex_unlock(&mib->cnt_mutex);

	mib->cnt_ptr = 0;
	memset(mib->counters, 0, dev->mib_cnt * sizeof(u64));
}

static enum dsa_tag_protocol lan937x_get_tag_protocol(struct dsa_switch *ds,
						      int port,
						      enum dsa_tag_protocol mp)
{
	enum dsa_tag_protocol proto = DSA_TAG_PROTO_LAN937X_VALUE;

	return proto;
}

static int lan937x_enable_spi_indirect_access (struct ksz_device *dev)
{
	u8 data8;
	u16 data16;
	int ret;
	
	
	ret = ksz_read8(dev, REG_GLOBAL_CTRL_0, &data8);

	if (ret)
		return ret;
	
	/* Enable Phy access through SPI*/
	data8 &= ~SW_PHY_REG_BLOCK;

	ret = ksz_write8(dev, REG_GLOBAL_CTRL_0, data8);
	
	if (ret)
		return ret;

	ret = ksz_read16 (dev, REG_VPHY_SPECIAL_CTRL__2, &data16);

	if (ret)
		return ret;

	/*If already the access is not enabled go ahead and allow SPI access*/
	if(!(data16 & VPHY_SPI_INDIRECT_ENABLE)) {
		data16 |= VPHY_SPI_INDIRECT_ENABLE;
		ret = ksz_write16 (dev, REG_VPHY_SPECIAL_CTRL__2, data16);
		
		if (ret)
			return ret;
	}
	return ret;
}
static bool lan937x_is_tx_phy_port(struct ksz_device *dev, int physical_port)
{
	int logical_port;

	/*Get the logical to physical PHY mapping*/
	logical_port = dev->logical_port_map[physical_port];

	return logical_port == dev->tx_phy_logical_prt_n;
}
static int lan937x_t1_tx_phy_write (struct ksz_device *dev,int addr,int reg,u16 val)
{
	int ret,logical_port;
	u16 data;
	u16 temp,addr_base;

	pr_info ("lan937x_phy_write16 start, addr:0x%x reg:0x%x,val:0x%x",addr,reg,val);

	/* No real PHY after this. */
	if (addr >= dev->phy_port_cnt)
		return 0;

	/*Enable Indirect Access from SPI to the VPHY registers*/
	ret = lan937x_enable_spi_indirect_access(dev);

	if (ret)
		return ret;

	/*Get the logical to physical PHY mapping*/
	logical_port = dev->logical_port_map[addr];

	/*Physical to logical mapping is not done here as the dts would
	be updated correctly as per the SKU What we are getting as addr is logical port*/

	if (logical_port == LOGICAL_PORT_INVALID)
		return -EINVAL; /*addr given in the argument is invalid*/
	
	if (lan937x_is_tx_phy_port(dev, addr)) {
		addr_base = REG_PORT_TX_PHY_CTRL_BASE;
	} else {
		addr_base = REG_PORT_T1_PHY_CTRL_BASE;
	}

	temp = dev->dev_ops->get_port_addr(logical_port, (addr_base + (reg << 2)));

	ret = ksz_write16(dev, REG_VPHY_IND_ADDR__2, temp);
	if (ret)
		return ret;

	/*Write the data to be written to theVPHY reg*/
	ret = ksz_write16(dev, REG_VPHY_IND_DATA__2, val);
	if (ret)
		return ret;

	/*Write the Write En and Busy bit*/
	ret = ksz_write16(dev, REG_VPHY_IND_CTRL__2, (VPHY_IND_WRITE | VPHY_IND_BUSY));

	if (ret)
		return ret;

	do {
		ret = ksz_read16(dev, REG_VPHY_IND_CTRL__2, &data);	
		if (ret)
			return ret;
	}while (data & VPHY_IND_BUSY);
		
	return 0;
}
static int lan937x_t1_tx_phy_read (struct ksz_device *dev,int addr, int reg)
{
	u16 val = 0xffff;
	int ret,logical_port;
	u16 temp,addr_base;

	/* No real PHY after this. Simulate the PHY.
	 * A fixed PHY can be setup in the device tree, but this function is
	 * still called for that port during initialization.
	 * For RGMII PHY there is no way to access it so the fixed PHY should
	 * be used.  For SGMII PHY the supporting code will be added later.
	 */
	
	//pr_info ("lan937x_phy_read16, addr:0x%x reg:0x%x, dev->phy_port_cnt=%d",addr,reg,dev->phy_port_cnt);
	if (addr >= dev->phy_port_cnt) {
		struct ksz_port *p = &dev->ports[addr];
		pr_info("simulate");
		switch (reg) {
		case MII_BMCR:
			val = 0x1140;
			break;
		case MII_BMSR:
			val = 0x796d;
			break;
		case MII_PHYSID1:
			val = 0x0022;
			break;
		case MII_PHYSID2:
			val = 0x1631;
			break;
		case MII_ADVERTISE:
			val = 0x05e1;
			break;
		case MII_LPA:
			val = 0xc5e1;
			break;
		case MII_CTRL1000:
			val = 0x0700;
			break;
		case MII_STAT1000:
			if (p->phydev.speed == SPEED_1000)
				val = 0x3800;
			else
				val = 0;
			break;
		}
	} else {
		//pr_info("readinfo from device");

		/*Enable Indirect Access from SPI to the VPHY registers*/
		ret = lan937x_enable_spi_indirect_access(dev);

		if (ret)
			return ret;

		/*Physical to logical mapping is not done here as the dts would
		be updated correctly as per the SKU; What we are getting as addr is logical port*/
		
		/*Get the logical to physical PHY mapping*/
		logical_port = dev->logical_port_map[addr];

		if (logical_port == LOGICAL_PORT_INVALID)
			return -EINVAL; /*addr given in the argument is invalid*/
		
		if (lan937x_is_tx_phy_port(dev, addr)) {
			addr_base = REG_PORT_TX_PHY_CTRL_BASE;
		} else {
			addr_base = REG_PORT_T1_PHY_CTRL_BASE;
		}

		temp = dev->dev_ops->get_port_addr(logical_port, (addr_base + (reg << 2)));

		ret = ksz_write16(dev, REG_VPHY_IND_ADDR__2, temp);

		if (ret)
			return ret;

		/*Write REAd and Busy bit to start the transaction*/
		ret = ksz_write16(dev, REG_VPHY_IND_CTRL__2, VPHY_IND_BUSY);

		if (ret)
			return ret;
		do {
			/*Keep read ing the register until the BUSY bit is cleared*/
			ret = ksz_read16(dev, REG_VPHY_IND_CTRL__2, &val);	

			if(ret)
				return ret;
		}while (val & VPHY_IND_BUSY);

		/*Read the VPHY register which has the PHY data*/
		ksz_read16(dev, REG_VPHY_IND_DATA__2, &val);

		if (reg == MII_BMSR && !lan937x_is_tx_phy_port(dev, addr)) {
			val |= MII_BMSR_100BASE_TX_FD;
		}
		//pr_info ("lan937x_phy_read16 start, addr:0x%x reg:0x%x,val:0x%x",addr,reg,val);
	}
	
	return val;

}
static int lan937x_phy_read16(struct dsa_switch *ds, int addr, int reg)
{
	struct ksz_device *dev = ds->priv;

	return lan937x_t1_tx_phy_read(dev, addr, reg);
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
	int i;
	pr_info("lan937x_get_strings port:%d",port);
	if (stringset != ETH_SS_STATS)
		return;

	for (i = 0; i < TOTAL_SWITCH_COUNTER_NUM; i++) {
		memcpy(buf + i * ETH_GSTRING_LEN, lan937x_mib_names[i].string,
		       ETH_GSTRING_LEN);
	}
}

static void lan937x_cfg_port_member(struct ksz_device *dev, int port,
				    u8 member)
{
	lan937x_pwrite32(dev, port, REG_PORT_VLAN_MEMBERSHIP__4, member);
	dev->ports[port].member = member;
}

static void lan937x_port_stp_state_set(struct dsa_switch *ds, int port,
				       u8 state)
{
	struct ksz_device *dev = ds->priv;
	struct ksz_port *p = &dev->ports[port];
	u8 data;
	int member = -1;
	int forward = dev->member;

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
	if (data & PORT_RX_ENABLE)
		dev->rx_ports |= (1 << port);
	else
		dev->rx_ports &= ~(1 << port);
	if (data & PORT_TX_ENABLE)
		dev->tx_ports |= (1 << port);
	else
		dev->tx_ports &= ~(1 << port);

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

static void lan937x_flush_dyn_mac_table(struct ksz_device *dev, int port)
{
	u8 data;

	regmap_update_bits(dev->regmap[0], REG_SW_LUE_CTRL_2,
			   SW_FLUSH_OPTION_M << SW_FLUSH_OPTION_S,
			   SW_FLUSH_OPTION_DYN_MAC << SW_FLUSH_OPTION_S);

	if (port < dev->mib_port_cnt) {
		/* flush individual port */
		lan937x_pread8(dev, port, P_STP_CTRL, &data);
		if (!(data & PORT_LEARN_DISABLE))
			lan937x_pwrite8(dev, port, P_STP_CTRL,
				    data | PORT_LEARN_DISABLE);
		lan937x_cfg(dev, S_FLUSH_TABLE_CTRL, SW_FLUSH_DYN_MAC_TABLE, true);
		lan937x_pwrite8(dev, port, P_STP_CTRL, data);
	} else {
		/* flush all */
		lan937x_cfg(dev, S_FLUSH_TABLE_CTRL, SW_FLUSH_STP_TABLE, true);
	}
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

static void lan937x_port_vlan_add(struct dsa_switch *ds, int port,
				  const struct switchdev_obj_port_vlan *vlan)
{
	struct ksz_device *dev = ds->priv;
	u32 vlan_table[3];
	u16 vid;
	bool untagged = vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED;

	for (vid = vlan->vid_begin; vid <= vlan->vid_end; vid++) {
		if (lan937x_get_vlan_table(dev, vid, vlan_table)) {
			dev_dbg(dev->dev, "Failed to get vlan table\n");
			return;
		}

		vlan_table[0] = VLAN_VALID | (vid & VLAN_FID_M);
		if (untagged)
			vlan_table[1] |= BIT(port);
		else
			vlan_table[1] &= ~BIT(port);
		vlan_table[1] &= ~(BIT(dev->cpu_port));

		vlan_table[2] |= BIT(port) | BIT(dev->cpu_port);

		if (lan937x_set_vlan_table(dev, vid, vlan_table)) {
			dev_dbg(dev->dev, "Failed to set vlan table\n");
			return;
		}

		/* change PVID */
		if (vlan->flags & BRIDGE_VLAN_INFO_PVID)
			lan937x_pwrite16(dev, port, REG_PORT_DEFAULT_VID, vid);
	}
}

static int lan937x_port_vlan_del(struct dsa_switch *ds, int port,
				 const struct switchdev_obj_port_vlan *vlan)
{
	struct ksz_device *dev = ds->priv;
	bool untagged = vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED;
	u32 vlan_table[3];
	u16 vid;
	u16 pvid;

	lan937x_pread16(dev, port, REG_PORT_DEFAULT_VID, &pvid);
	pvid = pvid & 0xFFF;

	for (vid = vlan->vid_begin; vid <= vlan->vid_end; vid++) {
		if (lan937x_get_vlan_table(dev, vid, vlan_table)) {
			dev_dbg(dev->dev, "Failed to get vlan table\n");
			return -ETIMEDOUT;
		}

		vlan_table[2] &= ~BIT(port);

		if (pvid == vid)
			pvid = 1;

		if (untagged)
			vlan_table[1] &= ~BIT(port);

		if (lan937x_set_vlan_table(dev, vid, vlan_table)) {
			dev_dbg(dev->dev, "Failed to set vlan table\n");
			return -ETIMEDOUT;
		}
	}

	lan937x_pwrite16(dev, port, REG_PORT_DEFAULT_VID, pvid);

	return 0;
}

static int lan937x_port_fdb_add(struct dsa_switch *ds, int port,
				const unsigned char *addr, u16 vid)
{
	struct ksz_device *dev = ds->priv;
	u32 alu_table[4];
	u32 data;
	int ret = 0;

	mutex_lock(&dev->alu_mutex);

	/* find any entry with mac & vid */
	data = vid << ALU_FID_INDEX_S;
	data |= ((addr[0] << 8) | addr[1]);
	ksz_write32(dev, REG_SW_ALU_INDEX_0, data);

	data = ((addr[2] << 24) | (addr[3] << 16));
	data |= ((addr[4] << 8) | addr[5]);
	ksz_write32(dev, REG_SW_ALU_INDEX_1, data);

	/* start read operation */
	ksz_write32(dev, REG_SW_ALU_CTRL__4, ALU_READ | ALU_START);

	/* wait to be finished */
	ret = lan937x_wait_alu_ready(dev);
	if (ret) {
		dev_dbg(dev->dev, "Failed to read ALU\n");
		goto exit;
	}

	/* read ALU entry */
	lan937x_read_table(dev, alu_table);

	/* update ALU entry */
	alu_table[0] = ALU_V_STATIC_VALID;
	alu_table[1] |= BIT(port);
	if (vid)
		alu_table[1] |= ALU_V_USE_FID;
	alu_table[2] = (vid << ALU_V_FID_S);
	alu_table[2] |= ((addr[0] << 8) | addr[1]);
	alu_table[3] = ((addr[2] << 24) | (addr[3] << 16));
	alu_table[3] |= ((addr[4] << 8) | addr[5]);

	lan937x_write_table(dev, alu_table);

	ksz_write32(dev, REG_SW_ALU_CTRL__4, ALU_WRITE | ALU_START);

	/* wait to be finished */
	ret = lan937x_wait_alu_ready(dev);
	if (ret)
		dev_dbg(dev->dev, "Failed to write ALU\n");

exit:
	mutex_unlock(&dev->alu_mutex);

	return ret;
}

static int lan937x_port_fdb_del(struct dsa_switch *ds, int port,
				const unsigned char *addr, u16 vid)
{
	struct ksz_device *dev = ds->priv;
	u32 alu_table[4];
	u32 data;
	int ret = 0;

	mutex_lock(&dev->alu_mutex);

	/* read any entry with mac & vid */
	data = vid << ALU_FID_INDEX_S;
	data |= ((addr[0] << 8) | addr[1]);
	ksz_write32(dev, REG_SW_ALU_INDEX_0, data);

	data = ((addr[2] << 24) | (addr[3] << 16));
	data |= ((addr[4] << 8) | addr[5]);
	ksz_write32(dev, REG_SW_ALU_INDEX_1, data);

	/* start read operation */
	ksz_write32(dev, REG_SW_ALU_CTRL__4, ALU_READ | ALU_START);

	/* wait to be finished */
	ret = lan937x_wait_alu_ready(dev);
	if (ret) {
		dev_dbg(dev->dev, "Failed to read ALU\n");
		goto exit;
	}

	ksz_read32(dev, REG_SW_ALU_VAL_A, &alu_table[0]);
	if (alu_table[0] & ALU_V_STATIC_VALID) {
		ksz_read32(dev, REG_SW_ALU_VAL_B, &alu_table[1]);
		ksz_read32(dev, REG_SW_ALU_VAL_C, &alu_table[2]);
		ksz_read32(dev, REG_SW_ALU_VAL_D, &alu_table[3]);

		/* clear forwarding port */
		alu_table[2] &= ~BIT(port);

		/* if there is no port to forward, clear table */
		if ((alu_table[2] & ALU_V_PORT_MAP) == 0) {
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

	ksz_write32(dev, REG_SW_ALU_CTRL__4, ALU_WRITE | ALU_START);

	/* wait to be finished */
	ret = lan937x_wait_alu_ready(dev);
	if (ret)
		dev_dbg(dev->dev, "Failed to write ALU\n");

exit:
	mutex_unlock(&dev->alu_mutex);

	return ret;
}

static void lan937x_convert_alu(struct alu_struct *alu, u32 *alu_table)
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
	int ret = 0;
	u32 lan937x_data;
	u32 alu_table[4];
	struct alu_struct alu;
	int timeout;

	mutex_lock(&dev->alu_mutex);

	/* start ALU search */
	ksz_write32(dev, REG_SW_ALU_CTRL__4, ALU_START | ALU_SEARCH);

	do {
		timeout = 1000;
		do {
			ksz_read32(dev, REG_SW_ALU_CTRL__4, &lan937x_data);
			if ((lan937x_data & ALU_VALID) || !(lan937x_data & ALU_START))
				break;
			usleep_range(1, 10);
		} while (timeout-- > 0);

		if (!timeout) {
			dev_dbg(dev->dev, "Failed to search ALU\n");
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

	/* stop ALU search */
	ksz_write32(dev, REG_SW_ALU_CTRL__4, 0);

	mutex_unlock(&dev->alu_mutex);

	return ret;
}

static void lan937x_port_mdb_add(struct dsa_switch *ds, int port,
				 const struct switchdev_obj_port_mdb *mdb)
{
	struct ksz_device *dev = ds->priv;
	u32 static_table[4];
	u32 data;
	int index;
	u32 mac_hi, mac_lo;

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
		if (lan937x_wait_alu_sta_ready(dev)) {
			dev_dbg(dev->dev, "Failed to read ALU STATIC\n");
			goto exit;
		}

		/* read ALU static table */
		lan937x_read_table(dev, static_table);

		if (static_table[0] & ALU_V_STATIC_VALID) {
			/* check this has same vid & mac address */
			if (((static_table[2] >> ALU_V_FID_S) == mdb->vid) &&
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
	if (index == dev->num_statics)
		goto exit;

	/* add entry */
	static_table[0] = ALU_V_STATIC_VALID;
	static_table[1] |= BIT(port);
	if (mdb->vid)
		static_table[1] |= ALU_V_USE_FID;
	static_table[2] = (mdb->vid << ALU_V_FID_S);
	static_table[2] |= mac_hi;
	static_table[3] = mac_lo;

	lan937x_write_table(dev, static_table);

	data = (index << ALU_STAT_INDEX_S) | ALU_STAT_START;
	ksz_write32(dev, REG_SW_ALU_STAT_CTRL__4, data);

	/* wait to be finished */
	if (lan937x_wait_alu_sta_ready(dev))
		dev_dbg(dev->dev, "Failed to read ALU STATIC\n");

exit:
	mutex_unlock(&dev->alu_mutex);
}

static int lan937x_port_mdb_del(struct dsa_switch *ds, int port,
				const struct switchdev_obj_port_mdb *mdb)
{
	struct ksz_device *dev = ds->priv;
	u32 static_table[4];
	u32 data;
	int index;
	int ret = 0;
	u32 mac_hi, mac_lo;

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
			dev_dbg(dev->dev, "Failed to read ALU STATIC\n");
			goto exit;
		}

		/* read ALU static table */
		lan937x_read_table(dev, static_table);

		if (static_table[0] & ALU_V_STATIC_VALID) {
			/* check this has same vid & mac address */

			if (((static_table[2] >> ALU_V_FID_S) == mdb->vid) &&
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

	/* clear port */
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
		dev_dbg(dev->dev, "Failed to read ALU STATIC\n");

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

static void lan937x_phy_setup(struct ksz_device *dev, int port,
			      struct phy_device *phy)
{
	pr_info("lan937x_phy_setup: start");
	/* Only apply to port with PHY. */
	if (port >= dev->phy_port_cnt)
		return;
	
	/* The MAC actually cannot run in 1000 half-duplex mode. */
	phy_remove_link_mode(phy,
			     ETHTOOL_LINK_MODE_1000baseT_Half_BIT);


	phy_remove_link_mode(phy,
				     ETHTOOL_LINK_MODE_1000baseT_Full_BIT);
}

static void lan937x_set_gbit(struct ksz_device *dev, bool gbit, u8 *data)
{
	if (gbit)
		*data &= ~PORT_MII_NOT_1GBIT;
	else
		*data |= PORT_MII_NOT_1GBIT;

}

static int lan937x_get_xmii(struct ksz_device *dev, u8 data)
{
	int mode;

	switch (data & PORT_MII_SEL_M) {
	case PORT_MII_SEL:
		mode = 0;
		break;
	case PORT_RMII_SEL:
		mode = 1;
		break;
	case PORT_RGMII_SEL:
		mode = 2;
		break;
	default:
		/*MII Interface*/
		mode = 0;
		break;
	}

	return mode;
}

static void lan937x_set_xmii(struct ksz_device *dev, int mode, u8 *data)
{
	u8 xmii;

	switch (mode) {
	case 0:
		xmii = PORT_MII_SEL;
		break;
	case 1:
		xmii = PORT_RMII_SEL;
		break;
	case 2:
		xmii = PORT_RGMII_SEL;
		break;
	default:
		xmii = PORT_RGMII_SEL;
		break;
	}
	
	*data &= ~PORT_MII_SEL_M;
	*data |= xmii;
}

static phy_interface_t lan937x_get_interface(struct ksz_device *dev, int port)
{
	phy_interface_t interface;
	bool gbit;
	int mode;
	u8 data8;
	pr_info("get interface, port:%d",port);
	if (port < dev->phy_port_cnt)
		return PHY_INTERFACE_MODE_NA;

	lan937x_pread8(dev, port, REG_PORT_XMII_CTRL_1, &data8);
	pr_info("REG_PORT_XMII_CTRL_1:0x%x",data8);

	gbit = !(data8 & PORT_MII_NOT_1GBIT);

	mode = lan937x_get_xmii(dev, data8);

	pr_info("gbit:%d,mode:%d",gbit,mode);
	switch (mode) {
	case 1:
		interface = PHY_INTERFACE_MODE_RMII;
		break;
	case 2:
		interface = PHY_INTERFACE_MODE_RGMII;
		pr_info("interface data:0x%x", data8);
		if (data8 & PORT_RGMII_ID_EG_ENABLE) 
			interface = PHY_INTERFACE_MODE_RGMII_TXID;
		if (data8 & PORT_RGMII_ID_IG_ENABLE) {
			interface = PHY_INTERFACE_MODE_RGMII_RXID;
			if (data8 & PORT_RGMII_ID_EG_ENABLE)
				interface = PHY_INTERFACE_MODE_RGMII_ID;
		}
		break;
	case 0:
	default:
		/*Mode 0 & Mode 3 are MII*/
		interface = PHY_INTERFACE_MODE_MII;
		break;

	}
	return interface;
}

static void lan937x_port_setup(struct ksz_device *dev, int port, bool cpu_port)
{
	u8 data8;
	u8 member;
	u16 data16;
	struct ksz_port *p = &dev->ports[port];
	pr_info("port set up port:%d",port);
	/* enable tag tail for host port */
	if (cpu_port)
		lan937x_port_cfg(dev, port, REG_PORT_CTRL_0, PORT_TAIL_TAG_ENABLE,
			     true);

	lan937x_port_cfg(dev, port, REG_PORT_CTRL_0, PORT_MAC_LOOPBACK, false);

	/* set back pressure */
	lan937x_port_cfg(dev, port, REG_PORT_MAC_CTRL_1, PORT_BACK_PRESSURE, true);

	/* enable broadcast storm limit */
	lan937x_port_cfg(dev, port, P_BCAST_STORM_CTRL, PORT_BROADCAST_STORM, true);

	/* disable DiffServ priority */
	lan937x_port_cfg(dev, port, P_PRIO_CTRL, PORT_DIFFSERV_PRIO_ENABLE, false);

	/* replace priority */
	lan937x_port_cfg(dev, port, REG_PORT_MRI_MAC_CTRL, PORT_USER_PRIO_CEILING,
		     false);
	lan937x_port_cfg32(dev, port, REG_PORT_MTI_QUEUE_CTRL_0__4,
			   MTI_PVID_REPLACE, false);

	/* enable 802.1p priority */
	lan937x_port_cfg(dev, port, P_PRIO_CTRL, PORT_802_1P_PRIO_ENABLE, true);

	if (port < dev->phy_port_cnt) {
		pr_info("port < dev->phy_port_cnt: %d",port);
		//TODO: For future reservation: any other writes to be added?
		//To be removed before submitting the driver
	} else {

		/* configure MAC to 1G & RGMII mode */
		lan937x_pread8(dev, port, REG_PORT_XMII_CTRL_1, &data8);
		pr_info("swich interface:%s, port:%d",  phy_modes(dev->interface),port);
		switch (dev->interface) {
		case PHY_INTERFACE_MODE_MII:
			pr_info("PHY_INTERFACE_MODE_MII");
			lan937x_set_xmii(dev, 0, &data8);
			lan937x_set_gbit(dev, false, &data8);
			p->phydev.speed = SPEED_100;
			break;
		case PHY_INTERFACE_MODE_RMII:
			pr_info("PHY_INTERFACE_MODE_RMII");
			lan937x_set_xmii(dev, 1, &data8);
			lan937x_set_gbit(dev, false, &data8);
			p->phydev.speed = SPEED_100;
			break;
		default:
			pr_info("default");	
			lan937x_set_xmii(dev, 3, &data8);
			lan937x_set_gbit(dev, true, &data8);
			data8 &= ~PORT_RGMII_ID_IG_ENABLE;
			data8 &= ~PORT_RGMII_ID_EG_ENABLE;
			if (dev->interface == PHY_INTERFACE_MODE_RGMII_ID ||
			    dev->interface == PHY_INTERFACE_MODE_RGMII_RXID)
				data8 |= PORT_RGMII_ID_IG_ENABLE;
			if (dev->interface == PHY_INTERFACE_MODE_RGMII_ID ||
			    dev->interface == PHY_INTERFACE_MODE_RGMII_TXID)
				data8 |= PORT_RGMII_ID_EG_ENABLE;
			p->phydev.speed = SPEED_1000;
			break;
		}
		lan937x_pwrite8(dev, port, REG_PORT_XMII_CTRL_1, data8);
		p->phydev.duplex = 1;
	}
	mutex_lock(&dev->dev_mutex);
	if (cpu_port) {
		member = dev->port_mask;
		dev->on_ports = dev->host_mask;
		dev->live_ports = dev->host_mask;
	} else {
		member = dev->host_mask | p->vid_member;
		dev->on_ports |= (1 << port);

		/* Link was detected before port is enabled. */
		if (p->phydev.link)
			dev->live_ports |= (1 << port);
	}
	mutex_unlock(&dev->dev_mutex);
	lan937x_cfg_port_member(dev, port, member);

	/* clear pending interrupts */
	if (port < dev->phy_port_cnt)
		lan937x_pread16(dev, port, REG_PORT_PHY_INT_ENABLE, &data16);
	
	pr_info("port setup end");
}

static void lan937x_config_cpu_port(struct dsa_switch *ds)
{
	struct ksz_device *dev = ds->priv;
	struct ksz_port *p;
	phy_interface_t interface;
	int i;
	
	ds->num_ports = dev->port_cnt;

	for (i = 0; i < dev->port_cnt; i++) {
		pr_info("port num inside lan937x_config_cpu_port:%d",i);

		if (dsa_is_cpu_port(ds, i) && (dev->cpu_ports & (1 << i))) {
			pr_info("cpu port:%d",i);
			

			dev->cpu_port = i;
			dev->host_mask = (1 << dev->cpu_port);
			dev->port_mask |= dev->host_mask;

			/* Read from XMII register to determine host port
			 * interface.  If set specifically in device tree
			 * note the difference to help debugging.
			 */
			interface = lan937x_get_interface(dev, i);
			pr_info ("interface:%s",phy_modes(interface));
			if (!dev->interface)
				dev->interface = interface;
			if (interface && interface != dev->interface)
				dev_info(dev->dev,
					 "use %s instead of %s\n",
					  phy_modes(dev->interface),
					  phy_modes(interface));

			/* enable cpu port */
			lan937x_port_setup(dev, i, true);
			pr_info("enable cpu port done: %d",i);
			p = &dev->ports[dev->cpu_port];
			p->vid_member = dev->port_mask;
			p->on = 1;
		}
	}

	dev->member = dev->host_mask;

	for (i = 0; i < dev->mib_port_cnt; i++) {
		if (i == dev->cpu_port)
			continue;
		p = &dev->ports[i];

		/* Initialize to non-zero so that lan937x_cfg_port_member() will
		 * be called.
		 */
		p->vid_member = (1 << i);
		p->member = dev->port_mask;
		lan937x_port_stp_state_set(ds, i, BR_STATE_DISABLED);
		p->on = 1;
		if (i < dev->phy_port_cnt)
			p->phy = 1;

		if (dev->chip_id == 0x00937400 && i == 7) {
			/* SGMII PHY detection code is not implemented yet. */
			p->phy = 0;
		}
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
	pr_info("ksz setup");
	ret = lan937x_reset_switch(dev);
	if (ret) {
		dev_err(ds->dev, "failed to reset switch\n");
		return ret;
	}

	/* Required for port partitioning. */
	lan937x_cfg32(dev, REG_SW_QM_CTRL__4, UNICAST_VLAN_BOUNDARY,
		      true);

	/* Do not work correctly with tail tagging. */
	lan937x_cfg(dev, REG_SW_MAC_CTRL_0, SW_CHECK_LENGTH, false);

	/* accept packet up to 2000bytes */
	lan937x_cfg(dev, REG_SW_MAC_CTRL_1, SW_LEGAL_PACKET_DISABLE, true);

	lan937x_config_cpu_port(ds);

	lan937x_cfg(dev, REG_SW_MAC_CTRL_1, MULTICAST_STORM_DISABLE, true);

	/* queue based egress rate limit */
	lan937x_cfg(dev, REG_SW_MAC_CTRL_5, SW_OUT_RATE_LIMIT_QUEUE_BASED, true);

	/* enable global MIB counter freeze function */
	lan937x_cfg(dev, REG_SW_MAC_CTRL_6, SW_MIB_COUNTER_FREEZE, true);

	/* start switch */
	lan937x_cfg(dev, REG_SW_OPERATION, SW_START, true);

	ksz_init_mib_timer(dev);
	
	pr_info("port setup end");

	return 0;
}


static int lan937x_change_mtu(struct dsa_switch *ds, int port, int mtu)
{
	struct ksz_device *dev = ds->priv;
	u16 max_size;
	
	pr_info("lan937x_change_mtu port %d, mtu: %d", port, mtu);
	
	if (mtu >= FR_MIN_SIZE) {
		lan937x_port_cfg(dev,port, REG_PORT_MAC_CTRL_0,PORT_JUMBO_EN , true);
		max_size = FR_MAX_SIZE;
	} else {
		lan937x_port_cfg(dev, port, REG_PORT_MAC_CTRL_0,PORT_JUMBO_EN , false);
		max_size = FR_MIN_SIZE;
	}
	lan937x_pwrite16(dev,port, PORT_MAX_FR_SIZE, max_size );
	return 0;
	
}
static int lan937x_get_max_mtu(struct dsa_switch *ds, int port)
{
	pr_info("get max mtu port:%d",port);
	return FR_MAX_SIZE;
}
static void lan937x_phylink_validate(struct dsa_switch *ds, int port,
			  unsigned long *supported,
			  struct phylink_link_state *state)
{
	struct ksz_device *dev = ds->priv;
	__ETHTOOL_DECLARE_LINK_MODE_MASK(mask) = { 0, };

	pr_info("Phy link Validate: port:%d",port);
	/*phylink_warn(pl, "validation of %s with support %*pb and advertisement %*pb failed: %d\n",
			     phy_modes(config.interface),
			     __ETHTOOL_LINK_MODE_MASK_NBITS, phy->supported,
			     __ETHTOOL_LINK_MODE_MASK_NBITS, config.advertising,
			     ret);*/
	pr_info("First supported %*pb",__ETHTOOL_LINK_MODE_MASK_NBITS, supported);
	pr_info("First state->advertising %*pb",__ETHTOOL_LINK_MODE_MASK_NBITS, state->advertising);


	if (phy_interface_mode_is_rgmii(state->interface) || lan937x_is_tx_phy_port(dev,port)) {
		phylink_set(mask, 1000baseT_Full);
		phylink_set(mask, 1000baseT_Half);
		phylink_set(mask, 10baseT_Half);
		phylink_set(mask, 10baseT_Full);
		phylink_set(mask, 100baseT_Half);
		phylink_set(mask, 100baseT_Full);
		phylink_set(mask, Autoneg);
		phylink_set_port_modes(mask);
		phylink_set(mask, Pause);
		phylink_set(mask, Asym_Pause);
	}

	if (!phy_interface_mode_is_8023z(state->interface)) {
		phylink_set(mask, 100baseT_Full);
	}

	bitmap_and(supported, supported, mask,
		   __ETHTOOL_LINK_MODE_MASK_NBITS);
	bitmap_and(state->advertising, state->advertising, mask,
		   __ETHTOOL_LINK_MODE_MASK_NBITS);

	pr_info("last mask %*pb",__ETHTOOL_LINK_MODE_MASK_NBITS, mask);
	pr_info("last supported %*pb",__ETHTOOL_LINK_MODE_MASK_NBITS, supported);
	pr_info("last state->advertising %*pb",__ETHTOOL_LINK_MODE_MASK_NBITS, state->advertising);

	pr_info("last last state->advertising %*pb",__ETHTOOL_LINK_MODE_MASK_NBITS, state->advertising);
}

static int lan937x_phylink_mac_link_state(struct dsa_switch *ds, int port,
			       struct phylink_link_state *state)
{
	struct ksz_device *dev = ds->priv;
	int ret = -EOPNOTSUPP;
	pr_info("lan937x_phylink_mac_link_state: port:%d",port);
	/*if ((phy_interface_mode_is_8023z(state->interface) ||
	     state->interface == PHY_INTERFACE_MODE_SGMII) &&
	     dev->ops->serdes_link_state)
		ret = dev->ops->serdes_link_state(dev, port, state);*/

	return 0;
}
static void lan937x_phylink_mac_config(struct dsa_switch *ds, int port,
			    unsigned int mode,
			    const struct phylink_link_state *state)
{
	/*configure the MAC for the selected mode and state
	For T1 Phy, only 100Base & Full Duplex are only valid, rest of the items are not valid
	For Tx Phy, it */
	
	struct ksz_device *dev = ds->priv;

	pr_info("lan937x_phylink_mac_config: port:%d,mode:%d,speed:%d",port,mode,state->speed);
	pr_info("lan937x_phylink_mac_config: duplex:%d,pause:%d,link:%d",state->duplex,state->pause,state->link);
	pr_info("lan937x_phylink_mac_config: an_enabled:%d,an_complete:%d",state->an_enabled,state->an_complete);
	pr_info("lan937x_phylink_mac_config: advertising:%*pb,lp_advertising:%*pb",__ETHTOOL_LINK_MODE_MASK_NBITS,state->advertising,__ETHTOOL_LINK_MODE_MASK_NBITS,state->lp_advertising);

	/*For mode configuration, valid state members are interface and advertising*/
	if (mode == MLO_AN_PHY)	{
		
	}
	if (mode == MLO_AN_FIXED) {
		
	}

	/*if ((phy_interface_mode_is_8023z(state->interface) ||
	     state->interface == PHY_INTERFACE_MODE_SGMII) &&
	     dev->ops->serdes_config)
		dev->ops->serdes_config(dev, port, mode, state);*/
}

static void lan937x_phylink_mac_an_restart(struct dsa_switch *ds, int port)
{
	struct ksz_device *dev = ds->priv;
	int regval;
	pr_info("lan937x_phylink_mac_an_restart: port:%d",port);

	/*Auto negotiation is not supported for T1 & MII ports*/
	if(!lan937x_is_tx_phy_port(dev,port))
		return;
	
	regval = lan937x_t1_tx_phy_read(dev, port, MII_BMCR);

	regval |= BMCR_ANRESTART;

	lan937x_t1_tx_phy_write(dev, port, MII_BMCR, regval);
}
static void lan937x_phylink_mac_link_down(struct dsa_switch *ds, int port,
			       unsigned int mode,
			       phy_interface_t interface)
{
	struct ksz_device *dev = ds->priv;
	pr_info("lan937x_phylink_mac_link_down: port:%d",port);

	/*If mode is not an in-band negotiation mode (as defined by phylink_autoneg_inband()), 
	force the link down and disable any Energy Efficient Ethernet MAC configuration*/

	/*TODO:Force the link down, for power saving */

	/*100BT_EEE_DIS & 1000BT_EEE_DIS are 1 by default EEE is disabled by default*/

}


static void lan937x_phylink_mac_link_up(struct dsa_switch *ds, int port,
			     unsigned int mode,
			     phy_interface_t interface,
			     struct phy_device *phydev,
			     int speed, int duplex,
			     bool tx_pause, bool rx_pause)
{
	struct ksz_device *dev = ds->priv;

	pr_info("lan937x_phylink_mac_link_up: port:%d,mode:%d,speed:%d,duplex:%d,tx_pause:%d,rx_pause:%d",port,mode,speed,duplex,tx_pause,rx_pause);
	pr_info("interface:%s",phy_modes(interface));

	/*TODO: speed, duplex, tx_pause and rx_pause indicate the finalised link settings, 
	and should be used to configure the MAC block appropriately*/

	/*TODO: If phy is non-NULL, configure Energy Efficient Ethernet by calling phy_init_eee() 
	and perform appropriate MAC configuration for EEE*/
	if (mode == MLO_AN_PHY)
		return;

	if (mode == MLO_AN_FIXED)
		return;

}

static const struct dsa_switch_ops lan937x_switch_ops = {
	.get_tag_protocol	= lan937x_get_tag_protocol,
	.setup			= lan937x_setup,
	.phy_read		= lan937x_phy_read16,
	.phy_write		= lan937x_phy_write16,
	.port_enable		= ksz_enable_port,
	.port_disable		= ksz_disable_port,
	.get_strings		= lan937x_get_strings,
	.get_ethtool_stats	= ksz_get_ethtool_stats,
	.get_sset_count		= ksz_sset_count,
	.port_bridge_join	= ksz_port_bridge_join,
	.port_bridge_leave	= ksz_port_bridge_leave,
	.port_stp_state_set	= lan937x_port_stp_state_set,
	.port_fast_age		= ksz_port_fast_age,
	.port_vlan_filtering	= lan937x_port_vlan_filtering,
	.port_vlan_prepare	= ksz_port_vlan_prepare,
	.port_vlan_add		= lan937x_port_vlan_add,
	.port_vlan_del		= lan937x_port_vlan_del,
	.port_fdb_dump		= lan937x_port_fdb_dump,
	.port_fdb_add		= lan937x_port_fdb_add,
	.port_fdb_del		= lan937x_port_fdb_del,
	.port_mdb_prepare       = ksz_port_mdb_prepare,
	.port_mdb_add           = lan937x_port_mdb_add,
	.port_mdb_del           = lan937x_port_mdb_del,
	.port_mirror_add	= lan937x_port_mirror_add,
	.port_mirror_del	= lan937x_port_mirror_del,
	.port_max_mtu		= lan937x_get_max_mtu,
	.port_change_mtu	= lan937x_change_mtu,
	.phylink_validate	= lan937x_phylink_validate,
	.phylink_mac_link_state	= lan937x_phylink_mac_link_state,
	.phylink_mac_config	= lan937x_phylink_mac_config,
	.phylink_mac_an_restart	= lan937x_phylink_mac_an_restart,
	.phylink_mac_link_down	= lan937x_phylink_mac_link_down,
	.phylink_mac_link_up	= lan937x_phylink_mac_link_up,
};

static u32 lan937x_get_port_addr(int port, int offset)
{
	return PORT_CTRL_ADDR(port, offset);
}

static int lan937x_switch_detect(struct ksz_device *dev)
{
	u32 id32;
	int ret;

	/*Read Chip ID*/
	ret = ksz_read32(dev, REG_CHIP_ID0__1, &id32);
	
	if (ret)
		return ret;

	if (id32 != 0) {
		dev->chip_id = id32;
		pr_info("Chip: 0x%x",id32);
		ret = 0;
	} else {
		ret = -EINVAL;
	}
		
	return ret;
}

struct lan937x_chip_data {
	u32 chip_id;
	const char *dev_name;
	int num_vlans;
	int num_alus;
	int num_statics;
	int cpu_ports;
	int port_cnt;
	int phy_port_cnt;
	int mib_port_cnt;
	u8 tx_phy_logical_prt_n;
	u8 sgmii_port_num;
	u8  logical_addr_map [10];
};


static const struct lan937x_chip_data lan937x_switch_chips[] = {
	{
		.chip_id = 0x00937000,
		.dev_name = "LAN9370",
		.num_vlans = 4096,
		.num_alus = 4096,
		.num_statics = 16,
		.cpu_ports = 0x7F,	/* can be configured as cpu port */
		.port_cnt = 5,		/* total physical port count */
		.mib_port_cnt = 5,
		.phy_port_cnt = 4,
		.tx_phy_logical_prt_n = NO_TX_PHY_PRESENT,
		.sgmii_port_num = NO_SGMII_PRESENT,
						// AFE0  AFE1  AFE3  AFE4  RGMII2 	
		.logical_addr_map = {1, 	2,   3,    4,    5, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
	{
		.chip_id = 0x00937100,
		.dev_name = "LAN9371",
		.num_vlans = 4096,
		.num_alus = 4096,
		.num_statics = 16,
		.cpu_ports = 0x7F,	/* can be configured as cpu port */
		.port_cnt = 6,		/* total physical port count */
		.mib_port_cnt = 6,
		.phy_port_cnt = 4,
		.tx_phy_logical_prt_n = 4, /*Tx Phy logical port number*/
		.sgmii_port_num = NO_SGMII_PRESENT,
						 //AFE0  AFE1  AFE3 TxPHY  RGMII2  RGMII1  	
		.logical_addr_map = {1,   2,   3,   4,  	5,      6,  0xff, 0xff, 0xff, 0xff },
	},
	{
		.chip_id = 0x00937200,
		.dev_name = "LAN9372",
		.num_vlans = 4096,
		.num_alus = 4096,
		.num_statics = 16,
		.cpu_ports = 0x7F,	/* can be configured as cpu port */
		.port_cnt = 8,		/* total port count */
		.mib_port_cnt = 8,
		.phy_port_cnt = 6,
		.tx_phy_logical_prt_n = 4, /*Tx Phy logical port number*/
		.sgmii_port_num = NO_SGMII_PRESENT,
					     //AFE0  AFE1  AFE2  AFE3  AFE4  TxPHY RGMII2  RGMII1  	
		.logical_addr_map = {1, 	2,   8,    3,    7,   4,    5,   	6 , 0xff, 0xff },

	},
	{
		.chip_id = 0x00937300,
		.dev_name = "LAN9373",
		.num_vlans = 4096,
		.num_alus = 4096,
		.num_statics = 16,
		.cpu_ports = 0x7F,	/* can be configured as cpu port */
		.port_cnt = 5,		/* total physical port count */
		.mib_port_cnt = 5,
		.phy_port_cnt = 3,
		.tx_phy_logical_prt_n = NO_TX_PHY_PRESENT,
		.sgmii_port_num = 4,
						//AFE0  AFE1  AFE2  AFE3  AFE4 SGMII  RGMII2  RGMII1	
		.logical_addr_map = {1,  2,   8,    3,    7,     4,     5,   	6,   0xff, 0xff},

	},
	{
		.chip_id = 0x00937400,
		.dev_name = "LAN9374",
		.num_vlans = 4096,
		.num_alus = 4096,
		.num_statics = 16,
		.cpu_ports = 0x7f,	/* can be configured as cpu port */
		.port_cnt = 8,		/* total physical port count */
		.mib_port_cnt = 8,
		.phy_port_cnt = 6,
		.tx_phy_logical_prt_n = NO_TX_PHY_PRESENT,
		.sgmii_port_num = NO_SGMII_PRESENT,
							//AFE0  AFE1  AFE2  AFE3  AFE4  AFE5  	
		.logical_addr_map = {1, 	2,   8,    3,    7,    4,   	
							//RGMII2/Port6/CPU  RGMII1/Port7
							5,  				6			, 0xff, 0xff},
	},
	
};

static int lan937x_switch_init(struct ksz_device *dev)
{
	int i;

	dev->ds->ops = &lan937x_switch_ops;

	for (i = 0; i < ARRAY_SIZE(lan937x_switch_chips); i++) {
		const struct lan937x_chip_data *chip = &lan937x_switch_chips[i];

		if (dev->chip_id == chip->chip_id) {
			dev->name = chip->dev_name;
			dev->num_vlans = chip->num_vlans;
			dev->num_alus = chip->num_alus;
			dev->num_statics = chip->num_statics;
			dev->port_cnt = chip->port_cnt;
			dev->cpu_ports = chip->cpu_ports;
			dev->mib_port_cnt = chip->mib_port_cnt;
			dev->logical_port_map = chip->logical_addr_map;
			dev->phy_port_cnt = chip->phy_port_cnt;
			dev->tx_phy_logical_prt_n = chip->tx_phy_logical_prt_n;
			dev->sgmii_port_num = chip->sgmii_port_num;

			break;
		}
	}

	/* no switch found */
	if (!dev->port_cnt)
		return -ENODEV;


	dev->port_mask = (1 << dev->port_cnt) - 1;

	dev->reg_mib_cnt = SWITCH_COUNTER_NUM;
	dev->mib_cnt = TOTAL_SWITCH_COUNTER_NUM;

	i = dev->mib_port_cnt;
	dev->ports = devm_kzalloc(dev->dev, sizeof(struct ksz_port) * i,
				  GFP_KERNEL);
	if (!dev->ports)
		return -ENOMEM;

	for (i = 0; i < dev->mib_port_cnt; i++) {

		mutex_init(&dev->ports[i].mib.cnt_mutex);
		dev->ports[i].mib.counters =
			devm_kzalloc(dev->dev,
				     sizeof(u64) *
				     (TOTAL_SWITCH_COUNTER_NUM + 1),
				     GFP_KERNEL);
		if (!dev->ports[i].mib.counters)
			return -ENOMEM;

	}

	return 0;
}

static void lan937x_switch_exit(struct ksz_device *dev)
{
	lan937x_reset_switch(dev);
}

static const struct ksz_dev_ops lan937x_dev_ops = {
	.get_port_addr = lan937x_get_port_addr,
	.cfg_port_member = lan937x_cfg_port_member,
	.flush_dyn_mac_table = lan937x_flush_dyn_mac_table,
	.phy_setup = lan937x_phy_setup,
	.port_setup = lan937x_port_setup,
	.r_mib_cnt = lan937x_r_mib_cnt,
	.r_mib_pkt = lan937x_r_mib_pkt,
	.freeze_mib = lan937x_freeze_mib,
	.port_init_cnt = lan937x_port_init_cnt,
	.shutdown = lan937x_reset_switch,
	.detect = lan937x_switch_detect,
	.init = lan937x_switch_init,
	.exit = lan937x_switch_exit,
};

int lan937x_switch_register(struct ksz_device *dev)
{
	return ksz_switch_register(dev, &lan937x_dev_ops);
}
EXPORT_SYMBOL(lan937x_switch_register);

MODULE_AUTHOR("Ganesh Kumar Gurumurthy <GaneshKumar.Gurumurthy@microchip.com>,"
				"Prasanna Vengateshan Varadharajan <Prasanna.VengateshanVaradharajan@microchip.com>");
MODULE_DESCRIPTION("Microchip LAN937x Series Switch DSA Driver");
MODULE_LICENSE("GPL");
