// SPDX-License-Identifier: GPL-2.0
/* Microchip lan937x dev ops functions
 * Copyright (C) 2019-2021 Microchip Technology Inc.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/iopoll.h>
#include <linux/of_mdio.h>
#include <linux/platform_data/microchip-ksz.h>
#include <linux/phy.h>
#include <linux/if_bridge.h>
#include <net/dsa.h>
#include <net/switchdev.h>

#include "lan937x_reg.h"
#include "ksz_common.h"
#include "lan937x_dev.h"

const struct mib_names lan937x_mib_names[] = {
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

struct prt_init {
	int addr;
	u8 mask;
	bool is_set;
};

int lan937x_cfg(struct ksz_device *dev, u32 addr, u8 bits, bool set)
{
	return regmap_update_bits(dev->regmap[0], addr, bits, set ? bits : 0);
}

int lan937x_port_cfg(struct ksz_device *dev, int port, int offset,
		     u8 bits, bool set)
{
	return regmap_update_bits(dev->regmap[0], PORT_CTRL_ADDR(port, offset),
			   bits, set ? bits : 0);
}

int lan937x_cfg32(struct ksz_device *dev, u32 addr, u32 bits, bool set)
{
	return regmap_update_bits(dev->regmap[2], addr, bits, set ? bits : 0);
}

int lan937x_pread8(struct ksz_device *dev, int port, int offset,
		   u8 *data)
{
	return ksz_read8(dev, PORT_CTRL_ADDR(port, offset), data);
}

int lan937x_pread16(struct ksz_device *dev, int port, int offset,
		    u16 *data)
{
	return ksz_read16(dev, PORT_CTRL_ADDR(port, offset), data);
}

int lan937x_pread32(struct ksz_device *dev, int port, int offset,
		    u32 *data)
{
	return ksz_read32(dev, PORT_CTRL_ADDR(port, offset), data);
}

int lan937x_pwrite8(struct ksz_device *dev, int port,
		    int offset, u8 data)
{
	return ksz_write8(dev, PORT_CTRL_ADDR(port, offset), data);
}

int lan937x_pwrite16(struct ksz_device *dev, int port,
		     int offset, u16 data)
{
	return ksz_write16(dev, PORT_CTRL_ADDR(port, offset), data);
}

int lan937x_pwrite32(struct ksz_device *dev, int port,
		     int offset, u32 data)
{
	return ksz_write32(dev, PORT_CTRL_ADDR(port, offset), data);
}

int lan937x_port_cfg32(struct ksz_device *dev, int port, int offset,
		       u32 bits, bool set)
{
	return regmap_update_bits(dev->regmap[2], PORT_CTRL_ADDR(port, offset),
			   bits, set ? bits : 0);
}

void lan937x_cfg_port_member(struct ksz_device *dev, int port,
			     u8 member)
{
	lan937x_pwrite32(dev, port, REG_PORT_VLAN_MEMBERSHIP__4, member);

	dev->ports[port].member = member;
}

static void lan937x_flush_dyn_mac_table(struct ksz_device *dev, int port)
{
	unsigned int value;
	u8 data;

	regmap_update_bits(dev->regmap[0], REG_SW_LUE_CTRL_2,
			   SW_FLUSH_OPTION_M << SW_FLUSH_OPTION_S,
			   SW_FLUSH_OPTION_DYN_MAC << SW_FLUSH_OPTION_S);

	if (port < dev->port_cnt) {
		/* flush individual port */
		lan937x_pread8(dev, port, P_STP_CTRL, &data);
		if (!(data & PORT_LEARN_DISABLE))
			lan937x_pwrite8(dev, port, P_STP_CTRL,
					data | PORT_LEARN_DISABLE);
		lan937x_cfg(dev, S_FLUSH_TABLE_CTRL, SW_FLUSH_DYN_MAC_TABLE, true);

		regmap_read_poll_timeout(dev->regmap[0],
					 S_FLUSH_TABLE_CTRL,
				value, !(value & SW_FLUSH_DYN_MAC_TABLE), 10, 1000);

		lan937x_pwrite8(dev, port, P_STP_CTRL, data);
	} else {
		/* flush all */
		lan937x_cfg(dev, S_FLUSH_TABLE_CTRL, SW_FLUSH_STP_TABLE, true);
	}
}

static void lan937x_r_mib_cnt(struct ksz_device *dev, int port, u16 addr,
			      u64 *cnt)
{
	unsigned int val;
	u32 data;
	int ret;

	/* Enable MIB Counter read*/
	data = MIB_COUNTER_READ;
	data |= (addr << MIB_COUNTER_INDEX_S);
	lan937x_pwrite32(dev, port, REG_PORT_MIB_CTRL_STAT__4, data);

	ret = regmap_read_poll_timeout(dev->regmap[2],
				       PORT_CTRL_ADDR(port,
						      REG_PORT_MIB_CTRL_STAT__4),
					   val, !(val & MIB_COUNTER_READ), 10, 1000);
	/* failed to read MIB. get out of loop */
	if (ret) {
		dev_err(dev->dev, "Failed to get MIB\n");
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

int lan937x_reset_switch(struct ksz_device *dev)
{
	u32 data32;
	u8 data8;
	int rc;

	/* reset switch */
	rc = lan937x_cfg(dev, REG_SW_OPERATION, SW_RESET, true);
	if (rc < 0)
		return rc;

	/* default configuration */
	rc = ksz_read8(dev, REG_SW_LUE_CTRL_1, &data8);
	if (rc < 0)
		return rc;

	data8 = SW_AGING_ENABLE | SW_LINK_AUTO_AGING |
	      SW_SRC_ADDR_FILTER;

	rc = ksz_write8(dev, REG_SW_LUE_CTRL_1, data8);
	if (rc < 0)
		return rc;

	/* disable interrupts */
	rc = ksz_write32(dev, REG_SW_INT_MASK__4, SWITCH_INT_MASK);
	if (rc < 0)
		return rc;

	rc = ksz_write32(dev, REG_SW_PORT_INT_MASK__4, 0xFF);
	if (rc < 0)
		return rc;

	rc = ksz_read32(dev, REG_SW_PORT_INT_STATUS__4, &data32);
	if (rc < 0)
		return rc;

	/* set broadcast storm protection 10% rate */
	rc = regmap_update_bits(dev->regmap[1], REG_SW_MAC_CTRL_2,
				BROADCAST_STORM_RATE,
			   (BROADCAST_STORM_VALUE *
			   BROADCAST_STORM_PROT_RATE) / 100);

	return rc;
}

static int lan937x_switch_detect(struct ksz_device *dev)
{
	u32 id32;
	int ret;

	/* Read Chip ID */
	ret = ksz_read32(dev, REG_CHIP_ID0__1, &id32);

	if (ret)
		return ret;

	if (id32 != 0) {
		dev->chip_id = id32;
		dev_info(dev->dev, "Chip ID: 0x%x", id32);
		ret = 0;
	} else {
		ret = -EINVAL;
	}

	return ret;
}

static void lan937x_switch_exit(struct ksz_device *dev)
{
	lan937x_reset_switch(dev);
}

int lan937x_enable_spi_indirect_access(struct ksz_device *dev)
{
	u16 data16;
	u8 data8;
	int rc;

	rc = ksz_read8(dev, REG_GLOBAL_CTRL_0, &data8);
	if (rc < 0)
		return rc;

	/* Check if PHY register is blocked */
	if (data8 & SW_PHY_REG_BLOCK) {
		/* Enable Phy access through SPI*/
		data8 &= ~SW_PHY_REG_BLOCK;

		rc = ksz_write8(dev, REG_GLOBAL_CTRL_0, data8);
		if (rc < 0)
			return rc;
	}

	rc = ksz_read16(dev, REG_VPHY_SPECIAL_CTRL__2, &data16);
	if (rc < 0)
		return rc;

	/* Allow SPI access */
	data16 |= VPHY_SPI_INDIRECT_ENABLE;
	rc = ksz_write16(dev, REG_VPHY_SPECIAL_CTRL__2, data16);

	return rc;
}

bool lan937x_is_internal_phy_port(struct ksz_device *dev, int port)
{
	/* Check if the port is RGMII */
	if (port == LAN937X_RGMII_1_PORT || port == LAN937X_RGMII_2_PORT)
		return false;

	/* Check if the port is SGMII */
	if (port == LAN937X_SGMII_PORT &&
	    GET_CHIP_ID_LSB(dev->chip_id) == CHIP_ID_73)
		return false;

	return true;
}

static u32 lan937x_get_port_addr(int port, int offset)
{
	return PORT_CTRL_ADDR(port, offset);
}

bool lan937x_is_internal_100BTX_phy_port(struct ksz_device *dev, int port)
{
	/* Check if the port is internal tx phy port */
	if (lan937x_is_internal_phy_port(dev, port) && port == LAN937X_TXPHY_PORT)
		if ((GET_CHIP_ID_LSB(dev->chip_id) == CHIP_ID_71) ||
		    (GET_CHIP_ID_LSB(dev->chip_id) == CHIP_ID_72))
			return true;

	return false;
}

bool lan937x_is_internal_t1_phy_port(struct ksz_device *dev, int port)
{
	/* Check if the port is internal t1 phy port */
	if (lan937x_is_internal_phy_port(dev, port) &&
	    !lan937x_is_internal_100BTX_phy_port(dev, port))
		return true;

	return false;
}

int lan937x_internal_phy_write(struct ksz_device *dev, int addr,
			       int reg, u16 val)
{
	u16 temp, addr_base;
	unsigned int value;
	int rc;

	/* Check for internal phy port */
	if (!lan937x_is_internal_phy_port(dev, addr))
		return 0;

	if (lan937x_is_internal_100BTX_phy_port(dev, addr))
		addr_base = REG_PORT_TX_PHY_CTRL_BASE;
	else
		addr_base = REG_PORT_T1_PHY_CTRL_BASE;

	temp = PORT_CTRL_ADDR(addr, (addr_base + (reg << 2)));

	rc = ksz_write16(dev, REG_VPHY_IND_ADDR__2, temp);
	if (rc < 0)
		return rc;

	/* Write the data to be written to the VPHY reg */
	rc = ksz_write16(dev, REG_VPHY_IND_DATA__2, val);
	if (rc < 0)
		return rc;

	/* Write the Write En and Busy bit */
	rc = ksz_write16(dev, REG_VPHY_IND_CTRL__2, (VPHY_IND_WRITE
				| VPHY_IND_BUSY));
	if (rc < 0)
		return rc;

	rc = regmap_read_poll_timeout(dev->regmap[1],
				      REG_VPHY_IND_CTRL__2,
				value, !(value & VPHY_IND_BUSY), 10, 1000);

	/* failed to write phy register. get out of loop */
	if (rc < 0) {
		dev_err(dev->dev, "Failed to write phy register\n");
		return rc;
	}

	return 0;
}

int lan937x_internal_phy_read(struct ksz_device *dev, int addr,
			      int reg, u16 *val)
{
	u16 temp, addr_base;
	unsigned int value;
	int rc;

	/* Check for internal phy port */
	if (!lan937x_is_internal_phy_port(dev, addr))
		return 0;

	if (lan937x_is_internal_100BTX_phy_port(dev, addr))
		addr_base = REG_PORT_TX_PHY_CTRL_BASE;
	else
		addr_base = REG_PORT_T1_PHY_CTRL_BASE;

	/* get register address based on the logical port */
	temp = PORT_CTRL_ADDR(addr, (addr_base + (reg << 2)));

	rc = ksz_write16(dev, REG_VPHY_IND_ADDR__2, temp);
	if (rc < 0)
		return rc;

	/* Write Read and Busy bit to start the transaction*/
	rc = ksz_write16(dev, REG_VPHY_IND_CTRL__2, VPHY_IND_BUSY);
	if (rc < 0)
		return rc;

	rc = regmap_read_poll_timeout(dev->regmap[1],
				      REG_VPHY_IND_CTRL__2,
				value, !(value & VPHY_IND_BUSY), 10, 1000);

	/*  failed to read phy register. get out of loop */
	if (rc < 0) {
		dev_err(dev->dev, "Failed to read phy register\n");
		return rc;
	}

	/* Read the VPHY register which has the PHY data*/
	rc = ksz_read16(dev, REG_VPHY_IND_DATA__2, val);

	return rc;
}

static void lan937x_set_gbit(struct ksz_device *dev, bool gbit, u8 *data)
{
	if (gbit)
		*data &= ~PORT_MII_NOT_1GBIT;
	else
		*data |= PORT_MII_NOT_1GBIT;
}

void lan937x_port_setup(struct ksz_device *dev, int port, bool cpu_port)
{
	struct ksz_port *p = &dev->ports[port];
	u8 data8, member;

	/* enable tag tail for host port */
	if (cpu_port) {
		lan937x_port_cfg(dev, port, REG_PORT_CTRL_0, PORT_TAIL_TAG_ENABLE,
				 true);
		/* Enable jumbo packet in host port so that frames are not
		 * counted as oversized.
		 */
		lan937x_port_cfg(dev, port, REG_PORT_MAC_CTRL_0, PORT_JUMBO_PACKET,
				 true);
		lan937x_pwrite16(dev, port, REG_PORT_MTU__2, FR_SIZE_CPU_PORT);
	}

	lan937x_port_cfg(dev, port, REG_PORT_MAC_CTRL_0, PORT_FR_CHK_LENGTH,
			 false);

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

	if (!lan937x_is_internal_phy_port(dev, port)) {
		/* force flow control off*/
		lan937x_port_cfg(dev, port, REG_PORT_XMII_CTRL_0,
				 PORT_FORCE_TX_FLOW_CTRL | PORT_FORCE_RX_FLOW_CTRL,
			     false);

		lan937x_pread8(dev, port, REG_PORT_XMII_CTRL_1, &data8);

		/* clear MII selection & set it based on interface later */
		data8 &= ~PORT_MII_SEL_M;

		/* configure MAC based on p->interface */
		switch (p->interface) {
		case PHY_INTERFACE_MODE_MII:
			lan937x_set_gbit(dev, false, &data8);
			data8 |= PORT_MII_SEL;
			break;
		case PHY_INTERFACE_MODE_RMII:
			lan937x_set_gbit(dev, false, &data8);
			data8 |= PORT_RMII_SEL;
			break;
		default:
			lan937x_set_gbit(dev, true, &data8);
			data8 |= PORT_RGMII_SEL;

			data8 &= ~PORT_RGMII_ID_IG_ENABLE;
			data8 &= ~PORT_RGMII_ID_EG_ENABLE;

			if (p->interface == PHY_INTERFACE_MODE_RGMII_ID ||
			    p->interface == PHY_INTERFACE_MODE_RGMII_RXID)
				data8 |= PORT_RGMII_ID_IG_ENABLE;

			if (p->interface == PHY_INTERFACE_MODE_RGMII_ID ||
			    p->interface == PHY_INTERFACE_MODE_RGMII_TXID)
				data8 |= PORT_RGMII_ID_EG_ENABLE;
			break;
		}
		lan937x_pwrite8(dev, port, REG_PORT_XMII_CTRL_1, data8);
	}

	if (cpu_port)
		member = dev->port_mask;
	else
		member = dev->host_mask | p->vid_member;

	lan937x_cfg_port_member(dev, port, member);
}

static int lan937x_sw_mdio_read(struct mii_bus *bus, int addr, int regnum)
{
	struct ksz_device *dev = bus->priv;
	u16 val;
	int rc;

	rc = lan937x_internal_phy_read(dev, addr, regnum, &val);
	if (rc < 0)
		return rc;

	return val;
}

static int lan937x_sw_mdio_write(struct mii_bus *bus, int addr, int regnum, u16 val)
{
	struct ksz_device *dev = bus->priv;

	return lan937x_internal_phy_write(dev, addr, regnum, val);
}

static int lan937x_mdio_register(struct dsa_switch *ds)
{
	struct ksz_device *dev = ds->priv;
	int ret;

	dev->mdio_np = of_get_compatible_child(ds->dev->of_node, "microchip,lan937x-mdio");

	if (!dev->mdio_np) {
		dev_err(ds->dev, "no MDIO bus node\n");
		return -ENODEV;
	}

	ds->slave_mii_bus = devm_mdiobus_alloc(ds->dev);

	if (!ds->slave_mii_bus)
		return -ENOMEM;

	ds->slave_mii_bus->priv = ds->priv;
	ds->slave_mii_bus->read = lan937x_sw_mdio_read;
	ds->slave_mii_bus->write = lan937x_sw_mdio_write;
	ds->slave_mii_bus->name = "lan937x slave smi";
	snprintf(ds->slave_mii_bus->id, MII_BUS_ID_SIZE, "SMI-%d",
		 ds->index);
	ds->slave_mii_bus->parent = ds->dev;
	ds->slave_mii_bus->phy_mask = ~ds->phys_mii_mask;

	ret = of_mdiobus_register(ds->slave_mii_bus, dev->mdio_np);

	if (ret) {
		dev_err(ds->dev, "unable to register MDIO bus %s\n",
			ds->slave_mii_bus->id);
		of_node_put(dev->mdio_np);
		return ret;
	}

	return 0;
}

static int lan937x_switch_init(struct ksz_device *dev)
{
	int i, ret;

	dev->ds->ops = &lan937x_switch_ops;

	/* Check device tree */
	ret = lan937x_check_device_id(dev);

	if (ret)
		return ret;

	dev->port_mask = (1 << dev->port_cnt) - 1;

	dev->reg_mib_cnt = SWITCH_COUNTER_NUM;
	dev->mib_cnt = ARRAY_SIZE(lan937x_mib_names);

	dev->ports = devm_kzalloc(dev->dev,
				  dev->port_cnt * sizeof(struct ksz_port),
				  GFP_KERNEL);
	if (!dev->ports)
		return -ENOMEM;

	for (i = 0; i < dev->port_cnt; i++) {
		mutex_init(&dev->ports[i].mib.cnt_mutex);
		dev->ports[i].mib.counters =
			devm_kzalloc(dev->dev,
				     sizeof(u64) *
				     (dev->mib_cnt + 1),
				     GFP_KERNEL);
		if (!dev->ports[i].mib.counters)
			return -ENOMEM;
	}

	/* set the real number of ports */
	dev->ds->num_ports = dev->port_cnt;
	return 0;
}

static int lan937x_init(struct ksz_device *dev)
{
	int rc;

	rc = lan937x_switch_init(dev);
	if (rc < 0) {
		dev_err(dev->dev, "failed to initialize the switch");
		return rc;
	}

	/* enable Indirect Access from SPI to the VPHY registers */
	rc = lan937x_enable_spi_indirect_access(dev);
	if (rc < 0) {
		dev_err(dev->dev, "failed to enable spi indirect access");
		return rc;
	}

	rc = lan937x_mdio_register(dev->ds);
	if (rc < 0) {
		dev_err(dev->dev, "failed to register the mdio");
		return rc;
	}

	return 0;
}

const struct ksz_dev_ops lan937x_dev_ops = {
	.get_port_addr = lan937x_get_port_addr,
	.cfg_port_member = lan937x_cfg_port_member,
	.flush_dyn_mac_table = lan937x_flush_dyn_mac_table,
	.port_setup = lan937x_port_setup,
	.r_mib_cnt = lan937x_r_mib_cnt,
	.r_mib_pkt = lan937x_r_mib_pkt,
	.port_init_cnt = lan937x_port_init_cnt,
	.shutdown = lan937x_reset_switch,
	.detect = lan937x_switch_detect,
	.init = lan937x_init,
	.exit = lan937x_switch_exit,
};
