// SPDX-License-Identifier: GPL-2.0
/* Microchip lan937x dev ops functions
 * Copyright (C) 2019-2020 Microchip Technology Inc.
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
#include "lan937x_dev.h"

const struct mib_names lan937x_mib_names[TOTAL_SWITCH_COUNTER_NUM] = {
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

static const struct lan937x_chip_data lan937x_switch_chips[] = {
	{
		.chip_id = 0x00937000,
		.dev_name = "LAN9370",
		.num_vlans = 4096,
		.num_alus = 1024,
		.num_statics = 256,
		/* can be configured as cpu port */
		.cpu_ports = 0x10,
		/* total physical port count */
		.port_cnt = 5,
		.phy_port_cnt = 4,
	},
	{
		.chip_id = 0x00937100,
		.dev_name = "LAN9371",
		.num_vlans = 4096,
		.num_alus = 1024,
		.num_statics = 256,
		/* can be configured as cpu port */
		.cpu_ports = 0x30,
		/* total physical port count */
		.port_cnt = 6,
		.phy_port_cnt = 4,
	},
	{
		.chip_id = 0x00937200,
		.dev_name = "LAN9372",
		.num_vlans = 4096,
		.num_alus = 1024,
		.num_statics = 256,
		/* can be configured as cpu port */
		.cpu_ports = 0x30,
		/* total port count */
		.port_cnt = 8,
		.phy_port_cnt = 6,
	},
	{
		.chip_id = 0x00937300,
		.dev_name = "LAN9373",
		.num_vlans = 4096,
		.num_alus = 1024,
		.num_statics = 256,
		/* can be configured as cpu port */
		.cpu_ports = 0x38,
		/* total physical port count */
		.port_cnt = 5,
		.phy_port_cnt = 3,
	},
	{
		.chip_id = 0x00937400,
		.dev_name = "LAN9374",
		.num_vlans = 4096,
		.num_alus = 1024,
		.num_statics = 256,
		/* can be configured as cpu port */
		.cpu_ports = 0x30,
		/* total physical port count */
		.port_cnt = 8,
		.phy_port_cnt = 6,
	},

};

void lan937x_cfg(struct ksz_device *dev, u32 addr, u8 bits, bool set)
{
	regmap_update_bits(dev->regmap[0], addr, bits, set ? bits : 0);
}

void lan937x_port_cfg(struct ksz_device *dev, int port, int offset,
		      u8 bits, bool set)
{
	regmap_update_bits(dev->regmap[0], PORT_CTRL_ADDR(port, offset),
			   bits, set ? bits : 0);
}

void lan937x_cfg32(struct ksz_device *dev, u32 addr, u32 bits, bool set)
{
	regmap_update_bits(dev->regmap[2], addr, bits, set ? bits : 0);
}

void lan937x_pread8(struct ksz_device *dev, int port, int offset,
		    u8 *data)
{
	ksz_read8(dev, PORT_CTRL_ADDR(port, offset), data);
}

void lan937x_pread16(struct ksz_device *dev, int port, int offset,
		     u16 *data)
{
	ksz_read16(dev, PORT_CTRL_ADDR(port, offset), data);
}

void lan937x_pread32(struct ksz_device *dev, int port, int offset,
		     u32 *data)
{
	ksz_read32(dev, PORT_CTRL_ADDR(port, offset), data);
}

void lan937x_pwrite8(struct ksz_device *dev, int port,
		     int offset, u8 data)
{
	ksz_write8(dev, PORT_CTRL_ADDR(port, offset), data);
}

void lan937x_pwrite16(struct ksz_device *dev, int port,
		      int offset, u16 data)
{
	ksz_write16(dev, PORT_CTRL_ADDR(port, offset), data);
}

void lan937x_pwrite32(struct ksz_device *dev, int port,
		      int offset, u32 data)
{
	ksz_write32(dev, PORT_CTRL_ADDR(port, offset), data);
}

void lan937x_port_cfg32(struct ksz_device *dev, int port, int offset,
			u32 bits, bool set)
{
	regmap_update_bits(dev->regmap[2], PORT_CTRL_ADDR(port, offset),
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
				       PORT_CTRL_ADDR(port,
						      REG_PORT_MIB_CTRL_STAT__4),
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

int lan937x_reset_switch(struct ksz_device *dev)
{
	u32 data32;
	u8 data8;

	/* reset switch */
	lan937x_cfg(dev, REG_SW_OPERATION, SW_RESET, true);

	/* default configuration */
	ksz_read8(dev, REG_SW_LUE_CTRL_1, &data8);
	data8 = SW_AGING_ENABLE | SW_LINK_AUTO_AGING |
	      SW_SRC_ADDR_FILTER;
	ksz_write8(dev, REG_SW_LUE_CTRL_1, data8);

	/* disable interrupts */
	ksz_write32(dev, REG_SW_INT_MASK__4, SWITCH_INT_MASK);
	ksz_write32(dev, REG_SW_PORT_INT_MASK__4, 0xFF);
	ksz_read32(dev, REG_SW_PORT_INT_STATUS__4, &data32);

	/* set broadcast storm protection 10% rate */
	regmap_update_bits(dev->regmap[1], REG_SW_MAC_CTRL_2,
			   BROADCAST_STORM_RATE,
			   (BROADCAST_STORM_VALUE *
			   BROADCAST_STORM_PROT_RATE) / 100);

	return 0;
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
	int ret;

	ret = ksz_read8(dev, REG_GLOBAL_CTRL_0, &data8);

	if (ret)
		return ret;

	/* Check if PHY register is blocked */
	if (data8 & SW_PHY_REG_BLOCK) {
		/* Enable Phy access through SPI*/
		data8 &= ~SW_PHY_REG_BLOCK;
		ret = ksz_write8(dev, REG_GLOBAL_CTRL_0, data8);

		if (ret)
			return ret;
	}

	ret = ksz_read16(dev, REG_VPHY_SPECIAL_CTRL__2, &data16);

	if (ret)
		return ret;

	/* If already the access is not enabled go ahead and allow SPI access */
	if (!(data16 & VPHY_SPI_INDIRECT_ENABLE)) {
		data16 |= VPHY_SPI_INDIRECT_ENABLE;
		ret = ksz_write16(dev, REG_VPHY_SPECIAL_CTRL__2, data16);

		if (ret)
			return ret;
	}

	return ret;
}

bool lan937x_is_internal_phy_port(struct ksz_device *dev, int port)
{
	if (port == LAN937X_RGMII_1_PORT || port == LAN937X_RGMII_2_PORT)
		return false;

	if (port == LAN937X_SGMII_PORT &&
	    GET_CHIP_ID_LSB(dev->chip_id) == CHIP_ID_73)
		return false;

	return true;
}

u32 lan937x_get_port_addr(int port, int offset)
{
	return PORT_CTRL_ADDR(port, offset);
}

bool lan937x_is_internal_tx_phy_port(struct ksz_device *dev, int port)
{
	if (lan937x_is_internal_phy_port(dev, port) && port == LAN937X_SGMII_PORT)
		if ((GET_CHIP_ID_LSB(dev->chip_id) == CHIP_ID_71) ||
		    (GET_CHIP_ID_LSB(dev->chip_id) == CHIP_ID_72))
			return true;

	return false;
}

int lan937x_t1_tx_phy_write(struct ksz_device *dev, int addr,
			    int reg, u16 val)
{
	u16 temp, addr_base;
	unsigned int value;
	int ret;

	/* Check for phy port */
	if (!lan937x_is_internal_phy_port(dev, addr))
		return 0;

	if (ret) {
		dev_dbg(dev->dev, "Failed to enable VPHY indirect access from SPI");
		return ret;
	}

	if (lan937x_is_internal_tx_phy_port(dev, addr))
		addr_base = REG_PORT_TX_PHY_CTRL_BASE;
	else
		addr_base = REG_PORT_T1_PHY_CTRL_BASE;

	temp = PORT_CTRL_ADDR(addr, (addr_base + (reg << 2)));

	ksz_write16(dev, REG_VPHY_IND_ADDR__2, temp);

	/* Write the data to be written to the VPHY reg */
	ksz_write16(dev, REG_VPHY_IND_DATA__2, val);

	/* Write the Write En and Busy bit */
	ksz_write16(dev, REG_VPHY_IND_CTRL__2, (VPHY_IND_WRITE
				| VPHY_IND_BUSY));

	ret = regmap_read_poll_timeout(dev->regmap[1],
				       REG_VPHY_IND_CTRL__2,
				value, !(value & VPHY_IND_BUSY), 10, 1000);

	/* failed to write phy register. get out of loop */
	if (ret) {
		dev_dbg(dev->dev, "Failed to write phy register\n");
		return ret;
	}

	return 0;
}

int lan937x_t1_tx_phy_read(struct ksz_device *dev, int addr,
			   int reg, u16 *val)
{
	u16 temp, addr_base;
	unsigned int value;
	int ret;

	/* No real PHY after this. Simulate the PHY.
	 * A fixed PHY can be setup in the device tree, but this function is
	 * still called for that port during initialization.
	 * For RGMII PHY there is no way to access it so the fixed PHY should
	 * be used.  For SGMII PHY the supporting code will be added later.
	 */

	if (!lan937x_is_internal_phy_port(dev, addr)) {
		struct ksz_port *p = &dev->ports[addr];

		switch (reg) {
		case MII_BMCR:
			*val = 0x1140;
			break;
		case MII_BMSR:
			*val = 0x796d;
			break;
		case MII_PHYSID1:
			*val = 0x0022;
			break;
		case MII_PHYSID2:
			*val = 0x1631;
			break;
		case MII_ADVERTISE:
			*val = 0x05e1;
			break;
		case MII_LPA:
			*val = 0xc5e1;
			break;
		case MII_CTRL1000:
			*val = 0x0700;
			break;
		case MII_STAT1000:
			if (p->phydev.speed == SPEED_1000)
				*val = 0x3800;
			else
				*val = 0;
			break;
		}
	} else {
		if (ret) {
			dev_dbg(dev->dev, "Failed to enable VPHY indirect access from SPI");
			return ret;
		}

		pr_info("prt:%d,rg:%x", addr,reg);
		if (lan937x_is_internal_tx_phy_port(dev, addr))
			addr_base = REG_PORT_TX_PHY_CTRL_BASE;
		else
			addr_base = REG_PORT_T1_PHY_CTRL_BASE;

		/* get register address based on the logical port */
		temp = PORT_CTRL_ADDR(addr, (addr_base + (reg << 2)));

		ksz_write16(dev, REG_VPHY_IND_ADDR__2, temp);
		/* Write Read and Busy bit to start the transaction*/
		ksz_write16(dev, REG_VPHY_IND_CTRL__2, VPHY_IND_BUSY);

		ret = regmap_read_poll_timeout(dev->regmap[1],
					       REG_VPHY_IND_CTRL__2,
					value, !(value & VPHY_IND_BUSY), 10, 1000);

		/*  failed to read phy register. get out of loop */
		if (ret) {
			dev_dbg(dev->dev, "Failed to read phy register\n");
			return ret;
		}
		/* Read the VPHY register which has the PHY data*/
		ksz_read16(dev, REG_VPHY_IND_DATA__2, val);
	}

	return 0;
}

void lan937x_t1_tx_phy_mod_bits(struct ksz_device *dev, int port,
				int reg, u16 val, bool set)
{
	u16 data;

	/* read phy register */
	lan937x_t1_tx_phy_read(dev, port, reg, &data);

	/* set/clear the data */
	if (set)
		data |= val;
	else
		data &= ~val;

	/* write phy register */
	lan937x_t1_tx_phy_write(dev, port, reg, data);
}

static u32 lan937x_tx_phy_bank_read(struct ksz_device *dev, int port,
				    u8 bank, u8 reg)
{
	u16 data_hi;
	u16 data_lo;
	u16 ctrl;

	ctrl = ((u16)bank & TX_REG_BANK_SEL_M) << TX_REG_BANK_SEL_S;
	ctrl |= ((u16)reg & TX_READ_ADDR_M) << TX_READ_ADDR_S;

	/* write ctrl register with appropriate value */
	ctrl |= TX_IND_DATA_READ;
	lan937x_t1_tx_phy_write(dev, port, REG_PORT_TX_IND_CTRL, ctrl);

	/* if bank is WOL value to be written again to reflect correct bank */
	if (bank == TX_REG_BANK_SEL_WOL)
		lan937x_t1_tx_phy_write(dev, port, REG_PORT_TX_IND_CTRL, ctrl);

	/* read data hi & low value */
	lan937x_t1_tx_phy_read(dev, port, REG_PORT_TX_READ_DATA_LO, &data_lo);
	lan937x_t1_tx_phy_read(dev, port, REG_PORT_TX_READ_DATA_HI, &data_hi);

	return ((u32)data_hi << 16) | data_lo;
}

static void lan937x_tx_phy_bank_write(struct ksz_device *dev, int port,
				      u8 bank, u8 reg, u16 val)
{
	u16 ctrl;

	/* write the value */
	lan937x_t1_tx_phy_write(dev, port, REG_PORT_TX_WRITE_DATA, val);
	ctrl = ((u16)bank & TX_REG_BANK_SEL_M) << TX_REG_BANK_SEL_S;
	ctrl |= (reg & TX_WRITE_ADDR_M);

	if (bank == TX_REG_BANK_SEL_DSP || bank == TX_REG_BANK_SEL_BIST)
		ctrl |= TX_TEST_MODE;
	/* write ctrl register with write operation bit set */
	ctrl |= TX_IND_DATA_WRITE;
	lan937x_t1_tx_phy_write(dev, port, REG_PORT_TX_IND_CTRL, ctrl);
}

static void tx_phy_setup(struct ksz_device *dev, int port)
{
	u16 data_lo;

	lan937x_t1_tx_phy_read(dev, port, REG_PORT_TX_SPECIAL_MODES, &data_lo);
	/* Need to change configuration from 6 to other value. */
	data_lo &= TX_PHYADDR_M;

	lan937x_t1_tx_phy_write(dev, port, REG_PORT_TX_SPECIAL_MODES, data_lo);

    /* Need to toggle test_mode bit to enable DSP access. */
	lan937x_t1_tx_phy_write(dev, port, REG_PORT_TX_IND_CTRL, TX_TEST_MODE);
	lan937x_t1_tx_phy_write(dev, port, REG_PORT_TX_IND_CTRL, 0);

	/* Note TX_TEST_MODE is then always enabled so this is not required. */
	lan937x_t1_tx_phy_write(dev, port, REG_PORT_TX_IND_CTRL, TX_TEST_MODE);
	lan937x_t1_tx_phy_write(dev, port, REG_PORT_TX_IND_CTRL, 0);
}

static void tx_phy_port_init(struct ksz_device *dev, int port)
{
	u32 data;

	/* Software reset. */
	lan937x_t1_tx_phy_mod_bits(dev, port, MII_BMCR, BMCR_RESET, true);

	/* tx phy setup */
	tx_phy_setup(dev, port);

	/* tx phy init sequence */
	data = lan937x_tx_phy_bank_read(dev, port, TX_REG_BANK_SEL_VMDAC,
					TX_VMDAC_ZQ_CAL_CTRL);
	data |= TX_START_ZQ_CAL;
	lan937x_tx_phy_bank_write(dev, port, TX_REG_BANK_SEL_VMDAC,
				  TX_VMDAC_ZQ_CAL_CTRL, data);
	lan937x_tx_phy_bank_write(dev, port, TX_REG_BANK_SEL_VMDAC, TX_VMDAC_CTRL0,
				  TX_VMDAC_CTRL0_VAL);
	lan937x_tx_phy_bank_write(dev, port, TX_REG_BANK_SEL_VMDAC, TX_VMDAC_CTRL1,
				  TX_VMDAC_CTRL1_VAL);
	data = lan937x_tx_phy_bank_read(dev, port, TX_REG_BANK_SEL_VMDAC,
					TX_VMDAC_MISC_PCS_CTRL0);
	data |= TX_MISC_PCS_CTRL0_13;
	lan937x_tx_phy_bank_write(dev, port, TX_REG_BANK_SEL_VMDAC,
				  TX_VMDAC_MISC_PCS_CTRL0, data);

	lan937x_tx_phy_bank_write(dev, port, TX_REG_BANK_SEL_DSP, TX_DSP_DCBLW,
				  TX_DSP_DCBLW_VAL);
	lan937x_tx_phy_bank_write(dev, port, TX_REG_BANK_SEL_DSP, TX_DSP_A11_CONFIG,
				  TX_DSP_A11_CONFIG_VAL);
	lan937x_tx_phy_bank_write(dev, port, TX_REG_BANK_SEL_DSP, TX_DSP_A10_CONFIG,
				  TX_DSP_A10_CONFIG_VAL);
	data = lan937x_tx_phy_bank_read(dev, port, TX_REG_BANK_SEL_DSP,
					TX_DSP_A5_CONFIG);
	data &= ~(TX_A5_TXCLKPHSEL_M << TX_A5_TXCLKPHSEL_S);
	data |= (TX_A5_TXCLK_2_NS << TX_A5_TXCLKPHSEL_S);
	lan937x_tx_phy_bank_write(dev, port, TX_REG_BANK_SEL_VMDAC,
				  TX_DSP_A5_CONFIG, data);
}

static void lan937x_t1_phy_bank_sel(struct ksz_device *dev, int port,
				    u8 bank, u8 addr, u16 oper)
{
	u16 data, ctrl;
	u8 prev_bank;

	lan937x_t1_tx_phy_read(dev, port, REG_PORT_T1_EXT_REG_CTRL, &ctrl);
	prev_bank = (ctrl >> T1_REG_BANK_SEL_S) & T1_REG_BANK_SEL_M;
	ctrl &= T1_PCS_STS_CNT_RESET;

	data = ((u16)bank & T1_REG_BANK_SEL_M) << T1_REG_BANK_SEL_S;
	data |= (addr & T1_REG_ADDR_M);
	data |= oper;
	data |= ctrl;

	/* if the bank is DSP need to write twice */
	if (bank != prev_bank && bank == T1_REG_BANK_SEL_DSP) {
		u16 t = data & ~T1_REG_ADDR_M;

		t &= ~oper;
		t |= T1_IND_DATA_READ;

		/* Need to write twice to access correct register. */
		lan937x_t1_tx_phy_write(dev, port, REG_PORT_T1_EXT_REG_CTRL, t);
	}

	lan937x_t1_tx_phy_write(dev, port, REG_PORT_T1_EXT_REG_CTRL, data);
}

static void lan937x_t1_phy_bank_read(struct ksz_device *dev, int port,
				     u8 bank, u8 addr, u16 *val)
{
	/* select the bank for read operation */
	lan937x_t1_phy_bank_sel(dev, port, bank, addr, T1_IND_DATA_READ);

	/* read bank */
	lan937x_t1_tx_phy_read(dev, port, REG_PORT_T1_EXT_REG_RD_DATA, val);
}

static void lan937x_t1_phy_bank_write(struct ksz_device *dev, int port,
				      u8 bank, u8 addr, u16 val)
{
	/* write the data to be written into the bank */
	lan937x_t1_tx_phy_write(dev, port, REG_PORT_T1_EXT_REG_WR_DATA, val);
	/* select the bank for write operation */
	lan937x_t1_phy_bank_sel(dev, port, bank, addr, T1_IND_DATA_WRITE);
}

static void t1_phy_port_init(struct ksz_device *dev, int port)
{
	u16 val;

	/* Power down the PHY. */
	lan937x_t1_tx_phy_mod_bits(dev, port, REG_PORT_T1_PHY_BASIC_CTRL,
				   PORT_T1_POWER_DOWN, true);

	/* Make sure software initialization sequence is used. */
	lan937x_t1_tx_phy_mod_bits(dev, port, REG_PORT_T1_POWER_DOWN_CTRL,
				   T1_HW_INIT_SEQ_ENABLE, false);

	/* Configure master/slave. true=master, false=slave */
	lan937x_t1_tx_phy_mod_bits(dev, port, REG_PORT_T1_PHY_M_CTRL,
				   PORT_T1_M_CFG, true);

	/* Software reset. */
	lan937x_t1_tx_phy_mod_bits(dev, port, REG_PORT_T1_PHY_BASIC_CTRL,
				   PORT_T1_PHY_RESET, true);

	/* cdr mode */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x34, 0x0001);

	/* setting lock 3 mufac */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x1B, 0x0B6A);

	/* setting pos lock mufac */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x1C, 0x0B6B);

	/* setting lock1 win config */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x11, 0x2A74);

	/* setting lock2 win config */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x12, 0x2B70);

	/* setting lock3 win config */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x13, 0x2B6C);

	/* setting plock */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x14, 0x2974);

	/* setting lock threshold config */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x16, 0xC803);

	/* slv fd stg bmp */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x24, 0x0002);

	/* Blw BW config lock stage 3 */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x2A, 0x003C);

	/* Blw BW config */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x56, 0x3CAA);

	/* Blw BW config */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x57, 0x1E47);

	/* Blw BW config */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x58, 0x1E4E);

	/* Blw BW config */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x59, 0x1E56);

	/* disable scrambler lock timeout 0-disable 1- enable */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x32, 0x00F6);

	/* reducing energy detect partial timeout */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x3C, 0x64CC);

	lan937x_t1_tx_phy_read(dev, port, 0x0A, &val);

	if ((val & 0x4000) == 0)
		lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_PCS, 0x26, 0x1770);

	/* pwr dn Config */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x04, 0x16D7);

	/* scrambler lock hysterisis */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_PCS, 0x00, 0x7FFF);

	/* eq status timer control */
	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_PCS, 0x02, 0x07FF);

	/* MANUAL STD POLARITY */
	lan937x_t1_tx_phy_write(dev, port, 0x17, 0x0080);

	/* disable master mode energy detect */
	lan937x_t1_tx_phy_mod_bits(dev, port, 0x10, 0x0040, false);

	lan937x_t1_phy_bank_read(dev, port, T1_REG_BANK_SEL_AFE, 0x0B, &val);

	val &= ~0x001E;
	/* increase tx amp to 0b0101 */
	val |= 0x000A;

	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_AFE, 0x0B, val);

	lan937x_t1_phy_bank_write(dev, port, T1_REG_BANK_SEL_DSP, 0x25, 0x23E0);

	/* Set HW_INIT */
	lan937x_t1_tx_phy_mod_bits(dev, port, REG_PORT_T1_POWER_DOWN_CTRL,
				   T1_HW_INIT_SEQ_ENABLE, true);

	/* Power up the PHY. */
	lan937x_t1_tx_phy_mod_bits(dev, port, REG_PORT_T1_PHY_BASIC_CTRL,
				   PORT_T1_POWER_DOWN, false);
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
	u16 data16;

	/* enable tag tail for host port */
	if (cpu_port) {
		lan937x_port_cfg(dev, port, REG_PORT_CTRL_0, PORT_TAIL_TAG_ENABLE,
				 true);
		/* Enable jumbo packet in host port so that frames are not
		 * counted as oversized.
		 */
		lan937x_port_cfg(dev, port, REG_PORT_MAC_CTRL_0, PORT_JUMBO_PACKET,
				 true);
		lan937x_pwrite16(dev, port, REG_PORT_MTU__2, 1540);
	}

	lan937x_port_cfg(dev, port, REG_PORT_MAC_CTRL_0, PORT_FR_CHK_LENGTH, false);

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

	if (lan937x_is_internal_phy_port(dev, port)) {
		if (lan937x_is_internal_tx_phy_port(dev, port))
			tx_phy_port_init(dev, port);
		else
			t1_phy_port_init(dev, port);

	} else {
		/* force flow control off*/
		lan937x_port_cfg(dev, port, REG_PORT_XMII_CTRL_0,
				 PORT_FORCE_TX_FLOW_CTRL | PORT_FORCE_RX_FLOW_CTRL,
			     false);

		/* configure MAC to 1G & RGMII mode  */
		lan937x_pread8(dev, port, REG_PORT_XMII_CTRL_1, &data8);

		switch (p->interface) {
		case PHY_INTERFACE_MODE_MII:
			lan937x_set_xmii(dev, 0, &data8);
			lan937x_set_gbit(dev, false, &data8);
			data8 |= PORT_MII_NOT_1GBIT;
			p->phydev.speed = SPEED_100;
			break;
		case PHY_INTERFACE_MODE_RMII:
			lan937x_set_xmii(dev, 1, &data8);
			lan937x_set_gbit(dev, false, &data8);
			data8 |= PORT_MII_NOT_1GBIT;
			p->phydev.speed = SPEED_100;
			break;
		default:
			lan937x_set_xmii(dev, 3, &data8);
			lan937x_set_gbit(dev, true, &data8);
			data8 |= PORT_MII_NOT_1GBIT;
			data8 &= ~PORT_RGMII_ID_IG_ENABLE;
			data8 &= ~PORT_RGMII_ID_EG_ENABLE;
			if (p->interface == PHY_INTERFACE_MODE_RGMII_ID ||
			    p->interface == PHY_INTERFACE_MODE_RGMII_RXID)
				data8 |= PORT_RGMII_ID_IG_ENABLE;
			if (p->interface == PHY_INTERFACE_MODE_RGMII_ID ||
			    p->interface == PHY_INTERFACE_MODE_RGMII_TXID)
				data8 |= PORT_RGMII_ID_EG_ENABLE;
			p->phydev.speed = SPEED_1000;
			break;
		}
		lan937x_pwrite8(dev, port, REG_PORT_XMII_CTRL_1, data8);
		p->phydev.duplex = 1;
	}
	mutex_lock(&dev->dev_mutex);
	if (cpu_port)
		member = dev->port_mask;
	else
		member = dev->host_mask | p->vid_member;
	mutex_unlock(&dev->dev_mutex);
	lan937x_cfg_port_member(dev, port, member);

	/* clear pending interrupts */
	if (lan937x_is_internal_phy_port(dev, port))
		lan937x_pread16(dev, port, REG_PORT_PHY_INT_ENABLE, &data16);
}

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
			dev->phy_port_cnt = chip->phy_port_cnt;
			break;
		}
	}

	/* no switch found */
	if (!dev->port_cnt)
		return -ENODEV;

	dev->port_mask = (1 << dev->port_cnt) - 1;

	dev->reg_mib_cnt = SWITCH_COUNTER_NUM;
	dev->mib_cnt = TOTAL_SWITCH_COUNTER_NUM;

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
				     (TOTAL_SWITCH_COUNTER_NUM + 1),
				     GFP_KERNEL);
		if (!dev->ports[i].mib.counters)
			return -ENOMEM;
	}

	/* set the real number of ports */
	dev->ds->num_ports = dev->port_cnt;
	return 0;
}

const struct ksz_dev_ops lan937x_dev_ops = {
	.get_port_addr = lan937x_get_port_addr,
	.cfg_port_member = lan937x_cfg_port_member,
	.flush_dyn_mac_table = lan937x_flush_dyn_mac_table,
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
