// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2018 Microchip Technology

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/mii.h>
#include <linux/phy.h>

/* External Register Control Register */
#define LAN87XX_EXT_REG_CTL                     (0x14)
#define LAN87XX_EXT_REG_CTL_RD_CTL              (0x1000)
#define LAN87XX_EXT_REG_CTL_WR_CTL              (0x0800)

/* External Register Read Data Register */
#define LAN87XX_EXT_REG_RD_DATA                 (0x15)

/* External Register Write Data Register */
#define LAN87XX_EXT_REG_WR_DATA                 (0x16)

/* Interrupt Source Register */
#define LAN87XX_INTERRUPT_SOURCE                (0x18)

/* Interrupt Mask Register */
#define LAN87XX_INTERRUPT_MASK                  (0x19)
#define LAN87XX_MASK_LINK_UP                    (0x0004)
#define LAN87XX_MASK_LINK_DOWN                  (0x0002)

/* phyaccess nested types */
#define	PHYACC_ATTR_MODE_READ		0
#define	PHYACC_ATTR_MODE_WRITE		1
#define	PHYACC_ATTR_MODE_MODIFY		2
#define	PHYACC_ATTR_MODE_POLL		3

#define	PHYACC_ATTR_BANK_SMI		0
#define	PHYACC_ATTR_BANK_MISC		1
#define	PHYACC_ATTR_BANK_PCS		2
#define	PHYACC_ATTR_BANK_AFE		3
#define	PHYACC_ATTR_BANK_DSP		4
#define	PHYACC_ATTR_BANK_MAX		7

#define T1_M_CTRL_REG			0x09
#define T1_M_CFG			BIT(11)

#define T1_MODE_STAT_REG		0x11
#define T1_DSCR_LOCK_STATUS_MSK 	BIT(3)
#define T1_LINK_UP_MSK			BIT(0)

#define T1_REG_BANK_SEL_MASK		0x7
#define T1_REG_BANK_SEL			8
#define T1_REG_ADDR_MASK		0xFF

#define T1_M_STATUS_REG			0x0A
#define T1_LOCAL_RX_OK  		BIT(13)
#define T1_REMOTE_RX_OK 		BIT(12)

#define LAN87XX_PHY_ID			0x0007c150
#define LAN937X_T1_PHY_ID		0x0007c181
#define LAN87XX_PHY_ID_MASK		0xfffffff0
#define LAN937X_PHY_ID_MASK		0xfffffff0

/* T1 Registers */
#define T1_AFE_PORT_CFG1_REG		0x0B
#define T1_POWER_DOWN_CONTROL_REG	0x1A
#define T1_SLV_FD_MULT_CFG_REG  	0x18
#define T1_CDR_CFG_PRE_LOCK_REG 	0x05
#define T1_CDR_CFG_POST_LOCK_REG	0x06
#define T1_LCK_STG2_MUFACT_CFG_REG	0x1A
#define T1_LCK_STG3_MUFACT_CFG_REG	0x1B
#define T1_POST_LCK_MUFACT_CFG_REG	0x1C
#define T1_TX_RX_FIFO_CFG_REG		0x02
#define T1_TX_LPF_FIR_CFG_REG		0x55
#define T1_SQI_CONFIG_REG		0x2E
#define T1_MDIO_CONTROL2_REG		0x10
#define T1_INTERRUPT_SOURCE_REG 	0x18
#define T1_INTERRUPT2_SOURCE_REG	0x08

#define DRIVER_AUTHOR	"Nisar Sayed <nisar.sayed@microchip.com>"
#define DRIVER_DESC	"Microchip LAN87XX/LAN937X T1 PHY driver"

struct access_ereg_val {
	u8  mode;
	u8  bank;
	u8  offset;
	u16 val;
	u16 mask;
};

static int access_ereg(struct phy_device *phydev, u8 mode, u8 bank,
		       u8 offset, u16 val)
{
	u8 prev_bank;
	u16 ereg = 0;
	int rc = 0;
	u16 t;

	/* return if mode and bank are invalid */
	if (mode > PHYACC_ATTR_MODE_WRITE || bank > PHYACC_ATTR_BANK_MAX)
		return -EINVAL;

	/* if the bank is SMI, then call phy_read() & phy_write() directly */
	if (bank == PHYACC_ATTR_BANK_SMI) {
		if (mode == PHYACC_ATTR_MODE_WRITE)
			rc = phy_write(phydev, offset, val);
		else
			rc = phy_read(phydev, offset);
		return rc;
	}

	if (mode == PHYACC_ATTR_MODE_WRITE) {
		/* Initialize to Write Mode */
		ereg = LAN87XX_EXT_REG_CTL_WR_CTL;

		/* Write the data to be written in to the Bank */
		rc = phy_write(phydev, LAN87XX_EXT_REG_WR_DATA, val);
		if (rc < 0)
			return rc;
	} else {
		/* Initialize to Read Mode */
		ereg = LAN87XX_EXT_REG_CTL_RD_CTL;
	}

	ereg |= (bank << 8) | offset;

	/* DSP bank access workaround for lan937x*/
	if (phydev->phy_id == LAN937X_T1_PHY_ID) {
		/* Read previous selected bank */
		rc = phy_read(phydev, LAN87XX_EXT_REG_CTL);
		if (rc < 0)
			return rc;

		/* Store the prev_bank */
		prev_bank = (rc >> T1_REG_BANK_SEL) & T1_REG_BANK_SEL_MASK;

		if (bank != prev_bank && bank == PHYACC_ATTR_BANK_DSP) {
			t = ereg & ~T1_REG_ADDR_MASK;

			t &= ~LAN87XX_EXT_REG_CTL_WR_CTL;
			t |= LAN87XX_EXT_REG_CTL_RD_CTL;

			/*access twice for DSP bank change,dummy access*/
			rc = phy_write(phydev, LAN87XX_EXT_REG_CTL, t);
			if (rc < 0)
				return rc;
		}
	}

	rc = phy_write(phydev, LAN87XX_EXT_REG_CTL, ereg);
	if (rc < 0)
		return rc;

	if (mode == PHYACC_ATTR_MODE_READ)
		rc = phy_read(phydev, LAN87XX_EXT_REG_RD_DATA);

	return rc;
}

static int access_ereg_modify_changed(struct phy_device *phydev,
				      u8 bank, u8 offset, u16 val, u16 mask)
{
	int new = 0, rc = 0;

	if (bank > PHYACC_ATTR_BANK_MAX)
		return -EINVAL;

	rc = access_ereg(phydev, PHYACC_ATTR_MODE_READ, bank, offset, val);
	if (rc < 0)
		return rc;

	new = val | (rc & (mask ^ 0xFFFF));
	rc = access_ereg(phydev, PHYACC_ATTR_MODE_WRITE, bank, offset, new);

	return rc;
}

static int access_ereg_clr_poll_timeout(struct phy_device *phydev, u8 bank,
					u8 offset, u16 mask, u16 clr)
{
	int val;

	if (bank != PHYACC_ATTR_BANK_SMI)
		return -EINVAL;

	return phy_read_poll_timeout(phydev, offset, val, (val & mask) == clr,
				     150, 30000, true);
}

static int lan87xx_phy_init(struct phy_device *phydev)
{
	static const struct access_ereg_val init[] = {
		/* TXPD/TXAMP6 Configs*/
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_AFE,
		  T1_AFE_PORT_CFG1_REG,       0x002D,  0 },
		/* HW_Init Hi and Force_ED */
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_SMI,
		  T1_POWER_DOWN_CONTROL_REG,  0x0308,  0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_SLV_FD_MULT_CFG_REG,     0x0D53,  0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_CDR_CFG_PRE_LOCK_REG,    0x0AB2,  0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_CDR_CFG_POST_LOCK_REG,   0x0AB3,  0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_LCK_STG2_MUFACT_CFG_REG, 0x0AEA,  0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_LCK_STG3_MUFACT_CFG_REG, 0x0AEB,  0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_POST_LCK_MUFACT_CFG_REG, 0x0AEB,  0 },
		/* Pointer delay */
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_RX_FIFO_CFG_REG, 0x1C00, 0 },
		/* Tx iir edits */
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1000, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1861, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1061, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1922, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1122, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1983, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1183, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1944, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1144, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x18c5, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x10c5, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1846, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1046, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1807, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1007, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1808, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1008, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1809, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1009, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x180A, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x100A, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x180B, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x100B, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x180C, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x100C, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x180D, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x100D, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x180E, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x100E, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x180F, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x100F, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1810, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1010, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1811, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1011, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_TX_LPF_FIR_CFG_REG, 0x1000, 0 },
		/* SQI enable */
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_DSP,
		  T1_SQI_CONFIG_REG,		0x9572, 0 },
		/* Flag LPS and WUR as idle errors */
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_SMI,
		  T1_MDIO_CONTROL2_REG,		0x0014, 0 },
		/* Restore state machines without clearing registers */
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_SMI,
		  T1_POWER_DOWN_CONTROL_REG,	0x0200, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_SMI,
		  T1_MDIO_CONTROL2_REG,		0x0094, 0 },
		{ PHYACC_ATTR_MODE_POLL, PHYACC_ATTR_BANK_SMI,
		  T1_MDIO_CONTROL2_REG,		0x0080, 0 },
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_AFE,
		  T1_AFE_PORT_CFG1_REG,		0x000C, 0 },
		/* Read INTERRUPT_SOURCE Register */
		{ PHYACC_ATTR_MODE_READ, PHYACC_ATTR_BANK_SMI,
		  T1_INTERRUPT_SOURCE_REG,	0,	0 },
		/* Read INTERRUPT_SOURCE Register */
		{ PHYACC_ATTR_MODE_READ, PHYACC_ATTR_BANK_MISC,
		  T1_INTERRUPT2_SOURCE_REG,	0,	0 },
		/* HW_Init Hi */
		{ PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_SMI,
		  T1_POWER_DOWN_CONTROL_REG,	0x0300, 0 },
	};
	int rc, i;

	/* Set Master Mode */
	rc = access_ereg_modify_changed(phydev, PHYACC_ATTR_BANK_SMI,
					T1_M_CTRL_REG, T1_M_CFG, T1_M_CFG);
	if (rc < 0)
		return rc;

	/* phy Soft reset */
	rc = genphy_soft_reset(phydev);
	if (rc < 0)
		return rc;

	/* PHY Initialization */
	for (i = 0; i < ARRAY_SIZE(init); i++) {
		if (init[i].mode == PHYACC_ATTR_MODE_MODIFY) {
			rc = access_ereg_modify_changed(phydev, init[i].bank,
							init[i].offset,
							init[i].val,
							init[i].mask);
		} else if (init[i].mode == PHYACC_ATTR_MODE_POLL) {
			rc = access_ereg_clr_poll_timeout(phydev, init[i].bank,
							  init[i].offset,
							  init[i].val,
							  init[i].mask);
		} else {
			rc = access_ereg(phydev, init[i].mode, init[i].bank,
					 init[i].offset, init[i].val);
		}
		if (rc < 0)
			return rc;
	}

	return 0;
}

static int lan87xx_phy_config_intr(struct phy_device *phydev)
{
	int rc, val = 0;

	if (phydev->interrupts == PHY_INTERRUPT_ENABLED) {
		/* unmask all source and clear them before enable */
		rc = phy_write(phydev, LAN87XX_INTERRUPT_MASK, 0x7FFF);
		rc = phy_read(phydev, LAN87XX_INTERRUPT_SOURCE);
		val = LAN87XX_MASK_LINK_UP | LAN87XX_MASK_LINK_DOWN;
		rc = phy_write(phydev, LAN87XX_INTERRUPT_MASK, val);
	} else {
		rc = phy_write(phydev, LAN87XX_INTERRUPT_MASK, val);
		if (rc)
			return rc;

		rc = phy_read(phydev, LAN87XX_INTERRUPT_SOURCE);
	}

	return rc < 0 ? rc : 0;
}

static irqreturn_t lan87xx_handle_interrupt(struct phy_device *phydev)
{
	int irq_status;

	irq_status = phy_read(phydev, LAN87XX_INTERRUPT_SOURCE);
	if (irq_status < 0) {
		phy_error(phydev);
		return IRQ_NONE;
	}

	if (irq_status == 0)
		return IRQ_NONE;

	phy_trigger_machine(phydev);

	return IRQ_HANDLED;
}

static int lan87xx_config_init(struct phy_device *phydev)
{
	int rc = lan87xx_phy_init(phydev);

	if (rc < 0)
		phydev_err(phydev, "failed to initialize phy\n");

	return rc < 0 ? rc : 0;
}

static int lan937x_read_status(struct phy_device *phydev)
{
	int val;

	val = phy_read(phydev, T1_MODE_STAT_REG);

	if (val < 0)
		return val;

	if (val & T1_LINK_UP_MSK)
		phydev->link = 1;
	else
		phydev->link = 0;

	phydev->duplex = DUPLEX_FULL;
	phydev->speed = SPEED_100;
	phydev->pause = 0;
	phydev->asym_pause = 0;

	return 0;
}

static int lan937x_config_init(struct phy_device *phydev)
{
	/* lan87xx & lan937x follows same init sequence */
	return lan87xx_config_init(phydev);
}

static struct phy_driver microchip_t1_phy_driver[] = {
	{
		.phy_id = LAN87XX_PHY_ID,
		.phy_id_mask = LAN87XX_PHY_ID_MASK,
		.name = "LAN87xx T1",
		.features = PHY_BASIC_T1_FEATURES,
		.config_init = lan87xx_config_init,
		.config_intr = lan87xx_phy_config_intr,
		.handle_interrupt = lan87xx_handle_interrupt,
		.suspend = genphy_suspend,
		.resume = genphy_resume,
	},
	{
		.phy_id = LAN937X_T1_PHY_ID,
		.phy_id_mask = LAN937X_PHY_ID_MASK,
		.name = "LAN937x T1",
		.read_status = lan937x_read_status,
		.features = PHY_BASIC_T1_FEATURES,
		.config_init = lan937x_config_init,
		.suspend = genphy_suspend,
		.resume = genphy_resume,
	}
};

module_phy_driver(microchip_t1_phy_driver);

static struct mdio_device_id __maybe_unused microchip_t1_tbl[] = {
	{ LAN87XX_PHY_ID, LAN87XX_PHY_ID_MASK },
	{ LAN937X_T1_PHY_ID, LAN937X_PHY_ID_MASK },
	{}
};

MODULE_DEVICE_TABLE(mdio, microchip_t1_tbl);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");
