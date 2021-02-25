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
#define 	PHYACC_ATTR_MODE_POLL		3

#define	PHYACC_ATTR_BANK_SMI		0
#define	PHYACC_ATTR_BANK_MISC		1
#define	PHYACC_ATTR_BANK_PCS		2
#define	PHYACC_ATTR_BANK_AFE		3
#define	PHYACC_ATTR_BANK_DSP		4
#define	PHYACC_ATTR_BANK_MAX		7

#define DRIVER_AUTHOR	"Nisar Sayed <nisar.sayed@microchip.com>"
#define DRIVER_DESC	"Microchip LAN87XX T1 PHY driver"


#define REG_PORT_T1_PHY_BASIC_CTRL	0x00

#define PORT_T1_PHY_RESET		BIT(15)
#define PORT_T1_PHY_LOOPBACK		BIT(14)
#define PORT_T1_SPEED_100MBIT		BIT(13)
#define PORT_T1_POWER_DOWN		BIT(11)
#define PORT_T1_ISOLATE			BIT(10)
#define PORT_T1_FULL_DUPLEX		BIT(8)

#define REG_PORT_T1_PHY_BASIC_STATUS	0x01

#define PORT_T1_MII_SUPPRESS_CAPABLE	BIT(6)
#define PORT_T1_LINK_STATUS		BIT(2)
#define PORT_T1_EXTENDED_CAPABILITY	BIT(0)

#define REG_PORT_T1_PHY_ID_HI		0x02
#define REG_PORT_T1_PHY_ID_LO		0x03

#define LAN937X_T1_ID_HI		0x0007
#define LAN937X_T1_ID_LO		0xC150

#define REG_PORT_T1_PHY_M_CTRL	0x09

#define PORT_T1_MANUAL_CFG		BIT(12)
#define PORT_T1_M_CFG		BIT(11)

#define REG_PORT_T1_PHY_M_STATUS	0x0A

#define REG_PORT_T1_MODE_STAT			0x11
#define T1_PORT_DSCR_LOCK_STATUS_MSK	BIT(3)
#define T1_PORT_LINK_UP_MSK				BIT(0)

#define REG_PORT_T1_LOOPBACK_CTRL	0x12

#define REG_PORT_T1_RESET_CTRL		0x13

#define T1_PHYADDR_S			11

#define REG_PORT_T1_EXT_REG_CTRL	0x14

#define T1_PCS_STS_CNT_RESET		BIT(15)
#define T1_IND_DATA_READ		BIT(12)
#define T1_IND_DATA_WRITE		BIT(11)
#define T1_REG_BANK_SEL_M		0x7
#define T1_REG_BANK_SEL_S		8
#define T1_REG_BANK_SEL_INST		5
#define T1_REG_BANK_SEL_DSP		4
#define T1_REG_BANK_SEL_AFE		3
#define T1_REG_BANK_SEL_PCS		2
#define T1_REG_BANK_SEL_MISC		1
#define T1_REG_ADDR_M			0xFF

#define REG_PORT_T1_EXT_REG_RD_DATA	0x15
#define REG_PORT_T1_EXT_REG_WR_DATA	0x16

#define REG_PORT_T1_PCS_CTRL		0x17

#define REG_PORT_T1_PHY_INT_STATUS	0x18
#define REG_PORT_T1_PHY_INT_ENABLE	0x19

#define T1_PHY_CTRL_MAXWAIT_TIMER_INT	BIT(8)
#define T1_ZERO_TIMER_INT		BIT(7)
#define T1_ENERGY_OFF_INT		BIT(6)
#define T1_IDLE_ERR_THRESH_DET_INT	BIT(4)
#define T1_LINK_UP_INT			BIT(2)
#define T1_LINK_DOWN_INT		BIT(1)
#define T1_ENERGY_ON_INT		BIT(0)

#define REG_PORT_T1_POWER_DOWN_CTRL	0x1A

#define T1_BIST_LINK_UP			BIT(15)
#define T1_EMERGENCY_STOP		BIT(14)
#define T1_PTP_ENABLE			BIT(13)
#define T1_PCS_LINK_CTRL_ENABLE		BIT(12)
#define T1_DSP_START_EQUALIZER		BIT(11)
#define T1_START_ZQ_CAL			BIT(10)
#define T1_FORCE_TX_ENABLE		BIT(9)
#define T1_HW_INIT_SEQ_ENABLE		BIT(8)
#define T1_WAKE_ENABLE			BIT(7)
#define T1_LINK_UP_REQ			BIT(6)
#define T1_AUTO_CLR_EPDWRDOWN		BIT(5)
#define T1_ENERGY_DETECT_POWER_DOWN	BIT(4)
#define T1_FORCE_ENERGY_DETECT		BIT(3)
#define T1_AUTO_SLEEP_WAKEUP		BIT(2)
#define T1_ENERGY_DETECT_HW_ENABLE	BIT(1)
#define T1_ENERGY_DETECT_ENABLE		BIT(0)

#define REG_PORT_T1_BIST_CTRL		0x1B
#define REG_PORT_T1_BIST_STAT		0x1C
#define REG_PORT_T1_BIST_ERR_CNT_STS	0x1D
#define REG_PORT_T1_PCS_RX_ERR_CNT_STS	0x1E
#define REG_PORT_T1_TS_CTRL_STAT	0x1F

#define REG_PORT_T1_PCS_DESCRM_CTRL_0	0x00

#define T1_PCS_SEND_IDLE_LOC_RCV_STS	BIT(15)
#define T1_PCS_DESCR_RELOCK_ON_IDLE	BIT(14)
#define T1_PCS_DESCR_RELOCK_ON_RCV	BIT(13)
#define T1_PCS_DESCR_RELOCK_ON_EQ	BIT(12)
#define T1_PCS_DESCR_LOCK_SYM_CNT	0x0FC0
#define T1_PCS_DESCR_LOCK_CHK_WIN	0x003F

#define REG_PORT_T1_PCS_DESCRM_CTRL_1	0x01

#define T1_PCS_DESCR_PIPE_DELAY		0x0700
#define T1_PCS_FEED_DESCR_LFSR_WIN	0x003F

#define REG_PORT_T1_PCS_EQ_TIMER_CTRL	0x02

#define REG_PORT_T1_PCS_RX_ERR_CNT	0x0E

#define REG_PORT_T1_PCS_ED_STABILITY	0x26

#define REG_PORT_T1_PHY_M_CTRL	0x09

#define PORT_T1_MANUAL_CFG		BIT(12)
#define PORT_T1_M_CFG		BIT(11)

#define REG_PORT_T1_PHY_M_STATUS	0x0A

#define PORT_T1_LOCAL_M		BIT(14)
#define PORT_T1_LOCAL_RX_OK		BIT(13)
#define PORT_T1_REMOTE_RX_OK		BIT(12)
#define PORT_T1_IDLE_ERR_CNT_M		0xFF

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
	u16 ereg;
	int rc;

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

	/* Read previous selected bank */
	rc = phy_read(phydev, LAN87XX_EXT_REG_CTL);

	if (rc < 0)
		return rc;

	/* Store the prev_bank */
	prev_bank = (rc >> T1_REG_BANK_SEL_S) & T1_REG_BANK_SEL_M;

	/* if the bank is DSP need to write twice */
	if (bank != prev_bank && bank == PHYACC_ATTR_BANK_DSP) {
		u16 t = ereg & ~T1_REG_ADDR_M;

		t &= ~LAN87XX_EXT_REG_CTL_WR_CTL;
		t |= LAN87XX_EXT_REG_CTL_RD_CTL;

		/* Need to write twice to access correct register. */
		rc = phy_write(phydev, LAN87XX_EXT_REG_CTL, t);

		if (rc < 0)
			return rc;
	}

	ereg |= (bank << 8) | offset;

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

static int access_ereg_clr_poll_timeout(struct phy_device *phydev,
				      u8 bank, u8 offset, u16 mask, u16 clr)
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
		/* TX Amplitude = 5 */
		{PHYACC_ATTR_MODE_MODIFY, PHYACC_ATTR_BANK_AFE, 0x0B,
		 0x000A, 0x001E},
		/* Clear SMI interrupts */
		{PHYACC_ATTR_MODE_READ, PHYACC_ATTR_BANK_SMI, 0x18,
		 0, 0},
		/* Clear MISC interrupts */
		{PHYACC_ATTR_MODE_READ, PHYACC_ATTR_BANK_MISC, 0x08,
		 0, 0},
		/* Turn on TC10 Ring Oscillator (ROSC) */
		{PHYACC_ATTR_MODE_MODIFY, PHYACC_ATTR_BANK_MISC, 0x20,
		 0x0020, 0x0020},
		/* WUR Detect Length to 1.2uS, LPC Detect Length to 1.09uS */
		{PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_PCS, 0x20,
		 0x283C, 0},
		/* Wake_In Debounce Length to 39uS, Wake_Out Length to 79uS */
		{PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_MISC, 0x21,
		 0x274F, 0},
		/* Enable Auto Wake Forward to Wake_Out, ROSC on, Sleep,
		 * and Wake_In to wake PHY
		 */
		{PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_MISC, 0x20,
		 0x80A7, 0},
		/* Enable WUP Auto Fwd, Enable Wake on MDI, Wakeup Debouncer
		 * to 128 uS
		 */
		{PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_MISC, 0x24,
		 0xF110, 0},
		/* Enable HW Init */
		{PHYACC_ATTR_MODE_MODIFY, PHYACC_ATTR_BANK_SMI, 0x1A,
		 0x0100, 0x0100},
	};
	int rc, i;

	/* Start manual initialization procedures in Managed Mode */
	rc = access_ereg_modify_changed(phydev, PHYACC_ATTR_BANK_SMI,
					0x1a, 0x0000, 0x0100);
	if (rc < 0)
		return rc;

	/* Soft Reset the SMI block */
	rc = access_ereg_modify_changed(phydev, PHYACC_ATTR_BANK_SMI,
					0x00, 0x8000, 0x8000);
	if (rc < 0)
		return rc;

	/* Check to see if the self-clearing bit is cleared */
	usleep_range(1000, 2000);
	rc = access_ereg(phydev, PHYACC_ATTR_MODE_READ,
			 PHYACC_ATTR_BANK_SMI, 0x00, 0);
	if (rc < 0)
		return rc;
	if ((rc & 0x8000) != 0)
		return -ETIMEDOUT;

	/* PHY Initialization */
	for (i = 0; i < ARRAY_SIZE(init); i++) {
		if (init[i].mode == PHYACC_ATTR_MODE_MODIFY) {
			rc = access_ereg_modify_changed(phydev, init[i].bank,
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

	return rc < 0 ? rc : 0;
}

static int lan937x_read_status(struct phy_device *phydev)
{
	int val1, val2;

	val1 = phy_read(phydev, REG_PORT_T1_PHY_M_STATUS);

	if (val1 < 0)
		return val1;

	val2 = phy_read(phydev, REG_PORT_T1_MODE_STAT);

	if (val2 < 0)
		return val2;
	
	if (val1 & (PORT_T1_LOCAL_RX_OK | PORT_T1_REMOTE_RX_OK) &&
	    val2 & (T1_PORT_DSCR_LOCK_STATUS_MSK | T1_PORT_LINK_UP_MSK))
		phydev->link = 1;
	else
		phydev->link = 0;

	phydev->duplex = DUPLEX_FULL;
	phydev->speed = SPEED_100;
	phydev->pause = phydev->asym_pause = 0;

	return 0;
}

static int lan937x_t1_phy_init (struct phy_device *phydev)
{
	static const struct access_ereg_val init[] = {
		/* TXPD/TXAMP6 and HW_Init Hi and Force_ED*/
		{PHYACC_ATTR_MODE_WRITE,  T1_REG_BANK_SEL_AFE,  0x0B, 
		0x002D, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x18,
		 0x0D53, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x05,
		 0x0AB2, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x06,
		 0x0AB3, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x1A,
		 0x0AEA, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x1B, 0x0AEB, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x1C, 0x0AEB, 0},
		// Pointer delay
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x02, 0x1C00, 0},
		// ---- tx iir edits ----
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1000, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1861, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1061, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1922, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1122, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1983, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1183, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1944, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1144, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x18c5, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x10c5, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1846, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1046, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1807, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1007, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1808, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1008, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1809, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1009, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x180A, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x100A, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x180B, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x100B, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x180C, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x100C, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x180D, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x100D, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x180E, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x100E, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x180F, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x100F, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1810, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1010, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1811, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1011, 0},
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x55, 0x1000, 0},
		// SQI enable
		{PHYACC_ATTR_MODE_WRITE, T1_REG_BANK_SEL_DSP, 0x2E,  0x9572, 0},
		// Flag LPS and WUR as idle errors
		//phy_write(phydev,0x10, 0x0014);
		{PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_SMI, 0x10,  0x0014, 0},
		// End 10x
		
		// Restore state machines without clearing registers
		//phy_write(phydev,0x1A, 0x0200);
		{PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_SMI, 0x1A,  0x0200, 0},
		//phy_write(phydev,0x10, 0x0094);
		{PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_SMI, 0x10,  0x0094, 0},

		{PHYACC_ATTR_MODE_POLL, PHYACC_ATTR_BANK_SMI, 0x10,  0x0080, 0},

		{PHYACC_ATTR_MODE_WRITE, PHYACC_ATTR_BANK_AFE, 0x0B, 0x000C, 0},

		/*Read INTERRUPT_SOURCE Register*/
		{PHYACC_ATTR_MODE_READ, PHYACC_ATTR_BANK_SMI, 0x18, 0, 0},

		/*Read INTERRUPT_SOURCE Register*/
		{PHYACC_ATTR_MODE_READ, PHYACC_ATTR_BANK_MISC, 0x08, 0, 0},

	};
	int rc, i;
	
	/* Power down the PHY */
	rc = access_ereg_modify_changed(phydev, PHYACC_ATTR_BANK_SMI, REG_PORT_T1_PHY_BASIC_CTRL,
	 PORT_T1_POWER_DOWN, PORT_T1_POWER_DOWN);
	
	if (rc < 0)
		return rc;
	
	rc = access_ereg_modify_changed(phydev, PHYACC_ATTR_BANK_SMI, REG_PORT_T1_POWER_DOWN_CTRL,
	 0x0000, T1_HW_INIT_SEQ_ENABLE);

	if (rc < 0)
		return rc;
	
	rc = access_ereg_modify_changed(phydev, PHYACC_ATTR_BANK_SMI, REG_PORT_T1_PHY_M_CTRL,
	 PORT_T1_M_CFG, PORT_T1_M_CFG);
	
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
			init[i].offset, init[i].val, init[i].mask);
		}
		else {
			rc = access_ereg(phydev, init[i].mode, init[i].bank,
					 init[i].offset, init[i].val);
		}
		if (rc < 0)
			return rc;
	}
	/* Set HW_INIT */
	rc = access_ereg_modify_changed(phydev, PHYACC_ATTR_BANK_SMI, REG_PORT_T1_POWER_DOWN_CTRL,
	 T1_HW_INIT_SEQ_ENABLE, T1_HW_INIT_SEQ_ENABLE);

	if (rc < 0)
		return rc;

	rc = access_ereg_modify_changed(phydev, PHYACC_ATTR_BANK_SMI, REG_PORT_T1_PHY_BASIC_CTRL,
	 0x0000, PORT_T1_POWER_DOWN);
	
	if (rc < 0)
		return rc;

	return 0;
}

static int lan937x_t1_phy_config_init(struct phy_device *phydev)
{
	int rc = lan937x_t1_phy_init(phydev);

	if (rc < 0)
		phydev_err(phydev, "failed to initialize phy\n");

	return rc < 0 ? rc : 0;
}


static struct phy_driver microchip_t1_phy_driver[] = {
	/*{
		.phy_id         = 0x0007c150,
		.phy_id_mask    = 0xfffffff0,
		.name           = "Microchip LAN87xx T1",

		.features       = PHY_BASIC_T1_FEATURES,

		.config_init	= lan87xx_config_init,

		.config_intr    = lan87xx_phy_config_intr,
		.handle_interrupt = lan87xx_handle_interrupt,

		.suspend        = genphy_suspend,
		.resume         = genphy_resume,
	}*/
	{
	.phy_id         = 0x0007c150,
	.phy_id_mask    = 0xfffffff0,
	.name           = "Microchip LAN87xx T1",
/*	.read_status 	= lan937x_read_status,*/

	.features       = PHY_BASIC_T1_FEATURES,

	.config_init	= lan937x_t1_phy_config_init,
	/*.config_init	= lan937x_t1_phy_init_ext,*/

	.suspend        = genphy_suspend,
	.resume         = genphy_resume,
	}
};

module_phy_driver(microchip_t1_phy_driver);

static struct mdio_device_id __maybe_unused microchip_t1_tbl[] = {
	/*{ 0x0007c150, 0xfffffff0 },*/
	{0x0007c150, 0xfffffff0 },
	{ }
};

MODULE_DEVICE_TABLE(mdio, microchip_t1_tbl);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");
