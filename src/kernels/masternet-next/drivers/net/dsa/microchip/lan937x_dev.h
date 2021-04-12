/* SPDX-License-Identifier: GPL-2.0 */
/* Microchip lan937x dev ops headers
 * Copyright (C) 2019-2021 Microchip Technology Inc.
 */

#ifndef __LAN937X_CFG_H
#define __LAN937X_CFG_H

int lan937x_cfg(struct ksz_device *dev, u32 addr, u8 bits, bool set);
int lan937x_port_cfg(struct ksz_device *dev, int port, int offset,
		     u8 bits, bool set);
int lan937x_cfg32(struct ksz_device *dev, u32 addr, u32 bits, bool set);
int lan937x_pread8(struct ksz_device *dev, int port, int offset,
		   u8 *data);
int lan937x_pread16(struct ksz_device *dev, int port, int offset,
		    u16 *data);
int lan937x_pread32(struct ksz_device *dev, int port, int offset,
		    u32 *data);
int lan937x_pwrite8(struct ksz_device *dev, int port,
		    int offset, u8 data);
int lan937x_pwrite16(struct ksz_device *dev, int port,
		     int offset, u16 data);
int lan937x_pwrite32(struct ksz_device *dev, int port,
		     int offset, u32 data);
int lan937x_port_cfg32(struct ksz_device *dev, int port, int offset,
		       u32 bits, bool set);
int lan937x_internal_phy_write(struct ksz_device *dev, int addr,
			       int reg, u16 val);
int lan937x_internal_phy_read(struct ksz_device *dev, int addr,
			      int reg, u16 *val);
bool lan937x_is_internal_100BTX_phy_port(struct ksz_device *dev, int port);
bool lan937x_is_internal_t1_phy_port(struct ksz_device *dev, int port);
bool lan937x_is_internal_phy_port(struct ksz_device *dev, int port);
int lan937x_reset_switch(struct ksz_device *dev);
void lan937x_cfg_port_member(struct ksz_device *dev, int port,
			     u8 member);
void lan937x_port_setup(struct ksz_device *dev, int port, bool cpu_port);
int lan937x_enable_spi_indirect_access(struct ksz_device *dev);

struct mib_names {
	int index;
	char string[ETH_GSTRING_LEN];
};

struct lan_alu_struct {
	/* entry 1 */
	u8	is_static:1;
	u8	is_src_filter:1;
	u8	is_dst_filter:1;
	u8	prio_age:3;
	u32	_reserv_0_1:23;
	u8	mstp:3;
	/* entry 2 */
	u8	is_override:1;
	u8	is_use_fid:1;
	u32	_reserv_1_1:22;
	u8	port_forward:8;
	/* entry 3 & 4*/
	u32	_reserv_2_1:9;
	u8	fid:7;
	u8	mac[ETH_ALEN];
};

extern const struct dsa_switch_ops lan937x_switch_ops;
extern const struct ksz_dev_ops lan937x_dev_ops;
extern const struct mib_names lan937x_mib_names[];

#endif
