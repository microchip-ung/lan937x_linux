// SPDX-License-Identifier: GPL-2.0
/* Microchip 
 * Copyright (C) 2019-2020 Microchip Technology Inc.
 */

#ifndef __LAN937X_CFG_H
#define __LAN937X_CFG_H

void lan937x_cfg(struct ksz_device *dev, u32 addr, u8 bits, bool set);
void lan937x_port_cfg(struct ksz_device *dev, int port, int offset,
			     u8 bits, bool set);
void lan937x_cfg32(struct ksz_device *dev, u32 addr, u32 bits, bool set);
void lan937x_pread8(struct ksz_device *dev, int port, int offset,
				  u8 *data);
void lan937x_pread16(struct ksz_device *dev, int port, int offset,
				   u16 *data);
void lan937x_pread32(struct ksz_device *dev, int port, int offset,
				   u32 *data);
void lan937x_pwrite8(struct ksz_device *dev, int port,
				   int offset, u8 data);
void lan937x_pwrite16(struct ksz_device *dev, int port,
				    int offset, u16 data);
void lan937x_pwrite32(struct ksz_device *dev, int port,
				    int offset, u32 data);
void lan937x_port_cfg32(struct ksz_device *dev, int port, int offset,
			       u32 bits, bool set);     
int lan937x_t1_tx_phy_write(struct ksz_device *dev, int addr,
				   int reg, u16 val);
int lan937x_t1_tx_phy_read(struct ksz_device *dev, int addr,
				  int reg, u16 *val);
bool lan937x_is_tx_phy_port (struct ksz_device *dev, int port);
bool isphyport (struct ksz_device *dev, int port);
int lan937x_reset_switch(struct ksz_device *dev);
void lan937x_cfg_port_member(struct ksz_device *dev, int port,
				    u8 member);
void lan937x_port_setup(struct ksz_device *dev, int port, bool cpu_port);
int lan937x_sw_register(struct ksz_device *dev);
int lan937x_enable_spi_indirect_access(struct ksz_device *dev);

struct mib_names{
	int index;
	char string[ETH_GSTRING_LEN];
};

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
	u8 tx_phy_log_prt;
	u8  log_addr_map[10];
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
extern const struct mib_names lan937x_mib_names[TOTAL_SWITCH_COUNTER_NUM];

#endif