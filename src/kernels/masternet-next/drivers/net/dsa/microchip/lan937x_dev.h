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
int lan937x_pwrite8_bulk(struct ksz_device *dev, int port, int offset,
			 u8 *data, u8 n);
int lan937x_internal_phy_write(struct ksz_device *dev, int addr,
			       int reg, u16 val);
int lan937x_internal_phy_read(struct ksz_device *dev, int addr,
			      int reg, u16 *val);
bool lan937x_is_internal_phy_port(struct ksz_device *dev, int port);
bool lan937x_is_internal_base_tx_phy_port(struct ksz_device *dev, int port);
bool lan937x_is_internal_base_t1_phy_port(struct ksz_device *dev, int port);
bool lan937x_is_rgmii_port(struct ksz_device *dev, int port);
int lan937x_reset_switch(struct ksz_device *dev);
void lan937x_cfg_port_member(struct ksz_device *dev, int port,
			     u8 member);
void lan937x_port_setup(struct ksz_device *dev, int port, bool cpu_port);
int lan937x_enable_spi_indirect_access(struct ksz_device *dev);
void lan937x_config_interface(struct ksz_device *dev, int port,
			      int speed, int duplex,
			      bool tx_pause, bool rx_pause);
void lan937x_mac_config(struct ksz_device *dev, int port,
			phy_interface_t interface);
void lan937x_r_mib_pkt(struct ksz_device *dev, int port, u16 addr,
		       u64 *dropped, u64 *cnt);

struct mib_names {
	int index;
	char string[ETH_GSTRING_LEN];
};

enum lan937x_mib_list {
	lan937x_mib_rx_hi_pri_byte = 0,
	lan937x_mib_rx_undersize,
	lan937x_mib_rx_fragments,
	lan937x_mib_rx_oversize,
	lan937x_mib_rx_jabbers,
	lan937x_mib_rx_sym_err,
	lan937x_mib_rx_crc_err,
	lan937x_mib_rx_align_err,
	lan937x_mib_rx_mac_ctrl,
	lan937x_mib_rx_pause,
	lan937x_mib_rx_bcast,
	lan937x_mib_rx_mcast,
	lan937x_mib_rx_ucast,
	lan937x_mib_rx_64_or_less,
	lan937x_mib_rx_65_127,
	lan937x_mib_rx_128_255,
	lan937x_mib_rx_256_511,
	lan937x_mib_rx_512_1023,
	lan937x_mib_rx_1024_1522,
	lan937x_mib_rx_1523_2000,
	lan937x_mib_rx_2001,
	lan937x_mib_tx_hi_pri_byte,
	lan937x_mib_tx_late_col,
	lan937x_mib_tx_pause,
	lan937x_mib_tx_bcast,
	lan937x_mib_tx_mcast,
	lan937x_mib_tx_ucast,
	lan937x_mib_tx_deferred,
	lan937x_mib_tx_total_col,
	lan937x_mib_tx_exc_col,
	lan937x_mib_tx_single_col,
	lan937x_mib_tx_mult_col,
	lan937x_mib_rx_total,
	lan937x_mib_tx_total,
	lan937x_mib_rx_discard,
	lan937x_mib_tx_discard,
};

struct lan_alu_struct {
	/* entry 1 */
	u32	is_static:1;
	u32	is_src_filter:1;
	u32	is_dst_filter:1;
	u32	prio_age:3;
	u32	_reserv_0_1:23;
	u32	mstp:3;
	/* entry 2 */
	u32	is_override:1;
	u32	is_use_fid:1;
	u32	_reserv_1_1:22;
	u32	port_forward:8;
	/* entry 3 & 4*/
	u32	_reserv_2_1:9;
	u32	fid:7;
	u8	mac[ETH_ALEN];
};

struct lan937x_vlan {
	/* entry 1 */
	bool valid;
	u8 fid;
	/* entry 2 */
	u32 untag_prtmap;
	/* entry 3 */
	u32 fwd_map;
};

extern const struct dsa_switch_ops lan937x_switch_ops;
extern const struct ksz_dev_ops lan937x_dev_ops;
extern const struct mib_names lan937x_mib_names[];

#endif
