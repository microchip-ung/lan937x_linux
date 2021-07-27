// SPDX-License-Identifier: GPL-2.0
/* Microchip lan937x dev ops functions
 * Copyright (C) 2019-2020 Microchip Technology Inc.
 */
#include <net/dsa.h>
#include <net/switchdev.h>
#include "lan937x_reg.h"
#include "ksz_common.h"
#include "lan937x_dev.h"
#include "lan937x_tc.h"
#include <linux/printk.h>
#include "lan937x_flower.h"
#include "lan937x_acl.h"

const struct lan937x_acl_rfr acl_rfrs_table[MAX_ACL_PARSER][MAX_RFR] = {
	{ /**RFRs Supported in PARSER 0*/
		{	.rfr_valid = true,
			.dissectors_covered = DST_MAC_DISSECTOR_PRESENT,
			.l4 = false,
			.l3 = false,
			.l2 = true,
			.rng_match_en = false,
			.ofst = 0,
			.len = 6,
			.rng_ofst = 0, },

		{	.rfr_valid = true,
			.dissectors_covered = SRC_MAC_DISSECTOR_PRESENT,
			.l4 = false,
			.l3 = false,
			.l2 = true,
			.rng_match_en = false,
			.ofst = 6,
			.len = 6,
			.rng_ofst = 0, },

		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },

	},

	{/**RFRs Supported in PARSER 1*/
		{	.rfr_valid = true,
			.dissectors_covered = DST_MAC_DISSECTOR_PRESENT,
			.l4 = false,
			.l3 = false,
			.l2 = true,
			.rng_match_en = false,
			.ofst = 0,
			.len = 6,
			.rng_ofst = 0, },

		{	.rfr_valid = true,
			.dissectors_covered = SRC_MAC_DISSECTOR_PRESENT,
			.l4 = false,
			.l3 = false,
			.l2 = true,
			.rng_match_en = false,
			.ofst = 6,
			.len = 6,
			.rng_ofst = 0, },

		{	.rfr_valid = true,
			.dissectors_covered = VLAN_TAG_DISSECTORS_PRESENT,
			.l4 = false,
			.l3 = false,
			.l2 = true,
			.rng_match_en = false,
			.ofst = 12,
			.len = 4,
			.rng_ofst = 0, },

		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
	},

	{/**RFRs Supported in PARSER 2*/
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
	},

	{/**RFRs Supported in PARSER 3*/
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
		{	.rfr_valid = false, },
	}
};

int lan937x_get_acl_requirements(enum lan937x_filter_type filter_type,
				 u8 *parser_idx, u8 *n_entries)
{
	switch (filter_type) {
	case LAN937x_VLAN_UNAWARE_FILTER:
		*parser_idx = 0;
		*n_entries = 1;
		break;
	case LAN937x_VLAN_AWARE_FILTER:
		*parser_idx = 1;
		*n_entries = 1;
		break;
	case LAN937x_BCAST_FILTER:
	default:
		return -EINVAL;

	}

	return 0;
}

static int lan937x_acl_byte_enable_write(struct ksz_device *dev, int port,
					 struct lan937x_acl_byte_en *cfg)
{
	u8 *msk = cfg->acl_mask;
	u16 reg_ofst;
	u8 i = 0;
	int rc;
	u8 val;

	reg_ofst = LAN937X_ACL_CTRL_BASE_ADDR + LAN937X_ACL_PORT_ABER_REG;

	while (i < sizeof(*cfg)) {
		val = msk[i];
		rc = lan937x_pwrite8(dev, port, reg_ofst + i, val);
		pr_info("Byte En: %x,%d,%d", val, i, rc);
		if (rc)
			return rc;
		i++;
	}
	return 0;
}

static int lan937x_wait_tcam_busy(struct ksz_device *dev, int port)
{
	u16 reg_ofst = LAN937X_ACL_CTRL_BASE_ADDR + LAN937X_ACL_PORT_ARACR_REG;
	int timeout = 1000; /**To-Do: Proper Justification needed*/
	u32 val = 0;
	bool busy;
	int rc;

	do {
		rc = lan937x_pread32(dev, port, reg_ofst, &val);
		if (rc)
			return -EBUSY;
		busy = (val & LAN937X_ACL_PORT_ARACR_TCAM_OPERATION_STATUS);
		timeout--;
	} while (!busy && timeout);

	if (!timeout) {
		pr_info("Timeout");
		return -EBUSY;
	}
	return 0;
}

static int lan937x_set_acl_access_ctl(struct ksz_device *dev,
				      int port,
				      struct lan937x_acl_access_ctl *acc_ctl)
{
	u16 reg_ofst = LAN937X_ACL_CTRL_BASE_ADDR + LAN937X_ACL_PORT_ARACR_REG;
	int rc = lan937x_wait_tcam_busy(dev, port);
	u32 val;

	if (!rc) {
		val = acl_pri_low(acc_ctl->pri_low);
		val |= acl_tcam_flush(acc_ctl->tcam_flush);
		val |= acl_tcam_vben(acc_ctl->tcam_vben);
		val |= acl_tcam_vbi(acc_ctl->tcam_vbi);
		val |= acl_tcam_row_vld(acc_ctl->tcam_row_vld);
		val |= acl_row_shift(acc_ctl->row_shift);
		val |= acl_tcam_req(acc_ctl->tcam_req);
		val |= acl_tcam_acc(acc_ctl->tcam_acc);
		val |= acl_num_shift(acc_ctl->num_shift);
		val |= acl_tcam_addr(acc_ctl->tcam_addr);

		rc = lan937x_pwrite32(dev, port, reg_ofst, val);
		if (rc)
			return rc;
		rc = lan937x_wait_tcam_busy(dev, port);
	}
	return rc;
}

int lan937x_readback(struct ksz_device *dev, int port,
		     struct lan937x_acl_access_ctl *paccess_ctl,
		     int size_dwords)
{
	u16 reg_ofst;
	u32 val = 0;
	int rc;
	u8 i;

	reg_ofst = LAN937X_ACL_CTRL_BASE_ADDR + LAN937X_ACL_PORT_ADR_REG;

	/*Clear the ACL Data Reg before reading*/
	for (i = 0; i < size_dwords; i++) {
		rc = lan937x_pwrite32(dev, port, reg_ofst + (4 * i), val);
		if (rc)
			return rc;
	}

	rc = lan937x_set_acl_access_ctl(dev,
					port, paccess_ctl);
	pr_info("**************Readback*********************");

	for (i = 0; i < size_dwords; i++) {
		rc = lan937x_pread32(dev, port, reg_ofst + (4 * i), &val);
		pr_info("%x", val);
		if (rc)
			return rc;
	}
	pr_info("***********************************");

	return rc;
}

static int lan937x_write_reg_block(struct ksz_device *dev,
				   u8 port, u16 reg_ofst,
				   u8 *data, u8 length)
{
	u8 i, val;
	int rc;

	for (i = 0; i < length; i++) {
		val = data[i];
		rc = lan937x_pwrite8(dev, port, reg_ofst + i, val);
		if (rc)
			return rc;
	}
	return 0;
}

static int lan937x_acl_entry_write(struct ksz_device *dev,
				   u8 port, u8 entry_idx,
				   struct lan937x_acl_entry *acl_entry)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	struct lan937x_acl_access_ctl access_ctl;
	struct lan937x_acl_byte_en byte_en_cfg;
	u16 reg_ofst;
	int rc;

	reg_ofst = LAN937X_ACL_CTRL_BASE_ADDR + LAN937X_ACL_PORT_ADR_REG;
	pr_info("ACL MASK:");
	rc = lan937x_write_reg_block(dev, port, reg_ofst,
				     &acl_entry->acl_mask[0],
				     MAX_ACL_DATA_MASK_SIZE);
	pr_info("ACL DATA:");
	rc = lan937x_write_reg_block(dev, port,
				     reg_ofst + MAX_ACL_DATA_MASK_SIZE,
				     &acl_entry->acl_data[0],
				     MAX_ACL_DATA_MASK_SIZE);

	reg_ofst = LAN937X_ACL_CTRL_BASE_ADDR + LAN937X_ACL_PORT_AAR_REG;
	pr_info("ACL Action:");
	rc = lan937x_write_reg_block(dev, port, reg_ofst,
				     &acl_entry->acl_action[0],
				     MAX_ACL_ACTION_SIZE);

	memset(&byte_en_cfg, 0xFF, sizeof(struct lan937x_acl_byte_en));

	rc = lan937x_acl_byte_enable_write(dev, port, &byte_en_cfg);
	/*To-Do: to remove if not required*/
	/*Work Around suggestion as per Ethutil test scripts*/
	rc = lan937x_pwrite16(dev, port, 0x66C, 0xFFFF);

	rc = lan937x_pwrite16(dev, port, 0x672, 0xFFFF);

	pr_info("entry_idx %d", entry_idx);
	access_ctl.tcam_addr = entry_idx;
	res->tcam_entries_used[entry_idx] = true;
	access_ctl.tcam_vben = true;
	access_ctl.tcam_vbi = true;
	access_ctl.tcam_row_vld = 0x0F;
	access_ctl.tcam_req = TCAM_REQ_TYPE_WRITE_TCAM;
	access_ctl.tcam_acc = TCAM_MASK_DATA;

	rc = lan937x_set_acl_access_ctl(dev,
					port, &access_ctl);

	/*Test Code*/
	{
		access_ctl.tcam_req = TCAM_REQ_TYPE_READ_TCAM;
		lan937x_readback(dev, port, &access_ctl, 26);
	}
	return rc;
}

static int lan937x_acl_fill_entry(struct ksz_device *dev,
				  int port, u8 parser_idx,
				  enum lan937x_acl_dissector_type type,
				  struct lan937x_key *key,
				  struct lan937x_acl_entry *acl_entry)
{
	const struct lan937x_acl_rfr *rfr_ptr = acl_rfrs_table[parser_idx];
	u8 *mask = &acl_entry->acl_mask[1];
	u8 *data = &acl_entry->acl_data[1];
	struct vlan_tag *t_data;
	struct vlan_tag *t_msk;
	u8 ofst = 0;
	int i;

	for (i = 0; i < MAX_RFR_PER_PARSER; i++) {
		if (rfr_ptr[i].rfr_valid) {
			if (rfr_ptr[i].dissectors_covered & BIT(type)) {
				switch (type) {
				case acl_dst_mac_dissector:
					pr_info("acl_dst_mac_dissector");
					u64_to_ether_addr(key->dst_mac.mask,
							  &mask[ofst]);
					u64_to_ether_addr(key->dst_mac.value,
							  &data[ofst]);
					break;

				case acl_src_mac_dissector:
					pr_info("acl_src_mac_dissector");
					u64_to_ether_addr(key->src_mac.mask,
							  &mask[ofst]);
					u64_to_ether_addr(key->src_mac.value,
							  &data[ofst]);
					break;

				case acl_vlan_id_dissector:
					t_msk = (struct vlan_tag *)
							&mask[ofst];
					t_data = (struct vlan_tag *)
							&data[ofst];

					t_msk->tci[0] |= (key->vlan_id.mask
							 & 0x0F00) >> 8;
					t_msk->tci[1] |= (key->vlan_id.mask);
					t_data->tci[0] |= (key->vlan_id.value
							  & 0x0F00) >> 8;
					t_data->tci[1] |= (key->vlan_id.value);
					break;

				case acl_vlan_pcp_dissector:
					t_msk = (struct vlan_tag *)
							&mask[ofst];
					t_data = (struct vlan_tag *)
							&data[ofst];

					t_msk->tci[0] |= (key->vlan_prio.mask
							 & 0x07) << 5;
					t_data->tci[0] |= (key->vlan_prio.value
							  & 0x07) << 5;
					break;
				case acl_ethtype_dissector:
					mask[ofst] |= (key->ethtype.mask
						       & 0xFF00) >> 8;
					mask[ofst + 1] |= (key->ethtype.mask
							   & 0x00FF);
					data[ofst] |= (key->ethtype.value
						       & 0xFF00) >> 5;
					data[ofst + 1] |= (key->ethtype.mask
							   & 0x00FF);
					break;
				}
				return 0;
			}

			ofst += rfr_ptr[i].len;
		} else {
			return -EINVAL;
		}
	}
	return -EINVAL;
}

int lan937x_acl_program_entry(struct ksz_device *dev, int port,
			      struct lan937x_flower_rule *rule)
{
	struct lan937x_flower_action *action = &rule->flower->action;
	u32 actions_presence_mask = action->actions_presence_mask;
	struct lan937x_key *key = &rule->flower->filter.key;
	struct lan937x_resrc_alloc *resrc = rule->resrc;
	u16 acl_dissector_map = key->acl_dissector_map;
	struct lan937x_acl_entry *acl_entry;
	int rc = EINVAL;
	u8 *acl_action;
	u8 i;

	if (!(resrc->resrc_used_mask & BIT(LAN937X_TCAM_ENTRIES))) {
		pr_info("TCAM Not Used ");
		return 0;
	}

	acl_entry = kzalloc(sizeof(*acl_entry), GFP_KERNEL);

	if (!acl_entry)
		return -ENOSPC;

	for (i = 0; ((acl_dissector_map != 0) &&
		     (i < LAN937X_NUM_DISSECTORS_SUPPORTED)); i++) {
		if (acl_dissector_map & BIT(i)) {
			acl_dissector_map &= ~BIT(i);
			rc = lan937x_acl_fill_entry(dev, port,
						    resrc->type.tcam.parser,
						    i, key, acl_entry);
			if (rc)
				return rc;
		}
	}

	for (i = 0; ((actions_presence_mask != 0) &&
		     (i < LAN937X_NUM_ACTIONS_SUPPORTED)); i++) {
		if (actions_presence_mask & BIT(i)) {
			actions_presence_mask &= ~BIT(i);
			acl_action = acl_entry->acl_action;

			switch (i) {
			case LAN937X_ACT_REDIRECT_FLOW:
				acl_action[3] |= ((0x03 >> TCAM_AAR_MM_H_POS)
					  & LAN937X_ACL_AAR_MM_H);
				acl_action[4] |= ((0x03 << TCAM_AAR_MM_L_POS)
					  & LAN937X_ACL_AAR_MM_L);
				acl_action[4] |= ((action->redirect_port_mask
					       >> TCAM_AAR_DP_H_POS)
					      & LAN937X_ACL_AAR_DPORT_H);
				acl_action[5] |= ((action->redirect_port_mask
					       << TCAM_AAR_DP_L_POS)
					      & LAN937X_ACL_AAR_DPORT_L);
			break;
			case LAN937X_ACT_STREAM_POLICE:
			case LAN937X_ACT_STREAM_GATE:
				acl_action[0] |= ((resrc->type.strm_flt.en
						   << TCAM_AAR_STREAM_EN_POS)
						  & LAN937X_ACL_AAR_STREAM_EN);
				acl_action[0] |= (resrc->type.strm_flt.en
						  & LAN937X_ACL_AAR_STREAM_ID);
			break;
			case LAN937X_ACT_DROP:
				acl_action[3] |= ((0x03 >> TCAM_AAR_MM_H_POS)
						  & LAN937X_ACL_AAR_MM_H);
				acl_action[4] |= ((0x03 << TCAM_AAR_MM_L_POS)
						  & LAN937X_ACL_AAR_MM_L);
				acl_action[4] |= ((0x00 >> TCAM_AAR_DP_H_POS)
						  & LAN937X_ACL_AAR_DPORT_H);
				acl_action[5] |= ((0x00 << TCAM_AAR_DP_L_POS)
						  & LAN937X_ACL_AAR_DPORT_L);
			break;
			default:
				return -EINVAL;
			}
		}
	}

	acl_entry->acl_mask[0] |= 0x00;
	acl_entry->acl_data[0] |= (resrc->type.tcam.parser << 6);

	rc = lan937x_acl_entry_write(dev, port,
				     resrc->type.tcam.index, acl_entry);
	kfree(acl_entry);

	return rc;
}

static int lan937x_set_rfr_entry(struct ksz_device *dev, int port,
				 u8 parser_idx, u8 rfr_idx,
				 const struct lan937x_acl_rfr *rfr_entry)
{
	struct lan937x_rfr_reg_type rfr_data;
	u8 tcam_addr_access;
	u16 reg_ofst;
	int rc;

	tcam_addr_access = parser_idx % 2;

	reg_ofst = LAN937X_ACL_CTRL_BASE_ADDR + (rfr_idx * MAX_RFR_SIZE) +
			(tcam_addr_access * MAX_RFR_SIZE * MAX_RFR_PER_PARSER);

	rfr_data.u32value = ((rfr_entry->rng_match_en
			     << TCAM_RFR_RN_EN_POS) & TCAM_RFR_EN_RNGM);
	rfr_data.u32value |= ((rfr_entry->l4
			       << TCAM_RFR_L4_POS) & TCAM_RFR_L4);
	rfr_data.u32value |= ((rfr_entry->l3
			       << TCAM_RFR_L3_POS) & TCAM_RFR_L3);
	rfr_data.u32value |= ((rfr_entry->l2
			       << TCAM_RFR_L2_POS) & TCAM_RFR_L2);
	rfr_data.u32value |= (((rfr_entry->ofst >> 1)/*bytes to words*/
			       << TCAM_RFR_OFST_POS) & TCAM_RFR_OFST);
	rfr_data.u32value |= (((rfr_entry->len >> 1)/*bytes to words*/
			       << TCAM_RFR_LEN_POS) & TCAM_RFR_LEN);
	rfr_data.u32value |= ((rfr_entry->rng_ofst
			       << TCAM_RFR_RNG_POS) & TCAM_RFR_RNG_OFST);

	pr_info("Parser=%u,rfr_idx=%u, val=%x\r\n",
		parser_idx, rfr_idx, rfr_data.u32value);

	rc = lan937x_pwrite32(dev, port, reg_ofst, rfr_data.u32value);

	return rc;
}

static int lan937x_program_rfrs(struct ksz_device *dev,
				int port)
{
	struct lan937x_acl_access_ctl access_ctl;
	const struct lan937x_acl_rfr *rfr_entry;
	int parser_idx, rfr_idx;
	bool pgm_valid = false;
	int count = 0;
	int rc;

	pr_info("lan937x_program_rfrs");

	for (parser_idx = 0; parser_idx < MAX_ACL_PARSERS; parser_idx++) {
		count++;

		for (rfr_idx = 0; rfr_idx < MAX_RFR_PER_PARSER; rfr_idx++) {
			rfr_entry = &acl_rfrs_table[parser_idx][rfr_idx];

			if (rfr_entry->rfr_valid) {
				rc = lan937x_set_rfr_entry(dev, port,
							   parser_idx,
							   rfr_idx,
							   rfr_entry);
				if (rc)
					return rc;
				pgm_valid = true;
			} else {
				break;
			}
		}

		if (count == (MAX_PARSER_PER_ENTRY)) {
			/*only RFRs for 2 Parsers are programmable at once*/
			count = 0;

			if (!pgm_valid)
				continue;

			pgm_valid = false;

			if (parser_idx < MAX_PARSER_PER_ENTRY)
				access_ctl.tcam_addr = TCAM_PARSER_0_1;
			else
				access_ctl.tcam_addr = TCAM_PARSER_2_3;

			access_ctl.tcam_vben = true;
			access_ctl.tcam_vbi = true;
			access_ctl.tcam_row_vld = 0x0F;
			access_ctl.tcam_req = TCAM_REQ_TYPE_WRITE_RFR;
			access_ctl.tcam_acc = TCAM_MASK_DATA;

			rc = lan937x_set_acl_access_ctl(dev,
							port, &access_ctl);

			/*Test Code*/
			{
			access_ctl.tcam_req = TCAM_REQ_TYPE_READ_RFR;
			lan937x_readback(dev, port,
					 &access_ctl, 20);
			}
		}
	}
	return rc;
}

int lan937x_init_acl_parsers(struct ksz_device *dev, int port)
{
	int rc;
	u16 reg_ofst = LAN937X_ACL_CTRL_BASE_ADDR + LAN937X_ACL_PORT_PCTRL_REG;

	rc = lan937x_program_rfrs(dev, port);
	if (rc)
		return rc;

	rc = lan937x_pwrite32(dev, port,
			      reg_ofst,
			      (BIT(30) | BIT(18) |
			       BIT(26) | BIT(27) | BIT(14)));
	if (rc)
		return rc;

	rc = lan937x_pwrite8(dev, port, REG_PORT_RX_AUTH_CTL,
			     (BIT(2) | BIT(1)));
	/*Test Code*/
	{
		u32 test_val;

		rc = lan937x_pread32(dev, port,
				     reg_ofst,
				     &test_val);
		pr_info("PSRCTL: %x", test_val);
	}

	return rc;
}
