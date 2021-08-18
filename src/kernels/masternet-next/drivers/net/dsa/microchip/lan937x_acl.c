// SPDX-License-Identifier: GPL-2.0
/* Microchip lan937x dev ops functions
 * Copyright (C) 2019-2021 Microchip Technology Inc.
 */
#include <net/dsa.h>
#include <net/switchdev.h>
#include "lan937x_reg.h"
#include "ksz_common.h"
#include "lan937x_dev.h"
#include "lan937x_tc.h"
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

int lan937x_get_acl_req(enum lan937x_filter_type filter_type,
			u8 *parser_idx, u8 *n_entries)
{
	switch (filter_type) {

	case LAN937x_VLAN_UNAWARE_FILTER:
		*parser_idx = 0;
		*n_entries = 1;	/*Also determines num parsers*/
		break;
	case LAN937x_VLAN_AWARE_FILTER:
		*parser_idx = 1;
		*n_entries = 1; /*Also determines num parsers*/
		break;
	case LAN937x_BCAST_FILTER:
	default:
		return -EINVAL;

	}

	return 0;
}

static int lan937x_wait_tcam_busy(struct ksz_device *dev, int port)
{
	int timeout_us = 1000; /**To-Do: Proper Justification needed*/
	int poll_us = 10;
	unsigned int val;
	int rc;
	
	rc = regmap_read_poll_timeout(dev->regmap[2], 
				      (ACL_CTRL_PORT_BASE_ADDR(port) + 
				       REG_ACL_PORT_ARACR),
				      val, 
				      val & ACL_ARACR_TCAM_OP_STS,
				      poll_us, 
				      timeout_us);
	/*For debugging*/
	if (rc == -ETIMEDOUT) {
		pr_info("Timeout");
	}
	return rc;
}

static int lan937x_set_acl_access_ctl(struct ksz_device *dev,
				      int port,
				      struct lan937x_acl_access_ctl *acc_ctl)
{
	int rc = lan937x_wait_tcam_busy(dev, port);
	u32 val;

	if (rc)
		return rc;

	val = acl_acc_ctl(acc_ctl);
	
	rc = lan937x_pwrite32(dev, port, REG_ACL_PORT_ARACR, val);
	if (rc)
		return rc;

	rc = lan937x_wait_tcam_busy(dev, port);
	return rc;
}

static int lan937x_readback(struct ksz_device *dev, int port,
			    struct lan937x_acl_access_ctl *access_ctl,
			    int size_dwords)
{
	u32 val = 0;
	int rc;
	u8 i;

	/*Clear the ACL Data Reg before reading*/
	for (i = 0; (i < (TCAM_ADR_SIZE/4)+2); i++) {
		rc = lan937x_pwrite32(dev, port, REG_ACL_PORT_ADR + (4 * i), val);
		if (rc)
			return rc;
	}

	rc = lan937x_set_acl_access_ctl(dev,
					port, access_ctl);
	if(rc)
		return rc;
	pr_info("**************Readback*********************");

	for (i = 0; i < size_dwords; i++) {
		rc = lan937x_pread32(dev, port, REG_ACL_PORT_ADR + (4 * i), &val);
		pr_info("%x", val);
		if (rc)
			return rc;
	}
	pr_info("***********************************");

	return rc;
}

static int lan937x_acl_entry_write(struct ksz_device *dev,
				   u8 port, u8 entry_idx,
				   struct lan937x_acl_entry *acl_entry)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	struct lan937x_acl_access_ctl access_ctl;
	struct lan937x_acl_byte_en byte_en_cfg;
	int rc;

	pr_info("ACL MASK:");
	rc = lan937x_pwrite8_bulk(dev, port, REG_ACL_PORT_ADR,
				  &acl_entry->acl_mask[0], 
				  MAX_ACL_DATA_MASK_SIZE);
	if (rc)
		return rc;

	pr_info("ACL DATA:");
	rc = lan937x_pwrite8_bulk(dev, port, 
				  REG_ACL_PORT_ADR + MAX_ACL_DATA_MASK_SIZE,
				  &acl_entry->acl_data[0], 
				  MAX_ACL_DATA_MASK_SIZE);	
	if (rc)
		return rc;

	pr_info("ACL Action:");
	rc = lan937x_pwrite8_bulk(dev, port, REG_ACL_PORT_AAR,
				  &acl_entry->acl_action[0], 
				  MAX_ACL_ACTION_SIZE);	
	if (rc)
		return rc;

	memset(&byte_en_cfg, 0xFF, sizeof(byte_en_cfg));
	rc = lan937x_pwrite8_bulk(dev, port, REG_ACL_PORT_ABER,
				  &byte_en_cfg.acl_mask[0],
				  sizeof(byte_en_cfg));
	if (rc)
		return rc;

	/*To-Do: to remove if not required*/
	/*Work Around suggestion as per Ethutil test scripts*/
	rc = lan937x_pwrite16(dev, port, 0x66C, 0xFFFF);
	if (rc)
		return rc;	
	rc = lan937x_pwrite16(dev, port, 0x672, 0xFFFF);
	if (rc)
		return rc;

	pr_info("entry_idx %d", entry_idx);
	clr_data(access_ctl);
	set_tcam_addr(access_ctl,entry_idx);
	set_pri_low(access_ctl, true);
	set_tcam_vben(access_ctl, true);
	set_tcam_vbi(access_ctl, true);
	set_tcam_row_vld(access_ctl, 0x0F);
	set_tcam_req(access_ctl, TCAM_REQ_TYPE_WRITE_TCAM);
	set_tcam_acc(access_ctl, TCAM_MASK_DATA);
	
	rc = lan937x_set_acl_access_ctl(dev,
					port, &access_ctl);
	if (rc)
		return rc;
	/*Test Code*/
	{
		rc = lan937x_pwrite8_bulk(dev, port, REG_ACL_PORT_ABER,
					  &byte_en_cfg.acl_mask[0],
					  sizeof(byte_en_cfg));
		set_tcam_req(access_ctl, TCAM_REQ_TYPE_READ_TCAM);
		lan937x_readback(dev, port, &access_ctl, 26);
	}

	res->tcam_entries_used[entry_idx] = true;	
	return rc;
}

static int lan937x_acl_fill_entry(struct ksz_device *dev,
				  int port, u8 parser_idx,
				  enum lan937x_acl_dissector_type type,
				  struct lan937x_key *key,
				  struct lan937x_acl_entry *acl_entry)
{
	const struct lan937x_acl_rfr *rfr_ptr = acl_rfrs_table[parser_idx];
	u8 *mask = &acl_entry->acl_mask[TCAM_MULTI_KEY_ENTRY_START];
	u8 *data = &acl_entry->acl_data[TCAM_MULTI_KEY_ENTRY_START];
	struct vlan_tag *t_data;
	struct vlan_tag *t_msk;
	u8 ofst = 0;
	int i;

	for (i = 0; i < MAX_RFR_PER_PARSER; i++) {

		if (!(rfr_ptr[i].rfr_valid)) 
			return -EINVAL; /*Dissector not part of Parser*/

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
				t_msk = (struct vlan_tag *)&mask[ofst];
				t_data = (struct vlan_tag *)&data[ofst];

				t_msk->tci[0] |= (key->vlan_id.mask
							& 0x0F00) >> 8;
				t_msk->tci[1] |= (key->vlan_id.mask);
				t_data->tci[0] |= (key->vlan_id.value
							& 0x0F00) >> 8;
				t_data->tci[1] |= (key->vlan_id.value);
				break;

			case acl_vlan_pcp_dissector:
				t_msk = (struct vlan_tag *)&mask[ofst];
				t_data = (struct vlan_tag *)&data[ofst];

				t_msk->tci[0] |= (key->vlan_prio.mask
							& 0x07) << 5;
				t_data->tci[0] |= (key->vlan_prio.value
							& 0x07) << 5;
				break;
				
			case acl_ethtype_dissector:
				mask[ofst] |= ((key->ethtype.mask
						& 0xFF00) >> 8);
				mask[ofst + 1] |= (key->ethtype.mask & 0x00FF);
				data[ofst] |= (key->ethtype.value
						& 0xFF00) >> 5;
				data[ofst + 1] |= (key->ethtype.mask & 0x00FF);
				break;
			}
			return 0;
		}
		ofst += rfr_ptr[i].len;
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
	u8 n_entries;
	u8 parser;
	u8 i,j;

	n_entries = resrc->type.tcam.n_entries;
	parser = resrc->type.tcam.parser;

	acl_entry = devm_kzalloc(dev->dev, sizeof(*acl_entry) * n_entries, 
				 GFP_KERNEL);

	if (!acl_entry)
		return -ENOSPC;

	for (i = 0; ((acl_dissector_map != 0) &&
		     (i < LAN937X_NUM_DISSECTORS_SUPPORTED)); i++) {

		if (!(acl_dissector_map & BIT(i)))
			continue;

		acl_dissector_map &= ~BIT(i);

		for (j = 0; j < n_entries; j++) {
			rc = lan937x_acl_fill_entry(dev, port,parser + j ,
						    i, key, &acl_entry[j]);
			if (!rc)
				break;
		}
		if (rc)
			goto out;
	}

	for (i = 0; ((actions_presence_mask != 0) &&
		     (i < LAN937X_NUM_ACTIONS_SUPPORTED)); i++) {

		if (!(actions_presence_mask & BIT(i)))
			continue;

		actions_presence_mask &= ~BIT(i);

		/**Only use the first entry to fill the action*/
		acl_action = acl_entry[0].acl_action;

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
			acl_action[0] |= (resrc->type.strm_flt.index
						& LAN937X_ACL_AAR_STREAM_ID);
			/*acl_action[0] |= (1 << TCAM_AAR_COUNT_POS);*/
						
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
			rc = -EINVAL;
			goto out;
		}
		
	}

	/* For Multiple format Key
	Bit 383:382 PARSER_NUM Programmed to the 1st parser used TCAM rule*/
	for (j = 0; j < n_entries; j++) {
		acl_entry[j].acl_mask[0] |= ((~(parser /*+ j*/)) << 6);
		acl_entry[j].acl_data[0] |= ((parser /*+ j*/) << 6);
		
		rc = lan937x_acl_entry_write(dev, port,
					     resrc->type.tcam.index + j,
					     &acl_entry[j]);
		if (rc)
			break;					     
	}
out:
	devm_kfree(dev->dev,acl_entry);
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

	reg_ofst = ACL_CTRL_BASE_ADDR + (rfr_idx * MAX_RFR_SIZE) +
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

			if (!(rfr_entry->rfr_valid))
				break;

			rc = lan937x_set_rfr_entry(dev, port, parser_idx,
						   rfr_idx, rfr_entry);
			if (rc)
				return rc;
			pgm_valid = true;
			
		}

		/* At once Rule Format regs for 2 Parsers are programmable */
		if (count != (MAX_PARSER_PER_ENTRY))
			continue;
		
		count = 0;

		if (!pgm_valid)
			continue;

		pgm_valid = false;
		clr_data(access_ctl);
		if (parser_idx < MAX_PARSER_PER_ENTRY)
			set_tcam_addr(access_ctl, TCAM_PARSER_0_1);
		else
			set_tcam_addr(access_ctl, TCAM_PARSER_2_3);

		set_tcam_vben(access_ctl, true);
		set_tcam_vbi(access_ctl, true);
		set_tcam_row_vld(access_ctl, 0x0F);
		set_tcam_req(access_ctl, TCAM_REQ_TYPE_WRITE_RFR);
		set_tcam_acc(access_ctl, TCAM_MASK_DATA);

		rc = lan937x_set_acl_access_ctl(dev, port, &access_ctl);
		if (rc)
			return rc;
		/*Test Code*/
		{
			set_tcam_req(access_ctl, TCAM_REQ_TYPE_READ_RFR);
			lan937x_readback(dev, port, &access_ctl, 20);
		}
	}
	return rc;
}

int lan937x_init_acl_parsers(struct ksz_device *dev, int port)
{
	int rc;

	rc = lan937x_program_rfrs(dev, port);
	if (rc)
		return rc;

	rc = lan937x_pwrite32(dev, port, REG_ACL_PORT_PCTRL,
			      (BIT(30) | BIT(18) |
			       BIT(26) | BIT(27) | BIT(14)));
	if (rc)
		return rc;

	rc = lan937x_pwrite8(dev, port, REG_PORT_RX_AUTH_CTL,
			     (BIT(2) | BIT(1)));
	if (rc)
		return rc;
	/*Test Code*/
	{
		u32 test_val;

		rc = lan937x_pread32(dev, port, REG_ACL_PORT_PCTRL, &test_val);
		if (rc)
			return rc;				     
		pr_info("PSRCTL: %x", test_val);
	}

	return rc;
}

int lan937x_acl_free_entry(struct ksz_device *dev, int port,
			   struct lan937x_flower_rule *rule)
{
	struct lan937x_flr_blk *blk = lan937x_get_flr_blk(dev, port);
	struct lan937x_resrc_alloc *resrc = rule->resrc;
	struct lan937x_acl_access_ctl access_ctl;
	struct lan937x_flower_rule *nxt_rule;
	u8 n_entries;
	u8 i, row;
	int rc;

	n_entries = resrc->type.tcam.n_entries;
	pr_info("n_entries %d", n_entries);

	if (!n_entries)
		return 0; // Nothing to delete
	
	for (i = 0; i< n_entries; i++) {
		clr_data(access_ctl);
		set_tcam_addr(access_ctl,resrc->type.tcam.index + i);
		set_pri_low(access_ctl,true);
		set_tcam_vben(access_ctl,true);
		/*vbi - 0: TCAM entry is invalid.*/
		set_tcam_vbi(access_ctl,false);
		set_tcam_row_vld(access_ctl,0x0F);
		set_tcam_req(access_ctl,TCAM_REQ_TYPE_WRITE_TCAM);
		set_tcam_acc(access_ctl,TCAM_MASK_DATA);
		pr_info("Invalidate Entry %x", access_ctl.tcam_addr);
		pr_info("Invalidate Entry %x", access_ctl.tcam_addr);
		rc = lan937x_set_acl_access_ctl(dev, port, &access_ctl);
		if (rc)
			return rc;
	}

	/* If deleted rule is occupying the last row of tcam
	   then shifting the rows is not necessry */
	if ((i + resrc->type.tcam.index) >= LAN937X_NUM_TCAM_ENTRIES) 
		goto clr_sts;

	/* Shift the TCAM Entries up to fillup the hole */
	clr_data(access_ctl);
	set_row_shift(access_ctl, i + resrc->type.tcam.index);

	if(-ENOSPC == lan937x_assign_tcam_entries(dev, port, 0x01,
						  &access_ctl.tcam_addr))
		set_tcam_addr(access_ctl, LAN937X_NUM_TCAM_ENTRIES - 1);

	set_pri_low(access_ctl, true);
	set_tcam_vben(access_ctl, true);
	set_tcam_vbi(access_ctl, false);
	set_tcam_row_vld(access_ctl, 0x0F);
	set_num_shift(access_ctl, n_entries);
	set_tcam_req(access_ctl, TCAM_REQ_TYPE_SHIFT_TCAM);
	set_tcam_acc(access_ctl, TCAM_MASK_DATA);

	rc = lan937x_set_acl_access_ctl(dev, port, &access_ctl);		
	if (rc)
		return rc;

	pr_info("Shifting %d till %d", access_ctl.row_shift, 
		access_ctl.tcam_addr);
	/*Deleted rule no longer has any tcam entries
	The hole created due to eletion is just filled by shift operation*/
	resrc->type.tcam.n_entries = 0x00;

	/*Adjust the start index of all the flower rules
	occupying tcam rows below the deleted entry */
	nxt_rule = rule;
	while(false == list_is_last(&nxt_rule->list,&blk->rules)) {

		list_next_entry(nxt_rule, list);

		resrc = nxt_rule->resrc;
		if(resrc->type.tcam.n_entries) {
			resrc->type.tcam.index = resrc->type.tcam.index - 
						 access_ctl.num_shift;
		}
	}

clr_sts:
	/* Clear the status of freed up rows to "Available for new rule" */
	if(-ENOSPC == lan937x_assign_tcam_entries(dev, port, 0x01, &row))
		row = LAN937X_NUM_TCAM_ENTRIES;

	for (i = 0; i< n_entries; i++) {
		--row;
		blk->res.tcam_entries_used[row] = false;
		pr_info("freed %d", row);
	}
	return rc;
}


