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


const struct lan937x_acl_rfr acl_rfrs_table[MAX_ACL_PARSER][MAX_RFR_PER_PARSER] = {
	{ /**RFRs Supported in PARSER 0*/
		{
			.rfr_valid = true,
			.dissectors_covered = BIT(acl_dst_mac_dissector),
			.l4 = false,
			.l3 = false,
			.l2 = true,
			.rng_match_en = false,
			.ofst = 0,
			.len = 6,
			.rng_ofst = 0, },

		{
			.rfr_valid = true,
			.dissectors_covered = BIT(acl_src_mac_dissector),
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
		{
			.rfr_valid = true,
			.dissectors_covered = BIT(acl_dst_mac_dissector),
			.l4 = false,
			.l3 = false,
			.l2 = true,
			.rng_match_en = false,
			.ofst = 0,
			.len = 6,
			.rng_ofst = 0, },

		{
			.rfr_valid = true,
			.dissectors_covered = BIT(acl_src_mac_dissector),
			.l4 = false,
			.l3 = false,
			.l2 = true,
			.rng_match_en = false,
			.ofst = 6,
			.len = 6,
			.rng_ofst = 0, },
		
		{
			.rfr_valid = true,
			.dissectors_covered = BIT(acl_vlan_id_dissector) | BIT(acl_vlan_pcp_dissector),
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
				u8 *parser_idx, u8 *num_entries)
{
	switch(filter_type) {
		case LAN937x_VLAN_UNAWARE_FILTER:
			*parser_idx = 0;
			*num_entries = 1;
			return 0;
		case LAN937x_VLAN_AWARE_FILTER:
			pr_info("lan937x_get_acl_requirements");
			*parser_idx = 1;
			*num_entries = 1;
			return 0;
	}
	return EINVAL;
}
 
static int lan937x_acl_byte_enable_write(struct ksz_device *dev,
				int port, struct lan937x_acl_byte_enable_reg *cfg)
{
	u16 reg_offset;
	u8 i,reg_val;
	u8* ptr = cfg->acl_mask;
	int rc;

	reg_offset= LAN937X_ACL_CTRL_BASE_ADDR + LAN937X_ACL_PORT_ABER_REG;

	i = 0;
	while (i< sizeof(struct lan937x_acl_byte_enable_reg)) {
		reg_val = ptr[i];
		rc= lan937x_pwrite8(dev, port, reg_offset + i, reg_val);
		pr_info("Byte En: %x,%d,%d",reg_val,i,rc);
		if (rc) {
			return rc;
		}
		i++;
	}

	return 0;
}
 
static int lan937x_wait_tcam_busy(struct ksz_device *dev, int port)
{
	bool busy;
	int timeout = 1000;
	u16 reg_offset =LAN937X_ACL_CTRL_BASE_ADDR +LAN937X_ACL_PORT_ARACR_REG;
	u32 reg_val = 0;
	int rc;
	
	do {
		rc =lan937x_pread32(dev,port, reg_offset, &reg_val);
		if (rc) {
			return EBUSY;
		}
		busy = (reg_val & LAN937X_ACL_PORT_ARACR_TCAM_OPERATION_STATUS);
		timeout--;
	} while(!busy && timeout);
	
	if (!timeout){
		pr_info("Timeout");
		return EBUSY; 
	}
	return 0;
}

 
static int lan937x_set_acl_access_control(struct ksz_device *dev, 
			int port, struct lan937x_acl_access_ctl_reg *access_ctrl)
{
	u32 reg_val;
	u16 reg_offset =LAN937X_ACL_CTRL_BASE_ADDR +LAN937X_ACL_PORT_ARACR_REG;
	int rc = lan937x_wait_tcam_busy(dev, port);

	pr_info("lan937x_set_acl_access_control");
	if(!rc) {
		reg_val =((access_ctrl->pri_low << TCAM_LO_PRI_POS) & LAN937X_ACL_PORT_ARACR_ADD_SHIFT_LO_PRI);
		reg_val |= ((access_ctrl->tcam_flush << TCAM_FLUSH_POS) & LAN937X_ACL_PORT_ARACR_TCAM_FLUSH);
		reg_val |= ((access_ctrl->tcam_vben << TCAM_VBEN_POS) & LAN937X_ACL_PORT_ARACR_TCAM_VBEN);
		reg_val |= ((access_ctrl->tcam_vbi << TCAM_VBI_POS) & LAN937X_ACL_PORT_ARACR_TCAM_VBI);
		reg_val |= ((access_ctrl->tcam_row_vld << TCAM_ROW_VLD_POS) & LAN937X_ACL_PORT_ARACR_TCAM_ROW_VLD);
		reg_val |= ((access_ctrl->row_shift << TCAM_START_ROW_SHIFT_POS) & LAN937X_ACL_PORT_ARACR_START_ROW_SHFIT);
		reg_val |= ((access_ctrl->tcam_req << TCAM_REQ_TYPE_POS) & LAN937X_ACL_PORT_ARACR_TCAM_REQ_TYPE);
		reg_val |= ((access_ctrl->tcam_acc<< TCAM_ACC_TYPE_POS) & LAN937X_ACL_PORT_ARACR_TCAM_ACC_TYPE);
		reg_val |= ((access_ctrl->num_shift<< TCAM_NUM_SHIFT_POS) & LAN937X_ACL_PORT_ARACR_TCAM_NUM_SHIFT);
		reg_val |= (access_ctrl->tcam_addr & LAN937X_ACL_PORT_ARACR_TCAM_ADDR_MASK);
		
		rc= lan937x_pwrite32(dev, port, reg_offset, reg_val);
		if (rc) {
		return rc;
		}
		
	rc = lan937x_wait_tcam_busy(dev, port);
	}
	return rc;
}


int lan937x_readback(struct ksz_device *dev, int port,
	 struct lan937x_acl_access_ctl_reg* ptcam_access_ctl,int size_dwords)
{
	u16 reg_offset;
	u8 i;
	u32 reg_val = 0;
	int rc;
	reg_offset= LAN937X_ACL_CTRL_BASE_ADDR + LAN937X_ACL_PORT_ADR_REG;


	/*Clear the ACL Data Reg before reading*/
	for (i =0; i<size_dwords; i++)
	{
		rc= lan937x_pwrite32 (dev, port, reg_offset + (4*i), reg_val);
		if (rc) {
			return rc;
		}
	}

	rc = lan937x_set_acl_access_control(dev, 
			port, ptcam_access_ctl);
	pr_info("**************Readback*********************");
	for (i =0; i<size_dwords; i++)
	{
		rc= lan937x_pread32 (dev, port, reg_offset + (4*i), &reg_val);
		pr_info("%x",reg_val);
		if (rc) {
			return rc;
		}
	}
	pr_info("***********************************");

	return rc;	
}

static int lan937x_write_reg_block (struct ksz_device *dev,\
				u8 port,u16 reg_offset,u8* data, u8 length)
{
	u8 i,reg_val;
	int rc = 0;
	for (i=0;i<length;i++) {
		reg_val = data[i];
		pr_info("%x",reg_val);
		rc= lan937x_pwrite8(dev, port, reg_offset + i, reg_val);
		if (rc) {
			return rc;
		}
	}
	return rc;
}

static int lan937x_acl_entry_write(struct ksz_device *dev, 
				u8 port, u8 tcam_entry_index, struct lan937x_acl_entry *acl_entry)
{
	u16 reg_offset;
	u8 i,reg_val;
	int rc;
	struct lan937x_acl_access_ctl_reg tcam_access_ctl;
	struct lan937x_acl_byte_enable_reg byte_en_cfg;

	reg_offset= LAN937X_ACL_CTRL_BASE_ADDR + LAN937X_ACL_PORT_ADR_REG;
	pr_info("ACL MASK:");
	rc = lan937x_write_reg_block (dev, port, reg_offset,
				 &acl_entry->acl_mask[0],MAX_ACL_DATA_MASK_SIZE);

	pr_info("ACL DATA:");
	rc = lan937x_write_reg_block (dev, port, reg_offset + MAX_ACL_DATA_MASK_SIZE,
				 &acl_entry->acl_data[0],MAX_ACL_DATA_MASK_SIZE);

	reg_offset= LAN937X_ACL_CTRL_BASE_ADDR + LAN937X_ACL_PORT_AAR_REG;
	pr_info("ACL Action:");
	rc = lan937x_write_reg_block (dev, port, reg_offset,
				 &acl_entry->acl_action[0],MAX_ACL_ACTION_SIZE);

	memset(&byte_en_cfg,0xFF,sizeof(struct lan937x_acl_byte_enable_reg));

	rc =lan937x_acl_byte_enable_write(dev, port,&byte_en_cfg);

	/*Work Around suggestion as per Ethutil test scripts*/
	rc= lan937x_pwrite16(dev, port, 0x66C, 0xFFFF);

	rc= lan937x_pwrite16(dev, port, 0x672, 0xFFFF);
	/******************************************************/

	pr_info("tcam_access_ctl %d",tcam_entry_index);
	tcam_access_ctl.tcam_addr = tcam_entry_index;
	dev->flower_block[port].flow_resources.tcam_entries_used[tcam_entry_index] = true;
	tcam_access_ctl.tcam_vben = true;
	tcam_access_ctl.tcam_vbi= true;
	tcam_access_ctl.tcam_row_vld = 0x0F;
	tcam_access_ctl.tcam_req = TCAM_REQ_TYPE_WRITE_TCAM;
	tcam_access_ctl.tcam_acc = TCAM_MASK_DATA;

	rc = lan937x_set_acl_access_control(dev, 
			port, &tcam_access_ctl);

	/*Test Code*/
	{
		u32 test_val;
		tcam_access_ctl.tcam_req = TCAM_REQ_TYPE_READ_TCAM;
		lan937x_readback(dev, port,&tcam_access_ctl,26);
		rc= lan937x_pread32 (dev, port, 0x67C, &test_val);
		pr_info("PSRCTL: %x",test_val);
	}
	return rc;
}


static int lan937x_acl_fill_entry_layout (struct ksz_device *dev, 
						int port, u8 parser_idx,
						enum lan937x_acl_dissector_type dissector_type,
						struct lan937x_key *key,
						struct lan937x_acl_entry *acl_entry)
{
	struct lan937x_acl_rfr *rfr_ptr = acl_rfrs_table[parser_idx];
	int i;
	u8 *ptr_acl_mask;//= &acl_entry->acl_mask[0];
	u8 *ptr_acl_data;//= &acl_entry->acl_data[0];

	//if (parser_idx) {
	ptr_acl_mask = &acl_entry->acl_mask[1];
	ptr_acl_data = &acl_entry->acl_data[1];
	//}

	pr_info("lan937x_acl_fill_entry_layout");

	for (i=0; i<MAX_RFR_PER_PARSER;i++) {
		if(rfr_ptr[i].rfr_valid) {
			if(rfr_ptr[i].dissectors_covered & BIT(dissector_type)) {
				switch (dissector_type) {
					case acl_dst_mac_dissector:
						pr_info("acl_dst_mac_dissector");
						u64_to_ether_addr(key->dst_mac.mask,ptr_acl_mask);
						u64_to_ether_addr(key->dst_mac.value,ptr_acl_data);
					break;

					case acl_src_mac_dissector:
						pr_info("acl_src_mac_dissector");
						u64_to_ether_addr(key->src_mac.mask,&ptr_acl_mask[6]);
						u64_to_ether_addr(key->src_mac.value,&ptr_acl_data[6]);
					break;

					case acl_vlan_id_dissector:
						pr_info("acl_vlan_id_dissector");
						ptr_acl_mask[14] |= (key->vlan_id.mask & 0x0F00) >> 8;
						ptr_acl_mask[15] |= (key->vlan_id.mask);
						ptr_acl_data[14] |= (key->vlan_id.value & 0x0F00) >> 8;
						ptr_acl_data[15] |= (key->vlan_id.value);						
					break;

					case acl_vlan_pcp_dissector:
						pr_info("acl_vlan_pcp_dissector");
						ptr_acl_mask[14] |= (key->vlan_prio.mask & 0x07) << 5;
						ptr_acl_data[14] |= (key->vlan_prio.value & 0x07) << 5;
					break;

					case acl_ethtype_dissector:
						pr_info("acl_ethtype_dissector");
						u8 idx = 12;	/**Parser Properties to be defined*/
						if (parser_idx == 0x01)
							if (rfr_ptr[i].dissectors_covered &
								 (BIT(acl_vlan_id_dissector) | BIT(acl_vlan_pcp_dissector)))
								 idx += 4; //Compensate the Vlan tag presence

						ptr_acl_mask[idx] |= (key->ethtype.mask & 0xFF00) >> 8;
						ptr_acl_mask[idx+1] |= (key->ethtype.mask & 0x00FF);
						ptr_acl_data[idx] |= (key->ethtype.value & 0xFF00) >> 5;
						ptr_acl_data[idx+1] |= (key->ethtype.mask & 0x00FF);
					break;
				}
				return 0;
			}
		}
	}
	return EINVAL;
}

int lan937x_acl_program_entry (struct ksz_device *dev, int port, 
		struct lan937x_flower_rule *rule)
{
	struct lan937x_key *key = &rule->pflower_params->filter.key;
	struct lan937x_flower_action *action = &rule->pflower_params->action;
	struct lan937x_rule_resource *resrc = rule->prule_resource;
	u16 acl_dissector_map = key->acl_dissector_map;
	u32 actions_presence_mask = action->actions_presence_mask;
	struct lan937x_acl_rfr* rfr;
	struct lan937x_acl_entry *acl_entry;
	u8 i;
	int rc = EINVAL;

	if (!(resrc->resource_used_mask 
				& BIT(LAN937X_TCAM_ENTRIES))){
		pr_info("TCAM Not Used ");
		return 0;
	}

	acl_entry = kzalloc(sizeof(struct lan937x_acl_entry), GFP_KERNEL);

	if(!acl_entry)
		return ENOSPC;

	for (i = 0; (acl_dissector_map!=0) && (i < LAN937X_NUM_DISSECTORS_SUPPORTED); i++) {
		pr_info("acl_dissector_map %x",acl_dissector_map);
		if(acl_dissector_map & BIT(i)) {
			acl_dissector_map &= ~BIT(i);
			rc = lan937x_acl_fill_entry_layout (dev, port,\
					 resrc->resource.tcam.parser,i,key, acl_entry);
			if (rc)
				return rc;
		}
	}

	for (i = 0; (actions_presence_mask!=0) && (i < LAN937X_NUM_ACTIONS_SUPPORTED); i++) {
		if(actions_presence_mask & BIT(i)) {
			actions_presence_mask &= ~BIT(i);
			switch (i) {
				case LAN937X_ACTION_REDIRECT_FLOW:
					acl_entry->acl_action[3] |= ((0x03 >> TCAM_AAR_MM_DATA_H_POS)
														 & LAN937X_ACL_PORT_AAR_MM_H);
					acl_entry->acl_action[4] |= ((0x03 << TCAM_AAR_MM_L_DATA_POS) 
														 & LAN937X_ACL_PORT_AAR_MM_L);
					acl_entry->acl_action[4] |= ((action->redirect_port_mask >> TCAM_AAR_PORT_DATA_H_POS) 
														 & LAN937X_ACL_PORT_AAR_DPORT_H);
					acl_entry->acl_action[5] |= ((action->redirect_port_mask << TCAM_AAR_PORT_DATA_L_POS) 
														 & LAN937X_ACL_PORT_AAR_DPORT_L);
				break;
				case LAN937X_ACTION_STREAM_POLICE:
				case LAN937X_ACTION_STREAM_GATE:
					acl_entry->acl_action[0] |= ((resrc->resource.stream_filter.en 
								<< TCAM_AAR_STREAM_EN_POS) & LAN937X_ACL_PORT_AAR_STREAM_EN);
					acl_entry->acl_action[0] |= (resrc->resource.stream_filter.en 
								& LAN937X_ACL_PORT_AAR_STREAM_ID);				
				break;
				case LAN937X_ACTION_DROP:
					acl_entry->acl_action[3] |= ((0x03 >> TCAM_AAR_MM_DATA_H_POS)
														 & LAN937X_ACL_PORT_AAR_MM_H);
					acl_entry->acl_action[4] |= ((0x03 << TCAM_AAR_MM_L_DATA_POS) 
														 & LAN937X_ACL_PORT_AAR_MM_L);
					acl_entry->acl_action[4] |= ((0x00 >> TCAM_AAR_PORT_DATA_H_POS) 
														 & LAN937X_ACL_PORT_AAR_DPORT_H);
					acl_entry->acl_action[5] |= ((0x00 << TCAM_AAR_PORT_DATA_L_POS) 
														 & LAN937X_ACL_PORT_AAR_DPORT_L);				
				break;
				default:
					return EINVAL;
			}
		}
	}

	// if (!rc) {
	// 	acl_entry->acl_action[0]= ((rule->acl_action.frm_ts << TCAM_AAR_TS_POS) & LAN937X_ACL_PORT_AAR_TS);
	// 	acl_entry->acl_action[0] |= ((rule->acl_action.frm_cnt_en << TCAM_AAR_COUNT_POS) & LAN937X_ACL_PORT_AAR_COUNT);
	// 	acl_entry->acl_action[0] |= ((rule->acl_action.cnt_sel << TCAM_AAR_COUNT_SEL_POS) & LAN937X_ACL_PORT_AAR_COUNT_SEL);
	// 	acl_entry->acl_action[0] |= ((rule->acl_action.str_en << TCAM_AAR_STREAM_EN_POS) & LAN937X_ACL_PORT_AAR_STREAM_EN);
	// 	acl_entry->acl_action[0] |= (rule->acl_action.str_idx & LAN937X_ACL_PORT_AAR_STREAM_ID);
	// 	acl_entry->acl_action[1] = ((rule->acl_action.rep_vlan_en << TCAM_AAR_RVTG_POS) & LAN937X_ACL_PORT_AAR_RVTG);
	// 	acl_entry->acl_action[1] |= ((rule->acl_action.vlan_id >> TCAM_AAR_VID_DATA_H_POS) & LAN937X_ACL_PORT_AAR_VID_H);
	// 	acl_entry->acl_action[2] = ((rule->acl_action.vlan_id << TCAM_AAR_VID_DATA_L_POS ) & LAN937X_ACL_PORT_AAR_VID_L);
	// 	acl_entry->acl_action[2] |= (rule->acl_action.pri_mode & LAN937X_ACL_PORT_AAR_QUE_EN);
	// 	acl_entry->acl_action[3] = ((rule->acl_action.que_sel << TCAM_AAR_QUE_SEL_POS) & LAN937X_ACL_PORT_AAR_QUE_SEL);
	// 	acl_entry->acl_action[3] |= ((rule->acl_action.remark_pri_en << TCAM_AAR_RP_POS) & LAN937X_ACL_PORT_AAR_RP);
	// 	acl_entry->acl_action[3] |= ((rule->acl_action.pri << TCAM_AAR_PRI_POS) & LAN937X_ACL_PORT_AAR_PRI);
	// 	acl_entry->acl_action[3] |= ((rule->acl_action.map_mode >> TCAM_AAR_MM_DATA_H_POS) & LAN937X_ACL_PORT_AAR_MM_H);
	// 	acl_entry->acl_action[4] = ((rule->acl_action.map_mode << TCAM_AAR_MM_L_DATA_POS) & LAN937X_ACL_PORT_AAR_MM_L);
	// 	acl_entry->acl_action[4] |= ((rule->acl_action.dst_port >> TCAM_AAR_PORT_DATA_H_POS) & LAN937X_ACL_PORT_AAR_DPORT_H);
	// 	acl_entry->acl_action[5] = ((rule->acl_action.dst_port << TCAM_AAR_PORT_DATA_L_POS) & LAN937X_ACL_PORT_AAR_DPORT_L);
	// }

	//if (resrc->resource.tcam.parser) {
	acl_entry->acl_mask[0]|= 0x00;
	acl_entry->acl_data[0]|= (resrc->resource.tcam.parser << 6);
	//}

	rc = lan937x_acl_entry_write(dev, port, resrc->resource.tcam.start_index,acl_entry);
	kfree(acl_entry);

	return rc;

}

static int lan937x_set_rfr_entry(struct ksz_device *dev, int port, u8 parser_idx,
	u8 rfr_idx,const struct lan937x_acl_rfr *rfr_entry)
{
	struct lan937x_rfr_reg_type rfr_data;
	u16 reg_offset;
	u32 reg_val;
	int rc =EINVAL;
	u8 tcam_addr_access;

	tcam_addr_access = parser_idx % 2;

	reg_offset = LAN937X_ACL_CTRL_BASE_ADDR + (rfr_idx *MAX_RFR_SIZE) + 
	(tcam_addr_access * MAX_RFR_SIZE * MAX_RFR_PER_PARSER);

	rfr_data.u32value = ((rfr_entry->rng_match_en
			<< TCAM_RFR_RN_EN_POS) & TCAM_RFR_EN_RNGM);
	rfr_data.u32value|= ((rfr_entry->l4 
			<< TCAM_RFR_L4_POS) & TCAM_RFR_L4);
	rfr_data.u32value|= ((rfr_entry->l3 
			<< TCAM_RFR_L3_POS) & TCAM_RFR_L3);
	rfr_data.u32value|= ((rfr_entry->l2 
			<< TCAM_RFR_L2_POS) & TCAM_RFR_L2);
	rfr_data.u32value|= (((rfr_entry->ofst >> 1)/*bytes to words*/
			<< TCAM_RFR_OFST_POS) & TCAM_RFR_OFST);
	rfr_data.u32value|= (((rfr_entry->len >> 1)/*bytes to words*/
			<< TCAM_RFR_LEN_POS) & TCAM_RFR_LEN);
	rfr_data.u32value|= ((rfr_entry->rng_ofst 
			<< TCAM_RFR_RNG_POS) & TCAM_RFR_RNG_OFST);

	pr_info("Offset:%x,Parser=%hu,rfr_idx=%hu, reg_val=%x\r\n",reg_offset,parser_idx,rfr_idx,rfr_data.u32value);

	rc = lan937x_pwrite32(dev, port,reg_offset, rfr_data.u32value);

	return rc;
}


static int lan937x_program_rfrs(struct ksz_device *dev, 
							int port)
{
	const struct lan937x_acl_rfr* rfr_entry;
	struct lan937x_acl_access_ctl_reg tcam_access_ctl;
	int rc= EINVAL;
	bool pgm_valid = false;
	int parser_idx,rfr_idx;
	int count = 0;

	pr_info("lan937x_program_rfrs");

	for (parser_idx = 0; parser_idx<MAX_ACL_PARSERS; parser_idx++) {
		for (rfr_idx=0; rfr_idx < MAX_RFR_PER_PARSER; rfr_idx++) {
			rfr_entry = &acl_rfrs_table[parser_idx][rfr_idx];
			if (rfr_entry->rfr_valid) {
				pr_info("rfr_valid");
				rc = lan937x_set_rfr_entry(dev, port, parser_idx,
											rfr_idx, rfr_entry);
				if (rc)
					return rc;
				pgm_valid = true;
			} else {
				break;
			}
		}

		count++;
		if(count == (MAX_PARSER_PER_ENTRY)){
			/*only RFRs for 2 Parsers programmable at once*/
			count = 0;
			if (pgm_valid){
				pgm_valid = false;
				if(parser_idx < MAX_PARSER_PER_ENTRY) {
					tcam_access_ctl.tcam_addr = TCAM_PARSER_0_1;
				}else{
					tcam_access_ctl.tcam_addr = TCAM_PARSER_2_3;
				}
				tcam_access_ctl.tcam_vben = true;
				tcam_access_ctl.tcam_vbi = true;
				tcam_access_ctl.tcam_row_vld = 0x0F;
				tcam_access_ctl.tcam_req = TCAM_REQ_TYPE_WRITE_RFR;
				tcam_access_ctl.tcam_acc = TCAM_MASK_DATA;

				rc = lan937x_set_acl_access_control(dev, 
				port, &tcam_access_ctl);

				/*Test Code*/{
				tcam_access_ctl.tcam_req = TCAM_REQ_TYPE_READ_RFR;
				lan937x_readback(dev, port,
						&tcam_access_ctl,20);
				}
			}
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

	rc = lan937x_pwrite32(dev, port,\
		LAN937X_ACL_CTRL_BASE_ADDR+LAN937X_ACL_PORT_PCTRL_REG,\
		 (BIT(30)|BIT(18)|BIT(26)|BIT(27)|BIT(14)));
	if (rc)
		return rc;

	rc = lan937x_pwrite8(dev, port,REG_PORT_RX_AUTH_CTL, (BIT(2) | BIT(1)));

	return rc;
}
