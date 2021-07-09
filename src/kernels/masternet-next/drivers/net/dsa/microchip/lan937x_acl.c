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


/* -----------------------------------------------------------------------------
*FUNCTION DESCRIPTION
*----------------------------------------------------------------------------
*Funciton Name: EthSwt_SetAclByteEnCfg
*Parameters : port - port Id
: cfg* - AclByteEnDataValue Pointer
*Return Value : E_OK - On Success
* : E_NOT_OK - On Any failure 
*pre-conditions : The function will be called after EthSwt_Init
*Description: Writes data to Byte enable config register
*******************************************************************************/
 
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


/* -----------------------------------------------------------------------------
*FUNCTION DESCRIPTION
*----------------------------------------------------------------------------
*Funciton Name: EthSwt_IsTcamBusy
*Parameters : port - Port Id
*Return Value : E_OK - On Success
* : E_NOT_OK - On Any failure 
*pre-conditions : The function will be called after EthSwt_Init
*Description: Checks for is TCAM Busy
*******************************************************************************/
 
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
	
	if (!timeout)
		return EBUSY; 
	return 0;
}

/* -----------------------------------------------------------------------------
*FUNCTION DESCRIPTION
*----------------------------------------------------------------------------
*Funciton Name: lan937x_set_acl_access_control
*Parameters : Port - port Id
: access* - AclAccCtrlDataValue pointer
*Return Value : E_OK - On Success
* : E_NOT_OK - On Any failure 
*pre-conditions : The function will be called after EthSwt_Init
*Description: Writes the data to Access config register
*******************************************************************************/
 
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



static int lan937x_find_free_tcam_rule_slot (struct ksz_device *dev,
												int port, u8 *slot )
{
	int i;

	for (i = 0; i < LAN937X_NUM_TCAM_ENTRIES_PER_PORT; i++)
		if (!dev->flower_block[port].tcam_entry_slots_used[i]) {
			slot = i;
			pr_info("lan937x_find_free_tcam_rule_slot %d",i);
			return 0;
		}
	return -1;
}

static int lan937x_acl_entry_write(struct ksz_device *dev, 
				u8 port, struct lan937x_acl_entry *acl_entry)
{
	u16 reg_offset;
	u8 i,reg_val;
	int rc;
	reg_offset= LAN937X_ACL_CTRL_BASE_ADDR + LAN937X_ACL_PORT_ADR_REG;
	struct lan937x_acl_access_ctl_reg tcam_access_ctl;
	struct lan937x_acl_byte_enable_reg byte_en_cfg;

	pr_info("ACL MASK:");
	for (i=0;i<48;i++) {
		reg_val = acl_entry->acl_mask[i];
		pr_info("%x",reg_val);
		rc= lan937x_pwrite8(dev, port, reg_offset + i, reg_val);
		if (rc) {
			return rc;
		}
	}

	pr_info("ACL DATA:");
	for (i=0;i<48;i++) {
		reg_val = acl_entry->acl_data[i];
		rc= lan937x_pwrite8(dev, port, 
				reg_offset + i + MAX_ACL_DATA_MASK_SIZE,
				reg_val);
		if (rc) {
		return rc;
		}
	}

	reg_offset= LAN937X_ACL_CTRL_BASE_ADDR + LAN937X_ACL_PORT_AAR_REG;
	pr_info("ACL Action:");
	for (i=0;i< 8;i++) {
		reg_val = acl_entry->acl_action[i];
		rc= lan937x_pwrite8(dev, port, 
				reg_offset + i,
				reg_val);
		pr_info("%x",reg_val);
		if (rc) {
		return rc;
		}
	}

	memset(&byte_en_cfg,0xFF,sizeof(struct lan937x_acl_byte_enable_reg));

	rc =lan937x_acl_byte_enable_write(dev, port,&byte_en_cfg);

	/*Work Around suggestion as per Ethutil test scripts*/
	rc= lan937x_pwrite16(dev, port, 0x66C, 0xFFFF);

	rc= lan937x_pwrite16(dev, port, 0x672, 0xFFFF);
	/******************************************************/

	rc = lan937x_find_free_tcam_rule_slot(dev,
						port, &tcam_access_ctl.tcam_addr);
	if (rc) {
		return rc;
	}
	pr_info("tcam_access_ctl");
	dev->flower_block[port].tcam_entry_slots_used[tcam_access_ctl.tcam_addr] = true;
	tcam_access_ctl.tcam_vben = true;
	tcam_access_ctl.tcam_vbi= true;
	tcam_access_ctl.tcam_row_vld = 0x0F;
	tcam_access_ctl.tcam_req = TCAM_REQ_TYPE_WRITE_TCAM;
	tcam_access_ctl.tcam_acc = TCAM_MASK_DATA;

	rc = lan937x_set_acl_access_control(dev, 
			port, &tcam_access_ctl);

	/*Test Code*/
	tcam_access_ctl.tcam_req = TCAM_REQ_TYPE_READ_TCAM;
	lan937x_readback(dev, port,
			&tcam_access_ctl,26);
	u32 test_val;
	rc= lan937x_pread32 (dev, port, 0x67C, &test_val);
	pr_info("PSRCTL: %x",test_val);
	return rc;
}


static int lan937x_acl_fill_entry_layout (struct ksz_device *dev, 
						int port, u8 parser_idx,
						enum lan937x_acl_dissector_type dissector_type,
						struct lan937x_key *key,
						struct lan937x_acl_entry *acl_entry)
{
	struct lan937x_acl_rfr *rfr_ptr = dev->rfr_table[port].rfr_entries[parser_idx];
	int i;
	pr_info("lan937x_acl_fill_entry_layout");
	for (i=0; i<MAX_RFR_PER_PARSER;i++) {
		if(rfr_ptr[i].rfr_valid) {
			if(rfr_ptr[i].type ==dissector_type) {
				switch (dissector_type) {
					case acl_dst_mac_dissector:
					/**Problems here,
					 * 1) key->dst_mac.mask is U64 type, copying it into array !! ndianness problem?
					 * 2) the offset in acl_entry is decided by presence and absence of RFRs, 
					 * that should be configurable
					*/
						pr_info("acl_dst_mac_dissector");
						u64_to_ether_addr(key->dst_mac.mask,acl_entry->acl_mask);
						u64_to_ether_addr(key->dst_mac.value,acl_entry->acl_data);
					break;

					case acl_src_mac_dissector:
						pr_info("acl_src_mac_dissector");
						u64_to_ether_addr(key->src_mac.mask,&acl_entry->acl_mask[6]);
						u64_to_ether_addr(key->src_mac.value,&acl_entry->acl_data[6]);
					break;
				}
				return 0;
			}
		}
	}
	return EINVAL;
}

int lan937x_acl_program_entry (struct ksz_device *dev, int port, u8 parser_idx,
					struct lan937x_rule *rule )
{
	u16 acl_dissector_map = rule->filter.key.acl_dissector_map;
	struct lan937x_key *key = &rule->filter.key;
	u8 i;
	struct lan937x_acl_rfr* rfr;
	int rc = EINVAL;
	struct lan937x_acl_entry acl_entry;

	memset(&acl_entry, 0, sizeof(acl_entry));

	pr_info("acl_dissector_map %x",acl_dissector_map);
	//acl_num_dissectors - 5
	for (i = 0; (acl_dissector_map!=0) && (i < 5); i++) {
		pr_info("acl_dissector_map %x",acl_dissector_map);
		if(acl_dissector_map & (1<<i)) {
			acl_dissector_map &= ~(1<<i);
			rc = lan937x_acl_fill_entry_layout (dev, port, parser_idx,i,key, &acl_entry);
			if (rc)
				return rc;
		}
	}

	if (!rc) {
		acl_entry.acl_action[0]= ((rule->acl_action.frm_ts << TCAM_AAR_TS_POS) & LAN937X_ACL_PORT_AAR_TS);
		acl_entry.acl_action[0] |= ((rule->acl_action.frm_cnt_en << TCAM_AAR_COUNT_POS) & LAN937X_ACL_PORT_AAR_COUNT);
		acl_entry.acl_action[0] |= ((rule->acl_action.cnt_sel << TCAM_AAR_COUNT_SEL_POS) & LAN937X_ACL_PORT_AAR_COUNT_SEL);
		acl_entry.acl_action[0] |= ((rule->acl_action.str_en << TCAM_AAR_STREAM_EN_POS) & LAN937X_ACL_PORT_AAR_STREAM_EN);
		acl_entry.acl_action[0] |= (rule->acl_action.str_idx & LAN937X_ACL_PORT_AAR_STREAM_ID);
		acl_entry.acl_action[1] = ((rule->acl_action.rep_vlan_en << TCAM_AAR_RVTG_POS) & LAN937X_ACL_PORT_AAR_RVTG);
		acl_entry.acl_action[1] |= ((rule->acl_action.vlan_id >> TCAM_AAR_VID_DATA_H_POS) & LAN937X_ACL_PORT_AAR_VID_H);
		acl_entry.acl_action[2] = ((rule->acl_action.vlan_id << TCAM_AAR_VID_DATA_L_POS ) & LAN937X_ACL_PORT_AAR_VID_L);
		acl_entry.acl_action[2] |= (rule->acl_action.pri_mode & LAN937X_ACL_PORT_AAR_QUE_EN);
		acl_entry.acl_action[3] = ((rule->acl_action.que_sel << TCAM_AAR_QUE_SEL_POS) & LAN937X_ACL_PORT_AAR_QUE_SEL);
		acl_entry.acl_action[3] |= ((rule->acl_action.remark_pri_en << TCAM_AAR_RP_POS) & LAN937X_ACL_PORT_AAR_RP);
		acl_entry.acl_action[3] |= ((rule->acl_action.pri << TCAM_AAR_PRI_POS) & LAN937X_ACL_PORT_AAR_PRI);
		acl_entry.acl_action[3] |= ((rule->acl_action.map_mode >> TCAM_AAR_MM_DATA_H_POS) & LAN937X_ACL_PORT_AAR_MM_H);
		acl_entry.acl_action[4] = ((rule->acl_action.map_mode << TCAM_AAR_MM_L_DATA_POS) & LAN937X_ACL_PORT_AAR_MM_L);
		acl_entry.acl_action[4] |= ((rule->acl_action.dst_port >> TCAM_AAR_PORT_DATA_H_POS) & LAN937X_ACL_PORT_AAR_DPORT_H);
		acl_entry.acl_action[5] = ((rule->acl_action.dst_port << TCAM_AAR_PORT_DATA_L_POS) & LAN937X_ACL_PORT_AAR_DPORT_L);
	}

	return lan937x_acl_entry_write(dev, port, &acl_entry);

}



/* -----------------------------------------------------------------------------
*FUNCTION DESCRIPTION
*----------------------------------------------------------------------------
*Funciton Name: EthSwt_AclRfrDataWrite
*Parameters : 
*Return Value : E_OK - On Success
* : E_NOT_OK - On Any failure 
*pre-conditions : The function will be called after EthSwt_Init
*Description: Writes Data to local structure in RFR Register format
*******************************************************************************/

void lan937x_set_rfr_data(struct lan937x_acl_rfr *rfr_ptr, bool l4, bool l3, 
				bool l2, bool rne,u16 ofst,u16 len,u8 rnofst)
{
	rfr_ptr->l4 = l4 ? true : false;
	rfr_ptr->l3 = l3 ? true : false;
	rfr_ptr->l2 = l2 ? true : false;
	rfr_ptr->rng_match_en = rne ? !!rne : 0;
	rfr_ptr->ofst = ofst;
	rfr_ptr->len = len;
	rfr_ptr->rng_ofst = rnofst;
}

/* -----------------------------------------------------------------------------
*FUNCTION DESCRIPTION
*----------------------------------------------------------------------------
*Funciton Name: EthSwt_GetAclRfrEntry
*Parameters : port -Port id
: entry* - AclRfrDataValue Pointer
*Return Value : E_OK - On Success
* : E_NOT_OK - On Any failure 
*pre-conditions : The function will be called after EthSwt_Init
*Description: Reads the RfrRegister ans stores in entry ptr.
*******************************************************************************/
#if 0//(ETHSWT_GET_ACL_RFR_ENTRY_API == (STD_ON))
static Std_ReturnType EthSwt_GetAclRfrEntry(u8 SwitchId, u8 port, AclRuleCfg_t *entry)
{
VAR(u8, ETHSWITCH_APPL_VAR) rfr_data[MAX_RFR_SIZE];
VAR(u16, ETHSWITCH_APPL_VAR) regstart, regend;
VAR(u32, ETHSWITCH_APPL_VAR) reg_val;
VAR(int, ETHSWITCH_APPL_VAR) status = E_OK, size, count = 0, parser = 0;
 
regstart= LAN937X_ACL_CTRL_PORT_ADDR(port, LAN937X_ACL_PORT_ADR_REG);
regend= regstart + (MAX_PARSER_PER_ENTRY * MAX_RFR_PER_PARSER * MAX_RFR_SIZE);
while (regstart < regend) {
for (size = 0; size < MAX_RFR_SIZE; size++) {
status = REG_READ8(SwitchId, regstart, &reg_val);
if (status<0) {
return E_NOT_OK;
}
rfr_data[size] = (reg_val & HALF_WORD_MASK);
regstart ++;
}
reg_val = (rfr_data[0] << (WORD_SHIFT + BYTE_SHIFT));
reg_val |= (rfr_data[1] << WORD_SHIFT);
reg_val |= (rfr_data[2] << BYTE_SHIFT);
reg_val |= rfr_data[3];
//Debug_print("reg_val=%x\r\n",reg_val);
entry->rfr[parser][count].rng_match_en = ((reg_val & TCAM_RFR_EN_RNGM) >> TCAM_RFR_RN_EN_POS);
entry->rfr[parser][count].l4 = ((reg_val & TCAM_RFR_L4) >> TCAM_RFR_L4_POS);
entry->rfr[parser][count].l3 = ((reg_val & TCAM_RFR_L3) >> TCAM_RFR_L3_POS);
entry->rfr[parser][count].l2 = ((reg_val & TCAM_RFR_L2) >> TCAM_RFR_L2_POS);
entry->rfr[parser][count].ofst = ((reg_val & TCAM_RFR_OFST) >> TCAM_RFR_OFST_POS);
entry->rfr[parser][count].len = ((reg_val & TCAM_RFR_LEN) >> TCAM_RFR_LEN_POS);
entry->rfr[parser][count].rng_ofst = ((reg_val & TCAM_RFR_RNG_OFST) >> TCAM_RFR_RNG_POS);
count++;
if (count == MAX_RFR_PER_PARSER) {
count = 0;
parser++;
}
}
return E_OK;
}
#endif
 
/* -----------------------------------------------------------------------------
*FUNCTION DESCRIPTION
*----------------------------------------------------------------------------
*Funciton Name:lan937x_set_rfr_entry
*Parameters : port -Port id
: rfr_entry* - single RFR
*Description: This function Writes Data to ACL data Register and makes it 
ready for initiating RFR programming
*******************************************************************************/
static int lan937x_set_rfr_entry(struct ksz_device *dev, int port, u8 parser_idx,
	u8 rfr_idx,struct lan937x_acl_rfr rfr_entry)
{
	struct lan937x_rfr_reg_type rfr_data;
	u16 reg_offset;
	u32 reg_val;
	int rc =EINVAL;
	u8 tcam_addr_access;

	tcam_addr_access = parser_idx % 2;

	reg_offset = LAN937X_ACL_CTRL_BASE_ADDR + (rfr_idx *MAX_RFR_SIZE) + 
	(tcam_addr_access * MAX_RFR_SIZE * MAX_RFR_PER_PARSER);

	rfr_data.u32value = ((rfr_entry.rng_match_en
	<< TCAM_RFR_RN_EN_POS) & TCAM_RFR_EN_RNGM);
	rfr_data.u32value|= ((rfr_entry.l4 
	<< TCAM_RFR_L4_POS) & TCAM_RFR_L4);
	rfr_data.u32value|= ((rfr_entry.l3 
	<< TCAM_RFR_L3_POS) & TCAM_RFR_L3);
	rfr_data.u32value|= ((rfr_entry.l2 
	<< TCAM_RFR_L2_POS) & TCAM_RFR_L2);
	rfr_data.u32value|= ((rfr_entry.ofst 
	<< TCAM_RFR_OFST_POS) & TCAM_RFR_OFST);
	rfr_data.u32value|= ((rfr_entry.len 
	<< TCAM_RFR_LEN_POS) & TCAM_RFR_LEN);
	rfr_data.u32value|= ((rfr_entry.rng_ofst 
	<< TCAM_RFR_RNG_POS) & TCAM_RFR_RNG_OFST);
	pr_info("Parser=%hu,rfr_idx=%hu, reg_val=%x\r\n",parser_idx,rfr_idx,rfr_data.u32value);

	rc = lan937x_pwrite32(dev, port,reg_offset, rfr_data.u32value);
	// if (rc == 0) {
	// 	//rc = lan937x_pread32(dev,port,reg_offset,&reg_val);
	// 	//pr_info("Readback=%X", reg_val);
	// }
	return rc;
}


static int lan937x_program_rfrs(struct ksz_device *dev, 
	int port)
{
	struct lan937x_acl_rfr rfr_entry;
	struct lan937x_acl_access_ctl_reg tcam_access_ctl;
	int rc= EINVAL;
	bool pgm_valid = false;
	int parser_idx,rfr_idx;

	pr_info("lan937x_program_rfrs");

	/*Program RFRs for Parser 0 and 1*/
	for (parser_idx = 0; parser_idx<MAX_PARSER_PER_ENTRY; parser_idx++) {
		for (rfr_idx=0; rfr_idx < MAX_RFR_PER_PARSER; rfr_idx++) {
			rfr_entry = dev->rfr_table[port].rfr_entries[parser_idx][rfr_idx];
			if (rfr_entry.rfr_valid) {
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
	}

	if (pgm_valid) {
		tcam_access_ctl.tcam_addr = TCAM_PARSER_0_1;
		tcam_access_ctl.tcam_vben = true;
		tcam_access_ctl.tcam_vbi = true;
		tcam_access_ctl.tcam_row_vld = 0x0F;
		tcam_access_ctl.tcam_req = TCAM_REQ_TYPE_WRITE_RFR;
		tcam_access_ctl.tcam_acc = TCAM_MASK_DATA;


		rc = lan937x_set_acl_access_control(dev, 
		port, &tcam_access_ctl);

		/*Test Code*/
		tcam_access_ctl.tcam_req = TCAM_REQ_TYPE_READ_RFR;
		lan937x_readback(dev, port,
	 			&tcam_access_ctl,10);
	}


	/*Program RFRs for Parser 2 and 3*/
	/*To be added on need basis*/
return rc;
}


int lan937x_init_acl_parsers(struct ksz_device *dev, int port)
{
	int rc;
	/* Parser - 0 : Universal packet format, unaware of any tags*/

	/*1st RFR to match Destination address*/
	struct lan937x_acl_rfr *rfr = &dev->rfr_table[port].rfr_entries[0][0];
	rfr->type = acl_dst_mac_dissector;
	lan937x_set_rfr_data (rfr, false,false,true,false,0x00,0x03,0x00);/*3 Words*/
	rfr->rfr_valid = true;

	/*2nd RFR to match Source address*/
	rfr = &dev->rfr_table[port].rfr_entries[0][1];
	rfr->type = acl_src_mac_dissector;
	lan937x_set_rfr_data (rfr, false,false,true,false,0x06,0x03,0x00);/*3 Words*/
	rfr->rfr_valid = true;

	/* 3rd RFR to match vlan tag and vlan pcp */
	// rfr = &dev->rfr_table.rfr_entries[0][2];
	// rfr.type = acl_vlan_id_dissector;
	// lan937x_set_rfr_data (rfr, false,false,true,false,14,1,0x00);/*1 Words*/
	rc = lan937x_program_rfrs(dev, port);

	rc = lan937x_pwrite8(dev, port,REG_PORT_RX_AUTH_CTL, (BIT(2) | BIT(1)));
	

return rc;
}
