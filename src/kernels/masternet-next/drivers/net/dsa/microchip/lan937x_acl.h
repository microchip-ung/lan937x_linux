// SPDX-License-Identifier: GPL-2.0
/* Microchip LAN937X switch driver main logic
 * Copyright (C) 2019-2021 Microchip Technology Inc.
 */

#ifndef _NET_DSA_DRIVERS_LAN937X_ACL_H
#define _NET_DSA_DRIVERS_LAN937X_ACL_H

/* ACL Registers START */
#define LAN937X_ACL_CTRL_BASE_ADDR  (0x600)
#define LAN937X_ACL_CTRL_PORT_BASE_ADDR(port) (port * 0x1000)
#define LAN937X_ACL_CTRL_PORT_ADDR(port, offset) (LAN937X_ACL_CTRL_PORT_BASE_ADDR(port) + \
(LAN937X_ACL_CTRL_BASE_ADDR+(offset)))
/* Reg Base address */
#define LAN937X_ACL_PORT_ADR_REG  (0x00)  /* 96 byets */
#define LAN937X_ACL_PORT_AAR_REG  (0x60)  /* 08 bytes */
#define LAN937X_ACL_PORT_ABER_REG (0x68)  /* 14 bytes */
#define LAN937X_ACL_PORT_ARACR_REG (0x78)  /* 04 bytes */
#define LAN937X_ACL_PORT_PCTRL_REG (0x7C)  /* 04 bytes */
#define LAN937X_ACL_PORT_FR_COUNT0_REG (0x80)  /* 04 bytes */
#define LAN937X_ACL_PORT_FR_COUNT1_REG (0x84)  /* 04 bytes */
#define LAN937X_ACL_PORT_FR_COUNT2_REG (0x88)  /* 04 bytes */
#define LAN937X_ACL_PORT_FR_COUNT3_REG (0x8C)  /* 04 bytes */
#define LAN937X_ACL_PORT_NMATCH_REG (0x94)  /* 08 bytes */
#define LAN937X_ACL_PORT_INT_STS_REG (0xA0)  /* 01 byte  */
#define LAN937X_ACL_PORT_INT_MASK_REG  (0xA2)  /* 01 byte  */
#define LAN937X_ACL_PORT_SPARE_REG (0xC0)  /* 04 byte  */
#define LAN937X_ACL_PORT_TCAM_BIST0_REG (0xD0)  /* 02 byte  */
#define LAN937X_ACL_PORT_TCAM_BIST1_REG (0xD2)  /* 01 byte  */
#define LAN937X_ACL_PORT_TCAM_BIST2_REG (0xD3)  /* 01 byte  */
#define LAN937X_ACL_PORT_TCAM_BIST3_REG (0xD4)  /* 01 byte  */
#define LAN937X_ACL_PORT_TCAM_BITMAP_REG (0xE0)  /* 16 bytes */
 
/* Reg Data */
#define LAN937X_ACL_PORT_ARACR_ADD_SHIFT_LO_PRI  (0x10000000)
#define LAN937X_ACL_PORT_ARACR_TCAM_FLUSH  (0x08000000)
#define LAN937X_ACL_PORT_ARACR_TCAM_VBEN   (0x04000000)
#define LAN937X_ACL_PORT_ARACR_TCAM_VBI (0x02000000)
#define LAN937X_ACL_PORT_ARACR_TCAM_ROW_VLD  (0x01E00000)
#define LAN937X_ACL_PORT_ARACR_START_ROW_SHFIT   (0x000FC000)
#define LAN937X_ACL_PORT_ARACR_TCAM_OPERATION_STATUS (0x00002000)
#define LAN937X_ACL_PORT_ARACR_TCAM_REQ_TYPE (0x00001C00)
#define LAN937X_ACL_PORT_ARACR_TCAM_ACC_TYPE (0x00000300)
#define LAN937X_ACL_PORT_ARACR_TCAM_NUM_SHIFT (0x000000C0)
#define LAN937X_ACL_PORT_ARACR_TCAM_ADDR_MASK (0x0000003F)
 
#define LAN937X_ACL_PORT_PCTRL_NUM_KEY_FORMAT (0xF0000000)
#define LAN937X_ACL_PORT_PCTRL_KEY_TYPE (0x0F000000)
#define LAN937X_ACL_PORT_PCTRL_IP_OPTIONS  (0x00F00000)
#define LAN937X_ACL_PORT_PCTRL_VLAN_TAG (0x000F0000)
#define LAN937X_ACL_PORT_PCTRL_ABS_OFF (0x0000F000)
#define LAN937X_ACL_PORT_PCTRL_HSR_TAG (0x00000F00)
#define LAN937X_ACL_PORT_PCTRL_SNAP_TAG (0x000000F0)
 
#define LAN937X_ACL_PORT_INT_STS_TOP  (0x00000001)
#define LAN937X_ACL_PORT_INT_STS_FRC0 (0x00000002)
#define LAN937X_ACL_PORT_INT_STS_FRC1 (0x00000004)
#define LAN937X_ACL_PORT_INT_STS_FRC2 (0x00000008)
#define LAN937X_ACL_PORT_INT_STS_FRC3 (0x00000010)
#define LAN937X_ACL_PORT_INT_STS_FRCX (0x0000001E)
#define LAN937X_ACL_PORT_INT_MASK_TOP (0x00000001)
#define LAN937X_ACL_PORT_INT_MASK_FRC0 (0x00000002)
#define LAN937X_ACL_PORT_INT_MASK_FRC1 (0x00000004)
#define LAN937X_ACL_PORT_INT_MASK_FRC2 (0x00000008)
#define LAN937X_ACL_PORT_INT_MASK_FRC3 (0x00000010)
#define LAN937X_ACL_PORT_INT_MASK_FRCX (0x0000001E)
 
#define LAN937X_ACL_PORT_TCAM_BIST0_TCAMSEL  (0x00000600)
#define LAN937X_ACL_PORT_TCAM_BIST0_FAIL   (0x00000100)
#define LAN937X_ACL_PORT_TCAM_BIST0_PASS   (0x00000080)
#define LAN937X_ACL_PORT_TCAM_BIST0_PAUSE  (0x00000040)
#define LAN937X_ACL_PORT_TCAM_BIST0_SHO (0x00000020)
#define LAN937X_ACL_PORT_TCAM_BIST0_SHI (0x00000010)
#define LAN937X_ACL_PORT_TCAM_BIST0_RESUME (0x00000008)
#define LAN937X_ACL_PORT_TCAM_BIST0_RTNEN  (0x00000004)
#define LAN937X_ACL_PORT_TCAM_BIST0_RUN (0x00000002)
#define LAN937X_ACL_PORT_TCAM_BIST0_RESET  (0x00000001)
#define LAN937X_ACL_PORT_TCAM_BIST1_DEFADDR  (0x0000007F)
#define LAN937X_ACL_PORT_TCAM_BIST2_FAILSEQ  (0x000000FF)
#define LAN937X_ACL_PORT_TCAM_BIST3_SKPERRCNT (0x0000001F)
 
#define TCAM_BIST_TCAMSEL_SHIFT  9
#define TCAM_BIST_FAIL_SHIFT 8
#define TCAM_BIST_PASS_SHIFT 7
#define TCAM_BIST_PAUSE_SHIFT 6
#define TCAM_BIST_SHO_SHIFT  5
#define TCAM_BIST_SHI_SHIFT  4
#define TCAM_BIST_RESUME_SHIFT   3
#define TCAM_BIST_RTNEN_SHIFT 2
#define TCAM_BIST_RUN_SHIFT  1
#define TCAM_BIST_RESET_SHIFT 0
 
/* AAR0 [40:33]*/
#define LAN937X_ACL_PORT_AAR_TS   (0x80)
#define LAN937X_ACL_PORT_AAR_COUNT (0x40)
#define LAN937X_ACL_PORT_AAR_COUNT_SEL (0x30)
#define LAN937X_ACL_PORT_AAR_STREAM_EN (0x8)
#define LAN937X_ACL_PORT_AAR_STREAM_ID (0x7)
 
/* AAR1 [32:25] */
#define LAN937X_ACL_PORT_AAR_RVTG (0x80)
#define LAN937X_ACL_PORT_AAR_VID_H (0x7F)
/* AAR2 [24:17] */
#define LAN937X_ACL_PORT_AAR_VID_L (0xFC)
#define LAN937X_ACL_PORT_AAR_QUE_EN (0x03)
/* ARR3 [16:9] */
#define LAN937X_ACL_PORT_AAR_QUE_SEL (0xE0)
#define LAN937X_ACL_PORT_AAR_RP   (0x10)
#define LAN937X_ACL_PORT_AAR_PRI  (0x0E)
#define LAN937X_ACL_PORT_AAR_MM_H (0x01)
/* ARR4 [8:1] */
#define LAN937X_ACL_PORT_AAR_MM_L (0x80)
#define LAN937X_ACL_PORT_AAR_DPORT_H (0x7F)
/* AAR5 [0] */
#define LAN937X_ACL_PORT_AAR_DPORT_L (0x80)
 
#define TCAM_RFR_EN_RNGM (0x20000000)
#define TCAM_RFR_L4 (0x10000000)
#define TCAM_RFR_L3 (0x08000000)
#define TCAM_RFR_L2 (0x04000000)
#define TCAM_RFR_OFST (0x03FFE000)
#define TCAM_RFR_LEN  (0x00000F80)
#define TCAM_RFR_RNG_OFST  (0x0000003E)
 
/* Reg Mask */
#define TCAM_LO_PRI_POS 28
#define TCAM_FLUSH_POS  27
#define TCAM_VBEN_POS   26
#define TCAM_VBI_POS 25
#define TCAM_ROW_VLD_POS  21
#define TCAM_START_ROW_SHIFT_POS 14
#define TCAM_OPERATION_STATUS_POS  13
#define TCAM_REQ_TYPE_POS 10
#define TCAM_ACC_TYPE_POS 8
#define TCAM_NUM_SHIFT_POS  6
#define TCAM_ADDR_POS   0
 
/* AAR0 [63:56]*/
#define TCAM_AAR_TS_POS 7
#define TCAM_AAR_COUNT_POS 6
#define TCAM_AAR_COUNT_SEL_POS 4
#define TCAM_AAR_STREAM_EN_POS 3
#define TCAM_AAR_STREAM_ID_POS 0
/* AAR1 [55:48] */				
#define TCAM_AAR_RVTG_POS 7
#define TCAM_AAR_VID_DATA_H_POS 6
/* AAR2 [47:40] */
#define TCAM_AAR_VID_DATA_L_POS 2
/* ARR3 [39:32] */			
#define TCAM_AAR_QUE_SEL_POS  5
#define TCAM_AAR_RP_POS 4			
#define TCAM_AAR_PRI_POS  1			
#define TCAM_AAR_MM_DATA_H_POS  1
/* ARR4 [31:24] */			
#define TCAM_AAR_MM_L_DATA_POS  7
#define TCAM_AAR_PORT_DATA_H_POS 1
/* AAR5 [23:16] */			
#define TCAM_AAR_PORT_DATA_L_POS 7
/* AAR6 [15:8] */
/* AAR7 [7:0 */
 
#define TCAM_NUM_KEY_FORMAT_POS 28
#define TCAM_KEY_TYPE_POS 24
#define TCAM_IP_OPTIONS_POS 20
#define TCAM_VLAN_TAG_POS 16
#define TCAM_ABS_OFF_POS  12
#define TCAM_HSR_TAG_POS  8
#define TCAM_SNAP_TAG_POS 4
 
#define TCAM_RFR_RN_EN_POS 29
#define TCAM_RFR_L4_POS 28
#define TCAM_RFR_L3_POS 27
#define TCAM_RFR_L2_POS 26
#define TCAM_RFR_OFST_POS  13
#define TCAM_RFR_LEN_POS 7
#define TCAM_RFR_RNG_POS 1
 
#define LAN937X_MAX_RFR 10
 
#define TCAM_INT_TOP 0
#define TCAM_INT_FRC0 1
#define TCAM_INT_FRC1 2
#define TCAM_INT_FRC2 3
#define TCAM_INT_FRC3 4
#define TCAM_INT_FRCX 1
/* Misc */
#define TCAM_REQ_TYPE_READ_TCAM 0x0
#define TCAM_REQ_TYPE_WRITE_TCAM 0x1
#define TCAM_REQ_TYPE_ADD_TCAM  0x2
#define TCAM_REQ_TYPE_SHIFT_TCAM 0x3
#define TCAM_REQ_TYPE_READ_KIVR 0x4
#define TCAM_REQ_TYPE_WRITE_KIVR 0x5
#define TCAM_REQ_TYPE_READ_RFR  0x6
#define TCAM_REQ_TYPE_WRITE_RFR 0x7
#define TCAM_ADDR_KIVR_0_1  0x00
#define TCAM_ADDR_KIVR_2_3  0x01
#define TCAM_ADDR_RFR_0_1 0x00
#define TCAM_ADDR_RFR_2_3 0x01
#define TCAM_ADDR_RNG_BND 0x02
#define TCAM_ADDR_RNG_CMP 0x03
 
#define TCAM_ADR_SIZE 96
#define TCAM_AAR_SIZE 6

#define TCAM_MASK 0x01
#define TCAM_DATA 0x02
#define TCAM_MASK_DATA  0x03

#define TCAM_PARSER_0_1 0x00
#define TCAM_PARSER_2_3 0x01

#define TCAM_RC_ULM 0x02
#define TCAM_RC_CMP 0x03
 
#define ADR2RFR 0x01
#define RFR2ADR 0x02
#define ADR2KIVR  0x03
#define KIVR2ADR  0x04
#define ADR2ADR 0x05
 
#define ACLTCAMHW  0x01
#define ACLTCAMRAM 0x02
#define ACLRFRHW 0x03
#define ACLRFRRAM  0x04
#define ACLTCAMDATA 0x02
#define ACLKIVRHW  0x05
#define ACLKIVRRAM 0x06
#define ACLRCMHW 0x07
#define ACLRCMRAM  0x08
 
#define ACLTCAMMASK 0x01
#define ACLTCAMDATA 0x02
#define ACLTCAMAAR 0x03
#define ACLTCAMPARX 0x04
#define ACLTCAMPARX_1  0x05
 
#define ACLTCAMPARSER0 0x00
#define ACLTCAMPARSER1 0x01
#define ACLTCAMPARSER2 0x02
#define ACLTCAMPARSER3 0x03
#define ACLTCAMPARSER_0_1 0x04
#define ACLTCAMPARSER_2_3 0x05
#define ACLTCAM_UMR 0x01
#define ACLTCAM_LMR 0x02
#define ACLTCAM_RCS 0x00
#define ACLTCAM_RCMRRAM 0x00
#define ACLTCAM_RCMWRAM 0x01
#define ACLTCAM_RCMRHW 0x02
#define ACLTCAM_RCMWHW 0x03
 
#define ACLPARSER_X 0x00
#define ACLPARSER_Y 0x01

/*ACL MACRO*/
#define MAX_ACL_ENTRIES 64
#define MAX_ACL_DATA_MASK_SIZE 48  /* Bytes */
#define MAX_ACL_ACTION_SIZE 8   /* Bytes */
#define MAX_KIVR_SIZE 48  /* Bytes */
#define MAX_RFR_SIZE  4   /* Bytes */
#define MAX_RNG_BOUND_SIZE 2   /* Bytes */
#define MAX_RNG_COMP_SIZE  2   /* Bytes */
#define MAX_RNG_MASK_SIZE  4   /* Bytes */
#define MAX_BYTE_ENABLE_SIZE 14  /* Bytes */
#define MAX_MASK_DATA_BEN_SIZE 6   /* Bytes */
#define MAX_ACL_COUNTER_SIZE 4   /* Bytes */
#define MAX_ACL_NMATCH_SIZE 8   /* Bytes */
#define MAX_DSCP_X_COLOR 16
#define MAX_RX_QUEUE  8
#define MAX_METER_STREAM 8
#define MAX_MAC_LENGTH  6
#define MAX_ACL_FRAME_COUNT 4
#define MAX_ACL_PARSERS 4
#define MAX_PARSER_PER_ENTRY 2
#define MAX_RFR_PER_PARSER 10
#define MAX_ACL_PARSER  4
#define MAX_RNG_CMP_PER_PARSER 10
#define MAX_RNG_LB  16
#define MAX_RNG_UB  16


enum lan937x_acl_dissector_type{ 
	acl_dst_mac_dissector,
	acl_src_mac_dissector,
	acl_vlan_id_dissector,
	acl_vlan_pcp_dissector,
	acl_ethtype_dissector,
	acl_num_dissectors
};

/****************************
 * TCAM Structures
 * ***************************/
struct lan937x_acl_action {
	bool frm_ts;
	bool frm_cnt_en;
	u8 cnt_sel;
	bool str_en;
	u8 str_idx;
	bool rep_vlan_en;
	u16 vlan_id;
	u8 pri_mode;
	u8 que_sel;
	bool remark_pri_en;
	u8 pri;
	u8 map_mode;
	u8 dst_port;
};

struct lan937x_acl_entry{
	u8 acl_mask[MAX_ACL_DATA_MASK_SIZE];
	u8 acl_data[MAX_ACL_DATA_MASK_SIZE];
	u8 acl_action[MAX_ACL_ACTION_SIZE];
};

struct lan937x_acl_rfr{ 
	bool rfr_valid;
	u16 dissectors_covered;
	bool rng_match_en;
	bool l4;
	bool l3;
	bool l2;
	u16 ofst;
	u16 len;
	u8 rng_ofst;
};

struct lan937x_acl_rfr_table{ 
 struct lan937x_acl_rfr rfr_entries[MAX_PARSER_PER_ENTRY][MAX_RFR_PER_PARSER];
};

struct lan937x_rfr_reg_type{ 
	union{
		u8 bval[MAX_RFR_SIZE];
		u32 u32value;
	};
};

struct lan937x_acl_range_cfg{ 
 u16 rng_upper_bound[MAX_RNG_UB];
 u16 rng_lower_bound[MAX_RNG_LB];
 u32 rng_bound_msk;
};
 
struct lan937x_acl_range_comparator{
 u16 rng_cmp[MAX_ACL_PARSER][MAX_RNG_CMP_PER_PARSER];
};
 

struct lan937x_acl_kivr{  
 u8 kivr[MAX_PARSER_PER_ENTRY][MAX_KIVR_SIZE];
};
 
struct lan937x_acl_access_ctl_reg{ 
 bool pri_low;
 bool tcam_flush;
 bool tcam_vben;
 bool tcam_vbi;
 u8 tcam_row_vld;
 u8 row_shift;
 u8 tcam_req;
 u8 tcam_acc;
 u8 num_shift;
 u8 tcam_addr;
};
 
struct lan937x_acl_byte_enable_reg{ 
	u8 acl_mask[6];
	u8 acl_data[6];
	u8 acl_action[1];
}__attribute__ ((__packed__));

struct lan937x_acl_parser_ctl_reg{  
 u8 key_fmt;
 bool key_type[MAX_ACL_PARSER];
 bool ip_opts[MAX_ACL_PARSER];
 bool vlan_tag[MAX_ACL_PARSER];
 bool abs_off[MAX_ACL_PARSER];
 bool hsr_tag[MAX_ACL_PARSER];
 bool snap_tag[MAX_ACL_PARSER];
};

struct lan937x_acl_frame_cnt{ 
 bool clear_cnt[MAX_ACL_FRAME_COUNT];
 u32 frm_cnt[MAX_ACL_FRAME_COUNT];
};
 
struct lan937x_acl_neg_match{ 
 bool nmatch[MAX_ACL_ENTRIES];
};
 
struct lan937x_acl_interrupt_cfg{ 
 bool frm_cnt_int[MAX_ACL_FRAME_COUNT];
 bool tcm_op_done;
};

#endif