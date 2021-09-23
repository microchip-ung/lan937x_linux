/* SPDX-License-Identifier: GPL-2.0 */
/* Microchip switch driver common header
 *
 * Copyright (C) 2019-2021 Microchip Technology Inc.
 */
#ifndef _NET_DSA_DRIVERS_LAN937X_ACL_H
#define _NET_DSA_DRIVERS_LAN937X_ACL_H

/*ToDo: Remove unused defines*/

/* Reg Data */
#define ACL_ARACR_ADD_SHIFT_LO_PRI  	(0x10000000)
#define ACL_ARACR_TCAM_FLUSH  		(0x08000000)
#define ACL_ARACR_TCAM_VBEN   		(0x04000000)
#define ACL_ARACR_TCAM_VBI 		(0x02000000)
#define ACL_ARACR_TCAM_ROW_VLD  	(0x01E00000)
#define ACL_ARACR_START_ROW_SHFIT   	(0x000FC000)
#define ACL_ARACR_TCAM_OP_STS 		(0x00002000)
#define ACL_ARACR_TCAM_REQ_TYPE 	(0x00001C00)
#define ACL_ARACR_TCAM_ACC_TYPE 	(0x00000300)
#define ACL_ARACR_TCAM_NUM_SHIFT 	(0x000000C0)
#define ACL_ARACR_TCAM_ADDR_MASK 	(0x0000003F)

#define ACL_PCTRL_NUM_KEY_FORMAT 	(0xF0000000)
#define ACL_PCTRL_KEY_TYPE 		(0x0F000000)
#define ACL_PCTRL_IP_OPTIONS  		(0x00F00000)
#define ACL_PCTRL_VLAN_TAG 		(0x000F0000)
#define ACL_PCTRL_ABS_OFF 		(0x0000F000)
#define ACL_PCTRL_HSR_TAG 		(0x00000F00)
#define ACL_PCTRL_SNAP_TAG 		(0x000000F0)

#define ACL_INT_STS_TOP  		(0x00000001)
#define ACL_INT_STS_FRC0 		(0x00000002)
#define ACL_INT_STS_FRC1 		(0x00000004)
#define ACL_INT_STS_FRC2 		(0x00000008)
#define ACL_INT_STS_FRC3 		(0x00000010)
#define ACL_INT_STS_FRCX 		(0x0000001E)
#define ACL_INT_MASK_TOP 		(0x00000001)
#define ACL_INT_MASK_FRC0 		(0x00000002)
#define ACL_INT_MASK_FRC1 		(0x00000004)
#define ACL_INT_MASK_FRC2 		(0x00000008)
#define ACL_INT_MASK_FRC3 		(0x00000010)
#define ACL_INT_MASK_FRCX 		(0x0000001E)

#define ACL_TCAM_BIST0_TCAMSEL  	(0x00000600)
#define ACL_TCAM_BIST0_FAIL   		(0x00000100)
#define ACL_TCAM_BIST0_PASS   		(0x00000080)
#define ACL_TCAM_BIST0_PAUSE  		(0x00000040)
#define ACL_TCAM_BIST0_SHO 		(0x00000020)
#define ACL_TCAM_BIST0_SHI 		(0x00000010)
#define ACL_TCAM_BIST0_RESUME 		(0x00000008)
#define ACL_TCAM_BIST0_RTNEN  		(0x00000004)
#define ACL_TCAM_BIST0_RUN 		(0x00000002)
#define ACL_TCAM_BIST0_RESET  		(0x00000001)
#define ACL_TCAM_BIST1_DEFADDR  	(0x0000007F)
#define ACL_TCAM_BIST2_FAILSEQ  	(0x000000FF)
#define ACL_TCAM_BIST3_SKPERRCNT 	(0x0000001F)

#define TCAM_BIST_TCAMSEL_SHIFT  	9
#define TCAM_BIST_FAIL_SHIFT 		8
#define TCAM_BIST_PASS_SHIFT 		7
#define TCAM_BIST_PAUSE_SHIFT 		6
#define TCAM_BIST_SHO_SHIFT  		5
#define TCAM_BIST_SHI_SHIFT  		4
#define TCAM_BIST_RESUME_SHIFT   	3
#define TCAM_BIST_RTNEN_SHIFT 		2
#define TCAM_BIST_RUN_SHIFT  		1
#define TCAM_BIST_RESET_SHIFT 		0

/* AAR0 [40:33]*/
#define LAN937X_ACL_AAR_TS   		(0x80)
#define LAN937X_ACL_AAR_COUNT 		(0x40)
#define LAN937X_ACL_AAR_COUNT_SEL 	(0x30)
#define LAN937X_ACL_AAR_STREAM_EN 	(0x8)
#define LAN937X_ACL_AAR_STREAM_ID 	(0x7)

/* AAR1 [32:25] */
#define LAN937X_ACL_AAR_RVTG 		(0x80)
#define LAN937X_ACL_AAR_VID_H 		(0x7F)
/* AAR2 [24:17] */
#define LAN937X_ACL_AAR_VID_L 		(0xFC)
#define LAN937X_ACL_AAR_QUE_EN 		(0x03)
/* ARR3 [16:9] */
#define LAN937X_ACL_AAR_QUE_SEL 	(0xE0)
#define LAN937X_ACL_AAR_RP   		(0x10)
#define LAN937X_ACL_AAR_PRI  		(0x0E)
#define LAN937X_ACL_AAR_MM_H 		(0x01)
/* ARR4 [8:1] */
#define LAN937X_ACL_AAR_MM_L 		(0x80)
#define LAN937X_ACL_AAR_DPORT_H 	(0x7F)
/* AAR5 [0] */
#define LAN937X_ACL_AAR_DPORT_L 	(0x80)

#define TCAM_RFR_EN_RNGM 		(0x20000000)
#define TCAM_RFR_L4 			(0x10000000)
#define TCAM_RFR_L3 			(0x08000000)
#define TCAM_RFR_L2 			(0x04000000)
#define TCAM_RFR_OFST 			(0x03FFE000)
#define TCAM_RFR_LEN  			(0x00000F80)
#define TCAM_RFR_RNG_OFST  		(0x0000003E)

/* Reg Mask */
#define TCAM_LO_PRI_POS 		28
#define TCAM_FLUSH_POS  		27
#define TCAM_VBEN_POS   		26
#define TCAM_VBI_POS 			25
#define TCAM_ROW_VLD_POS  		21
#define TCAM_START_ROW_SHIFT_POS 	14
#define TCAM_OPERATION_STATUS_POS  	13
#define TCAM_REQ_TYPE_POS 		10
#define TCAM_ACC_TYPE_POS 		8
#define TCAM_NUM_SHIFT_POS  		6
#define TCAM_ADDR_POS   		0

/* AAR0 [63:56]*/
#define TCAM_AAR_TS_POS 		7
#define TCAM_AAR_COUNT_POS 		6
#define TCAM_AAR_COUNT_SEL_POS 		4
#define TCAM_AAR_STREAM_EN_POS 		3
#define TCAM_AAR_STREAM_ID_POS 		0
/* AAR1 [55:48] */
#define TCAM_AAR_RVTG_POS 		7
#define TCAM_AAR_VID_DATA_H_POS 	6
/* AAR2 [47:40] */
#define TCAM_AAR_VID_DATA_L_POS 	2
#define TCAM_AAR_QUE_EN_POS  0
/* ARR3 [39:32] */
#define TCAM_AAR_QUE_SEL_POS  		5
#define TCAM_AAR_RP_POS 		4
#define TCAM_AAR_PRI_POS  		1
#define TCAM_AAR_MM_H_POS  		1
/* ARR4 [31:24] */
#define TCAM_AAR_MM_L_POS  		7
#define TCAM_AAR_DP_H_POS 		1
/* AAR5 [23:16] */
#define TCAM_AAR_DP_L_POS 		7
/* AAR6 [15:8] */
/* AAR7 [7:0 */

/* Map Mode value defines */
/* The forwarding map from the lookup table is replaced with DPORT map.*/
#define MM_REPLACE_FWD_LKUP_TABLE	0x03
/**the forwarding map from the lookup table is AND'ed with DPORT map*/
#define MM_AND_FWD_LKUP_TABLE		0x02
/**the forwarding map from the lookup table is OR'ed with DPORT map*/
#define MM_OR_FWD_LKUP_TABLE		0x01
/**No remapping of Dport*/
#define MM_NO_REMAPPING			0x00

#define TCAM_NUM_KEY_FORMAT_POS 	28
#define TCAM_KEY_TYPE_POS 		24
#define TCAM_IP_OPTIONS_POS 		20
#define TCAM_VLAN_TAG_POS 		16
#define TCAM_ABS_OFF_POS  		12
#define TCAM_HSR_TAG_POS  		8
#define TCAM_SNAP_TAG_POS 		4

#define TCAM_RFR_RN_EN_POS 		29
#define TCAM_RFR_L4_POS 		28
#define TCAM_RFR_L3_POS 		27
#define TCAM_RFR_L2_POS 		26
#define TCAM_RFR_OFST_POS  		13
#define TCAM_RFR_LEN_POS 		7
#define TCAM_RFR_RNG_POS 		1

#define LAN937X_MAX_RFR 		10

#define TCAM_INT_TOP 			0
#define TCAM_INT_FRC0 			1
#define TCAM_INT_FRC1 			2
#define TCAM_INT_FRC2 			3
#define TCAM_INT_FRC3 			4
#define TCAM_INT_FRCX 			1
/* Misc */
#define TCAM_REQ_TYPE_READ_TCAM 	0x0
#define TCAM_REQ_TYPE_WRITE_TCAM 	0x1
#define TCAM_REQ_TYPE_ADD_TCAM  	0x2
#define TCAM_REQ_TYPE_SHIFT_TCAM 	0x3
#define TCAM_REQ_TYPE_READ_KIVR 	0x4
#define TCAM_REQ_TYPE_WRITE_KIVR 	0x5
#define TCAM_REQ_TYPE_READ_RFR  	0x6
#define TCAM_REQ_TYPE_WRITE_RFR 	0x7
#define TCAM_ADDR_KIVR_0_1  		0x00
#define TCAM_ADDR_KIVR_2_3  		0x01
#define TCAM_ADDR_RFR_0_1 		0x00
#define TCAM_ADDR_RFR_2_3 		0x01
#define TCAM_ADDR_RNG_BND 		0x02
#define TCAM_ADDR_RNG_CMP 		0x03

#define TCAM_ADR_SIZE 			96
#define TCAM_AAR_SIZE 			6

#define TCAM_MASK 			0x01
#define TCAM_DATA 			0x02
#define TCAM_MASK_DATA  		0x03

#define TCAM_MULTI_KEY_ENTRY_START	0x01

#define TCAM_PARSER_0_1 		0x00
#define TCAM_PARSER_2_3 		0x01

#define TCAM_RC_ULM 			0x02
#define TCAM_RC_CMP 			0x03

#define ADR2RFR 			0x01
#define RFR2ADR 			0x02
#define ADR2KIVR			0x03
#define KIVR2ADR			0x04
#define ADR2ADR 			0x05

#define ACLTCAMHW  			0x01
#define ACLTCAMRAM 			0x02
#define ACLRFRHW 			0x03
#define ACLRFRRAM  			0x04
#define ACLTCAMDATA 			0x02
#define ACLKIVRHW  			0x05
#define ACLKIVRRAM 			0x06
#define ACLRCMHW 			0x07
#define ACLRCMRAM  			0x08

#define ACLTCAMMASK 			0x01
#define ACLTCAMDATA 			0x02
#define ACLTCAMAAR 			0x03
#define ACLTCAMPARX 			0x04
#define ACLTCAMPARX_1  			0x05

/*ACL MACRO*/
#define MAX_ACL_ENTRIES 		64
#define MAX_ACL_DATA_MASK_SIZE 		48  /* Bytes */
#define MAX_ACL_ACTION_SIZE 		8   /* Bytes */
#define MAX_KIVR_SIZE 			48  /* Bytes */
#define MAX_RFR_SIZE  			4   /* Bytes */
#define MAX_RNG_BOUND_SIZE 		2   /* Bytes */
#define MAX_RNG_COMP_SIZE  		2   /* Bytes */
#define MAX_RNG_MASK_SIZE  		4   /* Bytes */
#define MAX_BYTE_ENABLE_SIZE 		14  /* Bytes */
#define MAX_MASK_DATA_BEN_SIZE 		6   /* Bytes */
#define MAX_ACL_COUNTER_SIZE 		4   /* Bytes */
#define MAX_ACL_NMATCH_SIZE 		8   /* Bytes */
#define MAX_DSCP_X_COLOR 		16
#define MAX_RX_QUEUE  			8
#define MAX_METER_STREAM 		8
#define MAX_MAC_LENGTH 			6
#define MAX_ACL_FRAME_COUNT 		4
#define MAX_ACL_PARSERS 		4
#define MAX_PARSER_PER_ENTRY 		2
#define MAX_RFR_PER_PARSER 		10
#define MAX_RFR				MAX_RFR_PER_PARSER
#define MAX_ACL_PARSER  		4
#define MAX_RNG_CMP_PER_PARSER 		10
#define MAX_RNG_LB  			16
#define MAX_RNG_UB  			16

#define PARSER_IDX_0			0
#define PARSER_IDX_1			1
#define PARSER_IDX_2			2
#define PARSER_IDX_3			3

#define RFR_IDX_0			0
#define RFR_IDX_1			1
#define RFR_IDX_2			2
#define RFR_IDX_3			3
#define RFR_IDX_4			4
#define RFR_IDX_5			5
#define RFR_IDX_6			6
#define RFR_IDX_7			7
#define RFR_IDX_8			8
#define RFR_IDX_9			9

/**Key Format
 * Multi Key Format - First byte of Entry should match Parser index to 
 * avoid false matches
 * Univerasal Format - No Parser index matches. Only dissector classification
*/
#define PARSER_UNIVERSAL_FORMAT		0x00
#define PARSER_MULTI_KEY_FORMAT		0x01

enum lan937x_acl_dissector_type {
	acl_dst_mac_dissector,
	acl_src_mac_dissector,
	acl_vlan_id_dissector,
	acl_vlan_pcp_dissector,
	acl_ethtype_dissector,
	acl_ipv4_tos_dissector,
	acl_ipv4_ttl_dissector,
	acl_ipv4_protocol_dissector,
	acl_ipv4_src_ip_dissector,
	acl_ipv4_dst_ip_dissector,
	acl_ipv6_tc_dissector,
	acl_ipv6_hop_dissector,
	acl_ipv6_nxt_hdr_dissector,
	acl_ipv6_src_ip_dissector,
	acl_ipv6_dst_ip_dissector,
	acl_l4_src_port_dissector,
	acl_l4_dst_port_dissector,

	acl_num_dissectors_supported,
};

#define DST_MAC_DISSECTOR_PRESENT	BIT(acl_dst_mac_dissector)
#define SRC_MAC_DISSECTOR_PRESENT	BIT(acl_src_mac_dissector)
#define VLAN_ID_DISSECTOR_PRESENT	BIT(acl_vlan_id_dissector)
#define VLAN_PCP_DISSECTOR_PRESENT	BIT(acl_vlan_pcp_dissector)
#define ETHTYPE_DISSECTOR_PRESENT	BIT(acl_ethtype_dissector)
#define IPV4_TOS_DISSECTOR_PRESENT	BIT(acl_ipv4_tos_dissector)
#define IPV4_TTL_DISSECTOR_PRESENT	BIT(acl_ipv4_ttl_dissector)
#define IPV4_PROTO_DISSECTOR_PRESENT	BIT(acl_ipv4_protocol_dissector)
#define IPV4_SRC_IP_DISSECTOR_PRESENT	BIT(acl_ipv4_src_ip_dissector)
#define IPV4_DST_IP_DISSECTOR_PRESENT	BIT(acl_ipv4_dst_ip_dissector)
#define IPV6_TC_DISSECTOR_PRESENT	BIT(acl_ipv6_tc_dissector)
#define IPV6_HOP_DISSECTOR_PRESENT	BIT(acl_ipv6_hop_dissector)
#define IPV6_NXT_HDR_DISSECTOR_PRESENT	BIT(acl_ipv6_nxt_hdr_dissector)
#define IPV6_SRC_IP_DISSECTOR_PRESENT	BIT(acl_ipv6_src_ip_dissector)
#define IPV6_DST_IP_DISSECTOR_PRESENT	BIT(acl_ipv6_dst_ip_dissector)
#define L4_SRC_PORT_DISSECTOR_PRESENT	BIT(acl_l4_src_port_dissector)
#define L4_DST_PORT_DISSECTOR_PRESENT	BIT(acl_l4_dst_port_dissector)

#define VLAN_TAG_DISSECTORS_PRESENT	(VLAN_ID_DISSECTOR_PRESENT | \
					VLAN_PCP_DISSECTOR_PRESENT)

/**TCAM Access Control Register defines*/

#define acl_pri_low(val)	((((u32)val) << TCAM_LO_PRI_POS)\
				 & ACL_ARACR_ADD_SHIFT_LO_PRI)
#define acl_tcam_flush(val)	((((u32)val) << TCAM_FLUSH_POS)\
				 & ACL_ARACR_TCAM_FLUSH)
#define acl_tcam_vben(val)	((((u32)val) << TCAM_VBEN_POS)\
				 & ACL_ARACR_TCAM_VBEN)
#define acl_tcam_vbi(val)	((((u32)val) << TCAM_VBI_POS)\
				 & ACL_ARACR_TCAM_VBI)
#define acl_tcam_row_vld(val)	((((u32)val) << TCAM_ROW_VLD_POS)\
				 & ACL_ARACR_TCAM_ROW_VLD)
#define acl_row_shift(val)	((((u32)val) << TCAM_START_ROW_SHIFT_POS)\
				 & ACL_ARACR_START_ROW_SHFIT)
#define acl_tcam_req(val)	((((u32)val) << TCAM_REQ_TYPE_POS)\
				 & ACL_ARACR_TCAM_REQ_TYPE)
#define acl_tcam_acc(val)	((((u32)val) << TCAM_ACC_TYPE_POS)\
				 & ACL_ARACR_TCAM_ACC_TYPE)
#define acl_num_shift(val)	((((u32)val) << TCAM_NUM_SHIFT_POS)\
				 & ACL_ARACR_TCAM_NUM_SHIFT)
#define acl_tcam_addr(val)	(((u32)val) & ACL_ARACR_TCAM_ADDR_MASK)

/**Form the register value to program in the acl_access control register*/
#define acl_acc_ctl(acc)	(acl_pri_low(acc->pri_low) |\
				 acl_tcam_flush(acc->tcam_flush) |\
				 acl_tcam_vben(acc->tcam_vben) |\
				 acl_tcam_vbi(acc->tcam_vbi) |\
				 acl_tcam_row_vld(acc->tcam_row_vld) |\
				 acl_row_shift(acc->row_shift) |\
				 acl_tcam_req(acc->tcam_req) |\
				 acl_tcam_acc(acc->tcam_acc) |\
				 acl_num_shift(acc->num_shift) |\
				 acl_tcam_addr(acc->tcam_addr))

/****************************
 * TCAM data structures
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

struct lan937x_acl_entry {
	u8 acl_entry_index;
	u8 acl_mask[MAX_ACL_DATA_MASK_SIZE];
	u8 acl_data[MAX_ACL_DATA_MASK_SIZE];
	u8 acl_action[MAX_ACL_ACTION_SIZE];
};

/* Defines to help filling the action RAM contents */
#define set_que_en(act)		act[2] |= (0x03 >> TCAM_AAR_QUE_EN_POS)

#define set_que_sel(act, pri)	act[3] |= ((pri >> TCAM_AAR_QUE_SEL_POS)\
				  	   & LAN937X_ACL_AAR_QUE_SEL)

#define set_map_mode(act, MM)	act[3] |= ((MM >> TCAM_AAR_MM_H_POS)\
					   & LAN937X_ACL_AAR_MM_H);\
				act[4] |= ((MM << TCAM_AAR_MM_L_POS)\
					   & LAN937X_ACL_AAR_MM_L)

#define set_dst_port(act, dp)	act[4] |= ((dp >> TCAM_AAR_DP_H_POS)\
					   & LAN937X_ACL_AAR_DPORT_H);\
				act[5] |= ((dp << TCAM_AAR_DP_L_POS)\
					   & LAN937X_ACL_AAR_DPORT_L)

#define set_strm_en(act, en)	act[0] |= ((en << TCAM_AAR_STREAM_EN_POS)\
					   & LAN937X_ACL_AAR_STREAM_EN)

#define set_strm_id(act, i)	act[0] |= (i & LAN937X_ACL_AAR_STREAM_ID)

#define set_fr_counter(act,i)	act[0] |= ((1 << TCAM_AAR_COUNT_POS) | \
					   (i << TCAM_AAR_COUNT_SEL_POS))


struct lan937x_acl_rfr {
	u32 dissectors_covered;
	u8 layer;
	u16 ofst;
	u8 len;
	bool rng_match_en;	
	u8 rng_ofst;
};
/* enum for layer 2, layer 3, layer 4*/
enum layer{
	l2,
	l3,
	l4,
};

/**Defines to set RFR fields*/
#define RFR_RNG_MATCH_EN(X)	((X << TCAM_RFR_RN_EN_POS) & TCAM_RFR_EN_RNGM)
#define RFR_OSFT_L4_RELATV(X)	((((u32)X)<< TCAM_RFR_L4_POS) & TCAM_RFR_L4)
#define RFR_OSFT_L3_RELATV(X)	((((u32)X)<< TCAM_RFR_L3_POS) & TCAM_RFR_L3)
#define RFR_OSFT_L2_RELATV(X)	((((u32)X)<< TCAM_RFR_L2_POS) & TCAM_RFR_L2)

/* Set offset address to extract field from packet, Offset address is 
 * expected interms of number of words instead of bytes, */
/* #define OFST_CHK_VLD(X)	#if(X & BIT(0))
				#error "RFR Offset cannot be a ODD Number"
			#endif\
			X */
#define RFR_OFST(X)	(((X >> 1) << TCAM_RFR_OFST_POS) & TCAM_RFR_OFST)
/* Set Length to extract field from packet, length is 
 * expected interms of number of words instead of bytes, */
/* #define LEN_CHK_VLD(X)	#if(X & BIT(0))
				#error "RFR Length cannot be a ODD Number"
			#elif(X > 24)
				#error "RFR Length more than 48 bytes"
			#endif\
			X */
#define RFR_LENGTH(X)	(((X >> 1) << TCAM_RFR_LEN_POS) & TCAM_RFR_LEN)

#define RFR_RNG_OSFT(X)	(((X) << TCAM_RFR_RNG_POS) & TCAM_RFR_RNG_OFST)


struct lan937x_acl_rfr_table {
	struct lan937x_acl_rfr rfr_entries[MAX_PARSER_PER_ENTRY][MAX_RFR];
};

struct lan937x_rfr_reg_type {
	union{	/*Why union inside a structure ??*/
		u8 bval[MAX_RFR_SIZE];
		u32 u32value;
	};
};

struct lan937x_acl_range_cfg {
	u16 rng_upper_bound[MAX_RNG_UB];
	u16 rng_lower_bound[MAX_RNG_LB];
	u32 rng_bound_msk;
};

struct lan937x_acl_range_comparator {
	u16 rng_cmp[MAX_ACL_PARSER][MAX_RNG_CMP_PER_PARSER];
};

struct lan937x_acl_kivr {
	u8 kivr[MAX_PARSER_PER_ENTRY][MAX_KIVR_SIZE];
};

struct lan937x_acl_access_ctl {
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

/*Macros to set values in lan937x_acl_access_ctl*/
#define clr_data(data)	memset(&data,0x00,sizeof(data))
#define set_pri_low(acc, val)	acc.pri_low = val
#define set_tcam_flush(acc, val)	acc.tcam_flush = val
#define set_tcam_vben(acc, val)	acc.tcam_vben = val
#define set_tcam_vbi(acc, val)	acc.tcam_vbi = val
#define set_tcam_row_vld(acc,val)	acc.tcam_row_vld = val
#define set_row_shift(acc,val)	acc.row_shift = val
#define set_tcam_req(acc,val)	acc.tcam_req = val
#define set_tcam_acc(acc,val)	acc.tcam_acc = val
#define set_num_shift(acc,val)	acc.num_shift = val
#define set_tcam_addr(acc,val)	acc.tcam_addr = val

struct lan937x_acl_byte_en {
	u8 acl_mask[6];
	u8 acl_data[6];
	u8 acl_action[1];
} __packed;

struct lan937x_acl_parser_ctl_reg {
	u8 key_fmt;
	bool key_type[MAX_ACL_PARSER];
	bool ip_opts[MAX_ACL_PARSER];
	bool vlan_tag[MAX_ACL_PARSER];
	bool abs_off[MAX_ACL_PARSER];
	bool hsr_tag[MAX_ACL_PARSER];
	bool snap_tag[MAX_ACL_PARSER];
};

struct lan937x_acl_frame_cnt {
	bool clear_cnt[MAX_ACL_FRAME_COUNT];
	u32 frm_cnt[MAX_ACL_FRAME_COUNT];
};

struct lan937x_acl_neg_match {
	bool nmatch[MAX_ACL_ENTRIES];
};

struct lan937x_acl_interrupt_cfg {
	bool frm_cnt_int[MAX_ACL_FRAME_COUNT];
	bool tcm_op_done;
};

/************************************
 * Packet Formats supported by TCAM
 * ***********************************/

struct packet_universal {
	u8  dst_mac[6];        /* destination eth addr        */
	u8  src_mac[6];        /* source ether addr        */
	u16 ether_type;        /* packet type ID field        */
} __packed;

struct packet_extentions {
	u16 offset;	/* offset address from start of packet**/
	u16 size;	/* Size of the extension */
};

struct vlan_tag {
	u16 vlan_tpid;
	u8 tci[2];
} __packed;

#endif
