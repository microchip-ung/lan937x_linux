/**
 * Microchip tcm_itf header
 *
 * Copyright (c) 2015 Microchip Technology Inc.
 *	Tristram Ha <Tristram.Ha@microchip.com>
 *
 * Copyright (c) 2013-2015 Micrel, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __TCAMITF__H__
#define __TCAMITF__H__

#pragma pack(push) 
#pragma pack(1)

typedef int Boolean;
#define MCHP_TRUE	1
#define MCHP_FALSE	0

#define MAX_PORT	8
#define TCAM_ENTRIES	64
#define MAX_ENTRIES_PER_RULE 4

#define ACLFN		6
#define INGRESS_POLICY			8

#define REG_ACL_ADR_OFFSET	0x00 /*0x00-0x5f*/
#define REG_ACL_AAR_OFFSET	0x60 /*0x60-0x65*/
#define REG_ACL_ABER_OFFSET	0x68/*0x68-0x77*/
#define REG_ACL_ARACR_OFFSET	0x78;/*0x78-0x7b*/
#define REG_ACL_PCTRL_OFFSET	0x7c/*0x7c-0x7f*/

#define TCAM_ENABLEBIT_LEN		14// 14 byte is enough, other 2 byte is reserved,-> 16
#define REG_ACL_ENABLE_OFFSET		3
#define ACL_ENABLE						0x04

typedef enum{
    TCAMERR_NOERROR=0,
    TCAMERR_PARAM,
    TCAMERR_BUSY,
    TCAMERR_MEMORY,
    TCAMERR_NO_ROOM,
    TCAMERR_UNKNOWN_CMD,
    TCAMERR_IOCTL,
    TCAMERR_UNKNOWN,
}TCAMERR;


typedef union{
   struct{
       unsigned char l2	    :1;
       unsigned char l3	    :1;
       unsigned char l4	    :1;
       unsigned char unused :3;
       unsigned char key    :2;
   }s;

   unsigned char mulfm_ctrl;
}MULFM_CONTROL; /*Multiple format control byte*/

/* TCAM Action Register Definition*/
typedef union{    
    struct {
            unsigned long dport		: 8 ;
            unsigned long mm		: 2 ;
            unsigned long pri		: 3 ;
            unsigned long rp		: 1 ;
            unsigned long que_sel	: 3 ;
            unsigned long que_en	: 2 ;
            unsigned long vid		: 13 ;
    } low;
    unsigned long aar_low ;
}AAR_LOW;	

typedef union{    
    struct {
            unsigned short rvtg		: 1 ;
	    unsigned short stream_id	: 3 ;
	    unsigned short stream_en	: 1 ;
	    unsigned short count_sel	: 2 ;
	    unsigned short count	: 1 ;
	    unsigned short TS		: 1 ;
	    unsigned short unused	: 7 ;
    }high;
    unsigned short aar_high ;
}AAR_HIGH;
 
 typedef struct {
   AAR_LOW aar_low;
   AAR_HIGH aar_high;	
} TCAM_AAR;


/*TCAM ACL Byte Enable Register*/
typedef struct{
  unsigned char enable_bit[TCAM_ENABLEBIT_LEN];
}TCAM_ABER;

/*TCAM ACL Access Control Register Definition*/
typedef union {
        struct {
                unsigned long tcam_addr			: 6 ;
		unsigned long num_shift			: 2 ;
		unsigned long tcam_acc_type		: 2 ;
		unsigned long tcam_req_type		: 3 ;
		unsigned long tcam_operation_status	: 1 ;
		unsigned long start_row_shift		: 6 ;
		unsigned long reserved			: 1 ;
		unsigned long tcam_row_vld		: 4 ;
		unsigned long tcam_vbi			: 1 ;
		unsigned long tcam_vben			: 1 ;
		unsigned long tcam_flush		: 1 ;
		unsigned long add_shift_lo_pri		: 1 ;
		unsigned long unused			: 3 ;

	  }s;
	 unsigned long aracr ;
}TCAM_ARACR;


/*TCAM ACL Parser Control Register Definition*/
typedef union {
        struct {
                unsigned long reserved			: 4 ;
		
		unsigned long snap_tag3			: 1 ;
		unsigned long snap_tag2			: 1 ;
		unsigned long snap_tag1			: 1 ;
		unsigned long snap_tag0			: 1 ;

		unsigned long hsr_tag3			: 1 ;
		unsigned long hsr_tag2			: 1 ;
		unsigned long hsr_tag1			: 1 ;
		unsigned long hsr_tag0			: 1 ;

		unsigned long abs_off3			: 1 ;
		unsigned long abs_off2			: 1 ;
		unsigned long abs_off1			: 1 ;
		unsigned long abs_off0			: 1 ;
		unsigned long vlan_tag3			: 1 ;
		unsigned long vlan_tag2			: 1 ;
		unsigned long vlan_tag1			: 1 ;
		unsigned long vlan_tag0			: 1 ;
		unsigned long ip_option3		: 1 ;
		unsigned long ip_option2		: 1 ;
		unsigned long ip_option1		: 1 ;
		unsigned long ip_option0		: 1 ;
		

		unsigned long key_type3			: 1 ;
		unsigned long key_type2			: 1 ;
		unsigned long key_type1			: 1 ;
		unsigned long key_type0			: 1 ;
		unsigned long num_key_format		: 4 ;
	    }s;
	   unsigned long pctrl_a ;
}TCAM_PCTRL;

/*TCAM Rule Format Register Definition*/
typedef union {
    struct{
	unsigned long reserved			: 1 ;
	unsigned long range_word_offset		: 5 ;
	unsigned long length			: 6 ;
	unsigned long offset			: 14 ;
	unsigned long start_l2			: 1 ;
	unsigned long start_l3			: 1 ;
	unsigned long start_l4			: 1 ;
	unsigned long enable_range_match	: 1 ;
	unsigned long reserved2			: 2 ;
    }s;
    unsigned long rfr;
}RFR;

typedef struct{
    RFR rfr_ay[10];
}RFRAY;

/*TCAM Range Register Definition*/
typedef struct{
    unsigned short low_bound;
    unsigned short up_bound;
    unsigned short range_mask;
}TCAM_RANGE;

typedef struct{
    TCAM_RANGE range[16];
}TCAM_RANGE_AY;

typedef struct{
 unsigned short comparator[10]; 
}ARCSR_AY;

typedef struct{
    unsigned char kivr[48];
}KIVR;


typedef struct{
unsigned char mask[48];
}TCAM_MASK;

typedef struct{
unsigned char data[48];
}TCAM_DATA;

/* for multiple entry rule, maximun enties is 4 */
typedef struct{
 TCAM_MASK tcam_mask[4];
 TCAM_DATA tcam_data[4];
}TCAM_ENTRY;


typedef struct{
char	name[32];
int	start_entry;	    /* the start entry in the TCAM*/
int     entries;	    /* how many entries for this rule (1-4) */	    
TCAM_AAR act;
TCAM_ENTRY tcam_entries; /* mask and data*/
}ACL_RULE;

typedef struct{
   int all_rules;
   ACL_RULE acl_rule[64];
}PORT_ACL_RULE;

/****************************** Ethernet Driver  IOCTL ***************************************/
/* for macb ethernet driver, I want to use SIOCDEVPRIVATE +12 for TCAM ACL */

/*the struct pass to ifreq.ifr_data*/
typedef enum{
 TCAMACL_RESET=0,
 TCAMACL_GET_RULE_COUNT,
 TCAMACL_GET_RULE_INFO_BYINDEX,
 TCAMACL_GET_RULE_INFO_BYNAME,
 TCAMACL_ADD_RULE,
 TCAMACL_READ,
 TCAMACL_INSERT,
 TCAMACL_SHIFT,
 TCAMACL_PARSER_READ,
 TCAMACL_PARSER_WRITE,
 TCAMACL_RFR_READ,
 TCAMACL_RFR_WRITE,
 TCAMACL_KIVR_READ,
 TCAMACL_KIVR_WRITE,
 REG_ACCESS,
 TCAMACL_BIT_TEST,
 /*Range Match Command*/
 TCAMACL_RANGE_READ,
 TCAMACL_RANGE_WRITE,
 TCAMACL_COMPARATOR_READ,
 TCAMACL_COMPARATOR_WRITE,
}TCAMACLCMD;

struct tcam_acl{
  TCAMACLCMD cmd;
  void * pfn;
};

typedef struct{
 int port;
}TCAMACL_RESE_FN;

typedef struct{
int port;
int * pn;
}TCAMACL_GET_RULE_COUNT_FN;

typedef struct{
int port;
int index; 
ACL_RULE * prule;
}TCAMACL_GET_RULE_INFO_BYINDEX_FN;

typedef struct{
 int port;
 char name[32];
 ACL_RULE * prule;
}TCAMACL_GET_RULE_INFO_BYNAME_FN;

typedef struct{
 int port;
 char name[32];
 int index;
 int entries;
 TCAM_AAR * pact;
 TCAM_ENTRY * ptcam_entry;
}TCAMACL_ADD_RULE_FN;

typedef struct{
int port;
int index; 
char *  pmask;
char *  pdata;
}TCAMACL_READ_FN;

typedef struct{
int port;
int index; 
int start_row_shift;
const  TCAM_AAR * pact;
const char * pmask;
const char * pdata;
}TCAMACL_INSERT_FN;

typedef struct{
int port;
int new_entry;
int start_row_shift;
int num_shift;
Boolean down;
}TCAMACL_SHIFT_FN;

typedef struct{
int port;
unsigned long * pparser;
}TCAMACL_PARSER_READ_FN;

typedef struct{
int port;
unsigned long  parser;
}TCAMACL_PARSER_WRITE_FN;
 
typedef struct{
int port;
int parser;
RFRAY * prfr;
}TCAMACL_RFR_READ_FN;


typedef struct{
int port;
int parser;
const RFRAY * prfr;   
}TCAMACL_RFR_WRITE_FN;


typedef struct{
int port;
TCAM_RANGE_AY * prange_ay;
}TCAMACL_RANGE_READ_FN;

typedef struct{
int port;
const TCAM_RANGE_AY * prange_ay;
}TCAMACL_RANGE_WRITE_FN;


typedef struct{
int port;
int parser;
ARCSR_AY * parcsr_ay;
}TCAMACL_ARCSR_READ_FN;


typedef struct{
int port;
int parser;
const ARCSR_AY * parcsr_ay;   
}TCAMACL_ARCSR_WRITE_FN;



typedef struct{
int port;
int parser; 
KIVR * pkivr;
}TCAMACL_KIVR_READ_FN;

typedef struct{
  int port;
  int parser;
  const KIVR * pkivr;   
 }TCAMACL_KIVR_WRITE_FN;


typedef struct{
 int port;
}TCAMACL_BIT_WRITE_FN;

typedef enum{
REG8=0,
REG16,
REG32,
}REGBIT;

typedef struct{
REGBIT regbit;
Boolean fread;
unsigned long  addr;
unsigned long * pout;
unsigned long  in;
}REG_FN;

/**********************************************************************************************/
#define RESET		    		"reset"
#define RULE_COUNT	    		"rc"
#define RULE_INFO_INDEX			"rbi"
#define RULE_INFO_NAME			"rbn"
#define ADD_RULE	    		"ar"
#define READ_ENTRY	    		"ren"
#define INSERT_ONE_ENTRY	    	"inst"
//#define SHIFT		    		"sht"
#define PARSER_READ	    		"pr"
#define PARSER_WRITE	    		"pw"
#define RFR_READ	    		"rr"
#define RFR_WRITE	    		"rw"
#define KIVR_READ	    		"kr"
#define KIVR_WRITE	    		"kw"
/*The command only for testnig purpose*/
#define TCAM_BIT_TEST			"bt"
/*the command for  read/ write register */
#define REG8_READ	    		"rg8"
#define REG8_WRITE	    		"wg8"
#define REG16_READ	    		"rg16"
#define REG16_WRITE	    		"wg16"
#define REG32_READ	    		"rg32"
#define REG32_WRITE	    		"wg32"
/*the commands for range checking */
#define RANG_READ			"rngr"
#define RANG_WRITE			"rngw"
#define ARCSR_READ			"asr"
#define ARCSR_WRITE			"asw"

#ifdef __cplusplus
extern "C" {
#endif
    TCAMERR tcam_reset(int port);
    TCAMERR tcam_get_rule_count(int port,int * pn);
    TCAMERR tcam_get_rule_info_byindex(int port,int index, const ACL_RULE * * prule);
    TCAMERR tcam_get_rule_info_byname(int port,const char * name, const ACL_RULE * * prule);
    TCAMERR tcam_add_rule(int port, const char * name,int index, int entries, const  TCAM_AAR * pact, const TCAM_ENTRY * ptcam_entry);
    TCAMERR tcam_read (int port,int index, char * const pmask, char * const pdata);
    TCAMERR tcam_write_add(int port, int index, Boolean insert, int row_shift, const  TCAM_AAR * pact, const char * pmask, const char * pdata);
    TCAMERR tcam_shift(int port, int new_entry, int start_row_shift, int num_shift, Boolean down);
    TCAMERR parser_read(int port, TCAM_PCTRL * const  parser);
    TCAMERR parser_write(int port, unsigned long  parser);
    TCAMERR rfr_read(int port, int parser,  RFRAY * const prfr);
    TCAMERR rfr_write(int port,int parser,  const RFRAY * prfr);

    TCAMERR range_read(int port,  TCAM_RANGE_AY  * const   prange_ay);
    TCAMERR range_write(int port, const TCAM_RANGE_AY * prange_ay);

    TCAMERR arcsr_read(int port, int parser,  ARCSR_AY * const parcsr_ay);
    TCAMERR arcsr_write(int port,int parser,  const ARCSR_AY * parcsr_ay);

    TCAMERR kivr_read(int port, int parser,  KIVR * const pkivr);
    TCAMERR kivr_write(int port,int parser,  const KIVR * pkivr);
    TCAMERR tcam_randon_write_test(int port);

#ifdef __cplusplus
}
#endif


#pragma pack(pop) 
#endif 