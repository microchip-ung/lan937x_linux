#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tcam_itf.h"

#ifdef WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
extern int tcam_acl_proc(struct ksz_sw *sw, void * parg);
#define closeskt closesocket
#else /*Linux*/
#include <net/if.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/timeb.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#define closeskt close

#endif


typedef TCAMERR (* tcam_fn)(void * pcmd, const char ** param);
typedef struct {
    const char * pscmd;
    const char * description;
    tcam_fn pfn;
    int param;
} TCAM_CMDS;

#define MAX_PARAM	17
char test_mask[48];
char test_data[48];
static int g_sockfd;
static const char * cmd_param[16];

extern TCAMERR  syserr_to_err(int err);
/*static functions */
//static unsigned long find_length(FILE *fp);
static TCAMERR process_cmd(char * ps);
static char get_first_char(char *p, char  ** ppout);
static void print_tcamerr(TCAMERR err);
static const TCAM_CMDS * getcmd(char * ps);
static TCAMERR reset_fn(void * pcmd, const char ** param);
static TCAMERR rule_count_fn(void * pcmd, const char ** param);
static TCAMERR rule_index_fn(void * pcmd, const char ** param);
static TCAMERR rule_name_fn(void * pcmd, const char ** param);
static TCAMERR add_rule_fn(void * pcmd, const char ** param);
static TCAMERR read_entry_fn(void * pcmd, const char ** param);
static TCAMERR insert_one_entry_fn(void * pcmd, const char ** param);
//static TCAMERR shift_fn(void * pcmd, const char ** param);
static TCAMERR parser_read_fn(void * pcmd, const char ** param);
static TCAMERR parser_write_fn(void * pcmd, const char ** param);
static TCAMERR rfr_read_fn(void * pcmd, const char ** param);
static TCAMERR rfr_write_fn(void * pcmd, const char ** param);
static TCAMERR kvir_read_fn(void * pcmd, const char ** param);
static TCAMERR kvir_write_fn(void * pcmd, const char ** param);

static TCAMERR reg8_read_fn(void * pcmd, const char ** param);
static TCAMERR reg8_write_fn(void * pcmd, const char ** param);
static TCAMERR reg16_read_fn(void * pcmd, const char ** param);
static TCAMERR reg16_write_fn(void * pcmd, const char ** param);
static TCAMERR reg32_read_fn(void * pcmd, const char ** param);
static TCAMERR reg32_write_fn(void * pcmd, const char ** param);
static TCAMERR tcam_bit_test_fn(void * pcmd, const char ** param);
static TCAMERR fill_data(char * pin, char * pout);
static void print_mask_data(Boolean fmask, const char * p);

static TCAMERR range_read_fn(void * pcmd, const char ** param);
static TCAMERR range_write_fn(void * pcmd, const char ** param);
static TCAMERR parser_range(const char * pin,TCAM_RANGE *prange);

static TCAMERR arcsr_read_fn(void * pcmd, const char ** param);
static TCAMERR arcsr_write_fn(void * pcmd, const char ** param);

#ifndef WIN32
static int do_ioctl( struct tcam_acl * paction);
#endif
/*******************************************/

const TCAM_CMDS tcam_cmd[]= {
    {RESET,"TCAM Reset",reset_fn,1},
    {RULE_COUNT,"Get Rule Count",rule_count_fn,1},
    {RULE_INFO_INDEX,"Get Rule Info By Index",rule_index_fn,2},
    {RULE_INFO_NAME,"Get Rule Info By Name",rule_name_fn,2},
    {ADD_RULE,"Add Rule",add_rule_fn,13},/*port,name,index,entries,action,mask1,data1,mask2,data2,mask3,data3,mask4,data4 */
    {READ_ENTRY,"Read A TCAM Entry",read_entry_fn,2},
    {INSERT_ONE_ENTRY,"Insert A TCAM Entry",insert_one_entry_fn,6},/*port,index,start_row_shift, act,mask,data */
    //Don't need, as we have Add Rule command   {SHIFT,"Shift TCAM Entries",shift_fn,5},/*port, new_entry,start_row_shift,num_shift,down */
    {PARSER_READ,"Parser Read",parser_read_fn,1},
    {PARSER_WRITE,"Parser Write",parser_write_fn,2},
    {RFR_READ,"RFR Read",rfr_read_fn,2},   /*port, parser*/
    {RFR_WRITE,"RFR Write",rfr_write_fn,12}, /*port, parser, --> 10 RFRs */
    {KIVR_READ,"KVIR Read",kvir_read_fn,2},  /*port, parser*/
    {KIVR_WRITE,"KVIR Write",kvir_write_fn,3}, /*port, parser,  48 byte KIVR in xx-xx-xx...... format*/
    /*the command for read/write register*/
    {REG8_READ,"Read 8 bit register",reg8_read_fn,1},
    {REG8_WRITE,"Write 8 bit register",reg8_write_fn,2},
    {REG16_READ,"Read 16 bit register",reg16_read_fn,1},
    {REG16_WRITE,"Write 16 bit register",reg16_write_fn,2},
    {REG32_READ,"Read 32 bit register",reg32_read_fn,1},
    {REG32_WRITE,"Write 32 bit register",reg32_write_fn,2},
    {TCAM_BIT_TEST,"TCAM bit write test ",tcam_bit_test_fn,2},
    /*the command for range checking */
    {RANG_READ,"Read Range",range_read_fn,1}, /*port*/
    {RANG_WRITE,"Write Range",range_write_fn,17}, /*port, 16 Ranges*/
    {ARCSR_READ, "Read arcsr", arcsr_read_fn,2}, /*port, parser*/
    {ARCSR_WRITE,"Write arcsr",arcsr_write_fn,12}, /*port, parser,10 ARCSRs*/
    
    /*last row*/
    {NULL,0},
};

static void print_rfr(unsigned long rfr_in)
{
	RFR rfr;
	rfr.rfr=rfr_in;
	
	printf("reserved2=0x%02x\n",rfr.s.reserved2);
	printf("enable_range_match=0x%02x\n",rfr.s.enable_range_match);

	printf("start_l4=0x%02x\n",rfr.s.start_l4);
	printf("start_l3=0x%02x\n",rfr.s.start_l3);
	printf("start_l2=0x%02x\n",rfr.s.start_l2);
	
	printf("offset=0x%02x\n",rfr.s.offset);
	printf("length=0x%02x\n",rfr.s.length);
	printf("range_word_offset=0x%02x\n",rfr.s.range_word_offset);
	printf("reserved=0x%02x\n",rfr.s.reserved);
}

static void print_mask_data(Boolean fmask, const char * p)
{
    int i;
    char c;
    if(fmask)
        printf("Mask:\n");
    else
        printf("Data:\n");
    for(i=1; i<=48; i++) {
        c=(*(p+i-1));
        printf("%02x ",c&0xff);
        if(!(i%8))
            printf("\n");

    }

}

static TCAMERR fill_data(char * pin, char *  pout)
{
    char *token;
    int i,n;
    unsigned long l;
    /* get the first token */
    token = strtok(pin, "-");
    if(!token)
        return TCAMERR_PARAM;
    i=0;
    /* walk through other tokens */
    while( token != NULL ) {
        n=sscanf(token,"%02x",(unsigned int *)&l);
        if(n!=1){
        	/*the input is not a Hex number*/
        	return TCAMERR_PARAM;
        }
        pout[i]=(char)(l&0xff);
        i++;
        if(i>48)
            return TCAMERR_PARAM;
        token = strtok(NULL, "-");
    }
    if(i!=48)
        return TCAMERR_PARAM;
    else
        return TCAMERR_NOERROR;
}

static TCAMERR parser_range(const char * pin,TCAM_RANGE *prange)
{

    char *token;
    int i,n;
    unsigned long l;
    unsigned short u[3];
    /* get the first token */
    token = strtok(pin, ":");
    if(!token)
        return TCAMERR_PARAM;
    i=0;
    /* walk through other tokens */
    while( token != NULL ) {
        n=sscanf(token,"%04x",(unsigned int *)&l);
        if(n!=1){
        	/*the input is not a Hex number*/
        	return TCAMERR_PARAM;
        }
        
	u[i]=(unsigned short)(l&0xffff);
        
	i++;
        if(i>3)
            return TCAMERR_PARAM;
        token = strtok(NULL, ":");
    }
    if(i!=3)
        return TCAMERR_PARAM;
    
    prange->low_bound=u[0];    
    prange->up_bound=u[1];
    prange->range_mask=u[2];

    return TCAMERR_NOERROR;

}

static TCAMERR reset_fn(void * pcmd, const char ** param)
{
    int drverr=0;
    struct tcam_acl action;
    TCAMACL_RESE_FN reset_st;
    int port=atoi(param[0]);

    reset_st.port=port;
    action.cmd=TCAMACL_RESET;
    action.pfn=&reset_st;

#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif

    return (TCAMERR) drverr;
}


static TCAMERR rule_count_fn(void * pcmd, const char ** param)
{
    int drverr=0;
    struct tcam_acl action;
    int count;

    TCAMACL_GET_RULE_COUNT_FN rule_count;
    int port=atoi(param[0]);
    rule_count.port=port;
    rule_count.pn=&count;

    action.cmd= TCAMACL_GET_RULE_COUNT;
    action.pfn=&rule_count;
#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif


    if(drverr ==0) {
        printf("%s: get rule count=%d \n",((TCAM_CMDS *)pcmd)->description, count);
        return TCAMERR_NOERROR;
    }
    return (TCAMERR)drverr;
}
static TCAMERR rule_index_fn(void * pcmd, const char ** param)
{
    int drverr=0,i;
    struct tcam_acl action;
    ACL_RULE rule;
    TCAMACL_GET_RULE_INFO_BYINDEX_FN rule_index;

    rule_index.port=atoi(param[0]);
    rule_index.index=atoi(param[1]);
    rule_index.prule=&rule;

    action.cmd= TCAMACL_GET_RULE_INFO_BYINDEX;
    action.pfn=&rule_index;

#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif


    if(drverr ==0) {
        printf("%s: name=%s start entry=%d  entries=%d act=%04x:%x \n",((TCAM_CMDS *)pcmd)->description,
               rule_index.prule->name,rule_index.prule->start_entry,rule_index.prule->entries,
               (unsigned int)rule_index.prule->act.aar_high.aar_high, (unsigned int)rule_index.prule->act.aar_low.aar_low);

        for(i=0; i<rule_index.prule->entries; i++) {
            print_mask_data(1,(const char *)&rule_index.prule->tcam_entries.tcam_mask[i].mask[0]);
            print_mask_data(0,(const char *)&rule_index.prule->tcam_entries.tcam_data[i].data[0]);
        }

    }
    return (TCAMERR)drverr;


}
static TCAMERR rule_name_fn(void * pcmd, const char ** param)
{


    int drverr=0,i;
    struct tcam_acl action;
    ACL_RULE rule;
    TCAMACL_GET_RULE_INFO_BYNAME_FN rule_name;

    rule_name.port=atoi(param[0]);
    strcpy(rule_name.name,param[1]);
    rule_name.prule=&rule;

    action.cmd= TCAMACL_GET_RULE_INFO_BYNAME;
    action.pfn=&rule_name;

#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif


    if(drverr ==0) {
        printf("%s: name=%s start entry=%d  entries=%d act=%04x:%x \n",((TCAM_CMDS *)pcmd)->description,
               rule_name.prule->name,rule_name.prule->start_entry,rule_name.prule->entries,
               (unsigned int)rule_name.prule->act.aar_high.aar_high,(unsigned int)rule_name.prule->act.aar_low.aar_low);

        for(i=0; i<rule_name.prule->entries; i++) {
            print_mask_data(1,(const char *)&rule_name.prule->tcam_entries.tcam_mask[i].mask[0]);
            print_mask_data(0,(const char *)&rule_name.prule->tcam_entries.tcam_data[i].data[0]);
        }

    }
    return (TCAMERR)drverr;

}
static TCAMERR add_rule_fn(void * pcmd, const char ** param)
{
    TCAMERR err;
    int drverr=0;
    int i,j;
    unsigned long l1,l2;
    struct tcam_acl action;
    TCAMACL_ADD_RULE_FN add_rule;
    TCAM_AAR act;
    TCAM_ENTRY tcam_entry;
    add_rule.port=atoi(param[0]);
    strcpy(add_rule.name,param[1]);
    add_rule.index=atoi(param[2]);
    add_rule.entries=atoi(param[3]);
 
    i=sscanf(param[4],"%x:%x",(unsigned int *)&l1,(unsigned int *)&l2);
    if(i!=2)
	return TCAMERR_PARAM;
    

    act.aar_high.aar_high=(unsigned short)(l1&0xFFFF);
    act.aar_low.aar_low=l2;
   
    j=0;
    for(i=0; i<8; i+=2) {
        err=fill_data((char *)param[5+i],(char *)&tcam_entry.tcam_mask[j].mask[0]);
        if(err!= TCAMERR_NOERROR)
            break;
        err=fill_data((char *)param[5+i+1],(char *)&tcam_entry.tcam_data[j].data[0]);
        if(err!= TCAMERR_NOERROR)
            break;
        j++;
    }

    if(i!=8) {
        printf("The paramter %d is error \n",(5+i+1));
        return err;
    }

    add_rule.pact=&act;
    add_rule.ptcam_entry=&tcam_entry;
    action.cmd= TCAMACL_ADD_RULE;
    action.pfn=&add_rule;
#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif

    if(drverr==0) {
        printf("%s: Done\n",((TCAM_CMDS *)pcmd)->description);
    }
    return (TCAMERR)drverr;

}
static TCAMERR read_entry_fn(void * pcmd, const char ** param)
{

    int drverr=0;

    struct tcam_acl action;
    TCAMACL_READ_FN tcam_read;
    char mask[48], data[48];

    tcam_read.port=atoi(param[0]);
    tcam_read.index=atoi(param[1]);
    tcam_read.pmask=&mask[0];
    tcam_read.pdata=&data[0];

    action.cmd= TCAMACL_READ;
    action.pfn=&tcam_read;
#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif

    if(drverr ==0) {
        printf("%s: Port=%d TCAM entry=%d: \n",((TCAM_CMDS *)pcmd)->description,tcam_read.port, tcam_read.index);
        print_mask_data(1,&mask[0]);
        print_mask_data(0,&data[0]);
    }

    return (TCAMERR)drverr;

}


/*the function is only for testing purpose, it insert one entry directly to TCAM hardware*/
static TCAMERR insert_one_entry_fn(void * pcmd, const char ** param)
{
    
    TCAMERR err;
    int drverr=0;
    int i,j;
    unsigned long l1,l2;
    struct tcam_acl action;
    TCAMACL_INSERT_FN insert_tcam;
    TCAM_AAR act;
    char mask[48];
    char data[48];
    insert_tcam.port=atoi(param[0]);
    insert_tcam.index=atoi(param[1]);
    insert_tcam.start_row_shift=atoi(param[2]);
  
    i=sscanf(param[3],"%x:%x",(unsigned int *)&l1,(unsigned int *)&l2);
    if(i!=2)
	return TCAMERR_PARAM;

    act.aar_high.aar_high=(unsigned short)(l1&0xFFFF);
    act.aar_low.aar_low=l2;
   
     err=fill_data((char *)param[4],(char *)&mask[0]);
     if(err!= TCAMERR_NOERROR)
            return err;
     err=fill_data((char *)param[5],(char *)&data[0]);
     if(err!= TCAMERR_NOERROR)
            return err;
    insert_tcam.pact=&act;
    insert_tcam.pmask=&mask[0];
    insert_tcam.pdata=&data[0];
    action.cmd= TCAMACL_INSERT;
    action.pfn=&insert_tcam;
#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif
    if(drverr==0) {
        printf("%s: Done\n",((TCAM_CMDS *)pcmd)->description);
    }

    return (TCAMERR)drverr;
}

#if 0
static TCAMERR shift_fn(void * pcmd, const char ** param)
{
    return TCAMERR_NOERROR;
}
#endif

static TCAMERR parser_read_fn(void * pcmd, const char ** param)
{

    int drverr=0;
    unsigned long reg;
    struct tcam_acl action;
    TCAMACL_PARSER_READ_FN parser_read;

    parser_read.port=atoi(param[0]);
    parser_read.pparser=&reg;

    action.cmd= TCAMACL_PARSER_READ;
    action.pfn=&parser_read;
#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif

    if(drverr ==0) {
        printf("%s: Port=%d Parser Register=0x%08x \n",((TCAM_CMDS *)pcmd)->description,parser_read.port,(unsigned int )reg);
    }

    return (TCAMERR)drverr;
}
static TCAMERR parser_write_fn(void * pcmd, const char ** param)
{

    int i,drverr=0;
    struct tcam_acl action;
    TCAMACL_PARSER_WRITE_FN parser_write;
    parser_write.port=atoi(param[0]);
    i=sscanf(param[1],"%x",(unsigned int *)&parser_write.parser);
    if(i!=1)
	return TCAMERR_PARAM;

    action.cmd= TCAMACL_PARSER_WRITE;
    action.pfn=&parser_write;
#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif

    if(drverr ==0) {
        printf("%s: done \n",((TCAM_CMDS *)pcmd)->description);
    }

    return (TCAMERR)drverr;
}
static TCAMERR rfr_read_fn(void * pcmd, const char ** param)
{

    int i;
    int drverr=0;
    struct tcam_acl action;
    RFRAY rfray;
    TCAMACL_RFR_READ_FN rfr_read;

    rfr_read.port=atoi(param[0]);
    rfr_read.parser=atoi(param[1]);
    rfr_read.prfr=&rfray;

    action.cmd= TCAMACL_RFR_READ;
    action.pfn=&rfr_read;
#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif


    if(drverr ==0) {
        printf("%s: Port=%d Parse=%d\n",((TCAM_CMDS *)pcmd)->description,rfr_read.port,rfr_read.parser);
        printf("RFR: \n");
        for(i=0; i<10; i++) {
            printf("0x%08x ",(unsigned int )rfray.rfr_ay[i].rfr);
            
        }
	
        printf("\n");
    }

    return (TCAMERR)drverr;


}
static TCAMERR rfr_write_fn(void * pcmd, const char ** param)
{
    int i,j,drverr=0;
    struct tcam_acl action;
    RFRAY rfray;
    TCAMACL_RFR_WRITE_FN rfr_write;

    rfr_write.port=atoi(param[0]);
    rfr_write.parser=atoi(param[1]);
    rfr_write.prfr=&rfray;
    for(i=0; i<10; i++){
       j=sscanf(param[i+2],"%x",(unsigned int *)&rfray.rfr_ay[i].rfr);
       if(j!=1)
	   return TCAMERR_PARAM;
    }
    action.cmd= TCAMACL_RFR_WRITE;
    action.pfn=&rfr_write;
#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif

    if(drverr==0) {
        printf("%s: Done\n",((TCAM_CMDS *)pcmd)->description);
    }
    return (TCAMERR)drverr;
}
static TCAMERR kvir_read_fn(void * pcmd, const char ** param)
{

    int i,drverr=0;
    struct tcam_acl action;
    KIVR kivr;
    TCAMACL_KIVR_READ_FN kivr_read;

    kivr_read.port=atoi(param[0]);
    kivr_read.parser=atoi(param[1]);
    kivr_read.pkivr=&kivr;

    action.cmd= TCAMACL_KIVR_READ;
    action.pfn=&kivr_read;
#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif

    if(drverr ==0) {
        char c, * p;
        printf("%s: Port=%d Parse=%d\n",((TCAM_CMDS *)pcmd)->description,kivr_read.port,kivr_read.parser);
        printf("KIVR: \n");
        p=(char *)&kivr;
        for(i=1; i<=48; i++) { /* i=1 to void new line from i%8*/
            c=(*(p+i-1));
            printf("%02x ",c&0xff);
            if(!(i%8))
                printf("\n");
        }
    }

    return (TCAMERR)drverr;
}

static TCAMERR kvir_write_fn(void * pcmd, const char ** param)
{
    TCAMERR err;
    int drverr=0;
    struct tcam_acl action;
    KIVR kivr;
    TCAMACL_KIVR_WRITE_FN kivr_write;

    kivr_write.port=atoi(param[0]);
    kivr_write.parser=atoi(param[1]);
    kivr_write.pkivr=&kivr;

    err=fill_data((char *)param[2],(char *)&kivr);
    if(err!= TCAMERR_NOERROR)
        return err;


    action.cmd= TCAMACL_KIVR_WRITE;
    action.pfn=&kivr_write;
#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif

    if(drverr==0) {
        printf("%s: Done\n",((TCAM_CMDS *)pcmd)->description);
    }

    return (TCAMERR)drverr;

}

static TCAMERR register_read(void * pcmd, const char ** param, REGBIT bit)
{


    int i,drverr=0;
    struct tcam_acl action;
    REG_FN regfn;
    unsigned long l;
    regfn.fread=1;
    i=sscanf(param[0],"%x",(unsigned int *)&regfn.addr);
    if(i!=1)
	return TCAMERR_PARAM;

    regfn.regbit=bit;
    regfn.pout=&l;
    regfn.in=0;

    action.cmd= REG_ACCESS;
    action.pfn=&regfn;

#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif


    if(drverr==0) {
        if(bit==REG8)
            printf("%s: addr=0x%04x value=0x%02x\n", ((TCAM_CMDS *)pcmd)->description,(unsigned int)regfn.addr,(unsigned int)(l&0xff));
        else if(bit==REG16)
            printf("%s: addr=0x%04x value=0x%04x\n", ((TCAM_CMDS *)pcmd)->description,(unsigned int)regfn.addr,(unsigned int)(l&0xffff));
        else
            printf("%s: addr=0x%04x value=0x%08x\n", ((TCAM_CMDS *)pcmd)->description,(unsigned int)regfn.addr,(unsigned int)l);
    }

    return (TCAMERR)drverr;


}

static TCAMERR register_write(void * pcmd, const char ** param, REGBIT bit)
{


    int i,drverr=0;
    struct tcam_acl action;
    REG_FN regfn;
    unsigned long l;
    regfn.fread=0;
    i=sscanf(param[0],"%x",(unsigned int *)&regfn.addr);
    if(i!=1)
	return TCAMERR_PARAM;
    regfn.regbit=bit;
    regfn.pout=&l;
    i=sscanf(param[1],"%x",(unsigned int *)&regfn.in);
    if(i!=1)
	return TCAMERR_PARAM;
    
    action.cmd= REG_ACCESS;
    action.pfn=&regfn;

#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif


    if(drverr==0) {
        printf("%s: addr=0x%x value=0x%x Done\n",((TCAM_CMDS *)pcmd)->description,(unsigned int )regfn.addr, (unsigned int )regfn.in);
    }

    return (TCAMERR)drverr;


}


static TCAMERR reg8_read_fn(void * pcmd, const char ** param)
{
    printf("reg8 read\n");
    return register_read(pcmd, param, REG8);

}



static TCAMERR reg8_write_fn(void * pcmd, const char ** param)
{
    return register_write(pcmd, param, REG8);
}

static TCAMERR reg16_read_fn(void * pcmd, const char ** param)
{
    return register_read(pcmd, param, REG16);
}

static TCAMERR reg16_write_fn(void * pcmd, const char ** param)
{
    return register_write(pcmd, param, REG16);
}

static TCAMERR reg32_read_fn(void * pcmd, const char ** param)
{
    return register_read(pcmd, param, REG32);
}

static TCAMERR reg32_write_fn(void * pcmd, const char ** param)
{
    return register_write(pcmd, param, REG32);
}



static TCAMERR tcam_bit_test_fn(void * pcmd, const char ** param)
{
    int drverr=0;
    struct tcam_acl action;
    TCAMACL_BIT_WRITE_FN bitfn;
    int i,count;
    bitfn.port=atoi(param[0]);
    count=atoi(param[1]);

    action.cmd= TCAMACL_BIT_TEST;
    action.pfn=&bitfn;

    for(i=0;i<count;i++){
#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif
      if(drverr!=0)
	  		return (TCAMERR)drverr;
    }
    
    printf("bit test is successful\n");
    return (TCAMERR)drverr;
}


static TCAMERR range_read_fn(void * pcmd, const char ** param)
{
    int i;
    int drverr=0;
    struct tcam_acl action;
    TCAM_RANGE_AY    range_ay;
    TCAMACL_RANGE_READ_FN range_read;
   
    range_read.port=atoi(param[0]);
    range_read.prange_ay=&range_ay;

    action.cmd= TCAMACL_RANGE_READ;
    action.pfn=&range_read;
#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif


    if(drverr ==0) {
        printf("%s: Port=%d \n",((TCAM_CMDS *)pcmd)->description,range_read.port);
        printf("RANGE: \n");
        for(i=0; i<16; i++) {
	    printf("(%d)[low=0x%04x,up=0x%04x,mask=0x%02x] \n",i,(unsigned int )range_ay.range[i].low_bound,range_ay.range[i].up_bound,range_ay.range[i].range_mask);
            
        }
	printf("\n");
    }

    return (TCAMERR)drverr;

}
static TCAMERR range_write_fn(void * pcmd, const char ** param)
{

    int i,j,drverr=0;
    struct tcam_acl action;
    TCAMERR err;
    TCAM_RANGE_AY range_ay;
    TCAMACL_RANGE_WRITE_FN range_write;

    range_write.port=atoi(param[0]);
    range_write.prange_ay=&range_ay;

    for(i=0; i<16; i++){
       
       err=parser_range(param[i+1],&range_ay.range[i]);
       if(err!=TCAMERR_NOERROR)
	   return TCAMERR_PARAM;
    }
    action.cmd= TCAMACL_RANGE_WRITE;
    action.pfn=&range_write;
#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif

    if(drverr==0) {
        printf("%s: Done\n",((TCAM_CMDS *)pcmd)->description);
    }
    return (TCAMERR)drverr;
  
    
}


static TCAMERR arcsr_read_fn(void * pcmd, const char ** param)
{
     int i,drverr=0;
    struct tcam_acl action;
    ARCSR_AY arcsr_ay;
    TCAMACL_ARCSR_READ_FN arcsr_read;

    arcsr_read.port=atoi(param[0]);
    arcsr_read.parser=atoi(param[1]);
    arcsr_read.parcsr_ay=&arcsr_ay;

    action.cmd= TCAMACL_COMPARATOR_READ;
    action.pfn=&arcsr_read;
#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif


    if(drverr ==0) {
        printf("%s: Port=%d Parse=%d\n",((TCAM_CMDS *)pcmd)->description,arcsr_read.port,arcsr_read.parser);
        printf("ARCSR: \n");
        for(i=0; i<10; i++) {
	    printf("0x%04x ",(unsigned short)arcsr_ay.comparator[i]);
            
        }
	
        printf("\n");
    }

    return (TCAMERR)drverr;

}
static TCAMERR arcsr_write_fn(void * pcmd, const char ** param)
{
    struct tcam_acl action;
    int i,j,drverr=0;
    unsigned int l;
    TCAMERR err;
    ARCSR_AY arcsr_ay;
    TCAMACL_ARCSR_WRITE_FN arcsr_write;

    arcsr_write.port=atoi(param[0]);
    arcsr_write.parser=atoi(param[1]);
    arcsr_write.parcsr_ay=&arcsr_ay;
    
     for(i=0; i<10; i++){
	 j=sscanf(param[i+2],"%x",(unsigned int *)&l);
	 arcsr_ay.comparator[i]=l&0xffff;          
       if(j!=1)
	   return TCAMERR_PARAM;
    }
    action.cmd= TCAMACL_COMPARATOR_WRITE;
    action.pfn=&arcsr_write;
#ifdef WIN32
    drverr=tcam_acl_proc(NULL,&action);
#else
    drverr=do_ioctl(&action);
#endif

    if(drverr==0) {
        printf("%s: Done\n",((TCAM_CMDS *)pcmd)->description);
    }
    return (TCAMERR)drverr;
}


static  const TCAM_CMDS * getcmd(char * ps)
{
    const TCAM_CMDS * pcmd=&tcam_cmd[0];
    while(pcmd->pscmd) {
        if(strcmp(pcmd->pscmd,ps)==0)
            return pcmd;
        pcmd++;
    }
    return NULL;
}

static void print_tcamerr(TCAMERR err)
{
    switch (err) {
    case TCAMERR_NOERROR:
        break;
    case TCAMERR_PARAM:
        printf("Error: invalid parameter\n");
        break;
    case TCAMERR_BUSY:
        printf("Warning: TCAM is busy\n");
        break;
    case TCAMERR_MEMORY:
        printf("Error: no memory\n");
        break;
    case TCAMERR_NO_ROOM:
        printf("Error: no rom for new rule\n");
        break;
    case TCAMERR_UNKNOWN_CMD:
        printf("Error:  Unknown command \n");
        break;
    case TCAMERR_UNKNOWN:
        printf("Error: unknown error\n");
        break;
    case TCAMERR_IOCTL:
        printf("Error ioctl error\n");
        break;
    default:
        printf("Error: unknown error\n");
        break;
    }
}

char get_first_char(char *p, char  ** ppOut)
{
    while(*p!='\0' && *p!='\n') {
        if(*p!=' '&& *p!='\t') {
            *ppOut=p;
            return *p;

        } else
            p++;
    }
    *ppOut=p;
    return *p;
}

static Boolean empty_line(const char * pIn)
{
    while(*pIn!='\0') {
        if(*pIn==' ' || *pIn=='\n' || *pIn=='\r') {
            pIn++;
            continue;
        } else
            return MCHP_FALSE;
    }
    return MCHP_TRUE;
}

static TCAMERR process_cmd(char * pin)
{

    char c, * ps, * pnext, *token;
    int i;
    const TCAM_CMDS * pcmd=NULL;
    ps=pin;
    /* replace '\r' or '\n' with zero terminatio*/
    while(*ps!='\0') {
        if(*ps=='\r' || *ps=='\n') {
            *ps=0x00;
            break;
        }
        ps++;
    }

    /*skip the empty line*/
    if(empty_line(pin))
        return TCAMERR_NOERROR;


    /* skip the comment line*/
    c=get_first_char(pin,&pnext);

    if(c=='#')
        return TCAMERR_NOERROR;

    memset(&cmd_param[0],0,sizeof(cmd_param));
    /* get the first token */
    token = strtok(pin, " ");
    if(!token)
        return TCAMERR_UNKNOWN_CMD;
    i=0;
    /* walk through other tokens */
    while( token != NULL ) {

        switch(i) {
        case  0: /*first parameter is command*/
            pcmd=getcmd(token);
            if(!pcmd)
                return TCAMERR_UNKNOWN_CMD;
            break;

        case  MAX_PARAM+1:
            return TCAMERR_UNKNOWN_CMD;

        default:
            cmd_param[i-1]=token;
            break;
        }
        i++;
        token = strtok(NULL, " ");
    }

    if((i-1)!=pcmd->param)
        return TCAMERR_PARAM;

    return pcmd->pfn((void *)pcmd,&cmd_param[0]);

}

#if 0
static unsigned long find_length(FILE *fp)
{
    unsigned long length = 0;

    fseek(fp, 0L, SEEK_END);
    length = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    return length;
}
#endif

static char ifName[32]="eth0";
static char line[2048];

int main(int argc , const char * argv[])
{
    FILE * fp;
    int i;
    if(argc!=2) {
        printf("tcam_setup  FileName\n");
        return -1;
    }
    fp=fopen(argv[1] ,"rb");
    if(!fp) {
        printf("Error: Fail to open %s \n",argv[1]);
        return -1;
    }

    for(i=0; i<48; i++) {
        test_mask[i]=i;
        test_data[i]=i+48;
    }
    printf("tcam_setup programe begin run\n");
#ifdef WIN32
    {
        WSADATA wsaData = {0};
        int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0) {
            wprintf(L"WSAStartup failed: %d\n", iResult);
            return 1;
        }
    }
#endif
    /*open a UDP packet*/
    g_sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if(g_sockfd<0) {
        printf("Error: fail to open the UDB socket\n");
        return -1;
    }
    while (fgets(&line[0], sizeof(line), fp) != NULL) {
        TCAMERR err;
        //printf("%s\n", line);
        err=process_cmd(line);
        if(err != TCAMERR_NOERROR) {
            print_tcamerr(err);
            break;
        }

    }
    printf("the program exit\n");

    closeskt(g_sockfd);
    fclose(fp);
    return 0;
}

#ifndef WIN32
static int do_ioctl( struct tcam_acl * paction)
{
    struct ifreq ifr;
    int err;
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifName, sizeof(ifr.ifr_name));
    ifr.ifr_data = (char *)paction;;
    err=ioctl(g_sockfd, SIOCDEVPRIVATE+12, &ifr);
    if(err !=0)
        printf("ioctl error err=%d \n",err);
    return err;
}
#endif