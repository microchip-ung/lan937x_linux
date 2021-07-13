#ifndef _NET_DSA_DRIVERS_LAN937X_FLOWER_H
#define _NET_DSA_DRIVERS_LAN937X_FLOWER_H

#include "lan937x_acl.h"

enum lan937x_key_type {
	LAN937x_KEY_BCAST,
	LAN937x_KEY_VLAN_UNAWARE,
	LAN937x_KEY_VLAN_AWARE,
};

enum lan937x_rule_type {
	LAN937X_TRAFFIC_CLASS_ASSIGNMENT,
	LAN937X_REDIRECT_FLOW,
	LAN937X_RULE_BCAST_POLICER,
	LAN937X_RULE_TC_POLICER,
	LAN937X_RULE_PSFP,
	LAN937X_RULE_DROP,
	LAN937X_RULE_INVALID,
};


struct lan937x_val_mask_u64 {
	u64 value;
	u64 mask;
};

struct lan937x_val_mask_u16 {
	u16 value;
	u16 mask;
};

struct lan937x_key {
	/*Bit 0 to 15 assigned to members starting src_mac to ..*/
	u16 acl_dissector_map; 
	union {
		// struct {
		// 	struct lan937x_val_mask_u64 dst_mac;
		// 	struct lan937x_val_mask_u64 src_mac;
		// 	struct lan937x_val_mask_u16 ethtype;
		// } vlan_unaware;

		struct {
			struct lan937x_val_mask_u64 dst_mac;
			struct lan937x_val_mask_u64 src_mac;
			struct lan937x_val_mask_u16 vlan_id;
			struct lan937x_val_mask_u16 vlan_prio;
			struct lan937x_val_mask_u16 ethtype;
		} ;//vlan_aware;
	};
};

struct lan937x_filter {
	enum lan937x_key_type key_type;
	struct lan937x_key key;
};


struct lan937x_rule {
	struct list_head list;
	unsigned long cookie;
	struct lan937x_filter filter;
	enum lan937x_rule_type type;

	/* Configure Action */
	union {

		struct {
			int pcp;
			u64 rate_bytes_per_sec;
			u32 burst;			
		}tc_policer_cfg;

		/* LAN937X_RULE_PSFP */
		struct {
			/** Flow Meter Component */
			bool flowmeter_en;
			int flowmeter_idx;
			u64 rate_bytes_per_sec;
			u32 burst;

			/**Stream Filter Component */
			int streamfilter_idx;
			u32	mtu;

			/**Gate Component*/
			bool gate_en;
			int gate_idx;
			int maxlen;
			int ipv;
			u64 base_time;
			u64 cycle_time;
			int num_entries;
			struct action_gate_entry *entries;
			struct flow_stats stats;
		} strm_psfp_cfg;
	};

	struct lan937x_acl_action acl_action;
};

/************************************
 * Packet Formats supported by TCAM
 * ***********************************/

struct packet_universal
{
  u8  dst_mac[6];        /* destination eth addr        */
  u8  src_mac[6];        /* source ether addr        */
  u16 ether_type;        /* packet type ID field        */
} __attribute__ ((__packed__));

struct packet_extentions
{
	u16 offset;	/* offset address from start of packet**/
	u16 size;	/* Size of the extention */
};

struct packet_vlan_extn
{
  u16 vlan_tpid;
  u16 vlan_tci;
} __attribute__ ((__packed__));


int lan937x_tc_flower_add(struct dsa_switch *ds, int port,\
			   struct flow_cls_offload *cls, bool ingress);
void lan937x_flower_setup(struct dsa_switch *ds);


int lan937x_init_acl_parsers(struct ksz_device *dev,int port);
int lan937x_acl_program_entry(struct ksz_device *dev, int port,\
					struct lan937x_rule *rule);


#endif

