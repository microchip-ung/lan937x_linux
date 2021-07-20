#ifndef _NET_DSA_DRIVERS_LAN937X_FLOWER_H
#define _NET_DSA_DRIVERS_LAN937X_FLOWER_H

#include "lan937x_acl.h"

enum lan937x_filter_type {
	LAN937x_BCAST_FILTER,
	LAN937x_VLAN_UNAWARE_FILTER,
	LAN937x_VLAN_AWARE_FILTER,
};

enum lan937x_actions_id {
	LAN937X_ACTION_TRAFFIC_CLASS_ASSIGN,
	LAN937X_ACTION_REDIRECT_FLOW,
	LAN937X_ACTION_BCAST_POLICE,
	LAN937X_ACTION_TC_POLICE,
	LAN937X_ACTION_STREAM_POLICE,
	LAN937X_ACTION_STREAM_GATE,
	LAN937X_ACTION_DROP,

	LAN937X_NUM_ACTIONS_SUPPORTED,
};


struct lan937x_val_mask_u64 {
	u64 value;
	u64 mask;
};

struct lan937x_val_mask_u16 {
	u16 value;
	u16 mask;
};

enum lan937x_dissector_id {
	LAN937X_DISSECTOR_DST_MAC,
	LAN937X_DISSECTOR_SRC_MAC,
	LAN937X_DISSECTOR_VLAN_ID,
	LAN937X_DISSECTOR_VLAN_PRIO,
	LAN937X_DISSECTOR_ETHTYPE,

	LAN937X_NUM_DISSECTORS_SUPPORTED,
};

struct lan937x_key {
	u16 acl_dissector_map; /*Bits follow lan937x_dissector_id order.*/

	struct {
		struct lan937x_val_mask_u64 dst_mac;
		struct lan937x_val_mask_u64 src_mac;
		struct lan937x_val_mask_u16 vlan_id;
		struct lan937x_val_mask_u16 vlan_prio;
		struct lan937x_val_mask_u16 ethtype;
	};
};

struct lan937x_flower_filter {
	enum 	lan937x_filter_type filter_type;
	struct  lan937x_key key;
};

struct lan937x_flower_action {
	u8 num_actions;
	u32 actions_presence_mask; /**bits allocated in lan937x_actions_id order*/

	struct {
		u64 rate_bytes_per_sec; 
		u32 burst;
		u32 mtu;
	}pol;

	struct {
		int ipv; 
		u64 base_time; 
		u64 cycle_time;
		int num_entries;
		struct action_gate_entry *entries; 
		struct flow_stats stats;
	}gate;

	u8 redirect_port_mask;

};

enum lan937x_resource_id {
	LAN937X_TCAM_ENTRIES,
	LAN937X_STREAM_FILTER,
	LAN937X_PSFP_GATE,
	LAN937X_TC_POLICER,
	LAN937X_BROADCAST_POLICER,

	LAN937X_NUM_RESOURCES,
};

struct lan937x_rule_resource {
	u16 resource_used_mask; /*Bits assigned in lan937x_resource_id order*/
	struct {
		struct {
			u8 parser;
			u8 num_entries;
			u8 start_index;
		}tcam;

		struct {
			bool en;
			u8 stream_index;
		}stream_filter;

		struct {
			bool en;
			u8 index;
		}gate;

		u8 tc_pol_used_mask;

		u8 broadcast_pol_en;
	}resource;
};

struct lan937x_flower{
	struct lan937x_flower_filter filter;
	struct lan937x_flower_action action;
};


struct lan937x_flower_rule {
	struct list_head list;
	unsigned long cookie;
	struct lan937x_flower *pflower_params;
	struct lan937x_rule_resource* prule_resource;
	//struct lan937x_acl_action acl_action;
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
					struct lan937x_flower_rule *rule);
int	lan937x_tc_flower_del(struct dsa_switch *ds, int port,
				struct flow_cls_offload *cls, bool ingress);
int lan937x_tc_flower_stats(struct dsa_switch *ds, int port,
				    struct flow_cls_offload *cls, bool ingress);

extern int lan937x_get_acl_requirements(enum lan937x_filter_type filter_type,
				u8 *parser_idx, u8 *num_entries);
#endif

