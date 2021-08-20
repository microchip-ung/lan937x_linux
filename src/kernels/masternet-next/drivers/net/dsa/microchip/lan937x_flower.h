/* SPDX-License-Identifier: GPL-2.0 */
/* Microchip switch driver common header
 *
 * Copyright (C) 2019-2021 Microchip Technology Inc.
 */
#ifndef _NET_DSA_DRIVERS_LAN937X_FLOWER_H
#define _NET_DSA_DRIVERS_LAN937X_FLOWER_H

#include "lan937x_tc.h"
#include "lan937x_acl.h"

#define LAN937X_NUM_TCAM_ENTRIES	MAX_ACL_ENTRIES
#define LAN937X_NUM_STREAM_FILTERS	8
#define LAN937X_NUM_GATES		8

struct lan937x_p_res {
	bool tcam_entries_used[LAN937X_NUM_TCAM_ENTRIES];
	bool stream_filters_used[LAN937X_NUM_STREAM_FILTERS];
	bool gate_used[LAN937X_NUM_GATES];
	bool tc_policers_used[LAN937X_NUM_TC];
	bool broadcast_pol_used;
};

struct lan937x_flr_blk {
	struct list_head rules;	/**Element type: lan937x_flower_rule*/
	struct lan937x_p_res res;
};

enum lan937x_filter_type {
	LAN937x_BCAST_FILTER,
	LAN937x_VLAN_UNAWARE_FILTER,
	LAN937x_VLAN_AWARE_FILTER,
};

enum lan937x_actions_id {
	LAN937X_ACT_TRAFFIC_CLASS_ASSIGN,
	LAN937X_ACT_REDIRECT_FLOW,
	LAN937X_ACT_BCAST_POLICE,
	LAN937X_ACT_TC_POLICE,
	LAN937X_ACT_STREAM_POLICE,
	LAN937X_ACT_STREAM_GATE,
	LAN937X_ACT_DROP,
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

struct lan937x_val_mask_u8 {
	u8 value;
	u8 mask;
};

struct lan937x_ipv4_addr {
	u8 value[4];
	u8 mask[4];
};

struct lan937x_ipv6_addr {
	u8 value[16];
	u8 mask[16];
};

#define LAN937X_NUM_DISSECTORS_SUPPORTED acl_num_dissectors_supported

struct 	lan937x_ipv4{
	struct lan937x_ipv4_addr sip;
	struct lan937x_ipv4_addr dip;
	struct lan937x_val_mask_u8 ttl;
	struct lan937x_val_mask_u8 tos;
	struct lan937x_val_mask_u8 proto;
};

struct 	lan937x_ipv6{
	struct lan937x_ipv6_addr sip;
	struct lan937x_ipv6_addr dip;
	struct lan937x_val_mask_u8 hop;
	struct lan937x_val_mask_u8 tc;
	struct lan937x_val_mask_u8 next_hdr;
};

struct lan937x_key {
	u32 acl_dissector_map; /*Bits follow lan937x_dissector_id order.*/

	struct {
		struct lan937x_val_mask_u64 dst_mac;
		struct lan937x_val_mask_u64 src_mac;
		struct lan937x_val_mask_u16 vlan_id;
		struct lan937x_val_mask_u16 vlan_prio;
		struct lan937x_val_mask_u16 ethtype;
		union{
			struct lan937x_ipv4 ipv4;
			struct lan937x_ipv6 ipv6;
		};
		struct lan937x_val_mask_u16 src_port;
		struct lan937x_val_mask_u16 dst_port;
	};
};

struct lan937x_flower_filter {
	enum	lan937x_filter_type type;
	struct  lan937x_key key;
};

struct lan937x_flower_action {
	u8 n_actions;
	u32 actions_presence_mask; /**bits in lan937x_actions_id order*/

	struct {
		u64 rate_bytes_per_sec;
		u32 burst;
		u32 mtu;
	} police;

	struct {
		int ipv;
		u64 base_time;
		u64 cycle_time;
		int n_entries;
		struct action_gate_entry *entries;
		struct flow_stats stats;
	} gate;

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

struct lan937x_resrc_alloc {
	u16 resrc_used_mask; /*Bits assigned in lan937x_resource_id order*/
	struct {
		struct {
			u8 parser;
			u8 n_entries;
			u8 index;
		} tcam;

		struct {
			bool en;
			u8 index;
		} strm_flt;

		struct {
			bool en;
			u8 index;
		} gate;

		u8 tc_pol_used;
		u8 broadcast_pol_en;
	} type;
};

struct lan937x_flower {
	struct lan937x_flower_filter filter;
	struct lan937x_flower_action action;
};

struct lan937x_flower_rule {
	struct list_head list;
	unsigned long cookie;
	struct lan937x_flower *flower;
	struct lan937x_resrc_alloc *resrc;
};

int lan937x_tc_flower_add(struct dsa_switch *ds, int port,
			  struct flow_cls_offload *cls, bool ingress);
int lan937x_flower_setup(struct dsa_switch *ds);

int lan937x_init_acl_parsers(struct ksz_device *dev, int port);

int lan937x_acl_program_entry(struct ksz_device *dev, int port,
			      struct lan937x_flower_rule *rule);
int lan937x_tc_flower_del(struct dsa_switch *ds, int port,
			  struct flow_cls_offload *cls, bool ingress);
int lan937x_tc_flower_stats(struct dsa_switch *ds, int port,
			    struct flow_cls_offload *cls, bool ingress);

int lan937x_get_acl_req(enum lan937x_filter_type type,
			u8 *parser_idx, u8 *num_entries);
struct lan937x_flr_blk *lan937x_get_flr_blk (struct ksz_device *dev,
					     int port);
struct lan937x_p_res *lan937x_get_flr_res (struct ksz_device *dev,
					 int port);

extern int lan937x_tc_pol_rate_to_reg (u64 rate_bytes_per_sec, u8* regval);
int lan937x_assign_tcam_entries(struct ksz_device *dev,
				       int port, u8 num_entry_reqd,
				       u8 *tcam_idx);
int lan937x_acl_free_entry(struct ksz_device *dev, int port,
			   struct lan937x_flower_rule *rule);

#endif

