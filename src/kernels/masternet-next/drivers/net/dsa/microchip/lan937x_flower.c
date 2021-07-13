#if 1
// SPDX-License-Identifier: GPL-2.0
/* Microchip LAN937X switch driver main logic
 * Copyright (C) 2019-2021 Microchip Technology Inc.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/iopoll.h>
#include <linux/phy.h>
#include <linux/if_bridge.h>
#include <net/dsa.h>
#include <net/switchdev.h>
#include "lan937x_reg.h"
#include "lan937x_ptp.h"
#include "ksz_common.h"
#include "lan937x_dev.h"
#include "lan937x_tc.h"
#include "lan937x_flower.h"


void lan937x_flower_setup (struct dsa_switch *ds)
{
	struct ksz_device *dev = ds->priv;
	int port,rc;

	for (port = 0; port < LAN937X_MAX_PORTS; port++) {
		rc = lan937x_init_acl_parsers(dev,port);
		INIT_LIST_HEAD(&dev->flower_block[port].rules);
		memset(dev->flower_block[port].gate_used,0,LAN937X_NUM_GATES_PER_PORT);
		memset(dev->flower_block[port].stream_filters_used,0,LAN937X_NUM_STREAM_FILTERS_PER_PORT);
		memset(dev->flower_block[port].tcam_entry_slots_used,0,LAN937X_NUM_TCAM_ENTRIES_PER_PORT);
		
	}
}

static int lan937x_find_free_stream_filter(struct ksz_device *dev,
						int port)
{
	int i;

	for (i = 0; i < LAN937X_NUM_STREAM_FILTERS_PER_PORT; i++)
		if (!dev->flower_block[port].stream_filters_used[i]) {
			pr_info("lan937x_find_free_stream_filter %d",i);
			return i;
		}
	return NULL;
}

struct lan937x_rule* lan937x_rule_find(struct ksz_device *dev, 
						int port, unsigned long cookie)
{
	struct lan937x_rule *rule;

	list_for_each_entry(rule, &dev->flower_block[port].rules, list)
		if (rule->cookie == cookie) {
			pr_info("lan937x_rule_find %lu",cookie);
			return rule;
		}

	return NULL;
}

static int lan937x_flower_parse_key(struct netlink_ext_ack *extack,
				    struct flow_cls_offload *cls,
				    struct lan937x_filter *filter)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);
	struct flow_dissector *dissector = rule->match.dissector;
	bool is_bcast_dmac = false;
	u64 dmac = U64_MAX;
	u64 dmac_mask = U64_MAX;
	u64 smac = U64_MAX;
	u64 smac_mask = U64_MAX;
	u16 vid = U16_MAX;
	u16 vid_mask = U16_MAX;
	u16 pcp = U16_MAX;
	u16 pcp_mask = U16_MAX;
	
	pr_info("lan937x_flower_parse_key");

	if (dissector->used_keys &
	    ~(BIT(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT(FLOW_DISSECTOR_KEY_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_VLAN) |
	      BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS))) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Unsupported keys used");
		return -EOPNOTSUPP;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);
		if (match.key->n_proto) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Matching on protocol not supported");
			return -EOPNOTSUPP;
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		u8 bcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
		u8 null[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		struct flow_match_eth_addrs match;

		flow_rule_match_eth_addrs(rule, &match);

		if (!ether_addr_equal_masked(match.key->src, null,
					     match.mask->src)) {
			smac_mask = ether_addr_to_u64(match.mask->src);
			smac = ether_addr_to_u64(match.key->src);
			pr_info("smac %X:%X",smac,smac_mask);

		}

		dmac_mask = ether_addr_to_u64(match.mask->dst);
		dmac = ether_addr_to_u64(match.key->dst);
		pr_info("dmac %X:%X",dmac,dmac_mask);

		is_bcast_dmac = ether_addr_equal(match.key->dst, bcast);
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan match;

		flow_rule_match_vlan(rule, &match);

		if (match.mask->vlan_id) {
			vid = match.key->vlan_id;
			vid_mask = match.mask->vlan_id;
			pr_info("vid %X:%X",vid,vid_mask);

		}

		if (match.mask->vlan_priority) {
			pcp = match.key->vlan_priority;
			pcp_mask = match.mask->vlan_priority;
			pr_info("pcp %X:%X",pcp,pcp_mask);

		}
	}
	
	filter->key.acl_dissector_map = 0x0000;

	if(vid == U16_MAX && pcp == U16_MAX) { /**Key has NO parameter from VLAN Tag */
		if(smac!=U64_MAX) {
			filter->key.acl_dissector_map |= (1<<acl_src_mac_dissector);
			filter->key.src_mac.value = smac;
			filter->key.src_mac.mask = ~(smac & smac_mask);
			filter->key_type = LAN937x_KEY_VLAN_UNAWARE;
		}else if(is_bcast_dmac) {
			filter->key_type = LAN937x_KEY_BCAST;
			return 0;
		}

		if(dmac!=U64_MAX) {
			filter->key.acl_dissector_map |= (1<<acl_dst_mac_dissector);
			filter->key.dst_mac.value = dmac;
			filter->key.dst_mac.mask = ~(dmac & dmac_mask);
			filter->key_type = LAN937x_KEY_VLAN_UNAWARE;
			pr_info("VLANunAw FieldPresence %X",filter->key.acl_dissector_map);
		}

		return 0;
	}else {	/**Key has atleast one parameter from VLAN Tag */
		if(smac!=U64_MAX) {
			filter->key.acl_dissector_map |= (1<<acl_src_mac_dissector);
			filter->key.src_mac.value = smac;
			filter->key.src_mac.mask = ~(smac & smac_mask);
		}		
		if(dmac!=U64_MAX) {
			filter->key.acl_dissector_map |= (1<<acl_dst_mac_dissector);
			filter->key.dst_mac.value = dmac;
			filter->key.dst_mac.mask = ~(dmac & dmac_mask);
		}
		if(vid!=U16_MAX) {
			filter->key.acl_dissector_map |= (1<<acl_vlan_id_dissector);
			filter->key.vlan_id.value = vid;
			filter->key.vlan_id.mask = ~(vid & vid_mask);
		}
		if(pcp!=U16_MAX) {
			filter->key.acl_dissector_map |= (1<<acl_vlan_pcp_dissector);
			filter->key.vlan_prio.value = pcp;
			filter->key.vlan_prio.mask = ~(pcp & pcp_mask);
		}
		filter->key_type = LAN937x_KEY_VLAN_AWARE;
		pr_info("VlanAw FieldPresence %X",filter->key.acl_dissector_map);

		return 0;
	}

	NL_SET_ERR_MSG_MOD(extack, "Not matching on any known key");
	return -EOPNOTSUPP;
}


static int lan937x_setup_bcast_policer(struct ksz_device *dev, struct netlink_ext_ack *extack,
				    unsigned long cookie, int port, 
				    u64 rate_bytes_per_sec,
				    u32 burst)
{

	/* Step 1: Check if rate-burst rule is programable or not 
		if not programmable then invoke lan937x_setup_perstream_policer */

	struct lan937x_rule *rule = lan937x_rule_find(dev, port, cookie);

	/*To do: to know what the cookie exactly used for, why should we look into the existing rules database*/
	bool new_rule = false;
	int rc;

	if (!rule) {
		rule = kzalloc(sizeof(*rule), GFP_KERNEL);
		if (!rule)
			return -ENOMEM;

		rule->cookie = cookie;
		rule->type = LAN937X_RULE_BCAST_POLICER;
		new_rule = true;
	}

	rule->tc_policer_cfg.rate_bytes_per_sec = div_u64(rate_bytes_per_sec *
						       					512, 1000000);

	rule->tc_policer_cfg.burst = burst;


	/** To-Do: Determine whether we want to proceed with TCAM configuration here itself
	 * Note: There can be Gate action following this
	// */
	// rc = sja1105_static_config_reload(priv, SJA1105_BEST_EFFORT_POLICING);
	rc = 0; ////Temporary
out:
	if (rc == 0 && new_rule) {
		list_add(&rule->list, &(dev->flower_block[port].rules));
	} else if (new_rule) {
		kfree(rule);
	}

	return rc;
}


static int lan937x_setup_action_redirect (struct ksz_device *dev, struct netlink_ext_ack *extack,
				    unsigned long cookie, int port, 
					struct lan937x_filter *filter,int dest_port)
{
	struct lan937x_rule *rule = lan937x_rule_find(dev, port, cookie);

	/*To do: to know what the cookie exactly used for, why should we look into the existing rules database*/
	bool new_rule = false;
	int rc=0;

	pr_info("Cookie:%lu",cookie);

	if (!rule) {	/*If there are multiple actions, and already rule was created in another action context*/
		rule = kzalloc(sizeof(*rule), GFP_KERNEL);
		if (!rule)
			return -ENOMEM;
		memset(rule, 0, sizeof(rule));
		rule->cookie = cookie;
		rule->type = LAN937X_REDIRECT_FLOW;
		new_rule = true;
	}

	if (rule->type == LAN937X_RULE_DROP) {
		NL_SET_ERR_MSG_MOD(extack, "Drop action cannot go with other actions");
		rc = -EINVAL;
		goto  out;
	}
	/** To-Do: Should this be done only using TCAM?
	 *  can it not be implementable using ALU table modifications ?, if the classifier involves only the dst addr*/
	rule->acl_action.map_mode = 0x03;//bypass the ALU table
	rule->acl_action.dst_port = dest_port;//drop

	memcpy(&rule->filter, filter, sizeof(struct lan937x_filter));
	

out:
	if (rc == 0 && new_rule) {
		list_add(&rule->list, &(dev->flower_block[port].rules));
	} else if (new_rule) {
		kfree(rule);
	} else {
		list_del(&rule->list);	/*Why it doesnt require the list itself?*/
	}

	return rc;
}

static int lan937x_setup_action_drop (struct ksz_device *dev, struct netlink_ext_ack *extack,
				    unsigned long cookie, int port, 
					struct lan937x_filter *filter)
{
	struct lan937x_rule *rule = lan937x_rule_find(dev, port, cookie);

	/*To do: to know what the cookie exactly used for, why should we look into the existing rules database*/
	bool new_rule = false;
	int rc = 0;

	pr_info("Cookie:%lu",cookie);

	if (!rule) {	/*If there are multiple actions, and already rule was created in another action context*/
		rule = kzalloc(sizeof(*rule), GFP_KERNEL);
		if (!rule)
			return -ENOMEM;
		memset(rule, 0, sizeof(rule));
		rule->cookie = cookie;
		rule->type = LAN937X_RULE_DROP;
		new_rule = true;
	}

	if (rule->type!=LAN937X_RULE_DROP) {
		NL_SET_ERR_MSG_MOD(extack, "Drop action cannot go with other actions");
		rc = -EINVAL;
		goto out;
	}
	/** To-Do: Should this be done only using TCAM?
	 *  can it not be implementable using ALU table modifications ?, if the classifier involves only the dst addr*/
	rule->acl_action.map_mode = 0x03;//bypass the ALU table
	rule->acl_action.dst_port = 0x00;//drop

	memcpy(&rule->filter, filter, sizeof(struct lan937x_filter));

out:
	if (rc == 0 && new_rule) {
		list_add(&rule->list, &(dev->flower_block[port].rules));
	} else if (new_rule) {
		kfree(rule);
	} else {
		list_del(&rule->list);	/*Why it doesnt require the list itself?*/
	}

	return rc;
}

static int lan937x_setup_tc_policer(struct ksz_device *dev, struct netlink_ext_ack *extack,
				    unsigned long cookie, int port, 
					struct lan937x_filter *filter,
				    u64 rate_bytes_per_sec,
				    u32 burst)
{

	/* Step 1: Check if rate-burst rule is programable or not 
		if not programmable then invoke lan937x_setup_perstream_policer */

	struct lan937x_rule *rule = lan937x_rule_find(dev, port, cookie);

	/*To do: to know what the cookie exactly used for, why should we look into the existing rules database*/
	bool new_rule = false;
	int rc;

	if (!rule) {
		rule = kzalloc(sizeof(*rule), GFP_KERNEL);
		if (!rule)
			return -ENOMEM;

		rule->cookie = cookie;
		rule->type = LAN937X_RULE_TC_POLICER;
		rule->filter.key_type =  filter->key_type;
		new_rule = true;
	}

	rule->tc_policer_cfg.rate_bytes_per_sec = div_u64(rate_bytes_per_sec *
						       					512, 1000000);

	rule->tc_policer_cfg.burst = burst;



	/** To-Do: Determine whether we want to proceed with TCAM configuration here itself
	 * Note: There can be Gate action following this
	// */
	// rc = sja1105_static_config_reload(priv, SJA1105_BEST_EFFORT_POLICING);
	rc = 0; ////Temporary

out:
	if (rc == 0 && new_rule) {
		list_add(&rule->list, &(dev->flower_block[port].rules));
	} else if (new_rule) {
		kfree(rule);
	}

	return rc;
}


static int lan937x_setup_perstream_policer(struct ksz_device *dev, struct netlink_ext_ack *extack,
				    unsigned long cookie, int port, 
					struct lan937x_filter *filter,
				    u64 rate_bytes_per_sec,
				    u32 burst,
					u32 mtu)
{
	struct lan937x_rule *rule = lan937x_rule_find(dev, port, cookie);

	/*To do: to know what the cookie exactly used for, why should we look into the existing rules database*/
	bool new_rule = false;
	int rc;
	pr_info("Cookie:%lu",cookie);

	if (!rule) {	/*If there are multiple actions, and already rule was created in another action context*/
		rule = kzalloc(sizeof(*rule), GFP_KERNEL);
		if (!rule)
			return -ENOMEM;
		memset(rule, 0, sizeof(rule));
		rule->cookie = cookie;
		rule->type = LAN937X_RULE_PSFP;
		rule->strm_psfp_cfg.streamfilter_idx = lan937x_find_free_stream_filter(dev,port);
		rule->strm_psfp_cfg.flowmeter_idx 	= rule->strm_psfp_cfg.streamfilter_idx;
		rule->strm_psfp_cfg.flowmeter_en = true;
		//rule->acl_action.str_en = true;
		//rule->acl_action.str_idx = rule->strm_psfp_cfg.streamfilter_idx;

		rule->acl_action.map_mode = 0x03;
		rule->acl_action.dst_port = 0x00;
		new_rule = true;
	}

	memcpy(&rule->filter, filter, sizeof(struct lan937x_filter));

	if (rule->type!=LAN937X_RULE_PSFP) {
		NL_SET_ERR_MSG_MOD(extack, "Actions does not go well together");
		rc = -EINVAL;
		goto out;		
	}

	if (rule->strm_psfp_cfg.streamfilter_idx == -1) {
		NL_SET_ERR_MSG_MOD(extack, "All Stream filters already utilized");
		rc = -ENOSPC;
		goto out;
	}

	rule->strm_psfp_cfg.rate_bytes_per_sec = div_u64(rate_bytes_per_sec *
						       					512, 1000000);
	rule->strm_psfp_cfg.burst = burst;

	rule->strm_psfp_cfg.mtu = mtu;

	// /* TODO: support per-flow MTU */
	// policing[rule->tc_pol.sharindx].maxlen = VLAN_ETH_FRAME_LEN +
	// 					 ETH_FCS_LEN;

	/** To-Do: Determine whether we want to proceed with TCAM configuration here itself
	 * Note: There can be Gate action following this
	// */
	// rc = sja1105_static_config_reload(priv, SJA1105_BEST_EFFORT_POLICING);
	rc = 0; ////Temporary
out:
	if (rc == 0 && new_rule) {
		dev->flower_block[port].stream_filters_used[rule->strm_psfp_cfg.streamfilter_idx] = true;
		list_add(&rule->list, &(dev->flower_block[port].rules));
	} else if (new_rule) {
		kfree(rule);
	} else {
		list_del(&rule->list);	/*Why it doesnt require the list itself?*/
	}

	return rc;
}


static int lan937x_flower_policer(struct ksz_device *dev , struct netlink_ext_ack *extack, 
					unsigned long cookie, int port,
					struct lan937x_filter *filter,
				  	u64 rate_bytes_per_sec,
				  	u32 burst,
					u32 mtu)
{
	switch (filter->key_type) {
	case LAN937x_KEY_BCAST:
		pr_info("BCAST:%lu",cookie);
		return lan937x_setup_bcast_policer(dev, extack, cookie, port,
						rate_bytes_per_sec, burst);
	case LAN937x_KEY_VLAN_AWARE:
		if (filter->key.acl_dissector_map == acl_vlan_pcp_dissector) {
			pr_info("AWARE:%lu",cookie);
			return lan937x_setup_tc_policer(dev, extack, cookie, port,
						filter, rate_bytes_per_sec,
						burst);
		}
	case LAN937x_KEY_VLAN_UNAWARE:
		pr_info("UNAWARE:%lu",cookie);
		return lan937x_setup_perstream_policer(dev, extack, cookie, port,
						filter, rate_bytes_per_sec,
						burst,mtu);
	default:
		NL_SET_ERR_MSG_MOD(extack, "Unknown keys for policing");
		return -EOPNOTSUPP;
	}
}



static int lan937x_psfp_configure(struct ksz_device *dev,
				int port, struct lan937x_rule *rule)
{
	/*1) PSFP rules require TCAM */
	/* a) Identify the Free Entries */
	/* b) Identify the data mask */
	/* c) Identify the action setting */

	/*2) Program TCAM */
	/*3) Program PSFP */
	/* Then get ready to bury this !!*/
	return 0;
}

static int lan937x_flower_configure(struct ksz_device *dev, int port,
				struct lan937x_filter *filter)
{
	struct lan937x_rule *rule;// = lan937x_rule_find(dev, port, cookie);
	int rc=0;

	switch(rule->type) {
	case LAN937X_TRAFFIC_CLASS_ASSIGNMENT:

	break;
	case LAN937X_REDIRECT_FLOW:

	break;
	case LAN937X_RULE_BCAST_POLICER:

	break;
	case LAN937X_RULE_TC_POLICER:

	break;
	case LAN937X_RULE_PSFP:
		lan937x_psfp_configure(dev, port, rule);
	break;
	}
	return rc;
}


int lan937x_tc_flower_add(struct dsa_switch *ds, int port,
			   struct flow_cls_offload *cls, bool ingress)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);
	struct netlink_ext_ack *extack = cls->common.extack;	
	struct ksz_device *dev = ds->priv;
	const struct flow_action_entry *act;
	unsigned long cookie = cls->cookie;
	struct lan937x_filter *filter = kzalloc(sizeof(struct lan937x_filter), GFP_KERNEL);
	struct lan937x_rule *entry_rule;

	bool routing_rule = false;
	bool gate_rule = false;
	bool vl_rule = false;

	int rc, i;
	/**Parse the Keys*/
	rc = lan937x_flower_parse_key(extack, cls, filter);

	if (rc)
		return rc;

	/**Parse the actions*/
	flow_action_for_each(i, act, &rule->action) {
		switch (act->id) {
		case FLOW_ACTION_POLICE: {
			if (act->police.rate_pkt_ps) {
				NL_SET_ERR_MSG_MOD(extack,
						   "QoS offload not support packets per second");
				rc = -EOPNOTSUPP;
				goto out;
			}
			pr_info("FLOW_ACTION_POLICE %lu:%lu:%lu",act->police.rate_bytes_ps,act->police.burst,act->police.mtu);

			rc = lan937x_flower_policer(dev, extack, cookie, port,
						    filter,
						    act->police.rate_bytes_ps,
						    act->police.burst,
							act->police.mtu);
			if (rc)
				goto out;
			break;
		}
		case FLOW_ACTION_TRAP: {

			break;
		}
		case FLOW_ACTION_REDIRECT: {
			struct dsa_port *to_dp;

			to_dp = dsa_port_from_netdev(act->dev);

			break;
		}
		case FLOW_ACTION_DROP:
			rc = lan937x_setup_action_drop(dev, extack, cookie, port,\
						    filter);
			break;
		case FLOW_ACTION_GATE:

			break;
		default:
			NL_SET_ERR_MSG_MOD(extack,
					   "Action not supported");
			rc = -EOPNOTSUPP;
			goto out;
		}
	}

	/** Reserve the hardware Resources */
	entry_rule = lan937x_rule_find(dev, port, cookie);
	rc = lan937x_acl_program_entry(dev, port,\
					entry_rule);
	if (rc){
		pr_info("Error!!!!");
	}
out:
	kfree(filter);
	return rc;
}

#endif