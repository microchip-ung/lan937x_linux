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
#include "lan937x_acl.h"


void lan937x_flower_setup (struct dsa_switch *ds)
{
	struct ksz_device *dev = ds->priv;
	int port,rc;

	for (port = 0; port < LAN937X_MAX_PORTS; port++) {
		rc = lan937x_init_acl_parsers(dev,port);
		INIT_LIST_HEAD(&dev->flower_block[port].rules);
		memset(dev->flower_block[port].flow_resources.gate_used,0,LAN937X_NUM_GATES_PER_PORT);
		memset(dev->flower_block[port].flow_resources.stream_filters_used,0,LAN937X_NUM_STREAM_FILTERS_PER_PORT);
		memset(dev->flower_block[port].flow_resources.tcam_entries_used,0,LAN937X_NUM_TCAM_ENTRIES_PER_PORT);
		memset(dev->flower_block[port].flow_resources.tc_policers_used,0,LAN937X_NUM_TCAM_ENTRIES_PER_PORT);
		dev->flower_block[port].flow_resources.broadcast_pol_used = false;
	}
}

static int lan937x_assign_stream_filter(struct ksz_device *dev,
						int port, u8 *stream_idx)
{
	int i = 0;

	while (i < LAN937X_NUM_STREAM_FILTERS_PER_PORT) {
		//pr_info("lan937x_find_free_stream_filter %d",i);
		if (!(dev->flower_block[port].flow_resources.stream_filters_used[i])){
			*stream_idx = i;
			pr_info("lan937x_find_free_stream_filter %d",i);
			return 0;
		}
		i++;
	}
	pr_info("Error");
	return -ENOSPC;
}

static int lan937x_check_tc_pol_availability (struct ksz_device *dev,
											 int port,
											 int traffic_class) {
	
	if(dev->flower_block[port].flow_resources.tc_policers_used[traffic_class])
				return -ENOSPC;
	
	return 0;
}


static int lan937x_assign_tcam_entries(struct ksz_device *dev,
						int port,u8 num_entry_reqd, u8 *tcam_idx)
{
	int i,j,count;

	for (i = 0; i < LAN937X_NUM_TCAM_ENTRIES_PER_PORT; i++) {
		count = 0;
		for (j = 0; j < num_entry_reqd; j++) {
			if (!(dev->flower_block[port].flow_resources.tcam_entries_used[i+j])) {
				pr_info("lan937x_assign_tcam_entries %d",i);
				count++;
			}
		}

		if(count == num_entry_reqd) {
			pr_info("lan937x_assign_tcam_entries %d",i);			
			*tcam_idx = i;
			return 0;
		}
	}
	return -ENOSPC;
}

struct lan937x_flower_rule *lan937x_rule_find (struct ksz_device *dev, 
						int port, unsigned long cookie)
{
	struct lan937x_flower_rule *rule;

	list_for_each_entry(rule, &dev->flower_block[port].rules, list)
		if (rule->cookie == cookie) {
			pr_info("lan937x_rule_find %lu",cookie);
			return rule;
		}

	return NULL;
}

static int lan937x_flower_parse_key(struct netlink_ext_ack *extack,
				    struct flow_cls_offload *cls,
				    struct lan937x_flower_filter *filter)
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
	

	if(vid == U16_MAX && pcp == U16_MAX) { /**Key has NO parameter from VLAN Tag */
		if(smac!=U64_MAX) {
			filter->key.acl_dissector_map |= (1<<acl_src_mac_dissector);
			filter->key.src_mac.value = smac;
			filter->key.src_mac.mask = ~(smac & smac_mask);
			filter->filter_type = LAN937x_VLAN_UNAWARE_FILTER;
		}else if(is_bcast_dmac) {
			filter->filter_type = LAN937x_BCAST_FILTER;
			return 0;
		}

		if(dmac!=U64_MAX) {
			filter->key.acl_dissector_map |= (1<<acl_dst_mac_dissector);
			filter->key.dst_mac.value = dmac;
			filter->key.dst_mac.mask = ~(dmac & dmac_mask);
			filter->filter_type = LAN937x_VLAN_UNAWARE_FILTER;
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
		filter->filter_type = LAN937x_VLAN_AWARE_FILTER;
		pr_info("VlanAw FieldPresence %X",filter->key.acl_dissector_map);

		return 0;
	}

	NL_SET_ERR_MSG_MOD(extack, "Not matching on any known key");
	return -EOPNOTSUPP;
}


static int lan937x_setup_bcast_policer(struct ksz_device *dev,
					struct netlink_ext_ack *extack,
				    int port,
					struct lan937x_flower_rule *rule,
				    u64 rate_bytes_per_sec,
				    u32 burst)
{
	struct lan937x_flower *flower = rule->pflower_params;
	struct lan937x_rule_resource *rule_rsrc = rule->prule_resource;
	int rc;

	pr_info("lan937x_setup_bcast_policer");

	flower->action.actions_presence_mask |= BIT(LAN937X_ACTION_BCAST_POLICE);
	
	if(dev->flower_block[port].flow_resources.broadcast_pol_used) {
		NL_SET_ERR_MSG_MOD(extack, "Broadcast Policer already exists");
		return ENOSPC;
	}
		
	flower->action.pol.rate_bytes_per_sec = rate_bytes_per_sec;//div_u64(rate_bytes_per_sec *\
						       					//512, 1000000);
	flower->action.pol.burst = burst;
	//flower->action.pol.mtu = mtu;

	rule_rsrc->resource_used_mask |= BIT(LAN937X_BROADCAST_POLICER);

	return rc;
}


static int lan937x_setup_action_redirect (struct ksz_device *dev,
				    struct netlink_ext_ack *extack,
				    int port,
					struct lan937x_flower_rule *rule,
					unsigned long destport_mask)
{
	struct lan937x_flower *flower = rule->pflower_params;
	struct lan937x_rule_resource *rule_rsrc = rule->prule_resource;
	int rc = EINVAL;

	pr_info("lan937x_setup_stream_policer");

	flower->action.actions_presence_mask |= BIT(LAN937X_ACTION_REDIRECT_FLOW);

	if(!rule_rsrc->resource.tcam.num_entries) {

		rc = lan937x_get_acl_requirements(flower->filter.filter_type,\
					&(rule_rsrc->resource.tcam.parser),\
					&(rule_rsrc->resource.tcam.num_entries));
		if(rc) {
			return rc;
		}
		rc = lan937x_assign_tcam_entries(dev,\
							port,\
							rule_rsrc->resource.tcam.num_entries,\
							&(rule_rsrc->resource.tcam.start_index));
		if(rc) {
			return rc;
		}
	}

	flower->action.redirect_port_mask  |= destport_mask;

	rule_rsrc->resource_used_mask |= BIT(LAN937X_TCAM_ENTRIES);

	return rc;
}

static int lan937x_setup_action_drop (struct ksz_device *dev,
					struct netlink_ext_ack *extack,
				    int port,
					struct lan937x_flower_rule *rule)
{
	struct lan937x_flower *flower = rule->pflower_params;
	struct lan937x_rule_resource *rule_rsrc = rule->prule_resource;
	int rc = EINVAL;

	pr_info("lan937x_setup_action_drop");
	pr_info("%lu", rule);


	flower->action.actions_presence_mask |= BIT(LAN937X_ACTION_DROP);

	if(flower->action.num_actions == 1) {

		rc = lan937x_get_acl_requirements(flower->filter.filter_type,\
					&(rule_rsrc->resource.tcam.parser),\
					&(rule_rsrc->resource.tcam.num_entries));
		if(rc) {
			return rc;
		}
		rc = lan937x_assign_tcam_entries(dev,\
							port,\
							rule_rsrc->resource.tcam.num_entries,\
							&(rule_rsrc->resource.tcam.start_index));
		if(rc) {
			return rc;
		}
	}

	rule_rsrc->resource_used_mask |= BIT(LAN937X_TCAM_ENTRIES);
	return rc;
}



static int lan937x_setup_tc_policer(struct ksz_device *dev,
					struct netlink_ext_ack *extack,
				    int port,
					struct lan937x_flower_rule *rule,
				    u64 rate_bytes_per_sec,
				    u32 burst)
{
	struct lan937x_flower *flower = rule->pflower_params;
	struct lan937x_rule_resource *rule_rsrc = rule->prule_resource;
	int rc;

	pr_info("lan937x_setup_tc_policer");

	flower->action.actions_presence_mask |= BIT(LAN937X_ACTION_STREAM_POLICE);
	
	rc = lan937x_check_tc_pol_availability (dev, port, flower->filter.key.vlan_prio.value);

	if(rc) {
		NL_SET_ERR_MSG_MOD(extack, "TC Policer already exists");
		return rc;
	}
		
	flower->action.pol.rate_bytes_per_sec = div_u64(rate_bytes_per_sec *\
						       					512, 1000000);
	flower->action.pol.burst = burst;
	//flower->action.pol.mtu = mtu;

	rule_rsrc->resource_used_mask |= BIT(LAN937X_TC_POLICER);

	return rc;
}


static int lan937x_setup_stream_policer(struct ksz_device *dev,
					struct netlink_ext_ack *extack,
				    int port,
					struct lan937x_flower_rule *rule,
				    u64 rate_bytes_per_sec,
				    u32 burst,
					u32 mtu)
{
	struct lan937x_flower *flower = rule->pflower_params;
	struct lan937x_rule_resource *rule_rsrc = rule->prule_resource;
	int rc = 0;

	pr_info("lan937x_setup_stream_policer");

	flower->action.actions_presence_mask |= BIT(LAN937X_ACTION_STREAM_POLICE);
	
	if(!rule_rsrc->resource.stream_filter.en) {
		rc = lan937x_assign_stream_filter\
				(dev,port,&rule_rsrc->resource.stream_filter.stream_index);
		if(rc) {
			return rc;
		}
	
		rc = lan937x_get_acl_requirements(flower->filter.filter_type,\
					&rule_rsrc->resource.tcam.parser,\
					&rule_rsrc->resource.tcam.num_entries);
		if(rc) {
			return rc;
		}
		rc = lan937x_assign_tcam_entries(dev,\
							port,\
							rule_rsrc->resource.tcam.num_entries,\
							&rule_rsrc->resource.tcam.start_index);
		if(rc) {
			return rc;
		}

		rule_rsrc->resource.stream_filter.en = true;		
	}

	flower->action.pol.rate_bytes_per_sec = rate_bytes_per_sec;//div_u64(rate_bytes_per_sec *\
						       					//512, 1000000);
	flower->action.pol.burst = burst;
	flower->action.pol.mtu = mtu;

	rule_rsrc->resource_used_mask |= BIT(LAN937X_STREAM_FILTER) | BIT(LAN937X_TCAM_ENTRIES);
	return rc;
}


static int lan937x_flower_policer(struct ksz_device *dev , struct netlink_ext_ack *extack, 
					int port,
					struct lan937x_flower_rule *rule,
				  	u64 rate_bytes_per_sec,
				  	u32 burst,
					u32 mtu)
{
	struct lan937x_flower *flower = rule->pflower_params;
	switch (flower->filter.filter_type){

	case LAN937x_BCAST_FILTER:
		return lan937x_setup_bcast_policer(dev, extack, port,rule,
						rate_bytes_per_sec, burst);

	case LAN937x_VLAN_AWARE_FILTER:
		if(flower->action.num_actions == 1) {
			if (flower->filter.key.acl_dissector_map == acl_vlan_pcp_dissector) {
				return lan937x_setup_tc_policer(dev, extack, port,\
							rule, rate_bytes_per_sec,\
							burst);
			}
		}
	case LAN937x_VLAN_UNAWARE_FILTER:
		return lan937x_setup_stream_policer(dev, extack, port,
						rule, rate_bytes_per_sec,
						burst,mtu);
	default:
		NL_SET_ERR_MSG_MOD(extack, "Unknown keys for policing");
		return -EOPNOTSUPP;
	}
}


int lan937x_flower_rule_init (struct lan937x_flower_rule **flower_rule)
{
	(*flower_rule) = 
		kzalloc(sizeof(struct lan937x_flower_rule), GFP_KERNEL);
	
	pr_info("%lu", *flower_rule);

	if (!*flower_rule)
		return -ENOMEM;

	(*flower_rule)->pflower_params = 
		kzalloc(sizeof(struct lan937x_flower), GFP_KERNEL);
	
	pr_info("%lu", (*flower_rule)->pflower_params);

	if (!(*flower_rule)->pflower_params) {
		kfree(*flower_rule);
		return -ENOMEM;
	}

	(*flower_rule)->prule_resource = 
		kzalloc(sizeof(struct lan937x_rule_resource), GFP_KERNEL);

	pr_info("%lu", (*flower_rule)->prule_resource);

	if (!(*flower_rule)->prule_resource) {
		kfree((*flower_rule)->pflower_params);
		kfree(*flower_rule);
		return -ENOMEM;
	}

	return 0;
}

static int lan937x_flower_parse_actions(struct ksz_device *dev,
				struct netlink_ext_ack *extack,
				int port,
				struct flow_rule *rule,
				struct lan937x_flower_rule *flower_rule)
{
	int rc, i;
	const struct flow_action_entry *act;

	flower_rule->pflower_params->action.num_actions = \
					rule->action.num_entries;

	/**For every action identify the capability and hw resource availability*/
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

			rc = lan937x_flower_policer(dev, extack, port,
						    flower_rule,
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

			rc = lan937x_setup_action_redirect (dev, extack,\
				    port,\
					flower_rule,\
					BIT(to_dp->index));
			break;
		}
		case FLOW_ACTION_DROP:
			rc = lan937x_setup_action_drop(dev, extack, port,\
						    flower_rule);
			break;
		case FLOW_ACTION_GATE:
			rc = -EOPNOTSUPP;
			break;
		default:
			NL_SET_ERR_MSG_MOD(extack,
					   "Action not supported");
			rc = -EOPNOTSUPP;
			goto out;
		}
	}
out:
	return rc;
}

static int lan937x_flower_hw_configuration (struct ksz_device *dev,
				int port,
				struct lan937x_flower_rule *rule)
{
	struct lan937x_key *key = &rule->pflower_params->filter.key;
	struct lan937x_flower_action *action = &rule->pflower_params->action;
	struct lan937x_rule_resource *resrc = rule->prule_resource;
	u16 acl_dissector_map = key->acl_dissector_map;
	u32 actions_presence_mask = action->actions_presence_mask;
	int i;
	int rc = 0;

	for (i = 0; (actions_presence_mask!=0) && (i < LAN937X_NUM_ACTIONS_SUPPORTED); i++) {
		if(actions_presence_mask & BIT(i)) {
			actions_presence_mask &= ~BIT(i);
			switch (i) {
				case LAN937X_ACTION_TC_POLICE:

				break;

				case LAN937X_ACTION_BCAST_POLICE:

				break;

				case LAN937X_ACTION_STREAM_POLICE:
					if(resrc->resource.stream_filter.en){
						u8 stream_index = resrc->resource.stream_filter.stream_index;
						u64 cir;
						u16 burst;
						u32 reg_val;

						pr_info ("lan937x_flower_hw_configuration");
						
						rc= lan937x_pwrite8(dev, port, REG_PORT_RX_QCI_PTR, stream_index);
						/*PSFP enable*/
						rc= lan937x_pwrite8(dev, port, REG_PORT_RX_PSFP, BIT(0));

						cir = div_u64(action->pol.rate_bytes_per_sec*5242,10000000);
						pr_info ("cir %lu", cir);
						reg_val = ((cir << 16) & 0xFFFF) | (cir & 0xFFFF);
						rc= lan937x_pwrite32(dev, port, REG_PORT_RX_QCI_METER_SR,reg_val);

						burst = action->pol.burst;
						pr_info ("burst %lu", burst);
						reg_val = ((burst << 16) & 0xFFFF) | (burst & 0xFFFF);
						rc= lan937x_pwrite32(dev, port, REG_PORT_RX_QCI_METER_BS,reg_val);

						/**Enable flow meter of Id same as stream ID*/
						reg_val = BIT(11) | ((stream_index & 0x07) <<8);
						rc= lan937x_pwrite32(dev, port, REG_PORT_RX_QCI_FS_CTL,reg_val);

					}
				break;
				case LAN937X_ACTION_STREAM_GATE:

				break;
			}
		}
	}
	return rc;
}


int lan937x_tc_flower_add (struct dsa_switch *ds, int port,
			   struct flow_cls_offload *cls, bool ingress)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);
	struct netlink_ext_ack *extack = cls->common.extack;	
	struct ksz_device *dev = ds->priv;
	int rc, i;
	struct lan937x_flower_rule *flower_rule;

	if (lan937x_flower_rule_init(&flower_rule))
		return -ENOMEM;
	
	flower_rule->cookie = cls->cookie;

	/**Parse the Keys and identify the hw resouces required*/
	rc = lan937x_flower_parse_key(extack, cls, 
			&flower_rule->pflower_params->filter);
	
	if (rc)
		goto err;

	rc = lan937x_flower_parse_actions(dev,extack,\
								port,rule,flower_rule);

	if (rc)
		goto err;

	/** Configure the hardware Resources */
	rc = lan937x_flower_hw_configuration(dev, port,\
					flower_rule);
	if (rc)
		goto err;

	rc = lan937x_acl_program_entry(dev, port,\
					flower_rule);
	if (rc) {
		goto err;
		pr_info("Error!!!!");
	}

	kfree(flower_rule->pflower_params);
	flower_rule->pflower_params == NULL;
	list_add(&flower_rule->list, &dev->flower_block[port].rules);
	return rc;

err:
	kfree(flower_rule);
	return rc;
}



int	lan937x_tc_flower_del(struct dsa_switch *ds, int port,
				struct flow_cls_offload *cls, bool ingress)
{
	pr_info ("Flower Deletion: %lu", cls->cookie);
	return 0;
}

int lan937x_tc_flower_stats(struct dsa_switch *ds, int port,
				    struct flow_cls_offload *cls, bool ingress)
{
	pr_info ("Flower Status: %lu", cls->cookie);
	return 0;	
}

