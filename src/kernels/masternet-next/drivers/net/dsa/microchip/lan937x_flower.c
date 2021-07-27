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

struct lan937x_flr_blk *lan937x_get_flr_blk (struct ksz_device *dev,
					     int port)
{
	struct ksz_port *p = &dev->ports[port];

	return p->priv;
}

struct lan937x_p_res *lan937x_get_flr_res (struct ksz_device *dev,
					 int port)
{
	struct lan937x_flr_blk *blk = lan937x_get_flr_blk(dev, port);

	return &blk->res;
}

void lan937x_flower_setup(struct dsa_switch *ds)
{
	struct ksz_device *dev = ds->priv;
	int port, rc;

	for (port = 0; port < dev->port_cnt; port++) {
		struct lan937x_flr_blk *blk = lan937x_get_flr_blk(dev, port);
		struct lan937x_p_res *res = &blk->res;

		rc = lan937x_init_acl_parsers(dev, port);

		INIT_LIST_HEAD(&blk->rules);

		memset(res->gate_used, 0, LAN937X_NUM_GATES);
		memset(res->stream_filters_used, 0,
		       LAN937X_NUM_STREAM_FILTERS);
		memset(res->tcam_entries_used, 0,
		       LAN937X_NUM_TCAM_ENTRIES);
		memset(res->tc_policers_used, 0, LAN937X_NUM_TC);
		res->broadcast_pol_used = false;
	}
}

static int lan937x_assign_stream_filter(struct ksz_device *dev,
					int port, u8 *stream_idx)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	int i;

	for (i = 0; i < LAN937X_NUM_STREAM_FILTERS; i++) {
		if (!(res->stream_filters_used[i])) {
			*stream_idx = i;
			return 0;
		}
	}
	return -ENOSPC;
}

static int lan937x_check_tc_pol_availability(struct ksz_device *dev,
					     int port, int traffic_class)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);

	if (res->tc_policers_used[traffic_class])
		return -ENOSPC;

	return 0;
}

static int lan937x_assign_tcam_entries(struct ksz_device *dev,
				       int port, u8 num_entry_reqd,
				       u8 *tcam_idx)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	int i, j, count;

	for (i = 0; i < LAN937X_NUM_TCAM_ENTRIES; i++) {
		count = 0;
		for (j = 0; j < num_entry_reqd; j++) {
			if (!(res->tcam_entries_used[i + j]))
				count++;
		}
		if (count == num_entry_reqd) {
			*tcam_idx = i;
			return 0;
		}
	}
	return -ENOSPC;
}

struct lan937x_flower_rule *lan937x_rule_find(struct ksz_device *dev,
					      int port, unsigned long cookie)
{
	struct lan937x_flr_blk *blk = lan937x_get_flr_blk(dev, port);
	struct lan937x_flower_rule *rule;

	list_for_each_entry(rule, &blk->rules, list)
		if (rule->cookie == cookie) {
			pr_info("%s %lu", __func__, cookie);
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
	struct lan937x_key *key = &filter->key;
	bool is_bcast_dmac = false;
	u64 dmac_mask = U64_MAX;
	u64 smac_mask = U64_MAX;
	u16 vid_mask = U16_MAX;
	u16 pcp_mask = U16_MAX;
	u64 dmac = U64_MAX;
	u64 smac = U64_MAX;
	u16 vid = U16_MAX;
	u16 pcp = U16_MAX;

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
		}

		dmac_mask = ether_addr_to_u64(match.mask->dst);
		dmac = ether_addr_to_u64(match.key->dst);
		is_bcast_dmac = ether_addr_equal(match.key->dst, bcast);
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan match;

		flow_rule_match_vlan(rule, &match);

		if (match.mask->vlan_id) {
			vid = match.key->vlan_id;
			vid_mask = match.mask->vlan_id;
		}

		if (match.mask->vlan_priority) {
			pcp = match.key->vlan_priority;
			pcp_mask = match.mask->vlan_priority;
		}
	}

	if (vid == U16_MAX && pcp == U16_MAX) {
		/**Key has NO parameter from VLAN Tag */
		if (smac != U64_MAX) {
			key->acl_dissector_map |= SRC_MAC_DISSECTOR_PRESENT;
			key->src_mac.value = smac;
			key->src_mac.mask = ~(smac & smac_mask);
			filter->filter_type = LAN937x_VLAN_UNAWARE_FILTER;
		} else if (is_bcast_dmac) {
			filter->filter_type = LAN937x_BCAST_FILTER;
			return 0;
		}

		if (dmac != U64_MAX) {
			key->acl_dissector_map |= DST_MAC_DISSECTOR_PRESENT;
			key->dst_mac.value = dmac;
			key->dst_mac.mask = ~(dmac & dmac_mask);
			filter->filter_type = LAN937x_VLAN_UNAWARE_FILTER;
		}
		return 0;
	} else {	/**Key has at least one parameter from VLAN Tag */
		if (smac != U64_MAX) {
			key->acl_dissector_map |= SRC_MAC_DISSECTOR_PRESENT;
			key->src_mac.value = smac;
			key->src_mac.mask = ~(smac & smac_mask);
		}
		if (dmac != U64_MAX) {
			key->acl_dissector_map |= DST_MAC_DISSECTOR_PRESENT;
			key->dst_mac.value = dmac;
			key->dst_mac.mask = ~(dmac & dmac_mask);
		}
		if (vid != U16_MAX) {
			key->acl_dissector_map |= VLAN_ID_DISSECTOR_PRESENT;
			key->vlan_id.value = vid;
			key->vlan_id.mask = ~(vid & vid_mask);
		}
		if (pcp != U16_MAX) {
			key->acl_dissector_map |= VLAN_PCP_DISSECTOR_PRESENT;
			key->vlan_prio.value = pcp;
			key->vlan_prio.mask = ~(pcp & pcp_mask);
		}
		filter->filter_type = LAN937x_VLAN_AWARE_FILTER;
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
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	struct lan937x_resrc_alloc *rsrc = rule->resrc;
	struct lan937x_flower *flower = rule->flower;
	int rc;

	flower->action.actions_presence_mask |= BIT(LAN937X_ACT_BCAST_POLICE);

	if (res->broadcast_pol_used) {
		NL_SET_ERR_MSG_MOD(extack, "Broadcast Policer already exists");
		return -ENOSPC;
	}

	flower->action.police.rate_bytes_per_sec = rate_bytes_per_sec;
	//div_u64(rate_bytes_per_sec * 512, 1000000);
	flower->action.police.burst = burst;
	//flower->action.police.mtu = mtu;

	rsrc->resrc_used_mask |= BIT(LAN937X_BROADCAST_POLICER);

	return rc;
}

static int lan937x_setup_action_redirect(struct ksz_device *dev,
					 struct netlink_ext_ack *extack,
					 int port,
					 struct lan937x_flower_rule *rule,
					 unsigned long destport_mask)
{
	struct lan937x_resrc_alloc *rsrc = rule->resrc;
	struct lan937x_flower *flower = rule->flower;
	int rc = EINVAL;

	flower->action.actions_presence_mask |= BIT(LAN937X_ACT_REDIRECT_FLOW);

	if (!rsrc->type.tcam.n_entries) {
		rc = lan937x_get_acl_requirements(flower->filter.filter_type,
						  &rsrc->type.tcam.parser,
						  &rsrc->type.tcam.n_entries);
		if (rc)
			return rc;

		rc = lan937x_assign_tcam_entries(dev,
						 port,
						 rsrc->type.tcam.n_entries,
						 &rsrc->type.tcam.index);
		if (rc)
			return rc;
	}

	flower->action.redirect_port_mask  |= destport_mask;

	rsrc->resrc_used_mask |= BIT(LAN937X_TCAM_ENTRIES);

	return rc;
}

static int lan937x_setup_action_drop(struct ksz_device *dev,
				     struct netlink_ext_ack *extack,
				     int port,
				     struct lan937x_flower_rule *rule)
{
	struct lan937x_resrc_alloc *rsrc = rule->resrc;
	struct lan937x_flower *flower = rule->flower;
	u8 *n_entries = &rsrc->type.tcam.n_entries;
	u8 *parser = &rsrc->type.tcam.parser;
	u8 *index = &rsrc->type.tcam.index;
	int rc = EINVAL;

	flower->action.actions_presence_mask |= BIT(LAN937X_ACT_DROP);

	if (flower->action.n_actions == 1) {
		rc = lan937x_get_acl_requirements(flower->filter.filter_type,
						  parser, n_entries);
		if (rc)
			return rc;
		rc = lan937x_assign_tcam_entries(dev, port, *n_entries,
						 index);
		if (rc)
			return rc;
	}
	rsrc->resrc_used_mask |= BIT(LAN937X_TCAM_ENTRIES);
	return rc;
}

static int lan937x_setup_tc_policer(struct ksz_device *dev,
				    struct netlink_ext_ack *extack,
				    int port,
				    struct lan937x_flower_rule *rule,
				    u64 rate_bytes_per_sec,
				    u32 burst)
{
	struct lan937x_resrc_alloc *rsrc = rule->resrc;
	struct lan937x_flower *flower = rule->flower;
	struct lan937x_flower_action *action;
	struct lan937x_key *key;
	int rc;

	action = &flower->action;
	action->actions_presence_mask |= BIT(LAN937X_ACT_STREAM_POLICE);

	key = &flower->filter.key;
	rc = lan937x_check_tc_pol_availability(dev,
					       port, key->vlan_prio.value);
	if (rc) {
		NL_SET_ERR_MSG_MOD(extack, "TC Policer already exists");
		return rc;
	}

	action->police.rate_bytes_per_sec = div_u64(rate_bytes_per_sec *
							512, 1000000);
	action->police.burst = burst;
	//flower->action.police.mtu = mtu;

	rsrc->resrc_used_mask |= BIT(LAN937X_TC_POLICER);

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
	struct lan937x_resrc_alloc *rsrc = rule->resrc;
	struct lan937x_flower *flower = rule->flower;
	struct lan937x_flower_action *action;
	int rc = 0;

	action = &flower->action;
	action->actions_presence_mask |= BIT(LAN937X_ACT_STREAM_POLICE);

	if (!rsrc->type.strm_flt.en) {
		rc = lan937x_assign_stream_filter(dev, port,
						  &rsrc->type.strm_flt.index);
		if (rc)
			return rc;

		rc = lan937x_get_acl_requirements(flower->filter.filter_type,
						  &rsrc->type.tcam.parser,
						  &rsrc->type.tcam.n_entries);
		if (rc)
			return rc;

		rc = lan937x_assign_tcam_entries(dev,
						 port,
						 rsrc->type.tcam.n_entries,
						 &rsrc->type.tcam.index);
		if (rc)
			return rc;

		rsrc->type.strm_flt.en = true;
	}

	action->police.rate_bytes_per_sec = rate_bytes_per_sec;
	//div_u64(rate_bytes_per_sec * 512, 1000000);
	action->police.burst = burst;
	action->police.mtu = mtu;

	rsrc->resrc_used_mask |= (BIT(LAN937X_STREAM_FILTER) |
				  BIT(LAN937X_TCAM_ENTRIES));
	return rc;
}

static int lan937x_flower_policer(struct ksz_device *dev,
				  struct netlink_ext_ack *extack,
				  int port,
				  struct lan937x_flower_rule *rule,
				  u64 rate_bytes_per_sec,
				  u32 burst,
				  u32 mtu)
{
	struct lan937x_flower *flower = rule->flower;
	struct lan937x_key *key;
	
	//TODO:Balaje
	switch (flower->filter.filter_type) {
	case LAN937x_BCAST_FILTER:
		return lan937x_setup_bcast_policer(dev, extack, port, rule,
						   rate_bytes_per_sec, burst);

	case LAN937x_VLAN_AWARE_FILTER:
		key = &flower->filter.key;
		if ((flower->action.n_actions == 1) &&
		    (key->acl_dissector_map == VLAN_PCP_DISSECTOR_PRESENT)) {
			return lan937x_setup_tc_policer(dev, extack, port,
							rule,
							rate_bytes_per_sec,
							burst);
		}
	case LAN937x_VLAN_UNAWARE_FILTER:
		return lan937x_setup_stream_policer(dev, extack, port,
						    rule, rate_bytes_per_sec,
						    burst, mtu);
	default:
		NL_SET_ERR_MSG_MOD(extack, "Unknown keys for policing");
		return -EOPNOTSUPP;
	}
}

int lan937x_flower_rule_init(struct lan937x_flower_rule **flower_rule)
{
	struct lan937x_flower_rule *t;

	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		return -ENOMEM;

	t->flower = kzalloc(sizeof(*t->flower), GFP_KERNEL);
	if (!t->flower) {
		kfree(t);
		return -ENOMEM;
	}

	t->resrc = kzalloc(sizeof(*t->resrc), GFP_KERNEL);
	if (!t->resrc) {
		kfree(t->flower);
		kfree(t);
		return -ENOMEM;
	}

	*flower_rule = t;
	return 0;
}

static int lan937x_flower_parse_actions(struct ksz_device *dev,
					struct netlink_ext_ack *extack,
					int port,
					struct flow_rule *rule,
					struct lan937x_flower_rule *flower_rule)
{
	const struct flow_action_entry *act;
	struct lan937x_flower *flower;
	int rc = 0;
	int i;

	flower = flower_rule->flower;
	flower->action.n_actions = rule->action.num_entries;

	/**For every action identify the capability & hw resrc availability*/
	flow_action_for_each(i, act, &rule->action) {
		switch (act->id) {
		case FLOW_ACTION_POLICE: {
			if (act->police.rate_pkt_ps) {
				NL_SET_ERR_MSG_MOD(extack,
						   "QoS offload not support packets per second");
				rc = -EOPNOTSUPP;
				goto out;
			}
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

			rc = lan937x_setup_action_redirect(dev, extack,
							   port,
							   flower_rule,
							   BIT(to_dp->index));
			break;
		}
		case FLOW_ACTION_DROP:
			rc = lan937x_setup_action_drop(dev, extack, port,
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

static int lan937x_flower_hw_configuration(struct ksz_device *dev,
					   int port,
					   struct lan937x_flower_rule *rule)
{
	struct lan937x_flower_action *action = &rule->flower->action;
	u32 actions_presence_mask = action->actions_presence_mask;
	struct lan937x_resrc_alloc *resrc = rule->resrc;
	u16 burst;
	u8 index;
	u64 cir;
	u32 val;
	int rc;
	int i;

	for (i = 0; ((actions_presence_mask != 0)  &&
		     (i < LAN937X_NUM_ACTIONS_SUPPORTED)); i++) {
		if (actions_presence_mask & BIT(i)) {
			actions_presence_mask &= ~BIT(i);
			switch (i) {
			case LAN937X_ACT_TC_POLICE:

				break;

			case LAN937X_ACT_BCAST_POLICE:

				break;

			case LAN937X_ACT_STREAM_POLICE:
				if (!resrc->type.strm_flt.en)
					return -EINVAL;

				index = resrc->type.strm_flt.index;
				rc = lan937x_pwrite8(dev, port,
						     REG_PORT_RX_QCI_PTR,
						     index);
				/*PSFP enable*/
				rc = lan937x_pwrite8(dev, port,
						     REG_PORT_RX_PSFP, BIT(0));

				cir = div_u64(action->police.rate_bytes_per_sec
					      * 5242, 10000000);
				pr_info("CIR %llu", cir);
				val = ((cir << 16) & 0xFFFF) | (cir & 0xFFFF);
				rc = lan937x_pwrite32(dev, port,
						      REG_PORT_RX_QCI_METER_SR,
						      val);

				burst = action->police.burst;
				pr_info("burst %u", burst);
				val = (((burst << 16) & 0xFFFF) |
				       (burst & 0xFFFF));
				rc = lan937x_pwrite32(dev, port,
						      REG_PORT_RX_QCI_METER_BS,
						      val);

				/**Enable flow meter of Id same as stream ID*/
				val = BIT(11) | ((index & 0x07) << 8);
				rc = lan937x_pwrite32(dev, port,
						      REG_PORT_RX_QCI_FS_CTL,
						      val);
				break;
			case LAN937X_ACT_STREAM_GATE:

				break;
			}
		}
	}
	return 0;
}

int lan937x_tc_flower_add(struct dsa_switch *ds, int port,
			  struct flow_cls_offload *cls, bool ingress)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);
	struct netlink_ext_ack *extack = cls->common.extack;
	struct lan937x_flower_rule *flower_rule;
	struct ksz_device *dev = ds->priv;
	struct lan937x_flr_blk *blk = lan937x_get_flr_blk(dev,port);
	int rc;

	if (lan937x_flower_rule_init(&flower_rule))
		return -ENOMEM;

	flower_rule->cookie = cls->cookie;

	/**Parse the Keys and identify the hw resources required*/
	rc = lan937x_flower_parse_key(extack, cls,
				      &flower_rule->flower->filter);
	if (rc)
		goto err;

	rc = lan937x_flower_parse_actions(dev, extack,
					  port, rule, flower_rule);
	if (rc)
		goto err;

	/** Configure the hardware Resources */
	rc = lan937x_flower_hw_configuration(dev, port,
					     flower_rule);
	if (rc)
		goto err;

	rc = lan937x_acl_program_entry(dev, port,
				       flower_rule);
	if (rc) {
		goto err;
		pr_info("Error!!!!");
	}

	kfree(flower_rule->flower);
	
	list_add(&flower_rule->list, &blk->rules);
	return 0;
err:
	kfree(flower_rule->flower);
	kfree(flower_rule->resrc);
	kfree(flower_rule);
	return rc;
}

int	lan937x_tc_flower_del(struct dsa_switch *ds, int port,
			      struct flow_cls_offload *cls, bool ingress)
{
	pr_info("Flower Deletion: %lu", cls->cookie);
	return 0;
}

int lan937x_tc_flower_stats(struct dsa_switch *ds, int port,
			    struct flow_cls_offload *cls, bool ingress)
{
	pr_info("Flower Status: %lu", cls->cookie);
	return 0;
}

