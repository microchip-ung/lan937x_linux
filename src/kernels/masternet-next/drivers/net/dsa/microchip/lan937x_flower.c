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

struct lan937x_flr_blk *lan937x_get_flr_blk(struct ksz_device *dev, int port)
{
	struct ksz_port *p = &dev->ports[port];

	return p->priv;
}

struct lan937x_p_res *lan937x_get_flr_res(struct ksz_device *dev, int port)
{
	struct lan937x_flr_blk *blk = lan937x_get_flr_blk(dev, port);

	return &blk->res;
}

static int lan937x_assign_stream_filter(struct ksz_device *dev, int port,
					u8 *stream_idx)
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

static int lan937x_check_tc_pol_availability(struct ksz_device *dev, int port,
					     int traffic_class)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);

	if (res->tc_policers_used[traffic_class])
		return -ENOSPC;

	return 0;
}

static int lan937x_assign_tcam_counters(struct ksz_device *dev, int port,
					u8 *countr)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	u8 i;

	for (i = 0; i < LAN937x_NUM_TCAM_COUNTERS; i++) {
		if (!(res->tcam_frm_counters[i])) {
			*countr = i;

			return 0;
		}
	}

	*countr = STATS_COUNTER_NOT_ASSIGNED; //Invalid Value
	return -ENOSPC;
}

int lan937x_assign_tcam_entries(struct ksz_device *dev, int port,
				u8 num_entry_reqd, u8 *tcam_idx)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	int i, j, count;

	for (i = 0; i < LAN937X_NUM_TCAM_ENTRIES; i++) {
		count = 0;
		for (j = 0; j < num_entry_reqd; j++) {
			if (i + j > LAN937X_NUM_TCAM_ENTRIES)
				goto out;

			if (!(res->tcam_entries_used[i + j]))
				count++;
		}

		if (count == num_entry_reqd) {
			*tcam_idx = i;

			return 0;
		}
	}
out:
	return -ENOSPC;
}

struct lan937x_flower_rule *lan937x_rule_find(struct ksz_device *dev, int port,
					      unsigned long cookie)
{
	struct lan937x_flower_rule *rule;
	struct lan937x_flr_blk *blk = lan937x_get_flr_blk(dev, port);

	list_for_each_entry(rule, &blk->rules, list) {
		if (rule->cookie == cookie)
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
	u16 proto = ntohs(cls->common.protocol);
	bool is_bcast_dmac = false;
	bool match_proto = false;

	if (dissector->used_keys &
	    ~(BIT(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT(FLOW_DISSECTOR_KEY_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_VLAN) |
	      BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_IP) |
	      BIT(FLOW_DISSECTOR_KEY_PORTS))) {
		NL_SET_ERR_MSG_MOD(extack, "Unsupported keys used");
		return -EOPNOTSUPP;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);
		if (proto == ETH_P_IP) {
			key->ipv4.proto.value = match.key->ip_proto;
			key->ipv4.proto.mask = match.mask->ip_proto;
			key->acl_dissector_map |= IPV4_PROTO_DISSECTOR_PRESENT;
			match_proto = true;
		}
		if (proto == ETH_P_IPV6) {
			key->ipv6.next_hdr.value = match.key->ip_proto;
			key->ipv6.next_hdr.mask = match.mask->ip_proto;
			key->acl_dissector_map |= IPV6_NXTHDR_DISSECTOR_PRESENT;
			match_proto = true;
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		u8 bcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
		u8 null[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		struct flow_match_eth_addrs match;

		flow_rule_match_eth_addrs(rule, &match);

		if (!ether_addr_equal_masked(match.key->src, null,
					     match.mask->src)) {
			key->src_mac.mask = ether_addr_to_u64(match.mask->src);
			key->src_mac.value = ether_addr_to_u64(match.key->src);
			key->acl_dissector_map |= SRC_MAC_DISSECTOR_PRESENT;
		}
		is_bcast_dmac = ether_addr_equal(match.key->dst, bcast);
		key->dst_mac.mask = ether_addr_to_u64(match.mask->dst);
		key->dst_mac.value = ether_addr_to_u64(match.key->dst);
		key->acl_dissector_map |= DST_MAC_DISSECTOR_PRESENT;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan match;

		flow_rule_match_vlan(rule, &match);
		if (match.mask->vlan_id) {
			key->vlan_id.value = match.key->vlan_id;
			key->vlan_id.mask = match.mask->vlan_id;
			key->acl_dissector_map |= VLAN_ID_DISSECTOR_PRESENT;
		}

		if (match.mask->vlan_priority) {
			key->vlan_prio.value = match.key->vlan_priority;
			key->vlan_prio.mask = match.mask->vlan_priority;
			key->acl_dissector_map |= VLAN_PCP_DISSECTOR_PRESENT;
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS) &&
	    proto == ETH_P_IP) {
		struct flow_match_ipv4_addrs match;
		u8 *tmp;

		flow_rule_match_ipv4_addrs(rule, &match);

		tmp = &key->ipv4.sip.value[0];
		memcpy(tmp, &match.key->src, 4);

		tmp = &key->ipv4.sip.mask[0];
		memcpy(tmp, &match.mask->src, 4);

		tmp = &key->ipv4.dip.value[0];
		memcpy(tmp, &match.key->dst, 4);

		tmp = &key->ipv4.dip.mask[0];
		memcpy(tmp, &match.mask->dst, 4);

		key->acl_dissector_map |= (IPV4_SRC_IP_DISSECTOR_PRESENT |
					   IPV4_DST_IP_DISSECTOR_PRESENT);
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV6_ADDRS) &&
	    proto == ETH_P_IPV6) {
		struct flow_match_ipv6_addrs match;
		u8 *tmp;

		flow_rule_match_ipv6_addrs(rule, &match);

		tmp = &key->ipv6.sip.value[0];
		memcpy(tmp, &match.key->src.s6_addr[0], 16);

		tmp = &key->ipv6.sip.mask[0];
		memcpy(tmp, &match.mask->src.s6_addr[0], 16);

		tmp = &key->ipv6.dip.value[0];
		memcpy(tmp, &match.key->dst.s6_addr[0], 16);

		tmp = &key->ipv6.dip.mask[0];
		memcpy(tmp, &match.mask->dst.s6_addr[0], 16);

		key->acl_dissector_map |= (IPV6_SRC_IP_DISSECTOR_PRESENT |
					   IPV6_DST_IP_DISSECTOR_PRESENT);
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IP)) {
		struct flow_match_ip match;

		flow_rule_match_ip(rule, &match);
		if (proto == ETH_P_IP) {
			key->ipv4.tos.value = match.key->tos;
			key->ipv4.tos.mask = match.mask->tos;

			key->ipv4.ttl.value = match.key->ttl;
			key->ipv4.ttl.mask = match.mask->ttl;

			key->acl_dissector_map |= (IPV4_TOS_DISSECTOR_PRESENT |
						   IPV4_TTL_DISSECTOR_PRESENT);
		}

		if (proto == ETH_P_IPV6) {
			key->ipv6.tc.value = match.key->tos;
			key->ipv6.tc.mask = match.mask->tos;

			key->ipv6.hop.value = match.key->ttl;
			key->ipv6.hop.mask = match.mask->ttl;

			key->acl_dissector_map |= (IPV6_TC_DISSECTOR_PRESENT |
						   IPV6_HOP_DISSECTOR_PRESENT);
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_ports(rule, &match);

		key->src_port.value = ntohs(match.key->src);
		key->src_port.mask =  ntohs(match.mask->src);
		key->dst_port.value = ntohs(match.key->dst);
		key->dst_port.mask = ntohs(match.mask->dst);
		key->acl_dissector_map |= (L4_SRC_PORT_DISSECTOR_PRESENT |
					   L4_DST_PORT_DISSECTOR_PRESENT);
	}

	if (proto != ETH_P_ALL && match_proto) {
		/* TODO: support SNAP, LLC etc */
		if (proto < ETH_P_802_3_MIN)
			return -EOPNOTSUPP;
		key->ethtype.value = (proto);
		key->ethtype.mask = (0xffff);
		key->acl_dissector_map |= ETHTYPE_DISSECTOR_PRESENT;
	}

	if (key->acl_dissector_map == DST_MAC_DISSECTOR_PRESENT &&
	    is_bcast_dmac) {
		filter->type = LAN937x_BCAST_FILTER;
	} else if (key->acl_dissector_map & (VLAN_ID_DISSECTOR_PRESENT |
					  VLAN_PCP_DISSECTOR_PRESENT)){
		filter->type = LAN937x_VLAN_AWARE_FILTER;
	} else {
		filter->type = LAN937x_VLAN_UNAWARE_FILTER;
	}

	return 0;
}

static int lan937x_setup_bcast_policer(struct ksz_device *dev,
				       struct netlink_ext_ack *extack, int port,
				       struct lan937x_flower_rule *rule)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	struct lan937x_resrc_alloc *rsrc = rule->resrc;

	if (res->broadcast_pol_used) {
		NL_SET_ERR_MSG_MOD(extack, "Broadcast Policer already exists");
		return -ENOSPC;
	}

	rsrc->resrc_used_mask |= BIT(LAN937X_BROADCAST_POLICER);

	return 0;
}

static int lan937x_setup_action_redirect(struct ksz_device *dev,
					 struct netlink_ext_ack *extack,
					 int port,
					 struct lan937x_flower_rule *rule,
					 unsigned long destport_mask)
{
	struct lan937x_resrc_alloc *rsrc = rule->resrc;
	struct lan937x_flower *flower = rule->flower;
	int rc = 0;

	flower->action.actions_presence_mask |= BIT(LAN937X_ACT_REDIRECT_FLOW);

	if (!rsrc->type.tcam.n_entries) {
		rc = lan937x_get_acl_req(flower->filter.type,
					 &rsrc->type.tcam.parser,
					 &rsrc->type.tcam.n_entries);
		if (rc)
			return rc;
		rc = lan937x_assign_tcam_entries(dev, port,
						 rsrc->type.tcam.n_entries,
						 &rsrc->type.tcam.index);
		if (rc) {
			NL_SET_ERR_MSG_MOD(extack, "TCAM entry unavailable");
			return rc;
		}
		lan937x_assign_tcam_counters(dev, port, &rsrc->type.tcam.cntr);
	}
	flower->action.redirect_port_mask |= destport_mask;
	rsrc->resrc_used_mask |= BIT(LAN937X_TCAM_ENTRIES);

	return rc;
}

static int lan937x_setup_action_drop(struct ksz_device *dev,
				     struct netlink_ext_ack *extack, int port,
				     struct lan937x_flower_rule *rule)
{
	struct lan937x_resrc_alloc *rsrc = rule->resrc;
	struct lan937x_flower *flower = rule->flower;
	u8 *n_entries = &rsrc->type.tcam.n_entries;
	u8 *parser = &rsrc->type.tcam.parser;
	u8 *index = &rsrc->type.tcam.index;
	int rc = 0;

	flower->action.actions_presence_mask |= BIT(LAN937X_ACT_DROP);

	if (flower->action.n_actions == 1) {
		rc = lan937x_get_acl_req(flower->filter.type,
					 parser, n_entries);
		if (rc)
			return rc;

		rc = lan937x_assign_tcam_entries(dev, port, *n_entries, index);
		if (rc) {
			NL_SET_ERR_MSG_MOD(extack, "TCAM entry unavailable");
			return rc;
		}

		lan937x_assign_tcam_counters(dev, port, &rsrc->type.tcam.cntr);
	}
	rsrc->resrc_used_mask |= BIT(LAN937X_TCAM_ENTRIES);
	return rc;
}

static int lan937x_setup_action_priority(struct ksz_device *dev,
					 struct netlink_ext_ack *extack,
					 int port, u32 priority,
					 struct lan937x_flower_rule *rule)
{
	struct lan937x_resrc_alloc *rsrc = rule->resrc;
	struct lan937x_flower *flower = rule->flower;
	u8 *n_entries = &rsrc->type.tcam.n_entries;
	u8 *parser = &rsrc->type.tcam.parser;
	u8 *index = &rsrc->type.tcam.index;
	int rc = 0;

	flower->action.actions_presence_mask |= BIT(LAN937X_ACT_PRIORITY);
	rc = lan937x_get_acl_req(flower->filter.type,
				 parser, n_entries);
	if (rc)
		return rc;

	rc = lan937x_assign_tcam_entries(dev, port, *n_entries, index);

	if (rc) {
		NL_SET_ERR_MSG_MOD(extack, "TCAM entry unavailable");
		return rc;
	}
	lan937x_assign_tcam_counters(dev, port, &rsrc->type.tcam.cntr);
	flower->action.skbedit_prio = priority;
	rsrc->resrc_used_mask |= BIT(LAN937X_TCAM_ENTRIES);
	return rc;
}

static int lan937x_setup_tc_policer(struct ksz_device *dev,
				    struct netlink_ext_ack *extack, int port,
				    struct lan937x_flower_rule *rule,
				    u64 rate_bytes_per_sec, u32 burst)
{
	struct lan937x_resrc_alloc *rsrc = rule->resrc;
	struct lan937x_flower *flower = rule->flower;
	struct lan937x_flower_action *action;
	struct lan937x_key *key;
	int rc;

	action = &flower->action;
	action->actions_presence_mask |= BIT(LAN937X_ACT_TC_POLICE);

	key = &flower->filter.key;
	rc = lan937x_check_tc_pol_availability(dev, port,
					       key->vlan_prio.value);
	if (rc) {
		NL_SET_ERR_MSG_MOD(extack, "TC Policer already exists");
		return rc;
	}

	action->police.rate_bytes_per_sec = div_u64(rate_bytes_per_sec *
						    512, 1000000);
	action->police.burst = burst;
	/* Burst Setting is not supported by Queue Policer Hardware*/
	NL_SET_ERR_MSG_MOD(extack,
			   "Burst setting not supported by Queue Policer hw");
	rsrc->type.tc_pol_used = key->vlan_prio.value;
	rsrc->resrc_used_mask |= BIT(LAN937X_TC_POLICER);

	return rc;
}

static int lan937x_setup_stream_policer(struct ksz_device *dev,
					struct netlink_ext_ack *extack,
					int port,
					struct lan937x_flower_rule *rule,
					u64 rate_bytes_per_sec, u32 burst,
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
		if (rc) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Stream filter not available");
			return rc;
		}

		rc = lan937x_get_acl_req(flower->filter.type,
					 &rsrc->type.tcam.parser,
					 &rsrc->type.tcam.n_entries);
		if (rc)
			return rc;

		rc = lan937x_assign_tcam_entries(dev, port,
						 rsrc->type.tcam.n_entries,
						 &rsrc->type.tcam.index);
		if (rc) {
			NL_SET_ERR_MSG_MOD(extack, "TCAM entry not available");
			return rc;
		}

		/* Stream policer uses PSFP counters for stats, so tcam
		 * counter assignment is needed
		 */
		rsrc->type.tcam.cntr = STATS_COUNTER_NOT_ASSIGNED;
		rsrc->type.strm_flt.en = true;
	}

	action->police.rate_bytes_per_sec = rate_bytes_per_sec;
	action->police.burst = burst;
	action->police.mtu = mtu;
	rsrc->resrc_used_mask |= (BIT(LAN937X_STREAM_FILTER) |
				  BIT(LAN937X_TCAM_ENTRIES));
	return rc;
}

static int lan937x_flower_policer(struct ksz_device *dev,
				  struct netlink_ext_ack *extack, int port,
				  struct lan937x_flower_rule *rule,
				  u64 rate_bytes_per_sec, u32 burst, u32 mtu)
{
	struct lan937x_flower *flower = rule->flower;
	struct lan937x_key *key;
	int rc;

	switch (flower->filter.type) {
	case LAN937x_BCAST_FILTER:
		rc = lan937x_setup_bcast_policer(dev, extack, port, rule);
		if (rc)
			return rc;

		/* Utilize the Stream Filter to Implement BCAST Policer*/
		return lan937x_setup_stream_policer(dev, extack, port, rule,
						    rate_bytes_per_sec, burst,
						    mtu);
	case LAN937x_VLAN_AWARE_FILTER:
		key = &flower->filter.key;
		if (flower->action.n_actions == 1 &&
		    key->acl_dissector_map == VLAN_PCP_DISSECTOR_PRESENT) {
			return lan937x_setup_tc_policer(dev, extack, port, rule,
							rate_bytes_per_sec,
							burst);
		}
		fallthrough;
	case LAN937x_VLAN_UNAWARE_FILTER:
		return lan937x_setup_stream_policer(dev, extack, port, rule,
						    rate_bytes_per_sec, burst,
						    mtu);
	default:
		NL_SET_ERR_MSG_MOD(extack, "Unknown keys for policing");
		return -EOPNOTSUPP;
	}
}

int lan937x_flower_rule_init(struct ksz_device *dev,
			     struct lan937x_flower_rule **flower_rule)
{
	struct lan937x_flower_rule *t;

	t = devm_kzalloc(dev->dev, sizeof(*t), GFP_KERNEL);
	if (!t)
		return -ENOMEM;

	t->flower = devm_kzalloc(dev->dev, sizeof(*t->flower), GFP_KERNEL);
	if (!t->flower) {
		devm_kfree(dev->dev, t);
		return -ENOMEM;
	}

	t->resrc = devm_kzalloc(dev->dev, sizeof(*t->resrc), GFP_KERNEL);
	if (!t->resrc) {
		devm_kfree(dev->dev, t->flower);
		devm_kfree(dev->dev, t);
		return -ENOMEM;
	}

	*flower_rule = t;
	return 0;
}

static int lan937x_flower_parse_actions(struct ksz_device *dev,
					struct netlink_ext_ack *extack,
					int port, struct flow_rule *rule,
					struct lan937x_flower_rule *flower_rule)
{
	const struct flow_action_entry *act;
	struct lan937x_flower *flower;
	int rc = 0;
	int i;

	flower = flower_rule->flower;
	flower->action.n_actions = rule->action.num_entries;

	/**For every action, identify the capability & hw resrc availability*/
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
			unsigned int cpu = dsa_upstream_port(dev->ds, port);

			rc = lan937x_setup_action_redirect(dev, extack,
							   port,
							   flower_rule,
							   BIT(cpu));
			break;
		}
		case FLOW_ACTION_REDIRECT: {
			struct dsa_port *to_dp;

			to_dp = dsa_port_from_netdev(act->dev);

			rc = lan937x_setup_action_redirect(dev, extack, port,
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
		case FLOW_ACTION_PRIORITY:
			if (act->priority >= dev->ds->num_tx_queues) {
				NL_SET_ERR_MSG_MOD(extack,
						   "Only priorities 0..7 are supported");
				return -EINVAL;
			}

			rc = lan937x_setup_action_priority(dev, extack, port,
							   act->priority,
							   flower_rule);
			break;
		default:
			NL_SET_ERR_MSG_MOD(extack, "Action not supported");
			rc = -EOPNOTSUPP;
			goto out;
		}
	}
out:
	return rc;
}

static int lan937x_init_tc_policer_hw(struct ksz_device *dev, int port)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	int rc, i;

	rc = lan937x_port_cfg(dev, port, REG_PORT_MAC_IN_RATE_LIMIT,
			      PORT_RATE_LIMIT, false);

	for (i = 0; i < LAN937X_NUM_TC; i++) {
		rc = lan937x_pwrite8(dev, port, REG_PORT_PRI0_IN_RLIMIT_CTL + i,
				     0x00);
		if (rc)
			return rc;
		/* Note that the update will not take effect until the
		 * Port Queue 7 Ingress Limit ctrl Register is written.
		 */
		rc = lan937x_pwrite8(dev, port, REG_PORT_PRI7_IN_RLIMIT_CTL,
				     0x00);
		if (rc)
			return rc;
		res->tc_policers_used[i] = false;
	}

	return 0;
}

static int lan937x_cfg_tc_policer_hw(struct ksz_device *dev, int port,
				     struct lan937x_resrc_alloc *resrc,
				     u64 rate_bytes_per_sec)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	u8 code = 0;
	int rc, i;

	rc = lan937x_tc_pol_rate_to_reg(rate_bytes_per_sec, &code);
	if (rc)
		return rc;

	/** Clear Port Rate Limit to Priority based Rate Limit*/
	rc = lan937x_port_cfg(dev, port, REG_PORT_MAC_IN_RATE_LIMIT,
			      PORT_RATE_LIMIT, false);
	if (rc)
		return rc;

	i = resrc->type.tc_pol_used;
	rc = lan937x_pwrite8(dev, port, REG_PORT_PRI0_IN_RLIMIT_CTL + i, code);
	if (rc)
		return rc;
	/* Note that the update will not take effect until the Port Queue 7
	 * Ingress Limit ctrl Register is written. When port-based rate limiting
	 * is used a value of 0h should be written to Port Queue 7 Egress Limit
	 * Control Register.
	 */
	rc = lan937x_pread8(dev, port, REG_PORT_PRI7_IN_RLIMIT_CTL, &code);
	rc = lan937x_pwrite8(dev, port, REG_PORT_PRI7_IN_RLIMIT_CTL, code);
	if (rc)
		return rc;

	res->tc_policers_used[i] = true;

	return 0;
}

static int lan937x_init_strm_filter_hw(struct ksz_device *dev, int port)
{
	int rc, i;

	rc = lan937x_pwrite32(dev, port, REG_PORT_RX_PSFP, 0x00);
	if (rc)
		return rc;

	for (i = 0; i < LAN937X_NUM_STREAM_FILTERS; i++) {
		rc = lan937x_pwrite32(dev, port, REG_PORT_RX_QCI_PTR, i);
		if (rc)
			return rc;
		/*Clear the Meter Enable and Gate enable*/
		rc = lan937x_pwrite32(dev, port, REG_PORT_RX_QCI_FS_CTL, 0x00);
		if (rc)
			return rc;
	}
	return rc;
}

/* The PSFP rate limiting register contains 16 bit field each for CIR and PIR
 * The individual bits in CIR/PIR is assigned weightage in bits/sec unit.
 * To arrive at desired frequency, set one or more registers bits, which
 * cumulatively match the desired frequency approximately.
 * The below logic identifies the reg value by accumulating the weights until
 * the desired frequency is exceeded, and then looks back and removes the
 * weights to bring it further near the desired value. This function returns a
 * value that is greater than or equal to the desired value
 */
static u16 lan937x_psfp_rate_to_reg(u64 rate_bytes_per_sec)
{
	u64 rate_bps = (8 * rate_bytes_per_sec);
	u64 t_rate = 0;
	u16 regcode;
	u8 i = 0;
	int j;
	u32 t;
	const u32 regbit_weightage_bps[] = {	1525,		/*BIT 0*/
						3051,		/*BIT 1*/
						6103,		/*BIT 2*/
						12207,		/*BIT 3*/
						24414,		/*BIT 4*/
						48828,		/*BIT 5*/
						97656,		/*BIT 6*/
						195312,		/*BIT 7*/
						390625,		/*BIT 8*/
						781250,		/*BIT 9*/
						1562500,	/*BIT 10*/
						3125000,	/*BIT 11*/
						6250000,	/*BIT 12*/
						12500000,	/*BIT 13*/
						25000000,	/*BIT 14*/
						50000000	/*BIT 15*/
	};

	/*Reg Field Size is 16 bits*/
	while (i < 16) {
		if (t_rate < rate_bps) {
			/*Accumulate until desired frequency is exceeded*/
			t_rate = t_rate + regbit_weightage_bps[i];
			regcode |= BIT(i);
		} else {
			break;
		}
		i++;
	}

	if (t_rate != rate_bps) {
		/* j tracks the last bit index accumulated */
		j = i - 1;
		while (j >= 0) {
			t = t_rate - regbit_weightage_bps[j];
			if (t >= rate_bps) {
				/*Remove bits that are giving excessive value*/
				t_rate = t;
				regcode &= ~BIT(j);
			}
			j--;
		}
	}

	return regcode;
}

static int lan937x_cfg_strm_policer_hw(struct ksz_device *dev, int port,
				       struct lan937x_resrc_alloc *resrc,
				       struct lan937x_flower_action *action)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	u32 burst;
	u8 index;
	u16 cir;
	u32 val;
	int rc;

	if (!resrc->type.strm_flt.en)
		return -EINVAL;

	rc = lan937x_pwrite32(dev, port, REG_PORT_RX_PSFP, PSFP_ENABLE);
	if (rc)
		return rc;

	index = resrc->type.strm_flt.index;
	rc = lan937x_pwrite32(dev, port, REG_PORT_RX_QCI_PTR, index);
	if (rc)
		return rc;

	rc = lan937x_pwrite8(dev, port, REG_PORT_METER_RED_INT_MSK,
			     PORT_METER_RED_INT_MSK_ALL);
	if (rc)
		return rc;

	cir = lan937x_psfp_rate_to_reg(action->police.rate_bytes_per_sec);

	val = METER_SR_UPDT_RATE(cir, cir);/*fill PIR with same vaue*/

	rc = lan937x_pwrite32(dev, port, REG_PORT_RX_QCI_METER_SR, val);
	if (rc)
		return rc;

	burst = action->police.burst;
	val = METER_SR_UPDT_BURST(burst, burst);/*fill Peak burst same */

	rc = lan937x_pwrite32(dev, port, REG_PORT_RX_QCI_METER_BS, val);
	if (rc)
		return rc;

	/**Enable flow meter of Id (same as stream ID)*/
	val = (FS_CTL_METER_EN |
	       FS_UPDT_METER_IDX(index) |
	       FS_UPDT_MTU(action->police.mtu) |
	       FS_CTL_MAX_SDU_EN);
	rc = lan937x_pwrite32(dev, port, REG_PORT_RX_QCI_FS_CTL, val);
	if (rc)
		return rc;

	res->stream_filters_used[index] = true;

	return rc;
}

static int lan937x_flower_configure_hw(struct ksz_device *dev, int port,
				       struct lan937x_flower_rule *rule)
{
	struct lan937x_flower_action *action = &rule->flower->action;
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	u32 actions_presence_mask = action->actions_presence_mask;
	struct lan937x_resrc_alloc *resrc = rule->resrc;
	u64 rate = action->police.rate_bytes_per_sec;
	int rc;
	u8 i;

	if (resrc->resrc_used_mask & BIT(LAN937X_TCAM_ENTRIES)) {
		rc = lan937x_acl_program_entry(dev, port, rule);
		if (rc)
			return rc;
		if (resrc->type.tcam.cntr != STATS_COUNTER_NOT_ASSIGNED)
			res->tcam_frm_counters[resrc->type.tcam.cntr] = true;
	}

	for (i = 0; ((actions_presence_mask != 0) &&
		     (i < LAN937X_NUM_ACTIONS_SUPPORTED));
	     i++) {
		if (!(actions_presence_mask & BIT(i)))
			continue;

		actions_presence_mask &= ~BIT(i);

		switch (i) {
		case LAN937X_ACT_TC_POLICE:
			rc = lan937x_cfg_tc_policer_hw(dev, port, resrc, rate);
			break;

		case LAN937X_ACT_STREAM_POLICE:
			rc = lan937x_cfg_strm_policer_hw(dev, port, resrc,
							 action);
			break;

		case LAN937X_ACT_STREAM_GATE:
			/*To do*/
			break;
		}

		if (rc)
			return rc;
	}
	return 0;
}

/* Adjust the tcam start index of all the flower rules
 * occupying tcam rows below the deleted entry.
 */
static void lan937x_flower_recfg_tcam_idx(struct ksz_device *dev, int port,
					  struct lan937x_flower_rule *rule,
					  u8 n_entries)
{
	struct lan937x_flr_blk *blk = lan937x_get_flr_blk(dev, port);
	struct lan937x_resrc_alloc *resrc;
	struct lan937x_flower_rule *nxt_rule;
	u8 i, row;

	nxt_rule = rule;
	while (!list_is_first(&nxt_rule->list, &blk->rules)) {
		nxt_rule = list_prev_entry(nxt_rule, list);
		resrc = nxt_rule->resrc;

		if (resrc->type.tcam.n_entries) {
			resrc->type.tcam.index = (resrc->type.tcam.index -
						  n_entries);
		}
	}

	/* Clear the status of freed up rows to "Available for new rule" */
	if (-ENOSPC == lan937x_assign_tcam_entries(dev, port, 0x01, &row))
		row = LAN937X_NUM_TCAM_ENTRIES;

	for (i = 0; i < n_entries; i++) {
		--row;
		blk->res.tcam_entries_used[row] = false;
	}
}

static int lan937x_flower_free_resrcs(struct ksz_device *dev, int port,
				      struct lan937x_flower_rule *rule)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	struct lan937x_resrc_alloc *resrc = rule->resrc;
	int rc;
	int i;

	if (resrc->resrc_used_mask & BIT(LAN937X_TC_POLICER)) {
		i = resrc->type.tc_pol_used;
		rc = lan937x_pwrite8(dev, port, REG_PORT_PRI0_IN_RLIMIT_CTL + i,
				     0x00);
		if (rc)
			return rc;
		res->tc_policers_used[i] = false;
	}

	if (resrc->resrc_used_mask & BIT(LAN937X_TCAM_ENTRIES)) {
		u8 n_entries = resrc->type.tcam.n_entries;

		if (resrc->type.tcam.cntr != STATS_COUNTER_NOT_ASSIGNED)
			res->tcam_frm_counters[resrc->type.tcam.cntr] = false;

		if (resrc->type.tcam.n_entries) {
			rc = lan937x_acl_free_entry(dev, port, rule);
			lan937x_flower_recfg_tcam_idx(dev, port, rule,
						      n_entries);
		}
	}

	if (resrc->resrc_used_mask & BIT(LAN937X_STREAM_FILTER)) {
		if (!(resrc->type.strm_flt.en))
			return -EINVAL;

		i = resrc->type.strm_flt.index;

		rc = lan937x_pwrite32(dev, port, REG_PORT_RX_QCI_PTR, i);
		if (rc)
			return rc;
		/*Clear the Meter,Gate enable, Max SDU, Oversize block etc*/
		rc = lan937x_pwrite32(dev, port, REG_PORT_RX_QCI_FS_CTL, 0x00);
		if (rc)
			return rc;

		res->stream_filters_used[i] = false;
	}

	if (resrc->resrc_used_mask & BIT(LAN937X_BROADCAST_POLICER)) {
		if (resrc->type.broadcast_pol_en)
			res->broadcast_pol_used = false;
	}

	return 0;
}

int lan937x_cls_flower_add(struct dsa_switch *ds, int port,
			   struct flow_cls_offload *cls, bool ingress)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);
	struct netlink_ext_ack *extack = cls->common.extack;
	struct lan937x_flower_rule *flower_rule;
	struct ksz_device *dev = ds->priv;
	struct lan937x_flr_blk *blk = lan937x_get_flr_blk(dev, port);
	int rc;

	if (lan937x_flower_rule_init(dev, &flower_rule))
		return -ENOMEM;

	flower_rule->cookie = cls->cookie;

	/**Parse the Keys and identify the hw resources required*/
	rc = lan937x_flower_parse_key(extack, cls,
				      &flower_rule->flower->filter);
	if (rc)
		goto err;

	rc = lan937x_flower_parse_actions(dev, extack, port, rule, flower_rule);
	if (rc)
		goto err;

	/** Configure the hardware Resources */
	rc = lan937x_flower_configure_hw(dev, port, flower_rule);
	if (rc)
		goto err;

	devm_kfree(dev->dev, flower_rule->flower);
	list_add(&flower_rule->list, &blk->rules);
	cls->stats.pkts = 0x00;
	cls->stats.drops = 0x00;
	flower_rule->flower = NULL;
	return 0;
err:
	devm_kfree(dev->dev, flower_rule->flower);
	devm_kfree(dev->dev, flower_rule->resrc);
	devm_kfree(dev->dev, flower_rule);
	return rc;
}

int lan937x_cls_flower_del(struct dsa_switch *ds, int port,
			   struct flow_cls_offload *cls, bool ingress)
{
	struct ksz_device *dev = ds->priv;
	struct lan937x_flower_rule *rule;
	int rc;

	rule = lan937x_rule_find(dev, port, cls->cookie);
	if (!rule)
		return 0; /* There is No such Rule to delete*/

	rc = lan937x_flower_free_resrcs(dev, port, rule);
	if (rc)
		return rc;

	/*Delete the rule*/
	list_del(&rule->list);
	if (rule->flower)
		devm_kfree(dev->dev, rule->flower);
	devm_kfree(dev->dev, rule->resrc);
	devm_kfree(dev->dev, rule);
	return rc;
}

int lan937x_flower_setup(struct dsa_switch *ds)
{
	struct ksz_device *dev = ds->priv;
	int port, rc;

	for (port = 0; port < dev->port_cnt; port++) {
		struct lan937x_flr_blk *blk = lan937x_get_flr_blk(dev, port);
		struct lan937x_p_res *res = &blk->res;

		rc = lan937x_init_acl_parsers(dev, port);
		if (rc)
			return rc;

		rc = lan937x_init_strm_filter_hw(dev, port);
		if (rc)
			return rc;

		rc = lan937x_init_tc_policer_hw(dev, port);
		if (rc)
			return rc;

		INIT_LIST_HEAD(&blk->rules);

		memset(res->gate_used, false, LAN937X_NUM_GATES);
		memset(res->stream_filters_used, false,
		       LAN937X_NUM_STREAM_FILTERS);
		memset(res->tcam_entries_used, false, LAN937X_NUM_TCAM_ENTRIES);
		memset(res->tc_policers_used, false, LAN937X_NUM_TC);

		res->broadcast_pol_used = false;
	}

	return 0;
}

int lan937x_cls_flower_stats(struct dsa_switch *ds, int port,
			     struct flow_cls_offload *cls, bool ingress)
{
	struct ksz_device *dev = ds->priv;
	struct lan937x_resrc_alloc *resrc;
	struct lan937x_flower_rule *rule;
	struct flow_stats stats = {0};
	struct lan937x_p_res *res;
	u32 drops;
	u32 pkts;
	int rc;
	u8 i;

	res = lan937x_get_flr_res(dev, port);
	rule = lan937x_rule_find(dev, port, cls->cookie);
	if (!rule)
		return -EINVAL;

	resrc = rule->resrc;
	if (resrc->resrc_used_mask & BIT(LAN937X_TCAM_ENTRIES)) {
		if (resrc->type.tcam.cntr != STATS_COUNTER_NOT_ASSIGNED) {
			i = resrc->type.tcam.cntr;

			rc = lan937x_pread32(dev, port,
					     (REG_ACL_PORT_FR_COUNT0 + (i * 4)),
					     &pkts);
			cls->stats.pkts = 0;
			stats.pkts = (res->tcam_match_cntr_bkup[i] +
				      pkts - rule->stats.pkts);
			rule->stats.pkts = res->tcam_match_cntr_bkup[i] + pkts;
		} else if (resrc->resrc_used_mask &
			   BIT(LAN937X_STREAM_FILTER)) {
			i = resrc->type.strm_flt.index;

			rc = lan937x_pwrite32(dev, port, REG_PORT_RX_QCI_PTR,
					      i);
			if (rc)
				return rc;

			rc = lan937x_pread32(dev, port,
					     REG_PORT_RX_QCI_FS_FM,
					     &pkts);
			if (rc)
				return rc;

			rc = lan937x_pread32(dev, port,
					     REG_PORT_RX_QCI_FS_FD,
					     &drops);
			if (rc)
				return rc;

			/* Hardware Counters are 20bit counters
			 * Counter overflow cases are handled.
			 */
			cls->stats.pkts = 0;
			cls->stats.drops = 0;

			stats.pkts = (res->psfp_match_cntr_bkup[i] +
				      pkts - rule->stats.pkts);
			stats.drops = (res->psfp_drop_cntr_bkup[i] +
				       drops - rule->stats.drops);

			rule->stats.pkts = res->psfp_match_cntr_bkup[i] + pkts;
			rule->stats.drops = res->psfp_drop_cntr_bkup[i] + drops;
		}
	} else {
		return 0;
	}

	flow_stats_update(&cls->stats, 0x0, stats.pkts, stats.drops,
			  stats.lastused, FLOW_ACTION_HW_STATS_IMMEDIATE);

	return 0;
}

irqreturn_t lan937x_qci_cntr_isr(struct ksz_device *dev, int port)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	u8 sf_cntr_sts;
	u8 sf_int_sts;
	int rc;
	u8 i;

	/*Identify from which instance of Stream filter the Intr is raised */
	rc = lan937x_pread8(dev, port, REG_PORT_RX_CNT_OVR_INT_STS,
			    &sf_int_sts);
	if (rc)
		return IRQ_NONE;

	for (i = 0; i < LAN937X_NUM_STREAM_FILTERS; i++) {
		if (sf_int_sts & BIT(i)) {
			rc = lan937x_pwrite32(dev, port,
					      REG_PORT_RX_QCI_PTR, i);
			if (rc)
				return IRQ_NONE;
			/*Identify from which counter overflowed */
			rc = lan937x_pread8(dev, port,
					    REG_PORT_STREAM_CNT_STS,
					     &sf_cntr_sts);
			if (rc)
				return IRQ_NONE;

			/*Check whether Frame Match counter overflowed */
			if (sf_cntr_sts & FILT_STR_FR_MATCH_CNT_OVR) {
				u64 *cntr = &res->psfp_match_cntr_bkup[i];

				*cntr += FR_MATCH_CNTR_MAX;
				*cntr &= ~((u64)FR_MATCH_CNTR_MAX);
			}
			/*Check whether Flow Meter Drop counter overflowed */
			if (sf_cntr_sts & FILT_STR_FR_FAIL_DROP_CNT_OVR) {
				u64 *cntr = &res->psfp_drop_cntr_bkup[i];

				*cntr += FR_DROP_CNTR_MAX;
				*cntr &= ~((u64)FR_DROP_CNTR_MAX);
			}

			/*Clear the interrupt */
			rc =  lan937x_pwrite8(dev, port,
					      REG_PORT_STREAM_CNT_STS,
					       sf_cntr_sts);
			if (rc)
				return IRQ_NONE;
		}
	}
	return IRQ_HANDLED;
}
