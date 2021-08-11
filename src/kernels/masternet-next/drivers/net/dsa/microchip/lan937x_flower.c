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

static int lan937x_rule_find(struct ksz_device *dev,
			     int port, unsigned long cookie,
			     struct lan937x_flower_rule *rule)
{
	struct lan937x_flr_blk *blk = lan937x_get_flr_blk(dev, port);

	list_for_each_entry(rule, &blk->rules, list)
		if (rule->cookie == cookie) {
			pr_info("%s %lu", __func__, cookie);
			return 0;
		}

	return -EINVAL;
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
	int rc = 0;

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
	int rc = 0;

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
	action->actions_presence_mask |= BIT(LAN937X_ACT_TC_POLICE);

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
	rsrc->type.tc_pol_used = key->vlan_prio.value;
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

int lan937x_flower_rule_init(struct ksz_device *dev,
			     struct lan937x_flower_rule **flower_rule)
{
	struct lan937x_flower_rule *t;

	t = devm_kzalloc(dev->dev,sizeof(*t), GFP_KERNEL);
	if (!t)
		return -ENOMEM;
	pr_info("%x",t);

	t->flower = devm_kzalloc(dev->dev,sizeof(*t->flower), GFP_KERNEL);
	if (!t->flower) {
		kfree(t);
		return -ENOMEM;
	}

	t->resrc = devm_kzalloc(dev->dev,sizeof(*t->resrc), GFP_KERNEL);
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
		case FLOW_ACTION_PRIORITY:
			NL_SET_ERR_MSG_MOD(extack, "To be supported");
			NL_SET_ERR_MSG_MOD(extack, "To be supported");
			pr_info("To be supported");
			pr_info("To be supported");
			pr_info("To be supported");
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

static int lan937x_init_tc_policer_hw(struct ksz_device *dev, int port)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	int rc,i;

	rc = lan937x_port_cfg(dev, port, REG_PORT_MAC_IN_RATE_LIMIT, 
			      PORT_RATE_LIMIT, false);
	
	for (i =0; i<LAN937X_NUM_TC; i++) {
		rc = lan937x_pwrite8(dev, port, 
				     REG_PORT_PRI0_IN_RLIMIT_CTL + i, 0x00);
		if (rc)
			return rc;
		/**Note that the update will not take effect until the 
		Port Queue 7 Ingress Limit ctrl Register is written.*/
		rc = lan937x_pwrite8(dev, port, 
				     REG_PORT_PRI7_IN_RLIMIT_CTL, 0x00);
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
	int rc,i;

	rc = lan937x_tc_pol_rate_to_reg(rate_bytes_per_sec, &code);
	if (rc)
		return rc;

	rc = lan937x_port_cfg(dev, port, REG_PORT_MAC_IN_RATE_LIMIT, 
			      PORT_RATE_LIMIT, true);	
	if (rc)
		return rc;
	
	i = resrc->type.tc_pol_used;
	rc = lan937x_pwrite8(dev, port, REG_PORT_PRI0_IN_RLIMIT_CTL + i, 
			     code);
	if (rc) 
		return rc;	
	/**Note that the update will not take effect until the Port Queue 7 
	Ingress Limit ctrl Register is written. When port-based rate limiting
	is used a value of 0h should be written to Port Queue 7 Egress Limit
	Control Register.*/
	rc = lan937x_pread8(dev, port, REG_PORT_PRI7_IN_RLIMIT_CTL, &code);
	rc = lan937x_pwrite8(dev, port, REG_PORT_PRI7_IN_RLIMIT_CTL, code);
	if (rc) 
		return rc;

	res->tc_policers_used[i] = true;

	return 0;
}

static int lan937x_init_strm_policer_hw (struct ksz_device *dev, int port)
{
	int rc;
	rc = lan937x_pwrite32(dev, port, REG_PORT_RX_PSFP, 0x00);
	if (rc) 
		return rc;
	rc = lan937x_pwrite32(dev, port, REG_PORT_RX_QCI_FS_CTL, 0x00);
	if (rc) 
		return rc;
	

}

/*The PSFP rate limiting register contains 16 bit field each for CIR and PIR
The individual bits in CIR/PIR is assigned weightage in terms of bps.
To arrive at desired frequency, set one or more registers bits, which 
cumulatively match the desired frequency approximately.
The below logic identifies the reg value by accumulating the weights until the 
desired frequency is exceeded, and then looks back and removes the weights to
bring it further near the desired value. This function returns a value that is 
greater than or equal to the desired value*/
static u16 lan937x_psfp_rate_to_reg (u64 rate_bytes_per_sec)
{
	u8 i;
	u32 t;
	int j;
	u16 regcode;
	u64 t_rate = 0;
	u64 rate_bps = (8 * rate_bytes_per_sec);
	const u32 regbit_weightage_bps[] = {1525,		/*BIT 0*/
					     3051,		/*BIT 1*/
					     6103,		/*BIT 2*/
					     12207,		/*BIT 3*/
					     24414,		/*BIT 4*/
					     48828,		/*BIT 5*/
					     97656,		/*BIT 6*/
					     195312,		/*BIT 7*/
					     390625,		/*BIT 8*/
					     781250,		/*BIT 9*/
					     1562500,		/*BIT 10*/
					     3125000,		/*BIT 11*/
					     6250000,		/*BIT 12*/
					     12500000,		/*BIT 13*/
					     25000000,		/*BIT 14*/
					     50000000		/*BIT 15*/
					};
	i=0;
	while (i<16) { /*Reg Field Size is 16 bits*/
		if (t_rate < rate_bps) {
			/*accumulate until desired frequency is exceeded*/
			t_rate = t_rate + regbit_weightage_bps[i];
			regcode |= BIT(i);
		}
		else
			break;
		i++;
	}
	
	if(t_rate != rate_bps) {
		j = i-1;	/* is the last bit index accumulated */
		while (j>=0) {
			t = t_rate - regbit_weightage_bps[j];
			if (t >= rate_bps) {
				/*remove bits that are giving excessive value*/
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
	int rc;
	u16 cir;
	u32 val;
	u8 index;
	u32 burst;
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);

	if (!resrc->type.strm_flt.en)
		return -EINVAL;

	rc = lan937x_pwrite32(dev, port, REG_PORT_RX_PSFP, PSFP_ENABLE);
	if (rc) 
		return rc;

	index = resrc->type.strm_flt.index;
	rc = lan937x_pwrite32(dev, port, REG_PORT_RX_QCI_PTR, index);
	if (rc) 
		return rc;

	rc = lan937x_pwrite8(dev, port,REG_PORT_METER_RED_INT_MSK,
			     PORT_METER_RED_INT_MSK_ALL);
	if (rc) 
		return rc;
	/**Enable flow meter of Id same as stream ID*/
	val = (FS_CTL_METER_EN |
	       ((index & FS_CTL_METER_IDX_MSK) << FS_CTL_METER_IDX_POS) | 
	       ((action->police.mtu & FS_CTL_MAX_SDU_MASK) <<
	        FS_CTL_MAX_SDU_POS) | FS_CTL_MAX_SDU_EN);
	rc = lan937x_pwrite32(dev, port, REG_PORT_RX_QCI_FS_CTL, val);
	if (rc) 
		return rc;	
			
	cir = lan937x_psfp_rate_to_reg(action->police.rate_bytes_per_sec);
	
	val = (((cir & METER_SR_MASK ) << METER_SR_CIR_POS) |
	       (cir & METER_SR_MASK));/*fill PIR with same vaue*/
	rc = lan937x_pwrite32(dev, port, REG_PORT_RX_QCI_METER_SR, val);
	if (rc) 
		return rc;	

	burst = action->police.burst;
	val = (((burst & METER_BS_MASK) << METER_BS_CBS_POS) |
		(burst & METER_BS_MASK));
	rc = lan937x_pwrite32(dev, port, REG_PORT_RX_QCI_METER_BS, val);
	if (rc) 
		return rc;	

	res->stream_filters_used[index] = true;

	return rc;
}

static int lan937x_flower_configure_hw(struct ksz_device *dev,
				       int port,
				       struct lan937x_flower_rule *rule)
{
	struct lan937x_flower_action *action = &rule->flower->action;
	//struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	u32 actions_presence_mask = action->actions_presence_mask;
	struct lan937x_resrc_alloc *resrc = rule->resrc;
	u64 rate = action->police.rate_bytes_per_sec;
	u8 index;
	int rc;
	u8 i;

	if (resrc->resrc_used_mask & BIT(LAN937X_TCAM_ENTRIES)) {
		rc = lan937x_acl_program_entry(dev, port, rule);
		if (rc)
			return rc;
	}

	for (i = 0; ((actions_presence_mask != 0)  &&
		     (i < LAN937X_NUM_ACTIONS_SUPPORTED)); i++) {

		if (!(actions_presence_mask & BIT(i)))
			continue;

		actions_presence_mask &= ~BIT(i);

		switch (i) {
		case LAN937X_ACT_TC_POLICE:
			rc = lan937x_cfg_tc_policer_hw(dev, port, 
						       resrc, rate);
			/*Identify if mtu can be configured*/
			/*Show to user that burst setting is ignored**/
			break;

		case LAN937X_ACT_BCAST_POLICE:

			break;

		case LAN937X_ACT_STREAM_POLICE:
			rc = lan937x_cfg_strm_policer_hw(dev, port,
							 resrc, action);
			break;

		case LAN937X_ACT_STREAM_GATE:

			break;
		}
	}
	return 0;
}

static int lan937x_flower_freeup_hw(struct ksz_device *dev, int port,
				    struct lan937x_flower_rule *rule)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	struct lan937x_resrc_alloc *resrc = rule->resrc;
	u16 adr;
	int rc;
	int i;

	if(resrc->resrc_used_mask & LAN937X_TC_POLICER) {
		i = resrc->type.tc_pol_used;
		rc = lan937x_pwrite8(dev, port, 
				     REG_PORT_PRI0_IN_RLIMIT_CTL+ i, 0x00);
		if (rc)
			return rc;
		res->tc_policers_used[i] =false;
	}

	if(resrc->resrc_used_mask & LAN937X_TCAM_ENTRIES) {
		if(resrc->type.tcam.n_entries) {

		}
	}

	if(resrc->resrc_used_mask & LAN937X_STREAM_FILTER) {
		if (resrc->type.strm_flt.en) {
			i = resrc->type.strm_flt.index;
			res->stream_filters_used[i] = false;
		}
	}

	if(resrc->resrc_used_mask & LAN937X_BROADCAST_POLICER) {	
		if (resrc->type.broadcast_pol_en) {
			/* To Do*/
		}
	}

	if(resrc->resrc_used_mask & LAN937X_PSFP_GATE) {
		if (resrc->type.gate.en) {
			/*TCAM Rule shall be deleted*/
			i = resrc->type.gate.index;
			res->gate_used[i] = false;
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

	if (lan937x_flower_rule_init(dev,&flower_rule))
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
	rc = lan937x_flower_configure_hw(dev, port,
					 flower_rule);
	if (rc)
		goto err;	
	
	kfree(flower_rule->flower);
	list_add(&flower_rule->list, &blk->rules);
	return 0;
err:
	kfree(flower_rule->flower);
	kfree(flower_rule->resrc);
	kfree(flower_rule);
	return rc;
}

int lan937x_tc_flower_del(struct dsa_switch *ds, int port,
			  struct flow_cls_offload *cls, bool ingress)
{
	struct lan937x_flower_rule *rule;
	int rc;
	
	rc = lan937x_rule_find(ds->priv,port, cls->cookie, rule);
	if (rc)
		return rc;

	//rc = lan937x_free_resrcs(ds->dev, port, rule);
	//if (rc)
	//	return rc;		
	pr_info("Flower Deletion: %lu", cls->cookie);


	return rc;
}

int lan937x_tc_flower_stats(struct dsa_switch *ds, int port,
			    struct flow_cls_offload *cls, bool ingress)
{
	pr_info("Flower Status: %lu", cls->cookie);
	return 0;
}

	
