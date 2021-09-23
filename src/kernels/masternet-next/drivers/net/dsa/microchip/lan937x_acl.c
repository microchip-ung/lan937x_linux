// SPDX-License-Identifier: GPL-2.0
/* Microchip lan937x dev ops functions
 * Copyright (C) 2019-2021 Microchip Technology Inc.
 */
#include <net/dsa.h>
#include <net/switchdev.h>
#include "ksz_common.h"
#include "lan937x_reg.h"
#include "lan937x_dev.h"
#include "lan937x_tc.h"
#include "lan937x_flower.h"
#include "lan937x_acl.h"

const u8 parser_key_format[MAX_ACL_PARSER] = {
	[PARSER_IDX_0] = PARSER_MULTI_KEY_FORMAT,
	[PARSER_IDX_1] = PARSER_UNIVERSAL_FORMAT,
	[PARSER_IDX_2] = PARSER_MULTI_KEY_FORMAT,
	[PARSER_IDX_3] = PARSER_UNIVERSAL_FORMAT
};

const struct lan937x_acl_rfr acl_rfrs_table[MAX_ACL_PARSER][MAX_RFR] = {
	[PARSER_IDX_0] = {
		[RFR_IDX_0] = {
			.dissectors_covered = DST_MAC_DISSECTOR_PRESENT,
			.layer = l2,
			.ofst = 0,
			.len = 6,
			.rng_match_en = false,
		},
		[RFR_IDX_1] = {
			.dissectors_covered = SRC_MAC_DISSECTOR_PRESENT,
			.layer = l2,
			.ofst = 6,
			.len = 6,
			.rng_match_en = false,
		},
		[RFR_IDX_2] = {
			.dissectors_covered = ETHTYPE_DISSECTOR_PRESENT,
			.layer = l2,
			.ofst = 12,
			.len = 2,
			.rng_match_en = false,
		},
		[RFR_IDX_3] = {
			.dissectors_covered = IPV4_TOS_DISSECTOR_PRESENT,
			.layer = l3,
			.ofst = 0,
			.len = 4,
			.rng_match_en = false,
		},
		[RFR_IDX_4] = {
			.dissectors_covered = (IPV4_TTL_DISSECTOR_PRESENT |
					       IPV4_PROTO_DISSECTOR_PRESENT),
			.layer = l3,
			.ofst = 8,
			.len = 4,
			.rng_match_en = false,
		},
		[RFR_IDX_5] = {
			.dissectors_covered = (IPV4_SRC_IP_DISSECTOR_PRESENT),
			.layer = l3,
			.ofst = 12,
			.len = 4,
			.rng_match_en = false,
		},
		[RFR_IDX_6] = {
			.dissectors_covered = (IPV4_DST_IP_DISSECTOR_PRESENT),
			.layer = l3,
			.ofst = 16,
			.len = 4,
			.rng_match_en = false,
		},
		[RFR_IDX_7] = {
			.dissectors_covered = (L4_SRC_PORT_DISSECTOR_PRESENT),
			.layer = l4,
			.ofst = 0,
			.len = 2,
			.rng_match_en = false,
		},
		[RFR_IDX_8] = {
			.dissectors_covered = (L4_DST_PORT_DISSECTOR_PRESENT),
			.layer = l4,
			.ofst = 2,
			.len = 2,
			.rng_match_en = false,
		},
		[RFR_IDX_9] = {
			.dissectors_covered = 0,
		},
	},
	[PARSER_IDX_1] = {
		[RFR_IDX_0] = {
			.dissectors_covered = IPV6_TC_DISSECTOR_PRESENT,
			.layer = l3,
			.ofst = 0,
			.len = 4,
			.rng_match_en = false,
		},
		[RFR_IDX_1] = {
			.dissectors_covered = (IPV6_HOP_DISSECTOR_PRESENT |
					       IPV6_NXTHDR_DISSECTOR_PRESENT),
			.layer = l3,
			.ofst = 4,
			.len = 4,
			.rng_match_en = false,
		},
		[RFR_IDX_2] = {
			.dissectors_covered = (IPV6_SRC_IP_DISSECTOR_PRESENT),
			.layer = l3,
			.ofst = 8,
			.len = 16,
			.rng_match_en = false,
		},
		[RFR_IDX_3] = {
			.dissectors_covered = (IPV6_DST_IP_DISSECTOR_PRESENT),
			.layer = l3,
			.ofst = 24,
			.len = 16,
			.rng_match_en = false,
		},
		[RFR_IDX_4] = {
			.dissectors_covered = 0,
		},
		[RFR_IDX_5] = {
			.dissectors_covered = 0,
		},
		[RFR_IDX_6] = {
			.dissectors_covered = 0,
		},
		[RFR_IDX_7] = {
			.dissectors_covered = 0,
		},
		[RFR_IDX_8] = {
			.dissectors_covered = 0,
		},
		[RFR_IDX_9] = {
			.dissectors_covered = 0,
		},
	},
	[PARSER_IDX_2] = {
		[RFR_IDX_0] = {
			.dissectors_covered = DST_MAC_DISSECTOR_PRESENT,
			.layer = l2,
			.ofst = 0,
			.len = 6,
			.rng_match_en = false,
		},
		[RFR_IDX_1] = {
			.dissectors_covered = SRC_MAC_DISSECTOR_PRESENT,
			.layer = l2,
			.ofst = 6,
			.len = 6,
			.rng_match_en = false,
		},
		[RFR_IDX_2] = {
			.dissectors_covered = VLAN_TAG_DISSECTORS_PRESENT,
			.layer = l2,
			.ofst = 12,
			.len = 4,
			.rng_match_en = false,
		},
		[RFR_IDX_3] = {
			.dissectors_covered = ETHTYPE_DISSECTOR_PRESENT,
			.layer = l2,
			.ofst = 12 + sizeof(struct vlan_tag),
			.len = 2,
			.rng_match_en = false,
		},
		[RFR_IDX_4] = {
			.dissectors_covered = IPV4_TOS_DISSECTOR_PRESENT,
			.layer = l3,
			.ofst = 0 + sizeof(struct vlan_tag),
			.len = 4,
			.rng_match_en = false,
		},
		[RFR_IDX_5] = {
			.dissectors_covered = (IPV4_TTL_DISSECTOR_PRESENT |
					       IPV4_PROTO_DISSECTOR_PRESENT),
			.layer = l3,
			.ofst = 8 + sizeof(struct vlan_tag),
			.len = 4,
			.rng_match_en = false,
		},
		[RFR_IDX_6] = {
			.dissectors_covered = (IPV4_SRC_IP_DISSECTOR_PRESENT),
			.layer = l3,
			.ofst = 12 + sizeof(struct vlan_tag),
			.len = 4,
			.rng_match_en = false,
		},
		[RFR_IDX_7] = {
			.dissectors_covered = (IPV4_DST_IP_DISSECTOR_PRESENT),
			.layer = l3,
			.ofst = 16 + sizeof(struct vlan_tag),
			.len = 4,
			.rng_match_en = false,
		},
		[RFR_IDX_8] = {
			.dissectors_covered = (L4_SRC_PORT_DISSECTOR_PRESENT),
			.layer = l4,
			.ofst = 0 + sizeof(struct vlan_tag),
			.len = 2,
			.rng_match_en = false,
		},
		[RFR_IDX_9] = {
			.dissectors_covered = (L4_DST_PORT_DISSECTOR_PRESENT),
			.layer = l4,
			.ofst = 2 + sizeof(struct vlan_tag),
			.len = 2,
			.rng_match_en = false,
		},
	},
	[PARSER_IDX_3] = {
		[RFR_IDX_0] = {
			.dissectors_covered = IPV6_TC_DISSECTOR_PRESENT,
			.layer = l3,
			.ofst = 0,
			.len = 4,
			.rng_match_en = false,
		},
		[RFR_IDX_1] = {
			.dissectors_covered = (IPV6_HOP_DISSECTOR_PRESENT |
					       IPV6_NXTHDR_DISSECTOR_PRESENT),
			.layer = l3,
			.ofst = 4,
			.len = 4,
			.rng_match_en = false,
		},
		[RFR_IDX_2] = {
			.dissectors_covered = (IPV6_SRC_IP_DISSECTOR_PRESENT),
			.layer = l3,
			.ofst = 8,
			.len = 16,
			.rng_match_en = false,
		},
		[RFR_IDX_3] = {
			.dissectors_covered = (IPV6_DST_IP_DISSECTOR_PRESENT),
			.layer = l3,
			.ofst = 24,
			.len = 16,
			.rng_match_en = false,
		},
		[RFR_IDX_4] = {
			.dissectors_covered = 0,
		},
		[RFR_IDX_5] = {
			.dissectors_covered = 0,
		},
		[RFR_IDX_6] = {
			.dissectors_covered = 0,
		},
		[RFR_IDX_7] = {
			.dissectors_covered = 0,
		},
		[RFR_IDX_8] = {
			.dissectors_covered = 0,
		},
		[RFR_IDX_9] = {
			.dissectors_covered = 0,
		},
	}
};

int lan937x_get_acl_req(enum lan937x_filter_type type,
			u8 *parser_idx, u8 *n_entries)
{
	switch (type) {
	case LAN937x_VLAN_UNAWARE_FILTER:
		*parser_idx = 0;
		*n_entries = 2;
		break;
	case LAN937x_VLAN_AWARE_FILTER:
		*parser_idx = 2;
		*n_entries = 2; 
		break;
	case LAN937x_BCAST_FILTER:
	default:
		return -EINVAL;
	}

	return 0;
}

static int lan937x_wait_tcam_busy(struct ksz_device *dev, int port)
{
	unsigned int val;

	return regmap_read_poll_timeout(dev->regmap[2],
				      PORT_CTRL_ADDR(port, REG_ACL_PORT_ARACR),
				      val,
				      val & ACL_ARACR_TCAM_OP_STS,
				      10,
				      10000);
}

static int lan937x_set_acl_access_ctl(struct ksz_device *dev,
				      int port,
				      struct lan937x_acl_access_ctl *acc_ctl)
{
	u32 val;
	int rc;
	
	rc = lan937x_wait_tcam_busy(dev, port);
	if (rc)
		return rc;

	val = acl_acc_ctl(acc_ctl);

	rc = lan937x_pwrite32(dev, port, REG_ACL_PORT_ARACR, val);
	if (rc)
		return rc;

	rc = lan937x_wait_tcam_busy(dev, port);
	return rc;
}

static int lan937x_acl_entry_write(struct ksz_device *dev,
				   u8 port, u8 entry_idx,
				   struct lan937x_acl_entry *acl_entry)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	struct lan937x_acl_access_ctl access_ctl;
	struct lan937x_acl_byte_en byte_en_cfg;
	int rc;

	rc = lan937x_wait_tcam_busy(dev, port);
	if (rc)
		return rc;

	/* Write TCAM mask in ADR */
	rc = lan937x_pwrite8_bulk(dev, port, REG_ACL_PORT_ADR,
				  &acl_entry->acl_mask[0],
				  MAX_ACL_DATA_MASK_SIZE);
	if (rc)
		return rc;

	/* Write TCAM Data in ADR */
	rc = lan937x_pwrite8_bulk(dev, port,
				  REG_ACL_PORT_ADR + MAX_ACL_DATA_MASK_SIZE,
				  &acl_entry->acl_data[0],
				  MAX_ACL_DATA_MASK_SIZE);
	if (rc)
		return rc;

	/* Write AAR */
	rc = lan937x_pwrite8_bulk(dev, port, REG_ACL_PORT_AAR,
				  &acl_entry->acl_action[0],
				  MAX_ACL_ACTION_SIZE);
	if (rc)
		return rc;

	/* Each bit of this BYTE_EN register defines which
	 * bytes in ADR & AAR are writable
	 */
	memset(&byte_en_cfg, 0xFF, sizeof(byte_en_cfg));
	rc = lan937x_pwrite8_bulk(dev, port, REG_ACL_PORT_ABER,
				  &byte_en_cfg.acl_mask[0],
				  sizeof(byte_en_cfg));
	if (rc)
		return rc;

	/* HW workaround for ACL write */
	rc = lan937x_pwrite16(dev, port, 0x66C, 0xFFFF);
	if (rc)
		return rc;

	/* HW workaround for ACL write */
	rc = lan937x_pwrite16(dev, port, 0x672, 0xFFFF);
	if (rc)
		return rc;

	/* Clear data in access_ctl */
	clr_data(access_ctl);

	/* Set TCAM Control Register for TCAM Entry Write */
	set_tcam_addr(access_ctl, entry_idx);
	set_pri_low(access_ctl, true);
	set_tcam_vben(access_ctl, true);
	set_tcam_vbi(access_ctl, true);
	set_tcam_row_vld(access_ctl, 0x0F);
	set_tcam_req(access_ctl, TCAM_REQ_TYPE_WRITE_TCAM);
	set_tcam_acc(access_ctl, TCAM_MASK_DATA);

	/* Write ACL register */
	rc = lan937x_set_acl_access_ctl(dev,
					port, &access_ctl);
	if (rc)
		return rc;
	
	res->tcam_entries_used[entry_idx] = true;

	return rc;
}

static void lan937x_cpy_array_to_entry(u8 *s_data, u8 *s_mask,
				       struct lan937x_acl_entry *acl_entry,
				       u8 offset,
				       u8 n)
{
	u8 *d_mask = &acl_entry->acl_mask[offset];
	u8 *d_data = &acl_entry->acl_data[offset];
	u8 i;

	for (i = 0; i < n; i++) {
		/* Apply mask to data given from the rule */
		s_data[i] &= s_mask[i];

		/* As per datasheet, TCAM mask should be inverted of data
		 * for strict match
		 */
		s_mask[i] &= (~s_data[i]);

		/* Copy Mask & Data to TCAM Entry */
		d_mask[i] = s_mask[i];
		d_data[i] = s_data[i];
	}
}

static void lan937x_cpy_ethaddr_to_entry(struct lan937x_val_mask_u64 *ethaddr,
					 struct lan937x_acl_entry *acl_entry,
					 u8 offset)
{
	u64 tdata = ethaddr->value;
	u64 tmask = ethaddr->mask;

	/* Apply mask to data given from the rule */
	tdata &= tmask;

	/* As per datasheet, TCAM mask should be inverted of data
	 * for strict match
	 */
	tmask &= (~tdata);

	/* Copy Mask & Data to TCAM Entry */
	u64_to_ether_addr(tmask, &acl_entry->acl_mask[offset]);
	u64_to_ether_addr(tdata, &acl_entry->acl_data[offset]);
}

static void lan937x_cpy_u8_to_entry(struct lan937x_val_mask_u8 *field,
				    struct lan937x_acl_entry *acl_entry,
				    u8 offset)
{
	u8 tdata = field->value;
	u8 tmask = field->mask;

	/* Apply mask to data given from the rule */
	tdata &= tmask;

	/* As per datasheet, TCAM mask should be inverted of data
	 * for strict match
	 */
	tmask &= (~tdata);

	/* Copy Mask & Data to TCAM Entry */
	acl_entry->acl_mask[offset] |= (tmask);
	acl_entry->acl_data[offset] |= (tdata);
}

static void lan937x_cpy_u16_to_entry(struct lan937x_val_mask_u16 *field,
				     struct lan937x_acl_entry *acl_entry,
				     u8 offset)
{
	u16 tdata = cpu_to_be16(field->value);
	u16 tmask = cpu_to_be16(field->mask);

	/* Apply mask to data given from the rule */
	tdata &= tmask;

	/* As per datasheet, TCAM mask should be inverted of data
	 * for strict match
	 */
	tmask &= (~tdata);

	acl_entry->acl_mask[offset + 1] |= ((tmask & 0xFF00) >> 8);
	acl_entry->acl_mask[offset] |= (tmask & 0x00FF);
	acl_entry->acl_data[offset + 1] |= (tdata & 0xFF00) >> 8;
	acl_entry->acl_data[offset] |= (tdata & 0x00FF);
}

static int lan937x_acl_fill_entry(struct ksz_device *dev,
				  int port, u8 parser_idx,
				  enum lan937x_acl_dissector_type disctr,
				  struct lan937x_key *key,
				  struct lan937x_acl_entry *acl_entry)
{
	const struct lan937x_acl_rfr *rfr_ptr = acl_rfrs_table[parser_idx];
	u8 *acl_mask = acl_entry->acl_mask;
	u8 *acl_data = acl_entry->acl_data;
	u8 ofst = 0;
	int i;

	if (parser_key_format[parser_idx] == PARSER_MULTI_KEY_FORMAT)
		ofst += TCAM_MULTI_KEY_ENTRY_START;

	for (i = 0; i < MAX_RFR_PER_PARSER; i++) {
		/* No more valid RFRs in Parser */
		if (!rfr_ptr[i].dissectors_covered)
			break; 

		if (!(rfr_ptr[i].dissectors_covered & BIT(disctr))) {
			/* Accumulate the length of all previous RFRs till 
			 * the intended RFR which carries the intended
			 * dissector. Accumulated offset is finally used as the
			 * offset in TCAM entry to fill TCAM data
			 */
			ofst += rfr_ptr[i].len;
			continue;
		}

		switch (disctr) {
		case acl_dst_mac_dissector:
			lan937x_cpy_ethaddr_to_entry(&key->dst_mac,
							acl_entry,
							ofst);
			break;
		case acl_src_mac_dissector:
			lan937x_cpy_ethaddr_to_entry(&key->src_mac,
							acl_entry,
							ofst);
			break;
		case acl_vlan_id_dissector: {
			u16 tdata = cpu_to_be16(key->vlan_id.value);
			u16 tmask = cpu_to_be16(key->vlan_id.mask);

			tdata &= tmask;
			tmask &= (~tdata);

			acl_mask[ofst + 2] |= (tmask & 0x0F);
			acl_mask[ofst + 3] |= (tmask & 0xFF00) >> 8;
			acl_data[ofst + 2] |= (tdata & 0x0F);
			acl_data[ofst + 3] |= (tdata & 0xFF00) >> 8;
			break;
		}
		case acl_vlan_pcp_dissector: {
			u16 tdata = key->vlan_prio.value;
			u16 tmask = key->vlan_prio.mask;

			tdata &= tmask;
			tmask &= (~tdata);

			acl_mask[ofst + 2] |= (tmask & 0x07) << 5;
			acl_data[ofst + 2] |= (tdata & 0x07) << 5;
			break;
		}
		case acl_ethtype_dissector:
			lan937x_cpy_u16_to_entry(&key->ethtype,
						 acl_entry,
						 ofst);
			break;
		case acl_ipv4_tos_dissector: {
			/* IPV4 TOS starts at offset 1 byte from RFR start */
			lan937x_cpy_u8_to_entry(&key->ipv4.tos,
						acl_entry,
						ofst + 1);				
			break;
		}
		case acl_ipv4_ttl_dissector: {
			lan937x_cpy_u8_to_entry(&key->ipv4.ttl,
						acl_entry,
						ofst);				
			break;
		}
		case acl_ipv4_protocol_dissector: {
			/* IPV4 proto starts at offset 1 byte from RFR start */
			lan937x_cpy_u8_to_entry(&key->ipv4.proto,
						acl_entry,
						ofst + 1);					
			break;
		}
		case acl_ipv4_src_ip_dissector: {
			lan937x_cpy_array_to_entry(key->ipv4.sip.value,
						   key->ipv4.sip.mask, 
						   acl_entry,
						   ofst, 0x04);
			break;
		}
		case acl_ipv4_dst_ip_dissector: {
			lan937x_cpy_array_to_entry(key->ipv4.dip.value,
						   key->ipv4.dip.mask, 
						   acl_entry,
						   ofst, 0x04);
			break;
		}
		case acl_ipv6_tc_dissector: {
			u8 tdata = key->ipv6.tc.value;
			u8 tmask = key->ipv6.tc.mask;

			tdata &= tmask;
			tmask &= (~tdata);

			acl_mask[ofst]	|= ((tmask & 0xF0) >> 0x04);
			acl_data[ofst]	|= ((tdata & 0xF0) >> 0x04);
			acl_mask[ofst + 1] |= ((tmask & 0x0F) << 0x04);
			acl_data[ofst + 1] |= ((tdata & 0x0F) << 0x04);
			break;
		}
		case acl_ipv6_nxt_hdr_dissector: {
			/* IPV6 next header starts at offset 2 byte from RFR
			 * start
			 */
			lan937x_cpy_u8_to_entry(&key->ipv6.next_hdr,
						acl_entry,
						ofst + 2);				
			break;
		}
		case acl_ipv6_hop_dissector: {
			/* IPV6 hop starts at offset 3 byte from RFR start */
			lan937x_cpy_u8_to_entry(&key->ipv6.hop,
						acl_entry,
						ofst + 3);				
			break;
		}
		case acl_ipv6_src_ip_dissector: {
			lan937x_cpy_array_to_entry(key->ipv6.sip.value,
						   key->ipv6.sip.mask,
						   acl_entry,
						   ofst, 16);
			break;
		}
		case acl_ipv6_dst_ip_dissector: {
			lan937x_cpy_array_to_entry(key->ipv6.dip.value,
						   key->ipv6.dip.mask, 
						   acl_entry,
						   ofst, 16);
			break;
		}
		case acl_l4_src_port_dissector: {
			lan937x_cpy_u16_to_entry(&key->src_port,
						 acl_entry,
						 ofst);				
			break;
		}
		case acl_l4_dst_port_dissector: {
			lan937x_cpy_u16_to_entry(&key->dst_port,
						 acl_entry,
						 ofst);
			break;
		}
		default:
			break;
		} /*switch ends*/

		return 0;
	}

	return -EINVAL;
}

int lan937x_acl_program_entry(struct ksz_device *dev, int port,
			      struct lan937x_flower_rule *rule)
{
	struct lan937x_flower_action *action = &rule->flower->action;
	u32 actions_presence_mask = action->actions_presence_mask;
	struct lan937x_key *key = &rule->flower->filter.key;
	struct lan937x_resrc_alloc *resrc = rule->resrc;
	u32 acl_dissector_map = key->acl_dissector_map;
	u8 n_entries = resrc->type.tcam.n_entries;
	u8 parser = resrc->type.tcam.parser;
	struct lan937x_acl_entry *acl_entry;
	int rc = EINVAL;
	u8 *acl_action;
	u8 i, j;

	acl_entry = devm_kzalloc(dev->dev, sizeof(*acl_entry) * n_entries,
				 GFP_KERNEL);

	if (!acl_entry)
		return -ENOSPC;

	for (i = 0; ((acl_dissector_map != 0) &&
		     (i < LAN937X_NUM_DISSECTORS_SUPPORTED)); i++) {
		if (!(acl_dissector_map & BIT(i)))
			continue;

		acl_dissector_map &= ~BIT(i);

		for (j = 0; j < n_entries; j++) {
			rc = lan937x_acl_fill_entry(dev, port, parser + j,
						    i, key, &acl_entry[j]);
			if (!rc)
				break;
		}
		if (rc)
			goto out;
	}

	for (i = 0; ((actions_presence_mask != 0) &&
		     (i < LAN937X_NUM_ACTIONS_SUPPORTED)); i++) {
		if (!(actions_presence_mask & BIT(i)))
			continue;

		actions_presence_mask &= ~BIT(i);

		/* Only use the first entry to fill the action */
		acl_action = acl_entry[0].acl_action;

		switch (i) {
		case LAN937X_ACT_REDIRECT_FLOW:
			set_map_mode(acl_action, MM_REPLACE_FWD_LKUP_TABLE);
			set_dst_port(acl_action, action->redirect_port_mask);
			break;
		case LAN937X_ACT_STREAM_POLICE:
		case LAN937X_ACT_STREAM_GATE:
			set_strm_en(acl_action, resrc->type.strm_flt.en);
			set_strm_id(acl_action,resrc->type.strm_flt.index);
			break;
		case LAN937X_ACT_DROP:
			set_map_mode(acl_action, MM_REPLACE_FWD_LKUP_TABLE);
			/* Donot forward to any valid port */
			set_dst_port(acl_action, 0x00);
			break;
		case LAN937X_ACT_PRIORITY:
			set_que_en(acl_action);
			set_que_sel(acl_action, action->skbedit_prio);
			break;
		default:
			rc = -EINVAL;
			goto out;
		}
	}
	if (resrc->type.tcam.cntr != STATS_COUNTER_NOT_ASSIGNED)
		set_fr_counter(acl_action, resrc->type.tcam.cntr);

	/* For Multiple format Key
	 * Bit 383:382 PARSER_NUM Programmed to the 1st parser used TCAM rule
	 */
	if (parser_key_format[parser] == PARSER_MULTI_KEY_FORMAT) {
		acl_entry[0].acl_mask[0] |= ((~parser) << 6);
		acl_entry[0].acl_data[0] |= (parser << 6);
	}

	for (j = 0; j < n_entries; j++) {
		rc = lan937x_acl_entry_write(dev, port,
					     resrc->type.tcam.index + j,
					     &acl_entry[j]);
		if (rc)
			break;
	}

out:
	devm_kfree(dev->dev, acl_entry);
	return rc;
}

static int lan937x_set_rfr_entry(struct ksz_device *dev, int port,
				 u8 parser_idx, u8 rfr_idx,
				 const struct lan937x_acl_rfr *rfr_entry)
{
	struct lan937x_rfr_reg_type rfr_data;
	u8 tcam_addr_access;
	u16 reg_ofst;
	int rc;

	tcam_addr_access = parser_idx % 2;

	reg_ofst = ACL_CTRL_BASE_ADDR + (rfr_idx * MAX_RFR_SIZE) +
		   (tcam_addr_access * MAX_RFR_SIZE * MAX_RFR_PER_PARSER);

	if (!(rfr_entry->dissectors_covered)) {
		/*Ensure unused RFRs arent filled with junk*/
		rfr_data.u32value = 0x00000000;
		goto pgm;
	}

	rfr_data.u32value = (RFR_OSFT_L4_RELATV(rfr_entry->layer == l4) |
			     RFR_OSFT_L3_RELATV(rfr_entry->layer == l3) |
			     RFR_OSFT_L2_RELATV(rfr_entry->layer == l2));
	rfr_data.u32value |= RFR_OFST(rfr_entry->ofst);
	rfr_data.u32value |= RFR_LENGTH(rfr_entry->len);
	rfr_data.u32value |= RFR_RNG_MATCH_EN(rfr_entry->rng_match_en);
	rfr_data.u32value |= RFR_RNG_OSFT(rfr_entry->rng_ofst);

pgm:
	rc = lan937x_pwrite32(dev, port, reg_ofst, rfr_data.u32value);

	return rc;
}

static int lan937x_program_rfrs(struct ksz_device *dev,
				int port)
{
	struct lan937x_acl_access_ctl access_ctl;
	const struct lan937x_acl_rfr *rfr_entry;
	int parser_idx, rfr_idx;
	int count = 0;
	int rc;

	for (parser_idx = 0; parser_idx < MAX_ACL_PARSERS; parser_idx++) {
		for (rfr_idx = 0; rfr_idx < MAX_RFR_PER_PARSER; rfr_idx++) {
			rfr_entry = &acl_rfrs_table[parser_idx][rfr_idx];
			rc = lan937x_set_rfr_entry(dev, port, parser_idx,
						   rfr_idx, rfr_entry);
			if (rc)
				return rc;
		}

		/* Increament the parser count */
		count++;

		/* At once Rule Format regs for 2 Parsers are programmable */
		if (count != (MAX_PARSER_PER_ENTRY))
			continue;

		/* Restart the parser counter */
		count = 0;

		clr_data(access_ctl);

		if (parser_idx < MAX_PARSER_PER_ENTRY)
			set_tcam_addr(access_ctl, TCAM_PARSER_0_1);
		else
			set_tcam_addr(access_ctl, TCAM_PARSER_2_3);

		set_tcam_vben(access_ctl, true);
		set_tcam_vbi(access_ctl, true);
		set_tcam_row_vld(access_ctl, 0x0F);
		set_tcam_req(access_ctl, TCAM_REQ_TYPE_WRITE_RFR);
		set_tcam_acc(access_ctl, TCAM_MASK_DATA);

		rc = lan937x_set_acl_access_ctl(dev, port, &access_ctl);
		if (rc)
			return rc;
	}

	return rc;
}

int lan937x_init_acl_parsers(struct ksz_device *dev, int port)
{
	int rc;

	rc = lan937x_program_rfrs(dev, port);
	if (rc)
		return rc;

	rc = lan937x_pwrite32(dev, port, REG_ACL_PORT_PCTRL,
			      (PCTRL_TWO_FORMAT_TWO_PARSER_EACH |
			       PCTRL_KEY2_VLAN_TAG_EN	|
			       PCTRL_KEYTYPE0_MULTI_FMT |
			       PCTRL_KEYTYPE2_MULTI_FMT));
	if (rc)
		return rc;

	rc = lan937x_pwrite8(dev, port, REG_PORT_RX_AUTH_CTL,
			     (AUTH_CTL_ACL_PASS_MODE | AUTH_CTL_ACL_ENABLE));

	return rc;
}

int lan937x_acl_free_entry(struct ksz_device *dev, int port,
			   struct lan937x_flower_rule *rule)
{
	struct lan937x_resrc_alloc *resrc = rule->resrc;
	u8 n_entries = resrc->type.tcam.n_entries;
	struct lan937x_acl_access_ctl access_ctl;
	bool last_entry;
	u8 i, row;
	int rc;

	/* Nothing to delete */
	if (!n_entries)
		return 0; 
		
	/* Shift all the TCAM Entries that are below the current entry upwards 
	 * by n_entries time to over write the current rule 
	 */
	clr_data(access_ctl);

	/* Assign the first entry index */
	set_row_shift(access_ctl, (n_entries + resrc->type.tcam.index));

	/* Identify the row where the Last Entry is present*/
	rc = lan937x_assign_tcam_entries(dev, port, 0x01,
					 &access_ctl.tcam_addr);
	if (rc == -ENOSPC){
		set_tcam_addr(access_ctl, LAN937X_NUM_TCAM_ENTRIES);
		last_entry = true;
	}

	if ((access_ctl.row_shift == access_ctl.tcam_addr) ||
	    last_entry == true) {
		/* There are no valid entries below the current
		 * rule under deletion. So No shifting is necessary
		 */
		set_pri_low(access_ctl, true);
		set_tcam_vben(access_ctl, true);
		set_tcam_vbi(access_ctl, false);
		set_tcam_row_vld(access_ctl, 0x0F);
		set_num_shift(access_ctl, (n_entries - 1));
		set_tcam_req(access_ctl, TCAM_REQ_TYPE_SHIFT_TCAM);
		set_tcam_acc(access_ctl, TCAM_MASK_DATA);

		rc = lan937x_set_acl_access_ctl(dev, port, &access_ctl);
		if (rc)
			return rc;
	}

	/* After shifting upward, invalidate the very last n_entries.
	 * If last_entry is true then shifting will not happen, but the last
	 * n_entries will be invalidated, which will decommision the rule
	 * */
	row = access_ctl.tcam_addr;
	for (i = (row - 1); i > (row - n_entries); i--) {
		clr_data(access_ctl);

		set_tcam_addr(access_ctl, i);
		set_pri_low(access_ctl, true);
		set_tcam_vben(access_ctl, true);
		/*vbi - 0: makes TCAM entry invalid.*/
		set_tcam_vbi(access_ctl, false);
		set_tcam_row_vld(access_ctl, 0x0F);
		set_tcam_req(access_ctl, TCAM_REQ_TYPE_WRITE_TCAM);
		set_tcam_acc(access_ctl, TCAM_MASK_DATA);

		rc = lan937x_set_acl_access_ctl(dev, port, &access_ctl);
		if (rc)
			return rc;
	}

	/* Deleted rule no longer has any tcam entries */
	resrc->type.tcam.n_entries = 0x00;

	return rc;
}

static int lan937x_program_kivr(struct ksz_device *dev,
				int port)
{
	/* 1) RFRs says what value of the field it covers is invalid
	 *    and can be safely put in the KIVR
	 *    e.g. IPV4 protocol value 0xFF is Reserved.
	 * 2) when range matching is involved then a value that is not
	 *    within that range is required.
	 * To Be Implemented when required..
	 */
	return 0;
}

irqreturn_t lan937x_acl_isr(struct ksz_device *dev, int port)
{
	struct lan937x_p_res *res = lan937x_get_flr_res(dev, port);
	u8 intsts;
	int ret;

	ret = lan937x_pread8(dev, port, REG_ACL_PORT_INT_STS, &intsts);
	if (ret)
		return IRQ_NONE;
	
	if (intsts & ACL_FR_COUNT_OVR0) {
		res->tcam_match_cntr_bkup[0] += ACL_FR_COUNT_MAX_VALUE;
		res->tcam_match_cntr_bkup[0] &= ~((u64)ACL_FR_COUNT_MAX_VALUE);
	}
	if (intsts & ACL_FR_COUNT_OVR1) {
		res->tcam_match_cntr_bkup[1] += ACL_FR_COUNT_MAX_VALUE;
		res->tcam_match_cntr_bkup[1] &= ~((u64)ACL_FR_COUNT_MAX_VALUE);
	}
	if (intsts & ACL_FR_COUNT_OVR2) {
		res->tcam_match_cntr_bkup[2] += ACL_FR_COUNT_MAX_VALUE;
		res->tcam_match_cntr_bkup[2] &= ~((u64)ACL_FR_COUNT_MAX_VALUE);
	}
	if (intsts & ACL_FR_COUNT_OVR3) {
		res->tcam_match_cntr_bkup[3] += ACL_FR_COUNT_MAX_VALUE;
		res->tcam_match_cntr_bkup[3] &= ~((u64)ACL_FR_COUNT_MAX_VALUE);
	}

	ret =  lan937x_pwrite8(dev, port, REG_ACL_PORT_INT_STS, intsts);
	if (ret)
		return IRQ_NONE;

	return IRQ_HANDLED;
}
