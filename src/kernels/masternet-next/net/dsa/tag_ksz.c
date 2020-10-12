// SPDX-License-Identifier: GPL-2.0+
/*
 * net/dsa/tag_ksz.c - Microchip KSZ Switch tag format handling
 * Copyright (c) 2017 Microchip Technology
 */

#include <linux/etherdevice.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <../drivers/net/dsa/microchip/ksz_common.h>
#include <net/dsa.h>
#include "dsa_priv.h"

/* Typically only one byte is used for tail tag. */
#define KSZ_EGRESS_TAG_LEN		1
#define KSZ_INGRESS_TAG_LEN		1

static struct sk_buff *ksz_common_xmit(struct sk_buff *skb,
				       struct net_device *dev, int len)
{
	struct sk_buff *nskb;
	int padlen;

	padlen = (skb->len >= ETH_ZLEN) ? 0 : ETH_ZLEN - skb->len;

	if (skb_tailroom(skb) >= padlen + len) {
		/* Let dsa_slave_xmit() free skb */
		if (__skb_put_padto(skb, skb->len + padlen, false))
			return NULL;

		nskb = skb;
	} else {
		nskb = alloc_skb(NET_IP_ALIGN + skb->len +
				 padlen + len, GFP_ATOMIC);
		if (!nskb)
			return NULL;
		skb_reserve(nskb, NET_IP_ALIGN);

		skb_reset_mac_header(nskb);
		skb_set_network_header(nskb,
				       skb_network_header(skb) - skb->head);
		skb_set_transport_header(nskb,
					 skb_transport_header(skb) - skb->head);
		skb_copy_and_csum_dev(skb, skb_put(nskb, skb->len));

		/* Let skb_put_padto() free nskb, and let dsa_slave_xmit() free
		 * skb
		 */
		if (skb_put_padto(nskb, nskb->len + padlen))
			return NULL;

		consume_skb(skb);
	}

	return nskb;
}

static struct sk_buff *ksz_common_rcv(struct sk_buff *skb,
				      struct net_device *dev,
				      unsigned int port, unsigned int len)
{
	skb->dev = dsa_master_find_slave(dev, 0, port);
	if (!skb->dev)
		return NULL;

	pskb_trim_rcsum(skb, skb->len - len);

	skb->offload_fwd_mark = true;

	return skb;
}

/*
 * For Ingress (Host -> KSZ8795), 1 byte is added before FCS.
 * ---------------------------------------------------------------------------
 * DA(6bytes)|SA(6bytes)|....|Data(nbytes)|tag(1byte)|FCS(4bytes)
 * ---------------------------------------------------------------------------
 * tag : each bit represents port (eg, 0x01=port1, 0x02=port2, 0x10=port5)
 *
 * For Egress (KSZ8795 -> Host), 1 byte is added before FCS.
 * ---------------------------------------------------------------------------
 * DA(6bytes)|SA(6bytes)|....|Data(nbytes)|tag0(1byte)|FCS(4bytes)
 * ---------------------------------------------------------------------------
 * tag0 : zero-based value represents port
 *	  (eg, 0x00=port1, 0x02=port3, 0x06=port7)
 */

#define KSZ8795_TAIL_TAG_OVERRIDE	BIT(6)
#define KSZ8795_TAIL_TAG_LOOKUP		BIT(7)

static struct sk_buff *ksz8795_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct dsa_port *dp = dsa_slave_to_port(dev);
	struct sk_buff *nskb;
	u8 *tag;
	u8 *addr;

	nskb = ksz_common_xmit(skb, dev, KSZ_INGRESS_TAG_LEN);
	if (!nskb)
		return NULL;

	/* Tag encoding */
	tag = skb_put(nskb, KSZ_INGRESS_TAG_LEN);
	addr = skb_mac_header(nskb);

	*tag = 1 << dp->index;
	if (is_link_local_ether_addr(addr))
		*tag |= KSZ8795_TAIL_TAG_OVERRIDE;

	return nskb;
}

static struct sk_buff *ksz8795_rcv(struct sk_buff *skb, struct net_device *dev,
				  struct packet_type *pt)
{
	u8 *tag = skb_tail_pointer(skb) - KSZ_EGRESS_TAG_LEN;

	return ksz_common_rcv(skb, dev, tag[0] & 7, KSZ_EGRESS_TAG_LEN);
}

static const struct dsa_device_ops ksz8795_netdev_ops = {
	.name	= "ksz8795",
	.proto	= DSA_TAG_PROTO_KSZ8795,
	.xmit	= ksz8795_xmit,
	.rcv	= ksz8795_rcv,
	.overhead = KSZ_INGRESS_TAG_LEN,
};

DSA_TAG_DRIVER(ksz8795_netdev_ops);
MODULE_ALIAS_DSA_TAG_DRIVER(DSA_TAG_PROTO_KSZ8795);

/*
 * For Ingress (Host -> KSZ9477), 2 bytes are added before FCS.
 * ---------------------------------------------------------------------------
 * DA(6bytes)|SA(6bytes)|....|Data(nbytes)|tag0(1byte)|tag1(1byte)|FCS(4bytes)
 * ---------------------------------------------------------------------------
 * tag0 : Prioritization (not used now)
 * tag1 : each bit represents port (eg, 0x01=port1, 0x02=port2, 0x10=port5)
 *
 * For Egress (KSZ9477 -> Host), 1 byte is added before FCS.
 * ---------------------------------------------------------------------------
 * DA(6bytes)|SA(6bytes)|....|Data(nbytes)|tag0(1byte)|FCS(4bytes)
 * ---------------------------------------------------------------------------
 * tag0 : zero-based value represents port
 *	  (eg, 0x00=port1, 0x02=port3, 0x06=port7)
 */

#define KSZ9477_INGRESS_TAG_LEN		2
#define KSZ9477_PTP_TAG_LEN		4
#define KSZ9477_PTP_TAG_INDICATION	0x80

#define KSZ9477_TAIL_TAG_OVERRIDE	BIT(9)
#define KSZ9477_TAIL_TAG_LOOKUP		BIT(10)

static struct sk_buff *ksz9477_xmit(struct sk_buff *skb,
				    struct net_device *dev)
{
	struct dsa_port *dp = dsa_slave_to_port(dev);
	struct sk_buff *nskb;
	__be16 *tag;
	u8 *addr;
	u16 val;

	nskb = ksz_common_xmit(skb, dev, KSZ9477_INGRESS_TAG_LEN);
	if (!nskb)
		return NULL;

	/* Tag encoding */
	tag = skb_put(nskb, KSZ9477_INGRESS_TAG_LEN);
	addr = skb_mac_header(nskb);

	val = BIT(dp->index);

	if (is_link_local_ether_addr(addr))
		val |= KSZ9477_TAIL_TAG_OVERRIDE;

	*tag = cpu_to_be16(val);

	return nskb;
}

static struct sk_buff *ksz9477_rcv(struct sk_buff *skb, struct net_device *dev,
				   struct packet_type *pt)
{
	/* Tag decoding */
	u8 *tag = skb_tail_pointer(skb) - KSZ_EGRESS_TAG_LEN;
	unsigned int port = tag[0] & 7;
	unsigned int len = KSZ_EGRESS_TAG_LEN;

	/* Extra 4-bytes PTP timestamp */
	if (tag[0] & KSZ9477_PTP_TAG_INDICATION)
		len += KSZ9477_PTP_TAG_LEN;

	return ksz_common_rcv(skb, dev, port, len);
}

static const struct dsa_device_ops ksz9477_netdev_ops = {
	.name	= "ksz9477",
	.proto	= DSA_TAG_PROTO_KSZ9477,
	.xmit	= ksz9477_xmit,
	.rcv	= ksz9477_rcv,
	.overhead = KSZ9477_INGRESS_TAG_LEN,
};

DSA_TAG_DRIVER(ksz9477_netdev_ops);
MODULE_ALIAS_DSA_TAG_DRIVER(DSA_TAG_PROTO_KSZ9477);

#define KSZ9893_TAIL_TAG_OVERRIDE	BIT(5)
#define KSZ9893_TAIL_TAG_LOOKUP		BIT(6)

static struct sk_buff *ksz9893_xmit(struct sk_buff *skb,
				    struct net_device *dev)
{
	struct dsa_port *dp = dsa_slave_to_port(dev);
	struct sk_buff *nskb;
	u8 *addr;
	u8 *tag;

	nskb = ksz_common_xmit(skb, dev, KSZ_INGRESS_TAG_LEN);
	if (!nskb)
		return NULL;

	/* Tag encoding */
	tag = skb_put(nskb, KSZ_INGRESS_TAG_LEN);
	addr = skb_mac_header(nskb);

	*tag = BIT(dp->index);

	if (is_link_local_ether_addr(addr))
		*tag |= KSZ9893_TAIL_TAG_OVERRIDE;

	return nskb;
}

static const struct dsa_device_ops ksz9893_netdev_ops = {
	.name	= "ksz9893",
	.proto	= DSA_TAG_PROTO_KSZ9893,
	.xmit	= ksz9893_xmit,
	.rcv	= ksz9477_rcv,
	.overhead = KSZ_INGRESS_TAG_LEN,
	.tail_tag = true,
};

DSA_TAG_DRIVER(ksz9893_netdev_ops);
MODULE_ALIAS_DSA_TAG_DRIVER(DSA_TAG_PROTO_KSZ9893);

#define LAN937X_INGRESS_TAG_LEN		2

#define LAN937X_TAIL_TAG_OVERRIDE	BIT(11)
#define LAN937X_TAIL_TAG_LOOKUP		BIT(12)
#define LAN937X_TAIL_TAG_VALID		BIT(13)

static struct ksz_device *get_ksz_priv(struct net_device *dev,
				       int device)
{
	struct dsa_port *cpu_dp = dev->dsa_ptr;
	struct dsa_switch_tree *dst = cpu_dp->dst;
	struct dsa_port *dp;
	struct net_device *netdev;
	struct dsa_switch *ds;

	/*Find one of the slave port (0) to get priv data*/
	list_for_each_entry(dp, &dst->ports, list)
		if (dp->ds->index == device && dp->index == 0 &&
		    dp->type == DSA_PORT_TYPE_USER){
			netdev = dp->slave;
			ds = dsa_slave_to_port(netdev)->ds;
			return ds->priv;
		}

	return NULL;
}

static struct sk_buff *lan937x_xmit(struct sk_buff *skb,
				    struct net_device *dev)
{
	struct dsa_port *dp = dsa_slave_to_port(dev);
	struct dsa_switch *ds = dp->ds;
	struct ksz_device *ksz_dev = ds->priv;
	struct sk_buff *nskb;
	__be16 *tag;
	u8 *addr;
	u16 val;

	nskb = ksz_common_xmit(skb, dev, LAN937X_INGRESS_TAG_LEN);
	if (!nskb)
		return NULL;

	/* Tag encoding */
	tag = skb_put(nskb, LAN937X_INGRESS_TAG_LEN);
	addr = skb_mac_header(nskb);

	val = BIT(ksz_dev->log_prt_map[dp->index] - 1);

	if (is_link_local_ether_addr(addr))
		val |= LAN937X_TAIL_TAG_OVERRIDE;

	/* Tail tag valid bit - This bit should always be set by the CPU*/
	val |= LAN937X_TAIL_TAG_VALID;

	*tag = cpu_to_be16(val);

	return nskb;
}

static struct sk_buff *lan937x_rcv(struct sk_buff *skb, struct net_device *dev,
				   struct packet_type *pt)
{
	/* Tag decoding */
	u8 *tag = skb_tail_pointer(skb) - KSZ_EGRESS_TAG_LEN;
	unsigned int len = KSZ_EGRESS_TAG_LEN;
	unsigned int port, i;
	unsigned int log_prt = (tag[0] & 7) + 1;

	/*get lan937x priv data*/
	struct ksz_device *ksz_dev = get_ksz_priv(dev, 0);

	/* Find Physical Port*/
	for (i = 0; i < 10; i++)
		if (log_prt == ksz_dev->log_prt_map[i])
			port = i;

	/* Extra 4-bytes PTP timestamp */
	if (tag[0] & KSZ9477_PTP_TAG_INDICATION)
		len += KSZ9477_PTP_TAG_LEN;

	return ksz_common_rcv(skb, dev, port, len);
}

static const struct dsa_device_ops lan937x_netdev_ops = {
	.name	= "lan937x",
	.proto	= DSA_TAG_PROTO_LAN937X,
	.xmit	= lan937x_xmit,
	.rcv	= lan937x_rcv,
	.overhead = LAN937X_INGRESS_TAG_LEN,
};

DSA_TAG_DRIVER(lan937x_netdev_ops);
MODULE_ALIAS_DSA_TAG_DRIVER(DSA_TAG_PROTO_LAN937X);

static struct dsa_tag_driver *dsa_tag_driver_array[] = {
	&DSA_TAG_DRIVER_NAME(ksz8795_netdev_ops),
	&DSA_TAG_DRIVER_NAME(ksz9477_netdev_ops),
	&DSA_TAG_DRIVER_NAME(ksz9893_netdev_ops),
	&DSA_TAG_DRIVER_NAME(lan937x_netdev_ops),
};

module_dsa_tag_drivers(dsa_tag_driver_array);

MODULE_LICENSE("GPL");
