// SPDX-License-Identifier: GPL-2.0+
/*
 * net/dsa/tag_ksz.c - Microchip KSZ Switch tag format handling
 * Copyright (c) 2017 Microchip Technology
 */

#include "../../drivers/net/dsa/microchip/ksz_common.h"
#include <linux/etherdevice.h>
#include <linux/ptp_classify.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/dsa/lan937x.h>
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

/*
 * For Ingress (Host -> LAN937x), 2 bytes are added before FCS.
 * ---------------------------------------------------------------------------
 * DA(6bytes)|SA(6bytes)|....|Data(nbytes)|tag0(1byte)|tag1(1byte)|FCS(4bytes)
 * ---------------------------------------------------------------------------
 * tag0 : Prioritization (not used now)
 * tag1 : each bit represents port (eg, 0x01=port1, 0x02=port2, 0x10=port5)
 *
 * For Egress (LAN937x -> Host), 1 byte is added before FCS.
 * ---------------------------------------------------------------------------
 * DA(6bytes)|SA(6bytes)|....|Data(nbytes)|tag0(1byte)|FCS(4bytes)
 * ---------------------------------------------------------------------------
 * tag0 : zero-based value represents port
 *	  (eg, 0x00=port1, 0x02=port3, 0x06=port7)
 *
 * As per LAN937x design, logical port numbering(1 to max_port) need to be
 * used for register access based on physical port number (0 based value,
 * Ex, equals to the number mentioned in the hardware pins TXP4,RXP4...).
 * A simple conversion is followed when referring the LAN937x registers,
 * so that the user can configure the device tree as usual just by seeing
 * the physical port numbers in the board.
 *
 * For Ingress, appropriate Logical port number value must be set in
 * tag bytes from physical port number.
 *
 * For Egress, tag bytes from switch will have logical port number,
 * so get the right physical port.
 */
#define LAN937X_INGRESS_TAG_LEN		2
#define LAN937X_PTP_TAG_LEN             4

#define LAN937X_PTP_TAG_INDICATION      BIT(7)
#define LAN937X_TAIL_TAG_OVERRIDE	BIT(11)
#define LAN937X_TAIL_TAG_LOOKUP		BIT(12)
#define LAN937X_TAIL_TAG_VALID		BIT(13)

/* Find appropriate slave based on the logical port.
 * Logical port number is stored for each slave of dsa_port priv data 
 * during probe
 */
static struct dsa_port *ksz_get_dsa_phy_port(struct net_device *dev,
					     int device, int log_prt)
{
	struct dsa_port *cpu_dp = dev->dsa_ptr;
	struct dsa_switch_tree *dst = cpu_dp->dst;
	struct dsa_port *dp;
	struct lan937x_port_ext *kp;

	/*Find right target based on log_prt number*/
	list_for_each_entry(dp, &dst->ports, list)
		if (dp->ds->index == device &&
		    dp->type == DSA_PORT_TYPE_USER){
			kp = dp->priv;
			if (kp->lp_num == log_prt)
				return dp;
		}

	return NULL;
}

#if IS_ENABLED(CONFIG_NET_DSA_MICROCHIP_LAN937X_PTP)

ktime_t lan937x_tstamp_to_clock(struct ksz_device *ksz, u32 tstamp) 
{
	struct timespec64 ts = ktime_to_timespec64(tstamp);
	struct timespec64 ptp_clock_time;
	struct timespec64 diff;
	unsigned long flags;

	spin_lock_irqsave(&ksz->ptp_clock_lock, flags);
	ptp_clock_time = ksz->ptp_clock_time;
	spin_unlock_irqrestore(&ksz->ptp_clock_lock, flags);

	/* calculate full time from partial time stamp */
	ts.tv_sec = (ptp_clock_time.tv_sec & ~3) | ts.tv_sec;

	/* find nearest possible point in time */
	diff = timespec64_sub(ts, ptp_clock_time);
	if (diff.tv_sec > 2)
		ts.tv_sec -= 4;
	else if (diff.tv_sec < -2)
		ts.tv_sec += 4;

	return timespec64_to_ktime(ts);
}
EXPORT_SYMBOL(lan937x_tstamp_to_clock);

struct ksz9477_skb_cb {
	unsigned int ptp_type;
	/* Do not cache pointer to PTP header between ksz9477_ptp_port_txtstamp
	 * and ksz9xxx_xmit() (will become invalid during dsa_realloc_skb()).
	 */
	u8 ptp_msg_type;
};

#define KSZ9477_SKB_CB(skb) \
	((struct ksz9477_skb_cb *)DSA_SKB_CB_PRIV(skb))

static void lan937x_xmit_timestamp(struct sk_buff *skb __maybe_unused) 
{ 
	struct sk_buff *clone = DSA_SKB_CB(skb)->clone;
	struct ptp_header *ptp_hdr;
	unsigned int ptp_type;
	u32 tstamp_raw = 0;
	u8 ptp_msg_type;
	s64 correction;

//	if (!clone)
//		goto out_put_tag;

	/* Use cached PTP type from ksz9477_ptp_port_txtstamp().  */
/*	ptp_type = KSZ9477_SKB_CB(clone)->ptp_type;
	if (ptp_type == PTP_CLASS_NONE)
	{
		return;
	}

	ptp_hdr = ptp_parse_header(skb, ptp_type);
	if (!ptp_hdr)
	{
		return;
	}

	ptp_msg_type = KSZ9477_SKB_CB(clone)->ptp_msg_type;
*/	
out_put_tag:
	put_unaligned_be32(tstamp_raw, skb_put(skb, LAN937X_PTP_TAG_LEN));
}

static void lan937x_rcv_timestamp(struct sk_buff *skb __maybe_unused, u8 *tag __maybe_unused,
                                 struct net_device *dev __maybe_unused,
                                 unsigned int port __maybe_unused)
{
	struct skb_shared_hwtstamps *hwtstamps = skb_hwtstamps(skb);
	u8 *tstamp_raw = tag - KSZ9477_PTP_TAG_LEN;
//	enum ksz9477_ptp_event_messages msg_type;
	struct dsa_switch *ds = dev->dsa_ptr->ds;
	struct ksz_device *ksz = ds->priv;
	struct ksz_port *prt = &ksz->ports[port];
	struct ptp_header *ptp_hdr;
	unsigned int ptp_type;
	ktime_t tstamp;
	u8 data;

	/* convert time stamp and write to skb */
	tstamp = ksz9477_decode_tstamp(get_unaligned_be32(tstamp_raw),
				       -prt->tstamp_rx_latency_ns);
	memset(hwtstamps, 0, sizeof(*hwtstamps));
	hwtstamps->hwtstamp = lan937x_tstamp_to_clock(ksz, tstamp);

	__skb_push(skb, ETH_HLEN);
	ptp_type = ptp_classify_raw(skb);
	__skb_pull(skb, ETH_HLEN);

/*	pr_err("debug 1\n");
	if (ptp_type == PTP_CLASS_NONE)
		return;
*/
	ptp_hdr = ptp_parse_header(skb, ptp_type);
	if (!ptp_hdr)
		return;

	data = ptp_get_msgtype(ptp_hdr, ptp_type);
	/*if(data == 0)
	pr_err("packet recv is sync\n");
	else if(data == 2)
	pr_err("packet recv is pdelay_req\n");
	else if(data == 3)
		pr_err("data recv is delay_resp\n");
	else
		pr_err("data recv is %d\n", data);
	*/	
	//if (msg_type != PTP_Event_Message_Pdelay_Req)
//		return;
}

#else

static void lan937x_xmit_timestamp(struct sk_buff *skb __maybe_unused) 
{}

static void lan937x_rcv_timestamp(struct sk_buff *skb __maybe_unused, u8 *tag __maybe_unused,
                                 struct net_device *dev __maybe_unused,
                                 unsigned int port __maybe_unused)
{}
#endif

static struct sk_buff *lan937x_xmit(struct sk_buff *skb,
				    struct net_device *dev)
{
	struct dsa_port *dp = dsa_slave_to_port(dev);
	struct lan937x_port_ext *kp = dp->priv;
	struct sk_buff *nskb;
	__be16 *tag;
	u8 *addr;
	u16 val;


	nskb = ksz_common_xmit(skb, dev, LAN937X_INGRESS_TAG_LEN);
	if (!nskb)
		return NULL;

	/* Tag encoding */
        lan937x_xmit_timestamp(skb);
	tag = skb_put(nskb, LAN937X_INGRESS_TAG_LEN);
	addr = skb_mac_header(nskb);

	/* Set appropriate bit mask for logical port number */
	val = BIT(kp->lp_num - 1);

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
	unsigned int log_prt = (tag[0] & 7) + 1;

	/* tag[0] contains logical number, find the right target*/
	struct dsa_port *kp = ksz_get_dsa_phy_port(dev, 0, log_prt);

	/* Extra 4-bytes PTP timestamp */
	if (tag[0] & LAN937X_PTP_TAG_INDICATION)
	{
                lan937x_rcv_timestamp(skb, tag, dev, log_prt);
		len += KSZ9477_PTP_TAG_LEN;
	}

	return ksz_common_rcv(skb, dev, kp->index, len);
}

static const struct dsa_device_ops lan937x_netdev_ops = {
	.name	= "lan937x",
	.proto	= DSA_TAG_PROTO_LAN937X,
	.xmit	= lan937x_xmit,
	.rcv	= lan937x_rcv,
	.overhead = LAN937X_INGRESS_TAG_LEN + LAN937X_PTP_TAG_LEN,
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
