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
#include <net/dsa.h>
#include "dsa_priv.h"

/* Typically only one byte is used for tail tag. */
#define KSZ_EGRESS_TAG_LEN		1
#define KSZ_INGRESS_TAG_LEN		1

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
	u8 *tag;
	u8 *addr;

	/* Tag encoding */
	tag = skb_put(skb, KSZ_INGRESS_TAG_LEN);
	addr = skb_mac_header(skb);

	*tag = 1 << dp->index;
	if (is_link_local_ether_addr(addr))
		*tag |= KSZ8795_TAIL_TAG_OVERRIDE;

	return skb;
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
	.tail_tag = true,
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
	__be16 *tag;
	u8 *addr;
	u16 val;

	/* Tag encoding */
	tag = skb_put(skb, KSZ9477_INGRESS_TAG_LEN);
	addr = skb_mac_header(skb);

	val = BIT(dp->index);

	if (is_link_local_ether_addr(addr))
		val |= KSZ9477_TAIL_TAG_OVERRIDE;

	*tag = cpu_to_be16(val);

	return skb;
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
	.tail_tag = true,
};

DSA_TAG_DRIVER(ksz9477_netdev_ops);
MODULE_ALIAS_DSA_TAG_DRIVER(DSA_TAG_PROTO_KSZ9477);

#define KSZ9893_TAIL_TAG_OVERRIDE	BIT(5)
#define KSZ9893_TAIL_TAG_LOOKUP		BIT(6)

static struct sk_buff *ksz9893_xmit(struct sk_buff *skb,
				    struct net_device *dev)
{
	struct dsa_port *dp = dsa_slave_to_port(dev);
	u8 *addr;
	u8 *tag;

	/* Tag encoding */
	tag = skb_put(skb, KSZ_INGRESS_TAG_LEN);
	addr = skb_mac_header(skb);

	*tag = BIT(dp->index);

	if (is_link_local_ether_addr(addr))
		*tag |= KSZ9893_TAIL_TAG_OVERRIDE;

	return skb;
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

/* For Ingress (Host -> LAN937x), 2 bytes are added before FCS.
 * ---------------------------------------------------------------------------
 * DA(6bytes)|SA(6bytes)|....|Data(nbytes)|tag0(1byte)|tag1(1byte)|FCS(4bytes)
 * ---------------------------------------------------------------------------
 * tag0 : represents tag override, lookup and valid
 * tag1 : each bit represents port (eg, 0x01=port1, 0x02=port2, 0x80=port8)
 *
 * For Egress (LAN937x -> Host), 1 byte is added before FCS.
 * ---------------------------------------------------------------------------
 * DA(6bytes)|SA(6bytes)|....|Data(nbytes)|tag0(1byte)|FCS(4bytes)
 * ---------------------------------------------------------------------------
 * tag0 : zero-based value represents port
 *	  (eg, 0x00=port1, 0x02=port3, 0x07=port8)
 */
#define LAN937X_INGRESS_TAG_LEN		2
#define LAN937X_PTP_TAG_LEN             4

#define LAN937X_PTP_TAG_INDICATION      BIT(7)
#define LAN937X_TAIL_TAG_OVERRIDE	BIT(11)
#define LAN937X_TAIL_TAG_LOOKUP		BIT(12)
#define LAN937X_TAIL_TAG_VALID		BIT(13)
#define LAN937X_TAIL_TAG_PORT_MASK	7


ktime_t lan937x_tstamp_reconstruct(struct ksz_device_ptp_shared *ksz, u32 tstamp) 
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
EXPORT_SYMBOL(lan937x_tstamp_reconstruct);


static void lan937x_xmit_timestamp(struct sk_buff *skb) 
{ 
	u32 tstamp_raw = 0;

	put_unaligned_be32(tstamp_raw, skb_put(skb, LAN937X_PTP_TAG_LEN));
}

static struct sk_buff *ksz9477_defer_xmit(struct dsa_port *dp,
					  struct sk_buff *skb)
{
	struct lan937x_port_ext *kp = dp->priv;
	struct lan937x_port_ptp_shared *ptp_shared = &kp->ptp_shared;
	struct sk_buff *clone = DSA_SKB_CB(skb)->clone;
	u8 ptp_msg_type;

	if (!clone)
		return skb;  /* no deferred xmit for this packet */

	/* Use cached PTP msg type from ksz9477_ptp_port_txtstamp().  */
	ptp_msg_type = KSZ9477_SKB_CB(clone)->ptp_msg_type;
	if (ptp_msg_type == 0x00)
	{
		skb_queue_tail(&ptp_shared->xmit_sync_queue, skb_get(skb));
		kthread_queue_work(ptp_shared->xmit_sync_worker, &ptp_shared->xmit_sync_work);

		return NULL;
	}
        else if (ptp_msg_type == 0x02)
	{
		skb_queue_tail(&ptp_shared->xmit_pdelayreq_queue, skb_get(skb));
		kthread_queue_work(ptp_shared->xmit_pdelayreq_worker, &ptp_shared->xmit_pdelayreq_work);

		return NULL;
	}
        else if (ptp_msg_type == 0x03)
	{
		skb_queue_tail(&ptp_shared->xmit_pdelayrsp_queue, skb_get(skb));
		kthread_queue_work(ptp_shared->xmit_pdelayrsp_worker, &ptp_shared->xmit_pdelayrsp_work);

		return NULL;
	}
	else
	{
                //goto out_free_clone;
                return skb;
	}

out_free_clone:
	kfree_skb(clone);
	DSA_SKB_CB(skb)->clone = NULL;
	return skb;
}

static void lan937x_rcv_timestamp(struct sk_buff *skb , u8 *tag ,
                                 struct dsa_port *dp)
{
	struct skb_shared_hwtstamps *hwtstamps = skb_hwtstamps(skb);
	u8 *tstamp_raw = tag - KSZ9477_PTP_TAG_LEN;
	struct lan937x_port_ext *kp = dp->priv;
	struct lan937x_port_ptp_shared *ptp_shared = &kp->ptp_shared;
	ktime_t tstamp;
 
	/* convert time stamp and write to skb */
	tstamp = ksz9477_decode_tstamp(get_unaligned_be32(tstamp_raw));
	memset(hwtstamps, 0, sizeof(*hwtstamps));
	hwtstamps->hwtstamp = lan937x_tstamp_reconstruct(ptp_shared->dev, tstamp);
}


static struct sk_buff *lan937x_xmit(struct sk_buff *skb,
				    struct net_device *dev)
{
	struct dsa_port *dp = dsa_slave_to_port(dev);
	struct lan937x_port_ext *kp = dp->priv;
	struct lan937x_port_ptp_shared *port_ptp_shared = &kp->ptp_shared;
	struct ksz_device_ptp_shared *ptp_shared = port_ptp_shared->dev;
	struct sk_buff *nskb;
	__be16 *tag;
	u8 *addr;
	u16 val;

	/* Tag encoding */
	if (test_bit(LAN937X_HWTS_EN, &ptp_shared->state))
        	lan937x_xmit_timestamp(skb);

	tag = skb_put(nskb, LAN937X_INGRESS_TAG_LEN);
	addr = skb_mac_header(nskb);

	val = BIT(dp->index);

	if (is_link_local_ether_addr(addr))
		val |= LAN937X_TAIL_TAG_OVERRIDE;

	/* Tail tag valid bit - This bit should always be set by the CPU*/
	val |= LAN937X_TAIL_TAG_VALID;

	*tag = cpu_to_be16(val);

	return ksz9477_defer_xmit(dp, nskb);
//	return nskb;
}

static struct sk_buff *lan937x_rcv(struct sk_buff *skb, struct net_device *dev,
				   struct packet_type *pt)
{
	/* Tag decoding */
	u8 *tag = skb_tail_pointer(skb) - KSZ_EGRESS_TAG_LEN;
	unsigned int port = tag[0] & LAN937X_TAIL_TAG_PORT_MASK;
	unsigned int len = KSZ_EGRESS_TAG_LEN;

	/* Extra 4-bytes PTP timestamp */
	if (tag[0] & LAN937X_PTP_TAG_INDICATION)
	{
                lan937x_rcv_timestamp(skb, tag, kp);
		len += KSZ9477_PTP_TAG_LEN;
	}

	return ksz_common_rcv(skb, dev, port, len);
}

static const struct dsa_device_ops lan937x_netdev_ops = {
	.name	= "lan937x",
	.proto	= DSA_TAG_PROTO_LAN937X,
	.xmit	= lan937x_xmit,
	.rcv	= lan937x_rcv,
	.overhead = LAN937X_INGRESS_TAG_LEN + LAN937X_PTP_TAG_LEN,
	.tail_tag = true,
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
