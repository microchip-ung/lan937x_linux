#ifndef _NET_DSA_KSZ_COMMON_H_
#define _NET_DSA_KSZ_COMMON_H_

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/ktime.h>
#include <linux/kthread.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_classify.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/time64.h>
#include <net/dsa.h>

/* All time stamps from the KSZ consist of 2 bits for seconds and 30 bits for
 * nanoseconds. This is NOT the same as 32 bits for nanoseconds.
 */
#define KSZ_TSTAMP_SEC_MASK  GENMASK(31, 30)
#define KSZ_TSTAMP_NSEC_MASK GENMASK(29, 0)

#define KSZ9477_HWTS_EN  0
#define LAN937X_HWTS_EN  0

struct ksz_device_ptp_shared {
	/* protects ptp_clock_time (user space (various syscalls)
	 * vs. softirq in ksz9477_rcv_timestamp()).
	 */
	spinlock_t ptp_clock_lock;
	/* approximated current time, read once per second from hardware */
	struct timespec64 ptp_clock_time;
	unsigned long state;
};

struct lan937x_port_ptp_shared{
	struct ksz_device_ptp_shared *dev;
        struct kthread_worker *sync_worker;
        struct kthread_worker *pdelayreq_worker;
        struct kthread_worker *pdelayrsp_worker;
	struct kthread_work sync_work;
	struct sk_buff_head sync_queue;
	struct kthread_work pdelayreq_work;
	struct sk_buff_head pdelayreq_queue;
	struct kthread_work pdelayrsp_work;
	struct sk_buff_head pdelayrsp_queue;
};

struct ksz_port_ptp_shared {
	struct ksz_device_ptp_shared *dev;
	struct kthread_worker *xmit_worker;
	struct kthread_work xmit_work;
	struct sk_buff_head xmit_queue;
};

/* net/dsa/tag_ksz.c */
static inline ktime_t ksz_decode_tstamp(u32 tstamp)
{
	u64 ns = FIELD_GET(KSZ_TSTAMP_SEC_MASK, tstamp) * NSEC_PER_SEC +
		 FIELD_GET(KSZ_TSTAMP_NSEC_MASK, tstamp);

	return ns_to_ktime(ns);
}

ktime_t ksz_tstamp_reconstruct(struct ksz_device_ptp_shared *ksz,
				   ktime_t tstamp);

struct ksz_skb_cb {
	unsigned int ptp_type;
	/* Do not cache pointer to PTP header between ksz9477_ptp_port_txtstamp
	 * and ksz9xxx_xmit() (will become invalid during dsa_realloc_skb()).
	 */
	u8 ptp_msg_type;
};

#define KSZ_SKB_CB(skb) \
	((struct ksz_skb_cb *)DSA_SKB_CB_PRIV(skb))

#endif /* _NET_DSA_KSZ_COMMON_H_ */
