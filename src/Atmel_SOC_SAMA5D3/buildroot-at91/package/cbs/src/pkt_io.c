
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <alloca.h>
#include <argp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <linux/if_vlan.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <pthread.h>     /* pthread functions and data structures */


#define ETHER_ADDR_LEN 6

#define MAGIC 0xCC

//#define DEBUG

static uint8_t tifname[IFNAMSIZ];
static uint8_t rifname[IFNAMSIZ];
static uint8_t dstaddr[ETH_ALEN];
static uint8_t srcaddr[ETH_ALEN];

static int priority = -1;
static size_t size = 0;
static uint32_t seq;
static int delay = -1;
static uint64_t num_tx_packets = 1;
static uint64_t num_rx_packets = 0;
static uint64_t dport = 0;
static uint64_t sport = 0;
static uint16_t vlanid = 0;
static uint32_t dipv4addr = 0;
static uint32_t sipv4addr = 0;
static int pkt_rcd = 0;
static int pkt_txd = 0;
uint16_t eth_type = ETH_P_IPV6;
pthread_mutex_t lock;

static struct argp_option options[] = {
    {"tx-iname", 'T', "IFNAME", 0, "Network Interface to send packets" },
    {"rx-iname", 'R', "IFNAME", 0, "Network Interface to send packets" },
    {"tx-num-packets", 't', "NUM", 0, "Number of packets to be transmitted"},
    {"rx-num-packets", 'r', "NUM", 0, "Number of packets to be received"},
	{"dst-mac", 'd', "MACADDR", 0, "Stream Destination MAC address" },
    {"src_mac", 's', "MACADDR", 0, "Stream Source MAC address"},
    {"dst-ip6", 'i', "IPADDR", 0, "ipv6 destination ip" },
    {"src_ip6", 'I', "IPADDR", 0, "ipv6 source ip"},
    {"dst-ip4", 'j', "IPADDR", 0, "ipv4 destination ip" },
    {"src_ip4", 'J', "IPADDR", 0, "ipv4 source ip"},
    {"dst-port", 'k', "NUM", 0, "ipv4/ipv6 destination port" },
    {"src-port", 'K', "NUM", 0, "ipv4/ipv6 source port"},
	{"delay", 'D', "NUM", 0, "Delay (in us) between packet transmission" },
	{"prio", 'p', "NUM", 0, "SO_PRIORITY to be set in socket" },
	{"packet-size", 'S', "NUM", 0, "Size of packets to be transmitted" },
    {"eth-type", 'e', "NUM", 0, "Ethernet Packet Type" },
    {"vid", 'v', "NUM", 0, "VLAN ID" },
	{ 0 }
};

static error_t parser(int key, char *arg, struct argp_state *state)
{
	int res;
    int eth_type_l;
    int ipv4addr[4];

	switch (key) {
	case 'd':
		res = sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
					&dstaddr[0], &dstaddr[1], &dstaddr[2],
					&dstaddr[3], &dstaddr[4], &dstaddr[5]);
		if (res != 6) {
			printf("Invalid address\n");
			exit(EXIT_FAILURE);
		}

		break;
	case 'D':
		delay = atoi(arg);
		break;
    case 'k':
		dport = atoi(arg);
		break;
    case 'K':
		sport = atoi(arg);
		break;
    case 'v':
		vlanid = atoi(arg);
		break;
    case 'j':
        res = sscanf(arg, "%d.%d.%d.%d",
					&ipv4addr[0], &ipv4addr[1], &ipv4addr[2],
					&ipv4addr[3]);
		if (res != 4) {
			printf("Invalid dest ipv4 addr\n");
			exit(EXIT_FAILURE);
		}    
        dipv4addr= ipv4addr[0] & 0xFF;
        dipv4addr |= (ipv4addr[1] << 8) & 0xFFFF;
        dipv4addr |= (ipv4addr[2] << 16) & 0xFFFFFF;
        dipv4addr |= (ipv4addr[3] << 24) & 0xFFFFFFFF;
        //printf("\n%x\n",dipv4addr);
        break;
    case 'J':
        res = sscanf(arg, "%d.%d.%d.%d",
					&ipv4addr[0], &ipv4addr[1], &ipv4addr[2],
					&ipv4addr[3]);
		if (res != 4) {
			printf("Invalid source ipv4 addr\n");
			exit(EXIT_FAILURE);
		}    
        sipv4addr= ipv4addr[0] & 0xFF;
        sipv4addr |= (ipv4addr[1] << 8) & 0xFFFF;
        sipv4addr |= (ipv4addr[2] << 16) & 0xFFFFFF;
        sipv4addr |= (ipv4addr[3] << 24) & 0xFFFFFFFF;
        //printf("\n%x\n",sipv4addr);
        
        break;
	case 'T':
		strncpy(tifname, arg, IFNAMSIZ-1);
		break;
    case 'R':
		strncpy(rifname, arg, IFNAMSIZ-1);
		break;
	case 'p':
		priority = atoi(arg);
		break;
	case 'S':
		size = atoi(arg);
		break;
    case 't':
        num_tx_packets = atoi(arg);
        break;
    case 'r':
        num_rx_packets = atoi(arg);
        break;
    case 'e':
        eth_type_l = atoi(arg);
        switch (eth_type_l)
        {
            case 0:
                eth_type = ETH_P_IPV6;
            break;
            case 1:
            default:
                eth_type = ETH_P_IP;
            break;
        }
        break;
    case 's':
        res = sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
					&srcaddr[0], &srcaddr[1], &srcaddr[2],
					&srcaddr[3], &srcaddr[4], &srcaddr[5]);
		if (res != 6) {
			printf("Invalid address\n");
			exit(EXIT_FAILURE);
		}
	}

	return 0;
}

static struct argp argp = { options, parser };

static int setup_socket (int is_tx, struct sockaddr_ll *sk_addr)
{
    int fd, res;
	struct ifreq req;
    struct ifreq if_mac;
    struct ethhdr *eh; 

    int sockopt;

    uint8_t ifname[IFNAMSIZ];

    /* tx & rx interfaces are different */
    if (is_tx)
        strncpy(ifname, tifname, IFNAMSIZ-1);
    else
        strncpy(ifname, rifname, IFNAMSIZ-1);

     
     /* Open RAW socket to send/receive all packet types */
	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		perror("Couldn't open socket");
		return -1;
	}

    /* Get interface index */
	strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
	res = ioctl(fd, SIOCGIFINDEX, &req);
	if (res < 0) {
		perror("Couldn't get interface index");
        close(fd);
		return -1;
	}

    sk_addr->sll_ifindex = req.ifr_ifindex;

    if(!is_tx)
    {
        /* Get existing flags */
        ioctl(fd, SIOCGIFFLAGS, &req);
        req.ifr_flags |= IFF_PROMISC;

        /* set promisc mode */
        ioctl(fd, SIOCSIFFLAGS, &req);

        /* Allow the socket to be reused - incase connection is closed prematurely */
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
            perror("setsockopt");
            close(fd);
            return -1;
        }

        /* Bind to device */
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, IFNAMSIZ-1) == -1)	{
            perror("SO_BINDTODEVICE");
            close(fd);
            return -1;
        }
    }
    else
    {
        /* Get the MAC address of the interface to send on */
        memset(&if_mac, 0, sizeof(struct ifreq));
        strncpy(if_mac.ifr_name, ifname, IFNAMSIZ-1);

        if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0) {
            perror("SIOCGIFHWADDR");
            close(fd);
            return -1;
        }

        memcpy(sk_addr->sll_addr, dstaddr, ETH_ALEN);
    }

    return fd;
}


struct recv_thread_data{
    struct sockaddr_ll *sk_addr;
    int fd;
};

static void* recv_packet(void *rthreaddata)
{  
    unsigned char *buffer = alloca(1514);
    struct recv_thread_data *rt = (struct recv_thread_data *)rthreaddata;
    uint32_t *seq = (uint32_t *)&buffer[0];
    struct sockaddr_ll addr;
    socklen_t addr_len = sizeof(addr);
    uint32_t expected_seq = 0;
    int buflen;
  
   
    while (num_rx_packets)
    {
        /* Reset the buffer */
        memset(buffer, MAGIC, 1514);

        /* used recvfrom function so that the sockaddr will have
         the details to filter
        */
        buflen = recvfrom(rt->fd, buffer, 1514, 0,  (struct sockaddr*)&addr, &addr_len);
        //buflen = recv(rt->fd, buffer, 1514, 0);

        if(buflen < 0) {
            printf("error in reading recvfrom function\n");
            goto err;
        }

#ifdef DEBUG
        printf("\n");
#endif

        /* do not receive own packet */
        if (addr.sll_pkttype != PACKET_OUTGOING) {
#ifdef DEBUG 
            printf ("\nRx\n");
#endif
            /* if the index is not matching , then this is not the sent packet */
            if (rt->sk_addr->sll_ifindex != addr.sll_ifindex)
                continue;

            /* For the first time expected_seq is 0 */
            if (*seq == expected_seq)
            {
                num_rx_packets--;
                expected_seq++;
                pkt_rcd++;
            }
        }

#ifdef DEBUG
        for (int i=0; i < size; i++)
            printf("0x%x ", buffer[i]);
        
        printf("\n");
#endif
    }
out1:
    printf("\n Number of packets received %d\n\n", pkt_rcd);
    close(rt->fd);
    return 0;

err:
    close(rt->fd);
    return (void *)-1;
}

/*
struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8			priority:4,
				version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8			version:4,
				priority:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8			flow_lbl[3];

	__be16			payload_len;
	__u8			nexthdr;
	__u8			hop_limit;

	struct	in6_addr	saddr;
	struct	in6_addr	daddr;
};
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
};
/**
 *	struct vlan_ethhdr - vlan ethernet header (ethhdr + vlan_hdr)
 *	@h_dest: destination ethernet address
 *	@h_source: source ethernet address
 *	@h_vlan_proto: ethernet protocol
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_ethhdr {
	unsigned char	h_dest[ETH_ALEN];
	unsigned char	h_source[ETH_ALEN];
	__be16		h_vlan_proto;
	__be16		h_vlan_TCI;
	__be16		h_vlan_encapsulated_proto;
}__attribute__((packed));



static int tx_packet (int fd, struct sockaddr_ll *sk_addr)
{
    int res, n;
	struct ifreq req;
    struct ifreq if_mac;
	uint8_t data[1514];
    struct ethhdr *eh; 
	struct iphdr *iph;
    struct tcphdr *tcph;
    struct ipv6hdr *ip6h;
    struct vlan_ethhdr *veh;
    uint32_t *seq_ptr = (uint32_t *) &data[0];
    static int ip_id_count= 0;
    int sethdr = 0;
    
    size = 0;
	memset(data, MAGIC, sizeof(data));

    *seq_ptr = seq++;


    if (vlanid != 0)
    {
        veh = (struct vlan_ethhdr *) &data[0];

        sethdr = sizeof(struct vlan_ethhdr);

        veh->h_vlan_proto = htons(ETH_P_8021Q);
        veh->h_vlan_TCI  = htons(vlanid);

        /* ethertype field */
        veh->h_vlan_encapsulated_proto = htons(eth_type);
    }
    else
    {
        eh = (struct ethhdr *) &data[0];
  

        /* fill src address */
        //memcpy (eh->h_source, srcaddr, ETH_ALEN);

        // eh->h_source[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
        // eh->h_source[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
        // eh->h_source[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
        // eh->h_source[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
        // eh->h_source[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
        // eh->h_source[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];

        /* fill dst address */
        //memcpy (eh->h_dest, dstaddr, ETH_ALEN);

        
        sethdr = sizeof(struct ethhdr);

        /* ethertype field */
        eh->h_proto = htons(eth_type);
    }

    size += sethdr;

    if (eth_type == ETH_P_IPV6) {
        ip6h = (struct ipv6hdr *) (data + sethdr);
        size += sizeof(struct ipv6hdr);

        tcph = (struct tcphdr *)(data + sethdr+ sizeof(struct ipv6hdr));
        size += sizeof(struct tcphdr);

        ip6h->version = 6;
		ip6h->priority = 0;
		ip6h->flow_lbl[0] = 0;
		ip6h->flow_lbl[1] = 0;
		ip6h->flow_lbl[2] = 0;
		ip6h->payload_len = 0;
		ip6h->nexthdr = 0;
		ip6h->hop_limit = 0;


        tcph->source = sport;
	    tcph->dest = dport;
        tcph->ack_seq = 0;
        tcph->ack = 1;
        
    }
    else {
        iph = (struct iphdr *) (data + sethdr);
        size += sizeof(struct iphdr);

        tcph = (struct tcphdr *)(data + sethdr+ sizeof(struct iphdr));
        size += sizeof(struct tcphdr);

        iph->version  = 4;
        iph->ihl      = 5;
        iph->tos      = 0;
        iph->frag_off = 0;
        //if (ip_dont_fragment(sk, &rt->u.dst))
        //    iph->frag_off |= htons(IP_DF);
        iph->ttl      = 0x40;

        iph->protocol = IPPROTO_TCP;
        iph->tot_len  = htons(size);
        iph->id       = 0;

        if (sipv4addr != 0)
            iph->saddr = sipv4addr;

        if (dipv4addr != 0)
            iph->daddr = dipv4addr;

        tcph->source = 100;
	    tcph->dest = 200;
        tcph->ack_seq = 0;
        tcph->ack = 1;
    }
    
    /* Packet data */
	data[size++] = 0xde;
	data[size++] = 0xad;
	data[size++] = 0xbe;
	data[size++] = 0xef;

#ifdef DEBUG
    for (int i=0; i<26; i++)
       printf(" 0x%x ", data[i]);
#endif

    size += sizeof(struct ethhdr);

    sk_addr->sll_halen = ETH_ALEN; // length of destination mac address

#ifdef DEBUG
    printf("\n");
#endif

    /* Send packets */
    n = sendto(fd, data, size, 0, (struct sockaddr *)sk_addr,
							sizeof(struct sockaddr_ll));

    return 0;

err:
	close(fd);
	return -1;

}

int main(int argc, char *argv[])
{
	struct sockaddr_ll sk_tx_addr;
    struct sockaddr_ll sk_rx_addr;
    struct recv_thread_data rtdata;
    int tx_fd, rx_fd, rc;
    pthread_t  thread_id;     	/* thread's ID (just an integer)          */

	argp_parse(&argp, argc, argv, 0, NULL, NULL);

    tx_fd = setup_socket (1, &sk_tx_addr);

    if (tx_fd < 0) {
        perror ("setup_socket failed for Tx port");
        exit(1);
    }

    rx_fd = setup_socket (0, &sk_rx_addr);

    if (rx_fd < 0) {
        perror ("setup_socket failed for Rx port");
        exit(1);
    }
    
    /* Pass the data to the thread */
    rtdata.fd = rx_fd;
    rtdata.sk_addr = &sk_rx_addr;

    /* create a new thread that will execute 'PrintHello' */
    rc = pthread_create(&thread_id, NULL, recv_packet, (void*)&rtdata);  

    /* could not create thread */
    if(rc) {
        printf("\n ERROR: return code from pthread_create is %d \n", rc);
        exit(1);
    }
  
	printf("Sending packets...\n");

	while (num_tx_packets--) {
		ssize_t n;
       
        n = tx_packet(tx_fd, &sk_tx_addr);
	
		if (n < 0)
			perror("Failed to send data");

		if (delay > 0)
			usleep(delay);

        pkt_txd++;
	}

    printf("\n Number of packets Transmitted %d\n", pkt_txd);
    pthread_join(thread_id, NULL);

    close(tx_fd);
}
