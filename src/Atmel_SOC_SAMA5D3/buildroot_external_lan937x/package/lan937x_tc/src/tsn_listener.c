#include <alloca.h>
//#include <argp.h>
//#include <arpa/inet.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <unistd.h>

static uint8_t ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static uint64_t data_count;
static int size = 1500;
static time_t interval = 1;
static bool check_seq = false;
static uint64_t expected_seq;
/*
static struct argp_option options[] = {
	{"check-seq", 'c', NULL, 0, "Check sequence number within packet" },
	{"dst-addr", 'd', "MACADDR", 0, "Stream Destination MAC address" },
	{"ifname", 'i', "IFNAME", 0, "Network Interface" },
	{"interval", 'I', "SEC", 0, "Interval between bandwidth reports" },
	{"packet-size", 's', "NUM", 0, "Expected packet size" },
	{ 0 }
};

static error_t parser(int key, char *arg, struct argp_state *state)
{
	int res;

	switch (key) {
	case 'c':
		check_seq = true;
		break;
	case 'd':
		res = sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
					&macaddr[0], &macaddr[1], &macaddr[2],
					&macaddr[3], &macaddr[4], &macaddr[5]);
		if (res != 6) {
			printf("Invalid address\n");
			exit(EXIT_FAILURE);
		}

		break;
	case 'i':
		strncpy(ifname, arg, sizeof(ifname) - 1);
		break;
	case 'I':
		interval = atoi(arg);
		break;
	case 's':
		size = atoi(arg);
		break;
	}

	return 0;
}

static struct argp argp = { options, parser };
*/
static int setup_timer(void)
{
	int fd, res;
	struct itimerspec tspec = { 0 };

	fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (fd < 0) {
		perror("Couldn't create timer");
		return -1;
	}

	tspec.it_value.tv_sec = interval;
	tspec.it_interval.tv_sec = interval;

	res = timerfd_settime(fd, 0, &tspec, NULL);
	if (res < 0) {
		perror("Couldn't set timer");
		close(fd);
		return -1;
	}

	return fd;
}

static int setup_socket(void)
{
	int fd, res;
	struct sockaddr_ll sk_addr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_TSN),
	};

	fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_TSN));
	if (fd < 0) {
		perror("Couldn't open socket");
		return -1;
	}

	/* If user provided a network interface, bind() to it. */
	if (ifname[0] != '\0') {
		struct ifreq req;

		strncpy(req.ifr_name, "br0", sizeof(req.ifr_name));
		res = ioctl(fd, SIOCGIFINDEX, &req);
		if (res < 0) {
			perror("Couldn't get interface index");
			goto err;
		}

		sk_addr.sll_ifindex = req.ifr_ifindex;

		res = bind(fd, (struct sockaddr *) &sk_addr, sizeof(sk_addr));
		if (res < 0) {
			perror("Couldn't bind() to interface");
			goto err;
		}
	}

	/* If user provided the stream destination address, set it as multicast
	 * address.
	 */
	if (macaddr[0] != '\0') {
		struct packet_mreq mreq;

		mreq.mr_ifindex = sk_addr.sll_ifindex;
		mreq.mr_type = PACKET_MR_MULTICAST;
		mreq.mr_alen = ETH_ALEN;
		memcpy(&mreq.mr_address, macaddr, ETH_ALEN);

		res = setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
					&mreq, sizeof(struct packet_mreq));
		if (res < 0) {
			perror("Couldn't set PACKET_ADD_MEMBERSHIP");
			goto err;
		}
	}

	return fd;

err:
	close(fd);
	return -1;
}

static void recv_packet(int fd)
{
	uint8_t *data = alloca(size);
	ssize_t n = recv(fd, data, size, 0);

	if (n < 0) {
		perror("Failed to receive data");
		return;
	}

	if (n != size)
		printf("Size mismatch: expected %d, got %d\n", size, n);

	if (check_seq) {
		uint64_t *seq = (uint64_t *) &data[0];

		/* If 'expected_seq' is equal to zero, it means this is the
		 * first packet we received so we don't know what sequence
		 * number to expect.
		 */
		if (expected_seq == 0)
			expected_seq = *seq;

		if (*seq != expected_seq) {
			printf("Sequence mismatch: expected %llu, got %llu\n",
					expected_seq, *seq);

			expected_seq = *seq;
		}

		expected_seq++;
	}

	data_count += n;
}

static void report_bw(int fd)
{
	uint64_t expirations;
	ssize_t n = read(fd, &expirations, sizeof(uint64_t));

	if (n < 0) {
		perror("Couldn't read timerfd");
		return;
	}

	if (expirations != 1)
		printf("Some went wrong with timerfd\n");

	printf("Receiving data rate: %llu kbps\n", (data_count * 8) / (1000 * interval));

	data_count = 0;
}

int main(int argc, char *argv[])
{
	int sk_fd, timer_fd, res;
	struct pollfd fds[2];

//	argp_parse(&argp, argc, argv, 0, NULL, NULL);

	sk_fd = setup_socket();
	if (sk_fd < 0)
		return 1;

	timer_fd = setup_timer();
	if (timer_fd < 0) {
		close(sk_fd);
		return 1;
	}

	fds[0].fd = sk_fd;
	fds[0].events = POLLIN;
	fds[1].fd = timer_fd;
	fds[1].events = POLLIN;

	printf("Waiting for packets...\n");

	while (1) {
		res = poll(fds, 2, -1);
		if (res < 0) {
			perror("Error on poll()");
			goto err;
		}

		if (fds[0].revents & POLLIN)
			recv_packet(fds[0].fd);

		if (fds[1].revents & POLLIN) {
			report_bw(fds[1].fd);
		}
	}

	close(timer_fd);
	close(sk_fd);
	return 0;

err:
	close(timer_fd);
	close(sk_fd);
	return 1;
}
