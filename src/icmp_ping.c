#include "icmp_ping.h"

#include "wire.h"
#include "wire_stack.h"
#include "wire_log.h"
#include "wire_io.h"

#include <errno.h>
#include <netinet/ip_icmp.h>
#include <memory.h>

static wire_t icmp_rcv;
static uint16_t next_ping_id;
static struct list_head ping_list;
static wire_fd_state_t fd_state;
static int icmp_ping_initialized;

static icmp_ping_state_t *find_by_icmp_id_and_seq(uint16_t id, uint16_t seq)
{
	struct list_head *cur = ping_list.next;

	for (cur = ping_list.next; cur != &ping_list; cur = cur->next) {
		icmp_ping_state_t *ping_state = list_entry(cur, icmp_ping_state_t, list);
		if (ping_state->id == id) {
			if (ping_state->seq == seq)
				return ping_state;
			else
				return NULL;
		}
	}

	return NULL;
}

static void icmp_rcv_wire(void *arg)
{
	UNUSED(arg);

	char buf[2048];
	struct icmp *icmppkt;
	struct sockaddr_in from;
	socklen_t fromlen;
	struct timespec end_time;
	int max_consecutive;

	while (1) {
		if (--max_consecutive == 0) {
			// Do not hog the CPU
			wire_yield();
			max_consecutive = 20; // Reduced rate for repeat offense
		}

		fromlen = sizeof(from);
		int ret = recvfrom(fd_state.fd, buf, sizeof(buf), 0, &from, &fromlen);

		if (ret < 0) {
			if (errno != EINTR && errno != EAGAIN) {
				wire_log(WLOG_CRITICAL, "Unexpected error while receving from icmp socket: %m (%d)", errno);
				break;
			}
			max_consecutive = 100;
			wire_fd_mode_read(&fd_state);
			wire_fd_wait(&fd_state);
			continue;
		}

		clock_gettime(CLOCK_MONOTONIC, &end_time);

		if (fromlen != sizeof(from)) {
			wire_log(WLOG_WARNING, "Returned fromlen is unexpected (got %d expected %d)", fromlen, sizeof(from));
			continue;
		}

		// Validate IPv4

		// Validate ICMP
		icmppkt = (struct icmp *)(buf + sizeof(struct ip));
		if (icmppkt->icmp_type != ICMP_ECHOREPLY) {
			wire_log(WLOG_WARNING, "Got a non-reply ICMP message type=%d", icmppkt->icmp_type);
			continue;
		}

		icmp_ping_state_t *icmp_state = find_by_icmp_id_and_seq(ntohs(icmppkt->icmp_id), ntohs(icmppkt->icmp_seq));
		if (icmp_state) {
			icmp_state->end_time = end_time;
			wire_wait_resume(&icmp_state->wait);
		} else {
			wire_log(WLOG_DEBUG, "Couldnt find reply for id %u and seq %u", ntohs(icmppkt->icmp_id), ntohs(icmppkt->icmp_seq));
		}
	}

	wire_fd_mode_none(&fd_state);
	wio_close(fd_state.fd);
	wire_log(WLOG_CRITICAL, "icmp_rcv_wire bailed out");
}

int icmp_ping_init(void)
{
	struct timeval tv;
	int sfd = socket(AF_INET, SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC, IPPROTO_ICMP);
	if (sfd < 0)
		return -1;

	// In the receive part we want immediate receive
	tv.tv_sec = 0;
	tv.tv_usec = 10;
	setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	wire_fd_mode_init(&fd_state, sfd);

	list_head_init(&ping_list);
	wire_init(&icmp_rcv, "icmp receiver", icmp_rcv_wire, NULL, WIRE_STACK_ALLOC(20*4096));
	icmp_ping_initialized = 1;
	return 0;
}

static int ping_id_in_use(uint16_t ping_id)
{
	struct list_head *cur = ping_list.next;

	for (cur = ping_list.next; cur != &ping_list; cur = cur->next) {
		icmp_ping_state_t *ping_state = list_entry(cur, icmp_ping_state_t, list);
		if (ping_id == ping_state->id)
			return 1;
	}

	return 0;
}

void icmp_ping_state_init(icmp_ping_state_t *state)
{
	// TODO: Handle the case that all ping ids are in use (rather unlikely!)
	int i;

	for (i = 0; i < 16; i++) {
		if (!ping_id_in_use(next_ping_id))
			break;
		else
			next_ping_id++;
	}

	state->id = next_ping_id++;
	state->seq = 0;
	wire_wait_init(&state->wait);
	list_add_tail(&state->list, &ping_list);
}

void icmp_ping_state_release(icmp_ping_state_t *state)
{
	list_del(&state->list);
}

static int inet_cksum(uint16_t *addr, int len)
{
    register int nleft = len;
    register u_short *w = addr;
    register u_short answer;
    register u_int sum = 0;
    uint16_t odd_byte = 0;

    /*
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while( nleft > 1 )  {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if( nleft == 1 ) {
        *(u_char *)(&odd_byte) = *(u_char *)w;
        sum += odd_byte;
    }

    /*
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0x0000ffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);                     /* add carry */
    answer = ~sum;                          /* truncate to 16 bits */
    return (answer);
}

int icmp_ping_ipv4(struct sockaddr_in *addr, icmp_ping_state_t *state, double *rtt, wire_timeout_t *tout)
{
	if (!icmp_ping_initialized)
		return -1;

	struct icmp icmppkt;
	struct timespec start_time;
	int ret;

	memset(&icmppkt, 0, sizeof(icmppkt));

	wire_log(WLOG_DEBUG, "Sending ping to %08x id %d seq %d", addr->sin_addr.s_addr, state->id, state->seq);

	icmppkt.icmp_type = ICMP_ECHO;
	icmppkt.icmp_code = 0;
	icmppkt.icmp_cksum = 0;
	icmppkt.icmp_seq = ntohs(++state->seq);
	icmppkt.icmp_id = ntohs(state->id);

	icmppkt.icmp_cksum = inet_cksum((void*)&icmppkt, sizeof(icmppkt));

	state->end_time.tv_sec = 0;
	state->end_time.tv_nsec = 0;

	clock_gettime(CLOCK_MONOTONIC, &start_time);
	ret = sendto(fd_state.fd, &icmppkt, sizeof(icmppkt), 0, addr, sizeof(*addr));
	if (ret < 0)
		return -1;

	wire_timeout_wait(&state->wait, tout);

	if (state->end_time.tv_sec || state->end_time.tv_nsec) {
		*rtt = (state->end_time.tv_sec - start_time.tv_sec) + (state->end_time.tv_nsec - start_time.tv_nsec) / 1E9;
		return 0;
	}

	return -1;
}

int icmp_ping_ipv4_simple(struct sockaddr_in *addr, int *num_pings, double *min_rtt, double *avg_rtt, double *max_rtt)
{
	int count = 0;
	int i;
	double sum_rtt = 0.0;
	icmp_ping_state_t state;
	wire_timeout_t tout;

	if (!icmp_ping_initialized)
		return -1;

	wire_log(WLOG_DEBUG, "pinging host %08x", addr->sin_addr.s_addr);

	icmp_ping_state_init(&state);
	wire_timeout_init(&tout);

	for (i = 0; i < *num_pings; i++) {
		double rtt;

		wire_timeout_reset(&tout, 1000);
		int ret = icmp_ping_ipv4(addr, &state, &rtt, &tout);
		if (ret == 0) {
			count++;
			if (min_rtt && *min_rtt > rtt)
				*min_rtt = rtt;
			if (max_rtt && *max_rtt < rtt)
				*max_rtt = rtt;
			sum_rtt += rtt;
		}
	}

	icmp_ping_state_release(&state);
	wire_timeout_stop(&tout);

	*num_pings = count;

	if (count > 0) {
		if (avg_rtt)
			*avg_rtt = sum_rtt/count;
		return 0;
	}

	return -1;
}
