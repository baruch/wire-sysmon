#ifndef SYSMON_ICMP_PING_H
#define SYSMON_ICMP_PING_H

#include "list.h"
#include "wire_wait.h"
#include "wire_timeout.h"

#include <stdint.h>
#include <netinet/in.h>
#include <time.h>

typedef struct {
	struct list_head list;
	uint16_t id;
	uint16_t seq;
	wire_wait_t wait;
	struct timespec end_time;
} icmp_ping_state_t;

int icmp_ping_init(void);
void icmp_ping_state_init(icmp_ping_state_t *state);
void icmp_ping_state_release(icmp_ping_state_t *state);

int icmp_ping_ipv4(struct sockaddr_in *addr, icmp_ping_state_t *state, double *rtt, wire_timeout_t *tout);

int icmp_ping_ipv4_simple(struct sockaddr_in *addr, int *num_pings, double *min_rtt, double *avg_rtt, double *max_rtt);

#endif
