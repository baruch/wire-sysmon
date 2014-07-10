#include "wire.h"
#include "wire_fd.h"
#include "wire_pool.h"
#include "wire_stack.h"
#include "wire_io.h"
#include "wire_net.h"
#include "macros.h"
#include "http_parser.h"

#define DEBUG(...)

static wire_thread_t wire_thread_main;
static wire_t wire_accept_tcp;
static wire_pool_t tcp_pool;

#define TCP_POOL_SIZE 256

#include <sched.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <memory.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <sys/timerfd.h>
#include <time.h>
#include <sys/utsname.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "libwire/test/utils.h"

struct tcp_sock_info {
	socklen_t addrlen;
	struct sockaddr_in remote_addr;
	int fd;
};

#pragma pack(1)
struct msg_init {
	uint32_t version;
	uint32_t random;
	uint16_t port;
};

struct msg_result {
	uint64_t nsec;
};

struct msg_udp {
	uint32_t version;
	uint32_t random;
	uint32_t id;
};
#pragma pack()

static void xlog(const char *msg, ...)
{
	va_list ap;
	char buf[128];
	int n;

	va_start(ap, msg);
	n = vsnprintf(buf, sizeof(buf), msg, ap);
	va_end(ap);

	if (n > (int)sizeof(buf)-2)
		n = sizeof(buf)-2;
	buf[n] = '\n';
	buf[n+1] = 0;

	wio_write(2, buf, n+2); // Log to stderr
}

static int setup_udp_socket(uint16_t *port)
{
	int udp_fd = socket(AF_INET, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;

	int ret = bind(udp_fd, (struct sockaddr*)&addr, sizeof(addr));
	if (ret < 0) {
		xlog("Failed to bind to socket");
		wio_close(udp_fd);
		return -1;
	}

	socklen_t len = sizeof(addr);
	ret = getsockname(udp_fd, (struct sockaddr*)&addr, &len);
	if (ret < 0) {
		xlog("Failed to get socket port");
		wio_close(udp_fd);
		return -1;
	}

	*port = addr.sin_port;
	return udp_fd;
}

static int recv_udp(wire_fd_state_t *udp_state, wire_net_t *tcp_net, struct msg_udp *msg_udp, struct timespec *recv_time, struct sockaddr_in *remote)
{
	struct sockaddr_in remote_addr;
	socklen_t addrlen;
	int ret;

	do {
		ret = wire_timeout_wait(&udp_state->wait, &tcp_net->tout);
		clock_gettime(CLOCK_MONOTONIC, recv_time);
		if (ret != 1)
			return -1;
		addrlen = sizeof(remote_addr);
		ret = recvfrom(udp_state->fd, msg_udp, sizeof(*msg_udp), 0, &remote_addr, &addrlen);
		if (memcmp(&remote_addr, remote, sizeof(*remote)) != 0) {
			xlog("Remote address didn't match");
			return -1;
		}
	} while (ret < 0);

	return ret;
}

static void tcp_run(void *arg)
{
	struct tcp_sock_info *info = arg;
	int fd = info->fd;
	struct msg_init msg_init;
	struct msg_result msg_result;
	struct msg_udp msg_udp;
	wire_net_t net;
	size_t sent;
	int ret;
	struct sockaddr_in remote_addr = info->remote_addr;
	socklen_t addrlen = info->addrlen;
	wire_fd_state_t udp_state;
	struct timespec first_recv, second_recv;
	int udp_fd;

	udp_fd = setup_udp_socket(&msg_init.port);
	if (udp_fd < 0) {
		xlog("Setting up UDP socket failed");
		wio_close(fd);
		return;
	}

	wire_net_init(&net, fd);
	wire_timeout_reset(&net.tout, 5*1000);
	wire_fd_mode_init(&udp_state, udp_fd);

	msg_init.version = 1;
	msg_init.random = ((uint32_t)(long int)&msg_init) ^ time(NULL);

	ret = wire_net_write(&net, &msg_init, sizeof(msg_init), &sent);
	if (ret < 0 || sent != sizeof(msg_init)) {
		xlog("Failed to send UDP port to client");
		goto Exit;
	}

	// Wait for two packets on the UDP
	wire_fd_mode_read(&udp_state);
	if (recv_udp(&udp_state, &net, &msg_udp, &first_recv, &remote_addr) < 0)
		goto Exit;
	if (recv_udp(&udp_state, &net, &msg_udp, &second_recv, &remote_addr) < 0)
		goto Exit;

	// Send back timing on the TCP socket to let user calculate upload
	msg_result.nsec = (second_recv.tv_sec - first_recv.tv_sec) * 1000000000LL + (second_recv.tv_nsec - first_recv.tv_nsec);
	ret = wire_net_write(&net, &msg_result, sizeof(msg_result), &sent);
	if (ret < 0 || sent != sizeof(msg_result)) {
		xlog("Failed to send data on TCP socket");
		goto Exit;
	}

	// Send two packets on the UDP socket back to let user calculate download
	memset(&msg_udp, 0, sizeof(msg_udp));
	msg_udp.version = 1;
	msg_udp.random = msg_init.random;
	msg_udp.id = 0;
	ret = sendto(udp_fd, &msg_udp, sizeof(msg_udp), 0, (struct sockaddr*)&remote_addr, addrlen);
	if (ret < 0)
		xlog("Failed to send first UDP packet: %m");
	msg_udp.id = 1;
	ret = sendto(udp_fd, &msg_udp, sizeof(msg_udp), 0, (struct sockaddr*)&remote_addr, addrlen);
	if (ret < 0)
		xlog("Failed to send second UDP packet: %m");

Exit:
	wio_close(udp_fd);
	wio_close(fd);
}

static void tcp_accept_run(void *arg)
{
	UNUSED(arg);
	int port = 3030;
	int fd = socket_setup(port);
	if (fd < 0)
		return;

	xlog("Listening on port %d", port);

	wire_fd_state_t fd_state;
	wire_fd_mode_init(&fd_state, fd);

	/* To be as fast as possible we want to accept all pending connections
	 * without waiting in between, the throttling will happen by either there
	 * being no more pending listeners to accept or by the wire pool blocking
	 * when it is exhausted.
	 */
	while (1) {
		struct tcp_sock_info info;
		info.addrlen = sizeof(info.remote_addr);
		info.fd = accept(fd, &info.remote_addr, &info.addrlen);
		if (info.fd >= 0) {
			DEBUG("New connection: %d", info.fd);
			char name[32];
			snprintf(name, sizeof(name), "web %d", info.fd);
			wire_t *task = wire_pool_alloc_block(&tcp_pool, name, tcp_run, &info);
			if (task) {
				// Let the wire copy the data in the tcp_sock_info info variable
				wire_yield();
			} else {
				xlog("Web server is busy, sorry");
				close(info.fd);
			}
		} else {
			if (errno == EINTR || errno == EAGAIN) {
				/* Wait for the next connection */
				wire_fd_mode_read(&fd_state);
				wire_fd_wait(&fd_state);
			} else {
				xlog("Error accepting from listening socket: %m");
				break;
			}
		}
	}
}

int main()
{
	wire_thread_init(&wire_thread_main);
	wire_stack_fault_detector_install();
	wire_fd_init();
	wire_io_init(1);
	wire_pool_init(&tcp_pool, NULL, TCP_POOL_SIZE, 4096);
	wire_init(&wire_accept_tcp, "accept tcp", tcp_accept_run, NULL, WIRE_STACK_ALLOC(4096));
	wire_thread_run();
	return 0;
}
