#include "wire.h"
#include "wire_fd.h"
#include "wire_pool.h"
#include "wire_stack.h"
#include "wire_io.h"
#include "macros.h"
#include "http_parser.h"

#define xlog(...)
#define DEBUG(...)

static wire_thread_t wire_thread_main;
static wire_t wire_accept;
static wire_pool_t web_pool;

#include <sched.h>
#include <stdio.h>
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

#include "libwire/test/utils.h"

#define IF_MODIFIED_SINCE_HDR "If-Modified-Since"
#define WEB_POOL_SIZE 8
#define MODULE_PREFIX "/module.php?module="
#define WR_BUF_LEN 1024

static wire_thread_t wire_thread_main;
static wire_t wire_accept;
static wire_pool_t web_pool;

struct web_data {
	int fd;
	bool should_close;
	bool next_hdr_val_if_modified_since;
	char if_modified_since[32];
	wire_fd_state_t fd_state;
	char url[255];
};

typedef struct wire_timer {
	int timerfd;
	wire_fd_state_t fd_state;
} wire_timer_t;

static bool timer_start(wire_timer_t *timer, int msecs)
{
	int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC|TFD_NONBLOCK);
	if (fd < 0) {
		perror("Failed to create a timerfd");
		return false;
	}

	struct itimerspec timer_val = {
		.it_value = { .tv_sec = msecs / 1000, .tv_nsec = (msecs % 1000) * 1000000}
	};

	int ret = timerfd_settime(fd, 0, &timer_val, NULL);
	if (ret < 0) {
		perror("Failed to set time on timerfd");
		close(fd);
		return false;
	}

	timer->timerfd = fd;

	wire_fd_mode_init(&timer->fd_state, fd);
	wire_fd_mode_read(&timer->fd_state);

	return true;
}

static void timer_stop(wire_timer_t *timer)
{
	wire_fd_mode_none(&timer->fd_state);
	close(timer->timerfd);
}

static bool timer_triggered(wire_timer_t *timer)
{
	return timer->fd_state.wait.triggered;
}

static void timer_list_chain(wire_timer_t *timer, wire_wait_list_t *list)
{
	wire_fd_wait_list_chain(list, &timer->fd_state);
}

static int buf_write(wire_fd_state_t *fd_state, const char *buf, int len)
{
	int sent = 0;
	do {
		int ret = write(fd_state->fd, buf + sent, len - sent);
		if (ret == 0)
			return -1;
		else if (ret > 0) {
			sent += ret;
			if (sent == len)
				return 0;
		} else {
			// Error
			if (errno == EINTR || errno == EAGAIN) {
				wire_fd_mode_write(fd_state);
				wire_fd_wait(fd_state);
				wire_fd_mode_none(fd_state);
			} else {
				xlog("Error while writing into socket %d: %m", fd_state->fd);
				return -1;
			}
		}
	} while (1);
}

static void error_generic(struct web_data *d, int code, const char *code_str, const char *body, int body_len) __attribute__((noinline));
static void error_generic(struct web_data *d, int code, const char *code_str, const char *body, int body_len)
{
	char buf[4096];
	int buf_len = snprintf(buf, sizeof(buf), "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %u\r\nConnection:close\r\n\r\n",
			code, code_str, body_len);

	d->should_close = true;

	if (buf_write(&d->fd_state, buf, buf_len) < 0)
		return;

	if (body_len > 0)
		buf_write(&d->fd_state, body, body_len);
}

#define STR_WITH_LEN(s) s, strlen(s)

static void error_not_found(struct web_data *d) __attribute__((noinline));
static void error_not_found(struct web_data *d)
{
	error_generic(d, 404, "Not Found", STR_WITH_LEN("File not found\n"));
}

static void error_internal(struct web_data *d, const char *msg, int msg_len) __attribute__((noinline));
static void error_internal(struct web_data *d, const char *msg, int msg_len)
{
	error_generic(d, 500, "Internal Failure", msg, msg_len);
}

static void error_invalid(struct web_data *d)
{
	error_generic(d, 405, "Internal Method", STR_WITH_LEN("Invalid method used"));
}

static bool send_header(http_parser *parser, int code, const char *code_msg, off_t file_size, const char *last_modified, const char *content_type) __attribute__((noinline));
static bool send_header(http_parser *parser, int code, const char *code_msg, off_t file_size, const char *last_modified, const char *content_type)
{
	char data[2048];
	struct web_data *d = parser->data;
	int buf_len;

	int http_major = 1;
	int http_minor = 1;

	if (http_major > parser->http_major) {
		http_major = parser->http_major;
		http_minor = parser->http_minor;
	} else if (http_major == parser->http_major && http_minor > parser->http_minor) {
		http_minor = parser->http_minor;
	}

	buf_len = snprintf(data, sizeof(data), "HTTP/%d.%d %d %s\r\n"
	                                       "Content-Type: %s\r\n"
	                                       "Content-Length: %u\r\n"
	                                       "Cache-Control: max_age=3600\r\n"
	                                       "Last-Modified: %s\r\n"
	                                       "%s"
	                                       "\r\n",
			http_major, http_minor,
			code, code_msg,
			content_type,
			(unsigned)file_size,
			last_modified,
			!http_should_keep_alive(parser) ? "Connection: close\r\n" : "");
	if (buf_len > (int)sizeof(data)) {
		error_internal(d, STR_WITH_LEN("Failed to prepare header buffer"));
		return false;
	}
	if (buf_write(&d->fd_state, data, buf_len) < 0)
		return false;
	return true;
}

static bool send_header_ok(http_parser *parser, off_t file_size, const char *last_modified, const char *content_type)
{
	return send_header(parser, 200, "OK", file_size, last_modified, content_type);
}

static bool send_header_unmodified(http_parser *parser, off_t file_size, const char *last_modified)
{
	return send_header(parser, 304, "Not Modified", file_size, last_modified, "text/plain");
}

static void send_cached_file(http_parser *parser, const char *last_modified, const char *content_type, const char *buf, off_t buf_len, bool only_head) __attribute__((noinline));
static void send_cached_file(http_parser *parser, const char *last_modified, const char *content_type, const char *buf, off_t buf_len, bool only_head)
{
	struct web_data *d = parser->data;

	if (!send_header_ok(parser, buf_len, last_modified, content_type))
		return;

	if (only_head)
		return;

	if (buf_write(&d->fd_state, buf, buf_len) < 0)
		return;
}

#define MOD_ERR(name, msg, ...) \
	snprintf(buf, WR_BUF_LEN, "{\"module\": \"" name "\", \"error\": \"" msg "\"}", ##__VA_ARGS__), strlen(buf)

#define MOD_OK(name, msg, ...) \
	snprintf(buf, WR_BUF_LEN, "{\"module\": \"" name "\", \"data\": " msg "}", ##__VA_ARGS__), strlen(buf)

#define MOD_OK_STR(name, msg, ...) \
	snprintf(buf, WR_BUF_LEN, "{\"module\": \"" name "\", \"data\": \"" msg "\"}", ##__VA_ARGS__), strlen(buf)

static off_t module_hostname(char *buf)
{
	struct utsname uts;
	int ret;

	ret = uname(&uts);
	if (ret < 0) {
		return MOD_ERR("hostname", "failed to do uname: %m");
	} else {
		return MOD_OK_STR("hostname", "%s", uts.nodename);
	}
}

static off_t module_uptime(char *buf)
{
	int fd = wio_open("/proc/uptime", O_RDONLY, 0);
	if (fd < 0) {
		return MOD_ERR("uptime", "failed to open /proc/uptime: %m");
	}

	char data[32];
	int ret = wio_pread(fd, data, sizeof(data), 0);
	if (ret < 0) {
		wio_close(fd);
		return MOD_ERR("uptime", "failed to read from /proc/uptime: %m");
	}

	wio_close(fd);

	int uptime = atoi(data);
	int days = uptime / (24 * 60*60);
	int hours = (uptime - days*24*60*60) / (60*60);
	int minutes = (uptime - days*24*60*60 - hours * 60*60) / 60;

	return MOD_OK_STR("uptime", "%d days %d hours %d minutes", days, hours, minutes);
}

static off_t module_issue(char *buf)
{
	return MOD_OK_STR("issue", "unknown OS");
}

static off_t module_time(char *buf)
{
	char data[32];
	time_t now = time(NULL);

	ctime_r(&now, data);
	data[strlen(data)-1] = 0;
	return MOD_OK_STR("time", "%s", data);
}

static int get_num_cores(void)
{
	cpu_set_t cpumask[128];
	CPU_ZERO_S(128, cpumask);
	sched_getaffinity(0, 128, cpumask);
	return CPU_COUNT_S(128, cpumask);
}

static off_t module_numcores(char *buf)
{
	int num_cores = get_num_cores();
	return MOD_OK("numberofcores", "%d", num_cores);
}

static off_t module_loadavg(char *buf)
{
	int num_cores = get_num_cores();
	double loadavg[3];
	int ret = getloadavg(loadavg, 3);
	if (ret < 0) {
		return MOD_ERR("loadavg", "Failed to read load average: %m");
	}

	float min1_frac = loadavg[0];
	int min1_pcnt = min1_frac * 100.0 / num_cores;
	float min5_frac = loadavg[1];
	int min5_pcnt = min5_frac * 100.0 / num_cores;
	float min15_frac = loadavg[2];
	int min15_pcnt = min15_frac * 100.0 / num_cores;
	return MOD_OK("loadavg", "[[\"%.02f\", %d], [\"%.02f\", %d], [\"%.02f\", %d]]", min1_frac, min1_pcnt, min5_frac, min5_pcnt, min15_frac, min15_pcnt);
}

static off_t module_mem(char *buf)
{
	int fd = wio_open("/proc/meminfo", O_RDONLY, 0);
	if (fd < 0) {
		return MOD_ERR("mem", "Failed to open /proc/meminfo: %m");
	}

	char data[2048];
	int ret = wio_pread(fd, data, sizeof(data), 0);
	if (ret < 0) {
		wio_close(fd);
		return MOD_ERR("mem", "Failed to read from /proc/meminfo: %m");
	}

	wio_close(fd);

	// Parse the file now
	int mem_total = 0;
	int mem_free = 0;
	int mem_buffers = 0;
	int mem_cached = 0;

	char *start = data;
	char *end = data + ret;
	while (start && start < end) {
		char *name_end = memchr(start, ':', ret - (start - data));
		if (name_end == NULL)
			break;

		if (memcmp(start, "MemTotal", name_end - start) == 0) {
			mem_total = atoi(name_end+1);
		} else if (memcmp(start, "MemFree", name_end - start) == 0) {
			mem_free = atoi(name_end+1);
		} else if (memcmp(start, "Buffers", name_end - start) == 0) {
			mem_buffers = atoi(name_end+1);
		} else if (memcmp(start, "Cached", name_end - start) == 0) {
			mem_cached = atoi(name_end+1);
		}

		if (mem_total && mem_free && mem_buffers && mem_cached) {
			// We got everything we want, we can short circuit the rest of the parsing
			break;
		}

		start = memchr(name_end, '\n', ret - (name_end - data));
		if (start) {
			// Skip the \n to the start of the next line
			start++;
		}
	}

	mem_free += mem_buffers + mem_cached;
	int mem_used = mem_total - mem_free;
	return MOD_OK("mem", "[\"Mem:\",\"%d\",\"%d\",\"%d\"]", mem_total/1024, mem_used/1024, mem_free/1024);
}

struct modules {
	const char *name;
	off_t (*func)(char *buf);
} modules[] = {
	{"hostname", module_hostname},
	{"uptime", module_uptime},
	{"issue", module_issue},
	{"time", module_time},
	{"loadavg", module_loadavg},
	{"numberofcores", module_numcores},
	{"mem", module_mem},
};

#include "web.h"
static const char *request_get(const char *filename, off_t *buf_len, const char **last_modified, const char **content_type, char *wrbuf)
{
	unsigned i;

	if (strcmp(filename, "/") == 0)
		filename = "/index.html";

	for (i = 0; i < sizeof(static_paths)/sizeof(static_paths[0]); i++) {
		struct static_paths *spath = &static_paths[i];
		if (strncmp(filename, spath->web_path, strlen(spath->web_path)) == 0) {
			*buf_len = spath->len;
			*last_modified = spath->last_modified;
			*content_type = spath->content_type;
			return *spath->content;
		}
	}

	// What's left is only the monitoring modules
	if (strncmp(filename, MODULE_PREFIX, strlen(MODULE_PREFIX)) != 0)
		return NULL;

	for (i = 0; i < sizeof(modules)/sizeof(modules[0]); i++) {
		const struct modules *mod = &modules[i];
		if (strcmp(mod->name, filename + strlen(MODULE_PREFIX)) == 0) {
			*last_modified = "";
			*buf_len = mod->func(wrbuf);
			*content_type = "text/json";
			return wrbuf;
		}
	}

	return NULL;
}

static int on_message_complete(http_parser *parser)
{
	DEBUG("message complete");
	struct web_data *d = parser->data;
	const char *filename = d->url;
	off_t buf_len;
	const char *last_modified;
	const char *content_type;

	if (!http_should_keep_alive(parser))
		d->should_close = true;

	if (parser->method != HTTP_GET && parser->method != HTTP_HEAD) {
		error_invalid(d);
		return -1;
	}

	bool only_head = parser->method == HTTP_HEAD;

	char wrbuf[WR_BUF_LEN];
	const char *buf = request_get(filename, &buf_len, &last_modified, &content_type, wrbuf);

	DEBUG("If modified since is '%s' last modified is '%s'", d->if_modified_since, last_modified);
	if (buf && d->if_modified_since[0] && strcmp(d->if_modified_since, last_modified) == 0) {
		DEBUG("Not modified");
		if (!send_header_unmodified(parser, buf_len, last_modified)) {
			d->should_close = true;
			return -1;
		}
		return 0;
	}

	if (buf) {
		// File in cache, send from buffer
		send_cached_file(parser, last_modified, content_type, buf, buf_len, only_head);
	} else {
		error_not_found(d);
	}

	return -1;
}

static int on_url(http_parser *parser, const char *at, size_t length)
{
	UNUSED(parser);
	DEBUG("URL: %.*s", (int)length, at);
	struct web_data *d = parser->data;

	if (length == 0) {
		xlog("URL length cannot be zero");
		error_internal(d, STR_WITH_LEN("zero sized url\n"));
		return -1;
	}

	if (length > sizeof(d->url)) {
		xlog("Error while handling url, it's length is %u and the max length is %u", length, sizeof(d->url));
		error_internal(d, STR_WITH_LEN("url too long\n"));
		return -1;
	}

	memcpy(d->url, at, length);
	d->url[length] = 0;

	return 0;
}

static int on_header_field(http_parser *parser, const char *at, size_t length)
{
	struct web_data *d = parser->data;
	if (length == strlen(IF_MODIFIED_SINCE_HDR) && memcmp(at, IF_MODIFIED_SINCE_HDR, strlen(IF_MODIFIED_SINCE_HDR)) == 0) {
		d->next_hdr_val_if_modified_since = true;
		DEBUG("Got If-Modified-Since header");
	} else {
		d->next_hdr_val_if_modified_since = false;
	}
	return 0;
}

static int on_header_value(http_parser *parser, const char *at, size_t length)
{
	struct web_data *d = parser->data;
	if (d->next_hdr_val_if_modified_since) {
		DEBUG("Parsing If-Modified-Since string '%.*s'", length, at);

		int cur_len = strlen(d->if_modified_since);
		if (cur_len + length > sizeof(d->if_modified_since) - 1) {
			d->if_modified_since[0] = 0;
			d->next_hdr_val_if_modified_since = false;
			DEBUG("Too long if-modified-since header, ignoring it");
		} else {
			memcpy(d->if_modified_since + cur_len, at, length);
			d->if_modified_since[cur_len + length] = 0;
			DEBUG("If-Modified-Since is now %.*s", cur_len + length, d->if_modified_since);
		}
	}
	return 0;
}

static const struct http_parser_settings parser_settings = {
	.on_message_complete = on_message_complete,
	.on_url = on_url,
	.on_header_field = on_header_field,
	.on_header_value = on_header_value,
};

static void web_run(void *arg)
{
	struct web_data d = {
		.fd = (long int)arg,
	};
	http_parser parser;
	wire_timer_t timer;

	wire_fd_mode_init(&d.fd_state, d.fd);

	set_nonblock(d.fd);

	http_parser_init(&parser, HTTP_REQUEST);
	parser.data = &d;

	char buf[4096];
	bool bail_out = false;
	bool timer_stopped = true;
	do {
		if (timer_stopped) {
			timer_start(&timer, 10*1000);
			timer_stopped = false;
		}
		buf[0] = 0;
		int received = read(d.fd, buf, sizeof(buf));
		DEBUG("Received: %d %d", received, errno);
		if (received == 0) {
			/* Fall-through, tell parser about EOF */
			DEBUG("Received EOF");
		} else if (received < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				DEBUG("Waiting");
				/* Nothing received yet, wait for it */
				wire_fd_mode_read(&d.fd_state);

				wire_wait_list_t wait_list;
				wire_wait_list_init(&wait_list);
				wire_fd_wait_list_chain(&wait_list, &d.fd_state);
				timer_list_chain(&timer, &wait_list);
				wire_list_wait(&wait_list);

				DEBUG("Done waiting");
				if (!timer_triggered(&timer))
					continue;
			} else {
				DEBUG("Error receiving from socket %d: %m", d.fd);
				bail_out = true;
			}
		}

		timer_stop(&timer);
		timer_stopped = true;
		wire_fd_mode_none(&d.fd_state);

		if (bail_out)
			break;

		DEBUG("Processing %d", (int)received);
		size_t processed = http_parser_execute(&parser, &parser_settings, buf, received);
		if (parser.upgrade) {
			/* Upgrade not supported yet */
			xlog("Upgrade no supported, bailing out");
			break;
		} else if (received == 0) {
			// At EOF, exit now
			DEBUG("Received EOF");
			break;
		} else if (processed != (size_t)received) {
			// Error in parsing
			xlog("Not everything was parsed, error is likely, bailing out.");
			break;
		} else if (d.should_close) {
			DEBUG("Closing as requested");
			break;
		}
	} while (1);

	close(d.fd);
	DEBUG("Disconnected %d", d.fd);
}

static void accept_run(void *arg)
{
	UNUSED(arg);
	int port = 9090;
	int fd = socket_setup(port);
	if (fd < 0)
		return;

	xlog("Listening on port %d", port);

	wire_fd_state_t fd_state;
	wire_fd_mode_init(&fd_state, fd);
	wire_fd_mode_read(&fd_state);

	/* To be as fast as possible we want to accept all pending connections
	 * without waiting in between, the throttling will happen by either there
	 * being no more pending listeners to accept or by the wire pool blocking
	 * when it is exhausted.
	 */
	while (1) {
		int new_fd = accept(fd, NULL, NULL);
		if (new_fd >= 0) {
			DEBUG("New connection: %d", new_fd);
			char name[32];
			snprintf(name, sizeof(name), "web %d", new_fd);
			wire_t *task = wire_pool_alloc_block(&web_pool, name, web_run, (void*)(long int)new_fd);
			if (!task) {
				xlog("Web server is busy, sorry");
				close(new_fd);
			}
		} else {
			if (errno == EINTR || errno == EAGAIN) {
				/* Wait for the next connection */
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
	wire_io_init(8);
	wire_pool_init(&web_pool, NULL, WEB_POOL_SIZE, 4*4096);
	wire_init(&wire_accept, "accept", accept_run, NULL, WIRE_STACK_ALLOC(4096));
	wire_thread_run();
	return 0;
}
