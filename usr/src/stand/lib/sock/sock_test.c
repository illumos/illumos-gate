/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * sock_test.c.  Implementing a CLI for inetboot testing.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include "socket_impl.h"
#include "socket_inet.h"
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <netinet/in_systm.h>
#include <sys/promif.h>
#include <sys/salib.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include "tcp_inet.h"
#include "ipv4.h"
#include <netinet/tcp.h>

static int atoi(const char *);
static int st_accept(void);
static int st_bind(void);
static int st_connect(void);
static int st_echo(void);
static int st_getsockname(void);
static int st_getsockopt(void);
static int st_get_addr_and_port(in_addr_t *, unsigned short *);
static int st_get_buf_and_cnt(char **, int *);
static int st_listen(void);
static int st_match_option(char *, int *, int *);
static int st_send(void);
static int st_sendto(void);
static int st_recv(void);
static int st_recvfrom(void);
static int st_set_addr(void);
static int st_set_netmask(void);
static int st_set_router(void);
static int st_setsockopt(void);
static int st_socket(void);
static int st_sock_close(void);
static int st_tcp_tw_report(void);
static int st_toggle_promiscuous(void);
static int st_use_obp(void);

/* Wrapper for socket calls. */
static int st_local_accept(int, struct sockaddr *, socklen_t *);
static int st_local_bind(int, const struct sockaddr *, socklen_t);
static int st_local_connect(int,  const  struct  sockaddr  *, socklen_t);
static int st_local_getsockname(int, struct sockaddr *, socklen_t *);
static int st_local_getsockopt(int, int, int, void *, socklen_t *);
static int st_local_listen(int, int);
static int st_local_recv(int, void *, size_t, int);
static int st_local_recvfrom(int, void *, size_t, int, struct sockaddr *,
	socklen_t *);
static int st_local_send(int, const void *, size_t, int);
static int st_local_sendto(int, const void *, size_t, int,
	const struct sockaddr *, socklen_t);
static int st_local_setsockopt(int, int, int, const void *, socklen_t);
static int st_local_socket(int, int, int);
static int st_local_socket_close(int);

struct sock_test_cmd_s {
	char *st_cmd;
	int (*st_fn)(void);
};

static struct sock_test_cmd_s st_cmds[] = {
	{ "set_addr", st_set_addr},
	{ "set_netmask", st_set_netmask},
	{ "set_router", st_set_router},
	{ "socket", st_socket },
	{ "bind", st_bind },
	{ "accept", st_accept },
	{ "connect", st_connect },
	{ "listen", st_listen },
	{ "send", st_send },
	{ "sendto", st_sendto },
	{ "recv", st_recv },
	{ "recvfrom", st_recvfrom },
	{ "setsockopt", st_setsockopt },
	{ "getsockopt", st_getsockopt },
	{ "getsockname", st_getsockname },
	{ "close", st_sock_close },
	{ "echo", st_echo },
	{ "toggle_promiscous", st_toggle_promiscuous},
	{ "use_obp", st_use_obp},
	{ "tcp_tw_report", st_tcp_tw_report},
	{ NULL, NULL }
};

struct so_option_string_s {
	char *so_name;
	int so_opt;
	int so_opt_level;
} so_option_array[] = {
	{ "rcvtimeo", SO_RCVTIMEO, SOL_SOCKET },
	{ "dontroute", SO_DONTROUTE, SOL_SOCKET },
	{ "reuseaddr", SO_REUSEADDR, SOL_SOCKET },
	{ "rcvbuf", SO_RCVBUF, SOL_SOCKET },
	{ "sndbuf", SO_SNDBUF, SOL_SOCKET },
	{ NULL, 0 }
};

#define	NO_OPENED_SOCKET	-1

/* Right now, we only allow one socket at one time. */
static int g_sock_fd = NO_OPENED_SOCKET;
static int save_g_sock_fd = NO_OPENED_SOCKET;

/* Boolean to decide if OBP network routines should be used. */
static boolean_t use_obp = B_FALSE;


/*
 * The following routines are wrappers for the real socket routines.  The
 * boolean use_obp is used to decide whether the real socket routines is
 * called or the "equivalent" OBP provided routines should be called.
 */
static int
st_local_socket(int domain, int type, int protocol)
{
	if (!use_obp) {
		return (socket(domain, type, protocol));
	} else {
		return (0);
	}
}

static int
st_local_socket_close(int sd)
{
	if (!use_obp) {
		return (socket_close(sd));
	} else {
		return (0);
	}
}

static int
st_local_accept(int sd, struct sockaddr *addr, socklen_t *addr_len)
{
	if (!use_obp) {
		return (accept(sd, addr, addr_len));
	} else {
		return (0);
	}
}

static int
st_local_bind(int sd, const struct sockaddr *name, socklen_t namelen)
{
	if (!use_obp) {
		return (bind(sd, name, namelen));
	} else {
		return (0);
	}
}

static int
st_local_connect(int sd,  const struct sockaddr *addr, socklen_t addr_len)
{
	if (!use_obp) {
		return (connect(sd, addr, addr_len));
	} else {
		return (0);
	}
}

static int
st_local_listen(int sd,  int backlog)
{
	if (!use_obp) {
		return (listen(sd, backlog));
	} else {
		return (0);
	}
}

static int
st_local_send(int sd, const void *msg, size_t len, int flags)
{
	if (!use_obp) {
		return (send(sd, msg, len, flags));
	} else {
		return (0);
	}
}

static int
st_local_sendto(int sd, const void *msg, size_t len, int flags,
    const struct sockaddr *to, socklen_t tolen)
{
	if (!use_obp) {
		return (sendto(sd, msg, len, flags, to, tolen));
	} else {
		return (0);
	}
}

static int
st_local_recv(int sd, void *buf, size_t len, int flags)
{
	if (!use_obp) {
		return (recv(sd, buf, len, flags));
	} else {
		return (0);
	}
}

static int
st_local_recvfrom(int sd, void *buf, size_t len, int flags,
    struct sockaddr *from, socklen_t *fromlen)
{
	if (!use_obp) {
		return (recvfrom(sd, buf, len, flags, from, fromlen));
	} else {
		return (0);
	}
}

static int
st_local_getsockname(int sd, struct sockaddr *name, socklen_t *namelen)
{
	if (!use_obp) {
		return (getsockname(sd, name, namelen));
	} else {
		return (0);
	}
}


static int
st_local_getsockopt(int sd, int level, int option, void *optval,
    socklen_t *optlen)
{
	if (!use_obp) {
		return (getsockopt(sd, level, option, optval, optlen));
	} else {
		return (0);
	}
}

static int
st_local_setsockopt(int sd, int level, int option, const void *optval,
    socklen_t optlen)
{
	if (!use_obp) {
		return (setsockopt(sd, level, option, optval, optlen));
	} else {
		return (0);
	}
}

static int
atoi(const char *p)
{
	int n;
	int c = *p++, neg = 0;

	while (isspace(c)) {
		c = *p++;
	}
	if (!isdigit(c)) {
		switch (c) {
		case '-':
			neg++;
			/* FALLTHROUGH */
		case '+':
			c = *p++;
		}
	}
	for (n = 0; isdigit(c); c = *p++) {
		n *= 10; /* two steps to avoid unnecessary overflow */
		n += '0' - c; /* accum neg to avoid surprises at MAX */
	}
	return (neg ? n : -n);
}

int
st_interpret(char *buf)
{
	char *cmd;
	int i;

	if ((cmd = strtok(buf, " ")) == NULL)
		return (-1);

	for (i = 0; st_cmds[i].st_cmd != NULL; i++) {
		if (strcmp(cmd, st_cmds[i].st_cmd) == 0) {
			return (st_cmds[i].st_fn());
		}
	}
	printf("! Unknown command: %s\n", cmd);
	return (-1);
}


static int
st_socket(void)
{
	char *type;

	if ((type = strtok(NULL, " ")) == NULL) {
		printf("! usage: socket type\n");
		return (-1);
	}
	if (g_sock_fd != NO_OPENED_SOCKET) {
		printf("! Cannot open more than 1 socket\n");
		return (-1);
	}

	if (strcmp(type, "stream") == 0) {
		if ((g_sock_fd = st_local_socket(AF_INET, SOCK_STREAM,
		    0)) < 0) {
			printf("! Error in opening TCP socket: %d\n", errno);
			return (-1);
		} else {
			printf("@ TCP socket opened\n");
		}
	} else if (strcmp(type, "dgram") == 0) {
		if ((g_sock_fd = st_local_socket(AF_INET, SOCK_DGRAM,
		    0)) < 0) {
			printf("! Error in opening UDP socket: %d\n", errno);
			return (-1);
		} else {
			printf("@ UDP socket opened\n");
		}
	} else if (strcmp(type, "raw") == 0) {
		if ((g_sock_fd = st_local_socket(AF_INET, SOCK_RAW, 0)) < 0) {
			printf("! Error in opening RAW socket: %d\n", errno);
			return (-1);
		} else {
			printf("@ RAW socket opened\n");
		}
	} else {
		printf("! Unknown socket type: %s\n", type);
		return (-1);
	}

	return (0);
}

static int
st_set_addr(void)
{
	char *tmp;
	struct in_addr addr;

	tmp = strtok(NULL, " ");
	if (tmp == NULL) {
		printf("! No address given\n");
		return (-1);
	}
	if ((addr.s_addr = inet_addr(tmp)) == (uint32_t)-1) {
		printf("! Malformed address\n");
		return (-1);
	}

	ipv4_setipaddr(&addr);
	printf("@ IP address %s set\n", inet_ntoa(addr));

	return (0);
}

static int
st_set_netmask(void)
{
	char *tmp;
	struct in_addr addr;

	tmp = strtok(NULL, " ");
	if (tmp == NULL) {
		printf("! No netmask given\n");
		return (-1);
	}
	if ((addr.s_addr = inet_addr(tmp)) == (uint32_t)-1) {
		printf("! Malformed netmask\n");
		return (-1);
	}

	ipv4_setnetmask(&addr);
	printf("@ Netmask %s set\n", inet_ntoa(addr));

	return (0);
}

static int
st_set_router(void)
{
	char *tmp;
	struct in_addr addr;

	tmp = strtok(NULL, " ");
	if (tmp == NULL) {
		printf("! No router address given\n");
		return (-1);
	}
	if ((addr.s_addr = inet_addr(tmp)) == (uint32_t)-1) {
		printf("! Malformed router address\n");
		return (-1);
	}

	ipv4_setdefaultrouter(&addr);
	if (ipv4_route(IPV4_ADD_ROUTE, RT_DEFAULT, NULL, &addr) < 0) {
		printf("! Cannot add default route\n");
	} else {
		printf("@ Default router %s set\n", inet_ntoa(addr));
	}

	return (0);
}

static int
st_get_addr_and_port(in_addr_t *addr, unsigned short *port)
{
	char *tmp;

	if (g_sock_fd == NO_OPENED_SOCKET) {
		printf("! No socket opened\n");
		return (-1);
	}

	tmp = strtok(NULL, "/");
	if (tmp == NULL) {
		printf("! No address given\n");
		return (-1);
	}
	if ((*addr = inet_addr(tmp)) == (uint32_t)-1) {
		printf("! Malformed address\n");
		return (-1);
	}

	tmp = strtok(NULL, " ");
	if (tmp == NULL) {
		printf("! No port given\n");
		return (-1);
	}
	*port = htons(atoi(tmp));

	return (0);
}

static int
st_bind(void)
{
	struct sockaddr_in local_addr;

	if (st_get_addr_and_port(&(local_addr.sin_addr.s_addr),
	    &(local_addr.sin_port)) < 0) {
		return (-1);
	}

	local_addr.sin_family = AF_INET;
	if (st_local_bind(g_sock_fd, (struct sockaddr *)&local_addr,
	    sizeof (local_addr)) < 0) {
		printf("! Bind failed: %d\n", errno);
		return (-1);
	}
	printf("@ Socket bound to %s/%d\n", inet_ntoa(local_addr.sin_addr),
	    ntohs(local_addr.sin_port));
	return (0);
}

static int
st_listen(void)
{
	char *tmp;

	if (g_sock_fd == NO_OPENED_SOCKET) {
		printf("! No socket opened\n");
		return (-1);
	}
	if ((tmp = strtok(NULL, " ")) == NULL) {
		printf("! No backlog given\n");
		return (-1);
	}
	if (st_local_listen(g_sock_fd, atoi(tmp)) < 0) {
		printf("! Listen failed: %d\n", errno);
		return (-1);
	}
	printf("@ Listen succeeded\n");
	return (0);
}

static int
st_accept(void)
{
	struct sockaddr_in addr;
	socklen_t addr_len;
	int sd;

	if (g_sock_fd == NO_OPENED_SOCKET) {
		printf("! No socket opened\n");
		return (-1);
	}
	addr_len = sizeof (struct sockaddr_in);
	if ((sd = st_local_accept(g_sock_fd, (struct sockaddr *)&addr,
	    &addr_len)) < 0) {
		printf("! Accept failed: %d\n", errno);
		return (-1);
	}
	printf("@ Accept succeeded from %s:%d.  Socket descriptor saved\n",
	    inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	save_g_sock_fd = g_sock_fd;
	g_sock_fd = sd;
	return (0);
}

static int
st_connect(void)
{
	struct sockaddr_in peer_addr;

	if (st_get_addr_and_port(&(peer_addr.sin_addr.s_addr),
	    &(peer_addr.sin_port)) < 0) {
		return (-1);
	}

	peer_addr.sin_family = AF_INET;
	if (st_local_connect(g_sock_fd, (struct sockaddr *)&peer_addr,
	    sizeof (peer_addr)) < 0) {
		printf("! Connect failed: %d\n", errno);
		return (-1);
	}
	printf("@ Socket connected to %s/%d\n", inet_ntoa(peer_addr.sin_addr),
	    ntohs(peer_addr.sin_port));

	return (0);
}

static int
st_get_buf_and_cnt(char **buf, int *send_cnt)
{
	char *cnt;

	if ((*buf = strtok(NULL, " ")) == NULL) {
		printf("! No send buffer\n");
		return (-1);
	}
	if ((cnt = strtok(NULL, " ")) == NULL) {
		printf("! Missing send length\n");
		return (-1);
	}

	if ((*send_cnt = atoi(cnt)) < 0) {
		printf("! Invalid send count\n");
		return (-1);
	}
	return (0);
}

static int
st_send(void)
{
	char *buf;
	int send_cnt;

	if (g_sock_fd == NO_OPENED_SOCKET) {
		printf("! No socket opened\n");
		return (-1);
	}

	if (st_get_buf_and_cnt(&buf, &send_cnt) < 0)
		return (-1);

	if ((send_cnt = st_local_send(g_sock_fd, buf, send_cnt, 0)) < 0) {
		printf("! Send failed: %d\n", errno);
		return (-1);
	}
	printf("@ Send %d bytes\n", send_cnt);

	return (0);
}

static int
st_sendto(void)
{
	struct sockaddr_in peer_addr;
	char *buf;
	int send_cnt;

	if (st_get_addr_and_port(&(peer_addr.sin_addr.s_addr),
	    &(peer_addr.sin_port)) < 0) {
		return (-1);
	}
	peer_addr.sin_family = AF_INET;

	if (st_get_buf_and_cnt(&buf, &send_cnt) < 0)
		return (-1);

	if ((send_cnt = st_local_sendto(g_sock_fd, buf, send_cnt, 0,
	    (struct sockaddr *)&peer_addr, sizeof (peer_addr))) < 0) {
		printf("! Sendto failed: %d\n", errno);
		return (-1);
	}
	printf("@ Send %d bytes\n", send_cnt);

	return (0);
}

static int
st_recv(void)
{
	char *tmp;
	char *buf;
	int buf_len, ret;

	if (g_sock_fd == NO_OPENED_SOCKET) {
		printf("! No socket opened\n");
		return (-1);
	}

	if ((tmp = strtok(NULL, " ")) == NULL) {
		printf("! No buffer len given\n");
		return (-1);
	}
	buf_len = atoi(tmp);

	if ((buf = bkmem_zalloc(buf_len)) == NULL) {
		printf("! Cannot allocate buffer: %d\n", errno);
		return (-1);
	}
	if ((ret = st_local_recv(g_sock_fd, buf, buf_len, 0)) <= 0) {
		if (ret == 0) {
			printf("@ EOF received: %d\n", errno);
			return (0);
		}
		printf("! Cannot recv: %d\n", errno);
		return (-1);
	}
	printf("@ Bytes received: %d\n", ret);
	hexdump(buf, ret);
	bkmem_free(buf, buf_len);
	return (0);
}

static int
st_recvfrom(void)
{
	char *tmp;
	char *buf;
	int buf_len, ret;
	struct sockaddr_in from;
	socklen_t fromlen;

	if (g_sock_fd == NO_OPENED_SOCKET) {
		printf("! No socket opened\n");
		return (-1);
	}

	if ((tmp = strtok(NULL, " ")) == NULL) {
		printf("! No buffer len given\n");
		return (-1);
	}
	buf_len = atoi(tmp);

	if ((buf = bkmem_zalloc(buf_len)) == NULL) {
		printf("! Cannot allocate buffer: %d\n", errno);
		return (-1);
	}
	fromlen = sizeof (from);
	if ((ret = st_local_recvfrom(g_sock_fd, buf, buf_len, 0,
	    (struct sockaddr *)&from, &fromlen)) <= 0) {
		if (ret == 0) {
			printf("@ EOF received: %d\n", errno);
			return (0);
		}
		printf("! Cannot recv: %d\n", errno);
		return (-1);
	}
	printf("@ Bytes received from %s/%d: %d\n",
	    inet_ntoa(from.sin_addr), ntohs(from.sin_port), ret);
	hexdump(buf, ret);
	bkmem_free(buf, buf_len);
	return (0);
}

/*
 * To act as an echo server.  Note that it assumes the address and
 * netmask have been set.
 */
static int
st_echo(void)
{
	char *tmp;
	int listen_fd, newfd;
	int echo_port;
	struct sockaddr_in addr;
	socklen_t addr_size;
	int backlog = 20;
	char *buf;
	int buf_len, ret, snd_cnt;

	tmp = strtok(NULL, " ");
	if (tmp == NULL) {
		printf("! No echo port given\n");
		return (-1);
	}
	echo_port = atoi(tmp);
	tmp = strtok(NULL, " ");
	if (tmp == NULL) {
		printf("! No buffer size given\n");
		return (-1);
	}
	buf_len = atoi(tmp);

	/* Create local socket for echo server */
	if ((listen_fd = st_local_socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("! Error in opening TCP socket: %d\n", errno);
		return (-1);
	} else {
		printf("@ Local TCP socket opened\n");
	}

	/* Bind local socket */
	addr.sin_family = AF_INET;
	addr.sin_port = htons(echo_port);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (st_local_bind(listen_fd, (struct sockaddr *)&addr,
	    sizeof (addr)) < 0) {
		printf("! Bind failed: %d\n", errno);
		return (-1);
	}
	if (st_local_listen(listen_fd, backlog) < 0) {
		printf("! Listen failed: %d\n", errno);
		return (-1);
	}

	addr_size = sizeof (addr);
	if ((newfd = st_local_accept(listen_fd, (struct sockaddr *)&addr,
	    &addr_size)) < 0) {
		printf("! Accept failed: %d\n", errno);
		(void) st_local_socket_close(listen_fd);
		return (-1);
	}
	printf("@ Accepted connection: %s/%d\n", inet_ntoa(addr.sin_addr),
		ntohs(addr.sin_port));
	(void) st_local_socket_close(listen_fd);

	if ((buf = bkmem_zalloc(buf_len)) == NULL) {
		printf("! Cannot allocate buffer: %d\n", errno);
		(void) st_local_socket_close(newfd);
		return (-1);
	}
	while ((ret = st_local_recv(newfd, buf, buf_len, 0)) > 0) {
		printf("@ Bytes received: %d\n", ret);
		hexdump(buf, ret);
		if ((snd_cnt = st_local_send(newfd, buf, ret, 0)) < ret) {
			printf("! Send failed: %d\n", errno);
			bkmem_free(buf, buf_len);
			return (-1);
		}
		printf("@ Sent %d bytes\n", snd_cnt);
	}
	(void) st_local_socket_close(newfd);
	if (ret < 0) {
		printf("! Cannot recv: %d\n", errno);
		bkmem_free(buf, buf_len);
		return (-1);
	} else {
		return (0);
	}
}

static int
st_match_option(char *opt_s, int *opt, int *opt_level)
{
	int i;

	for (i = 0; so_option_array[i].so_name != NULL; i++) {
		if (strcmp(so_option_array[i].so_name, opt_s) == 0) {
			*opt = so_option_array[i].so_opt;
			*opt_level = so_option_array[i].so_opt_level;
			return (0);
		}
	}
	printf("! Unknown option\n");
	return (-1);
}

static int
st_setsockopt(void)
{
	char *tmp;
	int opt, opt_level, opt_val;

	if (g_sock_fd == NO_OPENED_SOCKET) {
		printf("! No socket opened\n");
		return (-1);
	}

	if ((tmp = strtok(NULL, " ")) == NULL) {
		printf("! No option given\n");
		return (-1);
	}
	if (st_match_option(tmp, &opt, &opt_level) < 0) {
		return (-1);
	}

	/* We only support integer option for the moment. */
	if ((tmp = strtok(NULL, " ")) == NULL) {
		printf("! No option value given\n");
		return (-1);
	}
	opt_val = atoi(tmp);

	if (st_local_setsockopt(g_sock_fd, opt_level, opt, &opt_val,
	    sizeof (int)) < 0) {
		printf("! Cannot set option: %d\n", errno);
		return (-1);
	}
	printf("@ Option set successfully\n");
	return (0);
}

static int
st_getsockname(void)
{
	struct sockaddr_in addr;
	socklen_t len;

	if (g_sock_fd == NO_OPENED_SOCKET) {
		printf("! No socket opened\n");
		return (-1);
	}

	len = sizeof (addr);
	if (st_local_getsockname(g_sock_fd, (struct sockaddr *)&addr,
	    &len) < 0) {
		printf("! getsockname failed: %d\n", errno);
		return (-1);
	}
	printf("@ Local socket name: %s/%d\n", inet_ntoa(addr.sin_addr),
	    ntohs(addr.sin_port));
	return (0);
}

static int
st_getsockopt(void)
{
	char *tmp;
	int opt, opt_level, opt_val;
	socklen_t opt_len;

	if (g_sock_fd == NO_OPENED_SOCKET) {
		printf("! No socket opened\n");
		return (-1);
	}

	if ((tmp = strtok(NULL, " ")) == NULL) {
		printf("! No option given\n");
		return (-1);
	}
	if (st_match_option(tmp, &opt, &opt_level) < 0) {
		return (-1);
	}

	opt_len = sizeof (opt_val);
	if (st_local_getsockopt(g_sock_fd, opt_level, opt, &opt_val,
	    &opt_len) < 0) {
		printf("! Cannot get option: %d\n", errno);
		return (-1);
	}
	printf("@ Option value is %d\n", opt_val);
	return (-1);
}

static int
st_sock_close(void)
{
	if (g_sock_fd == NO_OPENED_SOCKET) {
		printf("! No socket opened\n");
		return (-1);
	}
	if (st_local_socket_close(g_sock_fd) < 0) {
		printf("! Error in closing socket: %d\n", errno);
		return (-1);
	}
	printf("@ Socket closed");
	if (save_g_sock_fd != NO_OPENED_SOCKET) {
		g_sock_fd = save_g_sock_fd;
		save_g_sock_fd = NO_OPENED_SOCKET;
		printf(", switching to saved socket descriptor\n");
	} else {
		g_sock_fd = NO_OPENED_SOCKET;
		printf("\n");
	}
	return (0);
}

static int
st_toggle_promiscuous(void)
{
	/* We always start with non-promiscuous mode. */
	static boolean_t promiscuous = B_FALSE;

	promiscuous = !promiscuous;
	(void) ipv4_setpromiscuous(promiscuous);
	printf("@ Setting promiscuous to %d\n", promiscuous);
	return (0);
}

static int
st_use_obp(void)
{
	if ((use_obp = !use_obp) == B_TRUE) {
		printf("@ Now using OBP routines\n");
	} else {
		printf("@ Now using socket routines\n");
	}
	return (0);
}

static int
st_tcp_tw_report(void)
{
	printf("@ TCP Time Wait report\n");
	tcp_time_wait_report();
	return (0);
}
