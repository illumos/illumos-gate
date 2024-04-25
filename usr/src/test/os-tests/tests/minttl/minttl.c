/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Basic set of tests for IP_MINTTL and IPV6_MINHOPCOUNT. The main design of
 * this is to spin up connections on localhost that walk through different
 * socket types and confirm that we can use the corresponding socket option and
 * that we receive traffic when the TTL is set and not otherwise.
 */

#include <err.h>
#include <port.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#include <sys/sysmacros.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/debug.h>

/*
 * The IP protocols 0xfd-0xfe are reserved for experiments. This is the safest
 * IP protocol for us to use then in our testing for raw sockets.
 */
#define	TTL_IPPROTO_EXP	0xfd

static hrtime_t tt_sock_to = MSEC2NSEC(100); /* ms in ns */
static const uint32_t tt_msg = 0x7777;

typedef enum {
	TTL_SENDRECV,
	TTL_NOCONNECT,
	TTL_NODATA
} ttl_pass_t;

typedef struct {
	const char *tt_desc;
	int tt_domain;
	int tt_type;
	int tt_ttl;
	int tt_proto;
	int tt_minttl;
	ttl_pass_t tt_pass;
} ttl_test_t;

static const ttl_test_t ttl_tests[] = {
	{
		.tt_desc = "IPv4 TCP TTL/MIN: unset/0",
		.tt_domain = PF_INET,
		.tt_type = SOCK_STREAM,
		.tt_ttl = 0,
		.tt_minttl = 0,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv4 TCP TTL/MIN: 200/100",
		.tt_domain = PF_INET,
		.tt_type = SOCK_STREAM,
		.tt_ttl = 200,
		.tt_minttl = 100,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv4 TCP TTL/MIN: 255/255",
		.tt_domain = PF_INET,
		.tt_type = SOCK_STREAM,
		.tt_ttl = 255,
		.tt_minttl = 255,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv4 TCP TTL/MIN: 23/169",
		.tt_domain = PF_INET,
		.tt_type = SOCK_STREAM,
		.tt_ttl = 23,
		.tt_minttl = 169,
		.tt_pass = TTL_NOCONNECT
	}, {
		.tt_desc = "IPv4 TCP TTL/MIN: 254/255",
		.tt_domain = PF_INET,
		.tt_type = SOCK_STREAM,
		.tt_ttl = 254,
		.tt_minttl = 255,
		.tt_pass = TTL_NOCONNECT
	}, {
		.tt_desc = "IPv4 UDP TTL/MIN: unset/0",
		.tt_domain = PF_INET,
		.tt_type = SOCK_DGRAM,
		.tt_ttl = 0,
		.tt_minttl = 0,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv4 UDP TTL/MIN: 200/100",
		.tt_domain = PF_INET,
		.tt_type = SOCK_DGRAM,
		.tt_ttl = 200,
		.tt_minttl = 100,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv4 UDP TTL/MIN: 255/255",
		.tt_domain = PF_INET,
		.tt_type = SOCK_DGRAM,
		.tt_ttl = 255,
		.tt_minttl = 255,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv4 UDP TTL/MIN: 23/169",
		.tt_domain = PF_INET,
		.tt_type = SOCK_DGRAM,
		.tt_ttl = 23,
		.tt_minttl = 169,
		.tt_pass = TTL_NODATA
	}, {
		.tt_desc = "IPv4 UDP TTL/MIN: 254/255",
		.tt_domain = PF_INET,
		.tt_type = SOCK_DGRAM,
		.tt_ttl = 254,
		.tt_minttl = 255,
		.tt_pass = TTL_NODATA
	}, {
		.tt_desc = "IPv4 SCTP TTL/MIN: unset/0",
		.tt_domain = PF_INET,
		.tt_type = SOCK_STREAM,
		.tt_proto = IPPROTO_SCTP,
		.tt_ttl = 0,
		.tt_minttl = 0,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv4 SCTP TTL/MIN: 200/100",
		.tt_domain = PF_INET,
		.tt_type = SOCK_STREAM,
		.tt_proto = IPPROTO_SCTP,
		.tt_ttl = 200,
		.tt_minttl = 100,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv4 SCTP TTL/MIN: 255/255",
		.tt_domain = PF_INET,
		.tt_type = SOCK_STREAM,
		.tt_proto = IPPROTO_SCTP,
		.tt_ttl = 255,
		.tt_minttl = 255,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv4 SCTP TTL/MIN: 23/169",
		.tt_domain = PF_INET,
		.tt_type = SOCK_STREAM,
		.tt_proto = IPPROTO_SCTP,
		.tt_ttl = 23,
		.tt_minttl = 169,
		.tt_pass = TTL_NOCONNECT
	}, {
		.tt_desc = "IPv4 SCTP TTL/MIN: 254/255",
		.tt_domain = PF_INET,
		.tt_type = SOCK_STREAM,
		.tt_proto = IPPROTO_SCTP,
		.tt_ttl = 254,
		.tt_minttl = 255,
		.tt_pass = TTL_NOCONNECT
	}, {
		.tt_desc = "IPv4 RAW (0xfd) TTL/MIN: unset/0",
		.tt_domain = PF_INET,
		.tt_type = SOCK_RAW,
		.tt_proto = TTL_IPPROTO_EXP,
		.tt_ttl = 0,
		.tt_minttl = 0,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv4 RAW (0xfd) TTL/MIN: 200/100",
		.tt_domain = PF_INET,
		.tt_type = SOCK_RAW,
		.tt_proto = TTL_IPPROTO_EXP,
		.tt_ttl = 200,
		.tt_minttl = 100,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv4 RAW (0xfd) TTL/MIN: 255/255",
		.tt_domain = PF_INET,
		.tt_type = SOCK_RAW,
		.tt_proto = TTL_IPPROTO_EXP,
		.tt_ttl = 255,
		.tt_minttl = 255,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv4 RAW (0xfd) TTL/MIN: 23/169",
		.tt_domain = PF_INET,
		.tt_type = SOCK_RAW,
		.tt_proto = TTL_IPPROTO_EXP,
		.tt_ttl = 23,
		.tt_minttl = 169,
		.tt_pass = TTL_NODATA
	}, {
		.tt_desc = "IPv4 RAW (0xfd) TTL/MIN: 254/255",
		.tt_domain = PF_INET,
		.tt_type = SOCK_RAW,
		.tt_proto = TTL_IPPROTO_EXP,
		.tt_ttl = 254,
		.tt_minttl = 255,
		.tt_pass = TTL_NODATA
	}, {
		.tt_desc = "IPv6 TCP TTL/MIN: unset/0",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_STREAM,
		.tt_ttl = 0,
		.tt_minttl = 0,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv6 TCP TTL/MIN: 200/100",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_STREAM,
		.tt_ttl = 200,
		.tt_minttl = 100,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv6 TCP TTL/MIN: 255/255",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_STREAM,
		.tt_ttl = 255,
		.tt_minttl = 255,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv6 CTP TTL/MIN: 23/169",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_STREAM,
		.tt_ttl = 23,
		.tt_minttl = 169,
		.tt_pass = TTL_NOCONNECT
	}, {
		.tt_desc = "IPv6 CTP TTL/MIN: 254/255",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_STREAM,
		.tt_ttl = 254,
		.tt_minttl = 255,
		.tt_pass = TTL_NOCONNECT
	}, {
		.tt_desc = "IPv6 UDP TTL/MIN: unset/0",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_DGRAM,
		.tt_ttl = 0,
		.tt_minttl = 0,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv6 UDP TTL/MIN: 200/100",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_DGRAM,
		.tt_ttl = 200,
		.tt_minttl = 100,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv6 UDP TTL/MIN: 255/255",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_DGRAM,
		.tt_ttl = 255,
		.tt_minttl = 255,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv6 UDP TTL/MIN: 23/169",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_DGRAM,
		.tt_ttl = 23,
		.tt_minttl = 169,
		.tt_pass = TTL_NODATA
	}, {
		.tt_desc = "IPv6 UDP TTL/MIN: 254/255",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_DGRAM,
		.tt_ttl = 254,
		.tt_minttl = 255,
		.tt_pass = TTL_NODATA
	}, {
		.tt_desc = "IPv6 SCTP TTL/MIN: unset/0",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_STREAM,
		.tt_proto = IPPROTO_SCTP,
		.tt_ttl = 0,
		.tt_minttl = 0,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv6 SCTP TTL/MIN: 200/100",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_STREAM,
		.tt_proto = IPPROTO_SCTP,
		.tt_ttl = 200,
		.tt_minttl = 100,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv6 SCTP TTL/MIN: 255/255",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_STREAM,
		.tt_proto = IPPROTO_SCTP,
		.tt_ttl = 255,
		.tt_minttl = 255,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv6 SCTP TTL/MIN: 23/169",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_STREAM,
		.tt_proto = IPPROTO_SCTP,
		.tt_ttl = 23,
		.tt_minttl = 169,
		.tt_pass = TTL_NOCONNECT
	}, {
		.tt_desc = "IPv6 SCTP TTL/MIN: 254/255",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_STREAM,
		.tt_proto = IPPROTO_SCTP,
		.tt_ttl = 254,
		.tt_minttl = 255,
		.tt_pass = TTL_NOCONNECT
	}, {
		.tt_desc = "IPv6 RAW (0xfd) TTL/MIN: unset/0",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_RAW,
		.tt_proto = TTL_IPPROTO_EXP,
		.tt_ttl = 0,
		.tt_minttl = 0,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv6 RAW (0xfd) TTL/MIN: 200/100",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_RAW,
		.tt_proto = TTL_IPPROTO_EXP,
		.tt_ttl = 200,
		.tt_minttl = 100,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv6 RAW (0xfd) TTL/MIN: 255/255",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_RAW,
		.tt_proto = TTL_IPPROTO_EXP,
		.tt_ttl = 255,
		.tt_minttl = 255,
		.tt_pass = TTL_SENDRECV
	}, {
		.tt_desc = "IPv6 RAW (0xfd) TTL/MIN: 23/169",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_RAW,
		.tt_proto = TTL_IPPROTO_EXP,
		.tt_ttl = 23,
		.tt_minttl = 169,
		.tt_pass = TTL_NODATA
	}, {
		.tt_desc = "IPv6 RAW (0xfd) TTL/MIN: 254/255",
		.tt_domain = PF_INET6,
		.tt_type = SOCK_RAW,
		.tt_proto = TTL_IPPROTO_EXP,
		.tt_ttl = 254,
		.tt_minttl = 255,
		.tt_pass = TTL_NODATA
	}
};

static bool
ttl_bind_dest(const ttl_test_t *test, int sock, struct sockaddr_storage *dst)
{
	socklen_t len;
	struct sockaddr_storage addr;

	(void) memset(&addr, 0, sizeof (struct sockaddr_storage));

	if (test->tt_domain == PF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)&addr;
		in->sin_family = AF_INET;
		in->sin_port = htons(0);
		if (inet_pton(AF_INET, "127.0.0.1", &in->sin_addr) != 1) {
			warnx("TEST FAILED: %s: failed to convert 127.0.0.1 "
			    "to an IPv4 address", test->tt_desc);
			return (false);
		}
		len = sizeof (struct sockaddr_in);
	} else {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&addr;
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(0);
		if (inet_pton(AF_INET6, "::1", &in6->sin6_addr) != 1) {
			warnx("TEST FAILED: %s: failed to convert ::1 "
			    "to an IPv6 address", test->tt_desc);
			return (false);
		}
		len = sizeof (struct sockaddr_in6);
	}

	if (bind(sock, (struct sockaddr *)&addr, len) != 0) {
		warn("TEST FAILED: %s: failed to bind listen socket",
		    test->tt_desc);
		return (false);
	}

	len = sizeof (struct sockaddr_storage);
	if (getsockname(sock, (struct sockaddr *)dst, &len) != 0) {
		warn("TEST FAILED: %s: failed to retrieve socket address ",
		    test->tt_desc);
		return (false);
	}

	return (true);
}

/*
 * Our job is to attempt to connect to the other end with our current settings.
 * This may not work, so we use our port to get things ready just in case.
 */
static bool
ttl_connect(const ttl_test_t *test, int port, int src, int dst, int *cfd,
    const struct sockaddr *addr)
{
	struct timespec to = { .tv_nsec = tt_sock_to };
	int namelen = test->tt_domain == PF_INET ? sizeof (struct sockaddr_in) :
	    sizeof (struct sockaddr_in6);
	int conn;
	port_event_t pe;

	if (listen(dst, 5) != 0) {
		warn("TEST FAILED: %s: failed to listen", test->tt_desc);
		return (false);
	}

	if (connect(src, addr, namelen) != 0 && errno != EINPROGRESS) {
		warn("TEST FAILED: %s: failed to connect", test->tt_desc);
		return (false);
	}

	if (port_associate(port, PORT_SOURCE_FD, src, POLLOUT, NULL) != 0) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: %s: could not port "
		    "associate to watch connect", test->tt_desc);
	}

	if (port_get(port, &pe, &to) != 0) {
		if (test->tt_pass == TTL_NOCONNECT) {
			(void) printf("TEST PASSED: %s: correctly failed to "
			    "connect\n", test->tt_desc);
			return (true);
		} else {
			warn("TEST FAILED: %s: timed out waiting to connect",
			    test->tt_desc);
			return (false);
		}
	}

	if ((pe.portev_events & POLLOUT) == 0) {
		warnx("TEST FAILED: %s: connect port event doesn't contain "
		    "POLLOUT, found 0x%x", test->tt_desc, pe.portev_events);
		return (false);
	}

	/*
	 * Now make sure the listen socket is ready.
	 */
	if (port_associate(port, PORT_SOURCE_FD, dst, POLLIN, NULL) != 0) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: %s: could not port "
		    "associate to watch accept", test->tt_desc);
	}

	if (port_get(port, &pe, &to) != 0) {
		warn("TEST FAILED: %s: timed out waiting to accept",
		    test->tt_desc);
		return (false);
	}

	if ((pe.portev_events & POLLIN) == 0) {
		warnx("TEST FAILED: %s: accept port event doesn't contain "
		    "POLLIN, found 0x%x", test->tt_desc, pe.portev_events);
		return (false);
	}

	conn = accept4(dst, NULL, NULL, SOCK_NONBLOCK);
	if (conn < 0) {
		warn("TEST FAILED: %s: failed to get client connection",
		    test->tt_desc);
		return (false);
	}

	if (test->tt_pass != TTL_SENDRECV) {
		warnx("TEST FAILED: %s: expected connect to fail, but passed",
		    test->tt_desc);
		return (false);
	}

	*cfd = conn;
	return (true);
}

static bool
ttl_check_ancil(const ttl_test_t *test, const struct msghdr *msg)
{
	int level, ttlopt;

	if (test->tt_domain == PF_INET) {
		level = IPPROTO_IP;
		ttlopt = IP_RECVTTL;
	} else {
		level = IPPROTO_IPV6;
		ttlopt = IPV6_HOPLIMIT;
	}

	if (msg->msg_controllen != CMSG_SPACE(sizeof (int))) {
		warnx("TEST FAILED: %s: expected %u bytes of ancillary "
		    "data, found %u", test->tt_desc, CMSG_SPACE(sizeof (int)),
		    msg->msg_controllen);
		return (false);
	}

	for (const struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(msg, cmsg)) {
		int val;

		if (cmsg->cmsg_level != level || cmsg->cmsg_type != ttlopt)
			continue;
		(void) memcpy(&val, CMSG_DATA(cmsg), sizeof (int));
		if (test->tt_ttl != 0 && val != test->tt_ttl) {
			warnx("TEST FAILED: %s: TTL/HLIM mismatch: expected "
			    "0x%x, found 0x%x", test->tt_desc, test->tt_ttl,
			    val);
			return (false);
		}

		(void) printf("TEST PASSED: %s: TTL/HLIM is correct\n",
		    test->tt_desc);
		return (true);
	}

	warnx("TEST FAILED: %s: failed to find TTL/HLIM in ancillary options",
	    test->tt_desc);
	return (false);
}

/*
 * Attempt to send data with the TTLs set up appropriately. This might fail,
 * hence our port_associate dance and unfortunately regrettable timeout.
 */
static bool
ttl_sendrecv(const ttl_test_t *test, int port, int src, int dst,
    struct sockaddr *addr)
{
	struct timespec to = { .tv_nsec = tt_sock_to };
	int namelen = test->tt_domain == PF_INET ? sizeof (struct sockaddr_in) :
	    sizeof (struct sockaddr_in6);
	uint8_t ancil[CMSG_SPACE(sizeof (int)) * 2];
	port_event_t pe;
	struct msghdr msg;
	uint32_t data;
	struct iovec iov;
	ssize_t sret;

	if (sendto(src, &tt_msg, sizeof (tt_msg), MSG_NOSIGNAL, addr,
	    namelen) != sizeof (tt_msg)) {
		warn("TEST FAILED: %s: failed to write message to socket",
		    test->tt_desc);
	}

	if (port_associate(port, PORT_SOURCE_FD, dst, POLLIN, NULL) != 0) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: %s: could not port "
		    "associate to watch recv", test->tt_desc);
	}

	if (port_get(port, &pe, &to) != 0) {
		if (test->tt_pass == TTL_NODATA) {
			(void) printf("TEST PASSED: %s: timed out waiting "
			    "for data\n", test->tt_desc);
			return (true);
		} else {
			warn("TEST FAILED: %s: timed out waiting to recv",
			    test->tt_desc);
			return (false);
		}
	}

	if ((pe.portev_events & POLLIN) == 0) {
		warnx("TEST FAILED: %s: receive port event doesn't contain "
		    "POLLIN, found 0x%x", test->tt_desc, pe.portev_events);
		return (false);
	}

	(void) memset(&msg, 0, sizeof (msg));
	iov.iov_base = (void *)&data;
	iov.iov_len = sizeof (data);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ancil;
	msg.msg_controllen = sizeof (ancil);

	sret = recvmsg(dst, &msg, MSG_DONTWAIT);
	if (sret != (ssize_t)sizeof (data)) {
		warnx("TEST FAILED: %s: failed to receive data: %zx",
		    test->tt_desc, sret);
		return (false);
	}

	if (test->tt_pass != TTL_SENDRECV) {
		warnx("TEST FAILED: %s: found data, despite expecting not to",
		    test->tt_desc);
		return (false);
	}

	/*
	 * We skip testing the data on raw sockets so we can ignore having to
	 * parse the IPv4 or IPv6 headers.
	 */
	if (data != tt_msg && test->tt_type != SOCK_RAW) {
		warnx("TEST FAILED: %s: data mismatch: expected 0x%x, found "
		    "0x%x", test->tt_desc, tt_msg, data);
		return (false);
	}

	if (test->tt_type == SOCK_DGRAM && !ttl_check_ancil(test, &msg)) {
		return (false);
	}

	(void) printf("TEST PASSED: %s: Successfully received data\n",
	    test->tt_desc);
	return (true);
}

static bool
ttl_test_one(const ttl_test_t *test)
{
	int src = -1, dst = -1, cfd = -1, port = -1, tdst;
	int level, ttlopt, minttlopt, recvopt, en = 1;
	bool ret = true;
	struct sockaddr_storage dst_addr;

	if ((port = port_create()) < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to create event port");
	}

	src = socket(test->tt_domain, test->tt_type | SOCK_NONBLOCK,
	    test->tt_proto);
	if (src < 0) {
		warn("TEST FAILED: %s: failed to create source socket",
		    test->tt_desc);
		ret = false;
		goto cleanup;
	}

	dst = socket(test->tt_domain, test->tt_type | SOCK_NONBLOCK,
	    test->tt_proto);
	if (dst < 0) {
		warn("TEST FAILED: %s: failed to create destination socket",
		    test->tt_desc);
		ret = false;
		goto cleanup;
	}

	if (!ttl_bind_dest(test, dst, &dst_addr)) {
		ret = false;
		goto cleanup;
	}

	if (test->tt_domain == PF_INET) {
		level = IPPROTO_IP;
		ttlopt = IP_TTL;
		minttlopt = IP_MINTTL;
		recvopt = IP_RECVTTL;
	} else {
		level = IPPROTO_IPV6;
		ttlopt = IPV6_UNICAST_HOPS;
		minttlopt = IPV6_MINHOPCOUNT;
		recvopt = IPV6_RECVHOPLIMIT;
	}

	if (test->tt_ttl > 0 && setsockopt(src, level, ttlopt, &test->tt_ttl,
	    sizeof (int)) != 0) {
		warn("TEST FAILED: %s: failed to set TTL/HLIM to %d",
		    test->tt_desc, test->tt_ttl);
		ret = false;
		goto cleanup;
	}

	if (setsockopt(dst, level, minttlopt, &test->tt_minttl,
	    sizeof (int)) != 0) {
		warn("TEST FAILED: %s: failed to set min TTL/HLIM to %d",
		    test->tt_desc, test->tt_minttl);
		ret = false;
		goto cleanup;
	}

	if (test->tt_type == SOCK_DGRAM && setsockopt(dst, level, recvopt, &en,
	    sizeof (int)) != 0) {
		warn("TEST FAILED: %s failed to enable receiving the TTL",
		    test->tt_desc);
		ret = false;
		goto cleanup;
	}

	if (test->tt_type != SOCK_DGRAM && test->tt_type != SOCK_RAW) {
		if (!ttl_connect(test, port, src, dst, &cfd,
		    (struct sockaddr *)&dst_addr)) {
			ret = false;
			goto cleanup;
		}
		if (test->tt_pass != TTL_SENDRECV) {
			goto cleanup;
		}
		tdst = cfd;
	} else {
		tdst = dst;
	}

	if (!ttl_sendrecv(test, port, src, tdst,
	    (struct sockaddr *)&dst_addr)) {
		ret = false;
		goto cleanup;
	}

cleanup:
	if (port > -1)
		(void) close(port);
	if (src > -1)
		(void) close(src);
	if (dst > -1)
		(void) close(dst);
	if (cfd > -1)
		(void) close(cfd);
	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(ttl_tests); i++) {
		if (!ttl_test_one(&ttl_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
