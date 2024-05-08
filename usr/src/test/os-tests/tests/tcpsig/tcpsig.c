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
 * Basic set of tests for TCP_MD5SIG. The main design of this is to spin up
 * connections on localhost that walk through different options and confirm
 * that traffic either flows or is dropped according to the configuration.
 */

#include <err.h>
#include <port.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/sysmacros.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/debug.h>

static hrtime_t sock_to = MSEC2NSEC(100); /* ms in ns */
static const uint32_t msgdata = 0x7777;

/*
 * Port setup - see tcpsig_init
 */

/* No SAs are configured */
#define	PORT_NOSA	24134
/* SAs exist in both directions, and the authentication keys match */
#define	PORT_BIDIR	24135
/* SAs exist in both directions, but the authentication keys don't match */
#define	PORT_MISMATCH	24136
/* A single SA exists in the outbound direction, none for inbound */
#define	PORT_OBSA	24137
/* A single SA exists in the inbound direction, none for outbound */
#define	PORT_IBSA	24138

typedef enum {
	TCPSIG_SENDRECV,
	TCPSIG_NOCONNECT,
	TCPSIG_CONNREFUSED,
	TCPSIG_NODATA
} tcpsig_pass_t;

typedef struct {
	const char		*tt_desc;
	const int		tt_domain;
	const uint16_t		tt_port;
	const bool		tt_enable_src;
	const bool		tt_enable_dst;
	const tcpsig_pass_t	tt_pass;
} tcpsig_test_t;

static const tcpsig_test_t tcpsig_tests[] = {
	/* Tests using the port that (hopefully) has no SAs configured */
	{
		.tt_desc = "IPv4 NOSA with MD5 enabled on both sides",
		.tt_domain = PF_INET,
		.tt_port = PORT_NOSA,
		.tt_enable_src = true,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_CONNREFUSED
	}, {
		.tt_desc = "IPv4 NOSA with MD5 disabled on both sides",
		.tt_domain = PF_INET,
		.tt_port = PORT_NOSA,
		.tt_enable_src = false,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_SENDRECV
	}, {
		.tt_desc = "IPv4 NOSA with MD5 enabled on src only",
		.tt_domain = PF_INET,
		.tt_port = PORT_NOSA,
		.tt_enable_src = true,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_CONNREFUSED
	}, {
		.tt_desc = "IPv4 NOSA with MD5 enabled on dst only",
		.tt_domain = PF_INET,
		.tt_port = PORT_NOSA,
		.tt_enable_src = false,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_SENDRECV
	},
	{
		.tt_desc = "IPv6 NOSA with MD5 enabled on both sides",
		.tt_domain = PF_INET6,
		.tt_port = PORT_NOSA,
		.tt_enable_src = true,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_CONNREFUSED
	}, {
		.tt_desc = "IPv6 NOSA with MD5 disabled on both sides",
		.tt_domain = PF_INET6,
		.tt_port = PORT_NOSA,
		.tt_enable_src = false,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_SENDRECV
	}, {
		.tt_desc = "IPv6 NOSA with MD5 enabled on src only",
		.tt_domain = PF_INET6,
		.tt_port = PORT_NOSA,
		.tt_enable_src = true,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_CONNREFUSED
	}, {
		.tt_desc = "IPv6 NOSA with MD5 enabled on dst only",
		.tt_domain = PF_INET6,
		.tt_port = PORT_NOSA,
		.tt_enable_src = false,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_SENDRECV
	},
	/* Tests using the port that has bi-directional SAs configured */
	{
		.tt_desc = "IPv4 BIDIR with MD5 enabled on both sides",
		.tt_domain = PF_INET,
		.tt_port = PORT_BIDIR,
		.tt_enable_src = true,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_SENDRECV
	}, {
		.tt_desc = "IPv4 BIDIR with MD5 disabled on both sides",
		.tt_domain = PF_INET,
		.tt_port = PORT_BIDIR,
		.tt_enable_src = false,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_SENDRECV
	}, {
		.tt_desc = "IPv4 BIDIR with MD5 enabled on src only",
		.tt_domain = PF_INET,
		.tt_port = PORT_BIDIR,
		.tt_enable_src = true,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_NOCONNECT
	}, {
		.tt_desc = "IPv4 BIDIR with MD5 enabled on dst only",
		.tt_domain = PF_INET,
		.tt_port = PORT_BIDIR,
		.tt_enable_src = false,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_NOCONNECT
	}, {
		.tt_desc = "IPv6 BIDIR with MD5 enabled on both sides",
		.tt_domain = PF_INET6,
		.tt_port = PORT_BIDIR,
		.tt_enable_src = true,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_SENDRECV
	}, {
		.tt_desc = "IPv6 BIDIR with MD5 disabled on both sides",
		.tt_domain = PF_INET6,
		.tt_port = PORT_BIDIR,
		.tt_enable_src = false,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_SENDRECV
	}, {
		.tt_desc = "IPv6 BIDIR with MD5 enabled on src only",
		.tt_domain = PF_INET6,
		.tt_port = PORT_BIDIR,
		.tt_enable_src = true,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_NOCONNECT
	}, {
		.tt_desc = "IPv6 BIDIR with MD5 enabled on dst only",
		.tt_domain = PF_INET6,
		.tt_port = PORT_BIDIR,
		.tt_enable_src = false,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_NOCONNECT
	},
	/* Tests using the port with mismatching SA keys */
	{
		/*
		 * Both sides of the connection have access to the two
		 * SAs and will use the correct key depending on the direction
		 * of the traffic. We therefore expect this to succeed.
		 * `tcpdump -M` can be used to verify that a different key is
		 * being used in each direction.
		 */
		.tt_desc = "IPv4 MISMATCH with MD5 enabled on both sides",
		.tt_domain = PF_INET,
		.tt_port = PORT_MISMATCH,
		.tt_enable_src = true,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_SENDRECV
	}, {
		.tt_desc = "IPv4 MISMATCH with MD5 disabled on both sides",
		.tt_domain = PF_INET,
		.tt_port = PORT_MISMATCH,
		.tt_enable_src = false,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_SENDRECV
	}, {
		.tt_desc = "IPv4 MISMATCH with MD5 enabled on src only",
		.tt_domain = PF_INET,
		.tt_port = PORT_MISMATCH,
		.tt_enable_src = true,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_NOCONNECT
	}, {
		.tt_desc = "IPv4 MISMATCH with MD5 enabled on dst only",
		.tt_domain = PF_INET,
		.tt_port = PORT_MISMATCH,
		.tt_enable_src = false,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_NOCONNECT
	}, {
		.tt_desc = "IPv6 MISMATCH with MD5 enabled on both sides",
		.tt_domain = PF_INET6,
		.tt_port = PORT_MISMATCH,
		.tt_enable_src = true,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_SENDRECV
	}, {
		.tt_desc = "IPv6 MISMATCH with MD5 disabled on both sides",
		.tt_domain = PF_INET6,
		.tt_port = PORT_MISMATCH,
		.tt_enable_src = false,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_SENDRECV
	}, {
		.tt_desc = "IPv6 MISMATCH with MD5 enabled on src only",
		.tt_domain = PF_INET6,
		.tt_port = PORT_MISMATCH,
		.tt_enable_src = true,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_NOCONNECT
	}, {
		.tt_desc = "IPv6 MISMATCH with MD5 enabled on dst only",
		.tt_domain = PF_INET6,
		.tt_port = PORT_MISMATCH,
		.tt_enable_src = false,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_NOCONNECT
	},
	/* Tests using the port with only an outbound SA */
	{
		.tt_desc = "IPv4 OBSA with MD5 enabled on both sides",
		.tt_domain = PF_INET,
		.tt_port = PORT_OBSA,
		.tt_enable_src = true,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_NOCONNECT
	}, {
		.tt_desc = "IPv4 OBSA with MD5 disabled on both sides",
		.tt_domain = PF_INET,
		.tt_port = PORT_OBSA,
		.tt_enable_src = false,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_SENDRECV
	}, {
		.tt_desc = "IPv4 OBSA with MD5 enabled on src only",
		.tt_domain = PF_INET,
		.tt_port = PORT_OBSA,
		.tt_enable_src = true,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_NOCONNECT
	}, {
		.tt_desc = "IPv4 OBSA with MD5 enabled on dst only",
		.tt_domain = PF_INET,
		.tt_port = PORT_OBSA,
		.tt_enable_src = false,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_NOCONNECT
	}, {
		.tt_desc = "IPv6 OBSA with MD5 enabled on both sides",
		.tt_domain = PF_INET6,
		.tt_port = PORT_OBSA,
		.tt_enable_src = true,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_NOCONNECT
	}, {
		.tt_desc = "IPv6 OBSA with MD5 disabled on both sides",
		.tt_domain = PF_INET6,
		.tt_port = PORT_OBSA,
		.tt_enable_src = false,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_SENDRECV
	}, {
		.tt_desc = "IPv6 OBSA with MD5 enabled on src only",
		.tt_domain = PF_INET6,
		.tt_port = PORT_OBSA,
		.tt_enable_src = true,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_NOCONNECT
	}, {
		.tt_desc = "IPv6 OBSA with MD5 enabled on dst only",
		.tt_domain = PF_INET6,
		.tt_port = PORT_OBSA,
		.tt_enable_src = false,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_NOCONNECT
	},
	/* Tests using the port with only an inbound SA */
	{
		.tt_desc = "IPv4 IBSA with MD5 enabled on both sides",
		.tt_domain = PF_INET,
		.tt_port = PORT_IBSA,
		.tt_enable_src = true,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_CONNREFUSED
	}, {
		.tt_desc = "IPv4 IBSA with MD5 disabled on both sides",
		.tt_domain = PF_INET,
		.tt_port = PORT_IBSA,
		.tt_enable_src = false,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_SENDRECV
	}, {
		.tt_desc = "IPv4 IBSA with MD5 enabled on src only",
		.tt_domain = PF_INET,
		.tt_port = PORT_IBSA,
		.tt_enable_src = true,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_CONNREFUSED
	}, {
		.tt_desc = "IPv4 IBSA with MD5 enabled on dst only",
		.tt_domain = PF_INET,
		.tt_port = PORT_IBSA,
		.tt_enable_src = false,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_SENDRECV
	}, {
		.tt_desc = "IPv6 IBSA with MD5 enabled on both sides",
		.tt_domain = PF_INET6,
		.tt_port = PORT_IBSA,
		.tt_enable_src = true,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_CONNREFUSED
	}, {
		.tt_desc = "IPv6 IBSA with MD5 disabled on both sides",
		.tt_domain = PF_INET6,
		.tt_port = PORT_IBSA,
		.tt_enable_src = false,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_SENDRECV
	}, {
		.tt_desc = "IPv6 IBSA with MD5 enabled on src only",
		.tt_domain = PF_INET6,
		.tt_port = PORT_IBSA,
		.tt_enable_src = true,
		.tt_enable_dst = false,
		.tt_pass = TCPSIG_CONNREFUSED
	}, {
		.tt_desc = "IPv6 IBSA with MD5 enabled on dst only",
		.tt_domain = PF_INET6,
		.tt_port = PORT_IBSA,
		.tt_enable_src = false,
		.tt_enable_dst = true,
		.tt_pass = TCPSIG_SENDRECV
	}
};

static bool
tcpsig_bind_dest(const tcpsig_test_t *test, int sock,
    struct sockaddr_storage *dst)
{
	socklen_t len;
	struct sockaddr_storage addr;

	(void) memset(&addr, 0, sizeof (struct sockaddr_storage));

	if (test->tt_domain == PF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)&addr;
		in->sin_family = AF_INET;
		in->sin_port = htons(test->tt_port);
		if (inet_pton(AF_INET, "127.0.0.1", &in->sin_addr) != 1) {
			warnx("TEST FAILED: %s: failed to convert 127.0.0.1 "
			    "to an IPv4 address", test->tt_desc);
			return (false);
		}
		len = sizeof (struct sockaddr_in);
	} else {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&addr;
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(test->tt_port);
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
tcpsig_connect(const tcpsig_test_t *test, int port, int src, int dst, int *cfd,
    const struct sockaddr *addr)
{
	struct timespec to = { .tv_nsec = sock_to };
	int namelen = test->tt_domain == PF_INET ? sizeof (struct sockaddr_in) :
	    sizeof (struct sockaddr_in6);
	int conn, opt;
	unsigned int optlen;
	port_event_t pe;

	if (listen(dst, 5) != 0) {
		warn("TEST FAILED: %s: failed to listen", test->tt_desc);
		return (false);
	}

	if (connect(src, addr, namelen) != 0 && errno != EINPROGRESS) {
		if (errno == ECONNREFUSED &&
		    test->tt_pass == TCPSIG_CONNREFUSED) {
			(void) printf("TEST PASSED: %s: connection refused\n",
			    test->tt_desc);
			return (true);
		}
		warn("TEST FAILED: %s: failed to connect", test->tt_desc);
		return (false);
	}

	if (port_associate(port, PORT_SOURCE_FD, src, POLLOUT, NULL) != 0) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: %s: could not port "
		    "associate to watch connect", test->tt_desc);
	}

	if (port_get(port, &pe, &to) != 0) {
		if (test->tt_pass == TCPSIG_NOCONNECT) {
			(void) printf(
			    "TEST PASSED: %s: correctly failed to connect\n",
			    test->tt_desc);
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

	optlen = sizeof (opt);
	if (getsockopt(conn, IPPROTO_TCP, TCP_MD5SIG, &opt, &optlen) != 0) {
		warn("TEST FAILED: %s: failed to retrieve accepted socket "
		    "TCP_MD5SIG option", test->tt_desc);
		return (false);
	}

	if (optlen != sizeof (opt)) {
		warn("TEST FAILED: %s: TCP_MD5SIG option has wrong length %d "
		    "(expected %ld).", test->tt_desc, optlen, sizeof (opt));
		return (false);
	}

	/*
	 * For tests where the TCP MD5 option is not enabled on the source, but
	 * is on the destination, and where we expect the connection to
	 * succeed, we also expect that the socket option has been disabled on
	 * accept(). Check.
	 */
	if (test->tt_enable_dst && !test->tt_enable_src &&
	    test->tt_pass == TCPSIG_SENDRECV && opt != 0) {
		warnx("TEST FAILED: %s: TCP_MD5SIG is set and should not be",
		    test->tt_desc);
		return (false);
	} else if (test->tt_enable_src && opt == 0) {
		warnx("TEST FAILED: %s: TCP_MD5SIG is not set and should be",
		    test->tt_desc);
		return (false);
	}

	if (test->tt_pass != TCPSIG_SENDRECV &&
	    test->tt_pass != TCPSIG_NODATA) {
		warnx("TEST FAILED: %s: expected connect to fail, but passed",
		    test->tt_desc);
		return (false);
	}

	*cfd = conn;
	return (true);
}

/*
 * Attempt to send data with the tcpsigs set up appropriately. This might fail,
 * hence our port_associate dance and unfortunately regrettable timeout.
 */
static bool
tcpsig_sendrecv(const tcpsig_test_t *test, int port, int src, int dst)
{
	struct timespec to = { .tv_nsec = sock_to };
	port_event_t pe;
	uint32_t data;
	ssize_t sret;

	if (send(src, &msgdata, sizeof (msgdata), MSG_NOSIGNAL) !=
	    sizeof (msgdata)) {
		warn("TEST FAILED: %s: failed to write message to socket",
		    test->tt_desc);
	}

	if (port_associate(port, PORT_SOURCE_FD, dst, POLLIN, NULL) != 0) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: %s: could not port "
		    "associate to watch recv", test->tt_desc);
	}

	if (port_get(port, &pe, &to) != 0) {
		if (test->tt_pass == TCPSIG_NODATA) {
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

	sret = recv(dst, &data, sizeof (data), MSG_DONTWAIT);
	if (sret != (ssize_t)sizeof (data)) {
		warnx("TEST FAILED: %s: failed to receive data: %zx",
		    test->tt_desc, sret);
		return (false);
	}

	if (test->tt_pass != TCPSIG_SENDRECV) {
		warnx("TEST FAILED: %s: found data, despite expecting not to",
		    test->tt_desc);
		return (false);
	}

	if (data != msgdata) {
		warnx("TEST FAILED: %s: data mismatch: expected 0x%x, found "
		    "0x%x", test->tt_desc, msgdata, data);
		return (false);
	}

	(void) printf("TEST PASSED: %s: successfully received data\n",
	    test->tt_desc);
	return (true);
}

static bool
tcpsig_test_one(const tcpsig_test_t *test)
{
	int src = -1, dst = -1, cfd = -1, port = -1, tdst;
	int x;
	bool ret = true;
	struct sockaddr_storage dst_addr;

	if ((port = port_create()) < 0)
		err(EXIT_FAILURE, "TEST FAILED: failed to create event port");

	src = socket(test->tt_domain, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (src < 0) {
		warn("TEST FAILED: %s: failed to create source socket",
		    test->tt_desc);
		ret = false;
		goto cleanup;
	}

	x = test->tt_enable_src ? 1 : 0;
	if (setsockopt(src, IPPROTO_TCP, TCP_MD5SIG, &x, sizeof (x)) != 0) {
		warn("TEST FAILED: %s: failed to configure src MD5SIG option",
		    test->tt_desc);
		ret = false;
		goto cleanup;
	}

	dst = socket(test->tt_domain, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (dst < 0) {
		warn("TEST FAILED: %s: failed to create destination socket",
		    test->tt_desc);
		ret = false;
		goto cleanup;
	}

	x = test->tt_enable_dst ? 1 : 0;
	if (setsockopt(dst, IPPROTO_TCP, TCP_MD5SIG, &x, sizeof (x)) != 0) {
		warn("TEST FAILED: %s: failed to configure dst MD5SIG option",
		    test->tt_desc);
		ret = false;
		goto cleanup;
	}

	if (!tcpsig_bind_dest(test, dst, &dst_addr)) {
		ret = false;
		goto cleanup;
	}

	if (!tcpsig_connect(test, port, src, dst, &cfd,
	    (struct sockaddr *)&dst_addr)) {
		ret = false;
		goto cleanup;
	}

	if (test->tt_pass != TCPSIG_SENDRECV && test->tt_pass != TCPSIG_NODATA)
		goto cleanup;

	tdst = cfd;

	if (!tcpsig_sendrecv(test, port, src, tdst)) {
		ret = false;
		goto cleanup;
	}

cleanup:
	if (port > -1)
		(void) close(port);
	if (src > -1) {
		(void) shutdown(src, SHUT_RDWR);
		(void) close(src);
	}
	if (dst > -1)
		(void) close(dst);
	if (cfd > -1)
		(void) close(cfd);
	return (ret);
}

int
main(int argc, char **argv)
{
	size_t max = ARRAY_SIZE(tcpsig_tests) - 1;
	int ret = EXIT_SUCCESS;

	if (argc == 2) {
		const char *errstr;
		size_t idx;

		idx = (size_t)strtonumx(argv[1], 0, max, &errstr, 0);
		if (errstr != NULL) {
			(void) fprintf(stderr, "Syntax: %s [test number]\n",
			    getprogname());
			(void) fprintf(stderr,
			    "Test number is in the range [0-%u]\n", max);
			(void) fprintf(stderr, "\nAvailable tests:\n");
			for (size_t i = 0; i <= max; i++) {
				(void) fprintf(stderr, "    %5d - %s\n", i,
				    tcpsig_tests[i].tt_desc);
			}
			return (EXIT_FAILURE);
		}

		if (!tcpsig_test_one(&tcpsig_tests[idx]))
			ret = EXIT_FAILURE;
	} else {
		for (size_t i = 0; i <= max; i++) {
			if (!tcpsig_test_one(&tcpsig_tests[i]))
				ret = EXIT_FAILURE;
		}
		if (ret == EXIT_SUCCESS)
			(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
