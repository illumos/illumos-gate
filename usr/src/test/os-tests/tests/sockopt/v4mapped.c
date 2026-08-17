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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Tests for IP-level and IPv6-level socket options on connections that use
 * IPv4 on the wire but belong to AF_INET6 sockets. Such connections arise
 * when a dual-stack listener accepts a connection from an IPv4 peer, and
 * when an AF_INET6 socket connects to an IPv4-mapped IPv6 address.
 *
 * On these connections, options at the IPPROTO_IP level must be available,
 * along with the subset of IPPROTO_IPV6 options which control fields that
 * are also present in the IPv4 header: IPV6_UNICAST_HOPS, IPV6_TCLASS and
 * IPV6_MINHOPCOUNT. Other IPPROTO_IPV6 options must remain unavailable.
 * IPPROTO_IP options must also remain unavailable on sockets that use IPv6
 * on the wire, and the IPv6 options must remain unavailable on AF_INET
 * sockets.
 *
 * As well as walking through set/get combinations on TCP and UDP sockets in
 * the various address configurations, this verifies that data still flows
 * once options have been changed, and that a minimum TTL configured through
 * IP_MINTTL on an IPv4-mapped connection is applied to inbound segments.
 */

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * How long to wait for data that is expected to arrive, how long to wait
 * before concluding that dropped data is not going to arrive, and how long
 * to allow for a TCP retransmission to deliver data that was previously
 * dropped.
 */
#define	FLOW_WAIT_MS	5000
#define	DROP_WAIT_MS	300
#define	REXMIT_WAIT_MS	15000

static const uint32_t flow_msg = 0x77e57e57;

typedef enum {
	SOP_SET,	/* set must succeed and the value read back match */
	SOP_SET_ERR,	/* set must fail with the given errno */
	SOP_GET_ERR	/* get must fail with the given errno */
} probe_kind_t;

typedef struct {
	probe_kind_t p_kind;
	const char *p_desc;
	int p_level;
	int p_name;
	int p_value;
	int p_get_level;	/* SOP_SET: the option to read back */
	int p_get_name;
	int p_errno;
} probe_t;

typedef enum {
	CONN_TCP_ACCEPT,	/* test the accepted socket */
	CONN_TCP_CLIENT,	/* test the connecting socket */
	CONN_UDP,		/* test a connected UDP socket */
	CONN_NONE		/* test an unconnected socket */
} conn_kind_t;

typedef struct {
	const char *sc_desc;
	conn_kind_t sc_kind;
	int sc_lfam;		/* listener/peer socket family */
	bool sc_v6only;		/* IPV6_V6ONLY on an AF_INET6 listener */
	int sc_cfam;		/* client socket family */
	const char *sc_dst;	/* address the client connects to */
	int sc_type;		/* CONN_NONE: socket type */
	const probe_t *sc_probes;
	size_t sc_nprobes;
	bool sc_dataflow;	/* verify that data flows after the probes */
} scenario_t;

/*
 * Probes for a connection which uses IPv4 on the wire via an AF_INET6
 * socket. The IPPROTO_IP options and the three shared-field IPPROTO_IPV6
 * options must work, reading and writing the same underlying state, while
 * other IPPROTO_IPV6 options must be rejected. The minimum TTL is returned
 * to zero at the end so that the subsequent data flow check is not
 * affected by it.
 */
static const probe_t mapped_probes[] = {
	{
		.p_kind = SOP_SET,
		.p_desc = "IP_TTL round trip",
		.p_level = IPPROTO_IP,
		.p_name = IP_TTL,
		.p_value = 53,
		.p_get_level = IPPROTO_IP,
		.p_get_name = IP_TTL
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IP_TOS round trip",
		.p_level = IPPROTO_IP,
		.p_name = IP_TOS,
		.p_value = 0x48,
		.p_get_level = IPPROTO_IP,
		.p_get_name = IP_TOS
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IPV6_UNICAST_HOPS round trip",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_UNICAST_HOPS,
		.p_value = 63,
		.p_get_level = IPPROTO_IPV6,
		.p_get_name = IPV6_UNICAST_HOPS
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IPV6_TCLASS round trip",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_TCLASS,
		.p_value = 0x8c,
		.p_get_level = IPPROTO_IPV6,
		.p_get_name = IPV6_TCLASS
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IPV6_MINHOPCOUNT round trip",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_MINHOPCOUNT,
		.p_value = 90,
		.p_get_level = IPPROTO_IPV6,
		.p_get_name = IPV6_MINHOPCOUNT
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IP_TTL is visible as IPV6_UNICAST_HOPS",
		.p_level = IPPROTO_IP,
		.p_name = IP_TTL,
		.p_value = 77,
		.p_get_level = IPPROTO_IPV6,
		.p_get_name = IPV6_UNICAST_HOPS
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IPV6_UNICAST_HOPS is visible as IP_TTL",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_UNICAST_HOPS,
		.p_value = 44,
		.p_get_level = IPPROTO_IP,
		.p_get_name = IP_TTL
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IPV6_TCLASS is mirrored to IP_TOS",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_TCLASS,
		.p_value = 0x28,
		.p_get_level = IPPROTO_IP,
		.p_get_name = IP_TOS
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IP_TOS is visible as IPV6_TCLASS",
		.p_level = IPPROTO_IP,
		.p_name = IP_TOS,
		.p_value = 0x58,
		.p_get_level = IPPROTO_IPV6,
		.p_get_name = IPV6_TCLASS
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IP_MINTTL is visible as IPV6_MINHOPCOUNT",
		.p_level = IPPROTO_IP,
		.p_name = IP_MINTTL,
		.p_value = 42,
		.p_get_level = IPPROTO_IPV6,
		.p_get_name = IPV6_MINHOPCOUNT
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IPV6_MINHOPCOUNT clears IP_MINTTL",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_MINHOPCOUNT,
		.p_value = 0,
		.p_get_level = IPPROTO_IP,
		.p_get_name = IP_MINTTL
	}, {
		.p_kind = SOP_SET_ERR,
		.p_desc = "IPV6_RECVTCLASS cannot be set",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_RECVTCLASS,
		.p_value = 1,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_GET_ERR,
		.p_desc = "IPV6_RECVTCLASS cannot be read",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_RECVTCLASS,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_SET_ERR,
		.p_desc = "IPV6_USE_MIN_MTU cannot be set",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_USE_MIN_MTU,
		.p_value = 1,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_GET_ERR,
		.p_desc = "IPV6_USE_MIN_MTU cannot be read",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_USE_MIN_MTU,
		.p_errno = EINVAL
	}
};

/*
 * Probes for a native IPv4 TCP connection. The IPPROTO_IP options must
 * work as they always have, and the three shared-field IPPROTO_IPV6
 * options must be rejected on an AF_INET socket even though the connection
 * uses IPv4 on the wire.
 */
static const probe_t v4_tcp_probes[] = {
	{
		.p_kind = SOP_SET,
		.p_desc = "IP_TTL round trip",
		.p_level = IPPROTO_IP,
		.p_name = IP_TTL,
		.p_value = 53,
		.p_get_level = IPPROTO_IP,
		.p_get_name = IP_TTL
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IP_TOS round trip",
		.p_level = IPPROTO_IP,
		.p_name = IP_TOS,
		.p_value = 0x48,
		.p_get_level = IPPROTO_IP,
		.p_get_name = IP_TOS
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IP_MINTTL round trip",
		.p_level = IPPROTO_IP,
		.p_name = IP_MINTTL,
		.p_value = 100,
		.p_get_level = IPPROTO_IP,
		.p_get_name = IP_MINTTL
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IP_MINTTL can be cleared",
		.p_level = IPPROTO_IP,
		.p_name = IP_MINTTL,
		.p_value = 0,
		.p_get_level = IPPROTO_IP,
		.p_get_name = IP_MINTTL
	}, {
		.p_kind = SOP_SET_ERR,
		.p_desc = "IPV6_UNICAST_HOPS cannot be set",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_UNICAST_HOPS,
		.p_value = 63,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_SET_ERR,
		.p_desc = "IPV6_TCLASS cannot be set",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_TCLASS,
		.p_value = 0x28,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_SET_ERR,
		.p_desc = "IPV6_MINHOPCOUNT cannot be set",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_MINHOPCOUNT,
		.p_value = 90,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_GET_ERR,
		.p_desc = "IPV6_UNICAST_HOPS cannot be read",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_UNICAST_HOPS,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_GET_ERR,
		.p_desc = "IPV6_TCLASS cannot be read",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_TCLASS,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_GET_ERR,
		.p_desc = "IPV6_MINHOPCOUNT cannot be read",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_MINHOPCOUNT,
		.p_errno = EINVAL
	}
};

/*
 * Probes for a native IPv6 TCP connection. The IPPROTO_IPV6 options must
 * work and the IPPROTO_IP options must be rejected. The minimum hop count
 * is returned to zero at the end so that the subsequent data flow check is
 * not affected by it.
 */
static const probe_t v6_tcp_probes[] = {
	{
		.p_kind = SOP_SET,
		.p_desc = "IPV6_UNICAST_HOPS round trip",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_UNICAST_HOPS,
		.p_value = 63,
		.p_get_level = IPPROTO_IPV6,
		.p_get_name = IPV6_UNICAST_HOPS
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IPV6_TCLASS round trip",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_TCLASS,
		.p_value = 0x8c,
		.p_get_level = IPPROTO_IPV6,
		.p_get_name = IPV6_TCLASS
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IPV6_MINHOPCOUNT round trip",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_MINHOPCOUNT,
		.p_value = 90,
		.p_get_level = IPPROTO_IPV6,
		.p_get_name = IPV6_MINHOPCOUNT
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IPV6_MINHOPCOUNT can be cleared",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_MINHOPCOUNT,
		.p_value = 0,
		.p_get_level = IPPROTO_IPV6,
		.p_get_name = IPV6_MINHOPCOUNT
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IPV6_RECVTCLASS round trip",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_RECVTCLASS,
		.p_value = 1,
		.p_get_level = IPPROTO_IPV6,
		.p_get_name = IPV6_RECVTCLASS
	}, {
		.p_kind = SOP_SET_ERR,
		.p_desc = "IP_TTL cannot be set",
		.p_level = IPPROTO_IP,
		.p_name = IP_TTL,
		.p_value = 53,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_SET_ERR,
		.p_desc = "IP_TOS cannot be set",
		.p_level = IPPROTO_IP,
		.p_name = IP_TOS,
		.p_value = 0x48,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_SET_ERR,
		.p_desc = "IP_MINTTL cannot be set",
		.p_level = IPPROTO_IP,
		.p_name = IP_MINTTL,
		.p_value = 100,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_GET_ERR,
		.p_desc = "IP_TTL cannot be read",
		.p_level = IPPROTO_IP,
		.p_name = IP_TTL,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_GET_ERR,
		.p_desc = "IP_TOS cannot be read",
		.p_level = IPPROTO_IP,
		.p_name = IP_TOS,
		.p_errno = EINVAL
	}
};

/*
 * Probes for an unconnected AF_INET6 socket, which uses IPv6 on the wire
 * until it is connected somewhere. The IPPROTO_IP options must be rejected
 * and the IPPROTO_IPV6 options must work. Shared between SOCK_STREAM and
 * SOCK_DGRAM scenarios.
 */
static const probe_t unconn6_probes[] = {
	{
		.p_kind = SOP_SET,
		.p_desc = "IPV6_UNICAST_HOPS round trip",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_UNICAST_HOPS,
		.p_value = 63,
		.p_get_level = IPPROTO_IPV6,
		.p_get_name = IPV6_UNICAST_HOPS
	}, {
		.p_kind = SOP_SET_ERR,
		.p_desc = "IP_TTL cannot be set",
		.p_level = IPPROTO_IP,
		.p_name = IP_TTL,
		.p_value = 53,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_SET_ERR,
		.p_desc = "IP_MINTTL cannot be set",
		.p_level = IPPROTO_IP,
		.p_name = IP_MINTTL,
		.p_value = 100,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_GET_ERR,
		.p_desc = "IP_TTL cannot be read",
		.p_level = IPPROTO_IP,
		.p_name = IP_TTL,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_GET_ERR,
		.p_desc = "IP_TOS cannot be read",
		.p_level = IPPROTO_IP,
		.p_name = IP_TOS,
		.p_errno = EINVAL
	}
};

/*
 * Probes for a UDP AF_INET6 socket connected to an IPv4-mapped address.
 */
static const probe_t udp_mapped_probes[] = {
	{
		.p_kind = SOP_SET,
		.p_desc = "IP_TTL round trip",
		.p_level = IPPROTO_IP,
		.p_name = IP_TTL,
		.p_value = 53,
		.p_get_level = IPPROTO_IP,
		.p_get_name = IP_TTL
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IP_TOS round trip",
		.p_level = IPPROTO_IP,
		.p_name = IP_TOS,
		.p_value = 0x48,
		.p_get_level = IPPROTO_IP,
		.p_get_name = IP_TOS
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IP_TTL is visible as IPV6_UNICAST_HOPS",
		.p_level = IPPROTO_IP,
		.p_name = IP_TTL,
		.p_value = 77,
		.p_get_level = IPPROTO_IPV6,
		.p_get_name = IPV6_UNICAST_HOPS
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IPV6_TCLASS is mirrored to IP_TOS",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_TCLASS,
		.p_value = 0x28,
		.p_get_level = IPPROTO_IP,
		.p_get_name = IP_TOS
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IP_TOS is visible as IPV6_TCLASS",
		.p_level = IPPROTO_IP,
		.p_name = IP_TOS,
		.p_value = 0x58,
		.p_get_level = IPPROTO_IPV6,
		.p_get_name = IPV6_TCLASS
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IP_MINTTL is visible as IPV6_MINHOPCOUNT",
		.p_level = IPPROTO_IP,
		.p_name = IP_MINTTL,
		.p_value = 42,
		.p_get_level = IPPROTO_IPV6,
		.p_get_name = IPV6_MINHOPCOUNT
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IPV6_MINHOPCOUNT clears IP_MINTTL",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_MINHOPCOUNT,
		.p_value = 0,
		.p_get_level = IPPROTO_IP,
		.p_get_name = IP_MINTTL
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IPV6_USE_MIN_MTU remains available",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_USE_MIN_MTU,
		.p_value = 1,
		.p_get_level = IPPROTO_IPV6,
		.p_get_name = IPV6_USE_MIN_MTU
	}
};

/*
 * Probes for a native IPv4 UDP socket.
 */
static const probe_t v4_udp_probes[] = {
	{
		.p_kind = SOP_SET,
		.p_desc = "IP_TTL round trip",
		.p_level = IPPROTO_IP,
		.p_name = IP_TTL,
		.p_value = 53,
		.p_get_level = IPPROTO_IP,
		.p_get_name = IP_TTL
	}, {
		.p_kind = SOP_SET,
		.p_desc = "IP_TOS round trip",
		.p_level = IPPROTO_IP,
		.p_name = IP_TOS,
		.p_value = 0x48,
		.p_get_level = IPPROTO_IP,
		.p_get_name = IP_TOS
	}, {
		.p_kind = SOP_SET_ERR,
		.p_desc = "IPV6_UNICAST_HOPS cannot be set",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_UNICAST_HOPS,
		.p_value = 63,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_SET_ERR,
		.p_desc = "IPV6_TCLASS cannot be set",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_TCLASS,
		.p_value = 0x28,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_GET_ERR,
		.p_desc = "IPV6_UNICAST_HOPS cannot be read",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_UNICAST_HOPS,
		.p_errno = EINVAL
	}, {
		.p_kind = SOP_GET_ERR,
		.p_desc = "IPV6_TCLASS cannot be read",
		.p_level = IPPROTO_IPV6,
		.p_name = IPV6_TCLASS,
		.p_errno = EINVAL
	}
};

static socklen_t
mkaddr(struct sockaddr_storage *ss, int fam, const char *addr, in_port_t port)
{
	(void) memset(ss, 0, sizeof (*ss));
	if (fam == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)ss;

		sin->sin_family = AF_INET;
		sin->sin_port = port;
		if (addr != NULL &&
		    inet_pton(AF_INET, addr, &sin->sin_addr) != 1) {
			errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
			    "convert %s to an IPv4 address", addr);
		}
		return (sizeof (*sin));
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = port;
		if (addr != NULL &&
		    inet_pton(AF_INET6, addr, &sin6->sin6_addr) != 1) {
			errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
			    "convert %s to an IPv6 address", addr);
		}
		return (sizeof (*sin6));
	}
}

static in_port_t
addr_port(const struct sockaddr_storage *ss)
{
	if (ss->ss_family == AF_INET)
		return (((const struct sockaddr_in *)ss)->sin_port);
	return (((const struct sockaddr_in6 *)ss)->sin6_port);
}

/*
 * Establish a TCP connection over loopback according to the scenario and
 * return the socket under test along with its peer.
 */
static bool
tcp_pair(const scenario_t *sc, int *testfd, int *peerfd)
{
	struct sockaddr_storage laddr, daddr;
	int lsock = -1, csock = -1, asock = -1;
	int v6only = sc->sc_v6only ? 1 : 0;
	socklen_t llen, dlen;

	lsock = socket(sc->sc_lfam, SOCK_STREAM, 0);
	if (lsock == -1) {
		warn("TEST FAILED: %s: failed to create listener",
		    sc->sc_desc);
		goto fail;
	}

	if (sc->sc_lfam == AF_INET6 && setsockopt(lsock, IPPROTO_IPV6,
	    IPV6_V6ONLY, &v6only, sizeof (v6only)) != 0) {
		warn("TEST FAILED: %s: failed to set IPV6_V6ONLY",
		    sc->sc_desc);
		goto fail;
	}

	llen = mkaddr(&laddr, sc->sc_lfam, NULL, htons(0));
	if (bind(lsock, (struct sockaddr *)&laddr, llen) != 0) {
		warn("TEST FAILED: %s: failed to bind listener", sc->sc_desc);
		goto fail;
	}
	if (listen(lsock, 5) != 0) {
		warn("TEST FAILED: %s: failed to listen", sc->sc_desc);
		goto fail;
	}
	llen = sizeof (laddr);
	if (getsockname(lsock, (struct sockaddr *)&laddr, &llen) != 0) {
		warn("TEST FAILED: %s: failed to retrieve listener address",
		    sc->sc_desc);
		goto fail;
	}

	csock = socket(sc->sc_cfam, SOCK_STREAM, 0);
	if (csock == -1) {
		warn("TEST FAILED: %s: failed to create client", sc->sc_desc);
		goto fail;
	}

	dlen = mkaddr(&daddr, sc->sc_cfam, sc->sc_dst, addr_port(&laddr));
	if (connect(csock, (struct sockaddr *)&daddr, dlen) != 0) {
		warn("TEST FAILED: %s: failed to connect to %s", sc->sc_desc,
		    sc->sc_dst);
		goto fail;
	}

	asock = accept(lsock, NULL, NULL);
	if (asock == -1) {
		warn("TEST FAILED: %s: failed to accept", sc->sc_desc);
		goto fail;
	}

	(void) close(lsock);

	if (sc->sc_kind == CONN_TCP_ACCEPT) {
		*testfd = asock;
		*peerfd = csock;
	} else {
		*testfd = csock;
		*peerfd = asock;
	}
	return (true);

fail:
	if (lsock != -1)
		(void) close(lsock);
	if (csock != -1)
		(void) close(csock);
	if (asock != -1)
		(void) close(asock);
	return (false);
}

/*
 * Create a bound UDP peer socket and a UDP client socket connected to it
 * according to the scenario. The connected client is the socket under test.
 */
static bool
udp_pair(const scenario_t *sc, int *testfd, int *peerfd)
{
	struct sockaddr_storage paddr, daddr;
	int psock = -1, csock = -1;
	socklen_t plen, dlen;

	psock = socket(sc->sc_lfam, SOCK_DGRAM, 0);
	if (psock == -1) {
		warn("TEST FAILED: %s: failed to create peer", sc->sc_desc);
		goto fail;
	}

	plen = mkaddr(&paddr, sc->sc_lfam, NULL, htons(0));
	if (bind(psock, (struct sockaddr *)&paddr, plen) != 0) {
		warn("TEST FAILED: %s: failed to bind peer", sc->sc_desc);
		goto fail;
	}
	plen = sizeof (paddr);
	if (getsockname(psock, (struct sockaddr *)&paddr, &plen) != 0) {
		warn("TEST FAILED: %s: failed to retrieve peer address",
		    sc->sc_desc);
		goto fail;
	}

	csock = socket(sc->sc_cfam, SOCK_DGRAM, 0);
	if (csock == -1) {
		warn("TEST FAILED: %s: failed to create client", sc->sc_desc);
		goto fail;
	}

	dlen = mkaddr(&daddr, sc->sc_cfam, sc->sc_dst, addr_port(&paddr));
	if (connect(csock, (struct sockaddr *)&daddr, dlen) != 0) {
		warn("TEST FAILED: %s: failed to connect to %s", sc->sc_desc,
		    sc->sc_dst);
		goto fail;
	}

	*testfd = csock;
	*peerfd = psock;
	return (true);

fail:
	if (psock != -1)
		(void) close(psock);
	if (csock != -1)
		(void) close(csock);
	return (false);
}

static bool
probe_run(const char *scen, int fd, const probe_t *p)
{
	socklen_t len = sizeof (int);
	int val = p->p_value;

	switch (p->p_kind) {
	case SOP_SET:
		if (setsockopt(fd, p->p_level, p->p_name, &val,
		    sizeof (val)) != 0) {
			warn("TEST FAILED: %s: %s: setsockopt", scen,
			    p->p_desc);
			return (false);
		}
		val = -1;
		if (getsockopt(fd, p->p_get_level, p->p_get_name, &val,
		    &len) != 0) {
			warn("TEST FAILED: %s: %s: getsockopt", scen,
			    p->p_desc);
			return (false);
		}
		if (val != p->p_value) {
			warnx("TEST FAILED: %s: %s: expected %d, found %d",
			    scen, p->p_desc, p->p_value, val);
			return (false);
		}
		break;
	case SOP_SET_ERR:
		if (setsockopt(fd, p->p_level, p->p_name, &val,
		    sizeof (val)) != -1) {
			warnx("TEST FAILED: %s: %s: setsockopt incorrectly "
			    "passed", scen, p->p_desc);
			return (false);
		}
		if (errno != p->p_errno) {
			warnx("TEST FAILED: %s: %s: expected errno %s, "
			    "found %s", scen, p->p_desc,
			    strerrorname_np(p->p_errno),
			    strerrorname_np(errno));
			return (false);
		}
		break;
	case SOP_GET_ERR:
		if (getsockopt(fd, p->p_level, p->p_name, &val, &len) != -1) {
			warnx("TEST FAILED: %s: %s: getsockopt incorrectly "
			    "passed", scen, p->p_desc);
			return (false);
		}
		if (errno != p->p_errno) {
			warnx("TEST FAILED: %s: %s: expected errno %s, "
			    "found %s", scen, p->p_desc,
			    strerrorname_np(p->p_errno),
			    strerrorname_np(errno));
			return (false);
		}
		break;
	}

	(void) printf("TEST PASSED: %s: %s\n", scen, p->p_desc);
	return (true);
}

static bool
stream_flow(const char *scen, const char *dir, int src, int dst)
{
	struct pollfd pfd = { .fd = dst, .events = POLLIN };
	uint32_t rval = 0;

	if (send(src, &flow_msg, sizeof (flow_msg), 0) !=
	    (ssize_t)sizeof (flow_msg)) {
		warn("TEST FAILED: %s: %s: send", scen, dir);
		return (false);
	}
	if (poll(&pfd, 1, FLOW_WAIT_MS) != 1) {
		warnx("TEST FAILED: %s: %s: timed out waiting for data",
		    scen, dir);
		return (false);
	}
	if (recv(dst, &rval, sizeof (rval), MSG_DONTWAIT) !=
	    (ssize_t)sizeof (rval) || rval != flow_msg) {
		warnx("TEST FAILED: %s: %s: failed to receive data", scen,
		    dir);
		return (false);
	}
	return (true);
}

/*
 * Send a datagram from the connected socket to its peer, then have the peer
 * reply to the received source address, and check that both arrive.
 */
static bool
dgram_flow(const char *scen, int csock, int psock)
{
	struct pollfd pfd = { .fd = psock, .events = POLLIN };
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof (from);
	uint32_t rval = 0;

	if (send(csock, &flow_msg, sizeof (flow_msg), 0) !=
	    (ssize_t)sizeof (flow_msg)) {
		warn("TEST FAILED: %s: failed to send to peer", scen);
		return (false);
	}
	if (poll(&pfd, 1, FLOW_WAIT_MS) != 1) {
		warnx("TEST FAILED: %s: timed out waiting for the peer to "
		    "receive data", scen);
		return (false);
	}
	if (recvfrom(psock, &rval, sizeof (rval), MSG_DONTWAIT,
	    (struct sockaddr *)&from, &fromlen) !=
	    (ssize_t)sizeof (rval) || rval != flow_msg) {
		warnx("TEST FAILED: %s: peer failed to receive data", scen);
		return (false);
	}

	if (sendto(psock, &flow_msg, sizeof (flow_msg), 0,
	    (struct sockaddr *)&from, fromlen) !=
	    (ssize_t)sizeof (flow_msg)) {
		warn("TEST FAILED: %s: peer failed to reply", scen);
		return (false);
	}
	pfd.fd = csock;
	rval = 0;
	if (poll(&pfd, 1, FLOW_WAIT_MS) != 1) {
		warnx("TEST FAILED: %s: timed out waiting for the reply",
		    scen);
		return (false);
	}
	if (recv(csock, &rval, sizeof (rval), MSG_DONTWAIT) !=
	    (ssize_t)sizeof (rval) || rval != flow_msg) {
		warnx("TEST FAILED: %s: failed to receive the reply", scen);
		return (false);
	}
	return (true);
}

static const scenario_t scenarios[] = {
	{
		.sc_desc = "TCP mapped accept",
		.sc_kind = CONN_TCP_ACCEPT,
		.sc_lfam = AF_INET6,
		.sc_v6only = false,
		.sc_cfam = AF_INET,
		.sc_dst = "127.0.0.1",
		.sc_probes = mapped_probes,
		.sc_nprobes = ARRAY_SIZE(mapped_probes),
		.sc_dataflow = true
	}, {
		.sc_desc = "TCP mapped connect",
		.sc_kind = CONN_TCP_CLIENT,
		.sc_lfam = AF_INET,
		.sc_cfam = AF_INET6,
		.sc_dst = "::ffff:127.0.0.1",
		.sc_probes = mapped_probes,
		.sc_nprobes = ARRAY_SIZE(mapped_probes),
		.sc_dataflow = true
	}, {
		.sc_desc = "TCP native IPv4 accept",
		.sc_kind = CONN_TCP_ACCEPT,
		.sc_lfam = AF_INET,
		.sc_cfam = AF_INET,
		.sc_dst = "127.0.0.1",
		.sc_probes = v4_tcp_probes,
		.sc_nprobes = ARRAY_SIZE(v4_tcp_probes),
		.sc_dataflow = true
	}, {
		.sc_desc = "TCP native IPv6 accept",
		.sc_kind = CONN_TCP_ACCEPT,
		.sc_lfam = AF_INET6,
		.sc_v6only = true,
		.sc_cfam = AF_INET6,
		.sc_dst = "::1",
		.sc_probes = v6_tcp_probes,
		.sc_nprobes = ARRAY_SIZE(v6_tcp_probes),
		.sc_dataflow = true
	}, {
		.sc_desc = "TCP unconnected AF_INET6",
		.sc_kind = CONN_NONE,
		.sc_cfam = AF_INET6,
		.sc_type = SOCK_STREAM,
		.sc_probes = unconn6_probes,
		.sc_nprobes = ARRAY_SIZE(unconn6_probes)
	}, {
		.sc_desc = "UDP mapped connect",
		.sc_kind = CONN_UDP,
		.sc_lfam = AF_INET,
		.sc_cfam = AF_INET6,
		.sc_dst = "::ffff:127.0.0.1",
		.sc_probes = udp_mapped_probes,
		.sc_nprobes = ARRAY_SIZE(udp_mapped_probes),
		.sc_dataflow = true
	}, {
		.sc_desc = "UDP native IPv4",
		.sc_kind = CONN_UDP,
		.sc_lfam = AF_INET,
		.sc_cfam = AF_INET,
		.sc_dst = "127.0.0.1",
		.sc_probes = v4_udp_probes,
		.sc_nprobes = ARRAY_SIZE(v4_udp_probes),
		.sc_dataflow = true
	}, {
		.sc_desc = "UDP unconnected AF_INET6",
		.sc_kind = CONN_NONE,
		.sc_cfam = AF_INET6,
		.sc_type = SOCK_DGRAM,
		.sc_probes = unconn6_probes,
		.sc_nprobes = ARRAY_SIZE(unconn6_probes)
	}
};

static bool
scenario_run(const scenario_t *sc)
{
	int testfd = -1, peerfd = -1;
	bool ret = true;

	switch (sc->sc_kind) {
	case CONN_TCP_ACCEPT:
	case CONN_TCP_CLIENT:
		if (!tcp_pair(sc, &testfd, &peerfd))
			return (false);
		break;
	case CONN_UDP:
		if (!udp_pair(sc, &testfd, &peerfd))
			return (false);
		break;
	case CONN_NONE:
		testfd = socket(sc->sc_cfam, sc->sc_type, 0);
		if (testfd == -1) {
			warn("TEST FAILED: %s: failed to create socket",
			    sc->sc_desc);
			return (false);
		}
		break;
	}

	for (size_t i = 0; i < sc->sc_nprobes; i++) {
		if (!probe_run(sc->sc_desc, testfd, &sc->sc_probes[i]))
			ret = false;
	}

	if (sc->sc_dataflow) {
		bool flow;

		if (sc->sc_kind == CONN_UDP) {
			flow = dgram_flow(sc->sc_desc, testfd, peerfd);
		} else {
			flow = stream_flow(sc->sc_desc, "test to peer",
			    testfd, peerfd) &&
			    stream_flow(sc->sc_desc, "peer to test",
			    peerfd, testfd);
		}
		if (flow) {
			(void) printf("TEST PASSED: %s: data flows\n",
			    sc->sc_desc);
		} else {
			ret = false;
		}
	}

	if (testfd != -1)
		(void) close(testfd);
	if (peerfd != -1)
		(void) close(peerfd);
	return (ret);
}

/*
 * Verify that IP_MINTTL set on the socket accepted from an IPv4 peer by a
 * dual-stack listener is applied to inbound segments. The peer transmits
 * with a TTL below the configured minimum and the data must not arrive
 * until the minimum is cleared, at which point TCP retransmission delivers
 * it.
 */
static bool
test_mapped_minttl(void)
{
	const char *desc = "TCP mapped accept honours IP_MINTTL";
	const scenario_t sc = {
		.sc_desc = desc,
		.sc_kind = CONN_TCP_ACCEPT,
		.sc_lfam = AF_INET6,
		.sc_v6only = false,
		.sc_cfam = AF_INET,
		.sc_dst = "127.0.0.1"
	};
	struct pollfd pfd = { .events = POLLIN };
	int asock = -1, csock = -1;
	uint32_t rval = 0;
	bool ret = false;
	int val, pres;

	if (!tcp_pair(&sc, &asock, &csock))
		return (false);

	val = 200;
	if (setsockopt(csock, IPPROTO_IP, IP_TTL, &val, sizeof (val)) != 0) {
		warn("TEST FAILED: %s: failed to set the peer's IP_TTL",
		    desc);
		goto out;
	}
	val = 255;
	if (setsockopt(asock, IPPROTO_IP, IP_MINTTL, &val,
	    sizeof (val)) != 0) {
		warn("TEST FAILED: %s: failed to set IP_MINTTL", desc);
		goto out;
	}

	if (send(csock, &flow_msg, sizeof (flow_msg), 0) !=
	    (ssize_t)sizeof (flow_msg)) {
		warn("TEST FAILED: %s: send", desc);
		goto out;
	}

	pfd.fd = asock;
	pres = poll(&pfd, 1, DROP_WAIT_MS);
	if (pres == -1) {
		warn("TEST FAILED: %s: poll", desc);
		goto out;
	}
	if (pres != 0) {
		warnx("TEST FAILED: %s: data arrived despite the TTL being "
		    "below IP_MINTTL", desc);
		goto out;
	}

	val = 0;
	if (setsockopt(asock, IPPROTO_IP, IP_MINTTL, &val,
	    sizeof (val)) != 0) {
		warn("TEST FAILED: %s: failed to clear IP_MINTTL", desc);
		goto out;
	}

	if (poll(&pfd, 1, REXMIT_WAIT_MS) != 1) {
		warnx("TEST FAILED: %s: timed out waiting for data after "
		    "clearing IP_MINTTL", desc);
		goto out;
	}
	if (recv(asock, &rval, sizeof (rval), MSG_DONTWAIT) !=
	    (ssize_t)sizeof (rval) || rval != flow_msg) {
		warnx("TEST FAILED: %s: failed to receive data", desc);
		goto out;
	}

	(void) printf("TEST PASSED: %s\n", desc);
	ret = true;
out:
	if (asock != -1)
		(void) close(asock);
	if (csock != -1)
		(void) close(csock);
	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(scenarios); i++) {
		if (!scenario_run(&scenarios[i]))
			ret = EXIT_FAILURE;
	}

	if (!test_mapped_minttl())
		ret = EXIT_FAILURE;

	if (ret == EXIT_SUCCESS)
		(void) printf("All tests passed successfully\n");

	return (ret);
}
