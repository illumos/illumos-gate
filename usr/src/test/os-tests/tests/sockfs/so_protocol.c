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
 * Basic tests to verify that SO_PROTOCOL, SO_DOMAIN, and SO_TYPE perform as we
 * expect.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <err.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <net/pfkeyv2.h>
#include <net/pfpolicy.h>

typedef struct {
	const char *sp_desc;
	int sp_dom;
	int sp_type;
	int sp_prot;
	int sp_expprot;
	bool sp_noproto;
} so_prot_test_t;

static const so_prot_test_t so_prot_tests[] = { {
	.sp_desc = "IPv4 TCP (prot=0)",
	.sp_dom = PF_INET,
	.sp_type = SOCK_STREAM,
	.sp_prot = 0,
	.sp_expprot = IPPROTO_TCP
}, {
	.sp_desc = "IPv4 TCP (prot=TCP)",
	.sp_dom = PF_INET,
	.sp_type = SOCK_STREAM,
	.sp_prot = IPPROTO_TCP,
	.sp_expprot = IPPROTO_TCP
}, {
	.sp_desc = "IPv4 UDP (prot=0)",
	.sp_dom = PF_INET,
	.sp_type = SOCK_DGRAM,
	.sp_prot = 0,
	.sp_expprot = IPPROTO_UDP
}, {
	.sp_desc = "IPv4 UDP (prot=UDP)",
	.sp_dom = PF_INET,
	.sp_type = SOCK_DGRAM,
	.sp_prot = IPPROTO_UDP,
	.sp_expprot = IPPROTO_UDP
}, {
	.sp_desc = "IPv4 SCTP (type=STREAM)",
	.sp_dom = PF_INET,
	.sp_type = SOCK_STREAM,
	.sp_prot = IPPROTO_SCTP,
	.sp_expprot = IPPROTO_SCTP
}, {
	.sp_desc = "IPv4 SCTP (type=SEQPACKET)",
	.sp_dom = PF_INET,
	.sp_type = SOCK_SEQPACKET,
	.sp_prot = IPPROTO_SCTP,
	.sp_expprot = IPPROTO_SCTP
}, {
	.sp_desc = "IPv6 TCP (prot=0)",
	.sp_dom = PF_INET6,
	.sp_type = SOCK_STREAM,
	.sp_prot = 0,
	.sp_expprot = IPPROTO_TCP
}, {
	.sp_desc = "IPv6 TCP (prot=TCP)",
	.sp_dom = PF_INET6,
	.sp_type = SOCK_STREAM,
	.sp_prot = IPPROTO_TCP,
	.sp_expprot = IPPROTO_TCP
}, {
	.sp_desc = "IPv6 UDP (prot=0)",
	.sp_dom = PF_INET6,
	.sp_type = SOCK_DGRAM,
	.sp_prot = 0,
	.sp_expprot = IPPROTO_UDP
}, {
	.sp_desc = "IPv6 UDP (prot=UDP)",
	.sp_dom = PF_INET6,
	.sp_type = SOCK_DGRAM,
	.sp_prot = IPPROTO_UDP,
	.sp_expprot = IPPROTO_UDP
}, {
	.sp_desc = "IPv6 SCTP (type=STREAM)",
	.sp_dom = PF_INET6,
	.sp_type = SOCK_STREAM,
	.sp_prot = IPPROTO_SCTP,
	.sp_expprot = IPPROTO_SCTP
}, {
	.sp_desc = "IPv6 SCTP (type=SEQPACKET)",
	.sp_dom = PF_INET6,
	.sp_type = SOCK_SEQPACKET,
	.sp_prot = IPPROTO_SCTP,
	.sp_expprot = IPPROTO_SCTP
}, {
	.sp_desc = "UDS (type=STREAM)",
	.sp_dom = PF_UNIX,
	.sp_type = SOCK_STREAM,
	.sp_prot = 0,
	.sp_expprot = 0
}, {
	.sp_desc = "UDS (type=DGRAM)",
	.sp_dom = PF_UNIX,
	.sp_type = SOCK_DGRAM,
	.sp_prot = 0,
	.sp_expprot = 0
}, {
	.sp_desc = "UDS (type=SEQPACKET)",
	.sp_dom = PF_UNIX,
	.sp_type = SOCK_SEQPACKET,
	.sp_prot = 0,
	.sp_expprot = 0
}, {
	.sp_desc = "PF_KEY",
	.sp_dom = PF_KEY,
	.sp_type = SOCK_RAW,
	.sp_prot = PF_KEY_V2,
	.sp_expprot = PF_KEY_V2
}, {
	.sp_desc = "PF_POLICY",
	.sp_dom = PF_POLICY,
	.sp_type = SOCK_RAW,
	.sp_prot = PF_POLICY_V1,
	.sp_expprot = PF_POLICY_V1
}, {
	.sp_desc = "ICMP",
	.sp_dom = PF_INET,
	.sp_type = SOCK_RAW,
	.sp_prot = IPPROTO_ICMP,
	.sp_expprot = IPPROTO_ICMP
}, {
	.sp_desc = "ICMPv6",
	.sp_dom = PF_INET6,
	.sp_type = SOCK_RAW,
	.sp_prot = IPPROTO_ICMPV6,
	.sp_expprot = IPPROTO_ICMPV6
}, {
	.sp_desc = "PF_ROUTE (IPv4)",
	.sp_dom = PF_ROUTE,
	.sp_type = SOCK_RAW,
	.sp_prot = AF_INET,
	.sp_expprot = AF_INET
}, {
	.sp_desc = "PF_ROUTE (IPv6)",
	.sp_dom = PF_ROUTE,
	.sp_type = SOCK_RAW,
	.sp_prot = AF_INET6,
	.sp_expprot = AF_INET6
}, {
	.sp_desc = "PF_ROUTE (IPv4+IPv6)",
	.sp_dom = PF_ROUTE,
	.sp_type = SOCK_RAW,
	.sp_prot = 0,
	.sp_expprot = 0
}, {
	.sp_desc = "Trill",
	.sp_dom = PF_TRILL,
	.sp_type = SOCK_DGRAM,
	.sp_prot = 0,
	.sp_expprot = 0
}  };

static bool
so_test_one(const so_prot_test_t *test)
{
	int s, opt;
	socklen_t len;
	bool ret = true;

	s = socket(test->sp_dom, test->sp_type, test->sp_prot);
	if (s < 0) {
		warn("TEST FAILED: %s: failed to create socket with "
		    "domain/type/protocol 0x%x/0x%x/0x%x", test->sp_desc,
		    test->sp_dom, test->sp_type, test->sp_prot);
		return (false);
	}

	len = sizeof (opt);
	if (getsockopt(s, SOL_SOCKET, SO_DOMAIN, &opt, &len) != 0) {
		warn("TEST FAILED: %s: failed to get SO_DOMAIN", test->sp_desc);
		ret = false;
	} else if (opt != test->sp_dom) {
		warnx("TEST FAILED: %s: expected domain 0x%x, but found 0x%x",
		    test->sp_desc, test->sp_dom, opt);
		ret = false;
	} else {
		(void) printf("TEST PASSED: %s: received correct domain\n",
		    test->sp_desc);
	}

	len = sizeof (opt);
	if (getsockopt(s, SOL_SOCKET, SO_TYPE, &opt, &len) != 0) {
		warn("TEST FAILED: %s: failed to get SO_TYPE", test->sp_desc);
		ret = false;
	} else if (opt != test->sp_type) {
		warnx("TEST FAILED: %s: expected type 0x%x, but found 0x%x",
		    test->sp_desc, test->sp_type, opt);
		ret = false;
	} else {
		(void) printf("TEST PASSED: %s: received correct type\n",
		    test->sp_desc);
	}

	len = sizeof (opt);
	if (getsockopt(s, SOL_SOCKET, SO_PROTOCOL, &opt, &len) != 0) {
		warn("TEST FAILED: %s: failed to get SO_PROTOCOL",
		    test->sp_desc);
		ret = false;
	} else if (opt != test->sp_expprot) {
		warnx("TEST FAILED: %s: expected protocol 0x%x, but found 0x%x",
		    test->sp_desc, test->sp_expprot, opt);
		ret = false;
	} else {
		(void) printf("TEST PASSED: %s: received correct protocol\n",
		    test->sp_desc);
	}

	VERIFY0(close(s));
	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(so_prot_tests); i++) {
		if (!so_test_one(&so_prot_tests[i]))
			ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS)
		(void) printf("All tests passed successfully\n");
	return (ret);
}
