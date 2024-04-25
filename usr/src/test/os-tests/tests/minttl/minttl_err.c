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
 * Go through and test various cases that should fail with setting both
 * IP_MINTTL and IPV6_MINHOPCOUNT. In particular we want to verify that the
 * following fail:
 *
 *  o Testing it on non-IP related sockets (UDS, PF_KEY, etc.)
 *  o Setting IP_MINTTL on an IPv6 socket and IPV6_MINHOPCOUNT on IPv4
 *  o Using negative values on supported sockets
 *  o Using values greater than 255 on supported sockets
 *
 * This does not test using the wrong socket level for a given option because
 * they can end up as valid settings.
 */

#include <stdlib.h>
#include <err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <net/pfkeyv2.h>
#include <net/pfpolicy.h>

typedef struct {
	const char *me_desc;
	int me_domain;
	int me_type;
	int me_proto;
	int me_value;
	int me_level;
	int me_sockopt;
	int me_errno;
} minttl_err_test_t;

static const minttl_err_test_t minttl_err_tests[] = {
	{
		.me_desc = "IP_MINTTL: UDS SOCK_STREAM not supported",
		.me_domain = PF_UNIX,
		.me_type = SOCK_STREAM,
		.me_level = IPPROTO_IP,
		.me_sockopt = IP_MINTTL,
		.me_errno = ENOPROTOOPT
	}, {
		.me_desc = "IP_MINTTL: UDS SOCK_DGRAM not supported",
		.me_domain = PF_UNIX,
		.me_type = SOCK_DGRAM,
		.me_level = IPPROTO_IP,
		.me_sockopt = IP_MINTTL,
		.me_errno = ENOPROTOOPT
	}, {
		.me_desc = "IP_MINTTL: UDS SOCK_SEQPACKET not supported",
		.me_domain = PF_UNIX,
		.me_type = SOCK_SEQPACKET,
		.me_level = IPPROTO_IP,
		.me_sockopt = IP_MINTTL,
		.me_errno = ENOPROTOOPT
	}, {
		.me_desc = "IP_MINTTL: PF_ROUTE IPv4 not supported",
		.me_domain = PF_ROUTE,
		.me_type = SOCK_RAW,
		.me_proto = AF_INET,
		.me_level = IPPROTO_IP,
		.me_sockopt = IP_MINTTL,
		.me_errno = ENOPROTOOPT
	}, {
		.me_desc = "IP_MINTTL: PF_ROUTE IPv6 not supported",
		.me_domain = PF_ROUTE,
		.me_type = SOCK_RAW,
		.me_proto = AF_INET6,
		.me_level = IPPROTO_IP,
		.me_sockopt = IP_MINTTL,
		.me_errno = ENOPROTOOPT
	}, {
		.me_desc = "IP_MINTTL: PF_POLICY not supported",
		.me_domain = PF_POLICY,
		.me_type = SOCK_RAW,
		.me_proto = PF_POLICY_V1,
		.me_level = IPPROTO_IP,
		.me_sockopt = IP_MINTTL,
		.me_errno = ENOPROTOOPT
	}, {
		.me_desc = "IP_MINTTL: PF_KEY not supported",
		.me_domain = PF_KEY,
		.me_type = SOCK_RAW,
		.me_proto = PF_KEY_V2,
		.me_level = IPPROTO_IP,
		.me_sockopt = IP_MINTTL,
		.me_errno = ENOPROTOOPT
	}, {
		.me_desc = "IPV6_MINHOPCOUNT: UDS SOCK_STREAM not supported",
		.me_domain = PF_UNIX,
		.me_type = SOCK_STREAM,
		.me_level = IPPROTO_IPV6,
		.me_sockopt = IPV6_MINHOPCOUNT,
		.me_errno = ENOPROTOOPT
	}, {
		.me_desc = "IPV6_MINHOPCOUNT: UDS SOCK_DGRAM not supported",
		.me_domain = PF_UNIX,
		.me_type = SOCK_DGRAM,
		.me_level = IPPROTO_IPV6,
		.me_sockopt = IPV6_MINHOPCOUNT,
		.me_errno = ENOPROTOOPT
	}, {
		.me_desc = "IPV6_MINHOPCOUNT: UDS SOCK_SEQPACKET not supported",
		.me_domain = PF_UNIX,
		.me_type = SOCK_SEQPACKET,
		.me_level = IPPROTO_IPV6,
		.me_sockopt = IPV6_MINHOPCOUNT,
		.me_errno = ENOPROTOOPT
	}, {
		.me_desc = "IPV6_MINHOPCOUNT: PF_ROUTE IPv4 not supported",
		.me_domain = PF_ROUTE,
		.me_type = SOCK_RAW,
		.me_proto = AF_INET,
		.me_level = IPPROTO_IPV6,
		.me_sockopt = IPV6_MINHOPCOUNT,
		.me_errno = ENOPROTOOPT
	}, {
		.me_desc = "IPV6_MINHOPCOUNT: PF_ROUTE IPv6 not supported",
		.me_domain = PF_ROUTE,
		.me_type = SOCK_RAW,
		.me_proto = AF_INET6,
		.me_level = IPPROTO_IPV6,
		.me_sockopt = IPV6_MINHOPCOUNT,
		.me_errno = ENOPROTOOPT
	}, {
		.me_desc = "IPV6_MINHOPCOUNT: PF_POLICY not supported",
		.me_domain = PF_POLICY,
		.me_type = SOCK_RAW,
		.me_proto = PF_POLICY_V1,
		.me_level = IPPROTO_IPV6,
		.me_sockopt = IPV6_MINHOPCOUNT,
		.me_errno = ENOPROTOOPT
	}, {
		.me_desc = "IPV6_MINHOPCOUNT: PF_KEY not supported",
		.me_domain = PF_KEY,
		.me_type = SOCK_RAW,
		.me_proto = PF_KEY_V2,
		.me_level = IPPROTO_IPV6,
		.me_sockopt = IPV6_MINHOPCOUNT,
		.me_errno = ENOPROTOOPT
	}, {
		.me_desc = "IP_MINTTL can't be set on IPv6 TCP socket",
		.me_domain = PF_INET6,
		.me_type = SOCK_STREAM,
		.me_level = IPPROTO_IP,
		.me_sockopt = IP_MINTTL,
		.me_errno = EINVAL
	}, {
		.me_desc = "IP_MINTTL can't be set on IPv6 UDP socket",
		.me_domain = PF_INET6,
		.me_type = SOCK_DGRAM,
		.me_level = IPPROTO_IP,
		.me_sockopt = IP_MINTTL,
		.me_errno = EINVAL
	}, {
		.me_desc = "IP_MINTTL can't be set on IPv6 SCTP socket",
		.me_domain = PF_INET6,
		.me_type = SOCK_STREAM,
		.me_proto = IPPROTO_SCTP,
		.me_level = IPPROTO_IP,
		.me_sockopt = IP_MINTTL,
		.me_errno = EINVAL
	}, {
		.me_desc = "IPV6_MINHOPCOUNT can't be set on IPv4 TCP socket",
		.me_domain = PF_INET,
		.me_type = SOCK_STREAM,
		.me_level = IPPROTO_IPV6,
		.me_sockopt = IPV6_MINHOPCOUNT,
		.me_errno = EINVAL
	}, {
		.me_desc = "IPV6_MINHOPCOUNT can't be set on IPv4 UDP socket",
		.me_domain = PF_INET,
		.me_type = SOCK_DGRAM,
		.me_level = IPPROTO_IPV6,
		.me_sockopt = IPV6_MINHOPCOUNT,
		.me_errno = EINVAL
	}, {
		.me_desc = "IPV6_MINHOPCOUNT can't be set on IPv4 SCTP socket",
		.me_domain = PF_INET,
		.me_type = SOCK_STREAM,
		.me_proto = IPPROTO_SCTP,
		.me_level = IPPROTO_IPV6,
		.me_sockopt = IPV6_MINHOPCOUNT,
		.me_errno = EINVAL
	}, {
		.me_desc = "IP_MINTTL: negative value rejected",
		.me_domain = PF_INET,
		.me_type = SOCK_STREAM,
		.me_value = -1,
		.me_level = IPPROTO_IP,
		.me_sockopt = IP_MINTTL,
		.me_errno = EINVAL
	}, {
		.me_desc = "IP_MINTTL: larger value rejected",
		.me_domain = PF_INET,
		.me_type = SOCK_STREAM,
		.me_value = 256,
		.me_level = IPPROTO_IP,
		.me_sockopt = IP_MINTTL,
		.me_errno = EINVAL
	}, {
		.me_desc = "IPV6_MINHOPCOUNT: negative value rejected",
		.me_domain = PF_INET6,
		.me_type = SOCK_STREAM,
		.me_value = -1,
		.me_level = IPPROTO_IPV6,
		.me_sockopt = IPV6_MINHOPCOUNT,
		.me_errno = EINVAL
	}, {
		.me_desc = "IPV6_MINHOPCOUNT: larger value rejected",
		.me_domain = PF_INET6,
		.me_type = SOCK_STREAM,
		.me_value = 256,
		.me_level = IPPROTO_IPV6,
		.me_sockopt = IPV6_MINHOPCOUNT,
		.me_errno = EINVAL
	}
};

static bool
minttl_err_one(const minttl_err_test_t *test)
{
	int sock = -1, val;
	bool ret = false;

	sock = socket(test->me_domain, test->me_type, test->me_proto);
	if (sock < 0) {
		warn("TEST FAILED: %s: failed to create socket", test->me_desc);
		goto out;
	}

	val = test->me_value;
	if (setsockopt(sock, test->me_level, test->me_sockopt, &val,
	    sizeof (val)) != -1) {
		warnx("TEST FAILED: %s: setsockopt incorrectly passed",
		    test->me_desc);
	} else if (errno != test->me_errno) {
		int e = errno;
		warnx("TEST FAILED: %s: expected errno %s, found %s",
		    test->me_desc, strerrorname_np(test->me_errno),
		    strerrorname_np(e));
	} else {
		(void) printf("TEST PASSED: %s\n", test->me_desc);
		ret = true;
	}
out:
	if (sock > -1)
		(void) close(sock);
	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(minttl_err_tests); i++) {
		if (!minttl_err_one(&minttl_err_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests completed successfully\n");
	}

	return (ret);
}
