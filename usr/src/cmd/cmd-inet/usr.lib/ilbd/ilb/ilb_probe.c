/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <libgen.h>
#include <fcntl.h>

/*
 * The following values are what ilbd will set argv[0] to.  This determines
 * what type of probe to send out.
 */
#define	PROBE_PING	"ilb_ping"
#define	PROBE_PROTO	"ilb_probe"

/* The transport protocol to use in the probe.  Value of argv[3]. */
#define	PROTO_TCP	"TCP"
#define	PROTO_UDP	"UDP"

enum probe_type { ping_probe, tcp_probe, udp_probe };

/* Load balance mode.  Value of argv[4]. */
#define	MODE_DSR	"DSR"
#define	MODE_NAT	"NAT"
#define	MODE_HALF_NAT	"HALF_NAT"

enum lb_mode { dsr, nat, half_nat };

/* Number of arguments to the command from ilbd. */
#define	PROG_ARGC	7

/* Size of buffer used to receive ICMP packet */
#define	RECV_PKT_SZ	256

/*
 * Struct to store the probe info (most is passed in using the argv[] array to
 * the command given by ilbd).  The argv[] contains the following.
 *
 * argv[0] is either PROBE_PING or PROBE_PROTO
 * argv[1] is the VIP
 * argv[2] is the backend server address
 * argv[3] is the transport protocol used in the rule
 * argv[4] is the load balance mode, "DSR", "NAT", "HALF-NAT"
 * argv[5] is the probe port
 * argv[6] is the probe timeout
 *
 * The following three fields are used in sending ICMP ECHO probe.
 *
 * echo_id is the ID set in the probe
 * echo_seq is the sequence set in the probe
 * echo_cookie is the random number data in a probe
 * lport is the local port (in network byte order) used to send the probe
 */
typedef struct {
	enum probe_type		probe;
	struct in6_addr		vip;		/* argv[1] */
	struct in6_addr		srv_addr;	/* argv[2] */
	int			proto;		/* argv[3] */
	enum lb_mode		mode;		/* argv[4] */
	in_port_t		port;		/* argv[5] */
	uint32_t		timeout;	/* argv[6] */

	uint16_t		echo_id;
	uint16_t		echo_seq;
	uint32_t		echo_cookie;
	in_port_t		lport;
} probe_param_t;

/* Global variable to indicate whether a timeout means success. */
static boolean_t timeout_is_good;

/* SIGALRM handler */
/* ARGSUSED */
static void
probe_exit(int s)
{
	if (timeout_is_good) {
		(void) printf("0");
		exit(0);
	} else {
		(void) printf("-1");
		exit(255);
	}
}

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 * (copied from ping.c)
 */
static ushort_t
in_cksum(ushort_t *addr, int len)
{
	int nleft = len;
	ushort_t *w = addr;
	ushort_t answer;
	ushort_t odd_byte = 0;
	int sum = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(uchar_t *)(&odd_byte) = *(uchar_t *)w;
		sum += odd_byte;
	}

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

/* It is assumed that argv[] contains PROBE_ARGC arguments. */
static boolean_t
parse_probe_param(char *argv[], probe_param_t *param)
{
	int32_t port;
	int64_t timeout;
	struct in_addr v4addr;

	if (strcmp(basename(argv[0]), PROBE_PING) == 0) {
		param->probe = ping_probe;
	} else {
		if (strcmp(basename(argv[0]), PROBE_PROTO) != 0)
			return (B_FALSE);

		if (strcasecmp(argv[3], PROTO_TCP) == 0) {
			param->probe = tcp_probe;
			param->proto = IPPROTO_TCP;
		} else if (strcasecmp(argv[3], PROTO_UDP) == 0) {
			param->probe = udp_probe;
			param->proto = IPPROTO_UDP;
		} else {
			return (B_FALSE);
		}
	}

	if (strchr(argv[1], ':') != NULL) {
		if (inet_pton(AF_INET6, argv[1], &param->vip) == 0)
			return (B_FALSE);
	} else if (strchr(argv[1], '.') != NULL) {
		if (inet_pton(AF_INET, argv[1], &v4addr) == 0)
			return (B_FALSE);
		IN6_INADDR_TO_V4MAPPED(&v4addr, &param->vip);
	} else {
		return (B_FALSE);
	}

	/*
	 * The address family of vip and srv_addr should be the same for
	 * now.  But in future, we may allow them to be different...  So
	 * we don't do a check here.
	 */
	if (strchr(argv[2], ':') != NULL) {
		if (inet_pton(AF_INET6, argv[2], &param->srv_addr) == 0)
			return (B_FALSE);
	} else if (strchr(argv[2], '.') != NULL) {
		if (inet_pton(AF_INET, argv[2], &v4addr) == 0)
			return (B_FALSE);
		IN6_INADDR_TO_V4MAPPED(&v4addr, &param->srv_addr);
	} else {
		return (B_FALSE);
	}

	if (strcasecmp(argv[4], MODE_DSR) == 0)
		param->mode = dsr;
	else if (strcasecmp(argv[4], MODE_NAT) == 0)
		param->mode = nat;
	else if (strcasecmp(argv[4], MODE_HALF_NAT) == 0)
		param->mode = half_nat;
	else
		return (B_FALSE);

	if ((port = atoi(argv[5])) <= 0 || port > USHRT_MAX)
		return (B_FALSE);
	param->port = port;

	if ((timeout = strtoll(argv[6], NULL, 10)) <= 0 || timeout > UINT_MAX)
		return (B_FALSE);
	param->timeout = timeout;

	return (B_TRUE);
}

/*
 * Set up the destination address to be used to send a probe based on
 * param.
 */
static int
set_sockaddr(struct sockaddr_storage *addr, socklen_t *addr_len,
    void **next_hop, probe_param_t *param)
{
	int af;
	struct in6_addr *param_addr;
	struct sockaddr_in *v4_addr;
	struct sockaddr_in6 *v6_addr;
	boolean_t nh = B_FALSE;

	switch (param->mode) {
	case dsr:
		param_addr = &param->vip;
		nh = B_TRUE;
		break;
	case nat:
	case half_nat:
		param_addr = &param->srv_addr;
		break;
	}
	if (IN6_IS_ADDR_V4MAPPED(param_addr)) {
		af = AF_INET;
		v4_addr = (struct sockaddr_in *)addr;
		IN6_V4MAPPED_TO_INADDR(param_addr, &v4_addr->sin_addr);
		v4_addr->sin_family = AF_INET;
		v4_addr->sin_port = htons(param->port);

		*addr_len = sizeof (*v4_addr);
	} else {
		af = AF_INET6;
		v6_addr = (struct sockaddr_in6 *)addr;
		v6_addr->sin6_family = AF_INET6;
		v6_addr->sin6_addr = *param_addr;
		v6_addr->sin6_port = htons(param->port);
		v6_addr->sin6_flowinfo = 0;
		v6_addr->sin6_scope_id = 0;

		*addr_len = sizeof (*v6_addr);
	}

	if (!nh) {
		*next_hop = NULL;
		return (af);
	}

	if (af == AF_INET) {
		ipaddr_t *nh_addr;

		nh_addr = malloc(sizeof (ipaddr_t));
		IN6_V4MAPPED_TO_IPADDR(&param->srv_addr, *nh_addr);
		*next_hop = nh_addr;
	} else {
		struct sockaddr_in6 *nh_addr;

		nh_addr = malloc(sizeof (*nh_addr));
		nh_addr->sin6_family = AF_INET6;
		nh_addr->sin6_addr = param->srv_addr;
		nh_addr->sin6_flowinfo = 0;
		nh_addr->sin6_scope_id = 0;
		*next_hop = nh_addr;
	}

	return (af);
}

/*
 * Use TCP to check if the peer server is alive.  Create a TCP socket and
 * then call connect() to reach the peer server.  If connect() does not
 * return within the timeout period, the SIGALRM handler will be invoked
 * and tell ilbd that the peer server is not alive.
 */
static int
tcp_query(probe_param_t *param)
{
	int ret;
	int sd, af;
	struct sockaddr_storage dst_addr;
	socklen_t dst_addr_len;
	void *next_hop;
	hrtime_t start, end;
	uint32_t rtt;

	ret = 0;
	next_hop = NULL;

	af = set_sockaddr(&dst_addr, &dst_addr_len, &next_hop, param);

	if ((sd = socket(af, SOCK_STREAM, param->proto)) == -1)
		return (-1);

	/* DSR mode, need to set the next hop */
	if (next_hop != NULL) {
		if (af == AF_INET) {
			if (setsockopt(sd, IPPROTO_IP, IP_NEXTHOP, next_hop,
			    sizeof (ipaddr_t)) < 0) {
				ret = -1;
				goto out;
			}
		} else {
			if (setsockopt(sd, IPPROTO_IPV6, IPV6_NEXTHOP,
			    next_hop, sizeof (struct sockaddr_in6)) < 0) {
				ret = -1;
				goto out;
			}
		}
	}

	timeout_is_good = B_FALSE;
	(void) alarm(param->timeout);
	start = gethrtime();
	if (connect(sd, (struct sockaddr *)&dst_addr, dst_addr_len) != 0) {
		ret = -1;
		goto out;
	}
	end = gethrtime();

	rtt = (end - start) / (NANOSEC / MICROSEC);
	if (rtt == 0)
		rtt = 1;
	(void) printf("%u", rtt);

out:
	(void) close(sd);
	return (ret);
}

/*
 * Check if the ICMP packet is a port unreachable message in respnsed to
 * our probe.  Return -1 if no, 0 if yes.
 */
static int
check_icmp_unreach_v4(struct icmp *icmph, probe_param_t *param)
{
	struct udphdr *udph;
	struct ip *iph;

	if (icmph->icmp_type != ICMP_UNREACH)
		return (-1);
	if (icmph->icmp_code != ICMP_UNREACH_PORT)
		return (-1);

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	iph = (struct ip *)((char *)icmph + ICMP_MINLEN);
	if (iph->ip_p != IPPROTO_UDP)
		return (-1);

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	udph = (struct udphdr *)((char *)iph + (iph->ip_hl << 2));
	if (udph->uh_dport != htons(param->port))
		return (-1);
	if (udph->uh_sport != param->lport)
		return (-1);

	/* All matched, it is a response to the probe we sent. */
	return (0);
}

/*
 * Check if the ICMP packet is a reply to our echo request.  Need to match
 * the ID and sequence.
 */
static int
check_icmp_echo_v4(struct icmp *icmph, probe_param_t *param)
{
	uint32_t cookie;
	in_port_t port;

	if (icmph->icmp_type != ICMP_ECHOREPLY)
		return (-1);
	if (icmph->icmp_id != param->echo_id)
		return (-1);
	if (icmph->icmp_seq != param->echo_seq)
		return (-1);

	bcopy(icmph->icmp_data, &cookie, sizeof (cookie));
	if (cookie != param->echo_cookie)
		return (-1);
	bcopy(icmph->icmp_data + sizeof (cookie), &port, sizeof (port));
	if (port != param->port)
		return (-1);

	/* All matched, it is a response to the echo we sent. */
	return (0);
}

/* Verify if an ICMP packet is what we expect. */
static int
check_icmp_v4(char *buf, ssize_t rcvd, probe_param_t *param)
{
	struct ip *iph;
	struct icmp *icmph;

	/*
	 * We can dereference the length field without worry since the stack
	 * should not have sent up the packet if it is smaller than a normal
	 * ICMPv4 packet.
	 */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	iph = (struct ip *)buf;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	icmph = (struct icmp *)((char *)iph + (iph->ip_hl << 2));

	/*
	 * If we sent an UDP probe, check if the packet is a port
	 * unreachable message in response to our probe.
	 *
	 * If we sent an ICMP echo request, check if the packet is a reply
	 * to our echo request.
	 */
	if (param->probe == udp_probe) {
		/* Is the packet large enough for further checking? */
		if (rcvd < 2 * sizeof (struct ip) + ICMP_MINLEN +
		    sizeof (struct udphdr)) {
			return (-1);
		}
		return (check_icmp_unreach_v4(icmph, param));
	} else {
		if (rcvd < sizeof (struct ip) + ICMP_MINLEN)
			return (-1);
		return (check_icmp_echo_v4(icmph, param));
	}
}

/*
 * Check if the ICMPv6 packet is a port unreachable message in respnsed to
 * our probe.  Return -1 if no, 0 if yes.
 */
static int
check_icmp_unreach_v6(icmp6_t *icmp6h, probe_param_t *param)
{
	ip6_t *ip6h;
	struct udphdr *udph;

	if (icmp6h->icmp6_type != ICMP6_DST_UNREACH)
		return (-1);
	if (icmp6h->icmp6_code != ICMP6_DST_UNREACH_NOPORT)
		return (-1);

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	ip6h = (ip6_t *)((char *)icmp6h + ICMP6_MINLEN);
	if (ip6h->ip6_nxt != IPPROTO_UDP)
		return (-1);

	udph = (struct udphdr *)(ip6h + 1);

	if (udph->uh_dport != htons(param->port))
		return (-1);
	if (udph->uh_sport != param->lport)
		return (-1);

	return (0);
}

/*
 * Check if the ICMPv6 packet is a reply to our echo request.  Need to match
 * the ID and sequence.
 */
static int
check_icmp_echo_v6(icmp6_t *icmp6h, probe_param_t *param)
{
	char *tmp;
	uint32_t cookie;
	in_port_t port;

	if (icmp6h->icmp6_type != ICMP6_ECHO_REPLY)
		return (-1);
	if (icmp6h->icmp6_id != param->echo_id)
		return (-1);
	if (icmp6h->icmp6_seq != param->echo_seq)
		return (-1);
	tmp = (char *)icmp6h + ICMP6_MINLEN;
	bcopy(tmp, &cookie, sizeof (cookie));
	if (cookie != param->echo_cookie)
		return (-1);
	tmp += sizeof (cookie);
	bcopy(tmp, &port, sizeof (port));
	if (port != param->port)
		return (-1);

	/* All matched, it is a response to the echo we sent. */
	return (0);
}

/* Verify if an ICMPv6 packet is what we expect. */
static int
check_icmp_v6(char *buf, ssize_t rcvd, probe_param_t *param)
{
	icmp6_t *icmp6h;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	icmp6h = (icmp6_t *)(buf);

	/*
	 * If we sent an UDP probe, check if the packet is a port
	 * unreachable message.
	 *
	 * If we sent an ICMPv6 echo request, check if the packet is a reply.
	 */
	if (param->probe == udp_probe) {
		/* Is the packet large enough for further checking? */
		if (rcvd < sizeof (ip6_t) + ICMP6_MINLEN +
		    sizeof (struct udphdr)) {
			return (-1);
		}
		return (check_icmp_unreach_v6(icmp6h, param));
	} else {
		if (rcvd < ICMP6_MINLEN)
			return (-1);
		return (check_icmp_echo_v6(icmp6h, param));
	}
}

/*
 * Wait for an ICMP reply indefinitely.  If we get what we expect, return 0.
 * If an error happnes, return -1.
 */
static int
wait_icmp_reply(int af, int recv_sd, struct sockaddr_storage *exp_from,
    probe_param_t *param)
{
	char buf[RECV_PKT_SZ];
	socklen_t from_len;
	ssize_t rcvd;
	int ret;

	for (;;) {
		if (af == AF_INET) {
			struct sockaddr_in v4_from;

			from_len = sizeof (v4_from);
			if ((rcvd = recvfrom(recv_sd, buf, RECV_PKT_SZ, 0,
			    (struct sockaddr *)&v4_from, &from_len)) < 0) {
				ret = -1;
				break;
			}

			/* Packet not from our peer, ignore it. */
			if ((((struct sockaddr_in *)exp_from)->sin_addr.s_addr)
			    != v4_from.sin_addr.s_addr) {
				continue;
			}
			if (check_icmp_v4(buf, rcvd, param) == 0) {
				ret = 0;
				break;
			}
		} else {
			struct sockaddr_in6 v6_from;

			from_len = sizeof (struct sockaddr_in6);
			if ((rcvd = recvfrom(recv_sd, buf, RECV_PKT_SZ, 0,
			    (struct sockaddr *)&v6_from, &from_len)) < 0) {
				ret = -1;
				break;
			}

			if (!IN6_ARE_ADDR_EQUAL(&(v6_from.sin6_addr),
			    &((struct sockaddr_in6 *)exp_from)->sin6_addr)) {
				continue;
			}
			if (check_icmp_v6(buf, rcvd, param) == 0) {
				ret = 0;
				break;
			}
		}
	}
	return (ret);
}

/* Return the local port used (network byte order) in a socket. */
static int
get_lport(int sd, in_port_t *lport)
{
	struct sockaddr_storage addr;
	socklen_t addr_sz;

	addr_sz = sizeof (addr);
	if (getsockname(sd, (struct sockaddr *)&addr, &addr_sz) != 0)
		return (-1);
	if (addr.ss_family == AF_INET)
		*lport = ((struct sockaddr_in *)&addr)->sin_port;
	else
		*lport = ((struct sockaddr_in6 *)&addr)->sin6_port;
	return (0);
}

/*
 * Use UDP to check if the peer server is alive.  Send a 0 length UDP packet
 * to the peer server.  If there is no one listening, the peer IP stack
 * should send back a port unreachable ICMP(v4/v6) packet.  If the peer
 * server is alive, there should be no response.  So if we get SIGALRM,
 * the peer is alive.
 */
static int
udp_query(probe_param_t *param)
{
	int ret;
	int send_sd, recv_sd, af;
	struct sockaddr_storage dst_addr;
	socklen_t addr_len;
	void *next_hop;
	char buf[1];
	struct itimerval timeout;
	uint64_t tm;

	ret = 0;
	next_hop = NULL;

	af = set_sockaddr(&dst_addr, &addr_len, &next_hop, param);

	if ((send_sd = socket(af, SOCK_DGRAM, param->proto)) == -1)
		return (-1);
	if ((recv_sd = socket(af, SOCK_RAW, (af == AF_INET) ? IPPROTO_ICMP :
	    IPPROTO_ICMPV6)) == -1) {
		return (-1);
	}

	/* DSR mode, need to set the next hop */
	if (next_hop != NULL) {
		if (af == AF_INET) {
			if (setsockopt(send_sd, IPPROTO_IP, IP_NEXTHOP,
			    next_hop, sizeof (ipaddr_t)) < 0) {
				ret = -1;
				goto out;
			}
		} else {
			if (setsockopt(send_sd, IPPROTO_IPV6, IPV6_NEXTHOP,
			    next_hop, sizeof (struct sockaddr_in6)) < 0) {
				ret = -1;
				goto out;
			}
		}
	}

	/*
	 * If ilbd asks us to wait at most t, we will wait for at most
	 * t', which is 3/4 of t.  If we wait for too long, ilbd may
	 * timeout and kill us.
	 */
	timeout.it_interval.tv_sec = 0;
	timeout.it_interval.tv_usec = 0;
	tm = (param->timeout * MICROSEC >> 2) * 3;
	if (tm > MICROSEC) {
		timeout.it_value.tv_sec = tm / MICROSEC;
		timeout.it_value.tv_usec = tm - (timeout.it_value.tv_sec *
		    MICROSEC);
	} else {
		timeout.it_value.tv_sec = 0;
		timeout.it_value.tv_usec = tm;
	}
	timeout_is_good = B_TRUE;
	if (setitimer(ITIMER_REAL, &timeout, NULL) != 0) {
		ret = -1;
		goto out;
	}

	if (sendto(send_sd, buf, 0, 0, (struct sockaddr *)&dst_addr,
	    addr_len) != 0) {
		ret = -1;
		goto out;
	}
	if ((ret = get_lport(send_sd, &param->lport)) != 0)
		goto out;

	/*
	 * If the server app is listening, we should not get back a
	 * response.  So if wait_icmp_reply() returns, either there
	 * is an error or we get back something.
	 */
	(void) wait_icmp_reply(af, recv_sd, &dst_addr, param);
	ret = -1;

out:
	(void) close(send_sd);
	(void) close(recv_sd);
	return (ret);
}

/*
 * Size (in uint32_t) of the ping packet to be sent to server.  It includes
 * a cookie (random number) + the target port.  The cookie and port are used
 * for matching ping request since there can be many such ping packets sent
 * to different servers from the same source address and using the same VIP.
 * The last two bytes are for padding.
 *
 */
#define	PING_PKT_LEN \
	((ICMP_MINLEN + 2 * sizeof (uint32_t)) / sizeof (uint32_t))

/*
 * Try to get a random number from the pseudo random number device
 * /dev/urandom.  If there is any error, return (uint32_t)gethrtime()
 * as a back up.
 */
static uint32_t
get_random(void)
{
	int fd;
	uint32_t num;

	if ((fd = open("/dev/urandom", O_RDONLY)) == -1)
		return ((uint32_t)gethrtime());

	if (read(fd, &num, sizeof (num)) != sizeof (num))
		num = ((uint32_t)gethrtime());

	(void) close(fd);
	return (num);
}

/*
 * Use ICMP(v4/v6) echo request to check if the peer server machine is
 * reachable.  Send a echo request and expect to get back a echo reply.
 */
static int
ping_query(probe_param_t *param)
{
	int ret;
	int sd, af;
	struct sockaddr_storage dst_addr;
	socklen_t dst_addr_len;
	void *next_hop;
	hrtime_t start, end;
	uint32_t rtt;
	uint32_t buf[PING_PKT_LEN];
	struct icmp *icmph;

	ret = 0;
	next_hop = NULL;

	af = set_sockaddr(&dst_addr, &dst_addr_len, &next_hop, param);

	if ((sd = socket(af, SOCK_RAW, (af == AF_INET) ? IPPROTO_ICMP :
	    IPPROTO_ICMPV6)) == -1) {
		return (-1);
	}

	/* DSR mode, need to set the next hop */
	if (next_hop != NULL) {
		if (af == AF_INET) {
			if (setsockopt(sd, IPPROTO_IP, IP_NEXTHOP, next_hop,
			    sizeof (ipaddr_t)) < 0) {
				ret = -1;
				goto out;
			}
		} else {
			if (setsockopt(sd, IPPROTO_IPV6, IPV6_NEXTHOP,
			    next_hop, sizeof (struct sockaddr_in6)) < 0) {
				ret = -1;
				goto out;
			}
		}
	}

	bzero(buf, sizeof (buf));
	icmph = (struct icmp *)buf;
	icmph->icmp_type = af == AF_INET ? ICMP_ECHO : ICMP6_ECHO_REQUEST;
	icmph->icmp_code = 0;
	icmph->icmp_cksum = 0;
	icmph->icmp_id = htons(gethrtime() % USHRT_MAX);
	icmph->icmp_seq = htons(gethrtime() % USHRT_MAX);

	param->echo_cookie = get_random();
	bcopy(&param->echo_cookie, icmph->icmp_data,
	    sizeof (param->echo_cookie));
	bcopy(&param->port, icmph->icmp_data + sizeof (param->echo_cookie),
	    sizeof (param->port));
	icmph->icmp_cksum = in_cksum((ushort_t *)buf, sizeof (buf));
	param->echo_id = icmph->icmp_id;
	param->echo_seq = icmph->icmp_seq;

	timeout_is_good = B_FALSE;
	(void) alarm(param->timeout);
	start = gethrtime();
	if (sendto(sd, buf, sizeof (buf), 0, (struct sockaddr *)&dst_addr,
	    dst_addr_len) != sizeof (buf)) {
		ret = -1;
		goto out;
	}
	if (wait_icmp_reply(af, sd, &dst_addr, param) != 0) {
		ret = -1;
		goto out;
	}
	end = gethrtime();

	rtt = (end - start) / (NANOSEC / MICROSEC);
	if (rtt == 0)
		rtt = 1;
	(void) printf("%u", rtt);

out:
	(void) close(sd);
	return (ret);
}

int
main(int argc, char *argv[])
{
	probe_param_t param;
	int ret;

	/* ilbd should pass in PROG_ARGC parameters. */
	if (argc != PROG_ARGC) {
		(void) printf("-1");
		return (-1);
	}

	if (signal(SIGALRM, probe_exit) == SIG_ERR) {
		(void) printf("-1");
		return (-1);
	}

	if (!parse_probe_param(argv, &param)) {
		(void) printf("-1");
		return (-1);
	}

	switch (param.probe) {
	case ping_probe:
		ret = ping_query(&param);
		break;
	case tcp_probe:
		ret = tcp_query(&param);
		break;
	case udp_probe:
		ret = udp_query(&param);
		break;
	}

	if (ret == -1)
		(void) printf("-1");

	return (ret);
}
