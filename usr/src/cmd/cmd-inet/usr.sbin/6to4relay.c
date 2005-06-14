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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/socket.h>
#include <sys/stream.h>
#include <sys/param.h>

#include <net/route.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inet/tun.h>

#include <locale.h>

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <stropts.h>
#include <fcntl.h>

/*
 * Converts an IPv4 address to a 6to4 /64 route.  Address is of the form
 * 2002:<V4ADDR>:<SUBNETID>::/64 where SUBNETID will always be 0 and V4ADDR
 * equals the input IPv4 address.  IN6_V4ADDR_TO_6TO4(v4, v6) creates an
 * address of form 2002:<V4ADDR>:<SUBNETID>::<HOSTID>, where SUBNETID equals 0
 * and HOSTID equals 1.  For this route, we are not concerned about the
 * HOSTID portion of the address, thus it can be set to 0.
 *
 *  void V4ADDR_TO_6TO4_RT(const struct in_addr *v4, in6_addr_t *v6)
 */
#define	V4ADDR_TO_6TO4_RT(v4, v6) \
	(IN6_V4ADDR_TO_6TO4(v4, v6), (v6)->_S6_un._S6_u32[3] = 0)

static void strioctl(int, void *, size_t);
static void getkstatus(ipaddr_t *);
static void printkstatus(void);
static void modifyroute(unsigned int, in6_addr_t *);
static void setkrraddr(ipaddr_t);
static void printerror(char *);
static void usage(void);

/* booleans corresponding to command line flags */
static boolean_t eflag = B_FALSE;
static boolean_t dflag = B_FALSE;
static boolean_t aflag = B_FALSE;

static int fd = -1;

/*
 * srtioctl(cmd, buf, size)
 *
 * Passes the contents of 'buf' using the ioctl specified by 'cmd', by way of
 * the I_STR ioctl mechanism.  The response of the ioctl will be stored in buf
 * when this function returns.  The input 'size' specifies the size of the
 * buffer to be passed.
 */
static void
strioctl(int cmd, void *buf, size_t size)
{
	struct strioctl ioc;

	(void) memset(&ioc, 0, sizeof (ioc));

	ioc.ic_cmd = cmd;
	ioc.ic_timout = 0;
	ioc.ic_len = size;
	ioc.ic_dp = (char *)buf;

	if (ioctl(fd, I_STR, &ioc) < 0) {
		printerror("ioctl (I_STR)");
		(void) close(fd);
		exit(EXIT_FAILURE);
		/* NOTREACHED */
	}
}


/*
 * getkstatus(out_addr)
 *
 * Queries the kernel for the 6to4 Relay Router destination address by sending
 * the SIOCG6TO4TUNRRADDR ioctl to the tunnel module using the I_STR ioctl
 * mechanism.  The value returned, through the ioctl, will be an ipaddr_t
 * embedded in a strioctl.  Output parameter is set with result.
 */
static void
getkstatus(ipaddr_t *out_addr)
{
	ipaddr_t an_addr;

	/* Get the Relay Router address from the kernel */
	strioctl(SIOCG6TO4TUNRRADDR, &an_addr, sizeof (an_addr));

	*out_addr = an_addr;	/* set output parameter */
}


/*
 * printkstatus()
 *
 * Queries the kernel for the current 6to4 Relay Router value, prints
 * a status message based on the value and exits this command.
 * INADDR_ANY is used to denote that Relay Router communication support is
 * disabled within the kernel.
 */
static void
printkstatus(void)
{
	ipaddr_t rr_addr;
	char buf[INET6_ADDRSTRLEN];

	getkstatus(&rr_addr);	/* get value from kernel */
	(void) printf("6to4relay: ");
	if (rr_addr == INADDR_ANY) {
		(void) printf(gettext("6to4 Relay Router communication "
		    "support is disabled.\n"));
	} else {
		(void) printf(gettext("6to4 Relay Router communication "
		    "support is enabled.\n"));
		(void) printf(gettext("IPv4 destination address of Relay "
		    "Router = "));
		(void) printf("%s\n",
		    inet_ntop(AF_INET, &rr_addr, buf, sizeof (buf)));
	}
}

/*
 * modifyroute(cmd, in_gw)
 *
 * Modifies a default IPv6 route with DST = ::, GATEWAY = in_gw, NETMASK = ::
 * and flags = <GATEWAY, STATIC>.
 * This route is to be propagated through the 6to4 site so that 6to4 hosts
 * can send packets to native IPv6 hosts behind a remote 6to4 Relay Router.
 */
static void
modifyroute(unsigned int cmd, in6_addr_t *in_gw)
{
	static int rtmseq;
	int rtsock;
	int rlen;

	static struct {
		struct rt_msghdr	rt_hdr;
		struct sockaddr_in6	rt_dst;
		struct sockaddr_in6	rt_gate;
		struct sockaddr_in6	rt_mask;
	} rt_msg;

	/* Open a routing socket for passing route commands */
	if ((rtsock = socket(AF_ROUTE, SOCK_RAW, AF_INET)) < 0) {
		printerror("socket");
		(void) close(fd);
		exit(EXIT_FAILURE);
		/* NOTREACHED */
	}

	(void) memset(&rt_msg, 0, sizeof (rt_msg));
	rt_msg.rt_hdr.rtm_msglen = sizeof (rt_msg);
	rt_msg.rt_hdr.rtm_version = RTM_VERSION;
	rt_msg.rt_hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
	rt_msg.rt_hdr.rtm_pid = getpid();
	rt_msg.rt_hdr.rtm_type = cmd;
	rt_msg.rt_hdr.rtm_seq = ++rtmseq;
	rt_msg.rt_hdr.rtm_flags = RTF_STATIC | RTF_GATEWAY;

	/* DST */
	rt_msg.rt_dst.sin6_family = AF_INET6;
	(void) memset(&rt_msg.rt_dst.sin6_addr.s6_addr, 0,
	    sizeof (in6_addr_t));

	/* GATEWAY */
	rt_msg.rt_gate.sin6_family = AF_INET6;
	bcopy(in_gw->s6_addr, &rt_msg.rt_gate.sin6_addr.s6_addr,
	    sizeof (in6_addr_t));

	/* NETMASK */
	rt_msg.rt_mask.sin6_family = AF_INET6;
	(void) memset(&rt_msg.rt_mask.sin6_addr.s6_addr, 0,
	    sizeof (in6_addr_t));

	/* Send the routing message */
	rlen = write(rtsock, &rt_msg, rt_msg.rt_hdr.rtm_msglen);
	if (rlen < rt_msg.rt_hdr.rtm_msglen) {
		if (rlen < 0) {
			(void) fprintf(stderr,
			    gettext("6to4relay: write to routing socket: %s\n"),
			    strerror(errno));
		} else {
			(void) fprintf(stderr, gettext("6to4relay: write to "
			    "routing socket got only %d for rlen\n"), rlen);
		}
	}
	(void) close(rtsock);
}

/*
 * setkrraddr(in_addr)
 *
 * Sets the 6to4 Relay Router destination address value in the kernel using
 * the SIOCS6TO4TUNRRADDR ioctl using the I_STR ioctl mechanism.
 * The address is sent to the kernel, as an ipaddr_t, embedded in an strioctl.
 */
static void
setkrraddr(ipaddr_t in_addr)
{
	/* set Relay Router address */
	strioctl(SIOCS6TO4TUNRRADDR, &in_addr, sizeof (in_addr));
}

static void
printerror(char *s)
{
	int sverrno = errno;

	(void) fprintf(stderr, "6to4relay: ");
	if (s != NULL)
		(void) fprintf(stderr, "%s: ", s);
	(void) fprintf(stderr, "%s\n", strerror(sverrno));
}

static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("usage:\n"
		"\t6to4relay\n"
		"\t6to4relay -e [-a <addr>]\n"
		"\t6to4relay -d\n"
		"\t6to4relay -h\n"));
}

int
main(int argc, char **argv)
{
	int ch;
	char *in_addr = NULL;
	int ret = EXIT_SUCCESS;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* open /dev/ip for use */
	if ((fd = open("/dev/ip", O_RDWR)) == -1) {
		printerror(gettext("can't open /dev/ip"));
		exit(EXIT_FAILURE);
	}

	if (ioctl(fd, I_PUSH, TUN_NAME) < 0) {
		printerror("ioctl (I_PUSH)");
		ret = EXIT_FAILURE;
		goto done;
	}

	/* If no args are specified, print status as queried from kernel */
	if (argc < 2) {
		printkstatus();
		goto done;
	}
	while ((ch = getopt(argc, argv, "ea:dh")) != EOF) {
		switch (ch) {
		case 'e':
			eflag = B_TRUE;
			break;
		case 'd':
			dflag = B_TRUE;
			break;
		case 'a':
			aflag = B_TRUE;
			in_addr = optarg;
			break;
		case 'h':
			usage();
			goto done;
		default:
			usage();
			ret = EXIT_FAILURE;
			goto done;
		}
	}
	/*
	 * If -a is specified, -e must also be specified.  Also, the
	 * combination of -e and -d is illegal.  Fail on either case.
	 */
	if ((aflag && !eflag) || (eflag && dflag)) {
		usage();
		ret = EXIT_FAILURE;
		goto done;
	}

	/*
	 * Enable Relay Router communication support in the kernel.
	 */
	if (eflag) {
		struct in_addr current_addr; /* addr currently set in kernel */
		struct in_addr new_addr; /* new addr we plan to set */
		in6_addr_t v6_rt;

		/*
		 * if -a was not specified, the well-known anycast will
		 * be used.
		 */
		if (!aflag) {
			new_addr.s_addr = htonl(INADDR_6TO4RRANYCAST);

		} else if (inet_pton(AF_INET, in_addr, &new_addr) <= 0) {
			(void) fprintf(stderr, gettext("6to4relay: input "
			    "address (%s) is not a valid IPv4 dotted-decimal "
			    "string.\n"), in_addr);
			ret = EXIT_FAILURE;
			goto done;
		}

		/*
		 * INADDR_ANY has special meaning in the kernel, reject this
		 * input and exit.
		 */
		if (new_addr.s_addr == INADDR_ANY) {
			(void) fprintf(stderr, gettext("6to4relay: input "
			    "(0.0.0.0) is not a valid IPv4 unicast "
			    "address.\n"));
			ret = EXIT_FAILURE;
			goto done;
		}

		/*
		 * get the current Relay Router address from the kernel.
		 *
		 * 1. If the current address is INADDR_ANY, set the new
		 *    address in the kernel and add a default IPv6 route using
		 *    the new address.
		 *
		 * 2. If the current address is different than the new address,
		 *    set the new address in the kernel, delete the
		 *    old default IPv6 route and add a new default IPv6 route
		 *    (using the new address).
		 *
		 * 3. If the kernel address is the same as the one we are
		 *    adding, no additional processing is needed.
		 */
		getkstatus(&current_addr.s_addr);

		if (current_addr.s_addr == INADDR_ANY) {
			setkrraddr(new_addr.s_addr);
			V4ADDR_TO_6TO4_RT(&new_addr, &v6_rt);
			modifyroute(RTM_ADD, &v6_rt);
		} else if (new_addr.s_addr != current_addr.s_addr) {
			setkrraddr(new_addr.s_addr);
			/* remove old default IPv6 route */
			V4ADDR_TO_6TO4_RT(&current_addr, &v6_rt);
			modifyroute(RTM_DELETE, &v6_rt);
			/*
			 * Add new default IPv6 route using a 6to4 address
			 * created from the address we just set in the kernel.
			 */
			V4ADDR_TO_6TO4_RT(&new_addr, &v6_rt);
			modifyroute(RTM_ADD, &v6_rt);
		}
	}

	/*
	 * Disable Relay Router communication support in kernel.
	 */
	if (dflag) {
		struct in_addr current_addr; /* addr currently set in kernel */
		in6_addr_t v6_rt;

		/*
		 * get Relay Router address from the kernel and delete
		 * default IPv6 route that was added for it.
		 */
		getkstatus(&current_addr.s_addr);
		if (current_addr.s_addr == INADDR_ANY) {
			/*
			 * Feature is already disabled in kernel, no
			 * additional processing is needed.
			 */
			goto done;
		}

		V4ADDR_TO_6TO4_RT(&current_addr, &v6_rt);
		modifyroute(RTM_DELETE, &v6_rt);

		/*
		 * INADDR_ANY (0.0.0.0) is used by the kernel to disable Relay
		 * Router communication support.
		 */
		setkrraddr(INADDR_ANY);
	}
done:
	(void) close(fd);
	return (ret);
}
