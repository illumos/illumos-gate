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

#include <sys/socket.h>
#include <sys/stream.h>
#include <sys/param.h>

#include <net/route.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <locale.h>

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <stropts.h>
#include <fcntl.h>
#include <libdliptun.h>

static void usage(void);

static dladm_handle_t	handle;
/* booleans corresponding to command line flags */
static boolean_t	eflag = B_FALSE;
static boolean_t	dflag = B_FALSE;
static boolean_t	aflag = B_FALSE;


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
	struct in_addr	rr_addr;
	char		buf[INET6_ADDRSTRLEN];
	char		errstr[DLADM_STRSIZE];
	dladm_status_t	status;

	status = dladm_iptun_get6to4relay(handle, &rr_addr);
	if (status != DLADM_STATUS_OK) {
		(void) fprintf(stderr, gettext("6to4relay: unable to get "
		    "6to4 relay status: %s\n"),
		    dladm_status2str(status, errstr));
		return;
	}
	(void) printf("6to4relay: ");
	if (rr_addr.s_addr == INADDR_ANY) {
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
		(void) fprintf(stderr, gettext("6to4relay: unable to modify "
		    "default IPv6 route: socket: %s\n"), strerror(errno));
		return;
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
	int		ch;
	char		*relay_arg = NULL;
	dladm_status_t	status;
	char		errstr[DLADM_STRSIZE];

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if ((status = dladm_open(&handle)) != DLADM_STATUS_OK) {
		(void) fprintf(stderr, gettext("6to4relay: error opening "
		    "dladm handle: %s\n"), dladm_status2str(status, errstr));
		return (EXIT_FAILURE);
	}

	/* If no args are specified, print the current status. */
	if (argc < 2) {
		printkstatus();
		return (EXIT_SUCCESS);
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
			relay_arg = optarg;
			break;
		case 'h':
			usage();
			return (EXIT_SUCCESS);
		default:
			usage();
			return (EXIT_FAILURE);
		}
	}
	/*
	 * If -a is specified, -e must also be specified.  Also, the
	 * combination of -e and -d is illegal.  Fail on either case.
	 */
	if ((aflag && !eflag) || (eflag && dflag)) {
		usage();
		return (EXIT_FAILURE);
	}

	/*
	 * Enable Relay Router communication support in the kernel.
	 */
	if (eflag) {
		struct in_addr current_addr;
		struct in_addr new_addr;
		in6_addr_t v6_rt;

		/*
		 * if -a was not specified, the well-known anycast will
		 * be used.
		 */
		if (!aflag) {
			new_addr.s_addr = htonl(INADDR_6TO4RRANYCAST);
		} else if (inet_pton(AF_INET, relay_arg, &new_addr) <= 0) {
			(void) fprintf(stderr, gettext("6to4relay: input "
			    "address (%s) is not a valid IPv4 dotted-decimal "
			    "string.\n"), relay_arg);
			return (EXIT_FAILURE);
		}

		status = dladm_iptun_get6to4relay(handle, &current_addr);
		if (status != DLADM_STATUS_OK) {
			(void) fprintf(stderr, gettext("6to4relay: "
			    "unable to obtain current 6to4 relay address: %s"),
			    dladm_status2str(status, errstr));
			return (EXIT_FAILURE);
		}

		if (current_addr.s_addr == new_addr.s_addr)
			return (EXIT_SUCCESS);

		status = dladm_iptun_set6to4relay(handle, &new_addr);
		if (status != DLADM_STATUS_OK) {
			(void) fprintf(stderr, gettext("6to4relay: "
			    "unable to set the 6to4 relay router address: "
			    "%s\n"), dladm_status2str(status, errstr));
			return (EXIT_FAILURE);
		}

		if (current_addr.s_addr != INADDR_ANY) {
			/* remove old default IPv6 route */
			IN6_V4ADDR_TO_6TO4(&current_addr, &v6_rt);
			modifyroute(RTM_DELETE, &v6_rt);
		}

		IN6_V4ADDR_TO_6TO4(&new_addr, &v6_rt);
		modifyroute(RTM_ADD, &v6_rt);
	}

	/*
	 * Disable Relay Router communication support in kernel.
	 */
	if (dflag) {
		struct in_addr rr_addr;
		in6_addr_t v6_rt;

		/*
		 * get Relay Router address from the kernel and delete
		 * default IPv6 route that was added for it.
		 */
		status = dladm_iptun_get6to4relay(handle, &rr_addr);
		if (status != DLADM_STATUS_OK) {
			(void) fprintf(stderr, gettext("6to4relay: "
			    "unable to obtain current 6to4 relay address: %s"),
			    dladm_status2str(status, errstr));
			return (EXIT_FAILURE);
		}
		if (rr_addr.s_addr == INADDR_ANY)
			return (EXIT_SUCCESS);

		IN6_V4ADDR_TO_6TO4(&rr_addr, &v6_rt);
		modifyroute(RTM_DELETE, &v6_rt);

		/*
		 * INADDR_ANY (0.0.0.0) is used by the kernel to disable Relay
		 * Router communication support.
		 */
		rr_addr.s_addr = INADDR_ANY;
		status = dladm_iptun_set6to4relay(handle, &rr_addr);
		if (status != DLADM_STATUS_OK) {
			(void) fprintf(stderr, gettext("6to4relay: "
			    "unable to disable tunneling to 6to4 relay router: "
			    "%s\n"), dladm_status2str(status, errstr));
			return (EXIT_FAILURE);
		}
	}

	return (EXIT_SUCCESS);
}
