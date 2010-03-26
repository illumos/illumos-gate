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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_NDPD_DEFS_H
#define	_NDPD_DEFS_H

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <syslog.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <sys/stropts.h>

#include <string.h>
#include <ctype.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/route.h>
#include <libipadm.h>
#include <ipadm_ndpd.h>

#include "tables.h"

#ifdef	__cplusplus
extern "C" {
#endif

#define	CURHOP_UNSPECIFIED 0
#define	PATH_NDPD_CONF	"/etc/inet/ndpd.conf"
#define	PATH_PID	"/var/run/in.ndpd.pid"

extern int debug, no_loopback;

extern struct in6_addr all_nodes_mcast;
extern struct in6_addr all_routers_mcast;

extern int			rtsock;
extern struct	rt_msghdr	*rt_msg;
extern struct	sockaddr_in6	*rta_gateway;
extern struct	sockaddr_dl	*rta_ifp;

/* Debug flags */
#define	D_ALL		0xffff
#define	D_DEFAULTS	0x0001		/* Default values in config file */
#define	D_CONFIG	0x0002		/* Config file */
#define	D_PHYINT	0x0004		/* phyint table */
#define	D_PREFIX	0x0008		/* prefix table */
#define	D_ROUTER	0x0010		/* router table */
#define	D_STATE		0x0020		/* RS/RA state machine */
#define	D_IFSCAN	0x0040		/* Scan of kernel interfaces */
#define	D_TIMER		0x0080		/* Timer mechanism */
#define	D_PARSE		0x0100		/* config file parser */
#define	D_PKTIN		0x0200		/* Received packet */
#define	D_PKTBAD	0x0400		/* Malformed packet */
#define	D_PKTOUT	0x0800		/* Sent packet */
#define	D_TMP		0x1000		/* RFC3041 mechanism */
#define	D_DHCP		0x2000		/* RFC3315 DHCPv6 (stateful addrs) */

#define	IF_SEPARATOR		':'
#define	IPV6_MAX_HOPS		255
#define	IPV6_MIN_MTU		(1024+256)
#define	IPV6_ABITS		128
#define	TMP_TOKEN_BITS		64
#define	TMP_TOKEN_BYTES		(TMP_TOKEN_BITS / 8)
#define	MAX_DAD_FAILURES	5

/* Return a random number from a an range inclusive of the endpoints */
#define	GET_RANDOM(LOW, HIGH) (random() % ((HIGH) - (LOW) + 1) + (LOW))

#define	TIMER_INFINITY	0xFFFFFFFFU	/* Never time out */
#define	PREFIX_INFINITY 0XFFFFFFFFU	/* A "forever" prefix lifetime */

/*
 * Used by 2 hour rule for stateless addrconf
 */
#define	MIN_VALID_LIFETIME	(2*60*60)		/* In seconds */

/*
 * Control how often pi_ReachableTime gets re-randomized
 */
#define	MIN_REACH_RANDOM_INTERVAL	(60*1000)	/* 1 minute in ms */
#define	MAX_REACH_RANDOM_INTERVAL	(60*60*1000)	/* 1 hour in ms */

/*
 * Parsing constants
 */
#define	MAXLINELEN	4096
#define	MAXARGSPERLINE	128

void		timer_schedule(uint_t delay);
extern void	logmsg(int level, const char *fmt, ...);
extern void	logperror(const char *str);
extern void	logperror_pi(const struct phyint *pi, const char *str);
extern void	logperror_pr(const struct prefix *pr, const char *str);
extern int	parse_config(char *config_file, boolean_t file_required);

extern int	poll_add(int fd);
extern int	poll_remove(int fd);

extern char	*fmt_lla(char *llabuf, int bufsize, uchar_t *lla, int llalen);

extern int	do_dad(char *ifname, struct sockaddr_in6 *testaddr);

#ifdef	__cplusplus
}
#endif

#endif	/* _NDPD_DEFS_H */
