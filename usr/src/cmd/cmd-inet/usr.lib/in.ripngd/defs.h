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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef	_IN_RIPNGD_DEFS_H
#define	_IN_RIPNGD_DEFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/stream.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <net/route.h>
#include <protocols/ripngd.h>

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <netdb.h>

#include <signal.h>
#include <stropts.h>
#include <arpa/inet.h>

#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>
#include <limits.h>

#include "table.h"
#include "trace.h"
#include "interface.h"

#define	PATH_PID	"/var/run/in.ripngd.pid"

/*
 * Timer values (in seconds) used in managing the routing table.
 * Every update forces an entry's timer to be reset.  After
 * EXPIRE_TIME without updates, the entry is marked invalid,
 * but held onto until GARBAGE_TIME so that others may
 * see it "be deleted".
 */
#define	EXPIRE_TIME		180	/* time to mark entry invalid */
#define	GARBAGE_TIME		300	/* time to garbage collect */
#define	MIN_SUPPLY_TIME		15	/* min. time to supply tables */
#define	MAX_SUPPLY_TIME		45	/* max. time to supply tables */
#define	MIN_WAIT_TIME		1	/* min. interval to multicast changes */
#define	MAX_WAIT_TIME		5	/* max. time to delay changes */

/*
 * Return a random number from a an range inclusive of the endpoints
 */
#define	GET_RANDOM(LOW, HIGH) (random() % ((HIGH) - (LOW) + 1) + (LOW))

/*
 * When we find any interfaces marked down we rescan the
 * kernel every CHECK_INTERVAL seconds to see if they've
 * come up.
 */
#define	CHECK_INTERVAL		60
#define	START_POLL_SIZE		5

#define	min(a, b)		((a) > (b) ? (b) : (a))

/*
 * The maximum receive buffer size is controlled via Solaris' NDD udp_max_buf
 * tunable.
 */
#define	RCVBUFSIZ		65536

#define	TIME_TO_MSECS(tval)	((tval).tv_sec * 1000 + (tval).tv_usec / 1000)

#define	HOPCNT_INFINITY		16		/* RFC 2080, section 2.1 */
#define	HOPCNT_NEXTHOP		255		/* RFC 2080, section 2.1.1 */

/*
 * XXX Some of these are defined in <inet/ip6.h> under _KERNEL (but should be
 * defined in <netinet/ip6.h> for completeness).
 */
#define	IPV6_MAX_HOPS		255		/* Max IPv6 hops */
#define	IPV6_MAX_PACKET		65535		/* maximum IPv6 packet size */
#define	IPV6_MIN_MTU		1280		/* Minimum IPv6 MTU */

extern struct		sockaddr_in6 allrouters;
extern struct		in6_addr allrouters_in6;
extern char		*control;
extern boolean_t	dopoison;
extern struct		interface *ifnet;
extern boolean_t	install;
extern int		iocsoc;
extern struct		timeval lastfullupdate;
extern struct		timeval lastmcast;
extern int		max_poll_ifs;
extern struct		rip6 *msg;
extern boolean_t	needupdate;
extern struct		timeval nextmcast;
extern struct		timeval now;
extern char		*packet;
extern struct		pollfd *poll_ifs;
extern int		poll_ifs_num;
extern int		rip6_port;
extern int		supplyinterval;
extern boolean_t	supplier;

extern void		dynamic_update(struct interface *);
extern void		in_data(struct interface *);
extern void		initifs(void);
extern void		sendpacket(struct sockaddr_in6 *, struct interface *,
    int, int);
extern void		setup_rtsock(void);
extern void		solicitall(struct sockaddr_in6 *);
extern void		supply(struct sockaddr_in6 *, struct interface *,
    int, boolean_t);
extern void		supplyall(struct sockaddr_in6 *, int,
    struct interface *, boolean_t);
extern void		term(void);
extern void		timer(void);
extern void		timevaladd(struct timeval *, struct timeval *);

#ifdef	__cplusplus
}
#endif

#endif	/* _IN_RIPNGD_DEFS_H */
