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

#ifndef	_MPD_DEFS_H
#define	_MPD_DEFS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <alloca.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <limits.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <syslog.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <stropts.h>
#include <sys/tihdr.h>
#include <inet/mib2.h>

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
#include <net/if_dl.h>

#include <inet/ip.h>
#include <libintl.h>
#include <locale.h>
#include <deflt.h>

#include <libdlpi.h>
#include <libinetutil.h>
#include <libnvpair.h>
#include <libsysevent.h>
#include <sys/sysevent.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/ipmp.h>

#include <ipmp_mpathd.h>
#include <ipmp_query_impl.h>
#include <assert.h>

/* Debug flags */
#define	D_ALL		0xffff		/* enable all debug */
#define	D_PROBE		0x0001		/* probe mechanism */
#define	D_FAILREP	0x0002		/* failure/repair mechanism */
#define	D_PHYINT	0x0004		/* phyint table */
#define	D_LOGINT	0x0008		/* logint table */
#define	D_TARGET	0x0010		/* target table */
#define	D_TIMER		0x0020		/* Timer mechanism */
#define	D_PKTBAD	0x0040		/* Malformed packet */
#define	D_LINKNOTE	0x0080		/* Link up/down notifications */
/*
 * Need a common header file that defines the 2 constants below.
 * Many applications need them.
 */
#define	IF_SEPARATOR		':'
#define	IPV6_MAX_HOPS		255

/*
 * General parameters for phyint failure/repair detection
 */
#define	NUM_PROBE_FAILS		5	/* NUM_PROBE_FAILS probe failures */
					/* trigger NIC failure detection */
#define	NUM_PROBE_REPAIRS	10	/* NUM_PROBE_REPAIRS probe repairs */
					/* trigger NIC repair detection */

#define	MIN_RANDOM_FACTOR	0.5	/* Randomization factors to */
#define	MAX_RANDOM_FACTOR	1.0	/* determine probe send time */

#define	MIN_PROBE_TARGETS	3	/* Minimum number of targets */
#define	MAX_PROBE_TARGETS	5	/* Maximum number of targets */

/*
 * A target that is declared slow is usable again after MIN_RECOVERY_TIME ns
 */
#define	MIN_RECOVERY_TIME	(60000000000LL) /* (In ns) 60 secs */

/*
 * If the Failure Detection Time (FDT) is bumped up because the target CRTT
 * is high, it won't be reduced for the next MIN_SETTLING_TIME ns, to prevent
 * flapping of FDT
 */
#define	MIN_SETTLING_TIME	(60000000000LL) /* (In ns) 60 secs */

/*
 * An admin or script might place a phyint in a group before assigning a test
 * address.  To give them time to configure a test address, we delay whining
 * about it being missing for TESTADDR_CONF_TIME seconds.
 */
#define	TESTADDR_CONF_TIME	20

/*
 * The circular probe stats array should be able to hold enough
 * samples to detect phyint failure, target failure, phyint repair
 * and target repair.
 */
#define	PROBE_STATS_COUNT	\
	((uint16_t)(NUM_PROBE_REPAIRS * MAX_PROBE_TARGETS + 2))

#define	FAILURE_DETECTION_TIME	10000	/* Default is 10 s */
#define	MIN_FAILURE_DETECTION_TIME	100	/* Minimum is 100 ms */
#define	FAILURE_DETECTION_QP	40	/* quiet period, in seconds */

#define	NEXT_FDT_MULTIPLE	2	/* Raise or lower the FDT by this */
					/* factor when required */
#define	LOWER_FDT_TRIGGER	4	/* Lower the FDT if crtt is less */
					/* than FDT / LOWER_FDT_TRIGGER  */
#define	EXCEPTION_FACTOR	2	/* The exception target has a crtt */
					/* greater by this factor */

#define	IF_SCAN_INTERVAL	20000	/* Do initifs() every 20 secs */

/* Return a random number from a range inclusive of the endpoints */
#define	GET_RANDOM(LOW, HIGH) (random() % ((HIGH) - (LOW) + 1) + (LOW))

#define	TIMER_INFINITY	0x7FFFFFFFU	/* Never time out */

/*
 * Comparing unsigned 32 bit time values in a circular 32-bit sequence space
 */
#define	TIME_GE(a, b)	((int32_t)((a) - (b)) >= 0)
#define	TIME_GT(a, b)	((int32_t)((a) - (b)) >  0)
#define	TIME_LT(a, b)	((int32_t)((a) - (b)) <  0)
#define	TIME_LE(a, b)	((int32_t)((a) - (b)) <= 0)

/*
 * Comparing unsigned 16 bit sequence numbers in a circular 16-bit
 * sequence space
 */
#define	SEQ_GE(a, b)	((int16_t)((a) - (b)) >= (int16_t)0)
#define	SEQ_GT(a, b)	((int16_t)((a) - (b)) >  (int16_t)0)
#define	SEQ_LT(a, b)	((int16_t)((a) - (b)) <  (int16_t)0)
#define	SEQ_LE(a, b)	((int16_t)((a) - (b)) <= (int16_t)0)

#define	AF_OTHER(af)	((af) == AF_INET ? AF_INET6 : AF_INET)
#define	AF_STR(af)	((af) == AF_INET ? "inet" : "inet6")

/*
 * Globals
 */
extern boolean_t failback_enabled;	/* cmd option to disable failbacks */
extern boolean_t track_all_phyints;	/* cmd option to track all phyints */

					/* all times below in millisec */
extern	int	user_probe_interval;	/* interval between probes, as */
					/* derived from user specified fdt */
extern	int	user_failure_detection_time; /* User specified fdt */

extern	int	ifsock_v4;		/* IPv4 socket for ioctls */
extern	int	ifsock_v6;		/* IPv6 socket for ioctls */

extern int debug;			/* debug option */
extern boolean_t cleanup_started;	/* true if we're shutting down */
extern boolean_t handle_link_notifications;

/*
 * Function prototypes
 */
extern void	timer_schedule(uint_t delay);
extern void	logmsg(int pri, const char *fmt, ...);
extern void	logperror(const char *str);
extern int	poll_add(int fd);
extern int	poll_remove(int fd);
extern uint64_t	getcurrentsec(void);
extern uint_t	getcurrenttime(void);

#define	logerr(...)	logmsg(LOG_ERR, __VA_ARGS__)
#define	logtrace(...)	logmsg(LOG_INFO, __VA_ARGS__)
#define	logdebug(...)	logmsg(LOG_DEBUG, __VA_ARGS__)

#ifdef	__cplusplus
}
#endif

#endif	/* _MPD_DEFS_H */
