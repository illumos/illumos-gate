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
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routing table management daemon.
 */

/*
 * Trace record format.
 */
struct	iftrace {
	time_t	ift_stamp;		/* time stamp */
	struct	sockaddr_in6 ift_who;	/* from/to */
	char	*ift_packet;		/* pointer to packet */
	int	ift_size;		/* size of packet */
	int	ift_metric;		/* metric on associated metric */
};

/*
 * Per interface packet tracing buffers.  An incoming and
 * outgoing circular buffer of packets is maintained, per
 * interface, for debugging.  Buffers are dumped whenever
 * an interface is marked down.
 */
struct	ifdebug {
	struct	iftrace *ifd_records;	/* array of trace records */
	struct	iftrace *ifd_front;	/* next empty trace record */
	int	ifd_count;		/* number of unprinted records */
	struct	interface *ifd_if;	/* for locating stuff */
};

/*
 * Packet tracing stuff.
 */
extern FILE		*ftrace;
extern boolean_t	tracepackets;
extern int		tracing;

#define	ACTION_BIT	0x0001
#define	INPUT_BIT	0x0002
#define	OUTPUT_BIT	0x0004

#define	TRACE_ACTION(action, route) { \
	if (tracing & ACTION_BIT) \
		traceaction(ftrace, (action), (route)); \
}

#define	TRACE_INPUT(ifp, src, size) { \
	if ((tracing & INPUT_BIT) && ((ifp) != NULL)) { \
		trace(&(ifp)->int_input, (src), packet, (size), \
		    (ifp)->int_metric); \
	} \
	if (tracepackets) { \
		dumppacket(stdout, "from", (struct sockaddr_in6 *)(src), \
		    packet, (size)); \
	} \
}
#define	TRACE_OUTPUT(ifp, dst, size) { \
	if ((tracing & OUTPUT_BIT) && ((ifp) != NULL)) { \
		trace(&(ifp)->int_output, (dst), packet, (size), \
		    (ifp)->int_metric); \
	} \
	if (tracepackets) { \
		dumppacket(stdout, "to", (struct sockaddr_in6 *)(dst), \
		    packet, (size)); \
	} \
}

extern void	dumppacket(FILE *, char *, struct sockaddr_in6 *, char *, int);
extern void	trace(struct ifdebug *, struct sockaddr_in6 *, char *, int,
    int);
extern void	traceaction(FILE *, char *, struct rt_entry *);
extern void	traceinit(struct interface *);
extern void	traceon(char *);
extern void	traceonfp(FILE *);
