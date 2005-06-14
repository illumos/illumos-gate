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
%/*
% * Copyright (c) 1985, 1990, 1991 by Sun Microsystems, Inc.
% */

%/* from rstat.x */

/*
 * Gather statistics on remote machines
 */

#ifdef RPC_HDR
%
%#pragma ident	"%Z%%M%	%I%	%E% SMI"
%
%/*
% * Scale factor for scaled integers used to count load averages.
% */
%#ifndef	FSCALE
%#define	FSHIFT	8	/* bits to right of fixed binary point */
%#define	FSCALE	(1<<FSHIFT)
%#endif	/* ndef FSCALE */
%
%#ifndef DST_NONE
%#include <sys/time.h>		/* The time struct defined below is	*/
%#endif				/* meant to match struct timeval.	*/
%
%
%
%
%
%
#elif RPC_SVC
%
%/*
% *  Server side stub routines for the rstat daemon
% */
%
#elif RPC_CLNT
%
%/*
% *  Client side stub routines for the rstat daemon
% */
%
#elif RPC_XDR
%/*
% * XDR routines for the rstat daemon, rup and perfmeter.
% */
%
%/*
% * xdr_timeval was used in previous releases.
% */
%
%bool_t
%#ifdef __STDC__
%xdr_timeval(XDR *xdrs, struct timeval *tvp)
%#else /* K&R C */
%xdr_timeval(xdrs, tvp)
%	XDR *xdrs;
%	struct timeval *tvp;
%#endif /* K&R C */
%{
%	return (xdr_rstat_timeval(xdrs, (rstat_timeval *)tvp));
%}

%
#endif

const RSTAT_CPUSTATES = 4;
const RSTAT_DK_NDRIVE = 4;

/*
 * the cpu stat values
 */

const RSTAT_CPU_USER = 0;
const RSTAT_CPU_NICE = 1;
const RSTAT_CPU_SYS = 2;
const RSTAT_CPU_IDLE = 3;

/*
 * GMT since 0:00, January 1, 1970
 */
struct rstat_timeval {
	int tv_sec;	/* seconds */
	int tv_usec;	/* and microseconds */
};

struct statsvar {				/* RSTATVERS_VAR */
	int cp_time<>; 		/* variable number of CPU states */
	int dk_xfer<>;		/* variable number of disks */
	unsigned v_pgpgin;	/* these are cumulative sum */
	unsigned v_pgpgout;
	unsigned v_pswpin;
	unsigned v_pswpout;
	unsigned v_intr;
	int if_ipackets;
	int if_ierrors;
	int if_opackets;
	int if_oerrors;
	int if_collisions;
	unsigned v_swtch;
	int avenrun[3];
	rstat_timeval boottime;
	rstat_timeval curtime;
};

struct statstime {				/* RSTATVERS_TIME */
	int cp_time[RSTAT_CPUSTATES];
	int dk_xfer[RSTAT_DK_NDRIVE];
	unsigned int v_pgpgin;	/* these are cumulative sum */
	unsigned int v_pgpgout;
	unsigned int v_pswpin;
	unsigned int v_pswpout;
	unsigned int v_intr;
	int if_ipackets;
	int if_ierrors;
	int if_oerrors;
	int if_collisions;
	unsigned int v_swtch;
	int avenrun[3];
	rstat_timeval boottime;
	rstat_timeval curtime;
	int if_opackets;
};

program RSTATPROG {
        /*
         * Version 4 allows for variable number of disk and RSTAT_CPU states.
         */
	version RSTATVERS_VAR {
		statsvar
		RSTATPROC_STATS (void) = 1;
		unsigned int
		RSTATPROC_HAVEDISK (void) = 2;
	} = 4;
	/*
	 * Newest version includes current time and context switching info
	 */
	version RSTATVERS_TIME {
		statstime
		RSTATPROC_STATS(void) = 1;
		unsigned int
		RSTATPROC_HAVEDISK(void) = 2;
	} = 3;
} = 100001;

#ifdef RPC_HDR
%
%#if defined(__STDC__) || defined(__cplusplus)
%enum clnt_stat rstat(char *, struct statstime *);
%int havedisk(char *);
%#else
%enum clnt_stat rstat();
%int havedisk();
%#endif
%
#endif
