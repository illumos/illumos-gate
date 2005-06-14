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
% * Version 2 rstat; for backwards compatibility only.
% */

%/*
% * Copyright (c) 1985, 1990, 1991 by Sun Microsystems, Inc.
% */

%/* from rstat_v2.x */

#ifdef RPC_HDR
%
%#pragma ident	"%Z%%M%	%I%	%E% SMI"
%
#endif

const RSTAT_V2_CPUSTATES = 4;
const RSTAT_V2_DK_NDRIVE = 4;

/*
 * the cpu stat values
 */

const RSTAT_V2_CPU_USER = 0;
const RSTAT_V2_CPU_NICE = 1;
const RSTAT_V2_CPU_SYS = 2;
const RSTAT_V2_CPU_IDLE = 3;

/*
 * GMT since 0:00, January 1, 1970
 */
struct rstat_v2_timeval {
	int tv_sec;	/* seconds */
	int tv_usec;	/* and microseconds */
};

struct statsswtch {				/* RSTATVERS_SWTCH */
	int cp_time[RSTAT_V2_CPUSTATES];
	int dk_xfer[RSTAT_V2_DK_NDRIVE];
	int v_pgpgin;	/* these are cumulative sum */
	int v_pgpgout;
	int v_pswpin;
	int v_pswpout;
	int v_intr;
	int if_ipackets;
	int if_ierrors;
	int if_oerrors;
	int if_collisions;
	int v_swtch;
	int avenrun[3];
	rstat_v2_timeval boottime;
};

program RSTATPROG {
	/*
	 * Does not have current time
	 */
	version RSTATVERS_SWTCH {
		statsswtch
		RSTATPROC_STATS(void) = 1;

		unsigned int
		RSTATPROC_HAVEDISK(void) = 2;
	} = 2;
} = 100001;
