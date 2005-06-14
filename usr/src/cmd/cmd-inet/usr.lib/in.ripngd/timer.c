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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routing Table Management Daemon
 */
#include "defs.h"

int supplyinterval;			/* current supply interval */

/*
 * Timer routine.  Performs routing information supply
 * duties and manages timers on routing table entries.
 * Management of the RTS_CHANGED bit assumes that we multicast
 * each time called.
 */
void
timer(void)
{
	struct rthash *rh;
	struct rt_entry *rt;
	boolean_t timetomulticast = _B_FALSE;
	int i;
	static int iftime;		/* interface timer */
	static int mtime;		/* periodic mcast supply timer */
	static int alarmtime = 0;	/* time elapsed since last call */
	int mintime;			/* tracks when next timer will expire */

	/*
	 * On the initial call to timer(), the various times that are kept track
	 * of need to be initialized.  After initializing everything, "remember"
	 * (via a static) how long until the next timer expires.
	 */
	if (alarmtime == 0) {
		supplyinterval = GET_RANDOM(MIN_SUPPLY_TIME, MAX_SUPPLY_TIME);
		iftime = 0;
		mtime = supplyinterval;
		alarmtime = supplyinterval;
		(void) alarm(alarmtime);
		return;
	}

	/*
	 * Initialize mintime to a suitable "large" value and then compare it to
	 * other times in the future to determine which event will occur next.
	 */
	mintime = INT_MAX;
	(void) sighold(SIGHUP);
	(void) sighold(SIGUSR1);
	(void) sighold(SIGUSR2);

	iftime += alarmtime;
	if (iftime >= CHECK_INTERVAL) {
		initifs();
		iftime = 0;
	}
	mintime = min(mintime, CHECK_INTERVAL - iftime);

	mtime += alarmtime;
	if (mtime >= supplyinterval) {
		if (supplier)
			timetomulticast = _B_TRUE;
		mtime = 0;
		supplyinterval = GET_RANDOM(MIN_SUPPLY_TIME, MAX_SUPPLY_TIME);
	}
	mintime = min(mintime, supplyinterval - mtime);

	for (i = IPV6_ABITS; i >= 0; i--) {
		if (net_hashes[i] == NULL)
			continue;

		for (rh = net_hashes[i];
		    rh < &net_hashes[i][ROUTEHASHSIZ]; rh++) {
			for (rt = rh->rt_forw; rt != (struct rt_entry *)rh;
			    rt = rt->rt_forw) {
				/*
				 * We don't advance time on a routing entry for
				 * an interface because we catch
				 * interfaces going up and down in initifs.
				 */
				rt->rt_state &= ~RTS_CHANGED;
				if ((rt->rt_state & RTS_INTERFACE) != 0)
					continue;
				rt->rt_timer += alarmtime;
				if (rt->rt_timer >= GARBAGE_TIME) {
					rt = rt->rt_back;
					rtdelete(rt->rt_forw);
					continue;
				}
				if (rt->rt_timer >= EXPIRE_TIME) {
					rtdown(rt);
					mintime = min(mintime,
					    GARBAGE_TIME - rt->rt_timer);
				} else {
					mintime = min(mintime,
					    EXPIRE_TIME - rt->rt_timer);
				}
			}
		}
	}

	if (timetomulticast) {
		supplyall(&allrouters, 0, (struct interface *)NULL, _B_TRUE);
		(void) gettimeofday(&now, (struct timezone *)NULL);
		lastmcast = now;
		lastfullupdate = now;
		needupdate = _B_FALSE;	/* cancel any pending dynamic update */
		nextmcast.tv_sec = 0;
	}
	(void) sigrelse(SIGUSR2);
	(void) sigrelse(SIGUSR1);
	(void) sigrelse(SIGHUP);

	/*
	 * "Remember" (via a static) how long until the next timer expires.
	 */
	alarmtime = mintime;
	(void) alarm(alarmtime);
}

/*
 * On SIGTERM, let everyone know we're going away.
 */
void
term(void)
{
	struct rthash *rh;
	struct rt_entry *rt;
	int i;

	if (!supplier)
		exit(EXIT_SUCCESS);
	for (i = IPV6_ABITS; i >= 0; i--) {
		if (net_hashes[i] == NULL)
			continue;

		for (rh = net_hashes[i]; rh < &net_hashes[i][ROUTEHASHSIZ];
		    rh++) {
			for (rt = rh->rt_forw; rt != (struct rt_entry *)rh;
			    rt = rt->rt_forw) {
				rt->rt_metric = HOPCNT_INFINITY;
			}
		}
	}
	supplyall(&allrouters, 0, (struct interface *)NULL, _B_TRUE);
	(void) unlink(PATH_PID);
	exit(EXIT_SUCCESS);
}
