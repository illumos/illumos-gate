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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/vmsystm.h>
#include <sys/cpuvar.h>
#include <sys/sysinfo.h>

/*
 * This define represents the number of
 * useful pages transferred per paging i/o operation, under the assumption
 * that half of the total number is actually useful.  However, if there's
 * only one page transferred per operation, we assume that it's useful.
 */

#ifdef	lint
#define	UsefulPagesPerIO	1
#else	/* lint */
#define	UsefulPagesPerIO	nz((MAXBSIZE/PAGESIZE)/2)
#endif	/* lint */

extern int dopageout;

/* Average new into old with aging factor time */
#define	ave(smooth, cnt, time) \
	smooth = ((time - 1) * (smooth) + (cnt)) / (time)

/*
 * pagein and pageout rates for use by swapper.
 */
ulong_t pginrate;		/* 5 second average	*/
ulong_t pgoutrate;		/* 5 second average	*/

static ulong_t ogpagein;	/* pagein rate a sec ago */
static ulong_t ogpageout;	/* pageout rate a sec ago */

/*
 * Called once a second to gather statistics.
 */
void
vmmeter(void)
{
	cpu_t *cp;
	ulong_t gpagein, gpageout;

	/*
	 * Compute 5 sec and 30 sec average free memory values.
	 */
	ave(avefree, freemem, 5);
	ave(avefree30, freemem, 30);

	/*
	 * Compute the 5 secs average of pageins and pageouts.
	 */
	gpagein = gpageout = 0;

	cp = cpu_list;
	do {
		gpagein += (ulong_t)CPU_STATS(cp, vm.pgin);
		gpageout += (ulong_t)CPU_STATS(cp, vm.pgout);
	} while ((cp = cp->cpu_next) != cpu_list);

	if ((gpagein >= ogpagein) && (gpageout >= ogpageout)) {
		ave(pginrate, gpagein - ogpagein, 5);
		ave(pgoutrate, gpageout - ogpageout, 5);
	}

	/*
	 * Save the current pagein/pageout values.
	 */
	ogpagein = gpagein;
	ogpageout = gpageout;

	if (!lotsfree || !dopageout)
		return;

	/*
	 * Decay deficit by the expected number of pages brought in since
	 * the last call (i.e., in the last second).  The calculation
	 * assumes that one half of the pages brought in are actually
	 * useful (see comment above), and that half of the overall
	 * paging i/o activity is pageins as opposed to pageouts (the
	 * trailing factor of 2)  It also assumes that paging i/o is done
	 * in units of MAXBSIZE bytes, which is a dubious assumption to
	 * apply to all file system types.
	 */
	deficit -= MIN(deficit,
	    MAX(deficit / 10, UsefulPagesPerIO * maxpgio / 2));
}
