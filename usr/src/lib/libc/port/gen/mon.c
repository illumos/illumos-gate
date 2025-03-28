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
 * Copyright 2025 MNX Cloud, Inc.
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 *	Environment variable PROFDIR added such that:
 *		If PROFDIR doesn't exist, "mon.out" is produced as before.
 *		If PROFDIR = NULL, no profiling output is produced.
 *		If PROFDIR = string, "string/pid.progname" is produced,
 *		  where name consists of argv[0] suitably massaged.
 *
 *
 *	Routines:
 *		(global) monitor	init, cleanup for prof(1)iling
 *		(global) _mcount	function call counter
 *		(global) _mcount_newent	call count entry manager
 *		(static) _mnewblock	call count block allocator
 *
 *
 *	Monitor(), coordinating with mcount(), mcount_newent() and mnewblock(),
 *	maintains a series of one or more blocks of prof-profiling
 *	information.  These blocks are added in response to calls to
 *	monitor() (explicitly or via mcrt[01]'s _start) and, via mcount()'s
 *	calls to mcount_newent() thence to mnewblock().
 *	The blocks are tracked via a linked list of block anchors,
 *	which each point to a block.
 *
 *
 *	An anchor points forward, backward and 'down' (to a block).
 *	A block has the profiling information, and consists of
 *	three regions: a header, a function call count array region,
 *	and an optional execution histogram region, as illustrated below.
 *
 *
 *		 "anchor"
 *		+========+
 *	prior<--|        |-->next anchor
 *	anchor	|        |
 *		+========+
 *		 |
 *		 |
 *		 V "block"
 *		+-----------+
 *		+  header   +
 *		+-----------+
 *		+           +
 *		+ fcn call  +	// data collected by mcount
 *		+  counts   +
 *		+  array    +
 *		+           +
 *		+-----------+
 *		+           +
 *		+ execution +	// data collected by system call,
 *		+ profile   +	// profil(2) (assumed ALWAYS specified
 *		+ histogram +	// by monitor()-caller, even if small;
 *		+           +	// never specified by mnewblock()).
 *		+-----------+
 *
 *	The first time monitor() is called, it sets up the chain
 *	by allocating an anchor and initializing countbase and countlimit
 *	to zero.  Everyone assumes that they start out zeroed.
 *
 *	When a user (or _start from mcrt[01]) calls monitor(), they
 *	register a buffer which contains the third region (either with
 *	a meaningful size, or so short that profil-ing is being shut off).
 *
 *	For each fcn, the first time it calls mcount(), mcount calls
 *	mcount_newent(), which parcels out the fcn call count entries
 *	from the current block, until they are exausted; then it calls
 *	mnewblock().
 *
 *	Mnewbloc() allocates a block Without a third region, and
 *	links in a new associated anchor, adding a new anchor&block pair
 *	to the linked list.  Each new mnewblock() block or user block,
 *	is added to the list as it comes in, FIFO.
 *
 *	When monitor() is called to close up shop, it writes out
 *	a summarizing header, ALL the fcn call counts from ALL
 *	the blocks, and the Last specified execution histogram
 *	(currently there is no neat way to accumulate that info).
 *	This preserves all call count information, even when
 *	new blocks are specified.
 *
 *	NOTE - no block passed to monitor() may be freed, until
 *	it is called to clean up!!!!
 *
 */

#pragma weak _monitor = monitor

#include "lint.h"
#include "mtlib.h"
#include "libc.h"
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <mon.h>
#include <fcntl.h>
#include <unistd.h>
#include <thread.h>
#include <synch.h>

#define	PROFDIR	"PROFDIR"

static mutex_t mon_lock = DEFAULTMUTEX;

char **___Argv = NULL; /* initialized to argv array by mcrt0 (if loaded) */

/*
 * countbase and countlimit are used to parcel out
 * the pc,count cells from the current block one at
 * a time to each profiled function, the first time
 * that function is called.
 * When countbase reaches countlimit, mcount() calls
 * mnewblock() to link in a new block.
 *
 * Only monitor/mcount/mcount_newent/mnewblock() should change these!!
 * Correct that: only these routines are ABLE to change these;
 * countbase/countlimit are now STATIC!
 */
static char *countbase;		/* addr of next pc,count cell to use in block */
static char *countlimit;	/* addr lim for cells (addr after last cell) */

typedef struct anchor	ANCHOR;

struct anchor {
	ANCHOR  *next, *prior;	/* forward, backward ptrs for list */
	struct hdr  *monBuffer;	/* 'down' ptr, to block */
	short  flags;		/* indicators - has histogram designation */

	int  histSize;		/* if has region3, this is size. */
};

#define	HAS_HISTOGRAM	0x0001		/* this buffer has a histogram */

static ANCHOR	*curAnchor = NULL;	/* addr of anchor for current block */
static ANCHOR    firstAnchor;		/* the first anchor to use */
					/* - hopefully the Only one needed */
					/* a speedup for most cases. */
static char *mon_out;

static int writeBlocks(void);
static void _mnewblock(void);
struct cnt *_mcount_newent(void);

/*
 * int (*alowpc)(), (*ahighpc)(); boundaries of text to be monitored
 * WORD *buffer;	ptr to space for monitor data(WORDs)
 * size_t bufsize;	size of above space(in WORDs)
 * size_t nfunc;	max no. of functions whose calls are counted
 *			(default nfunc is 300 on PDP11, 600 on others)
 */
void
monitor(int (*alowpc)(void), int (*ahighpc)(void), WORD *buffer,
    size_t bufsize, size_t nfunc)
{
	uint_t scale;
	long text;
	char *s;
	struct hdr *hdrp;
	ANCHOR  *newanchp;
	size_t	ssiz;
	int error;
	char	*lowpc = (char *)alowpc;
	char	*highpc = (char *)ahighpc;

	lmutex_lock(&mon_lock);

	if (lowpc == NULL) {		/* true only at the end */
		error = 0;
		if (curAnchor != NULL) { /* if anything was collected!.. */
			profil(NULL, 0, 0, 0);
			if (writeBlocks() == 0)
				error = errno;
		}
		lmutex_unlock(&mon_lock);
		if (error) {
			errno = error;
			perror(mon_out);
		}
		return;
	}

	/*
	 * Ok - they want to submit a block for immediate use, for
	 *	function call count consumption, and execution profile
	 *	histogram computation.
	 * If the block fails sanity tests, just bag it.
	 * Next thing - get name to use. If PROFDIR is NULL, let's
	 *	get out now - they want No Profiling done.
	 *
	 * Otherwise:
	 * Set the block hdr cells.
	 * Get an anchor for the block, and link the anchor+block onto
	 *	the end of the chain.
	 * Init the grabba-cell externs (countbase/limit) for this block.
	 * Finally, call profil and return.
	 */

	ssiz = ((sizeof (struct hdr) + nfunc * sizeof (struct cnt)) /
	    sizeof (WORD));
	if (ssiz >= bufsize || lowpc >= highpc) {
		lmutex_unlock(&mon_lock);
		return;
	}

	s = getenv(PROFDIR);
	if (s == NULL || ___Argv == NULL) {
		mon_out = MON_OUT; /* use default "mon.out" */
	} else if (*s == '\0') { /* value of PROFDIR is NULL */
		lmutex_unlock(&mon_lock);
		return; /* no profiling on this run */
	} else { /* construct "PROFDIR/pid.progname" */
		int n;
		pid_t pid;
		char *name;
		size_t len;

		len = strlen(s);
		/* 15 is space for /pid.mon.out\0, if necessary */
		mon_out = libc_malloc(len + strlen(___Argv[0]) + 15);
		if (mon_out == NULL) {
			lmutex_unlock(&mon_lock);
			perror("");
			return;
		}
		(void) strcpy(mon_out, s);
		name = mon_out + len;
		*name++ = '/'; /* two slashes won't hurt */

		if ((pid = getpid()) <= 0) /* extra test just in case */
			pid = 1; /* getpid returns something inappropriate */

		/* suppress leading zeros */
		for (n = 10000; n > pid; n /= 10)
			;
		for (; ; n /= 10) {
			*name++ = pid/n + '0';
			if (n == 1)
				break;
			pid %= n;
		}
		*name++ = '.';

		if (___Argv != NULL) {	/* mcrt0.s executed */
			if ((s = strrchr(___Argv[0], '/')) != NULL)
				(void) strcpy(name, s + 1);
			else
				(void) strcpy(name, ___Argv[0]);
		} else {
			(void) strcpy(name, MON_OUT);
		}
	}


	hdrp = (struct hdr *)(uintptr_t)buffer;	/* initialize 1st region */
	hdrp->lpc = lowpc;
	hdrp->hpc = highpc;
	hdrp->nfns = nfunc;

	/* get an anchor for the block */
	newanchp = (curAnchor == NULL) ? &firstAnchor :
	    (ANCHOR *)libc_malloc(sizeof (ANCHOR));

	if (newanchp == NULL) {
		lmutex_unlock(&mon_lock);
		perror("monitor");
		return;
	}

	/* link anchor+block into chain */
	newanchp->monBuffer = hdrp;		/* new, down. */
	newanchp->next  = NULL;			/* new, forward to NULL. */
	newanchp->prior = curAnchor;		/* new, backward. */
	if (curAnchor != NULL)
		curAnchor->next = newanchp;	/* old, forward to new. */
	newanchp->flags = HAS_HISTOGRAM;	/* note it has a histgm area */

	/* got it - enable use by mcount() */
	countbase  = (char *)buffer + sizeof (struct hdr);
	countlimit = countbase + (nfunc * sizeof (struct cnt));

	/* (set size of region 3) */
	newanchp->histSize = (int)
	    (bufsize * sizeof (WORD) - (countlimit - (char *)buffer));


	/* done w/regions 1 + 2: setup 3  to activate profil processing. */
	buffer += ssiz;			/* move ptr past 2'nd region */
	bufsize -= ssiz;		/* no. WORDs in third region */
					/* no. WORDs of text */
	text = (highpc - lowpc + sizeof (WORD) - 1) / sizeof (WORD);

	/*
	 * scale is a 16 bit fixed point fraction with the decimal
	 * point at the left
	 */
	if (bufsize < text) {
		/* make sure cast is done first! */
		double temp = (double)bufsize;
		scale = (uint_t)((temp * (long)0200000L) / text);
	} else {
		/* scale must be less than 1 */
		scale = 0xffff;
	}
	bufsize *= sizeof (WORD);	/* bufsize into # bytes */
	profil(buffer, bufsize, (ulong_t)lowpc, scale);


	curAnchor = newanchp;	/* make latest addition, the cur anchor */
	lmutex_unlock(&mon_lock);
}

/*
 * writeBlocks() - write accumulated profiling info, std fmt.
 *
 * This routine collects the function call counts, and the
 * last specified profil buffer, and writes out one combined
 * 'pseudo-block', as expected by current and former versions
 * of prof.
 */
static int
writeBlocks(void)
{
	int fd;
	int ok;
	ANCHOR *ap;		/* temp anchor ptr */
	struct hdr sum;		/* summary header (for 'pseudo' block) */
	ANCHOR *histp;		/* anchor with histogram to use */

	if ((fd = creat(mon_out, 0666)) < 0)
		return (0);

	/*
	 * this loop (1) computes # funct cts total
	 *  (2) finds anchor of last block w / hist(histp)
	 */
	histp = NULL;
	for (sum.nfns = 0, ap = &firstAnchor; ap != NULL; ap = ap->next) {
		sum.nfns += ap->monBuffer->nfns; /* accum num of cells */
		if (ap->flags & HAS_HISTOGRAM)
			histp = ap;	 /* remember lastone with a histgm */
	}


	/* copy pc range from effective histgm */
	sum.lpc = histp->monBuffer->lpc;
	sum.hpc = histp->monBuffer->hpc;

	ok = (write(fd, (char *)&sum, sizeof (sum)) == sizeof (sum));

	if (ok) {		/* if the hdr went out ok.. */
		size_t amt;
		char *p;

		/* write out the count arrays (region 2's) */
		for (ap = &firstAnchor; ok && ap != NULL; ap = ap->next) {
			amt = ap->monBuffer->nfns * sizeof (struct cnt);
			p = (char *)ap->monBuffer + sizeof (struct hdr);

			ok = (write(fd, p, amt) == amt);
		}

		/* count arrays out; write out histgm area */
		if (ok) {
			p = (char *)histp->monBuffer + sizeof (struct hdr) +
			    (histp->monBuffer->nfns * sizeof (struct cnt));
			amt = histp->histSize;

			ok = (write(fd, p, amt) == amt);

		}
	}

	(void) close(fd);

	return (ok);	/* indicate success */
}


/*
 * mnewblock()-allocate and link in a new region1&2 block.
 *
 * This routine, called by mcount_newent(), allocates a new block
 * containing only regions 1 & 2 (hdr and fcn call count array),
 * and an associated anchor (see header comments), inits the
 * header (region 1) of the block, links the anchor into the
 * list, and resets the countbase/limit pointers.
 *
 * This routine cannot be called recursively, since (each) mcount
 * has a local lock which prevents recursive calls to mcount_newent.
 * See mcount_newent for more details.
 *
 */

#define	THISMANYFCNS	(MPROGS0*2)

/*
 * call libc_malloc() to get an anchor & a regn1&2 block, together
 */
#define	GETTHISMUCH	(sizeof (ANCHOR) +	/* get an ANCHOR */  \
			(sizeof (struct hdr) +	/* get Region 1 */   \
			THISMANYFCNS * sizeof (struct cnt))) /* Region 2 */  \
						/* but No region 3 */


static void
_mnewblock(void)
{
	struct hdr *hdrp;
	ANCHOR	*newanchp;
	ANCHOR	*p;

					/* get anchor And block, together */
	p = libc_malloc(GETTHISMUCH);
	if (p == NULL) {
		perror("mcount(mnewblock)");
		return;
	}

	newanchp = p;
	hdrp = (struct hdr *)(p + 1);

					/* initialize 1st region to dflts */
	hdrp->lpc = 0;
	hdrp->hpc = 0;
	hdrp->nfns = THISMANYFCNS;

					/* link anchor+block into chain */
	newanchp->monBuffer = hdrp;		/* new, down. */
	newanchp->next  = NULL;			/* new, forward to NULL. */
	newanchp->prior = curAnchor;		/* new, backward. */
	if (curAnchor != NULL)
		curAnchor->next = newanchp;	/* old, forward to new. */
	newanchp->flags = 0;		/* note that it has NO histgm area */

					/* got it - enable use by mcount() */
	countbase  = (char *)hdrp + sizeof (struct hdr);
	countlimit = countbase + (THISMANYFCNS * sizeof (struct cnt));

	newanchp->histSize = 0;	/* (set size of region 3.. to 0) */


	curAnchor = newanchp;		/* make latest addition, cur anchor */
}

/*
 * mcount_newent() -- call to get a new mcount call count entry.
 *
 * this function is called by _mcount to get a new call count entry
 * (struct cnt, in the region allocated by monitor()), or to return
 * zero if profiling is off.
 *
 * This function acts as a funnel, an access function to make sure
 * that all instances of mcount (the one in the a.out, and any in
 * any shared objects) all get entries from the same array, and
 * all know when profiling is off.
 *
 * NOTE: when mcount calls this function, it sets a private flag
 * so that it does not call again until this function returns,
 * thus preventing recursion.
 *
 * At Worst, the mcount in either a shared object or the a.out
 * could call once, and then the mcount living in the shared object
 * with monitor could call a second time (i.e. libc.so.1, although
 * presently it does not have mcount in it).  This worst case
 * would involve Two active calls to mcount_newent, which it can
 * handle, since the second one would find a already-set value
 * in countbase.
 *
 * The only unfortunate result is that No new call counts
 * will be handed out until this function returns.
 * Thus if libc_malloc or other routines called inductively by
 * this routine have not yet been provided with a call count entry,
 * they will not get one until this function call is completed.
 * Thus a few calls to library routines during the course of
 * profiling setup, may not be counted.
 *
 * NOTE: countbase points at the next available entry, and
 * countlimit points past the last valid entry, in the current
 * function call counts array.
 *
 *
 * if profiling is off		// countbase==0
 *   just return 0
 *
 * else
 *   if need more entries	// because countbase points last valid entry
 *     link in a new block, resetting countbase and countlimit
 *   endif
 *   if Got more entries
 *     return pointer to the next available entry, and
 *     update pointer-to-next-slot before you return.
 *
 *   else			// failed to get more entries
 *     just return 0
 *
 *   endif
 * endif
 */

struct cnt *
_mcount_newent(void)
{
	if (countbase == 0)
		return (NULL);

	if (countbase >= countlimit)
		_mnewblock();		/* get a new block; set countbase */

	if (countbase != 0) {
		struct cnt *cur_countbase = (struct cnt *)(uintptr_t)countbase;

		countbase += sizeof (struct cnt);
		return (cur_countbase);
	}
	return (NULL);
}
