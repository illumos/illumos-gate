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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2016 by Delphix. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <sys/atomic.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/cmn_err.h>

#include <sys/strft.h>

int str_ftnever = 0;

static void mblk_free(mblk_t *);
static void esballoc_mblk_free(mblk_t *);

/*
 * A few things from os/strsubr.c
 */

int
strwaitbuf(size_t size, int pri)
{
	return (0);
}

/*
 * Return size of message of block type (bp->b_datap->db_type)
 */
size_t
xmsgsize(mblk_t *bp)
{
	unsigned char type;
	size_t count = 0;

	type = bp->b_datap->db_type;

	for (; bp; bp = bp->b_cont) {
		if (type != bp->b_datap->db_type)
			break;
		ASSERT(bp->b_wptr >= bp->b_rptr);
		count += bp->b_wptr - bp->b_rptr;
	}
	return (count);
}

/* ARGSUSED */
bufcall_id_t
bufcall(size_t size, uint_t pri, void (*func)(void *), void *arg)
{
	cmn_err(CE_NOTE, "bufcall() called!");
	return ("fake bufcall id");
}

/* ARGSUSED */
void
unbufcall(bufcall_id_t id)
{
}

/* ARGSUSED */
void
freebs_enqueue(mblk_t *mp, dblk_t *dbp)
{
	/*
	 * Won't bother with esb_queue_t async free here.
	 * Rather just free this mblk directly.
	 */
	esballoc_mblk_free(mp);
}

static void
esballoc_mblk_free(mblk_t *mp)
{
	mblk_t	*nextmp;

	for (; mp != NULL; mp = nextmp) {
		nextmp = mp->b_next;
		mp->b_next = NULL;
		mblk_free(mp);
	}
}

static void
mblk_free(mblk_t *mp)
{
	dblk_t *dbp = mp->b_datap;
	frtn_t *frp = dbp->db_frtnp;

	mp->b_next = NULL;
	if (dbp->db_fthdr != NULL)
		str_ftfree(dbp);

	ASSERT(dbp->db_fthdr == NULL);
	frp->free_func(frp->free_arg);
	ASSERT(dbp->db_mblk == mp);

	if (dbp->db_credp != NULL) {
		crfree(dbp->db_credp);
		dbp->db_credp = NULL;
	}
	dbp->db_cpid = -1;
	dbp->db_struioflag = 0;
	dbp->db_struioun.cksum.flags = 0;

	kmem_cache_free(dbp->db_cache, dbp);
}

/* ARGSUSED */
mblk_t *
mmd_copy(mblk_t *bp, int flags)
{
	return (NULL);
}

/*
 * A little bit from os/streamio.c
 */

static volatile uint32_t ioc_id;

int
getiocseqno(void)
{
	uint32_t i;

	i = atomic_inc_32_nv(&ioc_id);

	return ((int)i);
}
