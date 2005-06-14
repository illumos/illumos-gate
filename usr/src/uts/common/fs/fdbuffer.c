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
 * Copyright (c) 1998,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/ddi.h>

#include <sys/fdbuffer.h>

#ifdef DEBUG
static int fdb_debug;
#define	FDB_D_CREATE	001
#define	FDB_D_ALLOC	002
#define	FDB_D_IO	004
#define	FDB_D_ASYNC	010
#define	DEBUGF(lvl, args)	{ if ((lvl) & fdb_debug) cmn_err args; }
#else
#define	DEBUGF(level, args)
#endif
static struct kmem_cache *fdb_cache;
static void fdb_zero_holes(fdbuffer_t *fdb);

/* ARGSUSED */
static int
fdb_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
	fdbuffer_t *fdb = buf;

	mutex_init(&fdb->fd_mutex, NULL, MUTEX_DEFAULT, NULL);

	return (0);
}

/* ARGSUSED */
static void
fdb_cache_destructor(void *buf, void *cdrarg)
{
	fdbuffer_t *fdb = buf;

	mutex_destroy(&fdb->fd_mutex);
}

void
fdb_init()
{
	fdb_cache = kmem_cache_create("fdb_cache", sizeof (fdbuffer_t),
	    0, fdb_cache_constructor, fdb_cache_destructor,
	    NULL, NULL, NULL, 0);
}

static void
fdb_prepare(fdbuffer_t *fdb)
{
	fdb->fd_holes = NULL;
	fdb->fd_iofunc = NULL;
	fdb->fd_iargp = NULL;
	fdb->fd_parentbp = NULL;
	fdb->fd_resid = 0;
	fdb->fd_iocount = 0;
	fdb->fd_iodispatch = 0;
	fdb->fd_err = 0;
}

fdbuffer_t *
fdb_page_create(page_t *pp, size_t len, int flags)
{
	fdbuffer_t *fdb;

	DEBUGF(FDB_D_CREATE, (CE_NOTE,
	    "?fdb_page_create: pp: %p len: %lux flags: %x",
	    (void *)pp, len, flags));

	ASSERT(flags & (FDB_READ|FDB_WRITE));

	fdb = kmem_cache_alloc(fdb_cache, KM_SLEEP);

	fdb_prepare(fdb);

	fdb->fd_type = FDB_PAGEIO;
	fdb->fd_len = len;
	fdb->fd_state = flags;
	fdb->fd_pages = pp;

	return (fdb);
}

fdbuffer_t *
fdb_addr_create(
	caddr_t addr,
	size_t len,
	int flags,
	page_t **pplist,
	struct proc *procp)
{
	fdbuffer_t *fdb;

	DEBUGF(FDB_D_CREATE, (CE_NOTE,
	    "?fdb_addr_create: addr: %p len: %lux flags: %x",
	    (void *)addr, len, flags));

	ASSERT(flags & (FDB_READ|FDB_WRITE));

	fdb = kmem_cache_alloc(fdb_cache, KM_SLEEP);

	fdb_prepare(fdb);

	fdb->fd_type = FDB_VADDR;
	fdb->fd_len = len;
	fdb->fd_state = flags;
	fdb->fd_addr = addr;
	fdb->fd_shadow = pplist;
	fdb->fd_procp = procp;

	return (fdb);
}

void
fdb_set_iofunc(fdbuffer_t *fdb, fdb_iodone_t iofunc, void *ioargp, int flag)
{
	ASSERT(fdb);
	ASSERT(iofunc);
	ASSERT((flag & ~FDB_ICALLBACK) == 0);

	fdb->fd_iofunc = iofunc;
	fdb->fd_iargp = ioargp;

	mutex_enter(&fdb->fd_mutex);

	if (flag & FDB_ICALLBACK)
		fdb->fd_state |= FDB_ICALLBACK;

	fdb->fd_state |= FDB_ASYNC;

	mutex_exit(&fdb->fd_mutex);
}

int
fdb_get_error(fdbuffer_t *fdb)
{
	return (fdb->fd_err);
}

void
fdb_free(fdbuffer_t *fdb)
{
	fdb_holes_t *fdh, *fdhp;

	DEBUGF(FDB_D_CREATE, (CE_NOTE, "?fdb_free: addr: %p flags: %x",
	    (void *)fdb, fdb->fd_state));

	ASSERT(fdb);
	ASSERT(fdb->fd_iodispatch == 0);

	if (fdb->fd_state & FDB_ZEROHOLE) {
		fdb_zero_holes(fdb);
	}

	for (fdh = fdb->fd_holes; fdh; ) {
		fdhp = fdh;
		fdh = fdh->next_hole;
		kmem_free(fdhp, sizeof (fdb_holes_t));
	}

	if (fdb->fd_parentbp != NULL) {
		switch (fdb->fd_type) {
		case FDB_PAGEIO:
			pageio_done(fdb->fd_parentbp);
			break;
		case FDB_VADDR:
			kmem_free(fdb->fd_parentbp, sizeof (struct buf));
			break;
		default:
			cmn_err(CE_CONT, "?fdb_free: Unknown fdb type.");
			break;
		}
	}

	kmem_cache_free(fdb_cache, fdb);

}

/*
 * The offset should be from the begining of the buffer
 * it has nothing to do with file offset. This fact should be
 * reflected in the caller of this routine.
 */

void
fdb_add_hole(fdbuffer_t *fdb, u_offset_t off, size_t len)
{
	fdb_holes_t *this_hole;

	ASSERT(fdb);
	ASSERT(off < fdb->fd_len);

	DEBUGF(FDB_D_IO, (CE_NOTE, "?fdb_add_hole: off %llx len %lx",
	    off, len));

	this_hole = kmem_alloc(sizeof (fdb_holes_t), KM_SLEEP);
	this_hole->off = off;
	this_hole->len = len;

	if (fdb->fd_holes == NULL || off < fdb->fd_holes->off) {
		this_hole->next_hole = fdb->fd_holes;
		fdb->fd_holes = this_hole;
	} else {
		fdb_holes_t *fdhp = fdb->fd_holes;

		while (fdhp->next_hole && off > fdhp->next_hole->off)
			fdhp = fdhp->next_hole;

		this_hole->next_hole = fdhp->next_hole;
		fdhp->next_hole = this_hole;
	}

	mutex_enter(&fdb->fd_mutex);

	fdb->fd_iocount += len;

	mutex_exit(&fdb->fd_mutex);
}

fdb_holes_t *
fdb_get_holes(fdbuffer_t *fdb)
{
	ASSERT(fdb);

	if (fdb->fd_state & FDB_ZEROHOLE) {
		fdb_zero_holes(fdb);
	}

	return (fdb->fd_holes);
}

/*
 * Note that offsets refer to offsets from the begining of the buffer
 * and as such the memory should be cleared accordingly.
 */

static void
fdb_zero_holes(fdbuffer_t *fdb)
{
	fdb_holes_t *fdh = fdb->fd_holes;
	page_t *pp;

	ASSERT(fdb);

	if (!fdh)
		return;

	switch (fdb->fd_type) {
	case FDB_PAGEIO:
		pp = fdb->fd_pages;
		while (fdh) {
			fdb_holes_t *pfdh = fdh;
			size_t l = fdh->len;
			u_offset_t o = fdh->off;
			ASSERT(pp);

			do {
				int  zerolen;
				ASSERT(o >= pp->p_offset);

				/*
				 * This offset is wrong since
				 * the offset passed from the pages
				 * perspective starts at some virtual
				 * address but the hole is relative
				 * to the beginning of the fdbuffer.
				 */
				if (o >= pp->p_offset + PAGESIZE)
					continue;

				zerolen = min(PAGESIZE, l);

				ASSERT(zerolen > 0);
				ASSERT(zerolen <= PAGESIZE);

				pagezero(pp, ((uintptr_t)o & PAGEOFFSET),
				    zerolen);

				l -= zerolen;
				o += zerolen;

				if (l == 0)
					break;

			} while (pp = page_list_next(pp));

			if (!pp)
				break;

			fdh = fdh->next_hole;
			kmem_free(pfdh, sizeof (fdb_holes_t));
		}
		break;
	case FDB_VADDR:
		while (fdh) {
			fdb_holes_t *pfdh = fdh;

			bzero(fdb->fd_addr + fdh->off, fdh->len);

			fdh = fdh->next_hole;
			kmem_free(pfdh, sizeof (fdb_holes_t));
		}
	default:
		panic("fdb_zero_holes: Unknown fdb type.");
		break;
	}
}


buf_t *
fdb_iosetup(fdbuffer_t *fdb, u_offset_t off, size_t len, struct vnode *vp,
    int b_flags)
{
	buf_t *bp;

	DEBUGF(FDB_D_IO, (CE_NOTE,
	    "?fdb_iosetup: off: %llx len: %lux fdb: len: %lux flags: %x",
	    off, len, fdb->fd_len, fdb->fd_state));

	ASSERT(fdb);

	mutex_enter(&fdb->fd_mutex);

	ASSERT(((b_flags & B_READ) && (fdb->fd_state & FDB_READ)) ||
	    ((b_flags & B_WRITE) && (fdb->fd_state & FDB_WRITE)));
	/*
	 * The fdb can be used either in sync or async mode, if the
	 * buffer has not been used it may be used in either mode, but
	 * once you have started to use the buf in either mode all
	 * subsequent i/o requests must take place the same way.
	 */

	ASSERT(((b_flags & B_ASYNC) &&
	    ((fdb->fd_state & FDB_ASYNC) || !(fdb->fd_state & FDB_SYNC))) ||
	    (!(b_flags & B_ASYNC) &&
	    ((fdb->fd_state & FDB_SYNC) || !(fdb->fd_state & FDB_ASYNC))));


	fdb->fd_state |= b_flags & B_ASYNC ? FDB_ASYNC : FDB_SYNC;

	fdb->fd_iodispatch++;

	ASSERT((fdb->fd_state & FDB_ASYNC && fdb->fd_iofunc != NULL) ||
	    fdb->fd_state & FDB_SYNC);

	mutex_exit(&fdb->fd_mutex);

	ASSERT((len & (DEV_BSIZE - 1)) == 0);
	ASSERT(off+len <= fdb->fd_len);

	switch (fdb->fd_type) {
	case FDB_PAGEIO:
		if (fdb->fd_parentbp == NULL) {
			bp = pageio_setup(fdb->fd_pages, len, vp, b_flags);
			fdb->fd_parentbp = bp;
		}
		break;
	case FDB_VADDR:
		if (fdb->fd_parentbp == NULL) {

			bp = kmem_alloc(sizeof (buf_t), KM_SLEEP);
			bioinit(bp);
			bp->b_error = 0;
			bp->b_proc = fdb->fd_procp;
			bp->b_flags = b_flags | B_BUSY | B_PHYS;
			bp->b_bcount = len;
			bp->b_un.b_addr = fdb->fd_addr;
			bp->b_shadow = fdb->fd_shadow;
			if (fdb->fd_shadow != NULL)
				bp->b_flags |= B_SHADOW;
			fdb->fd_parentbp = bp;
		}
		break;
	default:
		panic("fdb_iosetup: Unsupported fdb type.");
		break;
	};

	bp = bioclone(fdb->fd_parentbp, off, len, 0, 0,
	    (b_flags & B_ASYNC) ? (int (*)())fdb_iodone : NULL,
	    NULL, KM_SLEEP);

	bp->b_forw = (struct buf *)fdb;

	if (b_flags & B_ASYNC)
		bp->b_flags |= B_ASYNC;

	return (bp);
}

size_t
fdb_get_iolen(fdbuffer_t *fdb)
{
	ASSERT(fdb);
	ASSERT(fdb->fd_iodispatch == 0);

	return (fdb->fd_iocount - fdb->fd_resid);
}

void
fdb_ioerrdone(fdbuffer_t *fdb, int error)
{
	ASSERT(fdb);
	ASSERT(fdb->fd_state & FDB_ASYNC);

	DEBUGF(FDB_D_IO, (CE_NOTE,
	    "?fdb_ioerrdone: fdb: len: %lux flags: %x error: %d",
	    fdb->fd_len, fdb->fd_state, error));

	mutex_enter(&fdb->fd_mutex);

	fdb->fd_err = error;

	if (error)
		fdb->fd_state |= FDB_ERROR;
	else
		fdb->fd_state |= FDB_DONE;

	/*
	 * If there is outstanding i/o return wainting for i/o's to complete.
	 */
	if (fdb->fd_iodispatch > 0) {
		mutex_exit(&fdb->fd_mutex);
		return;
	}

	mutex_exit(&fdb->fd_mutex);
	fdb->fd_iofunc(fdb, fdb->fd_iargp, NULL);
}

void
fdb_iodone(buf_t *bp)
{
	fdbuffer_t *fdb = (fdbuffer_t *)bp->b_forw;
	int	error, isasync;
	int	icallback;

	ASSERT(fdb);

	DEBUGF(FDB_D_IO, (CE_NOTE,
	    "?fdb_iodone: fdb: len: %lux flags: %x error: %d",
	    fdb->fd_len, fdb->fd_state, geterror(bp)));

	if (bp->b_flags & B_REMAPPED)
		bp_mapout(bp);

	mutex_enter(&fdb->fd_mutex);

	icallback = fdb->fd_state & FDB_ICALLBACK;
	isasync = fdb->fd_state & FDB_ASYNC;

	ASSERT(fdb->fd_iodispatch > 0);
	fdb->fd_iodispatch--;

	if (error = geterror(bp)) {
		fdb->fd_err = error;
		if (bp->b_resid)
			fdb->fd_resid += bp->b_resid;
		else
			fdb->fd_resid += bp->b_bcount;
	}

	fdb->fd_iocount += bp->b_bcount;

	/*
	 * ioack collects the total amount of i/o accounted for
	 * this includes:
	 *
	 *	- i/o completed
	 *	- i/o attempted but not completed,
	 *	- i/o not done due to holes.
	 *
	 * Once the entire i/o ranges has been accounted for we'll
	 * call the async function associated with the fdb.
	 *
	 */

	if ((fdb->fd_iodispatch == 0) &&
	    (fdb->fd_state & (FDB_ERROR|FDB_DONE))) {

		mutex_exit(&fdb->fd_mutex);

		if (isasync || icallback) {
			fdb->fd_iofunc(fdb, fdb->fd_iargp, bp);
		}

	} else {

		mutex_exit(&fdb->fd_mutex);

		if (icallback) {
			fdb->fd_iofunc(fdb, fdb->fd_iargp, bp);
		}
	}

	freerbuf(bp);
}
