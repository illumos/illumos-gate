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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * These routines simply provide wrappers around malloc(3C) and free(3C)
 * for now.  In the future we hope to provide a userland equivalent to
 * the kmem allocator, including cache allocators.
 */

#include <strings.h>
#include <stdlib.h>
#include <poll.h>

#ifdef _KMDB
#include <kmdb/kmdb_fault.h>
#endif
#include <mdb/mdb_debug.h>
#include <mdb/mdb_stdlib.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb_umem.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

#define	UMF_DEBUG			0x1

#ifdef DEBUG
int mdb_umem_flags = UMF_DEBUG;
#else
int mdb_umem_flags = 0;
#endif

struct mdb_mblk {
	void *blk_addr;			/* address of allocated block */
	size_t blk_size;		/* size of block in bytes */
	struct mdb_mblk *blk_next;	/* link to next block */
};

/*ARGSUSED*/
static void *
mdb_umem_handler(size_t nbytes, size_t align, uint_t flags)
{
#ifdef _KMDB

	/*
	 * kmdb has a fixed, dedicated VA range in which to play.  This range
	 * won't change size while the debugger is running, regardless of how
	 * long we wait.  As a result, the only sensible course of action is
	 * to fail the request.  If we're here, however, the request was made
	 * with UM_SLEEP.  The caller is thus not expecting a NULL back.  We'll
	 * have to fail the current dcmd set.
	 */
	if (mdb.m_depth > 0) {
		warn("failed to allocate %lu bytes -- recovering\n",
		    (ulong_t)nbytes);

		kmdb_print_stack();

		longjmp(mdb.m_frame->f_pcb, MDB_ERR_NOMEM);
	}

#else

	/*
	 * mdb, on the other hand, can afford to wait, as someone may actually
	 * free something.
	 */
	if (errno == EAGAIN) {
		void *ptr = NULL;
		char buf[64];

		(void) mdb_iob_snprintf(buf, sizeof (buf),
		    "[ sleeping for %lu bytes of free memory ... ]",
		    (ulong_t)nbytes);

		(void) mdb_iob_puts(mdb.m_err, buf);
		(void) mdb_iob_flush(mdb.m_err);

		do {
			(void) poll(NULL, 0, 1000);
			if (align != 0)
				ptr = memalign(align, nbytes);
			else
				ptr = malloc(nbytes);
		} while (ptr == NULL && errno == EAGAIN);

		if (ptr != NULL)
			return (ptr);

		(void) memset(buf, '\b', strlen(buf));
		(void) mdb_iob_puts(mdb.m_err, buf);
		(void) mdb_iob_flush(mdb.m_err);

		(void) memset(buf, ' ', strlen(buf));
		(void) mdb_iob_puts(mdb.m_err, buf);
		(void) mdb_iob_flush(mdb.m_err);

		(void) memset(buf, '\b', strlen(buf));
		(void) mdb_iob_puts(mdb.m_err, buf);
		(void) mdb_iob_flush(mdb.m_err);
	}
#endif

	die("failed to allocate %lu bytes -- terminating\n", (ulong_t)nbytes);

	/*NOTREACHED*/

	return (NULL);
}

static void
mdb_umem_gc_enter(void *ptr, size_t nbytes)
{
	mdb_mblk_t *blkp = mdb_alloc(sizeof (mdb_mblk_t), UM_SLEEP);

	blkp->blk_addr = ptr;
	blkp->blk_size = nbytes;
	blkp->blk_next = mdb.m_frame->f_mblks;

	mdb.m_frame->f_mblks = blkp;
}

/*
 * If we're compiled in debug mode, we use this function (gratuitously
 * stolen from kmem.c) to set uninitialized and freed regions to
 * special bit patterns.
 */
static void
mdb_umem_copy_pattern(uint32_t pattern, void *buf_arg, size_t size)
{
	/* LINTED - alignment of bufend */
	uint32_t *bufend = (uint32_t *)((char *)buf_arg + size);
	uint32_t *buf = buf_arg;

	while (buf < bufend - 3) {
		buf[3] = buf[2] = buf[1] = buf[0] = pattern;
		buf += 4;
	}

	while (buf < bufend)
		*buf++ = pattern;
}

void *
mdb_alloc_align(size_t nbytes, size_t align, uint_t flags)
{
	void *ptr;
	size_t obytes = nbytes;

	if (nbytes == 0 || nbytes > MDB_ALLOC_MAX)
		return (NULL);

	nbytes = (nbytes + sizeof (uint32_t) - 1) & ~(sizeof (uint32_t) - 1);
	if (nbytes < obytes || nbytes == 0)
		return (NULL);

	if (align != 0)
		ptr = memalign(align, nbytes);
	else
		ptr = malloc(nbytes);

	if (flags & UM_SLEEP) {
		while (ptr == NULL)
			ptr = mdb_umem_handler(nbytes, align, flags);
	}

	if (ptr != NULL && (mdb_umem_flags & UMF_DEBUG) != 0)
		mdb_umem_copy_pattern(UMEM_UNINITIALIZED_PATTERN, ptr, nbytes);

	if (flags & UM_GC)
		mdb_umem_gc_enter(ptr, nbytes);

	return (ptr);
}

void *
mdb_alloc(size_t nbytes, uint_t flags)
{
	return (mdb_alloc_align(nbytes, 0, flags));
}

void *
mdb_zalloc(size_t nbytes, uint_t flags)
{
	void *ptr = mdb_alloc(nbytes, flags);

	if (ptr != NULL)
		bzero(ptr, nbytes);

	return (ptr);
}

void
mdb_free(void *ptr, size_t nbytes)
{
	ASSERT(ptr != NULL || nbytes == 0);

	nbytes = (nbytes + sizeof (uint32_t) - 1) & ~(sizeof (uint32_t) - 1);

	if (ptr != NULL) {
		if (mdb_umem_flags & UMF_DEBUG)
			mdb_umem_copy_pattern(UMEM_FREE_PATTERN, ptr, nbytes);
		free(ptr);
	}
}

void
mdb_free_align(void *ptr, size_t nbytes)
{
	mdb_free(ptr, nbytes);
}

void
mdb_recycle(mdb_mblk_t **blkpp)
{
	mdb_mblk_t *blkp, *nblkp;

	for (blkp = *blkpp; blkp != NULL; blkp = nblkp) {
		mdb_dprintf(MDB_DBG_UMEM,
		    "garbage collect %p size %lu bytes\n", blkp->blk_addr,
		    (ulong_t)blkp->blk_size);

		nblkp = blkp->blk_next;
		mdb_free(blkp->blk_addr, blkp->blk_size);
		mdb_free(blkp, sizeof (mdb_mblk_t));
	}

	*blkpp = NULL;
}
