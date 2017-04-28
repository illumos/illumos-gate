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
/*
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/open.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/ddi.h>

#include <sys/nsc_thread.h>
#include <sys/nsctl/nsctl.h>

#include <sys/sdt.h>		/* dtrace is S10 or later */

#include <vm/seg_kmem.h>
#include "sd_bcache.h"
#include "sd_trace.h"
#include "sd_io.h"
#include "sd_iob.h"
#include "sd_misc.h"
#if defined(_SD_DEBUG)			/* simulate disk errors */
#include "sd_tdaemon.h"
#endif

#ifndef DS_DDICT
extern uintptr_t kobj_getsymvalue(char *, int);	/* DDI violation */
#endif

#define	DO_PAGE_LIST	sdbc_do_page	/* enable pagelist code */

int sdbc_do_page = 0;

#define	SGIO_MAX 254

static kmutex_t sdbc_bio_mutex;
static int sdbc_bio_count;

static unsigned long page_size, page_offset_mask;

#ifdef _SD_BIO_STATS
static __start_io_count = 0;
#endif /* _SD_BIO_STATS */

/*
 * Forward declare all statics that are used before defined to enforce
 * parameter checking.  Also forward-declare all functions that have 64-bit
 * argument types to enforce correct parameter checking.
 *
 * Some (if not all) of these could be removed if the code were reordered
 */

static int _sd_sync_ea(struct buf *, iob_hook_t *);
static int _sd_async_ea(struct buf *, iob_hook_t *);
static void _sd_pack_pages(struct buf *bp, struct buf *list, sd_addr_t *addr,
    nsc_off_t offset, nsc_size_t size);
static void _sd_pack_pages_nopageio(struct buf *bp, struct buf *list,
    sd_addr_t *addr, nsc_off_t offset, nsc_size_t size);
static void _sd_setup_iob(struct buf *bp, dev_t dev, nsc_off_t pos, int flag);

#ifdef	DEBUG
static int _sdbc_ioj_lookup(dev_t);
static void _sdbc_ioj_clear_err(int);
#endif

static int SD_WRITES_TOT = 0;
static int SD_WRITES_LEN[100];

_sd_buf_list_t _sd_buflist;

/*
 * _sd_add_vm_to_bp_plist - add the page corresponding to the
 * virtual address "v" (kernel virtaddr) to the pagelist linked
 * to buffer "bp".
 *
 * The virtual address "v" is "known" to be allocated by segkmem
 * and we can look up the page by using the segkmem vnode kvp.
 * This violates the ddi/ddk but is workable for now anyway.
 *
 *
 */
static void
_sd_add_vm_to_bp_plist(struct buf *bp, unsigned char *v)
{
	page_t   *pp;
	page_t   *one_pg = NULL;

	pp = page_find(&kvp, (u_offset_t)((uintptr_t)v & ~page_offset_mask));
	if (!pp) {
		cmn_err(CE_PANIC,
		    "_sd_add_vm_to_bp_plist: couldn't find page for 0x%p",
		    (void *)v);
	}

	page_add(&one_pg, pp);
	page_list_concat(&(bp->b_pages), &one_pg);

}

#ifdef _SD_BIO_STATS
static int
_sd_count_pages(page_t *pp)
{
	int cnt = 0;
	page_t *pp1;
	if (pp == NULL)
		return (cnt);

	for (cnt = 1, pp1 = pp->p_next; pp != pp1; cnt++, pp1 = pp1->p_next)
		;

	return (cnt);
}
#endif /* _SD_BIO_STATS */


/*
 * _sdbc_iobuf_load - load time initialization of io bufs structures.
 *
 *
 * RETURNS:
 *	0  - success.
 *      -1 - failure.
 *
 * USAGE:
 *	This routine initializes load time buf structures.
 *      Should be called when the cache is loaded.
 */

int
_sdbc_iobuf_load(void)
{
	mutex_init(&sdbc_bio_mutex, NULL, MUTEX_DRIVER, NULL);

	/*
	 * HACK add a ref to kvp, to prevent VN_RELE on it from panicing
	 * the system
	 */
	VN_HOLD(&kvp);

	return (0);
}

/*
 * _sdbc_iobuf_unload - unload time cleanup of io buf structures.
 *
 *
 * USAGE:
 *	This routine removes load time buf structures.
 *      Should be called when the cache is unloaded.
 */
void
_sdbc_iobuf_unload(void)
{
	mutex_enter(&kvp.v_lock);
	ASSERT(kvp.v_count == 1);
	VN_RELE_LOCKED(&kvp);
	mutex_exit(&kvp.v_lock);

	mutex_destroy(&sdbc_bio_mutex);
	bzero(&_sd_buflist, sizeof (_sd_buf_list_t));
}

/*
 * _sdbc_iobuf_configure - configure a list of io bufs for later use.
 *
 * ARGUMENTS:
 *	num_bufs - number of buffers. (from the configuration file)
 *
 * RETURNS:
 *	0  - success.
 * <0  - failure.
 *
 * USAGE:
 *	This routine configures the buf structures for io.
 *      Should be called when the cache is configured.
 */

int
_sdbc_iobuf_configure(int num)
{
	int i;
	_sd_buf_list_t *buflist;
	iob_hook_t *hook;
	char symbol_name[32];

	if (!num || (num > _SD_DEFAULT_IOBUFS))
		num = _SD_DEFAULT_IOBUFS;

	if ((_sd_buflist.hooks = (iob_hook_t *)nsc_kmem_zalloc(
	    num * sizeof (iob_hook_t), KM_SLEEP, sdbc_iobuf_mem)) == NULL) {
		return (-1);
	}

	buflist = &_sd_buflist;
	buflist->bl_init_count = num;
	buflist->bl_hooks_avail = num;
	buflist->bl_hook_lowmark = num;
	hook = buflist->hooks;
	buflist->hook_head = hook;
	for (i = 0; i < num; i++, hook++) {
		cv_init(&hook->wait, NULL, CV_DRIVER, NULL);
		(void) sprintf(symbol_name, "sd_iob_dcb%d", i);
		hook->iob_drv_iodone = (dcb_t)kobj_getsymvalue(symbol_name, 0);
		if (!hook->iob_drv_iodone) {
			return (-2);
		}
		hook->next_hook = hook+1;
	}
	(hook-1)->next_hook = NULL;

	for (i = 0; i < MAX_HOOK_LOCKS; i++)
		mutex_init(&_sd_buflist.hook_locks[i], NULL, MUTEX_DRIVER,
		    NULL);

	cv_init(&_sd_buflist.hook_wait, NULL, CV_DRIVER, NULL);
	_sd_buflist.hook_waiters = 0;

	sdbc_bio_count = 0;
	SD_WRITES_TOT = 0;
	bzero(SD_WRITES_LEN, sizeof (SD_WRITES_LEN));

	/* pagelist i/o pages must be done in cache_init */

	page_size = ptob(1);
	page_offset_mask = page_size - 1;

	return (0);
}

/*
 * _sdbc_iobuf_deconfigure - release all memory allocated for buf list
 *
 * ARGUMENTS:
 *	None.
 *
 * RETURNS:
 *	0
 */
void
_sdbc_iobuf_deconfigure(void)
{
	ushort_t i;

	if (_sd_buflist.hooks) {
		for (i = 0; i < _sd_buflist.bl_init_count; i ++) {
			cv_destroy(&_sd_buflist.hooks[i].wait);
		}
		cv_destroy(&_sd_buflist.hook_wait);
		nsc_kmem_free(_sd_buflist.hooks,
		    _sd_buflist.bl_init_count * sizeof (iob_hook_t));
		for (i = 0; i < MAX_HOOK_LOCKS; i ++) {
			mutex_destroy(&_sd_buflist.hook_locks[i]);
		}
	}

	_sd_buflist.hooks = NULL;

#ifdef DEBUG
	{
	void _sdbc_ioj_clear_err(int);
	_sdbc_ioj_clear_err(-1); /* clear any injected i/o errors */
	_sdbc_ioj_set_dev(-1, 0); /* clear dev entries */
	}
#endif

}

/*
 * _sd_pending_iobuf()
 *
 * Return the number of I/O bufs outstanding
 */
int
_sd_pending_iobuf(void)
{
	return (sdbc_bio_count);
}

/*
 * _sd_get_iobuf - allocate a buf.
 *
 * ARGUMENTS:
 *	None.
 *
 * RETURNS:
 *	NULL - failure.
 *      buf ptr otherwise.
 *
 * ASSUMPTIONS - process could block if we run out.
 *
 */
/*ARGSUSED*/
static struct buf *
_sd_get_iobuf(int num_bdl)
{
	struct buf *bp;

	/* Get a buffer, ready for page list i/o */

	if (DO_PAGE_LIST)
		bp = pageio_setup(NULL, 0, &kvp, 0);
	else
		bp = getrbuf(KM_SLEEP);

	if (bp == NULL)
		return (NULL);
	mutex_enter(&sdbc_bio_mutex);
	sdbc_bio_count++;
	mutex_exit(&sdbc_bio_mutex);
	return (bp);
}

/*
 * _sd_put_iobuf - put a buf back in the freelist.
 *
 * ARGUMENTS:
 *	bp - buf pointer.
 *
 * RETURNS:
 *	0
 *
 */
static void
_sd_put_iobuf(struct buf *bp)
{
	mutex_enter(&sdbc_bio_mutex);
	sdbc_bio_count--;
	mutex_exit(&sdbc_bio_mutex);
	if (DO_PAGE_LIST)
		pageio_done(bp);
	else
		freerbuf(bp);
}


/* use for ORing only */
#define	B_KERNBUF 0

static void
_sd_setup_iob(struct buf *bp, dev_t dev, nsc_off_t pos, int flag)
{
	bp->b_pages = NULL;
	bp->b_un.b_addr = 0;

	flag &= (B_READ | B_WRITE);

	/*
	 * if pagelist i/o, _sd_get_iobuf()/pageio_setup() has already
	 * set b_flags to
	 * B_KERNBUF | B_PAGEIO | B_NOCACHE | B_BUSY (sol 6,7,8)
	 * or
	 * B_PAGEIO | B_NOCACHE | B_BUSY (sol 9)
	 */

	bp->b_flags |= B_KERNBUF | B_BUSY | flag;

	bp->b_error = 0;

	bp->b_forw = NULL;
	bp->b_back = NULL;

	bp->b_lblkno = (diskaddr_t)pos;
	bp->b_bufsize = 0;
	bp->b_resid = 0;
	bp->b_proc = NULL;
	bp->b_edev = dev;
}


/*
 * _sd_get_hook - get an iob hook from the free list.
 *
 * ARGUMENTS:
 *	none
 *
 * RETURNS:
 *	the newly allocated iob_hook.
 *
 */
static iob_hook_t *
_sd_get_hook(void)
{

	iob_hook_t *ret;

	mutex_enter(&sdbc_bio_mutex);

retry:
	ret = _sd_buflist.hook_head;
	if (ret)
		_sd_buflist.hook_head = ret->next_hook;
	else {
		++_sd_buflist.hook_waiters;
		if (_sd_buflist.max_hook_waiters < _sd_buflist.hook_waiters)
			_sd_buflist.max_hook_waiters = _sd_buflist.hook_waiters;
		cv_wait(&_sd_buflist.hook_wait, &sdbc_bio_mutex);
		--_sd_buflist.hook_waiters;
		goto retry;
	}

	if (_sd_buflist.bl_hook_lowmark > --_sd_buflist.bl_hooks_avail)
		_sd_buflist.bl_hook_lowmark = _sd_buflist.bl_hooks_avail;

	mutex_exit(&sdbc_bio_mutex);
	ret->skipped = 0;

	ret->count = 0;

#ifdef _SD_BIO_STATS
	ret->PAGE_IO = 0;
	ret->NORM_IO = 0;
	ret->NORM_IO_SIZE = 0;
	ret->SKIP_IO = 0;
	ret->PAGE_COMBINED = 0;
#endif /* _SD_BIO_STATS */

	return (ret);
}

/*
 * _sd_put_hook - put an iob hook back on the free list.
 *
 * ARGUMENTS:
 *	hook - an iob_hook to be returned to the freelist.
 *
 *
 */
static void
_sd_put_hook(iob_hook_t *hook)
{

	mutex_enter(&sdbc_bio_mutex);

	if (_sd_buflist.hook_waiters) {
		cv_signal(&_sd_buflist.hook_wait);
	}
	hook->next_hook = _sd_buflist.hook_head;
	_sd_buflist.hook_head = hook;

	++_sd_buflist.bl_hooks_avail;

	mutex_exit(&sdbc_bio_mutex);
}

/*
 * _sd_extend_iob - the i/o block we are handling needs a new struct buf to
 *    describe the next hunk of i/o. Get a new struct buf initialize it based
 *    on the state in the struct buf we are passed as an arg.
 * ARGUMENTS:
 *    head_bp - a buffer header in the current i/o block we are handling.
 *              (generally the initial header but in fact could be any
 *               of the ones [if any] that were chained to the initial
 *		 one).
 */
static struct buf *
_sd_extend_iob(struct buf *head_bp)
{
	struct buf *bp;
	iob_hook_t *hook = (iob_hook_t *)head_bp->b_private;


	if (!(bp = _sd_get_iobuf(0)))
		return (0);

	bp->b_pages = NULL;
	bp->b_un.b_addr = 0;

	bp->b_flags |=  (head_bp->b_flags & (B_READ | B_WRITE));

	if (!DO_PAGE_LIST)
		bp->b_flags |= B_KERNBUF | B_BUSY;

	bp->b_error = 0;

	/*
	 *  b_forw/b_back  will form a doubly linked list of all the buffers
	 *  associated with this block of i/o.
	 *  hook->tail points to the last buffer in the chain.
	 */
	bp->b_forw = NULL;
	bp->b_back = hook->tail;
	hook->tail->b_forw = bp;
	hook->tail = bp;
	hook->count++;

	ASSERT(BLK_FBA_OFF(hook->size) == 0);

	bp->b_lblkno = (diskaddr_t)hook->start_fba +
	    (diskaddr_t)FBA_NUM(hook->size);

	bp->b_bufsize = 0;
	bp->b_resid = 0;
	bp->b_proc = NULL;
	bp->b_edev = head_bp->b_edev;

	bp->b_iodone = NULL; /* for now */
	bp->b_private = hook;

	return (bp);
}

/*
 * sd_alloc_iob - start processing a block of i/o. This allocates an initial
 *	buffer header for describing the i/o and a iob_hook for collecting
 *	information about all the i/o requests added to this buffer.
 *
 * ARGUMENTS:
 *      dev - the device all the i/o is destined for.
 *	fba_pos - the initial disk block to read.
 *	blks - ignored
 *	flag - signal whether this is a read or write request.
 *
 * RETURNS:
 *	pointer to free struct buf which will be used to describe i/o request.
 */
/* ARGSUSED */
struct buf *
sd_alloc_iob(dev_t dev, nsc_off_t fba_pos, int blks, int flag)
{
	struct buf *bp;
	iob_hook_t *hook;

	if (!(bp = _sd_get_iobuf(0)))
		return (0);

	_sd_setup_iob(bp, dev, fba_pos, flag);

	bp->b_iodone = NULL; /* for now */
	hook = _sd_get_hook();
	if (!hook) {
		/* can't see how this could happen */
		_sd_put_iobuf(bp);
		return (0);
	}

	/*
	 *  pick an arbitrary lock
	 */
	hook->lockp = &_sd_buflist.hook_locks[((long)hook >> 9) &
	    (MAX_HOOK_LOCKS - 1)];
	hook->start_fba = fba_pos;
	hook->last_fba = fba_pos;
	hook->size = 0;
	hook->tail = bp;
	hook->chain = bp;
	hook->count = 1;
	hook->error = 0;
	bp->b_private = hook;

	return (bp);
}

/*
 * _sd_pack_pages - produce i/o requests that will perform the type of i/o
 *      described by bp (READ/WRITE). It attempt to tack the i/o onto the
 *      buf pointer to by list to minimize the number of bufs required.
 *
 * ARGUMENTS:
 *  bp - is the i/o description i.e. head
 *  list - is where to start adding this i/o request (null if we should extend)
 *  addr - address describing where the data is.
 *  offset - offset from addr where data begins
 *  size - size of the i/o request.
 */
static void
_sd_pack_pages(struct buf *bp, struct buf *list, sd_addr_t *addr,
    nsc_off_t offset, nsc_size_t size)
{
	uintptr_t start_addr, end_addr;
	int page_end_aligned;
#ifdef _SD_BIO_STATS
	iob_hook_t *hook = (iob_hook_t *)bp->b_private;
	struct buf *orig_list = list;
#endif /* _SD_BIO_STATS */

	start_addr = (uintptr_t)addr->sa_virt + offset;
	end_addr = start_addr + size;

	page_end_aligned = !(end_addr & page_offset_mask);

	if (!list && !(list = _sd_extend_iob(bp))) {
		/*
		 *  we're hosed since we have no error return...
		 *  though we could ignore stuff from here on out
		 *  and return ENOMEM when we get to sd_start_io.
		 *  This will do for now.
		 */
		cmn_err(CE_PANIC, "_sd_pack_pages: couldn't extend iob");
	}

	/*
	 *	We only want to do pagelist i/o if we end on a page boundary.
	 *	If we don't end on a page boundary we won't combine with the
	 *	next request and so we may as well do it as normal as it
	 *	will only use one buffer.
	 */

	if (DO_PAGE_LIST && page_end_aligned) {
		if (start_addr & page_offset_mask) {
			/*
			 * handle the partial page
			 */
			if (list->b_bufsize) {
				if (!(list = _sd_extend_iob(bp))) {
					/*
					 * we're hosed since we have no error
					 * return though we could ignore stuff
					 * from here on out and return ENOMEM
					 * when we get to sd_start_io.
					 *  This will do for now.
					 */
					cmn_err(CE_PANIC,
					"_sd_pack_pages: couldn't extend iob");
				}
			}
#ifdef _SD_BIO_STATS
			hook->PAGE_IO++;
#endif /* _SD_BIO_STATS */
			_sd_add_vm_to_bp_plist(list,
			    (unsigned char *) start_addr);
			list->b_bufsize = page_size -
			    (start_addr & page_offset_mask);
			list->b_un.b_addr = (caddr_t)
			    (start_addr & page_offset_mask);
			size -= list->b_bufsize;
			start_addr += list->b_bufsize;
		}
		/*
		 *	Now fill with all the full pages remaining.
		 */
		for (; size > 0; size -= page_size) {
#ifdef _SD_BIO_STATS
			hook->PAGE_IO++;
#endif /* _SD_BIO_STATS */

			_sd_add_vm_to_bp_plist(list,
			    (unsigned char *) start_addr);
			start_addr += page_size;
			list->b_bufsize += page_size;
#ifdef _SD_BIO_STATS
			if (list == orig_list)
				hook->PAGE_COMBINED++;
#endif /* _SD_BIO_STATS */
		}
		if (size)
			cmn_err(CE_PANIC, "_sd_pack_pages: bad size: %"
			    NSC_SZFMT, size);
	} else {
		/*
		 *  Wasn't worth it as pagelist i/o, do as normal
		 */
		if (list->b_bufsize && !(list = _sd_extend_iob(bp))) {
			/*
			 *  we're hosed since we have no error return...
			 *  though we could ignore stuff from here on out
			 *  and return ENOMEM when we get to sd_start_io.
			 *  This will do for now.
			 */
			cmn_err(CE_PANIC,
			    "_sd_pack_pages: couldn't extend iob");
		}

		/* kernel virtual */
		list->b_flags &= ~(B_PHYS | B_PAGEIO);
		list->b_un.b_addr = (caddr_t)start_addr;
#ifdef _SD_BIO_STATS
		hook->NORM_IO++;
		hook->NORM_IO_SIZE += size;
#endif /* _SD_BIO_STATS */
		list->b_bufsize = (size_t)size;
	}

}

/*
 * perform same function as _sd_pack_pages() when not doing pageio
 */
static void
_sd_pack_pages_nopageio(struct buf *bp, struct buf *list, sd_addr_t *addr,
    nsc_off_t offset, nsc_size_t size)
{
	uintptr_t start_addr;
#ifdef _SD_BIO_STATS
	iob_hook_t *hook = (iob_hook_t *)bp->b_private;
	struct buf *orig_list = list;
#endif /* _SD_BIO_STATS */

	start_addr = (uintptr_t)addr->sa_virt + offset;

	if (!list && !(list = _sd_extend_iob(bp))) {
		/*
		 *  we're hosed since we have no error return...
		 *  though we could ignore stuff from here on out
		 *  and return ENOMEM when we get to sd_start_io.
		 *  This will do for now.
		 */
		cmn_err(CE_PANIC, "_sd_pack_pages_nopageio: couldn't "
		    "extend iob");
	}

	if (list->b_bufsize &&
	    (start_addr == (uintptr_t)(list->b_un.b_addr + list->b_bufsize))) {
		/* contiguous */
		list->b_bufsize += (size_t)size;
	} else {
		/*
		 * not contiguous mem (extend) or first buffer (bufsize == 0).
		 */
		if (list->b_bufsize && !(list = _sd_extend_iob(bp))) {
			/*
			 *  we're hosed since we have no error return...
			 *  though we could ignore stuff from here on out
			 *  and return ENOMEM when we get to sd_start_io.
			 *  This will do for now.
			 */
			cmn_err(CE_PANIC, "_sd_pack_pages_nopageio: couldn't "
			    "extend iob");
		}
		list->b_un.b_addr = (caddr_t)start_addr;
		list->b_bufsize = (size_t)size;
	}

#ifdef _SD_BIO_STATS
	hook->NORM_IO++;
	hook->NORM_IO_SIZE += size;
#endif /* _SD_BIO_STATS */
}

/*
 * sd_add_fba - add an i/o request to the block of i/o described by bp.
 *	We try and combine this request with the previous request. In
 *	Addition we try and do the i/o as PAGELIST_IO if it satisfies
 *	the restrictions for it. If the i/o request can't be combined
 *	we extend the i/o description with a new buffer header and add
 *	it to the chain headed by bp.
 *
 * ARGUMENTS:
 *      bp - the struct buf describing the block i/o we are collecting.
 *	addr - description of the address where the data will read/written to.
 *             A NULL indicates that this i/o request doesn't need to actually
 *             happen. Used to mark reads when the fba is already in cache and
 *             dirty.
 *
 *	fba_pos - offset from address in addr where the i/o is to start.
 *
 *	fba_len - number of consecutive fbas to transfer.
 *
 *  NOTE: It is assumed that the memory is physically contiguous but may span
 *  multiple pages (should a cache block be larger than a page).
 *
 */
void
sd_add_fba(struct buf *bp, sd_addr_t *addr, nsc_off_t fba_pos,
    nsc_size_t fba_len)
{
	nsc_off_t offset;
	nsc_size_t size;
	iob_hook_t *hook = (iob_hook_t *)bp->b_private;

	size = FBA_SIZE(fba_len);
	offset = FBA_SIZE(fba_pos);

	if (addr) {
		/*
		 *  See if this can be combined with previous request(s)
		 */
		if (!bp->b_bufsize) {
			if (DO_PAGE_LIST)
				_sd_pack_pages(bp, bp, addr, offset, size);
			else
				_sd_pack_pages_nopageio(bp, bp, addr, offset,
				    size);
		} else {
			if (DO_PAGE_LIST) {
				if (hook->tail->b_flags & B_PAGEIO) {
					/*
					 * Last buffer was a pagelist. Unless a
					 * skip was detected the last request
					 * ended on a page boundary. If this
					 * one starts on one we combine the
					 * best we can.
					 */
					if (hook->skipped)
						_sd_pack_pages(bp, NULL, addr,
						    offset, size);
					else
						_sd_pack_pages(bp, hook->tail,
						    addr, offset, size);
				} else {
					/*
					 * Last buffer was vanilla i/o or worse
					 * (sd_add_mem)
					 */
					_sd_pack_pages(bp, NULL, addr, offset,
					    size);
				}
			} else {
				if (hook->skipped)
					_sd_pack_pages_nopageio(bp, NULL,
					    addr, offset, size);
				else
					_sd_pack_pages_nopageio(bp,
					    hook->tail, addr, offset, size);
			}
		}
		hook->skipped = 0;
	} else {
		/* Must be a read of dirty block we want to discard */

		ASSERT(bp->b_flags & B_READ);
#ifdef _SD_BIO_STATS
		hook->SKIP_IO++;
#endif /* _SD_BIO_STATS */
		hook->skipped = 1;
		if (!bp->b_bufsize)
			bp->b_lblkno += fba_len;
	}
	hook->size += size;

}

/*
 * sd_add_mem - add an i/o request to the block of i/o described by bp.
 *	The memory target for this i/o may span multiple pages and may
 *	not be physically contiguous.
 *      also the len might also not be a multiple of an fba.
 *
 * ARGUMENTS:
 *      bp - the struct buf describing the block i/o we are collecting.
 *
 *	buf - target of this i/o request.
 *
 *	len - number of bytes to transfer.
 *
 */
void
sd_add_mem(struct buf *bp, char *buf, nsc_size_t len)
{
	nsc_size_t n;
	uintptr_t start;
	iob_hook_t *hook = (iob_hook_t *)bp->b_private;

	start = (uintptr_t)buf & page_offset_mask;

	for (; len > 0; buf += n, len -= n, start = 0) {
		n = min((nsc_size_t)len, (nsc_size_t)(page_size - start));
		/*
		 *  i/o size must be multiple of an FBA since we can't
		 *  count on lower level drivers to understand b_offset
		 */
		if (BLK_FBA_OFF(n) != 0) {
			cmn_err(CE_WARN,
			    "!sdbc(sd_add_mem) i/o request not FBA sized (%"
			    NSC_SZFMT ")", n);
		}

		if (!bp->b_bufsize) {
			/* first request */
			bp->b_flags &= ~(B_PHYS | B_PAGEIO);
			bp->b_un.b_addr = buf;
			bp->b_bufsize = (size_t)n;
		} else {
			struct buf *new_bp;
			if (!(new_bp = _sd_extend_iob(bp))) {
				/* we're hosed */
				cmn_err(CE_PANIC,
				"sd_add_mem: couldn't extend iob");
			}
			new_bp->b_flags &= ~(B_PHYS | B_PAGEIO);
			new_bp->b_un.b_addr = buf;
			new_bp->b_bufsize = (size_t)n;
		}
		hook->size += n;
	}
}


/*
 * sd_start_io - start all the i/o needed to satisfy the i/o request described
 *	by bp. If supplied the a non-NULL fn then this is an async request
 *	and we will return NSC_PENDING and call fn when all the i/o complete.
 *	Otherwise this is a synchronous request and we sleep until all the
 *	i/o is complete. If any buffer in the chain gets an error we return
 *	the first error we see (once all the i/o is complete).
 *
 * ARGUMENTS:
 *      bp - the struct buf describing the block i/o we are collecting.
 *
 *	strategy - strategy function to call if known by the user, or NULL.
 *
 *	fn - user's callback function. NULL implies synchronous request.
 *
 *	arg - an argument passed to user's callback function.
 *
 */
int
sd_start_io(struct buf *bp, strategy_fn_t strategy, sdbc_ea_fn_t fn,
    blind_t arg)
{
	int err;
	iob_hook_t *hook = (iob_hook_t *)bp->b_private;
	struct buf *bp_next;
	int (*ea_fn)(struct buf *, iob_hook_t *);
#ifdef _SD_BIO_STATS
	static int total_pages, total_pages_combined, total_norm;
	static int total_norm_combined, total_skipped;
	static nsc_size_t total_norm_size;

	static int total_bufs;
	static int total_xpages_w, total_ypages_w;
	static int total_xpages_r, total_ypages_r;
	static int max_run_r, max_run_w;

#endif /* _SD_BIO_STATS */

	hook->func = fn;
	hook->param = arg;
	if (fn != NULL)
		ea_fn = _sd_async_ea;
	else
		ea_fn = _sd_sync_ea;

	hook->iob_hook_iodone = ea_fn;

#ifdef _SD_BIO_STATS
	__start_io_count++;
	total_pages += hook->PAGE_IO;
	total_pages_combined += hook->PAGE_COMBINED;
	total_norm += hook->NORM_IO;
	total_norm_size += hook->NORM_IO_SIZE;
	total_skipped += hook->SKIP_IO;
#endif /* _SD_BIO_STATS */

	for (; bp; bp = bp_next) {

	DTRACE_PROBE4(sd_start_io_bufs, struct buf *, bp, long, bp->b_bufsize,
	    int, bp->b_flags, iob_hook_t *, hook);

		bp_next = bp->b_forw;
		if (!(bp->b_flags & B_READ)) {
			SD_WRITES_TOT++;
			SD_WRITES_LEN[(bp->b_bufsize/32768) %
			    (sizeof (SD_WRITES_LEN)/sizeof (int))]++;
		}
		bp->b_iodone = hook->iob_drv_iodone;
		bp->b_bcount = bp->b_bufsize;
		bp->b_forw = NULL;
		bp->b_back = NULL;
		bp->b_private = NULL;

#ifdef _SD_BIO_STATS
		total_bufs ++;
		if (bp->b_flags & B_PAGEIO) {
			int i;
			i = _sd_count_pages(bp->b_pages);
			if (bp->b_flags & B_READ) {
				if (i > max_run_r)
					max_run_r = i;
				total_xpages_r += i;
				total_ypages_r++;
			} else {
				if (i > max_run_w)
					max_run_w = i;
				total_xpages_w += i;
				total_ypages_w++;
			}
		}
#endif /* _SD_BIO_STATS */


		/*
		 *  It's possible for us to be told to read a dirty block
		 *  where all the i/o can go away (e.g. read one fba, it's
		 *  in cache and dirty) so we really have nothing to do but
		 *  say we're done.
		 */
		if (bp->b_bcount) {
			if (!strategy) {
				strategy =
				    nsc_get_strategy(getmajor(bp->b_edev));
			}

			if (!strategy) {
				bp->b_flags |= B_ERROR;
				bp->b_error = ENXIO;
				(*bp->b_iodone)(bp);
			} else
#ifdef DEBUG
			/* inject i/o error for testing */
			if (bp->b_error = _sdbc_ioj_lookup(bp->b_edev)) {
				bp->b_flags |= B_ERROR;
				(*bp->b_iodone)(bp);
			} else
#endif
			{
				(*strategy)(bp);
			}
		} else {
			(*bp->b_iodone)(bp);
		}

	}

#ifdef _SD_BIO_STATS
	if (__start_io_count == 2000) {
		__start_io_count = 0;
		cmn_err(CE_WARN,
		    "!sdbc(sd_start_io) t_bufs %d pages %d "
		    "combined %d norm %d norm_size %" NSC_SZFMT " skipped %d",
		    total_bufs,
		    total_pages, total_pages_combined, total_norm,
		    total_norm_size, total_skipped);

		total_bufs = 0;
		total_pages = 0;
		total_pages_combined = 0;
		total_norm = 0;
		total_norm_combined = 0;
		total_skipped = 0;
		total_norm_size = 0;

		cmn_err(CE_WARN,
		    "!sdbc(sd_start_io)(r) max_run %d, total_xp %d total yp %d",
		    max_run_r, total_xpages_r, total_ypages_r);

		total_xpages_r = 0;
		total_ypages_r = 0;
		max_run_r = 0;

		cmn_err(CE_WARN,
		    "!sdbc(sd_start_io)(w) max_run %d, total_xp %d total yp %d",
		    max_run_w, total_xpages_w, total_ypages_w);

		total_xpages_w = 0;
		total_ypages_w = 0;
		max_run_w = 0;
	}
#endif /* _SD_BIO_STATS */

	if (ea_fn == _sd_async_ea) {
		DTRACE_PROBE(sd_start_io_end);

		return (NSC_PENDING);
	}

	mutex_enter(hook->lockp);

	while (hook->count) {
		cv_wait(&hook->wait, hook->lockp);
	}
	mutex_exit(hook->lockp);

	err = hook->error ? hook->error : NSC_DONE;
	bp = hook->tail;
	_sd_put_hook(hook);
	_sd_put_iobuf(bp);

	return (err);
}

/*
 * _sd_sync_ea - called when a single i/o operation is complete. If this
 *      is the last outstanding i/o we wakeup the sleeper.
 *	If this i/o had an error then we store the error result in the
 *	iob_hook if this was the first error.
 *
 * ARGUMENTS:
 *      bp - the struct buf describing the block i/o that just completed.
 *
 * Comments:
 *	This routine is called at interrupt level when the io is done.
 */

static int
_sd_sync_ea(struct buf *bp, iob_hook_t *hook)
{

	int error;
	int done;

	/*
	 *  We get called for each buf that completes. When they are all done.
	 *  we wakeup the waiter.
	 */
	error = (bp->b_flags & B_ERROR) ? bp->b_error : 0;

	mutex_enter(hook->lockp);

	if (!hook->error)
		hook->error = error;

	done = !(--hook->count);
	if (done) {
		/* remember the last buffer so we can free it later */
		hook->tail = bp;
		cv_signal(&hook->wait);
	}
	mutex_exit(hook->lockp);

	/*
	 *  let sd_start_io free the final buffer so the hook can be returned
	 *  first.
	 */
	if (!done)
		_sd_put_iobuf(bp);

	return (0);
}

/*
 * static int
 * _sd_async_ea - End action for async read/write.
 *
 * ARGUMENTS:
 *	bp 	- io buf pointer.
 *
 * RETURNS:
 *	NONE.
 *
 * Comments:
 *	This routine is called at interrupt level when the io is done.
 *	This is only called when the operation is asynchronous.
 */
static int
_sd_async_ea(struct buf *bp, iob_hook_t *hook)
{
	int done, error;

	/*
	 *  We get called for each buf that completes. When they are all done.
	 *  we call the requestor's callback function.
	 */
	error = (bp->b_flags & B_ERROR) ? bp->b_error : 0;

	mutex_enter(hook->lockp);
	done = !(--hook->count);

	if (!hook->error)
		hook->error = error;

	mutex_exit(hook->lockp);

	bp->b_forw = NULL;
	bp->b_back = NULL;

	if (done) {
		nsc_off_t fba_pos;
		nsc_size_t fba_len;
		int error;
		sdbc_ea_fn_t fn;
		blind_t arg;

		arg   =  hook->param;
		fn    =  hook->func;
		error = hook->error;
#if defined(_SD_DEBUG)			/* simulate disk errors */
		if (_test_async_fail == bp->b_edev) error = EIO;
#endif

		/* MAKE SURE b_lblkno, b_count never changes!! */
		fba_pos = hook->start_fba;
		fba_len = FBA_LEN(hook->size);

		_sd_put_hook(hook);
		_sd_put_iobuf(bp);
		(*fn)(arg, fba_pos, fba_len, error);
	} else
		_sd_put_iobuf(bp);

	return (0);
}

#ifdef DEBUG
typedef struct ioerr_inject_s {
	dev_t ioj_dev;
	int   ioj_err;
	int   ioj_cnt;
} ioerr_inject_t;

static ioerr_inject_t *ioerr_inject_table = NULL;

void
_sdbc_ioj_load()
{
	ioerr_inject_table =
	    kmem_zalloc(sdbc_max_devs * sizeof (ioerr_inject_t), KM_SLEEP);
}

void
_sdbc_ioj_unload()
{
	if (ioerr_inject_table != NULL) {
		kmem_free(ioerr_inject_table,
		    sdbc_max_devs * sizeof (ioerr_inject_t));
		ioerr_inject_table = NULL;
	}
}

static int
_sdbc_ioj_lookup(dev_t dev)
{
	int cd;

	for (cd = 0; cd < sdbc_max_devs; ++cd)
		if (ioerr_inject_table[cd].ioj_dev == dev) {
			if (ioerr_inject_table[cd].ioj_cnt > 0) {
				--ioerr_inject_table[cd].ioj_cnt;
				return (0);
			} else {
				return (ioerr_inject_table[cd].ioj_err);
			}
		}
	return (0);
}

void
_sdbc_ioj_set_dev(int cd, dev_t crdev)
{
	int i;

	if (cd == -1) {  /* all  -- used for clearing table on shutdown */
		for (i = 0; i < sdbc_max_devs; ++i)  {
			ioerr_inject_table[i].ioj_dev = crdev;
		}
	} else
		ioerr_inject_table[cd].ioj_dev = crdev; /* assume valid cd */
}

static
void
_sdbc_ioj_set_err(int cd, int err, int count)
{
	int i;

	if (cd == -1) {  /* all */
		for (i = 0; i < sdbc_max_devs; ++i)  {
			ioerr_inject_table[i].ioj_err = err;
			ioerr_inject_table[i].ioj_cnt = count;
		}
	} else {
		ioerr_inject_table[cd].ioj_err = err;
		ioerr_inject_table[cd].ioj_cnt = count;
	}
}

static void
_sdbc_ioj_clear_err(int cd)
{
	_sdbc_ioj_set_err(cd, 0, 0);
}

int
_sdbc_inject_ioerr(int cd, int ioj_err, int count)
{
	if ((cd < -1) || (cd >= sdbc_max_devs))
		return (EINVAL);

	_sdbc_ioj_set_err(cd, ioj_err, count);

	return (0);
}

int
_sdbc_clear_ioerr(int cd)
{
	if ((cd < -1) || (cd >= sdbc_max_devs))
		return (EINVAL);

	_sdbc_ioj_clear_err(cd);

	return (0);
}
#endif
