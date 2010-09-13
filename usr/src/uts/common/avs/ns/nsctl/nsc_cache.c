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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/ddi.h>

#define	__NSC_GEN__
#include "nsc_dev.h"

#ifdef DS_DDICT
#include "../contract.h"
#endif

#include "../nsctl.h"


#define	_I(x)	(((long)(&((nsc_io_t *)0)->x))/sizeof (long))


nsc_def_t _nsc_cache_def[] = {
	"AllocBuf",	(uintptr_t)nsc_ioerr,	_I(alloc_buf),
	"FreeBuf",	(uintptr_t)nsc_fatal,	_I(free_buf),
	"Read",		(uintptr_t)nsc_fatal,	_I(read),
	"Write",	(uintptr_t)nsc_fatal,	_I(write),
	"Zero",		(uintptr_t)nsc_fatal,	_I(zero),
	"Copy",		(uintptr_t)nsc_ioerr,	_I(copy),
	"CopyDirect",	(uintptr_t)nsc_ioerr,	_I(copy_direct),
	"Uncommit",	(uintptr_t)nsc_null,	_I(uncommit),
	"AllocHandle",	(uintptr_t)nsc_null,	_I(alloc_h),
	"FreeHandle",	(uintptr_t)nsc_fatal,	_I(free_h),
	"TrackSize",	(uintptr_t)nsc_null,	_I(trksize),
	"Discard",	(uintptr_t)nsc_null,	_I(discard),
	"Sizes",	(uintptr_t)nsc_null,	_I(sizes),
	"GetPinned",	(uintptr_t)nsc_null,	_I(getpin),
	"NodeHints",	(uintptr_t)nsc_inval,	_I(nodehints),
	0,		0,		0
};


static int _nsc_alloc_buf_h(blind_t, nsc_off_t, nsc_size_t, int,
    nsc_buf_t **, nsc_fd_t *);
static int _nsc_copy_h(nsc_buf_t *, nsc_buf_t *, nsc_off_t,
    nsc_off_t, nsc_size_t);

extern nsc_io_t *_nsc_reserve_io(char *, int);
extern void _nsc_release_io(nsc_io_t *);

extern kmutex_t _nsc_io_lock;




/* ARGSUSED */

void
_nsc_add_cache(nsc_io_t *io)
{
}


nsc_buf_t *
nsc_alloc_handle(nsc_fd_t *fd, void (*d_cb)(), void (*r_cb)(), void (*w_cb)())
{
	nsc_buf_t *h = (*fd->sf_aio->alloc_h)(d_cb, r_cb, w_cb, fd->sf_cd);

	if (h)
		h->sb_fd = fd;

	return (h);
}


int
nsc_free_handle(nsc_buf_t *h)
{
	if (h == NULL || (h->sb_flag & NSC_ABUF))
		return (EINVAL);

	return ((*h->sb_fd->sf_aio->free_h)(h, h->sb_fd->sf_cd));
}


int
nsc_alloc_abuf(nsc_off_t pos, nsc_size_t len, int flag, nsc_buf_t **ptr)
{
	nsc_buf_t *h;
	nsc_io_t *io;
	int rc;

	if (*ptr != NULL)
		return (EINVAL);

	if (flag & NSC_NODATA)
		return (EINVAL);

	io = _nsc_reserve_io(NULL, NSC_ANON);
	if (io == NULL)
		return (ENOBUFS);

	if ((h = (*io->alloc_h)(NULL, NULL, NULL, NSC_ANON_CD)) == NULL) {
		_nsc_release_io(io);
		return (ENOBUFS);
	}

	rc = (*io->alloc_buf)(NSC_ANON_CD, pos, len,
	    NSC_NOCACHE|flag, &h, NULL);
	if (rc <= 0) {
		h->sb_flag &= ~NSC_HALLOCATED;
		h->sb_flag |= NSC_ABUF;
		h->sb_fd = (nsc_fd_t *)io;	/* note overloaded field */

		*ptr = h;

		mutex_enter(&_nsc_io_lock);
		io->abufcnt++;
		mutex_exit(&_nsc_io_lock);
	}

	_nsc_release_io(io);
	return (rc);
}


int
nsc_alloc_buf(nsc_fd_t *fd, nsc_off_t pos, nsc_size_t len,
    int flag, nsc_buf_t **ptr)
{
	int (*fn)() = _nsc_alloc_buf_h;

	if ((fd->sf_avail & NSC_WRITE) == 0)
		if (flag & NSC_WRBUF)
			return (EACCES);

	if ((flag & (NSC_READ|NSC_WRITE|NSC_NODATA)) ==
	    (NSC_READ|NSC_NODATA)) {
		/*
		 * NSC_NODATA access checks.
		 *
		 * - NSC_READ|NSC_NODATA is illegal since there would
		 *   be no data buffer to immediately read the data into.
		 * - NSC_WRITE|NSC_NODATA is valid since the client can
		 *   provide the buffer and then call nsc_write() as
		 *   necessary.
		 * - NSC_NODATA is valid since the client can provide the
		 *   buffer and then call nsc_read() or nsc_write() as
		 *   necessary.
		 */
		return (EACCES);
	}

	if (*ptr) {
		fn = fd->sf_aio->alloc_buf;
		(*ptr)->sb_fd = fd;
	}

	return (*fn)(fd->sf_cd, pos, len, flag, ptr, fd);
}


/* ARGSUSED */

static int
_nsc_alloc_buf_h(blind_t cd, nsc_off_t pos, nsc_size_t len,
    int flag, nsc_buf_t **ptr, nsc_fd_t *fd)
{
	nsc_buf_t *h;
	int rc;

	if (!(h = nsc_alloc_handle(fd, NULL, NULL, NULL)))
		return (ENOBUFS);

	if ((rc = nsc_alloc_buf(fd, pos, len, flag, &h)) <= 0) {
		h->sb_flag &= ~NSC_HALLOCATED;
		*ptr = h;
		return (rc);
	}

	(void) nsc_free_handle(h);
	return (rc);
}


int
nsc_read(nsc_buf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	if ((h->sb_flag & NSC_ABUF) ||
	    ((h->sb_flag & NSC_NODATA) && h->sb_vec == NULL))
		return (EIO);

	return ((*h->sb_fd->sf_aio->read)(h, pos, len, flag));
}


int
nsc_write(nsc_buf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	if ((h->sb_flag & NSC_ABUF) ||
	    ((h->sb_flag & NSC_NODATA) && h->sb_vec == NULL))
		return (EIO);

	return ((*h->sb_fd->sf_aio->write)(h, pos, len, flag));
}


int
nsc_zero(nsc_buf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	if ((h->sb_flag & NSC_ABUF) ||
	    ((h->sb_flag & NSC_NODATA) && h->sb_vec == NULL))
		return (EIO);

	return ((*h->sb_fd->sf_aio->zero)(h, pos, len, flag));
}


int
nsc_copy(nsc_buf_t *h1, nsc_buf_t *h2, nsc_off_t pos1,
    nsc_off_t pos2, nsc_size_t len)
{
	nsc_io_t *io1, *io2;
	int rc = EIO;

	if (((h1->sb_flag & NSC_NODATA) && h1->sb_vec == NULL) ||
	    ((h2->sb_flag & NSC_NODATA) && h2->sb_vec == NULL))
		return (EIO);

	if (h1->sb_fd && h2->sb_fd) {
		io1 = (h1->sb_flag & NSC_ABUF) ?
		    (nsc_io_t *)h1->sb_fd : h1->sb_fd->sf_aio;

		io2 = (h2->sb_flag & NSC_ABUF) ?
		    (nsc_io_t *)h2->sb_fd : h2->sb_fd->sf_aio;

		if (io1 == io2)
			rc = (*io1->copy)(h1, h2, pos1, pos2, len);
	}

	if (rc != EIO)
		return (rc);

	return (_nsc_copy_h(h1, h2, pos1, pos2, len));
}


static int
_nsc_copy_h(nsc_buf_t *h1, nsc_buf_t *h2, nsc_off_t pos1,
    nsc_off_t pos2, nsc_size_t len)
{
	nsc_vec_t *v1, *v2;
	uchar_t *a1, *a2;
	int sz, l1, l2, lenbytes;	/* byte sizes within an nsc_vec_t */

	if (pos1 < h1->sb_pos || pos1 + len > h1->sb_pos + h1->sb_len ||
	    pos2 < h2->sb_pos || pos2 + len > h2->sb_pos + h2->sb_len)
		return (EINVAL);

	if (!len)
		return (0);

	/* find starting point in "from" vector */

	v1 = h1->sb_vec;
	pos1 -= h1->sb_pos;

	for (; pos1 >= FBA_NUM(v1->sv_len); v1++)
		pos1 -= FBA_NUM(v1->sv_len);

	a1 = v1->sv_addr + FBA_SIZE(pos1);
	l1 = v1->sv_len - FBA_SIZE(pos1);

	/* find starting point in "to" vector */

	v2 = h2->sb_vec;
	pos2 -= h2->sb_pos;

	for (; pos2 >= FBA_NUM(v2->sv_len); v2++)
		pos2 -= FBA_NUM(v2->sv_len);

	a2 = v2->sv_addr + FBA_SIZE(pos2);
	l2 = v2->sv_len - FBA_SIZE(pos2);

	/* copy required data */

	ASSERT(FBA_SIZE(len) < INT_MAX);
	lenbytes = (int)FBA_SIZE(len);

	while (lenbytes) {
		sz = min(l1, l2);
		sz = min(sz, lenbytes);

		bcopy(a1, a2, sz);

		l1 -= sz; l2 -= sz;
		a1 += sz; a2 += sz;
		lenbytes -= sz;

		if (!l1)
			a1 = (++v1)->sv_addr, l1 = v1->sv_len;
		if (!l2)
			a2 = (++v2)->sv_addr, l2 = v2->sv_len;
	}

	return (0);
}


int
nsc_copy_direct(nsc_buf_t *h1, nsc_buf_t *h2, nsc_off_t pos1,
    nsc_off_t pos2, nsc_size_t len)
{
	int rc = EIO;

	if (!h1 || !h2)
		return (EINVAL);

	if (((h1->sb_flag & NSC_NODATA) && h1->sb_vec == NULL) ||
	    ((h2->sb_flag & NSC_NODATA) && h2->sb_vec == NULL))
		return (EIO);

	if ((h2->sb_flag & NSC_RDWR) != NSC_WRITE) {
		cmn_err(CE_WARN,
		    "nsc_copy_direct: h2 (%p) flags (%x) include NSC_READ",
		    (void *)h2, h2->sb_flag);
	}

	if ((h2->sb_flag & NSC_WRTHRU) == 0) {
		cmn_err(CE_WARN,
		    "nsc_copy_direct: h2 (%p) flags (%x) do not "
		    "include NSC_WRTHRU", (void *)h2, h2->sb_flag);
		h2->sb_flag |= NSC_WRTHRU;
	}

	if (h1->sb_fd && h2->sb_fd && h1->sb_fd->sf_aio == h2->sb_fd->sf_aio)
		rc = (*h1->sb_fd->sf_aio->copy_direct)(h1, h2, pos1, pos2, len);

	if (rc != EIO)
		return (rc);

	/*
	 * The slow way ...
	 */

	rc = nsc_copy(h1, h2, pos1, pos2, len);
	if (rc <= 0)
		rc = nsc_write(h2, pos2, len, NSC_WRTHRU);

	return (rc);
}


int
nsc_uncommit(nsc_buf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	if (h->sb_flag & NSC_ABUF)
		return (EIO);

	return ((*h->sb_fd->sf_aio->uncommit)(h, pos, len, flag));
}


int
nsc_free_buf(nsc_buf_t *h)
{
	nsc_io_t *io;
	int abuf;
	int rc;

	if (h == NULL)
		return (0);

	if ((h->sb_flag & NSC_NODATA) && (h->sb_vec != NULL)) {
		h->sb_vec = NULL;
	}

	abuf = (h->sb_flag & NSC_ABUF);

	if (abuf)
		io = (nsc_io_t *)h->sb_fd;
	else
		io = h->sb_fd->sf_aio;

	rc = (*io->free_buf)(h);

	if (abuf && rc <= 0) {
		mutex_enter(&_nsc_io_lock);
		io->abufcnt--;
		mutex_exit(&_nsc_io_lock);
	}

	return (rc);
}


int
nsc_node_hints(uint_t *hints)
{
	return (_nsc_call_io(_I(nodehints), (blind_t)hints,
	    (blind_t)NSC_GET_NODE_HINT, 0));
}

int
nsc_node_hints_set(uint_t hints)
{
	return (_nsc_call_io(_I(nodehints), (blind_t)(unsigned long)hints,
	    (blind_t)NSC_SET_NODE_HINT, 0));
}


int
nsc_cache_sizes(int *asize, int *wsize)
{
	return (_nsc_call_io(_I(sizes), (blind_t)asize, (blind_t)wsize, 0));
}


int
nsc_set_trksize(nsc_fd_t *fd, nsc_size_t trsize)
{
	return (*fd->sf_aio->trksize)(fd->sf_cd, trsize);
}


int
nsc_get_pinned(nsc_fd_t *fd)
{
	return (*fd->sf_aio->getpin)(fd->sf_cd);
}


int
nsc_discard_pinned(nsc_fd_t *fd, nsc_off_t pos, nsc_size_t len)
{
	return (*fd->sf_aio->discard)(fd->sf_cd, pos, len);
}


void
nsc_pinned_data(nsc_iodev_t *iodev, nsc_off_t pos, nsc_size_t len)
{
	nsc_fd_t *fd;

	if (!iodev)
		return;

	mutex_enter(&iodev->si_dev->nsc_lock);
	iodev->si_busy++;
	mutex_exit(&iodev->si_dev->nsc_lock);

	for (fd = iodev->si_open; fd; fd = fd->sf_next)
		if (fd->sf_avail & _NSC_ATTACH)
			(*fd->sf_pinned)(fd->sf_arg, pos, len);

	_nsc_wake_dev(iodev->si_dev, &iodev->si_busy);
}


void
nsc_unpinned_data(nsc_iodev_t *iodev, nsc_off_t pos, nsc_size_t len)
{
	nsc_fd_t *fd;

	if (!iodev)
		return;

	mutex_enter(&iodev->si_dev->nsc_lock);
	iodev->si_busy++;
	mutex_exit(&iodev->si_dev->nsc_lock);

	for (fd = iodev->si_open; fd; fd = fd->sf_next)
		if (fd->sf_avail & _NSC_ATTACH)
			(*fd->sf_unpinned)(fd->sf_arg, pos, len);

	_nsc_wake_dev(iodev->si_dev, &iodev->si_busy);
}
