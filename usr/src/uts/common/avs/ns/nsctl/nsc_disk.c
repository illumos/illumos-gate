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
#include <sys/file.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/ddi.h>
#include <sys/sdt.h>

#define	__NSC_GEN__
#include "nsc_dev.h"
#include "nsc_disk.h"
#include "../nsctl.h"


#define	_I(x)	(((long)(&((nsc_io_t *)0)->x))/sizeof (long))

nsc_def_t _nsc_disk_def[] = {
	"UserRead",	(uintptr_t)nsc_ioerr,	_I(uread),
	"UserWrite",	(uintptr_t)nsc_ioerr,	_I(uwrite),
	"PartSize",	(uintptr_t)nsc_null,	_I(partsize),
	"MaxFbas",	(uintptr_t)nsc_null,	_I(maxfbas),
	"Control",	(uintptr_t)nsc_ioerr,	_I(control),
	0,		0,		0
};


extern nsc_mem_t *_nsc_local_mem;

static int _nsc_uread(dev_t, uio_t *, cred_t *, nsc_fd_t *);
static int _nsc_uwrite(dev_t, uio_t *, cred_t *, nsc_fd_t *);
static int _nsc_rw_uio(nsc_fd_t *, uio_t *, uio_rw_t);

static int _nsc_free_dhandle(nsc_dbuf_t *);
static int _nsc_alloc_dbuf(blind_t, nsc_off_t, nsc_size_t, int, nsc_dbuf_t **);
static int _nsc_free_dbuf(nsc_dbuf_t *);
static void _nsc_wait_dbuf(nsc_dbuf_t *);
static int _nsc_read_dbuf(nsc_dbuf_t *, nsc_off_t, nsc_size_t, int);
static int _nsc_write_dbuf(nsc_dbuf_t *, nsc_off_t, nsc_size_t, int);
static int _nsc_zero_dbuf(nsc_dbuf_t *, nsc_off_t, nsc_size_t, int);
static int _nsc_dbuf_io(int (*)(), nsc_dbuf_t *, nsc_off_t, nsc_size_t, int);

static nsc_dbuf_t *_nsc_alloc_dhandle(void (*)(), void (*)(), void (*)());


/*
 * void
 * _nsc_add_disk (nsc_io_t *io)
 *	Add disk interface functions.
 *
 * Calling/Exit State:
 *	Updates the I/O module with the appropriate
 *	interface routines.
 *
 * Description:
 *	Add functions to the I/O module to provide a disk
 *	or cache interface as appropriate.
 */
void
_nsc_add_disk(nsc_io_t *io)
{
	if ((io->alloc_buf != nsc_ioerr && io->free_buf != nsc_fatal) ||
	    (io->flag & NSC_FILTER)) {
		if (io->uread == nsc_ioerr)
			io->uread = _nsc_uread;

		if (io->uwrite == nsc_ioerr &&
		    (io->write != nsc_fatal || (io->flag & NSC_FILTER)))
			io->uwrite = _nsc_uwrite;

		return;
	}

	if (io->alloc_h != (nsc_buf_t *(*)())nsc_null ||
	    io->free_h != nsc_fatal || io->alloc_buf != nsc_ioerr ||
	    io->free_buf != nsc_fatal || io->read != nsc_fatal ||
	    io->write != nsc_fatal || io->zero != nsc_fatal)
		return;

	if (io->uread == nsc_ioerr && io->uwrite == nsc_ioerr)
		return;

	/*
	 * Layer the generic nsc_buf_t provider onto a uio_t provider.
	 */

	io->alloc_h = (nsc_buf_t *(*)())_nsc_alloc_dhandle;
	io->free_h = _nsc_free_dhandle;
	io->alloc_buf = _nsc_alloc_dbuf;
	io->free_buf = _nsc_free_dbuf;

	io->read = _nsc_read_dbuf;
	io->write = _nsc_write_dbuf;
	io->zero = _nsc_zero_dbuf;

	io->provide |= NSC_ANON;
}


int
nsc_uread(nsc_fd_t *fd, void *uiop, void *crp)
{
	return (*fd->sf_aio->uread)(fd->sf_cd, uiop, crp, fd);
}


int
nsc_uwrite(nsc_fd_t *fd, void *uiop, void *crp)
{
	if ((fd->sf_avail & NSC_WRITE) == 0)
		return (EIO);

	return (*fd->sf_aio->uwrite)(fd->sf_cd, uiop, crp, fd);
}


int
nsc_partsize(nsc_fd_t *fd, nsc_size_t *valp)
{
	*valp = 0;
	return (*fd->sf_aio->partsize)(fd->sf_cd, valp);
}


int
nsc_maxfbas(nsc_fd_t *fd, int flag, nsc_size_t *valp)
{
	*valp = 0;
	return (*fd->sf_aio->maxfbas)(fd->sf_cd, flag, valp);
}

int
nsc_control(nsc_fd_t *fd, int command, void *argp, int argl)
{
	return (*fd->sf_aio->control)(fd->sf_cd, command, argp, argl);
}


/* ARGSUSED */

static int
_nsc_uread(dev_t dev, uio_t *uiop, cred_t *crp, nsc_fd_t *fd)
{
	return (_nsc_rw_uio(fd, uiop, UIO_READ));
}


/* ARGSUSED */

static int
_nsc_uwrite(dev_t dev, uio_t *uiop, cred_t *crp, nsc_fd_t *fd)
{
	return (_nsc_rw_uio(fd, uiop, UIO_WRITE));
}


static int
_nsc_rw_uio(nsc_fd_t *fd, uio_t *uiop, uio_rw_t rw)
{
	nsc_size_t buflen, len, limit, chunk;
	nsc_off_t pos, off;
	nsc_buf_t *buf;
	nsc_vec_t *vec;
	size_t n;
	int rc;

	pos = FPOS_TO_FBA(uiop);
	off = FPOS_TO_OFF(uiop);
	len = FBA_LEN(uiop->uio_resid + off);

	DTRACE_PROBE3(_nsc_rw_uio_io,
		uint64_t, pos,
		uint64_t, off,
		uint64_t, len);

	/* prevent non-FBA bounded I/O - this is a disk driver! */
	if (off != 0 || FBA_OFF(uiop->uio_resid) != 0)
		return (EINVAL);

	if ((rc = nsc_partsize(fd, &limit)) != 0)
		return (rc);

	if ((rc = nsc_maxfbas(fd, 0, &chunk)) != 0)
		return (rc);

	DTRACE_PROBE2(_nsc_rw_uio_limit,
		uint64_t, limit,
		uint64_t, chunk);

	if (limit && pos >= limit) {
		if (pos > limit || rw == UIO_WRITE)
			return (ENXIO);
		return (0);
	}

	if (limit && pos + len > limit)
		len = limit - pos;

	while (len > 0) {
		buflen = min(len, chunk);

		buf = NULL;	/* always use a temporary buffer */
		if ((rc = nsc_alloc_buf(fd, pos, buflen,
		    (rw == UIO_READ) ? NSC_RDBUF : NSC_WRBUF, &buf)) > 0)
			return (rc);

		vec = buf->sb_vec;

		for (rc = 0;
		    !rc && uiop->uio_resid && vec->sv_addr;
		    vec++, off = 0) {
			n = min(vec->sv_len - off, uiop->uio_resid);
			rc = uiomove((char *)vec->sv_addr + off,
			    n, rw, uiop);
		}

		if (rw == UIO_WRITE) {
			if (rc) {
				(void) nsc_uncommit(buf, pos, buflen, 0);
			} else if ((rc = nsc_write(buf, pos, buflen, 0)) < 0) {
				rc = 0;
			}
		}

		(void) nsc_free_buf(buf);

		len -= buflen;
		pos += buflen;
	}

	return (rc);
}


/* ARGSUSED */

static nsc_dbuf_t *
_nsc_alloc_dhandle(void (*d_cb)(), void (*r_cb)(), void (*w_cb)())
{
	nsc_dbuf_t *h;

	if ((h = nsc_kmem_zalloc(sizeof (nsc_dbuf_t),
			KM_SLEEP, _nsc_local_mem)) == NULL)
		return (NULL);

	h->db_disc = d_cb;
	h->db_flag = NSC_HALLOCATED;

	return (h);
}


static int
_nsc_free_dhandle(nsc_dbuf_t *h)
{
	nsc_kmem_free(h, sizeof (*h));
	return (0);
}


static int
_nsc_alloc_dbuf(blind_t cd, nsc_off_t pos, nsc_size_t len,
    int flag, nsc_dbuf_t **hp)
{
	nsc_dbuf_t *h = *hp;
	int rc;

	if (cd == NSC_ANON_CD) {
		flag &= ~(NSC_READ | NSC_WRITE | NSC_RDAHEAD);
	} else {
		if (h->db_maxfbas == 0) {
			rc = nsc_maxfbas(h->db_fd, 0, &h->db_maxfbas);
			if (rc != 0)
				return (rc);
			else if (h->db_maxfbas == 0)
				return (EIO);
		}

		if (len > h->db_maxfbas)
			return (ENOSPC);
	}

	if (flag & NSC_NODATA) {
		ASSERT(!(flag & NSC_RDBUF));
		h->db_addr = NULL;
	} else {
		if (h->db_disc)
			(*h->db_disc)(h);

		if (!(h->db_addr = nsc_kmem_alloc(FBA_SIZE(len), KM_SLEEP, 0)))
			return (ENOMEM);
	}

	h->db_pos = pos;
	h->db_len = len;
	h->db_error = 0;
	h->db_flag |= flag;

	if (flag & NSC_NODATA) {
		h->db_vec = NULL;
	} else {
		h->db_vec = &h->db_bvec[0];
		h->db_bvec[0].sv_len = FBA_SIZE(len);
		h->db_bvec[0].sv_addr = (void *)h->db_addr;
		h->db_bvec[0].sv_vme = 0;

		h->db_bvec[1].sv_len = 0;
		h->db_bvec[1].sv_addr = 0;
		h->db_bvec[1].sv_vme = 0;
	}

	if ((flag & NSC_RDAHEAD) || (cd == NSC_ANON_CD))
		return (NSC_DONE);

	_nsc_wait_dbuf(h);

	if (flag & NSC_RDBUF) {
		if ((rc = _nsc_dbuf_io(nsc_uread, h, pos, len, flag)) != 0) {
			(void) _nsc_free_dbuf(h);
			return (rc);
		}
	}

	return (NSC_DONE);
}


static void
_nsc_wait_dbuf(nsc_dbuf_t *h)
{
	nsc_iodev_t *iodev = h->db_fd->sf_iodev;
	void (*fn)() = h->db_disc;
	nsc_dbuf_t *hp;

	mutex_enter(&iodev->si_lock);

	h->db_next = iodev->si_active;
	iodev->si_active = h;

	/* CONSTCOND */

	while (1) {
		for (hp = h->db_next; hp; hp = hp->db_next)
			if (h->db_pos + h->db_len > hp->db_pos &&
			    h->db_pos < hp->db_pos + hp->db_len) break;

		if (!hp)
			break;

		if (fn)
			(*fn)(h), fn = NULL;

		cv_wait(&iodev->si_cv, &iodev->si_lock);
	}

	mutex_exit(&iodev->si_lock);
}


static int
_nsc_free_dbuf(nsc_dbuf_t *h)
{
	nsc_dbuf_t **hpp, *hp;
	nsc_iodev_t *iodev;
	int wake = 0;

	if (h->db_fd && !(h->db_flag & NSC_ABUF)) {
		iodev = h->db_fd->sf_iodev;

		mutex_enter(&iodev->si_lock);

		hpp = (nsc_dbuf_t **)&iodev->si_active;

		for (; *hpp; hpp = &hp->db_next) {
			if ((hp = *hpp) == h) {
				*hpp = h->db_next;
				break;
			}

			if (h->db_pos + h->db_len > hp->db_pos &&
			    h->db_pos < hp->db_pos + hp->db_len) wake = 1;

		}
		if (wake)
			cv_broadcast(&iodev->si_cv);

		mutex_exit(&iodev->si_lock);
	}

	if (!(h->db_flag & NSC_NODATA) && h->db_addr)
		nsc_kmem_free(h->db_addr, FBA_SIZE(h->db_len));

	h->db_addr = NULL;
	h->db_flag &= NSC_HALLOCATED; /* clear flags, preserve NSC_HALLOCATED */

	if ((h->db_flag & NSC_HALLOCATED) == 0)
		(void) _nsc_free_dhandle(h);


	return (0);
}


static int
_nsc_read_dbuf(nsc_dbuf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	return (_nsc_dbuf_io(nsc_uread, h, pos, len, flag));
}


static int
_nsc_write_dbuf(nsc_dbuf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	return (_nsc_dbuf_io(nsc_uwrite, h, pos, len, flag));
}


static int
_nsc_zero_dbuf(nsc_dbuf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	return (_nsc_dbuf_io(NULL, h, pos, len, flag));
}


static int
_nsc_dbuf_io(int (*fn)(), nsc_dbuf_t *h, nsc_off_t pos,
    nsc_size_t len, int flag)
{
	nsc_vec_t *vp = NULL;
	cred_t *crp = NULL;
	iovec_t *iovp;
	nsc_size_t thisio;		/* bytes in this io */
	nsc_size_t todo;		/* anticipated bytes to go */
	nsc_size_t truedo;		/* actual bytes to go */
	nsc_off_t xpos;			/* offset of this io */
	int destidx;
	nsc_size_t firstentryfix;	/* value used for first entry */

	int (*iofn)();
	int rc = 0;

	if (!h->db_vec || (h->db_flag & NSC_ABUF))
		return (EIO);

	if (pos < h->db_pos || pos + len > h->db_pos + h->db_len)
		return (EINVAL);

	if (!len)
		return (0);
	if (fn == nsc_uread && (flag & NSC_RDAHEAD))
		return (0);

	if (h->db_disc)
		(*h->db_disc)(h);

	crp = ddi_get_cred();
	bzero(&h->db_uio, sizeof (uio_t));
	bzero(&h->db_iov[0], (_NSC_DBUF_NVEC * sizeof (iovec_t)));

	todo = FBA_SIZE(len);

	/*
	 * determine where in the vector array we should start.
	 */
	vp = h->db_vec;
	xpos = pos - h->db_pos;
	for (; xpos >= FBA_NUM(vp->sv_len); vp++)
		xpos -= FBA_NUM(vp->sv_len);

	firstentryfix = FBA_SIZE(xpos);

	xpos = pos;

	/*
	 * Loop performing i/o to the underlying driver.
	 */
	while (todo) {
		destidx = 0;
		thisio = 0;
		iofn = fn;

		/*
		 * Copy up to _NSC_DBUF_NVEC vector entries from the
		 * nsc_vec_t into the iovec_t so that the number of
		 * i/o operations is minimised.
		 */
		while (destidx < _NSC_DBUF_NVEC && todo) {
			iovp = &h->db_iov[destidx];

			ASSERT(FBA_LEN(vp->sv_len) == FBA_NUM(vp->sv_len));
			ASSERT((vp->sv_len - firstentryfix) && vp->sv_addr);

			truedo = min(vp->sv_len - firstentryfix, todo);
			iovp->iov_base = (caddr_t)vp->sv_addr + firstentryfix;
			firstentryfix = 0;
			iovp->iov_len = (size_t)truedo;
			if (!iofn) {
				bzero(iovp->iov_base, iovp->iov_len);
			}
			thisio += truedo;
			todo -= truedo;
			destidx++;
			vp++;
		}

		h->db_uio.uio_iovcnt = destidx;
		h->db_uio.uio_iov = &h->db_iov[0];
		h->db_uio.uio_segflg = UIO_SYSSPACE;
		h->db_uio.uio_resid = (size_t)thisio;

		SET_FPOS(&h->db_uio, xpos);

		if (!iofn) {
			iofn = nsc_uwrite;
		}

		rc = (*iofn)(h->db_fd, &h->db_uio, crp);
		if (rc != 0) {
			break;
		}

		ASSERT(FBA_LEN(thisio) == FBA_NUM(thisio));
		xpos += FBA_LEN(thisio);
	}

	return (rc);
}
