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
#include <sys/ddi.h>

#include <sys/ncall/ncall.h>

#define	__NSC_GEN__
#include "nsc_dev.h"
#include "nsc_ncallio.h"
#include "../nsctl.h"


extern nsc_mem_t *_nsc_local_mem;

extern void _nsc_init_ncio(void);
extern void _nsc_deinit_ncio(void);

static nsc_io_t *nsc_ncio_io;
static kmutex_t nsc_ncio_lock;
static nsc_ncio_dev_t *nsc_ncio_top;


/*
 * ncall-io io provider - client side.
 */


static int
nsc_ncio_split(char *node_and_path, char **pathp)
{
	char *cp;
	int i, snode;

	snode = 0;
	for (cp = node_and_path; *cp && *cp != ':'; cp++) {
		i = *cp - '0';
		if (i < 0 || i > 9)
			break;

		snode = (10 * snode) + i;
	}

	if (*cp != ':') {
		cmn_err(CE_WARN,
		    "ncio: failed to convert %s to node and path",
		    node_and_path);
		return (-1);
	}

	*pathp = cp + 1;
	return (snode);
}


/*
 * nsc_ncio_open()
 *
 * The pathname that is used with the NSC_NCALL io provider should be
 * of the form "<node>:<pathname>", where <node> is the decimal ncall
 * nodeid of the server machine and <pathname> is the pathname of the
 * device on the server node.
 */

/* ARGSUSED */
static int
nsc_ncio_open(char *node_and_path, int flag, blind_t *cdp, void *iodev)
{
	nsc_ncio_dev_t *ncp, *new;
	char *path = NULL;
	uint64_t phash;
	int snode;

	snode = nsc_ncio_split(node_and_path, &path);
	if (snode < 0)
		return (EINVAL);

	new = nsc_kmem_zalloc(sizeof (*new), KM_SLEEP, _nsc_local_mem);
	phash = nsc_strhash(path);

	if (new) {
		(void) strncpy(new->path, path, sizeof (new->path));
		new->phash = phash;
		new->snode = snode;
	}

	mutex_enter(&nsc_ncio_lock);

	for (ncp = nsc_ncio_top; ncp; ncp = ncp->next)
		if (ncp->phash == phash && strcmp(path, ncp->path) == 0)
			break;

	if (ncp == NULL && new != NULL) {
		ncp = new;
		new = NULL;
		ncp->next = nsc_ncio_top;
		nsc_ncio_top = ncp;
	}

	if (ncp != NULL)
		ncp->ref++;

	mutex_exit(&nsc_ncio_lock);

	if (new)
		nsc_kmem_free(new, sizeof (*new));

	if (!ncp)
		return (ENOMEM);

	*cdp = (blind_t)ncp;
	return (0);
}


static int
nsc_ncio_close(nsc_ncio_dev_t *ncp)
{
	nsc_ncio_dev_t **ncpp;
	int found, free;

	if (ncp == NULL)
		return (EINVAL);

	found = 0;
	free = 0;

	mutex_enter(&nsc_ncio_lock);

	for (ncpp = &nsc_ncio_top; *ncpp; ncpp = &((*ncpp)->next)) {
		if (*ncpp == ncp) {
			found = 1;
			break;
		}
	}

	if (!found) {
		mutex_exit(&nsc_ncio_lock);
		return (ENODEV);
	}

	ncp->ref--;
	if (ncp->ref == 0) {
		*ncpp = ncp->next;
		free = 1;
	}

	mutex_exit(&nsc_ncio_lock);

	if (free)
		nsc_kmem_free(ncp, sizeof (*ncp));

	return (0);
}


/* ARGSUSED1 */
static nsc_buf_t *
nsc_ncio_alloch(void (*d_cb)(), void (*r_cb)(), void (*w_cb)())
{
	nsc_ncio_buf_t *h;

	if ((h = nsc_kmem_zalloc(sizeof (*h), KM_SLEEP,
	    _nsc_local_mem)) == NULL)
		return (NULL);

	h->disc = d_cb;
	h->bufh.sb_flag = NSC_HALLOCATED;

	return (&h->bufh);
}


static int
nsc_ncio_freeh(nsc_ncio_buf_t *h)
{
	nsc_kmem_free(h, sizeof (*h));
	return (0);
}


static int
nsc_ncio_rwb(nsc_ncio_buf_t *h, nsc_off_t pos, nsc_size_t len,
    int flag, const int rwflag)
{
	nsc_ncio_rw_t *rw;
	ncall_t *ncall;
	int ncall_flag;
	int ncall_proc;
	int ncall_len;
	int rc, err;

	if (h->bufh.sb_flag & NSC_ABUF)
		return (EIO);

	if (pos < h->bufh.sb_pos ||
	    (pos + len) > (h->bufh.sb_pos + h->bufh.sb_len)) {
		return (EINVAL);
	}

	if (!len)
		return (0);

	if (rwflag == NSC_READ && (flag & NSC_RDAHEAD))
		return (0);

	/* CONSTCOND */
	if (sizeof (*rw) > NCALL_DATA_SZ) {
		/* CONSTCOND */
		ASSERT(sizeof (*rw) <= NCALL_DATA_SZ);
		return (ENXIO);
	}

	if (rwflag == NSC_READ) {
		ncall_flag = NCALL_RDATA;
		ncall_proc = NSC_NCIO_READ;
		ncall_len = sizeof (*rw) - sizeof (rw->rw_data);
	} else {
		ncall_flag = 0;
		ncall_proc = NSC_NCIO_WRITE;
		ncall_len = sizeof (*rw);
	}

	rw = &h->rw;

	if (rwflag == 0) {
		/* zero */
		bzero(rw->rw_data, sizeof (rw->rw_data));
	}

	if (h->disc)
		(*h->disc)(h);

	rc = ncall_alloc(rw->rw_snode, 0, 0, &ncall);
	if (rc != 0) {
		return (rc);
	}

	rw->rw_pos = (uint64_t)pos;
	rw->rw_len = (uint64_t)len;
	rc = ncall_put_data(ncall, rw, ncall_len);
	if (rc != 0) {
		return (rc);
	}

	rc = ncall_send(ncall, ncall_flag, ncall_proc);
	if (rc != 0) {
		return (rc);
	}

	rc = ncall_read_reply(ncall, 1, &err);
	if (rc != 0 || err != 0) {
		return (rc ? rc : err);
	}

	if (rwflag == NSC_READ) {
		rc = ncall_get_data(ncall, rw, sizeof (*rw));
		if (rc != 0) {
			return (rc);
		}
	}

	ncall_free(ncall);
	return (0);
}


static int
nsc_ncio_read(nsc_ncio_buf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	return (nsc_ncio_rwb(h, pos, len, flag, NSC_READ));
}


static int
nsc_ncio_write(nsc_ncio_buf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	return (nsc_ncio_rwb(h, pos, len, flag, NSC_WRITE));
}


static int
nsc_ncio_zero(nsc_ncio_buf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	return (nsc_ncio_rwb(h, pos, len, flag, 0));
}


static void
nsc_wait_ncio(nsc_ncio_buf_t *h)
{
	nsc_iodev_t *iodev = h->bufh.sb_fd->sf_iodev;
	void (*fn)() = h->disc;
	nsc_ncio_buf_t *hp;

	mutex_enter(&iodev->si_lock);

	h->next = iodev->si_active;
	iodev->si_active = h;

	/* CONSTCOND */

	while (1) {
		for (hp = h->next; hp; hp = hp->next) {
			if ((h->bufh.sb_pos + h->bufh.sb_len) >
			    hp->bufh.sb_pos &&
			    h->bufh.sb_pos <
			    (hp->bufh.sb_pos + hp->bufh.sb_len)) {
				/* found overlapping io in progress */
				break;
			}
		}

		if (!hp)
			break;

		if (fn) {
			(*fn)(h);
			fn = NULL;
		}

		cv_wait(&iodev->si_cv, &iodev->si_lock);
	}

	mutex_exit(&iodev->si_lock);
}


static int
nsc_ncio_freeb(nsc_ncio_buf_t *h)
{
	nsc_ncio_buf_t **hpp, *hp;
	nsc_iodev_t *iodev;
	int wake = 0;

	if ((h->bufh.sb_flag & NSC_HACTIVE) &&
	    h->bufh.sb_fd && !(h->bufh.sb_flag & NSC_ABUF)) {
		iodev = h->bufh.sb_fd->sf_iodev;

		mutex_enter(&iodev->si_lock);

		for (hpp = (nsc_ncio_buf_t **)&iodev->si_active;
		    *hpp; hpp = &hp->next) {
			if ((hp = *hpp) == h) {
				*hpp = h->next;
				break;
			}

			if ((h->bufh.sb_pos + h->bufh.sb_len) >
			    hp->bufh.sb_pos &&
			    h->bufh.sb_pos <
			    (hp->bufh.sb_pos + hp->bufh.sb_len)) {
				wake = 1;
			}
		}

		if (wake)
			cv_broadcast(&iodev->si_cv);

		mutex_exit(&iodev->si_lock);
	}

	/* clear flags, preserve NSC_HALLOCATED */
	h->bufh.sb_flag &= NSC_HALLOCATED;

	if ((h->bufh.sb_flag & NSC_HALLOCATED) == 0)
		(void) nsc_ncio_freeh(h);

	return (0);
}


static int
nsc_ncio_allocb(nsc_ncio_dev_t *ncp, nsc_off_t pos, nsc_size_t len,
    int flag, nsc_ncio_buf_t **hp)
{
	nsc_ncio_buf_t *h = *hp;
	int rc;

	if (h == NULL) {
		cmn_err(CE_WARN, "nsc_ncio_allocb: NULL handle!");
		return (EIO);
	}

	if (FBA_SIZE(len) > NSC_NCIO_MAXDATA) {
		/* too large */
		return (ENXIO);
	}

	if ((blind_t)ncp == NSC_ANON_CD) {
		flag &= ~(NSC_READ | NSC_WRITE | NSC_RDAHEAD);
	}

	if (h->disc)
		(*h->disc)(h);

	h->bufh.sb_pos = pos;
	h->bufh.sb_len = len;
	h->bufh.sb_error = 0;
	h->bufh.sb_flag |= flag | NSC_HACTIVE;
	h->bufh.sb_vec = &h->vec[0];

	if (!((blind_t)ncp == NSC_ANON_CD)) {
		(void) strncpy(h->rw.rw_path, ncp->path,
		    sizeof (h->rw.rw_path));
		h->rw.rw_snode = ncp->snode;
	}

	h->vec[0].sv_len = FBA_SIZE(len);
	h->vec[0].sv_addr = (uchar_t *)&h->rw.rw_data[0];
	h->vec[0].sv_vme = 0;

	h->vec[1].sv_len = 0;
	h->vec[1].sv_addr = 0;
	h->vec[1].sv_vme = 0;

	if ((flag & NSC_RDAHEAD) || ((blind_t)ncp == NSC_ANON_CD))
		return (NSC_DONE);

	nsc_wait_ncio(h);

	if (flag & NSC_READ) {
		if ((rc = nsc_ncio_read(h, pos, len, flag)) != 0) {
			(void) nsc_ncio_freeb(h);
			return (rc);
		}
	}

	return (NSC_DONE);
}


static int
nsc_ncio_partsize(nsc_ncio_dev_t *ncp, nsc_size_t *rvalp)
{
	*rvalp = (nsc_size_t)ncp->partsize;
	return (0);
}


/* ARGSUSED */
static int
nsc_ncio_maxfbas(nsc_ncio_dev_t *ncp, int flag, nsc_size_t *ptr)
{
	if (flag == NSC_CACHEBLK)
		*ptr = 1;
	else
		*ptr = FBA_NUM(NSC_NCIO_MAXDATA);

	return (0);
}


static int
nsc_ncio_attach(nsc_ncio_dev_t *ncp)
{
	nsc_ncio_size_t *size;
	ncall_t *ncall;
	int sizeh, sizel;
	int rc, err;

	/* CONSTCOND */
	if (sizeof (*size) > NCALL_DATA_SZ) {
		/* CONSTCOND */
		ASSERT(sizeof (*size) <= NCALL_DATA_SZ);
		return (ENXIO);
	}

	size = kmem_zalloc(sizeof (*size), KM_SLEEP);
	(void) strncpy(size->path, ncp->path, sizeof (size->path));

	rc = ncall_alloc(ncp->snode, 0, 0, &ncall);
	if (rc != 0) {
		kmem_free(size, sizeof (*size));
		return (rc);
	}

	rc = ncall_put_data(ncall, size, sizeof (*size));
	kmem_free(size, sizeof (*size));
	size = NULL;
	if (rc != 0)
		return (rc);

	rc = ncall_send(ncall, 0, NSC_NCIO_PARTSIZE);
	if (rc != 0)
		return (0);

	rc = ncall_read_reply(ncall, 3, &err, &sizeh, &sizel);
	if (rc != 0 || err != 0)
		return (rc ? rc : err);

	ncall_free(ncall);

	ncp->partsize = (uint64_t)(((uint64_t)sizeh << 32) | (uint64_t)sizel);
	return (0);
}


static nsc_def_t nsc_ncio_def[] = {
	{ "Open",	(uintptr_t)nsc_ncio_open,	0 },
	{ "Close",	(uintptr_t)nsc_ncio_close,	0 },
	{ "Attach",	(uintptr_t)nsc_ncio_attach,	0 },
	{ "AllocHandle", (uintptr_t)nsc_ncio_alloch,	0 },
	{ "FreeHandle",	(uintptr_t)nsc_ncio_freeh,	0 },
	{ "AllocBuf",	(uintptr_t)nsc_ncio_allocb,	0 },
	{ "FreeBuf",	(uintptr_t)nsc_ncio_freeb,	0 },
	{ "Read",	(uintptr_t)nsc_ncio_read,	0 },
	{ "Write",	(uintptr_t)nsc_ncio_write,	0 },
	{ "Zero",	(uintptr_t)nsc_ncio_zero,	0 },
	{ "PartSize",	(uintptr_t)nsc_ncio_partsize,	0 },
	{ "MaxFbas",	(uintptr_t)nsc_ncio_maxfbas,	0 },
	{ "Provide",	NSC_NCALL,			0 },
	{ 0,		0,				0 }
};


/*
 * ncall-io io provider - server side.
 */

/* ARGSUSED1 */
static void
nsc_rncio_partsize(ncall_t *ncall, int *ap)
{
	nsc_ncio_size_t *size;
	nsc_size_t partsize;
	int sizeh, sizel;
	nsc_fd_t *fd;
	int rc;

	size = kmem_alloc(sizeof (*size), KM_SLEEP);
	rc = ncall_get_data(ncall, size, sizeof (*size));
	if (rc != 0) {
		ncall_reply(ncall, EFAULT, 0, 0);
		kmem_free(size, sizeof (*size));
		return;
	}

	fd = nsc_open(size->path, NSC_CACHE | NSC_DEVICE | NSC_READ,
	    NULL, NULL, &rc);
	kmem_free(size, sizeof (*size));
	size = NULL;
	if (fd == NULL) {
		ncall_reply(ncall, rc, 0, 0);
		return;
	}

	rc = nsc_reserve(fd, NSC_PCATCH);
	if (rc != 0) {
		(void) nsc_close(fd);
		ncall_reply(ncall, rc, 0, 0);
		return;
	}

	sizeh = sizel = 0;
	rc = nsc_partsize(fd, &partsize);
	sizel = (int)(partsize & 0xffffffff);
	/* CONSTCOND */
	if (sizeof (nsc_size_t) > sizeof (int)) {
		sizeh = (int)((partsize & 0xffffffff00000000) >> 32);
	}

	nsc_release(fd);
	(void) nsc_close(fd);

	ncall_reply(ncall, rc, sizeh, sizel);
}


static int
nsc_rncio_copy(char *data, nsc_buf_t *bufp, const int read)
{
	nsc_vec_t *vec;
	char *datap;
	uint64_t tocopy;	/* bytes */
	int thischunk;		/* bytes */
	int rc;

	rc = 0;
	datap = data;
	vec = bufp->sb_vec;

	tocopy = FBA_SIZE(bufp->sb_len);

	while (tocopy > 0) {
		if (vec->sv_len == 0 || vec->sv_addr == 0) {
			rc = ENOSPC;
			break;
		}

		thischunk = (int)min((nsc_size_t)vec->sv_len, tocopy);

		if (read) {
			bcopy(vec->sv_addr, datap, thischunk);
		} else {
			bcopy(datap, vec->sv_addr, thischunk);
		}

		tocopy -= thischunk;
		if (thischunk == vec->sv_len)
			vec++;
	}

	return (rc);
}


/* ARGSUSED */
static void
nsc_rncio_io(ncall_t *ncall, int *ap, const int read)
{
	nsc_ncio_rw_t *rw;
	nsc_buf_t *bufp;
	nsc_fd_t *fd;
	nsc_size_t len;
	nsc_off_t pos;
	int ioflag;
	int rc;

	rw = kmem_alloc(sizeof (*rw), KM_SLEEP);
	rc = ncall_get_data(ncall, rw, sizeof (*rw));
	if (rc != 0) {
		ncall_reply(ncall, EFAULT);
		kmem_free(rw, sizeof (*rw));
		return;
	}

	ioflag = (read ? NSC_READ : NSC_WRITE);
	pos = (nsc_off_t)rw->rw_pos;
	len = (nsc_size_t)rw->rw_len;

	fd = nsc_open(rw->rw_path, NSC_CACHE | NSC_DEVICE | NSC_READ | ioflag,
	    NULL, NULL, &rc);
	if (fd == NULL) {
		ncall_reply(ncall, rc);
		kmem_free(rw, sizeof (*rw));
		return;
	}

	rc = nsc_reserve(fd, NSC_PCATCH);
	if (rc != 0) {
		ncall_reply(ncall, rc);
		(void) nsc_close(fd);
		kmem_free(rw, sizeof (*rw));
		return;
	}

	bufp = NULL;
	rc = nsc_alloc_buf(fd, pos, len, NSC_NOCACHE | ioflag, &bufp);
	if (rc > 0) {
		ncall_reply(ncall, rc);
		if (bufp != NULL) {
			(void) nsc_free_buf(bufp);
		}
		nsc_release(fd);
		(void) nsc_close(fd);
		kmem_free(rw, sizeof (*rw));
		return;
	}

	rc = nsc_rncio_copy(&rw->rw_data[0], bufp, read);
	if (rc == 0) {
		if (read) {
			/* store reply data */
			rc = ncall_put_data(ncall, rw, sizeof (*rw));
		} else {
			/* write new data */
			rc = nsc_write(bufp, pos, len, 0);
		}
	}

	ncall_reply(ncall, rc);

	(void) nsc_free_buf(bufp);
	nsc_release(fd);
	(void) nsc_close(fd);
	kmem_free(rw, sizeof (*rw));
}


static void
nsc_rncio_read(ncall_t *ncall, int *ap)
{
	nsc_rncio_io(ncall, ap, TRUE);
}


static void
nsc_rncio_write(ncall_t *ncall, int *ap)
{
	nsc_rncio_io(ncall, ap, FALSE);
}


/*
 * ncall-io io provider - setup.
 */

void
_nsc_init_ncio(void)
{
	mutex_init(&nsc_ncio_lock, NULL, MUTEX_DRIVER, NULL);

	ncall_register_svc(NSC_NCIO_PARTSIZE, nsc_rncio_partsize);
	ncall_register_svc(NSC_NCIO_WRITE, nsc_rncio_write);
	ncall_register_svc(NSC_NCIO_READ, nsc_rncio_read);

	nsc_ncio_io = nsc_register_io("ncall-io",
	    NSC_NCALL_ID | NSC_REFCNT, nsc_ncio_def);

	if (!nsc_ncio_io)
		cmn_err(CE_WARN, "_nsc_ncio_init: register io failed - ncall");
}


void
_nsc_deinit_ncio(void)
{
	if (nsc_ncio_io)
		(void) nsc_unregister_io(nsc_ncio_io, 0);

	ncall_unregister_svc(NSC_NCIO_PARTSIZE);
	ncall_unregister_svc(NSC_NCIO_WRITE);
	ncall_unregister_svc(NSC_NCIO_READ);

	nsc_ncio_io = NULL;
	mutex_destroy(&nsc_ncio_lock);
}
