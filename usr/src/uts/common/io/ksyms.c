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


/*
 * ksyms driver - exports a single symbol/string table for the kernel
 * by concatenating all the module symbol/string tables.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/uio.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/kobj.h>
#include <sys/ksyms.h>
#include <sys/vmsystm.h>
#include <vm/seg_vn.h>
#include <sys/atomic.h>
#include <sys/compress.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/list.h>

typedef struct ksyms_image {
	caddr_t	ksyms_base;	/* base address of image */
	size_t	ksyms_size;	/* size of image */
} ksyms_image_t;

typedef struct ksyms_buflist {
	list_node_t	buflist_node;
	char buf[1];
} ksyms_buflist_t;

typedef struct ksyms_buflist_hdr {
	list_t 	blist;
	int	nchunks;
	ksyms_buflist_t *cur;
	size_t	curbuf_off;
} ksyms_buflist_hdr_t;

#define	BUF_SIZE	(PAGESIZE - (size_t)offsetof(ksyms_buflist_t, buf))

int nksyms_clones;		/* tunable: max clones of this device */

static ksyms_image_t *ksyms_clones;	/* clone device array */
static dev_info_t *ksyms_devi;

static void
ksyms_bcopy(const void *srcptr, void *ptr, size_t rsize)
{

	size_t sz;
	const char *src = (const char *)srcptr;
	ksyms_buflist_hdr_t *hptr = (ksyms_buflist_hdr_t *)ptr;

	if (hptr->cur == NULL)
		return;

	while (rsize) {
		sz = MIN(rsize, (BUF_SIZE - hptr->curbuf_off));
		bcopy(src, (hptr->cur->buf + hptr->curbuf_off), sz);

		hptr->curbuf_off += sz;
		if (hptr->curbuf_off == BUF_SIZE) {
			hptr->curbuf_off = 0;
			hptr->cur = list_next(&hptr->blist, hptr->cur);
			if (hptr->cur == NULL)
				break;
		}
		src += sz;
		rsize -= sz;
	}
}

static void
ksyms_buflist_free(ksyms_buflist_hdr_t *hdr)
{
	ksyms_buflist_t *list;

	while (list = list_head(&hdr->blist)) {
		list_remove(&hdr->blist, list);
		kmem_free(list, PAGESIZE);
	}
	list_destroy(&hdr->blist);
	hdr->cur = NULL;
}


/*
 * Allocate 'size'(rounded to BUF_SIZE) bytes in chunks of BUF_SIZE, and
 * add it to the buf list.
 * Returns the total size rounded to BUF_SIZE.
 */
static size_t
ksyms_buflist_alloc(ksyms_buflist_hdr_t *hdr, size_t size)
{
	int chunks, i;
	ksyms_buflist_t *list;

	chunks = howmany(size, BUF_SIZE);

	if (hdr->nchunks >= chunks)
		return (hdr->nchunks * BUF_SIZE);

	/*
	 * Allocate chunks - hdr->nchunks buffers and add them to
	 * the list.
	 */
	for (i = chunks - hdr->nchunks; i > 0; i--) {

		if ((list = kmem_alloc(PAGESIZE, KM_NOSLEEP)) == NULL)
			break;

		list_insert_tail(&hdr->blist, list);
	}

	/*
	 * If we are running short of memory, free memory allocated till now
	 * and return.
	 */
	if (i > 0) {
		ksyms_buflist_free(hdr);
		return (0);
	}

	hdr->nchunks = chunks;
	hdr->cur = list_head(&hdr->blist);
	hdr->curbuf_off = 0;

	return (chunks * BUF_SIZE);
}

/*
 * rlen is in multiples of PAGESIZE
 */
static char *
ksyms_asmap(struct as *as, size_t rlen)
{
	char *addr = NULL;

	as_rangelock(as);
	map_addr(&addr, rlen, 0, 1, 0);
	if (addr == NULL || as_map(as, addr, rlen, segvn_create, zfod_argsp)) {
		as_rangeunlock(as);
		return (NULL);
	}
	as_rangeunlock(as);
	return (addr);
}

static char *
ksyms_mapin(ksyms_buflist_hdr_t *hdr, size_t size)
{
	size_t sz, rlen = roundup(size, PAGESIZE);
	struct as *as = curproc->p_as;
	char *addr, *raddr;
	ksyms_buflist_t *list = list_head(&hdr->blist);

	if ((addr = ksyms_asmap(as, rlen)) == NULL)
		return (NULL);

	raddr = addr;
	while (size > 0 && list != NULL) {
		sz = MIN(size, BUF_SIZE);

		if (copyout(list->buf, raddr, sz)) {
			(void) as_unmap(as, addr, rlen);
			return (NULL);
		}
		list = list_next(&hdr->blist, list);
		raddr += sz;
		size -= sz;
	}
	return (addr);
}

/*
 * Copy a snapshot of the kernel symbol table into the user's address space.
 * The symbol table is copied in fragments so that we do not have to
 * do a large kmem_alloc() which could fail/block if the kernel memory is
 * fragmented.
 */
/* ARGSUSED */
static int
ksyms_open(dev_t *devp, int flag, int otyp, struct cred *cred)
{
	minor_t clone;
	size_t size = 0;
	size_t realsize;
	char *addr;
	void *hptr = NULL;
	ksyms_buflist_hdr_t hdr;
	bzero(&hdr, sizeof (struct ksyms_buflist_hdr));
	list_create(&hdr.blist, PAGESIZE,
	    offsetof(ksyms_buflist_t, buflist_node));

	if (getminor(*devp) != 0)
		return (ENXIO);

	for (;;) {
		realsize = ksyms_snapshot(ksyms_bcopy, hptr, size);
		if (realsize <= size)
			break;
		size = realsize;
		size = ksyms_buflist_alloc(&hdr, size);
		if (size == 0)
			return (ENOMEM);
		hptr = (void *)&hdr;
	}

	addr = ksyms_mapin(&hdr, realsize);
	ksyms_buflist_free(&hdr);
	if (addr == NULL)
		return (EOVERFLOW);

	/*
	 * Reserve a clone entry.  Note that we don't use clone 0
	 * since that's the "real" minor number.
	 */
	for (clone = 1; clone < nksyms_clones; clone++) {
		if (atomic_cas_ptr(&ksyms_clones[clone].ksyms_base, 0, addr) ==
		    0) {
			ksyms_clones[clone].ksyms_size = realsize;
			*devp = makedevice(getemajor(*devp), clone);
			(void) ddi_prop_update_int(*devp, ksyms_devi,
			    "size", realsize);
			modunload_disable();
			return (0);
		}
	}
	cmn_err(CE_NOTE, "ksyms: too many open references");
	(void) as_unmap(curproc->p_as, addr, roundup(realsize, PAGESIZE));
	return (ENXIO);
}

/* ARGSUSED */
static int
ksyms_close(dev_t dev, int flag, int otyp, struct cred *cred)
{
	minor_t clone = getminor(dev);

	(void) as_unmap(curproc->p_as, ksyms_clones[clone].ksyms_base,
	    roundup(ksyms_clones[clone].ksyms_size, PAGESIZE));
	ksyms_clones[clone].ksyms_base = 0;
	modunload_enable();
	(void) ddi_prop_remove(dev, ksyms_devi, "size");
	return (0);
}

static int
ksyms_symtbl_copy(ksyms_image_t *kip, struct uio *uio, size_t len)
{
	char *buf;
	int error = 0;
	caddr_t base;
	off_t off = uio->uio_offset;
	size_t size;

	/*
	 * The symbol table is stored in the user address space,
	 * so we have to copy it into the kernel first,
	 * then copy it back out to the specified user address.
	 */
	buf = kmem_alloc(PAGESIZE, KM_SLEEP);
	base = kip->ksyms_base + off;
	while (len) {
		size = MIN(PAGESIZE, len);
		if (copyin(base, buf, size))
			error = EFAULT;
		else
			error = uiomove(buf, size, UIO_READ, uio);

		if (error)
			break;

		len -= size;
		base += size;
	}
	kmem_free(buf, PAGESIZE);
	return (error);
}

/* ARGSUSED */
static int
ksyms_read(dev_t dev, struct uio *uio, struct cred *cred)
{
	ksyms_image_t *kip = &ksyms_clones[getminor(dev)];
	off_t off = uio->uio_offset;
	size_t len = uio->uio_resid;

	if (off < 0 || off > kip->ksyms_size)
		return (EFAULT);

	if (len > kip->ksyms_size - off)
		len = kip->ksyms_size - off;

	if (len == 0)
		return (0);

	return (ksyms_symtbl_copy(kip, uio, len));
}

/* ARGSUSED */
static int
ksyms_segmap(dev_t dev, off_t off, struct as *as, caddr_t *addrp, off_t len,
    uint_t prot, uint_t maxprot, uint_t flags, struct cred *cred)
{
	ksyms_image_t *kip = &ksyms_clones[getminor(dev)];
	int error = 0;
	char *addr = NULL;
	size_t rlen = 0;
	struct iovec aiov;
	struct uio auio;

	if (flags & MAP_FIXED)
		return (ENOTSUP);

	if (off < 0 || len <= 0 || off > kip->ksyms_size ||
	    len > kip->ksyms_size - off)
		return (EINVAL);

	rlen = roundup(len, PAGESIZE);
	if ((addr = ksyms_asmap(as, rlen)) == NULL)
		return (EOVERFLOW);

	aiov.iov_base = addr;
	aiov.iov_len = len;
	auio.uio_offset = off;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = len;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = FREAD;
	auio.uio_extflg = UIO_COPY_CACHED;

	error = ksyms_symtbl_copy(kip, &auio, len);

	if (error)
		(void) as_unmap(as, addr, rlen);
	else
		*addrp = addr;
	return (error);
}

/* ARGSUSED */
static int
ksyms_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = ksyms_devi;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
ksyms_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);
	if (ddi_create_minor_node(devi, "ksyms", S_IFCHR, 0, DDI_PSEUDO, NULL)
	    == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}
	ksyms_devi = devi;
	return (DDI_SUCCESS);
}

static int
ksyms_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);
	ddi_remove_minor_node(devi, NULL);
	return (DDI_SUCCESS);
}

static struct cb_ops ksyms_cb_ops = {
	ksyms_open,		/* open */
	ksyms_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	ksyms_read,		/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	ksyms_segmap,		/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */
};

static struct dev_ops ksyms_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	ksyms_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	ksyms_attach,		/* attach */
	ksyms_detach,		/* detach */
	nodev,			/* reset */
	&ksyms_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* no bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, "kernel symbols driver", &ksyms_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, { (void *)&modldrv }
};

int
_init(void)
{
	int error;

	if (nksyms_clones == 0)
		nksyms_clones = maxusers + 50;

	ksyms_clones = kmem_zalloc(nksyms_clones *
	    sizeof (ksyms_image_t), KM_SLEEP);

	if ((error = mod_install(&modlinkage)) != 0)
		kmem_free(ksyms_clones, nksyms_clones * sizeof (ksyms_image_t));

	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) == 0)
		kmem_free(ksyms_clones, nksyms_clones * sizeof (ksyms_image_t));
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
