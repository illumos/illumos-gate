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
 * smbios(7D) driver
 *
 * This pseudo-driver makes available a snapshot of the system's SMBIOS image
 * that can be accessed using libsmbios.  Clients may access a snapshot using
 * either read(2) or mmap(2).  The driver returns the SMBIOS entry point data
 * followed by the SMBIOS structure table.  The entry point has its 'staddr'
 * field set to indicate the byte offset of the structure table.  The driver
 * uses the common SMBIOS API defined in <sys/smbios.h> to access the image.
 *
 * At present, the kernel takes a single snapshot of SMBIOS at boot time and
 * stores a handle for this snapshot in 'ksmbios'.  To keep track of driver
 * opens, we simply compare-and-swap this handle into an 'smb_clones' array.
 * Future x86 systems may need to support dynamic SMBIOS updates: when that
 * happens the SMBIOS API can be extended to support reference counting and
 * handles for different snapshots can be stored in smb_clones[].
 */

#include <sys/smbios.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/vmsystm.h>
#include <vm/seg_vn.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/stat.h>

typedef struct smb_clone {
	smbios_hdl_t *c_hdl;
	size_t c_eplen;
	size_t c_stlen;
} smb_clone_t;

static dev_info_t *smb_devi;
static smb_clone_t *smb_clones;
static int smb_nclones;

/*ARGSUSED*/
static int
smb_open(dev_t *dp, int flag, int otyp, cred_t *cred)
{
	minor_t c;

	if (ksmbios == NULL)
		return (ENXIO);

	/*
	 * Locate and reserve a clone structure.  We skip clone 0 as that is
	 * the real minor number, and we assign a new minor to each clone.
	 */
	for (c = 1; c < smb_nclones; c++) {
		if (atomic_cas_ptr(&smb_clones[c].c_hdl, NULL, ksmbios) == NULL)
			break;
	}

	if (c >= smb_nclones)
		return (EAGAIN);

	smb_clones[c].c_eplen = P2ROUNDUP(sizeof (smbios_entry_t), 16);
	smb_clones[c].c_stlen = smbios_buflen(smb_clones[c].c_hdl);

	*dp = makedevice(getemajor(*dp), c);

	(void) ddi_prop_update_int(*dp, smb_devi, "size",
	    smb_clones[c].c_eplen + smb_clones[c].c_stlen);

	return (0);
}

/*ARGSUSED*/
static int
smb_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	(void) ddi_prop_remove(dev, smb_devi, "size");
	smb_clones[getminor(dev)].c_hdl = NULL;
	return (0);
}

/*
 * Common code to copy out the SMBIOS snapshot used for both read and mmap.
 * The caller must validate uio_offset for us since semantics differ there.
 * The copy is done in two stages, either of which can be skipped based on the
 * offset and length: first we copy the entry point, with 'staddr' recalculated
 * to indicate the offset of the data buffer, and second we copy the table.
 */
static int
smb_uiomove(smb_clone_t *cp, uio_t *uio)
{
	off_t off = uio->uio_offset;
	size_t len = uio->uio_resid;
	int err = 0;

	if (off + len > cp->c_eplen + cp->c_stlen)
		len = cp->c_eplen + cp->c_stlen - off;

	if (off < cp->c_eplen) {
		smbios_entry_t *ep = kmem_zalloc(cp->c_eplen, KM_SLEEP);
		size_t eprlen = MIN(len, cp->c_eplen - off);

		switch (smbios_info_smbios(cp->c_hdl, ep)) {
		case SMBIOS_ENTRY_POINT_21:
			ep->ep21.smbe_staddr = (uint32_t)cp->c_eplen;
			break;
		case SMBIOS_ENTRY_POINT_30:
			ep->ep30.smbe_staddr = (uint64_t)cp->c_eplen;
			break;
		}
		smbios_checksum(cp->c_hdl, ep);

		err = uiomove((char *)ep + off, eprlen, UIO_READ, uio);
		kmem_free(ep, cp->c_eplen);

		off += eprlen;
		len -= eprlen;
	}

	if (err == 0 && off >= cp->c_eplen) {
		char *buf = (char *)smbios_buf(cp->c_hdl);
		size_t bufoff = off - cp->c_eplen;

		err = uiomove(buf + bufoff,
		    MIN(len, cp->c_stlen - bufoff), UIO_READ, uio);
	}

	return (err);
}

/*ARGSUSED*/
static int
smb_read(dev_t dev, uio_t *uio, cred_t *cred)
{
	smb_clone_t *cp = &smb_clones[getminor(dev)];

	if (uio->uio_offset < 0 ||
	    uio->uio_offset >= cp->c_eplen + cp->c_stlen)
		return (0);

	return (smb_uiomove(cp, uio));
}

/*ARGSUSED*/
static int
smb_segmap(dev_t dev, off_t off, struct as *as, caddr_t *addrp, off_t len,
    uint_t prot, uint_t maxprot, uint_t flags, cred_t *cred)
{
	smb_clone_t *cp = &smb_clones[getminor(dev)];

	size_t alen = P2ROUNDUP(len, PAGESIZE);
	caddr_t addr = NULL;

	iovec_t iov;
	uio_t uio;
	int err;

	if (len <= 0 || (flags & MAP_FIXED))
		return (EINVAL);

	if ((prot & PROT_WRITE) && (flags & MAP_SHARED))
		return (EACCES);

	if (off < 0 || off + len < off || off + len > cp->c_eplen + cp->c_stlen)
		return (ENXIO);

	as_rangelock(as);
	map_addr(&addr, alen, 0, 1, 0);

	if (addr != NULL)
		err = as_map(as, addr, alen, segvn_create, zfod_argsp);
	else
		err = ENOMEM;

	as_rangeunlock(as);
	*addrp = addr;

	if (err != 0)
		return (err);

	iov.iov_base = addr;
	iov.iov_len = len;

	bzero(&uio, sizeof (uio_t));
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = off;
	uio.uio_segflg = UIO_USERSPACE;
	uio.uio_extflg = UIO_COPY_DEFAULT;
	uio.uio_resid = len;

	if ((err = smb_uiomove(cp, &uio)) != 0)
		(void) as_unmap(as, addr, alen);

	return (err);
}

/*ARGSUSED*/
static int
smb_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = smb_devi;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
smb_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(devi, "smbios",
	    S_IFCHR, 0, DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}

	smb_devi = devi;
	return (DDI_SUCCESS);
}

static int
smb_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ddi_remove_minor_node(devi, NULL);
	return (DDI_SUCCESS);
}

static struct cb_ops smb_cb_ops = {
	smb_open,		/* open */
	smb_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	smb_read,		/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	smb_segmap,		/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* streamtab */
	D_NEW | D_MP		/* flags */
};

static struct dev_ops smb_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	smb_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	smb_attach,		/* attach */
	smb_detach,		/* detach */
	nodev,			/* reset */
	&smb_cb_ops,		/* cb ops */
	NULL,			/* bus ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, "System Management BIOS driver", &smb_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, { (void *)&modldrv }
};

int
_init(void)
{
	int err;

	if (smb_nclones <= 0)
		smb_nclones = maxusers;

	smb_clones = kmem_zalloc(sizeof (smb_clone_t) * smb_nclones, KM_SLEEP);

	if ((err = mod_install(&modlinkage)) != 0)
		kmem_free(smb_clones, sizeof (smb_clone_t) * smb_nclones);

	return (err);
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) == 0)
		kmem_free(smb_clones, sizeof (smb_clone_t) * smb_nclones);

	return (err);
}

int
_info(struct modinfo *mip)
{
	return (mod_info(&modlinkage, mip));
}
