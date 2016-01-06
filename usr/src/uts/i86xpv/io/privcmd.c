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

#include <sys/xpv_user.h>

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/vmsystm.h>
#include <sys/sdt.h>
#include <sys/hypervisor.h>
#include <sys/xen_errno.h>
#include <sys/policy.h>

#include <vm/hat_i86.h>
#include <vm/hat_pte.h>
#include <vm/seg_mf.h>

#include <xen/sys/privcmd.h>
#include <sys/privcmd_impl.h>

static dev_info_t *privcmd_devi;

/*ARGSUSED*/
static int
privcmd_getinfo(dev_info_t *devi, ddi_info_cmd_t cmd, void *arg, void **result)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
	case DDI_INFO_DEVT2INSTANCE:
		break;
	default:
		return (DDI_FAILURE);
	}

	switch (getminor((dev_t)arg)) {
	case PRIVCMD_MINOR:
		break;
	default:
		return (DDI_FAILURE);
	}

	if (cmd == DDI_INFO_DEVT2INSTANCE)
		*result = 0;
	else
		*result = privcmd_devi;
	return (DDI_SUCCESS);
}

static int
privcmd_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(devi, PRIVCMD_NODE,
	    S_IFCHR, PRIVCMD_MINOR, DDI_PSEUDO, 0) != DDI_SUCCESS)
		return (DDI_FAILURE);

	privcmd_devi = devi;
	ddi_report_dev(devi);
	return (DDI_SUCCESS);
}

static int
privcmd_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);
	ddi_remove_minor_node(devi, NULL);
	privcmd_devi = NULL;
	return (DDI_SUCCESS);
}

/*ARGSUSED1*/
static int
privcmd_open(dev_t *dev, int flag, int otyp, cred_t *cr)
{
	return (getminor(*dev) == PRIVCMD_MINOR ? 0 : ENXIO);
}

/*
 * Map a contiguous set of machine frames in a foreign domain.
 * Used in the following way:
 *
 *	privcmd_mmap_t p;
 *	privcmd_mmap_entry_t e;
 *
 *	addr = mmap(NULL, size, prot, MAP_SHARED, fd, 0);
 *	p.num = number of privcmd_mmap_entry_t's
 *	p.dom = domid;
 *	p.entry = &e;
 *	e.va = addr;
 *	e.mfn = mfn;
 *	e.npages = btopr(size);
 *	ioctl(fd, IOCTL_PRIVCMD_MMAP, &p);
 */
/*ARGSUSED2*/
int
do_privcmd_mmap(void *uarg, int mode, cred_t *cr)
{
	privcmd_mmap_t __mmapcmd, *mmc = &__mmapcmd;
	privcmd_mmap_entry_t *umme;
	struct as *as = curproc->p_as;
	struct seg *seg;
	int i, error = 0;

	if (ddi_copyin(uarg, mmc, sizeof (*mmc), mode))
		return (EFAULT);

	DTRACE_XPV3(mmap__start, domid_t, mmc->dom, int, mmc->num,
	    privcmd_mmap_entry_t *, mmc->entry);

	if (mmc->dom == DOMID_SELF) {
		error = ENOTSUP;	/* Too paranoid? */
		goto done;
	}

	for (umme = mmc->entry, i = 0; i < mmc->num; i++, umme++) {
		privcmd_mmap_entry_t __mmapent, *mme = &__mmapent;
		caddr_t addr;

		if (ddi_copyin(umme, mme, sizeof (*mme), mode)) {
			error = EFAULT;
			break;
		}

		DTRACE_XPV3(mmap__entry, ulong_t, mme->va, ulong_t, mme->mfn,
		    ulong_t, mme->npages);

		if (mme->mfn == MFN_INVALID) {
			error = EINVAL;
			break;
		}

		addr = (caddr_t)mme->va;

		/*
		 * Find the segment we want to mess with, then add
		 * the mfn range to the segment.
		 */
		AS_LOCK_ENTER(as, RW_READER);
		if ((seg = as_findseg(as, addr, 0)) == NULL ||
		    addr + mmu_ptob(mme->npages) > seg->s_base + seg->s_size)
			error = EINVAL;
		else
			error = segmf_add_mfns(seg, addr,
			    mme->mfn, mme->npages, mmc->dom);
		AS_LOCK_EXIT(as);

		if (error != 0)
			break;
	}

done:
	DTRACE_XPV1(mmap__end, int, error);

	return (error);
}

/*
 * Set up the address range to map to an array of mfns in
 * a foreign domain.  Used in the following way:
 *
 *	privcmd_mmap_batch_t p;
 *
 *	addr = mmap(NULL, size, prot, MAP_SHARED, fd, 0);
 *	p.num = number of pages
 *	p.dom = domid
 *	p.addr = addr;
 *	p.arr = array of mfns, indexed 0 .. p.num - 1
 *	ioctl(fd, IOCTL_PRIVCMD_MMAPBATCH, &p);
 */
/*ARGSUSED2*/
static int
do_privcmd_mmapbatch(void *uarg, int mode, cred_t *cr)
{
	privcmd_mmapbatch_t __mmapbatch, *mmb = &__mmapbatch;
	struct as *as = curproc->p_as;
	struct seg *seg;
	int i, error = 0;
	caddr_t addr;
	ulong_t *ulp;

	if (ddi_copyin(uarg, mmb, sizeof (*mmb), mode))
		return (EFAULT);

	DTRACE_XPV3(mmapbatch__start, domid_t, mmb->dom, int, mmb->num,
	    caddr_t, mmb->addr);

	addr = (caddr_t)mmb->addr;
	AS_LOCK_ENTER(as, RW_READER);
	if ((seg = as_findseg(as, addr, 0)) == NULL ||
	    addr + ptob(mmb->num) > seg->s_base + seg->s_size) {
		error = EINVAL;
		goto done;
	}

	for (i = 0, ulp = mmb->arr;
	    i < mmb->num; i++, addr += PAGESIZE, ulp++) {
		mfn_t mfn;

		if (fulword(ulp, &mfn) != 0) {
			error = EFAULT;
			break;
		}

		if (mfn == MFN_INVALID) {
			/*
			 * This mfn is invalid and should not be added to
			 * segmf, as we'd only cause an immediate EFAULT when
			 * we tried to fault it in.
			 */
			mfn |= XEN_DOMCTL_PFINFO_XTAB;
			continue;
		}

		if (segmf_add_mfns(seg, addr, mfn, 1, mmb->dom) == 0)
			continue;

		/*
		 * Tell the process that this MFN could not be mapped, so it
		 * won't later try to access it.
		 */
		mfn |= XEN_DOMCTL_PFINFO_XTAB;
		if (sulword(ulp, mfn) != 0) {
			error = EFAULT;
			break;
		}
	}

done:
	AS_LOCK_EXIT(as);

	DTRACE_XPV3(mmapbatch__end, int, error, struct seg *, seg, caddr_t,
	    mmb->addr);

	return (error);
}

/*ARGSUSED*/
static int
privcmd_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cr, int *rval)
{
	if (secpolicy_xvm_control(cr))
		return (EPERM);

	/*
	 * Everything is a -native- data type.
	 */
	if ((mode & FMODELS) != FNATIVE)
		return (EOVERFLOW);

	switch (cmd) {
	case IOCTL_PRIVCMD_HYPERCALL:
		return (do_privcmd_hypercall((void *)arg, mode, cr, rval));
	case IOCTL_PRIVCMD_MMAP:
		if (DOMAIN_IS_PRIVILEGED(xen_info))
			return (do_privcmd_mmap((void *)arg, mode, cr));
		break;
	case IOCTL_PRIVCMD_MMAPBATCH:
		if (DOMAIN_IS_PRIVILEGED(xen_info))
			return (do_privcmd_mmapbatch((void *)arg, mode, cr));
		break;
	default:
		break;
	}
	return (EINVAL);
}

/*
 * The real magic happens in the segmf segment driver.
 */
/*ARGSUSED8*/
static int
privcmd_segmap(dev_t dev, off_t off, struct as *as, caddr_t *addrp,
    off_t len, uint_t prot, uint_t maxprot, uint_t flags, cred_t *cr)
{
	struct segmf_crargs a;
	int error;

	if (secpolicy_xvm_control(cr))
		return (EPERM);

	as_rangelock(as);
	if ((flags & MAP_FIXED) == 0) {
		map_addr(addrp, len, (offset_t)off, 0, flags);
		if (*addrp == NULL) {
			error = ENOMEM;
			goto rangeunlock;
		}
	} else {
		/*
		 * User specified address
		 */
		(void) as_unmap(as, *addrp, len);
	}

	/*
	 * The mapping *must* be MAP_SHARED at offset 0.
	 *
	 * (Foreign pages are treated like device memory; the
	 * ioctl interface allows the backing objects to be
	 * arbitrarily redefined to point at any machine frame.)
	 */
	if ((flags & MAP_TYPE) != MAP_SHARED || off != 0) {
		error = EINVAL;
		goto rangeunlock;
	}

	a.dev = dev;
	a.prot = (uchar_t)prot;
	a.maxprot = (uchar_t)maxprot;
	error = as_map(as, *addrp, len, segmf_create, &a);

rangeunlock:
	as_rangeunlock(as);
	return (error);
}

static struct cb_ops privcmd_cb_ops = {
	privcmd_open,
	nulldev,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	privcmd_ioctl,
	nodev,		/* devmap */
	nodev,		/* mmap */
	privcmd_segmap,
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_64BIT | D_NEW | D_MP
};

static struct dev_ops privcmd_dv_ops = {
	DEVO_REV,
	0,
	privcmd_getinfo,
	nulldev,		/* identify */
	nulldev,		/* probe */
	privcmd_attach,
	privcmd_detach,
	nodev,			/* reset */
	&privcmd_cb_ops,
	0,			/* struct bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"privcmd driver",
	&privcmd_dv_ops
};

static struct modlinkage modl = {
	MODREV_1,
	&modldrv
};

int
_init(void)
{
	return (mod_install(&modl));
}

int
_fini(void)
{
	return (mod_remove(&modl));
}

int
_info(struct modinfo *modinfo)
{
	return (mod_info(&modl, modinfo));
}
