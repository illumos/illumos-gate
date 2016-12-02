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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/buf.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/signal.h>
#include <vm/page.h>
#include <vm/as.h>
#include <vm/hat.h>
#include <vm/seg.h>
#include <vm/seg_dev.h>
#include <vm/hat_i86.h>
#include <sys/ddi.h>
#include <sys/devops.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/fs/snode.h>
#include <sys/pci.h>
#include <sys/vmsystm.h>
#include <sys/int_fmtio.h>
#include <sys/gfx_private.h>

#ifdef __xpv
#include <sys/hypervisor.h>
#endif

/*
 * Create a dummy ddi_umem_cookie given to gfxp_devmap_umem_setup().
 */
ddi_umem_cookie_t
gfxp_umem_cookie_init(caddr_t kva, size_t size)
{
	struct ddi_umem_cookie *umem_cookie;

	umem_cookie = kmem_zalloc(sizeof (struct ddi_umem_cookie), KM_SLEEP);

	if (umem_cookie == NULL)
		return (NULL);

	umem_cookie->cvaddr = kva;
	umem_cookie->type = KMEM_NON_PAGEABLE;
	umem_cookie->size = size;

	return ((ddi_umem_cookie_t)umem_cookie);
}

void
gfxp_umem_cookie_destroy(ddi_umem_cookie_t cookie)
{
	kmem_free(cookie, sizeof (struct ddi_umem_cookie));
}

/*
 * called by driver devmap routine to pass kernel virtual address mapping
 * info to the framework.
 */
/*ARGSUSED*/
int
gfxp_devmap_umem_setup(devmap_cookie_t dhc, dev_info_t *dip,
    struct devmap_callback_ctl *callbackops, ddi_umem_cookie_t cookie,
    offset_t off, size_t len, uint_t maxprot, uint_t flags,
    ddi_device_acc_attr_t *accattrp)
{
	uint_t l_flags = flags & ~IOMEM_DATA_MASK; /* clear cache attrs */
	int e;

	/*
	 * Set an appropriate attribute from devacc_attr_dataorder
	 * to keep compatibility. The cache attributes are igonred
	 * if specified.
	 */
	if (accattrp != NULL) {
		if (accattrp->devacc_attr_dataorder == DDI_STRICTORDER_ACC) {
			l_flags |= IOMEM_DATA_UNCACHED;
		} else if (accattrp->devacc_attr_dataorder ==
		    DDI_MERGING_OK_ACC) {
			l_flags |= IOMEM_DATA_UC_WR_COMBINE;
		} else {
			l_flags |= IOMEM_DATA_CACHED;
		}
	}

	e = devmap_umem_setup(dhc, dip, callbackops, cookie, off, len, maxprot,
	    l_flags, accattrp);
	return (e);
}

/*
 * Replacement for devmap_devmem_setup() which will map a machine address
 * instead of a register set/offset.
 */
void
gfxp_map_devmem(devmap_cookie_t dhc, gfx_maddr_t maddr, size_t length,
    ddi_device_acc_attr_t *attrp)
{
	devmap_handle_t *dhp = (devmap_handle_t *)dhc;
	pfn_t pfn;


#ifdef __xpv
	ASSERT(DOMAIN_IS_INITDOMAIN(xen_info));
	pfn = xen_assign_pfn(mmu_btop(maddr));
#else
	pfn = mmu_btop(maddr);
#endif

	dhp->dh_pfn = pfn;
	dhp->dh_len = mmu_ptob(mmu_btopr(length));
	dhp->dh_roff = 0;

#ifndef DEVMAP_DEVMEM_COOKIE
#define	DEVMAP_DEVMEM_COOKIE	((ddi_umem_cookie_t)0x1) /* XXPV */
#endif /* DEVMAP_DEVMEM_COOKIE */
	dhp->dh_cookie = DEVMAP_DEVMEM_COOKIE;
	/*LINTED: E_EXPR_NULL_EFFECT*/
	dhp->dh_flags |= DEVMAP_DEFAULTS;
	dhp->dh_maxprot = PROT_ALL & dhp->dh_orig_maxprot;

	/* no callbacks needed */
	bzero(&dhp->dh_callbackops, sizeof (struct devmap_callback_ctl));

	switch (attrp->devacc_attr_dataorder) {
	case DDI_UNORDERED_OK_ACC:
		dhp->dh_hat_attr = HAT_UNORDERED_OK;
		break;
	case DDI_MERGING_OK_ACC:
		dhp->dh_hat_attr = HAT_MERGING_OK;
		break;
	case DDI_LOADCACHING_OK_ACC:
		dhp->dh_hat_attr = HAT_LOADCACHING_OK;
		break;
	case DDI_STORECACHING_OK_ACC:
		dhp->dh_hat_attr = HAT_STORECACHING_OK;
		break;
	case DDI_STRICTORDER_ACC:
	default:
		dhp->dh_hat_attr = HAT_STRICTORDER;
	}

	/* don't use large pages */
	dhp->dh_mmulevel = 0;
	dhp->dh_flags &= ~DEVMAP_FLAG_LARGE;

	dhp->dh_flags |= DEVMAP_SETUP_DONE;
}
