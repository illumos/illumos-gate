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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include "gfx_private.h"

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

	return ((ddi_umem_cookie_t *)umem_cookie);
}

void
gfxp_umem_cookie_destroy(ddi_umem_cookie_t cookie)
{
	kmem_free(cookie, sizeof (struct ddi_umem_cookie));
}

/*
 * called by driver devmap routine to pass kernel virtual address  mapping
 * info to the framework.    used only for kernel memory
 * allocated from ddi_dma_mem_alloc().
 */
/*ARGSUSED*/
int
gfxp_devmap_umem_setup(devmap_cookie_t dhc, dev_info_t *dip,
    struct devmap_callback_ctl *callbackops, ddi_umem_cookie_t cookie,
    offset_t off, size_t len, uint_t maxprot, uint_t flags,
    ddi_device_acc_attr_t *accattrp)
{
	devmap_handle_t *dhp = (devmap_handle_t *)dhc;
	struct ddi_umem_cookie *cp = (struct ddi_umem_cookie *)cookie;

#ifdef lint
	dip = dip;
#endif

	if (cookie == NULL)
		return (DDI_FAILURE);

	/* For UMEM_TRASH, this restriction is not needed */
	if ((off + len) > cp->size)
		return (DDI_FAILURE);

	/*
	 * First to check if this function has been called for this dhp.
	 */
	if (dhp->dh_flags & DEVMAP_SETUP_DONE)
		return (DDI_FAILURE);

	if ((dhp->dh_prot & dhp->dh_orig_maxprot & maxprot) != dhp->dh_prot)
		return (DDI_FAILURE);

	if (flags & DEVMAP_MAPPING_INVALID) {
		/*
		 * If DEVMAP_MAPPING_INVALID is specified, we have to grant
		 * remap permission.
		 */
		if (!(flags & DEVMAP_ALLOW_REMAP)) {
			return (DDI_FAILURE);
		}
	} else {
		dhp->dh_cookie = cookie;
		dhp->dh_roff = ptob(btop(off));
		dhp->dh_cvaddr = cp->cvaddr + dhp->dh_roff;
	}

	if (accattrp != NULL) {
		switch (accattrp->devacc_attr_dataorder) {
		case DDI_STRICTORDER_ACC:
			dhp->dh_hat_attr &= ~HAT_ORDER_MASK;
			dhp->dh_hat_attr |= (HAT_STRICTORDER|HAT_PLAT_NOCACHE);
			break;
		case DDI_UNORDERED_OK_ACC:
			dhp->dh_hat_attr &= ~HAT_ORDER_MASK;
			dhp->dh_hat_attr |= HAT_UNORDERED_OK;
			break;
		case DDI_MERGING_OK_ACC:
			dhp->dh_hat_attr &= ~HAT_ORDER_MASK;
			dhp->dh_hat_attr |= (HAT_MERGING_OK|HAT_PLAT_NOCACHE);
			break;
		case DDI_LOADCACHING_OK_ACC:
			dhp->dh_hat_attr &= ~HAT_ORDER_MASK;
			dhp->dh_hat_attr |= HAT_LOADCACHING_OK;
			break;
		case DDI_STORECACHING_OK_ACC:
			dhp->dh_hat_attr &= ~HAT_ORDER_MASK;
			dhp->dh_hat_attr |= HAT_STORECACHING_OK;
			break;
		default:
			return (DDI_FAILURE);
		}
	}

#ifdef __sparc
	if (accattrp != NULL) {
		if (accattrp->devacc_attr_endian_flags ==
			DDI_STRUCTURE_LE_ACC) {
			dhp->dh_hat_attr &= ~HAT_ENDIAN_MASK;
			dhp->dh_hat_attr |= HAT_STRUCTURE_LE;
		}
	}
#endif

	/*
	 * The default is _not_ to pass HAT_LOAD_NOCONSIST to hat_devload();
	 * we pass HAT_LOAD_NOCONSIST _only_ in cases where hat tries to
	 * create consistent mappings but our intention was to create
	 * non-consistent mappings.
	 *
	 * DEVMEM: hat figures it out it's DEVMEM and creates non-consistent
	 * mappings.
	 *
	 * kernel exported memory: hat figures it out it's memory and always
	 * creates consistent mappings.
	 *
	 * /dev/mem: non-consistent mappings. See comments in common/io/mem.c
	 *
	 * /dev/kmem: consistent mappings are created unless they are
	 * MAP_FIXED. We _explicitly_ tell hat to create non-consistent
	 * mappings by passing HAT_LOAD_NOCONSIST in case of MAP_FIXED
	 * mappings of /dev/kmem. See common/io/mem.c
	 */

	/* Only some of the flags bits are settable by the driver */
	dhp->dh_flags |= (flags & DEVMAP_SETUP_FLAGS);

	dhp->dh_len = ptob(btopr(len));
	dhp->dh_maxprot = maxprot & dhp->dh_orig_maxprot;
	ASSERT((dhp->dh_prot & dhp->dh_orig_maxprot & maxprot) == dhp->dh_prot);

	if (callbackops != NULL) {
		bcopy(callbackops, &dhp->dh_callbackops,
			sizeof (struct devmap_callback_ctl));
	}
	/*
	 * Initialize dh_lock if we want to do remap.
	 */
	if (dhp->dh_flags & DEVMAP_ALLOW_REMAP) {
		mutex_init(&dhp->dh_lock, NULL, MUTEX_DEFAULT, NULL);
		dhp->dh_flags |= DEVMAP_LOCK_INITED;
	}

	dhp->dh_flags |= DEVMAP_SETUP_DONE;

	return (DDI_SUCCESS);
}
