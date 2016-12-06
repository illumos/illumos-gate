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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/gfx_private.h>

/*
 * clone of ddi_segmap_setup(). Respects the requested cache
 * attributes so hat_devload() gives user space WC and
 * UC mappings for system memory.
 */

/*ARGSUSED*/
int
gfxp_ddi_segmap_setup(dev_t dev, off_t offset, struct as *as, caddr_t *addrp,
    off_t len, uint_t prot, uint_t maxprot, uint_t flags, cred_t *cred,
    ddi_device_acc_attr_t *accattrp, uint_t rnumber)
{
	struct segdev_crargs dev_a;
	int (*mapfunc)(dev_t dev, off_t off, int prot);
	uint_t hat_attr;
	pfn_t pfn;
	int error, i;

	if ((mapfunc = devopsp[getmajor(dev)]->devo_cb_ops->cb_mmap) == nodev)
		return (ENODEV);

	/*
	 * Character devices that support the d_mmap
	 * interface can only be mmap'ed shared.
	 */
	if ((flags & MAP_TYPE) != MAP_SHARED)
		return (EINVAL);

	/*
	 * Check that this region is indeed mappable on this platform.
	 * Use the mapping function.
	 */
	if (ddi_device_mapping_check(dev, accattrp, rnumber, &hat_attr) == -1)
		return (ENXIO);

	if (accattrp != NULL) {
		switch (accattrp->devacc_attr_dataorder) {
		case DDI_STRICTORDER_ACC:
			/* Want UC */
			hat_attr &= ~HAT_ORDER_MASK;
			hat_attr |= (HAT_STRICTORDER | HAT_PLAT_NOCACHE);
			break;
		case DDI_MERGING_OK_ACC:
			/* Want WC */
			hat_attr &= ~HAT_ORDER_MASK;
			hat_attr |= (HAT_MERGING_OK | HAT_PLAT_NOCACHE);
			break;
		}
	}

	/*
	 * Check to ensure that the entire range is
	 * legal and we are not trying to map in
	 * more than the device will let us.
	 */
	for (i = 0; i < len; i += PAGESIZE) {
		if (i == 0) {
			/*
			 * Save the pfn at offset here. This pfn will be
			 * used later to get user address.
			 */
			if ((pfn = (pfn_t)cdev_mmap(mapfunc, dev, offset,
					maxprot)) == PFN_INVALID)
				return (ENXIO);
		} else {
			if (cdev_mmap(mapfunc, dev, offset + i, maxprot) ==
				PFN_INVALID)
				return (ENXIO);
		}
	}

	as_rangelock(as);
	if ((flags & MAP_FIXED) == 0) {
		/*
		 * Pick an address w/o worrying about
		 * any vac alignment constraints.
		 */
		map_addr(addrp, len, ptob(pfn), 0, flags);
		if (*addrp == NULL) {
			as_rangeunlock(as);
			return (ENOMEM);
		}
	} else {
		/*
		 * User-specified address; blow away any previous mappings.
		 */
		(void) as_unmap(as, *addrp, len);
	}

	dev_a.mapfunc = mapfunc;
	dev_a.dev = dev;
	dev_a.offset = (offset_t)offset;
	dev_a.type = flags & MAP_TYPE;
	dev_a.prot = (uchar_t)prot;
	dev_a.maxprot = (uchar_t)maxprot;
	dev_a.hat_attr = hat_attr;
#if DEBUG
	dev_a.hat_flags = 0;
#else
	dev_a.hat_flags = HAT_LOAD_LOCK;
#endif
	dev_a.devmap_data = NULL;

	error = as_map(as, *addrp, len, segdev_create, &dev_a);
	as_rangeunlock(as);

	return (error);
}
