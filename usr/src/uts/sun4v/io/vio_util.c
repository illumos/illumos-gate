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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/stream.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/vio_util.h>

/*
 * Create a pool of mblks from which future vio_allocb() requests
 * will be serviced.
 *
 * NOTE: num_mblks has to non-zero and a power-of-2
 *
 * Returns 0 on success or EINVAL if num_mblks is zero or not
 * a power of 2.
 */
int
vio_create_mblks(uint64_t num_mblks, size_t mblk_size, vio_mblk_pool_t **poolp)
{
	vio_mblk_pool_t		*vmplp;
	vio_mblk_t		*vmp;
	uint8_t			*datap;
	int			i;

	if (!(num_mblks) || (!ISP2(num_mblks))) {
		*poolp = 0;
		return (EINVAL);
	}

	vmplp = kmem_zalloc(sizeof (*vmplp), KM_SLEEP);
	vmplp->quelen = num_mblks;
	vmplp->quemask = num_mblks - 1; /* expects quelen is power-of-2 */
	vmplp->mblk_size = mblk_size;

	mutex_init(&vmplp->hlock, NULL, MUTEX_DRIVER,
				DDI_INTR_PRI(DDI_INTR_SOFTPRI_DEFAULT));
	mutex_init(&vmplp->tlock, NULL, MUTEX_DRIVER,
				DDI_INTR_PRI(DDI_INTR_SOFTPRI_DEFAULT));

	vmplp->basep = kmem_zalloc(num_mblks * sizeof (vio_mblk_t), KM_SLEEP);
	vmplp->datap = kmem_zalloc(num_mblks * mblk_size, KM_SLEEP);
	vmplp->nextp = NULL;

	/* create a queue of pointers to free vio_mblk_t's */
	vmplp->quep = kmem_zalloc(vmplp->quelen * sizeof (vio_mblk_t *),
								KM_SLEEP);
	vmplp->head = 0;
	vmplp->tail =  0;

	for (i = 0, datap = vmplp->datap; i < num_mblks; i++) {

		vmp = &(vmplp->basep[i]);
		vmp->vmplp = vmplp;
		vmp->datap = datap;
		vmp->reclaim.free_func = vio_freeb;
		vmp->reclaim.free_arg = (caddr_t)vmp;
		vmp->mp = desballoc(vmp->datap, mblk_size, BPRI_MED,
		    &vmp->reclaim);

		if (vmp->mp == NULL)
			continue;

		/* put this vmp on the free stack */
		vmplp->quep[vmplp->tail] = vmp;
		vmplp->tail = (vmplp->tail + 1) & vmplp->quemask;

		datap += mblk_size;
	}

	*poolp = vmplp;
	return (0);
}

/*
 * Destroy the pool of mblks. This can only succeed when
 * all allocated mblks have been returned to the pool.
 *
 * It is up to the caller to ensure that no further mblks are
 * requested from the pool after destroy has been invoked.
 *
 * Returns 0 on success, EINVAL if handle is invalid, or
 * EBUSY if not all mblks reclaimed yet.
 */
int
vio_destroy_mblks(vio_mblk_pool_t *vmplp)
{
	if (vmplp == NULL)
		return (EINVAL);

	/*
	 * We can only destroy the pool once all the mblks have
	 * been reclaimed.
	 */
	if (vmplp->head != vmplp->tail) {
		/* some mblks still in use */
		return (EBUSY);
	}

	kmem_free(vmplp->basep, vmplp->quelen * sizeof (vio_mblk_t));
	kmem_free(vmplp->datap, vmplp->quelen * vmplp->mblk_size);
	kmem_free(vmplp->quep, vmplp->quelen * sizeof (vio_mblk_t *));

	mutex_destroy(&vmplp->hlock);
	mutex_destroy(&vmplp->tlock);

	kmem_free(vmplp, sizeof (*vmplp));

	return (0);
}

/*
 * Allocate a mblk from the free pool if one is available.
 * Otherwise returns NULL.
 */
mblk_t *
vio_allocb(vio_mblk_pool_t *vmplp)
{
	vio_mblk_t	*vmp = NULL;
	mblk_t		*mp = NULL;
	uint32_t	head;

	mutex_enter(&vmplp->hlock);
	head = (vmplp->head + 1) & vmplp->quemask;
	if (head != vmplp->tail) {
		/* we have free mblks */
		vmp = vmplp->quep[vmplp->head];
		mp = vmp->mp;
		vmplp->head = head;
	}
	mutex_exit(&vmplp->hlock);

	return (mp);
}

/*
 * Return a mblk to the free pool. Invoked when the upper IP
 * layers do freemsg() etc on the mblk they were passed.
 */
void
vio_freeb(void *arg)
{
	vio_mblk_t	*vmp = (vio_mblk_t *)arg;
	vio_mblk_pool_t	*vmplp = vmp->vmplp;

	vmp->mp = desballoc(vmp->datap, vmplp->mblk_size,
					BPRI_MED, &vmp->reclaim);

	mutex_enter(&vmplp->tlock);
	vmplp->quep[vmplp->tail] = vmp;
	vmplp->tail = (vmplp->tail + 1) & vmplp->quemask;
	mutex_exit(&vmplp->tlock);
}
