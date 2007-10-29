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
	vmplp->quep = kmem_zalloc(vmplp->quelen *
	    sizeof (vio_mblk_t *), KM_SLEEP);
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
	uint64_t i;
	uint64_t num_mblks;
	vio_mblk_t *vmp;

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

	num_mblks = vmplp->quelen;

	/*
	 * Set pool flag to tell vio_freeb() which is invoked from freeb(),
	 * that it is being called in the context of vio_destroy_mblks().
	 * This results in freeing only mblk_t and dblk_t structures for
	 * each mp. The associated data buffers are freed below as one big
	 * chunk through kmem_free(vmplp->datap).
	 */
	vmplp->flag |= VMPL_FLAG_DESTROYING;
	for (i = 0; i < num_mblks; i++) {
		vmp = &(vmplp->basep[i]);
		if (vmp->mp)
			freeb(vmp->mp);
	}
	vmplp->flag &= ~(VMPL_FLAG_DESTROYING);

	kmem_free(vmplp->basep, num_mblks * sizeof (vio_mblk_t));
	kmem_free(vmplp->datap, num_mblks * vmplp->mblk_size);
	kmem_free(vmplp->quep, num_mblks * sizeof (vio_mblk_t *));

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

	if (vmplp->flag & VMPL_FLAG_DESTROYING) {
		/*
		 * This flag indicates that freeb() is being called from
		 * vio_destroy_mblks().
		 * We don't need to alloc a new mblk_t/dblk_t pair for
		 * this data buffer, return from here and the data buffer
		 * itself will be freed in vio_destroy_mblks().
		 */
		return;
	}

	vmp->mp = desballoc(vmp->datap, vmplp->mblk_size,
	    BPRI_MED, &vmp->reclaim);

	mutex_enter(&vmplp->tlock);
	vmplp->quep[vmplp->tail] = vmp;
	vmplp->tail = (vmplp->tail + 1) & vmplp->quemask;
	mutex_exit(&vmplp->tlock);
}

/*
 * Create a multiple pools of mblks from which future vio_allocb()
 * or vio_multipool_allocb() requests will be serviced.
 *
 * Arguments:
 *	vmultip -- A pointer to vio_multi_pool_t structure.
 *	num_pools -- Number of the pools.
 *	... -- Variable arguments consisting a list of buffer sizes for
 *		each pool and list of number of buffers for each pool.
 *
 * NOTE: The restrictions of vio_create_mblks() apply to this interface also.
 *
 * Returns 0 on success or an error returned by vio_create_mblks().
 */
int
vio_init_multipools(vio_multi_pool_t *vmultip, int num_pools, ...)
{
	int		i;
	int		status;
	char		*tbuf;
	va_list		vap;
	vio_mblk_pool_t *fvmp = NULL;

	/*
	 * Allocate memory for all of the following in one allocation.
	 * 	bufsz_tbl -- sizeof (uint32_t) * num_pools
	 * 	nbuf_tbl  -- sizeof (uint32_t) * num_pools
	 *	vmpp	  -- sizeof (vio_mblk_pool_t *) * numpools
	 */
	vmultip->tbsz = (sizeof (uint32_t) * num_pools) +
	    (sizeof (uint32_t) * num_pools) +
	    (sizeof (vio_mblk_pool_t *) * num_pools);
	tbuf = kmem_zalloc(vmultip->tbsz, KM_SLEEP);
	vmultip->bufsz_tbl = (uint32_t *)tbuf;
	vmultip->nbuf_tbl = (uint32_t *)(tbuf +
	    (sizeof (uint32_t) * num_pools));
	vmultip->vmpp = (vio_mblk_pool_t **)(tbuf +
	    (sizeof (uint32_t) * num_pools * 2));
	vmultip->num_pools = num_pools;

	/* initialize the array first */
	va_start(vap, num_pools);
	for (i = 0; i < num_pools; i++) {
		vmultip->bufsz_tbl[i] = va_arg(vap, uint32_t);
	}
	for (i = 0; i < num_pools; i++) {
		vmultip->nbuf_tbl[i] = va_arg(vap, uint32_t);
	}
	va_end(vap);

	for (i = 0; i < vmultip->num_pools; i++) {
		status = vio_create_mblks(vmultip->nbuf_tbl[i],
		    vmultip->bufsz_tbl[i], &vmultip->vmpp[i]);
		if (status != 0) {
			vio_destroy_multipools(vmultip, &fvmp);
			/* We expect to free the pools without failure here */
			ASSERT(fvmp == NULL);
			return (status);
		}
	}
	return (0);
}

/*
 * Destroy the multiple pools of mblks. This can only succeed when
 * all allocated mblks have been returned to the pool.
 *
 * If a pool of mblks couldn't be destroyed, then the failed vio_mblk_pool_t
 * pointers are returned via th fvmp list. Its the caller's
 * responsibility to check this list and free them later at an appropriate
 * time with vio_destroy_mblks().
 *
 * Arguments:
 *	vmultip -- A pointer to vio_multi_pool_t structure.
 *	fvmp -- A list in which the pools that couldn't be destroyed are
 *		returned.
 */
void
vio_destroy_multipools(vio_multi_pool_t *vmultip, vio_mblk_pool_t **fvmp)
{
	int i;
	vio_mblk_pool_t *vmp;

	for (i = 0; i < vmultip->num_pools; i++) {
		if ((vmp = vmultip->vmpp[i]) != NULL) {
			if (vio_destroy_mblks(vmp)) {
				/*
				 * if we cannot reclaim all mblks, then
				 * return the pool in the failed vmp
				 * list(fvmp).
				 */
				vmp->nextp =  *fvmp;
				*fvmp = vmp;
			}
		}
	}
	kmem_free(vmultip->bufsz_tbl, vmultip->tbsz);
	vmultip->bufsz_tbl = NULL;
	vmultip->nbuf_tbl = NULL;
	vmultip->vmpp = NULL;
}


/*
 * Allocate an mblk from one of the free pools, but tries the pool that
 * best fits size requested first.
 */
mblk_t *
vio_multipool_allocb(vio_multi_pool_t *vmultip, size_t size)
{
	int i;
	mblk_t *mp = NULL;

	/* Try allocating any size that fits */
	for (i = 0; i < vmultip->num_pools; i++) {
		if (size > vmultip->bufsz_tbl[i]) {
			continue;
		}
		mp = vio_allocb(vmultip->vmpp[i]);
		if (mp != NULL) {
			break;
		}
	}
	return (mp);
}

/*
 * -----------------------------------------------------------------------------
 * LDoms versioning functions
 *
 * Future work: the version negotiating code in the various VIO drivers
 * could be made common and placed here.
 */

/*
 * Description:
 *	This function checks to see if the supplied version tuple (major,minor)
 *	is supported by the version 'ver', negotiated during the handshake
 *	between the client and the server (ver).
 *
 * Assumption:
 *	This function assumes that backward compatability is not broken in
 *	newer minor versions of the protocol (e.g. v1.5 & v1.1 support v1.0)
 *
 * Return Value:
 *	B_TRUE		- The (major,minor) version is supported
 *	B_FALSE		- not supported
 */
boolean_t
vio_ver_is_supported(vio_ver_t ver, uint16_t major, uint16_t minor)
{
	if ((ver.major == major) && (ver.minor >= minor))
		return (B_TRUE);

	return (B_FALSE);
}
