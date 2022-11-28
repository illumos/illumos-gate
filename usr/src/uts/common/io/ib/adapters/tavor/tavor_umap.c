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
 * tavor_umap.c
 *    Tavor Userland Mapping Routines
 *
 *    Implements all the routines necessary for enabling direct userland
 *    access to the Tavor hardware.  This includes all routines necessary for
 *    maintaining the "userland resources database" and all the support routines
 *    for the devmap calls.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/avl.h>
#include <sys/sysmacros.h>

#include <sys/ib/adapters/tavor/tavor.h>

/* Tavor HCA state pointer (extern) */
extern void *tavor_statep;

/* Tavor HCA Userland Resource Database (extern) */
extern tavor_umap_db_t tavor_userland_rsrc_db;

static int tavor_umap_uarpg(tavor_state_t *state, devmap_cookie_t dhp,
    tavor_rsrc_t *rsrcp, size_t *maplen, int *err);
static int tavor_umap_cqmem(tavor_state_t *state, devmap_cookie_t dhp,
    tavor_rsrc_t *rsrcp, offset_t off, size_t *maplen, int *err);
static int tavor_umap_qpmem(tavor_state_t *state, devmap_cookie_t dhp,
    tavor_rsrc_t *rsrcp, offset_t off, size_t *maplen, int *err);
static int tavor_umap_srqmem(tavor_state_t *state, devmap_cookie_t dhp,
    tavor_rsrc_t *rsrcp, offset_t off, size_t *maplen, int *err);
static int tavor_devmap_umem_map(devmap_cookie_t dhp, dev_t dev, uint_t flags,
    offset_t off, size_t len, void **pvtp);
static int tavor_devmap_umem_dup(devmap_cookie_t dhp, void *pvtp,
    devmap_cookie_t new_dhp, void **new_pvtp);
static void tavor_devmap_umem_unmap(devmap_cookie_t dhp, void *pvtp,
    offset_t off, size_t len, devmap_cookie_t new_dhp1, void **pvtp1,
    devmap_cookie_t new_dhp2, void **pvtp2);
static int tavor_devmap_devmem_map(devmap_cookie_t dhp, dev_t dev, uint_t flags,
    offset_t off, size_t len, void **pvtp);
static int tavor_devmap_devmem_dup(devmap_cookie_t dhp, void *pvtp,
    devmap_cookie_t new_dhp, void **new_pvtp);
static void tavor_devmap_devmem_unmap(devmap_cookie_t dhp, void *pvtp,
    offset_t off, size_t len, devmap_cookie_t new_dhp1, void **pvtp1,
    devmap_cookie_t new_dhp2, void **pvtp2);
static ibt_status_t tavor_umap_mr_data_in(tavor_mrhdl_t mr,
    ibt_mr_data_in_t *data, size_t data_sz);
static ibt_status_t tavor_umap_cq_data_out(tavor_cqhdl_t cq,
    mlnx_umap_cq_data_out_t *data, size_t data_sz);
static ibt_status_t tavor_umap_qp_data_out(tavor_qphdl_t qp,
    mlnx_umap_qp_data_out_t *data, size_t data_sz);
static ibt_status_t tavor_umap_srq_data_out(tavor_srqhdl_t srq,
    mlnx_umap_srq_data_out_t *data, size_t data_sz);
static int tavor_umap_db_compare(const void *query, const void *entry);
static ibt_status_t tavor_umap_pd_data_out(tavor_pdhdl_t pd,
    mlnx_umap_pd_data_out_t *data, size_t data_sz);


/*
 * These callbacks are passed to devmap_umem_setup() and devmap_devmem_setup(),
 * respectively.  They are used to handle (among other things) partial
 * unmappings and to provide a method for invalidating mappings inherited
 * as a result of a fork(2) system call.
 */
static struct devmap_callback_ctl tavor_devmap_umem_cbops = {
	DEVMAP_OPS_REV,
	tavor_devmap_umem_map,
	NULL,
	tavor_devmap_umem_dup,
	tavor_devmap_umem_unmap
};
static struct devmap_callback_ctl tavor_devmap_devmem_cbops = {
	DEVMAP_OPS_REV,
	tavor_devmap_devmem_map,
	NULL,
	tavor_devmap_devmem_dup,
	tavor_devmap_devmem_unmap
};

/*
 * tavor_devmap()
 *    Context: Can be called from user context.
 */
/* ARGSUSED */
int
tavor_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off, size_t len,
    size_t *maplen, uint_t model)
{
	tavor_state_t	*state;
	tavor_rsrc_t 	*rsrcp;
	minor_t		instance;
	uint64_t	key, value;
	uint_t		type;
	int		err, status;

	/* Get Tavor softstate structure from instance */
	instance = TAVOR_DEV_INSTANCE(dev);
	state = ddi_get_soft_state(tavor_statep, instance);
	if (state == NULL) {
		return (ENXIO);
	}

	/*
	 * Access to Tavor devmap interface is not allowed in
	 * "maintenance mode".
	 */
	if (state->ts_operational_mode == TAVOR_MAINTENANCE_MODE) {
		return (EFAULT);
	}

	/*
	 * The bottom bits of "offset" are undefined (number depends on
	 * system PAGESIZE).  Shifting these off leaves us with a "key".
	 * The "key" is actually a combination of both a real key value
	 * (for the purpose of database lookup) and a "type" value.  We
	 * extract this information before doing the database lookup.
	 */
	key  = off >> PAGESHIFT;
	type = key & MLNX_UMAP_RSRC_TYPE_MASK;
	key  = key >> MLNX_UMAP_RSRC_TYPE_SHIFT;
	status = tavor_umap_db_find(instance, key, type, &value, 0, NULL);
	if (status == DDI_SUCCESS) {
		rsrcp = (tavor_rsrc_t *)(uintptr_t)value;

		switch (type) {
		case MLNX_UMAP_UARPG_RSRC:
			/*
			 * Double check that process who open()'d Tavor is
			 * same process attempting to mmap() UAR page.
			 */
			if (key != ddi_get_pid()) {
				return (EINVAL);
			}

			/* Map the UAR page out for userland access */
			status = tavor_umap_uarpg(state, dhp, rsrcp, maplen,
			    &err);
			if (status != DDI_SUCCESS) {
				return (err);
			}
			break;

		case MLNX_UMAP_CQMEM_RSRC:
			/* Map the CQ memory out for userland access */
			status = tavor_umap_cqmem(state, dhp, rsrcp, off,
			    maplen, &err);
			if (status != DDI_SUCCESS) {
				return (err);
			}
			break;

		case MLNX_UMAP_QPMEM_RSRC:
			/* Map the QP memory out for userland access */
			status = tavor_umap_qpmem(state, dhp, rsrcp, off,
			    maplen, &err);
			if (status != DDI_SUCCESS) {
				return (err);
			}
			break;

		case MLNX_UMAP_SRQMEM_RSRC:
			/* Map the SRQ memory out for userland access */
			status = tavor_umap_srqmem(state, dhp, rsrcp, off,
			    maplen, &err);
			if (status != DDI_SUCCESS) {
				return (err);
			}
			break;

		default:
			TAVOR_WARNING(state, "unexpected rsrc type in devmap");
			return (EINVAL);
		}
	} else {
		return (EINVAL);
	}

	return (0);
}


/*
 * tavor_umap_uarpg()
 *    Context: Can be called from user context.
 */
static int
tavor_umap_uarpg(tavor_state_t *state, devmap_cookie_t dhp,
    tavor_rsrc_t *rsrcp, size_t *maplen, int *err)
{
	int		status;
	uint_t		maxprot;

	/* Map out the UAR page (doorbell page) */
	maxprot = (PROT_READ | PROT_WRITE | PROT_USER);
	status = devmap_devmem_setup(dhp, state->ts_dip,
	    &tavor_devmap_devmem_cbops, TAVOR_UAR_BAR, (rsrcp->tr_indx <<
	    PAGESHIFT), PAGESIZE, maxprot, DEVMAP_ALLOW_REMAP,
	    &state->ts_reg_accattr);
	if (status < 0) {
		*err = status;
		return (DDI_FAILURE);
	}

	*maplen = PAGESIZE;
	return (DDI_SUCCESS);
}


/*
 * tavor_umap_cqmem()
 *    Context: Can be called from user context.
 */
/* ARGSUSED */
static int
tavor_umap_cqmem(tavor_state_t *state, devmap_cookie_t dhp,
    tavor_rsrc_t *rsrcp, offset_t off, size_t *maplen, int *err)
{
	tavor_cqhdl_t	cq;
	size_t		size;
	uint_t		maxprot;
	int		status;

	/* Extract the Tavor CQ handle pointer from the tavor_rsrc_t */
	cq = (tavor_cqhdl_t)rsrcp->tr_addr;

	/* Round-up the CQ size to system page size */
	size = ptob(btopr(cq->cq_cqinfo.qa_size));

	/* Map out the CQ memory */
	maxprot = (PROT_READ | PROT_WRITE | PROT_USER);
	status = devmap_umem_setup(dhp, state->ts_dip,
	    &tavor_devmap_umem_cbops, cq->cq_cqinfo.qa_umemcookie, 0, size,
	    maxprot, (DEVMAP_ALLOW_REMAP | DEVMAP_DEFAULTS), NULL);
	if (status < 0) {
		*err = status;
		return (DDI_FAILURE);
	}
	*maplen = size;

	return (DDI_SUCCESS);
}


/*
 * tavor_umap_qpmem()
 *    Context: Can be called from user context.
 */
/* ARGSUSED */
static int
tavor_umap_qpmem(tavor_state_t *state, devmap_cookie_t dhp,
    tavor_rsrc_t *rsrcp, offset_t off, size_t *maplen, int *err)
{
	tavor_qphdl_t	qp;
	offset_t	offset;
	size_t		size;
	uint_t		maxprot;
	int		status;

	/* Extract the Tavor QP handle pointer from the tavor_rsrc_t */
	qp = (tavor_qphdl_t)rsrcp->tr_addr;

	/*
	 * Calculate the offset of the first work queue (send or recv) into
	 * the memory (ddi_umem_alloc()) allocated previously for the QP.
	 */
	offset = (offset_t)((uintptr_t)qp->qp_wqinfo.qa_buf_aligned -
	    (uintptr_t)qp->qp_wqinfo.qa_buf_real);

	/* Round-up the QP work queue sizes to system page size */
	size = ptob(btopr(qp->qp_wqinfo.qa_size));

	/* Map out the QP memory */
	maxprot = (PROT_READ | PROT_WRITE | PROT_USER);
	status = devmap_umem_setup(dhp, state->ts_dip,
	    &tavor_devmap_umem_cbops, qp->qp_wqinfo.qa_umemcookie, offset,
	    size, maxprot, (DEVMAP_ALLOW_REMAP | DEVMAP_DEFAULTS), NULL);
	if (status < 0) {
		*err = status;
		return (DDI_FAILURE);
	}
	*maplen = size;

	return (DDI_SUCCESS);
}


/*
 * tavor_umap_srqmem()
 *    Context: Can be called from user context.
 */
/* ARGSUSED */
static int
tavor_umap_srqmem(tavor_state_t *state, devmap_cookie_t dhp,
    tavor_rsrc_t *rsrcp, offset_t off, size_t *maplen, int *err)
{
	tavor_srqhdl_t	srq;
	offset_t	offset;
	size_t		size;
	uint_t		maxprot;
	int		status;

	/* Extract the Tavor SRQ handle pointer from the tavor_rsrc_t */
	srq = (tavor_srqhdl_t)rsrcp->tr_addr;

	/*
	 * Calculate the offset of the first shared recv queue into the memory
	 * (ddi_umem_alloc()) allocated previously for the SRQ.
	 */
	offset = (offset_t)((uintptr_t)srq->srq_wqinfo.qa_buf_aligned -
	    (uintptr_t)srq->srq_wqinfo.qa_buf_real);

	/* Round-up the SRQ work queue sizes to system page size */
	size = ptob(btopr(srq->srq_wqinfo.qa_size));

	/* Map out the QP memory */
	maxprot = (PROT_READ | PROT_WRITE | PROT_USER);
	status = devmap_umem_setup(dhp, state->ts_dip,
	    &tavor_devmap_umem_cbops, srq->srq_wqinfo.qa_umemcookie, offset,
	    size, maxprot, (DEVMAP_ALLOW_REMAP | DEVMAP_DEFAULTS), NULL);
	if (status < 0) {
		*err = status;
		return (DDI_FAILURE);
	}
	*maplen = size;

	return (DDI_SUCCESS);
}


/*
 * tavor_devmap_umem_map()
 *    Context: Can be called from kernel context.
 */
/* ARGSUSED */
static int
tavor_devmap_umem_map(devmap_cookie_t dhp, dev_t dev, uint_t flags,
    offset_t off, size_t len, void **pvtp)
{
	tavor_state_t		*state;
	tavor_devmap_track_t	*dvm_track;
	tavor_cqhdl_t		cq;
	tavor_qphdl_t		qp;
	tavor_srqhdl_t		srq;
	minor_t			instance;
	uint64_t		key;
	uint_t			type;

	/* Get Tavor softstate structure from instance */
	instance = TAVOR_DEV_INSTANCE(dev);
	state = ddi_get_soft_state(tavor_statep, instance);
	if (state == NULL) {
		return (ENXIO);
	}

	/*
	 * The bottom bits of "offset" are undefined (number depends on
	 * system PAGESIZE).  Shifting these off leaves us with a "key".
	 * The "key" is actually a combination of both a real key value
	 * (for the purpose of database lookup) and a "type" value.  Although
	 * we are not going to do any database lookup per se, we do want
	 * to extract the "key" and the "type" (to enable faster lookup of
	 * the appropriate CQ or QP handle).
	 */
	key  = off >> PAGESHIFT;
	type = key & MLNX_UMAP_RSRC_TYPE_MASK;
	key  = key >> MLNX_UMAP_RSRC_TYPE_SHIFT;

	/*
	 * Allocate an entry to track the mapping and unmapping (specifically,
	 * partial unmapping) of this resource.
	 */
	dvm_track = (tavor_devmap_track_t *)kmem_zalloc(
	    sizeof (tavor_devmap_track_t), KM_SLEEP);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*dvm_track))
	dvm_track->tdt_offset = off;
	dvm_track->tdt_state  = state;
	dvm_track->tdt_refcnt = 1;
	mutex_init(&dvm_track->tdt_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));

	/*
	 * Depending of the type of resource that has been mapped out, we
	 * need to update the QP or CQ handle to reflect that it has, in
	 * fact, been mapped.  This allows the driver code which frees a QP
	 * or a CQ to know whether it is appropriate to do a
	 * devmap_devmem_remap() to invalidate the userland mapping for the
	 * corresponding queue's memory.
	 */
	if (type == MLNX_UMAP_CQMEM_RSRC) {

		/* Use "key" (CQ number) to do fast lookup of CQ handle */
		cq = tavor_cqhdl_from_cqnum(state, key);

		/*
		 * Update the handle to the userland mapping.  Note:  If
		 * the CQ already has a valid userland mapping, then stop
		 * and return failure.
		 */
		mutex_enter(&cq->cq_lock);
		if (cq->cq_umap_dhp == NULL) {
			cq->cq_umap_dhp = dhp;
			dvm_track->tdt_size = cq->cq_cqinfo.qa_size;
			mutex_exit(&cq->cq_lock);
		} else {
			mutex_exit(&cq->cq_lock);
			goto umem_map_fail;
		}

	} else if (type == MLNX_UMAP_QPMEM_RSRC) {

		/* Use "key" (QP number) to do fast lookup of QP handle */
		qp = tavor_qphdl_from_qpnum(state, key);

		/*
		 * Update the handle to the userland mapping.  Note:  If
		 * the CQ already has a valid userland mapping, then stop
		 * and return failure.
		 */
		mutex_enter(&qp->qp_lock);
		if (qp->qp_umap_dhp == NULL) {
			qp->qp_umap_dhp = dhp;
			dvm_track->tdt_size = qp->qp_wqinfo.qa_size;
			mutex_exit(&qp->qp_lock);
		} else {
			mutex_exit(&qp->qp_lock);
			goto umem_map_fail;
		}

	} else if (type == MLNX_UMAP_SRQMEM_RSRC) {

		/* Use "key" (SRQ number) to do fast lookup on SRQ handle */
		srq = tavor_srqhdl_from_srqnum(state, key);

		/*
		 * Update the handle to the userland mapping.  Note:  If the
		 * SRQ already has a valid userland mapping, then stop and
		 * return failure.
		 */
		mutex_enter(&srq->srq_lock);
		if (srq->srq_umap_dhp == NULL) {
			srq->srq_umap_dhp = dhp;
			dvm_track->tdt_size = srq->srq_wqinfo.qa_size;
			mutex_exit(&srq->srq_lock);
		} else {
			mutex_exit(&srq->srq_lock);
			goto umem_map_fail;
		}
	}

	/*
	 * Pass the private "Tavor devmap tracking structure" back.  This
	 * pointer will be returned in subsequent "unmap" callbacks.
	 */
	*pvtp = dvm_track;

	return (DDI_SUCCESS);

umem_map_fail:
	mutex_destroy(&dvm_track->tdt_lock);
	kmem_free(dvm_track, sizeof (tavor_devmap_track_t));
	return (DDI_FAILURE);
}


/*
 * tavor_devmap_umem_dup()
 *    Context: Can be called from kernel context.
 */
/* ARGSUSED */
static int
tavor_devmap_umem_dup(devmap_cookie_t dhp, void *pvtp, devmap_cookie_t new_dhp,
    void **new_pvtp)
{
	tavor_state_t		*state;
	tavor_devmap_track_t	*dvm_track, *new_dvm_track;
	uint_t			maxprot;
	int			status;

	/*
	 * Extract the Tavor softstate pointer from "Tavor devmap tracking
	 * structure" (in "pvtp").
	 */
	dvm_track = (tavor_devmap_track_t *)pvtp;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*dvm_track))
	state = dvm_track->tdt_state;

	/*
	 * Since this devmap_dup() entry point is generally called
	 * when a process does fork(2), it is incumbent upon the driver
	 * to insure that the child does not inherit a valid copy of
	 * the parent's QP or CQ resource.  This is accomplished by using
	 * devmap_devmem_remap() to invalidate the child's mapping to the
	 * kernel memory.
	 */
	maxprot = (PROT_READ | PROT_WRITE | PROT_USER);
	status = devmap_devmem_remap(new_dhp, state->ts_dip, 0, 0,
	    dvm_track->tdt_size, maxprot, DEVMAP_MAPPING_INVALID, NULL);
	if (status != DDI_SUCCESS) {
		TAVOR_WARNING(state, "failed in tavor_devmap_umem_dup()");
		return (status);
	}

	/*
	 * Allocate a new entry to track the subsequent unmapping
	 * (specifically, all partial unmappings) of the child's newly
	 * invalidated resource.  Note: Setting the "tdt_size" field to
	 * zero here is an indication to the devmap_unmap() entry point
	 * that this mapping is invalid, and that its subsequent unmapping
	 * should not affect any of the parent's CQ or QP resources.
	 */
	new_dvm_track = (tavor_devmap_track_t *)kmem_zalloc(
	    sizeof (tavor_devmap_track_t), KM_SLEEP);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*new_dvm_track))
	new_dvm_track->tdt_offset = 0;
	new_dvm_track->tdt_state  = state;
	new_dvm_track->tdt_refcnt = 1;
	new_dvm_track->tdt_size	  = 0;
	mutex_init(&new_dvm_track->tdt_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));
	*new_pvtp = new_dvm_track;

	return (DDI_SUCCESS);
}


/*
 * tavor_devmap_umem_unmap()
 *    Context: Can be called from kernel context.
 */
/* ARGSUSED */
static void
tavor_devmap_umem_unmap(devmap_cookie_t dhp, void *pvtp, offset_t off,
    size_t len, devmap_cookie_t new_dhp1, void **pvtp1,
    devmap_cookie_t new_dhp2, void **pvtp2)
{
	tavor_state_t 		*state;
	tavor_rsrc_t 		*rsrcp;
	tavor_devmap_track_t	*dvm_track;
	tavor_cqhdl_t		cq;
	tavor_qphdl_t		qp;
	tavor_srqhdl_t		srq;
	uint64_t		key, value;
	uint_t			type;
	uint_t			size;
	int			status;

	/*
	 * Extract the Tavor softstate pointer from "Tavor devmap tracking
	 * structure" (in "pvtp").
	 */
	dvm_track = (tavor_devmap_track_t *)pvtp;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*dvm_track))
	state	  = dvm_track->tdt_state;

	/*
	 * Extract the "offset" from the "Tavor devmap tracking structure".
	 * Note: The input argument "off" is ignored here because the
	 * Tavor mapping interfaces define a very specific meaning to
	 * each "logical offset".  Also extract the "key" and "type" encoded
	 * in the logical offset.
	 */
	key  = dvm_track->tdt_offset >> PAGESHIFT;
	type = key & MLNX_UMAP_RSRC_TYPE_MASK;
	key  = key >> MLNX_UMAP_RSRC_TYPE_SHIFT;

	/*
	 * Extract the "size" of the mapping.  If this size is determined
	 * to be zero, then it is an indication of a previously invalidated
	 * mapping, and no CQ or QP resources should be affected.
	 */
	size = dvm_track->tdt_size;

	/*
	 * If only the "middle portion of a given mapping is being unmapped,
	 * then we are effectively creating one new piece of mapped memory.
	 * (Original region is divided into three pieces of which the middle
	 * piece is being removed.  This leaves two pieces.  Since we started
	 * with one piece and now have two pieces, we need to increment the
	 * counter in the "Tavor devmap tracking structure".
	 *
	 * If, however, the whole mapped region is being unmapped, then we
	 * have started with one region which we are completely removing.
	 * In this case, we need to decrement the counter in the "Tavor
	 * devmap tracking structure".
	 *
	 * In each of the remaining cases, we will have started with one
	 * mapped region and ended with one (different) region.  So no counter
	 * modification is necessary.
	 */
	mutex_enter(&dvm_track->tdt_lock);
	if ((new_dhp1 == NULL) && (new_dhp2 == NULL)) {
		dvm_track->tdt_refcnt--;
	} else if ((new_dhp1 != NULL) && (new_dhp2 != NULL)) {
		dvm_track->tdt_refcnt++;
	}
	mutex_exit(&dvm_track->tdt_lock);

	/*
	 * For each of the cases where the region is being divided, then we
	 * need to pass back the "Tavor devmap tracking structure".  This way
	 * we get it back when each of the remaining pieces is subsequently
	 * unmapped.
	 */
	if (new_dhp1 != NULL) {
		*pvtp1 = pvtp;
	}
	if (new_dhp2 != NULL) {
		*pvtp2 = pvtp;
	}

	/*
	 * If the "Tavor devmap tracking structure" is no longer being
	 * referenced, then free it up.  Otherwise, return.
	 */
	if (dvm_track->tdt_refcnt == 0) {
		mutex_destroy(&dvm_track->tdt_lock);
		kmem_free(dvm_track, sizeof (tavor_devmap_track_t));

		/*
		 * If the mapping was invalid (see explanation above), then
		 * no further processing is necessary.
		 */
		if (size == 0) {
			return;
		}
	} else {
		return;
	}

	/*
	 * Now that we can guarantee that the user memory is fully unmapped,
	 * we can use the "key" and "type" values to try to find the entry
	 * in the "userland resources database".  If it's found, then it
	 * indicates that the queue memory (CQ or QP) has not yet been freed.
	 * In this case, we update the corresponding CQ or QP handle to
	 * indicate that the "devmap_devmem_remap()" call will be unnecessary.
	 * If it's _not_ found, then it indicates that the CQ or QP memory
	 * was, in fact, freed before it was unmapped (thus requiring a
	 * previous invalidation by remapping - which will already have
	 * been done in the free routine).
	 */
	status = tavor_umap_db_find(state->ts_instance, key, type, &value,
	    0, NULL);
	if (status == DDI_SUCCESS) {
		/*
		 * Depending on the type of the mapped resource (CQ or QP),
		 * update handle to indicate that no invalidation remapping
		 * will be necessary.
		 */
		if (type == MLNX_UMAP_CQMEM_RSRC) {

			/* Use "value" to convert to CQ handle */
			rsrcp = (tavor_rsrc_t *)(uintptr_t)value;
			cq = (tavor_cqhdl_t)rsrcp->tr_addr;

			/*
			 * Invalidate the handle to the userland mapping.
			 * Note: We must ensure that the mapping being
			 * unmapped here is the current one for the CQ.  It
			 * is possible that it might not be if this CQ has
			 * been resized and the previous CQ memory has not
			 * yet been unmapped.  But in that case, because of
			 * the devmap_devmem_remap(), there is no longer any
			 * association between the mapping and the real CQ
			 * kernel memory.
			 */
			mutex_enter(&cq->cq_lock);
			if (cq->cq_umap_dhp == dhp) {
				cq->cq_umap_dhp = (devmap_cookie_t)NULL;
			}
			mutex_exit(&cq->cq_lock);

		} else if (type == MLNX_UMAP_QPMEM_RSRC) {

			/* Use "value" to convert to QP handle */
			rsrcp = (tavor_rsrc_t *)(uintptr_t)value;
			qp = (tavor_qphdl_t)rsrcp->tr_addr;

			/*
			 * Invalidate the handle to the userland mapping.
			 * Note: we ensure that the mapping being unmapped
			 * here is the current one for the QP.  This is
			 * more of a sanity check here since, unlike CQs
			 * (above) we do not support resize of QPs.
			 */
			mutex_enter(&qp->qp_lock);
			if (qp->qp_umap_dhp == dhp) {
				qp->qp_umap_dhp = (devmap_cookie_t)NULL;
			}
			mutex_exit(&qp->qp_lock);

		} else if (type == MLNX_UMAP_SRQMEM_RSRC) {

			/* Use "value" to convert to SRQ handle */
			rsrcp = (tavor_rsrc_t *)(uintptr_t)value;
			srq = (tavor_srqhdl_t)rsrcp->tr_addr;

			/*
			 * Invalidate the handle to the userland mapping.
			 * Note: we ensure that the mapping being unmapped
			 * here is the current one for the QP.  This is
			 * more of a sanity check here since, unlike CQs
			 * (above) we do not support resize of QPs.
			 */
			mutex_enter(&srq->srq_lock);
			if (srq->srq_umap_dhp == dhp) {
				srq->srq_umap_dhp = (devmap_cookie_t)NULL;
			}
			mutex_exit(&srq->srq_lock);
		}
	}
}


/*
 * tavor_devmap_devmem_map()
 *    Context: Can be called from kernel context.
 */
/* ARGSUSED */
static int
tavor_devmap_devmem_map(devmap_cookie_t dhp, dev_t dev, uint_t flags,
    offset_t off, size_t len, void **pvtp)
{
	tavor_state_t		*state;
	tavor_devmap_track_t	*dvm_track;
	minor_t			instance;

	/* Get Tavor softstate structure from instance */
	instance = TAVOR_DEV_INSTANCE(dev);
	state = ddi_get_soft_state(tavor_statep, instance);
	if (state == NULL) {
		return (ENXIO);
	}

	/*
	 * Allocate an entry to track the mapping and unmapping of this
	 * resource.  Note:  We don't need to initialize the "refcnt" or
	 * "offset" fields here, nor do we need to initialize the mutex
	 * used with the "refcnt".  Since UAR pages are single pages, they
	 * are not subject to "partial" unmappings.  This makes these other
	 * fields unnecessary.
	 */
	dvm_track = (tavor_devmap_track_t *)kmem_zalloc(
	    sizeof (tavor_devmap_track_t), KM_SLEEP);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*dvm_track))
	dvm_track->tdt_state  = state;
	dvm_track->tdt_size   = PAGESIZE;

	/*
	 * Pass the private "Tavor devmap tracking structure" back.  This
	 * pointer will be returned in a subsequent "unmap" callback.
	 */
	*pvtp = dvm_track;

	return (DDI_SUCCESS);
}


/*
 * tavor_devmap_devmem_dup()
 *    Context: Can be called from kernel context.
 */
/* ARGSUSED */
static int
tavor_devmap_devmem_dup(devmap_cookie_t dhp, void *pvtp,
    devmap_cookie_t new_dhp, void **new_pvtp)
{
	tavor_state_t		*state;
	tavor_devmap_track_t	*dvm_track;
	uint_t			maxprot;
	int			status;

	/*
	 * Extract the Tavor softstate pointer from "Tavor devmap tracking
	 * structure" (in "pvtp").  Note: If the tracking structure is NULL
	 * here, it means that the mapping corresponds to an invalid mapping.
	 * In this case, it can be safely ignored ("new_pvtp" set to NULL).
	 */
	dvm_track = (tavor_devmap_track_t *)pvtp;
	if (dvm_track == NULL) {
		*new_pvtp = NULL;
		return (DDI_SUCCESS);
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*dvm_track))
	state = dvm_track->tdt_state;

	/*
	 * Since this devmap_dup() entry point is generally called
	 * when a process does fork(2), it is incumbent upon the driver
	 * to insure that the child does not inherit a valid copy of
	 * the parent's resource.  This is accomplished by using
	 * devmap_devmem_remap() to invalidate the child's mapping to the
	 * kernel memory.
	 */
	maxprot = (PROT_READ | PROT_WRITE | PROT_USER);
	status = devmap_devmem_remap(new_dhp, state->ts_dip, 0, 0,
	    dvm_track->tdt_size, maxprot, DEVMAP_MAPPING_INVALID, NULL);
	if (status != DDI_SUCCESS) {
		TAVOR_WARNING(state, "failed in tavor_devmap_devmem_dup()");
		return (status);
	}

	/*
	 * Since the region is invalid, there is no need for us to
	 * allocate and continue to track an additional "Tavor devmap
	 * tracking structure".  Instead we return NULL here, which is an
	 * indication to the devmap_unmap() entry point that this entry
	 * can be safely ignored.
	 */
	*new_pvtp = NULL;

	return (DDI_SUCCESS);
}


/*
 * tavor_devmap_devmem_unmap()
 *    Context: Can be called from kernel context.
 */
/* ARGSUSED */
static void
tavor_devmap_devmem_unmap(devmap_cookie_t dhp, void *pvtp, offset_t off,
    size_t len, devmap_cookie_t new_dhp1, void **pvtp1,
    devmap_cookie_t new_dhp2, void **pvtp2)
{
	tavor_devmap_track_t	*dvm_track;

	/*
	 * Free up the "Tavor devmap tracking structure" (in "pvtp").
	 * There cannot be "partial" unmappings here because all UAR pages
	 * are single pages.  Note: If the tracking structure is NULL here,
	 * it means that the mapping corresponds to an invalid mapping.  In
	 * this case, it can be safely ignored.
	 */
	dvm_track = (tavor_devmap_track_t *)pvtp;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*dvm_track))
	if (dvm_track == NULL) {
		return;
	}

	kmem_free(dvm_track, sizeof (tavor_devmap_track_t));
}


/*
 * tavor_umap_ci_data_in()
 *    Context: Can be called from user or kernel context.
 */
/* ARGSUSED */
ibt_status_t
tavor_umap_ci_data_in(tavor_state_t *state, ibt_ci_data_flags_t flags,
    ibt_object_type_t object, void *hdl, void *data_p, size_t data_sz)
{
	int	status;

	/*
	 * Depending on the type of object about which additional information
	 * is being provided (currently only MR is supported), we call the
	 * appropriate resource-specific function.
	 */
	switch (object) {
	case IBT_HDL_MR:
		status = tavor_umap_mr_data_in((tavor_mrhdl_t)hdl,
		    (ibt_mr_data_in_t *)data_p, data_sz);
		if (status != DDI_SUCCESS) {
			return (status);
		}
		break;

	/*
	 * For other possible valid IBT types, we return IBT_NOT_SUPPORTED,
	 * since the Tavor driver does not support these.
	 */
	case IBT_HDL_HCA:
	case IBT_HDL_QP:
	case IBT_HDL_CQ:
	case IBT_HDL_PD:
	case IBT_HDL_MW:
	case IBT_HDL_AH:
	case IBT_HDL_SCHED:
	case IBT_HDL_EEC:
	case IBT_HDL_RDD:
	case IBT_HDL_SRQ:
		return (IBT_NOT_SUPPORTED);

	/*
	 * Any other types are invalid.
	 */
	default:
		return (IBT_INVALID_PARAM);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_umap_mr_data_in()
 *    Context: Can be called from user or kernel context.
 */
static ibt_status_t
tavor_umap_mr_data_in(tavor_mrhdl_t mr, ibt_mr_data_in_t *data,
    size_t data_sz)
{
	if (data->mr_rev != IBT_MR_DATA_IN_IF_VERSION) {
		return (IBT_NOT_SUPPORTED);
	}

	/* Check for valid MR handle pointer */
	if (mr == NULL) {
		return (IBT_MR_HDL_INVALID);
	}

	/* Check for valid MR input structure size */
	if (data_sz < sizeof (ibt_mr_data_in_t)) {
		return (IBT_INSUFF_RESOURCE);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*data))

	/*
	 * Ensure that the MR corresponds to userland memory and that it is
	 * a currently valid memory region as well.
	 */
	mutex_enter(&mr->mr_lock);
	if ((mr->mr_is_umem == 0) || (mr->mr_umemcookie == NULL)) {
		mutex_exit(&mr->mr_lock);
		return (IBT_MR_HDL_INVALID);
	}

	/*
	 * If it has passed all the above checks, then extract the callback
	 * function and argument from the input structure.  Copy them into
	 * the MR handle.  This function will be called only if the memory
	 * corresponding to the MR handle gets a umem_lockmemory() callback.
	 */
	mr->mr_umem_cbfunc = data->mr_func;
	mr->mr_umem_cbarg1 = data->mr_arg1;
	mr->mr_umem_cbarg2 = data->mr_arg2;
	mutex_exit(&mr->mr_lock);

	return (DDI_SUCCESS);
}


/*
 * tavor_umap_ci_data_out()
 *    Context: Can be called from user or kernel context.
 */
/* ARGSUSED */
ibt_status_t
tavor_umap_ci_data_out(tavor_state_t *state, ibt_ci_data_flags_t flags,
    ibt_object_type_t object, void *hdl, void *data_p, size_t data_sz)
{
	int	status;

	/*
	 * Depending on the type of object about which additional information
	 * is being requested (CQ or QP), we call the appropriate resource-
	 * specific mapping function.
	 */
	switch (object) {
	case IBT_HDL_CQ:
		status = tavor_umap_cq_data_out((tavor_cqhdl_t)hdl,
		    (mlnx_umap_cq_data_out_t *)data_p, data_sz);
		if (status != DDI_SUCCESS) {
			return (status);
		}
		break;

	case IBT_HDL_QP:
		status = tavor_umap_qp_data_out((tavor_qphdl_t)hdl,
		    (mlnx_umap_qp_data_out_t *)data_p, data_sz);
		if (status != DDI_SUCCESS) {
			return (status);
		}
		break;

	case IBT_HDL_SRQ:
		status = tavor_umap_srq_data_out((tavor_srqhdl_t)hdl,
		    (mlnx_umap_srq_data_out_t *)data_p, data_sz);
		if (status != DDI_SUCCESS) {
			return (status);
		}
		break;

	/*
	 * For other possible valid IBT types, we return IBT_NOT_SUPPORTED,
	 * since the Tavor driver does not support these.
	 */
	case IBT_HDL_PD:
		status = tavor_umap_pd_data_out((tavor_pdhdl_t)hdl,
		    (mlnx_umap_pd_data_out_t *)data_p, data_sz);
		if (status != DDI_SUCCESS) {
			return (status);
		}
		break;

	case IBT_HDL_HCA:
	case IBT_HDL_MR:
	case IBT_HDL_MW:
	case IBT_HDL_AH:
	case IBT_HDL_SCHED:
	case IBT_HDL_EEC:
	case IBT_HDL_RDD:
		return (IBT_NOT_SUPPORTED);

	/*
	 * Any other types are invalid.
	 */
	default:
		return (IBT_INVALID_PARAM);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_umap_cq_data_out()
 *    Context: Can be called from user or kernel context.
 */
static ibt_status_t
tavor_umap_cq_data_out(tavor_cqhdl_t cq, mlnx_umap_cq_data_out_t *data,
    size_t data_sz)
{
	/* Check for valid CQ handle pointer */
	if (cq == NULL) {
		return (IBT_CQ_HDL_INVALID);
	}

	/* Check for valid CQ mapping structure size */
	if (data_sz < sizeof (mlnx_umap_cq_data_out_t)) {
		return (IBT_INSUFF_RESOURCE);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*data))

	/*
	 * If it has passed all the above checks, then fill in all the useful
	 * mapping information (including the mapping offset that will be
	 * passed back to the devmap() interface during a subsequent mmap()
	 * call.
	 *
	 * The "offset" for CQ mmap()'s looks like this:
	 * +----------------------------------------+--------+--------------+
	 * |		   CQ Number		    |  0x33  | Reserved (0) |
	 * +----------------------------------------+--------+--------------+
	 *	   (64 - 8 - PAGESHIFT) bits	    8 bits	PAGESHIFT bits
	 *
	 * This returns information about the mapping offset, the length of
	 * the CQ memory, the CQ number (for use in later CQ doorbells), the
	 * number of CQEs the CQ memory can hold, and the size of each CQE.
	 */
	data->mcq_rev		= MLNX_UMAP_IF_VERSION;
	data->mcq_mapoffset	= ((((uint64_t)cq->cq_cqnum <<
	    MLNX_UMAP_RSRC_TYPE_SHIFT) | MLNX_UMAP_CQMEM_RSRC) << PAGESHIFT);
	data->mcq_maplen	= cq->cq_cqinfo.qa_size;
	data->mcq_cqnum		= cq->cq_cqnum;
	data->mcq_numcqe	= cq->cq_bufsz;
	data->mcq_cqesz		= sizeof (tavor_hw_cqe_t);

	return (DDI_SUCCESS);
}


/*
 * tavor_umap_qp_data_out()
 *    Context: Can be called from user or kernel context.
 */
static ibt_status_t
tavor_umap_qp_data_out(tavor_qphdl_t qp, mlnx_umap_qp_data_out_t *data,
    size_t data_sz)
{
	/* Check for valid QP handle pointer */
	if (qp == NULL) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Check for valid QP mapping structure size */
	if (data_sz < sizeof (mlnx_umap_qp_data_out_t)) {
		return (IBT_INSUFF_RESOURCE);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*data))

	/*
	 * If it has passed all the checks, then fill in all the useful
	 * mapping information (including the mapping offset that will be
	 * passed back to the devmap() interface during a subsequent mmap()
	 * call.
	 *
	 * The "offset" for QP mmap()'s looks like this:
	 * +----------------------------------------+--------+--------------+
	 * |		   QP Number		    |  0x44  | Reserved (0) |
	 * +----------------------------------------+--------+--------------+
	 *	   (64 - 8 - PAGESHIFT) bits	    8 bits	PAGESHIFT bits
	 *
	 * This returns information about the mapping offset, the length of
	 * the QP memory, and the QP number (for use in later send and recv
	 * doorbells).  It also returns the following information for both
	 * the receive work queue and the send work queue, respectively:  the
	 * offset (from the base mapped address) of the start of the given
	 * work queue, the 64-bit IB virtual address that corresponds to
	 * the base mapped address (needed for posting WQEs though the
	 * QP doorbells), the number of WQEs the given work queue can hold,
	 * and the size of each WQE for the given work queue.
	 */
	data->mqp_rev		= MLNX_UMAP_IF_VERSION;
	data->mqp_mapoffset	= ((((uint64_t)qp->qp_qpnum <<
	    MLNX_UMAP_RSRC_TYPE_SHIFT) | MLNX_UMAP_QPMEM_RSRC) << PAGESHIFT);
	data->mqp_maplen	= qp->qp_wqinfo.qa_size;
	data->mqp_qpnum		= qp->qp_qpnum;

	/*
	 * If this QP is associated with a shared receive queue (SRQ),
	 * then return invalid RecvQ parameters.  Otherwise, return
	 * the proper parameter values.
	 */
	if (qp->qp_srq_en == TAVOR_QP_SRQ_ENABLED) {
		data->mqp_rq_off	= (uint32_t)qp->qp_wqinfo.qa_size;
		data->mqp_rq_desc_addr	= (uint32_t)qp->qp_wqinfo.qa_size;
		data->mqp_rq_numwqe	= 0;
		data->mqp_rq_wqesz	= 0;
	} else {
		data->mqp_rq_off	= (uintptr_t)qp->qp_rq_buf -
		    (uintptr_t)qp->qp_wqinfo.qa_buf_aligned;
		data->mqp_rq_desc_addr	= (uint32_t)((uintptr_t)qp->qp_rq_buf -
		    qp->qp_desc_off);
		data->mqp_rq_numwqe	= qp->qp_rq_bufsz;
		data->mqp_rq_wqesz	= (1 << qp->qp_rq_log_wqesz);
	}
	data->mqp_sq_off	= (uintptr_t)qp->qp_sq_buf -
	    (uintptr_t)qp->qp_wqinfo.qa_buf_aligned;
	data->mqp_sq_desc_addr	= (uint32_t)((uintptr_t)qp->qp_sq_buf -
	    qp->qp_desc_off);
	data->mqp_sq_numwqe	= qp->qp_sq_bufsz;
	data->mqp_sq_wqesz	= (1 << qp->qp_sq_log_wqesz);

	return (DDI_SUCCESS);
}


/*
 * tavor_umap_srq_data_out()
 *    Context: Can be called from user or kernel context.
 */
static ibt_status_t
tavor_umap_srq_data_out(tavor_srqhdl_t srq, mlnx_umap_srq_data_out_t *data,
    size_t data_sz)
{
	/* Check for valid SRQ handle pointer */
	if (srq == NULL) {
		return (IBT_SRQ_HDL_INVALID);
	}

	/* Check for valid SRQ mapping structure size */
	if (data_sz < sizeof (mlnx_umap_srq_data_out_t)) {
		return (IBT_INSUFF_RESOURCE);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*data))

	/*
	 * If it has passed all the checks, then fill in all the useful
	 * mapping information (including the mapping offset that will be
	 * passed back to the devmap() interface during a subsequent mmap()
	 * call.
	 *
	 * The "offset" for SRQ mmap()'s looks like this:
	 * +----------------------------------------+--------+--------------+
	 * |		   SRQ Number		    |  0x66  | Reserved (0) |
	 * +----------------------------------------+--------+--------------+
	 *	   (64 - 8 - PAGESHIFT) bits	    8 bits	PAGESHIFT bits
	 *
	 * This returns information about the mapping offset, the length of the
	 * SRQ memory, and the SRQ number (for use in later send and recv
	 * doorbells).  It also returns the following information for the
	 * shared receive queue: the offset (from the base mapped address) of
	 * the start of the given work queue, the 64-bit IB virtual address
	 * that corresponds to the base mapped address (needed for posting WQEs
	 * though the QP doorbells), the number of WQEs the given work queue
	 * can hold, and the size of each WQE for the given work queue.
	 */
	data->msrq_rev		= MLNX_UMAP_IF_VERSION;
	data->msrq_mapoffset	= ((((uint64_t)srq->srq_srqnum <<
	    MLNX_UMAP_RSRC_TYPE_SHIFT) | MLNX_UMAP_SRQMEM_RSRC) << PAGESHIFT);
	data->msrq_maplen	= srq->srq_wqinfo.qa_size;
	data->msrq_srqnum	= srq->srq_srqnum;

	data->msrq_desc_addr	= (uint32_t)((uintptr_t)srq->srq_wq_buf -
	    srq->srq_desc_off);
	data->msrq_numwqe	= srq->srq_wq_bufsz;
	data->msrq_wqesz	= (1 << srq->srq_wq_log_wqesz);

	return (DDI_SUCCESS);
}

/*
 * tavor_umap_pd_data_out()
 *    Context: Can be called from user or kernel context.
 */
static ibt_status_t
tavor_umap_pd_data_out(tavor_pdhdl_t pd, mlnx_umap_pd_data_out_t *data,
    size_t data_sz)
{
	/* Check for valid PD handle pointer */
	if (pd == NULL) {
		return (IBT_PD_HDL_INVALID);
	}

	/* Check for valid PD mapping structure size */
	if (data_sz < sizeof (mlnx_umap_pd_data_out_t)) {
		return (IBT_INSUFF_RESOURCE);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*data))

	/*
	 * If it has passed all the checks, then fill the PD table index
	 * (the PD table allocated index for the PD pd_pdnum)
	 */
	data->mpd_rev	= MLNX_UMAP_IF_VERSION;
	data->mpd_pdnum	= pd->pd_pdnum;

	return (DDI_SUCCESS);
}

/*
 * tavor_umap_db_init()
 *    Context: Only called from attach() path context
 */
void
tavor_umap_db_init(void)
{
	/*
	 * Initialize the lock used by the Tavor "userland resources database"
	 * This is used to ensure atomic access to add, remove, and find
	 * entries in the database.
	 */
	mutex_init(&tavor_userland_rsrc_db.tdl_umapdb_lock, NULL,
	    MUTEX_DRIVER, NULL);

	/*
	 * Initialize the AVL tree used for the "userland resources
	 * database".  Using an AVL tree here provides the ability to
	 * scale the database size to large numbers of resources.  The
	 * entries in the tree are "tavor_umap_db_entry_t".
	 * The tree is searched with the help of the
	 * tavor_umap_db_compare() routine.
	 */
	avl_create(&tavor_userland_rsrc_db.tdl_umapdb_avl,
	    tavor_umap_db_compare, sizeof (tavor_umap_db_entry_t),
	    offsetof(tavor_umap_db_entry_t, tdbe_avlnode));
}


/*
 * tavor_umap_db_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
tavor_umap_db_fini(void)
{
	/* Destroy the AVL tree for the "userland resources database" */
	avl_destroy(&tavor_userland_rsrc_db.tdl_umapdb_avl);

	/* Destroy the lock for the "userland resources database" */
	mutex_destroy(&tavor_userland_rsrc_db.tdl_umapdb_lock);
}


/*
 * tavor_umap_db_alloc()
 *    Context: Can be called from user or kernel context.
 */
tavor_umap_db_entry_t *
tavor_umap_db_alloc(uint_t instance, uint64_t key, uint_t type, uint64_t value)
{
	tavor_umap_db_entry_t	*umapdb;

	/* Allocate an entry to add to the "userland resources database" */
	umapdb = kmem_zalloc(sizeof (tavor_umap_db_entry_t), KM_NOSLEEP);
	if (umapdb == NULL) {
		return (NULL);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*umapdb))

	/* Fill in the fields in the database entry */
	umapdb->tdbe_common.tdb_instance  = instance;
	umapdb->tdbe_common.tdb_type	  = type;
	umapdb->tdbe_common.tdb_key	  = key;
	umapdb->tdbe_common.tdb_value	  = value;

	return (umapdb);
}


/*
 * tavor_umap_db_free()
 *    Context: Can be called from user or kernel context.
 */
void
tavor_umap_db_free(tavor_umap_db_entry_t *umapdb)
{
	/* Free the database entry */
	kmem_free(umapdb, sizeof (tavor_umap_db_entry_t));
}


/*
 * tavor_umap_db_add()
 *    Context: Can be called from user or kernel context.
 */
void
tavor_umap_db_add(tavor_umap_db_entry_t *umapdb)
{
	mutex_enter(&tavor_userland_rsrc_db.tdl_umapdb_lock);
	tavor_umap_db_add_nolock(umapdb);
	mutex_exit(&tavor_userland_rsrc_db.tdl_umapdb_lock);
}


/*
 * tavor_umap_db_add_nolock()
 *    Context: Can be called from user or kernel context.
 */
void
tavor_umap_db_add_nolock(tavor_umap_db_entry_t *umapdb)
{
	tavor_umap_db_query_t	query;
	avl_index_t		where;

	ASSERT(MUTEX_HELD(&tavor_userland_rsrc_db.tdl_umapdb_lock));

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*umapdb))

	/*
	 * Copy the common portion of the "to-be-added" database entry
	 * into the "tavor_umap_db_query_t" structure.  We use this structure
	 * (with no flags set) to find the appropriate location in the
	 * "userland resources database" for the new entry to be added.
	 *
	 * Note: we expect that this entry should not be found in the
	 * database (unless something bad has happened).
	 */
	query.tqdb_common = umapdb->tdbe_common;
	query.tqdb_flags  = 0;
	(void) avl_find(&tavor_userland_rsrc_db.tdl_umapdb_avl, &query,
	    &where);

	/*
	 * Now, using the "where" field from the avl_find() operation
	 * above, we will insert the new database entry ("umapdb").
	 */
	avl_insert(&tavor_userland_rsrc_db.tdl_umapdb_avl, umapdb,
	    where);
}


/*
 * tavor_umap_db_find()
 *    Context: Can be called from user or kernel context.
 */
int
tavor_umap_db_find(uint_t instance, uint64_t key, uint_t type,
    uint64_t *value, uint_t flag, tavor_umap_db_entry_t	**umapdb)
{
	int	status;

	mutex_enter(&tavor_userland_rsrc_db.tdl_umapdb_lock);
	status = tavor_umap_db_find_nolock(instance, key, type, value, flag,
	    umapdb);
	mutex_exit(&tavor_userland_rsrc_db.tdl_umapdb_lock);

	return (status);
}


/*
 * tavor_umap_db_find_nolock()
 *    Context: Can be called from user or kernel context.
 */
int
tavor_umap_db_find_nolock(uint_t instance, uint64_t key, uint_t type,
    uint64_t *value, uint_t flags, tavor_umap_db_entry_t **umapdb)
{
	tavor_umap_db_query_t	query;
	tavor_umap_db_entry_t	*entry;
	avl_index_t		where;

	ASSERT(MUTEX_HELD(&tavor_userland_rsrc_db.tdl_umapdb_lock));

	/*
	 * Fill in key, type, instance, and flags values of the
	 * tavor_umap_db_query_t in preparation for the database
	 * lookup.
	 */
	query.tqdb_flags		= flags;
	query.tqdb_common.tdb_key	= key;
	query.tqdb_common.tdb_type	= type;
	query.tqdb_common.tdb_instance	= instance;

	/*
	 * Perform the database query.  If no entry is found, then
	 * return failure, else continue.
	 */
	entry = (tavor_umap_db_entry_t *)avl_find(
	    &tavor_userland_rsrc_db.tdl_umapdb_avl, &query, &where);
	if (entry == NULL) {
		return (DDI_FAILURE);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*entry))

	/*
	 * If the flags argument specifies that the entry should
	 * be removed if found, then call avl_remove() to remove
	 * the entry from the database.
	 */
	if (flags & TAVOR_UMAP_DB_REMOVE) {

		avl_remove(&tavor_userland_rsrc_db.tdl_umapdb_avl, entry);

		/*
		 * The database entry is returned with the expectation
		 * that the caller will use tavor_umap_db_free() to
		 * free the entry's memory.  ASSERT that this is non-NULL.
		 * NULL pointer should never be passed for the
		 * TAVOR_UMAP_DB_REMOVE case.
		 */
		ASSERT(umapdb != NULL);
	}

	/*
	 * If the caller would like visibility to the database entry
	 * (indicated through the use of a non-NULL "umapdb" argument),
	 * then fill it in.
	 */
	if (umapdb != NULL) {
		*umapdb = entry;
	}

	/* Extract value field from database entry and return success */
	*value = entry->tdbe_common.tdb_value;

	return (DDI_SUCCESS);
}


/*
 * tavor_umap_umemlock_cb()
 *    Context: Can be called from callback context.
 */
void
tavor_umap_umemlock_cb(ddi_umem_cookie_t *umem_cookie)
{
	tavor_umap_db_entry_t	*umapdb;
	tavor_state_t		*state;
	tavor_rsrc_t 		*rsrcp;
	tavor_mrhdl_t		mr;
	uint64_t		value;
	uint_t			instance;
	int			status;
	void			(*mr_callback)(void *, void *);
	void			*mr_cbarg1, *mr_cbarg2;

	/*
	 * If this was userland memory, then we need to remove its entry
	 * from the "userland resources database".  Note:  We use the
	 * TAVOR_UMAP_DB_IGNORE_INSTANCE flag here because we don't know
	 * which instance was used when the entry was added (but we want
	 * to know after the entry is found using the other search criteria).
	 */
	status = tavor_umap_db_find(0, (uint64_t)(uintptr_t)umem_cookie,
	    MLNX_UMAP_MRMEM_RSRC, &value, (TAVOR_UMAP_DB_REMOVE |
	    TAVOR_UMAP_DB_IGNORE_INSTANCE), &umapdb);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*umapdb))
	if (status == DDI_SUCCESS) {
		instance = umapdb->tdbe_common.tdb_instance;
		state = ddi_get_soft_state(tavor_statep, instance);
		if (state == NULL) {
			cmn_err(CE_WARN, "Unable to match Tavor instance\n");
			return;
		}

		/* Free the database entry */
		tavor_umap_db_free(umapdb);

		/* Use "value" to convert to an MR handle */
		rsrcp = (tavor_rsrc_t *)(uintptr_t)value;
		mr = (tavor_mrhdl_t)rsrcp->tr_addr;

		/*
		 * If a callback has been provided, call it first.  This
		 * callback is expected to do any cleanup necessary to
		 * guarantee that the subsequent MR deregister (below)
		 * will succeed.  Specifically, this means freeing up memory
		 * windows which might have been associated with the MR.
		 */
		mutex_enter(&mr->mr_lock);
		mr_callback = mr->mr_umem_cbfunc;
		mr_cbarg1   = mr->mr_umem_cbarg1;
		mr_cbarg2   = mr->mr_umem_cbarg2;
		mutex_exit(&mr->mr_lock);
		if (mr_callback != NULL) {
			mr_callback(mr_cbarg1, mr_cbarg2);
		}

		/*
		 * Then call tavor_mr_deregister() to release the resources
		 * associated with the MR handle.  Note: Because this routine
		 * will also check for whether the ddi_umem_cookie_t is in the
		 * database, it will take responsibility for disabling the
		 * memory region and calling ddi_umem_unlock().
		 */
		status = tavor_mr_deregister(state, &mr, TAVOR_MR_DEREG_ALL,
		    TAVOR_SLEEP);
		if (status != DDI_SUCCESS) {
			TAVOR_WARNING(state, "Unexpected failure in "
			    "deregister from callback\n");
		}
	}
}


/*
 * tavor_umap_db_compare()
 *    Context: Can be called from user or kernel context.
 */
static int
tavor_umap_db_compare(const void *q, const void *e)
{
	tavor_umap_db_common_t	*entry_common, *query_common;
	uint_t			query_flags;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*((tavor_umap_db_query_t *)q)))

	entry_common = &((tavor_umap_db_entry_t *)e)->tdbe_common;
	query_common = &((tavor_umap_db_query_t *)q)->tqdb_common;
	query_flags  = ((tavor_umap_db_query_t *)q)->tqdb_flags;

	/*
	 * The first comparison is done on the "key" value in "query"
	 * and "entry".  If they are not equal, then the appropriate
	 * search direction is returned.  Else, we continue by
	 * comparing "type".
	 */
	if (query_common->tdb_key < entry_common->tdb_key) {
		return (-1);
	} else if (query_common->tdb_key > entry_common->tdb_key) {
		return (+1);
	}

	/*
	 * If the search reaches this point, then "query" and "entry"
	 * have equal key values.  So we continue be comparing their
	 * "type" values.  Again, if they are not equal, then the
	 * appropriate search direction is returned.  Else, we continue
	 * by comparing "instance".
	 */
	if (query_common->tdb_type < entry_common->tdb_type) {
		return (-1);
	} else if (query_common->tdb_type > entry_common->tdb_type) {
		return (+1);
	}

	/*
	 * If the search reaches this point, then "query" and "entry"
	 * have exactly the same key and type values.  Now we consult
	 * the "flags" field in the query to determine whether the
	 * "instance" is relevant to the search.  If the
	 * TAVOR_UMAP_DB_IGNORE_INSTANCE flags is set, then return
	 * success (0) here.  Otherwise, continue the search by comparing
	 * instance values and returning the appropriate search direction.
	 */
	if (query_flags & TAVOR_UMAP_DB_IGNORE_INSTANCE) {
		return (0);
	}

	/*
	 * If the search has reached this point, then "query" and "entry"
	 * can only be differentiated by their instance values.  If these
	 * are not equal, then return the appropriate search direction.
	 * Else, we return success (0).
	 */
	if (query_common->tdb_instance < entry_common->tdb_instance) {
		return (-1);
	} else if (query_common->tdb_instance > entry_common->tdb_instance) {
		return (+1);
	}

	/* Everything matches... so return success */
	return (0);
}


/*
 * tavor_umap_db_set_onclose_cb()
 *    Context: Can be called from user or kernel context.
 */
int
tavor_umap_db_set_onclose_cb(dev_t dev, uint64_t flag,
    void (*callback)(void *), void *arg)
{
	tavor_umap_db_priv_t	*priv;
	tavor_umap_db_entry_t	*umapdb;
	minor_t			instance;
	uint64_t		value;
	int			status;

	instance = TAVOR_DEV_INSTANCE(dev);
	if (instance == -1) {
		return (DDI_FAILURE);
	}

	if (flag != TAVOR_ONCLOSE_FLASH_INPROGRESS) {
		return (DDI_FAILURE);
	}

	/*
	 * Grab the lock for the "userland resources database" and find
	 * the entry corresponding to this minor number.  Once it's found,
	 * allocate (if necessary) and add an entry (in the "tdb_priv"
	 * field) to indicate that further processing may be needed during
	 * Tavor's close() handling.
	 */
	mutex_enter(&tavor_userland_rsrc_db.tdl_umapdb_lock);
	status = tavor_umap_db_find_nolock(instance, dev,
	    MLNX_UMAP_PID_RSRC, &value, 0, &umapdb);
	if (status != DDI_SUCCESS) {
		mutex_exit(&tavor_userland_rsrc_db.tdl_umapdb_lock);
		return (DDI_FAILURE);
	}

	priv = (tavor_umap_db_priv_t *)umapdb->tdbe_common.tdb_priv;
	if (priv == NULL) {
		priv = (tavor_umap_db_priv_t *)kmem_zalloc(
		    sizeof (tavor_umap_db_priv_t), KM_NOSLEEP);
		if (priv == NULL) {
			mutex_exit(&tavor_userland_rsrc_db.tdl_umapdb_lock);
			return (DDI_FAILURE);
		}
	}

	/*
	 * Save away the callback and argument to be used during Tavor's
	 * close() processing.
	 */
	priv->tdp_cb	= callback;
	priv->tdp_arg	= arg;

	umapdb->tdbe_common.tdb_priv = (void *)priv;
	mutex_exit(&tavor_userland_rsrc_db.tdl_umapdb_lock);

	return (DDI_SUCCESS);
}


/*
 * tavor_umap_db_clear_onclose_cb()
 *    Context: Can be called from user or kernel context.
 */
int
tavor_umap_db_clear_onclose_cb(dev_t dev, uint64_t flag)
{
	tavor_umap_db_priv_t	*priv;
	tavor_umap_db_entry_t	*umapdb;
	minor_t			instance;
	uint64_t		value;
	int			status;

	instance = TAVOR_DEV_INSTANCE(dev);
	if (instance == -1) {
		return (DDI_FAILURE);
	}

	if (flag != TAVOR_ONCLOSE_FLASH_INPROGRESS) {
		return (DDI_FAILURE);
	}

	/*
	 * Grab the lock for the "userland resources database" and find
	 * the entry corresponding to this minor number.  Once it's found,
	 * remove the entry (in the "tdb_priv" field) that indicated the
	 * need for further processing during Tavor's close().  Free the
	 * entry, if appropriate.
	 */
	mutex_enter(&tavor_userland_rsrc_db.tdl_umapdb_lock);
	status = tavor_umap_db_find_nolock(instance, dev,
	    MLNX_UMAP_PID_RSRC, &value, 0, &umapdb);
	if (status != DDI_SUCCESS) {
		mutex_exit(&tavor_userland_rsrc_db.tdl_umapdb_lock);
		return (DDI_FAILURE);
	}

	priv = (tavor_umap_db_priv_t *)umapdb->tdbe_common.tdb_priv;
	if (priv != NULL) {
		kmem_free(priv, sizeof (tavor_umap_db_priv_t));
		priv = NULL;
	}

	umapdb->tdbe_common.tdb_priv = (void *)priv;
	mutex_exit(&tavor_userland_rsrc_db.tdl_umapdb_lock);
	return (DDI_SUCCESS);
}


/*
 * tavor_umap_db_clear_onclose_cb()
 *    Context: Can be called from user or kernel context.
 */
void
tavor_umap_db_handle_onclose_cb(tavor_umap_db_priv_t *priv)
{
	void	(*callback)(void *);

	ASSERT(MUTEX_HELD(&tavor_userland_rsrc_db.tdl_umapdb_lock));

	/*
	 * Call the callback.
	 *    Note: Currently there is only one callback (in "tdp_cb"), but
	 *    in the future there may be more, depending on what other types
	 *    of interaction there are between userland processes and the
	 *    driver.
	 */
	callback = priv->tdp_cb;
	callback(priv->tdp_arg);
}
