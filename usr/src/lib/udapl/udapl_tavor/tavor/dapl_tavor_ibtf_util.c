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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_evd_util.h"
#include "dapl_cr_util.h"
#include "dapl_lmr_util.h"
#include "dapl_rmr_util.h"
#include "dapl_cookie.h"
#include "dapl_ring_buffer_util.h"
#include "dapl_vendor.h"
#include "dapl_tavor_ibtf_impl.h"

/* Function prototypes */
static DAT_RETURN dapli_ib_cq_resize_internal(DAPL_EVD *, DAT_COUNT);

/*
 * The following declarations/fn are to used by the base library
 * place holder for now
 */

int	g_loopback_connection = 0;

/*
 * dapl_ib_cq_alloc
 *
 * Alloc a CQ
 *
 * Input:
 *	ia_handle		IA handle
 *	evd_ptr			pointer to EVD struct
 *	cno_ptr			pointer to CNO struct
 *	cqlen			minimum QLen
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_cq_alloc(
	IN  DAPL_IA		*ia_ptr,
	IN  DAPL_EVD		*evd_ptr,
	IN  DAPL_CNO		*cno_ptr,
	IN  DAT_COUNT		*cqlen)
{
	dapl_evd_create_t	create_msg;
	dapl_evd_free_t		free_msg;
	ib_cq_handle_t		cq_handle = IB_INVALID_HANDLE;
	int			ia_fd;
	int			hca_fd;
	int			retval;
	mlnx_umap_cq_data_out_t	*mcq;

	/* cq handle is created even for non-cq type events */
	/* since cq handle is where the evd fd gets stored. */
	cq_handle = (ib_cq_handle_t)
	    dapl_os_alloc(sizeof (struct dapls_ib_cq_handle));
	if (cq_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "cq_alloc: evd_ptr 0x%p, cq_handle == NULL\n",
		    evd_ptr);
		return (DAT_INSUFFICIENT_RESOURCES);
	}

	(void) dapl_os_memzero(cq_handle, sizeof (*cq_handle));

	/* get the hca information from ia_ptr */
	(void) dapl_os_memzero(&create_msg, sizeof (create_msg));
	create_msg.evd_flags = evd_ptr->evd_flags;
	create_msg.evd_cookie = (uintptr_t)evd_ptr;
	if (cno_ptr != NULL) {
		create_msg.evd_cno_hkey =
		    (uint64_t)cno_ptr->ib_cno_handle;
	}
	if (evd_ptr->evd_flags & (DAT_EVD_DTO_FLAG | DAT_EVD_RMR_BIND_FLAG)) {
		create_msg.evd_cq_size = (uint32_t)*cqlen;
	}

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "cq_alloc: evd 0x%p, flags 0x%x, cookie 0x%llx, hkey 0x%llx,\n"
	    "          cno_hkey 0x%llx, cq_size %d\n", evd_ptr,
	    create_msg.evd_flags, create_msg.evd_cookie, create_msg.evd_hkey,
	    create_msg.evd_cno_hkey, create_msg.evd_cq_size);

	ia_fd = ia_ptr->hca_ptr->ib_hca_handle->ia_fd;
	hca_fd = ia_ptr->hca_ptr->ib_hca_handle->hca_fd;
	mcq = (mlnx_umap_cq_data_out_t *)create_msg.evd_cq_data_out;

	/* The next line is only needed for backward compatibility */
	mcq->mcq_rev = MLNX_UMAP_IF_VERSION;

	/* call into driver to allocate cq */
	retval = ioctl(ia_fd, DAPL_EVD_CREATE, &create_msg);
	if (retval != 0 || mcq->mcq_rev != MLNX_UMAP_IF_VERSION) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "cq_alloc: evd_create failed, %s\n", strerror(errno));
		dapl_os_free(cq_handle, sizeof (struct dapls_ib_cq_handle));
		return (dapls_convert_error(errno, retval));
	}
	(void) dapl_os_memzero(cq_handle, sizeof (struct dapls_ib_cq_handle));
	dapl_os_lock_init(&cq_handle->cq_wrid_wqhdr_lock);

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "cq_alloc: created, evd 0x%p, hkey 0x%016llx\n\n", evd_ptr,
	    create_msg.evd_hkey);

	cq_handle->evd_hkey = create_msg.evd_hkey;

	if (evd_ptr->evd_flags & (DAT_EVD_DTO_FLAG | DAT_EVD_RMR_BIND_FLAG)) {

		/*
		 * allocate a hash table for wrid management, the key is
		 * a combination of QPnumber and SEND/RECV type. This is
		 * required only for evd which have a CQ mapped to
		 * it.
		 */
		if (DAT_SUCCESS != dapls_hash_create(DAPL_MED_HASHSIZE,
		    DAT_FALSE, &cq_handle->cq_wrid_wqhdr_list)) {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "cq_alloc: hash_create failed\n");
			dapl_os_free(cq_handle,
			    sizeof (struct dapls_ib_cq_handle));
			return (DAT_INSUFFICIENT_RESOURCES |
			    DAT_RESOURCE_MEMORY);
		}

		dapl_os_assert(create_msg.evd_cq_real_size > 0);

		/* In the case of Arbel or Hermon */
		if (mcq->mcq_polldbr_mapoffset != 0 ||
		    mcq->mcq_polldbr_maplen != 0)
			cq_handle->cq_poll_dbp = dapls_ib_get_dbp(
			    mcq->mcq_polldbr_maplen, hca_fd,
			    mcq->mcq_polldbr_mapoffset,
			    mcq->mcq_polldbr_offset);
		if (mcq->mcq_armdbr_mapoffset != 0 ||
		    mcq->mcq_armdbr_maplen != 0)
			cq_handle->cq_arm_dbp = dapls_ib_get_dbp(
			    mcq->mcq_armdbr_maplen, hca_fd,
			    mcq->mcq_armdbr_mapoffset,
			    mcq->mcq_armdbr_offset);

		cq_handle->cq_addr = (tavor_hw_cqe_t *)(void *) mmap64(
		    (void *)0, mcq->mcq_maplen,
		    (PROT_READ | PROT_WRITE), MAP_SHARED, hca_fd,
		    mcq->mcq_mapoffset);

		if (cq_handle->cq_addr == MAP_FAILED ||
		    cq_handle->cq_poll_dbp == MAP_FAILED ||
		    cq_handle->cq_arm_dbp == MAP_FAILED) {
			free_msg.evf_hkey = cq_handle->evd_hkey;
			retval = ioctl(ia_fd, DAPL_EVD_FREE, &free_msg);
			if (retval != 0) {
				dapl_dbg_log(DAPL_DBG_TYPE_ERR,
				    "cq_alloc: EVD_FREE err:%s\n",
				    strerror(errno));
			}

			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "cq_alloc: DAPL_CQ_ALLOC failed\n");
			/* free the hash table we created */
			(void) dapls_hash_free(cq_handle->cq_wrid_wqhdr_list);
			dapl_os_free(cq_handle,
			    sizeof (struct dapls_ib_cq_handle));
			return (DAT_INSUFFICIENT_RESOURCES);
		}

		cq_handle->cq_map_offset = mcq->mcq_mapoffset;
		cq_handle->cq_map_len = mcq->mcq_maplen;
		cq_handle->cq_num = mcq->mcq_cqnum;
		/*
		 * cq_size is the actual depth of the CQ which is 1 more
		 * than what ibt_alloc_cq reports. However the application
		 * can only use (cq_size - 1) entries.
		 */
		cq_handle->cq_size = create_msg.evd_cq_real_size + 1;
		cq_handle->cq_cqesz = mcq->mcq_cqesz;
		cq_handle->cq_iauar = ia_ptr->hca_ptr->ib_hca_handle->ia_uar;
		*cqlen = create_msg.evd_cq_real_size;

		DAPL_INIT_CQ(ia_ptr)(cq_handle);
	}

	evd_ptr->ib_cq_handle = cq_handle;
	return (DAT_SUCCESS);
}


/*
 * dapl_ib_cq_resize
 *
 * Resize a CQ
 *
 * Input:
 *	evd_ptr			pointer to EVD struct
 *	cqlen			new length of the cq
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *	DAT_INTERNAL_ERROR
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_cq_resize(
	IN  DAPL_EVD		*evd_ptr,
	IN  DAT_COUNT		cqlen)
{
	ib_cq_handle_t	cq_handle;
	DAT_RETURN	dat_status;

	dat_status = dapli_ib_cq_resize_internal(evd_ptr, cqlen);
	if (DAT_INSUFFICIENT_RESOURCES == dat_status) {
		cq_handle = evd_ptr->ib_cq_handle;
		/* attempt to resize back to the current size */
		dat_status = dapli_ib_cq_resize_internal(evd_ptr,
		    cq_handle->cq_size - 1);
		if (DAT_SUCCESS != dat_status) {
			/*
			 * XXX this is catastrophic need to post an event
			 * to the async evd
			 */
			return (DAT_INTERNAL_ERROR);
		}
	}

	return (dat_status);
}

/*
 * dapli_ib_cq_resize_internal
 *
 * An internal routine to resize a CQ.
 *
 * Input:
 *	evd_ptr			pointer to EVD struct
 *	cqlen			new length of the cq
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
static DAT_RETURN
dapli_ib_cq_resize_internal(
	IN  DAPL_EVD		*evd_ptr,
	IN  DAT_COUNT		cqlen)
{
	ib_cq_handle_t		cq_handle;
	dapl_cq_resize_t	resize_msg;
	int			ia_fd;
	int			hca_fd;
	int			retval;
	mlnx_umap_cq_data_out_t	*mcq;
	DAPL_HCA		*hca_ptr;
	dapls_hw_cqe_t		cq_addr;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "dapls_ib_cq_resize: evd 0x%p cq 0x%p "
	    "evd_hkey 0x%016llx cqlen %d\n",
	    evd_ptr, (void *)evd_ptr->ib_cq_handle,
	    evd_ptr->ib_cq_handle->evd_hkey, cqlen);

	cq_handle = evd_ptr->ib_cq_handle;
	/*
	 * Since CQs are created in powers of 2 with one non-usable slot,
	 * its possible that the previously allocated CQ has sufficient
	 * entries. If the current cq is big enough and it is mapped in
	 * we are done.
	 */
	if ((cqlen < cq_handle->cq_size) && (cq_handle->cq_addr)) {
		return (DAT_SUCCESS);
	}

	hca_ptr = evd_ptr->header.owner_ia->hca_ptr;

	/* unmap the CQ before resizing it */
	if (hca_ptr->hermon_resize_cq == 0) {
		if ((cq_handle->cq_addr) &&
		    (munmap((char *)cq_handle->cq_addr,
		    cq_handle->cq_map_len) < 0)) {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "cq_resize: munmap(%p:0x%llx) failed(%d)\n",
			    cq_handle->cq_addr, cq_handle->cq_map_len, errno);
			return (DAT_INVALID_HANDLE);
		}
		/* cq_addr is unmapped and no longer valid */
		cq_handle->cq_addr = NULL;
	}

	ia_fd = hca_ptr->ib_hca_handle->ia_fd;
	hca_fd = hca_ptr->ib_hca_handle->hca_fd;

	(void) dapl_os_memzero(&resize_msg, sizeof (resize_msg));
	mcq = (mlnx_umap_cq_data_out_t *)resize_msg.cqr_cq_data_out;
	resize_msg.cqr_evd_hkey = cq_handle->evd_hkey;
	resize_msg.cqr_cq_new_size = cqlen;

	/* The next line is only needed for backward compatibility */
	mcq->mcq_rev = MLNX_UMAP_IF_VERSION;
	retval = ioctl(ia_fd, DAPL_CQ_RESIZE, &resize_msg);
	if (retval != 0 || mcq->mcq_rev != MLNX_UMAP_IF_VERSION) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapls_ib_cq_resize: evd 0x%p, err: %s\n",
		    evd_ptr, strerror(errno));
		if (errno == EINVAL) { /* Couldn't find evd for this cq */
			return (DAT_INVALID_HANDLE);
		} else { /* Need to retry resize with a smaller qlen */
			return (DAT_INSUFFICIENT_RESOURCES);
		}
	}

	dapl_os_assert(cq_handle->cq_num == mcq->mcq_cqnum);

	/* In the case of Arbel or Hermon */
	if (mcq->mcq_polldbr_mapoffset != 0 ||
	    mcq->mcq_polldbr_maplen != 0)
		cq_handle->cq_poll_dbp = dapls_ib_get_dbp(
		    mcq->mcq_polldbr_maplen, hca_fd,
		    mcq->mcq_polldbr_mapoffset,
		    mcq->mcq_polldbr_offset);
	if (mcq->mcq_armdbr_mapoffset != 0 ||
	    mcq->mcq_armdbr_maplen != 0)
		cq_handle->cq_arm_dbp = dapls_ib_get_dbp(
		    mcq->mcq_armdbr_maplen, hca_fd,
		    mcq->mcq_armdbr_mapoffset,
		    mcq->mcq_armdbr_offset);

	cq_addr = (tavor_hw_cqe_t *)(void *)mmap64((void *)0,
	    mcq->mcq_maplen, (PROT_READ | PROT_WRITE),
	    MAP_SHARED, hca_fd, mcq->mcq_mapoffset);

	if (cq_addr == MAP_FAILED ||
	    cq_handle->cq_poll_dbp == MAP_FAILED ||
	    cq_handle->cq_arm_dbp == MAP_FAILED) {
		if (hca_ptr->hermon_resize_cq == 0)
			cq_handle->cq_addr = NULL;
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "cq_resize: mmap failed(%d)\n", errno);
		/* Need to retry resize with a smaller qlen */
		return (DAT_INSUFFICIENT_RESOURCES);
	}

	if (hca_ptr->hermon_resize_cq == 0) {
		cq_handle->cq_addr = cq_addr;
		cq_handle->cq_map_offset = mcq->mcq_mapoffset;
		cq_handle->cq_map_len = mcq->mcq_maplen;
		cq_handle->cq_size = resize_msg.cqr_cq_real_size + 1;
		cq_handle->cq_cqesz = mcq->mcq_cqesz;
		/*
		 * upon resize the old events are moved to the start of the CQ
		 * hence we need to reset the consumer index too
		 */
		cq_handle->cq_consindx = 0;
	} else {	/* Hermon */
		cq_handle->cq_resize_addr = cq_addr;
		cq_handle->cq_resize_map_offset = mcq->mcq_mapoffset;
		cq_handle->cq_resize_map_len = mcq->mcq_maplen;
		cq_handle->cq_resize_size = resize_msg.cqr_cq_real_size + 1;
		cq_handle->cq_resize_cqesz = mcq->mcq_cqesz;
	}

	return (DAT_SUCCESS);
}

/*
 * dapl_ib_cq_free
 *
 * Free a CQ
 *
 * Input:
 *	ia_handle		IA handle
 *	evd_ptr			pointer to EVD struct
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_cq_free(
	IN  DAPL_IA		*ia_ptr,
	IN  DAPL_EVD		*evd_ptr)
{
	dapl_evd_free_t		args;
	int			retval;
	ib_cq_handle_t		cq_handle = evd_ptr->ib_cq_handle;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "dapls_ib_cq_free: evd 0x%p cq 0x%p hkey %016llx\n", evd_ptr,
	    (void *)evd_ptr->ib_cq_handle, evd_ptr->ib_cq_handle->evd_hkey);

	/* If the cq was mmap'd unmap it before freeing it */
	if ((cq_handle->cq_addr) &&
	    (munmap((char *)cq_handle->cq_addr, cq_handle->cq_map_len) < 0)) {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "cq_free: (%p:0x%llx)\n", cq_handle->cq_addr,
			    cq_handle->cq_map_len);
	}


	args.evf_hkey = cq_handle->evd_hkey;

	retval = ioctl(ia_ptr->hca_ptr->ib_hca_handle->ia_fd,
	    DAPL_EVD_FREE, &args);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapls_ib_cq_free: evd 0x%p, err: %s\n",
		    evd_ptr, strerror(errno));
		return (dapls_convert_error(errno, retval));
	}

	dapl_os_free(cq_handle, sizeof (struct dapls_ib_cq_handle));
	evd_ptr->ib_cq_handle = NULL;

	return (DAT_SUCCESS);
}

/*
 * dapl_set_cq_notify
 *
 * Set up CQ completion notifications
 *
 * Input:
 *	ia_handle		IA handle
 *	evd_ptr			pointer to EVD struct
 *
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
/* ARGSUSED */
DAT_RETURN
dapls_set_cq_notify(
	IN  DAPL_IA		*ia_ptr,
	IN  DAPL_EVD		*evd_ptr)
{
	int			retval;
	ib_cq_handle_t		cq_handle = evd_ptr->ib_cq_handle;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "dapls_ib_cq_notify: evd 0x%p cq 0x%p\n", evd_ptr,
	    (void *)cq_handle);

	retval = DAPL_NOTIFY(evd_ptr)(cq_handle, IB_NOTIFY_ON_NEXT_COMP, 0);

	return (retval);

}

/* ARGSUSED */
DAT_RETURN
dapls_set_cqN_notify(
	IN  DAPL_IA		*ia_ptr,
	IN  DAPL_EVD		*evd_ptr,
	IN  uint32_t		num_events)
{
	int			retval;
	ib_cq_handle_t		cq_handle = evd_ptr->ib_cq_handle;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "dapls_set_cqN_notify:evd %p cq %p num_events %d\n", evd_ptr,
	    (void *)cq_handle, num_events);

	retval = DAPL_NOTIFY(evd_ptr)(cq_handle, IB_NOTIFY_ON_NEXT_NCOMP,
	    num_events);

	return (retval);

}

/*
 * dapls_ib_cqd_create
 *
 * Set up CQ notification event thread
 *
 * Input:
 *	ia_handle		IA handle
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
/* ARGSUSED */
DAT_RETURN
dapls_ib_cqd_create(
	IN  DAPL_HCA		*hca_ptr)
{
	return (DAT_SUCCESS);
}


/*
 * dapl_cqd_destroy
 *
 * Destroy CQ notification event thread
 *
 * Input:
 *	ia_handle		IA handle
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_cqd_destroy(
	IN  DAPL_HCA		*hca_ptr)
{
	dapl_evd_free_t		args;
	ib_cq_handle_t		cq_handle;
	int			retval;

	if (hca_ptr->null_ib_cq_handle != IB_INVALID_HANDLE) {
		/* free up the dummy cq */
		cq_handle = hca_ptr->null_ib_cq_handle;
		dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
		    "dapls_ib_cqd_destroy: cq %p\n", (void *)cq_handle);

		args.evf_hkey = cq_handle->evd_hkey;

		retval = ioctl(hca_ptr->ib_hca_handle->ia_fd,
		    DAPL_EVD_FREE, &args);
		if (retval != 0) {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "dapls_ib_cqd_destroy: EVD_FREE err:%d errno:%d\n",
			    retval, errno);
		}

		dapl_os_free(cq_handle, sizeof (struct dapls_ib_cq_handle));
		hca_ptr->null_ib_cq_handle = IB_INVALID_HANDLE;
	}

	return (DAT_SUCCESS);
}


/*
 * dapl_ib_pd_alloc
 *
 * Alloc a PD
 *
 * Input:
 *	ia_handle		IA handle
 *	PZ_ptr			pointer to PZEVD struct
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_pd_alloc(
	IN  DAPL_IA 		*ia,
	IN  DAPL_PZ 		*pz)
{
	struct dapls_ib_pd_handle *pd_p;
	dapl_pd_alloc_t args;
	int retval;

	pd_p = (struct dapls_ib_pd_handle *)dapl_os_alloc(sizeof (*pd_p));
	if (pd_p == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "pd_alloc: ia 0x%p, pz 0x%p, cannot allocate pd\n",
		    ia, pz);
		return (DAT_INSUFFICIENT_RESOURCES);
	}
	retval = ioctl(ia->hca_ptr->ib_hca_handle->ia_fd,
	    DAPL_PD_ALLOC, &args);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "pd_alloc: ia 0x%p, pz 0x%p, cannot create pd, "
		    "err: %s\n", ia, pz, strerror(errno));
		dapl_os_free(pd_p, sizeof (*pd_p));
		return (dapls_convert_error(errno, retval));
	}

	pd_p->pd_hkey = args.pda_hkey;
	pz->pd_handle = pd_p;
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "pd_alloc: successful, ia 0x%p, pz 0x%p, hkey %016llx\n",
	    ia, pz, args.pda_hkey);

	return (DAT_SUCCESS);
}


/*
 * dapl_ib_pd_free
 *
 * Free a PD
 *
 * Input:
 *	ia_handle		IA handle
 *	PZ_ptr			pointer to PZ struct
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_pd_free(
	IN  DAPL_PZ 		*pz)
{
	struct dapls_ib_pd_handle *pd_p;
	dapl_pd_free_t args;
	int retval;

	pd_p = (struct dapls_ib_pd_handle *)pz->pd_handle;
	args.pdf_hkey = pd_p->pd_hkey;

	retval = ioctl(pz->header.owner_ia->hca_ptr->ib_hca_handle->ia_fd,
	    DAPL_PD_FREE, &args);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "pd_free: pz 0x%p, cannot free pd\n", pz);
		return (dapls_convert_error(errno, retval));
	}
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "pd_free: pz 0x%p, hkey %016llx, freed\n", pz, pd_p->pd_hkey);
	dapl_os_free((void *)pd_p, sizeof (*pd_p));
	pz->pd_handle = NULL;
	return (DAT_SUCCESS);
}


/*
 * dapl_ib_mr_register
 *
 * Register a virtual memory region
 *
 * Input:
 *	ia_handle		IA handle
 *	lmr			pointer to dapl_lmr struct
 *	virt_addr		virtual address of beginning of mem region
 *	length			length of memory region
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_mr_register(
	IN  DAPL_IA 		*ia,
	IN  DAPL_LMR		*lmr,
	IN  DAT_PVOID		virt_addr,
	IN  DAT_VLEN		length,
	IN  DAT_MEM_PRIV_FLAGS  privileges)
{
	dapl_mr_register_t	reg_msg;
	ib_mr_handle_t		mr_handle;
	DAPL_PZ *		pz_handle;
	int			ia_fd;
	int			retval;

	ia_fd = ia->hca_ptr->ib_hca_handle->ia_fd;
	mr_handle = dapl_os_alloc(sizeof (struct dapls_ib_mr_handle));
	if (mr_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "mr_register: lmr 0x%p, ia 0x%p, "
		    "cannot alloc mr_handle\n", lmr, ia);
		return (DAT_INSUFFICIENT_RESOURCES);
	}
	pz_handle = ((DAPL_PZ *)lmr->param.pz_handle);
	if (pz_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "mr_register: lmr 0x%p, ia 0x%p, "
		    "pz_handle == NULL!\n", lmr, ia);
		dapl_os_free(mr_handle, sizeof (struct dapls_ib_mr_handle));
		return (DAT_INVALID_PARAMETER);
	}
	reg_msg.mr_pd_hkey = pz_handle->pd_handle->pd_hkey;
	reg_msg.mr_vaddr = (ib_vaddr_t)(uintptr_t)virt_addr;
	reg_msg.mr_len = (ib_memlen_t)length;
	reg_msg.mr_flags = (ibt_mr_flags_t)
	    dapl_lmr_convert_privileges(privileges);
	reg_msg.mr_flags |= IBT_MR_ENABLE_WINDOW_BIND;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "mr_register: lmr 0x%p, pd_hkey 0x%016llx, vaddr 0x%016llx, "
	    "len %llu, flags 0x%x\n", lmr, reg_msg.mr_pd_hkey,
	    reg_msg.mr_vaddr, reg_msg.mr_len, reg_msg.mr_flags);

	/* call into driver to allocate MR resource */
	retval = ioctl(ia_fd, DAPL_MR_REGISTER, &reg_msg);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "mr_register: lmr 0x%p, failed (%s)\n",
		    lmr, strerror(errno));
		dapl_os_free(mr_handle, sizeof (struct dapls_ib_mr_handle));
		return (dapls_convert_error(errno, retval));
	}
	mr_handle->mr_hkey = reg_msg.mr_hkey;
	lmr->param.lmr_context = (DAT_LMR_CONTEXT)reg_msg.mr_lkey;
	lmr->param.rmr_context = (DAT_RMR_CONTEXT)reg_msg.mr_rkey;
	lmr->param.registered_address = reg_msg.mr_vaddr;
	lmr->param.registered_size = reg_msg.mr_len;
	lmr->mr_handle = mr_handle;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "mr_register: successful, lmr 0x%p, mr_hkey 0x%016llx, "
	    "lmr_ctx 0x%08x\n\n", lmr, reg_msg.mr_hkey,
	    reg_msg.mr_lkey);
	return (DAT_SUCCESS);
}

/*
 * dapl_ib_mr_register_shared
 *
 * Register a shared virtual memory region
 *
 * Input:
 *	ia_handle		IA handle
 *	lmr			pointer to dapl_lmr struct
 *	virt_addr		virtual address of beginning of mem region
 *	cookie			shared memory identifer
 *	length			length of memory region
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_mr_register_shared(
	IN  DAPL_IA 		*ia,
	IN  DAPL_LMR		*lmr,
	IN  DAT_PVOID		virt_addr,
	IN  DAT_VLEN		length,
	IN  DAT_LMR_COOKIE	cookie,
	IN  DAT_MEM_PRIV_FLAGS  privileges)
{
	dapl_mr_register_shared_t	reg_msg;
	ib_mr_handle_t			mr_handle;
	DAPL_PZ				*pz_handle;
	int				ia_fd, i;
	int				retval;

	ia_fd = ia->hca_ptr->ib_hca_handle->ia_fd;
	mr_handle = dapl_os_alloc(sizeof (struct dapls_ib_mr_handle));
	if (mr_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "mr_register_shared: lmr 0x%p, ia 0x%p, "
		    "cannot alloc mr_handle\n", lmr, ia);
		return (DAT_INSUFFICIENT_RESOURCES);
	}
	pz_handle = ((DAPL_PZ *)lmr->param.pz_handle);
	if (pz_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "mr_register_shared: lmr 0x%p, ia 0x%p, "
		    "pz_handle == NULL!\n", lmr, ia);
		dapl_os_free(mr_handle, sizeof (struct dapls_ib_mr_handle));
		return (DAT_INVALID_PARAMETER);
	}
	reg_msg.mrs_pd_hkey = pz_handle->pd_handle->pd_hkey;
	reg_msg.mrs_vaddr = (ib_vaddr_t)(uintptr_t)virt_addr;
	reg_msg.mrs_len = (ib_memlen_t)length;
	reg_msg.mrs_flags = (ibt_mr_flags_t)
	    dapl_lmr_convert_privileges(privileges);
	reg_msg.mrs_flags |= IBT_MR_ENABLE_WINDOW_BIND;
	/*CONSTCOND*/
	dapl_os_assert(DAT_LMR_COOKIE_SIZE == sizeof (reg_msg.mrs_shm_cookie));
	(void) dapl_os_memcpy((void *)&reg_msg.mrs_shm_cookie, (void *)cookie,
	    DAT_LMR_COOKIE_SIZE);

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "mr_register_shared: lmr 0x%p, pd_hkey 0x%016llx, "
	    "vaddr 0x%016llx, len %llu, flags 0x%x\n",
	    lmr, reg_msg.mrs_pd_hkey, reg_msg.mrs_vaddr, reg_msg.mrs_len,
	    reg_msg.mrs_flags);

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "mr_register_shared: cookie \n0x");
	for (i = 4; i >= 0; i--) {
		dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
		    "%016llx", reg_msg.mrs_shm_cookie.mc_uint_arr[i]);
	}
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, "\n");

	/* call into driver to allocate MR resource */
	retval = ioctl(ia_fd, DAPL_MR_REGISTER_SHARED, &reg_msg);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "mr_register_shared: lmr 0x%p, failed (%s)\n",
		    lmr, strerror(errno));
		dapl_os_free(mr_handle, sizeof (struct dapls_ib_mr_handle));
		return (dapls_convert_error(errno, retval));
	}
	mr_handle->mr_hkey = reg_msg.mrs_hkey;
	lmr->param.lmr_context = (DAT_LMR_CONTEXT)reg_msg.mrs_lkey;
	lmr->param.rmr_context = (DAT_RMR_CONTEXT)reg_msg.mrs_rkey;
	lmr->param.registered_address = reg_msg.mrs_vaddr;
	lmr->param.registered_size = reg_msg.mrs_len;
	lmr->mr_handle = mr_handle;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "mr_register_shared: successful, lmr 0x%p, mr_hkey 0x%016llx, "
	    "lmr_ctx 0x%08x\n\n", lmr, reg_msg.mrs_hkey,
	    reg_msg.mrs_lkey);
	return (DAT_SUCCESS);
}

/*
 * dapl_ib_mr_deregister
 *
 * Free a memory region
 *
 * Input:
 *	lmr			pointer to dapl_lmr struct
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_mr_deregister(
	IN  DAPL_LMR		*lmr)
{
	dapl_mr_deregister_t args;
	int retval;

	args.mrd_hkey = lmr->mr_handle->mr_hkey;
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "mr_deregister: lmr 0x%p, hkey 0x%016llx, lmr_ctx 0x%08x\n"
	    "               vaddr 0x%016llx, len %llu, flags 0x%x\n",
	    lmr, args.mrd_hkey, lmr->param.lmr_context,
	    lmr->param.registered_address, lmr->param.registered_size,
	    dapl_lmr_convert_privileges(lmr->param.mem_priv) |
	    IBT_MR_ENABLE_WINDOW_BIND);

	/* call into driver to do MR deregister */
	retval = ioctl(lmr->header.owner_ia->hca_ptr->ib_hca_handle->ia_fd,
	    DAPL_MR_DEREGISTER, &args);

	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "mr_deregister: lmr 0x%p, failed (%s)\n",
		    lmr, strerror(errno));
		return (dapls_convert_error(errno, retval));
	}

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "mr_deregister: successful\n\n");
	dapl_os_free(lmr->mr_handle, sizeof (struct dapls_ib_mr_handle));
	lmr->mr_handle = NULL;
	return (DAT_SUCCESS);
}


/*
 * dapl_ib_mr_register_lmr
 *
 * Register a memory region based on attributes of an existing one
 *
 * Input:
 *	ia_handle		IA handle
 *	lmr			pointer to dapl_lmr struct
 *	virt_addr		virtual address of beginning of mem region
 *	length			length of memory region
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_mr_register_lmr(
	IN  DAPL_IA 			*ia,
	IN  DAPL_LMR			*lmr,
	IN  DAT_MEM_PRIV_FLAGS		privileges)
{
	dapl_mr_register_lmr_t		regl_msg;
	DAPL_LMR			*orig_lmr;
	struct dapls_ib_mr_handle	*orig_mr_handle;
	ib_mr_handle_t			mr_handle;
	int				ia_fd;
	int				retval;

	ia_fd = ia->hca_ptr->ib_hca_handle->ia_fd;
	mr_handle = dapl_os_alloc(sizeof (struct dapls_ib_mr_handle));
	if (mr_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "mr_register_lmr: lmr 0x%p, ia 0x%p, "
		    "cannot alloc mr_handle\n", lmr, ia);
		return (DAT_INSUFFICIENT_RESOURCES);
	}

	orig_lmr = (DAPL_LMR *)lmr->param.region_desc.for_lmr_handle;
	orig_mr_handle = (struct dapls_ib_mr_handle *)orig_lmr->mr_handle;
	regl_msg.mrl_orig_hkey = orig_mr_handle->mr_hkey;
	regl_msg.mrl_flags = (ibt_mr_flags_t)
	    dapl_lmr_convert_privileges(privileges);
	regl_msg.mrl_flags |= IBT_MR_ENABLE_WINDOW_BIND;
	regl_msg.mrl_lkey = regl_msg.mrl_rkey = 0;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "mr_register_lmr: lmr 0x%p, hkey 0x%016llx, lmr_ctx 0x%08x\n"
	    "                 vaddr 0x%016llx, len %llu, flags 0x%x\n",
	    lmr, mr_handle->mr_hkey, lmr->param.lmr_context,
	    orig_lmr->param.registered_address,
	    orig_lmr->param.registered_size,
	    dapl_lmr_convert_privileges(orig_lmr->param.mem_priv) |
	    IBT_MR_ENABLE_WINDOW_BIND);


	/* call into driver to allocate MR resource */
	retval = ioctl(ia_fd, DAPL_MR_REGISTER_LMR, &regl_msg);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "mr_register_lmr: failed (%s), orig_hkey (%016llx)\n",
		    strerror(errno), orig_mr_handle->mr_hkey);
		dapl_os_free(mr_handle, sizeof (struct dapls_ib_mr_handle));
		return (dapls_convert_error(errno, retval));
	}

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "mr_registered_lmr: successful, lmr 0x%p, hkey 0x%016llx\n",
	    lmr, regl_msg.mrl_hkey);

	mr_handle->mr_hkey = regl_msg.mrl_hkey;
	lmr->param.lmr_context = (DAT_LMR_CONTEXT)regl_msg.mrl_lkey;
	lmr->param.rmr_context = (DAT_RMR_CONTEXT)regl_msg.mrl_rkey;
	lmr->param.registered_address = orig_lmr->param.registered_address;
	lmr->param.registered_size = orig_lmr->param.registered_size;
	lmr->mr_handle = mr_handle;

	return (DAT_SUCCESS);
}


/*
 * dapls_ib_mw_alloc
 *
 * Bind a protection domain to a memory window
 *
 * Input:
 *	rmr			Initialized rmr to hold binding handles
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_mw_alloc(
	IN  DAPL_RMR	*rmr)
{
	DAPL_IA		*ia_hdl = (DAPL_IA *)rmr->param.ia_handle;
	DAPL_PZ		*pz_hdl = rmr->param.pz_handle;
	dapl_mw_alloc_t	args;
	ib_mw_handle_t	mw_handle;
	int		ia_fd;
	int		retval;

	ia_fd = ((struct dapls_ib_hca_handle *)(ia_hdl->hca_ptr->
	    ib_hca_handle))->ia_fd;

	mw_handle = dapl_os_alloc(sizeof (struct dapls_ib_mw_handle));
	if (mw_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "mw_alloc: rmr 0x%p, cannot alloc mw_handle\n", rmr);
		return (DAT_INSUFFICIENT_RESOURCES);
	}
	args.mw_pd_hkey = ((struct dapls_ib_pd_handle *)
	    (pz_hdl->pd_handle))->pd_hkey;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "mw_alloc: rmr 0x%p, pd_hkey 0x%016llx\n",
	    rmr, args.mw_pd_hkey);

	retval = ioctl(ia_fd, DAPL_MW_ALLOC, &args);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "mw_alloc: rmr 0x%p, failed (%s)\n", rmr, strerror(errno));
		dapl_os_free(mw_handle, sizeof (struct dapls_ib_mr_handle));
		return (dapls_convert_error(errno, retval));
	}

	mw_handle->mw_hkey = args.mw_hkey;
	rmr->mw_handle = mw_handle;
	rmr->param.rmr_context = (DAT_RMR_CONTEXT) args.mw_rkey;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "mw_alloc: successful, rmr 0x%p, mw_hkey 0x%llx, "
	    "rmr_ctx 0x%x\n\n", rmr, (uint64_t)args.mw_hkey,
	    rmr->param.rmr_context);

	return (DAT_SUCCESS);
}


/*
 * dapls_ib_mw_free
 *
 * Release bindings of a protection domain to a memory window
 *
 * Input:
 *	rmr			Initialized rmr to hold binding handles
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_mw_free(
	IN  DAPL_RMR	*rmr)
{
	DAPL_IA		*ia_hdl = rmr->param.ia_handle;
	dapl_mw_free_t	args;
	int		ia_fd;
	int		retval;

	ia_fd = ((struct dapls_ib_hca_handle *)(ia_hdl->hca_ptr->
	    ib_hca_handle))->ia_fd;

	args.mw_hkey = rmr->mw_handle->mw_hkey;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "mw_free: rmr 0x%p, mw_hkey 0x%016llx\n", rmr, args.mw_hkey);

	retval = ioctl(ia_fd, DAPL_MW_FREE, &args);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "mw_free: rmr 0x%p, failed (%s)\n", rmr, strerror(errno));
		return (dapls_convert_error(errno, retval));
	}

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, "mw_free: successful\n\n");
	dapl_os_free(rmr->mw_handle, sizeof (struct dapls_ib_mr_handle));
	rmr->mw_handle = NULL;

	return (DAT_SUCCESS);
}

/*
 * dapls_ib_mw_bind
 *
 * Bind a protection domain to a memory window
 *
 * Input:
 *	rmr			Initialized rmr to hold binding handles
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_mw_bind(
	IN  DAPL_RMR		*rmr,
	IN  DAT_LMR_CONTEXT	lmr_context,
	IN  DAPL_EP		*ep,
	IN  DAPL_COOKIE		*cookie,
	IN  DAT_VADDR		virtual_address,
	IN  DAT_VLEN		length,
	IN  DAT_MEM_PRIV_FLAGS	mem_priv,
	IN  DAT_COMPLETION_FLAGS completion_flags)
{
	ibt_send_wr_t	wre;
	ibt_wr_bind_t	wrbind;
	boolean_t	suppress_notification;
	int		retval;

	if (length > 0) {
		wrbind.bind_flags = (ibt_bind_flags_t)
		    (dapl_rmr_convert_privileges(mem_priv) |
		    IBT_WR_BIND_ATOMIC);
	} else {
		wrbind.bind_flags = (ibt_bind_flags_t)NULL;
	}
	wrbind.bind_rkey = rmr->param.rmr_context;
	wrbind.bind_va = virtual_address;
	wrbind.bind_len = length;
	wrbind.bind_lkey = lmr_context;

	wre.wr_id = (ibt_wrid_t)(uintptr_t)cookie;
	/*
	 * wre.wr_flags = (is_signaled) ? IBT_WR_SEND_SIGNAL :
	 *   IBT_WR_NO_FLAGS;
	 * Till we fix the chan alloc flags do the following -
	 */
	/* Translate dapl flags */
	wre.wr_flags = (DAT_COMPLETION_BARRIER_FENCE_FLAG &
	    completion_flags) ? IBT_WR_SEND_FENCE : 0;
	/* suppress completions */
	wre.wr_flags |= (DAT_COMPLETION_SUPPRESS_FLAG &
	    completion_flags) ? 0 : IBT_WR_SEND_SIGNAL;

	wre.wr_trans = IBT_RC_SRV;
	wre.wr_opcode = IBT_WRC_BIND;
	wre.wr_nds = 0;
	wre.wr_sgl = NULL;
	wre.wr.rc.rcwr.bind = &wrbind;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "mw_bind: rmr 0x%p, wr_flags 0x%x, rkey 0x%x, bind_flags 0x%x\n"
	    "         bind_va 0x%llx, bind_len 0x%llx, mem_priv 0x%x\n",
	    rmr, wre.wr_flags, wrbind.bind_rkey, wrbind.bind_flags,
	    wrbind.bind_va, wrbind.bind_len, mem_priv);

	if (ep->param.ep_attr.recv_completion_flags &
	    DAT_COMPLETION_UNSIGNALLED_FLAG) {
		/* This flag is used to control notification of completions */
		suppress_notification = (completion_flags &
		    DAT_COMPLETION_UNSIGNALLED_FLAG) ? B_TRUE : B_FALSE;
	} else {
		/*
		 * The evd waiter will use threshold to control wakeups
		 * Hence the event notification will be done via arming the
		 * CQ so we do not need special notification generation
		 * hence set suppression to true
		 */
		suppress_notification = B_TRUE;
	}

	retval = DAPL_SEND(ep)(ep, &wre, suppress_notification);

	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "mw_bind: rmr 0x%p, failed (%s)\n", rmr, strerror(errno));
		return (dapls_convert_error(errno, retval));
	}

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "mw_bind: new_rkey = 0x%x\n", wrbind.bind_rkey_out);
	rmr->param.rmr_context = (DAT_RMR_CONTEXT) wrbind.bind_rkey_out;

	return (DAT_SUCCESS);
}

/*
 * dapls_ib_mw_unbind
 *
 * Unbind a protection domain from a memory window
 *
 * Input:
 *	rmr			Initialized rmr to hold binding handles
 *
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_mw_unbind(
	IN  DAPL_RMR		*rmr,
	IN  DAT_LMR_CONTEXT	lmr_context,
	IN  DAPL_EP		*ep,
	IN  DAPL_COOKIE		*cookie,
	IN  DAT_COMPLETION_FLAGS completion_flags)
{
	DAT_RETURN retval;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "mw_unbind: rmr 0x%p, enter\n", rmr);

	retval = dapls_ib_mw_bind(rmr, lmr_context, ep, cookie,
	    (DAT_VADDR)0, (DAT_VLEN)0, (DAT_MEM_PRIV_FLAGS)NULL,
	    completion_flags);

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "mw_unbind: rmr 0x%p, exit\n\n", rmr);

	return (retval);
}

/*
 * Processes async events and calls appropriate callbacks so that events
 * can be posted to the async evd.
 */
void
dapls_ib_async_callback(
	IN    DAPL_EVD		  *async_evd,
	IN    ib_hca_handle_t	  hca_handle,
	IN    ib_error_record_t	  *event_ptr,
	IN    void		  *context)
{
	DAPL_IA			*ia_ptr;
	DAPL_EP			*ep_ptr;
	DAPL_EVD		*evd_ptr;
	dapl_ib_async_event_t	*async_evp;

	ia_ptr = (DAPL_IA *)context;

	dapl_os_assert(event_ptr != NULL);
	async_evp = (dapl_ib_async_event_t *)event_ptr;

	switch (async_evp->ibae_type) {
	case IBT_ERROR_INVALID_REQUEST_CHAN:
	case IBT_ERROR_CATASTROPHIC_CHAN:
		/*
		 * Walk the EPs to match this EP, then invoke the
		 * routine when we have the EP we need
		 */
		dapl_os_assert(!dapl_llist_is_empty(&ia_ptr->ep_list_head));
		dapl_os_lock(&ia_ptr->header.lock);

		ep_ptr = (DAPL_EP *)dapl_llist_next_entry(&ia_ptr->ep_list_head,
		    NULL);
		while (ep_ptr != NULL) {
			if (ep_ptr ==
			    (DAPL_EP *)(uintptr_t)async_evp->ibae_cookie) {
				break;
			}

			ep_ptr = (DAPL_EP *) dapl_llist_next_entry(
			    &ia_ptr->ep_list_head,
			    &ep_ptr->header.ia_list_entry);
		}

		dapl_os_unlock(&ia_ptr->header.lock);
		dapl_os_assert(ep_ptr != NULL);
		dapl_evd_qp_async_error_callback(hca_handle, NULL, event_ptr,
		    (void *)ep_ptr);
		break;
	case IBT_ERROR_CQ:
		/*
		 * Walk the EVDs to match this EVD, then invoke the
		 * routine when we have the EVD we need
		 */
		dapl_os_assert(!dapl_llist_is_empty(&ia_ptr->evd_list_head));
		dapl_os_lock(&ia_ptr->header.lock);

		evd_ptr = (DAPL_EVD *) dapl_llist_next_entry(
		    &ia_ptr->evd_list_head, NULL);
		while (evd_ptr != NULL) {
			if (evd_ptr ==
			    (DAPL_EVD *)(uintptr_t)async_evp->ibae_cookie) {
				break;
			}
			evd_ptr = (DAPL_EVD *)
			    dapl_llist_next_entry(&ia_ptr->evd_list_head,
			    &evd_ptr->header.ia_list_entry);
		}
		dapl_os_unlock(&ia_ptr->header.lock);
		dapl_os_assert(evd_ptr != NULL);
		dapl_evd_cq_async_error_callback(hca_handle, NULL, event_ptr,
		    (void *)evd_ptr);
		break;
	case IBT_ERROR_PORT_DOWN:
	case IBT_ERROR_LOCAL_CATASTROPHIC:
		dapl_evd_un_async_error_callback(hca_handle, event_ptr,
		    (void *)async_evd);
		break;
	default:
		/*
		 * We are not interested in the following events
		 * case IBT_EVENT_PATH_MIGRATED:
		 * case IBT_EVENT_COM_EST:
		 * case IBT_EVENT_SQD:
		 * case IBT_ERROR_PATH_MIGRATE_REQ:
		 * case IBT_EVENT_PORT_UP:
		 */
		dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
		    "dapls_ib_async_callback: unhandled async code:%x\n",
		    async_evp->ibae_type);
		break;
	}
}

/*
 * dapls_ib_setup_async_callback
 * The reference implementation calls this to register callbacks,
 * but since our model of polling for events is based on retrieving
 * events by the waiting thread itself this is a NOOP for us.
 */
/* ARGSUSED */
DAT_RETURN
dapls_ib_setup_async_callback(
	IN  DAPL_IA			*ia_ptr,
	IN  DAPL_ASYNC_HANDLER_TYPE	handler_type,
	IN  unsigned int		*callback_handle,
	IN  ib_async_handler_t		callback,
	IN  void			*context)
{
	return (DAT_SUCCESS);
}

/*
 * dapls_ib_query_hca
 *
 * Set up an asynchronous callbacks of various kinds
 *
 * Input:
 *	hca_handl		hca handle
 *	ep_attr			attribute of the ep
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_PARAMETER
 */

/* these are just arbitrary values for now */

static DAT_RETURN
dapls_ib_query_ia(
	IN  dapl_hca_attr_t		*hca_attr,
	IN  DAPL_HCA			*hca_ptr,
	OUT DAT_IA_ATTR			*ia_attr)
{
	(void) dapl_os_memzero(ia_attr, sizeof (*ia_attr));

	(void) dapl_os_strcpy(ia_attr->adapter_name, VN_ADAPTER_NAME);

	(void) sprintf(ia_attr->vendor_name, "0x%08x:0x%08x",
	    hca_attr->dhca_vendor_id, hca_attr->dhca_device_id);

	ia_attr->hardware_version_major = (DAT_UINT32)hca_attr->dhca_version_id;
	ia_attr->ia_address_ptr = (DAT_IA_ADDRESS_PTR)&hca_ptr->hca_address;
	ia_attr->max_eps = (DAT_COUNT)hca_attr->dhca_max_chans;
	ia_attr->max_dto_per_ep = (DAT_COUNT)hca_attr->dhca_max_chan_sz;
	ia_attr->max_rdma_read_per_ep_in = hca_attr->dhca_max_rdma_in_chan;
	ia_attr->max_rdma_read_per_ep_out = hca_attr->dhca_max_rdma_out_chan;
	ia_attr->max_evds = (DAT_COUNT)hca_attr->dhca_max_cq;
	ia_attr->max_evd_qlen = (DAT_COUNT)hca_attr->dhca_max_cq_sz;
	/* max_iov_segments_per_dto is for non-RDMA */
	ia_attr->max_iov_segments_per_dto = (DAT_COUNT)hca_attr->dhca_max_sgl;
	ia_attr->max_lmrs = (DAT_COUNT)hca_attr->dhca_max_memr;
	ia_attr->max_lmr_block_size = (DAT_VLEN)hca_attr->dhca_max_memr_len;
	ia_attr->max_lmr_virtual_address = (DAT_VADDR)DAPL_MAX_ADDRESS;
	ia_attr->max_pzs = (DAT_COUNT)hca_attr->dhca_max_pd;
	ia_attr->max_mtu_size = (DAT_VLEN)DAPL_IB_MAX_MESSAGE_SIZE;
	ia_attr->max_rdma_size = (DAT_VLEN)DAPL_IB_MAX_MESSAGE_SIZE;
	ia_attr->max_rmrs = (DAT_COUNT)hca_attr->dhca_max_mem_win;
	ia_attr->max_rmr_target_address = (DAT_VADDR)DAPL_MAX_ADDRESS;
	ia_attr->max_iov_segments_per_rdma_read =
	    (DAT_COUNT)hca_attr->dhca_max_sgl;
	ia_attr->max_iov_segments_per_rdma_write =
	    (DAT_COUNT)hca_attr->dhca_max_sgl;
	/* all instances of IA */
	ia_attr->max_rdma_read_in = hca_attr->dhca_max_rdma_in_chan *
	    hca_attr->dhca_max_chans;
	ia_attr->max_rdma_read_out = hca_attr->dhca_max_rdma_out_chan *
	    hca_attr->dhca_max_chans;
	ia_attr->max_rdma_read_per_ep_in_guaranteed = DAT_TRUE;
	ia_attr->max_rdma_read_per_ep_out_guaranteed = DAT_TRUE;
	ia_attr->max_srqs = (DAT_COUNT)hca_attr->dhca_max_srqs;
	ia_attr->max_ep_per_srq = ia_attr->max_eps;
	ia_attr->max_recv_per_srq = (DAT_COUNT)hca_attr->dhca_max_srqs_sz;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, "IA Attributes:\n"
	    "\tadapter_name %s\n "
	    "\tvendor_name %s\n "
	    "\thardware_version_major 0x%08x\n"
	    "\tmax_eps %d\n"
	    "\tmax_dto_per_ep %d\n"
	    "\tmax_rdma_read_per_ep_in %d\n"
	    "\tmax_rdma_read_per_ep_out %d\n"
	    "\tmax_evds %d\n"
	    "\tmax_evd_qlen %d\n"
	    "\tmax_iov_segments_per_dto %d\n"
	    "\tmax_lmrs %d\n"
	    "\tmax_lmr_block_size 0x%016llx\n"
	    "\tmax_lmr_virtual_address 0x%016llx\n"
	    "\tmax_pzs %d\n"
	    "\tmax_mtu_size 0x%016llx\n"
	    "\tmax_rdma_size 0x%016llx\n"
	    "\tmax_rmrs %d\n"
	    "\tmax_rmr_target_address 0x%016llx\n"
	    "\tmax_iov_segments_per_rdma_read %d\n"
	    "\tmax_iov_segments_per_rdma_write %d\n"
	    "\tmax_rdma_read_in %d\n"
	    "\tmax_rdma_read_out %d\n"
	    "\tmax_srqs %d\n"
	    "\tmax_ep_per_srq %d\n"
	    "\tmax_recv_per_srq %d\n"
	    "\n",
	    ia_attr->adapter_name,
	    ia_attr->vendor_name,
	    ia_attr->hardware_version_major,
	    ia_attr->max_eps,
	    ia_attr->max_dto_per_ep,
	    ia_attr->max_rdma_read_per_ep_in,
	    ia_attr->max_rdma_read_per_ep_out,
	    ia_attr->max_evds,
	    ia_attr->max_evd_qlen,
	    ia_attr->max_iov_segments_per_dto,
	    ia_attr->max_lmrs,
	    ia_attr->max_lmr_block_size,
	    ia_attr->max_lmr_virtual_address,
	    ia_attr->max_pzs,
	    ia_attr->max_mtu_size,
	    ia_attr->max_rdma_size,
	    ia_attr->max_rmrs,
	    ia_attr->max_rmr_target_address,
	    ia_attr->max_iov_segments_per_rdma_read,
	    ia_attr->max_iov_segments_per_rdma_write,
	    ia_attr->max_rdma_read_in,
	    ia_attr->max_rdma_read_out,
	    ia_attr->max_srqs,
	    ia_attr->max_ep_per_srq,
	    ia_attr->max_recv_per_srq);

	return (DAT_SUCCESS);
}

/* ARGSUSED */
static DAT_RETURN
dapls_ib_query_ep(
	IN  dapl_hca_attr_t		*hca_attr,
	IN  DAPL_HCA			*hca_ptr,
	OUT DAT_EP_ATTR			*ep_attr)
{
	(void) dapl_os_memzero(ep_attr, sizeof (*ep_attr));
	ep_attr->service_type = DAT_SERVICE_TYPE_RC;
	ep_attr->max_mtu_size = DAPL_IB_MAX_MESSAGE_SIZE;
	ep_attr->max_rdma_size = DAPL_IB_MAX_MESSAGE_SIZE;
	ep_attr->qos = DAT_QOS_BEST_EFFORT;
	ep_attr->max_recv_dtos = hca_attr->dhca_max_chan_sz;
	ep_attr->max_request_dtos = hca_attr->dhca_max_chan_sz;
	ep_attr->max_recv_iov = hca_attr->dhca_max_sgl;
	ep_attr->max_request_iov = hca_attr->dhca_max_sgl;
	ep_attr->request_completion_flags = DAT_COMPLETION_DEFAULT_FLAG;
	ep_attr->recv_completion_flags = DAT_COMPLETION_DEFAULT_FLAG;
	ep_attr->srq_soft_hw = DAT_HW_DEFAULT;
	return (DAT_SUCCESS);
}

static void
dapls_ib_query_srq(
	IN  dapl_hca_attr_t		*hca_attr,
	OUT DAT_SRQ_ATTR		*srq_attr)
{
	(void) dapl_os_memzero(srq_attr, sizeof (*srq_attr));
	srq_attr->max_recv_dtos = hca_attr->dhca_max_srqs_sz;
	srq_attr->max_recv_iov = hca_attr->dhca_max_srq_sgl;
	srq_attr->low_watermark = DAT_SRQ_LW_DEFAULT;
}

/* ARGSUSED */
DAT_RETURN
dapls_ib_query_hca(
	IN  DAPL_HCA			*hca_ptr,
	OUT DAT_IA_ATTR			*ia_attr,
	OUT DAT_EP_ATTR			*ep_attr,
	OUT DAT_SOCK_ADDR6		*ip_addr,
	OUT DAT_SRQ_ATTR		*srq_attr)
{
	dapl_ia_query_t args;
	int ia_fd, retval;

	if (hca_ptr == NULL) {
		return (DAT_INVALID_PARAMETER);
	}

	ia_fd = hca_ptr->ib_hca_handle->ia_fd;
	retval = ioctl(ia_fd, DAPL_IA_QUERY, &args);
	if (retval != 0) {
		return (dapls_convert_error(errno, retval));
	}

	if (ia_attr != NULL) {
		(void) dapls_ib_query_ia(&args.hca_attr, hca_ptr, ia_attr);
	}
	if (ep_attr != NULL) {
		(void) dapls_ib_query_ep(&args.hca_attr, hca_ptr, ep_attr);
	}
	if (srq_attr != NULL) {
		(void) dapls_ib_query_srq(&args.hca_attr, srq_attr);
	}
	if (ia_attr == NULL && ep_attr == NULL && srq_attr == NULL) {
		return (DAT_INVALID_PARAMETER);
	}
	return (DAT_SUCCESS);
}

void
dapls_ib_store_premature_events(
	IN ib_qp_handle_t	qp_ptr,
	IN ib_work_completion_t	*cqe_ptr)
{
	ib_srq_handle_t	srqp;
	int		head;

	if (qp_ptr->qp_srq_enabled) {
		/*
		 * For QPs with SRQ attached store the premature event in the
		 * SRQ's premature event list
		 */
		srqp = qp_ptr->qp_srq;
		dapl_os_assert(srqp->srq_freepr_num_events > 0);
		head = srqp->srq_freepr_events[srqp->srq_freepr_head];
		/*
		 * mark cqe as valid before storing it in the
		 * premature events list
		 */
		DAPL_SET_CQE_VALID(cqe_ptr);
		(void) dapl_os_memcpy(&(srqp->srq_premature_events[head]),
		    cqe_ptr, sizeof (*cqe_ptr));
		srqp->srq_freepr_head = (srqp->srq_freepr_head + 1) %
		    srqp->srq_wq_numwqe;
		srqp->srq_freepr_num_events--;
	} else {
		(void) dapl_os_memcpy(&(qp_ptr->qp_premature_events[
		    qp_ptr->qp_num_premature_events]),
		    cqe_ptr, sizeof (*cqe_ptr));
	}
	qp_ptr->qp_num_premature_events++;
}

void
dapls_ib_poll_premature_events(
	IN  DAPL_EP			*ep_ptr,
	OUT ib_work_completion_t	**cqe_ptr,
	OUT int				*nevents)
{
	ib_qp_handle_t qp = ep_ptr->qp_handle;

	if (qp->qp_srq_enabled) {
		*cqe_ptr = qp->qp_srq->srq_premature_events;
	} else {
		*cqe_ptr = qp->qp_premature_events;
	}

	*nevents = qp->qp_num_premature_events;
	qp->qp_num_premature_events = 0;
}

/*
 * Return the premature events to the free list after processing it
 * This function is called only for premature events on the SRQ
 */
void
dapls_ib_free_premature_events(
	IN  DAPL_EP	*ep_ptr,
	IN  int		free_index)
{
	ib_qp_handle_t	qp_ptr;
	ib_srq_handle_t	srq_ptr;
	int		tail;

	qp_ptr = ep_ptr->qp_handle;
	srq_ptr = qp_ptr->qp_srq;

	dapl_os_assert(qp_ptr->qp_srq_enabled);

	tail = srq_ptr->srq_freepr_tail;
	srq_ptr->srq_freepr_events[tail] = free_index;
	srq_ptr->srq_freepr_tail = (tail + 1) % srq_ptr->srq_wq_numwqe;
	srq_ptr->srq_freepr_num_events++;
	DAPL_SET_CQE_INVALID(&srq_ptr->srq_premature_events[free_index]);
}

/*
 * dapls_ib_get_async_event
 *
 * Translate an asynchronous event type to the DAT event.
 * Note that different providers have different sets of errors.
 *
 * Input:
 *	cause_ptr		provider event cause
 *
 * Output:
 *	async_event		DAT mapping of error
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_NOT_IMPLEMENTED	Caller is not interested this event
 */

DAT_RETURN dapls_ib_get_async_event(
	IN  ib_error_record_t		*cause_ptr,
	OUT DAT_EVENT_NUMBER		*async_event)
{
	ibt_async_code_t	code;
	DAT_RETURN		dat_status;

	dat_status = DAT_SUCCESS;
	code = (ibt_async_code_t)((dapl_ib_async_event_t *)cause_ptr->
	    ibae_type);

	switch (code) {
	case IBT_ERROR_CQ:
	case IBT_ERROR_ACCESS_VIOLATION_CHAN:
	case IBT_ERROR_INVALID_REQUEST_CHAN:
		*async_event = DAT_ASYNC_ERROR_PROVIDER_INTERNAL_ERROR;
		break;
	/* CATASTROPHIC errors */
	case IBT_ERROR_CATASTROPHIC_CHAN:
	case IBT_ERROR_LOCAL_CATASTROPHIC:
	case IBT_ERROR_PORT_DOWN:
		*async_event = DAT_ASYNC_ERROR_IA_CATASTROPHIC;
		break;
	default:
		/*
		 * Errors we are not interested in reporting:
		 * IBT_EVENT_PATH_MIGRATED
		 * IBT_ERROR_PATH_MIGRATE_REQ
		 * IBT_EVENT_COM_EST
		 * IBT_EVENT_SQD
		 * IBT_EVENT_PORT_UP
		 */
		dat_status = DAT_NOT_IMPLEMENTED;
	}
	return (dat_status);
}

DAT_RETURN
dapls_ib_event_poll(
	IN DAPL_EVD		*evd_ptr,
	IN uint64_t		timeout,
	IN uint_t		threshold,
	OUT dapl_ib_event_t	*evp_ptr,
	OUT int			*num_events)
{
	dapl_event_poll_t	evp_msg;
	int			ia_fd;
	int			retval;

	*num_events = 0;
	ia_fd = evd_ptr->header.owner_ia->hca_ptr->ib_hca_handle->ia_fd;

	evp_msg.evp_evd_hkey = evd_ptr->ib_cq_handle->evd_hkey;
	evp_msg.evp_threshold = threshold;
	evp_msg.evp_timeout = timeout;
	evp_msg.evp_ep = evp_ptr;
	if (evp_ptr) {
		evp_msg.evp_num_ev =
		    DAPL_MAX(evd_ptr->threshold, NUM_EVENTS_PER_POLL);
	} else {
		evp_msg.evp_num_ev = 0;
	}
	evp_msg.evp_num_polled = 0;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "event_poll: evd 0x%p, hkey 0x%llx, threshold %d,\n"
	    "            timeout 0x%llx, evp_ptr 0x%p, num_ev %d\n",
	    evd_ptr, evp_msg.evp_evd_hkey, evp_msg.evp_threshold,
	    timeout, evp_ptr, evp_msg.evp_num_ev);

	/*
	 * Poll the EVD and if there are no events then we wait in
	 * the kernel.
	 */
	retval = ioctl(ia_fd, DAPL_EVENT_POLL, &evp_msg);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_EVD,
		    "event_poll: evd 0x%p, retval %d err: %s\n",
		    evd_ptr, retval, strerror(errno));
		*num_events = evp_msg.evp_num_polled;
		return (dapls_convert_error(errno, retval));
	}

	dapl_dbg_log(DAPL_DBG_TYPE_EVD,
	    "dapls_ib_event_poll: evd %p nevents %d\n", evd_ptr,
	    evp_msg.evp_num_polled);

	*num_events = evp_msg.evp_num_polled;

	return (DAT_SUCCESS);
}

DAT_RETURN
dapls_ib_event_wakeup(
	IN DAPL_EVD		*evd_ptr)
{
	dapl_event_wakeup_t	evw_msg;
	int			ia_fd;
	int			retval;

	ia_fd = evd_ptr->header.owner_ia->hca_ptr->ib_hca_handle->ia_fd;

	evw_msg.evw_hkey = evd_ptr->ib_cq_handle->evd_hkey;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "event_wakeup: evd 0x%p, hkey 0x%llx\n",
	    evd_ptr, evw_msg.evw_hkey);

	/*
	 * Wakeup any thread waiting in the kernel on this EVD
	 */
	retval = ioctl(ia_fd, DAPL_EVENT_WAKEUP, &evw_msg);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_EVD,
		    "event_wakeup: evd 0x%p, retval %d err: %s\n",
		    evd_ptr, retval, strerror(errno));
		return (dapls_convert_error(errno, retval));
	}

	return (DAT_SUCCESS);
}

/*
 * dapls_ib_cq_peek is used by dapl_cno_wait(). After the CQ has been
 * inspected we arm the CQ if it was empty.
 *
 */
void dapls_ib_cq_peek(
	IN DAPL_EVD	*evd_ptr,
	OUT int		*num_cqe)
{
	DAPL_IA		*ia_ptr;

	*num_cqe = 0;
	if (evd_ptr->evd_flags & (DAT_EVD_DTO_FLAG | DAT_EVD_RMR_BIND_FLAG)) {
		DAPL_PEEK(evd_ptr)(evd_ptr->ib_cq_handle, num_cqe);
		/* No events found in CQ arm it now */
		if (*num_cqe == 0) {
			ia_ptr = evd_ptr->header.owner_ia;
			(void) dapls_set_cq_notify(ia_ptr, evd_ptr);
			dapl_dbg_log(DAPL_DBG_TYPE_EVD,
			    "dapls_ib_cq_peek: set_cq_notify\n");
		}
	}
}

/*
 * Modifies the CNO associated to an EVD
 */
DAT_RETURN dapls_ib_modify_cno(
	IN DAPL_EVD	*evd_ptr,
	IN DAPL_CNO	*cno_ptr)
{
	dapl_evd_modify_cno_t	evmc_msg;
	int			ia_fd;
	int			retval;

	ia_fd = evd_ptr->header.owner_ia->hca_ptr->ib_hca_handle->ia_fd;

	evmc_msg.evmc_hkey = evd_ptr->ib_cq_handle->evd_hkey;

	if (cno_ptr) {
		evmc_msg.evmc_cno_hkey = (uint64_t)cno_ptr->ib_cno_handle;
	} else {
		evmc_msg.evmc_cno_hkey = 0;
	}

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "modify_cno: evd 0x%p, hkey 0x%llx, cno 0x%p, cno_hkey 0x%llx\n",
	    evd_ptr, evmc_msg.evmc_hkey, cno_ptr, evmc_msg.evmc_cno_hkey);

	/*
	 * modify CNO associated with the EVD
	 */
	retval = ioctl(ia_fd, DAPL_EVD_MODIFY_CNO, &evmc_msg);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_EVD,
		    "modify_cno: evd 0x%p, cno %p retval %d err: %s\n",
		    evd_ptr, cno_ptr, retval, strerror(errno));
		return (dapls_convert_error(errno, retval));
	}

	return (DAT_SUCCESS);
}

DAT_RETURN
dapls_ib_cno_wait(
	IN DAPL_CNO	*cno_ptr,
	IN DAT_TIMEOUT	timeout,
	IN DAPL_EVD	**evd_ptr_p)
{
	dapl_cno_wait_t		args;
	int			retval;

	args.cnw_hkey = (uint64_t)cno_ptr->ib_cno_handle;
	if (timeout == DAT_TIMEOUT_INFINITE) {
		args.cnw_timeout = UINT64_MAX;
	} else {
		args.cnw_timeout = (uint64_t)timeout & 0x00000000ffffffff;
	}

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "cno_wait: cno 0x%p, hkey 0x%016llx, timeout 0x%016llx\n",
	    cno_ptr, args.cnw_hkey, args.cnw_timeout);

	retval = ioctl(cno_ptr->header.owner_ia->hca_ptr->
	    ib_hca_handle->ia_fd, DAPL_CNO_WAIT, &args);

	if (retval != 0) {
		*evd_ptr_p = (DAPL_EVD *)NULL;
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "cno_wait: cno 0x%p ioctl err: %s\n",
		    cno_ptr, strerror(errno));
		return (dapls_convert_error(errno, retval));
	}

	*evd_ptr_p = (DAPL_EVD *)(uintptr_t)args.cnw_evd_cookie;
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "cno_wait: woken up, cno 0x%p, evd 0x%p\n\n",
	    cno_ptr, *evd_ptr_p);

	return (DAT_SUCCESS);
}

DAT_RETURN
dapls_ib_cno_alloc(
	IN DAPL_IA	*ia_ptr,
	IN DAPL_CNO	*cno_ptr)
{
	dapl_cno_alloc_t	args;
	int			retval;

	if (cno_ptr->cno_wait_agent.instance_data != NULL ||
	    cno_ptr->cno_wait_agent.proxy_agent_func != NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "cno_alloc: cno 0x%p, wait_agent != NULL\n", cno_ptr);
		return (DAT_NOT_IMPLEMENTED);
	}

	retval = ioctl(ia_ptr->hca_ptr->ib_hca_handle->ia_fd,
	    DAPL_CNO_ALLOC, &args);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "cno_alloc: cno 0x%p ioctl err: %s\n",
		    cno_ptr, strerror(errno));
		return (dapls_convert_error(errno, retval));
	}

	cno_ptr->ib_cno_handle = (ib_cno_handle_t)args.cno_hkey;
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "cno_alloc: cno 0x%p allocated, ia_ptr 0x%p, hkey 0x%016llx\n",
	    cno_ptr, ia_ptr, args.cno_hkey);

	return (DAT_SUCCESS);
}

DAT_RETURN
dapls_ib_cno_free(
	IN DAPL_CNO	*cno_ptr)
{
	dapl_cno_free_t		args;
	int			retval;

	args.cnf_hkey = (uint64_t)cno_ptr->ib_cno_handle;
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "cno_free: cno 0x%p, hkey 0x%016llx\n",
	    cno_ptr, args.cnf_hkey);

	retval = ioctl(cno_ptr->header.owner_ia->hca_ptr->
	    ib_hca_handle->ia_fd, DAPL_CNO_FREE, &args);

	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "cno_free: cno 0x%p ioctl err: %s\n",
		    cno_ptr, strerror(errno));
		return (dapls_convert_error(errno, retval));
	}

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
	    "cno_free: cno 0x%p freed\n", cno_ptr);

	return (DAT_SUCCESS);
}

DAT_RETURN
dapls_convert_error(int errnum, int retval)
{
	if (retval < 0) {
		switch (errnum) {
		case EINVAL:
			return (DAT_INVALID_PARAMETER);
		case ENOMEM:
			return (DAT_INSUFFICIENT_RESOURCES);
		case ETIME:
			return (DAT_TIMEOUT_EXPIRED);
		case EINTR:
			return (DAT_INTERRUPTED_CALL);
		case EFAULT:
			return (DAT_INTERNAL_ERROR);
		default:
			return (DAT_INTERNAL_ERROR);
		}
	} else {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "ERROR: got IBTF error %d\n", retval);
		switch (retval) {
		case IBT_SERVICE_RECORDS_NOT_FOUND:
			/*
			 * Connecting to a non-existant conn qual gets
			 * us here
			 */
			return (DAT_ERROR(DAT_INVALID_PARAMETER,
			    DAT_INVALID_ADDRESS_UNREACHABLE));
		case IBT_INSUFF_RESOURCE:
		case IBT_INSUFF_KERNEL_RESOURCE:
			return (DAT_ERROR(DAT_INSUFFICIENT_RESOURCES, 0));
		case IBT_AR_NOT_REGISTERED:
			/*
			 * forward ipaddr lookup failed
			 */
			return (DAT_ERROR(DAT_INVALID_ADDRESS, 0));
		default:
			return (DAT_INTERNAL_ERROR);
		}
	}
}

typedef struct dapls_ib_dbp_page_s {
	uint32_t			*dbp_page_addr;
	uint64_t			dbp_mapoffset;
	struct dapls_ib_dbp_page_s	*next;
	int				fd;
} dapls_ib_dbp_page_t;

dapls_ib_dbp_page_t	*dapls_ib_pagelist = NULL;

/* Function that returns a pointer to the specified doorbell entry */
uint32_t *dapls_ib_get_dbp(uint64_t maplen, int fd, uint64_t mapoffset,
    uint32_t offset)
{
	dapls_ib_dbp_page_t	*new_page;
	dapls_ib_dbp_page_t	*cur_page;

	dapl_os_lock(&dapls_ib_dbp_lock);
	/* Check to see if page already mapped for entry */
	for (cur_page = dapls_ib_pagelist; cur_page != NULL;
	    cur_page = cur_page->next)
		if (cur_page->dbp_mapoffset == mapoffset &&
		    cur_page->fd == fd) {
			dapl_os_unlock(&dapls_ib_dbp_lock);
			return ((uint32_t *)
			    (offset + (uintptr_t)cur_page->dbp_page_addr));
		}

	/* If not, map a new page and prepend to pagelist */
	new_page = malloc(sizeof (dapls_ib_dbp_page_t));
	if (new_page == NULL) {
		dapl_os_unlock(&dapls_ib_dbp_lock);
		return (MAP_FAILED);
	}
	new_page->dbp_page_addr = (uint32_t *)(void *)mmap64((void *)0,
	    maplen, (PROT_READ | PROT_WRITE), MAP_SHARED, fd, mapoffset);
	if (new_page->dbp_page_addr == MAP_FAILED) {
		free(new_page);
		dapl_os_unlock(&dapls_ib_dbp_lock);
		return (MAP_FAILED);
	}
	new_page->next = dapls_ib_pagelist;
	new_page->dbp_mapoffset = mapoffset;
	new_page->fd = fd;
	dapls_ib_pagelist = new_page;
	dapl_os_unlock(&dapls_ib_dbp_lock);
	return ((uint32_t *)(offset + (uintptr_t)new_page->dbp_page_addr));
}
