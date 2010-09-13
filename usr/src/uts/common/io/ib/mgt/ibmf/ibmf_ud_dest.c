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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Should we maintain base lid for each port in ibmf_ci?
 */

/*
 * This file implements the UD destination resource management in IBMF.
 */

#include <sys/ib/mgt/ibmf/ibmf_impl.h>

extern int ibmf_trace_level;
extern ibmf_state_t *ibmf_statep;
static void ibmf_i_populate_ud_dest_list(ibmf_ci_t *cip, int kmflag);

/*
 * ibmf_i_init_ud_dest():
 * Initialize a cache of UD destination structure used to send UD traffic.
 * Also create a list of pre-allocated UD destination structures to
 * satisfy requests for a UD destination structure and its associated
 * address handle, from a thread in interrupt context. Threads in interrupt
 * context are not allowed to allocated their own address handles.
 */
void
ibmf_i_init_ud_dest(ibmf_ci_t *cip)
{
	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_ud_dest_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_ud_dest() enter, cip = %p\n",
	    tnf_opaque, cip, cip);

	/* initialize the UD dest list mutex */
	mutex_init(&cip->ci_ud_dest_list_mutex, NULL, MUTEX_DRIVER, NULL);

	/* populate the UD dest list if possible */
	ibmf_i_pop_ud_dest_thread(cip);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_ud_dest_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_ud_dest() exit\n");
}

/*
 * ibmf_i_fini_ud_dest():
 * Free up the UD destination cache and the linked list.
 */
void
ibmf_i_fini_ud_dest(ibmf_ci_t *cip)
{
	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_fini_ud_dest_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_fini_ud_dest() enter, cip = %p\n",
	    tnf_opaque, cip, cip);

	/* clean up the UD dest list */
	ibmf_i_clean_ud_dest_list(cip, B_TRUE);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_fini_ud_dest_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_fini_ud_dest() exit\n");
}

/*
 * ibmf_i_get_ud_dest():
 *	Get a UD destination structure from the list
 */
ibmf_ud_dest_t *
ibmf_i_get_ud_dest(ibmf_ci_t *cip)
{
	ibmf_ud_dest_t		*ibmf_ud_dest;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_get_ud_dest_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_get_ud_dest() enter, cip = %p\n",
	    tnf_opaque, cip, cip);

	mutex_enter(&cip->ci_ud_dest_list_mutex);
	ibmf_ud_dest = cip->ci_ud_dest_list_head;
	if (ibmf_ud_dest != NULL) {
		cip->ci_ud_dest_list_head = ibmf_ud_dest->ud_next;
		cip->ci_ud_dest_list_count--;
	}
	mutex_exit(&cip->ci_ud_dest_list_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_get_ud_dest_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_get_ud_dest() exit\n");
	return (ibmf_ud_dest);
}

/*
 * ibmf_i_put_ud_dest():
 *	Add a UD destination structure to the list
 */
void
ibmf_i_put_ud_dest(ibmf_ci_t *cip, ibmf_ud_dest_t *ud_dest)
{
	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_put_ud_dest_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_put_ud_dest() enter, cip = %p, "
	    "ud_dest = %p\n", tnf_opaque, cip, cip,
	    tnf_opaque, ud_dest, ud_dest);

	mutex_enter(&cip->ci_ud_dest_list_mutex);
	cip->ci_ud_dest_list_count++;
	ud_dest->ud_next = cip->ci_ud_dest_list_head;
	cip->ci_ud_dest_list_head = ud_dest;
	mutex_exit(&cip->ci_ud_dest_list_mutex);

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_put_ud_dest_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_put_ud_dest() exit, cip = %p\n",
	    tnf_opaque, cip, cip);
}

/*
 * ibmf_i_populate_ud_dest_list():
 * Maintain a list of IBMF UD destination structures to
 * satisfy requests for a UD destination structure and its associated
 * address handle, from a thread in interrupt context. Threads in interrupt
 * context are not allowed to allocate their own address handles.
 * Add to this list only if the number of entries in the list falls below
 * IBMF_UD_DEST_LO_WATER_MARK. When adding to the list, add entries upto
 * IBMF_UD_DEST_HI_WATER_MARK.
 */
static void
ibmf_i_populate_ud_dest_list(ibmf_ci_t *cip, int kmflag)
{
	ibmf_ud_dest_t		*ibmf_ud_dest;
	uint32_t		count;
	ibt_status_t		status;
	ibt_ud_dest_flags_t	ud_dest_flags = IBT_UD_DEST_NO_FLAGS;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_populate_ud_dest_list_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_populate_ud_dest_list() enter, cip = %p, kmflag = %d \n",
	    tnf_opaque, cip, cip, tnf_int, kmflag, kmflag);

	/* do not allow a population operation if non-blocking */
	if (kmflag == KM_NOSLEEP) {
		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_populate_ud_dest, IBMF_TNF_TRACE, "",
		    "ibmf_i_populate_ud_dest_list(): %s\n", tnf_string, msg,
		    "Skipping, called with non-blocking flag\n");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_populate_ud_dest_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_populate_ud_dest_list() exit\n");
		/*
		 * Don't return a failure code here.
		 * If ibmf_i_ud_dest_alloc() returns NULL, the
		 * the resource allocation will fail
		 */
		return;
	}

	mutex_enter(&cip->ci_ud_dest_list_mutex);
	count = cip->ci_ud_dest_list_count;

	/* nothing to do if count is above the low water mark */
	if (count > IBMF_UD_DEST_LO_WATER_MARK) {
		mutex_exit(&cip->ci_ud_dest_list_mutex);
		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_populate_ud_dest, IBMF_TNF_TRACE, "",
		    "ibmf_i_populate_ud_dest_list(): %s\n", tnf_string, msg,
		    "Count not below low water mark\n");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_populate_ud_dest_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_populate_ud_dest_list() exit\n");
		return;
	}

	/* populate the pool upto the high water mark */
	while (count < IBMF_UD_DEST_HI_WATER_MARK) {
		ibt_adds_vect_t adds_vect;

		ibmf_ud_dest = kmem_zalloc(sizeof (ibmf_ud_dest_t), kmflag);
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ibmf_ud_dest))

		/* Call IBTF to allocate an address handle */
		bzero(&adds_vect, sizeof (adds_vect));
		adds_vect.av_port_num = 1;
		adds_vect.av_srate = IBT_SRATE_1X;	/* assume the minimum */
		mutex_exit(&cip->ci_ud_dest_list_mutex);

		status = ibt_alloc_ah(cip->ci_ci_handle, ud_dest_flags,
		    cip->ci_pd, &adds_vect, &ibmf_ud_dest->ud_dest.ud_ah);
		if (status != IBT_SUCCESS) {
			kmem_free(ibmf_ud_dest, sizeof (ibmf_ud_dest_t));
			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_populate_ud_dest_err, IBMF_TNF_ERROR, "",
			    "ibmf_i_populate_ud_dest_list(): %s, status = %d\n",
			    tnf_string, msg, "ibt alloc ah failed",
			    tnf_uint, ibt_status, status);
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_populate_ud_dest_end, IBMF_TNF_TRACE, "",
			    "ibmf_i_populate_ud_dest_list() exit\n");
			return;
		}

		/* Add the ud_dest to the list */
		mutex_enter(&cip->ci_ud_dest_list_mutex);

		if (cip->ci_ud_dest_list_head != NULL)
			ibmf_ud_dest->ud_next = cip->ci_ud_dest_list_head;
		else
			ibmf_ud_dest->ud_next = NULL;

		cip->ci_ud_dest_list_head = ibmf_ud_dest;
		cip->ci_ud_dest_list_count++;

		/*
		 * Get the latest count since other threads may have
		 * added to the list as well.
		 */
		count = cip->ci_ud_dest_list_count;

	}

	mutex_exit(&cip->ci_ud_dest_list_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_populate_ud_dest_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_populate_ud_dest_list() exit\n");
}

/*
 * ibmf_i_clean_ud_dest_list():
 * Free up entries from the linked list of IBMF UD destination structures.
 * If the "all" argument is B_TRUE, free up all the entries in the list.
 * If the "all" argument is B_FALSE, free up entries to bring the total
 * down to IBMF_UD_DEST_HI_WATER_MARK.
 */
void
ibmf_i_clean_ud_dest_list(ibmf_ci_t *cip, boolean_t all)
{
	ibmf_ud_dest_t		*ibmf_ud_dest;
	ibt_ud_dest_t		*ud_dest;
	uint32_t		count;
	ibt_status_t		status;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_clean_ud_dest_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_clean_ud_dest_list() enter, "
	    "cip = %p, all = %d\n", tnf_opaque, cip, cip,
	    tnf_uint, all, all);

	mutex_enter(&cip->ci_ud_dest_list_mutex);

	/* Determine the number of UD destination resources to free */
	if (all == B_TRUE) {
		count = cip->ci_ud_dest_list_count;
	} else if (cip->ci_ud_dest_list_count > IBMF_UD_DEST_HI_WATER_MARK) {
		count = cip->ci_ud_dest_list_count -
		    IBMF_UD_DEST_HI_WATER_MARK;
	} else
		count = 0;

	while (count) {
		ibmf_ud_dest = cip->ci_ud_dest_list_head;
		ASSERT(ibmf_ud_dest != NULL);
		if (ibmf_ud_dest != NULL) {
			/* Remove ibmf_ud_dest from the list */
			cip->ci_ud_dest_list_head = ibmf_ud_dest->ud_next;
			cip->ci_ud_dest_list_count--;
			mutex_exit(&cip->ci_ud_dest_list_mutex);

			ud_dest = &ibmf_ud_dest->ud_dest;
			status = ibt_free_ah(cip->ci_ci_handle, ud_dest->ud_ah);
			if (status != IBT_SUCCESS) {
				IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
				    ibmf_i_clean_ud_dest_err, IBMF_TNF_ERROR,
				    "", "ibmf_i_clean_ud_dest_list(): %s, "
				    "status = %d\n", tnf_string, msg,
				    "ibt_free_ah failed", tnf_uint, ibt_status,
				    status);
				IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
				    ibmf_i_clean_ud_dest_end, IBMF_TNF_TRACE,
				    "", "ibmf_i_clean_ud_dest_list() exit\n");
				return;
			}

			/* Free the ud_dest context */
			kmem_free(ibmf_ud_dest, sizeof (ibmf_ud_dest_t));

			mutex_enter(&cip->ci_ud_dest_list_mutex);
		}
		/* Determine the number of UD destination resources to free */
		if (all == B_TRUE) {
			count = cip->ci_ud_dest_list_count;
		} else if (cip->ci_ud_dest_list_count >
		    IBMF_UD_DEST_HI_WATER_MARK) {
			count = cip->ci_ud_dest_list_count -
			    IBMF_UD_DEST_HI_WATER_MARK;
		} else
			count = 0;
	}

	mutex_exit(&cip->ci_ud_dest_list_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_clean_ud_dest_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_clean_ud_dest_list() exit\n");
}

/*
 * ibmf_i_alloc_ud_dest():
 *	Allocate and set up a UD destination context
 */
/*ARGSUSED*/
int
ibmf_i_alloc_ud_dest(ibmf_client_t *clientp, ibmf_msg_impl_t *msgimplp,
    ibt_ud_dest_hdl_t *ud_dest_p, boolean_t block)
{
	ibmf_ci_t 		*cip;
	ibmf_addr_info_t	*addrp;
	ibt_status_t		status;
	ibt_adds_vect_t		adds_vec;
	ibt_ud_dest_t		*ud_dest;
	int			ibmf_status, ret;

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_alloc_ud_dest_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_alloc_ud_dest_list() enter, "
	    "clientp = %p, msg = %p, ud_destp = %p, block = %d\n",
	    tnf_opaque, clientp, clientp, tnf_opaque, msg, msgimplp,
	    tnf_opaque, ud_dest_p, ud_dest_p, tnf_uint, block, block);

	_NOTE(ASSUMING_PROTECTED(*ud_dest_p))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ud_dest))

	addrp = &msgimplp->im_local_addr;
	cip = clientp->ic_myci;

	/*
	 * Dispatch a taskq to replenish the UD destination handle cache.
	 */
	mutex_enter(&cip->ci_ud_dest_list_mutex);
	if (cip->ci_ud_dest_list_count < IBMF_UD_DEST_LO_WATER_MARK) {
		ret = ibmf_ud_dest_tq_disp(cip);
		if (ret == 0) {
			IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L3,
			    ibmf_i_alloc_ud_dest_err, IBMF_TNF_ERROR, "",
			    "ibmf_i_alloc_ud_dest(): %s\n", tnf_string, msg,
			    "taskq dispatch of ud_dest population thread "
			    "failed");
		}
	}
	mutex_exit(&cip->ci_ud_dest_list_mutex);

	/* initialize the address vector bases on global/local address */
	if (msgimplp->im_msg_flags & IBMF_MSG_FLAGS_GLOBAL_ADDRESS) {
		/* fill in the grh stuff as expected by ibt */
		adds_vec.av_flow = msgimplp->im_global_addr.ig_flow_label;
		adds_vec.av_send_grh = B_TRUE;
		adds_vec.av_tclass = msgimplp->im_global_addr.ig_tclass;
		adds_vec.av_hop = msgimplp->im_global_addr.ig_hop_limit;
		if (msgimplp->im_unsolicited == B_TRUE) {
			adds_vec.av_sgid =
			    msgimplp->im_global_addr.ig_recver_gid;
			adds_vec.av_dgid =
			    msgimplp->im_global_addr.ig_sender_gid;
		} else {
			adds_vec.av_sgid =
			    msgimplp->im_global_addr.ig_sender_gid;
			adds_vec.av_dgid =
			    msgimplp->im_global_addr.ig_recver_gid;
		}
	} else {
		adds_vec.av_send_grh = B_FALSE;
	}

	/* common address vector initialization */
	adds_vec.av_dlid = addrp->ia_remote_lid;
	if ((clientp->ic_base_lid == 0) && (clientp->ic_qp->iq_qp_num != 0)) {
		/* Get the port's base LID */
		(void) ibt_get_port_state_byguid(
		    clientp->ic_client_info.ci_guid,
		    clientp->ic_client_info.port_num, NULL,
		    &clientp->ic_base_lid);
		if (clientp->ic_base_lid == 0) {
			IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_alloc_ud_dest_err, IBMF_TNF_ERROR, "",
			    "ibmf_i_alloc_ud_dest(): %s\n", tnf_string, msg,
			    "base_lid is not defined, i.e., port is down");
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_alloc_ud_dest_end, IBMF_TNF_TRACE, "",
			    "ibmf_i_alloc_ud_dest_list() exit\n");
			return (IBMF_BAD_PORT_STATE);
		}
	}
	adds_vec.av_src_path = addrp->ia_local_lid - clientp->ic_base_lid;
	adds_vec.av_srvl = addrp->ia_service_level;
	adds_vec.av_srate = IBT_SRATE_1X;
	adds_vec.av_port_num = clientp->ic_client_info.port_num;

	ud_dest = *ud_dest_p;

	/* If an IBT UD destination structure has not been allocated, do so */
	if (ud_dest == NULL) {

		ibmf_ud_dest_t *ibmf_ud_dest;

		/* Get a UD destination resource from the list */
		ibmf_ud_dest = ibmf_i_get_ud_dest(cip);
		if (ibmf_ud_dest == NULL) {
			IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_alloc_ud_dest_err, IBMF_TNF_ERROR, "",
			    "ibmf_i_alloc_ud_dest(): %s\n",
			    tnf_string, msg, "No ud_dest available");
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_alloc_ud_dest_end, IBMF_TNF_TRACE, "",
			    "ibmf_i_alloc_ud_dest_list() exit\n");
			return (IBMF_NO_RESOURCES);
		}
		ud_dest = &ibmf_ud_dest->ud_dest;
		msgimplp->im_ibmf_ud_dest = ibmf_ud_dest;
		ud_dest->ud_qkey = msgimplp->im_local_addr.ia_q_key;
		ud_dest->ud_dst_qpn = msgimplp->im_local_addr.ia_remote_qno;
		*ud_dest_p = ud_dest;
	} else {
		ud_dest->ud_qkey = msgimplp->im_local_addr.ia_q_key;
		ud_dest->ud_dst_qpn = msgimplp->im_local_addr.ia_remote_qno;
	}

	/* modify the address handle with the address vector information */
	status = ibt_modify_ah(cip->ci_ci_handle, ud_dest->ud_ah, &adds_vec);
	if (status != IBT_SUCCESS)
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_alloc_ud_dest_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_alloc_ud_dest(): %s, status = %d\n",
		    tnf_string, msg, "ibt alloc ah failed", tnf_uint,
		    ibt_status, status);

	ibmf_status = ibmf_i_ibt_to_ibmf_status(status);
	if (ibmf_status == IBMF_SUCCESS) {
		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, ud_dests_alloced, 1);
		mutex_exit(&clientp->ic_kstat_mutex);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_alloc_ud_dest_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_alloc_ud_dest() exit\n");

	return (ibmf_status);
}

/*
 * ibmf_i_free_ud_dest():
 *	Free up the UD destination context
 */
void
ibmf_i_free_ud_dest(ibmf_client_t *clientp, ibmf_msg_impl_t *msgimplp)
{
	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_free_ud_dest_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_free_ud_dest() enter\n");

	ibmf_i_put_ud_dest(clientp->ic_myci, msgimplp->im_ibmf_ud_dest);

	/* Clear the UD dest pointers so a new UD dest may be allocated */
	mutex_enter(&msgimplp->im_mutex);
	msgimplp->im_ibmf_ud_dest = NULL;
	msgimplp->im_ud_dest = NULL;
	mutex_exit(&msgimplp->im_mutex);

	mutex_enter(&clientp->ic_kstat_mutex);
	IBMF_SUB32_KSTATS(clientp, ud_dests_alloced, 1);
	mutex_exit(&clientp->ic_kstat_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_free_ud_dest_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_free_ud_dest() exit\n");

}

/*
 * ibmf_i_pop_ud_dest_thread()
 *
 * Wrapper function to call ibmf_i_populate_ud_dest_list() with
 * the KM_SLEEP flag.
 */
void
ibmf_i_pop_ud_dest_thread(void *argp)
{
	ibmf_ci_t *cip = (ibmf_ci_t *)argp;

	ibmf_i_populate_ud_dest_list(cip, KM_SLEEP);
}

/*
 * ibmf_ud_dest_tq_disp()
 *
 * Wrapper for taskq dispatch of the function that populates
 * the UD destination handle cache.
 */
int
ibmf_ud_dest_tq_disp(ibmf_ci_t *cip)
{
	return (taskq_dispatch(ibmf_statep->ibmf_taskq,
	    ibmf_i_pop_ud_dest_thread, cip, TQ_NOSLEEP));
}
