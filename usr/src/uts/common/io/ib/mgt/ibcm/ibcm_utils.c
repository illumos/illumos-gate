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

/*
 * ibcm_utils.c
 *
 * contains internal lookup functions of IB CM module
 * along with some other miscellaneous stuff
 *
 * TBD:
 * 1. Code needed to ensure that if any clients are using a service then
 * don't de-register it.
 */

#include <sys/ib/mgt/ibcm/ibcm_impl.h>
#include <sys/ddi.h>


/* statics */
static vmem_t		*ibcm_local_sid_arena;
static vmem_t		*ibcm_ip_sid_arena;
static ib_svc_id_t	ibcm_local_sid_seed;
static ib_com_id_t	ibcm_local_cid_seed;
_NOTE(READ_ONLY_DATA({ibcm_local_sid_arena ibcm_local_sid_seed
    ibcm_ip_sid_arena ibcm_local_cid_seed}))
static void		ibcm_delete_state_from_avl(ibcm_state_data_t *statep);
static void		ibcm_init_conn_trace(ibcm_state_data_t *statep);
static void		ibcm_fini_conn_trace(ibcm_state_data_t *statep);
static void		ibcm_dump_conn_trbuf(void *statep, char *line_prefix,
			    char *buf, int buf_size);

/*
 * ibcm_lookup_msg:
 *
 * Retrieves an existing state structure or creates a new one if none found.
 * This function is used during
 *	Passive connection side for INCOMING REQ/REJ/RTU/MRA/DREQ/DREP/LAP msgs
 *	Active connection side for INCOMING REP/REJ/MRA/DREQ/DREP/APR msgs
 *	Active side CM for outgoing REQ message.
 *
 * NOTE: Only return IBCM_LOOKUP_FAIL if lookup failed to find a match.
 *
 * Arguments are:-
 *	event_type	- type of message
 *			incoming REQ, REP, REJ, MRA, RTU
 *	remote_qpn	- Remote QP number
 *	comid		- local/remote comid
 *	remote_hca_guid	- Remote HCA GUID
 *	hcap		- HCA entry ptr
 *	rstatep		- return statep pointer
 *
 * Return Values:
 *	IBCM_LOOKUP_NEW		- new statep allocated
 *	IBCM_LOOKUP_EXISTS	- found an existing entry
 *	IBCM_LOOKUP_FAIL	- No lookup entry found
 *	IBCM_MEMORY_FAILURE	- Memory allocs failed
 */
ibcm_status_t
ibcm_lookup_msg(ibcm_event_type_t event_type, ib_com_id_t comid,
    ib_qpn_t remote_qpn, ib_guid_t remote_hca_guid, ibcm_hca_info_t *hcap,
    ibcm_state_data_t **rstatep)
{
	avl_index_t		where;
	ibcm_state_data_t	*sp;

	IBTF_DPRINTF_L4(cmlog, "ibcm_lookup_msg: event = 0x%x, comid = 0x%x",
	    event_type, comid);
	IBTF_DPRINTF_L4(cmlog, "ibcm_lookup_msg: rem_qpn = 0x%lX, "
	    "rem_hca_guid = 0x%llX", remote_qpn, remote_hca_guid);

	ASSERT(rw_lock_held(&hcap->hca_state_rwlock));

	/*
	 * Lookup in "hca_passive_tree" for IBCM_INCOMING_REQ and
	 * IBCM_INCOMING_REP_STALE;
	 *
	 * Lookup in "hca_passive_comid_tree" for IBCM_INCOMING_REQ_STALE
	 *
	 * All other lookups in "hca_active_tree".
	 *
	 * NOTE: "hca_active_tree" lookups are based on the local comid.
	 * "hca_passive_state_tree" lookups are based on remote QPN
	 * and remote hca GUID.
	 *
	 * Call avl_find to lookup in the respective tree and save result in
	 * "sp". If "sp" is null it implies that no match was found. If so,
	 * allocate a new ibcm_state_data_t and insert it into the AVL tree(s).
	 */
	if ((event_type == IBCM_INCOMING_REQ) ||
	    (event_type == IBCM_INCOMING_REP_STALE)) {
		ibcm_passive_node_info_t	info;

		info.info_qpn = remote_qpn;
		info.info_hca_guid = remote_hca_guid;

		/* Lookup based on Remote QPN and Remote GUID in Passive Tree */
		sp = avl_find(&hcap->hca_passive_tree, &info, &where);
	} else if ((event_type == IBCM_INCOMING_REQ_STALE) ||
	    (event_type == IBCM_INCOMING_REJ_RCOMID)) {
		ibcm_passive_comid_node_info_t	info;

		info.info_comid = comid;
		info.info_hca_guid = remote_hca_guid;

		/* Lookup based on Remote COMID in Passive Tree */
		sp = avl_find(&hcap->hca_passive_comid_tree, &info, &where);
	} else {	/* any other event including IBCM_OUTGOING_REQ */
		/* Lookup based on Local comid in Active Tree */
		sp = avl_find(&hcap->hca_active_tree, &comid, &where);
	}

	/* matching entry found !! */
	if (sp != NULL) {
		IBTF_DPRINTF_L4(cmlog, "ibcm_lookup_msg: match found "
		    "statep = %p", sp);
		if (event_type == IBCM_INCOMING_REQ)
			kmem_free(*rstatep, sizeof (ibcm_state_data_t));
		*rstatep = sp;		/* return the matched statep */

		mutex_enter(&(sp->state_mutex));
		IBCM_REF_CNT_INCR(sp); /* increment the ref count */
		mutex_exit(&(sp->state_mutex));

		return (IBCM_LOOKUP_EXISTS);
	}

	/*
	 * If we came here then it implies that CM didn't
	 * find a matching entry. We will create a new entry in avl tree,
	 * if event_type is INCOMING/OUTGOING REQ, REQ_STALE/REP_STALE.
	 * statep is created for INCOMING/OUTGOING REQ.
	 * For all other event_types we return lookup failure
	 */
	if (!((event_type == IBCM_INCOMING_REQ) ||
	    (event_type == IBCM_INCOMING_REQ_STALE) ||
	    (event_type == IBCM_INCOMING_REP_STALE) ||
	    (event_type == IBCM_OUTGOING_REQ))) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_lookup_msg: failed for "
		    "event type %x remote_comid = 0x%x",
		    event_type, comid);

		return (IBCM_LOOKUP_FAIL);
	}

	if ((event_type == IBCM_INCOMING_REQ) ||
	    (event_type == IBCM_OUTGOING_REQ)) {

		/* fill in the new ibcm_state_data */
		sp = *rstatep;

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sp))

		/* initialize statep */
		mutex_init(&sp->state_mutex, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&sp->block_client_cv, NULL, CV_DRIVER, NULL);
		cv_init(&sp->block_mad_cv, NULL, CV_DRIVER, NULL);

		sp->hcap = hcap;
		IBCM_REF_CNT_INCR(sp);
		sp->local_comid = comid;

		if (ibcm_enable_trace != 0)
			ibcm_init_conn_trace(sp);

		if (event_type == IBCM_INCOMING_REQ) {	/* Passive side */
			sp->state = IBCM_STATE_REQ_RCVD;
			sp->clnt_proceed = IBCM_BLOCK;
			sp->close_nocb_state = IBCM_UNBLOCK;
			sp->remote_hca_guid = remote_hca_guid;
			sp->remote_qpn = remote_qpn;

		} else if (event_type == IBCM_OUTGOING_REQ) { /* Active side */
			sp->close_nocb_state = IBCM_UNBLOCK;
			sp->state = IBCM_STATE_IDLE;
		}

		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*sp))

	} else {
		sp = *rstatep;	/* for incoming REQ/REP STALE only */
	}

	if ((event_type == IBCM_INCOMING_REQ) ||
	    (event_type == IBCM_INCOMING_REP_STALE)) {

		/* First, insert a new "sp" into "hca_passive_tree" @ "where" */
		avl_insert(&(hcap->hca_passive_tree), (void *)sp, where);

		if (event_type == IBCM_INCOMING_REQ) {	/* Only INCOMING_REQ */
			/*
			 * We have to do an avl_find() to figure out
			 * "where" to insert the statep into the active tree.
			 *
			 * CM doesn't care for avl_find's retval.
			 */
			(void) avl_find(&hcap->hca_active_tree,
			    &sp->local_comid, &where);

			/* Next, insert the "sp" into "hca_active_tree" */
			avl_insert(&hcap->hca_active_tree, (void *)sp, where);
		}
	} else if (event_type == IBCM_INCOMING_REQ_STALE) {
		avl_insert(&(hcap->hca_passive_comid_tree), (void *)sp, where);
	} else {	/* IBCM_OUTGOING_REQ */
		/* Insert the new sp only into "hca_active_tree", @ "where" */
		avl_insert(&(hcap->hca_active_tree), (void *)sp, where);
	}

	return (IBCM_LOOKUP_NEW);	/* return new lookup */
}


/*
 * ibcm_active_node_compare:
 * 	- AVL active tree node compare
 *
 * Arguments:
 *	p1	: pointer to local comid
 *	p2	: pointer to passed ibcm_state_data_t
 *
 * Return values:
 *	0	: match found
 *	-1	: no match but insert to left side of the tree
 *	+1	: no match but insert to right side of the tree
 */
int
ibcm_active_node_compare(const void *p1, const void *p2)
{
	ib_com_id_t		*local_comid = (ib_com_id_t *)p1;
	ibcm_state_data_t	*statep = (ibcm_state_data_t *)p2;

	IBTF_DPRINTF_L5(cmlog, "ibcm_active_node_compare: "
	    "comid: 0x%x, statep: 0x%p", *local_comid, statep);

	if (*local_comid > statep->local_comid) {
		return (+1);
	} else if (*local_comid < statep->local_comid) {
		return (-1);
	} else {
		return (0);
	}
}


/*
 * ibcm_passive_node_compare:
 * 	- AVL passive tree node compare (passive side)
 *
 * Arguments:
 *	p1	: pointer to ibcm_passive_node_info (remote qpn and remote guid)
 *	p2	: pointer to passed ibcm_state_data_t
 *
 * Return values:
 *	0	: match found
 *	-1	: no match but insert to left side of the tree
 *	+1	: no match but insert to right side of the tree
 */
int
ibcm_passive_node_compare(const void *p1, const void *p2)
{
	ibcm_state_data_t		*statep = (ibcm_state_data_t *)p2;
	ibcm_passive_node_info_t	*infop = (ibcm_passive_node_info_t *)p1;

	IBTF_DPRINTF_L5(cmlog, "ibcm_passive_node_compare: "
	    "statep: 0x%p, p1: 0x%p", statep, p1);

	/*
	 * PASSIVE SIDE: (REQ, REP, MRA, REJ)
	 *	always search by active COMID
	 */
	if (infop->info_qpn > statep->remote_qpn) {
		return (+1);
	} else if (infop->info_qpn < statep->remote_qpn) {
		return (-1);
	} else {
		if (infop->info_hca_guid < statep->remote_hca_guid) {
			return (-1);
		} else if (infop->info_hca_guid > statep->remote_hca_guid) {
			return (+1);
		} else {
			return (0);
		}
	}
}

/*
 * ibcm_passive_comid_node_compare:
 * 	- AVL passive comid tree node compare (passive side)
 *
 * Arguments:
 *	p1	: pointer to ibcm_passive_comid_node_info
 *		  (remote comid and remote guid)
 *	p2	: pointer to passed ibcm_state_data_t
 *
 * Return values:
 *	0	: match found
 *	-1	: no match but insert to left side of the tree
 *	+1	: no match but insert to right side of the tree
 */
int
ibcm_passive_comid_node_compare(const void *p1, const void *p2)
{
	ibcm_state_data_t		*statep = (ibcm_state_data_t *)p2;
	ibcm_passive_comid_node_info_t	*infop =
	    (ibcm_passive_comid_node_info_t *)p1;

	IBTF_DPRINTF_L5(cmlog, "ibcm_passive_comid_node_compare: "
	    "statep: 0x%p, p1: 0x%p", statep, p1);

	if (infop->info_comid > statep->remote_comid) {
		return (+1);
	} else if (infop->info_comid < statep->remote_comid) {
		return (-1);
	} else {
		if (infop->info_hca_guid < statep->remote_hca_guid) {
			return (-1);
		} else if (infop->info_hca_guid > statep->remote_hca_guid) {
			return (+1);
		} else {
			return (0);
		}
	}
}


void
ibcm_delete_state_from_avl(ibcm_state_data_t *statep)
{
	avl_index_t			a_where = 0;
	avl_index_t			p_where = 0;
	avl_index_t			pcomid_where = 0;
	ibcm_hca_info_t			*hcap;
	ibcm_state_data_t		*active_nodep, *passive_nodep;
	ibcm_state_data_t		*passive_comid_nodep;
	ibcm_passive_node_info_t	info;
	ibcm_passive_comid_node_info_t	info_comid;

	IBTF_DPRINTF_L4(cmlog, "ibcm_delete_state_from_avl: statep 0x%p",
	    statep);

	if (statep == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_delete_state_from_avl: statep"
		    " NULL");
		return;
	}

	hcap = statep->hcap;

	/*
	 * Once the avl tree lock is acquired, no other thread can increment
	 * ref cnt, until tree lock is exit'ed. Since the statep is removed
	 * from the avl's after acquiring lock below, no other thread can
	 * increment the ref cnt after acquiring the lock below
	 */

	rw_enter(&hcap->hca_state_rwlock, RW_WRITER);

	/* Lookup based on Local comid in the active tree */
	active_nodep = avl_find(&hcap->hca_active_tree, &(statep->local_comid),
	    &a_where);

	/* Lookup based on Remote QPN and Remote GUID in the passive tree */
	info.info_qpn = statep->remote_qpn;
	info.info_hca_guid = statep->remote_hca_guid;
	passive_nodep =  avl_find(&hcap->hca_passive_tree, &info, &p_where);

	/* Lookup based on Remote Comid and Remote GUID in the passive tree */
	info_comid.info_comid = statep->remote_comid;
	info_comid.info_hca_guid = statep->remote_hca_guid;
	passive_comid_nodep =  avl_find(&hcap->hca_passive_comid_tree,
	    &info_comid, &pcomid_where);

	/* remove it from the tree, destroy record and the nodep */
	if (active_nodep == statep) {
		avl_remove(&hcap->hca_active_tree, active_nodep);
	}

	if (passive_nodep == statep) {
		avl_remove(&hcap->hca_passive_tree, passive_nodep);
	}

	if (passive_comid_nodep == statep) {
		avl_remove(&hcap->hca_passive_comid_tree, passive_comid_nodep);
	}

	rw_exit(&hcap->hca_state_rwlock);
}

/*
 * ibcm_dealloc_state_data:
 *	Deallocates all buffers and the memory of state structure
 * This routine can be called on statep that has ref_cnt of 0, and that is
 * already deleted from the avl tree's
 *
 * Arguments are:-
 *	statep	- statep to be deleted
 *
 * Return Values:	NONE
 */
void
ibcm_dealloc_state_data(ibcm_state_data_t *statep)
{
	timeout_id_t timer_val;
	int dump_trace;
	IBTF_DPRINTF_L4(cmlog, "ibcm_dealloc_state_data: statep 0x%p", statep);

	if (statep == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_dealloc_state_data: statep NULL");
		return;
	}

	/* ref_cnt is 0 */
	/* If timer is running - expire it */
	mutex_enter(&statep->state_mutex);
	timer_val = statep->timerid;
	if (timer_val != 0) {
		statep->timerid = 0;
		mutex_exit(&statep->state_mutex);
		(void) untimeout(timer_val);
	} else
		mutex_exit(&statep->state_mutex);

	/* release the ref cnt on the associated ibmf qp */
	if (statep->stored_reply_addr.cm_qp_entry != NULL)
		ibcm_release_qp(statep->stored_reply_addr.cm_qp_entry);

	if (statep->stored_msg != NULL)
		(void) ibcm_free_out_msg(statep->stored_reply_addr.ibmf_hdl,
		    &statep->stored_msg);

	if (statep->dreq_msg != NULL)
		(void) ibcm_free_out_msg(statep->stored_reply_addr.ibmf_hdl,
		    &statep->dreq_msg);

	if (statep->drep_msg != NULL)
		(void) ibcm_free_out_msg(statep->stored_reply_addr.ibmf_hdl,
		    &statep->drep_msg);

	if (statep->mra_msg != NULL)
		(void) ibcm_free_out_msg(statep->stored_reply_addr.ibmf_hdl,
		    &statep->mra_msg);

	if (statep->lapr_msg != NULL)
		(void) ibcm_free_out_msg(statep->stored_reply_addr.ibmf_hdl,
		    &statep->lapr_msg);

	if (statep->defer_cm_msg != NULL)
		kmem_free(statep->defer_cm_msg, IBCM_MSG_SIZE);

	IBTF_DPRINTF_L4(cmlog, "ibcm_dealloc_state_data: done for sp = 0x%p",
	    statep);

	/* Ensure the thread doing ref cnt decr releases the mutex */
	mutex_enter(&statep->state_mutex);
	dump_trace = statep->cm_retries > 0;
	mutex_exit(&statep->state_mutex);

	/*
	 * now call the mutex_destroy() and cv_destroy()
	 */
	mutex_destroy(&statep->state_mutex);

	cv_destroy(&statep->block_client_cv);
	cv_destroy(&statep->block_mad_cv);

	/* free the comid */
	ibcm_free_comid(statep->hcap, statep->local_comid);

	/* Decrement the resource on hcap */
	ibcm_dec_hca_res_cnt(statep->hcap);

	/* dump the trace data into ibtf_debug_buf */
	if ((ibcm_enable_trace & 4) || dump_trace)
		ibcm_dump_conn_trace(statep);

	ibcm_fini_conn_trace(statep);

	/* free the statep */
	kmem_free(statep, sizeof (ibcm_state_data_t));
}

/*
 * ibcm_delete_state_data:
 *	Deletes the state from avl trees, and tries to deallocate state
 *
 * Arguments are:-
 *	statep	- statep to be deleted
 *
 * Return Values:	NONE
 */
void
ibcm_delete_state_data(ibcm_state_data_t *statep)
{
	IBTF_DPRINTF_L4(cmlog, "ibcm_delete_state_data:");

	ibcm_delete_state_from_avl(statep);

	/* Must acquire the state mutex to set delete_state_data */
	mutex_enter(&statep->state_mutex);
	if (statep->ref_cnt > 0) {
		statep->delete_state_data = B_TRUE;
		IBTF_DPRINTF_L4(cmlog, "ibcm_delete_state_data: statep 0x%p "
		    "ref_cnt = %x", statep, statep->ref_cnt);
		mutex_exit(&statep->state_mutex);
		return;
	}
	mutex_exit(&statep->state_mutex);

	ibcm_dealloc_state_data(statep);
}

/*
 * ibcm_find_sidr_entry:
 *	Routines for CM SIDR state structure list manipulation.
 *	Finds an entry based on lid, gid and grh exists fields
 *
 * INPUTS:
 *	lid:		LID of incoming SIDR REQ
 *	gid:		GID of incoming SIDR REQ
 *	grh_exists:	TRUE if GRH exists in the incoming SIDR REQ
 *	req_id:		Request ID
 *	hcap:		CM State table to search for SIDR state structure
 *	statep:		Returns a valid state structure, if one exists based
 *			on lid, gid and grh_exists fields
 *	flag:		IBCM_FLAG_LOOKUP - just lookup
 *			IBCM_FLAG_LOOKUP_AND_ADD - if lookup fails, add it.
 * Return Values:
 *	IBCM_LOOKUP_EXISTS	- found an existing entry
 *	IBCM_LOOKUP_FAIL	- failed to find an entry
 *	IBCM_LOOKUP_NEW		- created a new entry
 */
ibcm_status_t
ibcm_find_sidr_entry(ibcm_sidr_srch_t *srch_param, ibcm_hca_info_t *hcap,
    ibcm_ud_state_data_t **ud_statep, ibcm_lookup_flag_t flag)
{
	ibcm_status_t		status;
	ibcm_ud_state_data_t	*usp;

	IBTF_DPRINTF_L5(cmlog, "ibcm_find_sidr_entry: srch_params are:"
	    "lid=%x, (%llX, %llX), grh: %x, id: %x",
	    srch_param->srch_lid, srch_param->srch_gid.gid_prefix,
	    srch_param->srch_gid.gid_guid, srch_param->srch_grh_exists,
	    srch_param->srch_req_id);

	if (flag == IBCM_FLAG_ADD) {
		*ud_statep = ibcm_add_sidr_entry(srch_param, hcap);
		return (IBCM_LOOKUP_NEW);
	}

	usp = hcap->hca_sidr_list;	/* Point to the list */

	/* traverse the list for a matching entry */
	while (usp != NULL) {
		IBTF_DPRINTF_L5(cmlog, "ibcm_find_sidr_entry: "
		    "lid=%x, (%llX, %llX), grh: %x, id: %x",
		    usp->ud_sidr_req_lid, usp->ud_sidr_req_gid.gid_prefix,
		    usp->ud_sidr_req_gid.gid_guid, usp->ud_grh_exists,
		    usp->ud_req_id);

		if ((usp->ud_sidr_req_lid == srch_param->srch_lid) &&
		    ((srch_param->srch_gid.gid_prefix == 0) ||
		    (srch_param->srch_gid.gid_prefix ==
		    usp->ud_sidr_req_gid.gid_prefix)) &&
		    ((srch_param->srch_gid.gid_guid == 0) ||
		    (srch_param->srch_gid.gid_guid ==
		    usp->ud_sidr_req_gid.gid_guid)) &&
		    (srch_param->srch_req_id == usp->ud_req_id) &&
		    (usp->ud_grh_exists == srch_param->srch_grh_exists) &&
		    (usp->ud_mode == srch_param->srch_mode)) { /* found match */
			*ud_statep = usp;
			IBTF_DPRINTF_L5(cmlog, "ibcm_find_sidr_entry: "
			    "found usp = %p", usp);
			mutex_enter(&usp->ud_state_mutex);
			IBCM_UD_REF_CNT_INCR(usp);
			mutex_exit(&usp->ud_state_mutex);

			return (IBCM_LOOKUP_EXISTS);
		}
		usp = usp->ud_nextp;
	}

	/*
	 * If code came here --> it couldn't find a match.
	 *	OR
	 * the "hcap->hca_sidr_list" was NULL
	 */
	if (flag == IBCM_FLAG_LOOKUP) {
		IBTF_DPRINTF_L3(cmlog, "ibcm_find_sidr_entry: no match found "
		    "lid=%x, (%llX, %llX), grh: %x, id: %x",
		    srch_param->srch_lid, srch_param->srch_gid.gid_prefix,
		    srch_param->srch_gid.gid_guid, srch_param->srch_grh_exists,
		    srch_param->srch_req_id);
		status = IBCM_LOOKUP_FAIL;
	} else {
		*ud_statep = ibcm_add_sidr_entry(srch_param, hcap);
		status = IBCM_LOOKUP_NEW;
	}

	return (status);
}


/*
 * ibcm_add_sidr_entry:
 *	Adds a SIDR entry. Called *ONLY* from ibcm_find_sidr_entry()
 *
 * INPUTS:
 *	lid:		LID of incoming SIDR REQ
 *	gid:		GID of incoming SIDR REQ
 *	grh_exists:	TRUE if GRH exists in the incoming SIDR REQ
 *	req_id:		Request ID
 *	hcap:		CM State table to search for SIDR state structure
 * Return Values: NONE
 */
ibcm_ud_state_data_t *
ibcm_add_sidr_entry(ibcm_sidr_srch_t *srch_param, ibcm_hca_info_t *hcap)
{
	ibcm_ud_state_data_t	*ud_statep;

	IBTF_DPRINTF_L5(cmlog, "ibcm_add_sidr_entry: lid=%x, guid=%llX, "
	    "grh = %x req_id = %x", srch_param->srch_lid,
	    srch_param->srch_gid.gid_guid, srch_param->srch_grh_exists,
	    srch_param->srch_req_id);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ud_statep))

	/* didn't find the entry - so create new */
	ud_statep = kmem_zalloc(sizeof (ibcm_ud_state_data_t), KM_SLEEP);

	mutex_init(&ud_statep->ud_state_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ud_statep->ud_block_client_cv, NULL, CV_DRIVER, NULL);

	/* Initialize some ud_statep fields */
	mutex_enter(&ud_statep->ud_state_mutex);
	ud_statep->ud_hcap		= hcap;
	ud_statep->ud_req_id		= srch_param->srch_req_id;
	ud_statep->ud_ref_cnt		= 1;
	ud_statep->ud_grh_exists	= srch_param->srch_grh_exists;
	ud_statep->ud_sidr_req_lid	= srch_param->srch_lid;
	ud_statep->ud_sidr_req_gid	= srch_param->srch_gid;
	ud_statep->ud_mode		= srch_param->srch_mode;
	ud_statep->ud_max_cm_retries	= ibcm_max_retries;
	mutex_exit(&ud_statep->ud_state_mutex);

	/* Update the list */
	ud_statep->ud_nextp = hcap->hca_sidr_list;
	hcap->hca_sidr_list = ud_statep;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*ud_statep))

	return (ud_statep);
}


/*
 * ibcm_delete_ud_state_data:
 *	Deletes a given state structure
 *
 * Arguments are:-
 *	statep	- statep to be deleted
 *
 * Return Values:	NONE
 */
void
ibcm_delete_ud_state_data(ibcm_ud_state_data_t *ud_statep)
{
	ibcm_ud_state_data_t	*prevp, *headp;
	ibcm_hca_info_t		*hcap;

	IBTF_DPRINTF_L4(cmlog, "ibcm_delete_ud_state_data: ud_statep 0x%p",
	    ud_statep);

	if (ud_statep == NULL || ud_statep->ud_hcap == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_delete_ud_state_data: "
		    "ud_statep or hcap is NULL");
		return;
	}

	hcap = ud_statep->ud_hcap;

	rw_enter(&hcap->hca_sidr_list_lock, RW_WRITER);

	/* Next, remove this from the HCA SIDR list */
	if (hcap->hca_sidr_list != NULL) {
		prevp = NULL;
		headp = hcap->hca_sidr_list;

		while (headp != NULL) {
			/* delete the matching entry */
			if (headp == ud_statep) {
				if (prevp) {
					prevp->ud_nextp = headp->ud_nextp;
				} else {
					prevp = headp->ud_nextp;
					hcap->hca_sidr_list = prevp;
				}
				break;
			}
			prevp = headp;
			headp = headp->ud_nextp;
		}
	}

	rw_exit(&hcap->hca_sidr_list_lock);

	/*
	 * While ref_cnt >  0
	 * - implies someone else is accessing the statep (possibly in
	 * a timeout function handler etc.)
	 * - don't delete statep unless they are done otherwise potentially
	 * one could access released memory and panic.
	 */
	mutex_enter(&ud_statep->ud_state_mutex);
	if (ud_statep->ud_ref_cnt > 0) {
		ud_statep->ud_delete_state_data = B_TRUE;
		IBTF_DPRINTF_L4(cmlog, "ibcm_delete_ud_state_data: "
		    "ud_statep 0x%p ud_ref_cnt = %x", ud_statep,
		    ud_statep->ud_ref_cnt);
		mutex_exit(&ud_statep->ud_state_mutex);
		return;
	}
	mutex_exit(&ud_statep->ud_state_mutex);

	ibcm_dealloc_ud_state_data(ud_statep);
}

/*
 * ibcm_ud_dealloc_state_data:
 *	Deallocates a given ud state structure
 *
 * Arguments are:-
 *	ud statep	- ud statep to be deleted
 *
 * Return Values:	NONE
 */
void
ibcm_dealloc_ud_state_data(ibcm_ud_state_data_t *ud_statep)
{
	timeout_id_t		timer_val;

	IBTF_DPRINTF_L4(cmlog, "ibcm_dealloc_ud_state_data: ud_statep 0x%p",
	    ud_statep);

	/* If timer is running - expire it */
	mutex_enter(&ud_statep->ud_state_mutex);
	if (ud_statep->ud_timerid) {
		timer_val = ud_statep->ud_timerid;
		ud_statep->ud_timerid = 0;
		mutex_exit(&ud_statep->ud_state_mutex);
		(void) untimeout(timer_val);
		IBTF_DPRINTF_L2(cmlog, "ibcm_dealloc_ud_state_data: "
		    "Unexpected timer id 0x%p ud_statep 0x%p", timer_val,
		    ud_statep);
	} else
		mutex_exit(&ud_statep->ud_state_mutex);

	if (ud_statep->ud_stored_msg != NULL) {
		(void) ibcm_free_out_msg(
		    ud_statep->ud_stored_reply_addr.ibmf_hdl,
		    &ud_statep->ud_stored_msg);
	}

	/* release the ref cnt on the associated ibmf qp */
	ASSERT(ud_statep->ud_stored_reply_addr.cm_qp_entry != NULL);
	ibcm_release_qp(ud_statep->ud_stored_reply_addr.cm_qp_entry);

	/* Ensure the thread doing ref cnt decr releases the mutex */
	mutex_enter(&ud_statep->ud_state_mutex);
	mutex_exit(&ud_statep->ud_state_mutex);

	/* now do the mutex_destroy() and cv_destroy() */
	mutex_destroy(&ud_statep->ud_state_mutex);

	cv_destroy(&ud_statep->ud_block_client_cv);

	/* free the req id on SIDR REQ sender side */
	if (ud_statep->ud_mode == IBCM_ACTIVE_MODE)
		ibcm_free_reqid(ud_statep->ud_hcap, ud_statep->ud_req_id);

	/* Decrement the resource on hcap */
	ibcm_dec_hca_res_cnt(ud_statep->ud_hcap);

	/* free the statep */
	kmem_free(ud_statep, sizeof (ibcm_ud_state_data_t));
}


/*
 * ibcm_init_ids:
 *	Create the vmem arenas for the various global ids
 *
 * Arguments are:-
 *	NONE
 *
 * Return Values:	ibcm_status_t
 */

ibcm_status_t
ibcm_init_ids(void)
{
	timespec_t tv;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibcm_local_sid_arena))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibcm_ip_sid_arena))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibcm_local_sid_seed))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibcm_local_cid_seed))

	ibcm_local_sid_arena = vmem_create("ibcm_local_sid",
	    (void *)IBCM_INITIAL_SID, IBCM_MAX_LOCAL_SIDS, 1, NULL, NULL, NULL,
	    0, VM_SLEEP | VMC_IDENTIFIER);

	if (!ibcm_local_sid_arena)
		return (IBCM_FAILURE);

	ibcm_ip_sid_arena = vmem_create("ibcm_ip_sid", (void *)IBCM_INITIAL_SID,
	    IBCM_MAX_IP_SIDS, 1, NULL, NULL, NULL, 0,
	    VM_SLEEP | VMC_IDENTIFIER);

	if (!ibcm_ip_sid_arena)
		return (IBCM_FAILURE);

	/* create a random starting value for local service ids */
	gethrestime(&tv);
	ibcm_local_sid_seed = ((uint64_t)tv.tv_sec << 20) & 0x007FFFFFFFF00000;
	ASSERT((ibcm_local_sid_seed & IB_SID_AGN_MASK) == 0);
	ibcm_local_sid_seed |= IB_SID_AGN_LOCAL;

	ibcm_local_cid_seed = (ib_com_id_t)tv.tv_sec;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibcm_local_sid_arena))
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibcm_local_sid_seed))
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibcm_ip_sid_arena))
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibcm_local_cid_seed))

	return (IBCM_SUCCESS);
}


/*
 * ibcm_init_hca_ids:
 *	Create the vmem arenas for the various hca level ids
 *
 * Arguments are:-
 *	hcap		pointer to ibcm_hca_info_t
 *
 * Return Values:	ibcm_status_t
 */
ibcm_status_t
ibcm_init_hca_ids(ibcm_hca_info_t *hcap)
{
	hcap->hca_comid_arena = vmem_create("ibcm_com_ids",
	    (void *)IBCM_INITIAL_COMID, IBCM_MAX_COMIDS,
	    1, NULL, NULL, NULL, 0, VM_SLEEP | VMC_IDENTIFIER);

	if (!hcap->hca_comid_arena)
		return (IBCM_FAILURE);

	hcap->hca_reqid_arena = vmem_create("ibcm_req_ids",
	    (void *)IBCM_INITIAL_REQID, IBCM_MAX_REQIDS,
	    1, NULL, NULL, NULL, 0, VM_SLEEP | VMC_IDENTIFIER);

	if (!hcap->hca_reqid_arena) {
		vmem_destroy(hcap->hca_comid_arena);
		return (IBCM_FAILURE);
	}

	return (IBCM_SUCCESS);
}

/*
 * ibcm_free_ids:
 *	Destroy the vmem arenas for the various ids
 *
 * Arguments are:-
 *	NONE
 *
 * Return Values:	NONE
 */
void
ibcm_fini_ids(void)
{
	/* All arenas shall be valid */
	vmem_destroy(ibcm_local_sid_arena);
	vmem_destroy(ibcm_ip_sid_arena);
}

/*
 * ibcm_free_hca_ids:
 *	Destroy the vmem arenas for the various ids
 *
 * Arguments are:-
 *	hcap		pointer to ibcm_hca_info_t
 *
 * Return Values:	NONE
 */
void
ibcm_fini_hca_ids(ibcm_hca_info_t *hcap)
{
	/* All arenas shall be valid */
	vmem_destroy(hcap->hca_comid_arena);
	vmem_destroy(hcap->hca_reqid_arena);
}

/* Communication id management routines ie., allocate, free up comids */

/*
 * ibcm_alloc_comid:
 *	Allocate a new communication id
 *
 * Arguments are:-
 *	hcap	:	pointer to ibcm_hca_info_t
 *	comid:		pointer to the newly allocated communication id
 *
 * Return Values:	ibt_status_t
 */
ibcm_status_t
ibcm_alloc_comid(ibcm_hca_info_t *hcap, ib_com_id_t *comidp)
{
	ib_com_id_t comid;

	/* Use next fit, so least recently used com id is allocated */
	comid = (ib_com_id_t)(uintptr_t)vmem_alloc(hcap->hca_comid_arena, 1,
	    VM_SLEEP | VM_NEXTFIT);

	IBTF_DPRINTF_L4(cmlog, "ibcm_alloc_comid: hcap 0x%p comid 0x%lX", hcap,
	    comid);

	/*
	 * As comid is 32 bits, and maximum connections possible are 2^24
	 * per hca, comid allocation would never fail
	 */
	*comidp = comid + ibcm_local_cid_seed;
	if (comid == 0) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_alloc_comid: hcap 0x%p"
		    "no more comids available", hcap);
		return (IBCM_FAILURE);
	}

	return (IBCM_SUCCESS);
}

/*
 * ibcm_free_comid:
 *	Releases the given Communication Id
 *
 * Arguments are:
 *	hcap	:	pointer to ibcm_hca_info_t
 *	comid	:	Communication id to be free'd
 *
 * Return Values:	NONE
 */
void
ibcm_free_comid(ibcm_hca_info_t *hcap, ib_com_id_t comid)
{
	IBTF_DPRINTF_L4(cmlog, "ibcm_free_comid: hcap 0x%p"
	    "comid %x", hcap, comid);
	comid -= ibcm_local_cid_seed;
	vmem_free(hcap->hca_comid_arena, (void *)(uintptr_t)comid, 1);
}

/* Allocate and Free local service ids */

/*
 * ibcm_alloc_local_sids:
 *	Create and destroy the vmem arenas for the service ids
 *
 * Arguments are:-
 *	Number of contiguous SIDs needed
 *
 * Return Values:	starting SID
 */
ib_svc_id_t
ibcm_alloc_local_sids(int num_sids)
{
	ib_svc_id_t sid;

	sid = (ib_svc_id_t)(uintptr_t)vmem_alloc(ibcm_local_sid_arena,
	    num_sids, VM_SLEEP | VM_NEXTFIT);

	IBTF_DPRINTF_L4(cmlog, "ibcm_alloc_local_sids: ServiceID 0x%llX "
	    "num_sids %d", sid, num_sids);
	if (sid == 0) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_alloc_local_sids: "
		    "no more local sids available");
	} else {
		ASSERT((ibcm_local_sid_seed & IB_SID_AGN_MASK) ==
		    IB_SID_AGN_LOCAL);
		sid += ibcm_local_sid_seed;
		IBTF_DPRINTF_L4(cmlog, "ibcm_alloc_local_sids: Success: "
		    "allocated 0x%llX:%d", sid, num_sids);
	}
	return (sid);
}

/*
 * ibcm_free_local_sids:
 *	Releases the given Local service id
 *
 * Arguments are:
 *	num_sids:	Number of local service id's to be free'd
 *	service_id:	Starting local service id that needs to be free'd
 *
 * Return Values:	NONE
 */
void
ibcm_free_local_sids(ib_svc_id_t service_id, int num_sids)
{
	service_id -= ibcm_local_sid_seed;
	IBTF_DPRINTF_L4(cmlog, "ibcm_free_local_sids: "
	    "service_id 0x%llX num_sids %d", service_id, num_sids);
	vmem_free(ibcm_local_sid_arena,
	    (void *)(uintptr_t)service_id, num_sids);
}

/*
 * ibcm_alloc_ip_sid:
 *	Allocate a local IP SID.
 */
ib_svc_id_t
ibcm_alloc_ip_sid()
{
	ib_svc_id_t sid;

	sid = (ib_svc_id_t)(uintptr_t)vmem_alloc(ibcm_ip_sid_arena, 1,
	    VM_SLEEP | VM_NEXTFIT);
	if (sid == 0) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_alloc_ip_sid: no more RDMA IP "
		    "SIDs available");
	} else {
		sid += IB_SID_IPADDR_PREFIX;
		IBTF_DPRINTF_L4(cmlog, "ibcm_alloc_ip_sid: Success: RDMA IP SID"
		    " allocated : 0x%016llX", sid);
	}
	return (sid);
}

/*
 * ibcm_free_ip_sid:
 *	Releases the given IP Service ID
 */
void
ibcm_free_ip_sid(ib_svc_id_t sid)
{
	sid -= IB_SID_IPADDR_PREFIX;
	vmem_free(ibcm_ip_sid_arena, (void *)(uintptr_t)sid, 1);
}


/* Allocate and free request id routines for SIDR */

/*
 * ibcm_alloc_reqid:
 *	Allocate a new SIDR REQ request id
 *
 * Arguments are:-
 *	hcap	:	pointer to ibcm_hca_info_t
 *	*reqid	:	pointer to the new request id returned
 *
 * Return Values:	ibcm_status_t
 */
ibcm_status_t
ibcm_alloc_reqid(ibcm_hca_info_t *hcap, uint32_t *reqid)
{
	/* Use next fit, so least recently used com id is allocated */
	*reqid = (uint32_t)(uintptr_t)vmem_alloc(hcap->hca_reqid_arena, 1,
	    VM_SLEEP | VM_NEXTFIT);

	IBTF_DPRINTF_L4(cmlog, "ibcm_alloc_reqid: hcap 0x%p reqid %x", hcap,
	    *reqid);
	if (!(*reqid)) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_alloc_reqid: "
		    "no more req ids available");
		return (IBCM_FAILURE);
	}
	return (IBCM_SUCCESS);
}

/*
 * ibcm_free_reqid:
 *	Releases the given SIDR REQ request id
 *
 * Arguments are:
 *	hcap	:	pointer to ibcm_hca_info_t
 *	reqid	:	Request id to be free'd
 *
 * Return Values:	NONE
 */
void
ibcm_free_reqid(ibcm_hca_info_t *hcap, uint32_t reqid)
{
	IBTF_DPRINTF_L4(cmlog, "ibcm_free_reqid: hcap 0x%p reqid %x", hcap,
	    reqid);
	vmem_free(hcap->hca_reqid_arena, (void *)(uintptr_t)reqid, 1);
}

/*
 * ibcm_generate_tranid:
 *	Generate a new transaction id based on args
 *
 * Arguments are:-
 *	event_type	CM Message REQ/DREQ/LAP
 *	id		32 bit identifier
 *	cm_tran_priv	CM private data to be filled in top 28 MSB bits of
 *			tran id
 *
 *
 * Return Value:	uint64_t
 */
uint64_t
ibcm_generate_tranid(uint8_t event, uint32_t id, uint32_t cm_tran_priv)
{
	/*
	 * copy comid to bits 31-0 of tran id,
	 * attr id to bits 35-32 of tran id,
	 * cm_priv to bits 63-36 of tran id
	 */
	if (cm_tran_priv == 0)
		/*
		 * The below ensures that no duplicate transaction id is
		 * generated atleast for next 6 months. Calculations:
		 * (2^28)/(1000 * 60 * 24 * 30) = 6 approx
		 */
		cm_tran_priv = gethrtime() >> 20;	/* ~time in ms */

	return ((((uint64_t)cm_tran_priv << 36) | (uint64_t)event << 32) | id);
}

#ifdef DEBUG

/*
 * ibcm_decode_tranid:
 *	Decodes a given transaction id, assuming certain format.
 *
 * Arguments are:-
 *	tran_id		Transaction id to be decoded
 *	cm_tran_priv	CM private data retrieved from transaction id
 *
 * Return Value:	None
 */
void
ibcm_decode_tranid(uint64_t tran_id, uint32_t *cm_tran_priv)
{
	ib_com_id_t		id;
	ibcm_event_type_t	event;

	id = tran_id & 0xFFFFFFFF;
	event = (tran_id >> 32) & 0xF;

	IBTF_DPRINTF_L5(cmlog, "ibcm_decode_tranid: id = 0x%x, event = %x",
	    id, event);

	if (cm_tran_priv) {
		*cm_tran_priv = tran_id >> 36;
		IBTF_DPRINTF_L5(cmlog, "ibcm_decode_tranid: "
		    "cm_tran_priv = %x", *cm_tran_priv);
	}
}

#endif

/*
 * Service ID entry create and lookup functions
 */

/*
 * ibcm_svc_compare:
 * 	- AVL svc tree node compare
 *
 * Arguments:
 *	p1	: pointer to local comid
 *	p2	: pointer to passed ibcm_state_data_t
 *
 * Return values:
 *	0	: match found
 *	-1	: no match but insert to left side of the tree
 *	+1	: no match but insert to right side of the tree
 */
int
ibcm_svc_compare(const void *p1, const void *p2)
{
	ibcm_svc_lookup_t	*sidp = (ibcm_svc_lookup_t *)p1;
	ibcm_svc_info_t		*svcp = (ibcm_svc_info_t *)p2;
	ib_svc_id_t		start_sid = sidp->sid;
	ib_svc_id_t		end_sid = start_sid + sidp->num_sids - 1;

	IBTF_DPRINTF_L5(cmlog, "ibcm_svc_compare: "
	    "sid: 0x%llx, numsids: %d, node_sid: 0x%llx node_num_sids: %d",
	    sidp->sid, sidp->num_sids, svcp->svc_id, svcp->svc_num_sids);

	ASSERT(MUTEX_HELD(&ibcm_svc_info_lock));

	if (svcp->svc_id > end_sid)
		return (-1);
	if (svcp->svc_id + svcp->svc_num_sids - 1 < start_sid)
		return (+1);
	return (0);	/* means there is some overlap of SIDs */
}


/*
 * ibcm_create_svc_entry:
 *	Make sure no conflicting entry exists, then allocate it.
 *	Fill in the critical "look up" details that are provided
 *	in the arguments before dropping the lock.
 *
 * Return values:
 *	Pointer to ibcm_svc_info_t, if created, otherwise NULL.
 */
ibcm_svc_info_t *
ibcm_create_svc_entry(ib_svc_id_t sid, int num_sids)
{
	ibcm_svc_info_t	*svcp;
	ibcm_svc_info_t	*svcinfop;
	ibcm_svc_lookup_t svc;
	avl_index_t where = 0;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*svcinfop))

	/* assume success, and avoid kmem while holding the writer lock */
	svcinfop = kmem_zalloc(sizeof (*svcinfop), KM_SLEEP);
	svcinfop->svc_id = sid;
	svcinfop->svc_num_sids = num_sids;

	svc.sid = sid;
	svc.num_sids = num_sids;

	mutex_enter(&ibcm_svc_info_lock);
#ifdef __lock_lint
	ibcm_svc_compare(NULL, NULL);
#endif
	svcp = avl_find(&ibcm_svc_avl_tree, &svc, &where);
	if (svcp != NULL) {	/* overlab exists */
		mutex_exit(&ibcm_svc_info_lock);
		kmem_free(svcinfop, sizeof (*svcinfop));
		return (NULL);
	}
	avl_insert(&ibcm_svc_avl_tree, (void *)svcinfop, where);
	mutex_exit(&ibcm_svc_info_lock);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*svcinfop))

	return (svcinfop);
}

/*
 * ibcm_find_svc_entry:
 *	Finds a ibcm_svc_info_t entry into the CM's global table.
 *	The search done here assumes the list is sorted by SID.
 *
 * Arguments are:
 *	sid		- Service ID to look up
 *
 * Return values:
 *	Pointer to ibcm_svc_info_t, if found, otherwise NULL.
 */
ibcm_svc_info_t *
ibcm_find_svc_entry(ib_svc_id_t sid)
{
	ibcm_svc_info_t	*svcp;
	ibcm_svc_lookup_t svc;

	IBTF_DPRINTF_L3(cmlog, "ibcm_find_svc_entry: finding SID 0x%llX", sid);

	ASSERT(MUTEX_HELD(&ibcm_svc_info_lock));

	svc.sid = sid;
	svc.num_sids = 1;
#ifdef __lock_lint
	ibcm_svc_compare(NULL, NULL);
#endif
	svcp = avl_find(&ibcm_svc_avl_tree, &svc, NULL);
	if (svcp != NULL) {
		IBTF_DPRINTF_L3(cmlog, "ibcm_find_svc_entry: "
		    "found SID = 0x%llX", sid);
		return (svcp);	/* found it */
	}
	IBTF_DPRINTF_L3(cmlog, "ibcm_find_svc_entry: SID %llX not found", sid);
	return (NULL);
}

/*
 * ibcm_alloc_ibmf_msg:
 * Allocate an ibmf message structure and the additional memory required for
 * sending an outgoing CM mad.  The ibmf message structure contains two
 * ibmf_msg_bufs_t fields, one for the incoming MAD and one for the outgoing
 * MAD.  The CM must allocate the memory for the outgoing MAD.  The msg_buf
 * field has three buffers: the mad header, the class header, and the class
 * data.  To simplify the code and reduce the number of kmem_zalloc() calls,
 * ibcm_alloc_ibmf_msg will allocate one buffer and set the pointers to the
 * right offsets.  No class header is needed so only the mad header and class
 * data fields are used.
 */
ibt_status_t
ibcm_alloc_out_msg(ibmf_handle_t ibmf_handle, ibmf_msg_t **ibmf_msgpp,
    uint8_t method)
{
	ib_mad_hdr_t	*output_mad_hdr;
	int		sa_retval;

	if ((sa_retval =
	    ibmf_alloc_msg(ibmf_handle, IBMF_ALLOC_SLEEP, ibmf_msgpp)) !=
	    IBMF_SUCCESS) {
		IBTF_DPRINTF_L1(cmlog, "ibcm_alloc_out_msg: "
		    "ibmf_alloc_msg failed with IBMF_ALLOC_SLEEP");
		return (ibcm_ibmf_analyze_error(sa_retval));
	}

	(*ibmf_msgpp)->im_msgbufs_send.im_bufs_mad_hdr = kmem_zalloc(
	    IBCM_MAD_SIZE, KM_SLEEP);

	(*ibmf_msgpp)->im_msgbufs_send.im_bufs_cl_data_len = IBCM_MSG_SIZE;
	(*ibmf_msgpp)->im_msgbufs_send.im_bufs_cl_data =
	    (uchar_t *)((*ibmf_msgpp)->im_msgbufs_send.im_bufs_mad_hdr) +
	    IBCM_MAD_HDR_SIZE;

	/* initialize generic CM MAD header fields */
	output_mad_hdr = IBCM_OUT_HDRP((*ibmf_msgpp));
	output_mad_hdr->BaseVersion = IBCM_MAD_BASE_VERSION;
	output_mad_hdr->MgmtClass = MAD_MGMT_CLASS_COMM_MGT;
	output_mad_hdr->ClassVersion = IBCM_MAD_CLASS_VERSION;
	output_mad_hdr->R_Method = method;

	return (IBT_SUCCESS);
}

/*
 * ibcm_free_ibmf_msg:
 * Frees the buffer and ibmf message associated with an outgoing CM message.
 * This function should only be used to free messages created by
 * ibcm_alloc_out_msg.  Will return IBCM_FAILURE if the ibmf_free_msg() call
 * fails and IBCM_SUCCESS otherwise.
 */
ibcm_status_t
ibcm_free_out_msg(ibmf_handle_t ibmf_handle, ibmf_msg_t **ibmf_msgpp)
{
	int ibmf_status;

	kmem_free((*ibmf_msgpp)->im_msgbufs_send.im_bufs_mad_hdr,
	    IBCM_MAD_SIZE);

	if ((ibmf_status = ibmf_free_msg(ibmf_handle, ibmf_msgpp)) !=
	    IBMF_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_free_out_msg: "
		    "ibmf_free_msg failed %d", ibmf_status);
		return (IBCM_FAILURE);
	} else
		return (IBCM_SUCCESS);
}

ibcm_qp_list_t *
ibcm_find_qp(ibcm_hca_info_t *hcap, int port_no, ib_pkey_t pkey)
{
	ibcm_qp_list_t		*entry;
	ibmf_qp_handle_t	ibmf_qp;
	int			ibmf_status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*entry))

	mutex_enter(&ibcm_qp_list_lock);

	/*
	 * CM currently does not track port up and down status. If tracking of
	 * " port status" is added in the future, then CM could be optimized to
	 * re-use other ports on hcap, if the port associated with the above
	 * port_no is down. But, the issue of "reachability" needs to be
	 * handled, before selecting an alternative port different from above.
	 */
	entry = hcap->hca_port_info[port_no-1].port_qplist;
	while (entry != NULL) {
		if (entry->qp_pkey == pkey) {
			++entry->qp_ref_cnt;
			mutex_exit(&ibcm_qp_list_lock);
			return (entry);
		}
		entry = entry->qp_next;
	}

	/*
	 * entry not found, attempt to alloc a qp
	 * This may be optimized in the future, to allocate ibmf qp's
	 * once the "CM mgmt pkeys" are precisely known.
	 */
	ibmf_status = ibmf_alloc_qp(
	    hcap->hca_port_info[port_no-1].port_ibmf_hdl, pkey, IB_GSI_QKEY,
	    IBMF_ALT_QP_MAD_NO_RMPP, &ibmf_qp);

	if (ibmf_status != IBMF_SUCCESS) {
		mutex_exit(&ibcm_qp_list_lock);
		IBTF_DPRINTF_L2(cmlog, "ibcm_find_qp: failed to alloc IBMF QP"
		    "for Pkey = %x port_no = %x status = %d hcaguid = %llXp",
		    pkey, port_no, ibmf_status, hcap->hca_guid);
		/*
		 * This may be optimized in the future, so as CM would attempt
		 * to re-use other QP's whose ref cnt is 0 in the respective
		 * port_qplist, by doing an ibmf_modify_qp with pkey above.
		 */
		return (NULL);
	}

	entry = kmem_alloc(sizeof (ibcm_qp_list_t), KM_SLEEP);
	entry->qp_next = hcap->hca_port_info[port_no-1].port_qplist;
	hcap->hca_port_info[port_no-1].port_qplist = entry;
	entry->qp_cm = ibmf_qp;
	entry->qp_ref_cnt = 1;
	entry->qp_pkey = pkey;
	entry->qp_port = &(hcap->hca_port_info[port_no-1]);

	mutex_exit(&ibcm_qp_list_lock);

	/* set-up the handler */
	ibmf_status = ibmf_setup_async_cb(
	    hcap->hca_port_info[port_no-1].port_ibmf_hdl, ibmf_qp,
	    ibcm_recv_cb, entry, 0);

	ASSERT(ibmf_status == IBMF_SUCCESS);

#ifdef	DEBUG
	ibcm_query_qp(hcap->hca_port_info[port_no-1].port_ibmf_hdl, ibmf_qp);
#endif

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*entry))

	return (entry);
}

void
ibcm_release_qp(ibcm_qp_list_t *cm_qp_entry)
{
	mutex_enter(&ibcm_qp_list_lock);
	--cm_qp_entry->qp_ref_cnt;
	ASSERT(cm_qp_entry->qp_ref_cnt >= 0);
	mutex_exit(&ibcm_qp_list_lock);
}


/* called holding the ibcm_qp_list_lock mutex */
ibcm_status_t
ibcm_free_qp(ibcm_qp_list_t *cm_qp_entry)
{
	int	ibmf_status;

	IBTF_DPRINTF_L5(cmlog, "ibcm_free_qp: qp_hdl %p ref_cnt %d pkey %x",
	    cm_qp_entry->qp_cm, cm_qp_entry->qp_ref_cnt, cm_qp_entry->qp_pkey);

	/* check, there are no users of this ibmf qp */
	if (cm_qp_entry->qp_ref_cnt != 0)
		return (IBCM_FAILURE);

	/* Tear down the receive callback */
	ibmf_status = ibmf_tear_down_async_cb(
	    cm_qp_entry->qp_port->port_ibmf_hdl, cm_qp_entry->qp_cm, 0);
	if (ibmf_status != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_free_qp: "
		    "ibmf_tear_down_async_cb failed %d port_num %d",
		    ibmf_status, cm_qp_entry->qp_port->port_num);
		return (IBCM_FAILURE);
	}

	ibmf_status = ibmf_free_qp(cm_qp_entry->qp_port->port_ibmf_hdl,
	    &cm_qp_entry->qp_cm, 0);
	if (ibmf_status != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_free_qp: ibmf_free_qp failed for"
		    " ibmf_status %d qp hdl %p port_no %x", ibmf_status,
		    cm_qp_entry->qp_cm, cm_qp_entry->qp_port->port_num);
		return (IBCM_FAILURE);
	}

	return (IBCM_SUCCESS);
}

ibcm_status_t
ibcm_free_allqps(ibcm_hca_info_t *hcap, int port_no)
{
	ibcm_qp_list_t		*entry, *freed;
	ibcm_status_t		ibcm_status = IBCM_SUCCESS;

	IBTF_DPRINTF_L5(cmlog, "ibcm_free_allqps: hcap %p port_no %d", hcap,
	    port_no);

	mutex_enter(&ibcm_qp_list_lock);
	entry = hcap->hca_port_info[port_no-1].port_qplist;
	while ((entry != NULL) &&
	    ((ibcm_status = ibcm_free_qp(entry)) == IBCM_SUCCESS)) {
		freed = entry;
		entry = entry->qp_next;
		kmem_free(freed, sizeof (ibcm_qp_list_t));
	}

	if (ibcm_status != IBCM_SUCCESS)	/* sanity the linked list */
		hcap->hca_port_info[port_no-1].port_qplist = entry;
	else	/* all ibmf qp's of port must have been free'd successfully */
		hcap->hca_port_info[port_no-1].port_qplist = NULL;

	mutex_exit(&ibcm_qp_list_lock);
	return (ibcm_status);
}

/*
 * ibt_bind_service() and ibt_get_paths() needs the following helper function
 * to handle endianess in case of Service Data.
 */
void
ibcm_swizzle_from_srv(ibt_srv_data_t *sb_data, uint8_t *service_bytes)
{
	uint8_t		*p8 = service_bytes;
	uint16_t	*p16;
	uint32_t	*p32;
	uint64_t	*p64;
	int		i;

	for (i = 0; i < 16; i++)
		*p8++ = sb_data->s_data8[i];

	p16 = (uint16_t *)p8;
	for (i = 0; i < 8; i++)
		*p16++ = h2b16(sb_data->s_data16[i]);

	p32 = (uint32_t *)p16;
	for (i = 0; i < 4; i++)
		*p32++ = h2b32(sb_data->s_data32[i]);

	p64 = (uint64_t *)p32;
	for (i = 0; i < 2; i++)
		*p64++ = h2b64(sb_data->s_data64[i]);
}

void
ibcm_swizzle_to_srv(uint8_t *service_bytes, ibt_srv_data_t *sb_data)
{
	uint8_t		*p8 = service_bytes;
	uint16_t	*p16;
	uint32_t	*p32;
	uint64_t	*p64;
	int		i;

	for (i = 0; i < 16; i++)
		sb_data->s_data8[i] = *p8++;

	p16 = (uint16_t *)p8;
	for (i = 0; i < 8; i++)
		sb_data->s_data16[i] = h2b16(*p16++);

	p32 = (uint32_t *)p16;
	for (i = 0; i < 4; i++)
		sb_data->s_data32[i] = h2b32(*p32++);
	p64 = (uint64_t *)p32;

	for (i = 0; i < 2; i++)
		sb_data->s_data64[i] = h2b64(*p64++);
}

/* Trace related functions */

void
ibcm_init_conn_trace(ibcm_state_data_t *sp)
{
	IBTF_DPRINTF_L5(cmlog, "ibcm_init_conn_trace: statep %p", sp);

	/* Initialize trace related fields */

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sp->conn_trace))
	sp->conn_trace = kmem_zalloc(sizeof (ibcm_conn_trace_t), KM_SLEEP);
	if ((ibcm_enable_trace & 1) == 0)
		sp->conn_trace->conn_base_tm = gethrtime();
	sp->conn_trace->conn_allocated_trcnt = ibcm_conn_max_trcnt;
	sp->conn_trace->conn_trace_events =
	    kmem_zalloc(sp->conn_trace->conn_allocated_trcnt, KM_SLEEP);
	sp->conn_trace->conn_trace_event_times =
	    kmem_zalloc(sp->conn_trace->conn_allocated_trcnt *
	    sizeof (tm_diff_type), KM_SLEEP);
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*sp->conn_trace))
}

void
ibcm_fini_conn_trace(ibcm_state_data_t *statep)
{
	IBTF_DPRINTF_L5(cmlog, "ibcm_fini_conn_trace: statep %p tracep %p",
	    statep, statep->conn_trace);

	/* free the trace data */
	if (statep->conn_trace) {
		if (statep->conn_trace->conn_trace_events)
			kmem_free(statep->conn_trace->conn_trace_events,
			    statep->conn_trace->conn_allocated_trcnt);
		if (statep->conn_trace->conn_trace_event_times)
			kmem_free(statep->conn_trace->conn_trace_event_times,
			    statep->conn_trace->conn_allocated_trcnt *
			    sizeof (tm_diff_type));

		kmem_free(statep->conn_trace, sizeof (ibcm_conn_trace_t));
	}
}

/* mostly used to profile connection establishment times with dtrace */
void
ibcm_established(hrtime_t time_diff)
{
	if (time_diff > 1000000000LL)	/* 1 second */
		IBTF_DPRINTF_L2(cmlog, "slow connection time (%d seconds)",
		    (uint_t)(time_diff >> 30));
}

void
ibcm_insert_trace(void *statep, ibcm_state_rc_trace_qualifier_t event_qualifier)
{
	ibcm_conn_trace_t	*conn_trace;
	uint8_t			conn_trace_ind;
	hrtime_t		time_diff;
	hrtime_t		hrt;

	if (!(((ibcm_state_data_t *)statep)->conn_trace))
		return;

	conn_trace = ((ibcm_state_data_t *)statep)->conn_trace;

	if (!conn_trace->conn_trace_events)
		return;

	IBTF_DPRINTF_L5(cmlog, "ibcm_insert_trace: statep %p event %d",
	    statep, event_qualifier);

	mutex_enter(&ibcm_trace_mutex);

	/* No more trace memory available, hence return */
	if (conn_trace->conn_trace_ind == conn_trace->conn_allocated_trcnt) {
		mutex_exit(&ibcm_trace_mutex);
		return;
	} else
		++conn_trace->conn_trace_ind;

	conn_trace_ind = conn_trace->conn_trace_ind - 1;

	conn_trace->conn_trace_events[conn_trace_ind] = event_qualifier;

	if ((ibcm_enable_trace & 1) == 0) {
		hrt = gethrtime();
		time_diff = hrt - conn_trace->conn_base_tm;
		if (event_qualifier == IBCM_TRACE_CALLED_CONN_EST_EVENT)
			ibcm_established(time_diff);
		time_diff >>= 10;
		if (time_diff >= TM_DIFF_MAX) {
			/* RESET, future times are relative to new base time. */
			conn_trace->conn_base_tm = hrt;
			time_diff = 0;
		}
		conn_trace->conn_trace_event_times[conn_trace_ind] = time_diff;
	}

	mutex_exit(&ibcm_trace_mutex);

	IBTF_DPRINTF_L5(cmlog, "ibcm_insert_trace: statep %p inserted event %d",
	    statep, event_qualifier);
}

void
ibcm_dump_conn_trace(void *statep)
{
	IBTF_DPRINTF_L5(cmlog, "ibcm_dump_conn_trace: statep %p",
	    statep);

	mutex_enter(&ibcm_trace_print_mutex);
	ibcm_debug_buf[0] = '\0';
	ibcm_dump_conn_trbuf(statep, "ibcm: ", ibcm_debug_buf,
	    IBCM_DEBUG_BUF_SIZE);
	if (ibcm_debug_buf[0] != '\0')
		IBTF_DPRINTF_L2(cmlog, "\n%s", ibcm_debug_buf);

#ifdef	DEBUG

	if (ibcm_test_mode > 1)
		cmn_err(CE_CONT, "IBCM DEBUG TRACE:\n%s", ibcm_debug_buf);
#endif

	mutex_exit(&ibcm_trace_print_mutex);
}

void
ibcm_dump_conn_trbuf(void *statep, char *line_prefix, char *buf, int buf_size)
{
	ibcm_conn_trace_t	*conn_trace;
	int			tr_ind;
	ibcm_state_data_t	*sp;
	int	cur_size = 0;	/* size of item copied */
	int	rem_size;	/* remaining size in trace buffer */
	int	next_data = 0;	/* location where next item copied */

	if ((buf == NULL) || (buf_size <= 0))
		return;

	sp = (ibcm_state_data_t *)statep;

	if (!sp->conn_trace)
		return;

	conn_trace = sp->conn_trace;

	if (!conn_trace->conn_trace_events)
		return;

	rem_size = buf_size;

	/* Print connection level global data */

	/* Print statep, local comid, local qpn */
	cur_size = snprintf(&buf[next_data], rem_size, "%s%s0x%p\n%s%s0x%p\n"
	    "%s%s0x%x/%llx/%d\n%s%s0x%x\n%s%s0x%x/%llx\n%s%s0x%x\n%s%s%llu\n",
	    line_prefix, event_str[IBCM_DISPLAY_SID], (void *)sp,
	    line_prefix, event_str[IBCM_DISPLAY_CHAN], (void *)sp->channel,
	    line_prefix, event_str[IBCM_DISPLAY_LCID], sp->local_comid,
	    (longlong_t)sp->local_hca_guid, sp->prim_port,
	    line_prefix, event_str[IBCM_DISPLAY_LQPN], sp->local_qpn,
	    line_prefix, event_str[IBCM_DISPLAY_RCID], sp->remote_comid,
	    (longlong_t)sp->remote_hca_guid,
	    line_prefix, event_str[IBCM_DISPLAY_RQPN], sp->remote_qpn,
	    line_prefix, event_str[IBCM_DISPLAY_TM], conn_trace->conn_base_tm);

	rem_size = rem_size - cur_size;
	if (rem_size <= 0) {
		buf[buf_size-1] = '\n';
		return;
	}

	next_data = next_data + cur_size;

	for (tr_ind = 0; tr_ind < conn_trace->conn_trace_ind; tr_ind++) {
		cur_size = snprintf(&buf[next_data], rem_size,
		    "%s%sTM_DIFF %u\n", line_prefix,
		    event_str[conn_trace->conn_trace_events[tr_ind]],
		    conn_trace->conn_trace_event_times[tr_ind]);
		rem_size = rem_size - cur_size;
		if (rem_size <= 0) {
			buf[buf_size-1] = '\n';
			return;
		}
		next_data = next_data + cur_size;
	}

	buf[next_data] = '\0';
	IBTF_DPRINTF_L5(cmlog, "ibcm_dump_conn_trbuf: statep %p "
	    "debug buf size %d bytes", statep, next_data);
}


#ifdef	DEBUG

void
ibcm_query_qp(ibmf_handle_t ibmf_hdl, ibmf_qp_handle_t ibmf_qp)
{
	uint8_t		qp_port_num;
	ib_qpn_t	qp_num;
	ib_pkey_t	qp_pkey;
	ib_qkey_t	qp_qkey;
	int		ibmf_status;

	if (ibmf_qp == IBMF_QP_HANDLE_DEFAULT) {
		IBTF_DPRINTF_L4(cmlog, "ibcm_query_qp: QP1");
		return;
	}

	ibmf_status =
	    ibmf_query_qp(ibmf_hdl, ibmf_qp, &qp_num, &qp_pkey, &qp_qkey,
	    &qp_port_num, 0);

	ASSERT(ibmf_status == IBMF_SUCCESS);

	IBTF_DPRINTF_L5(cmlog, "ibcm_query_qp: qpn %x qkey %x pkey %x port %d",
	    qp_num, qp_qkey, qp_pkey, qp_port_num);
}

/*
 * ibcm_dump_raw_message:
 *	dumps 256 bytes of data of a raw message (REP/REQ/DREQ ...)
 *	(can be called from the kernel debugger w/ the message pointer)
 *
 * Arguments:
 *	msgp	- the messages that needs to be dumped
 *
 * Return values: NONE
 */
void
ibcm_dump_raw_message(uchar_t *c)
{
	int	i;

	for (i = 0; i < IBCM_MAD_SIZE; i += 16) {
		/* print in batches of 16 chars at a time */
		IBTF_DPRINTF_L4(cmlog,
		    "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
		    c[i], c[i + 1], c[i + 2], c[i + 3], c[i + 4], c[i + 5],
		    c[i + 6], c[i + 7], c[i + 8], c[i + 9], c[i + 10],
		    c[i + 11], c[i + 12], c[i + 13], c[i + 14], c[i + 15]);
	}
}


/*
 * ibcm_dump_srv_rec:
 *	Dumps Service Records.
 *
 * Arguments:
 *	srv_rec	- the pointer to sa_service_record_t struct.
 *
 * Return values: NONE
 */
void
ibcm_dump_srvrec(sa_service_record_t *srv_rec)
{
	uint8_t		i;

	IBTF_DPRINTF_L4(cmlog, "ibcm_dump_srvrec: Service Records");
	IBTF_DPRINTF_L4(cmlog, "SID       : 0x%016llX", srv_rec->ServiceID);
	IBTF_DPRINTF_L4(cmlog, "Svc GID   : 0x%016llX:0x%016llX",
	    srv_rec->ServiceGID.gid_prefix, srv_rec->ServiceGID.gid_guid);
	IBTF_DPRINTF_L4(cmlog, "Svc PKey  : 0x%X", srv_rec->ServiceP_Key);

	IBTF_DPRINTF_L4(cmlog, "Svc Lease : 0x%lX", srv_rec->ServiceLease);
	IBTF_DPRINTF_L4(cmlog, "Svc Key-hi: 0x%016llX", srv_rec->ServiceKey_hi);
	IBTF_DPRINTF_L4(cmlog, "Svc Key-lo: 0x%016llX", srv_rec->ServiceKey_lo);
	IBTF_DPRINTF_L4(cmlog, "Svc Name  : %s", srv_rec->ServiceName);
	IBTF_DPRINTF_L4(cmlog, "Svc Data  : ");
	for (i = 0; i < IB_SVC_DATA_LEN; i += 8) {
		IBTF_DPRINTF_L4(cmlog,
		    "\t 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X",
		    srv_rec->ServiceData[i], srv_rec->ServiceData[i+1],
		    srv_rec->ServiceData[i+2], srv_rec->ServiceData[i+3],
		    srv_rec->ServiceData[i+4], srv_rec->ServiceData[i+5],
		    srv_rec->ServiceData[i+6], srv_rec->ServiceData[i+7]);
	}
}


/*
 * ibcm_dump_pathrec:
 *	Dumps Path Records.
 *
 * Arguments:
 *	path_rec - the pointer to sa_path_record_t struct.
 *
 * Return values: NONE
 */
void
ibcm_dump_pathrec(sa_path_record_t *path_rec)
{
	IBTF_DPRINTF_L5(cmlog, "Path Record:");
	IBTF_DPRINTF_L5(cmlog, "SGID: (sn_prefix)  %016llX",
	    path_rec->SGID.gid_prefix);
	IBTF_DPRINTF_L5(cmlog, "SGID: (GUID)       %016llX",
	    path_rec->SGID.gid_guid);
	IBTF_DPRINTF_L5(cmlog, "DGID: (sn_prefix)  %016llX",
	    path_rec->DGID.gid_prefix);
	IBTF_DPRINTF_L5(cmlog, "DGID: (GUID)       %016llX",
	    path_rec->DGID.gid_guid);
	IBTF_DPRINTF_L5(cmlog, "SLID:              %04X", path_rec->SLID);
	IBTF_DPRINTF_L5(cmlog, "DLID:              %04X", path_rec->DLID);
	IBTF_DPRINTF_L5(cmlog, "Raw Traffic:       %01X", path_rec->RawTraffic);
	IBTF_DPRINTF_L5(cmlog, "Flow Label:        %05X", path_rec->FlowLabel);
	IBTF_DPRINTF_L5(cmlog, "Hop Limit:         %02X", path_rec->HopLimit);
	IBTF_DPRINTF_L5(cmlog, "TClass:            %02X", path_rec->TClass);
	IBTF_DPRINTF_L5(cmlog, "Reversible:	   %01X", path_rec->Reversible);
	IBTF_DPRINTF_L5(cmlog, "Numb Paths:        %02d", path_rec->NumbPath);
	IBTF_DPRINTF_L5(cmlog, "P_Key:             %04X", path_rec->P_Key);
	IBTF_DPRINTF_L5(cmlog, "SL:                %02X", path_rec->SL);
	IBTF_DPRINTF_L5(cmlog, "Path MTU Selector: %01X",
	    path_rec->MtuSelector);
	IBTF_DPRINTF_L5(cmlog, "Path MTU:          %02X", path_rec->Mtu);
	IBTF_DPRINTF_L5(cmlog, "Path Rate Selector:%01X",
	    path_rec->RateSelector);
	IBTF_DPRINTF_L5(cmlog, "Path Rate:         %02X", path_rec->Rate);
	IBTF_DPRINTF_L5(cmlog, "Packet LT Selector:%01X",
	    path_rec->PacketLifeTimeSelector);
	IBTF_DPRINTF_L5(cmlog, "Packet Life Time:  %d (dec)",
	    path_rec->PacketLifeTime);
	IBTF_DPRINTF_L5(cmlog, "Preference Bit:    %02X", path_rec->Preference);
}


/*
 * ibcm_dump_node_rec:
 *	Dumps Node Records.
 *
 * Arguments:
 *	nrec - the pointer to sa_node_record_t struct.
 *
 * Return values: NONE
 */
void
ibcm_dump_noderec(sa_node_record_t *nrec)
{
	IBTF_DPRINTF_L5(cmlog, "ibcm_dump_noderec: Node Info Record");
	IBTF_DPRINTF_L5(cmlog, "LID       : %04X", nrec->LID);
	IBTF_DPRINTF_L5(cmlog, "Base Ver  : %02X", nrec->NodeInfo.BaseVersion);
	IBTF_DPRINTF_L5(cmlog, "Class Ver : %02X", nrec->NodeInfo.ClassVersion);
	IBTF_DPRINTF_L5(cmlog, "Node Type : %02d", nrec->NodeInfo.NodeType);
	IBTF_DPRINTF_L5(cmlog, "Num Ports : %02X", nrec->NodeInfo.NumPorts);
	IBTF_DPRINTF_L5(cmlog, "SysImgGUID: %016llX",
	    nrec->NodeInfo.SystemImageGUID);
	IBTF_DPRINTF_L5(cmlog, "NODE GUID : %016llX", nrec->NodeInfo.NodeGUID);
	IBTF_DPRINTF_L5(cmlog, "Port GUID : %016llX", nrec->NodeInfo.PortGUID);
	IBTF_DPRINTF_L5(cmlog, "PartionCap: %04X", nrec->NodeInfo.PartitionCap);
	IBTF_DPRINTF_L5(cmlog, "Device ID : %04X", nrec->NodeInfo.DeviceID);
	IBTF_DPRINTF_L5(cmlog, "Revision  : %06X", nrec->NodeInfo.Revision);
	IBTF_DPRINTF_L5(cmlog, "LocalPort#: %02X", nrec->NodeInfo.LocalPortNum);
	IBTF_DPRINTF_L5(cmlog, "Vendor ID : %06X", nrec->NodeInfo.VendorID);
	IBTF_DPRINTF_L5(cmlog, "Description: %s",
	    (char *)&nrec->NodeDescription);
}
#endif


/*
 * ibcm_ibmf_analyze_error:
 *	Checks IBMF status and determines appropriate ibt status.
 *
 * Arguments:
 *	ibmf_status - IBMF Status
 *
 * Return values:
 *	ibt_status_t
 */
ibt_status_t
ibcm_ibmf_analyze_error(int ibmf_status)
{
	if (ibt_check_failure(ibmf_status, NULL) != IBT_FAILURE_STANDARD) {
		/*
		 * IBMF specific failure, return special error code
		 * to the client so that it can retrieve any associated ENA.
		 */
		return (ibmf_status);
	} else if (ibmf_status == IBMF_TRANS_TIMEOUT) {
		return (IBT_IBMF_TIMEOUT);
	} else {
		/*
		 * IBMF failed for some other reason, invalid arguments etc.
		 * Analyze, log ENA with IBTF and obtain a special ibt_status_t
		 * that indicates IBMF failure.
		 */
		if ((ibmf_status == IBMF_BAD_CLASS) ||
		    (ibmf_status == IBMF_BAD_HANDLE) ||
		    (ibmf_status == IBMF_BAD_QP_HANDLE) ||
		    (ibmf_status == IBMF_BAD_NODE) ||
		    (ibmf_status == IBMF_BAD_PORT) ||
		    (ibmf_status == IBMF_BAD_VERSION) ||
		    (ibmf_status == IBMF_BAD_FLAGS) ||
		    (ibmf_status == IBMF_BAD_SIZE) ||
		    (ibmf_status == IBMF_INVALID_GID) ||
		    (ibmf_status == IBMF_INVALID_ARG) ||
		    (ibmf_status == IBMF_INVALID_FIELD) ||
		    (ibmf_status == IBMF_UNSUPP_METHOD) ||
		    (ibmf_status == IBMF_UNSUPP_METHOD_ATTR)) {

			/*
			 * These errors, we should not see...
			 * something really bad happened!.
			 */
			IBTF_DPRINTF_L2(cmlog, "ibcm_ibmf_analyze_error: "
			    "Unexpected ERROR from IBMF - %d", ibmf_status);
		}
		return (ibt_get_module_failure(IBT_FAILURE_IBMF, 0));
	}
}
