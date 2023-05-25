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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/ib/mgt/ibcm/ibcm_impl.h>
#include <sys/callb.h>

/*
 * ibcm_sm.c
 *	These routines implement the CM state machine (both ACTIVE and PASSIVE)
 *
 * Points to Note :
 *
 * o  CM uses one ibcm_hca_info_t entry per HCA  to store all the
 *    connection state data belonging to that HCA in the AVL trees, etc.,
 *
 * o  There is one state structure per RC, referenced from three AVL trees
 *    ie. the HCA active AVL tree, and the HCA passive AVL tree and HCA
 *    passive comid tree
 *
 * o  SIDR state structures are stored in a linked list
 *
 * o  The term statep generally refers to RC, until explicitly mentioned
 *    in the notes below
 *
 * o  Any thread that may access statep increments the ref_cnt. This ensures
 *    that statep is not deleted when it is still being accessed and modified
 *    by other threads
 *
 * o  Any thread that may want to search the AVL tree(s) holds the hca state
 *    table reader lock. If it shall insert/delete a new state structure, then
 *    the lock held is writer lock.
 *
 * o  Incrementing and Decrementing the ref_cnt can happen only after acquiring
 *    statep mutex
 *
 * o  Deleting a statep can happen only by acquiring the hca state writer lock
 *    and statep mutex and if ref_cnt is zero.
 *
 * o  Statep mutexes are used to decrease the hca state table lock holding
 *    times. thus increasing more number of threads that can access hca
 *    global data structures
 *
 * o  Statep mutexes cannot be hold for long time. They are primarily used to
 *    check the state of statep, change it and exit the lock. Other threads
 *    checking this statep find statep's new state, and may exit without
 *    further processing (as the statep->state has changed).
 *
 * o  Statep mutex must be held while setting and unsetting the timer id
 *    values and during untimeout
 *
 * Re-stating, the overall purpose of these various locks are:
 *   - Minimize the time state table locks are held
 *   - Writer locks are held only while inserting/deleting into trees,
 *	so multiple readers can traverse data structures in parallel
 *   - Minimize the time statep mutex held, so other threads entering the same
 *	statep mutex are not held for long
 *
 * The CM state machine logic ensures that the statep is valid and exists
 * when timeout callback (ibcm_timeout_cb) is called. This is ensured by
 * cancelling timeouts on state changes, where appropriate
 *
 *
 * The timeout processing is handled in the context in which the
 * timeout callback is invoked.
 *
 * The CM STATE MACHINE logic flow:
 *
 * On an incoming MAD:-
 *
 * IBMF -> ibcm_process_incoming_mad
 *	Verify and branch to one of the below connection state routines.
 *	The callback arg from ibmf has the pointer to ibcm_hca_info_t
 *
 * 1. INCOMING REQ MAD
 *
 *	Acquire hca state table WRITER lock
 *	Do lookup in passive AVL tree by remote qpn and remote hca guid
 *
 *	If (new lookup)
 *
 *	  create new statep, initialize key fields
 *	  obtain new local com id, insert into hca state AVL tree
 *	  release hca state table WRITER lock
 *
 *	  Initialize remaining fields
 *	  If invalid service id,
 *		send a REJ reply,
 *		decr ref_cnt holding state mutex
 *	  If existing peer conn, check guids, and break the tie
 *	  Call the cep state transition function
 *	  Send an RTU/REJ reply
 *	  Check and handle for any incoming REJ's during REQ RCVD state
 *
 *    else if (existing lookup)
 *
 *	  increment refcnt holding state mutex
 *	  release hca state table WRITER lock
 *
 *	  re-acquire the statep mutex
 *	  if (statep->state is REP SENT/REJ SENT/ MRA SENT)
 *		resend the mad
 *	  else if established
 *		handle the stale detection
 *	  else
 *		drop the mad (no processing required)
 *	  decr statep->ref_cnt, release state mutex
 *
 *
 * 2. INCOMING REP MAD
 *
 *    Acquire hca state READER lock
 *    Do lookup in hca state tree by local com id
 *    Release hca state table READER lock
 *
 *    if lookup does not exist
 *	 return
 *
 *    if look up exists
 *	 incr statep->ref_cnt holding state mutex
 *
 *    acquire the statep lock
 *    if (state == ESTABLISHED or REJ SENt or MRA REP SENT)
 *	  resend the MAD
 *	  release state mutex, cancel req sent timer
 *	  decrement ref_cnt holding the statep lock
 *	  return
 *
 *    if (state == REQ_SENT or REP_WAIT)
 *	  first, change state to REP_RCVD
 *	  release statep lock
 *	  cancel timers
 *	  lookup in the passive tree by remote qpn and remote hca guid
 *	  if entry already exists
 *		 handle the stale detection
 *	  else
 *		add to the passive tree
 *
 *	  Initialize fields of statep
 *	  Call the qp state transition function
 *	  Post RTU/REJ reply
 *	  Acquire the state mutex
 *	  decrement the ref cnt
 *	  release the statep lock
 *
 * 3. INCOMING MRA
 *
 *	Acquire hca state table READER lock
 *	Do lookup in active hca state tree by local com id
 *	Release hca state table READER lock
 *
 *	If lookup does not exist
 *		return
 *
 *	if look up exists
 *		 incr statep->ref_cnt holding state mutex
 *
 *	acquire state mutex
 *	if (state is REQ_SENT or REP_SENT)
 *	  change state to REP WAIT or MRA REP RCVD
 *	  release state mutex
 *	  cancel the current timer
 *
 *	  reacquire state mutex
 *	  if (state is REP_WAIT or MRA_REP_RCVD)
 *		set new timer, using service timeout for the first timeout
 *    decr ref cnt, release state mutex
 *
 * 4. INCOMING RTU
 *
 *	Acquire hca state table READER lock
 *	Do lookup in active hca state tree by local com id
 *	Release hca state table READER lock
 *
 *	If lookup does not exist
 *		return
 *
 *	 if look up exists
 *		 incr statep->ref_cnt holding state mutex
 *
 *	acquire statep mutex
 *	if (state == REP_SENT or MRA REP RCVD))
 *	  change state to ESTABLISHED
 *	  release statep mutex
 *	  cancel timer
 *
 *	  Change QP state
 *
 *	  acquire the statep mutex
 *	decrement the ref count
 *	release statep mutex
 *
 * 5. INCOMING REJ
 *
 *	Acquire hca state table READER lock
 *	Do lookup in active hca state tree by local com id
 *	Release hca state table READER lock
 *
 *	If lookup does not exist
 *		return
 *
 *	if look up exists
 *		 incr statep->ref_cnt holding state mutex
 *
 *	if (state == REQ RCVD or REP RCVD MRA_SENT or MRA_REP_SNET)
 *	  set statep->delete = true
 *	  decrement the ref_cnt
 *	  release statep mutex;
 *
 *    else if (state == REQ_SENT or REP SENT or MRA REP Rcvd)
 *	 state = IBCM_STATE_DELETE
 *	 Cancel running timers
 *	 decrement the ref_cnt
 *	 release state mutex
 *	 Call the client QP handler
 *	 delete the state data
 *
 * 6. INCOMING DREQ
 *
 *	Acquire hca state table READER lock
 *	Do lookup in active hca state tree by local com id
 *	Release hca state table READER lock
 *
 *	If lookup does not exist
 *		return
 *
 *	if look up exists
 *		 incr statep->ref_cnt holding state mutex
 *
 *	acquire state mutex
 *	if (state is ESTABLISHED/DREQ SENT/TIMEWAIT)
 *	  if state is ESTABLISHED/DREQ SENT,
 *		change state to DREQ RECVD
 *		start timers
 *
 *    send DREP reply
 *    decr ref_cnt
 *    release state mutex
 *
 * 7.  Incoming DREP
 *
 *	Acquire hca state table READER lock
 *	Do lookup in active hca state tree by local com id
 *	Release hca state table READER lock
 *
 *	If lookup does not exist
 *		return
 *
 *	if look up exists
 *		 incr statep->ref_cnt holding state mutex
 *
 *	acquire state mutex
 *	if state is DREQ_SENT
 *	  change state to DREP_RCVD
 *	  cancel timer
 *	  change state to TIMEWAIT
 *	  set timewait timer
 *    decr ref_cnt
 *    release state mutex
 *
 * 8. Timeout handler
 *
 *  (for states REQ SENT/REP SENT/REJ SENT/DREQ SENT/DREP SENT/TIMEWAIT)
 *
 *	 acquire the statep mutex
 *
 *	 if (set state != stored_state)
 *	    The thread that changed the state is responsible for any cleanup
 *	    decrement ref cnt
 *	    release statep mutex
 *	    return
 *	 else if (statep's state == REJ SENT)
 *		change state to DELETE
 *		decrement ref cnt
 *		release statep mutex
 *		delete statep
 *		return
 *	 else if (state == TIME WAIT)
 *		do the time wait state processing
 *		decrement ref cnt
 *		change state to DELETE
 *		release statep mutex
 *		delete statep, and also QP
 *	 else if (remaining retry cnt > 0)
 *		resend the mad
 *		decrement ref cnt
 *		release statep mutex
 *	 else if (state == rep sent or req sent or mra rep rcvd or rep wait)
 *		(retry counter expired)
 *		change state to REJ SENT (No one shall delete in REJ SENT)
 *		decrement the ref_cnt
 *		release the statep mutex
 *		Post REJ MAD
 *		cv_signal anyone blocking
 *		Invoke client handler
 *	 else if state == DREQ_SENT
 *		change state to TIME WAIT
 *		decrement the ref cnt
 *		set a timer for time wait time
 *		release the statep mutex
 *
 *
 * SIDR processing
 *
 * 9. INCOMING SIDR_REQ MAD
 *
 *    Figure out LID/GID
 *    Do lookup in SIDR LIST based on LID, GID, grh_exists and req_id
 *    increment ud_statep->ud_ref_cnt
 *
 *    If (new lookup)
 *
 *	  validate service id, and the create new statep,
 *	  initialize key fields
 *	  do a lookup based on service id
 *	  if service_id_lookup returns exists
 *		set sidr_status to QPN_VALID
 *	  else
 *		set sidr_status to SID_INVALID
 *	  post SIDR_REP mad
 *	  decr ud_statep->ud_ref_cnt, release ud_state_mutex
 *
 *    else if (existing lookup)
 *
 *	  if (ud_statep->ud_state is SIDR_REP_SENT)
 *		resend the mad
 *
 *	  decr ud_statep->ud_ref_cnt, release ud_state_mutex
 *
 *
 * 10. INCOMING SIDR_REP MAD
 *
 *    Figure out LID/GID
 *    Do lookup in SIDR LIST based on LID, GID, grh_exists and req_id
 *    increment ud_statep->ud_ref_cnt
 *
 *    if look up doesn't exists
 *	  return
 *
 *    if (state == SIDR_REQ_SENT)
 *	  first, change state to SIDR_REP_RCVD
 *	  release statep lock
 *	  cancel timers
 *	  cv_signal anyone blocking
 *	  release the statep lock
 *	  extract return args
 *	  destroy the statep
 *
 * 11. Timeout handler
 *
 *  (for states SIDR_REQ_SENT/SIDR_REP_SENT)
 *
 *	 acquire the statep mutex
 *
 *	 if (statep's state == SIDR_REP_SENT SENT)
 *		change state to DELETE
 *		decrement ref cnt
 *		release statep mutex
 *		delete statep
 *		return
 *	 else if (remaining retry cnt > 0 and state is SIDR_REQ_SENT)
 *		resend the mad
 *		decrement ref cnt
 *		release statep mutex
 *	 else if (state == SIDR_REQ_SENT)
 *		(retry counter expired)
 *		change state to DELETE
 *		decrement the ref_cnt
 *		the statep mutex
 *		cv_signal anyone blocking
 *		Invoke client handler
 *		delete statep
 */

/* Function prototypes */
static void		ibcm_set_primary_adds_vect(ibcm_state_data_t *,
			    ibt_adds_vect_t *, ibcm_req_msg_t *);
static void		ibcm_set_alt_adds_vect(ibcm_state_data_t *,
			    ibt_adds_vect_t *, ibcm_req_msg_t *);
static ibt_status_t	ibcm_set_primary_cep_path(ibcm_state_data_t *,
			    ibt_cep_path_t *, ibcm_req_msg_t *);
static ibt_status_t	ibcm_set_alt_cep_path(ibcm_state_data_t *,
			    ibt_cep_path_t *, ibcm_req_msg_t *);
static ibt_status_t	ibcm_invoke_qp_modify(ibcm_state_data_t *,
			    ibcm_req_msg_t *, ibcm_rep_msg_t *);
static ibt_status_t	ibcm_invoke_rtu_qp_modify(ibcm_state_data_t *,
			    ib_time_t, ibcm_rep_msg_t *);
static ibcm_status_t	ibcm_sidr_req_ud_handler(ibcm_ud_state_data_t *,
			    ibcm_sidr_req_msg_t *, ibcm_mad_addr_t *,
			    ibt_sidr_status_t *);
static void		ibcm_sidr_rep_ud_handler(ibcm_ud_state_data_t *,
			    ibcm_sidr_rep_msg_t *);
static void		ibcm_handler_conn_fail(ibcm_state_data_t *,
			    uint8_t cf_code, uint8_t cf_msg,
			    ibt_cm_reason_t rej_reason, uint8_t *,
			    ibt_priv_data_len_t);
static void		ibcm_build_n_post_rej_mad(uint8_t *input_madp,
			    ib_com_id_t, ibcm_mad_addr_t *, int, uint16_t);
static void		ibcm_post_drep_mad(ibcm_state_data_t *);

static ibcm_status_t	ibcm_verify_req_gids_and_svcid(
			    ibcm_state_data_t *statep,
			    ibcm_req_msg_t *cm_req_msgp);

static void		ibcm_timeout_client_cb(ibcm_state_data_t *statep);
static void		ibcm_ud_timeout_client_cb(
			    ibcm_ud_state_data_t *ud_statep);

static void		ibcm_process_dreq_timeout(ibcm_state_data_t *statep);

static void		ibcm_fill_adds_from_lap(ibt_adds_vect_t *adds,
			    ibcm_lap_msg_t *lap_msg, ibcm_mode_t mode);

static void		ibcm_post_stored_apr_mad(ibcm_state_data_t *statep,
			    uint8_t *input_madp);

static ibcm_status_t	ibcm_set_qp_from_apr(ibcm_state_data_t *statep,
			    ibcm_lap_msg_t *lap_msg);

static boolean_t	ibcm_compare_prim_alt_paths(ibt_adds_vect_t *prim,
			    ibt_adds_vect_t *alt);

static void		ibcm_process_get_classport_info(ibcm_hca_info_t *hcap,
			    uint8_t *input_madp, ibcm_mad_addr_t *cm_mad_addr);

static void		ibcm_decode_classport_info(ibcm_hca_info_t *hcap,
			    uint8_t *input_madp, ibcm_mad_addr_t *cm_mad_addr);

static void		ibcm_post_rej_ver_mismatch(uint8_t *input_madp,
			    ibcm_mad_addr_t *cm_mad_addr);

static void		ibcm_init_clp_to_mad(ibcm_classportinfo_msg_t *clp,
			    ibt_redirect_info_t *rinfo);

static void		ibcm_init_clp_from_mad(ibcm_classportinfo_msg_t *clp,
			    ibt_redirect_info_t *rinfo);

static void		ibcm_copy_addl_rej(ibcm_state_data_t *statep,
			    ibcm_rej_msg_t *rej_msgp,
			    ibt_cm_conn_failed_t *failed);

static void		ibcm_return_open_data(ibcm_state_data_t *statep,
			    ibcm_rep_msg_t *rep_msgp,
			    ibt_cm_reason_t reject_reason);

/* limit the number of taskq threads to handle received MADs. */
int ibcm_recv_tasks = 0;
int ibcm_max_recv_tasks = 24;
int ibcm_recv_timeouts = 0;

/*
 * Tunable MAX MRA Service Timeout value in MicroSECONDS.
 *	0 - Tunable parameter not used.
 *
 *	Ex:   60000000 - Max MRA Service Delay is 60 Seconds.
 */
clock_t ibcm_mra_service_timeout_max = 0;

#ifdef	DEBUG

static void			print_modify_qp(char *prefix,
				    ibt_qp_hdl_t ibt_qp,
				    ibt_cep_modify_flags_t flags,
				    ibt_qp_info_t *qp_attr);
#endif

/*	Warlock annotations */

_NOTE(READ_ONLY_DATA(ibt_arej_info_u))

/*
 * ibcm_process_incoming_mad:
 *	The CM callback that is invoked by IBMF, when a valid CM MAD arrives
 *	on any of the registered ibmf handles by CM.
 *
 *	It is assumed that the incoming MAD (except for incoming REQ) belongs
 *	to a connection on the HCA, on which the MAD is received.
 *	The IBMF callback arg specifies ibcm_hca_info_t
 *
 * NOTE: IBMF always invokes ibcm_recv_cb() in a taskq. CM does some memory
 * allocations and invoke ibcm_sm_funcs_tbl[i]() in the same taskq.
 *
 * INPUTS:
 *	ibmf_handle	- IBMF Handle
 *	args		- from IBMF. Is a ptr to ibcm_hca_info_t
 *	status		- Callback status. Is mostly IBMF_SUCCESS
 *	madbuf		- IBMF allocated MAD buffer (CM should free it)
 *	madaddr		- IBMF MAD's address
 *	grhvalid	- If GRH is valid or not
 *
 * RETURN VALUES: NONE
 */
void
ibcm_process_incoming_mad(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args)
{
	uint8_t			method;		/* Method type in MAD hdr */
	ib_mad_hdr_t		*in_mad_hdr;	/* Incoming MAD's header */
	ibcm_hca_info_t		*hcap;		/* pointer to HCA entry */
	ibcm_port_info_t	*portp;
	ibcm_mad_addr_t		*cm_mad_addr;	/* MAD address information */
	ibcm_event_type_t	attr_id;	/* Attribute ID in MAD hdr */
	ibcm_mad_addr_t		loc_mad_addr;	/* MAD address information */
	ibcm_qp_list_t		*cm_qp_entry;
	int			ibmf_status;


	/* Noticed that IBMF always calls with IBMF_SUCCESS, but still check */
	if (msgp->im_msg_status != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_incoming_mad: "
		    "bad status %x", msgp->im_msg_status);
		/* IBMF allocates Input MAD, so free it here */
		if ((ibmf_status = ibmf_free_msg(ibmf_handle, &msgp)) !=
		    IBMF_SUCCESS)
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_incoming_mad: "
			    "ibmf_free_msg failed %d", ibmf_status);
		return;
	}

	/* Get the HCA entry pointer */
	cm_qp_entry = (ibcm_qp_list_t *)args;

	IBTF_DPRINTF_L5(cmlog, "ibcm_process_incoming_mad: ibmf_hdl %p "
	    "msg %p args %p", ibmf_handle, msgp, args);

#ifdef	DEBUG
	if (ibcm_test_mode > 1)
		ibcm_query_qp(ibmf_handle, cm_qp_entry->qp_cm);
#endif

	portp = cm_qp_entry->qp_port;
	hcap = portp->port_hcap;

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_incoming_mad: CM MAD on "
	    "port %d", portp->port_num);

	/* Increment hca ref cnt, if HCA is in attached state, else fail */
	if (ibcm_inc_hca_acc_cnt(hcap) != IBCM_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_incoming_mad: "
		    "hca not in attach state");
		/* IBMF allocates Input MAD, and ibcm free's it */
		if ((ibmf_status = ibmf_free_msg(ibmf_handle, &msgp)) !=
		    IBMF_SUCCESS)
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_incoming_mad: "
			    "ibmf_free_msg failed %d", ibmf_status);
		return;
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*cm_mad_addr))

	/* allocate memory for internal MAD address buffer */
	cm_mad_addr = &loc_mad_addr;
	bzero(cm_mad_addr, sizeof (ibcm_mad_addr_t));

	cm_mad_addr->port_num = portp->port_num;

	/* initialize cm_mad_addr field(s) */
	in_mad_hdr = msgp->im_msgbufs_recv.im_bufs_mad_hdr;

	if (in_mad_hdr->MgmtClass != MAD_MGMT_CLASS_COMM_MGT) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_incoming_mad: "
		    "bad mgmt class %x", in_mad_hdr->MgmtClass);
		if ((ibmf_status = ibmf_free_msg(ibmf_handle, &msgp)) !=
		    IBMF_SUCCESS)
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_incoming_mad: "
			    "ibmf_free_msg failed %d", ibmf_status);
		ibcm_dec_hca_acc_cnt(hcap);
		return;
	}

	cm_mad_addr->rcvd_addr = msgp->im_local_addr;
	if (msgp->im_msg_flags & IBMF_MSG_FLAGS_GLOBAL_ADDRESS) {
		cm_mad_addr->grh_hdr = msgp->im_global_addr;
		cm_mad_addr->grh_exists = B_TRUE;
		IBTF_DPRINTF_L3(cmlog, "ibcm_process_incoming_mad: "
		    "CM recv GID GUID %llX sender GID GUID %llX",
		    msgp->im_global_addr.ig_recver_gid.gid_guid,
		    msgp->im_global_addr.ig_sender_gid.gid_guid);
	}

	/* Save IBMF handle and ibmf qp related information */
	cm_mad_addr->ibmf_hdl = ibmf_handle;
	cm_mad_addr->cm_qp_entry = cm_qp_entry;

	/* IBMF does not initialize ia_p_key for non-QP1's */
	if (cm_qp_entry->qp_cm != IBMF_QP_HANDLE_DEFAULT)
		cm_mad_addr->rcvd_addr.ia_p_key = cm_qp_entry->qp_pkey;

	if (cm_mad_addr->rcvd_addr.ia_p_key & 0x8000)
		IBTF_DPRINTF_L5(cmlog, "ibcm_process_incoming_mad: PKEY %x",
		    cm_mad_addr->rcvd_addr.ia_p_key);
	else
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_incoming_mad: CM MAD "
		    "arrived from limited PKEY %x",
		    cm_mad_addr->rcvd_addr.ia_p_key);

	/* Retrieve the method and Attr-Id from generic mad header */
	method = in_mad_hdr->R_Method;
	attr_id = b2h16(in_mad_hdr->AttributeID);

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_incoming_mad: "
	    "Method %x Attribute %x", method, attr_id);

	if (in_mad_hdr->ClassVersion != IBCM_MAD_CLASS_VERSION) {

		IBTF_DPRINTF_L2(cmlog, "ibcm_process_incoming_mad: "
		    "unsupported ibcm class version %x",
		    in_mad_hdr->ClassVersion);

		if (attr_id == (IBCM_INCOMING_REQ + IBCM_ATTR_BASE_ID))
			ibcm_post_rej_ver_mismatch(
			    (uint8_t *)IBCM_IN_HDRP(msgp), cm_mad_addr);

		if ((ibmf_status = ibmf_free_msg(ibmf_handle, &msgp)) !=
		    IBMF_SUCCESS)
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_incoming_mad: "
			    "ibmf_free_msg failed %d", ibmf_status);
		ibcm_dec_hca_acc_cnt(hcap);
		return;
	}

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_incoming_mad: "
	    "Transaction Id 0x%llX", b2h64(in_mad_hdr->TransactionID));

#ifdef	DEBUG
	ibcm_decode_tranid(b2h64(in_mad_hdr->TransactionID), NULL);
#endif

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*cm_mad_addr))

	/*
	 * The following are valid combination of Method type
	 * and attribute id in the received MAD :-
	 *	o ClassPortInfo with Get method
	 *	o CM messages with Send method
	 */
	if ((attr_id == MAD_ATTR_ID_CLASSPORTINFO) &&
	    ((method == MAD_METHOD_GET) ||
	    (method == MAD_METHOD_GET_RESPONSE))) {
		if (method == MAD_METHOD_GET)
			ibcm_process_get_classport_info(hcap,
			    (uint8_t *)IBCM_IN_HDRP(msgp), cm_mad_addr);
		else if (method == MAD_METHOD_GET_RESPONSE)
			ibcm_decode_classport_info(hcap,
			    (uint8_t *)IBCM_IN_HDRP(msgp), cm_mad_addr);
	} else if ((attr_id >= IBCM_ATTR_BASE_ID) &&
	    (attr_id < (IBCM_ATTR_BASE_ID + IBCM_MAX_EVENTS)) &&
	    (method == MAD_METHOD_SEND)) {

		attr_id -= IBCM_ATTR_BASE_ID;	/* figure out CM message id */

		ASSERT(msgp->im_msgbufs_recv.im_bufs_mad_hdr != NULL);

		/* Call the CM process connection state function */
		ibcm_sm_funcs_tbl[attr_id](hcap,
		    (uint8_t *)IBCM_IN_HDRP(msgp), cm_mad_addr);
	} else {
		/*
		 * Any other combination of method and attribute are invalid,
		 * hence drop the MAD
		 */
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_incoming_mad: "
		    "unknown Method %x or Attribute %x", method, attr_id);
	}

	/* decrement the hcap access reference count */
	ibcm_dec_hca_acc_cnt(hcap);

	/* ASSERT(NO_LOCKS_HELD); */

	/* free up ibmf msgp  */
	if ((ibmf_status = ibmf_free_msg(ibmf_handle, &msgp)) != IBMF_SUCCESS)
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_incoming_mad: "
		    "ibmf_free_msg failed %d", ibmf_status);
}

/*
 * Structure to carry the arguments from ibcm_recv_cb() to
 * ibcm_recv_incoming_mad() via taskq_dispatch
 */
typedef struct ibcm_taskq_args_s {
	ibmf_handle_t	tq_ibmf_handle;
	ibmf_msg_t	*tq_ibmf_msgp;
	void		*tq_args;
} ibcm_taskq_args_t;

#define	IBCM_RECV_MAX	128
ibcm_taskq_args_t ibcm_recv_array[IBCM_RECV_MAX + 1];
int ibcm_get, ibcm_put;
int ibcm_recv_total;
int ibcm_recv_queued;

_NOTE(READ_ONLY_DATA(ibcm_taskq_args_t))

static int
ibcm_recv_dequeue(ibmf_handle_t *ibmf_handlep, ibmf_msg_t **msgpp, void **argsp)
{
	ibcm_taskq_args_t *tq;

	if (ibcm_put == ibcm_get)
		return (0);

	if (++ibcm_get >= IBCM_RECV_MAX)
		ibcm_get = 0;
	tq = ibcm_recv_array + ibcm_get;
	*ibmf_handlep = tq->tq_ibmf_handle;
	*msgpp = tq->tq_ibmf_msgp;
	*argsp = tq->tq_args;
	return (1);
}

static int
ibcm_recv_enqueue(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp, void *args)
{
	int next;
	ibcm_taskq_args_t *tq;

	ASSERT(MUTEX_HELD(&ibcm_recv_mutex));
	next = ibcm_put + 1;
	if (next >= IBCM_RECV_MAX)
		next = 0;
	if (next != ibcm_get) {
		ibcm_recv_queued++;
		ibcm_put = next;
		tq = ibcm_recv_array + next;
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*tq))
		tq->tq_ibmf_handle = ibmf_handle;
		tq->tq_ibmf_msgp = msgp;
		tq->tq_args = args;
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*tq))
		return (1);
	} else {
		return (0);
	}
}

void
ibcm_drop_msg(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp)
{
	int ibmf_status;

	IBTF_DPRINTF_L2(cmlog, "ibcm_drop_msg: discarding MAD");

	if ((ibmf_status = ibmf_free_msg(ibmf_handle, &msgp)) != IBMF_SUCCESS)
		IBTF_DPRINTF_L2(cmlog, "ibcm_drop_msg: "
		    "ibmf_free_msg failed %d", ibmf_status);
}

/*
 * Processing done in taskq thread.
 *
 * Calls ibcm_process_incoming_mad with all function arguments extracted
 * from args.  Afterwards, check for queued requests.
 */
static void
ibcm_recv_task(void *args)
{
	ibcm_taskq_args_t *taskq_args;
	ibmf_handle_t ibmf_handle;
	ibmf_msg_t *msgp;

	taskq_args = (ibcm_taskq_args_t *)args;

	IBTF_DPRINTF_L4(cmlog, "ibcm_recv_task: Processing incoming MAD"
	    " via taskq");

	ibcm_process_incoming_mad(taskq_args->tq_ibmf_handle,
	    taskq_args->tq_ibmf_msgp, taskq_args->tq_args);

	kmem_free(taskq_args, sizeof (ibcm_taskq_args_t));

	/* process queued entries before giving up this thread */
	mutex_enter(&ibcm_recv_mutex);
	while (ibcm_recv_dequeue(&ibmf_handle, &msgp, &args)) {
		mutex_exit(&ibcm_recv_mutex);
		ibcm_process_incoming_mad(ibmf_handle, msgp, args);
		mutex_enter(&ibcm_recv_mutex);
	}
	--ibcm_recv_tasks;
	mutex_exit(&ibcm_recv_mutex);
}

static void
ibcm_recv_timeout_cb(void *args)
{
	ibcm_taskq_args_t *tq = (ibcm_taskq_args_t *)args;
	int rv = 1;

	mutex_enter(&ibcm_recv_mutex);
	ibcm_recv_timeouts--;
	if (ibcm_recv_tasks == 0) {
		ibcm_recv_tasks++;
		mutex_exit(&ibcm_recv_mutex);
		if (taskq_dispatch(ibcm_taskq, ibcm_recv_task, tq,
		    TQ_NOQUEUE | TQ_NOSLEEP) == TASKQID_INVALID) {
			mutex_enter(&ibcm_recv_mutex);
			if (--ibcm_recv_tasks == 0) {
				(void) timeout(ibcm_recv_timeout_cb, tq, 1);
				ibcm_recv_timeouts++;
			} else {
				rv = ibcm_recv_enqueue(tq->tq_ibmf_handle,
				    tq->tq_ibmf_msgp, tq->tq_args);
				kmem_free(tq, sizeof (*tq));
			}
			mutex_exit(&ibcm_recv_mutex);
		}
	} else {
		/*
		 * one or more taskq threads are running now
		 * so just try to enqueue this one.
		 */
		rv = ibcm_recv_enqueue(tq->tq_ibmf_handle,
		    tq->tq_ibmf_msgp, tq->tq_args);
		kmem_free(tq, sizeof (*tq));
		mutex_exit(&ibcm_recv_mutex);
	}
	if (rv == 0)
		ibcm_drop_msg(tq->tq_ibmf_handle, tq->tq_ibmf_msgp);
}

/*
 * Dispatch to taskq if we're not using many, else just queue it
 * and have the taskq thread pick it up.  Return 0 if we're dropping it.
 */
static int
ibcm_recv_add_one(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp, void *args)
{
	int rv;
	ibcm_taskq_args_t *tq;

	mutex_enter(&ibcm_recv_mutex);
	ibcm_recv_total++;
	if (ibcm_recv_tasks >= ibcm_max_recv_tasks) { /* just queue this one */
		rv = ibcm_recv_enqueue(ibmf_handle, msgp, args);
		mutex_exit(&ibcm_recv_mutex);
		return (rv);
	} else {
		ibcm_recv_tasks++; /* dispatch this one to a taskq thread */
		mutex_exit(&ibcm_recv_mutex);
		tq = kmem_alloc(sizeof (*tq), KM_NOSLEEP);
		if (tq == NULL) {
			mutex_enter(&ibcm_recv_mutex);
			if (--ibcm_recv_tasks > 0)
				rv = ibcm_recv_enqueue(ibmf_handle, msgp, args);
			else	/* don't enqueue if no threads are running */
				rv = 0;
			mutex_exit(&ibcm_recv_mutex);
			return (rv);
		}
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*tq))
		tq->tq_ibmf_handle = ibmf_handle;
		tq->tq_ibmf_msgp = msgp;
		tq->tq_args = args;
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*tq))
		if (taskq_dispatch(ibcm_taskq, ibcm_recv_task, tq,
		    TQ_NOQUEUE | TQ_NOSLEEP) == TASKQID_INVALID) {
			/* dispatch failed */
			mutex_enter(&ibcm_recv_mutex);
			if (--ibcm_recv_tasks == 0) {
				/* try the dispatch again, after a tick */
				(void) timeout(ibcm_recv_timeout_cb, tq, 1);
				ibcm_recv_timeouts++;
				rv = 1;	/* indicate success */
			} else {
				rv = ibcm_recv_enqueue(ibmf_handle, msgp, args);
				kmem_free(tq, sizeof (*tq));
			}
			mutex_exit(&ibcm_recv_mutex);
			return (rv);
		} else {
			return (1);
		}
	}
}

/*
 * ibcm_recv_cb:
 *	The CM callback that is invoked by IBMF, when a valid CM MAD arrives
 *	on any of the registered ibmf handles by CM.
 *
 * INPUTS:
 *	ibmf_handle	- IBMF Handle
 *	msgp		- IBMF msg containing the MAD (allocated by IBMF)
 *	args		- Ptr to ibcm_hca_info_t
 *
 * RETURN VALUES: NONE
 */
void
ibcm_recv_cb(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp, void *args)
{
	if (ibcm_recv_add_one(ibmf_handle, msgp, args) == 0)
		ibcm_drop_msg(ibmf_handle, msgp);
}

/*
 * ibcm_process_req_msg:
 *	PASSIVE SIDE CM
 *	Called from ibcm_process_incoming_mad on reception of a REQ message
 *
 * Description:
 *	If it a new REQ (not duplicate)
 *		creates a new state structure in passive connection mode
 *		populate state structure fields
 *		inserts state structure in hca active and passive trees
 *		validates service id
 *		validates primary and alternate lid/gid in REQ,
 *		calls QP state transition function
 *		generates REP/REJ response
 *		stores the response MAD in state structure for future re-sends
 *		initializes timers as required
 *	If a duplicate REQ, action depends upon current state in the state
 *	structure
 *
 * INPUTS:
 *	hcap		- HCA entry ptr
 *	input_madp	- CM MAD that is input to this function
 *	cm_mad_addr	- Address information for the MAD
 *
 * RETURN VALUE:
 *	NONE
 */
void
ibcm_process_req_msg(ibcm_hca_info_t *hcap, uint8_t *input_madp,
    ibcm_mad_addr_t *cm_mad_addr)
{
	ibt_priv_data_len_t	arej_info_len = 0;
	ib_qpn_t		remote_qpn;
	ib_guid_t		remote_hca_guid;
	ib_com_id_t		remote_comid;
	ib_com_id_t		local_comid;
	ibcm_status_t		state_lookup_status;
	ibcm_status_t		comid_lookup_status;
	ibcm_status_t		response;
	ibcm_req_msg_t		*req_msgp =
	    (ibcm_req_msg_t *)&input_madp[IBCM_MAD_HDR_SIZE];
	ibt_cm_reason_t		reject_reason = IBT_CM_SUCCESS;
	ibcm_state_data_t	*statep;
	ibcm_state_data_t	*stale_statep = NULL;
	ibcm_status_t		svc_gid_check;
	uint32_t		psn24_timeout5_retry3;
	ibt_tran_srv_t		trans;

	IBTF_DPRINTF_L5(cmlog, "ibcm_process_req_msg(%p, %p, %p)",
	    hcap, input_madp, cm_mad_addr);

	/*
	 * Lookup for an existing state structure or create a new state struct
	 * If there is no entry, the lookup function also allocates a new
	 * state structure and inserts in the table, initializes remote qpn
	 * and hca guid from REQ
	 */
	remote_hca_guid = b2h64(req_msgp->req_local_ca_guid);
	remote_qpn = b2h32(req_msgp->req_local_qpn_plus) >> 8;
	remote_comid = b2h32(req_msgp->req_local_comm_id);

	IBCM_DUMP_RAW_MSG((uchar_t *)input_madp);

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_req_msg: remote_comid = %x"
	    " remote_qpn = %x", remote_comid, remote_qpn);

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_req_msg: remote_hcaguid = %llX",
	    remote_hca_guid);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*statep))

new_req:
	/* allocate the local_comid before proceeding */
	if (ibcm_alloc_comid(hcap, &local_comid) != IBCM_SUCCESS) {
		ibcm_build_n_post_rej_mad(input_madp,
		    b2h32(req_msgp->req_local_comm_id), cm_mad_addr,
		    IBT_CM_FAILURE_REQ, IBT_CM_NO_RESC);
		return;
	}

	/* allocate ibcm_state_data_t before grabbing the WRITER lock */
	statep = kmem_zalloc(sizeof (*statep), KM_SLEEP);

	rw_enter(&hcap->hca_state_rwlock, RW_WRITER);

	/* NOTE that only a writer lock is held here */

	state_lookup_status = ibcm_lookup_msg(IBCM_INCOMING_REQ,
	    local_comid, remote_qpn, remote_hca_guid, hcap, &statep);

	if (state_lookup_status == IBCM_LOOKUP_NEW) {
		/* seeing the REQ request for the first time */

		mutex_enter(&statep->state_mutex);
		/* Release the state table lock */
		rw_exit(&hcap->hca_state_rwlock);

		IBTF_DPRINTF_L4(cmlog, "ibcm_process_req_msg: New statep 0x%p"
		    " created", statep);

		psn24_timeout5_retry3 = b2h32(req_msgp->req_starting_psn_plus);

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*statep))

		/* if ibmf msg allocation fails, delete the statep */
		if (ibcm_alloc_out_msg(cm_mad_addr->ibmf_hdl,
		    &statep->stored_msg, MAD_METHOD_SEND) != IBT_SUCCESS) {

			IBCM_REF_CNT_DECR(statep);
			statep->state = IBCM_STATE_DELETE;
			mutex_exit(&statep->state_mutex);
			/* HCA res cnt decremented via ibcm_delete_state_data */
			ibcm_inc_hca_res_cnt(hcap);
			ibcm_delete_state_data(statep);
			return;
		}

		/* Allocate dreq_msg buf to be used during teardown. */
		if (ibcm_alloc_out_msg(cm_mad_addr->ibmf_hdl,
		    &statep->dreq_msg, MAD_METHOD_SEND) != IBT_SUCCESS) {

			IBCM_REF_CNT_DECR(statep);
			statep->state = IBCM_STATE_DELETE;
			mutex_exit(&statep->state_mutex);
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_req_msg: "
			    "statep 0x%p: Failed to allocate dreq_msg", statep);

			/* HCA res cnt decremented via ibcm_delete_state_data */
			ibcm_inc_hca_res_cnt(hcap);
			ibcm_delete_state_data(statep);
			return;
		}

		/* initialize some "statep" fields */
		statep->mode		= IBCM_PASSIVE_MODE;
		statep->hcap		= hcap;
		statep->remote_comid	= remote_comid;
		statep->svcid		= b2h64(req_msgp->req_svc_id);
		statep->local_qp_rnr_cnt =
		    req_msgp->req_mtu_plus & 0x7;

		/*
		 * get the remote_ack_delay, etc.
		 */
		statep->remote_ack_delay =
		    ibt_ib2usec(req_msgp->req_primary_localtime_plus >> 3);
		statep->cep_retry_cnt = psn24_timeout5_retry3 & 0x7;

		/*
		 * get the req_max_cm_retries
		 */
		statep->max_cm_retries = req_msgp->req_max_cm_retries_plus >> 4;
		statep->remaining_retry_cnt = statep->max_cm_retries;

		/* Approximate pkt life time for now */
		statep->pkt_life_time = statep->remote_ack_delay/2;

		/* Passive side timer is set to LocalCMRespTime in REQ */
		statep->timer_value =
		    ibt_ib2usec(psn24_timeout5_retry3 >> 3 & 0x1f);

		statep->starting_psn = psn24_timeout5_retry3 >> 8;

		IBTF_DPRINTF_L4(cmlog, "ibcm_process_req_msg: statep 0x%p "
		    "active cep timeout(usec) = %u",
		    statep, statep->remote_ack_delay);
		IBTF_DPRINTF_L4(cmlog, "ibcm_process_req_msg: "
		    "passive timer(usec) = %u", statep->timer_value);
		IBTF_DPRINTF_L4(cmlog, "ibcm_process_req_msg: "
		    "approx pkt lt(usec)= %u ", statep->pkt_life_time);
		IBTF_DPRINTF_L4(cmlog, "ibcm_process_req_msg: "
		    "max cm retries %u", statep->max_cm_retries);

		/* The reply ie., REP/REJ transaction id copied from REQ */
		IBCM_OUT_HDRP(statep->stored_msg)->TransactionID =
		    ((ib_mad_hdr_t *)(input_madp))->TransactionID;

		/*
		 * Initialize the stale clock. Any other REQ
		 * messages on this statep are considered as duplicate
		 * if they arrive within stale clock
		 * ibcm_adj_btime is used to offset for retry REQ's
		 * arriving  just after expected retry clock
		 */
		statep->stale_clock = gethrtime() +
		    (hrtime_t)(ibcm_adj_btime  * 1000000000) +
		    (hrtime_t)statep->remote_ack_delay *
		    (statep->max_cm_retries * (1000 / 2));

		mutex_exit(&statep->state_mutex);

		ibcm_insert_trace(statep, IBCM_TRACE_INCOMING_REQ);

		/* Increment the hca's resource count */
		ibcm_inc_hca_res_cnt(hcap);

		ibcm_build_reply_mad_addr(cm_mad_addr,
		    &statep->stored_reply_addr);

		if (statep->stored_reply_addr.cm_qp_entry == NULL) {

			IBTF_DPRINTF_L2(cmlog, "ibcm_process_req_msg: "
			    "statep 0x%p cm_qp_entry alloc failed", statep);

			/*
			 * Not much choice. CM MADs cannot go on QP1, not even
			 * REJ. Hence delete state data and go away silently.
			 * The remote will timeout after repeated attempts
			 */
			mutex_enter(&statep->state_mutex);
			IBCM_REF_CNT_DECR(statep);
			statep->state = IBCM_STATE_DELETE;
			mutex_exit(&statep->state_mutex);

			ibcm_delete_state_data(statep);
			return;
		}

		stale_statep = statep;
		rw_enter(&hcap->hca_state_rwlock, RW_WRITER);
		comid_lookup_status = ibcm_lookup_msg(IBCM_INCOMING_REQ_STALE,
		    remote_comid, 0, remote_hca_guid, hcap, &stale_statep);
		rw_exit(&hcap->hca_state_rwlock);

		if (comid_lookup_status == IBCM_LOOKUP_EXISTS) {

			IBTF_DPRINTF_L2(cmlog, "ibcm_process_req_msg: "
			    "dup comid %x stale_statep 0x%p statep 0x%p",
			    remote_comid, stale_statep, statep);

			ibcm_insert_trace(stale_statep,
			    IBCM_TRACE_STALE_DETECT);

			/* Send a REJ with duplicate com id */
			ibcm_post_rej_mad(statep, IBT_CM_DUP_COM_ID,
			    IBT_CM_FAILURE_REQ, NULL, 0);

			/*
			 * Don't free the ibmf msg, if stale_statep is not in
			 * ESTABLISHED state, because probability is very less.
			 * ibmf msg shall be deleted along with statep
			 */

			/*
			 * if stale_statep is in established state, process
			 * stale connection handling on stale_statep
			 */
			mutex_enter(&stale_statep->state_mutex);
			if (stale_statep->state == IBCM_STATE_ESTABLISHED) {

				stale_statep->state =
				    IBCM_STATE_TRANSIENT_DREQ_SENT;
				stale_statep->stale = B_TRUE;

				/* Cancel pending ibt_set_alt_path */
				ibcm_sync_lapr_idle(stale_statep);
				/* The above call releases the state mutex */

				if (stale_statep->dreq_msg == NULL)
					(void) ibcm_alloc_out_msg(stale_statep->
					    stored_reply_addr.ibmf_hdl,
					    &stale_statep->dreq_msg,
					    MAD_METHOD_SEND);

				/*
				 * Spec says, post DREQ MAD on the stale
				 * channel. This moves channel into timewait
				 */
				if (stale_statep->dreq_msg != NULL) {
					ibcm_post_dreq_mad(stale_statep);
					mutex_enter(&stale_statep->state_mutex);
				} else {
					mutex_enter(&stale_statep->state_mutex);
					/* Set it back to original state. */
					stale_statep->state =
					    IBCM_STATE_ESTABLISHED;
					cv_broadcast(
					    &stale_statep->block_mad_cv);
				}
			}

			IBCM_REF_CNT_DECR(stale_statep);
			mutex_exit(&stale_statep->state_mutex);

			mutex_enter(&statep->state_mutex);
			IBCM_REF_CNT_DECR(statep);
			mutex_exit(&statep->state_mutex);
			return;
		}

		/* If unknown service type, just post a REJ */
		trans = ((uint8_t *)&req_msgp->req_remote_eecn_plus)[3] >> 1 &
		    0x3;
		if ((trans != IBT_RC_SRV) && (trans != IBT_UC_SRV) &&
		    (trans != IBT_RD_SRV)) {

			IBTF_DPRINTF_L2(cmlog, "ibcm_process_req_msg: "
			    "statep 0x%p invalid transport type %x", statep,
			    trans);

			/* Send a REJ with invalid transport type */
			ibcm_post_rej_mad(statep, IBT_CM_INVALID_SRV_TYPE,
			    IBT_CM_FAILURE_REQ, NULL, 0);

			mutex_enter(&statep->state_mutex);
			IBCM_REF_CNT_DECR(statep);
			mutex_exit(&statep->state_mutex);
			return;
		}

		/* Validate the gids, lids and service id */
		svc_gid_check = ibcm_verify_req_gids_and_svcid(statep,
		    req_msgp);

		if (svc_gid_check == IBCM_FAILURE) {

			IBTF_DPRINTF_L3(cmlog, "ibcm_process_req_msg: Either "
			    "gid or sid invalid for statep 0x%p", statep);
			mutex_enter(&statep->state_mutex);
			IBCM_REF_CNT_DECR(statep);
			mutex_exit(&statep->state_mutex);

			/* REJ posted from ibcm_verify_req_gids_and_svcid */
			return;
		}

		/* Call the QP state transition processing function */
		response = ibcm_cep_state_req(statep, req_msgp,
		    &reject_reason, &arej_info_len);

		/* If defer, return holding the statep ref cnt */
		if (response == IBCM_DEFER) {
			IBTF_DPRINTF_L4(cmlog, "ibcm_process_req_msg: "
			    "statep %0xp client returned DEFER response",
			    statep);
			return;
		}

		/* statep ref cnt decremented in the func below */
		ibcm_handle_cep_req_response(statep, response,
		    reject_reason, arej_info_len);

		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*statep))

		return;

	} else {
		rw_exit(&hcap->hca_state_rwlock);
		ibcm_free_comid(hcap, local_comid);
	}

	if (state_lookup_status == IBCM_LOOKUP_EXISTS) {
		hrtime_t	cur_time;

		mutex_enter(&statep->state_mutex);

		/*
		 * There is an existing state structure entry
		 * with the same active comid
		 * Resending REP MAD is necessary only for REP/REJ/MRA Sent
		 * states
		 * Any other state implies the active has already received
		 * the REP/REJ response, and this REQ is an old MAD popping
		 * out of the fabric, hence no resend is required
		 */
		cur_time = gethrtime();

		if ((remote_comid == statep->remote_comid) &&
		    (IBCM_OUT_HDRP(statep->stored_msg)->TransactionID ==
		    ((ib_mad_hdr_t *)(input_madp))->TransactionID) &&
		    (cur_time <= statep->stale_clock)) {

			ibcm_insert_trace(statep, IBCM_TRACE_INCOMING_REQ);

			if (statep->state == IBCM_STATE_REP_SENT)
				ibcm_resend_rep_mad(statep);
			else if (statep->state == IBCM_STATE_REJ_SENT)
				ibcm_resend_rej_mad(statep);
			else if (statep->state == IBCM_STATE_MRA_SENT)
				ibcm_resend_mra_mad(statep);

			/* decrementing ref cnt and returning from below */

		} else if ((statep->state == IBCM_STATE_REJ_SENT) &&
		    remote_comid != statep->remote_comid) {
			timeout_id_t		timer_val;

			IBTF_DPRINTF_L2(cmlog, "ibcm_process_req_msg: "
			    "statep 0x%p being retired, REMOTE_QPN %x",
			    statep, remote_qpn);
			/*
			 * OK, this is reuse of the QPN on the active side
			 * that was not connected last time.  This REQ is
			 * considered NEW.  We delete the statep here,
			 * then start over from the top.
			 */
			statep->state = IBCM_STATE_DELETE;
			timer_val = statep->timerid;
			statep->timerid = 0;
			mutex_exit(&statep->state_mutex);
			if (timer_val)
				(void) untimeout(timer_val);
			IBCM_REF_CNT_DECR(statep);
			ibcm_delete_state_data(statep);
			goto new_req;

		/*
		 * The statep is stale in the following cases :-
		 *  1) if incoming REQ's comid's doesn't match with what is
		 *	stored in statep
		 *  2) incoming REQ's local comid matches with statep's
		 *	remote comid, but the REQ is for a new connection.
		 *	This is verified that by comparing the current time
		 *	with stale clock in statep
		 */
		} else {
			/* This is a stale connection on passive side */

			ibcm_insert_trace(statep, IBCM_TRACE_STALE_DETECT);

			IBTF_DPRINTF_L2(cmlog, "ibcm_process_req_msg: "
			    "stale detected statep %p state %x",
			    statep, statep->state);

			IBTF_DPRINTF_L4(cmlog, "ibcm_process_req_msg: "
			    "cur_time 0x%llX stale_clock 0x%llX", cur_time,
			    statep->stale_clock);

			if (statep->state == IBCM_STATE_ESTABLISHED) {

				statep->state = IBCM_STATE_TRANSIENT_DREQ_SENT;
				statep->stale = B_TRUE;

				/* Cancel pending ibt_set_alt_path */
				ibcm_sync_lapr_idle(statep);
				/* The above call releases the state mutex */

				if (statep->dreq_msg == NULL)
					(void) ibcm_alloc_out_msg(
					    statep->stored_reply_addr.ibmf_hdl,
					    &statep->dreq_msg, MAD_METHOD_SEND);

				/*
				 * Spec says, post DREQ MAD on the stale
				 * channel. This moves channel into timewait
				 */
				if (statep->dreq_msg != NULL)
					ibcm_post_dreq_mad(statep);
				else {
					mutex_enter(&statep->state_mutex);
					statep->state = IBCM_STATE_ESTABLISHED;
					cv_broadcast(&statep->block_mad_cv);
					mutex_exit(&statep->state_mutex);
				}
			} else {
				/*
				 * If not in established state, the CM
				 * protocol would timeout and delete the
				 * statep that is stale, eventually
				 */
				mutex_exit(&statep->state_mutex);
			}

			/* Post a REJ MAD to the incoming REQ's sender */
			ibcm_build_n_post_rej_mad(input_madp,
			    b2h32(req_msgp->req_local_comm_id),
			    cm_mad_addr, IBT_CM_FAILURE_REQ, IBT_CM_CONN_STALE);

			mutex_enter(&statep->state_mutex);
		}
		IBCM_REF_CNT_DECR(statep); /* decrement the ref count */
		mutex_exit(&statep->state_mutex);
	}
}

/*
 * ibcm_handle_cep_req_response:
 *	Processes the response from ibcm_cep_state_req. Called holding a
 *	statep ref cnt. The statep ref cnt is decremented before returning.
 */
void
ibcm_handle_cep_req_response(ibcm_state_data_t *statep, ibcm_status_t response,
    ibt_cm_reason_t reject_reason, uint8_t arej_info_len)
{
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*statep))

	if (response == IBCM_SEND_REP)
		ibcm_post_rep_mad(statep);
	else {
		ASSERT(response == IBCM_SEND_REJ);
		IBTF_DPRINTF_L4(cmlog, "ibcm_handle_cep_req_response: statep %p"
		    " posting REJ reject_reason = %d", statep, reject_reason);

		ibcm_post_rej_mad(statep,
		    reject_reason, IBT_CM_FAILURE_REQ,
		    NULL, arej_info_len);
	}

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*statep))

	mutex_enter(&statep->state_mutex);
	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}


/*
 * ibcm_process_rep_msg:
 *	ACTIVE SIDE CM
 *	Called from ibcm_process_incoming_mad on reception of a REP message
 *
 * INPUTS:
 *	hcap		- HCA entry pointer
 *	input_madp	- CM MAD that is input to this function
 *	cm_mad_addr	- Address information for the MAD
 *
 * RETURN VALUE:	NONE
 */
void
ibcm_process_rep_msg(ibcm_hca_info_t *hcap, uint8_t *input_madp,
    ibcm_mad_addr_t *cm_mad_addr)
{
	ibt_priv_data_len_t	arej_info_len = 0;
	ib_com_id_t		local_comid;
	timeout_id_t		timer_val;
	ibcm_status_t		lookup_status;	/* state lookup status */
	ibcm_status_t		stale_lookup_status;
	ibcm_status_t		stale_comid_lookup_status;
	ibcm_status_t		response;
	ibcm_rep_msg_t		*rep_msgp;	/* Response REP mesg */
	ibt_cm_reason_t		reject_reason;
	ibcm_state_data_t	*statep = NULL;
	ibcm_state_data_t	*stale_qpn = NULL;
	ibcm_state_data_t	*stale_comid = NULL;
	ib_guid_t		remote_ca_guid;

	IBTF_DPRINTF_L3(cmlog, "ibcm_process_rep_msg:");

	/* Lookup for an existing state structure */
	rep_msgp = (ibcm_rep_msg_t *)(&input_madp[IBCM_MAD_HDR_SIZE]);

	IBCM_DUMP_RAW_MSG((uchar_t *)input_madp);

	IBTF_DPRINTF_L5(cmlog, "ibcm_process_rep_msg: active comid: %x",
	    rep_msgp->rep_remote_comm_id);

	local_comid = b2h32(rep_msgp->rep_remote_comm_id);

	/* lookup message holding a reader lock */
	rw_enter(&hcap->hca_state_rwlock, RW_READER);
	lookup_status = ibcm_lookup_msg(IBCM_INCOMING_REP, local_comid, 0, 0,
	    hcap, &statep);
	rw_exit(&hcap->hca_state_rwlock);

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_rep_msg: lkup status %x, "
	    "statep 0x%p active comid %x", lookup_status, statep, local_comid);

	if (lookup_status == IBCM_LOOKUP_FAIL) {
		ibcm_build_n_post_rej_mad(input_madp,
		    b2h32(rep_msgp->rep_local_comm_id), cm_mad_addr,
		    IBT_CM_FAILURE_REP, IBT_CM_INVALID_CID);

		return;
	}

	/* if transaction id is not as expected, drop the REP mad */
	if (IBCM_OUT_HDRP(statep->stored_msg)->TransactionID !=
	    ((ib_mad_hdr_t *)(input_madp))->TransactionID) {

		IBTF_DPRINTF_L3(cmlog, "ibcm_process_rep_msg: statep 0x%p, "
		    "An REP MAD with tid expected 0x%llX tid found 0x%llX ",
		    statep,
		    b2h64(IBCM_OUT_HDRP(statep->stored_msg)->TransactionID),
		    b2h64(((ib_mad_hdr_t *)(input_madp))->TransactionID));

		mutex_enter(&statep->state_mutex);
		IBCM_REF_CNT_DECR(statep);
		mutex_exit(&statep->state_mutex);
		return;
	}

	ibcm_insert_trace(statep, IBCM_TRACE_INCOMING_REP);

	/* grab mutex first */
	mutex_enter(&statep->state_mutex);

	/*
	 * There is a state structure entry with active comid
	 * First, handle the re-send cases
	 * The resend routines below release the state mutex
	 */
	if (statep->state == IBCM_STATE_ESTABLISHED ||
	    statep->state == IBCM_STATE_DREQ_SENT)
		ibcm_resend_rtu_mad(statep);
	else if (statep->state == IBCM_STATE_REJ_SENT)
		ibcm_resend_rej_mad(statep);
	else if (statep->state == IBCM_STATE_MRA_REP_SENT)
		ibcm_resend_mra_mad(statep);
	else if ((statep->state == IBCM_STATE_REQ_SENT) ||
	    (statep->state == IBCM_STATE_REP_WAIT)) {

		/* change state */
		statep->state = IBCM_STATE_REP_RCVD;
		statep->clnt_proceed = IBCM_BLOCK;
		statep->local_qp_rnr_cnt =
		    rep_msgp->rep_rnr_retry_cnt_plus >> 5;

		/* cancel the REQ timer */
		if (statep->timerid != 0) {
			timer_val = statep->timerid;
			statep->timerid = 0;
			mutex_exit(&statep->state_mutex);
			(void) untimeout(timer_val);
		} else {
			mutex_exit(&statep->state_mutex);
		}

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*statep))

		/* Initialize the remote destination QPN for further MADs */
		statep->stored_reply_addr.rcvd_addr.ia_remote_qno =
		    cm_mad_addr->rcvd_addr.ia_remote_qno;
		statep->remote_qpn = b2h32(rep_msgp->rep_local_qpn_plus) >> 8;
		statep->remote_comid = b2h32(rep_msgp->rep_local_comm_id);
		bcopy(rep_msgp->rep_local_ca_guid, &remote_ca_guid,
		    sizeof (ib_guid_t));
		statep->remote_hca_guid = b2h64(remote_ca_guid);

		IBTF_DPRINTF_L4(cmlog, "ibcm_process_rep_msg: statep 0x%p "
		    "passive cid = %x passive qpn = %x", statep,
		    statep->remote_comid, statep->remote_qpn);

		IBTF_DPRINTF_L4(cmlog, "ibcm_process_rep_msg: statep 0x%p "
		    "passive hcaguid = %llX", statep, statep->remote_hca_guid);

		stale_qpn = statep;
		stale_comid = statep;

		/* Handle stale connection detection on active side */
		rw_enter(&hcap->hca_state_rwlock, RW_WRITER);

		stale_lookup_status = ibcm_lookup_msg(IBCM_INCOMING_REP_STALE,
		    0, statep->remote_qpn, statep->remote_hca_guid, hcap,
		    &stale_qpn);

		stale_comid_lookup_status = ibcm_lookup_msg(
		    IBCM_INCOMING_REQ_STALE, statep->remote_comid, 0,
		    statep->remote_hca_guid, hcap, &stale_comid);

		rw_exit(&hcap->hca_state_rwlock);

		/*
		 * Check for other side reusing QPN that was attempted
		 * to be used, but somehow we sent a REJ.
		 */
		mutex_enter(&stale_qpn->state_mutex);
		if ((stale_lookup_status == IBCM_LOOKUP_EXISTS) &&
		    (stale_comid_lookup_status != IBCM_LOOKUP_EXISTS) &&
		    (stale_qpn->state == IBCM_STATE_REJ_SENT)) {

			timeout_id_t		timer_val;

			IBTF_DPRINTF_L3(cmlog, "ibcm_process_rep_msg: "
			    "statep 0x%p being retired, REMOTE_QPN %x",
			    stale_qpn, statep->remote_qpn);
			/*
			 * OK, this is reuse of the QPN on the active side
			 * that was not connected last time.  This REQ is
			 * considered NEW.  We delete the statep here,
			 * then start over from the top.
			 */
			stale_qpn->state = IBCM_STATE_DELETE;
			timer_val = stale_qpn->timerid;
			stale_qpn->timerid = 0;
			mutex_exit(&stale_qpn->state_mutex);
			if (timer_val)
				(void) untimeout(timer_val);
			IBCM_REF_CNT_DECR(stale_qpn);
			ibcm_delete_state_data(stale_qpn);
			stale_qpn = statep;
			rw_enter(&hcap->hca_state_rwlock, RW_WRITER);
			stale_lookup_status = ibcm_lookup_msg(
			    IBCM_INCOMING_REP_STALE, 0, statep->remote_qpn,
			    statep->remote_hca_guid, hcap, &stale_qpn);
			rw_exit(&hcap->hca_state_rwlock);
			/* OK to continue now */
		} else
			mutex_exit(&stale_qpn->state_mutex);

		/*
		 * lookup exists implies that there is already an entry with
		 * the remote qpn/comid and remote hca guid
		 */
		if ((stale_lookup_status == IBCM_LOOKUP_EXISTS) ||
		    (stale_comid_lookup_status == IBCM_LOOKUP_EXISTS)) {

			IBTF_DPRINTF_L2(cmlog, "ibcm_process_rep_msg: "
			    "statep 0x%p stale detected "
			    "qpn_lkup %d comid_lkup %d", statep,
			    stale_lookup_status, stale_comid_lookup_status);

			/* Disassociate statep and QP */
			IBCM_SET_CHAN_PRIVATE(statep->channel, NULL);

			if (stale_lookup_status == IBCM_LOOKUP_EXISTS)
				reject_reason = IBT_CM_CONN_STALE;
			else
				reject_reason = IBT_CM_DUP_COM_ID;

			ibcm_handler_conn_fail(statep,
			    IBT_CM_FAILURE_REJ_SENT, IBT_CM_FAILURE_REP,
			    reject_reason,
			    IBCM_REJ_PRIV(statep->stored_msg),
			    IBT_REJ_PRIV_DATA_SZ);

			/* Send a REJ with stale reason for statep */
			ibcm_post_rej_mad(statep, reject_reason,
			    IBT_CM_FAILURE_REP, NULL, 0);

			/* Now let's handle the logic for stale connections */
			/* If in established state, stale_statep is stale */
			if (stale_lookup_status == IBCM_LOOKUP_EXISTS) {

				IBTF_DPRINTF_L2(cmlog, "ibcm_process_rep_msg: "
				    "state_qpn 0x%p stale QPN detected "
				    "state %X", stale_qpn, stale_qpn->state);

				ibcm_insert_trace(stale_qpn,
				    IBCM_TRACE_STALE_DETECT);

				mutex_enter(&stale_qpn->state_mutex);
				if (stale_qpn->state ==
				    IBCM_STATE_ESTABLISHED) {
					/* change state to DREQ sent */
					stale_qpn->state =
					    IBCM_STATE_TRANSIENT_DREQ_SENT;
					stale_qpn->stale = B_TRUE;

					/* wait for/cancel pending LAP/APR */
					ibcm_sync_lapr_idle(stale_qpn);
					/* above call releases state mutex */

					if (stale_qpn->dreq_msg == NULL)
						(void) ibcm_alloc_out_msg(
						    stale_qpn->
						    stored_reply_addr.ibmf_hdl,
						    &stale_qpn->dreq_msg,
						    MAD_METHOD_SEND);

					if (stale_qpn->dreq_msg != NULL) {
						ibcm_post_dreq_mad(stale_qpn);
						mutex_enter(
						    &stale_qpn->state_mutex);
					} else {
						mutex_enter(
						    &stale_qpn->state_mutex);
						stale_qpn->state =
						    IBCM_STATE_ESTABLISHED;
						cv_broadcast(
						    &stale_qpn->block_mad_cv);
					}
				}
				IBCM_REF_CNT_DECR(stale_qpn);
				mutex_exit(&stale_qpn->state_mutex);
			}

			if (stale_comid_lookup_status == IBCM_LOOKUP_EXISTS) {

				IBTF_DPRINTF_L2(cmlog, "ibcm_process_rep_msg: "
				    "state_comid 0x%p stale COMID detected "
				    "state %X", stale_comid,
				    stale_comid->state);

				mutex_enter(&stale_comid->state_mutex);
				if (!((stale_lookup_status ==
				    IBCM_LOOKUP_EXISTS) &&
				    (stale_qpn == stale_comid)) &&
				    (stale_comid->state ==
				    IBCM_STATE_ESTABLISHED)) {

					ibcm_insert_trace(stale_comid,
					    IBCM_TRACE_STALE_DETECT);

					/* change state to DREQ sent */
					stale_comid->state =
					    IBCM_STATE_TRANSIENT_DREQ_SENT;
					stale_comid->stale = B_TRUE;

					/* wait for/cancel pending LAP/APR */
					ibcm_sync_lapr_idle(stale_comid);

					/* above call releases state mutex */

					if (stale_comid->dreq_msg == NULL)
						(void) ibcm_alloc_out_msg(
						    stale_comid->
						    stored_reply_addr.ibmf_hdl,
						    &stale_comid->dreq_msg,
						    MAD_METHOD_SEND);

					if (stale_comid->dreq_msg != NULL) {
						ibcm_post_dreq_mad(stale_comid);
						mutex_enter(
						    &stale_comid->state_mutex);
					} else {
						mutex_enter(
						    &stale_comid->state_mutex);
						stale_comid->state =
						    IBCM_STATE_ESTABLISHED;
						cv_broadcast(
						    &stale_comid->block_mad_cv);
					}
				}
				IBCM_REF_CNT_DECR(stale_comid);
				mutex_exit(&stale_comid->state_mutex);
			}
			ibcm_return_open_data(statep, rep_msgp, reject_reason);
			return;
		}

		/*
		 * No need to handle out of memory conditions as we called
		 * ibcm_lookup_msg() with IBT_CHAN_BLOCKING flags.
		 */
		ASSERT(stale_lookup_status == IBCM_LOOKUP_NEW);

		/* Initialize the remote ack delay */
		statep->remote_ack_delay =
		    ibt_ib2usec(rep_msgp->rep_target_delay_plus >> 3);

		IBTF_DPRINTF_L4(cmlog, "ibcm_process_rep_msg: statep 0x%p"
		    " passive hca_ack_delay= %x ", statep,
		    statep->remote_ack_delay);

		response = ibcm_cep_state_rep(statep, rep_msgp,
		    &reject_reason, &arej_info_len);

		if (response == IBCM_DEFER) {
			IBTF_DPRINTF_L4(cmlog, "ibcm_process_rep_msg: "
			    "statep 0x%p client returned DEFER response",
			    statep);
			return;
		}
		ibcm_handle_cep_rep_response(statep, response,
		    reject_reason, arej_info_len, rep_msgp);

		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*statep))

		return;

	} else if (statep->state == IBCM_STATE_DELETE) {

		mutex_exit(&statep->state_mutex);
		ibcm_build_n_post_rej_mad(input_madp,
		    b2h32(rep_msgp->rep_local_comm_id), cm_mad_addr,
		    IBT_CM_FAILURE_REP, IBT_CM_INVALID_CID);
		mutex_enter(&statep->state_mutex);
	} else {

#ifdef DEBUG
		if (ibcm_test_mode > 0)
			if (statep->state == IBCM_STATE_REP_RCVD)
				IBTF_DPRINTF_L2(cmlog, "ibcm_process_rep_msg: "
				    "REP re-send from passive for statep 0x%p"
				    " in state %d", statep, statep->state);
			else
				IBTF_DPRINTF_L2(cmlog, "ibcm_process_rep_msg: "
				    "Unexpected REP for statep 0x%p in "
				    "state %d", statep, statep->state);
#endif
	}
	/* decrement ref count and return for LOOKUP_EXISTS */
	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);

}

/*
 * ibcm_handle_cep_req_response:
 *	Processes the response from ibcm_cep_state_rep. Called holding a
 *	statep ref cnt. The statep ref cnt is decremented before returning.
 */
void
ibcm_handle_cep_rep_response(ibcm_state_data_t *statep, ibcm_status_t response,
    ibt_cm_reason_t reject_reason, uint8_t arej_info_len,
    ibcm_rep_msg_t *rep_msgp)
{
	/* wait until the send completion callback is invoked for REQ post */
	mutex_enter(&statep->state_mutex);
	while (statep->send_mad_flags & IBCM_REQ_POST_BUSY)
		cv_wait(&statep->block_mad_cv, &statep->state_mutex);
	mutex_exit(&statep->state_mutex);

	if (response == IBCM_SEND_RTU) {
		/* if connection aborted, return */
		if (ibcm_post_rtu_mad(statep) != IBCM_SUCCESS) {
			mutex_enter(&statep->state_mutex);
			IBCM_REF_CNT_DECR(statep);
			mutex_exit(&statep->state_mutex);
			return;
		}

		/*
		 * Call client handler with cm event  IBT_CM_EVENT_CONN_EST to
		 * indicate RTU posted
		 */
		ibcm_cep_send_rtu(statep);
	} else {
		IBTF_DPRINTF_L4(cmlog, "ibcm_handle_cep_rep_response: statep %p"
		    " posting REJ reject_reason = %d", statep, reject_reason);

		ASSERT(response == IBCM_SEND_REJ);
		ibcm_post_rej_mad(statep, reject_reason, IBT_CM_FAILURE_REP,
		    NULL, arej_info_len);
	}

	ibcm_return_open_data(statep, rep_msgp, reject_reason);
}

/*
 * ibcm_return_open_data:
 *	Initializes the ibt_open_rc_channel return data. The statep ref cnt is
 *	decremented before returning.
 */
static void
ibcm_return_open_data(ibcm_state_data_t *statep, ibcm_rep_msg_t *rep_msgp,
    ibt_cm_reason_t reject_reason)
{
	/* signal waiting CV - blocking in ibt_open_channel() */
	if (statep->open_return_data != NULL) {
		if (statep->open_return_data->rc_priv_data_len > 0)
			bcopy(rep_msgp->rep_private_data,
			    statep->open_return_data->rc_priv_data,
			    statep->open_return_data->rc_priv_data_len);
		statep->open_return_data->rc_rdma_ra_in =
		    rep_msgp->rep_initiator_depth;
		statep->open_return_data->rc_rdma_ra_out =
		    rep_msgp->rep_resp_resources;
		statep->open_return_data->rc_failover_status =
		    rep_msgp->rep_target_delay_plus >> 1 & 3;
		statep->open_return_data->rc_status = reject_reason;

		mutex_enter(&statep->state_mutex);
		statep->open_done = B_TRUE;
		cv_broadcast(&statep->block_client_cv);
	} else mutex_enter(&statep->state_mutex);

	/* decrement ref count and return for LOOKUP_EXISTS */
	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}


/*
 * ibcm_process_mra_msg:
 *	Called from ibcm_process_incoming_mad on reception of a MRA message
 *
 *	Cancels existing timer, and sets a new timer based on timeout
 *	value from MRA message. The remaining retry count of statep is
 *	not changed, and timer value for the remaining retry timers is
 *	also not changed
 *
 * INPUTS:
 *	hcap		- HCA entry pointer
 *	input_madp	- CM MAD that is input to this function
 *	cm_mad_addr	- Address information for the MAD
 *
 * RETURN VALUE:	NONE
 */
void
ibcm_process_mra_msg(ibcm_hca_info_t *hcap, uint8_t *input_madp,
    ibcm_mad_addr_t *cm_mad_addr)
{
	ibcm_status_t		state_lookup_status;
	ibcm_mra_msg_t		*mra_msgp =
	    (ibcm_mra_msg_t *)(&input_madp[IBCM_MAD_HDR_SIZE]);
	ibcm_state_data_t	*statep = NULL;
	uint8_t			mra_msg;

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_mra_msg:");

	/* Lookup for an existing state structure (as a READER) */
	rw_enter(&hcap->hca_state_rwlock, RW_READER);
	state_lookup_status = ibcm_lookup_msg(IBCM_INCOMING_MRA,
	    b2h32(mra_msgp->mra_remote_comm_id), 0, 0, hcap, &statep);
	rw_exit(&hcap->hca_state_rwlock);

	/* if state doesn't exist just return */
	if (state_lookup_status != IBCM_LOOKUP_EXISTS) {
		ibcm_build_n_post_rej_mad(input_madp,
		    b2h32(mra_msgp->mra_local_comm_id), cm_mad_addr,
		    IBT_CM_FAILURE_UNKNOWN, IBT_CM_INVALID_CID);
		return;
	}

	if (IBCM_OUT_HDRP(statep->stored_msg)->TransactionID !=
	    ((ib_mad_hdr_t *)(input_madp))->TransactionID) {
		mutex_enter(&statep->state_mutex);
		IBCM_REF_CNT_DECR(statep);
		mutex_exit(&statep->state_mutex);
		IBTF_DPRINTF_L3(cmlog, "ibcm_process_mra_msg: statep 0x%p "
		    "MRA MAD with tid expected 0x%llX tid found 0x%llX "
		    "com id 0x%x arrived", statep,
		    b2h64(IBCM_OUT_HDRP(statep->stored_msg)->TransactionID),
		    b2h64(((ib_mad_hdr_t *)(input_madp))->TransactionID),
		    b2h32(mra_msgp->mra_local_comm_id));
		return;
	}

	ibcm_insert_trace(statep, IBCM_TRACE_INCOMING_MRA);

	mutex_enter(&statep->state_mutex);

	/*
	 * Only allow for REQ/REP "mra_msg_typ" ONLY
	 * (to validate MRA message received)?
	 */
	mra_msg = mra_msgp->mra_message_type_plus >> 6;
	if ((mra_msg != IBT_CM_MRA_TYPE_REQ) &&
	    (mra_msg != IBT_CM_MRA_TYPE_REP) &&
	    (mra_msg != IBT_CM_MRA_TYPE_LAP)) {

		IBTF_DPRINTF_L2(cmlog, "ibcm_process_mra_msg: statep 0x%p "
		    "Unexpected MRA MSG Type %x", statep, mra_msg);
		IBCM_REF_CNT_DECR(statep);
		mutex_exit(&statep->state_mutex);
		return;
	}

	if ((statep->state == IBCM_STATE_REQ_SENT) ||
	    (statep->state == IBCM_STATE_REP_SENT) ||
	    ((statep->state == IBCM_STATE_ESTABLISHED) &&
	    (statep->ap_state == IBCM_AP_STATE_LAP_SENT))) {
		timeout_id_t	timer_val = statep->timerid;
		clock_t		service_timeout;

		if (statep->state == IBCM_STATE_REQ_SENT) {
			mra_msg = IBT_CM_MRA_TYPE_REQ;
			statep->state = IBCM_STATE_REP_WAIT;
		} else if (statep->state == IBCM_STATE_REP_SENT) {
			mra_msg = IBT_CM_MRA_TYPE_REP;
			statep->state = IBCM_STATE_MRA_REP_RCVD;
		} else { /* statep->state == IBCM_STATE_LAP_SENT */
			mra_msg = IBT_CM_MRA_TYPE_LAP;
			statep->ap_state = IBCM_AP_STATE_MRA_LAP_RCVD;
		}

		/* cancel the timer */
		statep->timerid = 0;
		mutex_exit(&statep->state_mutex);

		(void) untimeout(timer_val);

		service_timeout =
		    ibt_ib2usec(mra_msgp->mra_service_timeout_plus >> 3);

		/*
		 * If tunable MAX MRA Service Timeout parameter is set, then
		 * verify whether the requested timer value exceeds the MAX
		 * value and reset the timer value to the MAX value.
		 */
		if (ibcm_mra_service_timeout_max &&
		    ibcm_mra_service_timeout_max < service_timeout) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_mra_msg: "
			    "Unexpected MRA Service Timeout value (%ld), Max "
			    "allowed is (%ld)", service_timeout,
			    ibcm_mra_service_timeout_max);
			service_timeout = ibcm_mra_service_timeout_max;
		}

		/*
		 * Invoke client handler to pass the MRA private data
		 */
		if (statep->cm_handler != NULL) {
			ibt_cm_event_t	event;

			bzero(&event, sizeof (event));

			event.cm_type = IBT_CM_EVENT_MRA_RCV;
			event.cm_channel = statep->channel;
			event.cm_session_id = NULL;
			event.cm_priv_data = mra_msgp->mra_private_data;
			event.cm_priv_data_len = IBT_MRA_PRIV_DATA_SZ;

			event.cm_event.mra.mra_msg_type = mra_msg;

			event.cm_event.mra.mra_service_time = service_timeout;

			/* Client cannot return private data */
			(void) statep->cm_handler(statep->state_cm_private,
			    &event, NULL, NULL, 0);
		}

		/*
		 * Must re-check state, as an RTU could have come
		 * after the above mutex_exit and mutex_enter below
		 */
		mutex_enter(&statep->state_mutex);
		if ((statep->state == IBCM_STATE_REP_WAIT) ||
		    (statep->state == IBCM_STATE_MRA_REP_RCVD) ||
		    (statep->ap_state == IBCM_AP_STATE_MRA_LAP_RCVD)) {

			statep->remaining_retry_cnt = statep->max_cm_retries;

			/*
			 * The timeout interval is changed only for the first
			 * retry.  The later retries use the timeout from
			 * statep->timer_value
			 */
			statep->timer_stored_state = statep->state;
			statep->timer_value = statep->pkt_life_time +
			    service_timeout;
			statep->timerid = IBCM_TIMEOUT(statep,
			    statep->timer_value);
		}

	} else if (statep->state == IBCM_STATE_DELETE) {

		mutex_exit(&statep->state_mutex);
		ibcm_build_n_post_rej_mad(input_madp,
		    b2h32(mra_msgp->mra_local_comm_id), cm_mad_addr,
		    IBT_CM_FAILURE_UNKNOWN, IBT_CM_INVALID_CID);
		mutex_enter(&statep->state_mutex);
	} else {

#ifdef DEBUG
		if (ibcm_test_mode > 0)
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_mra_msg: "
			    "Unexpected mra for statep 0x%p in state %d",
			    statep, statep->state);
#endif
	}

	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}


/*
 * ibcm_process_rtu_msg:
 *	Called from ibcm_process_incoming_mad on reception of a RTU message
 *
 *	Changes connection state to established if in REP SENT state
 *
 * INPUTS:
 *	hcap		- HCA entry pointer
 *	input_madp	- CM MAD that is input to this function
 *	cm_mad_addr	- Address information for the MAD
 *
 * RETURN VALUE:	NONE
 */
void
ibcm_process_rtu_msg(ibcm_hca_info_t *hcap, uint8_t *input_madp,
    ibcm_mad_addr_t *cm_mad_addr)
{
	timeout_id_t		timer_val;
	ibcm_status_t		status;
	ibcm_rtu_msg_t		*rtu_msg =
	    (ibcm_rtu_msg_t *)(&input_madp[IBCM_MAD_HDR_SIZE]);
	ibcm_state_data_t	*statep = NULL;

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_rtu_msg:");

	/* Lookup for an existing state structure - using a reader lock */
	rw_enter(&hcap->hca_state_rwlock, RW_READER);
	status = ibcm_lookup_msg(IBCM_INCOMING_RTU,
	    b2h32(rtu_msg->rtu_remote_comm_id), 0, 0, hcap, &statep);
	rw_exit(&hcap->hca_state_rwlock);

	/* if state doesn't exist just return */
	if (status != IBCM_LOOKUP_EXISTS) {
		ibcm_build_n_post_rej_mad(input_madp,
		    b2h32(rtu_msg->rtu_local_comm_id), cm_mad_addr,
		    IBT_CM_FAILURE_UNKNOWN, IBT_CM_INVALID_CID);
		return;
	}

	if (IBCM_OUT_HDRP(statep->stored_msg)->TransactionID !=
	    ((ib_mad_hdr_t *)(input_madp))->TransactionID) {
		mutex_enter(&statep->state_mutex);
		IBCM_REF_CNT_DECR(statep);
		mutex_exit(&statep->state_mutex);
		IBTF_DPRINTF_L3(cmlog, "ibcm_process_rtu_msg: statep 0x%p "
		    "An RTU MAD with tid expected 0x%llX tid found 0x%llX "
		    "com id 0x%x arrived", statep,
		    b2h64(IBCM_OUT_HDRP(statep->stored_msg)->TransactionID),
		    b2h64(((ib_mad_hdr_t *)(input_madp))->TransactionID),
		    b2h32(rtu_msg->rtu_remote_comm_id));
		return;
	}

	ibcm_insert_trace(statep, IBCM_TRACE_INCOMING_RTU);

	mutex_enter(&statep->state_mutex);

	if ((statep->state == IBCM_STATE_REP_SENT) ||
	    (statep->state == IBCM_STATE_MRA_REP_RCVD)) {

		/* transient until ibt_modify_qp succeeds to RTS */
		statep->state = IBCM_STATE_TRANSIENT_ESTABLISHED;

		timer_val = statep->timerid;
		statep->timerid = 0;
		mutex_exit(&statep->state_mutex);

		(void) untimeout(timer_val);

		ibcm_cep_state_rtu(statep, rtu_msg);

		mutex_enter(&statep->state_mutex);

	} else if (statep->state == IBCM_STATE_REJ_SENT) {
		ibcm_resend_rej_mad(statep);
	} else if (statep->state == IBCM_STATE_DELETE) {

		mutex_exit(&statep->state_mutex);
		ibcm_build_n_post_rej_mad(input_madp,
		    b2h32(rtu_msg->rtu_local_comm_id), cm_mad_addr,
		    IBT_CM_FAILURE_UNKNOWN, IBT_CM_INVALID_CID);
		mutex_enter(&statep->state_mutex);
	} else {

#ifdef DEBUG
		if ((ibcm_test_mode > 0) &&
		    (statep->state != IBCM_STATE_ESTABLISHED))
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_rtu_msg: "
			    "Unexpected rtu for statep 0x%p in state %d",
			    statep, statep->state);
#endif
	}

	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}


/*
 * ibcm_process_rej_msg:
 *	Called from ibcm_process_incoming_mad on reception of a REJ message.
 *
 * INPUTS:
 *	hcap		- HCA entry pointer
 *	input_madp	- CM MAD that is input to this function
 *	cm_mad_addr	- Address information for the MAD
 *
 * RETURN VALUE:	NONE
 */
/* ARGSUSED */
void
ibcm_process_rej_msg(ibcm_hca_info_t *hcap, uint8_t *input_madp,
    ibcm_mad_addr_t *cm_mad_addr)
{
	ibcm_status_t		state_lookup_status;
	ibcm_rej_msg_t		*rej_msg =
	    (ibcm_rej_msg_t *)(&input_madp[IBCM_MAD_HDR_SIZE]);
	ibcm_state_data_t	*statep = NULL;
	ib_guid_t		remote_hca_guid;
	ibcm_conn_state_t	rej_state;

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_rej_msg:");

	/* Lookup for an existing state structure */
	rw_enter(&hcap->hca_state_rwlock, RW_READER);	/* grab READER lock */

	if ((b2h32(rej_msg->rej_remote_comm_id) == 0) &&
	    ((rej_msg->rej_reject_info_len_plus >> 1) >= sizeof (ib_guid_t)) &&
	    (b2h16(rej_msg->rej_rejection_reason) == IBT_CM_TIMEOUT)) {
		bcopy(rej_msg->rej_addl_rej_info, &remote_hca_guid,
		    sizeof (ib_guid_t));
		remote_hca_guid = b2h64(remote_hca_guid);

		IBTF_DPRINTF_L4(cmlog, "ibcm_process_rej_msg: "
		    "hca guid in REJ's ARI =  %llX", remote_hca_guid);

		state_lookup_status = ibcm_lookup_msg(IBCM_INCOMING_REJ_RCOMID,
		    b2h32(rej_msg->rej_local_comm_id), 0, remote_hca_guid,
		    hcap, &statep);
	} else
		state_lookup_status = ibcm_lookup_msg(IBCM_INCOMING_REJ,
		    b2h32(rej_msg->rej_remote_comm_id), 0, 0, hcap, &statep);

	rw_exit(&hcap->hca_state_rwlock);


	/* if state doesn't exist just return */
	if (state_lookup_status != IBCM_LOOKUP_EXISTS) {

		IBTF_DPRINTF_L2(cmlog, "ibcm_process_rej_msg: no statep with "
		    "local com id %x remote com id %x reason %d",
		    b2h32(rej_msg->rej_remote_comm_id),
		    b2h32(rej_msg->rej_local_comm_id),
		    b2h16(rej_msg->rej_rejection_reason));

		/* Do NOT respond with invalid comid REJ */
		return;
	}

	IBTF_DPRINTF_L2(cmlog, "ibcm_process_rej_msg: statep 0x%p INCOMING_REJ",
	    statep);
	ibcm_insert_trace(statep, IBCM_TRACE_INCOMING_REJ);
	if (ibcm_enable_trace & 2)
		ibcm_dump_conn_trace(statep);

	mutex_enter(&statep->state_mutex);

	rej_state = statep->state;

	if ((statep->state == IBCM_STATE_REP_SENT) ||
	    (statep->state == IBCM_STATE_REQ_SENT) ||
	    (statep->state == IBCM_STATE_REP_WAIT) ||
	    (statep->state == IBCM_STATE_MRA_REP_RCVD)) {
		timeout_id_t	timer_val = statep->timerid;

		statep->state = IBCM_STATE_DELETE;

		/* cancel the REQ/REP timer */
		if (timer_val != 0) {
			statep->timerid = 0;
			mutex_exit(&statep->state_mutex);

			(void) untimeout(timer_val);
		} else {
			mutex_exit(&statep->state_mutex);
		}

		/*
		 * Call the QP state transition processing function
		 * NOTE: Input MAD is the REJ received, there is no output MAD
		 */
		ibcm_cep_state_rej(statep, rej_msg, rej_state);

		/* signal waiting CV - blocking in ibt_open_channel() */
		if (statep->open_return_data != NULL) {
			statep->open_return_data->rc_status =
			    b2h16(rej_msg->rej_rejection_reason);

			if (statep->open_return_data->rc_priv_data_len > 0)
				bcopy(rej_msg->rej_private_data,
				    statep->open_return_data->rc_priv_data,
				    min(
				    statep->open_return_data->rc_priv_data_len,
				    IBT_REJ_PRIV_DATA_SZ));
			mutex_enter(&statep->state_mutex);
			statep->open_done = B_TRUE;
			cv_broadcast(&statep->block_client_cv);
		} else {
			mutex_enter(&statep->state_mutex);
		}

		IBCM_REF_CNT_DECR(statep);
		mutex_exit(&statep->state_mutex);

		/* Now delete the statep */
		ibcm_delete_state_data(statep);

	} else if ((statep->state == IBCM_STATE_ESTABLISHED) &&
	    (statep->mode == IBCM_ACTIVE_MODE)) {

		IBTF_DPRINTF_L4(cmlog, "ibcm_process_rej_msg: statep 0x%p "
		    "REJ in established state", statep);

		statep->state = IBCM_STATE_TIMEWAIT;

		/* wait for/cancel pending LAP/APR, release state mutex */
		ibcm_sync_lapr_idle(statep);

		/* wait until client is informed CONN EST event */
		mutex_enter(&statep->state_mutex);
		while (statep->cep_in_rts == IBCM_BLOCK)
			cv_wait(&statep->block_mad_cv, &statep->state_mutex);
		mutex_exit(&statep->state_mutex);

		/*
		 * Call the QP state transition processing function
		 * NOTE: Input MAD is the REJ received, there is no output MAD
		 */
		ibcm_cep_state_rej_est(statep);

		/*
		 * Start the timewait state timer, as connection is in
		 * established state
		 */

		/*
		 * For passive side CM set it to remote_ack_delay
		 * For active side CM add the pkt_life_time * 2
		 */
		mutex_enter(&statep->state_mutex);
		statep->timer_value = statep->remote_ack_delay;
		/* statep->mode == IBCM_ACTIVE_MODE) */
		statep->timer_value += (2 * statep->pkt_life_time);

		statep->remaining_retry_cnt = 0;
		statep->timer_stored_state = statep->state;

		statep->timerid = IBCM_TIMEOUT(statep, statep->timer_value);

		IBCM_REF_CNT_DECR(statep);
		mutex_exit(&statep->state_mutex);

	} else if (((statep->state == IBCM_STATE_REQ_RCVD) ||
	    (statep->state == IBCM_STATE_REP_RCVD) ||
	    (statep->state == IBCM_STATE_MRA_SENT) ||
	    (statep->state == IBCM_STATE_MRA_REP_SENT)) &&
	    (b2h16(rej_msg->rej_rejection_reason) == IBT_CM_TIMEOUT)) {

		if (statep->abort_flag == IBCM_ABORT_INIT)
			statep->abort_flag = IBCM_ABORT_REJ;

		IBCM_REF_CNT_DECR(statep);
		mutex_exit(&statep->state_mutex);
	} else {

#ifdef DEBUG
		if ((ibcm_test_mode > 0) &&
		    (statep->state != IBCM_STATE_DELETE))
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_rej_msg: "
			    "Unexpected rej for statep 0x%p in state %d",
			    statep, statep->state);
#endif
		IBCM_REF_CNT_DECR(statep);
		mutex_exit(&statep->state_mutex);
	}
}


/*
 * ibcm_process_dreq_msg:
 *	Processes incoming DREQ message on active/passive side
 *
 * INPUTS:
 *	hcap		- HCA entry pointer
 *	input_madp	- CM MAD that is input to this function
 *	cm_mad_addr	- Address information for the MAD
 *
 * RETURN VALUE:	NONE
 */
/*ARGSUSED*/
void
ibcm_process_dreq_msg(ibcm_hca_info_t *hcap, uint8_t *input_madp,
    ibcm_mad_addr_t *cm_mad_addr)
{
	void			*priv_data = NULL;
	ibcm_status_t		state_lookup_status;
	ib_qpn_t		local_qpn;
	ibcm_dreq_msg_t		*dreq_msgp =
	    (ibcm_dreq_msg_t *)(&input_madp[IBCM_MAD_HDR_SIZE]);
	ibcm_state_data_t	*statep = NULL;
	uint8_t			close_event_type;
	ibt_cm_status_t		cb_status;

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_dreq_msg:");

	/* Lookup for an existing state structure */
	rw_enter(&hcap->hca_state_rwlock, RW_READER);

	state_lookup_status = ibcm_lookup_msg(IBCM_INCOMING_DREQ,
	    b2h32(dreq_msgp->dreq_remote_comm_id), 0, 0, hcap, &statep);
	rw_exit(&hcap->hca_state_rwlock);

	local_qpn = b2h32(dreq_msgp->dreq_remote_qpn_eecn_plus) >> 8;

	if (state_lookup_status != IBCM_LOOKUP_EXISTS) {
		IBTF_DPRINTF_L3(cmlog, "ibcm_process_dreq_msg: no statep with"
		    "com id %x", b2h32(dreq_msgp->dreq_remote_comm_id));
		/* implies a bogus message */
		return;
	}

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_dreq_msg: statep 0x%p "
	    "lookup status %x dreq qpn = %x", statep, state_lookup_status,
	    local_qpn);

	/*
	 * Local QPN check is necessary. There could be a DREQ from
	 * a remote stale connection processing with the same com id, but
	 * not intended for this statep
	 */
	mutex_enter(&statep->state_mutex);
	if ((statep->local_qpn != local_qpn) ||
	    (statep->remote_comid != b2h32(dreq_msgp->dreq_local_comm_id))) {

		IBTF_DPRINTF_L3(cmlog, "ibcm_process_dreq_msg:"
		    "statep->local_qpn = %x qpn in dreq = %x"
		    "statep->remote_comid = %x local comid in dreq = %x",
		    statep->local_qpn, local_qpn, statep->remote_comid,
		    b2h32(dreq_msgp->dreq_local_comm_id));

		IBCM_REF_CNT_DECR(statep);
		mutex_exit(&statep->state_mutex);
		return;
	}
	/*
	 * If another thread is processing a copy of this same DREQ,
	 * bail out here.
	 */
	if (statep->state == IBCM_STATE_TRANSIENT_DREQ_SENT ||
	    statep->drep_in_progress) {
		IBCM_REF_CNT_DECR(statep);
		mutex_exit(&statep->state_mutex);
		return;
	}
	switch (statep->state) {
	case IBCM_STATE_ESTABLISHED:
	case IBCM_STATE_DREQ_SENT:
	case IBCM_STATE_TIMEWAIT:
		break;
	default:
		/* All other states ignore DREQ */
		IBCM_REF_CNT_DECR(statep);
		mutex_exit(&statep->state_mutex);
		return;
	}
	statep->drep_in_progress = 1;

	/*
	 * If drep msg wasn't really required, it shall be deleted finally
	 * when statep goes away
	 */
	if (statep->drep_msg == NULL) {
		mutex_exit(&statep->state_mutex);
		if (ibcm_alloc_out_msg(statep->stored_reply_addr.ibmf_hdl,
		    &statep->drep_msg, MAD_METHOD_SEND) != IBT_SUCCESS) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_dreq_msg: "
			    "statep 0x%p ibcm_alloc_out_msg failed", statep);
			mutex_enter(&statep->state_mutex);
			statep->drep_in_progress = 0;
			IBCM_REF_CNT_DECR(statep);
			mutex_exit(&statep->state_mutex);
			return;
		}
		mutex_enter(&statep->state_mutex);
	}

	if (statep->state == IBCM_STATE_TRANSIENT_DREQ_SENT) {
		IBCM_REF_CNT_DECR(statep);
		statep->drep_in_progress = 0;
		mutex_exit(&statep->state_mutex);
		return;
	}

	/*
	 * Need to generate drep, as time wait can be reached either by an
	 * outgoing dreq or an incoming dreq
	 */
	if ((statep->state == IBCM_STATE_ESTABLISHED) ||
	    (statep->state == IBCM_STATE_DREQ_SENT)) {
		timeout_id_t	timer_val = statep->timerid;

		if (statep->state == IBCM_STATE_DREQ_SENT) {
			statep->state = IBCM_STATE_DREQ_RCVD;
			statep->timerid = 0;
			ibcm_close_done(statep, 0);
			mutex_exit(&statep->state_mutex);

			close_event_type = IBT_CM_CLOSED_DUP;
			if (timer_val != 0) {
				/* Cancel the timer set for DREP reception */
				(void) untimeout(timer_val);
			}
		} else {	/* In ESTABLISHED State */
			boolean_t	is_ofuv = statep->is_this_ofuv_chan;

			statep->state = IBCM_STATE_DREQ_RCVD;
			statep->clnt_proceed = IBCM_BLOCK;

			/* Cancel or wait for LAP/APR to complete */
			ibcm_sync_lapr_idle(statep);
			/* The above function releases the state mutex */

			/* wait until client knows CONN EST event */
			mutex_enter(&statep->state_mutex);
			while (statep->cep_in_rts == IBCM_BLOCK)
				cv_wait(&statep->block_mad_cv,
				    &statep->state_mutex);
			mutex_exit(&statep->state_mutex);

			close_event_type = IBT_CM_CLOSED_DREQ_RCVD;
			/* Move CEP to error state */
			if (is_ofuv == B_FALSE) /* Skip for OFUV channel */
				(void) ibcm_cep_to_error_state(statep);
		}
		mutex_enter(&statep->state_mutex);
		statep->drep_in_progress = 0;

		IBCM_OUT_HDRP(statep->drep_msg)->TransactionID =
		    ((ib_mad_hdr_t *)(input_madp))->TransactionID;

		priv_data = &(((ibcm_drep_msg_t *)
		    IBCM_OUT_MSGP(statep->drep_msg))->drep_private_data[0]);

		if (statep->close_ret_status)
			*statep->close_ret_status = close_event_type;

		if (statep->close_nocb_state != IBCM_FAIL) {
			ibtl_cm_chan_is_closing(statep->channel);
			statep->close_nocb_state = IBCM_BLOCK;
		}
		mutex_exit(&statep->state_mutex);

		/*
		 * if close_nocb_state is IBCM_FAIL, then cm_handler is NULL
		 * if close_nocb_state is IBCM_BLOCK, client cannot go away
		 */
		if (statep->cm_handler != NULL) {
			ibt_cm_event_t		event;
			ibt_cm_return_args_t	ret_args;

			bzero(&event, sizeof (event));
			bzero(&ret_args, sizeof (ret_args));

			event.cm_type = IBT_CM_EVENT_CONN_CLOSED;
			event.cm_channel = statep->channel;
			event.cm_session_id = statep;
			event.cm_priv_data = dreq_msgp->dreq_private_data;
			event.cm_priv_data_len = IBT_DREQ_PRIV_DATA_SZ;
			event.cm_event.closed = close_event_type;

			ibcm_insert_trace(statep,
			    IBCM_TRACE_CALLED_CONN_CLOSE_EVENT);

			cb_status = statep->cm_handler(statep->state_cm_private,
			    &event, &ret_args, priv_data,
			    IBT_DREP_PRIV_DATA_SZ);

			ibcm_insert_trace(statep,
			    IBCM_TRACE_RET_CONN_CLOSE_EVENT);

			if (cb_status == IBT_CM_DEFER) {
				mutex_enter(&statep->state_mutex);
				statep->clnt_proceed =
				    IBCM_UNBLOCK;
				cv_broadcast(&statep->block_client_cv);
				mutex_exit(&statep->state_mutex);

				IBTF_DPRINTF_L4(cmlog, "ibcm_process_dreq_msg:"
				    " statep 0x%p client returned DEFER "
				    "response", statep);
				return;
			}
		}

		/* fail/resume any blocked cm api call */
		mutex_enter(&statep->state_mutex);

		/* Signal for cm proceed api */
		statep->clnt_proceed = IBCM_FAIL;

		/* Signal for close with no callbacks */
		statep->close_nocb_state = IBCM_FAIL;

		/* Signal any waiting close channel thread */
		statep->close_done = B_TRUE;

		cv_broadcast(&statep->block_client_cv);
		mutex_exit(&statep->state_mutex);

		ibcm_handle_cep_dreq_response(statep, NULL, 0);

	} else if (statep->state == IBCM_STATE_TIMEWAIT) {
		statep->drep_in_progress = 0;
		if (statep->send_mad_flags & IBCM_DREP_POST_BUSY) {
			IBCM_REF_CNT_DECR(statep);
			mutex_exit(&statep->state_mutex);
			return;
		}
		statep->send_mad_flags |= IBCM_DREP_POST_BUSY;

		/* Release statep mutex before posting the MAD */
		mutex_exit(&statep->state_mutex);

		IBCM_OUT_HDRP(statep->drep_msg)->TransactionID =
		    ((ib_mad_hdr_t *)(input_madp))->TransactionID;

		ibcm_post_drep_mad(statep);
		/* ref cnt decremented in ibcm_post_drep_complete */
	} else {
#ifdef DEBUG
		if ((ibcm_test_mode > 0) &&
		    (statep->state != IBCM_STATE_DELETE))
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_dreq_msg: "
			    "Unexpected dreq for statep 0x%p in state %d",
			    statep, statep->state);
#endif
		IBCM_REF_CNT_DECR(statep);
		statep->drep_in_progress = 0;
		mutex_exit(&statep->state_mutex);
	}
}

/*
 * ibcm_handle_cep_dreq_response:
 *	Processes the response from client handler for an incoming DREQ.
 *	The statep ref cnt is decremented before returning.
 */
void
ibcm_handle_cep_dreq_response(ibcm_state_data_t *statep, void *priv_data,
    ibt_priv_data_len_t priv_data_len)
{
	if ((priv_data != NULL) && (priv_data_len > 0))
		bcopy(priv_data,
		    &(((ibcm_drep_msg_t *)
		    IBCM_OUT_MSGP(statep->drep_msg))->drep_private_data[0]),
		    min(priv_data_len, IBT_DREP_PRIV_DATA_SZ));

	ibcm_post_drep_mad(statep);
}


/*
 * ibcm_post_dreq_mad:
 *	Posts a DREQ MAD
 * Post DREQ now for TIMEWAIT state and DREQ_RCVD
 *
 * INPUTS:
 *	statep		- state pointer
 *
 * RETURN VALUE:
 *	NONE
 */
void
ibcm_post_dreq_mad(void *vstatep)
{
	ibcm_state_data_t	*statep = vstatep;
	ibcm_dreq_msg_t		*dreq_msgp;

	ASSERT(statep->dreq_msg != NULL);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*dreq_msgp))

	/* Fill in the DREQ message */
	dreq_msgp = (ibcm_dreq_msg_t *)IBCM_OUT_MSGP(statep->dreq_msg);
	dreq_msgp->dreq_local_comm_id = h2b32(statep->local_comid);
	dreq_msgp->dreq_remote_comm_id = h2b32(statep->remote_comid);
	dreq_msgp->dreq_remote_qpn_eecn_plus = h2b32(statep->remote_qpn << 8);

	IBCM_OUT_HDRP(statep->dreq_msg)->AttributeID =
	    h2b16(IBCM_INCOMING_DREQ + IBCM_ATTR_BASE_ID);

	/* wait until client knows CONN EST event */
	mutex_enter(&statep->state_mutex);
	while (statep->cep_in_rts == IBCM_BLOCK)
		cv_wait(&statep->block_mad_cv, &statep->state_mutex);
	mutex_exit(&statep->state_mutex);

	/* Transition QP/EEC state to ERROR state */
	(void) ibcm_cep_to_error_state(statep);

	IBCM_OUT_HDRP(statep->dreq_msg)->TransactionID =
	    h2b64(ibcm_generate_tranid(IBCM_INCOMING_DREQ, statep->local_comid,
	    0));

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*dreq_msgp))

	/* post the first DREQ via timeout callback */
	mutex_enter(&statep->state_mutex);

	statep->state = IBCM_STATE_DREQ_SENT;
	cv_broadcast(&statep->block_mad_cv);

	statep->timer_stored_state = statep->state;
	/* client cannot specify more than 16 retries */
	statep->timer_value = statep->remote_ack_delay;
	if (statep->mode == IBCM_ACTIVE_MODE) {
		statep->timer_value += (2 * statep->pkt_life_time);
	}
	statep->remaining_retry_cnt = statep->max_cm_retries + 1;
	statep->timerid = IBCM_TIMEOUT(statep, 0);
	mutex_exit(&statep->state_mutex);
}

/*
 * ibcm_post_drep_mad:
 *	Posts a DREP MAD
 * Post DREP now for TIMEWAIT state and DREQ_RCVD
 *
 * INPUTS:
 *	statep		- state pointer
 *
 * RETURN VALUE:
 *	NONE
 */
static void
ibcm_post_drep_mad(ibcm_state_data_t *statep)
{
	ibcm_drep_msg_t	*drep_msgp;

	drep_msgp = (ibcm_drep_msg_t *)IBCM_OUT_MSGP(statep->drep_msg);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*drep_msgp))

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_drep_mad:");

	/* Fill up DREP fields */
	drep_msgp->drep_local_comm_id = h2b32(statep->local_comid);
	drep_msgp->drep_remote_comm_id = h2b32(statep->remote_comid);
	IBCM_OUT_HDRP(statep->drep_msg)->AttributeID =
	    h2b16(IBCM_INCOMING_DREP + IBCM_ATTR_BASE_ID);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*drep_msgp))

	ibcm_insert_trace(statep, IBCM_TRACE_OUTGOING_DREP);

	/* Post the DREP MAD now.  */
	ibcm_post_rc_mad(statep, statep->drep_msg, ibcm_post_drep_complete,
	    statep);
}

/*
 * ibcm_process_drep_msg:
 *	Processes incoming DREP message on active/passive side
 *
 * INPUTS:
 *	hcap		- HCA entry pointer
 *	input_madp	- CM MAD that is input to this function
 *	cm_mad_addr	- Address information for the MAD
 *
 * RETURN VALUE: NONE
 */
/* ARGSUSED */
void
ibcm_process_drep_msg(ibcm_hca_info_t *hcap, uint8_t *input_madp,
    ibcm_mad_addr_t *cm_mad_addr)
{
	ibcm_status_t		state_lookup_status;
	ibcm_drep_msg_t		*drep_msgp =
	    (ibcm_drep_msg_t *)(&input_madp[IBCM_MAD_HDR_SIZE]);
	ibcm_state_data_t	*statep = NULL;

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_drep_msg:");

	/* Lookup for an existing state structure */
	rw_enter(&hcap->hca_state_rwlock, RW_READER);

	state_lookup_status = ibcm_lookup_msg(IBCM_INCOMING_DREP,
	    b2h32(drep_msgp->drep_remote_comm_id), 0, 0, hcap, &statep);
	rw_exit(&hcap->hca_state_rwlock);

	if (state_lookup_status != IBCM_LOOKUP_EXISTS) {
		IBTF_DPRINTF_L3(cmlog, "ibcm_process_drep_msg: no statep with"
		    "com id %x", b2h32(drep_msgp->drep_remote_comm_id));
		return;
	}

	/* if transaction id is not as expected, drop the DREP mad */
	if (IBCM_OUT_HDRP(statep->dreq_msg)->TransactionID !=
	    ((ib_mad_hdr_t *)(input_madp))->TransactionID) {
		mutex_enter(&statep->state_mutex);
		IBCM_REF_CNT_DECR(statep);
		mutex_exit(&statep->state_mutex);
		IBTF_DPRINTF_L3(cmlog, "ibcm_process_drep_msg: statep 0x%p "
		    "DREP with tid expected 0x%llX tid found 0x%llX", statep,
		    b2h64(IBCM_OUT_HDRP(statep->dreq_msg)->TransactionID),
		    b2h64(((ib_mad_hdr_t *)(input_madp))->TransactionID));
		return;
	}

	ibcm_insert_trace(statep, IBCM_TRACE_INCOMING_DREP);

	mutex_enter(&statep->state_mutex);

	if (statep->state == IBCM_STATE_DREQ_SENT) {
		timeout_id_t	timer_val = statep->timerid;

		statep->state = IBCM_STATE_DREP_RCVD;

		statep->timerid = 0;
		mutex_exit(&statep->state_mutex);
		(void) untimeout(timer_val);

		if (statep->stale == B_TRUE)
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_drep_msg: "
			    "statep 0x%p Unexpected DREP received for a stale "
			    "DREQ sent", statep);

		mutex_enter(&statep->state_mutex);
		/* allow free qp, if close channel with NOCALLBACKS didn't */
		if (statep->close_nocb_state != IBCM_FAIL) {
			ibtl_cm_chan_is_closing(statep->channel);
			statep->close_nocb_state = IBCM_BLOCK;
		}
		mutex_exit(&statep->state_mutex);

		/* if close_nocb_state is IBCM_FAIL, then cm_handler is NULL */
		if (statep->cm_handler != NULL) {
			ibt_cm_event_t		event;
			ibt_cm_return_args_t	ret_args;

			bzero(&event, sizeof (event));
			bzero(&ret_args, sizeof (ret_args));

			event.cm_type = IBT_CM_EVENT_CONN_CLOSED;
			event.cm_channel = statep->channel;
			event.cm_session_id = NULL;

			if (statep->stale == B_TRUE) {
				event.cm_event.closed = IBT_CM_CLOSED_STALE;
				event.cm_priv_data = NULL;
				event.cm_priv_data_len = 0;
			} else {
				event.cm_event.closed = IBT_CM_CLOSED_DREP_RCVD;
				event.cm_priv_data =
				    drep_msgp->drep_private_data;
				event.cm_priv_data_len = IBT_DREP_PRIV_DATA_SZ;
			}

			ibcm_insert_trace(statep,
			    IBCM_TRACE_CALLED_CONN_CLOSE_EVENT);

			(void) statep->cm_handler(statep->state_cm_private,
			    &event, &ret_args, NULL, 0);

			ibcm_insert_trace(statep,
			    IBCM_TRACE_RET_CONN_CLOSE_EVENT);
		}

		/* copy the private to close channel, if specified */
		if ((statep->close_ret_priv_data != NULL) &&
		    (statep->close_ret_priv_data_len != NULL) &&
		    (*statep->close_ret_priv_data_len > 0)) {
			bcopy(drep_msgp->drep_private_data,
			    statep->close_ret_priv_data,
			    min(*statep->close_ret_priv_data_len,
			    IBT_DREP_PRIV_DATA_SZ));
		}

		mutex_enter(&statep->state_mutex);
		if (statep->close_ret_status)
			*statep->close_ret_status = IBT_CM_CLOSED_DREP_RCVD;
		/* signal waiting CV - blocking in ibt_close_channel() */
		statep->close_done = B_TRUE;

		/* signal any blocked close channels with no callbacks */
		statep->close_nocb_state = IBCM_FAIL;

		cv_broadcast(&statep->block_client_cv);

		/* Set the timer wait state timer */
		statep->state = statep->timer_stored_state =
		    IBCM_STATE_TIMEWAIT;
		ibcm_close_done(statep, 0);

		statep->remaining_retry_cnt = 0;
		/*
		 * For passive side CM set it to remote_ack_delay
		 * For active side CM add the pkt_life_time * 2
		 */
		statep->timer_value = statep->remote_ack_delay;
		if (statep->mode == IBCM_ACTIVE_MODE) {
			statep->timer_value += (2 * statep->pkt_life_time);
		}

		/* start TIMEWAIT processing */
		statep->timerid = IBCM_TIMEOUT(statep, statep->timer_value);
	}

	/* There is no processing required for other states */
	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}

/*
 * Following are the routines used to resend various CM MADs as a response to
 * incoming MADs
 */
void
ibcm_resend_rtu_mad(ibcm_state_data_t *statep)
{
	ASSERT(MUTEX_HELD(&statep->state_mutex));

	IBTF_DPRINTF_L3(cmlog, "ibcm_resend_rtu_mad statep %p ", statep);

	/* don't care, if timer is running or not. Timer may be from LAP */

	if (!(statep->send_mad_flags & IBCM_RTU_POST_BUSY)) {
		statep->send_mad_flags |= IBCM_RTU_POST_BUSY;
		IBCM_REF_CNT_INCR(statep);	/* for non-blocking RTU post */
		mutex_exit(&statep->state_mutex);

		ibcm_insert_trace(statep, IBCM_TRACE_OUTGOING_RTU);

		ibcm_post_rc_mad(statep, statep->stored_msg,
		    ibcm_post_rtu_complete, statep);
		mutex_enter(&statep->state_mutex);
	}
	/* ref cnt is decremented in ibcm_post_rtu_complete */
}

void
ibcm_resend_rej_mad(ibcm_state_data_t *statep)
{
	timeout_id_t		timer_val = statep->timerid;

	ASSERT(MUTEX_HELD(&statep->state_mutex));

	IBTF_DPRINTF_L3(cmlog, "ibcm_resend_rej_mad statep %p ", statep);

	/* It's a too fast of a REQ or REP */
	if (timer_val == 0)
		return;

	statep->timerid = 0;
	if (!(statep->send_mad_flags & IBCM_REJ_POST_BUSY)) {
		statep->send_mad_flags |= IBCM_REJ_POST_BUSY;
		IBCM_REF_CNT_INCR(statep);	/* for nonblocking REJ post */
		mutex_exit(&statep->state_mutex);
		(void) untimeout(timer_val);

		ibcm_insert_trace(statep, IBCM_TRACE_OUTGOING_REJ);
		if (ibcm_enable_trace & 2)
			ibcm_dump_conn_trace(statep);
		else
			IBTF_DPRINTF_L2(cmlog, "ibcm_resend_rej_mad statep %p "
			    "OUTGOING_REJ", statep);

		ibcm_post_rc_mad(statep, statep->stored_msg,
		    ibcm_post_rej_complete, statep);
		mutex_enter(&statep->state_mutex);
	}
	/* return, holding the state mutex */
}

void
ibcm_resend_rep_mad(ibcm_state_data_t *statep)
{
	timeout_id_t		timer_val = statep->timerid;

	ASSERT(MUTEX_HELD(&statep->state_mutex));

	IBTF_DPRINTF_L3(cmlog, "ibcm_resend_rep_mad statep %p ", statep);

	/* REP timer that is set by ibcm_post_rep_mad */
	if (timer_val != 0) {
		/* Re-start REP timeout */
		statep->remaining_retry_cnt = statep->max_cm_retries;
		if (!(statep->send_mad_flags & IBCM_REP_POST_BUSY)) {
			statep->send_mad_flags |= IBCM_REP_POST_BUSY;
			/* for nonblocking REP post */
			IBCM_REF_CNT_INCR(statep);
			mutex_exit(&statep->state_mutex);

			ibcm_insert_trace(statep, IBCM_TRACE_OUT_REP_RETRY);

			ibcm_post_rc_mad(statep, statep->stored_msg,
			    ibcm_resend_post_rep_complete, statep);
			mutex_enter(&statep->state_mutex);
		}
	}

	/*
	 * else, timer is not yet set by ibcm_post_rep_mad. This is too fast
	 * of a REQ being re-transmitted.
	 */
}

void
ibcm_resend_mra_mad(ibcm_state_data_t *statep)
{
	ASSERT(MUTEX_HELD(&statep->state_mutex));

	IBTF_DPRINTF_L3(cmlog, "ibcm_resend_mra_mad statep %p ", statep);

	if (statep->send_mad_flags & IBCM_MRA_POST_BUSY)
		return;

	statep->send_mad_flags |= IBCM_MRA_POST_BUSY;

	statep->mra_time = gethrtime();
	IBCM_REF_CNT_INCR(statep);	/* for non-blocking MRA post */
	/* Exit the statep mutex, before sending the MAD */
	mutex_exit(&statep->state_mutex);

	ibcm_insert_trace(statep, IBCM_TRACE_OUTGOING_MRA);

	/* Always resend the response MAD to the original reply destination */
	ibcm_post_rc_mad(statep, statep->mra_msg, ibcm_post_mra_complete,
	    statep);

	mutex_enter(&statep->state_mutex);

	/* return, holding the state mutex */
}


/*
 * ibcm_post_rej_mad:
 *	Posts a REJ MAD and starts timer
 *
 * INPUTS:
 *	statep		- state pointer
 *	which_msg	- which message is being MRAed
 *	reject_reason	- Rejection reason See Section 12.6.7.2 rev1.0a IB Spec
 *	addl_rej_info	- Additional rej Information
 *	arej_info_len	- Additional rej Info length
 *
 * RETURN VALUE:
 *	NONE
 * Notes
 *  There is no need to hold the statep->mutex and call ibcm_post_rej_mad
 *  REJ can be posted either in IBCM_STATE_REQ_RCVD or IBCM_STATE_REP_RCVD
 *  In these states, there is no timer active, and an incoming REJ shall
 *  not modify the state or cancel timers
 *  An incoming REJ doesn't affect statep in state = IBCM_STATE_REJ_SENT/BUSY
 */
void
ibcm_post_rej_mad(ibcm_state_data_t *statep, ibt_cm_reason_t reject_reason,
    int which_msg, void *addl_rej_info, ibt_priv_data_len_t arej_info_len)
{
	ibcm_rej_msg_t	*rej_msg =
	    (ibcm_rej_msg_t *)IBCM_OUT_MSGP(statep->stored_msg);

	/* Message printed if connection gets REJed */
	IBTF_DPRINTF_L3(cmlog, "ibcm_post_rej_mad: "
	    "statep = %p, reject_reason = %d", statep, reject_reason);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*rej_msg))

	/* Initialize rej_msg fields */
	rej_msg->rej_local_comm_id = h2b32(statep->local_comid);
	rej_msg->rej_remote_comm_id = h2b32(statep->remote_comid);
	rej_msg->rej_msg_type_plus = (which_msg & 0x3) << 6;
	rej_msg->rej_reject_info_len_plus = arej_info_len << 1;
	rej_msg->rej_rejection_reason = h2b16((uint16_t)reject_reason);

	if ((arej_info_len != 0) && (addl_rej_info != NULL))
		bcopy(addl_rej_info, rej_msg->rej_addl_rej_info, arej_info_len);

	IBCM_OUT_HDRP(statep->stored_msg)->AttributeID =
	    h2b16(IBCM_INCOMING_REJ + IBCM_ATTR_BASE_ID);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*rej_msg))

	mutex_enter(&statep->state_mutex);

	/* signal any waiting close channels with blocking or no callbacks  */
	statep->close_done = B_TRUE;
	statep->close_nocb_state = IBCM_FAIL;

	cv_signal(&statep->block_client_cv);

	statep->timer_stored_state = statep->state = IBCM_STATE_REJ_SENT;
	statep->send_mad_flags |= IBCM_REJ_POST_BUSY;

	IBCM_REF_CNT_INCR(statep); /* for non-blocking post */
	mutex_exit(&statep->state_mutex);

	ibcm_insert_trace(statep, IBCM_TRACE_OUTGOING_REJ);
	if (ibcm_enable_trace & 2)
		ibcm_dump_conn_trace(statep);
	else
		IBTF_DPRINTF_L2(cmlog, "ibcm_post_rej_mad statep %p "
		    "OUTGOING_REJ", statep);

	ibcm_post_rc_mad(statep, statep->stored_msg, ibcm_post_rej_complete,
	    statep);
}


/*
 * ibcm_build_n_post_rej_mad:
 *	Builds and posts a REJ MAD for "reject_reason"
 *	Doesn't set a timer, and doesn't need statep
 *
 * INPUTS:
 *	input_madp	- Incoming MAD
 *	remote_comid	- Local comid in the message being rejected
 *	cm_mad_addr	- Address information for the MAD to be posted
 *	which_msg	- REJ message type ie., REJ for REQ/REP
 *
 * RETURN VALUE:
 *	NONE
 */
static void
ibcm_build_n_post_rej_mad(uint8_t *input_madp, ib_com_id_t remote_comid,
    ibcm_mad_addr_t *cm_mad_addr, int which_msg, uint16_t reject_reason)
{
	ibcm_rej_msg_t	*rej_msg;
	ibmf_msg_t	*cm_rej_msg;
	ibcm_mad_addr_t	rej_reply_addr;

	IBTF_DPRINTF_L3(cmlog, "ibcm_build_n_post_rej_mad: "
	    "remote_comid: %x reject_reason %d", remote_comid, reject_reason);

	if (ibcm_alloc_out_msg(cm_mad_addr->ibmf_hdl, &cm_rej_msg,
	    MAD_METHOD_SEND) != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_build_n_post_rej_mad: "
		    "ibcm_alloc_out_msg failed");
		return;
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*rej_msg))

	IBCM_OUT_HDRP(cm_rej_msg)->TransactionID =
	    ((ib_mad_hdr_t *)(input_madp))->TransactionID;

	/* Initialize rej_msg fields */
	rej_msg = (ibcm_rej_msg_t *)IBCM_OUT_MSGP(cm_rej_msg);
	rej_msg->rej_local_comm_id = 0;
	rej_msg->rej_remote_comm_id = h2b32(remote_comid);
	rej_msg->rej_msg_type_plus = (which_msg & 0x3) << 6;
	rej_msg->rej_reject_info_len_plus = 0;
	rej_msg->rej_rejection_reason = h2b16(reject_reason);

	IBCM_OUT_HDRP(cm_rej_msg)->AttributeID =
	    h2b16(IBCM_INCOMING_REJ + IBCM_ATTR_BASE_ID);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*rej_msg))

	ibcm_build_reply_mad_addr(cm_mad_addr, &rej_reply_addr);

	if (rej_reply_addr.cm_qp_entry != NULL) {
		(void) ibcm_post_mad(cm_rej_msg, &rej_reply_addr, NULL, NULL);
		ibcm_release_qp(rej_reply_addr.cm_qp_entry);
	}

	(void) ibcm_free_out_msg(cm_mad_addr->ibmf_hdl, &cm_rej_msg);
}

/* posts a REJ for an incoming REQ with unsupported class version */

static void
ibcm_post_rej_ver_mismatch(uint8_t *input_madp, ibcm_mad_addr_t *cm_mad_addr)
{
	ibcm_req_msg_t	*req_msgp =
	    (ibcm_req_msg_t *)&input_madp[IBCM_MAD_HDR_SIZE];
	ibcm_rej_msg_t	*rej_msg;
	ibmf_msg_t	*cm_rej_msg;
	ibcm_mad_addr_t	rej_reply_addr;

	IBTF_DPRINTF_L3(cmlog, "ibcm_post_rej_ver_mismatch: remote comid %x",
	    b2h32(req_msgp->req_local_comm_id));

	if (ibcm_alloc_out_msg(cm_mad_addr->ibmf_hdl, &cm_rej_msg,
	    MAD_METHOD_SEND) != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_post_rej_ver_mismatch: "
		    "ibcm_alloc_out_msg failed");
		return;
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*rej_msg))

	IBCM_OUT_HDRP(cm_rej_msg)->TransactionID =
	    ((ib_mad_hdr_t *)(input_madp))->TransactionID;

	/* Initialize rej_msg fields */
	rej_msg = (ibcm_rej_msg_t *)IBCM_OUT_MSGP(cm_rej_msg);
	rej_msg->rej_local_comm_id = 0;
	rej_msg->rej_remote_comm_id = req_msgp->req_local_comm_id;
	rej_msg->rej_msg_type_plus = IBT_CM_FAILURE_REQ << 6;
	rej_msg->rej_rejection_reason = h2b16(IBT_CM_CLASS_NO_SUPPORT);
	rej_msg->rej_reject_info_len_plus = 1 << 1;
	rej_msg->rej_addl_rej_info[0] = IBCM_MAD_CLASS_VERSION;

	IBCM_OUT_HDRP(cm_rej_msg)->AttributeID =
	    h2b16(IBCM_INCOMING_REJ + IBCM_ATTR_BASE_ID);
	IBCM_OUT_HDRP(cm_rej_msg)->Status = h2b16(MAD_STATUS_BAD_VERSION);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*rej_msg))

	ibcm_build_reply_mad_addr(cm_mad_addr, &rej_reply_addr);
	if (rej_reply_addr.cm_qp_entry != NULL) {
		(void) ibcm_post_mad(cm_rej_msg, &rej_reply_addr, NULL, NULL);
		ibcm_release_qp(rej_reply_addr.cm_qp_entry);
	}
	(void) ibcm_free_out_msg(cm_mad_addr->ibmf_hdl, &cm_rej_msg);
}


/*
 * ibcm_post_rep_mad:
 *	Posts a REP MAD and starts timer
 *
 * INPUTS:
 *	statep		- state pointer
 *
 * RETURN VALUE:
 *	NONE
 */
void
ibcm_post_rep_mad(ibcm_state_data_t *statep)
{
	ibcm_rep_msg_t	*rep_msgp =
	    (ibcm_rep_msg_t *)IBCM_OUT_MSGP(statep->stored_msg);
	ibmf_msg_t	*mra_msg = NULL;
	boolean_t	ret = B_FALSE;

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_rep_mad: statep 0x%p", statep);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*rep_msgp))

	/*
	 * All other REP fields, other that the 2 below, are filled in
	 * the ibcm_cep_state_req() function.
	 */
	rep_msgp->rep_local_comm_id = h2b32(statep->local_comid);
	rep_msgp->rep_remote_comm_id = h2b32(statep->remote_comid);
	IBCM_OUT_HDRP(statep->stored_msg)->AttributeID =
	    h2b16(IBCM_INCOMING_REP + IBCM_ATTR_BASE_ID);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*rep_msgp))

	/*
	 * Changing state and attempt to delete the mra msg must be done
	 * together holding the state_mutex
	 */
	mutex_enter(&statep->state_mutex);

	/* Now, attempt to delete the mra_msg, if there is one allocated */
	if (statep->mra_msg != NULL) {
		if (!(statep->send_mad_flags & IBCM_MRA_POST_BUSY)) {
			mra_msg = statep->mra_msg;
			statep->mra_msg = NULL;
		} else statep->delete_mra_msg = B_TRUE;
	}

	if (statep->abort_flag == IBCM_ABORT_CLIENT) {
		statep->state = IBCM_STATE_ABORTED;
		mutex_exit(&statep->state_mutex);
		ibcm_process_abort(statep);

		/* Now post a REJ MAD, rej reason consumer abort */
		ibcm_post_rej_mad(statep, IBT_CM_CONSUMER, IBT_CM_FAILURE_REQ,
		    NULL, 0);
		ret = B_TRUE;
	} else if (statep->abort_flag & IBCM_ABORT_REJ) {

		statep->state = IBCM_STATE_DELETE;
		mutex_exit(&statep->state_mutex);

		ibcm_process_abort(statep);
		ibcm_delete_state_data(statep);
		ret = B_TRUE;
	} else {

		statep->state = statep->timer_stored_state =
		    IBCM_STATE_REP_SENT;
		statep->remaining_retry_cnt = statep->max_cm_retries;
		statep->send_mad_flags |= IBCM_REP_POST_BUSY;
		IBCM_REF_CNT_INCR(statep);	/* for nonblocking REP Post */
		mutex_exit(&statep->state_mutex);
	}

	if (mra_msg != NULL)
		(void) ibcm_free_out_msg(statep->stored_reply_addr.ibmf_hdl,
		    &mra_msg);
	if (ret == B_TRUE)
		return;

	ibcm_insert_trace(statep, IBCM_TRACE_OUTGOING_REP);

	ibcm_post_rc_mad(statep, statep->stored_msg, ibcm_post_rep_complete,
	    statep);
}


/*
 * ibcm_post_rtu_mad:
 *	From active side post RTU MAD
 *
 * INPUTS:
 *	statep		- state pointer
 *
 * RETURN VALUE: NONE
 *
 * NOTE: No timer set after posting RTU
 */
ibcm_status_t
ibcm_post_rtu_mad(ibcm_state_data_t *statep)
{
	ibcm_rtu_msg_t	*rtu_msg;
	ibmf_msg_t	*mra_msg = NULL;
	boolean_t	ret = B_FALSE;

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_rtu_mad: statep 0x%p", statep);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*rtu_msg))

	rtu_msg = (ibcm_rtu_msg_t *)IBCM_OUT_MSGP(statep->stored_msg);

	rtu_msg->rtu_local_comm_id = h2b32(statep->local_comid);
	rtu_msg->rtu_remote_comm_id = h2b32(statep->remote_comid);
	IBCM_OUT_HDRP(statep->stored_msg)->AttributeID =
	    h2b16(IBCM_INCOMING_RTU + IBCM_ATTR_BASE_ID);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*rtu_msg))

	mutex_enter(&statep->state_mutex);

	/* Now, attempt to delete the mra_msg, if there is one allocated */
	if (statep->mra_msg != NULL) {
		if (!(statep->send_mad_flags & IBCM_MRA_POST_BUSY)) {
			mra_msg = statep->mra_msg;
			statep->mra_msg = NULL;
		} else statep->delete_mra_msg = B_TRUE;
	}

	if (statep->abort_flag == IBCM_ABORT_CLIENT) {
		statep->state = IBCM_STATE_ABORTED;
		mutex_exit(&statep->state_mutex);

		ibcm_process_abort(statep);

		/* Now post a REJ MAD */
		ibcm_post_rej_mad(statep, IBT_CM_CONSUMER, IBT_CM_FAILURE_REP,
		    NULL, 0);
		ret = B_TRUE;
	} else if (statep->abort_flag & IBCM_ABORT_REJ) {
		statep->state = IBCM_STATE_DELETE;
		mutex_exit(&statep->state_mutex);

		ibcm_process_abort(statep);
		ibcm_delete_state_data(statep);
		ret = B_TRUE;
	} else {
		statep->state = IBCM_STATE_ESTABLISHED;
		ibtl_cm_chan_is_open(statep->channel);
		statep->send_mad_flags |= IBCM_RTU_POST_BUSY;
		IBCM_REF_CNT_INCR(statep);	/* for nonblocking RTU post */
		mutex_exit(&statep->state_mutex);
	}

	if (mra_msg != NULL)
		(void) ibcm_free_out_msg(statep->stored_reply_addr.ibmf_hdl,
		    &mra_msg);

	if (ret == B_TRUE)	/* Abort case, no RTU posted */
		return (IBCM_FAILURE);

	ibcm_insert_trace(statep, IBCM_TRACE_OUTGOING_RTU);

	ibcm_post_rc_mad(statep, statep->stored_msg, ibcm_post_rtu_complete,
	    statep);
	return (IBCM_SUCCESS);
}


/*
 * ibcm_process_abort:
 *	Processes abort, if client requested abort connection attempt
 *
 * INPUTS:
 *	statep	- pointer to ibcm_state_data_t is passed
 *
 * RETURN VALUES: None
 */
void
ibcm_process_abort(ibcm_state_data_t *statep)
{
	IBTF_DPRINTF_L3(cmlog, "ibcm_process_abort: statep 0x%p", statep);

	/* move CEP to error state, before calling client handler */
	(void) ibcm_cep_to_error_state(statep);

	/* Now disassociate the link between statep and qp */
	IBCM_SET_CHAN_PRIVATE(statep->channel, NULL);

	/* invoke cm handler, for non-blocking open/close rc channel calls */
	if (statep->cm_handler) { /* cannot be NULL, but still .. */
		ibt_cm_event_t		event;
		ibt_cm_return_args_t	ret_args;

		bzero(&event, sizeof (event));
		bzero(&ret_args, sizeof (ret_args));

		if (statep->abort_flag & IBCM_ABORT_REJ)
			ibcm_handler_conn_fail(statep, IBT_CM_FAILURE_REJ_RCV,
			    IBT_CM_FAILURE_UNKNOWN, IBT_CM_TIMEOUT, NULL, 0);
		else {
			ibcm_path_cache_purge();

			event.cm_type = IBT_CM_EVENT_CONN_CLOSED;
			event.cm_channel = statep->channel;
			event.cm_event.closed = IBT_CM_CLOSED_ABORT;

			ibcm_insert_trace(statep,
			    IBCM_TRACE_CALLED_CONN_CLOSE_EVENT);

			if (statep->channel)
				ibtl_cm_chan_open_is_aborted(statep->channel);

			(void) statep->cm_handler(statep->state_cm_private,
			    &event, &ret_args, NULL, 0);

			ibcm_insert_trace(statep,
			    IBCM_TRACE_RET_CONN_CLOSE_EVENT);

			mutex_enter(&statep->state_mutex);
			ibcm_open_done(statep);
			mutex_exit(&statep->state_mutex);
		}
	}

	/*
	 * Unblock an ibt_open_rc_channel called in a blocking mode, though
	 * it is an unlikely scenario
	 */
	mutex_enter(&statep->state_mutex);

	statep->cm_retries++; /* cause connection trace to be printed */
	statep->open_done = B_TRUE;
	statep->close_done = B_TRUE;
	statep->close_nocb_state = IBCM_FAIL; /* sanity sake */

	if (statep->open_return_data != NULL) {
		/* REJ came first, and then client aborted connection */
		if (statep->abort_flag & IBCM_ABORT_REJ)
			statep->open_return_data->rc_status = IBT_CM_TIMEOUT;
		else statep->open_return_data->rc_status = IBT_CM_ABORT;
	}

	cv_broadcast(&statep->block_client_cv);
	mutex_exit(&statep->state_mutex);
	if (ibcm_enable_trace != 0)
		ibcm_dump_conn_trace(statep);
}

/*
 * ibcm_timeout_cb:
 *	Called when the timer expires
 *
 * INPUTS:
 *	arg	- ibcm_state_data_t is passed
 *
 * RETURN VALUES: NONE
 */
void
ibcm_timeout_cb(void *arg)
{
	ibcm_state_data_t	*statep = (ibcm_state_data_t *)arg;

	mutex_enter(&statep->state_mutex);

	/*
	 * The blocking operations are handled in a separate thread.
	 * All other non-blocking operations, including ibmf non-blocking
	 * posts are done from timeout context
	 */

	if ((statep->timer_stored_state != statep->state) ||
	    ((statep->timer_stored_state == IBCM_STATE_ESTABLISHED) &&
	    (statep->ap_state != statep->timer_stored_ap_state))) {
		mutex_exit(&statep->state_mutex);
		return;
	}

	IBTF_DPRINTF_L3(cmlog, "ibcm_timeout_cb: statep 0x%p state %x "
	    "ap_state %x", statep, statep->state, statep->ap_state);

	/* Processing depends upon current state */

	if (statep->state == IBCM_STATE_REJ_SENT) {
		statep->state = IBCM_STATE_DELETE;
		mutex_exit(&statep->state_mutex);

		/* Deallocate the CM state structure */
		ibcm_delete_state_data(statep);
		return;

	} else if (statep->state == IBCM_STATE_TIMEWAIT) {
		statep->state = IBCM_STATE_DELETE;

		/* TIME_WAIT timer expired, so cleanup */
		mutex_exit(&statep->state_mutex);

		if (statep->channel)
			ibtl_cm_chan_is_closed(statep->channel);

		if (statep->recycle_arg) {
			struct ibcm_taskq_recycle_arg_s *recycle_arg;

			recycle_arg = statep->recycle_arg;

			_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(
			    statep->recycle_arg))
			statep->recycle_arg = NULL;
			_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(statep->recycle_arg))

			/* if possible, do not slow down calling recycle func */
			if (taskq_dispatch(ibcm_taskq, ibcm_process_rc_recycle,
			    recycle_arg, TQ_NOQUEUE | TQ_NOSLEEP) ==
			    TASKQID_INVALID) {

				_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(
				    statep->recycle_arg))
				statep->recycle_arg = recycle_arg;
				_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(
				    statep->recycle_arg))
				ibcm_add_tlist(statep);
				return;
			}
		}

		ibcm_delete_state_data(statep);
		return;
	} else if (statep->remaining_retry_cnt > 0) {
		ibcm_conn_state_t	stored_state;
		ibcm_ap_state_t		stored_ap_state;

		statep->remaining_retry_cnt--;
		IBTF_DPRINTF_L3(cmlog, "ibcm_timeout_cb: statep 0x%p "
		    "attr-id= 0x%x, retries remaining = 0x%x", statep,
		    b2h16(IBCM_OUT_HDRP(statep->stored_msg)->AttributeID),
		    statep->remaining_retry_cnt);

		/*
		 * REP could be resent, either because of timeout or an
		 * incoming REQ. Any other MAD below can be resent, because
		 * of timeout only, hence send_mad_flag manipulation not
		 * required for those cases.
		 * If REP is already being retransmitted, then just set the
		 * timer and return. Else post REP in non-blocking mode
		 */
		if (statep->timer_stored_state == IBCM_STATE_REP_SENT) {
			if (statep->send_mad_flags & IBCM_REP_POST_BUSY) {
				statep->timerid = IBCM_TIMEOUT(statep,
				    statep->timer_value);
				mutex_exit(&statep->state_mutex);
				ibcm_insert_trace(statep,
				    IBCM_TRACE_TIMEOUT_REP);
				return;
			}

			/*
			 * Set REP  busy flag, so any incoming REQ's will not
			 * initiate new REP transmissions
			 */
			statep->send_mad_flags |= IBCM_REP_POST_BUSY;

		/* Since REQ/RTU/REJ on active side use same MAD, synchronize */
		} else if (statep->timer_stored_state == IBCM_STATE_REQ_SENT) {
			ASSERT((statep->send_mad_flags & IBCM_REQ_POST_BUSY)
			    == 0);
			statep->send_mad_flags |= IBCM_REQ_POST_BUSY;
		}

		IBCM_REF_CNT_INCR(statep);	/* for non-blocking post */
		stored_state = statep->timer_stored_state;
		stored_ap_state = statep->timer_stored_ap_state;
		mutex_exit(&statep->state_mutex);

		/* Post REQ MAD in non-blocking mode */
		if (stored_state == IBCM_STATE_REQ_SENT) {
			ibcm_insert_trace(statep, IBCM_TRACE_OUT_REQ_RETRY);
			ibcm_post_rc_mad(statep, statep->stored_msg,
			    ibcm_post_req_complete, statep);
		/* Post REQ MAD in non-blocking mode */
		} else if (stored_state == IBCM_STATE_REP_WAIT) {
			ibcm_insert_trace(statep, IBCM_TRACE_OUT_REQ_RETRY);
			ibcm_post_rc_mad(statep, statep->stored_msg,
			    ibcm_post_rep_wait_complete, statep);
		/* Post REP MAD in non-blocking mode */
		} else if (stored_state == IBCM_STATE_REP_SENT) {
			ibcm_insert_trace(statep, IBCM_TRACE_OUT_REP_RETRY);
			ibcm_post_rc_mad(statep, statep->stored_msg,
			    ibcm_post_rep_complete, statep);
		/* Post REP MAD in non-blocking mode */
		} else if (stored_state == IBCM_STATE_MRA_REP_RCVD) {
			ibcm_insert_trace(statep, IBCM_TRACE_OUT_REP_RETRY);
			mutex_enter(&statep->state_mutex);
			statep->mra_time = gethrtime();
			mutex_exit(&statep->state_mutex);
			ibcm_post_rc_mad(statep, statep->stored_msg,
			    ibcm_post_mra_rep_complete, statep);
		/* Post DREQ MAD in non-blocking mode */
		} else if (stored_state == IBCM_STATE_DREQ_SENT) {
			mutex_enter(&statep->state_mutex);
			if (statep->remaining_retry_cnt ==
			    statep->max_cm_retries)
				ibcm_insert_trace(statep,
				    IBCM_TRACE_OUTGOING_DREQ);
			else {
				ibcm_insert_trace(statep,
				    IBCM_TRACE_OUT_DREQ_RETRY);
				statep->cm_retries++;
				ibcm_close_done(statep, 0);
			}
			mutex_exit(&statep->state_mutex);
			ibcm_post_rc_mad(statep, statep->dreq_msg,
			    ibcm_post_dreq_complete, statep);
		/* post LAP MAD in non-blocking mode */
		} else if (stored_ap_state == IBCM_AP_STATE_LAP_SENT) {
			ibcm_insert_trace(statep, IBCM_TRACE_OUT_LAP_RETRY);
			ibcm_post_rc_mad(statep, statep->lapr_msg,
			    ibcm_post_lap_complete, statep);
		/* post LAP MAD in non-blocking mode */
		} else if (stored_ap_state == IBCM_AP_STATE_MRA_LAP_RCVD) {
			ibcm_insert_trace(statep, IBCM_TRACE_OUT_LAP_RETRY);
			mutex_enter(&statep->state_mutex);
			statep->mra_time = gethrtime();
			mutex_exit(&statep->state_mutex);
			ibcm_post_rc_mad(statep, statep->lapr_msg,
			    ibcm_post_mra_lap_complete, statep);
		}
		return;

	} else if ((statep->state == IBCM_STATE_REQ_SENT) ||
	    (statep->state == IBCM_STATE_REP_SENT) ||
	    (statep->state == IBCM_STATE_MRA_REP_RCVD) ||
	    (statep->state == IBCM_STATE_REP_WAIT)) {

		/*
		 * MAX retries reached, send a REJ to the remote,
		 * and close the connection
		 */
		statep->timedout_state = statep->state;
		statep->state = IBCM_STATE_TIMED_OUT;

		IBTF_DPRINTF_L3(cmlog, "ibcm_timeout_cb: "
		    "max retries done for statep 0x%p", statep);
		statep->cm_retries++; /* cause conn trace to print */
		mutex_exit(&statep->state_mutex);

		if ((statep->timedout_state == IBCM_STATE_REP_SENT) ||
		    (statep->timedout_state == IBCM_STATE_MRA_REP_RCVD))
			(void) ibcm_cep_to_error_state(statep);

		/* Disassociate statep from QP */
		IBCM_SET_CHAN_PRIVATE(statep->channel, NULL);

		/*
		 * statep is in REJ SENT state, the only way to get deleted is
		 * the timeout callback that is set after posting REJ
		 * The thread processing is required where cm handler is
		 * specified
		 */

		if (statep->cm_handler != NULL) {
			/* Attach the statep to timeout list */
			ibcm_add_tlist(statep);
		} else {
			ib_guid_t local_hca_guid;

			mutex_enter(&statep->state_mutex);

			/*
			 * statep->open_return_data is set for blocking
			 * No handler specified, hence signal blocked
			 * ibt_open_rc_channel from here
			 */
			if (statep->open_return_data != NULL) {
				statep->open_return_data->rc_status =
				    IBT_CM_TIMEOUT;
				statep->open_done = B_TRUE;
				cv_broadcast(&statep->block_client_cv);
			}

			mutex_exit(&statep->state_mutex);

			local_hca_guid = h2b64(statep->local_hca_guid);
			ibcm_post_rej_mad(statep, IBT_CM_TIMEOUT,
			    (statep->timedout_state == IBCM_STATE_REP_SENT ||
			    statep->timedout_state == IBCM_STATE_MRA_REP_RCVD) ?
			    IBT_CM_FAILURE_REP: IBT_CM_FAILURE_REQ,
			    &local_hca_guid, sizeof (ib_guid_t));
		}

	} else if ((statep->ap_state == IBCM_AP_STATE_LAP_SENT) ||
	    (statep->ap_state == IBCM_AP_STATE_MRA_LAP_RCVD)) {

		IBTF_DPRINTF_L4(cmlog, "ibcm_timeout_cb: statep 0x%p "
		    "LAP timed out",  statep);
		statep->timedout_state = statep->state;
		/*
		 * This state setting ensures that the processing of DREQ is
		 * sequentialized, once this ap_state is set. If statep is
		 * attached to timeout list, it cannot be re-attached as long
		 * as in this state
		 */
		statep->ap_state = IBCM_AP_STATE_TIMED_OUT;
		ibcm_open_done(statep);

		if (statep->cm_handler != NULL) {
			/* Attach statep to timeout list - thread handling */
			ibcm_add_tlist(statep);
		} else if (statep->ap_return_data != NULL) {
			/*
			 * statep->ap_return_data is initialized for blocking in
			 * ibt_set_alt_path(), signal the waiting CV
			 */
			statep->ap_return_data->ap_status = IBT_CM_AP_TIMEOUT;
			statep->ap_done = B_TRUE;
			cv_broadcast(&statep->block_client_cv);

			statep->ap_state = IBCM_AP_STATE_IDLE;
			/* Wake up threads waiting for LAP/APR to complete */
			cv_broadcast(&statep->block_mad_cv);
		}
		mutex_exit(&statep->state_mutex);

	} else if (statep->state == IBCM_STATE_DREQ_SENT) {

		statep->timedout_state = statep->state;
		statep->state = IBCM_STATE_TIMED_OUT;

		/*
		 * The logic below is necessary, for a race situation between
		 * ibt_close_rc_channel with no callbacks option and CM's
		 * internal stale connection handling on the same connection
		 */
		if (statep->close_nocb_state != IBCM_FAIL) {
			ASSERT(statep->close_nocb_state == IBCM_UNBLOCK);
			ibtl_cm_chan_is_closing(statep->channel);
			statep->close_nocb_state = IBCM_BLOCK;
		}

		mutex_exit(&statep->state_mutex);

		/*
		 * If cm handler is specified, then invoke handler for
		 * the DREQ timeout
		 */
		if (statep->cm_handler != NULL) {
			ibcm_add_tlist(statep);
			return;
		}

		ibcm_process_dreq_timeout(statep);
	} else {

#ifdef DEBUG
		if (ibcm_test_mode > 0)
			IBTF_DPRINTF_L2(cmlog, "ibcm_timeout_cb: "
			    "Unexpected unhandled timeout  for statep 0x%p "
			    "state %d", statep, statep->state);
#endif
		mutex_exit(&statep->state_mutex);
	}
}

/*
 * Following are set of ibmf send callback routines that are used when posting
 * various CM MADs in non-blocking post mode
 */

/*ARGSUSED*/
void
ibcm_post_req_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp, void *args)
{
	ibcm_state_data_t	*statep = (ibcm_state_data_t *)args;

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_req_complete statep %p ", statep);

	mutex_enter(&statep->state_mutex);
	ibcm_flow_dec(statep->post_time, "REQ");
	ibcm_insert_trace(statep, IBCM_TRACE_REQ_POST_COMPLETE);

	statep->send_mad_flags &= ~IBCM_REQ_POST_BUSY;

	/* signal any waiting threads for REQ MAD to become available */
	cv_signal(&statep->block_mad_cv);

	if (statep->state == IBCM_STATE_REQ_SENT)
		statep->timerid = IBCM_TIMEOUT(statep, statep->timer_value);

	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}

/*ARGSUSED*/
void
ibcm_post_rep_wait_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args)
{
	ibcm_state_data_t	*statep = (ibcm_state_data_t *)args;

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_rep_wait_complete statep %p", statep);

	mutex_enter(&statep->state_mutex);
	ibcm_flow_dec(statep->post_time, "REQ_RETRY");
	ibcm_insert_trace(statep, IBCM_TRACE_REQ_POST_COMPLETE);
	if (statep->state == IBCM_STATE_REP_WAIT)
		statep->timerid = IBCM_TIMEOUT(statep, statep->timer_value);
	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}

/*ARGSUSED*/
void
ibcm_post_rep_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp, void *args)
{
	ibcm_state_data_t	*statep = (ibcm_state_data_t *)args;

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_rep_complete statep %p", statep);

	mutex_enter(&statep->state_mutex);
	ibcm_flow_dec(statep->post_time, "REP");
	ibcm_insert_trace(statep, IBCM_TRACE_REP_POST_COMPLETE);
	statep->send_mad_flags &= ~IBCM_REP_POST_BUSY;
	if (statep->state == IBCM_STATE_REP_SENT)
		statep->timerid = IBCM_TIMEOUT(statep, statep->timer_value);
	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}

/*ARGSUSED*/
void
ibcm_resend_post_rep_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args)
{
	ibcm_state_data_t	*statep = (ibcm_state_data_t *)args;

	IBTF_DPRINTF_L4(cmlog, "ibcm_resend_post_rep_complete(%p)", statep);

	mutex_enter(&statep->state_mutex);
	ibcm_flow_dec(statep->post_time, "REP_RETRY");
	ibcm_insert_trace(statep, IBCM_TRACE_REP_POST_COMPLETE);
	statep->send_mad_flags &= ~IBCM_REP_POST_BUSY;

	/* No new timeout is set for resending a REP MAD for an incoming REQ */
	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}

/*ARGSUSED*/
void
ibcm_post_mra_rep_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args)
{
	ibcm_state_data_t	*statep = (ibcm_state_data_t *)args;

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_mra_rep_complete statep %p", statep);

	mutex_enter(&statep->state_mutex);
	ibcm_flow_dec(statep->mra_time, "MRA_REP");
	ibcm_insert_trace(statep, IBCM_TRACE_REP_POST_COMPLETE);
	if (statep->state == IBCM_STATE_MRA_REP_RCVD)
		statep->timerid = IBCM_TIMEOUT(statep, statep->timer_value);
	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}


/*ARGSUSED*/
void
ibcm_post_mra_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args)
{
	ibcm_state_data_t	*statep = (ibcm_state_data_t *)args;

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_mra_complete statep %p", statep);

	mutex_enter(&statep->state_mutex);
	ibcm_flow_dec(statep->mra_time, "MRA");
	ibcm_insert_trace(statep, IBCM_TRACE_MRA_POST_COMPLETE);

	if (statep->delete_mra_msg == B_TRUE) {
		ibmf_msg_t	*mra_msg;

		mra_msg = statep->mra_msg;
		statep->mra_msg = NULL;
		mutex_exit(&statep->state_mutex);
		(void) ibcm_free_out_msg(statep->stored_reply_addr.ibmf_hdl,
		    &mra_msg);
		mutex_enter(&statep->state_mutex);
	}
	statep->send_mad_flags &= ~IBCM_MRA_POST_BUSY;
	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}

/*ARGSUSED*/
void
ibcm_post_dreq_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp, void *args)
{
	ibcm_state_data_t	*statep = (ibcm_state_data_t *)args;

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_dreq_complete statep %p", statep);

	mutex_enter(&statep->state_mutex);
	ibcm_flow_dec(statep->post_time, "DREQ");
	ibcm_insert_trace(statep, IBCM_TRACE_DREQ_POST_COMPLETE);
	if (statep->state == IBCM_STATE_DREQ_SENT)
		statep->timerid = IBCM_TIMEOUT(statep, statep->timer_value);
	ibcm_close_done(statep, 1);
	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}

/*ARGSUSED*/
void
ibcm_post_lap_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp, void *args)
{
	ibcm_state_data_t	*statep = (ibcm_state_data_t *)args;

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_lap_complete statep %p", statep);

	mutex_enter(&statep->state_mutex);
	ibcm_flow_dec(statep->post_time, "LAP");
	ibcm_insert_trace(statep, IBCM_TRACE_LAP_POST_COMPLETE);
	if (statep->ap_state == IBCM_AP_STATE_LAP_SENT)
		statep->timerid = IBCM_TIMEOUT(statep, statep->timer_value);
	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}

/*ARGSUSED*/
void
ibcm_post_mra_lap_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args)
{
	ibcm_state_data_t	*statep = (ibcm_state_data_t *)args;

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_mra_lap_complete statep %p", statep);

	mutex_enter(&statep->state_mutex);
	ibcm_flow_dec(statep->mra_time, "MRA_LAP");
	ibcm_insert_trace(statep, IBCM_TRACE_LAP_POST_COMPLETE);
	if (statep->ap_state == IBCM_AP_STATE_MRA_LAP_RCVD)
		statep->timerid = IBCM_TIMEOUT(statep, statep->timer_value);
	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}

/*ARGSUSED*/
void
ibcm_post_rej_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args)
{
	ibcm_state_data_t	*statep = (ibcm_state_data_t *)args;

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_rej_complete statep %p", statep);

	mutex_enter(&statep->state_mutex);
	ibcm_flow_dec(statep->post_time, "REJ");
	ibcm_insert_trace(statep, IBCM_TRACE_REJ_POST_COMPLETE);
	statep->send_mad_flags &= ~IBCM_REJ_POST_BUSY;
	if (statep->state == IBCM_STATE_REJ_SENT) {
		statep->remaining_retry_cnt = 0;

		/* wait until all possible retransmits of REQ/REP happened */
		statep->timerid = IBCM_TIMEOUT(statep,
		    statep->timer_value * statep->max_cm_retries);
	}

	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}

/*ARGSUSED*/
void
ibcm_post_rtu_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args)
{
	ibcm_state_data_t	*statep = (ibcm_state_data_t *)args;

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_rtu_complete statep %p", statep);

	mutex_enter(&statep->state_mutex);
	ibcm_flow_dec(statep->post_time, "RTU");
	ibcm_insert_trace(statep, IBCM_TRACE_RTU_POST_COMPLETE);
	statep->send_mad_flags &= ~IBCM_RTU_POST_BUSY;
	IBCM_REF_CNT_DECR(statep);
	ibcm_open_done(statep);
	mutex_exit(&statep->state_mutex);
}

/*ARGSUSED*/
void
ibcm_post_apr_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args)
{
	ibcm_state_data_t	*statep = (ibcm_state_data_t *)args;

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_apr_complete statep %p", statep);

	mutex_enter(&statep->state_mutex);
	ibcm_flow_dec(statep->post_time, "APR");
	ibcm_insert_trace(statep, IBCM_TRACE_APR_POST_COMPLETE);
	/* As long as one APR mad in transit, no retransmits are allowed */
	statep->ap_state = IBCM_AP_STATE_IDLE;

	/* unblock any DREQ threads and close channels */
	cv_broadcast(&statep->block_mad_cv);
	IBCM_REF_CNT_DECR(statep); /* decrement the ref count */
	mutex_exit(&statep->state_mutex);

}

/*ARGSUSED*/
void
ibcm_post_stored_apr_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args)
{
	ibmf_msg_t	*ibmf_apr_msg = (ibmf_msg_t *)args;

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_stored_apr_complete args %p", args);

	ibcm_flow_dec(0, "APR_RESEND");
	(void) ibcm_free_out_msg(ibmf_handle, &ibmf_apr_msg);
}

/*ARGSUSED*/
void
ibcm_post_drep_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args)
{
	ibcm_state_data_t	*statep = (ibcm_state_data_t *)args;

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_drep_complete statep %p", statep);

	mutex_enter(&statep->state_mutex);
	ibcm_flow_dec(statep->post_time, "DREP");
	ibcm_insert_trace(statep, IBCM_TRACE_DREP_POST_COMPLETE);
	statep->send_mad_flags &= ~IBCM_REJ_POST_BUSY;

	if (statep->state == IBCM_STATE_DREQ_RCVD) {

		ibcm_close_done(statep, 1);
		statep->state = IBCM_STATE_TIMEWAIT;

		/*
		 * For passive side CM set it to remote_ack_delay
		 * For active side CM add the pkt_life_time * 2
		 */
		statep->timer_value = statep->remote_ack_delay;
		if (statep->mode == IBCM_ACTIVE_MODE)
			statep->timer_value += (2 * statep->pkt_life_time);
		statep->remaining_retry_cnt = 0;
		statep->timer_stored_state = statep->state;
		statep->timerid = IBCM_TIMEOUT(statep, statep->timer_value);
	}

	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}

/*ARGSUSED*/
void
ibcm_post_sidr_rep_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args)
{
	ibcm_ud_state_data_t	*ud_statep = (ibcm_ud_state_data_t *)args;

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_sidr_rep_complete ud_statep %p",
	    ud_statep);

	ibcm_flow_dec(0, "SIDR_REP");
	mutex_enter(&ud_statep->ud_state_mutex);
	ud_statep->ud_send_mad_flags &= ~IBCM_SREP_POST_BUSY;
	ud_statep->ud_remaining_retry_cnt = 0;
	if (ud_statep->ud_state == IBCM_STATE_SIDR_REP_SENT)
		ud_statep->ud_timerid = IBCM_UD_TIMEOUT(ud_statep,
		    ud_statep->ud_timer_value);
	IBCM_UD_REF_CNT_DECR(ud_statep);
	mutex_exit(&ud_statep->ud_state_mutex);

}

/*ARGSUSED*/
void
ibcm_post_sidr_req_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args)
{
	ibcm_ud_state_data_t	*ud_statep = (ibcm_ud_state_data_t *)args;

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_sidr_req_complete ud_statep %p",
	    ud_statep);

	ibcm_flow_dec(0, "SIDR_REQ");
	mutex_enter(&ud_statep->ud_state_mutex);
	if (ud_statep->ud_state == IBCM_STATE_SIDR_REQ_SENT)
		ud_statep->ud_timerid = IBCM_UD_TIMEOUT(ud_statep,
		    ud_statep->ud_timer_value);
	IBCM_UD_REF_CNT_DECR(ud_statep);
	mutex_exit(&ud_statep->ud_state_mutex);

}

/*
 * ibcm_process_dreq_timeout:
 *	Called when the timer expires on DREP
 *
 * INPUTS:
 *	arg	- ibcm_state_data_t is passed
 *
 * RETURN VALUES: NONE
 */
void
ibcm_process_dreq_timeout(ibcm_state_data_t *statep)
{
	mutex_enter(&statep->state_mutex);

	/* Max retries reached, move to the time wait state */
	statep->state = statep->timer_stored_state =
	    IBCM_STATE_TIMEWAIT;
	ibcm_close_done(statep, 0);

	/* Set the TIME_WAIT state timer value */
	statep->timer_value = statep->remote_ack_delay;
	if (statep->mode == IBCM_ACTIVE_MODE) {
		statep->timer_value += (2 * statep->pkt_life_time);
	}

	statep->timerid = IBCM_TIMEOUT(statep, statep->timer_value);

	if (statep->close_ret_status)
		if (statep->stale == B_TRUE)
			*statep->close_ret_status = IBT_CM_CLOSED_STALE;
		else *statep->close_ret_status = IBT_CM_CLOSED_DREQ_TIMEOUT;

	/* signal waiting CVs - blocking in ibt_close_channel() */
	statep->close_done = B_TRUE;
	if (statep->close_ret_priv_data_len != NULL)
		*statep->close_ret_priv_data_len = 0;

	/* unblock any close channel with no callbacks option */
	statep->close_nocb_state = IBCM_FAIL;

	cv_broadcast(&statep->block_client_cv);
	mutex_exit(&statep->state_mutex);
}

/*
 * ibcm_add_tlist:
 *	Adds the given RC statep to timeout list
 *
 * INPUTS:
 *	arg	- ibcm_state_data_t is passed
 *
 * RETURN VALUES: NONE
 */
void
ibcm_add_tlist(ibcm_state_data_t *statep)
{
	mutex_enter(&ibcm_timeout_list_lock);

	statep->timeout_next = NULL;
	if (ibcm_timeout_list_hdr == NULL) {
		ibcm_timeout_list_hdr = statep;
	} else {
		ibcm_timeout_list_tail->timeout_next = statep;
	}

	ibcm_timeout_list_tail = statep;

	cv_signal(&ibcm_timeout_list_cv);

	mutex_exit(&ibcm_timeout_list_lock);
	IBTF_DPRINTF_L3(cmlog, "ibcm_add_tlist: "
	    "attached state = %p to timeout list", statep);
}

void
ibcm_run_tlist_thread(void)
{
	mutex_enter(&ibcm_timeout_list_lock);
	cv_signal(&ibcm_timeout_list_cv);
	mutex_exit(&ibcm_timeout_list_lock);
}

/*
 * ibcm_add_ud_tlist:
 *	Adds the given UD statep to timeout list
 *
 * INPUTS:
 *	arg	- ibcm_ud_state_data_t is passed
 *
 * RETURN VALUES: NONE
 */
void
ibcm_add_ud_tlist(ibcm_ud_state_data_t *ud_statep)
{
	mutex_enter(&ibcm_timeout_list_lock);

	ud_statep->ud_timeout_next = NULL;
	if (ibcm_ud_timeout_list_hdr == NULL) {
		ibcm_ud_timeout_list_hdr = ud_statep;
	} else {
		ibcm_ud_timeout_list_tail->ud_timeout_next = ud_statep;
	}

	ibcm_ud_timeout_list_tail = ud_statep;

	cv_signal(&ibcm_timeout_list_cv);

	mutex_exit(&ibcm_timeout_list_lock);
	IBTF_DPRINTF_L3(cmlog, "ibcm_add_ud_tlist: "
	    "attached state = %p to ud timeout list", ud_statep);
}

/*
 * ibcm_process_tlist:
 *	Thread that processes all the RC and UD statep's from
 *	the appropriate lists
 *
 * INPUTS:
 *	NONE
 *
 * RETURN VALUES: NONE
 */
void
ibcm_process_tlist()
{
	ibcm_state_data_t	*statep;
	ibcm_ud_state_data_t	*ud_statep;
	callb_cpr_t		cprinfo;

	IBTF_DPRINTF_L5(cmlog, "ibcm_process_tlist: thread started");

	mutex_enter(&ibcm_timeout_list_lock);

	CALLB_CPR_INIT(&cprinfo, &ibcm_timeout_list_lock, callb_generic_cpr,
	    "ibcm_process_tlist");

	for (;;) {
		if (ibcm_timeout_list_flags & IBCM_TIMEOUT_THREAD_EXIT) {
			/* The thread needs to exit */
			cv_signal(&ibcm_timeout_thread_done_cv);
			break;
		}
		mutex_exit(&ibcm_timeout_list_lock);
		ibcm_check_for_opens();
		ibcm_check_for_async_close();
		mutex_enter(&ibcm_timeout_list_lock);

		/* First, handle pending RC statep's, followed by UD's */
		if (ibcm_timeout_list_hdr != NULL) {
			statep = ibcm_timeout_list_hdr;
			ibcm_timeout_list_hdr = statep->timeout_next;

			if (ibcm_timeout_list_hdr == NULL)
				ibcm_timeout_list_tail = NULL;

			statep->timeout_next = NULL;

			mutex_exit(&ibcm_timeout_list_lock);
			IBTF_DPRINTF_L3(cmlog, "ibcm_process_tlist: "
			    "scheduling state = %p", statep);
			ibcm_timeout_client_cb(statep);
			mutex_enter(&ibcm_timeout_list_lock);
		} else if (ibcm_ud_timeout_list_hdr != NULL) {
			ud_statep = ibcm_ud_timeout_list_hdr;
			ibcm_ud_timeout_list_hdr = ud_statep->ud_timeout_next;

			if (ibcm_ud_timeout_list_hdr == NULL)
				ibcm_ud_timeout_list_tail = NULL;

			ud_statep->ud_timeout_next = NULL;

			mutex_exit(&ibcm_timeout_list_lock);
			IBTF_DPRINTF_L3(cmlog, "ibcm_process_tlist: "
			    "ud scheduling state = %p", ud_statep);
			ibcm_ud_timeout_client_cb(ud_statep);
			mutex_enter(&ibcm_timeout_list_lock);
		} else {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&ibcm_timeout_list_cv, &ibcm_timeout_list_lock);
			CALLB_CPR_SAFE_END(&cprinfo, &ibcm_timeout_list_lock);
		}
	}

#ifndef	__lock_lint
	CALLB_CPR_EXIT(&cprinfo);	/* mutex_exit */
#endif
}


/*
 * ibcm_timeout_client_cb:
 *	Called from timeout thread processing
 *	Primary purpose is to call client handler
 *
 * INPUTS:
 *	arg	- ibcm_state_data_t is passed
 *
 * RETURN VALUES: NONE
 */
void
ibcm_timeout_client_cb(ibcm_state_data_t *statep)
{
	mutex_enter(&statep->state_mutex);

	if ((statep->state == IBCM_STATE_DELETE) &&
	    (statep->recycle_arg != NULL)) {
		struct ibcm_taskq_recycle_arg_s *recycle_arg;

		recycle_arg = statep->recycle_arg;
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(statep->recycle_arg))
		statep->recycle_arg = NULL;
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(statep->recycle_arg))
		mutex_exit(&statep->state_mutex);
		(void) ibcm_process_rc_recycle(recycle_arg);
		ibcm_delete_state_data(statep);
		return;
	}

	if ((statep->state == IBCM_STATE_DELETE) &&
	    (statep->delete_state_data == B_TRUE)) {
		mutex_exit(&statep->state_mutex);
		ibcm_dealloc_state_data(statep);
		return;
	}

	/* Else, it must be in TIMEOUT state, do the necessary processing */
	if (statep->state == IBCM_STATE_TIMED_OUT) {
		void		*data;
		uint8_t		cf_msg;
		ib_guid_t	local_hca_guid;

		mutex_exit(&statep->state_mutex);

		if (statep->timedout_state == IBCM_STATE_DREQ_SENT) {
			ibt_cm_event_t		event;
			ibt_cm_return_args_t	ret_args;

			bzero(&event, sizeof (event));
			bzero(&ret_args, sizeof (ret_args));

			event.cm_type = IBT_CM_EVENT_CONN_CLOSED;
			event.cm_channel = statep->channel;
			event.cm_session_id = NULL;
			event.cm_priv_data = NULL;
			event.cm_priv_data_len = 0;

			if (statep->stale == B_TRUE)
				event.cm_event.closed = IBT_CM_CLOSED_STALE;
			else event.cm_event.closed = IBT_CM_CLOSED_DREQ_TIMEOUT;

			/*
			 * cm handler cannot be non-NULL, as that check is
			 * already made in ibcm_timeout_cb
			 */
			ibcm_insert_trace(statep,
			    IBCM_TRACE_CALLED_CONN_CLOSE_EVENT);

			(void) statep->cm_handler(statep->state_cm_private,
			    &event, &ret_args, NULL, 0);

			ibcm_insert_trace(statep,
			    IBCM_TRACE_RET_CONN_CLOSE_EVENT);

			ibcm_process_dreq_timeout(statep);
			return;
		}

		data = ((ibcm_rej_msg_t *)
		    IBCM_OUT_MSGP(statep->stored_msg))->rej_private_data;

		if ((statep->timedout_state == IBCM_STATE_REQ_SENT) ||
		    (statep->timedout_state == IBCM_STATE_REP_WAIT)) {
			cf_msg = IBT_CM_FAILURE_REQ;
		} else {
			ASSERT(
			    (statep->timedout_state == IBCM_STATE_REP_SENT) ||
			    (statep->timedout_state ==
			    IBCM_STATE_MRA_REP_RCVD));
			cf_msg = IBT_CM_FAILURE_REP;
		}

		/*
		 * Invoke the CM handler w/ event IBT_CM_EVENT_TIMEOUT
		 * This callback happens for only active non blocking or
		 * passive client
		 */
		ibcm_handler_conn_fail(statep, IBT_CM_FAILURE_TIMEOUT,
		    cf_msg, IBT_CM_TIMEOUT, data, IBT_REJ_PRIV_DATA_SZ);

		/* signal the blocked ibt_open_rc_channel */
		mutex_enter(&statep->state_mutex);

		/*
		 * statep->open_return_data is set for blocking
		 * signal the blocked ibt_open_rc_channel
		 */
		if (statep->open_return_data != NULL) {
			statep->open_return_data->rc_status = IBT_CM_TIMEOUT;
			statep->open_done = B_TRUE;
			cv_broadcast(&statep->block_client_cv);
		}

		mutex_exit(&statep->state_mutex);

		local_hca_guid = h2b64(statep->local_hca_guid);
		ibcm_post_rej_mad(statep, IBT_CM_TIMEOUT,
		    IBT_CM_FAILURE_UNKNOWN, &local_hca_guid,
		    sizeof (ib_guid_t));
	} else if (statep->ap_state == IBCM_AP_STATE_TIMED_OUT) {

		mutex_exit(&statep->state_mutex);

		ibcm_handler_conn_fail(statep, IBT_CM_FAILURE_TIMEOUT,
		    IBT_CM_FAILURE_LAP, IBT_CM_TIMEOUT, NULL, 0);

		/* Now wake up threads waiting for LAP/APR to complete */
		mutex_enter(&statep->state_mutex);
		/*
		 * statep->ap_return_data is initialized for blocking in
		 * ibt_set_alt_path(), signal the waiting CV
		 */
		if (statep->ap_return_data != NULL) {
			statep->ap_return_data->ap_status = IBT_CM_AP_TIMEOUT;
			statep->ap_done = B_TRUE;
			cv_broadcast(&statep->block_client_cv);
		}
		statep->ap_state = IBCM_AP_STATE_IDLE;
		cv_broadcast(&statep->block_mad_cv);
		mutex_exit(&statep->state_mutex);
	} else {
		IBTF_DPRINTF_L2(cmlog, "ibcm_timeout_client_cb "
		    "Unexpected else path statep %p state %d ap_state %d",
		    statep, statep->state, statep->ap_state);
		mutex_exit(&statep->state_mutex);

	}
}

/*
 * ibcm_ud_timeout_client_cb:
 *	Called from UD timeout thread processing
 *	Primary purpose is to call client handler
 *
 * INPUTS:
 *	arg	- ibcm_ud_state_data_t is passed
 *
 * RETURN VALUES: NONE
 */
void
ibcm_ud_timeout_client_cb(ibcm_ud_state_data_t *ud_statep)
{
	ibt_cm_ud_event_t	ud_event;

	mutex_enter(&ud_statep->ud_state_mutex);

	if ((ud_statep->ud_state == IBCM_STATE_DELETE) &&
	    (ud_statep->ud_delete_state_data == B_TRUE)) {

		mutex_exit(&ud_statep->ud_state_mutex);
		ibcm_dealloc_ud_state_data(ud_statep);
		return;
	} else
		mutex_exit(&ud_statep->ud_state_mutex);

	/* Fill in ibt_cm_ud_event_t */
	ud_event.cm_type = IBT_CM_UD_EVENT_SIDR_REP;
	ud_event.cm_session_id = NULL;
	ud_event.cm_event.sidr_rep.srep_status = IBT_CM_SREP_TIMEOUT;

	(void) ud_statep->ud_cm_handler(ud_statep->ud_state_cm_private,
	    &ud_event, NULL, NULL, 0);

	/* Delete UD state data now, finally done with it */
	ibcm_delete_ud_state_data(ud_statep);
}


/*
 * ibcm_process_sidr_req_msg:
 *	This call processes an incoming SIDR REQ
 *
 * INPUTS:
 *	hcap		- HCA entry pointer
 *	input_madp	- Incoming CM SIDR REQ MAD
 *	cm_mad_addr	- Address information for the MAD to be posted
 *
 * RETURN VALUE:
 *	NONE
 */
void
ibcm_process_sidr_req_msg(ibcm_hca_info_t *hcap, uint8_t *input_madp,
    ibcm_mad_addr_t *cm_mad_addr)
{
	ib_gid_t		gid;
	ib_lid_t		lid;
	uint32_t		req_id;
	ibcm_status_t		state_lookup_status;
	ibcm_status_t		cm_status;
	ibt_sidr_status_t	sidr_status;
	ibcm_svc_info_t		*svc_infop;
	ibcm_svc_bind_t		*svc_bindp;
	ibcm_svc_bind_t		*tmp_bindp;
	ibcm_sidr_req_msg_t	*sidr_reqp = (ibcm_sidr_req_msg_t *)
	    (&input_madp[IBCM_MAD_HDR_SIZE]);
	ibcm_ud_state_data_t	*ud_statep = NULL;
	ibcm_sidr_srch_t	srch_sidr;
	ib_pkey_t		pkey;
	uint8_t			port_num;
	ib_guid_t		hca_guid;

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_sidr_req_msg:");

	hca_guid = hcap->hca_guid;
	port_num = cm_mad_addr->port_num;

	/* Figure out LID, GID, RequestId for svc_id lookup */
	lid = cm_mad_addr->rcvd_addr.ia_remote_lid;
	req_id = b2h32(sidr_reqp->sidr_req_request_id);
	pkey = b2h16(sidr_reqp->sidr_req_pkey);
	if (cm_mad_addr->grh_exists == B_TRUE)
		gid = cm_mad_addr->grh_hdr.ig_sender_gid;
	else
		gid.gid_prefix = gid.gid_guid = 0;

	/*
	 * Lookup for an existing state structure
	 * - if lookup fails it creates a new ud_state struct
	 * No need to hold a lock across the call to ibcm_find_sidr_entry() as
	 * the list lock is held in that function to find the matching entry.
	 */

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(srch_sidr))

	srch_sidr.srch_lid = lid;
	srch_sidr.srch_gid = gid;
	srch_sidr.srch_grh_exists = cm_mad_addr->grh_exists;
	srch_sidr.srch_req_id = req_id;
	srch_sidr.srch_mode = IBCM_PASSIVE_MODE;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(srch_sidr))

	rw_enter(&hcap->hca_sidr_list_lock, RW_WRITER);
	state_lookup_status = ibcm_find_sidr_entry(&srch_sidr, hcap, &ud_statep,
	    IBCM_FLAG_LOOKUP_AND_ADD);
	rw_exit(&hcap->hca_sidr_list_lock);

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_sidr_req_msg: ud_statep 0x%p "
	    "lookup status %x", ud_statep, state_lookup_status);

	if (state_lookup_status == IBCM_LOOKUP_NEW) {

		/* Increment hca's resource count */
		ibcm_inc_hca_res_cnt(hcap);

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ud_statep))

		/*
		 * Allocate CM MAD for a response
		 * This MAD is deallocated on state structure delete
		 * and re-used for all outgoing MADs for this connection.
		 * If MAD allocation fails, delete the ud statep
		 */
		if (ibcm_alloc_out_msg(cm_mad_addr->ibmf_hdl,
		    &ud_statep->ud_stored_msg, MAD_METHOD_SEND) !=
		    IBT_SUCCESS) {
			mutex_enter(&ud_statep->ud_state_mutex);
			IBCM_UD_REF_CNT_DECR(ud_statep);
			mutex_exit(&ud_statep->ud_state_mutex);
			ibcm_delete_ud_state_data(ud_statep);
			return;
		}

		/* Lookup for service */
		ud_statep->ud_svc_id = b2h64(sidr_reqp->sidr_req_service_id);
		ud_statep->ud_state  = IBCM_STATE_SIDR_REQ_RCVD;
		ud_statep->ud_clnt_proceed = IBCM_BLOCK;

		mutex_enter(&ibcm_svc_info_lock);

		svc_infop = ibcm_find_svc_entry(ud_statep->ud_svc_id);

		IBTF_DPRINTF_L4(cmlog, "ibcm_process_sidr_req_msg: "
		    " ud_statep 0x%p svc_info %p", ud_statep, svc_infop);

		/*
		 * No need to hold the ud state mutex, as no other thread
		 * modifies ud statep in IBCM_STATE_SIDR_REQ_RCVD state
		 */

		if (svc_infop != NULL) {
			/* find the "bind" entry that enables this port */

			svc_bindp = NULL;
			tmp_bindp = svc_infop->svc_bind_list;
			while (tmp_bindp) {
				if (tmp_bindp->sbind_hcaguid == hca_guid &&
				    tmp_bindp->sbind_port == port_num) {
					if (gid.gid_guid ==
					    tmp_bindp->sbind_gid.gid_guid &&
					    gid.gid_prefix ==
					    tmp_bindp->sbind_gid.gid_prefix) {
						/* a really good match */
						svc_bindp = tmp_bindp;
						if (pkey ==
						    tmp_bindp->sbind_pkey)
							/* absolute best */
							break;
					} else if (svc_bindp == NULL) {
						/* port match => a good match */
						svc_bindp = tmp_bindp;
					}
				}
				tmp_bindp = tmp_bindp->sbind_link;
			}
			if (svc_bindp == NULL) {
				svc_infop = NULL;
			}
		}

		IBCM_OUT_HDRP(ud_statep->ud_stored_msg)->TransactionID =
		    ((ib_mad_hdr_t *)(input_madp))->TransactionID;

		ibcm_build_reply_mad_addr(cm_mad_addr,
		    &ud_statep->ud_stored_reply_addr);

		if (ud_statep->ud_stored_reply_addr.cm_qp_entry == NULL) {

			mutex_exit(&ibcm_svc_info_lock);

			/* Not much choice. CM MADs cannot go on QP1 */
			mutex_enter(&ud_statep->ud_state_mutex);
			IBCM_UD_REF_CNT_DECR(ud_statep);
			ud_statep->ud_state = IBCM_STATE_DELETE;
			mutex_exit(&ud_statep->ud_state_mutex);

			ibcm_delete_ud_state_data(ud_statep);
			return;
		}

		if (svc_infop == NULL || svc_infop->svc_ud_handler == NULL) {
			/*
			 * Don't have a record of Service ID in CM's
			 * internal list registered at this gid/lid.
			 * So, send out Service ID not supported SIDR REP msg
			 */
			sidr_status = IBT_CM_SREP_SID_INVALID;
		} else {
			ud_statep->ud_cm_handler = svc_infop->svc_ud_handler;
			ud_statep->ud_state_cm_private =
			    svc_bindp->sbind_cm_private;
			IBCM_SVC_INCR(svc_infop);
			mutex_exit(&ibcm_svc_info_lock);

			/* Call Client's UD handler */
			cm_status = ibcm_sidr_req_ud_handler(ud_statep,
			    sidr_reqp, cm_mad_addr, &sidr_status);

			mutex_enter(&ibcm_svc_info_lock);
			IBCM_SVC_DECR(svc_infop);
		}

		mutex_exit(&ibcm_svc_info_lock);

		if (cm_status == IBCM_DEFER) {
			IBTF_DPRINTF_L4(cmlog, "ibcm_process_sidr_req_msg: "
			    "ud_statep 0x%p client returned DEFER response",
			    ud_statep);
			return;
		}

		ibcm_post_sidr_rep_mad(ud_statep, sidr_status);

		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*ud_statep))

		mutex_enter(&ud_statep->ud_state_mutex);
		IBCM_UD_REF_CNT_DECR(ud_statep);
		mutex_exit(&ud_statep->ud_state_mutex);
	} else {
		ASSERT(state_lookup_status == IBCM_LOOKUP_EXISTS);

		mutex_enter(&ud_statep->ud_state_mutex);

		if (ud_statep->ud_state == IBCM_STATE_SIDR_REP_SENT)
			ibcm_resend_srep_mad(ud_statep);

		IBCM_UD_REF_CNT_DECR(ud_statep);
		mutex_exit(&ud_statep->ud_state_mutex);
	}
}


/*
 * ibcm_process_sidr_rep_msg:
 *	This call processes an incoming SIDR REP
 *
 * INPUTS:
 *	hcap		- HCA entry pointer
 *	input_madp	- incoming CM SIDR REP MAD
 *	cm_mad_addr	- Address information for the MAD to be posted
 *
 * RETURN VALUE:
 *	NONE
 */
void
ibcm_process_sidr_rep_msg(ibcm_hca_info_t *hcap, uint8_t *input_madp,
    ibcm_mad_addr_t *cm_mad_addr)
{
	ib_lid_t		lid;
	ib_gid_t		gid;
	ibcm_status_t		status;
	ib_svc_id_t		tmp_svc_id;
	ibcm_sidr_rep_msg_t	*sidr_repp = (ibcm_sidr_rep_msg_t *)
	    (&input_madp[IBCM_MAD_HDR_SIZE]);
	ibcm_ud_state_data_t	*ud_statep = NULL;
	ibcm_sidr_srch_t	srch_sidr;

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_sidr_rep_msg:");

	lid = cm_mad_addr->rcvd_addr.ia_local_lid;
	if (cm_mad_addr->grh_exists == B_TRUE)
		gid = cm_mad_addr->grh_hdr.ig_recver_gid;
	else
		gid.gid_prefix = gid.gid_guid = 0;

	IBTF_DPRINTF_L3(cmlog, "ibcm_process_sidr_rep_msg: QPN rcvd = %x",
	    h2b32(sidr_repp->sidr_rep_qpn_plus) >> 8);

	/*
	 * Lookup for an existing state structure.
	 * No need to hold a lock as ibcm_find_sidr_entry() holds the
	 * list lock to find the matching entry.
	 */
	IBTF_DPRINTF_L4(cmlog, "ibcm_process_sidr_rep: lid=%x, (%llX, %llX), "
	    "grh = %x, id = %x", lid, gid.gid_prefix, gid.gid_guid,
	    cm_mad_addr->grh_exists, sidr_repp->sidr_rep_request_id);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(srch_sidr))

	srch_sidr.srch_lid = lid;
	srch_sidr.srch_gid = gid;
	srch_sidr.srch_grh_exists = cm_mad_addr->grh_exists;
	srch_sidr.srch_req_id = b2h32(sidr_repp->sidr_rep_request_id);
	srch_sidr.srch_mode = IBCM_ACTIVE_MODE;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(srch_sidr))

	rw_enter(&hcap->hca_sidr_list_lock, RW_READER);
	status = ibcm_find_sidr_entry(&srch_sidr, hcap, &ud_statep,
	    IBCM_FLAG_LOOKUP);
	rw_exit(&hcap->hca_sidr_list_lock);

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_sidr_rep_msg: ud_statep 0x%p "
	    "find sidr entry status = %x", ud_statep, status);

	if (status != IBCM_LOOKUP_EXISTS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_sidr_rep_msg: "
		    "No matching ud_statep for SIDR REP");
		return;
	}

	if (IBCM_OUT_HDRP(ud_statep->ud_stored_msg)->TransactionID !=
	    ((ib_mad_hdr_t *)(input_madp))->TransactionID) {
		mutex_enter(&ud_statep->ud_state_mutex);
		IBCM_UD_REF_CNT_DECR(ud_statep);
		mutex_exit(&ud_statep->ud_state_mutex);
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_sidr_rep_msg: "
		    "ud_statep 0x%p. A SIDR REP MAD with tid expected 0x%llX "
		    "tid found 0x%llX req_id %x arrived", ud_statep,
		    b2h64(
		    IBCM_OUT_HDRP(ud_statep->ud_stored_msg)->TransactionID),
		    b2h64(((ib_mad_hdr_t *)(input_madp))->TransactionID),
		    b2h32(sidr_repp->sidr_rep_request_id));
		return;
	}

	mutex_enter(&ud_statep->ud_state_mutex);

	/*
	 * We need to check service ID received against the one sent?
	 * If they don't match just return.
	 */
	bcopy(sidr_repp->sidr_rep_service_id, &tmp_svc_id, sizeof (tmp_svc_id));
	bcopy(&tmp_svc_id, sidr_repp->sidr_rep_service_id, sizeof (tmp_svc_id));
	if (ud_statep->ud_svc_id != b2h64(tmp_svc_id)) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_sidr_rep_msg: "
		    "ud_statep -0x%p svcids do not match %llx %llx",
		    ud_statep, ud_statep->ud_svc_id, b2h64(tmp_svc_id));

		IBCM_UD_REF_CNT_DECR(ud_statep);
		mutex_exit(&ud_statep->ud_state_mutex);
		return;
	}

	if (ud_statep->ud_state == IBCM_STATE_SIDR_REQ_SENT) {
		timeout_id_t	timer_val = ud_statep->ud_timerid;

		ud_statep->ud_state = IBCM_STATE_SIDR_REP_RCVD;
		ud_statep->ud_timerid = 0;
		mutex_exit(&ud_statep->ud_state_mutex);

		/* Cancel timer set after sending SIDR REQ */
		(void) untimeout(timer_val);

		/*
		 * Call Client's UD handler
		 */
		ibcm_sidr_rep_ud_handler(ud_statep, sidr_repp);

		mutex_enter(&ud_statep->ud_state_mutex);

		ud_statep->ud_state = IBCM_STATE_DELETE;

		/*
		 * ud_statep->ud_return_data is initialized for blocking in
		 * ibt_ud_get_dqpn(). Initialize its fields and
		 * signal the blocking call in ibt_ud_get_dqpn().
		 */
		if (ud_statep->ud_return_data != NULL) {
			/* get rep_qpn and rep_status */
			ibt_priv_data_len_t len;

			/* Copy the SIDR private data */
			len = min(ud_statep->ud_return_data->ud_priv_data_len,
			    IBT_SIDR_REP_PRIV_DATA_SZ);

			if ((ud_statep->ud_return_data->ud_priv_data != NULL) &&
			    (len > 0)) {
				bcopy(sidr_repp->sidr_rep_private_data,
				    ud_statep->ud_return_data->ud_priv_data,
				    len);
			}

			/* get status first */
			ud_statep->ud_return_data->ud_status =
			    sidr_repp->sidr_rep_rep_status;

			if (ud_statep->ud_return_data->ud_status ==
			    IBT_CM_SREP_QPN_VALID) {
				ud_statep->ud_return_data->ud_dqpn =
				    h2b32(sidr_repp->sidr_rep_qpn_plus) >> 8;
				ud_statep->ud_return_data->ud_qkey =
				    b2h32(sidr_repp->sidr_rep_qkey);
			}

			ud_statep->ud_blocking_done = B_TRUE;
			cv_broadcast(&ud_statep->ud_block_client_cv);
		}

		IBCM_UD_REF_CNT_DECR(ud_statep);
		mutex_exit(&ud_statep->ud_state_mutex);

		/* Delete UD state data now, finally done with it */
		ibcm_delete_ud_state_data(ud_statep);
	} else {
		IBTF_DPRINTF_L3(cmlog, "ibcm_process_sidr_rep_msg: "
		    "ud state is = 0x%x", ud_statep->ud_state);
		IBCM_UD_REF_CNT_DECR(ud_statep);
		mutex_exit(&ud_statep->ud_state_mutex);
	}
}


/*
 * ibcm_post_sidr_rep_mad:
 *	This call posts a SIDR REP MAD
 *
 * INPUTS:
 *	ud_statep	- pointer to ibcm_ud_state_data_t
 *	status		- Status information
 *
 * RETURN VALUE: NONE
 */
void
ibcm_post_sidr_rep_mad(ibcm_ud_state_data_t *ud_statep,
    ibt_sidr_status_t status)
{
	ib_svc_id_t		tmp_svc_id;
	ibcm_sidr_rep_msg_t	*sidr_repp =
	    (ibcm_sidr_rep_msg_t *)IBCM_OUT_MSGP(ud_statep->ud_stored_msg);
	clock_t			timer_value;

	IBTF_DPRINTF_L5(cmlog, "ibcm_post_sidr_rep_mad:");

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sidr_repp))

	IBCM_OUT_HDRP(ud_statep->ud_stored_msg)->AttributeID =
	    h2b16(IBCM_INCOMING_SIDR_REP + IBCM_ATTR_BASE_ID);

	/*
	 * Initialize SIDR REP message. (Other fields were
	 * already filled up in ibcm_sidr_req_ud_handler()
	 */
	sidr_repp->sidr_rep_request_id = h2b32(ud_statep->ud_req_id);
	tmp_svc_id = h2b64(ud_statep->ud_svc_id);
	bcopy(&tmp_svc_id, sidr_repp->sidr_rep_service_id, sizeof (tmp_svc_id));

	sidr_repp->sidr_rep_rep_status = (uint8_t)status;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*sidr_repp))

	/* post the SIDR REP MAD */
	ibcm_post_ud_mad(ud_statep, ud_statep->ud_stored_msg, NULL, NULL);

	timer_value = ibt_ib2usec(ibcm_max_sidr_rep_store_time);
	/*
	 * Hold the statep lock, as a SIDR REQ may come in after setting state
	 * but before timeout. This can result in a dangling timeout ie.,
	 * the incoming SIDR REQ would be unable to cancel this timeout
	 */
	mutex_enter(&ud_statep->ud_state_mutex);

	ud_statep->ud_remaining_retry_cnt = 1;
	ud_statep->ud_timer_value = timer_value;

	ud_statep->ud_timer_stored_state = ud_statep->ud_state =
	    IBCM_STATE_SIDR_REP_SENT;
	ud_statep->ud_timerid = IBCM_UD_TIMEOUT(ud_statep,
	    ud_statep->ud_timer_value);

	mutex_exit(&ud_statep->ud_state_mutex);
}


/*
 * ibcm_sidr_timeout_cb:
 *	Called when the timer expires on SIDR request
 *
 * INPUTS:
 *	arg	-	ibcm_ud_state_data_t with all the info
 *
 * RETURN VALUE: NONE
 */
void
ibcm_sidr_timeout_cb(void *arg)
{
	ibcm_ud_state_data_t	*ud_statep = (ibcm_ud_state_data_t *)arg;

	mutex_enter(&ud_statep->ud_state_mutex);
	ud_statep->ud_timerid = 0;

	IBTF_DPRINTF_L3(cmlog, "ibcm_sidr_timeout_cb: ud_statep 0x%p "
	    "state = 0x%x", ud_statep, ud_statep->ud_state);

	/* Processing depends upon current state */
	if (ud_statep->ud_state == IBCM_STATE_SIDR_REP_SENT) {
		ud_statep->ud_state = IBCM_STATE_DELETE;

		mutex_exit(&ud_statep->ud_state_mutex);

		/* Deallocate the CM state structure */
		ibcm_delete_ud_state_data(ud_statep);

	} else if ((ud_statep->ud_remaining_retry_cnt > 0) &&
	    (ud_statep->ud_state == IBCM_STATE_SIDR_REQ_SENT)) {

		ud_statep->ud_remaining_retry_cnt--;
		IBCM_UD_REF_CNT_INCR(ud_statep); /* for non-blocking post */
		IBTF_DPRINTF_L4(cmlog, "ibcm_sidr_timeout_cb: "
		    "ud_statep = %p, retries remaining = 0x%x",
		    ud_statep, ud_statep->ud_remaining_retry_cnt);
		mutex_exit(&ud_statep->ud_state_mutex);

		/* Post mad in non blocking mode */
		ibcm_post_ud_mad(ud_statep, ud_statep->ud_stored_msg,
		    ibcm_post_sidr_req_complete, ud_statep);

	} else if (ud_statep->ud_state == IBCM_STATE_SIDR_REQ_SENT) {

		/* This is on SIDR REQ Sender side processing */

		/* set state to IBCM_STATE_DELETE */
		ud_statep->ud_state = IBCM_STATE_DELETE;

		/*
		 * retry counter expired, clean up
		 *
		 * Invoke the client/server handler with a "status" of
		 * IBT_CM_SREP_TIMEOUT.
		 */

		if (ud_statep->ud_return_data != NULL) {
			ud_statep->ud_return_data->ud_status =
			    IBT_CM_SREP_TIMEOUT;
			ud_statep->ud_blocking_done = B_TRUE;
			cv_broadcast(&ud_statep->ud_block_client_cv);
		}

		mutex_exit(&ud_statep->ud_state_mutex);

		/* Invoke the client handler in a separate thread */
		if (ud_statep->ud_cm_handler != NULL) {
			/* UD state data is delete in timeout thread */
			ibcm_add_ud_tlist(ud_statep);
			return;
		}

		/* Delete UD state data now, finally done with it */
		ibcm_delete_ud_state_data(ud_statep);
	} else {

#ifdef DEBUG
		if (ibcm_test_mode > 0)
			IBTF_DPRINTF_L2(cmlog, "ibcm_sidr_timeout_cb: "
			    "Nop timeout  for ud_statep 0x%p in ud_state %d",
			    ud_statep, ud_statep->ud_state);
#endif
		mutex_exit(&ud_statep->ud_state_mutex);
	}
}


/*
 * ibcm_resend_srep_mad:
 *	Called on a duplicate incoming SIDR REQ on server side
 *	Posts the stored MAD from ud state structure using ud_stored_reply_addr
 *	Cancels any running timer, and then re-starts the timer
 *	This routine must be called with state structure table lock held
 *
 * INPUTS:
 *	ud_statep	-	ibcm_ud_state_data_t
 *
 * RETURN VALUE: NONE
 */
void
ibcm_resend_srep_mad(ibcm_ud_state_data_t *ud_statep)
{
	timeout_id_t		timer_val;

	ASSERT(MUTEX_HELD(&ud_statep->ud_state_mutex));

	IBTF_DPRINTF_L3(cmlog, "ibcm_resend_srep_mad: ud_statep 0x%p",
	    ud_statep);

	if (ud_statep->ud_send_mad_flags & IBCM_SREP_POST_BUSY)
		return;

	ud_statep->ud_send_mad_flags |= IBCM_SREP_POST_BUSY;

	/* for nonblocking SIDR REP Post */
	IBCM_UD_REF_CNT_INCR(ud_statep);

	/* Cancel currently running timer */
	timer_val = ud_statep->ud_timerid;

	if (ud_statep->ud_timerid != 0) {
		ud_statep->ud_timerid = 0;
		mutex_exit(&ud_statep->ud_state_mutex);
		(void) untimeout(timer_val);
	} else {
		mutex_exit(&ud_statep->ud_state_mutex);
	}

	/* Always resend the response MAD to the original reply destination */
	ibcm_post_ud_mad(ud_statep, ud_statep->ud_stored_msg,
	    ibcm_post_sidr_rep_complete, ud_statep);

	mutex_enter(&ud_statep->ud_state_mutex);
}


/*
 * ibcm_build_reply_mad_addr:
 *	Forms the reply MAD address based on "incoming mad addr" that is
 *	supplied as an arg.
 *
 *	Swaps the source and destination gids in ib_grh_t
 *
 * INPUTS:
 * inp_mad_addr:	Address information in the incoming MAD
 * out_mad_addr:	Derived address for the reply MAD
 *			The reply MAD address is derived based
 *			address information of incoming CM MAD
 * RETURN VALUE: NONE
 */
void
ibcm_build_reply_mad_addr(ibcm_mad_addr_t *inp_mad_addr,
    ibcm_mad_addr_t *out_mad_addr)
{
	IBTF_DPRINTF_L5(cmlog, "ibcm_build_reply_mad_addr:");

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*out_mad_addr))

	bcopy(inp_mad_addr, out_mad_addr, sizeof (ibcm_mad_addr_t));

	/* Swap the GIDs in the GRH */
	if (inp_mad_addr->grh_exists == B_TRUE) {
		ib_gid_t sgid = inp_mad_addr->grh_hdr.ig_sender_gid;

		/* swap the SGID and DGID */
		out_mad_addr->grh_hdr.ig_sender_gid =
		    inp_mad_addr->grh_hdr.ig_recver_gid;
		out_mad_addr->grh_hdr.ig_recver_gid = sgid;
	}

	/*
	 * CM posts response MAD on a new/existing internal QP on the same port
	 * and pkey
	 */
	out_mad_addr->cm_qp_entry =
	    ibcm_find_qp(inp_mad_addr->cm_qp_entry->qp_port->port_hcap,
	    inp_mad_addr->port_num, inp_mad_addr->rcvd_addr.ia_p_key);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*out_mad_addr))
}


/*
 * ibcm_post_rc_mad
 *	Posts a CM MAD associated with a RC statep
 *
 * INPUTS:
 * statep	: RC statep associated with the post
 * msgp		: CM MAD to be posted
 * post_cb	: non-NULL callback address implies non-blocking post
 * args		: Args to ibmf send callback
 *
 * RETURN VALUE: based on ibmf_send_mad
 */
void
ibcm_post_rc_mad(ibcm_state_data_t *statep, ibmf_msg_t *msgp,
    ibmf_msg_cb_t post_cb, void *args)
{
	ibt_status_t	status;

	mutex_enter(&statep->state_mutex);
	statep->post_time = gethrtime();
	mutex_exit(&statep->state_mutex);
	status = ibcm_post_mad(msgp, &statep->stored_reply_addr, post_cb,
	    args);
	if ((status != IBT_SUCCESS) && (post_cb != NULL))
		/* Call ibmf callback directly */
		(*post_cb)(NULL, msgp, args);
}


/*
 * ibcm_post_ud_mad
 *	Posts a CM MAD associated with a UD statep
 *
 * INPUTS:
 * ud_statep	: UD statep associated with the post
 * msgp		: CM MAD to be posted
 * post_cb	: non-NULL callback address implies non-blocking post
 * args		: Args to ibmf send callback
 *
 * RETURN VALUE: based on ibmf_send_mad
 */
void
ibcm_post_ud_mad(ibcm_ud_state_data_t *ud_statep, ibmf_msg_t *msgp,
    ibmf_msg_cb_t ud_post_cb, void *args)
{
	ibt_status_t	status;
	status = ibcm_post_mad(msgp, &ud_statep->ud_stored_reply_addr,
	    ud_post_cb, args);
	if ((status != IBT_SUCCESS) && (ud_post_cb != NULL))
		/* Call ibmf callback directly */
		(*ud_post_cb)(NULL, msgp, args);
}

/*
 * ibcm_post_mad:
 *	Posts CM MAD using IBMF in blocking mode
 *
 * INPUTS:
 * msgp		: CM MAD to be posted
 * cm_mad_addr	: Address information for the MAD to be posted
 * post_cb	: non-NULL callback address implies non-blocking post
 * args		: Args to ibmf send callback
 *
 * RETURN VALUE: based on ibmf_send_mad
 */
ibt_status_t
ibcm_post_mad(ibmf_msg_t *msgp, ibcm_mad_addr_t *cm_mad_addr,
    ibmf_msg_cb_t post_cb, void *args)
{
	int	post_status;

	IBTF_DPRINTF_L5(cmlog, "ibcm_post_mad: "
	    "ibmf_msg_t = %p, cm_madd_adr = %p", msgp, cm_mad_addr);

	IBTF_DPRINTF_L4(cmlog, "ibcm_post_mad: dlid = %x, d_qno= %x",
	    cm_mad_addr->rcvd_addr.ia_remote_lid,
	    cm_mad_addr->rcvd_addr.ia_remote_qno);
	IBTF_DPRINTF_L4(cmlog, "ibcm_post_mad: p_key = %x, q_key = %x, "
	    "sl = %x, grh_exists = %x",
	    cm_mad_addr->rcvd_addr.ia_p_key, cm_mad_addr->rcvd_addr.ia_q_key,
	    cm_mad_addr->rcvd_addr.ia_service_level, cm_mad_addr->grh_exists);

	/* Copy local addressing info */
	msgp->im_local_addr = cm_mad_addr->rcvd_addr;

	/* Copy global/GRH addressing info */
	if (cm_mad_addr->grh_exists == B_TRUE)
		msgp->im_global_addr = cm_mad_addr->grh_hdr;

	if (post_cb)
		ibcm_flow_inc();
	post_status = ibmf_msg_transport(
	    cm_mad_addr->ibmf_hdl, cm_mad_addr->cm_qp_entry->qp_cm, msgp,
	    NULL, post_cb, args, 0);
	if (post_status != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_post_mad: ibmf_msg_transport "
		    "failed: status %d, cb = %p", post_status, post_cb);
		/* Analyze the reason for failure */
		return (ibcm_ibmf_analyze_error(post_status));
	}

	return (IBT_SUCCESS);
}


/*
 * ibcm_process_get_classport_info:
 *	Get classportinfo
 *
 * INPUTS:
 *	hcap		- HCA entry pointer
 *	input_madp	- Input MAD pointer
 *	cm_mad_addr	- Address information for the MAD to be posted
 *
 * RETURN VALUE: NONE
 */
static void
ibcm_process_get_classport_info(ibcm_hca_info_t *hcap, uint8_t *input_madp,
    ibcm_mad_addr_t *cm_mad_addr)
{
	ibmf_msg_t		*msgp;

	IBTF_DPRINTF_L5(cmlog, "ibcm_process_get_classport_info: (%p, %p, %p)",
	    hcap, input_madp, cm_mad_addr);

	if (ibcm_alloc_out_msg(cm_mad_addr->ibmf_hdl, &msgp,
	    MAD_METHOD_GET_RESPONSE) != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_get_classport_info: "
		    "ibcm_alloc_out_msg failed");
		return;
	}

	/* copy the transaction id from input get mad */
	IBCM_OUT_HDRP(msgp)->TransactionID =
	    ((ib_mad_hdr_t *)(input_madp))->TransactionID;
	IBCM_OUT_HDRP(msgp)->AttributeID = h2b16(MAD_ATTR_ID_CLASSPORTINFO);

	bcopy(&ibcm_clpinfo, IBCM_OUT_MSGP(msgp), sizeof (ibcm_clpinfo));

	(void) ibcm_post_mad(msgp, cm_mad_addr, NULL, NULL);
	(void) ibcm_free_out_msg(cm_mad_addr->ibmf_hdl, &msgp);

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_get_classport_info: done");
}

/*
 * ibcm_decode_classport_info:
 *	Decode classportinfo
 *
 * INPUTS:
 *	hcap		- HCA entry pointer
 *	cm_mad_addr	- Address information for the MAD to be posted
 *	input_madp	- Input MAD pointer
 *
 * RETURN VALUE: NONE
 */
static void
ibcm_decode_classport_info(ibcm_hca_info_t *hcap, uint8_t *input_madp,
    ibcm_mad_addr_t *cm_mad_addr)
{
	ibcm_classportinfo_msg_t *portinfop = (ibcm_classportinfo_msg_t *)
	    (&input_madp[IBCM_MAD_HDR_SIZE]);
	IBTF_DPRINTF_L5(cmlog, "ibcm_decode_classport_info: (%p, %p, %p)",
	    hcap, input_madp, cm_mad_addr);

	/* Print various fields of received classportinfo in debuf buf */

	IBTF_DPRINTF_L4(cmlog, "ibcm_decode_classport_info: "
	    "Base version %d Class version %d", portinfop->BaseVersion,
	    portinfop->ClassVersion);
	IBTF_DPRINTF_L4(cmlog, "ibcm_decode_classport_info: "
	    "Cap Mask %d Resp Time %d", portinfop->CapabilityMask,
	    portinfop->RespTimeValue_plus);
}


/*
 * ibcm_handler_conn_fail:
 *	Helper function used to call client handler for Conn fail event
 *
 * INPUTS:
 *	statep:			The connection state pointer
 *	rej_type:		Message being rejected
 *	rej_reason:		Reason why CM is sending the REJ message
 *	client_data:		Private data returned by the client for REJ
 *	client_data_len:	Length of above client's private data.
 *
 * RETURN VALUE:	Client Handler's return status
 */
static void
ibcm_handler_conn_fail(ibcm_state_data_t *statep, uint8_t cf_code,
    uint8_t cf_msg, ibt_cm_reason_t cf_reason, uint8_t *client_data,
    ibt_priv_data_len_t client_data_len)
{
	ibt_cm_event_t	event;

	ibcm_path_cache_purge();

	if (statep->channel)
		ibtl_cm_chan_open_is_aborted(statep->channel);

	/* Invoke CM handler w/ event passed as arg */
	if (statep->cm_handler != NULL) {
		bzero(&event, sizeof (ibt_cm_event_t));

		event.cm_type = IBT_CM_EVENT_FAILURE;
		event.cm_channel = statep->channel;
		event.cm_session_id = NULL;
		event.cm_priv_data = NULL;
		event.cm_priv_data_len = 0;

		event.cm_event.failed.cf_code = cf_code;
		event.cm_event.failed.cf_msg =  cf_msg;
		event.cm_event.failed.cf_reason =  cf_reason;

		ibcm_insert_trace(statep, IBCM_TRACE_CALLED_CONN_FAIL_EVENT);

		(void) statep->cm_handler(statep->state_cm_private, &event,
		    NULL, client_data, client_data_len);

		ibcm_insert_trace(statep, IBCM_TRACE_RET_CONN_FAIL_EVENT);
	}
	if (ibcm_enable_trace != 0)
		ibcm_dump_conn_trace(statep);
	mutex_enter(&statep->state_mutex);
	ibcm_open_done(statep);
	mutex_exit(&statep->state_mutex);
}

/*
 * QP State transition functions here
 *
 * The brief description of these functions :
 *	Validate QP related attributes in the messages
 *	Call client/server callback handlers
 *	Change QP state
 *	Set QP attributes (modify QP)
 *	Fill up the response MADs
 */

/*
 * ibcm_set_primary_adds_vect:
 *	Helper function used to fill up ibt_adds_vect_t PRIMARY PATH
 *	(called from ibcm_cep_state_*() functions)
 *
 * INPUTS:
 * statep	: The connection state pointer
 * adds_vectp	: The ibt_adds_vect_t ptr that is being filled up
 * msgp		: CM REQ message that is the source of information
 *
 * RETURN VALUE:	NONE
 */
static void
ibcm_set_primary_adds_vect(ibcm_state_data_t *statep,
    ibt_adds_vect_t *adds_vectp, ibcm_req_msg_t *msgp)
{
	uint32_t flow_label20_res6_rate6;

	flow_label20_res6_rate6 = b2h32(msgp->req_primary_flow_label_plus);

	/* first setup the srvl, srate, dlid and dgid */
	adds_vectp->av_srvl = msgp->req_primary_sl_plus >> 4;
	adds_vectp->av_src_path = statep->prim_src_path_bits;

	if (statep->mode == IBCM_PASSIVE_MODE) {
		adds_vectp->av_dlid = b2h16(msgp->req_primary_l_port_lid);
		adds_vectp->av_dgid.gid_prefix =
		    b2h64(msgp->req_primary_l_port_gid.gid_prefix);
		adds_vectp->av_dgid.gid_guid =
		    b2h64(msgp->req_primary_l_port_gid.gid_guid);
		adds_vectp->av_sgid.gid_prefix =
		    b2h64(msgp->req_primary_r_port_gid.gid_prefix);
		adds_vectp->av_sgid.gid_guid =
		    b2h64(msgp->req_primary_r_port_gid.gid_guid);
		adds_vectp->av_srate = flow_label20_res6_rate6 & 0x3f;
	} else {
		adds_vectp->av_dlid = b2h16(msgp->req_primary_r_port_lid);
		adds_vectp->av_dgid.gid_prefix =
		    b2h64(msgp->req_primary_r_port_gid.gid_prefix);
		adds_vectp->av_dgid.gid_guid =
		    b2h64(msgp->req_primary_r_port_gid.gid_guid);
		adds_vectp->av_sgid.gid_prefix =
		    b2h64(msgp->req_primary_l_port_gid.gid_prefix);
		adds_vectp->av_sgid.gid_guid =
		    b2h64(msgp->req_primary_l_port_gid.gid_guid);
		adds_vectp->av_srate = statep->local_srate;
	}

	/* next copy off the GRH info if it exists  */
	if ((msgp->req_primary_sl_plus & 0x8) == 0) {
		adds_vectp->av_send_grh = B_TRUE;
		adds_vectp->av_flow = flow_label20_res6_rate6 >> 12;
		adds_vectp->av_tclass = msgp->req_primary_traffic_class;
		adds_vectp->av_hop = msgp->req_primary_hop_limit;
	} else {
		adds_vectp->av_send_grh = B_FALSE;
	}
}


/*
 * ibcm_set_alt_adds_vect:
 *	Helper function used to fill up ibt_adds_vect_t ALTERNATE PATH
 *	(called from ibcm_cep_state_*() functions)
 *
 * INPUTS:
 * statep	: The connection state pointer
 * adds_vectp	: The ibt_adds_vect_t ptr that is being filled up
 * msgp		: CM REQ message that is the source of information
 *
 * RETURN VALUE:	NONE
 */
static void
ibcm_set_alt_adds_vect(ibcm_state_data_t *statep,
    ibt_adds_vect_t *adds_vectp, ibcm_req_msg_t *msgp)
{
	ib_gid_t dgid;
	ib_gid_t sgid;
	uint32_t flow_label20_res6_rate6;

	flow_label20_res6_rate6 = b2h32(msgp->req_alt_flow_label_plus);

	/* first setup the srvl, srate, dlid and dgid */
	adds_vectp->av_srvl = msgp->req_alt_sl_plus >> 4;
	adds_vectp->av_src_path = statep->alt_src_path_bits;

	if (statep->mode == IBCM_PASSIVE_MODE) {
		adds_vectp->av_dlid = b2h16(msgp->req_alt_l_port_lid);
		bcopy(&msgp->req_alt_l_port_gid[0], &dgid, sizeof (ib_gid_t));
		bcopy(&msgp->req_alt_r_port_gid[0], &sgid, sizeof (ib_gid_t));
		adds_vectp->av_srate = flow_label20_res6_rate6 & 0x3f;
	} else {
		adds_vectp->av_dlid = b2h16(msgp->req_alt_r_port_lid);
		bcopy(&msgp->req_alt_r_port_gid[0], &dgid, sizeof (ib_gid_t));
		bcopy(&msgp->req_alt_l_port_gid[0], &sgid, sizeof (ib_gid_t));
		adds_vectp->av_srate = statep->local_alt_srate;
	}
	adds_vectp->av_dgid.gid_prefix = b2h64(dgid.gid_prefix);
	adds_vectp->av_dgid.gid_guid = b2h64(dgid.gid_guid);
	adds_vectp->av_sgid.gid_prefix = b2h64(sgid.gid_prefix);
	adds_vectp->av_sgid.gid_guid = b2h64(sgid.gid_guid);

	/* next copy off the GRH info if it exists  */
	if ((msgp->req_alt_sl_plus & 0x8) == 0) {
		adds_vectp->av_send_grh = B_TRUE;
		adds_vectp->av_flow = flow_label20_res6_rate6 >> 12;
		adds_vectp->av_tclass = msgp->req_alt_traffic_class;
		adds_vectp->av_hop = msgp->req_alt_hop_limit;
	} else {
		adds_vectp->av_send_grh = B_FALSE;	/* no GRH */
	}
}


/*
 * ibcm_set_primary_cep_path:
 *	Helper function used to fill up ibt_cep_path_t PRIMARY PATH
 *	(called from ibcm_cep_state_*() functions)
 *
 * INPUTS:
 * statep	: The connection state pointer
 * adds_vectp	: The ibt_cep_path_t ptr that is being filled up
 * msgp		: CM REQ message that is the source of information
 *
 * RETURN VALUE:	NONE
 */
static ibt_status_t
ibcm_set_primary_cep_path(ibcm_state_data_t *statep, ibt_cep_path_t *pathp,
    ibcm_req_msg_t *msgp)
{
	ibt_status_t		status;

	/* validate the PKEY in REQ for prim port */
	status = ibt_pkey2index_byguid(statep->local_hca_guid,
	    statep->prim_port, b2h16(msgp->req_part_key), &pathp->cep_pkey_ix);

	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_set_primary_cep_path: "
		    "statep 0x%p pkey %x prim_port %d ", statep,
		    b2h16(msgp->req_part_key), statep->prim_port);
		IBTF_DPRINTF_L2(cmlog, "ibcm_set_primary_cep_path: "
		    "statep 0x%p Invalid PKEY on prim_port, status %d ",
		    statep, status);
		return (status);
	}
	statep->pkey = b2h16(msgp->req_part_key);
	ibcm_set_primary_adds_vect(statep, &pathp->cep_adds_vect, msgp);
	return (IBT_SUCCESS);
}


/*
 * ibcm_set_alt_cep_path:
 *	Helper function used to fill up ibt_cep_path_t ALTERNATE PATH
 *	(called from ibcm_cep_state_*() functions)
 *
 * INPUTS:
 * statep	: The connection state pointer
 * adds_vectp	: The ibt_cep_path_t ptr that is being filled up
 * msgp		: CM REQ message that is the source of information
 *
 * RETURN VALUE:	NONE
 */
static ibt_status_t
ibcm_set_alt_cep_path(ibcm_state_data_t *statep, ibt_cep_path_t *pathp,
    ibcm_req_msg_t *msgp)
{
	ibt_status_t		status;

	if (b2h16(msgp->req_alt_l_port_lid) == 0) {
		/* no alternate path specified */
		return (IBT_SUCCESS);
	}

	/* validate the PKEY in REQ for alt port */
	status = ibt_pkey2index_byguid(statep->local_hca_guid,
	    statep->alt_port, b2h16(msgp->req_part_key), &pathp->cep_pkey_ix);

	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_set_alt_cep_path: "
		    "statep 0x%p pkey %x alt_port %d ", statep,
		    b2h16(msgp->req_part_key), statep->alt_port);
		IBTF_DPRINTF_L2(cmlog, "ibcm_set_alt_cep_path: "
		    "statep 0x%p Invalid PKEY on alt_port, status %d ",
		    statep, status);
		return (status);
	}
	pathp->cep_hca_port_num = statep->alt_port;
	ibcm_set_alt_adds_vect(statep, &pathp->cep_adds_vect, msgp);
	return (IBT_SUCCESS);

}

/*
 * ibcm_compare_prim_alt_paths:
 *	Helper function used to find if primary and alternate paths are
 *	identical
 *	(called from ibcm_cep_state_req)
 *
 * INPUTS:
 * req:			Pointer to ibt_cm_req_rcv_t, filled before invoking
 *			the function
 *
 * RETURN VALUE:	NONE
 */

static boolean_t
ibcm_compare_prim_alt_paths(ibt_adds_vect_t *prim, ibt_adds_vect_t *alt)
{

	if ((alt->av_dlid == prim->av_dlid) &&
	    (alt->av_dgid.gid_prefix == prim->av_dgid.gid_prefix) &&
	    (alt->av_dgid.gid_guid == prim->av_dgid.gid_guid) &&
	    (alt->av_sgid.gid_prefix == prim->av_sgid.gid_prefix) &&
	    (alt->av_sgid.gid_guid == prim->av_sgid.gid_guid) &&
	    (alt->av_src_path == prim->av_src_path)) {

		return (B_TRUE);
	}
	return (B_FALSE);
}


/*
 * ibcm_invoke_qp_modify:
 *	Helper function used to call ibt_modify_qp()
 *	called from ibcm_cep_state_req()/ibcm_cep_state_rep()
 *	It sets up qp_info/eec_info
 *
 *	Sets state to RTR as well.
 *
 *
 * INPUTS:
 *	statep:		The connection state pointer
 *	req_msgp:	The CM REQ message
 *
 * RETURN VALUE:
 *	IBT_SUCCESS	-	call succeeded
 */
static ibt_status_t
ibcm_invoke_qp_modify(ibcm_state_data_t *statep, ibcm_req_msg_t *req_msgp,
    ibcm_rep_msg_t *rep_msgp)
{
	ibt_status_t		status;
	ibt_qp_info_t		qp_info;
	ibt_cep_modify_flags_t	cep_flags;
	ibt_tran_srv_t		trans;

	cep_flags = IBT_CEP_SET_INIT_RTR | IBT_CEP_SET_PKEY_IX;
	trans = ((uint8_t *)&req_msgp->req_remote_eecn_plus)[3] >> 1 & 0x3;

	ASSERT(statep->channel != NULL);

	/*
	 * If alternate path is present in REQ message then
	 * OR in IBT_CEP_SET_ALT_PATH, if APM supported on hca
	 */
	if (b2h16(req_msgp->req_alt_l_port_lid) != 0) {

		if (statep->hcap->hca_caps & IBT_HCA_AUTO_PATH_MIG)
			cep_flags |= IBT_CEP_SET_ALT_PATH;
			/* default value of rep_failover is ACCEPT */
		else {
			rep_msgp->rep_target_delay_plus |=
			    IBT_CM_FAILOVER_REJ_NOTSUPP << 1;
			IBTF_DPRINTF_L3(cmlog, "ibcm_invoke_qp_modify"
			    " Alt Path specified in REQ, but not supported");
		}
	}

	/* If transport type is RD OR in IBC_CEP_SET_QKEY */
	if (trans == IBT_RD_SRV) {
		cep_flags |= IBT_CEP_SET_QKEY;
	}

	/* Start filling up ibt_qp_info_t.  */
	bzero(&qp_info, sizeof (qp_info));
	qp_info.qp_trans = trans;
	qp_info.qp_state = IBT_STATE_RTR;
	qp_info.qp_flags = IBT_CEP_NO_FLAGS;

	switch (trans) {
	case IBT_RC_SRV:

		if (statep->mode == IBCM_ACTIVE_MODE) {
			/* Setting PSN on RQ */

			IBCM_QPINFO_RC(qp_info).rc_rq_psn =
			    b2h32(req_msgp->req_starting_psn_plus) >> 8;

			IBCM_QPINFO_RC(qp_info).rc_dst_qpn =
			    b2h32(rep_msgp->rep_local_qpn_plus) >> 8;

			/* RDMA resources taken from negotiated REP values */
			IBCM_QPINFO_RC(qp_info).rc_rdma_ra_in =
			    rep_msgp->rep_initiator_depth;

		} else { /* Passive side CM */
			/* Setting PSN on SQ and RQ */
			IBCM_QPINFO_RC(qp_info).rc_sq_psn =
			    IBCM_QPINFO_RC(qp_info).rc_rq_psn =
			    b2h32(rep_msgp->rep_starting_psn_plus) >> 8;

			IBCM_QPINFO_RC(qp_info).rc_dst_qpn =
			    b2h32(req_msgp->req_local_qpn_plus) >> 8;

			/* RDMA resources taken from negotiated REP values */
			IBCM_QPINFO_RC(qp_info).rc_rdma_ra_in =
			    rep_msgp->rep_resp_resources;
		}

		/* XXX, Oh!, ibtl doesn't have interface for setting this */
		IBCM_QPINFO_RC(qp_info).rc_min_rnr_nak =
		    ibcm_default_rnr_nak_time;
		IBCM_QPINFO_RC(qp_info).rc_path_mtu =
		    req_msgp->req_mtu_plus >> 4;
		IBCM_QPINFO_RC(qp_info).rc_retry_cnt =
		    ((uint8_t *)&req_msgp->req_starting_psn_plus)[3] & 0x7;
		IBCM_QPINFO_RC(qp_info).rc_rnr_retry_cnt =
		    req_msgp->req_mtu_plus & 0x7;

		if ((status = ibcm_set_primary_cep_path(statep,
		    &IBCM_QPINFO_RC(qp_info).rc_path, req_msgp)) !=
		    IBT_SUCCESS)
			return (status);

		if ((status = ibcm_set_alt_cep_path(statep,
		    &IBCM_QPINFO_RC(qp_info).rc_alt_path, req_msgp)) !=
		    IBT_SUCCESS)
			return (status);

		break;
	case IBT_RD_SRV:
		if (statep->mode == IBCM_ACTIVE_MODE) { /* look at REP msg */
			IBCM_QPINFO(qp_info).rd.rd_qkey =
			    b2h32(rep_msgp->rep_local_qkey);
		} else {
			IBCM_QPINFO(qp_info).rd.rd_qkey =
			    b2h32(req_msgp->req_local_qkey);
		}

		break;

	case IBT_UC_SRV:
		if (statep->mode == IBCM_ACTIVE_MODE) { /* look at REP msg */
			IBCM_QPINFO_UC(qp_info).uc_sq_psn =
			    b2h32(req_msgp->req_starting_psn_plus) >> 8;
			IBCM_QPINFO_UC(qp_info).uc_dst_qpn =
			    b2h32(rep_msgp->rep_local_qpn_plus) >> 8;
		} else {
			IBCM_QPINFO_UC(qp_info).uc_rq_psn =
			    IBCM_QPINFO_UC(qp_info).uc_sq_psn =
			    b2h32(rep_msgp->rep_starting_psn_plus) >> 8;
			IBCM_QPINFO_UC(qp_info).uc_dst_qpn =
			    b2h32(req_msgp->req_local_qpn_plus) >> 8;
		}
		IBCM_QPINFO_UC(qp_info).uc_path_mtu =
		    req_msgp->req_mtu_plus >> 4;

		if ((status = ibcm_set_primary_cep_path(statep,
		    &IBCM_QPINFO_UC(qp_info).uc_path, req_msgp)) !=
		    IBT_SUCCESS)
			return (status);

		if ((status = ibcm_set_alt_cep_path(statep,
		    &IBCM_QPINFO_UC(qp_info).uc_alt_path, req_msgp)) !=
		    IBT_SUCCESS)
			return (status);

		break;
	default:
		IBTF_DPRINTF_L2(cmlog, "ibcm_invoke_qp_modify: "
		    "unknown svc_type = %x", trans);
		break;
	}

	/* Call modify_qp */
	status = ibt_modify_qp(statep->channel, cep_flags, &qp_info, NULL);
	IBTF_DPRINTF_L4(cmlog, "ibcm_invoke_qp_modify: statep 0x%p"
	    " ibt_modify_qp() Init to RTR returned = %d", statep, status);

	if (status == IBT_SUCCESS)
		ibcm_insert_trace(statep, IBCM_TRACE_INIT_RTR);
	else
		ibcm_insert_trace(statep, IBCM_TRACE_INIT_RTR_FAIL);

#ifdef	DEBUG

	print_modify_qp("Init to RTR", statep->channel, cep_flags, &qp_info);

	if (statep->channel != NULL) {
		ibt_qp_query_attr_t	qp_attrs;

		(void) ibt_query_qp(statep->channel, &qp_attrs);
		IBTF_DPRINTF_L4(cmlog, "ibcm_invoke_qp_modify: "
		    "qp_info.qp_state = %x", qp_attrs.qp_info.qp_state);
	}
#endif

	return (status);
}


/*
 * ibcm_verify_req_gids_and_svcid
 *	Validation of LIDs, GIDs and SVC ID
 *
 * INPUTS:
 *	statep		- state pointer
 *	cm_req_msgp	- REQ message pointer
 *
 * RETURN VALUE: IBCM_SUCCESS/IBCM_FAILURE
 *
 */
ibcm_status_t
ibcm_verify_req_gids_and_svcid(ibcm_state_data_t *statep,
    ibcm_req_msg_t *cm_req_msgp)
{
	ib_gid_t		gid;
	ib_gid_t		agid;
	ib_lid_t		lid;
	ibt_status_t		status;
	ibtl_cm_hca_port_t	port;
	ibt_cm_reason_t		reject_reason = IBT_CM_SUCCESS;
	ibcm_svc_info_t		*svc_infop;
	ibcm_svc_bind_t		*svc_bindp;
	ibcm_svc_bind_t		*tmp_bindp;
	ib_pkey_t		pkey;
	uint8_t			port_num;
	ib_guid_t		hca_guid;
	ibcm_ip_pvtdata_t	*ip_data;

	/* Verify LID and GID of primary port */

	gid.gid_prefix = b2h64(cm_req_msgp->req_primary_r_port_gid.gid_prefix);
	gid.gid_guid = b2h64(cm_req_msgp->req_primary_r_port_gid.gid_guid);

	IBTF_DPRINTF_L4(cmlog, "ibcm_verify_req_gids: statep 0x%p"
	    " PRIM _r_gid (%llx, %llx)", statep, gid.gid_prefix,
	    gid.gid_guid);

	IBTF_DPRINTF_L4(cmlog, "ibcm_verify_req_gids: statep 0x%p "
	    "PRIM passive lid %x", statep,
	    b2h16(cm_req_msgp->req_primary_r_port_lid));

	/* Verify GID validity, if specified */
	if ((status = ibtl_cm_get_hca_port(gid, 0, &port)) == IBT_SUCCESS) {

		IBTF_DPRINTF_L4(cmlog, "ibcm_verify_req_gids: statep 0x%p "
		    "prim_port_num %d", statep, port.hp_port);

		IBTF_DPRINTF_L4(cmlog, "ibcm_verify_req_gids: statep 0x%p "
		    "passive hca_guid 0x%llX", statep, port.hp_hca_guid);

		port_num = port.hp_port;
		hca_guid = port.hp_hca_guid;
	}

	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_verify_req_gids: statep 0x%p "
		    "ibtl_cm_get_hca_port() primary port failed = %d", statep,
		    status);
		reject_reason = IBT_CM_PRIM_GID;
		/* we will search for an acceptable GID to this port */
		port_num = statep->stored_reply_addr.port_num;
		hca_guid = statep->hcap->hca_guid;

	} else if (port.hp_base_lid !=
	    (b2h16(cm_req_msgp->req_primary_r_port_lid) &
	    (~((1 << port.hp_lmc) - 1)))) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_verify_req_gids: statep 0x%p "
		    "primary port lid invalid (%x, %x, %x)", statep,
		    port.hp_base_lid,
		    b2h16(cm_req_msgp->req_primary_r_port_lid), port.hp_lmc);
		reject_reason = IBT_CM_PRIM_LID;
	} else {

		statep->local_hca_guid = port.hp_hca_guid;
		statep->prim_port = port.hp_port;
		statep->prim_src_path_bits =
		    b2h16(cm_req_msgp->req_primary_r_port_lid) -
		    port.hp_base_lid;

		IBTF_DPRINTF_L4(cmlog, "ibcm_verify_req_gids: "
		    "statep 0x%p prim_port_path_bits %d ",
		    statep, statep->prim_src_path_bits);

		/* Verify LID and GID  of alternate port. Post REJ if invalid */

		/* Need a bcopy, as alt port gid is unaligned in req message */
		bcopy(&cm_req_msgp->req_alt_r_port_gid[0], &agid,
		    sizeof (ib_gid_t));
		agid.gid_prefix = b2h64(agid.gid_prefix);
		agid.gid_guid = b2h64(agid.gid_guid);

		IBTF_DPRINTF_L4(cmlog, "ibcm_verify_req_gids: statep 0x%p"
		    " Alt port_gid is (%llX:%llX)", statep, agid.gid_prefix,
		    agid.gid_guid);

		if ((agid.gid_prefix != 0) || (agid.gid_guid != 0)) {

			/* Verify GID validity, if specified */
			if ((status = ibtl_cm_get_hca_port(agid,
			    statep->local_hca_guid, &port)) != IBT_SUCCESS) {
				IBTF_DPRINTF_L2(cmlog,
				    "ibcm_verify_req_gids: ibtl_cm_get_hca_port"
				    " statep 0x%p alternate port failed = %d",
				    statep, status);
				reject_reason = IBT_CM_ALT_GID;

			} else if (port.hp_base_lid !=
			    (b2h16(cm_req_msgp->req_alt_r_port_lid) &
			    (~((1 << port.hp_lmc) - 1)))) {

				IBTF_DPRINTF_L2(cmlog,
				    "ibcm_verify_req_gids: statep 0x%p "
				    "alternate port lid invalid (%x, %x, %x)",
				    statep, port.hp_base_lid,
				    cm_req_msgp->req_alt_r_port_lid,
				    port.hp_lmc);
				reject_reason = IBT_CM_ALT_LID;
			} else { /* Alt LID and GID are valid */
				statep->alt_port = port.hp_port;
				statep->alt_src_path_bits =
				    b2h16(cm_req_msgp->req_alt_r_port_lid) -
				    port.hp_base_lid;

				IBTF_DPRINTF_L4(cmlog, "ibcm_verify_req_gids: "
				    "statep 0x%p alt_port_num %d "
				    "alt_rc_hca_guid 0x%llX", statep,
				    port.hp_port, port.hp_hca_guid);

				IBTF_DPRINTF_L4(cmlog, "ibcm_verify_req_gids: "
				    "statep 0x%p alt_port_path_bits %d ",
				    statep, statep->alt_src_path_bits);
			}
		}
	}

	mutex_enter(&ibcm_svc_info_lock);
	svc_infop = ibcm_find_svc_entry(statep->svcid);

	/*
	 * Note: When we return SUCCESS, the reader lock won't get dropped
	 * until after the cm_handler is called from ibcm_cep_state_req().
	 */

	IBTF_DPRINTF_L4(cmlog, "ibcm_verify_req_gids: "
	    "ibcm_find_svc_entry found svc_infop %p", svc_infop);

	/*
	 * Send REJ with reject reason "invalid service id" for the
	 * the following cases :-
	 * Service id is valid, but not available at gid/lid of REQ
	 * Service id is invalid
	 */

	if (svc_infop == NULL || svc_infop->svc_bind_list == NULL) {
		mutex_exit(&ibcm_svc_info_lock);

		IBTF_DPRINTF_L2(cmlog, "ibcm_verify_req_gids_and_svcid: "
		    "statep 0x%p svc_id %llX svc_infop NULL", statep,
		    statep->svcid);

		/* Send a REJ with invalid SID reason */
		ibcm_post_rej_mad(statep,
		    IBT_CM_INVALID_SID, IBT_CM_FAILURE_REQ, NULL, 0);
		return (IBCM_FAILURE);
	}

	if (svc_infop->svc_rc_handler == NULL) {
		mutex_exit(&ibcm_svc_info_lock);

		/* Send a REJ with invalid SID reason */
		ibcm_post_rej_mad(statep,
		    IBT_CM_INVALID_SRV_TYPE, IBT_CM_FAILURE_REQ, NULL, 0);
		return (IBCM_FAILURE);
	}

	/*
	 * Check if ServiceID is in RDMA IP CM SID range, if yes, we parse
	 * the REQ's Private Data and verify for it's goodness.
	 */
	if (((statep->svcid & IB_SID_IPADDR_PREFIX_MASK) == 0) &&
	    (statep->svcid & IB_SID_IPADDR_PREFIX)) {
		ibt_ari_ip_t	ari_ip;
		boolean_t	rdma_rej_mad = B_FALSE;

		ip_data = (ibcm_ip_pvtdata_t *)cm_req_msgp->req_private_data;

		bzero(&ari_ip, sizeof (ibt_ari_ip_t));

		/* RDMA IP CM Layer Rejects this */
		if (ip_data->ip_MajV != IBT_CM_IP_MAJ_VER) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_verify_req_gids_and_svcid:"
			    "IP MajorVer mis-match %d", ip_data->ip_MajV);
			ari_ip.ip_reason = IBT_ARI_IP_MAJOR_VERSION;
			ari_ip.ip_suggested_version = IBT_CM_IP_MAJ_VER;
			ari_ip.ip_suggested = B_TRUE;
			rdma_rej_mad = B_TRUE;
		} else if (ip_data->ip_MinV != IBT_CM_IP_MIN_VER) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_verify_req_gids_and_svcid:"
			    "IP MinorVer mis-match %d", ip_data->ip_MinV);
			ari_ip.ip_reason = IBT_ARI_IP_MINOR_VERSION;
			ari_ip.ip_suggested_version = IBT_CM_IP_MIN_VER;
			ari_ip.ip_suggested = B_TRUE;
			rdma_rej_mad = B_TRUE;
		} else if ((ip_data->ip_ipv != IBT_CM_IP_IPV_V4) &&
		    (ip_data->ip_ipv != IBT_CM_IP_IPV_V6)) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_verify_req_gids_and_svcid:"
			    " Invalid IPV specified %d", ip_data->ip_ipv);
			ari_ip.ip_reason = IBT_ARI_IP_IPV;
			ari_ip.ip_suggested_version = IBT_CM_IP_IPV_V4;
			ari_ip.ip_suggested = B_TRUE;
			rdma_rej_mad = B_TRUE;
		} else {
			/*
			 * Validate whether ip_addr specified are non-NULL.
			 *
			 * NOTE:
			 * RDMA ULP which is servicing this SID, should validate
			 * the correctness of srcip/dstip and accordingly post
			 * REJ related to ibt_ari_ip_reason_t of
			 * IBT_ARI_IP_SRC_ADDR, IBT_ARI_IP_DST_ADDR and
			 * IBT_ARI_IP_UNKNOWN_ADDR.
			 */
			if (ip_data->ip_ipv == IBT_CM_IP_IPV_V4) {
				if (ip_data->ip_srcv4 == 0) {
					IBTF_DPRINTF_L2(cmlog,
					    "ibcm_verify_req_gids_and_svcid: "
					    "Invalid NULL V4 SrcIp specified");
					rdma_rej_mad = B_TRUE;
					ari_ip.ip_reason = IBT_ARI_IP_SRC_ADDR;
					ari_ip.ip_suggested = B_TRUE;
					ari_ip.ip_suggested_version =
					    IBT_CM_IP_IPV_V4;
				} else if (ip_data->ip_dstv4 == 0) {
					IBTF_DPRINTF_L2(cmlog,
					    "ibcm_verify_req_gids_and_svcid: "
					    "Invalid NULL V4 DstIp specified");
					rdma_rej_mad = B_TRUE;
					ari_ip.ip_reason = IBT_ARI_IP_DST_ADDR;
					ari_ip.ip_suggested = B_TRUE;
					ari_ip.ip_suggested_version =
					    IBT_CM_IP_IPV_V4;
				}
			} else if (ip_data->ip_ipv == IBT_CM_IP_IPV_V6) {
				if (IN6_IS_ADDR_UNSPECIFIED(
				    &ip_data->ip_srcv6)) {
					IBTF_DPRINTF_L2(cmlog,
					    "ibcm_verify_req_gids_and_svcid: "
					    "Invalid NULL V6 SrcIp specified");
					rdma_rej_mad = B_TRUE;
					ari_ip.ip_reason = IBT_ARI_IP_SRC_ADDR;
					ari_ip.ip_suggested = B_TRUE;
					ari_ip.ip_suggested_version =
					    IBT_CM_IP_IPV_V6;
				} else if (IN6_IS_ADDR_UNSPECIFIED(
				    &ip_data->ip_dstv6)) {
					IBTF_DPRINTF_L2(cmlog,
					    "ibcm_verify_req_gids_and_svcid: "
					    "Invalid NULL V6 DstIp specified");
					rdma_rej_mad = B_TRUE;
					ari_ip.ip_reason = IBT_ARI_IP_DST_ADDR;
					ari_ip.ip_suggested = B_TRUE;
					ari_ip.ip_suggested_version =
					    IBT_CM_IP_IPV_V6;
				}
			}
			/* TBD: IBT_ARI_IP_UNKNOWN_ADDR */
		}
		if (rdma_rej_mad == B_TRUE) {
			ibt_ari_con_t	cons_rej;

			mutex_exit(&ibcm_svc_info_lock);

			cons_rej.rej_ari_len = 1 + sizeof (ibt_ari_ip_t);
			cons_rej.rej_ari[0] = 0; /* Rejected by CM Layer */
			bcopy(&ari_ip, &cons_rej.rej_ari[1],
			    sizeof (ibt_ari_ip_t));
			/* Send a REJ with CONSUMER REJ */
			ibcm_post_rej_mad(statep, IBT_CM_CONSUMER,
			    IBT_CM_FAILURE_REQ, &cons_rej,
			    sizeof (ibt_ari_con_t));
			return (IBCM_FAILURE);
		}
	}

	/* find the best "bind" entry that enables this port */

	pkey = b2h16(cm_req_msgp->req_part_key);
	svc_bindp = NULL;
	tmp_bindp = svc_infop->svc_bind_list;
	while (tmp_bindp) {
		if (tmp_bindp->sbind_hcaguid == hca_guid &&
		    tmp_bindp->sbind_port == port_num) {
			if (gid.gid_guid ==
			    tmp_bindp->sbind_gid.gid_guid &&
			    gid.gid_prefix ==
			    tmp_bindp->sbind_gid.gid_prefix) {
				/* gid match => really good match */
				svc_bindp = tmp_bindp;
				if (pkey == tmp_bindp->sbind_pkey)
					/* absolute best match */
					break;
			} else if (svc_bindp == NULL) {
				/* port match => a good match */
				svc_bindp = tmp_bindp;
			}
		}
		tmp_bindp = tmp_bindp->sbind_link;
	}
	if (svc_bindp == NULL) { /* port not enabled for this SID */
		mutex_exit(&ibcm_svc_info_lock);
		IBTF_DPRINTF_L2(cmlog,
		    "ibcm_verify_req_gids_and_svcid: statep 0x%p "
		    "no binding found", statep);
		ibcm_post_rej_mad(statep,
		    IBT_CM_INVALID_SID, IBT_CM_FAILURE_REQ, NULL, 0);
		return (IBCM_FAILURE);
	}
	/* copy the GID in case we need it in REJ below */
	gid.gid_prefix = b2h64(svc_bindp->sbind_gid.gid_prefix);
	gid.gid_guid = b2h64(svc_bindp->sbind_gid.gid_guid);

	statep->state_cm_private = svc_bindp->sbind_cm_private;
	statep->state_svc_infop = svc_infop;
	statep->cm_handler = svc_infop->svc_rc_handler;
	if (reject_reason == IBT_CM_SUCCESS)
		IBCM_SVC_INCR(svc_infop);
	mutex_exit(&ibcm_svc_info_lock);

	/*
	 * If the service id is valid, but gid in REQ is invalid,
	 * then send a REJ with invalid gid
	 * For Invalid primary gid, the ARI field is filled with
	 * with gid from svcinfo
	 * For invalid prim/alt gid reject, CM uses one of the gids
	 * registered in ARI.
	 * For invalid prim/alt lid reject, CM uses the base lid in ARI
	 */
	if (reject_reason != IBT_CM_SUCCESS) {

		switch (reject_reason) {

		case IBT_CM_PRIM_GID :
		case IBT_CM_ALT_GID :
			ibcm_post_rej_mad(statep,
			    reject_reason, IBT_CM_FAILURE_REQ,
			    &gid, sizeof (ib_gid_t));
			break;

		case IBT_CM_PRIM_LID :
		case IBT_CM_ALT_LID :

			lid = h2b16(port.hp_base_lid);
			ibcm_post_rej_mad(statep,
			    reject_reason, IBT_CM_FAILURE_REQ,
			    &lid, sizeof (ib_lid_t));
			break;
		}

		return (IBCM_FAILURE);
	}

	/* Service, primary/alt gid and lid are all valid */

	return (IBCM_SUCCESS);
}

/*
 * ibcm_cep_state_req:
 *	QP state transition function called for an incoming REQ on passive side
 *	LIDs and GIDs should be maintained and validated by the client handler
 *
 * INPUTS:
 *	statep		- state pointer
 *	cm_req_msgp	- REQ message pointer
 *	reject_reason	- Rejection reason See Section 12.6.7.2 rev1.0a IB Spec
 *	arej_info_len	- Additional Rejection reason info length
 *
 * RETURN VALUE: IBCM_SEND_REP/IBCM_SEND_REJ
 */
ibcm_status_t
ibcm_cep_state_req(ibcm_state_data_t *statep, ibcm_req_msg_t *cm_req_msgp,
    ibt_cm_reason_t *reject_reason, uint8_t *arej_len)
{
	void			*priv_data = NULL;
	ibt_cm_event_t		event;
	ibt_cm_status_t		cb_status;
	ibcm_status_t		status;
	ibt_cm_return_args_t	ret_args;
	ibcm_clnt_reply_info_t	clnt_info;

	IBTF_DPRINTF_L4(cmlog, "ibcm_cep_state_req: statep 0x%p", statep);
	IBTF_DPRINTF_L4(cmlog, "ibcm_cep_state_req: SID 0x%lX",
	    b2h64(cm_req_msgp->req_svc_id));
	/* client handler should be valid */
	ASSERT(statep->cm_handler != NULL);

	bzero(&event, sizeof (event));

	/* Fill in ibt_cm_event_t */
	event.cm_type = IBT_CM_EVENT_REQ_RCV;
	event.cm_session_id = statep;
	IBCM_EVT_REQ(event).req_service_id = b2h64(cm_req_msgp->req_svc_id);
	IBCM_EVT_REQ(event).req_transport =
	    ((uint8_t *)&cm_req_msgp->req_remote_eecn_plus)[3] >> 1 & 0x3;
	IBCM_EVT_REQ(event).req_timeout = ibt_ib2usec(
	    (((uint8_t *)&cm_req_msgp->req_remote_eecn_plus)[3] >> 3) & 0x1F);
	IBCM_EVT_REQ(event).req_retry_cnt =
	    ((uint8_t *)&cm_req_msgp->req_starting_psn_plus)[3] & 0x7;
	IBCM_EVT_REQ(event).req_rnr_retry_cnt = cm_req_msgp->req_mtu_plus & 0x7;
	IBCM_EVT_REQ(event).req_pkey = b2h16(cm_req_msgp->req_part_key);
	IBCM_EVT_REQ(event).req_rdma_ra_in =
	    ((uint8_t *)&cm_req_msgp->req_local_qpn_plus)[3];
	IBCM_EVT_REQ(event).req_rdma_ra_out =
	    ((uint8_t *)&cm_req_msgp->req_local_eec_no_plus)[3];

	/* Check for HCA limits for RDMA Resources */
	if (IBCM_EVT_REQ(event).req_rdma_ra_in >
	    statep->hcap->hca_max_rdma_in_qp) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_cep_state_req: statep 0x%p, REQ "
		    "req_rdma_ra_in %d is greater than HCA Limit %d, resetting"
		    "it to HCA limit", statep,
		    IBCM_EVT_REQ(event).req_rdma_ra_in,
		    statep->hcap->hca_max_rdma_in_qp);
		IBCM_EVT_REQ(event).req_rdma_ra_in =
		    statep->hcap->hca_max_rdma_in_qp;
	}

	if (IBCM_EVT_REQ(event).req_rdma_ra_out >
	    statep->hcap->hca_max_rdma_out_qp) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_cep_state_req: statep 0x%p, REQ "
		    "req_rdma_ra_out %d is greater than HCA Limit %d, resetting"
		    "it to HCA limit", statep,
		    IBCM_EVT_REQ(event).req_rdma_ra_out,
		    statep->hcap->hca_max_rdma_out_qp);
		IBCM_EVT_REQ(event).req_rdma_ra_out =
		    statep->hcap->hca_max_rdma_out_qp;
	}

	/* Account for CM and other software delays */
	if (IBCM_EVT_REQ(event).req_timeout > ibcm_sw_delay) {
		IBCM_EVT_REQ(event).req_timeout -= ibcm_sw_delay;
		IBTF_DPRINTF_L5(cmlog, "ibcm_cep_state_req: statep 0x%p"
		    "Avail resp time %d (usec)", statep,
		    IBCM_EVT_REQ(event).req_timeout);
	} else {
		IBTF_DPRINTF_L2(cmlog, "ibcm_cep_state_req: statep 0x%p "
		    "REQ rem_resp_time < local sw delay 0x%x", statep,
		    IBCM_EVT_REQ(event).req_timeout);

		IBCM_EVT_REQ(event).req_timeout = 0;
	}

	IBCM_EVT_REQ(event).req_prim_hca_port = statep->prim_port;
	IBCM_EVT_REQ(event).req_alt_hca_port = statep->alt_port;
	IBCM_EVT_REQ(event).req_hca_guid = statep->local_hca_guid;
	IBCM_EVT_REQ(event).req_remote_qpn = statep->remote_qpn;

	if (((uint8_t *)&cm_req_msgp->req_remote_eecn_plus)[3] &
	    IBT_CM_FLOW_CONTROL)
		IBCM_EVT_REQ(event).req_flags |= IBT_CM_FLOW_CONTROL;

	if ((cm_req_msgp->req_max_cm_retries_plus >> 3) & 0x1)
		IBCM_EVT_REQ(event).req_flags |= IBT_CM_SRQ_EXISTS;

	/* Initialize req.req_prim_addr */
	ibcm_set_primary_adds_vect(statep, &IBCM_EVT_REQ(event).req_prim_addr,
	    cm_req_msgp);

	/* Initialize req.req_alternate_path if they exist */
	if (b2h16(cm_req_msgp->req_alt_l_port_lid) != 0) {
		ibcm_set_alt_adds_vect(statep,
		    &IBCM_EVT_REQ(event).req_alt_addr, cm_req_msgp);

		/* Verify, alt path is not same as primary */
		if (ibcm_compare_prim_alt_paths(
		    &event.cm_event.req.req_prim_addr,
		    &event.cm_event.req.req_alt_addr) == B_TRUE) {
			/* XXX New REJ code needed */
			*reject_reason = IBT_CM_NO_RESC;
			IBTF_DPRINTF_L2(cmlog, "ibcm_cep_state_req: statep 0x%p"
			    " Alt and prim paths are same", statep);
			mutex_enter(&ibcm_svc_info_lock);
			IBCM_SVC_DECR(statep->state_svc_infop);
			mutex_exit(&ibcm_svc_info_lock);
			return (IBCM_SEND_REJ);
		}
	}

#ifdef	NO_EEC_SUPPORT_YET
	IBCM_EVT_REQ(event).req_rdc_exists = cm_req_msgp->req_mtu_plus >> 3 & 1;
	IBCM_EVT_REQ(event).req_remote_eecn =
	    b2h32(cm_req_msgp->req_remote_eecn_plus) >> 8;
	IBCM_EVT_REQ(event).req_local_eecn =
	    b2h32(cm_req_msgp->req_local_eec_no_plus) >> 8;
	IBCM_EVT_REQ(event).req_remote_qkey =
	    b2h32(cm_req_msgp->req_local_qkey);
#endif

	/* cm_req_msgp->req_private_data to event.cm_event.cm_priv_data */
	event.cm_priv_data = cm_req_msgp->req_private_data;

	event.cm_priv_data_len = IBT_REQ_PRIV_DATA_SZ;

	/*
	 * Allocate priv_data of size IBT_MAX_PRIV_DATA_SZ
	 */
	priv_data = kmem_zalloc(IBT_MAX_PRIV_DATA_SZ, KM_SLEEP);

	bzero(&ret_args, sizeof (ret_args));

	/* Fill in the default values from REQ, that client can modify */
	ret_args.cm_ret.rep.cm_rdma_ra_in = IBCM_EVT_REQ(event).req_rdma_ra_out;
	ret_args.cm_ret.rep.cm_rdma_ra_out = IBCM_EVT_REQ(event).req_rdma_ra_in;
	ret_args.cm_ret.rep.cm_rnr_retry_cnt = cm_req_msgp->req_mtu_plus & 0x7;

	ibcm_insert_trace(statep, IBCM_TRACE_CALLED_REQ_RCVD_EVENT);

	/* Invoke the client handler */
	statep->req_msgp = cm_req_msgp;
	cb_status = statep->cm_handler(statep->state_cm_private, &event,
	    &ret_args, priv_data, IBT_REP_PRIV_DATA_SZ);
	statep->req_msgp = NULL;

	ibcm_insert_trace(statep, IBCM_TRACE_RET_REQ_RCVD_EVENT);

	mutex_enter(&ibcm_svc_info_lock);
	IBCM_SVC_DECR(statep->state_svc_infop);
	mutex_exit(&ibcm_svc_info_lock);

	IBTF_DPRINTF_L4(cmlog, "ibcm_cep_state_req: Client handler returned %d"
	    " statep 0x%p", cb_status, statep);

	if (cb_status == IBT_CM_DEFER) {

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(statep->defer_cm_msg))

		if (statep->defer_cm_msg == NULL)
			statep->defer_cm_msg =
			    kmem_zalloc(IBCM_MSG_SIZE, KM_SLEEP);
		bcopy(cm_req_msgp, statep->defer_cm_msg, IBCM_MSG_SIZE);

		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(statep->defer_cm_msg))

		/*
		 * unblock any blocked cm proceed api calls. Do not access
		 * statep after cv_signal
		 */
		mutex_enter(&statep->state_mutex);
		statep->clnt_proceed = IBCM_UNBLOCK;
		cv_broadcast(&statep->block_client_cv);
		mutex_exit(&statep->state_mutex);

		kmem_free(priv_data, IBT_MAX_PRIV_DATA_SZ);
		return (IBCM_DEFER);
	}

	/* fail any blocked cm proceed api call - client bug */
	mutex_enter(&statep->state_mutex);
	statep->clnt_proceed = IBCM_FAIL;
	cv_broadcast(&statep->block_client_cv);
	mutex_exit(&statep->state_mutex);

	clnt_info.reply_event = (ibt_cm_proceed_reply_t *)&ret_args.cm_ret;
	clnt_info.priv_data = priv_data;
	clnt_info.priv_data_len = ret_args.cm_ret_len;

	status =
	    ibcm_process_cep_req_cm_hdlr(statep, cb_status,
	    &clnt_info, reject_reason, arej_len, cm_req_msgp);
	kmem_free(priv_data, IBT_MAX_PRIV_DATA_SZ);
	return (status);
}

/*
 * ibcm_process_cep_req_cm_hdlr:
 *	Processes the response from client handler for an incoming REQ.
 */
ibcm_status_t
ibcm_process_cep_req_cm_hdlr(ibcm_state_data_t *statep,
    ibt_cm_status_t cb_status, ibcm_clnt_reply_info_t *clnt_info,
    ibt_cm_reason_t *reject_reason, uint8_t *arej_len,
    ibcm_req_msg_t *cm_req_msg)
{
	ibt_status_t		status;
	ibt_qp_query_attr_t	qp_attrs;
	ibcm_state_data_t	*old_statep;
	ibt_channel_hdl_t	channel;
	ib_guid_t		local_ca_guid;
	ibcm_rej_msg_t		*rej_msgp;
#ifdef	NO_EEC_SUPPORT_YET
	ibt_eec_query_attr_t	eec_attrs;
#endif

	if (cb_status == IBT_CM_DEFAULT)
		cb_status = IBT_CM_REJECT;

	/* verify status */
	if (cb_status == IBT_CM_ACCEPT) {
		*reject_reason = IBT_CM_SUCCESS;
	} else if (cb_status == IBT_CM_REJECT) {
		*reject_reason = IBT_CM_CONSUMER;
	} else if (cb_status == IBT_CM_REDIRECT_PORT) {
		*reject_reason = IBT_CM_PORT_REDIRECT;
	} else if (cb_status == IBT_CM_REDIRECT) {
		*reject_reason = IBT_CM_REDIRECT_CM;
	} else if (cb_status == IBT_CM_NO_CHANNEL) {
		*reject_reason = IBT_CM_NO_CHAN;
	} else if (cb_status == IBT_CM_NO_RESOURCE) {
		*reject_reason = IBT_CM_NO_RESC;
	} else {
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_cep_req_cm_hdlr: statep %p"
		    " Client handler unexpected return %x", statep, cb_status);
		*reject_reason = IBT_CM_CONSUMER;
	}

	/* client handler gave CM ok */
	if (cb_status == IBT_CM_ACCEPT) {
		ibcm_rep_msg_t	*rep_msgp = (ibcm_rep_msg_t *)
		    IBCM_OUT_MSGP(statep->stored_msg);


		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*statep))
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*rep_msgp))

		/*
		 * Check first if ret_args make sense. If not, bailout
		 * here rather than going along and panicing later.
		 */
		channel = clnt_info->reply_event->rep.cm_channel;
		if (IBCM_INVALID_CHANNEL(channel)) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_cep_req_cm_hdlr: "
			    "statep 0x%p server's QP handle is NULL", statep);
			*reject_reason = IBT_CM_NO_CHAN;
		}

		IBCM_GET_CHAN_PRIVATE(channel, old_statep);

		if ((*reject_reason == IBT_CM_SUCCESS) &&
		    (old_statep != NULL)) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_cep_req_cm_hdlr: "
			    "statep 0x%p Channel being re-used on passive side",
			    statep);
			*reject_reason = IBT_CM_NO_CHAN;
		}
		if (old_statep != NULL)
			IBCM_RELEASE_CHAN_PRIVATE(channel);

		if (*reject_reason != IBT_CM_SUCCESS) {
			ibcm_handler_conn_fail(statep, IBT_CM_FAILURE_REJ_SENT,
			    IBT_CM_FAILURE_REQ, *reject_reason, NULL, 0);
			return (IBCM_SEND_REJ);
		}

		statep->channel = channel;
		status = ibt_query_qp(channel, &qp_attrs);

		if (status != IBT_SUCCESS) {
			IBTF_DPRINTF_L3(cmlog, "ibcm_process_cep_req_cm_hdlr: "
			    "statep %p ibt_query_qp failed %d", statep, status);
			*reject_reason = IBT_CM_NO_RESC;
			ibcm_handler_conn_fail(statep, IBT_CM_FAILURE_REJ_SENT,
			    IBT_CM_FAILURE_REQ, IBT_CM_CI_FAILURE, NULL, 0);
			return (IBCM_SEND_REJ);
		}

		if (qp_attrs.qp_info.qp_trans != IBT_RC_SRV) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_cep_req_cm_hdlr: "
			    "statep %p qp is not RC channel on server", statep);
			*reject_reason = IBT_CM_INVALID_SRV_TYPE;
			ibcm_handler_conn_fail(statep, IBT_CM_FAILURE_REJ_SENT,
			    IBT_CM_FAILURE_REQ, IBT_CM_CHAN_INVALID_STATE,
			    NULL, 0);
			return (IBCM_SEND_REJ);
		}

		if (qp_attrs.qp_info.qp_state != IBT_STATE_INIT &&
		    statep->is_this_ofuv_chan == B_FALSE) {
			IBTF_DPRINTF_L3(cmlog, "ibcm_process_cep_req_cm_hdlr: "
			    "qp state != INIT on server");
			*reject_reason = IBT_CM_CHAN_INVALID_STATE;
			ibcm_handler_conn_fail(statep, IBT_CM_FAILURE_REJ_SENT,
			    IBT_CM_FAILURE_REQ, IBT_CM_CHAN_INVALID_STATE,
			    NULL, 0);
			return (IBCM_SEND_REJ);
		} else if (statep->is_this_ofuv_chan &&
		    qp_attrs.qp_info.qp_state != IBT_STATE_RTR &&
		    qp_attrs.qp_info.qp_state != IBT_STATE_INIT) {
			IBTF_DPRINTF_L3(cmlog, "ibcm_process_cep_req_cm_hdlr: "
			    "qp state != INIT or RTR on server");
			*reject_reason = IBT_CM_CHAN_INVALID_STATE;
			ibcm_handler_conn_fail(statep, IBT_CM_FAILURE_REJ_SENT,
			    IBT_CM_FAILURE_REQ, IBT_CM_CHAN_INVALID_STATE,
			    NULL, 0);
			return (IBCM_SEND_REJ);
		}

		if (statep->is_this_ofuv_chan &&
		    qp_attrs.qp_info.qp_state == IBT_STATE_RTR &&
		    qp_attrs.qp_info.qp_transport.rc.rc_path.cep_hca_port_num !=
		    statep->prim_port) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_cep_req_cm_hdlr: "
			    "QP port invalid");
			*reject_reason = IBT_CM_CHAN_INVALID_STATE;
			ibcm_handler_conn_fail(statep, IBT_CM_FAILURE_REJ_SENT,
			    IBT_CM_FAILURE_REQ, IBT_CM_CHAN_INVALID_STATE,
			    NULL, 0);
			return (IBCM_SEND_REJ);
		} else if (statep->is_this_ofuv_chan &&
		    qp_attrs.qp_info.qp_state == IBT_STATE_RTR) {
			goto skip_init_trans;
		}

		/* Init to Init, if required */
		if (qp_attrs.qp_info.qp_transport.rc.rc_path.cep_hca_port_num !=
		    statep->prim_port) {

			ibt_qp_info_t		qp_info;
			ibt_cep_modify_flags_t	cep_flags;

			IBTF_DPRINTF_L5(cmlog, "ibcm_process_cep_req_cm_hdlr: "
			    "chan 0x%p chan port %d", channel,
			    qp_attrs.qp_info.qp_transport.rc.rc_path.\
			    cep_hca_port_num);

			IBTF_DPRINTF_L5(cmlog, "ibcm_process_cep_req_cm_hdlr: "
			    "chan 0x%p d path port %d", channel,
			    statep->prim_port);

			bzero(&qp_info, sizeof (qp_info));
			qp_info.qp_trans = IBT_RC_SRV;
			qp_info.qp_state = IBT_STATE_INIT;
			qp_info.qp_transport.rc.rc_path.cep_hca_port_num =
			    statep->prim_port;

			cep_flags = IBT_CEP_SET_STATE | IBT_CEP_SET_PORT;

			status = ibt_modify_qp(statep->channel, cep_flags,
			    &qp_info, NULL);

			if (status != IBT_SUCCESS) {
				IBTF_DPRINTF_L2(cmlog,
				    "ibcm_process_cep_req_cm_hdlr: "
				    "chan 0x%p ibt_modify_qp() = %d", channel,
				    status);
				*reject_reason = IBT_CM_NO_RESC;

				ibcm_insert_trace(statep,
				    IBCM_TRACE_INIT_INIT_FAIL);

				ibcm_handler_conn_fail(statep,
				    IBT_CM_FAILURE_REJ_SENT, IBT_CM_FAILURE_REQ,
				    IBT_CM_CI_FAILURE, NULL, 0);
				return (IBCM_SEND_REJ);
			} else {
				ibcm_insert_trace(statep,
				    IBCM_TRACE_INIT_INIT);

				IBTF_DPRINTF_L5(cmlog,
				    "ibcm_process_cep_req_cm_hdlr: "
				    "chan 0x%p ibt_modify_qp() = %d", channel,
				    status);
			}
		}
skip_init_trans:
		/* Do sanity tests even if we are skipping RTR */

		/* fill in the REP msg based on ret_args from client */
		if (clnt_info->reply_event->rep.cm_rdma_ra_out >
		    ((uint8_t *)&cm_req_msg->req_local_qpn_plus)[3]) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_req_cm_hdlr "
			    "statep 0x%p ERROR: InitiatorDepth(%d) is Greater "
			    "than ResponderResource(%d)", statep,
			    clnt_info->reply_event->rep.cm_rdma_ra_out,
			    ((uint8_t *)&cm_req_msg->req_local_qpn_plus)[3]);
			*reject_reason = IBT_CM_NOT_SUPPORTED;
			ibcm_handler_conn_fail(statep, IBT_CM_FAILURE_REJ_SENT,
			    IBT_CM_FAILURE_REQ, IBT_CM_NOT_SUPPORTED, NULL, 0);
			return (IBCM_SEND_REJ);
		}

		/* Check for HCA limits for RDMA Resources */
		if (clnt_info->reply_event->rep.cm_rdma_ra_in >
		    statep->hcap->hca_max_rdma_in_qp) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_req_cm_hdlr: "
			    "statep %p, ERROR: client specified rdma_ra_in %d "
			    "is greater than HCA Limit %d, rejecting MAD",
			    statep, clnt_info->reply_event->rep.cm_rdma_ra_in,
			    statep->hcap->hca_max_rdma_in_qp);
			*reject_reason = IBT_CM_NOT_SUPPORTED;
			ibcm_handler_conn_fail(statep, IBT_CM_FAILURE_REJ_SENT,
			    IBT_CM_FAILURE_REQ, IBT_CM_NOT_SUPPORTED, NULL, 0);
			return (IBCM_SEND_REJ);
		}

		if (clnt_info->reply_event->rep.cm_rdma_ra_out >
		    statep->hcap->hca_max_rdma_out_qp) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_req_cm_hdlr: "
			    "statep %p, ERROR: client specified rdma_ra_out %d "
			    "is greater than HCA Limit %d, rejecting MAD",
			    statep, clnt_info->reply_event->rep.cm_rdma_ra_out,
			    statep->hcap->hca_max_rdma_out_qp);
			*reject_reason = IBT_CM_NOT_SUPPORTED;
			ibcm_handler_conn_fail(statep, IBT_CM_FAILURE_REJ_SENT,
			    IBT_CM_FAILURE_REQ, IBT_CM_NOT_SUPPORTED, NULL, 0);
			return (IBCM_SEND_REJ);
		}

		rep_msgp->rep_resp_resources =
		    clnt_info->reply_event->rep.cm_rdma_ra_in;
		rep_msgp->rep_initiator_depth =
		    clnt_info->reply_event->rep.cm_rdma_ra_out;

		/* IBT_CM_FLOW_CONTROL is always set by default. */
		rep_msgp->rep_target_delay_plus |= IBT_CM_FLOW_CONTROL;

		rep_msgp->rep_rnr_retry_cnt_plus =
		    (clnt_info->reply_event->rep.cm_rnr_retry_cnt & 0x7) << 5;

		/*
		 * Check out whether SRQ is associated with this channel.
		 * If yes, then set the appropriate bit.
		 */
		if (qp_attrs.qp_srq != NULL) {
			rep_msgp->rep_rnr_retry_cnt_plus |= (1 << 4);
		}

		local_ca_guid = h2b64(statep->local_hca_guid);
		bcopy(&local_ca_guid, rep_msgp->rep_local_ca_guid,
		    sizeof (ib_guid_t));

		if (statep->is_this_ofuv_chan &&
		    qp_attrs.qp_info.qp_state == IBT_STATE_RTR)
			goto skip_rtr_trans;

		/* Transition QP from Init to RTR state */
		if (ibcm_invoke_qp_modify(statep, cm_req_msg, rep_msgp) !=
		    IBT_SUCCESS) {

			IBTF_DPRINTF_L2(cmlog, "ibcm_process_req_cm_hdlr "
			    "statep 0x%p ibcm_invoke_qp_modify failed because "
			    "of invalid data", statep);
			*reject_reason = IBT_CM_NO_RESC;
			ibcm_handler_conn_fail(statep, IBT_CM_FAILURE_REJ_SENT,
			    IBT_CM_FAILURE_REQ, IBT_CM_CI_FAILURE, NULL, 0);
			return (IBCM_SEND_REJ);
		}
skip_rtr_trans:

		/*
		 * Link statep and channel, once CM determines it is
		 * post REP definitely.
		 */
		IBCM_SET_CHAN_PRIVATE(statep->channel, statep);

		/*
		 * Fill up the REP fields from ret_args
		 * failover status,  from ret_args
		 *
		 * Fill up local QPN and EECN from ret_args->channel
		 */

		/* fill in REP msg bytes Qkey, Starting PSN, 12-15, and 16-19 */
		IBTF_DPRINTF_L4(cmlog, "ibcm_process_cep_req_cm_hdlr: "
		    "qp_info.qp_state = %x", qp_attrs.qp_info.qp_state);

		rep_msgp->rep_local_qpn_plus = h2b32(qp_attrs.qp_qpn << 8);

		statep->local_qpn = qp_attrs.qp_qpn;

		switch (qp_attrs.qp_info.qp_trans) {
		case IBT_RD_SRV:
			rep_msgp->rep_local_qkey = h2b32(
			    qp_attrs.qp_info.qp_transport.rd.rd_qkey);
			break;
		case IBT_RC_SRV:
			rep_msgp->rep_starting_psn_plus =
			    h2b32(IBCM_QP_RC(qp_attrs).rc_rq_psn << 8);
			break;
		case IBT_UC_SRV:
			rep_msgp->rep_starting_psn_plus =
			    h2b32(IBCM_QP_UC(qp_attrs).uc_sq_psn << 8);
			break;
		}

#ifdef	NO_EEC_SUPPORT_YET
		if (ret_args.cm_channel.ch_eec != NULL) {
			status = ibt_query_eec(ret_args.cm_channel.ch_eec,
			    &eec_attrs);
			if (status == IBT_SUCCESS) {
				rep_msgp->rep_local_eecn_plus =
				    h2b32(((uint32_t)eec_attrs.eec_eecn << 8));
			}
		}
#endif

		/* figure out Target ACK delay */
		rep_msgp->rep_target_delay_plus |= (status == IBT_SUCCESS) ?
		    statep->hcap->hca_ack_delay << 3 : 0;

		IBTF_DPRINTF_L4(cmlog, "ibcm_process_cep_req_cm_hdlr:statep %p "
		    "REP priv len %x", statep, clnt_info->priv_data_len);
		/* Copy PrivateData from priv_data */
		if (clnt_info->priv_data_len != 0) {
			bcopy(clnt_info->priv_data, rep_msgp->rep_private_data,
			    min(IBT_REP_PRIV_DATA_SZ,
			    clnt_info->priv_data_len));
		}

		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*statep))
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*rep_msgp))

		return (IBCM_SEND_REP);
	}

	/* REJ message */
	rej_msgp = (ibcm_rej_msg_t *)IBCM_OUT_MSGP(statep->stored_msg);

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_cep_req_cm_hdlr: statep %p REJ "
	    "priv len %x", statep, clnt_info->priv_data_len);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*rej_msgp))

	/* if priv_data_len != 0 use priv_data to copy back to rej_priv_data */
	if (clnt_info->priv_data_len != 0) {
		bcopy(clnt_info->priv_data, rej_msgp->rej_private_data,
		    min(IBT_REJ_PRIV_DATA_SZ, clnt_info->priv_data_len));
	}

	if (cb_status == IBT_CM_REDIRECT_PORT) {
		ib_gid_t tgid;

		tgid.gid_guid =
		    h2b64(clnt_info->reply_event->rej.ari_gid.gid_guid);
		tgid.gid_prefix =
		    h2b64(clnt_info->reply_event->rej.ari_gid.gid_prefix);

		*arej_len = sizeof (ib_gid_t);
		bcopy(&tgid, &rej_msgp->rej_addl_rej_info, sizeof (ib_gid_t));

		IBTF_DPRINTF_L3(cmlog, "ibcm_process_cep_req_cm_hdlr: ari_gid= "
		    "%llX:%llX", tgid.gid_prefix, tgid.gid_guid);

	} else if (cb_status == IBT_CM_REDIRECT) {
		ibcm_classportinfo_msg_t	tclp;

		ibcm_init_clp_to_mad(&tclp,
		    &clnt_info->reply_event->rej.ari_redirect);
		bcopy(&tclp, rej_msgp->rej_addl_rej_info, sizeof (tclp));

		*arej_len = sizeof (ibcm_classportinfo_msg_t);

	} else if (cb_status == IBT_CM_REJECT) {

		/* Fill up the REJ fields, from ret_args */
		*arej_len = min(
		    clnt_info->reply_event->rej.ari_consumer.rej_ari_len,
		    IBT_CM_ADDL_REJ_LEN);
		bcopy(clnt_info->reply_event->rej.ari_consumer.rej_ari,
		    &rej_msgp->rej_addl_rej_info, *arej_len);

		/*
		 * RDMA IP REQ was passed up to the ULP, the ULP decided to do
		 * a "normal" consumer REJ, by the returning IBT_CM_REJECT in
		 * the cm handler.
		 * CM has to do some extra stuff too, it has to
		 * a) return REJ code 28 (consumer) and b) put 0x1 in the first
		 * byte of the ARI data, to indicate that this is a RDMA aware
		 * ULP that is doing a consumer reject.  The ULP should have
		 * put its consumer specific data into ibt_arej_info_t(9s) at
		 * byte 1 of the rej_ari[] array.
		 */
		if (((statep->svcid & IB_SID_IPADDR_PREFIX_MASK) == 0) &&
		    (statep->svcid & IB_SID_IPADDR_PREFIX)) {
			rej_msgp->rej_addl_rej_info[0] = 1;
		}
	}

	rej_msgp->rej_msg_type_plus = IBT_CM_FAILURE_REQ << 6;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*rej_msgp))

	return (IBCM_SEND_REJ);
}

/*
 * ibcm_cep_state_rep:
 *	QP state transition function called for an incoming REP on active side
 *
 * INPUTS:
 *	statep		- state pointer
 *	cm_rep_msg	- REP message pointer
 *	reject_reason	- Rejection reason See Section 12.6.7.2 rev1.0a IB Spec
 *
 * RETURN VALUE:
 */
ibcm_status_t
ibcm_cep_state_rep(ibcm_state_data_t *statep, ibcm_rep_msg_t *cm_rep_msgp,
    ibt_cm_reason_t *reject_reason, uint8_t *arej_len)
{
	void			*priv_data = NULL;
	ibcm_status_t		rval = IBCM_SEND_RTU;
	ibt_cm_event_t		event;
	ibt_cm_status_t		cb_status = IBT_CM_ACCEPT;
	ibt_cm_return_args_t	ret_args;
	ibcm_clnt_reply_info_t	clnt_info;
	uint8_t			req_init_depth;

	IBTF_DPRINTF_L3(cmlog, "ibcm_cep_state_rep: statep 0x%p", statep);

	/* Check first if client handler is valid */
	if (statep->cm_handler != NULL) {
		/* initialize fields in ibt_cm_event_t */
		bzero(&event, sizeof (event));
		event.cm_type = IBT_CM_EVENT_REP_RCV;
		event.cm_channel = statep->channel;
		event.cm_session_id = statep;

		IBCM_EVT_REP(event).rep_rdma_ra_in =
		    cm_rep_msgp->rep_initiator_depth;
		req_init_depth =
		    ((uint8_t *)&(((ibcm_req_msg_t *)IBCM_OUT_MSGP(
		    statep->stored_msg))->req_local_eec_no_plus))[3];
		IBCM_EVT_REP(event).rep_rdma_ra_out =
		    min(cm_rep_msgp->rep_resp_resources, req_init_depth);

		IBTF_DPRINTF_L3(cmlog, "ibcm_cep_state_rep: statep 0x%p, "
		    "InitDepth %d, RespResr %d", statep,
		    cm_rep_msgp->rep_initiator_depth,
		    IBCM_EVT_REP(event).rep_rdma_ra_out);

		IBCM_EVT_REP(event).rep_service_time = ibt_ib2usec(
		    ((uint8_t *)&(((ibcm_req_msg_t *)IBCM_OUT_MSGP(
		    statep->stored_msg))->req_starting_psn_plus))[3] >> 3);

		IBCM_EVT_REP(event).rep_service_time -=
		    2 * statep->pkt_life_time - ibcm_sw_delay;

		IBCM_EVT_REP(event).rep_failover_status =
		    cm_rep_msgp->rep_target_delay_plus >> 1 & 3;

		if (cm_rep_msgp->rep_target_delay_plus & 0x1)
			IBCM_EVT_REP(event).rep_flags |= IBT_CM_FLOW_CONTROL;

		if ((cm_rep_msgp->rep_rnr_retry_cnt_plus >> 4) & 0x1)
			IBCM_EVT_REP(event).rep_flags |= IBT_CM_SRQ_EXISTS;

		IBTF_DPRINTF_L4(cmlog, "ibcm_cep_state_rep: statep 0x%p "
		    "rep_service_time %d", statep,
		    IBCM_EVT_REP(event).rep_service_time);

		event.cm_priv_data = &(cm_rep_msgp->rep_private_data[0]);
		event.cm_priv_data_len = IBT_REP_PRIV_DATA_SZ;

		/*
		 * Allocate priv_data of size IBT_MAX_PRIV_DATA_SZ
		 */
		priv_data = kmem_zalloc(IBT_MAX_PRIV_DATA_SZ, KM_SLEEP);
		bzero(&ret_args, sizeof (ret_args));


		ibcm_insert_trace(statep, IBCM_TRACE_CALLED_REP_RCVD_EVENT);

		/* invoke the CM handler */
		cb_status = statep->cm_handler(statep->state_cm_private, &event,
		    &ret_args, priv_data, IBT_RTU_PRIV_DATA_SZ);

		ibcm_insert_trace(statep, IBCM_TRACE_RET_REP_RCVD_EVENT);

		IBTF_DPRINTF_L4(cmlog, "ibcm_cep_state_rep: statep 0x%p "
		    "Client handler returned %x", statep, cb_status);

		if (cb_status == IBT_CM_DEFER) {
			if (statep->defer_cm_msg == NULL)
				statep->defer_cm_msg =
				    kmem_zalloc(IBCM_MSG_SIZE, KM_SLEEP);
			bcopy(cm_rep_msgp, statep->defer_cm_msg, IBCM_MSG_SIZE);

			/* unblock any blocked cm proceed api calls */
			mutex_enter(&statep->state_mutex);
			statep->clnt_proceed = IBCM_UNBLOCK;
			cv_broadcast(&statep->block_client_cv);
			mutex_exit(&statep->state_mutex);

			kmem_free(priv_data, IBT_MAX_PRIV_DATA_SZ);
			return (IBCM_DEFER);
		}
	}

	/* fail any blocked cm proceed api calls - client bug */
	mutex_enter(&statep->state_mutex);
	statep->clnt_proceed = IBCM_FAIL;
	cv_broadcast(&statep->block_client_cv);
	mutex_exit(&statep->state_mutex);

	clnt_info.reply_event = (ibt_cm_proceed_reply_t *)&ret_args.cm_ret;
	clnt_info.priv_data = priv_data;
	clnt_info.priv_data_len = ret_args.cm_ret_len;

	rval =
	    ibcm_process_cep_rep_cm_hdlr(statep, cb_status, &clnt_info,
	    reject_reason, arej_len, cm_rep_msgp);

	if (priv_data != NULL)
		kmem_free(priv_data, IBT_MAX_PRIV_DATA_SZ);
	return (rval);
}


/*
 * ibcm_process_cep_rep_cm_hdlr:
 *	Processes the response from client handler for an incoming REP.
 */
ibcm_status_t
ibcm_process_cep_rep_cm_hdlr(ibcm_state_data_t *statep,
    ibt_cm_status_t cb_status, ibcm_clnt_reply_info_t *clnt_info,
    ibt_cm_reason_t *reject_reason, uint8_t *arej_len,
    ibcm_rep_msg_t *cm_rep_msgp)
{
	ibcm_status_t		rval = IBCM_SEND_RTU;
	ibcm_rej_msg_t		*rej_msgp;

	if (cb_status == IBT_CM_DEFAULT)
		cb_status = IBT_CM_ACCEPT;

	if (cb_status == IBT_CM_REJECT) {
		*reject_reason = IBT_CM_CONSUMER;
	} else if (cb_status == IBT_CM_REDIRECT_PORT) {
		*reject_reason = IBT_CM_PORT_REDIRECT;
	} else if (cb_status == IBT_CM_REDIRECT) {
		*reject_reason = IBT_CM_REDIRECT_CM;
	} else if (cb_status == IBT_CM_NO_RESOURCE) {
		*reject_reason = IBT_CM_NO_RESC;
	} else if (cb_status != IBT_CM_ACCEPT) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_cep_rep_cm_hdlr: statep "
		    "0x%p, Client handler returned unexpected value %d",
		    statep, cb_status);
		*reject_reason = IBT_CM_CONSUMER;
	} else
		*reject_reason = IBT_CM_SUCCESS;


	/* We come here if status is ACCEPT or CM handler is NULL */
	if (cb_status == IBT_CM_ACCEPT) {
		ib_time_t	time;

		time = ibt_usec2ib(statep->pkt_life_time * 2 +
		    ibt_ib2usec(cm_rep_msgp->rep_target_delay_plus >> 3));

		IBTF_DPRINTF_L5(cmlog, "ibcm_process_cep_rep_cm_hdlr: statep %p"
		    " active cep_timeout(usec) 0x%x ", statep, time);

		IBTF_DPRINTF_L4(cmlog, "ibcm_process_cep_rep_cm_hdlr: statep %p"
		    " passive hca_ack_delay(ib_time) = 0x%x, ", statep,
		    cm_rep_msgp->rep_target_delay_plus >> 3);

		IBTF_DPRINTF_L5(cmlog, "ibcm_process_cep_rep_cm_hdlr: statep %p"
		    " rnr_retry_cnt = 0x%x", statep,
		    cm_rep_msgp->rep_rnr_retry_cnt_plus >> 5);

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*statep))
		statep->starting_psn =
		    b2h32(cm_rep_msgp->rep_starting_psn_plus) >> 8;

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*statep))

		/* Call IBTL CM's qp modify function from Init to RTR */
		if (ibcm_invoke_qp_modify(statep,
		    (ibcm_req_msg_t *)IBCM_OUT_MSGP(statep->stored_msg),
		    cm_rep_msgp) != IBT_SUCCESS) {

			IBTF_DPRINTF_L2(cmlog, "ibcm_process_cep_rep_cm_hdlr: "
			    "statep %p, ibcm_invoke_qp_modify to RTR failed",
			    statep);
			*reject_reason = IBT_CM_NO_RESC;
		/*
		 * Call modify qp function from RTR to RTS
		 * RDMA initiator depth on active is same as negotiated
		 * passive REP's responder resources
		 */
		} else if (ibcm_invoke_rtu_qp_modify(statep, time, cm_rep_msgp)
		    != IBT_SUCCESS) {

			IBTF_DPRINTF_L2(cmlog, "ibcm_process_cep_rep_cm_hdlr: "
			    "statep %p ibcm_invoke_rtu_qp_modify to RTS failed",
			    statep);
			(void) ibcm_cep_to_error_state(statep);
			*reject_reason = IBT_CM_NO_RESC;
		}

		if (*reject_reason == IBT_CM_NO_RESC) {

			/* Disassociate statep and QP */
			IBCM_SET_CHAN_PRIVATE(statep->channel, NULL);

			ibcm_handler_conn_fail(statep, IBT_CM_FAILURE_REJ_SENT,
			    IBT_CM_FAILURE_REP, IBT_CM_CI_FAILURE, NULL, 0);
			return (IBCM_SEND_REJ);	/* send REJ */
		}

		if (clnt_info->priv_data_len != 0) {
			ibcm_rtu_msg_t *rtu_msgp;
			rtu_msgp = (ibcm_rtu_msg_t *)
			    IBCM_OUT_MSGP(statep->stored_msg);
			bcopy(clnt_info->priv_data, rtu_msgp->rtu_private_data,
			    min(IBT_RTU_PRIV_DATA_SZ,
			    clnt_info->priv_data_len));
		}

		*reject_reason = IBT_CM_SUCCESS;
		return (rval);
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*rej_msgp))

	/* Fill up the REJ fields, from ret_args */
	rej_msgp = (ibcm_rej_msg_t *)IBCM_OUT_MSGP(statep->stored_msg);
	rej_msgp->rej_msg_type_plus = IBT_CM_FAILURE_REP << 6;

	/* if priv_len != 0 use priv_data to copy back to rej_priv_data */
	if (clnt_info->priv_data_len != 0)
		bcopy(clnt_info->priv_data, rej_msgp->rej_private_data,
		    min(IBT_REJ_PRIV_DATA_SZ, clnt_info->priv_data_len));

	if (clnt_info->reply_event != NULL)
		*arej_len =
		    min(clnt_info->reply_event->rej.ari_consumer.rej_ari_len,
		    IBT_CM_ADDL_REJ_LEN);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(clnt_info->reply_event->rej))

	if (*arej_len != 0)	/* asserts that clnt_info->reply_event != 0 */
		bcopy(clnt_info->reply_event->rej.ari_consumer.rej_ari,
		    &rej_msgp->rej_addl_rej_info, *arej_len);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(clnt_info->reply_event->rej))

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*rej_msgp))

	rval = IBCM_SEND_REJ;

	/* Disassociate statep and QP */
	IBCM_SET_CHAN_PRIVATE(statep->channel, NULL);

	/* callback client, to enable client to do resource cleanup */
	ibcm_handler_conn_fail(statep, IBT_CM_FAILURE_REJ_SENT,
	    IBT_CM_FAILURE_REP, *reject_reason, NULL, 0);

	return (rval);
}

/*
 * ibcm_invoke_rtu_qp_modify:
 *	Helper function to modify QP for RTU only called from
 *	ibcm_cep_state_rtu() and ibcm_cep_send_rtu()
 *
 * INPUTS:
 *	statep		- connection state pointer
 *
 * RETURN VALUE:
 */
static ibt_status_t
ibcm_invoke_rtu_qp_modify(ibcm_state_data_t *statep, ib_time_t timeout,
    ibcm_rep_msg_t *rep_msg)
{
	ibt_status_t		status;
	ibt_qp_info_t		qp_info;
	ibt_cep_modify_flags_t	cep_flags = IBT_CEP_SET_RTR_RTS;

	/* Start filling up ibt_qp_info_t.  */
	bzero(&qp_info, sizeof (qp_info));
	qp_info.qp_trans = ibtl_cm_get_chan_type(statep->channel);
	qp_info.qp_current_state = IBT_STATE_RTR;

	switch (qp_info.qp_trans) {
	case IBT_RC_SRV:
		IBCM_QPINFO_RC_PATH(qp_info).cep_timeout = timeout;
		IBCM_QPINFO_RC(qp_info).rc_retry_cnt = statep->cep_retry_cnt;
		IBCM_QPINFO_RC(qp_info).rc_rnr_retry_cnt =
		    statep->local_qp_rnr_cnt;
		IBCM_QPINFO_RC(qp_info).rc_sq_psn = statep->starting_psn;

		if (statep->mode == IBCM_ACTIVE_MODE) {
			IBCM_QPINFO_RC(qp_info).rc_rdma_ra_out =
			    rep_msg->rep_resp_resources;
		} else {
			IBCM_QPINFO_RC(qp_info).rc_rdma_ra_out =
			    rep_msg->rep_initiator_depth;
		}
		if (statep->alt_port &&
		    (((rep_msg->rep_target_delay_plus >> 1) & 0x3) ==
		    IBT_CM_FAILOVER_ACCEPT)) {
			/* failover was accepted */
			cep_flags |= IBT_CEP_SET_MIG;
			IBCM_QPINFO_RC(qp_info).rc_mig_state =
			    IBT_STATE_REARMED;
		}

		break;
	/* XXX RD? */
	case IBT_UC_SRV:
		IBCM_QPINFO_UC_PATH(qp_info).cep_timeout = timeout;
		break;
	default:
		IBTF_DPRINTF_L2(cmlog, "ibcm_invoke_rtu_qp_modify: "
		    "unknow svc_type = %x", qp_info.qp_trans);
		break;
	}

	/* Call modify_qp */
	status = ibt_modify_qp(statep->channel, cep_flags, &qp_info, NULL);
	IBTF_DPRINTF_L4(cmlog, "ibcm_invoke_rtu_qp_modify: statep 0x%p "
	    "modify qp status = %d", statep, status);

	if (status == IBT_SUCCESS)
		ibcm_insert_trace(statep, IBCM_TRACE_RTR_RTS);
	else
		ibcm_insert_trace(statep, IBCM_TRACE_RTR_RTS_FAIL);

#ifdef	DEBUG
	print_modify_qp("RTR to RTS", statep->channel, cep_flags, &qp_info);

	if (statep->channel != NULL) {
		ibt_qp_query_attr_t	qp_attrs;

		(void) ibt_query_qp(statep->channel, &qp_attrs);
		IBTF_DPRINTF_L4(cmlog, "ibcm_invoke_rtu_qp_modify: "
		    "qp_info.qp_state = %x", qp_attrs.qp_info.qp_state);
	}
#endif
	return (status);
}


/*
 * ibcm_cep_state_rtu:
 *	QP state transition function called for an incoming RTU
 *	on passive side.
 *
 * INPUTS:
 *	statep		- connection state pointer
 *	cm_rtu_msg	- RTU message pointer
 *
 */
void
ibcm_cep_state_rtu(ibcm_state_data_t *statep, ibcm_rtu_msg_t *cm_rtu_msgp)
{
	ibt_status_t	status;
	ibt_cm_event_t	event;
	ibcm_rep_msg_t	*rep_msgp = (ibcm_rep_msg_t *)
	    IBCM_OUT_MSGP(statep->stored_msg);

	IBTF_DPRINTF_L4(cmlog, "ibcm_cep_state_rtu: statep 0x%p", statep);

	ASSERT(statep->channel != NULL);

	/* RDMA initiator depth taken from negotiated REP values */
	status = ibcm_invoke_rtu_qp_modify(statep,
	    ibt_usec2ib(statep->remote_ack_delay), rep_msgp);

	if (status != IBT_SUCCESS) {

		(void) ibcm_cep_to_error_state(statep);
		/*
		 * Disassociate statep and QP, as there is a
		 * QP associated with this statep.
		 */
		IBCM_SET_CHAN_PRIVATE(statep->channel, NULL);

		ibcm_post_rej_mad(statep, IBT_CM_NO_RESC,
		    IBT_CM_FAILURE_UNKNOWN, NULL, 0);
		/*
		 * Invoke CM handler, so client/server can do
		 * resource cleanup. No private data can be returned here
		 */
		ibcm_handler_conn_fail(statep, IBT_CM_FAILURE_REJ_SENT,
		    IBT_CM_FAILURE_UNKNOWN, IBT_CM_NO_RESC, NULL, 0);

		/* unblock any pending DREQ threads */
		mutex_enter(&statep->state_mutex);
		statep->cep_in_rts = IBCM_FAIL;
		cv_broadcast(&statep->block_mad_cv);
		mutex_exit(&statep->state_mutex);
		return;
	}

	mutex_enter(&statep->state_mutex);
	statep->state = IBCM_STATE_ESTABLISHED;
	ibtl_cm_chan_is_open(statep->channel);
	mutex_exit(&statep->state_mutex);

	/* invoke the CM handler */
	ASSERT(statep->cm_handler != NULL);

	bzero(&event, sizeof (event));
	event.cm_channel = statep->channel;
	event.cm_session_id = NULL;

	event.cm_type = IBT_CM_EVENT_CONN_EST;
	if (cm_rtu_msgp != NULL) {
		event.cm_priv_data = &(cm_rtu_msgp->rtu_private_data[0]);
		event.cm_priv_data_len = IBT_RTU_PRIV_DATA_SZ;
	}

	ibcm_insert_trace(statep, IBCM_TRACE_CALLED_CONN_EST_EVENT);

	(void) statep->cm_handler(statep->state_cm_private, &event, NULL,
	    NULL, 0);

	ibcm_insert_trace(statep, IBCM_TRACE_RET_CONN_EST_EVENT);
	if (ibcm_enable_trace & 4)
		ibcm_dump_conn_trace(statep);
	else
		IBTF_DPRINTF_L2(cmlog, "ibcm_cep_state_rtu CONN_EST Channel %p",
		    statep->channel);

	/* unblock any pending DREQ threads */
	mutex_enter(&statep->state_mutex);
	statep->cep_in_rts = IBCM_UNBLOCK;
	cv_broadcast(&statep->block_mad_cv);
	mutex_exit(&statep->state_mutex);
}


/*
 * ibcm_cep_send_rtu:
 *	QP state transition function called for an outgoing RTU
 *	on active side.
 *
 * INPUTS:
 *	statep		- connection state pointer
 *
 * RETURN VALUE:
 */
void
ibcm_cep_send_rtu(ibcm_state_data_t *statep)
{
	/* invoke the CM handler */
	if (statep->cm_handler) {
		ibt_cm_event_t	event;

		bzero(&event, sizeof (event));
		event.cm_type  = IBT_CM_EVENT_CONN_EST;
		event.cm_channel = statep->channel;
		event.cm_session_id = NULL;
		event.cm_priv_data = NULL;
		event.cm_priv_data_len = 0;

		ibcm_insert_trace(statep, IBCM_TRACE_CALLED_CONN_EST_EVENT);

		(void) statep->cm_handler(statep->state_cm_private, &event,
		    NULL, NULL, 0);

		ibcm_insert_trace(statep, IBCM_TRACE_RET_CONN_EST_EVENT);

	} else {
		IBTF_DPRINTF_L2(cmlog, "ibcm_cep_send_rtu: cm_handler NULL");
	}
	if (ibcm_enable_trace & 4)
		ibcm_dump_conn_trace(statep);
	else
		IBTF_DPRINTF_L2(cmlog, "ibcm_cep_send_rtu CONN_EST Channel %p",
		    statep->channel);

	/* unblock any pending DREQ threads */
	mutex_enter(&statep->state_mutex);
	statep->cep_in_rts = IBCM_UNBLOCK;
	cv_broadcast(&statep->block_mad_cv);
	mutex_exit(&statep->state_mutex);
}


/*
 * ibcm_cep_to_error_state:
 *	CEP state transition function. Changes state to IBT_STATE_ERROR
 *
 * INPUTS:
 *	statep		- connection state pointer
 *
 * RETURN VALUE:
 *	IBT_SUCCESS	- if able to change state otherwise failure
 */
ibt_status_t
ibcm_cep_to_error_state(ibcm_state_data_t *statep)
{
	ibt_status_t		status = IBT_SUCCESS;

	if (statep->channel != NULL) {
		ibt_qp_info_t	qp_info;

		bzero(&qp_info, sizeof (qp_info));
		/* For now, set it to RC type */
		qp_info.qp_trans = IBT_RC_SRV;
		qp_info.qp_state = IBT_STATE_ERROR;

		/* Call modify_qp to move to ERROR state */
		status = ibt_modify_qp(statep->channel, IBT_CEP_SET_STATE,
		    &qp_info, NULL);

		IBTF_DPRINTF_L4(cmlog, "ibcm_cep_to_error_state: "
		    "statep %p ibt_modify_qp() = %d", statep, status);

		if (status == IBT_SUCCESS)
			ibcm_insert_trace(statep, IBCM_TRACE_ERROR);
		else
			ibcm_insert_trace(statep, IBCM_TRACE_ERROR_FAIL);

	}

#ifdef	NO_EEC_SUPPORT_YET
	if (statep->channel.ch_eec != NULL) {
		ibt_eec_info_t	eec_info;

		bzero(&eec_info, sizeof (ibt_eec_info_t));
		eec_info.eec_state = what;

		/* Call modify_eec */
		status = ibtl_cm_modify_eec(statep->channel.ch_eec, &eec_info,
		    IBT_CEP_SET_NOTHING);
		IBTF_DPRINTF_L4(cmlog, "ibcm_cep_to_error_state: "
		    "ibtl_cm_modify_eec() returned = %x", status);
	}
#endif

	return (status);
}


/*
 * ibcm_cep_state_rej:
 *	QP state transition function called for an incoming REJ
 *	on active/passive side
 *
 * INPUTS:
 *	statep		- connection state pointer
 *	rej_msgp	- REJ message pointer
 *	rej_state	- State where REJ processing began
 *
 * RETURN VALUE:
 */
void
ibcm_cep_state_rej(ibcm_state_data_t *statep, ibcm_rej_msg_t *rej_msgp,
    ibcm_conn_state_t rej_state)
{
	ibt_cm_event_t	event;
	ibt_status_t	status;

	IBTF_DPRINTF_L4(cmlog, "ibcm_cep_state_rej: statep 0x%p", statep);

	ibcm_path_cache_purge();

	if ((rej_state == IBCM_STATE_REP_SENT) ||
	    (rej_state == IBCM_STATE_MRA_REP_RCVD)) {
		status = ibcm_cep_to_error_state(statep);
		IBTF_DPRINTF_L5(cmlog, "ibcm_cep_state_rej: statep 0x%p "
		    "ibcm_cep_to_error_state returned %d", statep,
		    status);
	}

	if (statep->channel)
		ibtl_cm_chan_open_is_aborted(statep->channel);

	/* Disassociate state structure and CM */
	IBCM_SET_CHAN_PRIVATE(statep->channel, NULL);

	/* invoke the CM handler */
	bzero(&event, sizeof (event));
	if (statep->cm_handler) {
		event.cm_type = IBT_CM_EVENT_FAILURE;
		event.cm_channel = statep->channel;
		event.cm_session_id = NULL;

		/*
		 * copy rej_msgp->rej_private_data to
		 * event.cm_event.cm_priv_data
		 */
		event.cm_priv_data = &(rej_msgp->rej_private_data[0]);
		event.cm_priv_data_len = IBT_REJ_PRIV_DATA_SZ;

		event.cm_event.failed.cf_code = IBT_CM_FAILURE_REJ_RCV;
		event.cm_event.failed.cf_msg = rej_msgp->rej_msg_type_plus >> 6;
		event.cm_event.failed.cf_reason =
		    b2h16(rej_msgp->rej_rejection_reason);

		IBTF_DPRINTF_L3(cmlog, "ibcm_cep_state_rej: rej_reason = %d",
		    event.cm_event.failed.cf_reason);

		ibcm_copy_addl_rej(statep, rej_msgp, &event.cm_event.failed);

		(void) statep->cm_handler(statep->state_cm_private, &event,
		    NULL, NULL, 0);
	}

	if (statep->open_return_data != NULL)
		bcopy(&event.cm_event.failed.cf_additional,
		    &statep->open_return_data->rc_arej_info,
		    sizeof (ibt_arej_info_t));
	if (ibcm_enable_trace != 0)
		ibcm_dump_conn_trace(statep);
	mutex_enter(&statep->state_mutex);
	ibcm_open_done(statep);
	mutex_exit(&statep->state_mutex);
}

/* Used to initialize client args with addl rej information from REJ MAD */
static void
ibcm_copy_addl_rej(ibcm_state_data_t *statep, ibcm_rej_msg_t *rej_msgp,
    ibt_cm_conn_failed_t *failed)
{
	uint16_t	rej_reason = b2h16(rej_msgp->rej_rejection_reason);
	uint8_t		ari_len = rej_msgp->rej_reject_info_len_plus >> 1;
	ibcm_classportinfo_msg_t tclp;
	ibt_arej_info_t	*cf_addl = &failed->cf_additional;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*cf_addl))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(failed->cf_arej_info_valid))

	failed->cf_arej_info_valid = B_FALSE;

	IBTF_DPRINTF_L3(cmlog, "ibcm_copy_addl_rej: rej_reason = %d "
	    "ari_len = %d", rej_reason, ari_len);

	if ((statep->mode == IBCM_PASSIVE_MODE) &&
	    (rej_reason != IBT_CM_CONSUMER))
		return;

	switch (rej_reason) {
	case IBT_CM_PRIM_GID:
	case IBT_CM_ALT_GID:
	case IBT_CM_PORT_REDIRECT:
		if (ari_len < sizeof (ib_gid_t))
			break;
		failed->cf_arej_info_valid = B_TRUE;
		bcopy(rej_msgp->rej_addl_rej_info, &cf_addl->ari_gid,
		    sizeof (ib_gid_t));
		cf_addl->ari_gid.gid_guid = b2h64(cf_addl->ari_gid.gid_guid);
		cf_addl->ari_gid.gid_prefix =
		    b2h64(cf_addl->ari_gid.gid_prefix);

		IBTF_DPRINTF_L4(cmlog, "ibcm_copy_addl_rej: ari_gid= %llX:%llX",
		    cf_addl->ari_gid.gid_prefix, cf_addl->ari_gid.gid_guid);

		break;
	case IBT_CM_PRIM_LID:
	case IBT_CM_ALT_LID:
		if (ari_len < sizeof (ib_lid_t))
			break;
		failed->cf_arej_info_valid = B_TRUE;
		bcopy(rej_msgp->rej_addl_rej_info, &cf_addl->ari_lid,
		    sizeof (ib_lid_t));
		cf_addl->ari_lid = b2h16(cf_addl->ari_lid);
		IBTF_DPRINTF_L4(cmlog, "ibcm_copy_addl_rej: ari_lid= 0x%lX",
		    cf_addl->ari_lid);

		break;
	case IBT_CM_INVALID_PRIM_SL:
	case IBT_CM_INVALID_ALT_SL:
		if (ari_len < 1)
			break;
		failed->cf_arej_info_valid = B_TRUE;
		/* take the first 4 bits */
		cf_addl->ari_sl = rej_msgp->rej_addl_rej_info[0] >> 4;
		break;
	case IBT_CM_INVALID_PRIM_TC:
	case IBT_CM_INVALID_ALT_TC:
		if (ari_len < 1)
			break;
		failed->cf_arej_info_valid = B_TRUE;
		/* take the first byte */
		cf_addl->ari_tclass = rej_msgp->rej_addl_rej_info[0];
		break;
	case IBT_CM_INVALID_PRIM_HOP:
	case IBT_CM_INVALID_ALT_HOP:
		if (ari_len < 1)
			break;
		failed->cf_arej_info_valid = B_TRUE;
		/* take the first byte */
		cf_addl->ari_hop = rej_msgp->rej_addl_rej_info[0];
		break;
	case IBT_CM_INVALID_PRIM_RATE:
	case IBT_CM_INVALID_ALT_RATE:
		if (ari_len < 1)
			break;
		failed->cf_arej_info_valid = B_TRUE;
		/* take the first 6 bits */
		cf_addl->ari_rate = rej_msgp->rej_addl_rej_info[0] >> 2;
		break;
	case IBT_CM_REDIRECT_CM:
		if (ari_len < sizeof (ibcm_classportinfo_msg_t))
			break;
		failed->cf_arej_info_valid = B_TRUE;
		bcopy(rej_msgp->rej_addl_rej_info, &tclp, sizeof (tclp));
		ibcm_init_clp_from_mad(&tclp, &cf_addl->ari_redirect);
		break;
	case IBT_CM_INVALID_MTU:
		if (ari_len < 1)
			break;
		failed->cf_arej_info_valid = B_TRUE;
		/* take the first 4 bits */
		cf_addl->ari_mtu = rej_msgp->rej_addl_rej_info[0] >> 4;
		break;
	case IBT_CM_CONSUMER:
		if (ari_len == 0)
			break;
		failed->cf_arej_info_valid = B_TRUE;
		if (ari_len > IBT_CM_ADDL_REJ_LEN)
			ari_len = IBT_CM_ADDL_REJ_LEN;
		bcopy(&rej_msgp->rej_addl_rej_info,
		    cf_addl->ari_consumer.rej_ari, ari_len);
		cf_addl->ari_consumer.rej_ari_len = ari_len;
		break;
	case IBT_CM_INVALID_PRIM_FLOW:
	case IBT_CM_INVALID_ALT_FLOW:
		if (ari_len < 3)	/* 3 bytes needed for 20 bits */
			break;
		failed->cf_arej_info_valid = B_TRUE;
		/* take the first 20 bits */
		cf_addl->ari_flow =
		    b2h32(*(uint32_t *)&rej_msgp->rej_addl_rej_info) >> 12;
		break;
	default:
		break;
	}

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(failed->cf_arej_info_valid))
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*cf_addl))
}


/* Used to copy classportinfo to MAD from client initialized args */
static void
ibcm_init_clp_to_mad(ibcm_classportinfo_msg_t *clp, ibt_redirect_info_t *rinfo)
{

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*clp))

	bcopy(&ibcm_clpinfo, clp, sizeof (ibcm_clpinfo));

	clp->RedirectGID_hi = h2b64(rinfo->rdi_gid.gid_prefix);
	clp->RedirectGID_lo = h2b64(rinfo->rdi_gid.gid_guid);
	clp->RedirectTC_plus =
	    h2b32((rinfo->rdi_tclass << 24) | (rinfo->rdi_sl << 20) |
	    (rinfo->rdi_flow & 0xfffff));
	clp->RedirectLID = h2b16(rinfo->rdi_dlid);
	clp->RedirectQP_plus = h2b32(rinfo->rdi_qpn & 0xffffff);
	clp->RedirectQ_Key = h2b32(rinfo->rdi_qkey);
	clp->RedirectP_Key = h2b16(rinfo->rdi_pkey);

	IBTF_DPRINTF_L4(cmlog, "ibcm_init_clp_to_mad: RedirectGID= %llX:%llX,"
	    " RedirectLID= 0x%lX", clp->RedirectGID_hi, clp->RedirectGID_lo,
	    clp->RedirectLID);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*clp))
}


/* Used to initialize classportinfo to be returned to clients, from MAD */
static void
ibcm_init_clp_from_mad(ibcm_classportinfo_msg_t *clp,
    ibt_redirect_info_t *rinfo)
{
	uint32_t temp32;

	rinfo->rdi_gid.gid_prefix = b2h64(clp->RedirectGID_hi);
	rinfo->rdi_gid.gid_guid = b2h64(clp->RedirectGID_lo);
	temp32 = b2h32(clp->RedirectTC_plus);
	rinfo->rdi_tclass = temp32 >> 24;
	rinfo->rdi_sl = (temp32 >> 20) & 0xf;
	rinfo->rdi_flow = temp32 & 0xffff;
	rinfo->rdi_dlid = b2h16(clp->RedirectLID);
	rinfo->rdi_qpn = b2h32(clp->RedirectQP_plus & 0xffffff);
	rinfo->rdi_qkey = b2h32(clp->RedirectQ_Key);
	rinfo->rdi_pkey = b2h16(clp->RedirectP_Key);

	IBTF_DPRINTF_L4(cmlog, "ibcm_init_clp_from_mad: RedirectGID= %llX:%llX,"
	    " RedirectLID= 0x%lX", rinfo->rdi_gid.gid_prefix,
	    rinfo->rdi_gid.gid_guid, rinfo->rdi_dlid);
}


/*
 * ibcm_cep_state_rej_est:
 *	QP state transition function called for an incoming REJ
 *	on active side in established state
 *
 * INPUTS:
 *	statep		- connection state pointer
 *
 * RETURN VALUE:
 */
void
ibcm_cep_state_rej_est(ibcm_state_data_t *statep)
{
	ibt_cm_event_t	event;
	ibt_status_t	status;

	IBTF_DPRINTF_L3(cmlog, "ibcm_cep_state_rej_est:");

	status = ibcm_cep_to_error_state(statep);
	IBTF_DPRINTF_L4(cmlog, "ibcm_cep_state_rej_est: statep 0x%p "
	    "ibcm_cep_to_error_state returned %d", statep, status);

	/* Disassociate state structure and CM */
	IBCM_SET_CHAN_PRIVATE(statep->channel, NULL);

	ibtl_cm_chan_is_closing(statep->channel);

	/* invoke the CM handler */
	if (statep->cm_handler) {
		bzero(&event, sizeof (event));
		event.cm_type = IBT_CM_EVENT_CONN_CLOSED;
		event.cm_channel = statep->channel;
		event.cm_session_id = NULL;

		event.cm_priv_data = NULL;
		event.cm_priv_data_len = 0;

		event.cm_event.closed = IBT_CM_CLOSED_REJ_RCVD;

		IBTF_DPRINTF_L4(cmlog, "ibcm_cep_state_rej_est: "
		    "rej_reason = %d", event.cm_event.failed.cf_reason);

		ibcm_insert_trace(statep, IBCM_TRACE_CALLED_CONN_CLOSE_EVENT);

		(void) statep->cm_handler(statep->state_cm_private, &event,
		    NULL, NULL, 0);

		ibcm_insert_trace(statep, IBCM_TRACE_RET_CONN_CLOSE_EVENT);

	}
}


/*
 * ibcm_sidr_req_ud_handler:
 *	Invoke Client's UD handler For SIDR_REQ msg
 *
 * INPUTS:
 *	ud_statep	- ud_state pointer
 *	sidr_reqp	- SIDR_REQ message pointer
 *
 * RETURN VALUE: IBCM_SEND_REP/IBCM_SEND_REJ
 */
static ibcm_status_t
ibcm_sidr_req_ud_handler(ibcm_ud_state_data_t *ud_statep,
    ibcm_sidr_req_msg_t *sidr_reqp, ibcm_mad_addr_t *cm_mad_addr,
    ibt_sidr_status_t *sidr_status)
{
	void			*priv_data = NULL;
	ibt_cm_ud_event_t	ud_event;
	ibcm_sidr_rep_msg_t	*sidr_repp;
	ibt_cm_ud_return_args_t	ud_ret_args;
	ibt_cm_status_t		cb_status;
	ibt_qp_query_attr_t	qp_attr;
	ibt_status_t		retval;
	ibcm_ud_clnt_reply_info_t	ud_clnt_info;

	/* Check first if UD client handler is valid */
	ASSERT(ud_statep->ud_cm_handler != NULL);

	/* Fill in ibt_cm_ud_event_t */
	ud_event.cm_type = IBT_CM_UD_EVENT_SIDR_REQ;
	ud_event.cm_session_id = ud_statep;
	ud_event.cm_event.sidr_req.sreq_service_id = ud_statep->ud_svc_id;
	ud_event.cm_event.sidr_req.sreq_hca_guid = ud_statep->ud_hcap->hca_guid;
	ud_event.cm_event.sidr_req.sreq_pkey = b2h16(sidr_reqp->sidr_req_pkey);
	ud_event.cm_event.sidr_req.sreq_hca_port = cm_mad_addr->port_num;

	ud_event.cm_priv_data =
	    &(sidr_reqp->sidr_req_private_data[0]);
	ud_event.cm_priv_data_len = IBT_SIDR_REQ_PRIV_DATA_SZ;

	sidr_repp =
	    (ibcm_sidr_rep_msg_t *)IBCM_OUT_MSGP(ud_statep->ud_stored_msg);

	priv_data = &(sidr_repp->sidr_rep_private_data[0]);

	bzero(&ud_ret_args, sizeof (ud_ret_args));

	/* Invoke the client handler */
	cb_status = ud_statep->ud_cm_handler(ud_statep->ud_state_cm_private,
	    &ud_event, &ud_ret_args, priv_data, IBT_SIDR_REP_PRIV_DATA_SZ);

	if (cb_status == IBT_CM_DEFER) {

		/* unblock any blocked cm ud proceed api calls */
		mutex_enter(&ud_statep->ud_state_mutex);
		ud_statep->ud_clnt_proceed = IBCM_UNBLOCK;
		cv_broadcast(&ud_statep->ud_block_client_cv);
		mutex_exit(&ud_statep->ud_state_mutex);

		return (IBCM_DEFER);
	}

	/* fail any blocked ud cm proceed api calls - client bug */
	mutex_enter(&ud_statep->ud_state_mutex);
	ud_statep->ud_clnt_proceed = IBCM_FAIL;
	cv_broadcast(&ud_statep->ud_block_client_cv);
	mutex_exit(&ud_statep->ud_state_mutex);

	/* do the query qp as soon as possible, after return from cm handler */
	if (cb_status == IBT_CM_ACCEPT) {
		retval = ibt_query_qp(ud_ret_args.ud_channel, &qp_attr);
		if (retval != IBT_SUCCESS) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_sidr_req_ud_handler: "
			    "Failed to retrieve QPN from the channel: %d",
			    retval);
			*sidr_status = IBT_CM_SREP_NO_CHAN;
			return (IBCM_SEND_SIDR_REP);
		} else if (qp_attr.qp_info.qp_trans != IBT_UD_SRV) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_sidr_req_ud_handler: "
			    "Server/Passive returned non-UD %d transport type "
			    "QP", qp_attr.qp_info.qp_trans);
			*sidr_status = IBT_CM_SREP_NO_CHAN;
			return (IBCM_SEND_SIDR_REP);
		}

		ud_clnt_info.ud_qkey = qp_attr.qp_info.qp_transport.ud.ud_qkey;
		ud_clnt_info.ud_qpn = qp_attr.qp_qpn;
	}

	ud_clnt_info.priv_data = priv_data;
	ud_clnt_info.priv_data_len = ud_ret_args.ud_ret_len;

	ud_clnt_info.redirect_infop = &ud_ret_args.ud_redirect;

	ibcm_process_sidr_req_cm_hdlr(ud_statep, cb_status, &ud_clnt_info,
	    sidr_status, sidr_repp);

	return (IBCM_SEND_SIDR_REP);
}

/*ARGSUSED*/
void
ibcm_process_sidr_req_cm_hdlr(ibcm_ud_state_data_t *ud_statep,
    ibt_cm_status_t cb_status, ibcm_ud_clnt_reply_info_t *ud_clnt_info,
    ibt_sidr_status_t *sidr_status, ibcm_sidr_rep_msg_t *sidr_repp)
{
	void	*sidr_rep_privp;

	IBTF_DPRINTF_L5(cmlog, "ibcm_process_sidr_req_cm_hdlr(%p, %x, "
	    "%p, %p, %p)", ud_statep, cb_status, ud_clnt_info,
	    sidr_status, sidr_repp);

	if (cb_status == IBT_CM_DEFAULT)
		cb_status = IBT_CM_REJECT;

	if (cb_status == IBT_CM_ACCEPT)
		*sidr_status = IBT_CM_SREP_CHAN_VALID;
	else if ((cb_status == IBT_CM_REJECT) ||
	    (cb_status == IBT_CM_NO_RESOURCE))
		*sidr_status = IBT_CM_SREP_REJ;
	else if (cb_status == IBT_CM_NO_CHANNEL)
		*sidr_status = IBT_CM_SREP_NO_CHAN;
	else if (cb_status == IBT_CM_REDIRECT)
		*sidr_status = IBT_CM_SREP_REDIRECT;
	else *sidr_status = IBT_CM_SREP_REJ;

	/*
	 * For Accept and reject copy the private data, if ud_clnt_info
	 * priv_data does not point to SIDR Response private data. This
	 * copy is needed for ibt_cm_ud_proceed().
	 */
	sidr_rep_privp = (void *)(&(sidr_repp->sidr_rep_private_data[0]));
	if ((cb_status == IBT_CM_ACCEPT || cb_status == IBT_CM_REJECT) &&
	    (ud_clnt_info->priv_data != sidr_rep_privp) &&
	    ud_clnt_info->priv_data_len) {
		bcopy(ud_clnt_info->priv_data, sidr_rep_privp,
		    min(ud_clnt_info->priv_data_len,
		    IBT_SIDR_REP_PRIV_DATA_SZ));
	}

	if (*sidr_status != IBT_CM_SREP_CHAN_VALID) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_sidr_req_cm_hdlr: "
		    "ud_handler return a failure: %d", cb_status);
		if (*sidr_status == IBT_CM_SREP_REDIRECT) {
		/*
		 * typecasting to ibcm_classportinfo_msg_t is ok, as addl info
		 * begins at offset 24 in sidr rep
		 */
			ibcm_init_clp_to_mad(
			    (ibcm_classportinfo_msg_t *)
			    &sidr_repp->sidr_rep_class_port_info,
			    ud_clnt_info->redirect_infop);
		}
		return;
	}


	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sidr_repp))

	sidr_repp->sidr_rep_qkey =
	    h2b32(ud_clnt_info->ud_qkey);
	sidr_repp->sidr_rep_qpn_plus = h2b32(ud_clnt_info->ud_qpn << 8);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sidr_repp))
}

/*
 * ibcm_sidr_rep_ud_handler:
 *	Invoke Client's UD handler For SIDR_REP msg
 *
 * INPUTS:
 *	ud_statep	- ud_state pointer
 *	sidr_rep_msgp	- SIDR_REQ message pointer
 *
 */
static void
ibcm_sidr_rep_ud_handler(ibcm_ud_state_data_t *ud_statep,
    ibcm_sidr_rep_msg_t *sidr_rep_msgp)
{
	ibt_cm_ud_event_t	ud_event;

	IBTF_DPRINTF_L5(cmlog, "ibcm_sidr_rep_ud_handler: ud_statep 0x%p",
	    ud_statep);

	/* Check first if UD client handler is valid */
	if (ud_statep->ud_cm_handler == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_sidr_rep_ud_handler: "
		    "cm_handler NULL");
		return;
	}

	/* Fill in ibt_cm_ud_event_t */
	ud_event.cm_type = IBT_CM_UD_EVENT_SIDR_REP;
	ud_event.cm_session_id = NULL;
	ud_event.cm_event.sidr_rep.srep_status =
	    sidr_rep_msgp->sidr_rep_rep_status;
	ud_event.cm_event.sidr_rep.srep_remote_qpn =
	    b2h32(sidr_rep_msgp->sidr_rep_qpn_plus) >> 8;
	ud_event.cm_event.sidr_rep.srep_remote_qkey =
	    h2b32(sidr_rep_msgp->sidr_rep_qkey);

	if (ud_event.cm_event.sidr_rep.srep_status == IBT_CM_SREP_REDIRECT) {
		/*
		 * typecasting to ibcm_classportinfo_msg_t is ok, as addl info
		 * begins at offset 24 in sidr rep
		 */
		ibcm_init_clp_from_mad(
		    (ibcm_classportinfo_msg_t *)
		    sidr_rep_msgp->sidr_rep_class_port_info,
		    &ud_event.cm_event.sidr_rep.srep_redirect);

		if (ud_statep->ud_return_data != NULL)
			bcopy(&ud_event.cm_event.sidr_rep.srep_redirect,
			    &ud_statep->ud_return_data->ud_redirect,
			    sizeof (ibt_redirect_info_t));
	}

	ud_event.cm_priv_data = &(sidr_rep_msgp->sidr_rep_private_data[0]);
	ud_event.cm_priv_data_len = IBT_SIDR_REP_PRIV_DATA_SZ;

	/* Invoke the client handler - inform only, so ignore retval */
	(void) ud_statep->ud_cm_handler(ud_statep->ud_state_cm_private,
	    &ud_event, NULL, NULL, 0);


}

/*
 * ibcm_process_lap_msg:
 *	This call processes an incoming LAP message
 *
 * INPUTS:
 *	hcap		- HCA entry pointer
 *	input_madp	- incoming CM LAP MAD
 *	cm_mad_addr	- Address information for the MAD
 *
 * RETURN VALUE: NONE
 */
/* ARGSUSED */
void
ibcm_process_lap_msg(ibcm_hca_info_t *hcap, uint8_t *input_madp,
    ibcm_mad_addr_t *cm_mad_addr)
{
	ibcm_status_t		state_lookup_status;
	ibcm_lap_msg_t		*lap_msg = (ibcm_lap_msg_t *)
	    (&input_madp[IBCM_MAD_HDR_SIZE]);
	ibcm_apr_msg_t		*apr_msg;
	ibcm_state_data_t	*statep = NULL;

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_lap_msg:");

	rw_enter(&hcap->hca_state_rwlock, RW_READER);

	state_lookup_status = ibcm_lookup_msg(IBCM_INCOMING_LAP,
	    b2h32(lap_msg->lap_remote_comm_id), 0, 0, hcap, &statep);

	rw_exit(&hcap->hca_state_rwlock);

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_lap_msg: lookup status %x"
	    " com id %x", state_lookup_status,
	    b2h32(lap_msg->lap_remote_comm_id));

	if (state_lookup_status != IBCM_LOOKUP_EXISTS) {
		/* Post a REJ message ? - but spec doesn't state so */
		return;
	}

	/* There is an existing state structure entry with active comid */

	ibcm_insert_trace(statep, IBCM_TRACE_INCOMING_LAP);

	mutex_enter(&statep->state_mutex);

	if ((statep->state == IBCM_STATE_ESTABLISHED) &&
	    (statep->ap_state == IBCM_AP_STATE_IDLE) &&
	    (statep->mode == IBCM_PASSIVE_MODE)) {
		if ((statep->lapr_msg) &&
		    (IBCM_OUT_HDRP(statep->lapr_msg)->TransactionID ==
		    ((ib_mad_hdr_t *)(input_madp))->TransactionID))
			ibcm_post_stored_apr_mad(statep, input_madp);
		else {
			ibcm_status_t	clnt_response;

			statep->ap_state = IBCM_AP_STATE_LAP_RCVD;
			statep->clnt_proceed = IBCM_BLOCK;
			mutex_exit(&statep->state_mutex);

			if (statep->lapr_msg == NULL) {
				if (ibcm_alloc_out_msg(
				    statep->stored_reply_addr.ibmf_hdl,
				    &statep->lapr_msg, MAD_METHOD_SEND) !=
				    IBT_SUCCESS) {

					mutex_enter(&statep->state_mutex);
					statep->clnt_proceed = IBCM_FAIL;
					cv_broadcast(&statep->block_client_cv);
					IBCM_REF_CNT_DECR(statep);
					mutex_exit(&statep->state_mutex);
					return;
				}
			}
			apr_msg = (ibcm_apr_msg_t *)
			    IBCM_OUT_MSGP(statep->lapr_msg);
			IBCM_OUT_HDRP(statep->lapr_msg)->TransactionID =
			    ((ib_mad_hdr_t *)(input_madp))->TransactionID;
			clnt_response =
			    ibcm_cep_state_lap(statep, lap_msg, apr_msg);
			IBTF_DPRINTF_L4(cmlog, "ibcm_process_lap_msg:"
			    " statep 0x%p  apr status %d", statep,
			    apr_msg->apr_ap_status);

			if (clnt_response == IBCM_DEFER) {
				IBTF_DPRINTF_L4(cmlog, "ibcm_process_lap_msg: "
				    "client returned DEFER response");
				return;
			}

			/* fail any blocked cm proceed api calls - client bug */
			mutex_enter(&statep->state_mutex);
			statep->clnt_proceed = IBCM_FAIL;
			cv_broadcast(&statep->block_client_cv);
			mutex_exit(&statep->state_mutex);

			ibcm_post_apr_mad(statep);
			return;
		}
	}	/* drop the LAP MAD in any other state */

	IBCM_REF_CNT_DECR(statep); /* decrement the ref count */
	mutex_exit(&statep->state_mutex);
}

/*
 * ibcm_post_stored_apr_mad:
 *	Builds and posts an APR MAD from the stored APR MAD
 *
 * INPUTS:
 *	statep		- pointer to ibcm_state_data_t
 *	input_madp	- pointer to incoming lap mad
 *
 * RETURN VALUE:
 *	NONE
 *
 * This function is called holding the state mutex, and returns
 * holding the state mutex
 */
static void
ibcm_post_stored_apr_mad(ibcm_state_data_t *statep, uint8_t *input_madp)
{
	ibmf_msg_t	*ibmf_apr_msg;
	uint8_t		apr_msg[IBCM_MSG_SIZE];

	/* Need to make a copy, else an incoming new LAP may modify lapr_msg */
	bcopy(IBCM_OUT_MSGP(statep->lapr_msg), apr_msg, IBCM_MSG_SIZE);

	mutex_exit(&statep->state_mutex);

	if (ibcm_alloc_out_msg(statep->stored_reply_addr.ibmf_hdl,
	    &ibmf_apr_msg, MAD_METHOD_SEND) != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_post_stored_apr_mad: "
		    "ibcm_alloc_out_msg failed");
		mutex_enter(&statep->state_mutex);
		return;
	}

	bcopy(apr_msg, IBCM_OUT_MSGP(ibmf_apr_msg), IBCM_MSG_SIZE);

	IBCM_OUT_HDRP(ibmf_apr_msg)->AttributeID =
	    h2b16(IBCM_INCOMING_APR + IBCM_ATTR_BASE_ID);

	IBCM_OUT_HDRP(ibmf_apr_msg)->TransactionID =
	    ((ib_mad_hdr_t *)(input_madp))->TransactionID;

	ibcm_insert_trace(statep, IBCM_TRACE_OUTGOING_APR);

	ibcm_post_rc_mad(statep, ibmf_apr_msg, ibcm_post_stored_apr_complete,
	    ibmf_apr_msg);

	/* ibcm_free_out_msg done in ibcm_post_stored_apr_complete */

	mutex_enter(&statep->state_mutex);
}

/*
 * ibcm_cep_state_lap:
 *	This call processes an incoming LAP message for cep state
 *	transition and invoking cm handler
 *
 * INPUTS:
 *	statep		- pointer to ibcm_state_data_t
 *	lap_msg		- lap msg received
 *	apr_msg		- apr msg to be sent
 *
 * RETURN VALUE: NONE
 */
ibcm_status_t
ibcm_cep_state_lap(ibcm_state_data_t *statep, ibcm_lap_msg_t *lap_msg,
    ibcm_apr_msg_t *apr_msg)
{
	ibt_cm_event_t		event;
	ibt_cm_return_args_t	ret_args;
	ibt_cm_status_t		cb_status;
	ibcm_clnt_reply_info_t	clnt_info;


	IBTF_DPRINTF_L4(cmlog, "ibcm_cep_state_lap: statep 0x%p", statep);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*apr_msg))

	/* If APM is not supported, return error */
	if (!(statep->hcap->hca_caps & IBT_HCA_AUTO_PATH_MIG)) {
		apr_msg->apr_ap_status = IBT_CM_AP_NOT_SUPPORTED;
		return (IBCM_SEND_APR);
	}

	if (statep->local_qpn !=
	    b2h32(lap_msg->lap_remote_qpn_eecn_plus) >> 8) {
		apr_msg->apr_ap_status = IBT_CM_AP_REJECT;
		IBTF_DPRINTF_L4(cmlog, "ibcm_cep_state_lap: local_qpn %x does "
		    "not match remote's remote_qpn %x", statep->local_qpn,
		    b2h32(lap_msg->lap_remote_qpn_eecn_plus) >> 8);
		return (IBCM_SEND_APR);
	}

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apr_msg))

	/* Fill up the event */
	bzero(&event, sizeof (event));
	event.cm_type = IBT_CM_EVENT_LAP_RCV;
	event.cm_channel = statep->channel;
	event.cm_session_id = statep;
	event.cm_priv_data = lap_msg->lap_private_data;
	event.cm_priv_data_len =  IBT_LAP_PRIV_DATA_SZ;
	event.cm_event.lap.lap_timeout = ibt_ib2usec(
	    ((uint8_t *)&lap_msg->lap_remote_qpn_eecn_plus)[3] >> 3);

	ibcm_fill_adds_from_lap(&event.cm_event.lap.lap_alternate_path,
	    lap_msg, IBCM_PASSIVE_MODE);

	cb_status = statep->cm_handler(statep->state_cm_private, &event,
	    &ret_args, apr_msg->apr_private_data, IBT_APR_PRIV_DATA_SZ);

	IBTF_DPRINTF_L3(cmlog, "ibcm_cep_state_lap: cb_status = %d", cb_status);
	if (cb_status == IBT_CM_DEFER) {

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(statep->defer_cm_msg))

		if (statep->defer_cm_msg == NULL)
			statep->defer_cm_msg =
			    kmem_zalloc(IBCM_MSG_SIZE, KM_SLEEP);
		bcopy(lap_msg, statep->defer_cm_msg, IBCM_MSG_SIZE);

		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(statep->defer_cm_msg))

		/* unblock any blocked cm proceed api calls */
		mutex_enter(&statep->state_mutex);
		statep->clnt_proceed = IBCM_UNBLOCK;
		cv_broadcast(&statep->block_client_cv);
		mutex_exit(&statep->state_mutex);

		return (IBCM_DEFER);
	}

	clnt_info.reply_event = (ibt_cm_proceed_reply_t *)&ret_args.cm_ret;
	clnt_info.priv_data = NULL;
	clnt_info.priv_data_len = 0;

	ibcm_process_cep_lap_cm_hdlr(statep, cb_status, &clnt_info, lap_msg,
	    apr_msg);
	return (IBCM_SEND_APR);
}

/*
 * ibcm_fill_adds_from_lap:
 *	Fills the address vector (part of event structure passed to
 * client) from the LAP message
 *
 * INPUTS:
 *	adds		- Address vector to be filled-in
 *	lap_msg		- LAP message used to fill the address vector
 *
 * RETURN VALUE: NONE
 */
static void
ibcm_fill_adds_from_lap(ibt_adds_vect_t *adds, ibcm_lap_msg_t *lap_msg,
    ibcm_mode_t mode)
{
	adds->av_srvl = lap_msg->lap_alt_sl_plus >> 4;
	if (mode == IBCM_PASSIVE_MODE) {
		adds->av_dgid.gid_prefix =
		    b2h64(lap_msg->lap_alt_l_port_gid.gid_prefix);
		adds->av_dgid.gid_guid =
		    b2h64(lap_msg->lap_alt_l_port_gid.gid_guid);
		adds->av_sgid.gid_prefix =
		    b2h64(lap_msg->lap_alt_r_port_gid.gid_prefix);
		adds->av_sgid.gid_guid =
		    b2h64(lap_msg->lap_alt_r_port_gid.gid_guid);
		adds->av_dlid = b2h16(lap_msg->lap_alt_l_port_lid);
	} else {
		adds->av_sgid.gid_prefix =
		    b2h64(lap_msg->lap_alt_l_port_gid.gid_prefix);
		adds->av_sgid.gid_guid =
		    b2h64(lap_msg->lap_alt_l_port_gid.gid_guid);
		adds->av_dgid.gid_prefix =
		    b2h64(lap_msg->lap_alt_r_port_gid.gid_prefix);
		adds->av_dgid.gid_guid =
		    b2h64(lap_msg->lap_alt_r_port_gid.gid_guid);
		adds->av_dlid = b2h16(lap_msg->lap_alt_r_port_lid);
	}

	IBTF_DPRINTF_L4(cmlog, "ibcm_fill_adds_from_lap: SGID=(%llX:%llX)",
	    adds->av_sgid.gid_prefix, adds->av_sgid.gid_guid);

	IBTF_DPRINTF_L4(cmlog, "ibcm_fill_adds_from_lap: DGID=(%llX:%llX)",
	    adds->av_dgid.gid_prefix, adds->av_dgid.gid_guid);

	adds->av_srate = lap_msg->lap_alt_srate_plus & 0x3f;

	/* next copy off the GRH info if it exists  */
	if ((lap_msg->lap_alt_sl_plus & 0x8) == 0) {
		uint32_t flow_tclass = b2h32(lap_msg->lap_alt_flow_label_plus);

		adds->av_send_grh = B_TRUE;
		adds->av_flow = flow_tclass >> 12;
		adds->av_tclass = flow_tclass & 0xff;
		adds->av_hop = lap_msg->lap_alt_hop_limit;
	} else {
		adds->av_send_grh = B_FALSE;
	}
}

/*
 * ibcm_process_cep_lap_cm_hdlr:
 * Processes the cm handler response for an incoming LAP.
 */

void
ibcm_process_cep_lap_cm_hdlr(ibcm_state_data_t *statep,
    ibt_cm_status_t cb_status, ibcm_clnt_reply_info_t *clnt_info,
    ibcm_lap_msg_t *lap_msg, ibcm_apr_msg_t *apr_msg)
{
	ibtl_cm_hca_port_t	port;
	ibt_qp_query_attr_t	qp_attrs;
	ibt_cep_modify_flags_t	cep_flags;
	ibt_status_t		status;
	ibt_adds_vect_t		*adds;

	if (cb_status == IBT_CM_DEFAULT)
		cb_status = IBT_CM_REJECT;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*apr_msg))

	/* verify status */
	apr_msg->apr_addl_info_len = 0;
	if (cb_status == IBT_CM_ACCEPT) {
		apr_msg->apr_ap_status = IBT_CM_AP_LOADED;
	} else if (cb_status == IBT_CM_REJECT) {
		apr_msg->apr_ap_status = IBT_CM_AP_REJECT;
	} else if (cb_status == IBT_CM_REDIRECT) {
		apr_msg->apr_ap_status = IBT_CM_AP_REDIRECT;
		/* copy redirect info to APR */
		apr_msg->apr_addl_info_len = sizeof (ibcm_classportinfo_msg_t);
		ibcm_init_clp_to_mad(
		    (ibcm_classportinfo_msg_t *)apr_msg->apr_addl_info,
		    &clnt_info->reply_event->apr);
	} else if (cb_status == IBT_CM_NO_RESOURCE) {
		apr_msg->apr_ap_status = IBT_CM_AP_REJECT;
	} else {
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_cep_lap_cm_hdlr: statep %p"
		    " Client handler unexpected return %x", statep, cb_status);
		cb_status = IBT_CM_REJECT;
		apr_msg->apr_ap_status = IBT_CM_AP_REJECT;
	}

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_cep_lap_cm_hdlr: statep 0x%p "
	    " client handler returned %d, apr status %d", statep, cb_status,
	    apr_msg->apr_ap_status);

	/* copy private data to outgoing apr, specified via priv_data */
	if ((clnt_info->priv_data != NULL) && (clnt_info->priv_data_len > 0))
		bcopy(clnt_info->priv_data, apr_msg->apr_private_data,
		    min(clnt_info->priv_data_len, IBT_APR_PRIV_DATA_SZ));

	if (cb_status != IBT_CM_ACCEPT)
		return;

	if (ibt_query_qp(statep->channel, &qp_attrs) != IBT_SUCCESS ||
	    (qp_attrs.qp_info.qp_state != IBT_STATE_RTS &&
	    qp_attrs.qp_info.qp_state != IBT_STATE_SQD)) {
		apr_msg->apr_ap_status = IBT_CM_AP_REJECT;
		return;
	}

	/* Fill up input args for ibt_modify_qp */
	cep_flags = IBT_CEP_SET_ALT_PATH | IBT_CEP_SET_STATE;

	/* do RTS=>RTS or SQD=>SQD.  The next line is needed for RTS=>RTS. */
	qp_attrs.qp_info.qp_current_state = qp_attrs.qp_info.qp_state;

	adds = &IBCM_QP_RC(qp_attrs).rc_alt_path.cep_adds_vect;
	ibcm_fill_adds_from_lap(adds, lap_msg, IBCM_PASSIVE_MODE);

	if ((status = ibtl_cm_get_hca_port(adds->av_sgid,
	    statep->local_hca_guid, &port)) != IBT_SUCCESS) {

		IBTF_DPRINTF_L2(cmlog, "ibcm_process_cep_lap_cm_hdlr:"
		    " ibtl_cm_get_hca_port failed status %d", status);
		apr_msg->apr_ap_status = IBT_CM_AP_REJECT;
		return;
	}

	IBCM_QP_RC(qp_attrs).rc_alt_path.cep_hca_port_num = port.hp_port;

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_cep_lap_cm_hdlr: statep 0x%p "
	    "gid = (%llx, %llx), port_num = %d", statep,
	    IBCM_QP_RC(qp_attrs).rc_alt_path.cep_adds_vect.av_dgid.
	    gid_prefix,
	    IBCM_QP_RC(qp_attrs).rc_alt_path.cep_adds_vect.av_dgid.gid_guid,
	    port.hp_port);

	/* The pkey is same as the primary path */
	status = ibt_pkey2index_byguid(statep->local_hca_guid,
	    port.hp_port, statep->pkey,
	    &IBCM_QP_RC(qp_attrs).rc_alt_path.cep_pkey_ix);

	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_cep_lap_cm_hdlr: statep %p"
		    " ibt_pkey2index_byguid failed %d", statep, status);
		apr_msg->apr_ap_status = IBT_CM_AP_REJECT;
		return;
	}

	IBCM_QP_RC(qp_attrs).rc_alt_path.cep_timeout =
	    lap_msg->lap_alt_local_acktime_plus >> 3;

	qp_attrs.qp_info.qp_trans = IBT_RC_SRV;
	if (IBCM_QP_RC(qp_attrs).rc_mig_state == IBT_STATE_MIGRATED) {
		IBTF_DPRINTF_L3(cmlog, "ibcm_process_cep_lap_cm_hdlr: statep %p"
		    ": rearming APM", statep);
		cep_flags |= IBT_CEP_SET_MIG;
		IBCM_QP_RC(qp_attrs).rc_mig_state = IBT_STATE_REARMED;
	}
	status = ibt_modify_qp(statep->channel, cep_flags, &qp_attrs.qp_info,
	    NULL);

	if (status != IBT_SUCCESS) {
		ibcm_insert_trace(statep, IBCM_TRACE_SET_ALT_FAIL);
	} else
		ibcm_insert_trace(statep, IBCM_TRACE_SET_ALT);

#ifdef	DEBUG
	(void) ibt_query_qp(statep->channel, &qp_attrs);
	print_modify_qp("PASSIVE LAP QUERY", statep->channel,
	    cep_flags, &qp_attrs.qp_info);
#endif

	if (status != IBT_SUCCESS) {
		apr_msg->apr_ap_status = IBT_CM_AP_REJECT;
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_cep_lap_cm_hdlr:"
		    " ibt_modify_qp() returned = %d", status);
		return;
	}
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apr_msg))
}


/*
 * ibcm_post_apr_mad:
 *	Posts a APR MAD and starts timer
 *
 * INPUTS:
 *	statep		- state pointer
 *
 * RETURN VALUE: NONE
 */
void
ibcm_post_apr_mad(ibcm_state_data_t *statep)
{
	ibcm_apr_msg_t	*apr_msgp;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*apr_msgp))

	apr_msgp = (ibcm_apr_msg_t *)IBCM_OUT_MSGP(statep->lapr_msg);

	apr_msgp->apr_local_comm_id = h2b32(statep->local_comid);
	apr_msgp->apr_remote_comm_id = h2b32(statep->remote_comid);
	IBCM_OUT_HDRP(statep->lapr_msg)->AttributeID =
	    h2b16(IBCM_INCOMING_APR + IBCM_ATTR_BASE_ID);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apr_msgp))

	ibcm_insert_trace(statep, IBCM_TRACE_OUTGOING_APR);

	ibcm_post_rc_mad(statep, statep->lapr_msg, ibcm_post_apr_complete,
	    statep);
}

/*
 * ibcm_process_apr_msg:
 *	This call processes an incoming APR message
 *
 * INPUTS:
 *	hcap		- HCA entry pointer
 *	input_madp	- incoming CM SIDR REP MAD
 *	cm_mad_addr	- Address information for the MAD to be posted
 *
 * RETURN VALUE: NONE
 */
/*ARGSUSED*/
void
ibcm_process_apr_msg(ibcm_hca_info_t *hcap, uint8_t *input_madp,
    ibcm_mad_addr_t *cm_mad_addr)
{
	ibcm_status_t		state_lookup_status;
	ibcm_apr_msg_t		*apr_msg = (ibcm_apr_msg_t *)
	    (&input_madp[IBCM_MAD_HDR_SIZE]);
	ibcm_state_data_t	*statep = NULL;

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_apr_msg:");

	rw_enter(&hcap->hca_state_rwlock, RW_READER);
	state_lookup_status = ibcm_lookup_msg(IBCM_INCOMING_APR,
	    b2h32(apr_msg->apr_remote_comm_id), 0, 0, hcap, &statep);
	rw_exit(&hcap->hca_state_rwlock);

	if (state_lookup_status != IBCM_LOOKUP_EXISTS) {
		return;
	}

	/* if transaction id is not as expected, drop the APR mad */
	if (IBCM_OUT_HDRP(statep->lapr_msg)->TransactionID !=
	    ((ib_mad_hdr_t *)(input_madp))->TransactionID) {
		mutex_enter(&statep->state_mutex);
		IBCM_REF_CNT_DECR(statep);
		mutex_exit(&statep->state_mutex);
		IBTF_DPRINTF_L3(cmlog, "ibcm_process_apr_msg: statep 0x%p"
		    ": rcv'd APR MAD with comid 0x%x",
		    statep, b2h32(apr_msg->apr_remote_comm_id));
		IBTF_DPRINTF_L3(cmlog, "ibcm_process_apr_msg: "
		    "tid expected 0x%llX tid found 0x%llX",
		    b2h64(IBCM_OUT_HDRP(statep->lapr_msg)->TransactionID),
		    b2h64(((ib_mad_hdr_t *)(input_madp))->TransactionID));
		return;
	}

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_apr_msg: statep 0x%p "
	    "lookup status %x", statep, state_lookup_status);

	mutex_enter(&statep->state_mutex);

	if (!((statep->state == IBCM_STATE_ESTABLISHED) &&
	    ((statep->ap_state == IBCM_AP_STATE_LAP_SENT) ||
	    (statep->ap_state == IBCM_AP_STATE_MRA_LAP_RCVD)))) {
		IBCM_REF_CNT_DECR(statep); /* decrement the ref count */
		mutex_exit(&statep->state_mutex);
		return;
	}

	statep->ap_state = IBCM_AP_STATE_APR_RCVD;

	/* cancel the LAP timer */
	if (statep->timerid != 0) {
		timeout_id_t timer_val;
		timer_val = statep->timerid;
		statep->timerid = 0;
		mutex_exit(&statep->state_mutex);
		(void) untimeout(timer_val);
	} else {
		mutex_exit(&statep->state_mutex);
	}

	ibcm_insert_trace(statep, IBCM_TRACE_INCOMING_APR);

	ibcm_cep_state_apr(statep,
	    (ibcm_lap_msg_t *)IBCM_OUT_MSGP(statep->lapr_msg), apr_msg);

	mutex_enter(&statep->state_mutex);
	statep->ap_state = IBCM_AP_STATE_IDLE;

	/* unblock any DREQ threads and close channels */
	cv_broadcast(&statep->block_mad_cv);

	statep->ap_done = B_TRUE;

	/* wake up blocking ibt_set_alt_path */
	cv_broadcast(&statep->block_client_cv);

	IBCM_REF_CNT_DECR(statep); /* decrement the ref count */
	mutex_exit(&statep->state_mutex);
}

static void
ibcm_set_apr_arej(int ap_status, ibcm_apr_msg_t *apr_msgp,
    ibt_arej_info_t *ari, boolean_t *ari_valid)
{
	uint8_t ari_len = apr_msgp->apr_addl_info_len;
	ibcm_classportinfo_msg_t tclp;

	*ari_valid = B_FALSE;

	IBTF_DPRINTF_L3(cmlog, "ibcm_set_apr_arej: apr_status = %d "
	    "ari_len = %d", ap_status, ari_len);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ari))

	switch (ap_status) {
	case IBT_CM_AP_REDIRECT:
		if (ari_len < sizeof (ibcm_classportinfo_msg_t))
			break;
		*ari_valid = B_TRUE;
		bcopy(apr_msgp->apr_addl_info, &tclp, sizeof (tclp));
		ibcm_init_clp_from_mad(&tclp, &ari->ari_redirect);
		break;
	case IBT_CM_AP_RLID_REJECTED:
		if (ari_len < sizeof (ib_lid_t))
			break;
		*ari_valid = B_TRUE;
		bcopy(apr_msgp->apr_addl_info, &ari->ari_lid,
		    sizeof (ib_lid_t));
		ari->ari_lid = b2h16(ari->ari_lid);
		break;
	case IBT_CM_AP_RGID_REJECTED:
		if (ari_len < sizeof (ib_gid_t))
			break;
		*ari_valid = B_TRUE;
		bcopy(apr_msgp->apr_addl_info, &ari->ari_gid,
		    sizeof (ib_gid_t));
		ari->ari_gid.gid_guid = b2h64(ari->ari_gid.gid_guid);
		ari->ari_gid.gid_prefix = b2h64(ari->ari_gid.gid_prefix);

		IBTF_DPRINTF_L4(cmlog, "ibcm_set_apr_arej: ari_gid= %llX:%llX",
		    ari->ari_gid.gid_prefix, ari->ari_gid.gid_guid);
		break;
	case IBT_CM_AP_FLOW_REJECTED:
		if (ari_len < 3)	/* 3 bytes needed for 20 bits */
			break;
		*ari_valid = B_TRUE;
		/* take the first 20 bits */
		ari->ari_flow =
		    b2h32(*(uint32_t *)&apr_msgp->apr_addl_info) >> 12;
		break;
	case IBT_CM_AP_TCLASS_REJECTED:
		if (ari_len < 1)
			break;
		*ari_valid = B_TRUE;
		/* take the first byte */
		ari->ari_tclass = apr_msgp->apr_addl_info[0];
		break;
	case IBT_CM_AP_HOP_REJECTED:
		if (ari_len < 1)
			break;
		*ari_valid = B_TRUE;
		/* take the first byte */
		ari->ari_hop = apr_msgp->apr_addl_info[0];
		break;
	case IBT_CM_AP_RATE_REJECTED:
		if (ari_len < 1)
			break;
		*ari_valid = B_TRUE;
		/* take the first 6 bits */
		ari->ari_rate = apr_msgp->apr_addl_info[0] >> 2;
		break;
	case IBT_CM_AP_SL_REJECTED:
		if (ari_len < 1)
			break;
		*ari_valid = B_TRUE;
		/* take the first 4 bits */
		ari->ari_sl = apr_msgp->apr_addl_info[0] >> 4;
		break;
	default:
		break;
	}
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*ari))
}

/*
 * ibcm_cep_state_apr:
 *	This call processes an incoming APR message
 *
 * INPUTS:
 *	statep		- pointer to ibcm_state_data_t
 *	lap_msg		- lap msg sent earlier
 *	apr_msg		- apr msg received
 *
 * RETURN VALUE: NONE
 */
void
ibcm_cep_state_apr(ibcm_state_data_t *statep, ibcm_lap_msg_t *lap_msg,
    ibcm_apr_msg_t *apr_msg)
{
	ibt_cm_event_t		event;
	ibcm_status_t		status = IBCM_SUCCESS;
	uint8_t			ap_status = apr_msg->apr_ap_status;

	IBTF_DPRINTF_L3(cmlog, "ibcm_cep_state_apr: statep 0x%p, ap_status %d",
	    statep, ap_status);

	if (ap_status == IBT_CM_AP_LOADED)
		status = ibcm_set_qp_from_apr(statep, lap_msg);

	if (statep->ap_return_data != NULL) {	/* blocking call */

		/* copy the private data */
		if ((statep->ap_return_data->ap_priv_data != NULL) &&
		    (statep->ap_return_data->ap_priv_data_len > 0))
			bcopy(apr_msg->apr_private_data,
			    statep->ap_return_data->ap_priv_data,
			    statep->ap_return_data->ap_priv_data_len);

		/* initialize the ap status */
		if (status == IBCM_FAILURE) {
			statep->ap_return_data->ap_status = IBT_CM_AP_REJECT;
			statep->ap_return_data->ap_arej_info_valid = B_FALSE;
		} else {
			statep->ap_return_data->ap_status = ap_status;
			ibcm_set_apr_arej(ap_status, apr_msg,
			    &statep->ap_return_data->ap_arej_info,
			    &statep->ap_return_data->ap_arej_info_valid);
		}

		/* do a cv signal for a blocking ibt_set_alt_path */
		mutex_enter(&statep->state_mutex);
		statep->ap_done = B_TRUE;
		cv_broadcast(&statep->block_client_cv);
		mutex_exit(&statep->state_mutex);

	} else {	/* Non blocking call */
		/* Fill up the event */

		bzero(&event, sizeof (event));
		event.cm_type = IBT_CM_EVENT_APR_RCV;
		event.cm_channel = statep->channel;
		event.cm_session_id = NULL;
		event.cm_priv_data = apr_msg->apr_private_data;
		event.cm_priv_data_len =  IBT_APR_PRIV_DATA_SZ;
		if (status == IBCM_FAILURE) {
			event.cm_event.apr.apr_status = IBT_CM_AP_REJECT;
			event.cm_event.apr.apr_arej_info_valid = B_FALSE;
		} else {
			event.cm_event.apr.apr_status = ap_status;
			ibcm_set_apr_arej(ap_status, apr_msg,
			    &event.cm_event.apr.apr_arej_info,
			    &event.cm_event.apr.apr_arej_info_valid);
		}

		/* initialize the ap status */
		statep->cm_handler(statep->state_cm_private, &event,
		    NULL, apr_msg->apr_private_data, IBT_APR_PRIV_DATA_SZ);
	}
	mutex_enter(&statep->state_mutex);
	ibcm_open_done(statep);
	mutex_exit(&statep->state_mutex);
}

/*
 * ibcm_set_qp_from_apr:
 *	This call sets QP's alt path info based on APR message contents
 *
 * INPUTS:
 *	statep		- pointer to ibcm_state_data_t
 *	lap_msg		- lap msg sent earlier
 *
 * RETURN VALUE: ibcm_status_t
 */
static ibcm_status_t
ibcm_set_qp_from_apr(ibcm_state_data_t *statep, ibcm_lap_msg_t *lap_msg)
{
	ibtl_cm_hca_port_t	port;
	ibt_adds_vect_t		*adds;

	ibt_qp_query_attr_t	qp_attrs;
	ibt_cep_modify_flags_t	cep_flags;
	ibt_status_t		status;

	IBTF_DPRINTF_L3(cmlog, "ibcm_set_qp_from_apr: statep 0x%p", statep);

	status = ibt_query_qp(statep->channel, &qp_attrs);
	if (status != IBT_SUCCESS ||
	    (qp_attrs.qp_info.qp_state != IBT_STATE_RTS &&
	    qp_attrs.qp_info.qp_state != IBT_STATE_SQD)) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_set_qp_from_apr: ibt_query_qp "
		    "failed, status = %d, qp_state = %d", statep, status,
		    qp_attrs.qp_info.qp_state);
		return (IBCM_FAILURE);
	}

	/* Fill up input args for ibt_modify_qp */
	cep_flags = IBT_CEP_SET_ALT_PATH | IBT_CEP_SET_STATE;

	/* do RTS=>RTS or SQD=>SQD.  The next line is needed for RTS=>RTS. */
	qp_attrs.qp_info.qp_current_state = qp_attrs.qp_info.qp_state;

	/* Fill up input args for ibt_modify_qp */
	adds = &IBCM_QP_RC(qp_attrs).rc_alt_path.cep_adds_vect;

	ibcm_fill_adds_from_lap(adds, lap_msg, IBCM_ACTIVE_MODE);

	if ((status = ibtl_cm_get_hca_port(adds->av_sgid,
	    statep->local_hca_guid, &port)) != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_set_qp_from_apr: "
		    "ibtl_cm_get_hca_port failed status = %d", status);
		IBTF_DPRINTF_L5(cmlog, "ibcm_set_qp_from_apr:"
		    " ibtl_cm_get_hca_port sgid guid %llX",
		    adds->av_sgid.gid_guid);
		IBTF_DPRINTF_L5(cmlog, "ibcm_set_qp_from_apr:"
		    " ibtl_cm_get_hca_port sgid prefix %llX ",
		    adds->av_sgid.gid_prefix);
		return (IBCM_FAILURE);
	}

	IBCM_QP_RC(qp_attrs).rc_alt_path.cep_hca_port_num =
	    port.hp_port;

	IBTF_DPRINTF_L4(cmlog, "ibcm_set_qp_from_apr: "
	    "gid = %llx:%llx, port_num = %d",
	    IBCM_QP_RC(qp_attrs).rc_alt_path.cep_adds_vect.av_sgid.
	    gid_prefix,
	    IBCM_QP_RC(qp_attrs).rc_alt_path.cep_adds_vect.av_sgid.gid_guid,
	    port.hp_port);

	/* The pkey is same as the primary path */
	status = ibt_pkey2index_byguid(statep->local_hca_guid,
	    port.hp_port, statep->pkey,
	    &IBCM_QP_RC(qp_attrs).rc_alt_path.cep_pkey_ix);

	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_set_qp_from_apr: "
		    "ibt_pkey2index_byguid failed %d", status);
		return (IBCM_FAILURE);
	}
	qp_attrs.qp_info.qp_trans = IBT_RC_SRV;
	IBCM_QP_RC(qp_attrs).rc_alt_path.cep_timeout =
	    ibt_usec2ib(statep->remote_ack_delay +
	    2 * statep->rc_alt_pkt_lt);
	if (IBCM_QP_RC(qp_attrs).rc_mig_state == IBT_STATE_MIGRATED) {
		/* Need to rearm */
		IBTF_DPRINTF_L3(cmlog, "ibcm_set_qp_from_apr: statep 0x%p: "
		    "rearming APM", statep);
		cep_flags |= IBT_CEP_SET_MIG;
		IBCM_QP_RC(qp_attrs).rc_mig_state = IBT_STATE_REARMED;
	}

	status = ibt_modify_qp(statep->channel, cep_flags, &qp_attrs.qp_info,
	    NULL);

	if (status != IBT_SUCCESS)
		ibcm_insert_trace(statep, IBCM_TRACE_SET_ALT_FAIL);
	else
		ibcm_insert_trace(statep, IBCM_TRACE_SET_ALT);

#ifdef	DEBUG
	(void) ibt_query_qp(statep->channel, &qp_attrs);
	print_modify_qp("ACTIVE LAP QUERY", statep->channel,
	    cep_flags, &qp_attrs.qp_info);
#endif

	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_set_qp_from_apr:"
		    " ibt_modify_qp() failed, status = %d", status);
		return (IBCM_FAILURE);
	}

	return (IBCM_SUCCESS);
}

/*
 * ibcm_sync_lapr_idle:
 *
 *	This call either cancels a LAP/APR operation or waits
 *	until the operation is complete
 *
 * INPUTS:
 *	statep	Pointer to ibcm_state_data_t
 *
 * RETURN VALUE: NONE
 *
 * This function is called holding state mutex
 * This function returns, releasing the state mutex
 */
void
ibcm_sync_lapr_idle(ibcm_state_data_t *statep)
{
	timeout_id_t	timer_val = statep->timerid;
	ibt_cm_event_t	event;

	IBTF_DPRINTF_L3(cmlog, "ibcm_sync_lapr_idle:"
	    "statep %p state %d ap_state %d", statep, statep->state,
	    statep->ap_state);

	ASSERT(MUTEX_HELD(&statep->state_mutex));
	_NOTE(LOCK_RELEASED_AS_SIDE_EFFECT(&statep->state_mutex))

	/* Busy AP states on active/passive sides */
	if ((statep->ap_state == IBCM_AP_STATE_LAP_RCVD) ||
	    (statep->ap_state == IBCM_AP_STATE_APR_RCVD) ||
	    (statep->ap_state == IBCM_AP_STATE_MRA_LAP_SENT) ||
	    (statep->ap_state == IBCM_AP_STATE_TIMED_OUT)) {

		/* wait till ap_state becomes IBCM_AP_STATE_IDLE */
		while (statep->ap_state != IBCM_AP_STATE_IDLE)
			cv_wait(&statep->block_mad_cv, &statep->state_mutex);

		mutex_exit(&statep->state_mutex);

	} else if ((statep->ap_state == IBCM_AP_STATE_LAP_SENT) ||
	    (statep->ap_state == IBCM_AP_STATE_MRA_LAP_RCVD)) {

		/* fail the client's ibt_set_alt_path */

		/* blocking ibt_set_alt_path */
		if (statep->ap_return_data != NULL) {
			statep->ap_return_data->ap_status =
			    IBT_CM_AP_ABORT;
			statep->ap_state = IBCM_AP_STATE_IDLE;
			cv_broadcast(&statep->block_client_cv);
			IBTF_DPRINTF_L3(cmlog, "ibcm_sync_lapr_idle:"
			    "blocked wait");
		}

		statep->timerid = 0;
		/* Cancel the timeout */
		mutex_exit(&statep->state_mutex);
		if (timer_val != 0)
			(void) untimeout(timer_val);

		/* Non blocking ibt_set_alt_path */
		if (statep->ap_return_data == NULL) {

			/* Fill up the event */

			bzero(&event, sizeof (event));
			event.cm_type = IBT_CM_EVENT_APR_RCV;
			event.cm_channel = statep->channel;
			event.cm_session_id = NULL;
			event.cm_priv_data = NULL;
			event.cm_priv_data_len =  0;
			event.cm_event.apr.apr_status = IBT_CM_AP_ABORT;

			/* Call the cm handler */
			statep->cm_handler(statep->state_cm_private, &event,
			    NULL, NULL, 0);
			IBTF_DPRINTF_L3(cmlog, "ibcm_sync_lapr_idle:"
			    "non-blocked wait");
		}
	} else mutex_exit(&statep->state_mutex);

	ASSERT(!MUTEX_HELD(&statep->state_mutex));
}

#ifdef DEBUG

/*
 * Debug function used to print all the modify qp attributes.
 * Useful to manually verify the modify qp parameters are as
 * expected
 */
static void
print_modify_qp(char *prefix, ibt_qp_hdl_t ibt_qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *qp_attr)
{
	IBTF_DPRINTF_L4(cmlog, "PRINT_MODIFY_QP %s %p", prefix, ibt_qp);
	IBTF_DPRINTF_L4(cmlog, "PRINT_MODIFY_QP flags 0x%x", flags);

	IBTF_DPRINTF_L4(cmlog, "PRINT_MODIFY_QP "
	    "rc_rdma_ra_in %d rc_rdma_ra_out %d",
	    qp_attr->qp_transport.rc.rc_rdma_ra_in,
	    qp_attr->qp_transport.rc.rc_rdma_ra_out);

	IBTF_DPRINTF_L4(cmlog, "PRINT_MODIFY_QP primary: "
	    "port %d path bits %d dlid %X",
	    qp_attr->qp_transport.rc.rc_path.cep_hca_port_num,
	    qp_attr->qp_transport.rc.rc_path.cep_adds_vect.av_src_path,
	    qp_attr->qp_transport.rc.rc_path.cep_adds_vect.av_dlid);
	IBTF_DPRINTF_L4(cmlog, "PRINT_MODIFY_QP primary: "
	    "pkey index %d cep_timeout %d",
	    qp_attr->qp_transport.rc.rc_path.cep_pkey_ix,
	    qp_attr->qp_transport.rc.rc_path.cep_timeout);
	IBTF_DPRINTF_L4(cmlog, "PRINT_MODIFY_QP primary: "
	    "srvl %d flow label %d tclass %d",
	    qp_attr->qp_transport.rc.rc_path.cep_adds_vect.av_srvl,
	    qp_attr->qp_transport.rc.rc_path.cep_adds_vect.av_flow,
	    qp_attr->qp_transport.rc.rc_path.cep_adds_vect.av_tclass);
	IBTF_DPRINTF_L4(cmlog, "PRINT_MODIFY_QP primary: "
	    "hop %d srate %d sgid_ix %d send_grh %d",
	    qp_attr->qp_transport.rc.rc_path.cep_adds_vect.av_hop,
	    qp_attr->qp_transport.rc.rc_path.cep_adds_vect.av_srate,
	    qp_attr->qp_transport.rc.rc_path.cep_adds_vect.av_sgid_ix,
	    qp_attr->qp_transport.rc.rc_path.cep_adds_vect.av_send_grh);
	IBTF_DPRINTF_L4(cmlog, "PRINT_MODIFY_QP primary: "
	    "dgid prefix %llX dgid guid %llX",
	    qp_attr->qp_transport.rc.rc_path.cep_adds_vect.av_dgid.gid_prefix,
	    qp_attr->qp_transport.rc.rc_path.cep_adds_vect.av_dgid.gid_guid);
	IBTF_DPRINTF_L4(cmlog, "PRINT_MODIFY_QP primary: "
	    "sgid prefix %llX sgid guid %llX",
	    qp_attr->qp_transport.rc.rc_path.cep_adds_vect.av_sgid.gid_prefix,
	    qp_attr->qp_transport.rc.rc_path.cep_adds_vect.av_sgid.gid_guid);

	IBTF_DPRINTF_L4(cmlog, "PRINT_MODIFY_QP alternate: "
	    "port %d path bits %d dlid %X",
	    qp_attr->qp_transport.rc.rc_alt_path.cep_hca_port_num,
	    qp_attr->qp_transport.rc.rc_alt_path.cep_adds_vect.av_src_path,
	    qp_attr->qp_transport.rc.rc_alt_path.cep_adds_vect.av_dlid);
	IBTF_DPRINTF_L4(cmlog, "PRINT_MODIFY_QP alternate: "
	    "pkey index %d cep_timeout %d",
	    qp_attr->qp_transport.rc.rc_alt_path.cep_pkey_ix,
	    qp_attr->qp_transport.rc.rc_alt_path.cep_timeout);
	IBTF_DPRINTF_L4(cmlog, "PRINT_MODIFY_QP alternate: "
	    "srvl %d flow label %d tclass %d",
	    qp_attr->qp_transport.rc.rc_alt_path.cep_adds_vect.av_srvl,
	    qp_attr->qp_transport.rc.rc_alt_path.cep_adds_vect.av_flow,
	    qp_attr->qp_transport.rc.rc_alt_path.cep_adds_vect.av_tclass);
	IBTF_DPRINTF_L4(cmlog, "PRINT_MODIFY_QP alternate: "
	    "hop %d srate %d sgid_ix %d send_grh %d",
	    qp_attr->qp_transport.rc.rc_alt_path.cep_adds_vect.av_hop,
	    qp_attr->qp_transport.rc.rc_alt_path.cep_adds_vect.av_srate,
	    qp_attr->qp_transport.rc.rc_alt_path.cep_adds_vect.av_sgid_ix,
	    qp_attr->qp_transport.rc.rc_alt_path.cep_adds_vect.av_send_grh);
	IBTF_DPRINTF_L4(cmlog, "PRINT_MODIFY_QP alternate: "
	    "dgid prefix %llX dgid guid %llX",
	    qp_attr->qp_transport.rc.rc_alt_path.cep_adds_vect.av_dgid.
	    gid_prefix,
	    qp_attr->qp_transport.rc.rc_alt_path.cep_adds_vect.av_dgid.
	    gid_guid);
	IBTF_DPRINTF_L4(cmlog, "PRINT_MODIFY_QP alternate: "
	    "sgid prefix %llX sgid guid %llX",
	    qp_attr->qp_transport.rc.rc_alt_path.cep_adds_vect.av_sgid.
	    gid_prefix,
	    qp_attr->qp_transport.rc.rc_alt_path.cep_adds_vect.av_sgid.
	    gid_guid);
}
#endif
