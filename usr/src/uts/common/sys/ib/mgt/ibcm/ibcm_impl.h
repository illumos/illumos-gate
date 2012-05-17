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

#ifndef _SYS_IB_MGT_IBCM_IBCM_IMPL_H
#define	_SYS_IB_MGT_IBCM_IBCM_IMPL_H

/*
 * ibcm_impl.h
 *
 * This file contains all of the internal data structures and
 * definitions for IBCM.
 *
 * The general state transition processing of CM is achieved by the
 * following callgraph:
 *
 * CM INIT : Register for hca attach and detach callbacks, and other asyncs
 *
 * On new HCA attach:	Register with IBMF on all ports of upcoming HCA
 *			Specify CM callback and callback "per HCA arg"
 *			Register with SA, allocate AVL trees etc.
 *
 * IBMF Callback
 *  	Validate combination of method and attribute Id in the generic MAD hdr
 *	-> Call CM Connection state transition function based on attribute ID
 *	    Create/lookup/delete CM state structure and save it into avl tree
 *	    Handle duplicate messages and MRA to adjust timers etc.
 *	    Handle stale connections
 *	    Allocate reply MADs
 *		-> Call CM QP/EEC state transition function based on CM message
 *		     Change QP/EEC state  (to enable recvQ posting by client)
 *		     Call Client/Server handler callback function
 *		     Modify QP/EEC attributes
 *		     Optionally fill up some fields of response MAD
 *	    Post reply MADs
 *	    Store reply MADs and reply MAD address, if necessary
 *	    Initialize timeouts for the message
 *	    Change CM state
 *	    Deallocate reply MADs
 *
 * NOTES:
 * 	o There are *NO* explicit CM allocation and deallocation routines for
 *	CM MADs and state data structures
 *	o CM timeouts are scheduled using timeout(9f), and cancelled using
 *	untimeout(9f)
 *	o svc_id allocation scheme
 *	A new counter for svcid is maintained in ibcm_hca_info_t
 *	which is used to allocate svcid. The svcids are incremented
 *	sequentially and allocated (with wrap around on overflow) with
 *	these considerations:
 *		The WellKnown service id's and locally allocated svcid's
 *		could be maintained in separate lists, thus allowing the
 *		lists to be kept apart and sorted easily.
 *		The insertions are done at the end of the list
 *	o reqid allocation scheme
 *	The list is a sorted one (as reqid's are allocated sequentially).
 *	If there is a code required for wrap around, it would search for
 *	a reqid from the head of the list.
 *	The insertions are always done at the end of the lists
 *	o XXX svc_id allocation scheme and req_id allocation scheme will
 *	be revisited.
 */

#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/avl.h>
#include <sys/taskq.h>
#include <sys/vmem.h>
#include <sys/note.h>
#include <sys/t_lock.h>

#include <sys/ib/ibtl/ibvti.h>
#include <sys/ib/ibtl/impl/ibtl_cm.h>
#include <sys/ib/ibtl/impl/ibtl_util.h>
#include <sys/ib/mgt/ibmf/ibmf.h>
#include <sys/ib/mgt/ibcm/ibcm_trace.h>
#include <inet/ip.h>

#ifdef __cplusplus
extern "C" {
#endif

_NOTE(SCHEME_PROTECTS_DATA("Private", sa_service_record_s))
_NOTE(SCHEME_PROTECTS_DATA("Exclusive access to ibmf msg buf based on state",
ib_mad_hdr_t))
_NOTE(SCHEME_PROTECTS_DATA("Exclusive access to ibmf msg buf based on state",
_ibmf_msg))

/*
 * Defines for all CM state machine states, as defined in
 * section 12.9.7. IBCM_REJ_SENT is a state not defined in
 * the spec and is added for implementation purposes.
 */
typedef enum ibcm_conn_state_e {
	/* Initial states */
	IBCM_STATE_IDLE			= 0,
	IBCM_STATE_LISTEN,

	/* States during connection establishment */
	IBCM_STATE_REQ_SENT,
	IBCM_STATE_REQ_RCVD,
	IBCM_STATE_REP_SENT,
	IBCM_STATE_REP_RCVD,
	IBCM_STATE_REP_WAIT,
	IBCM_STATE_MRA_SENT,
	IBCM_STATE_MRA_REP_SENT,
	IBCM_STATE_MRA_REP_RCVD,

	/* States during connection establishment failures */
	IBCM_STATE_TIMED_OUT,
	IBCM_STATE_ABORTED,
	IBCM_STATE_REJ_SENT,

	/* Established state */
	IBCM_STATE_TRANSIENT_ESTABLISHED,
	IBCM_STATE_ESTABLISHED,

	/* States during connection teardown */
	IBCM_STATE_TRANSIENT_DREQ_SENT,
	IBCM_STATE_DREQ_SENT,
	IBCM_STATE_DREQ_RCVD,
	IBCM_STATE_DREP_RCVD,
	IBCM_STATE_TIMEWAIT,

	/* states for UD side of things */
	IBCM_STATE_SIDR_REQ_SENT,
	IBCM_STATE_SIDR_REQ_RCVD,
	IBCM_STATE_SIDR_REP_SENT,
	IBCM_STATE_SIDR_REP_RCVD,

	/* states common to RC and UD, during state resource deletion */
	IBCM_STATE_DELETE
} ibcm_conn_state_t;

/* Defines the AP states for LAP/APR */
typedef enum ibcm_ap_state_e {
	IBCM_AP_STATE_IDLE	= 0x0,
	IBCM_AP_STATE_LAP_SENT,
	IBCM_AP_STATE_LAP_RCVD,
	IBCM_AP_STATE_APR_RCVD,
	IBCM_AP_STATE_MRA_LAP_RCVD,
	IBCM_AP_STATE_MRA_LAP_SENT,
	IBCM_AP_STATE_TIMED_OUT
} ibcm_ap_state_t;

/*
 * Defines for the CM event types/MAD attribute IDs
 */
typedef enum ibcm_event_type_e {
	IBCM_INCOMING_REQ	= 0x0,
	IBCM_INCOMING_MRA	= 0x1,
	IBCM_INCOMING_REJ	= 0x2,
	IBCM_INCOMING_REP	= 0x3,
	IBCM_INCOMING_RTU	= 0x4,
	IBCM_INCOMING_DREQ	= 0x5,
	IBCM_INCOMING_DREP	= 0x6,
	IBCM_INCOMING_SIDR_REQ	= 0x7,
	IBCM_INCOMING_SIDR_REP	= 0x8,
	IBCM_INCOMING_LAP	= 0x9,
	IBCM_INCOMING_APR	= 0xA,
	IBCM_OUTGOING_REQ	= 0xB,	/* REQ Sent on active CM side */
	IBCM_INCOMING_REQ_STALE	= 0xC,	/* lookup by remote HCA and */
					/* remote comid */
	IBCM_INCOMING_REP_STALE	= 0xD,	/* lookup by passive HCA and QPN */
	IBCM_INCOMING_REJ_RCOMID = 0xE	/* lookup by remote com id */
} ibcm_event_type_t;

/*
 * IBMF calls back into CM on only the first 11 events defined in
 * ibcm_event_type_t. CM has pre-defined functions for these 11 events
 *
 */
#define	IBCM_MAX_EVENTS		11

/*
 * CM message attribute IDs begin at this "base ID". The first 11 event types
 * in ibcm_event_type_t are CM protocol messages that are posted to IBMF by
 * adding the "base_id" to the respective event type value. By subtracting
 * the "base_id" in IBMF callback in CM MAD, the message type is gotten back
 */
#define	IBCM_ATTR_BASE_ID		0x10

#define	IBCM_MAX_RETRY_CNT		15
#define	IBCM_ATTRID_FIELD_SIZE		4
#define	IBCM_TRANID_PRIV_FIELD_SIZE	28

#define	IBCM_RNR_RETRY_CNT_MASK		0x7	/* 3 bits */
#define	IBCM_MAX_RNR_RETRY_CNT		7

#define	IBCM_INITIAL_COMID		1
#define	IBCM_INITIAL_REQID		1
#define	IBCM_INITIAL_SID		1

/*
 * Maximum number of com ids / req ids that can be active at any given time
 * MUST ENSURE THAT (INITIAL ID + MAX IDS -1), for any of the IDs does not
 * exceed the max 32 bit
 */

/* An hca can have max of 2^24 -2  RC connections */
#define	IBCM_MAX_COMIDS		(0x01000000 - 2)
#define	IBCM_MAX_REQIDS		0xFFFFFFFF
#define	IBCM_MAX_LOCAL_SIDS	0xFFFFFFFF
#define	IBCM_MAX_IP_SIDS	0xFFFF

typedef uint32_t ib_com_id_t;	/* CM Communication ID */

/*
 * Defines the CM Mode of operation for a connection
 */
typedef enum ibcm_mode_e {
	IBCM_ACTIVE_MODE	= 1,	/* Active side CM */
	IBCM_PASSIVE_MODE	= 2	/* Passive side CM */
} ibcm_mode_t;


/* different IBCM return values */
typedef enum ibcm_status_e {
	IBCM_SUCCESS  		= 0,	/* good status */
	IBCM_LOOKUP_EXISTS,		/* statep lookup found existing entry */
	IBCM_LOOKUP_NEW,		/* lookup created new statep entry */
	IBCM_LOOKUP_FAIL,		/* lookup found no statep entry */
	IBCM_SEND_REJ,			/* CM QP state change sent REJ msg */
	IBCM_SEND_REP,			/* CM QP state change sent REP msg */
	IBCM_SEND_RTU,			/* CM QP state change sent RTU msg */
	IBCM_SEND_APR,			/* CM to send APR MAD as response */
	IBCM_SEND_SIDR_REP, 		/* client's UD handler returned this */
	IBCM_DEFER,			/* client's handler returned this */
	IBCM_FAILURE			/* generic IBCM failure */
} ibcm_status_t;

/*
 * Struct definition for addressing information that CM maintains for
 * each of the incoming MADs
 */
typedef	struct	ibcm_mad_addr {
	ibmf_global_addr_info_t	grh_hdr;	/* GRH related fields of MAD */
	ibmf_addr_info_t	rcvd_addr;	/* Outgoing/Incoming MAD addr */
	ibmf_handle_t		ibmf_hdl;	/* IBMF handle */
	boolean_t		grh_exists;	/* TRUE if grh exists */
	uint8_t			port_num;
	struct ibcm_qp_list_s	*cm_qp_entry;	/* IBMF hdl on which MAD rcvd */
						/* or on which MAD shall be */
						/* sent out */
} ibcm_mad_addr_t;

_NOTE(READ_ONLY_DATA(ibcm_mad_addr))

#define	IBCM_MAD_SIZE		0x100			/* size of MAD */
#define	IBCM_MAD_HDR_SIZE	sizeof (ib_mad_hdr_t)	/* size of MAD HDR */
#define	IBCM_MSG_SIZE		IBCM_MAD_SIZE-IBCM_MAD_HDR_SIZE

typedef enum ibcm_abort_flag_e {
	IBCM_ABORT_INIT		= 0,	/* no abort flag is set */
	IBCM_ABORT_CLIENT	= 1,	/* client requested connection abort */
	IBCM_ABORT_REJ		= 2	/* REJ received with timeout reason */
} ibcm_abort_flag_t;

typedef	enum ibcm_isync_e {
	IBCM_BLOCK	= 0,	/* Block cm operation */
	IBCM_UNBLOCK	= 1,	/* Unblock cm operation */
	IBCM_FAIL	= 2	/* fail cm operation */
} ibcm_isync_t;

/*
 * Define a connection state structure, used by the IBTF CM
 * to maintain state about connected QPs.
 *
 * mode			: CM connection mode active/passive
 * state		: CM connection state
 * ap_state		: CM AP Internal state to manage LAP/APR state machine
 * state_mutex		: lock for this structure
 * channel		: Channel associated with this RC state structure
 * ref_cnt		: Number of active threads that may reference this
 *			  state structure
 * svcid		: Service ID
 * cm_handler		: Client handler callback address
 * stored_reply_addr	: Address for replying using the stored mad
 * hcap			: A pointer to the HCA's entry
 * stored_msg		: Stores the response REP/REJ/RTU MAD
 * mra_msg		: Stores the response MRA MAD
 * dreq_msg		: Stores the DREQ MAD
 * drep_msg		: Stores the DREP MAD
 * lapr_msg		: Stores the LAP/APR MAD
 *			  detect duplicate LAP messages
 * local_comid  	: Local communication id
 * local_hca_guid	: Local HCA GUID
 * local_qpn		: Local QPN
 *
 * remote_comid 	: Remote communication id
 * remote_hca_guid	: Remote HCA GUID
 * remote_qpn		: Remote QPN
 *
 * timerid		: Timer id for the timeout either for re-sending the
 *			  stored mad or deleting the stored mad
 *			  Ex: A REJ/RTU response for an incoming REP
 *			      A REP response to an incoming REQ
 *			      An outgoing REQ on active connection side
 * timer_value		: Time for any of the above timers in HZ
 * pkt_life_time	: pkt life time from source to destination
 * remote_ack_delay	: Remote hca's ack delay in clock_t
 * rc_alt_pkt_lt	: Life time for new ALT path specified in LAP
 * stale_clock		: clock used to detect stale vs duplicate REQs
 * timer_stored_state	: state of connection for timeout() validation
 * timer_stored_ap_state: CM ap_state for timeout validation
 * remaining_retry_count: Remaining count for retries ie., posting stored MADs
 * max_cm_retries	: Max retry count for sending a REQ/REP/DREQ
 * delete_mra_msg	: Set to TRUE for deletion, if MRA re-send in progress
 * resend_mad		: B_TRUE, if REQ/REP/RTU/REJ MAD re-send is in progress
 * resend_mra_mad	: B_TRUE, if a MRA mad re-sens is in progress
 * cep_retry_cnt	: Retry count for CEP.
 * stale		: B_TRUE, if connection has become stale
 * blocking_done	: B_TRUE, if cv_signal been issued to block_client_cv
 * clnt_hdl		: Clnt_hdl passed in ibt_open_channel
 * return_data		: RC return args, valid for blocking
 *			  ibt_open_channel
 * drep_priv_data;	: The pointer to client specified outgoing private
 *			  data, from close channel API call
 * drep_priv_data_len   : The length of DREP private data that client would
 *			  like to be returned from close channel API call
 * delete_state_data	: B_TRUE, if CM decides to delete state data, but
 *			  there is some thread that could access state data
 *
 * avl_active_link	: For inserting this state-data into active AVL tree
 * avl_passive_link	: For inserting this state-data into passive AVL tree
 * Note : All timer values that are of type "clock_t" below are in usecs
 */
typedef struct ibcm_state_data_s {
	/* for AVL tree */
	avl_node_t		avl_active_link;
	avl_node_t		avl_passive_link;
	avl_node_t		avl_passive_comid_link;

	/* remote stuff */
	ib_guid_t		remote_hca_guid;
	ib_com_id_t		remote_comid;
	ib_qpn_t		remote_qpn;

	/* local stuff */
	ib_com_id_t		local_comid;
	ib_qpn_t		local_qpn;
	ib_guid_t		local_hca_guid;

	ibcm_mode_t		mode;
	ibcm_conn_state_t	state;
	ibcm_ap_state_t		ap_state;
	kmutex_t		state_mutex;
	ibt_channel_hdl_t	channel;	/* save a copy */

	/* ref_cnt so others cannot delete a statep that may be referenced */
	int			ref_cnt;

	ib_svc_id_t		svcid;
	ibt_cm_handler_t	cm_handler;

	ibcm_mad_addr_t		stored_reply_addr;

	struct ibcm_hca_info_s *hcap;

	ibmf_msg_t		*stored_msg;
	ibmf_msg_t		*mra_msg;
	ibmf_msg_t		*dreq_msg;
	ibmf_msg_t		*drep_msg;
	ibmf_msg_t		*lapr_msg;

	void			*defer_cm_msg;

	/* timeout related stuff */
	timeout_id_t		timerid;
	clock_t			timer_value;
	clock_t			pkt_life_time;
	clock_t			remote_ack_delay;
	clock_t			rc_alt_pkt_lt;

	hrtime_t		stale_clock;
	hrtime_t		post_time;
	hrtime_t		mra_time;

	ibcm_conn_state_t	timer_stored_state;
	ibcm_ap_state_t		timer_stored_ap_state;
	uint8_t			remaining_retry_cnt;
	uint8_t			max_cm_retries;
	uint8_t			cm_retries;

	uint8_t			drep_in_progress;

	/* some cep stuff, stored here temporarily during connection est  */
	uint8_t			cep_retry_cnt:3;
	ibt_srate_t		local_srate;
	ibt_srate_t		local_alt_srate;
	ib_pkey_t		pkey;
	uint8_t			prim_port;
	uint8_t			alt_port;
	uint32_t		starting_psn;
	ib_path_bits_t		prim_src_path_bits;
	ib_path_bits_t		alt_src_path_bits;

	boolean_t		delete_mra_msg;
	boolean_t		stale;
	boolean_t		delete_state_data;
	boolean_t		is_this_ofuv_chan;

	boolean_t		open_done;
	boolean_t		close_done;
	boolean_t		ap_done;

	uint8_t			send_mad_flags;
	uint8_t			close_flow;
	uint8_t			open_flow;
	ibcm_abort_flag_t	abort_flag;

	struct ibcm_state_data_s	*timeout_next;

	ibcm_conn_state_t	timedout_state;

	ibcm_isync_t		cep_in_rts;
	ibcm_isync_t		clnt_proceed;
	ibcm_isync_t		close_nocb_state;

	/* Clients' information */
	void			*state_cm_private;

	/* pointer to service info */
	struct ibcm_svc_info_s  *state_svc_infop;

	kcondvar_t		block_client_cv;
	kcondvar_t		block_mad_cv;

	/* Data for recycle function */
	struct ibcm_taskq_recycle_arg_s	*recycle_arg;

	/* Return data pointers in various cm api calls */
	ibt_rc_returns_t	*open_return_data;
	ibt_ap_returns_t	*ap_return_data;
	uint8_t			*close_ret_priv_data;
	ibt_priv_data_len_t	*close_ret_priv_data_len;
	uint8_t			*close_ret_status;

	/* for queuing of open_rc_channel requests */
	struct ibcm_state_data_s	*open_link;
	/* for queuing of non-blocking close_rc_channel requests */
	struct ibcm_state_data_s	*close_link;

	struct ibcm_conn_trace_s	*conn_trace;

	/* For ibt_ofuvcm_get_req_data() */
	void			*req_msgp;

	/* Stored RNR retry count from incoming REQ or REP */
	ibt_rnr_retry_cnt_t	local_qp_rnr_cnt;

} ibcm_state_data_t;

_NOTE(MUTEX_PROTECTS_DATA(ibcm_state_data_s::state_mutex,
    ibcm_state_data_s::{state ref_cnt timer_stored_state timer_value
    timer_stored_ap_state remaining_retry_cnt clnt_proceed cep_in_rts
    close_nocb_state block_client_cv block_mad_cv timedout_state cm_handler
    abort_flag mra_msg}))

_NOTE(READ_ONLY_DATA(ibcm_state_data_s::{mode channel svcid hcap
    local_comid local_hca_guid local_qpn remote_comid remote_hca_guid
    remote_qpn pkt_life_time remote_ack_delay rc_alt_pkt_lt stored_reply_addr
    max_cm_retries cep_retry_cnt local_srate local_alt_srate pkey
    prim_port alt_port starting_psn state_svc_infop avl_active_link
    avl_passive_link avl_passive_comid_link defer_cm_msg recycle_arg
    conn_trace}))

_NOTE(SCHEME_PROTECTS_DATA("Serailized access by block_client_cv",
    ibcm_state_data_s::{open_return_data ap_return_data close_ret_priv_data
    close_ret_priv_data_len close_ret_status}))

_NOTE(DATA_READABLE_WITHOUT_LOCK(ibcm_state_data_s::{timedout_state
    cm_handler mra_msg abort_flag local_qp_rnr_cnt}))

/*
 * Definitions for send mad flags. Respective bits in send_mad_flags or
 * ud_send_mad_flags are set to 1, during MAD transmission, and reset in
 * ibmf send completion callback or on completion of a blocking ibmf mad post.
 */
#define	IBCM_REP_POST_BUSY	1	/* REP post in progress */
#define	IBCM_REJ_POST_BUSY	2	/* REJ post in progress */
#define	IBCM_RTU_POST_BUSY	4	/* RTU post in progress */
#define	IBCM_MRA_POST_BUSY	8	/* MRA post in progress */
#define	IBCM_DREP_POST_BUSY	16	/* DREQ post in progress */
#define	IBCM_SREP_POST_BUSY	32	/* SIDR REP post in progress */

/* MADs that are retransmitted only because of a timeout */
#define	IBCM_REQ_POST_BUSY	64	/* REQ post in progress */


/* Incr/Decr ref_cnt by 1 */
#define	IBCM_REF_CNT_INCR(s)	(s->ref_cnt++)
#define	IBCM_REF_CNT_DECR(s)	\
	if ((--(s->ref_cnt) == 0) && (s->delete_state_data == B_TRUE)) { \
		ibcm_add_tlist(s);\
	} \
	ASSERT(s->ref_cnt >= 0);

/*
 * This macro checks if ch_qp/ch_eec handles are both not set for a channel
 */
#define	IBCM_INVALID_CHANNEL(chan)	(chan == NULL)

/*
 * The next macros are used to get/set the statep from the QP
 * handles, using the CM private data. These call into IBTL.
 * The WAIT and RELEASE macros deal with related issues that
 * require use of the same lock within IBTL.
 */
#define	IBCM_GET_CHAN_PRIVATE(ch, s) \
	if ((ch) != NULL) { \
		s = ibtl_cm_get_chan_private(ch); \
	} else \
		s = NULL;

#define	IBCM_SET_CHAN_PRIVATE(ch, s) \
	if ((ch) != NULL) { \
		ibtl_cm_set_chan_private(ch, (void *)(s)); \
	}

#define	IBCM_RELEASE_CHAN_PRIVATE(ch) \
	if ((ch) != NULL) { \
		ibtl_cm_release_chan_private(ch); \
	}

#define	IBCM_WAIT_CHAN_PRIVATE(ch) \
	ibtl_cm_wait_chan_private(ch);

/* In future, if we intend to change it to realtime_timeout, it's easy */
#define	IBCM_TIMEOUT(arg1, arg2)	timeout(ibcm_timeout_cb, arg1,\
						drv_usectohz(arg2))
#define	IBCM_UD_TIMEOUT(arg1, arg2)	timeout(ibcm_sidr_timeout_cb, arg1,\
						drv_usectohz(arg2))

extern void ibcm_open_enqueue(ibcm_state_data_t *statep);
extern void ibcm_open_done(ibcm_state_data_t *statep);
extern void ibcm_close_enqueue(ibcm_state_data_t *statep);
extern void ibcm_close_done(ibcm_state_data_t *statep, int send_done);
extern void ibcm_close_enter(void);
extern void ibcm_close_exit(void);
extern void ibcm_lapr_enter(void);
extern void ibcm_lapr_exit(void);
extern void ibcm_check_for_opens(void);
extern void ibcm_check_for_async_close(void);
extern void ibcm_close_start(ibcm_state_data_t *statep);
extern void ibcm_run_tlist_thread(void);

/*
 * Structures & defines for SIDR
 */

/*
 * Define a connection state structure, used for SIDR REQ and REP
 * (ibcm_ud_state_data_t - struct for SIDR connection)
 *
 * ud_state: 		CM connection state (See ibcm_conn_state_t)
 * ud_req_id:		Request ID
 * ud_svcid:		Service ID
 * ud_state_mutex:	CM connection state
 *
 * ud_max_cm_retries:	Max retry count for sending a SIDR REQ
 * ud_ref_cnt:		State ref count for not deleting accidentally
 * ud_remaining_retry_count: Remaining count for retries ie., posting
 *			stored MADs
 * ud_cm_handler:	Server's handler callback address
 *
 * ud_nextp:		CM link for IBTF list
 * ud_hcap:		A pointer to the HCA's entry
 *
 * ud_timerid:		Timer id for the timeout either for re-sending the
 *			stored mad or deleting the stored mad
 *			Ex: A SIDR REP response for an incoming SIDR REQ
 *			An outgoing SIDR REQ on active connection side
 * ud_timer_value:	Time for any of the above timers in HZ
 * ud_pkt_life_time:	pkt life time from source to destination
 * ud_stored_reply_addr: Address for replying using the stored mad
 *
 * ud_sidr_req_lid:	SIDR REQ sender's port LID
 * ud_sidr_req_gid:	SIDR REQ sender's port GID
 * ud_grh_exists:	TRUE if GRH exists in the incoming SIDR REQ
 *
 * ud_passive_qpn:	QPN allocated by server for a SIDR REQ
 * ud_passive_qpn_qkey:	QPN's QKEY allocated by server
 *
 * ud_block_client_cv:	CV condition variable on which ibt_ud_get_dqpn() waits,
 *			if called in blocking mode.
 * ud_return_data:	UD return args, valid for blocking ibt_ud_get_dqpn
 * ud_timer_stored_state: State stored for timeout handling
 * ud_blocking_done	: Tells if cv_wait is needed or not. To handle the
 *			  case where a cv_signal is received prior to its
 *			  cv_wait().
 * Note : All timer values that are of type "clock_t" below are in usec
 */
typedef struct ibcm_ud_state_data_s {
	kmutex_t		ud_state_mutex;
	ibcm_conn_state_t	ud_state;
	ibcm_mode_t		ud_mode;

	int			ud_ref_cnt;

	uint32_t		ud_req_id;
	ib_svc_id_t		ud_svc_id;

	uint8_t			ud_max_cm_retries;
	uint8_t			ud_remaining_retry_cnt;
	ibt_cm_ud_handler_t	ud_cm_handler;

	struct ibcm_ud_state_data_s	*ud_nextp;
	struct ibcm_hca_info_s *ud_hcap;

	/* timeout related stuff */
	timeout_id_t		ud_timerid;
	clock_t			ud_timer_value;
	clock_t			ud_pkt_life_time;
	ibcm_mad_addr_t		ud_stored_reply_addr;
	ibmf_msg_t		*ud_stored_msg;


	/* SIDR REQ side related */
	ib_lid_t		ud_sidr_req_lid;
	ib_gid_t		ud_sidr_req_gid;
	boolean_t		ud_grh_exists;

	/* Stored values on server/SIDR REP side for re-transmits */
	ib_qpn_t		ud_passive_qpn;
	ib_qkey_t		ud_passive_qp_qkey;

	/* Clients' information */
	void			*ud_state_cm_private;

	struct ibcm_ud_state_data_s	*ud_timeout_next;
	boolean_t		ud_delete_state_data;
	boolean_t		ud_blocking_done;

	uint8_t			ud_send_mad_flags;

	ibcm_isync_t		ud_clnt_proceed;

	/* The following fields are not used by server side connection */
	kcondvar_t		ud_block_client_cv;
	ibt_ud_returns_t	*ud_return_data;
	ibcm_conn_state_t	ud_timer_stored_state;
} ibcm_ud_state_data_t;

_NOTE(MUTEX_PROTECTS_DATA(ibcm_ud_state_data_s::ud_state_mutex,
    ibcm_ud_state_data_s::{ud_state ud_ref_cnt ud_timerid
    ud_delete_state_data ud_blocking_done ud_send_mad_flags ud_clnt_proceed
    ud_timer_stored_state ud_send_mad_flags ud_clnt_proceed
    ud_block_client_cv ud_timer_value ud_remaining_retry_cnt}))

_NOTE(READ_ONLY_DATA(ibcm_ud_state_data_s::{ud_mode ud_req_id ud_svc_id
    ud_max_cm_retries ud_pkt_life_time ud_stored_reply_addr ud_stored_msg
    ud_sidr_req_lid ud_sidr_req_gid ud_grh_exists ud_passive_qpn
    ud_passive_qp_qkey ud_state_cm_private ud_stored_reply_addr ud_stored_msg}))

_NOTE(SCHEME_PROTECTS_DATA("Serailized access by ud_block_client_cv",
    ibcm_ud_state_data_s::{ud_return_data}))

_NOTE(DATA_READABLE_WITHOUT_LOCK(ibcm_ud_state_data_s::{ud_cm_handler}))

/*
 * Structure used to specify the SIDR search parameters
 */
typedef struct ibcm_sidr_srch_s {
	ib_lid_t		srch_lid;
	ib_gid_t		srch_gid;
	boolean_t		srch_grh_exists;
	uint32_t		srch_req_id;
	ibcm_mode_t		srch_mode;
} ibcm_sidr_srch_t;

_NOTE(READ_ONLY_DATA(ibcm_sidr_srch_s))

/*
 * Incr/Decr ud_ref_cnt by 1
 */
#define	IBCM_UD_REF_CNT_INCR(s)	((s)->ud_ref_cnt++)
#define	IBCM_UD_REF_CNT_DECR(s)	\
	if ((--(s->ud_ref_cnt) == 0) && (s->ud_delete_state_data == B_TRUE)) { \
		ibcm_add_ud_tlist(s);\
	} \
	ASSERT(s->ud_ref_cnt >= 0);

/*
 * Structure to store the Service Registration and Service Bind entries.
 *
 * Well known service id's are unique on a given HCA, but can be registered
 * only at some GID's. Hence can be multiple GID's per Service ID. For each
 * such GID and PKEY combination registered, there will be an ibcm_svc_info_t
 * entry in the CM global service list.
 *
 * Annex A of the spec constrains that there shall be one service provider per
 * service id, which implies same svc_rc_handler for all such entries
 * There can be multiple transport types (svc_tran_type) per Service ID. For
 * each such transport type, there will be an ibcm_svc_info_t entry in the
 * CM global service list and cm handler can be different
 *
 * For locally allocated service id's (maintained by OS), there can be only
 * one GID, where the service can be registered
 *
 * svc_id:		Service ID
 * svc_num_sids:	Number (Range) of service-ids supported
 * svc_flags:		Service flags specified at registration time
 * svc_link:		Global AVL tree of ibcm_svc_info_t structs
 * svc_rc_handler:	Server handler for RC (only one is valid at a time)
 * svc_ud_handler:	Server handler for UD (only one is valid at a time)
 * svc_ref_cnt:		Reference count
 * svc_to_delete:	If 1, then the entry is marked to be deleted
 *
 * sbind_gid:		GID
 * sbind_pkey:		P_Key
 * sbind_lease:		Service Lease
 * sbind_name:		Service Name
 */
typedef struct ibcm_svc_info_s {
	avl_node_t		svc_link;
	struct ibcm_svc_bind_s	*svc_bind_list;
	ibt_cm_handler_t	svc_rc_handler;
	ibt_cm_ud_handler_t	svc_ud_handler;
	int			svc_ref_cnt;
	int			svc_to_delete;
	ib_svc_id_t		svc_id;
	int			svc_num_sids;
	ibt_service_flags_t	svc_flags;
} ibcm_svc_info_t;

typedef struct ibcm_svc_bind_s {
	struct ibcm_svc_bind_s	*sbind_link;
	void			*sbind_cm_private;
	ib_gid_t		sbind_gid;
	ib_guid_t		sbind_hcaguid;
	uint64_t		sbind_key[2];
				/* sbind_data is assumed to be 8-byte aligned */
	uint8_t			sbind_data[IB_SVC_DATA_LEN]; /* ServiceData */
	uint32_t		sbind_lease;
	ib_pkey_t		sbind_pkey;
	uint8_t			sbind_port;
	uint8_t			sbind_rewrite_state;
	char			sbind_name[IB_SVC_NAME_LEN];
} ibcm_svc_bind_t;

/*
 * Service records may be lost by the SM/SA (reboot, change in who
 * is the master, etc.).  When any of the above occurs, a PORT_UP
 * async event is supposed to occur, at which point we mark all of
 * our service record information as stale (REWRITE_NEEDED), and
 * subsequently make the necessary sa_update calls to get the
 * SM/SA in sync with all the service records we previously wrote.
 *
 * Values for sbind_rewrite_state follow.  This field is protected by
 * ibcm_svc_info_lock.  ibt_unbind_service has to wait until a service
 * binding is either idle or needed, sleeping on ibcm_svc_info_cv if
 * busy (rewrite in progress).
 */
#define	IBCM_REWRITE_IDLE	0
#define	IBCM_REWRITE_NEEDED	1
#define	IBCM_REWRITE_BUSY	2

typedef struct ibcm_port_up_s {
	ib_guid_t	pup_hca_guid;
	uint8_t		pup_port;
} ibcm_port_up_t;

/* arg is a pointer to ibcm_port_up_t */
extern void ibcm_service_record_rewrite_task(void *);

#define	IBCM_SVC_INCR(svcinfop) (svcinfop)->svc_ref_cnt++
#define	IBCM_SVC_DECR(svcinfop) \
	if (--((svcinfop)->svc_ref_cnt) == 0 && \
	    (svcinfop)->svc_to_delete) \
		cv_broadcast(&ibcm_svc_info_cv); \
	ASSERT(svcinfop->svc_ref_cnt >= 0);

_NOTE(READ_ONLY_DATA(ibcm_svc_info_s::{svc_rc_handler svc_ud_handler svc_id
    svc_num_sids svc_flags}))

_NOTE(READ_ONLY_DATA(ibcm_svc_bind_s::{sbind_cm_private sbind_gid sbind_hcaguid
    sbind_key sbind_data sbind_lease sbind_pkey sbind_port sbind_name}))

/* for avl tree search */
typedef struct ibcm_svc_lookup_s {
	ib_svc_id_t	sid;
	int		num_sids;
} ibcm_svc_lookup_t;

typedef struct ibcm_ar_ref_s {
	struct ibcm_ar_ref_s	*ar_ref_link;
	ibt_clnt_hdl_t		ar_ibt_hdl;
} ibcm_ar_ref_t;

typedef struct ibcm_ar_s {
	ibt_ar_t		ar;
	int			ar_flags;	/* 1 = INITING, 2 = FAILED */
	int			ar_waiters;	/* # of waiters */
	kcondvar_t		ar_cv;
	uint8_t			ar_port;
	uint8_t			ar_rewrite_state; /* see sbind_rewrite_state */
	ibcm_ar_ref_t		*ar_ibt_hdl_list;
	struct ibcm_ar_s	*ar_link;
	sa_service_record_t	*ar_srv_recp;
	ibmf_saa_handle_t	ar_saa_handle;
	struct ibcm_hca_info_s	*ar_hcap;
} ibcm_ar_t;

/* ar_flags */
#define	IBCM_AR_SUCCESS		0
#define	IBCM_AR_FAILED		1
#define	IBCM_AR_INITING		2


/*
 * These flags are used for adding (if an entry does not exist) or
 * for just looking one up
 */
typedef enum ibcm_lookup_flag_e {
	IBCM_FLAG_LOOKUP		= 0,	/* just lookup */
	IBCM_FLAG_ADD			= 1,	/* just add */
	IBCM_FLAG_LOOKUP_AND_ADD	= 2	/* lookup first. add if  */
						/* lookup failed */
} ibcm_lookup_flag_t;

typedef enum ibcm_finit_state_e {
	IBCM_FINIT_INIT,		/* CM's init is not yet completed */
	IBCM_FINIT_IDLE,		/* CM not in either init or fini */
	IBCM_FINIT_BUSY,		/* CM busy either in init or fini */
	IBCM_FINIT_FAIL,		/* Init failed */
	IBCM_FINIT_SUCCESS		/* Fini has succeeded */
} ibcm_finit_state_t;

/*
 * Identifies HCA's state. Used in the definition of ibcm_hca_info_t
 * If HCA is in ACTIVE state only does CM allow any MAD processing.
 */
typedef enum ibcm_hca_state_e {
	IBCM_HCA_INIT,
	IBCM_HCA_ACTIVE,
	IBCM_HCA_NOT_ACTIVE
} ibcm_hca_state_t;

/* QP information per pkey, stored in port information */
typedef struct ibcm_qp_list_s {
	ib_pkey_t		qp_pkey;
	ibmf_qp_handle_t	qp_cm;
	uint32_t		qp_ref_cnt;
	struct ibcm_port_info_s *qp_port;
	struct ibcm_qp_list_s	*qp_next;
} ibcm_qp_list_t;

_NOTE(READ_ONLY_DATA(ibcm_qp_list_s::{qp_pkey qp_cm qp_port qp_next}))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ibcm_qp_list_s))

/*
 * port information per HCA
 * port_ibmf_hdl	- contains IBMF handle for that port if valid
 *			  otherwise is NULL
 * port_ibmf_saa_hdl	- contains SA Access handle for that port if valid
 *			  otherwise is NULL
 */
typedef struct ibcm_port_info_s {
	ibmf_handle_t		port_ibmf_hdl;
	ibmf_saa_handle_t	port_ibmf_saa_hdl;
	ib_gid_t		port_sgid0;
	uint8_t			port_event_status;
	uint8_t			port_saa_open_in_progress;
	uint8_t			port_num;
	ibmf_register_info_t	port_ibmf_reg;
	ibmf_impl_caps_t	port_ibmf_caps;
	ibcm_qp_list_t		port_qp1;
	ibcm_qp_list_t		*port_qplist;
	struct ibcm_hca_info_s	*port_hcap;
} ibcm_port_info_t;

_NOTE(READ_ONLY_DATA(ibcm_port_info_s::{port_num port_ibmf_caps port_qp1
    port_hcap}))

/* Value to indicate to exit the timeout list processing thread */
#define	IBCM_TIMEOUT_THREAD_EXIT	01

/*
 * IBCM code relies on AVL routines already in kernel for faster lookups.
 * AVL was chosen over mod hashing mechanism based on the its internal
 * limitations in the kernel (no support for over 100,000 keys).
 *
 * IBCM uses two AVL trees on the passive side and one on active side per HCA.
 * The two trees are need on the passive side because the tree lookup criteria
 * changes based on the type of message being processed. On passive side it is
 * based on remote_qpn and remote_hca_guid for only incoming REQ message and for
 * for all other messages the search criteria is based upon remote_comid.
 * On active side the lookup criteria remains static based upon local_comid.
 *
 * AVL tree insertions are done by grabbing the writer lock (hca_state_rwlock)
 * and lookups are done by grabbing the reader lock.
 */

/*
 * CM's per HCA data structure.
 *
 * One such entry is added/removed on hca attach/detach notifications to CM
 * respectively.
 *
 * Comids are used for all connections. Req ids are used for SIDR REQ and
 * SIDR REP messages.  These are  simple counters that wrap around INT_MAX.
 * NOTE: The starting value for comid, per HCA, is 2.
 *
 * hca_state:		HCA's current state (ibcm_hca_state_t) - whether
 *				IBT_HCA_ACTIVE, IBT_HCA_NOT_ACTIVE,
 * hca_guid:            Active HCA guid
 * hca_caps:		HCA capability mask
 * hca_ack_delay:	HCA ack delay
 * hca_max_rdma_rd	Max RDMA in Reads
 * hca_max_rdma_dpt	Max RDMA out Reads
 * hca_active_tree:	This tree is used for lookups on Active/Passive side
 *			CM based on communication id ONLY.
 * hca_passive_tree:	This tree is used to lookup/create ibcm_state_data_t on
 *			Passive Side CM based on remote_qpn and remote_hca_guid.
 * hca_passive_comid_tree:
 *			This tree is used to lookup/create ibcm_state_data_t on
 *			Passive Side CM based on remote_comid and
 *			remote_hca_guid.
 * hca_state_rwlock:	reader/writer Lock for the hca entry
 *				for hca_active_tree
 *				for hca_passive_tree
 *				for hca_next_comid
 * hca_sidr_list:	List for UD side
 * hca_sidr_list_lock:	List lock for UD side
 *				for hca_sidr_list
 *				for hca_next_reqid
 * hca_next_reqid:	Next active ReqId
 * hca_next_comid:	Next active ComID
 * hca_next:		Pointer to the next HCA
 * hca_svc_cnt:		A count of services registered on this hca
 * hca_acc_cnt:		A count of active references to this ibcm_hca_info_t
 * hca_res_cnt:		A count of client's active resources on this hca
 * hca_num_ports:	Number of ports that this HCA has
 * hca_port_info:	Per port information (IBMA/SA access handles etc.)
 *
 * Note : The global mutex ibcm_global_hca_mutex declared in CM is used for
 * accesses to the following fields :
 * hca_acc_cnt, hca_res_cnt, hca_svc_cnt, hca_state
 */
typedef struct ibcm_hca_info_s {
	ibcm_hca_state_t	hca_state;		/* Is HCA attached? */
	ib_guid_t		hca_guid;		/* HCA's guid value */
	ibt_hca_flags_t		hca_caps;		/* HCA capabilities */
	uint32_t		hca_vendor_id:24;
	uint16_t		hca_device_id;
	ib_time_t		hca_ack_delay;		/* HCA ack delay */
	uint8_t			hca_max_rdma_in_qp;	/* Max RDMA in Reads */
	uint8_t			hca_max_rdma_out_qp;	/* Max RDMA out Reads */
	vmem_t			*hca_comid_arena;	/* arena for com ids */
	vmem_t			*hca_reqid_arena;	/* arena for req ids */
	avl_tree_t		hca_active_tree;	/* active node tree */
	avl_tree_t		hca_passive_tree;	/* passive node tree */
	avl_tree_t		hca_passive_comid_tree;	/* passive comid tree */
	krwlock_t		hca_state_rwlock;	/* per HCA lock */
	ibcm_ud_state_data_t	*hca_sidr_list;		/* SIDR state list */
	krwlock_t		hca_sidr_list_lock;

	struct ibcm_hca_info_s	*hca_next;		/* Next HCA entry */

	int			hca_svc_cnt;		/* # of */
							/* services allocated */
	int			hca_acc_cnt;		/* active references */
	int			hca_res_cnt;		/* total resources */
	uint8_t			hca_num_ports;		/* #ports on this HCA */
	ibcm_port_info_t	hca_port_info[1];	/* Per portinfo array */
} ibcm_hca_info_t;

_NOTE(RWLOCK_PROTECTS_DATA(ibcm_hca_info_s::hca_state_rwlock,
    ibcm_hca_info_s::{hca_active_tree hca_passive_tree hca_passive_comid_tree}))

_NOTE(SCHEME_PROTECTS_DATA("hca_sidr_list_lock protects hca_sidr_list",
    ibcm_hca_info_s::{hca_sidr_list}))

_NOTE(READ_ONLY_DATA(ibcm_hca_info_s::{hca_guid hca_caps hca_ack_delay
    hca_max_rdma_in_qp hca_max_rdma_out_qp hca_comid_arena hca_reqid_arena
    hca_passive_tree hca_active_tree hca_passive_comid_tree hca_num_ports }))

/* Are we on Tavor HCA */
#define	IBCM_IS_HCA_TAVOR(hcap)	\
	(((hcap)->hca_device_id == 0x5a44) && ((hcap)->hca_vendor_id == 0x15b3))

/*
 * called to ensure that HCA is in "attached" state and is willing to
 * process connections etc.
 */
#define	IBCM_ACCESS_HCA_OK(s)	((s)->hca_state == IBCM_HCA_ACTIVE)

/*
 * Passive AVL tree lookup info  (for hca_passive_tree)
 * CM needs this structure as passive tree lookups are based on
 * QPN and HCA GUID.
 */
typedef	struct ibcm_passive_node_info_s {
	ib_qpn_t	info_qpn;
	ib_guid_t	info_hca_guid;
} ibcm_passive_node_info_t;

/*
 * Passive Com ID AVL tree lookup info  (for hca_passive_comid_tree)
 * CM needs this structure as passive comid tree lookups are based on
 * Remote Com ID and Remote HCA GUID.
 */
typedef struct ibcm_passive_comid_node_info_s {
	ib_com_id_t	info_comid;
	ib_guid_t	info_hca_guid;
} ibcm_passive_comid_node_info_t;

/* CM proceed task args structure definition */
typedef struct ibcm_proceed_targs_s {
	ibt_cm_event_type_t	event;
	ibt_cm_status_t		status;
	union tst_t {
		struct rc_s {
			ibcm_state_data_t	*statep;
			ibt_cm_proceed_reply_t	rc_cm_event_data;
		} rc;
		struct ud_s {
			ibcm_ud_state_data_t	*ud_statep;
			ib_qpn_t		ud_qpn;
			ib_qkey_t		ud_qkey;
			ibt_redirect_info_t	ud_redirect_info;
		} ud;
	} tst;
	ibt_priv_data_len_t	priv_data_len;
	/* keep priv_data as the last field */
	uint8_t			priv_data[IBT_MAX_PRIV_DATA_SZ];
} ibcm_proceed_targs_t;

_NOTE(READ_ONLY_DATA(ibcm_proceed_targs_s))


/*
 * function prototypes for AVL tree compares
 */
int	ibcm_active_node_compare(const void *, const void *);
int	ibcm_passive_node_compare(const void *, const void *);
int	ibcm_passive_comid_node_compare(const void *, const void *);

/*
 * function prototypes to allocate IBMF/SA_ACCESS handles
 */
ibt_status_t	ibcm_hca_reinit_port(ibcm_hca_info_t *hca_p,
		    uint8_t port_index);

/* function prototypes to Manage CM's IBMF QP's */

ibcm_qp_list_t *ibcm_find_qp(ibcm_hca_info_t *hcap, int port_no,
		    ib_pkey_t pkey);

void		ibcm_release_qp(ibcm_qp_list_t *cm_qp_entry);

ibcm_status_t	ibcm_free_qp(ibcm_qp_list_t *cm_qp_entry);

ibcm_status_t	ibcm_free_allqps(ibcm_hca_info_t *hcap, int port_no);

/*
 * function prototypes to allocate and free outgoing CM messages
 */
ibt_status_t
ibcm_alloc_out_msg(ibmf_handle_t ibmf_handle, ibmf_msg_t **ibmf_msgpp,
    uint8_t method);
ibcm_status_t
ibcm_free_out_msg(ibmf_handle_t ibmf_handle, ibmf_msg_t **ibmf_msgpp);

/*
 * Definition for CM state transition processing function
 */
typedef void (*ibcm_state_handler_t)(ibcm_hca_info_t *hcap,
		uint8_t *cm_input_mad, ibcm_mad_addr_t *cm_mad_addr);

/*
 * CM REQ Message structure
 *
 * Request for communication.
 *
 * Things of interest are:-
 * ib_qpn_t cannot be used - it is typecast to uint32_t but is 24 bits
 * ib_eecn_t cannot be used - it is typecast to uint32_t but is 24 bits
 *
 * (See Table 85 REQ Message Contents - chapter 12 in IB Spec v1.0a)
 *
 */
typedef struct ibcm_req_msg_s {
	ib_com_id_t	req_local_comm_id;	/* Local communication id */
						/* 32 bits */
	uint32_t	req_rsvd1;		/* Reserved1 - 32 bits */
	ib_svc_id_t	req_svc_id;		/* Service Id - 64 bits */
	ib_guid_t	req_local_ca_guid;	/* Local CA GUID - 64 bits */
	uint32_t	req_rsvd1p;		/* Reserved1+ - 32 bits */
	ib_qkey_t	req_local_qkey;		/* Local Q_KEY - 32 bits */
	uint32_t	req_local_qpn_plus;	/* QPN_24 RESP_RSRC_8 */
						/* local side QPN - 24 bits */
						/* Offered responder */
						/* resources - 8 bits */
	uint32_t	req_local_eec_no_plus;	/* LOCAL_EECN_24 INIT_DEPTH_8 */
						/* Local side EECN - 24 bits */
						/* Offered initiator */
						/* depth - 8 bits */
	uint32_t	req_remote_eecn_plus;	/* REM_EECN_24 TO_5 TT_2 EE_1 */
						/* Remote side EECN - 24 bits */
						/* Remote CM timeout - 5 bits */
						/* Transport srvtype - 2 bits */
						/* End-to-End flow - 1 bit */
	uint32_t	req_starting_psn_plus;	/* START_PSN_24 TO_5 RETRY_3 */
						/* Starting PSN - 24 bits */
						/* Local CM timeout - 5 bits */
						/* Retry count - 3 bits */
	ib_pkey_t	req_part_key;		/* Partition key - 16 bits */
	uint8_t		req_mtu_plus;		/* PATH_MTU_4 RDC_1 RNR_3 */
						/* Path Pkt MTU - 4 bits */
						/* Does RDC exist? - 1 bits */
						/* RNR retry count - 3 bits */
	uint8_t		req_max_cm_retries_plus; /* MAX_CM_RET_4 SRQ_1 RSV_3 */
						/* Max CM retries - 4 bits */
						/* SRQ Exists - 1 bit */
						/* Reserved2 - 3 bits */
	ib_lid_t	req_primary_l_port_lid;	/* Primary local port LID */
	ib_lid_t	req_primary_r_port_lid;	/* Primary Remote port LID */
	ib_gid_t	req_primary_l_port_gid;	/* Primary local port GID */
	ib_gid_t	req_primary_r_port_gid;	/* Primary remote port GID */
	uint32_t	req_primary_flow_label_plus; /* FLOW_20 RSV_4 SRATE_6 */
						/* Prim. flow label - 20 bits */
						/* Reserved3 - 6 bits */
						/* Primary rate - 6 bits */
	uint8_t		req_primary_traffic_class;
						/* Primary Traffic class */
	uint8_t		req_primary_hop_limit;	/* Prim Hop Limit */
	uint8_t		req_primary_sl_plus;	/* PRIMARY_SL_4 LOCAL_1 RSV_3 */
						/* Primary SL - 4 bits */
						/* Prim. subnet local - 1 bit */
						/* Reserved4 - 3 bits */
	uint8_t		req_primary_localtime_plus; /* LOCAL_TO_5 RSV_3 */
						/* Primary local */
						/* timeout - 5 bits */
						/* Reserved5 - 3 bits */
	ib_lid_t	req_alt_l_port_lid;	/* Alt local port LID */
	ib_lid_t	req_alt_r_port_lid;	/* Alt Remote port LID */
	/* Note: req_alt_l_port_gid/req_alt_r_port_gid are not 8-byte aligned */
	uint8_t		req_alt_l_port_gid[16];	/* Alt local port GID */
	uint8_t		req_alt_r_port_gid[16];	/* Alt remote port GID */
	uint32_t	req_alt_flow_label_plus; /* ALT_FLOW_20 RSV_6 ARATE_6 */
						/* Alt flow label - 20 bits */
						/* Reserved6 - 6 bits */
						/* Alternate rate - 6 bits */
	uint8_t		req_alt_traffic_class;	/* Alt traffic class */
	uint8_t		req_alt_hop_limit;	/* Alt hop limit */
	uint8_t		req_alt_sl_plus;	/* ALT_SL_4 A_LOCAL_1 RSV_3 */
						/* Alternate SL - 4 bits */
						/* Alt subnet local - 1 bit */
						/* Reserved7 - 3 bits */
	uint8_t		req_alt_localtime_plus;	/* ALT_LOCAL_ACK_TO_5 RSV_3 */
						/* Alt Local ACK */
						/* timeout - 5 bits */
						/* Reserved8 - 3 bits */
	uint8_t		req_private_data[IBT_REQ_PRIV_DATA_SZ];
						/* Private data */
} ibcm_req_msg_t;


/*
 * The following set of defines are short-cuts to CEP_PATH or GRH info
 */
#define	IBCM_PRIM_CEP_PATH(s)	(s)->oc_path->pi_prim_cep_path
#define	IBCM_PRIM_ADDS_VECT(s)	(s)->oc_path->pi_prim_cep_path.cep_adds_vect

#define	IBCM_ALT_CEP_PATH(s)	(s)->oc_path->pi_alt_cep_path
#define	IBCM_ALT_ADDS_VECT(s)	(s)->oc_path->pi_alt_cep_path.cep_adds_vect

#define	IBCM_UD_CEP_PATH(s)	(s)->us_path_info->ai_cep_path
#define	IBCM_UD_ADDS_VECT(s)	(s)->us_path_info->ai_cep_path.cep_adds_vect

/*
 * The following set of defines are short-cuts to ibt_cm_event_t
 */
#define	IBCM_EVT_REQ(e)		(e).cm_event.req
#define	IBCM_EVT_REP(e)		(e).cm_event.rep

/*
 * The following set of defines are short-cuts to qp_attrs or qp_info
 */
#define	IBCM_QP_RC(q)		(q).qp_info.qp_transport.rc
#define	IBCM_QP_UD(q)		(q).qp_info.qp_transport.ud
#define	IBCM_QP_UC(q)		(q).qp_info.qp_transport.uc

#define	IBCM_QPINFO(q)		(q).qp_transport
#define	IBCM_QPINFO_RC(q)	(q).qp_transport.rc
#define	IBCM_QPINFO_RC_PATH(q)	(q).qp_transport.rc.rc_path
#define	IBCM_QPINFO_UC(q)	(q).qp_transport.uc
#define	IBCM_QPINFO_UC_PATH(q)	(q).qp_transport.uc.uc_path
#define	IBCM_QPINFO_UD(q)	(q).qp_transport.ud


/* The following set of defines are short-cuts to RC and SIDR MAD HDRs */

#define	IBCM_OUT_MADP(msgp)	(msgp->im_msgbufs_send.im_bufs_mad_hdr)
#define	IBCM_OUT_HDRP(msgp)	((ib_mad_hdr_t *)IBCM_OUT_MADP(msgp))
#define	IBCM_OUT_MSGP(msgp)	(msgp->im_msgbufs_send.im_bufs_cl_data)

#define	IBCM_IN_MADP(msgp)	(msgp->im_msgbufs_recv.im_bufs_mad_hdr)
#define	IBCM_IN_HDRP(msgp)	((ib_mad_hdr_t *)IBCM_IN_MADP(msgp))
#define	IBCM_IN_MSGP(msgp)	(msgp->im_msgbufs_recv.im_bufs_cl_data)

#define	IBCM_REJ_PRIV(msgp)  &(((ibcm_rej_msg_t *) \
	IBCM_OUT_MSGP(statep->stored_msg))->rej_private_data[0])
/*
 * CM MRA Message structure
 *
 * Message Receipt Acknowledgement (MRA).
 *
 * NOTE: IB hosts and targets are required to be able to receive and
 * act upon an MRA, but the ability to send an MRA is optional.
 */
typedef struct ibcm_mra_msg_s {
	ib_com_id_t	mra_local_comm_id;	/* Local communication id */
	ib_com_id_t	mra_remote_comm_id;	/* Remote communication id */
	uint8_t		mra_message_type_plus;	/* Message Type - 2 bits */
						/* Reserved1 - 6 bits */
	uint8_t		mra_service_timeout_plus; /* SVC_TO_5 RSV_3 */
						/* Service timeout - 5 bits */
						/* Reserved2 - 3 bits */
	uint8_t		mra_private_data[IBT_MRA_PRIV_DATA_SZ];
						/* Private data */
} ibcm_mra_msg_t;

/*
 * CM REJ Message structure
 * REJ indicates that the sender will not continue through the communication
 * establishment sequence and the reason why it will not.
 *
 * NOTE: See ibt_cm_reason_t in common/sys/ib/ib_cm.h for complete list
 * of rejection reasons supported.
 */
typedef struct ibcm_rej_msg_s {
	ib_com_id_t	rej_local_comm_id;	/* Local communication id */
	ib_com_id_t	rej_remote_comm_id;	/* Remote communication id */
	uint8_t		rej_msg_type_plus;	/* REJ_MSG_TYPE_2 RSV_6 */
						/* Msg being REJed - 2 bits */
						/* Reserved1 - 6 bits */
	uint8_t		rej_reject_info_len_plus; /* REJ_INFO_LEN_7 RSV_1 */
						/* Rej. Info Length - 7 bits */
						/* Reserved2 - 1 bit */
	uint16_t	rej_rejection_reason;	/* Reject err code - 16 bits */
	uint8_t		rej_addl_rej_info[IBT_CM_ADDL_REJ_LEN];
						/* Additional Reject Info */
	uint8_t		rej_private_data[IBT_REJ_PRIV_DATA_SZ];
						/* Private data */
} ibcm_rej_msg_t;

/*
 * CM REP Message structure
 *
 * REP is returned in response to REQ, indicating that the respondent
 * accepts the Service-ID, proposed primary port, and any parameters
 * specified in the PrivateData of the REQ.
 */
typedef struct ibcm_rep_msg_s {
	ib_com_id_t	rep_local_comm_id;	/* Local communication id */
	ib_com_id_t	rep_remote_comm_id;	/* Remote communication id */
	ib_qkey_t	rep_local_qkey;		/* Local Q_KEY */
	uint32_t	rep_local_qpn_plus;	/* LOCAL_QPN_24 RSV_8 */
						/* Local side QPN - 24 bits */
						/* Reserved1 - 8 bits */
	uint32_t	rep_local_eecn_plus;	/* LOCAL_EECN_24 RSV_8 */
						/* Local side EECN - 24 bits */
						/* Reserved2 - 8 bits */
	uint32_t	rep_starting_psn_plus;	/* STARTING_PSN_24 RSV_8 */
						/* Starting PSN - 24 bits */
						/* Reserved3 - 8 bits */
	uint8_t		rep_resp_resources;	/* Responder resources 8 bits */
	uint8_t		rep_initiator_depth;	/* Initiator depth - 8 bits */
	uint8_t		rep_target_delay_plus;	/* TGT_ACK_DLY_5 FAIL_2 EE_1 */
						/* Target ACK delay - 5 bits */
						/* Failover accepted - 2 bits */
						/* End-to-End flow control - */
						/* 1 bit */
	uint8_t		rep_rnr_retry_cnt_plus;	/* RNR_COUNT_3 SRQ_1 RSV_4 */
						/* RNR retry count - 3 bits */
						/* SRQ Exists - 1 bit */
						/* Reserved4 - 4 bits */
	uint8_t		rep_local_ca_guid[8];	/* Local CA GUID - 64 bits */
	uint8_t		rep_private_data[IBT_REP_PRIV_DATA_SZ];
						/* Private data */
} ibcm_rep_msg_t;


/*
 * CM RTU Message structure
 *
 * RTU indicates that the connection is established, and that the
 * recipient may begin transmitting.
 */
typedef struct ibcm_rtu_msg_s {
	ib_com_id_t	rtu_local_comm_id;	/* Local communication id */
	ib_com_id_t	rtu_remote_comm_id;	/* Remote communication id */
	uint8_t		rtu_private_data[IBT_RTU_PRIV_DATA_SZ];
						/* Private data */
} ibcm_rtu_msg_t;


/*
 * CM DREQ Message structure
 *
 * DREQ is sent to initiate the connection release sequence.
 */
typedef struct ibcm_dreq_msg_s {
	ib_com_id_t	dreq_local_comm_id;	/* Local communication id */
	ib_com_id_t	dreq_remote_comm_id;	/* Remote communication id */
	uint32_t	dreq_remote_qpn_eecn_plus; /* REM_EECN_24 RSV_8 */
						/* Remote QPN/EECN - 24 bits */
						/* reserved - 8 bits */
	uint8_t		dreq_private_data[IBT_DREQ_PRIV_DATA_SZ];
						/* Private data */
} ibcm_dreq_msg_t;


/*
 * CM DREP Message structure
 *
 * DREP is sent in response to DREQ, and signifies that the sender has
 * received DREQ.
 */
typedef struct ibcm_drep_msg_s {
	ib_com_id_t	drep_local_comm_id;	/* Local communication id */
	ib_com_id_t	drep_remote_comm_id;	/* Remote communication id */
	uint8_t		drep_private_data[IBT_DREP_PRIV_DATA_SZ];
						/* Private Data */
} ibcm_drep_msg_t;


/*
 * CM LAP Message structure
 *
 * NOTE: LAP and APR messages are optional. These are needed if CM
 * accepts REQ messages and agrees to perform Automatic Path Migration.
 *
 * This message is used to change the alternate path information for a
 * specific connection.
 */
typedef struct ibcm_lap_msg_s {
	ib_com_id_t	lap_local_comm_id;	/* Local communication id */
	ib_com_id_t	lap_remote_comm_id;	/* Remote communication id */
	uint32_t	lap_rsvd1;		/* Reserved - 32 bits */
	uint32_t	lap_remote_qpn_eecn_plus; /* REM_EECN_24 TO_5 RSV_3 */
						/* Remote QPN/EECN - 24 bits */
						/* Remote CM response */
						/* timeout - 5 bits */
						/* Reserved1 - 3 bits */
	uint32_t	lap_rsvd2;		/* Reserved2 - 32 bits */
	ib_lid_t	lap_alt_l_port_lid;	/* Alt local port LID */
	ib_lid_t	lap_alt_r_port_lid;	/* Alt Remote port LID */
	ib_gid_t	lap_alt_l_port_gid;	/* Alt local port GID */
	ib_gid_t	lap_alt_r_port_gid;	/* Alt remote port GID */
	uint32_t	lap_alt_flow_label_plus; /* ALT_FLOW_20 RSV_4 TCL_8 */
						/* Alt flow label - 20 bits */
						/* Reserved3 - 4 bits */
						/* Alt traffic class - 8 bits */
	uint8_t		lap_alt_hop_limit;	/* Alt hop limit */
	uint8_t		lap_alt_srate_plus;	/* Reserved4 - 2 bits */
						/* Alt. static rate - 6 bits */
	uint8_t		lap_alt_sl_plus;	/* ALT_SL_4 A_LOCAL_1 RSV_3 */
						/* Alternate SL - 4 bits */
						/* Alt subnet local - 1 bit */
						/* Reserved5 - 3 bits */
	uint8_t		lap_alt_local_acktime_plus; /* ALT_TO_5 RSV_3 */
						/* Alt Local ACK */
						/* timeout - 5 bits */
						/* Reserved6 - 3 bits */
	uint8_t		lap_private_data[IBT_LAP_PRIV_DATA_SZ];
						/* Private data */
} ibcm_lap_msg_t;


/*
 * CM APR Message structure
 *
 * APR is sent in response to a LAP request. MRA may be sent to allow
 * processing of the LAP.
 */
typedef struct ibcm_apr_msg_s {
	ib_com_id_t	apr_local_comm_id;	/* Local communication id */
	ib_com_id_t	apr_remote_comm_id;	/* Remote communication id */
	uint8_t		apr_addl_info_len;	/* Add'l Info Len - 8 bits */
	uint8_t		apr_ap_status;		/* AP status - 8 bits */
	uint16_t	apr_rsvd1;		/* Reserved1 - 16 bits */
	uint8_t		apr_addl_info[IBT_CM_APR_ADDL_LEN];
						/* Additional Information */
	uint8_t		apr_private_data[IBT_APR_PRIV_DATA_SZ];
						/* Private data */
} ibcm_apr_msg_t;


/*
 * CM SIDR_REQ Message structure
 *
 * NOTE: SIDR_REQ and SIDR_REP messages are conditionally required.
 * These are needed if non-management services are provided on the Channel
 * Adapter other than fixed QPNs. Management services include those
 * provided thru Subnet Manager Packets or thru General Management Packets.
 *
 * SIDR_REQ requests that the recipient return the information necessary
 * to communicate via UD messages with the entity specified by
 * SIDR_REQ:ServiceID
 */
typedef struct ibcm_sidr_req_msg_s {
	uint32_t	sidr_req_request_id;		/* Request id */
	ib_pkey_t	sidr_req_pkey;			/* P_Key */
	uint8_t		sidr_req_reserved[2];		/* Reserved */
	ib_svc_id_t	sidr_req_service_id;		/* Service Id */
	uint8_t		sidr_req_private_data[IBT_SIDR_REQ_PRIV_DATA_SZ];
							/* Private Data */
} ibcm_sidr_req_msg_t;


/*
 * CM SIDR_REP Message structure
 *
 * SIDR_REP returns the information necessary to communicate via UD
 * messages with the entity specified by SIDR_REQ:ServiceID
 */
typedef struct ibcm_sidr_rep_msg_s {
	uint32_t	sidr_rep_request_id;		/* Request id */
	uint8_t		sidr_rep_rep_status;		/* Status */
	uint8_t		sidr_rep_add_info_len;		/* Length of Add Info */
	uint8_t		sidr_rep_reserved1[2];		/* Reserved */
	uint32_t	sidr_rep_qpn_plus;		/* QPN_24 RSV_8 */
	/* since the 64-bit SID is not aligned, treat it as a byte array */
	uint8_t		sidr_rep_service_id[8];		/* Service Id */
	ib_qkey_t	sidr_rep_qkey;			/* Q_KEY */
	uint8_t		sidr_rep_class_port_info[IBT_CM_SIDR_CP_LEN];
							/* Class Port Info */
							/* aka., add'l info */
	uint8_t		sidr_rep_private_data[IBT_SIDR_REP_PRIV_DATA_SZ];
							/* Private data */
} ibcm_sidr_rep_msg_t;

typedef struct ibcm_classportinfo_msg_s {
	uint8_t		BaseVersion;		/* ver. of MAD base format */
	uint8_t		ClassVersion;		/* ver. of MAD class format */
	uint16_t	CapabilityMask;		/* capabilities of this class */
	uint32_t	RespTimeValue_plus;	/* reserved : 27 bits */
						/* resptime value : 5 bits */
	uint64_t	RedirectGID_hi;		/* dest gid of redirect msgs */
	uint64_t	RedirectGID_lo;		/* dest gid of redirect msgs */
	uint32_t	RedirectTC_plus;	/* traffic class: 8 bits */
						/* SL: 4 bits */
						/* Flow label: 20 bits */
	ib_lid_t	RedirectLID;		/* dlid for class services */
	ib_pkey_t	RedirectP_Key;		/* p_key for class services */
	uint32_t	RedirectQP_plus;	/* Reserved: 8 bits */
						/* QPN: 24 bits */
	ib_qkey_t	RedirectQ_Key;		/* q_key for class services */
	uint64_t	TrapGID_hi;		/* dest gid of trap msgs */
	uint64_t	TrapGID_lo;		/* dest gid of trap msgs */
	uint32_t	TrapTC_plus;		/* Trap traffic class, etc., */
	ib_lid_t	TrapLID;		/* dlid for traps */
	ib_pkey_t	TrapP_Key;		/* p_key for traps */
	uint32_t	TrapHL_plus;		/* Trap hop limit,etc., */
	ib_qkey_t	TrapQ_Key;		/* q_key for traps */
} ibcm_classportinfo_msg_t;

/* All msgs are readonly on receiving side */
_NOTE(READ_ONLY_DATA(ibcm_req_msg_s))
_NOTE(READ_ONLY_DATA(ibcm_rep_msg_s))
_NOTE(READ_ONLY_DATA(ibcm_mra_msg_s))
_NOTE(READ_ONLY_DATA(ibcm_rej_msg_s))
_NOTE(READ_ONLY_DATA(ibcm_lap_msg_s))
_NOTE(READ_ONLY_DATA(ibcm_apr_msg_s))
_NOTE(READ_ONLY_DATA(ibcm_sidr_req_msg_s))
_NOTE(READ_ONLY_DATA(ibcm_sidr_rep_msg_s))
_NOTE(READ_ONLY_DATA(ibcm_rtu_msg_s))
_NOTE(READ_ONLY_DATA(ibcm_dreq_msg_s))
_NOTE(READ_ONLY_DATA(ibcm_drep_msg_s))
_NOTE(READ_ONLY_DATA(ibcm_classportinfo_msg_s))

/* Prototype definitions for CM implementation functions */

/*
 * The callback from IBMF to CM. This routines calls one of the CM
 * state processing functions depending upon mesg/attribute id
 *
 * ibmf_handle	: IBMF handle on which CM MAD was received
 * pktp		: MAD packet
 * args		: IBMF receive mad callback arg
 */
void	ibcm_recv_cb(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp, void *args);

/*
 * Prototypes for CM state transition handling functions
 */

/*
 * The following are the CM state processing functions called on an
 * incoming REQ/REP/RTU/MRA/REJ/DREQ/DREP on active/passive sides
 * (Also handled are SIDR_REP and SIDR_REQ)
 * The brief description of these functions
 *	Search based on CM message fields in CM's HCA entry.
 *	Create/Delete state structures based on incoming message
 *	Handle duplicate messages and state transitions
 *	Set and Cancel timeouts
 *	Handle stale connections
 *	Change CM connection state
 *	Call CM CEP state transition functions to update CEP state
 *	and set CEP attributes
 *
 * INPUTS:
 *	hcap:		- IBMF callback argument
 *	cm_input_mad:	- ibmf message pointer of incoming MAD
 *	cm_mad_addr	- CM MAD address
 *
 * The state transition processing is specified in different functions based
 * on incoming message type rather than as one function because, the CM
 * processing is different for each of them.
 *
 * A global call table is initialized with these function addresses
 * (is defined in ibcm_impl.c), and invoked from ibcm_recv_cb
 * (IBMF's recv callback to CM) based on mesg/attribute id.
 */
void	ibcm_process_req_msg(ibcm_hca_info_t *hcap, uint8_t *cm_input_mad,
	    ibcm_mad_addr_t *cm_mad_addr);
void	ibcm_process_rep_msg(ibcm_hca_info_t *hcap, uint8_t *cm_input_mad,
	    ibcm_mad_addr_t *cm_mad_addr);
void	ibcm_process_rtu_msg(ibcm_hca_info_t *hcap, uint8_t *cm_input_mad,
	    ibcm_mad_addr_t *cm_mad_addr);
void	ibcm_process_dreq_msg(ibcm_hca_info_t *hcap, uint8_t *cm_input_mad,
	    ibcm_mad_addr_t *cm_mad_addr);
void	ibcm_process_drep_msg(ibcm_hca_info_t *hcap, uint8_t *cm_input_mad,
	    ibcm_mad_addr_t *cm_mad_addr);
void	ibcm_process_rej_msg(ibcm_hca_info_t *hcap, uint8_t *cm_input_mad,
	    ibcm_mad_addr_t *cm_mad_addr);
void	ibcm_process_mra_msg(ibcm_hca_info_t *hcap, uint8_t *cm_input_mad,
	    ibcm_mad_addr_t *cm_mad_addr);
void	ibcm_process_apr_msg(ibcm_hca_info_t *hcap, uint8_t *cm_input_mad,
	    ibcm_mad_addr_t *cm_mad_addr);
void	ibcm_process_lap_msg(ibcm_hca_info_t *hcap, uint8_t *cm_input_mad,
	    ibcm_mad_addr_t *cm_mad_addr);
void	ibcm_process_sidr_req_msg(ibcm_hca_info_t *hcap,
	    uint8_t *cm_input_mad, ibcm_mad_addr_t *cm_mad_addr);
void	ibcm_process_sidr_rep_msg(ibcm_hca_info_t *hcap,
	    uint8_t *cm_input_mad, ibcm_mad_addr_t *cm_mad_addr);

typedef enum ibcm_proceed_error_e {
	IBCM_PROCEED_INVALID_NONE	= 0,
	IBCM_PROCEED_INVALID_EVENT,
	IBCM_PROCEED_INVALID_EVENT_STATE,
	IBCM_PROCEED_INVALID_PRIV_SZ,
	IBCM_PROCEED_INVALID_LAP
} ibcm_proceed_error_t;

/* Encapsulates the information that client returns back from CM callback */
typedef struct ibcm_clnt_reply_info_s {
	ibt_cm_proceed_reply_t	*reply_event;
	void			*priv_data;
	ibt_priv_data_len_t	priv_data_len;
} ibcm_clnt_reply_info_t;

/* Encapsulates the information that UD client returns back from CM callback */
typedef struct ibcm_ud_clnt_reply_info_s {
	ib_qpn_t		ud_qpn;
	ib_qkey_t		ud_qkey;
	ibt_redirect_info_t	*redirect_infop;
	void			*priv_data;
	ibt_priv_data_len_t	priv_data_len;
} ibcm_ud_clnt_reply_info_t;

/*
 * Prototypes for CM CEP state transition handling functions. These are
 * called from CM connection state transition handling functions.
 *
 * The brief description of these functions :
 *	Validate CEP related attributes in the messages
 *	Change CEP state
 *	Set CEP attributes (modify CEP)
 *	Call client/server callback handlers
 *	Fill up the response MADs
 *
 * The arguments are :
 *	statep:		Connection state structure
 *	cm_req/rep/rtu/rej msg : Received CM message
 *	cm_output_mad	: The response CM MAD with some of the fields filled in
 *			  The cm output mad is allocated by CM state transition
 *			  functions and has generic MAD header
 *			  Certain fields like com id, etc., are filled by CM
 *			  connection state transition functions that are above
 */

/* QP state transition function called for an incoming REQ on passive side */
ibcm_status_t	ibcm_cep_state_req(ibcm_state_data_t *statep,
		    ibcm_req_msg_t *cm_req_msg, ibt_cm_reason_t *reason,
		    uint8_t *arej_info_len);

/* Processes QP state machine based on return values from cm handler */
ibcm_status_t	ibcm_process_cep_req_cm_hdlr(ibcm_state_data_t *statep,
		    ibt_cm_status_t cb_status,
		    ibcm_clnt_reply_info_t *clnt_info,
		    ibt_cm_reason_t *reject_reason, uint8_t *arej_len,
		    ibcm_req_msg_t *cm_req_msgp);

/* Processes CM state machine based on return values from ibcm_cep_state_req */
void		ibcm_handle_cep_req_response(ibcm_state_data_t *statep,
		    ibcm_status_t response, ibt_cm_reason_t reject_reason,
		    uint8_t arej_info_len);

/* QP state transition function called for an incoming REP on active side */
ibcm_status_t	ibcm_cep_state_rep(ibcm_state_data_t *statep,
		    ibcm_rep_msg_t *cm_rep_msg, ibt_cm_reason_t *reason,
		    uint8_t *arej_info_len);

/* Processes QP state machine based on return values from cm handler */
ibcm_status_t	ibcm_process_cep_rep_cm_hdlr(ibcm_state_data_t *statep,
		    ibt_cm_status_t cb_status,
		    ibcm_clnt_reply_info_t *clnt_info,
		    ibt_cm_reason_t *reject_reason, uint8_t *arej_len,
		    ibcm_rep_msg_t *cm_rep_msgp);

/* Processes CM state machine based on return values from ibcm_cep_state_rep */
void		ibcm_handle_cep_rep_response(ibcm_state_data_t *statep,
		    ibcm_status_t response, ibt_cm_reason_t reject_reason,
		    uint8_t arej_info_len, ibcm_rep_msg_t *rep_msgp);

/* QP state transition function called for an incoming RTU on passive side */
void	ibcm_cep_state_rtu(ibcm_state_data_t *statep,
	    ibcm_rtu_msg_t *cm_rtu_msg);

/* QP state transition func called for an incoming REJ on active/passive side */
void	ibcm_cep_state_rej(ibcm_state_data_t *statep,
	    ibcm_rej_msg_t *cm_rej_msg, ibcm_conn_state_t rej_state);

/* QP state transition func for an incoming REJ on active side in est state */
void	ibcm_cep_state_rej_est(ibcm_state_data_t *statep);

/*
 * QP state transition function called for an outgoing RTU on active side,
 * after setting CEP to RTS state active/passive side
 */
void	ibcm_cep_send_rtu(ibcm_state_data_t *statep);


/* QP state transition function called for an incoming LAP */
ibcm_status_t	ibcm_cep_state_lap(ibcm_state_data_t *statep,
		    ibcm_lap_msg_t *lap_msg, ibcm_apr_msg_t *apr_msg);

/* Processes QP state machine based on return value from cm handler for LAP */
void		ibcm_process_cep_lap_cm_hdlr(ibcm_state_data_t *statep,
		    ibt_cm_status_t cb_status,
		    ibcm_clnt_reply_info_t *clnt_info,
		    ibcm_lap_msg_t *lap_msg, ibcm_apr_msg_t *apr_msg);

void		ibcm_post_apr_mad(ibcm_state_data_t *statep);

void		ibcm_cep_state_apr(ibcm_state_data_t *statep,
		    ibcm_lap_msg_t *lap_msg, ibcm_apr_msg_t *apr_msg);

/* Processes CM state machine based on return value from cm handler */
void		ibcm_handle_cep_dreq_response(ibcm_state_data_t *statep,
		    void *priv_data, ibt_priv_data_len_t  priv_data_len);

/* Processes CM UD state machine based on return values from cm handler */
void		ibcm_process_sidr_req_cm_hdlr(ibcm_ud_state_data_t *ud_statep,
		    ibt_cm_status_t cb_status,
		    ibcm_ud_clnt_reply_info_t *ud_clnt_info,
		    ibt_sidr_status_t *sidr_status,
		    ibcm_sidr_rep_msg_t *sidr_repp);

void		ibcm_proceed_via_taskq(void *targs);
void		ibcm_ud_proceed_via_taskq(void *targs);

/*
 * Builds the reply MAD address based on "incoming mad addr" that is
 * supplied to it as an arg.
 *	Swaps the source and destination lids in ibmf_addr_info_t
 *	Swaps the source and destination gids in ib_grh_t
 *
 * INPUTS:
 *	incoming_cm_mad_addr	- Address information in the incoming MAD
 *	reply_cm_mad_addr	- Derived address for the reply MAD
 *				  The reply MAD address is derived based
 *				  address information of incoming CM MAD
 */
void	ibcm_build_reply_mad_addr(ibcm_mad_addr_t *incoming_cm_mad_addr,
	    ibcm_mad_addr_t *reply_cm_mad_addr);

/*  Posts RC CM MAD using IBMF */
void	ibcm_post_rc_mad(ibcm_state_data_t *statep, ibmf_msg_t *msgp,
	    ibmf_msg_cb_t post_cb, void *args);

/*  Posts UD CM MAD using IBMF */
void	ibcm_post_ud_mad(ibcm_ud_state_data_t *ud_statep, ibmf_msg_t *msgp,
	    ibmf_msg_cb_t ud_post_cb, void *args);

/*  Posts CM MAD using IBMF */
ibt_status_t	ibcm_post_mad(ibmf_msg_t *msgp, ibcm_mad_addr_t *cm_mad_addr,
	    ibmf_msg_cb_t post_cb, void *args);

/* Post REJ MAD */
void	ibcm_post_rej_mad(ibcm_state_data_t *statep, ibt_cm_reason_t reason,
	    int who, void *addl_rej_info, uint8_t arej_info_len);

/* Post REP MAD */
void	ibcm_post_rep_mad(ibcm_state_data_t *statep);

/* Post RTU MAD */
ibcm_status_t	ibcm_post_rtu_mad(ibcm_state_data_t *statep);

/* Post DREQ MAD */
void	ibcm_post_dreq_mad(void *statep);

/* Post LAP MAD */
void	ibcm_post_lap_mad(ibcm_state_data_t *statep);


/*
 * Posts CM SIDR MAD using IBMF in blocking mode
 *
 * INPUTS:
 *	ud_statep:	UD statep which is posting the mad
 *	cm_mad_addr:	Address information for the MAD to be posted
 *	status:		SIDR status
 */
void	ibcm_post_sidr_rep_mad(ibcm_ud_state_data_t *ud_statep,
	    ibt_sidr_status_t status);

/* prototypes to resend RC mad and UD MAD */
void	ibcm_resend_rep_mad(ibcm_state_data_t *statep);
void	ibcm_resend_rtu_mad(ibcm_state_data_t *statep);
void	ibcm_resend_rej_mad(ibcm_state_data_t *statep);
void	ibcm_resend_mra_mad(ibcm_state_data_t *statep);
void	ibcm_resend_srep_mad(ibcm_ud_state_data_t *statep);


/* Helper function used in connection abort processing */
void	ibcm_process_abort(ibcm_state_data_t	*statep);

/*
 * Prototypes for CM functions that lookup for a connection state structure
 */

/*
 * ibcm_lookup_msg:
 *
 * Retrieves an existing state structure or creates a new one if none found.
 * This function is used during passive side of connection establishment for
 * INCOMING REQ/REJ/RTU/MRA
 * This function is used during active side of connection establishment for
 * INCOMING REP/REJ/MRA
 * This function is used during active side of connection establishment for
 * an outgoing REQ.
 *
 * NOTE: IBCM_LOOKP_FAIL is only returned if a new entry wasn't created and
 * a match wasn't found.
 *
 * Arguments are:-
 *	ibcm_event_type_t	- what type of message
 *				  incoming REQ, REP, REJ, MRA, RTU, DREQ, DREP
 *	local_comid		- ONLY *NOT* valid for incoming REQ.
 *					needed for others
 *	remote_qpn		- Remote CM's QP number
 *	remote_hca_guid		- ONLY VALID FOR incoming REQ.
 *				  Ignored for others
 *	hcap			- HCA entry table pointer
 *	statep			- "return"ed state pointer
 *
 * Return Values:
 *	IBCM_LOOKUP_NEW		- new statep allocated
 *	IBCM_LOOKUP_EXISTS	- found an existing entry
 *	IBCM_LOOKUP_FAIL	- failed to find an entry
 *	IBCM_MEMORY_FAILURE	- failed to get memory
 *					iff flags != IBT_CHAN_BLOCKING
 */
ibcm_status_t	ibcm_lookup_msg(ibcm_event_type_t event_type,
		    ib_com_id_t local_comid, ib_qpn_t remote_qpn,
		    ib_guid_t remote_hca_guid, ibcm_hca_info_t *hcap,
		    ibcm_state_data_t **statep);


/*
 * Routines for CM SIDR state structure list manipulation
 * Wherever possible, the list routines of ibtl are used
 * for list manipulation
 */

/*
 * Finds an entry based on lid, gid and grh exists fields
 * lid:		LID of incoming SIDR REQ
 * gid:		GID of incoming SIDR REQ
 * grh_exists:		TRUE if GRH exists in the incoming SIDR REQ
 * hcap:	CM State HCA entry ptr to search for SIDR state structure
 * statep:	Returns a valid state structure, if one exists based
 *		on lid, gid and grh_exists fields
 * flag:	whether to just look OR to look and add if it doesn't exist.
 */
ibcm_status_t		ibcm_find_sidr_entry(ibcm_sidr_srch_t *srch_param,
			    ibcm_hca_info_t *hcap,
			    ibcm_ud_state_data_t **statep,
			    ibcm_lookup_flag_t flag);

ibcm_ud_state_data_t	*ibcm_add_sidr_entry(ibcm_sidr_srch_t *srch_param,
			    ibcm_hca_info_t *hcap);

/*
 * Deletes a given state structure, from both hca state and passive trees
 * If ref cnt is zero, deallocates all buffers and memory of state data
 */
void	ibcm_delete_state_data(ibcm_state_data_t *statep);

/*
 * Deallocates all the buffers and memory of state data.
 * This function must be called, only when ref_cnt is zero.
 */
void	ibcm_dealloc_state_data(ibcm_state_data_t *statep);

/*
 * Deletes a given UD state structure, from SIDR list.
 * The routine acquires and releases the SIDR list lock.
 */
void	ibcm_delete_ud_state_data(ibcm_ud_state_data_t *statep);
void	ibcm_dealloc_ud_state_data(ibcm_ud_state_data_t *statep);

/*
 * Service ID entry create and lookup functions
 */

/*
 * Adds/looks-up an ibcm_svc_info_t entry in the CM's global table.
 * This global table is defined in ibcm_impl.c.
 *
 * svc_info_list_lock must be held for RW_READER by caller of
 * ibcm_find_svc_entry().
 *
 * Arguments are:-
 *	sid		- service id
 *	num_sids	- Number (Range) of service-ids
 *
 * Return values:
 *	Pointer to ibcm_svc_info_t on success, otherwise NULL.
 */
int ibcm_svc_compare(const void *p1, const void *p2);
ibcm_svc_info_t *ibcm_create_svc_entry(ib_svc_id_t sid, int num_sids);
ibcm_svc_info_t *ibcm_find_svc_entry(ib_svc_id_t sid);

/*
 * The following are the function prototypes for various id initialization,
 * allocation, free and destroy operations. The cm id allocations are based
 * on vmem operations
 * The service id's are maintained globally per host
 * The com id and req id's are maintained per hca
 * To maintain compatibility with intel, service ids are allocated on a 32 bit
 * range, though spec has 64 bit range for service id's
 */
ibcm_status_t	ibcm_init_ids();
void		ibcm_fini_ids();

ibcm_status_t	ibcm_init_hca_ids(ibcm_hca_info_t *hcap);
void		ibcm_fini_hca_ids(ibcm_hca_info_t *hcap);

ibcm_status_t	ibcm_alloc_comid(ibcm_hca_info_t *hcap, ib_com_id_t *comid);
void		ibcm_free_comid(ibcm_hca_info_t *hcap, ib_com_id_t comid);

ibcm_status_t	ibcm_alloc_reqid(ibcm_hca_info_t *hcap, uint32_t *reqid);
void		ibcm_free_reqid(ibcm_hca_info_t *hcap, uint32_t reqid);

ib_svc_id_t	ibcm_alloc_local_sids(int num_sids);
void		ibcm_free_local_sids(ib_svc_id_t service_id, int num_sids);

ib_svc_id_t	ibcm_alloc_ip_sid();
void		ibcm_free_ip_sid(ib_svc_id_t sid);

uint64_t	ibcm_generate_tranid(uint8_t event, uint32_t id,
		    uint32_t cm_tran_priv);

void		ibcm_decode_tranid(uint64_t tran_id, uint32_t *cm_tran_priv);

ibcm_status_t	ibcm_ar_init(void);
ibcm_status_t	ibcm_ar_fini(void);

/* IP Addressing API debugging */
extern int ibcm_printip;	/* set to 1 to enable IBTF DPRINTFs */
extern void ibcm_ip_print(char *label, ibt_ip_addr_t *ipa);

#define	IBCM_PRINT_IP(LABEL, IP_ADDR)			\
	if (ibcm_printip) {			\
		ibcm_ip_print(LABEL, IP_ADDR);	\
	}
/*
 * These functions are called to do timeout processing from CM connection
 * state transitions. (Also for SIDR REQ and SIDR REP processing)
 *
 * Brief description :
 *	If retry count is below max retry value, then post the stored response
 *	MAD using IBMF in blocking mode, adjusts remaining retry counters.
 *	If retry counter reaches max value, then retry failure handling is
 *	done here
 *
 *	CM will ensure that the state data structure of the associated
 *	timeout is valid when this timeout function is called.
 *	(See timer_stored_state in ibcm_state_data_t and
 *	ud_timer_stored_state in ibcm_ud_state_data_t)
 */
void	ibcm_timeout_cb(void *arg);
void	ibcm_sidr_timeout_cb(void *arg);

/*
 * function prototypes for IBMF send completion callbacks on non-blocking
 * MAD posts
 */
void	ibcm_post_req_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
	    void *args);
void	ibcm_post_rep_wait_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
	    void *args);	/* MRA Rcvd on active side */
void	ibcm_post_rep_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
	    void *args);
void	ibcm_resend_post_rep_complete(ibmf_handle_t ibmf_handle,
	    ibmf_msg_t *msgp, void *args);
void	ibcm_post_mra_rep_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
	    void *args);	/* MRA Rcvd on passive side */
void	ibcm_post_rej_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
	    void *args);
void	ibcm_post_dreq_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
	    void *args);
void	ibcm_post_drep_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
	    void *args);
void	ibcm_post_lap_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
	    void *args);
void	ibcm_post_apr_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
	    void *args);
void	ibcm_post_stored_apr_complete(ibmf_handle_t ibmf_handle,
	    ibmf_msg_t *msgp, void *args);
void	ibcm_post_mra_lap_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
	    void *args);	/* MRA Rcvd for LAP on active side */
void	ibcm_post_mra_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
	    void *args);	/* for MRA sender */
void	ibcm_post_rtu_complete(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
	    void *args);

void	ibcm_post_sidr_req_complete(ibmf_handle_t ibmf_handle,
	    ibmf_msg_t *msgp, void *args);

/*
 * ibcm_find_hca_entry:
 *	Given a HCA's GUID find out ibcm_hca_info_t entry for that HCA
 *	This entry can be then used to access AVL tree/SIDR list etc.
 *
 *	NOTE: This entry is not removed from the "ibcm_hca_listp".
 *	And this function is called with ibcm_hca_list_mutex mutex held.
 *
 * INPUTS:
 *	hca_guid	- HCA's guid
 *
 * RETURN VALUE:
 *	hcap		- if a match is found, else NULL
 */
ibcm_hca_info_t	*ibcm_find_hca_entry(ib_guid_t hca_guid);
ibcm_hca_info_t	*ibcm_find_hcap_entry(ib_guid_t hca_guid);
void ibcm_delete_hca_entry(ibcm_hca_info_t *hcap);

/* Routines that manage the hca's temporary access count */
ibcm_status_t ibcm_inc_hca_acc_cnt(ibcm_hca_info_t *hca);
void ibcm_dec_hca_acc_cnt(ibcm_hca_info_t *hca);

/* Routines that manage the hca's resource count */
void ibcm_inc_hca_res_cnt(ibcm_hca_info_t *hca);
void ibcm_dec_hca_res_cnt(ibcm_hca_info_t *hca);

/* Routines that manage the hca's service count */
void ibcm_inc_hca_svc_cnt(ibcm_hca_info_t *hca);
void ibcm_dec_hca_svc_cnt(ibcm_hca_info_t *hca);

/* Routine to fetch the saa_handle */
ibmf_saa_handle_t ibcm_get_saa_handle(ibcm_hca_info_t *hcap, uint8_t port);

/* Allow some flow control of RC connection initiations */
void ibcm_flow_inc(void);
void ibcm_flow_dec(hrtime_t delta, char *mad_type);

/* Allow some flow control of SA requests */
void ibcm_sa_access_enter(void);
void ibcm_sa_access_exit(void);

/*
 * ibcm_cep_to_error_state:
 *	Helper function to transition a CEP to ERROR state
 *
 *	NOTE: This function checks if ch_qp is valid or ch_eec and calls
 *	into IBTL to transition the CEP.
 *
 * INPUTS:
 *	statep	- Connection state pointer
 *
 * RETURN VALUE:
 *	IBT_SUCCESS	- if CEP transition succeeded; else error
 */
ibt_status_t	ibcm_cep_to_error_state(ibcm_state_data_t *statep);

/*
 * Processes the pending stateps in a linked list. The operations are to
 * invoke a cm handler or delete statep
 * When the above operations are required on statep from a timeout handler,
 * they are linked for later processing by an independent thread
 */
void	ibcm_process_tlist();
/* Links RC stateps to an RC timeout processing list */
void	ibcm_add_tlist(ibcm_state_data_t *statep);

/* Links SIDR/UD stateps to an SIDR/UD timeout processing list */
void	ibcm_add_ud_tlist(ibcm_ud_state_data_t *ud_statep);

/*
 * This call either aborts a pending or completes a in-progress LAP/APR
 * operation
 */
void	ibcm_sync_lapr_idle(ibcm_state_data_t	*statep);

void	ibcm_process_rc_recycle(void *recycle_arg);

/*
 * Helper function to handle endianess in case of Service Data.
 * Used by ibt_bind_service() and ibt_get_paths().
 */
void ibcm_swizzle_from_srv(ibt_srv_data_t *sb_data, uint8_t *service_bytes);
void ibcm_swizzle_to_srv(uint8_t *service_bytes, ibt_srv_data_t *sb_data);

/* Misc ibcm global variables */
extern char			cmlog[];
extern ibt_clnt_hdl_t		ibcm_ibt_handle;
extern taskq_t			*ibcm_taskq;
extern ibcm_state_handler_t	ibcm_sm_funcs_tbl[];
extern uint8_t			ibcm_timeout_list_flags;
extern ibcm_classportinfo_msg_t	ibcm_clpinfo;

/* Global lists */
extern avl_tree_t	ibcm_svc_avl_tree;	/* global service id tree */
extern ibcm_state_data_t	*ibcm_timeout_list_hdr, *ibcm_timeout_list_tail;
extern ibcm_ud_state_data_t	*ibcm_ud_timeout_list_hdr,
				*ibcm_ud_timeout_list_tail;
/* Default global retry counts */
extern uint8_t		ibcm_max_retries;
extern uint32_t		ibcm_max_sa_retries;
extern int		ibcm_sa_timeout_delay;	/* in ticks */

/* Various default global timers */
extern ibt_rnr_nak_time_t	ibcm_default_rnr_nak_time;

extern clock_t		ibcm_local_processing_time;	/* usecs */
extern clock_t		ibcm_remote_response_time;
extern ib_time_t	ibcm_max_sidr_rep_proctime;
extern ib_time_t	ibcm_max_sidr_rep_store_time;
extern uint32_t		ibcm_adj_btime;
extern uint32_t		ibcm_sw_delay;

extern ib_time_t	ibcm_max_ib_pkt_lt;
extern ib_time_t	ibcm_max_ib_mad_pkt_lt;

/* Global locks */
extern kmutex_t		ibcm_svc_info_lock;
extern kmutex_t		ibcm_mcglist_lock;
extern kmutex_t		ibcm_global_hca_lock;
extern kmutex_t		ibcm_qp_list_lock;
extern kmutex_t		ibcm_timeout_list_lock;
extern kmutex_t		ibcm_recv_mutex;

/* Global cond variables */
extern kcondvar_t	ibcm_global_hca_cv;
extern kcondvar_t	ibcm_svc_info_cv;
extern kcondvar_t	ibcm_timeout_list_cv;
extern kcondvar_t	ibcm_timeout_thread_done_cv;

_NOTE(LOCK_ORDER(ibcm_state_data_s::state_mutex ibcm_timeout_list_lock))
_NOTE(LOCK_ORDER(ibcm_ud_state_data_s::ud_state_mutex ibcm_timeout_list_lock))
_NOTE(LOCK_ORDER(ibcm_hca_info_s::hca_state_rwlock
    ibcm_state_data_s::state_mutex))
_NOTE(LOCK_ORDER(ibcm_hca_info_s::hca_sidr_list_lock
    ibcm_ud_state_data_s::ud_state_mutex))

_NOTE(READ_ONLY_DATA(ibcm_local_processing_time ibcm_remote_response_time
    ibcm_max_sidr_rep_proctime ibcm_max_sidr_rep_store_time ibcm_adj_btime
    ibcm_sw_delay ibcm_max_retries ibcm_max_sa_retries))

/*
 * miscellaneous defines for retries, times etc.
 */
#define	IBCM_MAX_RETRIES		11	/* Max CM retries for a msg */
#define	IBCM_LOCAL_RESPONSE_TIME	300000	/* Local CM processing time */
						/* in usecs */
#define	IBCM_REMOTE_RESPONSE_TIME	300000	/* Remote CM response time  */
						/* in usecs */
#define	IBCM_MAX_SIDR_PROCESS_TIME	16	/* Time to process SIDR REP */
#define	IBCM_MAX_SIDR_PKT_LIFE_TIME	9	/* Approx pkt lt for UD srver */

#define	IBCM_MAX_IB_PKT_LT		20	/* 4 second */
#define	IBCM_MAX_IB_MAD_PKT_LT		18	/* 1 second */

#define	IBCM_MAX_SA_RETRIES		0	/* Max CM retry for SA update */

/* versions for CM MADs */
#define	IBCM_MAD_BASE_VERSION		1
#define	IBCM_MAD_CLASS_VERSION		2

/* for Class_Port_Info stuff - see section 16.7.3.1 in Vol1 IB Spec */
#define	IBCM_CPINFO_CAP_RC		0x0200	/* RC is supported */
#define	IBCM_CPINFO_CAP_RD		0x0400	/* RD is supported */
#define	IBCM_CPINFO_CAP_RAW		0x0800	/* Raw Datagrams supported */
#define	IBCM_CPINFO_CAP_UC		0x1000	/* UC supported */
#define	IBCM_CPINFO_CAP_SIDR		0x2000	/* SIDR supported */

#define	IBCM_V4_PART_OF_V6(v6)	v6.s6_addr32[3]
/* RDMA CM IP Service's Private Data Format. */
#ifdef _BIG_ENDIAN
typedef struct ibcm_ip_pvtdata_s {
	uint8_t		ip_MajV:4,
			ip_MinV:4;
	uint8_t		ip_ipv:4,
			ip_rsvd:4;	/* 0-3: rsvd, 4-7: ipv */
	uint16_t	ip_srcport;	/* Source Port */
	in6_addr_t	ip_srcip;	/* Source IP address. */
	in6_addr_t	ip_dstip;	/* Remote IP address. */
#define	ip_srcv4	IBCM_V4_PART_OF_V6(ip_srcip)
#define	ip_dstv4	IBCM_V4_PART_OF_V6(ip_dstip)
#define	ip_srcv6	ip_srcip
#define	ip_dstv6	ip_dstip
} ibcm_ip_pvtdata_t;
#else
typedef struct ibcm_ip_pvtdata_s {
	uint8_t		ip_MinV:4,
			ip_MajV:4;
	uint8_t		ip_rsvd:4,
			ip_ipv:4;	/* 0-3: rsvd, 4-7: ipv */
	uint16_t	ip_srcport;	/* Source Port */
	in6_addr_t	ip_srcip;	/* Source IP address. */
	in6_addr_t	ip_dstip;	/* Remote IP address. */
#define	ip_srcv4	IBCM_V4_PART_OF_V6(ip_srcip)
#define	ip_dstv4	IBCM_V4_PART_OF_V6(ip_dstip)
#define	ip_srcv6	ip_srcip
#define	ip_dstv6	ip_dstip
} ibcm_ip_pvtdata_t;
#endif

/*
 * for debug purposes
 */
#ifdef	DEBUG
extern	int ibcm_test_mode;

void	ibcm_query_qp(ibmf_handle_t ibmf_hdl, ibmf_qp_handle_t ibmf_qp);
void	ibcm_dump_raw_message(uchar_t *);
void	ibcm_dump_srvrec(sa_service_record_t *);
void	ibcm_dump_pathrec(sa_path_record_t *);
void	ibcm_dump_noderec(sa_node_record_t *);

void	ibcm_query_classport_info(ibt_channel_hdl_t channel);

#define	IBCM_DUMP_RAW_MSG(x)		ibcm_dump_raw_message(x)
#define	IBCM_DUMP_SERVICE_REC(x)	ibcm_dump_srvrec(x)
#define	IBCM_DUMP_PATH_REC(x)		ibcm_dump_pathrec(x)
#define	IBCM_DUMP_NODE_REC(x)		ibcm_dump_noderec(x)
#else
#define	IBCM_DUMP_RAW_MSG(x)
#define	IBCM_DUMP_SERVICE_REC(x)
#define	IBCM_DUMP_PATH_REC(x)
#define	IBCM_DUMP_NODE_REC(x)
#endif

ibt_status_t ibcm_ibmf_analyze_error(int ibmf_status);

ibt_status_t ibcm_contact_sa_access(ibmf_saa_handle_t saa_handle,
    ibmf_saa_access_args_t *access_args, size_t *length, void **results_p);

ibt_status_t	ibcm_ibtl_node_info(ib_guid_t, uint8_t, ib_lid_t,
    ibt_node_info_t *node_info);

void ibcm_path_cache_init(void);
void ibcm_path_cache_fini(void);
void ibcm_path_cache_purge(void);

#ifdef	__cplusplus
}
#endif


#endif /* _SYS_IB_MGT_IBCM_IBCM_IMPL_H */
