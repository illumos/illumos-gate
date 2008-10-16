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
 * ibcm_impl.c
 *
 * contains internal functions of IB CM module.
 *
 * TBD:
 * 1. HCA CATASTROPHIC/RECOVERED not handled yet
 */

#include <sys/ib/mgt/ibcm/ibcm_impl.h>
#include <sys/disp.h>


/* function prototypes */
static ibcm_status_t	ibcm_init(void);
static ibcm_status_t	ibcm_fini(void);

/* Routines to initialize and destory CM global locks and CVs */
static void		ibcm_init_locks(void);
static void		ibcm_fini_locks(void);

/* Routines that initialize/teardown CM's global hca structures */
static void		ibcm_init_hcas();
static ibcm_status_t	ibcm_fini_hcas();

static void		ibcm_init_classportinfo();
static void		ibcm_stop_timeout_thread();

/* Routines that handle HCA attach/detach asyncs */
static void		ibcm_hca_attach(ib_guid_t);
static ibcm_status_t	ibcm_hca_detach(ibcm_hca_info_t *);

/* Routines that initialize the HCA's port related fields */
static ibt_status_t	ibcm_hca_init_port(ibcm_hca_info_t *hcap,
			    uint8_t port_index);
static ibcm_status_t	ibcm_hca_fini_port(ibcm_hca_info_t *hcap,
			    uint8_t port_index);

static void ibcm_rc_flow_control_init(void);
static void ibcm_rc_flow_control_fini(void);

/*
 * Routines that check if hca's avl trees and sidr lists are free of any
 * active client resources ie., RC or UD state structures in certain states
 */
static ibcm_status_t	ibcm_check_avl_clean(ibcm_hca_info_t *hcap);
static ibcm_status_t	ibcm_check_sidr_clean(ibcm_hca_info_t *hcap);

/* Add a new hca structure to CM's global hca list */
static ibcm_hca_info_t	*ibcm_add_hca_entry(ib_guid_t hcaguid, uint_t nports);

static void		ibcm_comm_est_handler(ibt_async_event_t *);
void			ibcm_async_handler(void *, ibt_hca_hdl_t,
			    ibt_async_code_t, ibt_async_event_t *);

/* Global variables */
char			cmlog[] = "ibcm";	/* for debug log messages */
ibt_clnt_hdl_t		ibcm_ibt_handle;	/* IBT handle */
kmutex_t		ibcm_svc_info_lock;	/* list lock */
kcondvar_t		ibcm_svc_info_cv;	/* cv for deregister */
kmutex_t		ibcm_recv_mutex;
avl_tree_t		ibcm_svc_avl_tree;
taskq_t			*ibcm_taskq = NULL;
int			taskq_dispatch_fail_cnt;

kmutex_t		ibcm_trace_mutex;	/* Trace mutex */
kmutex_t		ibcm_trace_print_mutex;	/* Trace print mutex */
int			ibcm_conn_max_trcnt = IBCM_MAX_CONN_TRCNT;

int			ibcm_enable_trace = 2;	/* Trace level 4 by default */
int			ibcm_dtrace = 0; /* conditionally enable more dtrace */

_NOTE(MUTEX_PROTECTS_DATA(ibcm_svc_info_lock, ibcm_svc_info_s::{svc_bind_list
    svc_ref_cnt svc_to_delete}))

_NOTE(MUTEX_PROTECTS_DATA(ibcm_svc_info_lock, ibcm_svc_bind_s::{sbind_link}))

_NOTE(MUTEX_PROTECTS_DATA(ibcm_trace_mutex, ibcm_conn_trace_s))

_NOTE(DATA_READABLE_WITHOUT_LOCK(ibcm_conn_trace_s))

_NOTE(MUTEX_PROTECTS_DATA(ibcm_trace_print_mutex, ibcm_debug_buf))

_NOTE(DATA_READABLE_WITHOUT_LOCK(ibcm_debug_buf))

/*
 * Initial state is INIT. All hca dr's return success immediately in this
 * state, without adding or deleting any hca's to CM.
 */
ibcm_finit_state_t	ibcm_finit_state = IBCM_FINIT_INIT;

/* mutex and cv to manage hca's reference and resource count(s) */
kmutex_t		ibcm_global_hca_lock;
kcondvar_t		ibcm_global_hca_cv;

/* mutex and cv to sa session open */
kmutex_t		ibcm_sa_open_lock;
kcondvar_t		ibcm_sa_open_cv;
int			ibcm_sa_timeout_delay = 1;		/* in ticks */
_NOTE(MUTEX_PROTECTS_DATA(ibcm_sa_open_lock,
    ibcm_port_info_s::{port_ibmf_saa_hdl port_saa_open_in_progress}))

_NOTE(DATA_READABLE_WITHOUT_LOCK(ibcm_port_info_s::{port_ibmf_saa_hdl}))

/* serialize sm notice callbacks */
kmutex_t		ibcm_sm_notice_serialize_lock;

_NOTE(LOCK_ORDER(ibcm_sm_notice_serialize_lock ibcm_global_hca_lock))

_NOTE(MUTEX_PROTECTS_DATA(ibcm_global_hca_lock, ibcm_hca_info_s::{hca_state
    hca_svc_cnt hca_acc_cnt hca_res_cnt hca_next}))

_NOTE(MUTEX_PROTECTS_DATA(ibcm_global_hca_lock,
    ibcm_port_info_s::{port_ibmf_hdl}))

_NOTE(MUTEX_PROTECTS_DATA(ibcm_sm_notice_serialize_lock,
    ibcm_port_info_s::{port_event_status}))

_NOTE(DATA_READABLE_WITHOUT_LOCK(ibcm_hca_info_s::{hca_state}))
_NOTE(DATA_READABLE_WITHOUT_LOCK(
    ibcm_hca_info_s::{hca_port_info.port_ibmf_hdl}))

/* mutex for CM's qp list management */
kmutex_t		ibcm_qp_list_lock;

_NOTE(MUTEX_PROTECTS_DATA(ibcm_qp_list_lock, ibcm_port_info_s::{port_qplist}))
_NOTE(MUTEX_PROTECTS_DATA(ibcm_qp_list_lock, ibcm_qp_list_s))
_NOTE(MUTEX_PROTECTS_DATA(ibcm_qp_list_lock, ibcm_qp_list_s))

kcondvar_t		ibcm_timeout_list_cv;
kcondvar_t		ibcm_timeout_thread_done_cv;
kt_did_t		ibcm_timeout_thread_did;
ibcm_state_data_t	*ibcm_timeout_list_hdr, *ibcm_timeout_list_tail;
ibcm_ud_state_data_t	*ibcm_ud_timeout_list_hdr, *ibcm_ud_timeout_list_tail;
kmutex_t		ibcm_timeout_list_lock;
uint8_t			ibcm_timeout_list_flags = 0;
pri_t			ibcm_timeout_thread_pri = MINCLSYSPRI;

_NOTE(MUTEX_PROTECTS_DATA(ibcm_timeout_list_lock,
    ibcm_state_data_s::timeout_next))

_NOTE(MUTEX_PROTECTS_DATA(ibcm_timeout_list_lock,
    ibcm_ud_state_data_s::ud_timeout_next))

/*
 * Flow control logic for open_rc_channel uses the following.
 */

struct ibcm_open_s {
	kmutex_t		mutex;
	kcondvar_t		cv;
	uint8_t			task_running;
	uint_t			queued;
	uint_t			exit_deferred;
	uint_t			in_progress;
	uint_t			in_progress_max;
	uint_t			sends;
	uint_t			sends_max;
	uint_t			sends_lowat;
	uint_t			sends_hiwat;
	ibcm_state_data_t	*tail;
	ibcm_state_data_t	head;
} ibcm_open;

static void ibcm_open_task(void *);

/*
 * Flow control logic for SA access and close_rc_channel calls follows.
 */

int ibcm_close_simul_max	= 12;
int ibcm_lapr_simul_max		= 12;
int ibcm_saa_simul_max		= 8;

typedef struct ibcm_flow1_s {
	struct ibcm_flow1_s	*link;
	kcondvar_t		cv;
	uint8_t			waiters;	/* 1 to IBCM_FLOW_SIMUL_MAX */
} ibcm_flow1_t;

typedef struct ibcm_flow_s {
	ibcm_flow1_t		*list;
	uint_t			simul;	/* #requests currently outstanding */
	uint_t			simul_max;
	uint_t			waiters_per_chunk;
	uint_t			lowat;
	uint_t			lowat_default;
	/* statistics */
	uint_t			total;
} ibcm_flow_t;

ibcm_flow_t ibcm_saa_flow;
ibcm_flow_t ibcm_close_flow;
ibcm_flow_t ibcm_lapr_flow;

/* NONBLOCKING close requests are queued */
struct ibcm_close_s {
	kmutex_t		mutex;
	ibcm_state_data_t	*tail;
	ibcm_state_data_t	head;
} ibcm_close;

static ibt_clnt_modinfo_t ibcm_ibt_modinfo = {	/* Client's modinfop */
	IBTI_V2,
	IBT_CM,
	ibcm_async_handler,
	NULL,
	"IBCM"
};

/* IBCM's list of HCAs registered with it */
static ibcm_hca_info_t	*ibcm_hca_listp = NULL;	/* CM's HCA list */

/* Array of CM state call table functions */
ibcm_state_handler_t	ibcm_sm_funcs_tbl[] = {
	ibcm_process_req_msg,
	ibcm_process_mra_msg,
	ibcm_process_rej_msg,
	ibcm_process_rep_msg,
	ibcm_process_rtu_msg,
	ibcm_process_dreq_msg,
	ibcm_process_drep_msg,
	ibcm_process_sidr_req_msg,
	ibcm_process_sidr_rep_msg,
	ibcm_process_lap_msg,
	ibcm_process_apr_msg
};

/* the following globals are CM tunables */
ibt_rnr_nak_time_t	ibcm_default_rnr_nak_time = IBT_RNR_NAK_655ms;

uint32_t	ibcm_max_retries = IBCM_MAX_RETRIES;
clock_t		ibcm_local_processing_time = IBCM_LOCAL_RESPONSE_TIME;
clock_t		ibcm_remote_response_time = IBCM_REMOTE_RESPONSE_TIME;
ib_time_t	ibcm_max_sidr_rep_proctime = IBCM_MAX_SIDR_PROCESS_TIME;
ib_time_t	ibcm_max_sidr_pktlife_time = IBCM_MAX_SIDR_PKT_LIFE_TIME;

ib_time_t	ibcm_max_sidr_rep_store_time = 18;
uint32_t	ibcm_wait_for_acc_cnt_timeout = 500000;	/* 500 ms */
uint32_t	ibcm_wait_for_res_cnt_timeout = 500000;	/* 500 ms */

ib_time_t	ibcm_max_ib_pkt_lt = IBCM_MAX_IB_PKT_LT;
ib_time_t	ibcm_max_ib_mad_pkt_lt = IBCM_MAX_IB_MAD_PKT_LT;

/*
 * This delay accounts for time involved in various activities as follows :
 *
 * IBMF delays for posting the MADs in non-blocking mode
 * IBMF delays for receiving the MADs and delivering to CM
 * CM delays in processing the MADs before invoking client handlers,
 * Any other delays associated with HCA driver in processing the MADs and
 * 	other subsystems that CM may invoke (ex : SA, HCA driver)
 */
uint32_t	ibcm_sw_delay	= 1000;	/* 1000us / 1ms */
uint32_t	ibcm_max_sa_retries = IBCM_MAX_SA_RETRIES + 1;

/*	approx boot time */
uint32_t	ibcm_adj_btime = 4;	/* 4 seconds */

/*
 * The information in ibcm_clpinfo is kept in wireformat and is setup at
 * init time, and used read-only after that
 */
ibcm_classportinfo_msg_t	ibcm_clpinfo;

char	*event_str[] = {
	"NEVER SEE THIS             ",
	"SESSION_ID                 ",
	"CHAN_HDL                   ",
	"LOCAL_COMID/HCA/PORT       ",
	"LOCAL_QPN                  ",
	"REMOTE_COMID/HCA           ",
	"REMOTE_QPN                 ",
	"BASE_TIME                  ",
	"INCOMING_REQ               ",
	"INCOMING_REP               ",
	"INCOMING_RTU               ",
	"INCOMING_COMEST            ",
	"INCOMING_MRA               ",
	"INCOMING_REJ               ",
	"INCOMING_LAP               ",
	"INCOMING_APR               ",
	"INCOMING_DREQ              ",
	"INCOMING_DREP              ",
	"OUTGOING_REQ               ",
	"OUTGOING_REP               ",
	"OUTGOING_RTU               ",
	"OUTGOING_LAP               ",
	"OUTGOING_APR               ",
	"OUTGOING_MRA               ",
	"OUTGOING_REJ               ",
	"OUTGOING_DREQ              ",
	"OUTGOING_DREP              ",
	"REQ_POST_COMPLETE          ",
	"REP_POST_COMPLETE          ",
	"RTU_POST_COMPLETE          ",
	"MRA_POST_COMPLETE          ",
	"REJ_POST_COMPLETE          ",
	"LAP_POST_COMPLETE          ",
	"APR_POST_COMPLETE          ",
	"DREQ_POST_COMPLETE         ",
	"DREP_POST_COMPLETE         ",
	"TIMEOUT_REP                ",
	"CALLED_REQ_RCVD_EVENT      ",
	"RET_REQ_RCVD_EVENT         ",
	"CALLED_REP_RCVD_EVENT      ",
	"RET_REP_RCVD_EVENT         ",
	"CALLED_CONN_EST_EVENT      ",
	"RET_CONN_EST_EVENT         ",
	"CALLED_CONN_FAIL_EVENT     ",
	"RET_CONN_FAIL_EVENT        ",
	"CALLED_CONN_CLOSE_EVENT    ",
	"RET_CONN_CLOSE_EVENT       ",
	"INIT_INIT                  ",
	"INIT_INIT_FAIL             ",
	"INIT_RTR                   ",
	"INIT_RTR_FAIL              ",
	"RTR_RTS                    ",
	"RTR_RTS_FAIL               ",
	"RTS_RTS                    ",
	"RTS_RTS_FAIL               ",
	"TO_ERROR                   ",
	"ERROR_FAIL                 ",
	"SET_ALT                    ",
	"SET_ALT_FAIL               ",
	"STALE_DETECT               ",
	"OUTGOING_REQ_RETRY         ",
	"OUTGOING_REP_RETRY         ",
	"OUTGOING_LAP_RETRY         ",
	"OUTGOING_MRA_RETRY         ",
	"OUTGOING_DREQ_RETRY        ",
	"NEVER SEE THIS             "
};

char	ibcm_debug_buf[IBCM_DEBUG_BUF_SIZE];

_NOTE(SCHEME_PROTECTS_DATA("used in a localized function consistently",
    ibcm_debug_buf))
_NOTE(READ_ONLY_DATA(ibcm_taskq))

_NOTE(MUTEX_PROTECTS_DATA(ibcm_timeout_list_lock, ibcm_timeout_list_flags))
_NOTE(MUTEX_PROTECTS_DATA(ibcm_timeout_list_lock, ibcm_timeout_list_hdr))
_NOTE(MUTEX_PROTECTS_DATA(ibcm_timeout_list_lock, ibcm_ud_timeout_list_hdr))

#ifdef DEBUG
int		ibcm_test_mode = 0;	/* set to 1, if running tests */
#endif


/* Module Driver Info */
static struct modlmisc ibcm_modlmisc = {
	&mod_miscops,
	"IB Communication Manager"
};

/* Module Linkage */
static struct modlinkage ibcm_modlinkage = {
	MODREV_1,
	&ibcm_modlmisc,
	NULL
};


int
_init(void)
{
	int		rval;
	ibcm_status_t	status;

	status = ibcm_init();
	if (status != IBCM_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "_init: ibcm failed %d", status);
		return (EINVAL);
	}

	rval = mod_install(&ibcm_modlinkage);
	if (rval != 0) {
		IBTF_DPRINTF_L2(cmlog, "_init: ibcm mod_install failed %d",
		    rval);
		(void) ibcm_fini();
	}

	IBTF_DPRINTF_L5(cmlog, "_init: ibcm successful");
	return (rval);

}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ibcm_modlinkage, modinfop));
}


int
_fini(void)
{
	int status;

	if (ibcm_fini() != IBCM_SUCCESS)
		return (EBUSY);

	if ((status = mod_remove(&ibcm_modlinkage)) != 0) {
		IBTF_DPRINTF_L2(cmlog, "_fini: ibcm mod_remove failed %d",
		    status);
		return (status);
	}

	IBTF_DPRINTF_L5(cmlog, "_fini: ibcm successful");

	return (status);
}

/* Initializes all global mutex and CV in cm module */
static void
ibcm_init_locks()
{

	/* Verify CM MAD sizes */
#ifdef DEBUG

	if (ibcm_test_mode > 1) {

		IBTF_DPRINTF_L1(cmlog, "REQ MAD SIZE %d",
		    sizeof (ibcm_req_msg_t));
		IBTF_DPRINTF_L1(cmlog, "REP MAD SIZE %d",
		    sizeof (ibcm_rep_msg_t));
		IBTF_DPRINTF_L1(cmlog, "RTU MAD SIZE %d",
		    sizeof (ibcm_rtu_msg_t));
		IBTF_DPRINTF_L1(cmlog, "MRA MAD SIZE %d",
		    sizeof (ibcm_mra_msg_t));
		IBTF_DPRINTF_L1(cmlog, "REJ MAD SIZE %d",
		    sizeof (ibcm_rej_msg_t));
		IBTF_DPRINTF_L1(cmlog, "LAP MAD SIZE %d",
		    sizeof (ibcm_lap_msg_t));
		IBTF_DPRINTF_L1(cmlog, "APR MAD SIZE %d",
		    sizeof (ibcm_apr_msg_t));
		IBTF_DPRINTF_L1(cmlog, "DREQ MAD SIZE %d",
		    sizeof (ibcm_dreq_msg_t));
		IBTF_DPRINTF_L1(cmlog, "DREP MAD SIZE %d",
		    sizeof (ibcm_drep_msg_t));
		IBTF_DPRINTF_L1(cmlog, "SIDR REQ MAD SIZE %d",
		    sizeof (ibcm_sidr_req_msg_t));
		IBTF_DPRINTF_L1(cmlog, "SIDR REP MAD SIZE %d",
		    sizeof (ibcm_sidr_rep_msg_t));
	}

#endif

	/* Create all global locks within cm module */
	mutex_init(&ibcm_svc_info_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ibcm_timeout_list_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ibcm_global_hca_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ibcm_sa_open_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ibcm_recv_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ibcm_sm_notice_serialize_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ibcm_qp_list_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ibcm_trace_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ibcm_trace_print_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ibcm_svc_info_cv, NULL, CV_DRIVER, NULL);
	cv_init(&ibcm_timeout_list_cv, NULL, CV_DRIVER, NULL);
	cv_init(&ibcm_timeout_thread_done_cv, NULL, CV_DRIVER, NULL);
	cv_init(&ibcm_global_hca_cv, NULL, CV_DRIVER, NULL);
	cv_init(&ibcm_sa_open_cv, NULL, CV_DRIVER, NULL);
	avl_create(&ibcm_svc_avl_tree, ibcm_svc_compare,
	    sizeof (ibcm_svc_info_t),
	    offsetof(struct ibcm_svc_info_s, svc_link));

	IBTF_DPRINTF_L5(cmlog, "ibcm_init_locks: done");
}

/* Destroys all global mutex and CV in cm module */
static void
ibcm_fini_locks()
{
	/* Destroy all global locks within cm module */
	mutex_destroy(&ibcm_svc_info_lock);
	mutex_destroy(&ibcm_timeout_list_lock);
	mutex_destroy(&ibcm_global_hca_lock);
	mutex_destroy(&ibcm_sa_open_lock);
	mutex_destroy(&ibcm_recv_mutex);
	mutex_destroy(&ibcm_sm_notice_serialize_lock);
	mutex_destroy(&ibcm_qp_list_lock);
	mutex_destroy(&ibcm_trace_mutex);
	mutex_destroy(&ibcm_trace_print_mutex);
	cv_destroy(&ibcm_svc_info_cv);
	cv_destroy(&ibcm_timeout_list_cv);
	cv_destroy(&ibcm_timeout_thread_done_cv);
	cv_destroy(&ibcm_global_hca_cv);
	cv_destroy(&ibcm_sa_open_cv);
	avl_destroy(&ibcm_svc_avl_tree);

	IBTF_DPRINTF_L5(cmlog, "ibcm_fini_locks: done");
}


/* Initialize CM's classport info */
static void
ibcm_init_classportinfo()
{
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibcm_clpinfo));

	ibcm_clpinfo.BaseVersion = IBCM_MAD_BASE_VERSION;
	ibcm_clpinfo.ClassVersion = IBCM_MAD_CLASS_VERSION;

	/* For now, CM supports same capabilities at all ports */
	ibcm_clpinfo.CapabilityMask =
	    h2b16(IBCM_CPINFO_CAP_RC | IBCM_CPINFO_CAP_SIDR);

	/* Bits 0-7 are all 0 for Communication Mgmt Class */

	/* For now, CM has the same respvalue at all ports */
	ibcm_clpinfo.RespTimeValue_plus =
	    h2b32(ibt_usec2ib(ibcm_local_processing_time) & 0x1f);

	/* For now, redirect fields are set to 0 */
	/* Trap fields are not applicable to CM, hence set to 0 */

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibcm_clpinfo));
	IBTF_DPRINTF_L5(cmlog, "ibcm_init_classportinfo: done");
}

/*
 * ibcm_init():
 * 	- call ibt_attach()
 * 	- create AVL trees
 *	- Attach HCA handlers that are already present before
 *	CM got loaded.
 *
 * Arguments:	NONE
 *
 * Return values:
 *	IBCM_SUCCESS - success
 */
static ibcm_status_t
ibcm_init(void)
{
	ibt_status_t	status;
	kthread_t	*t;

	IBTF_DPRINTF_L3(cmlog, "ibcm_init:");

	ibcm_init_classportinfo();

	if (ibcm_init_ids() != IBCM_SUCCESS) {
		IBTF_DPRINTF_L1(cmlog, "ibcm_init: "
		    "fatal error: vmem_create() failed");
		return (IBCM_FAILURE);
	}
	ibcm_init_locks();

	if (ibcm_ar_init() != IBCM_SUCCESS) {
		IBTF_DPRINTF_L1(cmlog, "ibcm_init: "
		    "fatal error: ibcm_ar_init() failed");
		ibcm_fini_ids();
		ibcm_fini_locks();
		return (IBCM_FAILURE);
	}
	ibcm_rc_flow_control_init();

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibcm_taskq))
	ibcm_taskq = system_taskq;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibcm_taskq))

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibcm_timeout_list_flags))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibcm_timeout_thread_did))

	/* Start the timeout list processing thread */
	ibcm_timeout_list_flags = 0;
	t = thread_create(NULL, 0, ibcm_process_tlist, 0, 0, &p0, TS_RUN,
	    ibcm_timeout_thread_pri);
	ibcm_timeout_thread_did = t->t_did;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibcm_timeout_list_flags))
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibcm_timeout_thread_did))

	/*
	 * NOTE : if ibt_attach is done after ibcm_init_hcas, then some
	 * HCA DR events may be lost. CM could call re-init hca list
	 * again, but it is more complicated. Some HCA's DR's lost may
	 * be HCA detach, which makes hca list re-syncing and locking more
	 * complex
	 */
	status = ibt_attach(&ibcm_ibt_modinfo, NULL, NULL, &ibcm_ibt_handle);
	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_init(): ibt_attach failed %d",
		    status);
		(void) ibcm_ar_fini();
		ibcm_stop_timeout_thread();
		ibcm_fini_ids();
		ibcm_fini_locks();
		ibcm_rc_flow_control_fini();
		return (IBCM_FAILURE);
	}

	/* Block all HCA attach/detach asyncs */
	mutex_enter(&ibcm_global_hca_lock);

	ibcm_init_hcas();
	ibcm_finit_state = IBCM_FINIT_IDLE;

	ibcm_path_cache_init();

	/* Unblock any waiting HCA DR asyncs in CM */
	mutex_exit(&ibcm_global_hca_lock);

	IBTF_DPRINTF_L4(cmlog, "ibcm_init: done");
	return (IBCM_SUCCESS);
}

/* Allocates and initializes the "per hca" global data in CM */
static void
ibcm_init_hcas()
{
	uint_t	num_hcas = 0;
	ib_guid_t *guid_array;
	int i;

	IBTF_DPRINTF_L5(cmlog, "ibcm_init_hcas:");

	/* Get the number of HCAs */
	num_hcas = ibt_get_hca_list(&guid_array);
	IBTF_DPRINTF_L4(cmlog, "ibcm_init_hcas: ibt_get_hca_list() "
	    "returned %d hcas", num_hcas);

	ASSERT(MUTEX_HELD(&ibcm_global_hca_lock));

	for (i = 0; i < num_hcas; i++)
		ibcm_hca_attach(guid_array[i]);

	if (num_hcas)
		ibt_free_hca_list(guid_array, num_hcas);

	IBTF_DPRINTF_L5(cmlog, "ibcm_init_hcas: done");
}


/*
 * ibcm_fini():
 * 	- Deregister w/ ibt
 * 	- Cleanup IBCM HCA listp
 * 	- Destroy mutexes
 *
 * Arguments:	NONE
 *
 * Return values:
 *	IBCM_SUCCESS - success
 */
static ibcm_status_t
ibcm_fini(void)
{
	ibt_status_t	status;

	IBTF_DPRINTF_L3(cmlog, "ibcm_fini:");

	/*
	 * CM assumes that the all general clients got rid of all the
	 * established connections and service registrations, completed all
	 * pending SIDR operations before a call to ibcm_fini()
	 */

	if (ibcm_ar_fini() != IBCM_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_fini: ibcm_ar_fini failed");
		return (IBCM_FAILURE);
	}

	/* cleanup the svcinfo list */
	mutex_enter(&ibcm_svc_info_lock);
	if (avl_first(&ibcm_svc_avl_tree) != NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_fini: "
		    "ibcm_svc_avl_tree is not empty");
		mutex_exit(&ibcm_svc_info_lock);
		return (IBCM_FAILURE);
	}
	mutex_exit(&ibcm_svc_info_lock);

	/* disables any new hca attach/detaches */
	mutex_enter(&ibcm_global_hca_lock);

	ibcm_finit_state = IBCM_FINIT_BUSY;

	if (ibcm_fini_hcas() != IBCM_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_fini: "
		    "some hca's still have client resources");

		/* First, re-initialize the hcas */
		ibcm_init_hcas();
		/* and then enable the HCA asyncs */
		ibcm_finit_state = IBCM_FINIT_IDLE;
		mutex_exit(&ibcm_global_hca_lock);
		if (ibcm_ar_init() != IBCM_SUCCESS) {
			IBTF_DPRINTF_L1(cmlog, "ibcm_fini:ibcm_ar_init failed");
		}
		return (IBCM_FAILURE);
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibcm_timeout_list_hdr))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibcm_ud_timeout_list_hdr))

	ASSERT(ibcm_timeout_list_hdr == NULL);
	ASSERT(ibcm_ud_timeout_list_hdr == NULL);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibcm_timeout_list_hdr))
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibcm_ud_timeout_list_hdr))

	/* Release any pending asyncs on ibcm_global_hca_lock */
	ibcm_finit_state = IBCM_FINIT_SUCCESS;
	mutex_exit(&ibcm_global_hca_lock);

	ibcm_stop_timeout_thread();

	/*
	 * Detach from IBTL. Waits until all pending asyncs are complete.
	 * Above cv_broadcast wakes up any waiting hca attach/detach asyncs
	 */
	status = ibt_detach(ibcm_ibt_handle);

	/* if detach fails, CM didn't free up some resources, so assert */
	if (status != IBT_SUCCESS)
		IBTF_DPRINTF_L1(cmlog, "ibcm_fini: ibt_detach failed %d",
		    status);

	ibcm_rc_flow_control_fini();

	ibcm_path_cache_fini();

	ibcm_fini_ids();
	ibcm_fini_locks();
	IBTF_DPRINTF_L3(cmlog, "ibcm_fini: done");
	return (IBCM_SUCCESS);
}

/* This routine exit's the ibcm timeout thread  */
static void
ibcm_stop_timeout_thread()
{
	mutex_enter(&ibcm_timeout_list_lock);

	/* Stop the timeout list processing thread */
	ibcm_timeout_list_flags =
	    ibcm_timeout_list_flags | IBCM_TIMEOUT_THREAD_EXIT;

	/* Wake up, if the timeout thread is on a cv_wait */
	cv_signal(&ibcm_timeout_list_cv);

	mutex_exit(&ibcm_timeout_list_lock);
	thread_join(ibcm_timeout_thread_did);

	IBTF_DPRINTF_L5(cmlog, "ibcm_stop_timeout_thread: done");
}


/* Attempts to release all the hca's associated with CM */
static ibcm_status_t
ibcm_fini_hcas()
{
	ibcm_hca_info_t *hcap, *next;

	IBTF_DPRINTF_L4(cmlog, "ibcm_fini_hcas:");

	ASSERT(MUTEX_HELD(&ibcm_global_hca_lock));

	hcap = ibcm_hca_listp;
	while (hcap != NULL) {
		next = hcap->hca_next;
		if (ibcm_hca_detach(hcap) != IBCM_SUCCESS) {
			ibcm_hca_listp = hcap;
			return (IBCM_FAILURE);
		}
		hcap = next;
	}

	IBTF_DPRINTF_L4(cmlog, "ibcm_fini_hcas: SUCCEEDED");
	return (IBCM_SUCCESS);
}


/*
 * ibcm_hca_attach():
 *	Called as an asynchronous event to notify CM of an attach of HCA.
 *	Here ibcm_hca_info_t is initialized and all fields are
 *	filled in along with SA Access handles and IBMA handles.
 *	Also called from ibcm_init to initialize ibcm_hca_info_t's for each
 *	hca's
 *
 * Arguments: (WILL CHANGE BASED ON ASYNC EVENT CODE)
 *	hca_guid	- HCA's guid
 *
 * Return values: NONE
 */
static void
ibcm_hca_attach(ib_guid_t hcaguid)
{
	int			i;
	ibt_status_t		status;
	uint_t			nports = 0;
	ibcm_hca_info_t		*hcap;
	ibt_hca_attr_t		hca_attrs;

	IBTF_DPRINTF_L3(cmlog, "ibcm_hca_attach: guid = 0x%llX", hcaguid);

	ASSERT(MUTEX_HELD(&ibcm_global_hca_lock));

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*hcap))

	status = ibt_query_hca_byguid(hcaguid, &hca_attrs);
	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_hca_attach: "
		    "ibt_query_hca_byguid failed = %d", status);
		return;
	}
	nports = hca_attrs.hca_nports;

	IBTF_DPRINTF_L4(cmlog, "ibcm_hca_attach: num ports = %x", nports);

	if ((hcap = ibcm_add_hca_entry(hcaguid, nports)) == NULL)
		return;

	hcap->hca_guid = hcaguid;	/* Set GUID */
	hcap->hca_num_ports = nports;	/* Set number of ports */

	if (ibcm_init_hca_ids(hcap) != IBCM_SUCCESS) {
		ibcm_delete_hca_entry(hcap);
		return;
	}

	/* Store the static hca attribute data */
	hcap->hca_caps = hca_attrs.hca_flags;
	hcap->hca_vendor_id = hca_attrs.hca_vendor_id;
	hcap->hca_device_id = hca_attrs.hca_device_id;
	hcap->hca_ack_delay = hca_attrs.hca_local_ack_delay;
	hcap->hca_max_rdma_in_qp = hca_attrs.hca_max_rdma_in_qp;
	hcap->hca_max_rdma_out_qp = hca_attrs.hca_max_rdma_out_qp;

	/* loop thru nports and initialize IBMF handles */
	for (i = 0; i < hcap->hca_num_ports; i++) {
		status = ibt_get_port_state_byguid(hcaguid, i + 1, NULL, NULL);
		if (status != IBT_SUCCESS) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_hca_attach: "
			    "port_num %d state DOWN", i + 1);
		}

		hcap->hca_port_info[i].port_hcap = hcap;
		hcap->hca_port_info[i].port_num = i+1;

		if (ibcm_hca_init_port(hcap, i) != IBT_SUCCESS)
			IBTF_DPRINTF_L2(cmlog, "ibcm_hca_attach: "
			    "ibcm_hca_init_port failed %d port_num %d",
			    status, i+1);
	}

	/* create the "active" CM AVL tree */
	avl_create(&hcap->hca_active_tree, ibcm_active_node_compare,
	    sizeof (ibcm_state_data_t),
	    offsetof(struct ibcm_state_data_s, avl_active_link));

	/* create the "passive" CM AVL tree */
	avl_create(&hcap->hca_passive_tree, ibcm_passive_node_compare,
	    sizeof (ibcm_state_data_t),
	    offsetof(struct ibcm_state_data_s, avl_passive_link));

	/* create the "passive comid" CM AVL tree */
	avl_create(&hcap->hca_passive_comid_tree,
	    ibcm_passive_comid_node_compare,
	    sizeof (ibcm_state_data_t),
	    offsetof(struct ibcm_state_data_s, avl_passive_comid_link));

	/*
	 * Mark the state of the HCA to "attach" only at the end
	 * Now CM starts accepting incoming MADs and client API calls
	 */
	hcap->hca_state = IBCM_HCA_ACTIVE;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*hcap))

	IBTF_DPRINTF_L3(cmlog, "ibcm_hca_attach: ATTACH Done");
}

/*
 * ibcm_hca_detach():
 *	Called as an asynchronous event to notify CM of a detach of HCA.
 *	Here ibcm_hca_info_t is freed up and all fields that
 *	were initialized earlier are cleaned up
 *
 * Arguments: (WILL CHANGE BASED ON ASYNC EVENT CODE)
 *	hca_guid    - HCA's guid
 *
 * Return values:
 *	IBCM_SUCCESS	- able to detach HCA
 *	IBCM_FAILURE	- failed to detach HCA
 */
static ibcm_status_t
ibcm_hca_detach(ibcm_hca_info_t *hcap)
{
	int		port_index, i;
	ibcm_status_t	status = IBCM_SUCCESS;
	clock_t		absolute_time;

	IBTF_DPRINTF_L3(cmlog, "ibcm_hca_detach: hcap = 0x%p guid = 0x%llX",
	    hcap, hcap->hca_guid);

	ASSERT(MUTEX_HELD(&ibcm_global_hca_lock));

	/*
	 * Declare hca is going away to all CM clients. Wait until the
	 * access count becomes zero.
	 */
	hcap->hca_state = IBCM_HCA_NOT_ACTIVE;

	/* wait on response CV to 500mS */
	absolute_time = ddi_get_lbolt() +
	    drv_usectohz(ibcm_wait_for_acc_cnt_timeout);

	while (hcap->hca_acc_cnt > 0)
		if (cv_timedwait(&ibcm_global_hca_cv, &ibcm_global_hca_lock,
		    absolute_time) == -1)
			break;

	if (hcap->hca_acc_cnt != 0) {
		/* We got a timeout */
#ifdef DEBUG
		if (ibcm_test_mode > 0)
			IBTF_DPRINTF_L1(cmlog, "ibcm_hca_detach: Unexpected "
			    "abort due to timeout on acc_cnt %u",
			    hcap->hca_acc_cnt);
		else
#endif
			IBTF_DPRINTF_L2(cmlog, "ibcm_hca_detach: Aborting due"
			    " to timeout on acc_cnt %u", hcap->hca_acc_cnt);
		hcap->hca_state = IBCM_HCA_ACTIVE;
		return (IBCM_FAILURE);
	}

	/*
	 * First make sure, there are no active users of ibma handles,
	 * and then de-register handles.
	 */

	/* make sure that there are no "Service"s registered w/ this HCA. */
	if (hcap->hca_svc_cnt != 0) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_hca_detach: "
		    "Active services still there %d", hcap->hca_svc_cnt);
		hcap->hca_state = IBCM_HCA_ACTIVE;
		return (IBCM_FAILURE);
	}

	if (ibcm_check_sidr_clean(hcap) != IBCM_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_hca_detach:"
		    "There are active SIDR operations");
		hcap->hca_state = IBCM_HCA_ACTIVE;
		return (IBCM_FAILURE);
	}

	if (ibcm_check_avl_clean(hcap) != IBCM_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_hca_detach: "
		    "There are active RC connections");
		hcap->hca_state = IBCM_HCA_ACTIVE;
		return (IBCM_FAILURE);
	}

	/*
	 * Now, wait until all rc and sidr stateps go away
	 * All these stateps must be short lived ones, waiting to be cleaned
	 * up after some timeout value, based on the current state.
	 */
	IBTF_DPRINTF_L5(cmlog, "ibcm_hca_detach:hca_guid = 0x%llX res_cnt = %d",
	    hcap->hca_guid, hcap->hca_res_cnt);

	/* wait on response CV to 500mS */
	absolute_time = ddi_get_lbolt() +
	    drv_usectohz(ibcm_wait_for_res_cnt_timeout);

	while (hcap->hca_res_cnt > 0)
		if (cv_timedwait(&ibcm_global_hca_cv, &ibcm_global_hca_lock,
		    absolute_time) == -1)
			break;

	if (hcap->hca_res_cnt != 0) {
		/* We got a timeout waiting for hca_res_cnt to become 0 */
#ifdef DEBUG
		if (ibcm_test_mode > 0)
			IBTF_DPRINTF_L1(cmlog, "ibcm_hca_detach: Unexpected "
			    "abort due to timeout on res_cnt %d",
			    hcap->hca_res_cnt);
		else
#endif
			IBTF_DPRINTF_L2(cmlog, "ibcm_hca_detach: Aborting due"
			    " to timeout on res_cnt %d", hcap->hca_res_cnt);
		hcap->hca_state = IBCM_HCA_ACTIVE;
		return (IBCM_FAILURE);
	}

	/* Re-assert the while loop step above */
	ASSERT(hcap->hca_sidr_list == NULL);
	avl_destroy(&hcap->hca_active_tree);
	avl_destroy(&hcap->hca_passive_tree);
	avl_destroy(&hcap->hca_passive_comid_tree);

	/*
	 * Unregister all ports from IBMA
	 * If there is a failure, re-initialize any free'd ibma handles. This
	 * is required to receive the incoming mads
	 */
	status = IBCM_SUCCESS;
	for (port_index = 0; port_index < hcap->hca_num_ports; port_index++) {
		if ((status = ibcm_hca_fini_port(hcap, port_index)) !=
		    IBCM_SUCCESS) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_hca_detach: "
			    "Failed to free IBMA Handle for port_num %d",
			    port_index + 1);
			break;
		}
	}

	/* If detach fails, re-initialize ibma handles for incoming mads */
	if (status != IBCM_SUCCESS)  {
		for (i = 0; i < port_index; i++) {
			if (ibcm_hca_init_port(hcap, i) != IBT_SUCCESS)
				IBTF_DPRINTF_L2(cmlog, "ibcm_hca_detach: "
				    "Failed to re-allocate IBMA Handles for"
				    " port_num %d", port_index + 1);
		}
		hcap->hca_state = IBCM_HCA_ACTIVE;
		return (IBCM_FAILURE);
	}

	ibcm_fini_hca_ids(hcap);
	ibcm_delete_hca_entry(hcap);

	IBTF_DPRINTF_L3(cmlog, "ibcm_hca_detach: DETACH succeeded");
	return (IBCM_SUCCESS);
}

/* Checks, if there are any active sidr state entries in the specified hca */
static ibcm_status_t
ibcm_check_sidr_clean(ibcm_hca_info_t *hcap)
{
	ibcm_ud_state_data_t	*usp;
	uint32_t		transient_cnt = 0;

	IBTF_DPRINTF_L5(cmlog, "ibcm_check_sidr_clean:");

	rw_enter(&hcap->hca_sidr_list_lock, RW_WRITER);
	usp = hcap->hca_sidr_list;	/* Point to the list */
	while (usp != NULL) {
		mutex_enter(&usp->ud_state_mutex);
		if ((usp->ud_state != IBCM_STATE_SIDR_REP_SENT) &&
		    (usp->ud_state != IBCM_STATE_TIMED_OUT) &&
		    (usp->ud_state != IBCM_STATE_DELETE)) {

			IBTF_DPRINTF_L3(cmlog, "ibcm_check_sidr_clean:"
			    "usp = %p not in transient state = %d", usp,
			    usp->ud_state);

			mutex_exit(&usp->ud_state_mutex);
			rw_exit(&hcap->hca_sidr_list_lock);
			return (IBCM_FAILURE);
		} else {
			mutex_exit(&usp->ud_state_mutex);
			++transient_cnt;
		}

		usp = usp->ud_nextp;
	}
	rw_exit(&hcap->hca_sidr_list_lock);

	IBTF_DPRINTF_L4(cmlog, "ibcm_check_sidr_clean: transient_cnt %d",
	    transient_cnt);

	return (IBCM_SUCCESS);
}

/* Checks, if there are any active rc state entries, in the specified hca */
static ibcm_status_t
ibcm_check_avl_clean(ibcm_hca_info_t *hcap)

{
	ibcm_state_data_t	*sp;
	avl_tree_t		*avl_tree;
	uint32_t		transient_cnt = 0;

	IBTF_DPRINTF_L5(cmlog, "ibcm_check_avl_clean:");
	/*
	 * Both the trees ie., active and passive must reference to all
	 * statep's, so let's use one
	 */
	avl_tree = &hcap->hca_active_tree;

	rw_enter(&hcap->hca_state_rwlock, RW_WRITER);

	for (sp = avl_first(avl_tree); sp != NULL;
	    sp = avl_walk(avl_tree, sp, AVL_AFTER)) {
		mutex_enter(&sp->state_mutex);
		if ((sp->state != IBCM_STATE_TIMEWAIT) &&
		    (sp->state != IBCM_STATE_REJ_SENT) &&
		    (sp->state != IBCM_STATE_DELETE)) {
			IBTF_DPRINTF_L3(cmlog, "ibcm_check_avl_clean: "
			    "sp = %p not in transient state = %d", sp,
			    sp->state);
			mutex_exit(&sp->state_mutex);
			rw_exit(&hcap->hca_state_rwlock);
			return (IBCM_FAILURE);
		} else {
			mutex_exit(&sp->state_mutex);
			++transient_cnt;
		}
	}

	rw_exit(&hcap->hca_state_rwlock);

	IBTF_DPRINTF_L4(cmlog, "ibcm_check_avl_clean: transient_cnt %d",
	    transient_cnt);

	return (IBCM_SUCCESS);
}

/* Adds a new entry into CM's global hca list, if hca_guid is not there yet */
static ibcm_hca_info_t *
ibcm_add_hca_entry(ib_guid_t hcaguid, uint_t nports)
{
	ibcm_hca_info_t	*hcap;

	IBTF_DPRINTF_L5(cmlog, "ibcm_add_hca_entry: guid = 0x%llX",
	    hcaguid);

	ASSERT(MUTEX_HELD(&ibcm_global_hca_lock));

	/*
	 * Check if this hca_guid already in the list
	 * If yes, then ignore this and return NULL
	 */

	hcap = ibcm_hca_listp;

	/* search for this HCA */
	while (hcap != NULL) {
		if (hcap->hca_guid == hcaguid) {
			/* already exists */
			IBTF_DPRINTF_L2(cmlog, "ibcm_add_hca_entry: "
			    "hcap %p guid 0x%llX, entry already exists !!",
			    hcap, hcap->hca_guid);
			return (NULL);
		}
		hcap = hcap->hca_next;
	}

	/* Allocate storage for the new HCA entry found */
	hcap = kmem_zalloc(sizeof (ibcm_hca_info_t) +
	    (nports - 1) * sizeof (ibcm_port_info_t), KM_SLEEP);

	/* initialize RW lock */
	rw_init(&hcap->hca_state_rwlock, NULL, RW_DRIVER, NULL);
	/* initialize SIDR list lock */
	rw_init(&hcap->hca_sidr_list_lock, NULL, RW_DRIVER, NULL);
	/* Insert "hcap" into the global HCA list maintained by CM */
	hcap->hca_next = ibcm_hca_listp;
	ibcm_hca_listp = hcap;

	IBTF_DPRINTF_L5(cmlog, "ibcm_add_hca_entry: done hcap = 0x%p", hcap);

	return (hcap);

}

/* deletes the given ibcm_hca_info_t from CM's global hca list */
void
ibcm_delete_hca_entry(ibcm_hca_info_t *hcap)
{
	ibcm_hca_info_t	*headp, *prevp = NULL;

	/* ibcm_hca_global_lock is held */
	IBTF_DPRINTF_L5(cmlog, "ibcm_delete_hca_entry: guid = 0x%llX "
	    "hcap = 0x%p", hcap->hca_guid, hcap);

	ASSERT(MUTEX_HELD(&ibcm_global_hca_lock));

	headp = ibcm_hca_listp;
	while (headp != NULL) {
		if (headp == hcap) {
			IBTF_DPRINTF_L3(cmlog, "ibcm_delete_hca_entry: "
			    "deleting hcap %p hcaguid %llX", hcap,
			    hcap->hca_guid);
			if (prevp) {
				prevp->hca_next = headp->hca_next;
			} else {
				prevp = headp->hca_next;
				ibcm_hca_listp = prevp;
			}
			rw_destroy(&hcap->hca_state_rwlock);
			rw_destroy(&hcap->hca_sidr_list_lock);
			kmem_free(hcap, sizeof (ibcm_hca_info_t) +
			    (hcap->hca_num_ports - 1) *
			    sizeof (ibcm_port_info_t));
			return;
		}

		prevp = headp;
		headp = headp->hca_next;
	}
}

/*
 * ibcm_find_hca_entry:
 *	Given a HCA's GUID find out ibcm_hca_info_t entry for that HCA
 *	This entry can be then used to access AVL tree/SIDR list etc.
 *	If entry exists and in HCA ATTACH state, then hca's ref cnt is
 *	incremented and entry returned. Else NULL returned.
 *
 *	All functions that use ibcm_find_hca_entry and get a non-NULL
 *	return values must call ibcm_dec_hca_acc_cnt to decrement the
 *	respective hca ref cnt. There shouldn't be any usage of
 *	ibcm_hca_info_t * returned from ibcm_find_hca_entry,
 *	after decrementing the hca_acc_cnt
 *
 * INPUTS:
 *	hca_guid	- HCA's guid
 *
 * RETURN VALUE:
 *	hcap		- if a match is found, else NULL
 */
ibcm_hca_info_t *
ibcm_find_hca_entry(ib_guid_t hca_guid)
{
	ibcm_hca_info_t *hcap;

	IBTF_DPRINTF_L5(cmlog, "ibcm_find_hca_entry: guid = 0x%llX", hca_guid);

	mutex_enter(&ibcm_global_hca_lock);

	hcap = ibcm_hca_listp;
	/* search for this HCA */
	while (hcap != NULL) {
		if (hcap->hca_guid == hca_guid)
			break;
		hcap = hcap->hca_next;
	}

	/* if no hcap for the hca_guid, return NULL */
	if (hcap == NULL) {
		mutex_exit(&ibcm_global_hca_lock);
		return (NULL);
	}

	/* return hcap, only if it valid to use */
	if (hcap->hca_state == IBCM_HCA_ACTIVE) {
		++(hcap->hca_acc_cnt);

		IBTF_DPRINTF_L5(cmlog, "ibcm_find_hca_entry: "
		    "found hcap = 0x%p hca_acc_cnt %u", hcap,
		    hcap->hca_acc_cnt);

		mutex_exit(&ibcm_global_hca_lock);
		return (hcap);
	} else {
		mutex_exit(&ibcm_global_hca_lock);

		IBTF_DPRINTF_L2(cmlog, "ibcm_find_hca_entry: "
		    "found hcap = 0x%p not in active state", hcap);
		return (NULL);
	}
}

/*
 * Searches for ibcm_hca_info_t entry based on hca_guid, but doesn't increment
 * the hca's reference count. This function is used, where the calling context
 * is attempting to delete hcap itself and hence acc_cnt cannot be incremented
 * OR assumes that valid hcap must be available in ibcm's global hca list.
 */
ibcm_hca_info_t *
ibcm_find_hcap_entry(ib_guid_t hca_guid)
{
	ibcm_hca_info_t *hcap;

	IBTF_DPRINTF_L5(cmlog, "ibcm_find_hcap_entry: guid = 0x%llX", hca_guid);

	ASSERT(MUTEX_HELD(&ibcm_global_hca_lock));

	hcap = ibcm_hca_listp;
	/* search for this HCA */
	while (hcap != NULL) {
		if (hcap->hca_guid == hca_guid)
			break;
		hcap = hcap->hca_next;
	}

	if (hcap == NULL)
		IBTF_DPRINTF_L2(cmlog, "ibcm_find_hcap_entry: No hcap found for"
		    " hca_guid 0x%llX", hca_guid);
	else
		IBTF_DPRINTF_L5(cmlog, "ibcm_find_hcap_entry: hcap found for"
		    " hca_guid 0x%llX", hca_guid);

	return (hcap);
}

/* increment the hca's temporary reference count */
ibcm_status_t
ibcm_inc_hca_acc_cnt(ibcm_hca_info_t *hcap)
{
	mutex_enter(&ibcm_global_hca_lock);
	if (hcap->hca_state == IBCM_HCA_ACTIVE) {
		++(hcap->hca_acc_cnt);
		IBTF_DPRINTF_L5(cmlog, "ibcm_inc_hca_acc_cnt: "
		    "hcap = 0x%p  acc_cnt = %d ", hcap, hcap->hca_acc_cnt);
		mutex_exit(&ibcm_global_hca_lock);
		return (IBCM_SUCCESS);
	} else {
		IBTF_DPRINTF_L2(cmlog, "ibcm_inc_hca_acc_cnt: "
		    "hcap INACTIVE 0x%p  acc_cnt = %d ", hcap,
		    hcap->hca_acc_cnt);
		mutex_exit(&ibcm_global_hca_lock);
		return (IBCM_FAILURE);
	}
}

/* decrement the hca's ref count, and wake up any waiting threads */
void
ibcm_dec_hca_acc_cnt(ibcm_hca_info_t *hcap)
{
	mutex_enter(&ibcm_global_hca_lock);
	ASSERT(hcap->hca_acc_cnt > 0);
	--(hcap->hca_acc_cnt);
	IBTF_DPRINTF_L5(cmlog, "ibcm_dec_hca_acc_cnt: hcap = 0x%p "
	    "acc_cnt = %d", hcap, hcap->hca_acc_cnt);
	if ((hcap->hca_state == IBCM_HCA_NOT_ACTIVE) &&
	    (hcap->hca_acc_cnt == 0)) {
		IBTF_DPRINTF_L3(cmlog, "ibcm_dec_hca_acc_cnt: "
		    "cv_broadcast for hcap = 0x%p", hcap);
		cv_broadcast(&ibcm_global_hca_cv);
	}
	mutex_exit(&ibcm_global_hca_lock);
}

/* increment the hca's resource count */
void
ibcm_inc_hca_res_cnt(ibcm_hca_info_t *hcap)

{
	mutex_enter(&ibcm_global_hca_lock);
	++(hcap->hca_res_cnt);
	IBTF_DPRINTF_L5(cmlog, "ibcm_inc_hca_res_cnt: hcap = 0x%p "
	    "ref_cnt = %d", hcap, hcap->hca_res_cnt);
	mutex_exit(&ibcm_global_hca_lock);
}

/* decrement the hca's resource count, and wake up any waiting threads */
void
ibcm_dec_hca_res_cnt(ibcm_hca_info_t *hcap)
{
	mutex_enter(&ibcm_global_hca_lock);
	ASSERT(hcap->hca_res_cnt > 0);
	--(hcap->hca_res_cnt);
	IBTF_DPRINTF_L5(cmlog, "ibcm_dec_hca_res_cnt: hcap = 0x%p "
	    "ref_cnt = %d", hcap, hcap->hca_res_cnt);
	if ((hcap->hca_state == IBCM_HCA_NOT_ACTIVE) &&
	    (hcap->hca_res_cnt == 0)) {
		IBTF_DPRINTF_L3(cmlog, "ibcm_dec_hca_res_cnt: "
		    "cv_broadcast for hcap = 0x%p", hcap);
		cv_broadcast(&ibcm_global_hca_cv);
	}
	mutex_exit(&ibcm_global_hca_lock);
}

/* increment the hca's service count */
void
ibcm_inc_hca_svc_cnt(ibcm_hca_info_t *hcap)

{
	mutex_enter(&ibcm_global_hca_lock);
	++(hcap->hca_svc_cnt);
	IBTF_DPRINTF_L5(cmlog, "ibcm_inc_hca_svc_cnt: hcap = 0x%p "
	    "svc_cnt = %d", hcap, hcap->hca_svc_cnt);
	mutex_exit(&ibcm_global_hca_lock);
}

/* decrement the hca's service count */
void
ibcm_dec_hca_svc_cnt(ibcm_hca_info_t *hcap)
{
	mutex_enter(&ibcm_global_hca_lock);
	ASSERT(hcap->hca_svc_cnt > 0);
	--(hcap->hca_svc_cnt);
	IBTF_DPRINTF_L5(cmlog, "ibcm_dec_hca_svc_cnt: hcap = 0x%p "
	    "svc_cnt = %d", hcap, hcap->hca_svc_cnt);
	mutex_exit(&ibcm_global_hca_lock);
}

/*
 * The following code manages three classes of requests that CM makes to
 * the fabric.  Those three classes are SA_ACCESS, REQ/REP/RTU, and DREQ/DREP.
 * The main issue is that the fabric can become very busy, and the CM
 * protocols rely on responses being made based on a predefined timeout
 * value.  By managing how many simultaneous sessions are allowed, there
 * is observed extremely high reliability of CM protocol succeeding when
 * it should.
 *
 * SA_ACCESS and DREQ/DREP are managed at the thread level, whereby the
 * thread blocks until there are less than some number of threads doing
 * similar requests.
 *
 * REQ/REP/RTU requests beyond a given limit are added to a list,
 * allowing the thread to return immediately to its caller in the
 * case where the "mode" is IBT_NONBLOCKING.  This is the mode used
 * by uDAPL and seems to be an important feature/behavior.
 */

static int
ibcm_ok_to_start(struct ibcm_open_s *openp)
{
	return (openp->sends < openp->sends_hiwat &&
	    openp->in_progress < openp->in_progress_max);
}

void
ibcm_open_done(ibcm_state_data_t *statep)
{
	int run;
	ibcm_state_data_t **linkp, *tmp;

	ASSERT(MUTEX_HELD(&statep->state_mutex));
	if (statep->open_flow == 1) {
		statep->open_flow = 0;
		mutex_enter(&ibcm_open.mutex);
		if (statep->open_link == NULL) {
			ibcm_open.in_progress--;
			run = ibcm_ok_to_start(&ibcm_open);
		} else {
			ibcm_open.queued--;
			linkp = &ibcm_open.head.open_link;
			while (*linkp != statep)
				linkp = &((*linkp)->open_link);
			*linkp = statep->open_link;
			statep->open_link = NULL;
			/*
			 * If we remove what tail pointed to, we need
			 * to reassign tail (it is never NULL).
			 * tail points to head for the empty list.
			 */
			if (ibcm_open.tail == statep) {
				tmp = &ibcm_open.head;
				while (tmp->open_link != &ibcm_open.head)
					tmp = tmp->open_link;
				ibcm_open.tail = tmp;
			}
			run = 0;
		}
		mutex_exit(&ibcm_open.mutex);
		if (run)
			ibcm_run_tlist_thread();
	}
}

/* dtrace */
void
ibcm_open_wait(hrtime_t delta)
{
	if (delta > 1000000)
		IBTF_DPRINTF_L2(cmlog, "ibcm_open_wait: flow more %lld", delta);
}

void
ibcm_open_start(ibcm_state_data_t *statep)
{
	ibcm_insert_trace(statep, IBCM_TRACE_OUTGOING_REQ);

	mutex_enter(&statep->state_mutex);
	ibcm_open_wait(gethrtime() - statep->post_time);
	mutex_exit(&statep->state_mutex);

	ibcm_post_rc_mad(statep, statep->stored_msg, ibcm_post_req_complete,
	    statep);

	mutex_enter(&statep->state_mutex);
	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}

void
ibcm_open_enqueue(ibcm_state_data_t *statep)
{
	int run;

	mutex_enter(&statep->state_mutex);
	statep->post_time = gethrtime();
	mutex_exit(&statep->state_mutex);
	mutex_enter(&ibcm_open.mutex);
	if (ibcm_open.queued == 0 && ibcm_ok_to_start(&ibcm_open)) {
		ibcm_open.in_progress++;
		mutex_exit(&ibcm_open.mutex);
		ibcm_open_start(statep);
	} else {
		ibcm_open.queued++;
		statep->open_link = &ibcm_open.head;
		ibcm_open.tail->open_link = statep;
		ibcm_open.tail = statep;
		run = ibcm_ok_to_start(&ibcm_open);
		mutex_exit(&ibcm_open.mutex);
		if (run)
			ibcm_run_tlist_thread();
	}
}

ibcm_state_data_t *
ibcm_open_dequeue(void)
{
	ibcm_state_data_t *statep;

	ASSERT(MUTEX_HELD(&ibcm_open.mutex));
	ibcm_open.queued--;
	ibcm_open.in_progress++;
	statep = ibcm_open.head.open_link;
	ibcm_open.head.open_link = statep->open_link;
	statep->open_link = NULL;
	/*
	 * If we remove what tail pointed to, we need
	 * to reassign tail (it is never NULL).
	 * tail points to head for the empty list.
	 */
	if (ibcm_open.tail == statep)
		ibcm_open.tail = &ibcm_open.head;
	return (statep);
}

void
ibcm_check_for_opens(void)
{
	ibcm_state_data_t 	*statep;

	mutex_enter(&ibcm_open.mutex);

	while (ibcm_open.queued > 0) {
		if (ibcm_ok_to_start(&ibcm_open)) {
			statep = ibcm_open_dequeue();
			mutex_exit(&ibcm_open.mutex);

			ibcm_open_start(statep);

			mutex_enter(&ibcm_open.mutex);
		} else {
			break;
		}
	}
	mutex_exit(&ibcm_open.mutex);
}


static void
ibcm_flow_init(ibcm_flow_t *flow, uint_t simul_max)
{
	flow->list			= NULL;
	flow->simul			= 0;
	flow->waiters_per_chunk		= 4;
	flow->simul_max			= simul_max;
	flow->lowat			= simul_max - flow->waiters_per_chunk;
	flow->lowat_default		= flow->lowat;
	/* stats */
	flow->total			= 0;
}

static void
ibcm_rc_flow_control_init(void)
{
	mutex_init(&ibcm_open.mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_enter(&ibcm_open.mutex);
	ibcm_flow_init(&ibcm_close_flow, ibcm_close_simul_max);
	ibcm_flow_init(&ibcm_lapr_flow, ibcm_lapr_simul_max);
	ibcm_flow_init(&ibcm_saa_flow, ibcm_saa_simul_max);

	ibcm_open.queued 		= 0;
	ibcm_open.exit_deferred 	= 0;
	ibcm_open.in_progress 		= 0;
	ibcm_open.in_progress_max 	= 16;
	ibcm_open.sends 		= 0;
	ibcm_open.sends_max 		= 0;
	ibcm_open.sends_lowat 		= 8;
	ibcm_open.sends_hiwat 		= 16;
	ibcm_open.tail 			= &ibcm_open.head;
	ibcm_open.head.open_link 	= NULL;
	mutex_exit(&ibcm_open.mutex);

	mutex_init(&ibcm_close.mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_enter(&ibcm_close.mutex);
	ibcm_close.tail			= &ibcm_close.head;
	ibcm_close.head.close_link 	= NULL;
	mutex_exit(&ibcm_close.mutex);
}

static void
ibcm_rc_flow_control_fini(void)
{
	mutex_destroy(&ibcm_open.mutex);
	mutex_destroy(&ibcm_close.mutex);
}

static ibcm_flow1_t *
ibcm_flow_find(ibcm_flow_t *flow)
{
	ibcm_flow1_t *flow1;
	ibcm_flow1_t *f;

	f = flow->list;
	if (f) {	/* most likely code path */
		while (f->link != NULL)
			f = f->link;
		if (f->waiters < flow->waiters_per_chunk)
			return (f);
	}

	/* There was no flow1 list element ready for another waiter */
	mutex_exit(&ibcm_open.mutex);
	flow1 = kmem_alloc(sizeof (*flow1), KM_SLEEP);
	mutex_enter(&ibcm_open.mutex);

	f = flow->list;
	if (f) {
		while (f->link != NULL)
			f = f->link;
		if (f->waiters < flow->waiters_per_chunk) {
			kmem_free(flow1, sizeof (*flow1));
			return (f);
		}
		f->link = flow1;
	} else {
		flow->list = flow1;
	}
	cv_init(&flow1->cv, NULL, CV_DRIVER, NULL);
	flow1->waiters = 0;
	flow1->link = NULL;
	return (flow1);
}

static void
ibcm_flow_enter(ibcm_flow_t *flow)
{
	mutex_enter(&ibcm_open.mutex);
	if (flow->list == NULL && flow->simul < flow->simul_max) {
		flow->simul++;
		flow->total++;
		mutex_exit(&ibcm_open.mutex);
	} else {
		ibcm_flow1_t *flow1;

		flow1 = ibcm_flow_find(flow);
		flow1->waiters++;
		cv_wait(&flow1->cv, &ibcm_open.mutex);
		if (--flow1->waiters == 0) {
			cv_destroy(&flow1->cv);
			mutex_exit(&ibcm_open.mutex);
			kmem_free(flow1, sizeof (*flow1));
		} else
			mutex_exit(&ibcm_open.mutex);
	}
}

static void
ibcm_flow_exit(ibcm_flow_t *flow)
{
	mutex_enter(&ibcm_open.mutex);
	if (--flow->simul < flow->lowat) {
		if (flow->lowat < flow->lowat_default)
			flow->lowat++;
		if (flow->list) {
			ibcm_flow1_t *flow1;

			flow1 = flow->list;
			flow->list = flow1->link;	/* unlink */
			flow1->link = NULL;		/* be clean */
			flow->total += flow1->waiters;
			flow->simul += flow1->waiters;
			cv_broadcast(&flow1->cv);
		}
	}
	mutex_exit(&ibcm_open.mutex);
}

void
ibcm_flow_inc(void)
{
	mutex_enter(&ibcm_open.mutex);
	if (++ibcm_open.sends > ibcm_open.sends_max) {
		ibcm_open.sends_max = ibcm_open.sends;
		IBTF_DPRINTF_L2(cmlog, "ibcm_flow_inc: sends max = %d",
		    ibcm_open.sends_max);
	}
	mutex_exit(&ibcm_open.mutex);
}

static void
ibcm_check_send_cmpltn_time(hrtime_t delta, char *event_msg)
{
	if (delta > 4000000LL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_check_send_cmpltn_time: "
		    "%s: %lldns", event_msg, delta);
	}
}

void
ibcm_flow_dec(hrtime_t time, char *mad_type)
{
	int flow_exit = 0;
	int run = 0;

	if (ibcm_dtrace)
		ibcm_check_send_cmpltn_time(gethrtime() - time, mad_type);
	mutex_enter(&ibcm_open.mutex);
	ibcm_open.sends--;
	if (ibcm_open.sends < ibcm_open.sends_lowat) {
		run = ibcm_ok_to_start(&ibcm_open);
		if (ibcm_open.exit_deferred) {
			ibcm_open.exit_deferred--;
			flow_exit = 1;
		}
	}
	mutex_exit(&ibcm_open.mutex);
	if (flow_exit)
		ibcm_flow_exit(&ibcm_close_flow);
	if (run)
		ibcm_run_tlist_thread();
}

void
ibcm_close_enqueue(ibcm_state_data_t *statep)
{
	mutex_enter(&ibcm_close.mutex);
	statep->close_link = NULL;
	ibcm_close.tail->close_link = statep;
	ibcm_close.tail = statep;
	mutex_exit(&ibcm_close.mutex);
	ibcm_run_tlist_thread();
}

void
ibcm_check_for_async_close()
{
	ibcm_state_data_t 	*statep;

	mutex_enter(&ibcm_close.mutex);

	while (ibcm_close.head.close_link) {
		statep = ibcm_close.head.close_link;
		ibcm_close.head.close_link = statep->close_link;
		statep->close_link = NULL;
		if (ibcm_close.tail == statep)
			ibcm_close.tail = &ibcm_close.head;
		mutex_exit(&ibcm_close.mutex);
		ibcm_close_start(statep);
		mutex_enter(&ibcm_close.mutex);
	}
	mutex_exit(&ibcm_close.mutex);
}

void
ibcm_close_enter(void)
{
	ibcm_flow_enter(&ibcm_close_flow);
}

void
ibcm_close_exit(void)
{
	int flow_exit;

	mutex_enter(&ibcm_open.mutex);
	if (ibcm_open.sends < ibcm_open.sends_lowat ||
	    ibcm_open.exit_deferred >= 4)
		flow_exit = 1;
	else {
		flow_exit = 0;
		ibcm_open.exit_deferred++;
	}
	mutex_exit(&ibcm_open.mutex);
	if (flow_exit)
		ibcm_flow_exit(&ibcm_close_flow);
}

/*
 * This function needs to be called twice to finish our flow
 * control accounting when closing down a connection.  One
 * call has send_done set to 1, while the other has it set to 0.
 * Because of retries, this could get called more than once
 * with either 0 or 1, but additional calls have no effect.
 */
void
ibcm_close_done(ibcm_state_data_t *statep, int send_done)
{
	int flow_exit;

	ASSERT(MUTEX_HELD(&statep->state_mutex));
	if (statep->close_flow == 1) {
		if (send_done)
			statep->close_flow = 3;
		else
			statep->close_flow = 2;
	} else if ((send_done && statep->close_flow == 2) ||
	    (!send_done && statep->close_flow == 3)) {
		statep->close_flow = 0;
		mutex_enter(&ibcm_open.mutex);
		if (ibcm_open.sends < ibcm_open.sends_lowat ||
		    ibcm_open.exit_deferred >= 4)
			flow_exit = 1;
		else {
			flow_exit = 0;
			ibcm_open.exit_deferred++;
		}
		mutex_exit(&ibcm_open.mutex);
		if (flow_exit)
			ibcm_flow_exit(&ibcm_close_flow);
	}
}

void
ibcm_lapr_enter(void)
{
	ibcm_flow_enter(&ibcm_lapr_flow);
}

void
ibcm_lapr_exit(void)
{
	ibcm_flow_exit(&ibcm_lapr_flow);
}

void
ibcm_sa_access_enter()
{
	ibcm_flow_enter(&ibcm_saa_flow);
}

void
ibcm_sa_access_exit()
{
	ibcm_flow_exit(&ibcm_saa_flow);
}

static void
ibcm_sm_notice_handler(ibmf_saa_handle_t saa_handle,
    ibmf_saa_subnet_event_t saa_event_code,
    ibmf_saa_event_details_t *saa_event_details,
    void *callback_arg)
{
	ibcm_port_info_t	*portp = (ibcm_port_info_t *)callback_arg;
	ibt_subnet_event_code_t code;
	ibt_subnet_event_t	event;
	uint8_t			event_status;

	IBTF_DPRINTF_L3(cmlog, "ibcm_sm_notice_handler: saa_hdl %p, code = %d",
	    saa_handle, saa_event_code);

	mutex_enter(&ibcm_sm_notice_serialize_lock);

	switch (saa_event_code) {
	case IBMF_SAA_EVENT_MCG_CREATED:
		code = IBT_SM_EVENT_MCG_CREATED;
		break;
	case IBMF_SAA_EVENT_MCG_DELETED:
		code = IBT_SM_EVENT_MCG_DELETED;
		break;
	case IBMF_SAA_EVENT_GID_AVAILABLE:
		code = IBT_SM_EVENT_GID_AVAIL;
		ibcm_path_cache_purge();
		break;
	case IBMF_SAA_EVENT_GID_UNAVAILABLE:
		code = IBT_SM_EVENT_GID_UNAVAIL;
		ibcm_path_cache_purge();
		break;
	case IBMF_SAA_EVENT_SUBSCRIBER_STATUS_CHG:
		event_status =
		    saa_event_details->ie_producer_event_status_mask &
		    IBMF_SAA_EVENT_STATUS_MASK_PRODUCER_SM;
		if (event_status == (portp->port_event_status &
		    IBMF_SAA_EVENT_STATUS_MASK_PRODUCER_SM)) {
			mutex_exit(&ibcm_sm_notice_serialize_lock);
			return;	/* no change */
		}
		portp->port_event_status = event_status;
		if (event_status == IBMF_SAA_EVENT_STATUS_MASK_PRODUCER_SM)
			code = IBT_SM_EVENT_AVAILABLE;
		else
			code = IBT_SM_EVENT_UNAVAILABLE;
		break;
	default:
		mutex_exit(&ibcm_sm_notice_serialize_lock);
		return;
	}

	mutex_enter(&ibcm_global_hca_lock);

	/* don't send the event if we're tearing down */
	if (!IBCM_ACCESS_HCA_OK(portp->port_hcap)) {
		mutex_exit(&ibcm_global_hca_lock);
		mutex_exit(&ibcm_sm_notice_serialize_lock);
		return;
	}

	++(portp->port_hcap->hca_acc_cnt);
	mutex_exit(&ibcm_global_hca_lock);

	event.sm_notice_gid = saa_event_details->ie_gid;
	ibtl_cm_sm_notice_handler(portp->port_sgid0, code, &event);

	mutex_exit(&ibcm_sm_notice_serialize_lock);

	ibcm_dec_hca_acc_cnt(portp->port_hcap);
}

void
ibt_register_subnet_notices(ibt_clnt_hdl_t ibt_hdl,
    ibt_sm_notice_handler_t sm_notice_handler, void *private)
{
	ibcm_port_info_t	*portp;
	ibcm_hca_info_t		*hcap;
	uint8_t			port;
	int			num_failed_sgids;
	ibtl_cm_sm_init_fail_t	*ifail;
	ib_gid_t		*sgidp;

	IBTF_DPRINTF_L3(cmlog, "ibt_register_subnet_notices: ibt_hdl = %p",
	    ibt_hdl);

	mutex_enter(&ibcm_sm_notice_serialize_lock);

	ibtl_cm_set_sm_notice_handler(ibt_hdl, sm_notice_handler, private);
	if (sm_notice_handler == NULL) {
		mutex_exit(&ibcm_sm_notice_serialize_lock);
		return;
	}

	/* for each port, if service is not available, make a call */
	mutex_enter(&ibcm_global_hca_lock);
	num_failed_sgids = 0;
	hcap = ibcm_hca_listp;
	while (hcap != NULL) {
		portp = hcap->hca_port_info;
		for (port = 0; port < hcap->hca_num_ports; port++) {
			if (!(portp->port_event_status &
			    IBMF_SAA_EVENT_STATUS_MASK_PRODUCER_SM))
				num_failed_sgids++;
			portp++;
		}
		hcap = hcap->hca_next;
	}
	if (num_failed_sgids != 0) {
		ifail = kmem_alloc(sizeof (*ifail) +
		    (num_failed_sgids - 1) * sizeof (ib_gid_t), KM_SLEEP);
		ifail->smf_num_sgids = num_failed_sgids;
		ifail->smf_ibt_hdl = ibt_hdl;
		sgidp = &ifail->smf_sgid[0];
		hcap = ibcm_hca_listp;
		while (hcap != NULL) {
			portp = hcap->hca_port_info;
			for (port = 0; port < hcap->hca_num_ports; port++) {
				if (!(portp->port_event_status &
				    IBMF_SAA_EVENT_STATUS_MASK_PRODUCER_SM))
					*sgidp++ = portp->port_sgid0;
				portp++;
			}
			hcap = hcap->hca_next;
		}
	}
	mutex_exit(&ibcm_global_hca_lock);

	if (num_failed_sgids != 0) {
		ibtl_cm_sm_notice_init_failure(ifail);
		kmem_free(ifail, sizeof (*ifail) +
		    (num_failed_sgids - 1) * sizeof (ib_gid_t));
	}
	mutex_exit(&ibcm_sm_notice_serialize_lock);
}

/* The following is run from a taskq because we've seen the stack overflow. */
static void
ibcm_init_saa(void *arg)
{
	ibcm_port_info_t		*portp = (ibcm_port_info_t *)arg;
	int				status;
	ib_guid_t			port_guid;
	ibmf_saa_subnet_event_args_t	event_args;

	port_guid = portp->port_sgid0.gid_guid;

	IBTF_DPRINTF_L3(cmlog, "ibcm_init_saa: port guid %llX", port_guid);

	event_args.is_event_callback_arg = portp;
	event_args.is_event_callback = ibcm_sm_notice_handler;

	if ((status = ibmf_sa_session_open(port_guid, 0, &event_args,
	    IBMF_VERSION, 0, &portp->port_ibmf_saa_hdl)) != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_init_saa: "
		    "ibmf_sa_session_open failed for port guid %llX "
		    "status = %d", port_guid, status);
	} else {
		IBTF_DPRINTF_L2(cmlog, "ibcm_init_saa: "
		    "registered sa_hdl 0x%p for port guid %llX",
		    portp->port_ibmf_saa_hdl, port_guid);
	}

	mutex_enter(&ibcm_sa_open_lock);
	portp->port_saa_open_in_progress = 0;
	cv_broadcast(&ibcm_sa_open_cv);
	mutex_exit(&ibcm_sa_open_lock);
}

void
ibcm_init_saa_handle(ibcm_hca_info_t *hcap, uint8_t port)
{
	ibmf_saa_handle_t	saa_handle;
	uint8_t			port_index = port - 1;
	ibcm_port_info_t	*portp = &hcap->hca_port_info[port_index];
	ibt_status_t		ibt_status;

	if (port_index >= hcap->hca_num_ports)
		return;

	mutex_enter(&ibcm_sa_open_lock);
	if (portp->port_saa_open_in_progress) {
		mutex_exit(&ibcm_sa_open_lock);
		return;
	}

	saa_handle = portp->port_ibmf_saa_hdl;
	if (saa_handle != NULL) {
		mutex_exit(&ibcm_sa_open_lock);
		return;
	}

	portp->port_saa_open_in_progress = 1;
	mutex_exit(&ibcm_sa_open_lock);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(portp->port_event_status))

	/* The assumption is that we're getting event notifications */
	portp->port_event_status = IBMF_SAA_EVENT_STATUS_MASK_PRODUCER_SM;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(portp->port_event_status))

	ibt_status = ibt_get_port_state_byguid(portp->port_hcap->hca_guid,
	    portp->port_num, &portp->port_sgid0, NULL);
	if (ibt_status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_init_saa_handle: "
		    "ibt_get_port_state_byguid failed for guid %llX "
		    "with status %d", portp->port_hcap->hca_guid, ibt_status);
		mutex_enter(&ibcm_sa_open_lock);
		portp->port_saa_open_in_progress = 0;
		cv_broadcast(&ibcm_sa_open_cv);
		mutex_exit(&ibcm_sa_open_lock);
		return;
	}
	/* if the port is UP, try sa_session_open */
	(void) taskq_dispatch(ibcm_taskq, ibcm_init_saa, portp, TQ_SLEEP);
}


ibmf_saa_handle_t
ibcm_get_saa_handle(ibcm_hca_info_t *hcap, uint8_t port)
{
	ibmf_saa_handle_t	saa_handle;
	uint8_t			port_index = port - 1;
	ibcm_port_info_t	*portp = &hcap->hca_port_info[port_index];
	ibt_status_t		ibt_status;

	if (port_index >= hcap->hca_num_ports)
		return (NULL);

	mutex_enter(&ibcm_sa_open_lock);
	while (portp->port_saa_open_in_progress) {
		cv_wait(&ibcm_sa_open_cv, &ibcm_sa_open_lock);
	}

	saa_handle = portp->port_ibmf_saa_hdl;
	if (saa_handle != NULL) {
		mutex_exit(&ibcm_sa_open_lock);
		return (saa_handle);
	}

	portp->port_saa_open_in_progress = 1;
	mutex_exit(&ibcm_sa_open_lock);

	ibt_status = ibt_get_port_state_byguid(portp->port_hcap->hca_guid,
	    portp->port_num, &portp->port_sgid0, NULL);
	if (ibt_status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_get_saa_handle: "
		    "ibt_get_port_state_byguid failed for guid %llX "
		    "with status %d", portp->port_hcap->hca_guid, ibt_status);
		mutex_enter(&ibcm_sa_open_lock);
		portp->port_saa_open_in_progress = 0;
		cv_broadcast(&ibcm_sa_open_cv);
		mutex_exit(&ibcm_sa_open_lock);
		return (NULL);
	}
	/* if the port is UP, try sa_session_open */
	(void) taskq_dispatch(ibcm_taskq, ibcm_init_saa, portp, TQ_SLEEP);

	mutex_enter(&ibcm_sa_open_lock);
	while (portp->port_saa_open_in_progress) {
		cv_wait(&ibcm_sa_open_cv, &ibcm_sa_open_lock);
	}
	saa_handle = portp->port_ibmf_saa_hdl;
	mutex_exit(&ibcm_sa_open_lock);
	return (saa_handle);
}


/*
 * ibcm_hca_init_port():
 * 	- Register port with IBMA
 *
 * Arguments:
 *	hcap		- HCA's guid
 *	port_index	- port number minus 1
 *
 * Return values:
 *	IBCM_SUCCESS - success
 */
ibt_status_t
ibcm_hca_init_port(ibcm_hca_info_t *hcap, uint8_t port_index)
{
	int			status;
	ibmf_register_info_t	*ibmf_reg;

	IBTF_DPRINTF_L4(cmlog, "ibcm_hca_init_port: hcap = 0x%p port_num %d",
	    hcap, port_index + 1);

	ASSERT(MUTEX_HELD(&ibcm_global_hca_lock));

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(hcap->hca_port_info))

	if (hcap->hca_port_info[port_index].port_ibmf_hdl == NULL) {
		/* Register with IBMF */
		ibmf_reg = &hcap->hca_port_info[port_index].port_ibmf_reg;
		ibmf_reg->ir_ci_guid = hcap->hca_guid;
		ibmf_reg->ir_port_num = port_index + 1;
		ibmf_reg->ir_client_class = COMM_MGT_MANAGER_AGENT;

		/*
		 * register with management framework
		 */
		status = ibmf_register(ibmf_reg, IBMF_VERSION,
		    IBMF_REG_FLAG_NO_OFFLOAD, NULL, NULL,
		    &(hcap->hca_port_info[port_index].port_ibmf_hdl),
		    &(hcap->hca_port_info[port_index].port_ibmf_caps));

		if (status != IBMF_SUCCESS) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_hca_init_port: "
			    "ibmf_register failed for port_num %x, "
			    "status = %x", port_index + 1, status);
			return (ibcm_ibmf_analyze_error(status));
		}

		hcap->hca_port_info[port_index].port_qp1.qp_cm =
		    IBMF_QP_HANDLE_DEFAULT;
		hcap->hca_port_info[port_index].port_qp1.qp_port =
		    &(hcap->hca_port_info[port_index]);

		/*
		 * Register the read callback with IBMF.
		 * Since we just did an ibmf_register, handle is
		 * valid and ibcm_recv_cb() is valid so we can
		 * safely assert for success of ibmf_setup_recv_cb()
		 *
		 * Depending on the "state" of the HCA,
		 * CM may drop incoming packets
		 */
		status = ibmf_setup_async_cb(
		    hcap->hca_port_info[port_index].port_ibmf_hdl,
		    IBMF_QP_HANDLE_DEFAULT, ibcm_recv_cb,
		    &(hcap->hca_port_info[port_index].port_qp1), 0);
		ASSERT(status == IBMF_SUCCESS);

		IBTF_DPRINTF_L5(cmlog, "ibcm_hca_init_port: "
		    "IBMF hdl[%x] = 0x%p", port_index,
		    hcap->hca_port_info[port_index].port_ibmf_hdl);

		/* Attempt to get the saa_handle for this port */
		ibcm_init_saa_handle(hcap, port_index + 1);
	}

	return (IBT_SUCCESS);
}

/*
 * useful, to re attempt to initialize port ibma handles from elsewhere in
 * cm code
 */
ibt_status_t
ibcm_hca_reinit_port(ibcm_hca_info_t *hcap, uint8_t port_index)
{
	ibt_status_t	status;

	IBTF_DPRINTF_L5(cmlog, "ibcm_hca_reinit_port: hcap 0x%p port_num %d",
	    hcap, port_index + 1);

	mutex_enter(&ibcm_global_hca_lock);
	status = ibcm_hca_init_port(hcap, port_index);
	mutex_exit(&ibcm_global_hca_lock);
	return (status);
}


/*
 * ibcm_hca_fini_port():
 * 	- Deregister port with IBMA
 *
 * Arguments:
 *	hcap		- HCA's guid
 *	port_index	- port number minus 1
 *
 * Return values:
 *	IBCM_SUCCESS - success
 */
static ibcm_status_t
ibcm_hca_fini_port(ibcm_hca_info_t *hcap, uint8_t port_index)
{
	int			ibmf_status;
	ibcm_status_t		ibcm_status;

	IBTF_DPRINTF_L4(cmlog, "ibcm_hca_fini_port: hcap = 0x%p port_num %d ",
	    hcap, port_index + 1);

	ASSERT(MUTEX_HELD(&ibcm_global_hca_lock));

	if (hcap->hca_port_info[port_index].port_ibmf_saa_hdl != NULL) {
		IBTF_DPRINTF_L5(cmlog, "ibcm_hca_fini_port: "
		    "ibmf_sa_session_close IBMF SAA hdl %p",
		    hcap->hca_port_info[port_index].port_ibmf_saa_hdl);

		ibmf_status = ibmf_sa_session_close(
		    &hcap->hca_port_info[port_index].port_ibmf_saa_hdl, 0);
		if (ibmf_status != IBMF_SUCCESS) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_hca_fini_port: "
			    "ibmf_sa_session_close of port %d returned %x",
			    port_index + 1, ibmf_status);
			return (IBCM_FAILURE);
		}
	}

	if (hcap->hca_port_info[port_index].port_ibmf_hdl != NULL) {
		IBTF_DPRINTF_L5(cmlog, "ibcm_hca_fini_port: "
		    "ibmf_unregister IBMF Hdl %p",
		    hcap->hca_port_info[port_index].port_ibmf_hdl);

		/* clean-up all the ibmf qp's allocated on this port */
		ibcm_status = ibcm_free_allqps(hcap, port_index + 1);

		if (ibcm_status != IBCM_SUCCESS) {

			IBTF_DPRINTF_L2(cmlog, "ibcm_hca_fini_port: "
			    "ibcm_free_allqps failed for port_num %d",
			    port_index + 1);
			return (IBCM_FAILURE);
		}

		/* Tear down the receive callback */
		ibmf_status = ibmf_tear_down_async_cb(
		    hcap->hca_port_info[port_index].port_ibmf_hdl,
		    IBMF_QP_HANDLE_DEFAULT, 0);

		if (ibmf_status != IBMF_SUCCESS) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_hca_fini_port: "
			    "ibmf_tear_down_async_cb failed %d port_num %d",
			    ibmf_status, port_index + 1);
			return (IBCM_FAILURE);
		}

		/* Now, unregister with IBMF */
		ibmf_status = ibmf_unregister(
		    &hcap->hca_port_info[port_index].port_ibmf_hdl, 0);
		IBTF_DPRINTF_L4(cmlog, "ibcm_hca_fini_port: "
		    "ibmf_unregister of port_num %x returned %x",
		    port_index + 1, ibmf_status);

		if (ibmf_status == IBMF_SUCCESS)
			hcap->hca_port_info[port_index].port_ibmf_hdl = NULL;
		else {
			IBTF_DPRINTF_L2(cmlog, "ibcm_hca_fini_port: "
			    "ibmf_unregister failed %d port_num %d",
			    ibmf_status, port_index + 1);
			return (IBCM_FAILURE);
		}
	}
	return (IBCM_SUCCESS);
}

/*
 * ibcm_comm_est_handler():
 *	Check if the given channel is in ESTABLISHED state or not
 *
 * Arguments:
 *	eventp	- A pointer to an ibt_async_event_t struct
 *
 * Return values: NONE
 */
static void
ibcm_comm_est_handler(ibt_async_event_t *eventp)
{
	ibcm_state_data_t	*statep;

	IBTF_DPRINTF_L4(cmlog, "ibcm_comm_est_handler:");

	/* Both QP and EEC handles can't be NULL */
	if (eventp->ev_chan_hdl == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_comm_est_handler: "
		    "both QP and EEC handles are NULL");
		return;
	}

	/* get the "statep" from qp/eec handles */
	IBCM_GET_CHAN_PRIVATE(eventp->ev_chan_hdl, statep);
	if (statep == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_comm_est_handler: statep is NULL");
		return;
	}

	mutex_enter(&statep->state_mutex);

	IBCM_RELEASE_CHAN_PRIVATE(eventp->ev_chan_hdl);

	IBTF_DPRINTF_L4(cmlog, "ibcm_comm_est_handler: statep = %p", statep);

	IBCM_REF_CNT_INCR(statep);

	if ((statep->state == IBCM_STATE_REP_SENT) ||
	    (statep->state == IBCM_STATE_MRA_REP_RCVD)) {
		timeout_id_t	timer_val = statep->timerid;

		statep->state = IBCM_STATE_TRANSIENT_ESTABLISHED;

		if (timer_val) {
			statep->timerid = 0;
			mutex_exit(&statep->state_mutex);
			(void) untimeout(timer_val);
		} else
			mutex_exit(&statep->state_mutex);

		/* CM doesn't have RTU message here */
		ibcm_cep_state_rtu(statep, NULL);

	} else {
		if (statep->state == IBCM_STATE_ESTABLISHED ||
		    statep->state == IBCM_STATE_TRANSIENT_ESTABLISHED) {
			IBTF_DPRINTF_L4(cmlog, "ibcm_comm_est_handler: "
			    "Channel already in ESTABLISHED state");
		} else {
			/* An unexpected behavior from remote */
			IBTF_DPRINTF_L2(cmlog, "ibcm_comm_est_handler: "
			    "Unexpected in state = %d", statep->state);
		}
		mutex_exit(&statep->state_mutex);

		ibcm_insert_trace(statep, IBCM_TRACE_INCOMING_COMEST);
	}

	mutex_enter(&statep->state_mutex);
	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}


/*
 * ibcm_async_handler():
 *	CM's Async Handler
 *	(Handles ATTACH, DETACH, COM_EST events)
 *
 * Arguments:
 *	eventp	- A pointer to an ibt_async_event_t struct
 *
 * Return values: None
 *
 * NOTE : CM assumes that all HCA DR events are delivered sequentially
 * i.e., until ibcm_async_handler  completes for a given HCA DR, framework
 * shall not invoke ibcm_async_handler with another DR event for the same
 * HCA
 */
/* ARGSUSED */
void
ibcm_async_handler(void *clnt_hdl, ibt_hca_hdl_t hca_hdl,
    ibt_async_code_t code, ibt_async_event_t *eventp)
{
	ibcm_hca_info_t		*hcap;
	ibcm_port_up_t		*pup;

	IBTF_DPRINTF_L3(cmlog, "ibcm_async_handler: "
	    "clnt_hdl = %p, code = 0x%x, eventp = 0x%p",
	    clnt_hdl, code, eventp);

	mutex_enter(&ibcm_global_hca_lock);

	/* If fini is going to complete successfully, then return */
	if (ibcm_finit_state != IBCM_FINIT_IDLE) {

		/*
		 * This finit state implies one of the following:
		 * Init either didn't start or didn't complete OR
		 * Fini is about to return SUCCESS and release the global lock.
		 * In all these cases, it is safe to ignore the async.
		 */

		IBTF_DPRINTF_L2(cmlog, "ibcm_async_handler: ignoring event %x, "
		    "as either init didn't complete or fini about to succeed",
		    code);
		mutex_exit(&ibcm_global_hca_lock);
		return;
	}

	switch (code) {
	case IBT_EVENT_PORT_UP:
		mutex_exit(&ibcm_global_hca_lock);
		pup = kmem_alloc(sizeof (ibcm_port_up_t), KM_SLEEP);
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*pup))
		pup->pup_hca_guid = eventp->ev_hca_guid;
		pup->pup_port = eventp->ev_port;
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*pup))
		(void) taskq_dispatch(ibcm_taskq,
		    ibcm_service_record_rewrite_task, pup, TQ_SLEEP);
		ibcm_path_cache_purge();
		return;

	case IBT_HCA_ATTACH_EVENT:

		/* eventp->ev_hcaguid is the HCA GUID of interest */
		ibcm_hca_attach(eventp->ev_hca_guid);
		break;

	case IBT_HCA_DETACH_EVENT:

		/* eventp->ev_hca_guid is the HCA GUID of interest */
		if ((hcap = ibcm_find_hcap_entry(eventp->ev_hca_guid)) ==
		    NULL) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_async_handler:"
			    " hca %llX doesn't exist", eventp->ev_hca_guid);
			break;
		}

		(void) ibcm_hca_detach(hcap);
		break;

	case IBT_EVENT_COM_EST_QP:
		/* eventp->ev_qp_hdl is the ibt_qp_hdl_t of interest */
	case IBT_EVENT_COM_EST_EEC:
		/* eventp->ev_eec_hdl is the ibt_eec_hdl_t of interest */
		ibcm_comm_est_handler(eventp);
		break;
	default:
		break;
	}

	/* Unblock, any blocked fini/init operations */
	mutex_exit(&ibcm_global_hca_lock);
}
