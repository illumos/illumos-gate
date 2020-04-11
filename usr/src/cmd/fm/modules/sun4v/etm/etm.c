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

/*
 * etm.c	FMA Event Transport Module implementation, a plugin of FMD
 *		for sun4v/Ontario
 *
 * plugin for sending/receiving FMA events to/from service processor
 */

/*
 * --------------------------------- includes --------------------------------
 */

#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/ldom.h>
#include <sys/strlog.h>
#include <sys/syslog.h>
#include <sys/libds.h>
#include <netinet/in.h>
#include <fm/fmd_api.h>

#include "etm_xport_api.h"
#include "etm_etm_proto.h"
#include "etm_impl.h"
#include "etm_iosvc.h"
#include "etm_filter.h"
#include "etm_ckpt.h"

#include <pthread.h>
#include <signal.h>
#include <stropts.h>
#include <locale.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <values.h>
#include <alloca.h>
#include <errno.h>
#include <dlfcn.h>
#include <link.h>
#include <fcntl.h>
#include <time.h>

/*
 * ----------------------------- forward decls -------------------------------
 */

static void
etm_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class);

static int
etm_send(fmd_hdl_t *hdl, fmd_xprt_t *xp, fmd_event_t *event, nvlist_t *nvl);

static void
etm_send_to_remote_root(void *arg);

static void
etm_recv_from_remote_root(void *arg);

static void
etm_ckpt_remove(fmd_hdl_t *hdl, etm_iosvc_q_ele_t *ele);

/*
 * ------------------------- data structs for FMD ----------------------------
 */

static const fmd_hdl_ops_t fmd_ops = {
	etm_recv,	/* fmdo_recv */
	NULL,		/* fmdo_timeout */
	NULL,		/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
	etm_send,	/* fmdo_send */
};

static const fmd_prop_t fmd_props[] = {
	{ ETM_PROP_NM_XPORT_ADDRS,		FMD_TYPE_STRING, "" },
	{ ETM_PROP_NM_DEBUG_LVL,		FMD_TYPE_INT32, "0" },
	{ ETM_PROP_NM_DEBUG_MAX_EV_CNT,		FMD_TYPE_INT32, "-1" },
	{ ETM_PROP_NM_CONSOLE,			FMD_TYPE_BOOL, "false" },
	{ ETM_PROP_NM_SYSLOGD,			FMD_TYPE_BOOL, "true" },
	{ ETM_PROP_NM_FACILITY,			FMD_TYPE_STRING, "LOG_DAEMON" },
	{ ETM_PROP_NM_MAX_RESP_Q_LEN,		FMD_TYPE_UINT32, "32" },
	{ ETM_PROP_NM_BAD_ACC_TO_SEC,		FMD_TYPE_UINT32, "1" },
	{ ETM_PROP_NM_FMA_RESP_WAIT_TIME,	FMD_TYPE_INT32, "240" },
	{ NULL, 0, NULL }
};


static const fmd_hdl_info_t fmd_info = {
	"FMA Event Transport Module", "1.2", &fmd_ops, fmd_props
};

/*
 * ----------------------- private consts and defns --------------------------
 */

/* misc buffer for variable sized protocol header fields */

#define	ETM_MISC_BUF_SZ	(4 * 1024)

static uint32_t
etm_ldom_type = LDOM_TYPE_LEGACY;

/* try limit for IO operations w/ capped exp backoff sleep on retry */

/*
 * Design_Note:	ETM will potentially retry forever IO operations that the
 *		transport fails with EAGAIN (aka EWOULDBLOCK) rather than
 *		giving up after some number of seconds. This avoids
 *		dropping FMA events while the service processor is down,
 *		but at the risk of pending fmdo_recv() forever and
 *		overflowing FMD's event queue for ETM.
 *		A future TBD enhancement would be to always recv
 *		and send each ETM msg in a single read/write() to reduce
 *		the risk of failure between ETM msg hdr and body,
 *		assuming the MTU_SZ is large enough.
 */

#define	ETM_TRY_MAX_CNT		(MAXINT - 1)
#define	ETM_TRY_BACKOFF_RATE	(4)
#define	ETM_TRY_BACKOFF_CAP	(60)

/* amount to increment protocol transaction id on each new send */

#define	ETM_XID_INC		(2)

typedef struct etm_resp_q_ele {

	etm_xport_conn_t	rqe_conn;	/* open connection to send on */
	etm_proto_v1_pp_t	*rqe_hdrp;	/* ptr to ETM msg hdr */
	size_t			rqe_hdr_sz;	/* sizeof ETM msg hdr */
	int32_t			rqe_resp_code;	/* response code to send */

	struct etm_resp_q_ele	*rqe_nextp;	/* PRIVATE - next ele ptr */

} etm_resp_q_ele_t;	/* responder queue element */

/*
 * ---------------------------- global data ----------------------------------
 */

static fmd_hdl_t
*init_hdl = NULL;	/* used in mem allocator and several other places */

static int
etm_debug_lvl = 0;	/* debug level: 0 is off, 1 is on, 2 is more, etc */

static int
etm_debug_max_ev_cnt = -1; /* max allowed event count for debugging */

static fmd_xprt_t
*etm_fmd_xprt = NULL;	/* FMD transport layer handle */

static pthread_t
etm_svr_tid = 0;	/* thread id of connection acceptance server */

static pthread_t
etm_resp_tid = 0;	/* thread id of msg responder */

static etm_resp_q_ele_t
*etm_resp_q_head = NULL; /* ptr to cur head of responder queue */

static etm_resp_q_ele_t
*etm_resp_q_tail = NULL; /* ptr to cur tail of responder queue */

static uint32_t
etm_resp_q_cur_len = 0;	/* cur length (ele cnt) of responder queue */

static uint32_t
etm_resp_q_max_len = 0;	/* max length (ele cnt) of responder queue */

static uint32_t
etm_bad_acc_to_sec = 0;	/* sleep timeout (in sec) after bad conn accept */

static pthread_mutex_t
etm_resp_q_lock = PTHREAD_MUTEX_INITIALIZER;	/* protects responder queue */

static pthread_cond_t
etm_resp_q_cv = PTHREAD_COND_INITIALIZER;	/* nudges msg responder */

static volatile int
etm_is_dying = 0;	/* bool for dying (killing self) */

static uint32_t
etm_xid_cur = 0;	/* current transaction id for sends */

static uint32_t
etm_xid_ping = 0;	/* xid of last CONTROL msg sent requesting ping */

static uint32_t
etm_xid_ver_negot = 0;	/* xid of last CONTROL msg sent requesting ver negot */

static uint32_t
etm_xid_posted_logged_ev = 0;
			/* xid of last FMA_EVENT msg/event posted OK to FMD */

static uint32_t
etm_xid_posted_sa = 0;	/* xid of last ALERT msg/event posted OK to syslog */

static uint8_t
etm_resp_ver = ETM_PROTO_V1; /* proto ver [negotiated] for msg sends */

static uint32_t
etm_fma_resp_wait_time = 30;	/*  time (sec) wait for fma event resp */

static pthread_mutex_t
etm_write_lock = PTHREAD_MUTEX_INITIALIZER;	/* for write operations */

static log_ctl_t syslog_ctl;	/* log(7D) meta-data for each msg */
static int syslog_facility;	/* log(7D) facility (part of priority) */
static int syslog_logfd = -1;	/* log(7D) file descriptor */
static int syslog_msgfd = -1;	/* sysmsg(7D) file descriptor */
static int syslog_file = 0;	/* log to syslog_logfd */
static int syslog_cons = 0;	/* log to syslog_msgfd */

static const struct facility {
	const char *fac_name;
	int fac_value;
} syslog_facs[] = {
	{ "LOG_DAEMON", LOG_DAEMON },
	{ "LOG_LOCAL0", LOG_LOCAL0 },
	{ "LOG_LOCAL1", LOG_LOCAL1 },
	{ "LOG_LOCAL2", LOG_LOCAL2 },
	{ "LOG_LOCAL3", LOG_LOCAL3 },
	{ "LOG_LOCAL4", LOG_LOCAL4 },
	{ "LOG_LOCAL5", LOG_LOCAL5 },
	{ "LOG_LOCAL6", LOG_LOCAL6 },
	{ "LOG_LOCAL7", LOG_LOCAL7 },
	{ NULL, 0 }
};

static struct stats {

	/* ETM msg counters */

	fmd_stat_t etm_rd_hdr_fmaevent;
	fmd_stat_t etm_rd_hdr_control;
	fmd_stat_t etm_rd_hdr_alert;
	fmd_stat_t etm_rd_hdr_response;
	fmd_stat_t etm_rd_body_fmaevent;
	fmd_stat_t etm_rd_body_control;
	fmd_stat_t etm_rd_body_alert;
	fmd_stat_t etm_rd_body_response;
	fmd_stat_t etm_wr_hdr_fmaevent;
	fmd_stat_t etm_wr_hdr_control;
	fmd_stat_t etm_wr_hdr_response;
	fmd_stat_t etm_wr_body_fmaevent;
	fmd_stat_t etm_wr_body_control;
	fmd_stat_t etm_wr_body_response;

	fmd_stat_t etm_rd_max_ev_per_msg;
	fmd_stat_t etm_wr_max_ev_per_msg;

	fmd_stat_t etm_resp_q_cur_len;
	fmd_stat_t etm_resp_q_max_len;

	/* ETM byte counters */

	fmd_stat_t etm_wr_fmd_bytes;
	fmd_stat_t etm_rd_fmd_bytes;
	fmd_stat_t etm_wr_xport_bytes;
	fmd_stat_t etm_rd_xport_bytes;

	fmd_stat_t etm_magic_drop_bytes;

	/* ETM [dropped] FMA event counters */

	fmd_stat_t etm_rd_fmd_fmaevent;
	fmd_stat_t etm_wr_fmd_fmaevent;

	fmd_stat_t etm_rd_drop_fmaevent;
	fmd_stat_t etm_wr_drop_fmaevent;

	fmd_stat_t etm_rd_dup_fmaevent;
	fmd_stat_t etm_wr_dup_fmaevent;

	fmd_stat_t etm_rd_dup_alert;
	fmd_stat_t etm_wr_dup_alert;

	fmd_stat_t etm_enq_drop_resp_q;
	fmd_stat_t etm_deq_drop_resp_q;

	/* ETM protocol failures */

	fmd_stat_t etm_magic_bad;
	fmd_stat_t etm_ver_bad;
	fmd_stat_t etm_msgtype_bad;
	fmd_stat_t etm_subtype_bad;
	fmd_stat_t etm_xid_bad;
	fmd_stat_t etm_fmaeventlen_bad;
	fmd_stat_t etm_respcode_bad;
	fmd_stat_t etm_timeout_bad;
	fmd_stat_t etm_evlens_bad;

	/* IO operation failures */

	fmd_stat_t etm_xport_wr_fail;
	fmd_stat_t etm_xport_rd_fail;
	fmd_stat_t etm_xport_pk_fail;

	/* IO operation retries */

	fmd_stat_t etm_xport_wr_retry;
	fmd_stat_t etm_xport_rd_retry;
	fmd_stat_t etm_xport_pk_retry;

	/* system and library failures */

	fmd_stat_t etm_os_nvlist_pack_fail;
	fmd_stat_t etm_os_nvlist_unpack_fail;
	fmd_stat_t etm_os_nvlist_size_fail;
	fmd_stat_t etm_os_pthread_create_fail;

	/* xport API failures */

	fmd_stat_t etm_xport_get_ev_addrv_fail;
	fmd_stat_t etm_xport_open_fail;
	fmd_stat_t etm_xport_close_fail;
	fmd_stat_t etm_xport_accept_fail;
	fmd_stat_t etm_xport_open_retry;

	/* FMD entry point bad arguments */

	fmd_stat_t etm_fmd_init_badargs;
	fmd_stat_t etm_fmd_fini_badargs;

	/* Alert logging errors */

	fmd_stat_t etm_log_err;
	fmd_stat_t etm_msg_err;

	/* miscellaneous stats */

	fmd_stat_t etm_reset_xport;

} etm_stats = {

	/* ETM msg counters */

	{ "etm_rd_hdr_fmaevent", FMD_TYPE_UINT64,
		"ETM fmaevent msg headers rcvd from xport" },
	{ "etm_rd_hdr_control", FMD_TYPE_UINT64,
		"ETM control msg headers rcvd from xport" },
	{ "etm_rd_hdr_alert", FMD_TYPE_UINT64,
		"ETM alert msg headers rcvd from xport" },
	{ "etm_rd_hdr_response", FMD_TYPE_UINT64,
		"ETM response msg headers rcvd from xport" },
	{ "etm_rd_body_fmaevent", FMD_TYPE_UINT64,
		"ETM fmaevent msg bodies rcvd from xport" },
	{ "etm_rd_body_control", FMD_TYPE_UINT64,
		"ETM control msg bodies rcvd from xport" },
	{ "etm_rd_body_alert", FMD_TYPE_UINT64,
		"ETM alert msg bodies rcvd from xport" },
	{ "etm_rd_body_response", FMD_TYPE_UINT64,
		"ETM response msg bodies rcvd from xport" },
	{ "etm_wr_hdr_fmaevent", FMD_TYPE_UINT64,
		"ETM fmaevent msg headers sent to xport" },
	{ "etm_wr_hdr_control", FMD_TYPE_UINT64,
		"ETM control msg headers sent to xport" },
	{ "etm_wr_hdr_response", FMD_TYPE_UINT64,
		"ETM response msg headers sent to xport" },
	{ "etm_wr_body_fmaevent", FMD_TYPE_UINT64,
		"ETM fmaevent msg bodies sent to xport" },
	{ "etm_wr_body_control", FMD_TYPE_UINT64,
		"ETM control msg bodies sent to xport" },
	{ "etm_wr_body_response", FMD_TYPE_UINT64,
		"ETM response msg bodies sent to xport" },

	{ "etm_rd_max_ev_per_msg", FMD_TYPE_UINT64,
		"max FMA events per ETM msg from xport" },
	{ "etm_wr_max_ev_per_msg", FMD_TYPE_UINT64,
		"max FMA events per ETM msg to xport" },

	{ "etm_resp_q_cur_len", FMD_TYPE_UINT64,
		"cur enqueued response msgs to xport" },
	{ "etm_resp_q_max_len", FMD_TYPE_UINT64,
		"max enqueable response msgs to xport" },

	/* ETM byte counters */

	{ "etm_wr_fmd_bytes", FMD_TYPE_UINT64,
		"bytes of FMA events sent to FMD" },
	{ "etm_rd_fmd_bytes", FMD_TYPE_UINT64,
		"bytes of FMA events rcvd from FMD" },
	{ "etm_wr_xport_bytes", FMD_TYPE_UINT64,
		"bytes of FMA events sent to xport" },
	{ "etm_rd_xport_bytes", FMD_TYPE_UINT64,
		"bytes of FMA events rcvd from xport" },

	{ "etm_magic_drop_bytes", FMD_TYPE_UINT64,
		"bytes dropped from xport pre magic num" },

	/* ETM [dropped] FMA event counters */

	{ "etm_rd_fmd_fmaevent", FMD_TYPE_UINT64,
		"FMA events rcvd from FMD" },
	{ "etm_wr_fmd_fmaevent", FMD_TYPE_UINT64,
		"FMA events sent to FMD" },

	{ "etm_rd_drop_fmaevent", FMD_TYPE_UINT64,
		"dropped FMA events from xport" },
	{ "etm_wr_drop_fmaevent", FMD_TYPE_UINT64,
		"dropped FMA events to xport" },

	{ "etm_rd_dup_fmaevent", FMD_TYPE_UINT64,
	    "duplicate FMA events rcvd from xport" },
	{ "etm_wr_dup_fmaevent", FMD_TYPE_UINT64,
	    "duplicate FMA events sent to xport" },

	{ "etm_rd_dup_alert", FMD_TYPE_UINT64,
	    "duplicate ALERTs rcvd from xport" },
	{ "etm_wr_dup_alert", FMD_TYPE_UINT64,
	    "duplicate ALERTs sent to xport" },

	{ "etm_enq_drop_resp_q", FMD_TYPE_UINT64,
	    "dropped response msgs on enq" },
	{ "etm_deq_drop_resp_q", FMD_TYPE_UINT64,
	    "dropped response msgs on deq" },

	/* ETM protocol failures */

	{ "etm_magic_bad", FMD_TYPE_UINT64,
		"ETM msgs w/ invalid magic num" },
	{ "etm_ver_bad", FMD_TYPE_UINT64,
		"ETM msgs w/ invalid protocol version" },
	{ "etm_msgtype_bad", FMD_TYPE_UINT64,
		"ETM msgs w/ invalid message type" },
	{ "etm_subtype_bad", FMD_TYPE_UINT64,
		"ETM msgs w/ invalid sub type" },
	{ "etm_xid_bad", FMD_TYPE_UINT64,
		"ETM msgs w/ unmatched xid" },
	{ "etm_fmaeventlen_bad", FMD_TYPE_UINT64,
		"ETM msgs w/ invalid FMA event length" },
	{ "etm_respcode_bad", FMD_TYPE_UINT64,
		"ETM msgs w/ invalid response code" },
	{ "etm_timeout_bad", FMD_TYPE_UINT64,
		"ETM msgs w/ invalid timeout value" },
	{ "etm_evlens_bad", FMD_TYPE_UINT64,
		"ETM msgs w/ too many event lengths" },

	/* IO operation failures */

	{ "etm_xport_wr_fail", FMD_TYPE_UINT64,
		"xport write failures" },
	{ "etm_xport_rd_fail", FMD_TYPE_UINT64,
		"xport read failures" },
	{ "etm_xport_pk_fail", FMD_TYPE_UINT64,
		"xport peek failures" },

	/* IO operation retries */

	{ "etm_xport_wr_retry", FMD_TYPE_UINT64,
		"xport write retries" },
	{ "etm_xport_rd_retry", FMD_TYPE_UINT64,
		"xport read retries" },
	{ "etm_xport_pk_retry", FMD_TYPE_UINT64,
		"xport peek retries" },

	/* system and library failures */

	{ "etm_os_nvlist_pack_fail", FMD_TYPE_UINT64,
		"nvlist_pack failures" },
	{ "etm_os_nvlist_unpack_fail", FMD_TYPE_UINT64,
		"nvlist_unpack failures" },
	{ "etm_os_nvlist_size_fail", FMD_TYPE_UINT64,
		"nvlist_size failures" },
	{ "etm_os_pthread_create_fail", FMD_TYPE_UINT64,
		"pthread_create failures" },

	/* transport API failures */

	{ "etm_xport_get_ev_addrv_fail", FMD_TYPE_UINT64,
		"xport get event addrv API failures" },
	{ "etm_xport_open_fail", FMD_TYPE_UINT64,
		"xport open API failures" },
	{ "etm_xport_close_fail", FMD_TYPE_UINT64,
		"xport close API failures" },
	{ "etm_xport_accept_fail", FMD_TYPE_UINT64,
		"xport accept API failures" },
	{ "etm_xport_open_retry", FMD_TYPE_UINT64,
		"xport open API retries" },

	/* FMD entry point bad arguments */

	{ "etm_fmd_init_badargs", FMD_TYPE_UINT64,
	    "bad arguments from fmd_init entry point" },
	{ "etm_fmd_fini_badargs", FMD_TYPE_UINT64,
	    "bad arguments from fmd_fini entry point" },

	/* Alert logging errors */

	{ "etm_log_err", FMD_TYPE_UINT64,
		"failed to log message to log(7D)" },
	{ "etm_msg_err", FMD_TYPE_UINT64,
		"failed to log message to sysmsg(7D)" },

	/* miscellaneous stats */

	{ "etm_reset_xport", FMD_TYPE_UINT64,
		"xport resets after xport API failure" }
};


/*
 * -------------------- global data for Root ldom-------------------------
 */

ldom_hdl_t
*etm_lhp = NULL;		/* ldom pointer */

static void *etm_dl_hdl = (void *)NULL;
static const char *etm_dl_path = "libds.so.1";
static int etm_dl_mode = (RTLD_NOW | RTLD_LOCAL);

static int(*etm_ds_svc_reg)(ds_capability_t *cap, ds_ops_t *ops) =
	(int (*)(ds_capability_t *cap, ds_ops_t *ops))NULL;
static int(*etm_ds_clnt_reg)(ds_capability_t *cap, ds_ops_t *ops) =
	(int (*)(ds_capability_t *cap, ds_ops_t *ops))NULL;
static int(*etm_ds_send_msg)(ds_hdl_t hdl, void *buf, size_t buflen) =
	(int (*)(ds_hdl_t hdl, void *buf, size_t buflen))NULL;
static int(*etm_ds_recv_msg)(ds_hdl_t hdl, void *buf, size_t buflen,
    size_t *msglen) =
	(int (*)(ds_hdl_t hdl, void *buf, size_t buflen, size_t *msglen))NULL;
static int (*etm_ds_fini)(void) = (int (*)(void))NULL;

static pthread_mutex_t
iosvc_list_lock =  PTHREAD_MUTEX_INITIALIZER;

static pthread_t
etm_async_e_tid = 0;	/* thread id of io svc async event handler */

static etm_proto_v1_ev_hdr_t iosvc_hdr = {
	ETM_PROTO_MAGIC_NUM,	/* magic number */
	ETM_PROTO_V1,		/* default to V1, not checked */
	ETM_MSG_TYPE_FMA_EVENT,	/* Root Domain inteoduces only FMA events */
	0,			/* sub-type */
	0,			/* pad */
	0,			/* add the xid at the Q send time */
	ETM_PROTO_V1_TIMEOUT_NONE,
	0			/* ev_lens, 0-termed, after 1 FMA event */
};

/*
 * static iosvc_list
 */
static etm_iosvc_t iosvc_list[NUM_OF_ROOT_DOMAINS] = {
	{"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0},
	{"", 0}, {"", 0}
};

static etm_iosvc_t io_svc = {
	"\0",				/* ldom_name */
	PTHREAD_COND_INITIALIZER,	/* nudges */
	PTHREAD_MUTEX_INITIALIZER,	/* protects the iosvc msg Q */
	NULL,				/* iosvc msg Q head */
	NULL,				/* iosvc msg Q tail */
	0,				/* msg Q current length */
	100,				/* msg Q max length */
	0,				/* current transaction id */
	0,				/* xid of last event posted to FMD */
	DS_INVALID_HDL,			/* DS handle */
	NULL,				/* fmd xprt handle */
	0,				/* tid 4 send to remote RootDomain */
	0,				/* tid 4 recv from remote RootDomain */
	PTHREAD_COND_INITIALIZER,	/* nudges etm_send_to_remote_root */
	PTHREAD_MUTEX_INITIALIZER,	/* protects msg_ack_cv */
	0,				/* send/recv threads are not dying */
	0,				/* flag for start sending msg Q */
	0				/* indicate if the ACK has come  */
};
etm_iosvc_t *io_svc_p = &io_svc;


static uint32_t
flags;					/* flags for fmd_xprt_open */

static etm_async_event_ele_t
async_event_q[ASYNC_EVENT_Q_SIZE];	/* holds the async events */

static uint32_t
etm_async_q_head = 0;		/* ptr to cur head of async event queue */

static uint32_t
etm_async_q_tail = 0;		/* ptr to cur tail of async event queue */

static uint32_t
etm_async_q_cur_len = 0;	/* cur length (ele cnt) of async event queue */

static uint32_t
etm_async_q_max_len = ASYNC_EVENT_Q_SIZE;
				/* max length (ele cnt) of async event queue */

static pthread_cond_t
etm_async_event_q_cv = PTHREAD_COND_INITIALIZER;
				/* nudges  async event handler */

static pthread_mutex_t
etm_async_event_q_lock = PTHREAD_MUTEX_INITIALIZER;
				/* protects async event q */

static ds_ver_t
etm_iosvc_vers[] = { { 1, 0} };

#define	ETM_NVERS	(sizeof (etm_iosvc_vers) / sizeof (ds_ver_t))

static ds_capability_t
iosvc_caps = {
	"ETM",				/* svc_id */
	etm_iosvc_vers,			/* vers */
	ETM_NVERS			/* number of vers */
};

static void
etm_iosvc_reg_handler(ds_hdl_t hdl, ds_cb_arg_t arg, ds_ver_t *ver,
    ds_domain_hdl_t did);

static void
etm_iosvc_unreg_handler(ds_hdl_t hdl, ds_cb_arg_t arg);

static ds_ops_t
iosvc_ops = {
	etm_iosvc_reg_handler,		/* ds_reg_cb */
	etm_iosvc_unreg_handler,	/* ds_unreg_cb */
	NULL,				/* ds_data_cb */
	NULL				/* cb_arg */
};


/*
 * -------------------------- support functions ------------------------------
 */

/*
 * Design_Note:	Each failure worth reporting to FMD should be done using
 *		a single call to fmd_hdl_error() as it logs an FMA event
 *		for each call. Also be aware that all the fmd_hdl_*()
 *		format strings currently use platform specific *printf()
 *		routines; so "%p" under Solaris does not prepend "0x" to
 *		the outputted hex digits, while Linux and VxWorks do.
 */


/*
 * etm_show_time - display the current time of day (for debugging) using
 *		the given FMD module handle and annotation string
 */

static void
etm_show_time(fmd_hdl_t *hdl, char *note_str)
{
	struct timeval		tmv;		/* timeval */

	(void) gettimeofday(&tmv, NULL);
	fmd_hdl_debug(hdl, "info: %s: cur Unix Epoch time %d.%06d\n",
	    note_str, tmv.tv_sec, tmv.tv_usec);

} /* etm_show_time() */

/*
 * etm_hexdump - hexdump the given buffer (for debugging) using
 *		the given FMD module handle
 */

static void
etm_hexdump(fmd_hdl_t *hdl, void *buf, size_t byte_cnt)
{
	uint8_t		*bp;		/* byte ptr */
	int		i, j;		/* index */
	char		cb[80];		/* char buf */
	unsigned int	n;		/* a byte of data for sprintf() */

	bp = buf;
	j = 0;

	/*
	 * Design_Note:	fmd_hdl_debug() auto adds a newline if missing;
	 *		hence cb exists to accumulate a longer string.
	 */

	for (i = 1; i <= byte_cnt; i++) {
		n = *bp++;
		(void) sprintf(&cb[j], "%2.2x ", n);
		j += 3;
		/* add a newline every 16 bytes or at the buffer's end */
		if (((i % 16) == 0) || (i >= byte_cnt)) {
			cb[j-1] = '\0';
			fmd_hdl_debug(hdl, "%s\n", cb);
			j = 0;
		}
	} /* for each byte in the buffer */

} /* etm_hexdump() */

/*
 * etm_sleep - sleep the caller for the given number of seconds,
 *		return 0 or -errno value
 *
 * Design_Note:	To avoid interfering with FMD's signal mask (SIGALRM)
 *		do not use [Solaris] sleep(3C) and instead use
 *		pthread_cond_wait() or nanosleep(), both of which
 *		are POSIX spec-ed to leave signal masks alone.
 *		This is needed for Solaris and Linux (domain and SP).
 */

static int
etm_sleep(unsigned sleep_sec)
{
	struct timespec	tms;	/* for nanosleep() */

	tms.tv_sec = sleep_sec;
	tms.tv_nsec = 0;

	if (nanosleep(&tms, NULL) < 0) {
		/* errno assumed set by above call */
		return (-errno);
	}
	return (0);

} /* etm_sleep() */

/*
 * etm_conn_open - open a connection to the given transport address,
 *		return 0 and the opened connection handle
 *		or -errno value
 *
 * caveats:	the err_substr is used in failure cases for calling
 *		fmd_hdl_error()
 */

static int
etm_conn_open(fmd_hdl_t *hdl, char *err_substr,
    etm_xport_addr_t addr, etm_xport_conn_t *connp)
{
	etm_xport_conn_t	conn;	/* connection to return */
	int			nev;	/* -errno value */

	if ((conn = etm_xport_open(hdl, addr)) == NULL) {
		nev = (-errno);
		fmd_hdl_error(hdl, "error: %s: errno %d\n",
		    err_substr, errno);
		etm_stats.etm_xport_open_fail.fmds_value.ui64++;
		return (nev);
	} else {
		*connp = conn;
		return (0);
	}
} /* etm_conn_open() */

/*
 * etm_conn_close - close the given connection,
 *		return 0 or -errno value
 *
 * caveats:	the err_substr is used in failure cases for calling
 *		fmd_hdl_error()
 */

static int
etm_conn_close(fmd_hdl_t *hdl, char *err_substr, etm_xport_conn_t conn)
{
	int	nev;	/* -errno value */

	if (etm_xport_close(hdl, conn) == NULL) {
		nev = (-errno);
		fmd_hdl_error(hdl, "warning: %s: errno %d\n",
		    err_substr, errno);
		etm_stats.etm_xport_close_fail.fmds_value.ui64++;
		return (nev);
	} else {
		return (0);
	}
} /* etm_conn_close() */

/*
 * etm_io_op - perform an IO operation on the given connection
 *		with the given buffer,
 *		accommodating MTU size and retrying op if needed,
 *		return how many bytes actually done by the op
 *		or -errno value
 *
 * caveats:	the err_substr is used in failure cases for calling
 *		fmd_hdl_error()
 */

static ssize_t
etm_io_op(fmd_hdl_t *hdl, char *err_substr, etm_xport_conn_t conn,
    void *buf, size_t byte_cnt, int io_op)
{
	ssize_t		rv;		/* ret val / byte count */
	ssize_t		n;		/* gen use */
	uint8_t		*datap;		/* ptr to data */
	size_t		mtu_sz;		/* MTU size in bytes */
	int		(*io_func_ptr)(fmd_hdl_t *, etm_xport_conn_t,
	    void *, size_t);
	size_t		io_sz;		/* byte count for io_func_ptr */
	int		try_cnt;	/* number of tries done */
	int		sleep_sec;	/* exp backoff sleep period in sec */
	int		sleep_rv;	/* ret val from sleeping */
	fmd_stat_t	io_retry_stat;	/* IO retry stat to update */
	fmd_stat_t	io_fail_stat;	/* IO failure stat to update */

	if ((conn == NULL) || (buf == NULL)) {
		return (-EINVAL);
	}
	switch (io_op) {
	case ETM_IO_OP_RD:
		io_func_ptr = etm_xport_read;
		io_retry_stat = etm_stats.etm_xport_rd_retry;
		io_fail_stat = etm_stats.etm_xport_rd_fail;
		break;
	case ETM_IO_OP_WR:
		io_func_ptr = etm_xport_write;
		io_retry_stat = etm_stats.etm_xport_wr_retry;
		io_fail_stat = etm_stats.etm_xport_wr_fail;
		break;
	default:
		return (-EINVAL);
	}
	if (byte_cnt == 0) {
		return (byte_cnt);	/* nop */
	}

	/* obtain [current] MTU size */

	if ((n = etm_xport_get_opt(hdl, conn, ETM_XPORT_OPT_MTU_SZ)) < 0) {
		mtu_sz = ETM_XPORT_MTU_SZ_DEF;
	} else {
		mtu_sz = n;
	}

	/* loop until all IO done, try limit exceeded, or real failure */

	rv = 0;
	datap = buf;
	while (rv < byte_cnt) {
		io_sz = MIN((byte_cnt - rv), mtu_sz);
		try_cnt = 0;
		sleep_sec = 0;

		/* when give up, return -errno value even if partly done */

		while ((n = (*io_func_ptr)(hdl, conn, datap, io_sz)) ==
		    (-EAGAIN)) {
			try_cnt++;
			if (try_cnt > ETM_TRY_MAX_CNT) {
				rv = n;
				goto func_ret;
			}
			if (etm_is_dying) {
				rv = (-EINTR);
				goto func_ret;
			}
			if ((sleep_rv = etm_sleep(sleep_sec)) < 0) {
				rv = sleep_rv;
				goto func_ret;
			}
			sleep_sec = ((sleep_sec == 0) ? 1 :
			    (sleep_sec * ETM_TRY_BACKOFF_RATE));
			sleep_sec = MIN(sleep_sec, ETM_TRY_BACKOFF_CAP);
			io_retry_stat.fmds_value.ui64++;
			if (etm_debug_lvl >= 1) {
				fmd_hdl_debug(hdl, "info: retrying io op %d "
				    "due to EAGAIN\n", io_op);
			}
		} /* while trying the io operation */

		if (etm_is_dying) {
			rv = (-EINTR);
			goto func_ret;
		}
		if (n < 0) {
			rv = n;
			goto func_ret;
		}
		/* avoid spinning CPU when given 0 bytes but no error */
		if (n == 0) {
			if ((sleep_rv = etm_sleep(ETM_SLEEP_QUIK)) < 0) {
				rv = sleep_rv;
				goto func_ret;
			}
		}
		rv += n;
		datap += n;
	} /* while still have more data */

func_ret:

	if (rv < 0) {
		io_fail_stat.fmds_value.ui64++;
		fmd_hdl_debug(hdl, "error: %s: errno %d\n",
		    err_substr, (int)(-rv));
	}
	if (etm_debug_lvl >= 3) {
		fmd_hdl_debug(hdl, "info: io op %d ret %d of %d\n",
		    io_op, (int)rv, (int)byte_cnt);
	}
	return (rv);

} /* etm_io_op() */

/*
 * etm_magic_read - read the magic number of an ETM message header
 *		from the given connection into the given buffer,
 *		return 0 or -errno value
 *
 * Design_Note:	This routine is intended to help protect ETM from protocol
 *		framing errors as might be caused by an SP reset / crash in
 *		the middle of an ETM message send; the connection will be
 *		read from for as many bytes as needed until the magic number
 *		is found using a sliding buffer for comparisons.
 */

static int
etm_magic_read(fmd_hdl_t *hdl, etm_xport_conn_t conn, uint32_t *magic_ptr)
{
	int		rv;		/* ret val */
	uint32_t	magic_num;	/* magic number */
	int		byte_cnt;	/* count of bytes read */
	uint8_t		buf5[4+1];	/* sliding input buffer */
	int		i, j;		/* indices into buf5 */
	ssize_t		n;		/* gen use */
	uint8_t		drop_buf[1024];	/* dropped bytes buffer */

	rv = 0;		/* assume success */
	magic_num = 0;
	byte_cnt = 0;
	j = 0;

	/* magic number bytes are sent in network (big endian) order */

	while (magic_num != ETM_PROTO_MAGIC_NUM) {
		if ((n = etm_io_op(hdl, "bad io read on magic",
		    conn, &buf5[j], 1, ETM_IO_OP_RD)) < 0) {
			rv = n;
			goto func_ret;
		}
		byte_cnt++;
		j = MIN((j + 1), sizeof (magic_num));
		if (byte_cnt < sizeof (magic_num)) {
			continue;
		}

		if (byte_cnt > sizeof (magic_num)) {
			etm_stats.etm_magic_drop_bytes.fmds_value.ui64++;
			i = MIN(byte_cnt - j - 1, sizeof (drop_buf) - 1);
			drop_buf[i] = buf5[0];
			for (i = 0; i < j; i++) {
				buf5[i] = buf5[i+1];
			} /* for sliding the buffer contents */
		}
		(void) memcpy(&magic_num, &buf5[0], sizeof (magic_num));
		magic_num = ntohl(magic_num);
	} /* for reading bytes until find magic number */

func_ret:

	if (byte_cnt != sizeof (magic_num)) {
		fmd_hdl_debug(hdl, "warning: bad proto frame "
		    "implies corrupt/lost msg(s)\n");
	}
	if ((byte_cnt > sizeof (magic_num)) && (etm_debug_lvl >= 2)) {
		i = MIN(byte_cnt - sizeof (magic_num), sizeof (drop_buf));
		fmd_hdl_debug(hdl, "info: magic drop hexdump "
		    "first %d of %d bytes:\n", i,
		    byte_cnt - sizeof (magic_num));
		etm_hexdump(hdl, drop_buf, i);
	}

	if (rv == 0) {
		*magic_ptr = magic_num;
	}
	return (rv);

} /* etm_magic_read() */

/*
 * etm_hdr_read - allocate, read, and validate a [variable sized]
 *		ETM message header from the given connection,
 *		return the allocated ETM message header
 *		(which is guaranteed to be large enough to reuse as a
 *		RESPONSE msg hdr) and its size
 *		or NULL and set errno on failure
 */

static void *
etm_hdr_read(fmd_hdl_t *hdl, etm_xport_conn_t conn, size_t *szp)
{
	uint8_t			*hdrp;		/* ptr to header to return */
	size_t			hdr_sz;		/* sizeof *hdrp */
	etm_proto_v1_pp_t	pp;		/* protocol preamble */
	etm_proto_v1_ev_hdr_t	*ev_hdrp;	/* for FMA_EVENT msg */
	etm_proto_v1_ctl_hdr_t	*ctl_hdrp;	/* for CONTROL msg */
	etm_proto_v1_resp_hdr_t *resp_hdrp;	/* for RESPONSE msg */
	etm_proto_v3_sa_hdr_t	*sa_hdrp;	/* for ALERT msg */
	uint32_t		*lenp;		/* ptr to FMA event length */
	ssize_t			i, n;		/* gen use */
	uint8_t	misc_buf[ETM_MISC_BUF_SZ];	/* for var sized hdrs */
	int			dummy_int;	/* dummy var to appease lint */

	hdrp = NULL; hdr_sz = 0;

	/* read the magic number which starts the protocol preamble */

	if ((n = etm_magic_read(hdl, conn, &pp.pp_magic_num)) < 0) {
		errno = (-n);
		etm_stats.etm_magic_bad.fmds_value.ui64++;
		return (NULL);
	}

	/* read the rest of the protocol preamble all at once */

	if ((n = etm_io_op(hdl, "bad io read on preamble",
	    conn, &pp.pp_proto_ver, sizeof (pp) - sizeof (pp.pp_magic_num),
	    ETM_IO_OP_RD)) < 0) {
		errno = (-n);
		return (NULL);
	}

	/*
	 * Design_Note:	The magic number was already network decoded; but
	 *		some other preamble fields also need to be decoded,
	 *		specifically pp_xid and pp_timeout. The rest of the
	 *		preamble fields are byte sized and hence need no
	 *		decoding.
	 */

	pp.pp_xid = ntohl(pp.pp_xid);
	pp.pp_timeout = ntohl(pp.pp_timeout);

	/* sanity check the header as best we can */

	if ((pp.pp_proto_ver < ETM_PROTO_V1) ||
	    (pp.pp_proto_ver > ETM_PROTO_V3)) {
		fmd_hdl_error(hdl, "error: bad proto ver %d\n",
		    (int)pp.pp_proto_ver);
		errno = EPROTO;
		etm_stats.etm_ver_bad.fmds_value.ui64++;
		return (NULL);
	}

	dummy_int = pp.pp_msg_type;
	if ((dummy_int <= ETM_MSG_TYPE_TOO_LOW) ||
	    (dummy_int >= ETM_MSG_TYPE_TOO_BIG)) {
		fmd_hdl_error(hdl, "error: bad msg type %d", dummy_int);
		errno = EBADMSG;
		etm_stats.etm_msgtype_bad.fmds_value.ui64++;
		return (NULL);
	}

	/* handle [var sized] hdrs for FMA_EVENT, CONTROL, RESPONSE msgs */

	if (pp.pp_msg_type == ETM_MSG_TYPE_FMA_EVENT) {

		ev_hdrp = (void*)&misc_buf[0];
		hdr_sz = sizeof (*ev_hdrp);
		(void) memcpy(&ev_hdrp->ev_pp, &pp, sizeof (pp));

		/* sanity check the header's timeout */

		if ((ev_hdrp->ev_pp.pp_proto_ver == ETM_PROTO_V1) &&
		    (ev_hdrp->ev_pp.pp_timeout != ETM_PROTO_V1_TIMEOUT_NONE)) {
			errno = ETIME;
			etm_stats.etm_timeout_bad.fmds_value.ui64++;
			return (NULL);
		}

		/* get all FMA event lengths from the header */

		lenp = (uint32_t *)&ev_hdrp->ev_lens[0]; lenp--;
		i = -1;	/* cnt of length entries preceding 0 */
		do {
			i++; lenp++;
			if ((sizeof (*ev_hdrp) + (i * sizeof (*lenp))) >=
			    ETM_MISC_BUF_SZ) {
				errno = E2BIG;	/* ridiculous size */
				etm_stats.etm_evlens_bad.fmds_value.ui64++;
				return (NULL);
			}
			if ((n = etm_io_op(hdl, "bad io read on event len",
			    conn, lenp, sizeof (*lenp), ETM_IO_OP_RD)) < 0) {
				errno = (-n);
				return (NULL);
			}
			*lenp = ntohl(*lenp);

		} while (*lenp != 0);
		i += 0; /* first len already counted by sizeof(ev_hdr) */
		hdr_sz += (i * sizeof (*lenp));

		etm_stats.etm_rd_hdr_fmaevent.fmds_value.ui64++;

	} else if (pp.pp_msg_type == ETM_MSG_TYPE_CONTROL) {

		ctl_hdrp = (void*)&misc_buf[0];
		hdr_sz = sizeof (*ctl_hdrp);
		(void) memcpy(&ctl_hdrp->ctl_pp, &pp, sizeof (pp));

		/* sanity check the header's sub type (control selector) */

		if ((ctl_hdrp->ctl_pp.pp_sub_type <= ETM_CTL_SEL_TOO_LOW) ||
		    (ctl_hdrp->ctl_pp.pp_sub_type >= ETM_CTL_SEL_TOO_BIG)) {
			fmd_hdl_error(hdl, "error: bad ctl sub type %d\n",
			    (int)ctl_hdrp->ctl_pp.pp_sub_type);
			errno = EBADMSG;
			etm_stats.etm_subtype_bad.fmds_value.ui64++;
			return (NULL);
		}

		/* get the control length */

		if ((n = etm_io_op(hdl, "bad io read on ctl len",
		    conn, &ctl_hdrp->ctl_len, sizeof (ctl_hdrp->ctl_len),
		    ETM_IO_OP_RD)) < 0) {
			errno = (-n);
			return (NULL);
		}

		ctl_hdrp->ctl_len = ntohl(ctl_hdrp->ctl_len);

		etm_stats.etm_rd_hdr_control.fmds_value.ui64++;

	} else if (pp.pp_msg_type == ETM_MSG_TYPE_RESPONSE) {

		resp_hdrp = (void*)&misc_buf[0];
		hdr_sz = sizeof (*resp_hdrp);
		(void) memcpy(&resp_hdrp->resp_pp, &pp, sizeof (pp));

		/* sanity check the header's timeout */

		if (resp_hdrp->resp_pp.pp_timeout !=
		    ETM_PROTO_V1_TIMEOUT_NONE) {
			errno = ETIME;
			etm_stats.etm_timeout_bad.fmds_value.ui64++;
			return (NULL);
		}

		/* get the response code and length */

		if ((n = etm_io_op(hdl, "bad io read on resp code+len",
		    conn, &resp_hdrp->resp_code,
		    sizeof (resp_hdrp->resp_code)
		    + sizeof (resp_hdrp->resp_len),
		    ETM_IO_OP_RD)) < 0) {
			errno = (-n);
			return (NULL);
		}

		resp_hdrp->resp_code = ntohl(resp_hdrp->resp_code);
		resp_hdrp->resp_len = ntohl(resp_hdrp->resp_len);

		etm_stats.etm_rd_hdr_response.fmds_value.ui64++;

	} else if (pp.pp_msg_type == ETM_MSG_TYPE_ALERT) {

		sa_hdrp = (void*)&misc_buf[0];
		hdr_sz = sizeof (*sa_hdrp);
		(void) memcpy(&sa_hdrp->sa_pp, &pp, sizeof (pp));

		/* sanity check the header's protocol version */

		if (sa_hdrp->sa_pp.pp_proto_ver != ETM_PROTO_V3) {
			errno = EPROTO;
			etm_stats.etm_ver_bad.fmds_value.ui64++;
			return (NULL);
		}

		/* get the priority and length */

		if ((n = etm_io_op(hdl, "bad io read on sa priority+len",
		    conn, &sa_hdrp->sa_priority,
		    sizeof (sa_hdrp->sa_priority)
		    + sizeof (sa_hdrp->sa_len),
		    ETM_IO_OP_RD)) < 0) {
			errno = (-n);
			return (NULL);
		}

		sa_hdrp->sa_priority = ntohl(sa_hdrp->sa_priority);
		sa_hdrp->sa_len = ntohl(sa_hdrp->sa_len);

		etm_stats.etm_rd_hdr_alert.fmds_value.ui64++;

	} /* whether we have FMA_EVENT, ALERT, CONTROL, or RESPONSE msg */

	/*
	 * choose a header size that allows hdr reuse for RESPONSE msgs,
	 * allocate and populate the message header, and
	 * return alloc size to caller for later free of hdrp
	 */

	hdr_sz = MAX(hdr_sz, sizeof (*resp_hdrp));
	hdrp = fmd_hdl_zalloc(hdl, hdr_sz, FMD_SLEEP);
	(void) memcpy(hdrp, misc_buf, hdr_sz);

	if (etm_debug_lvl >= 3) {
		fmd_hdl_debug(hdl, "info: msg hdr hexdump %d bytes:\n", hdr_sz);
		etm_hexdump(hdl, hdrp, hdr_sz);
	}
	*szp = hdr_sz;
	return (hdrp);

} /* etm_hdr_read() */

/*
 * etm_hdr_write - create and write a [variable sized] ETM message header
 *		to the given connection appropriate for the given FMA event
 *		and type of nvlist encoding,
 *		return the allocated ETM message header and its size
 *		or NULL and set errno on failure
 */

static void*
etm_hdr_write(fmd_hdl_t *hdl, etm_xport_conn_t conn, nvlist_t *evp,
    int encoding, size_t *szp)
{
	etm_proto_v1_ev_hdr_t	*hdrp;		/* for FMA_EVENT msg */
	size_t			hdr_sz;		/* sizeof *hdrp */
	uint32_t		*lenp;		/* ptr to FMA event length */
	size_t			evsz;		/* packed FMA event size */
	ssize_t			n;		/* gen use */

	/* allocate and populate the message header for 1 FMA event */

	hdr_sz = sizeof (*hdrp) + (1 * sizeof (hdrp->ev_lens[0]));

	hdrp = fmd_hdl_zalloc(hdl, hdr_sz, FMD_SLEEP);

	/*
	 * Design_Note: Although the ETM protocol supports it, we do not (yet)
	 *		want responses/ACKs on FMA events that we send. All
	 *		such messages are sent with ETM_PROTO_V1_TIMEOUT_NONE.
	 */

	hdrp->ev_pp.pp_magic_num = ETM_PROTO_MAGIC_NUM;
	hdrp->ev_pp.pp_magic_num = htonl(hdrp->ev_pp.pp_magic_num);
	hdrp->ev_pp.pp_proto_ver = ETM_PROTO_V1;
	hdrp->ev_pp.pp_msg_type = ETM_MSG_TYPE_FMA_EVENT;
	hdrp->ev_pp.pp_sub_type = 0;
	hdrp->ev_pp.pp_rsvd_pad = 0;
	hdrp->ev_pp.pp_xid = etm_xid_cur;
	hdrp->ev_pp.pp_xid = htonl(hdrp->ev_pp.pp_xid);
	etm_xid_cur += ETM_XID_INC;
	hdrp->ev_pp.pp_timeout = ETM_PROTO_V1_TIMEOUT_NONE;
	hdrp->ev_pp.pp_timeout = htonl(hdrp->ev_pp.pp_timeout);

	lenp = &hdrp->ev_lens[0];

	if ((n = nvlist_size(evp, &evsz, encoding)) != 0) {
		errno = n;
		fmd_hdl_free(hdl, hdrp, hdr_sz);
		etm_stats.etm_os_nvlist_size_fail.fmds_value.ui64++;
		return (NULL);
	}

	/* indicate 1 FMA event, network encode its length, and 0-terminate */

	etm_stats.etm_wr_max_ev_per_msg.fmds_value.ui64 = 1;

	*lenp = evsz; *lenp = htonl(*lenp); lenp++;
	*lenp = 0; *lenp = htonl(*lenp); lenp++;

	/*
	 * write the network encoded header to the transport, and
	 * return alloc size to caller for later free
	 */

	if ((n = etm_io_op(hdl, "bad io write on event hdr",
	    conn, hdrp, hdr_sz, ETM_IO_OP_WR)) < 0) {
		errno = (-n);
		fmd_hdl_free(hdl, hdrp, hdr_sz);
		return (NULL);
	}

	*szp = hdr_sz;
	return (hdrp);

} /* etm_hdr_write() */

/*
 * etm_post_to_fmd - post the given FMA event to FMD
 *			via a FMD transport API call,
 *			return 0 or -errno value
 *
 * caveats:	the FMA event (evp) is freed by FMD,
 *		thus callers of this function should
 *		immediately discard any ptr they have to the
 *		nvlist without freeing or dereferencing it
 */

static int
etm_post_to_fmd(fmd_hdl_t *hdl, fmd_xprt_t *fmd_xprt, nvlist_t *evp)
{
	ssize_t			ev_sz;		/* sizeof *evp */

	(void) nvlist_size(evp, (size_t *)&ev_sz, NV_ENCODE_XDR);

	if (etm_debug_lvl >= 2) {
		etm_show_time(hdl, "ante ev post");
	}
	fmd_xprt_post(hdl, fmd_xprt, evp, 0);
	etm_stats.etm_wr_fmd_fmaevent.fmds_value.ui64++;
	etm_stats.etm_wr_fmd_bytes.fmds_value.ui64 += ev_sz;
	if (etm_debug_lvl >= 1) {
		fmd_hdl_debug(hdl, "info: event %p post ok to FMD\n", evp);
	}
	if (etm_debug_lvl >= 2) {
		etm_show_time(hdl, "post ev post");
	}
	return (0);

} /* etm_post_to_fmd() */

/*
 * Ideally we would just use syslog(3C) for outputting our messages.
 * Unfortunately, as this module is running within the FMA daemon context,
 * that would create the situation where this module's openlog() would
 * have the monopoly on syslog(3C) for the daemon and all its modules.
 * To avoid that situation, this module uses the same logic as the
 * syslog-msgs FM module to directly call into the log(7D) and sysmsg(7D)
 * devices for syslog and console.
 */

static int
etm_post_to_syslog(fmd_hdl_t *hdl, uint32_t priority, uint32_t body_sz,
    uint8_t *body_buf)
{
	char		*sysmessage;	/* Formatted message */
	size_t		formatlen;	/* maximum length of sysmessage */
	struct strbuf	ctl, dat;	/* structs pushed to the logfd */
	uint32_t	msgid;		/* syslog message ID number */

	if ((syslog_file == 0) && (syslog_cons == 0)) {
		return (0);
	}

	if (etm_debug_lvl >= 2) {
		etm_show_time(hdl, "ante syslog post");
	}

	formatlen = body_sz + 64; /* +64 for prefix strings added below */
	sysmessage = fmd_hdl_zalloc(hdl, formatlen, FMD_SLEEP);

	if (syslog_file) {
		STRLOG_MAKE_MSGID(body_buf, msgid);
		(void) snprintf(sysmessage, formatlen,
		    "SC Alert: [ID %u FACILITY_AND_PRIORITY] %s", msgid,
		    body_buf);

		syslog_ctl.pri = syslog_facility | priority;

		ctl.buf = (void *)&syslog_ctl;
		ctl.len = sizeof (syslog_ctl);

		dat.buf = sysmessage;
		dat.len = strlen(sysmessage) + 1;

		if (putmsg(syslog_logfd, &ctl, &dat, 0) != 0) {
			fmd_hdl_debug(hdl, "putmsg failed: %s\n",
			    strerror(errno));
			etm_stats.etm_log_err.fmds_value.ui64++;
		}
	}

	if (syslog_cons) {
		(void) snprintf(sysmessage, formatlen,
		    "SC Alert: %s\r\n", body_buf);

		dat.buf = sysmessage;
		dat.len = strlen(sysmessage) + 1;

		if (write(syslog_msgfd, dat.buf, dat.len) != dat.len) {
			fmd_hdl_debug(hdl, "write failed: %s\n",
			    strerror(errno));
			etm_stats.etm_msg_err.fmds_value.ui64++;
		}
	}

	fmd_hdl_free(hdl, sysmessage, formatlen);

	if (etm_debug_lvl >= 2) {
		etm_show_time(hdl, "post syslog post");
	}

	return (0);
}


/*
 * etm_req_ver_negot - send an ETM control message to the other end requesting
 *			that the ETM protocol version be negotiated/set
 */

static void
etm_req_ver_negot(fmd_hdl_t *hdl)
{
	etm_xport_addr_t	*addrv;		/* default dst addr(s) */
	etm_xport_conn_t	conn;		/* connection to other end */
	etm_proto_v1_ctl_hdr_t	*ctl_hdrp;	/* for CONTROL msg */
	size_t			hdr_sz;		/* sizeof header */
	uint8_t			*body_buf;	/* msg body buffer */
	uint32_t		body_sz;	/* sizeof *body_buf */
	ssize_t			i;		/* gen use */

	/* populate an ETM control msg to send */

	hdr_sz = sizeof (*ctl_hdrp);
	body_sz = (3 + 1);		/* version bytes plus null byte */

	ctl_hdrp = fmd_hdl_zalloc(hdl, hdr_sz + body_sz, FMD_SLEEP);

	ctl_hdrp->ctl_pp.pp_magic_num = htonl(ETM_PROTO_MAGIC_NUM);
	ctl_hdrp->ctl_pp.pp_proto_ver = ETM_PROTO_V1;
	ctl_hdrp->ctl_pp.pp_msg_type = ETM_MSG_TYPE_CONTROL;
	ctl_hdrp->ctl_pp.pp_sub_type = ETM_CTL_SEL_VER_NEGOT_REQ;
	ctl_hdrp->ctl_pp.pp_rsvd_pad = 0;
	etm_xid_ver_negot = etm_xid_cur;
	etm_xid_cur += ETM_XID_INC;
	ctl_hdrp->ctl_pp.pp_xid = htonl(etm_xid_ver_negot);
	ctl_hdrp->ctl_pp.pp_timeout = htonl(ETM_PROTO_V1_TIMEOUT_FOREVER);
	ctl_hdrp->ctl_len = htonl(body_sz);

	body_buf = (void*)&ctl_hdrp->ctl_len;
	body_buf += sizeof (ctl_hdrp->ctl_len);
	*body_buf++ = ETM_PROTO_V3;
	*body_buf++ = ETM_PROTO_V2;
	*body_buf++ = ETM_PROTO_V1;
	*body_buf++ = '\0';

	/*
	 * open and close a connection to send the ETM control msg
	 * to any/all of the default dst addrs
	 */

	if ((addrv = etm_xport_get_ev_addrv(hdl, NULL)) == NULL) {
		fmd_hdl_error(hdl,
		    "error: bad ctl dst addrs errno %d\n", errno);
		etm_stats.etm_xport_get_ev_addrv_fail.fmds_value.ui64++;
		goto func_ret;
	}

	for (i = 0; addrv[i] != NULL; i++) {

		if (etm_conn_open(hdl, "bad conn open during ver negot",
		    addrv[i], &conn) < 0) {
			continue;
		}
		if (etm_io_op(hdl, "bad io write on ctl hdr+body",
		    conn, ctl_hdrp, hdr_sz + body_sz, ETM_IO_OP_WR) >= 0) {
			etm_stats.etm_wr_hdr_control.fmds_value.ui64++;
			etm_stats.etm_wr_body_control.fmds_value.ui64++;
		}
		(void) etm_conn_close(hdl, "bad conn close during ver negot",
		    conn);

	} /* foreach dst addr */

func_ret:

	if (addrv != NULL) {
		etm_xport_free_addrv(hdl, addrv);
	}
	fmd_hdl_free(hdl, ctl_hdrp, hdr_sz + body_sz);

} /* etm_req_ver_negot() */



/*
 * etm_iosvc_msg_enq - add element to tail of ETM iosvc msg queue
 * etm_iosvc_msg_deq - del element from head of ETM iosvc msg  queue
 * need to grab the mutex lock before calling this routine
 * return >0 for success, or -errno value
 */
static int
etm_iosvc_msg_enq(fmd_hdl_t *hdl, etm_iosvc_t *iosvc, etm_iosvc_q_ele_t *msgp)
{
	etm_iosvc_q_ele_t		*newp;	/* ptr to new msg q ele */

	if (iosvc->msg_q_cur_len >= iosvc->msg_q_max_len) {
		fmd_hdl_debug(hdl, "warning: enq to full msg queue\n");
		return (-E2BIG);
	}

	newp = fmd_hdl_zalloc(hdl, sizeof (*newp), FMD_SLEEP);
	(void) memcpy(newp, msgp, sizeof (*newp));
	newp->msg_nextp = NULL;

	if (iosvc->msg_q_cur_len == 0) {
		iosvc->msg_q_head = newp;
	} else {
		iosvc->msg_q_tail->msg_nextp = newp;
	}

	iosvc->msg_q_tail = newp;
	iosvc->msg_q_cur_len++;
	fmd_hdl_debug(hdl, "info: current msg queue length %d\n",
	    iosvc->msg_q_cur_len);

	return (1);

} /* etm_iosvc_msg_enq() */

static int
etm_iosvc_msg_deq(fmd_hdl_t *hdl, etm_iosvc_t *iosvc, etm_iosvc_q_ele_t *msgp)
{
	etm_iosvc_q_ele_t	*oldp;	/* ptr to old msg q ele */

	if (iosvc->msg_q_cur_len == 0) {
		fmd_hdl_debug(hdl, "warning: deq from empty responder queue\n");
		return (-ENOENT);
	}

	(void) memcpy(msgp, iosvc->msg_q_head, sizeof (*msgp));
	msgp->msg_nextp = NULL;

	oldp = iosvc->msg_q_head;
	iosvc->msg_q_head = iosvc->msg_q_head->msg_nextp;

	/*
	 * free the mem alloc-ed in etm_iosvc_msg_enq()
	 */
	fmd_hdl_free(hdl, oldp, sizeof (*oldp));

	iosvc->msg_q_cur_len--;
	if (iosvc->msg_q_cur_len == 0) {
		iosvc->msg_q_tail = NULL;
	}

	return (1);

} /* etm_iosvc_msg_deq() */


/*
 * etm_msg_enq_head():
 * enq the msg to the head of the Q.
 * If the Q is full, drop the msg at the tail then enq the msg at head.
 * need to grab mutex lock iosvc->msg_q_lock before calling this routine.
 */
static void
etm_msg_enq_head(fmd_hdl_t *fmd_hdl, etm_iosvc_t *iosvc,
    etm_iosvc_q_ele_t *msg_ele)
{

	etm_iosvc_q_ele_t	*newp;	/* iosvc msg ele ptr */

	if (iosvc->msg_q_cur_len >= iosvc->msg_q_max_len) {
		fmd_hdl_debug(fmd_hdl,
		    "warning: add to head of a full msg queue."
		    " Drop the msg at the tail\n");
		/*
		 * drop the msg at the tail
		 */
		newp = iosvc->msg_q_head;
		while (newp->msg_nextp != iosvc->msg_q_tail) {
			newp = newp->msg_nextp;
		}

		/*
		 * free the msg in iosvc->msg_q_tail->msg
		 * free the mem pointed to by iosvc->msg_q_tail
		 */
		fmd_hdl_free(fmd_hdl, iosvc->msg_q_tail->msg,
		    iosvc->msg_q_tail->msg_size);
		fmd_hdl_free(fmd_hdl, iosvc->msg_q_tail, sizeof (*newp));
		iosvc->msg_q_tail = newp;
		iosvc->msg_q_tail->msg_nextp = NULL;
		iosvc->msg_q_cur_len--;
	}

	/*
	 * enq the msg to the head
	 */
	newp = fmd_hdl_zalloc(fmd_hdl, sizeof (*newp), FMD_SLEEP);
	(void) memcpy(newp, msg_ele, sizeof (*newp));
	if (iosvc->msg_q_cur_len == 0) {
		newp->msg_nextp = NULL;
		iosvc->msg_q_tail = newp;
	} else {
		newp->msg_nextp = iosvc->msg_q_head;
	}
	iosvc->msg_q_head = newp;
	iosvc->msg_q_cur_len++;
} /* etm_msg_enq_head() */

/*
 * etm_iosvc_cleanup():
 * Clean up an iosvc structure
 * 1) close the fmd_xprt if it has not been closed
 * 2) Terminate the send/revc threads
 * 3) If the clean_msg_q flag is set, free all fma events in the queue. In
 *    addition, if the chpt_remove flag is set, delete the checkpoint so that
 *    the events are not persisted.
 */
static void
etm_iosvc_cleanup(fmd_hdl_t *fmd_hdl, etm_iosvc_t *iosvc, boolean_t clean_msg_q,
    boolean_t ckpt_remove)
{

	etm_iosvc_q_ele_t	msg_ele;	/* io svc msg Q ele */

	iosvc->thr_is_dying = 1;

	iosvc->ds_hdl = DS_INVALID_HDL;
	if (iosvc->fmd_xprt != NULL) {
		fmd_xprt_close(fmd_hdl, iosvc->fmd_xprt);
		iosvc->fmd_xprt = NULL;
	} /* if fmd-xprt has been opened */

	if (iosvc->send_tid != 0) {
		fmd_thr_signal(fmd_hdl, iosvc->send_tid);
		fmd_thr_destroy(fmd_hdl, iosvc->send_tid);
		iosvc->send_tid = 0;
	} /* if io svc send thread was created ok */

	if (iosvc->recv_tid != 0) {
		fmd_thr_signal(fmd_hdl, iosvc->recv_tid);
		fmd_thr_destroy(fmd_hdl, iosvc->recv_tid);
		iosvc->recv_tid = 0;
	} /* if root domain recv thread was created */


	if (clean_msg_q) {
		iosvc->ldom_name[0] = '\0';

		(void) pthread_mutex_lock(&iosvc->msg_q_lock);
		while (iosvc->msg_q_cur_len > 0) {
			(void) etm_iosvc_msg_deq(fmd_hdl, iosvc, &msg_ele);
			if (ckpt_remove == B_TRUE &&
			    msg_ele.ckpt_flag != ETM_CKPT_NOOP) {
				etm_ckpt_remove(fmd_hdl, &msg_ele);
			}
			fmd_hdl_free(fmd_hdl, msg_ele.msg, msg_ele.msg_size);
		}
		(void) pthread_mutex_unlock(&iosvc->msg_q_lock);
	}

	return;

} /* etm_iosvc_cleanup() */

/*
 * etm_iosvc_lookup(using ldom_name or ds_hdl when ldom_name is empty)
 * not found, create one, add to iosvc_list
 */
etm_iosvc_t *
etm_iosvc_lookup(fmd_hdl_t *fmd_hdl, char *ldom_name, ds_hdl_t ds_hdl,
    boolean_t iosvc_create)
{
	uint32_t		i;			/* for loop var */
	int32_t			first_empty_slot = -1;	/* remember that */

	for (i = 0; i < NUM_OF_ROOT_DOMAINS; i++) {
		if (ldom_name[0] == '\0') {
			/*
			 * search by hdl passed in
			 * the only time this is used is at ds_unreg_cb time.
			 * there is no ldom name, only the valid ds_hdl.
			 * find an iosvc with the matching ds_hdl.
			 * ignore the iosvc_create flag, should never need to
			 * create an iosvc for ds_unreg_cb
			 */
			if (ds_hdl == iosvc_list[i].ds_hdl) {
				if (etm_debug_lvl >= 2) {
				fmd_hdl_debug(fmd_hdl,
			    "info: found an iosvc at slot %d w/ ds_hdl %d \n",
				    i, iosvc_list[i].ds_hdl);
				}
				if (iosvc_list[i].ldom_name[0] != '\0')
					if (etm_debug_lvl >= 2) {
						fmd_hdl_debug(fmd_hdl,
				    "info: found an iosvc w/ ldom_name %s \n",
						    iosvc_list[i].ldom_name);
				}
				return (&iosvc_list[i]);
			} else {
				continue;
			}
		} else if (iosvc_list[i].ldom_name[0] != '\0') {
			/*
			 * this is  an non-empty iosvc structure slot
			 */
			if (strcmp(ldom_name, iosvc_list[i].ldom_name) == 0) {
				/*
				 * found an iosvc structure that matches the
				 * passed in ldom_name, return the ptr
				 */
				if (etm_debug_lvl >= 2) {
					fmd_hdl_debug(fmd_hdl, "info: found an "
					    "iosvc at slot %d w/ ds_hdl %d \n",
					    i, iosvc_list[i].ds_hdl);
					fmd_hdl_debug(fmd_hdl, "info: found an "
					    "iosvc w/ ldom_name %s \n",
					    iosvc_list[i].ldom_name);
				}
				return (&iosvc_list[i]);
			} else {
				/*
				 * non-empty slot with no-matching name,
				 * move on to next slot.
				 */
				continue;
			}
		} else {
			/*
			 * found the 1st slot with ldom name being empty
			 * remember the slot #, will be used for creating one
			 */
			if (first_empty_slot == -1) {
				first_empty_slot = i;
			}
		}
	}
	if (iosvc_create == B_TRUE && first_empty_slot >= 0) {
		/*
		 * this is the case we need to add an iosvc at first_empty_slot
		 * for the ldom_name at iosvc_list[first_empty_slot]
		 */
		fmd_hdl_debug(fmd_hdl,
		    "info: create an iosvc with ldom name %s\n",
		    ldom_name);
		i = first_empty_slot;
		(void) memcpy(&iosvc_list[i], &io_svc, sizeof (etm_iosvc_t));
		(void) strcpy(iosvc_list[i].ldom_name, ldom_name);
		fmd_hdl_debug(fmd_hdl, "info: iosvc #%d has ldom name %s\n",
		    i, iosvc_list[i].ldom_name);
		return (&iosvc_list[i]);
	} else {
		return (NULL);
	}

} /* etm_iosvc_lookup() */


/*
 * etm_ckpt_remove:
 * remove the ckpt for the iosvc element
 */
static void
etm_ckpt_remove(fmd_hdl_t *hdl, etm_iosvc_q_ele_t *ele)
{
	int		err;			/* temp error */
	nvlist_t	*evp = NULL;		/* event pointer */
	etm_proto_v1_ev_hdr_t	*hdrp;		/* hdr for FMA_EVENT */
	char		*buf;			/* packed event pointer */

	if ((ele->ckpt_flag == ETM_CKPT_NOOP) ||
	    (etm_ldom_type != LDOM_TYPE_CONTROL)) {
		return;
	}

	/* the pointer to the packed event in the etm message */
	hdrp = (etm_proto_v1_ev_hdr_t *)((ptrdiff_t)ele->msg);
	buf = (char *)((ptrdiff_t)hdrp + sizeof (*hdrp)
	    + (1 * sizeof (hdrp->ev_lens[0])));

	/* unpack it, then uncheckpoited it */
	if ((err = nvlist_unpack(buf, hdrp->ev_lens[0], &evp, 0)) != 0) {
		fmd_hdl_debug(hdl, "failed to unpack event(rc=%d)\n", err);
		return;
	}
	(void) etm_ckpt_delete(hdl, evp);
	nvlist_free(evp);
}

/*
 * etm_send_ds_msg()
 * call ds_send_msg() to send the msg passed in.
 * timedcond_wait for the ACK to come back.
 * if the ACK doesn't come in the specified time, retrun -EAGAIN.
 * other wise, return 1.
 */
int
etm_send_ds_msg(fmd_hdl_t *fmd_hdl, boolean_t ckpt_remove, etm_iosvc_t *iosvc,
    etm_iosvc_q_ele_t *msg_ele, etm_proto_v1_ev_hdr_t *evhdrp)
{
	uint32_t		rc;		/* for return code  */

	struct timeval		tv;
	struct timespec		timeout;


	/*
	 * call ds_send_msg(). Return (-EAGAIN) if not successful
	 */
	if ((rc = (*etm_ds_send_msg)(iosvc->ds_hdl, msg_ele->msg,
	    msg_ele->msg_size)) != 0) {
		fmd_hdl_debug(fmd_hdl, "info: ds_send_msg rc %d xid %d\n",
		    rc, evhdrp->ev_pp.pp_xid);
			return (-EAGAIN);
	}

	/*
	 * wait on the cv for resp msg for cur_send_xid
	 */
	(void *) pthread_mutex_lock(&iosvc->msg_ack_lock);

	(void) gettimeofday(&tv, 0);
	timeout.tv_sec = tv.tv_sec + etm_fma_resp_wait_time;
	timeout.tv_nsec = 0;

	fmd_hdl_debug(fmd_hdl, "info: waiting on msg_ack_cv for ldom %s\n",
	    iosvc->ldom_name);
	rc = pthread_cond_timedwait(&iosvc->msg_ack_cv, &iosvc->msg_ack_lock,
	    &timeout);
	(void *) pthread_mutex_unlock(&iosvc->msg_ack_lock);
	fmd_hdl_debug(fmd_hdl,  "info: msg_ack_cv returns with rc %d\n", rc);

	/*
	 * check to see if ack_ok is non-zero
	 * if non-zero, resp msg has been received
	 */
	if (iosvc->ack_ok != 0) {
		/*
		 * ACK came ok,  this send is successful,
		 * tell the caller ready to send next.
		 * free mem alloc-ed in
		 * etm_pack_ds_msg
		 */
		if (ckpt_remove == B_TRUE &&
		    etm_ldom_type == LDOM_TYPE_CONTROL) {
			etm_ckpt_remove(fmd_hdl, msg_ele);
		}
		fmd_hdl_free(fmd_hdl, msg_ele->msg, msg_ele->msg_size);
		iosvc->cur_send_xid++;
		return (1);
	} else {
		/*
		 * the ACK did not come on time
		 * tell the caller to resend cur_send_xid
		 */
		return (-EAGAIN);
	} /* iosvc->ack_ok != 0 */
} /* etm_send_ds_msg() */

/*
 * both events from fmdo_send entry point and from SP are using the
 * etm_proto_v1_ev_hdr_t as its header and it will be the same header for all
 * ds send/recv msgs.
 * Idealy, we should use the hdr coming with the SP FMA event. Since fmdo_send
 * entry point can be called before FMA events from SP, we can't rely on
 * the SP FMA event hdr. Use the static hdr for packing ds msgs for fmdo_send
 * events.
 * return >0 for success, or -errno value
 * Design assumption: there is one FMA event per ds msg
 */
int
etm_pack_ds_msg(fmd_hdl_t *fmd_hdl, etm_iosvc_t *iosvc,
    etm_proto_v1_ev_hdr_t *ev_hdrp, size_t hdr_sz, nvlist_t *evp,
    etm_pack_msg_type_t msg_type, uint_t ckpt_opt)
{
	etm_proto_v1_ev_hdr_t	*hdrp;		/* for FMA_EVENT msg */
	uint32_t		*lenp;		/* ptr to FMA event length */
	size_t			evsz;		/* packed FMA event size */
	char			*buf;
	uint32_t		rc;		/* for return code  */
	char			*msg;		/* body of msg to be Qed */

	etm_iosvc_q_ele_t	msg_ele;	/* io svc msg Q ele */
	etm_proto_v1_ev_hdr_t	*evhdrp;


	if (ev_hdrp == NULL) {
		hdrp = &iosvc_hdr;
	} else {
		hdrp = ev_hdrp;
	}

	/*
	 * determine hdr_sz if 0, otherwise use the one passed in hdr_sz
	 */

	if (hdr_sz == 0) {
		hdr_sz = sizeof (*hdrp) + (1 * sizeof (hdrp->ev_lens[0]));
	}

	/*
	 * determine evp size
	 */
	(void) nvlist_size(evp, &evsz, NV_ENCODE_XDR);

	/* indicate 1 FMA event, no network encoding, and 0-terminate */
	lenp = &hdrp->ev_lens[0];
	*lenp = evsz;

	/*
	 * now the total of mem needs to be alloc-ed/ds msg size is
	 * hdr_sz + evsz
	 * msg will be freed in etm_send_to_remote_root() after ds_send_msg()
	 */
	msg = fmd_hdl_zalloc(fmd_hdl, hdr_sz + evsz, FMD_SLEEP);


	/*
	 * copy hdr, 0 terminate the length vector,  and then evp
	 */
	(void) memcpy(msg, hdrp, sizeof (*hdrp));
	hdrp = (etm_proto_v1_ev_hdr_t *)((ptrdiff_t)msg);
	lenp = &hdrp->ev_lens[0];
	lenp++;
	*lenp = 0;

	buf = fmd_hdl_zalloc(fmd_hdl, evsz, FMD_SLEEP);
	(void) nvlist_pack(evp, (char **)&buf, &evsz, NV_ENCODE_XDR, 0);
	(void) memcpy(msg + hdr_sz, buf, evsz);
	fmd_hdl_free(fmd_hdl, buf, evsz);

	fmd_hdl_debug(fmd_hdl, "info: hdr_sz= %d evsz= %d in etm_pack_ds_msg"
	    "for ldom %s\n", hdr_sz, evsz, iosvc->ldom_name);
	msg_ele.msg = msg;
	msg_ele.msg_size = hdr_sz + evsz;
	msg_ele.ckpt_flag = ckpt_opt;

	/*
	 * decide what to do with the msg:
	 * if SP ereports (msg_type == SP_MSG), always enq the msg
	 * if not SP ereports, ie, fmd xprt control msgs, enq it _only_ after
	 * resource.fm.xprt.run has been sent (which sets start_sending_Q to 1)
	 */
	if ((msg_type == SP_MSG) ||
	    (msg_type != SP_MSG) && (iosvc->start_sending_Q == 1)) {
		/*
		 * this is the case when the msg needs to be enq-ed
		 */
		(void) pthread_mutex_lock(&iosvc->msg_q_lock);
		rc = etm_iosvc_msg_enq(fmd_hdl, iosvc, &msg_ele);
		if ((rc > 0) && (ckpt_opt & ETM_CKPT_SAVE) &&
		    (etm_ldom_type == LDOM_TYPE_CONTROL)) {
			(void) etm_ckpt_add(fmd_hdl, evp);
		}
		if (iosvc->msg_q_cur_len == 1)
			(void) pthread_cond_signal(&iosvc->msg_q_cv);
		(void) pthread_mutex_unlock(&iosvc->msg_q_lock);
	} else {
		/*
		 * fmd RDWR xprt procotol startup msgs, send it now!
		 */
		iosvc->ack_ok = 0;
		evhdrp = (etm_proto_v1_ev_hdr_t *)((ptrdiff_t)msg_ele.msg);
		evhdrp->ev_pp.pp_xid = iosvc->cur_send_xid + 1;
		while (!iosvc->ack_ok && iosvc->ds_hdl != DS_INVALID_HDL &&
		    !etm_is_dying) {
			if (etm_send_ds_msg(fmd_hdl, B_FALSE, iosvc, &msg_ele,
			    evhdrp) < 0) {
				continue;
			}
		}
		if (msg_type == FMD_XPRT_RUN_MSG)
			iosvc->start_sending_Q = 1;
	}

	return (rc);

} /* etm_pack_ds_msg() */

/*
 * Design_Note:	For all etm_resp_q_*() functions and etm_resp_q_* globals,
 *		the mutex etm_resp_q_lock must be held by the caller.
 */

/*
 * etm_resp_q_enq - add element to tail of ETM responder queue
 * etm_resp_q_deq - del element from head of ETM responder queue
 *
 * return >0 for success, or -errno value
 */

static int
etm_resp_q_enq(fmd_hdl_t *hdl, etm_resp_q_ele_t *rqep)
{
	etm_resp_q_ele_t	*newp;	/* ptr to new resp q ele */

	if (etm_resp_q_cur_len >= etm_resp_q_max_len) {
		fmd_hdl_debug(hdl, "warning: enq to full responder queue\n");
		etm_stats.etm_enq_drop_resp_q.fmds_value.ui64++;
		return (-E2BIG);
	}

	newp = fmd_hdl_zalloc(hdl, sizeof (*newp), FMD_SLEEP);
	(void) memcpy(newp, rqep, sizeof (*newp));
	newp->rqe_nextp = NULL;

	if (etm_resp_q_cur_len == 0) {
		etm_resp_q_head = newp;
	} else {
		etm_resp_q_tail->rqe_nextp = newp;
	}
	etm_resp_q_tail = newp;
	etm_resp_q_cur_len++;
	etm_stats.etm_resp_q_cur_len.fmds_value.ui64 = etm_resp_q_cur_len;

	return (1);

} /* etm_resp_q_enq() */

static int
etm_resp_q_deq(fmd_hdl_t *hdl, etm_resp_q_ele_t *rqep)
{
	etm_resp_q_ele_t	*oldp;	/* ptr to old resp q ele */

	if (etm_resp_q_cur_len == 0) {
		fmd_hdl_debug(hdl, "warning: deq from empty responder queue\n");
		etm_stats.etm_deq_drop_resp_q.fmds_value.ui64++;
		return (-ENOENT);
	}

	(void) memcpy(rqep, etm_resp_q_head, sizeof (*rqep));
	rqep->rqe_nextp = NULL;

	oldp = etm_resp_q_head;
	etm_resp_q_head = etm_resp_q_head->rqe_nextp;
	fmd_hdl_free(hdl, oldp, sizeof (*oldp));

	etm_resp_q_cur_len--;
	etm_stats.etm_resp_q_cur_len.fmds_value.ui64 = etm_resp_q_cur_len;
	if (etm_resp_q_cur_len == 0) {
		etm_resp_q_tail = NULL;
	}

	return (1);

} /* etm_resp_q_deq() */

/*
 * etm_maybe_enq_response - check the given message header to see
 *				whether a response has been requested,
 *				if so then enqueue the given connection
 *				and header for later transport by the
 *				responder thread as an ETM response msg,
 *				return 0 for nop, >0 success, or -errno value
 */

static ssize_t
etm_maybe_enq_response(fmd_hdl_t *hdl, etm_xport_conn_t conn,
    void *hdrp, uint32_t hdr_sz, int32_t resp_code)
{
	ssize_t			rv;		/* ret val */
	etm_proto_v1_pp_t	*ppp;		/* protocol preamble ptr */
	uint8_t			orig_msg_type;	/* orig hdr's message type */
	uint32_t		orig_timeout;	/* orig hdr's timeout */
	etm_resp_q_ele_t	rqe;		/* responder queue ele */

	ppp = hdrp;
	orig_msg_type = ppp->pp_msg_type;
	orig_timeout = ppp->pp_timeout;

	/* bail out now if no response is to be sent */

	if (orig_timeout == ETM_PROTO_V1_TIMEOUT_NONE) {
		return (0);
	} /* if a nop */

	if ((orig_msg_type != ETM_MSG_TYPE_FMA_EVENT) &&
	    (orig_msg_type != ETM_MSG_TYPE_ALERT) &&
	    (orig_msg_type != ETM_MSG_TYPE_CONTROL)) {
		fmd_hdl_debug(hdl, "warning: bad msg type 0x%x\n",
		    orig_msg_type);
		return (-EINVAL);
	} /* if inappropriate hdr for a response msg */

	/*
	 * enqueue the msg hdr and nudge the responder thread
	 * if the responder queue was previously empty
	 */

	rqe.rqe_conn = conn;
	rqe.rqe_hdrp = hdrp;
	rqe.rqe_hdr_sz = hdr_sz;
	rqe.rqe_resp_code = resp_code;

	(void) pthread_mutex_lock(&etm_resp_q_lock);

	if (etm_resp_q_cur_len == etm_resp_q_max_len)
		(void) pthread_cond_wait(&etm_resp_q_cv, &etm_resp_q_lock);

	rv = etm_resp_q_enq(hdl, &rqe);
	if (etm_resp_q_cur_len == 1)
		(void) pthread_cond_signal(&etm_resp_q_cv);
	(void) pthread_mutex_unlock(&etm_resp_q_lock);

	return (rv);

} /* etm_maybe_enq_response() */

/*
 * Design_Note:	We rely on the fact that all message types have
 *		a common protocol preamble; if this fact should
 *		ever change it may break the code below. We also
 *		rely on the fact that FMA_EVENT and CONTROL headers
 *		returned by etm_hdr_read() will be sized large enough
 *		to reuse them as RESPONSE headers if the remote endpt
 *		asked for a response via the pp_timeout field.
 */

/*
 * etm_send_response - use the given message header and response code
 *			to construct an appropriate response message,
 *			and send it back on the given connection,
 *			return >0 for success, or -errno value
 */

static ssize_t
etm_send_response(fmd_hdl_t *hdl, etm_xport_conn_t conn,
    void *hdrp, int32_t resp_code)
{
	ssize_t			rv;		/* ret val */
	etm_proto_v1_pp_t	*ppp;		/* protocol preamble ptr */
	etm_proto_v1_resp_hdr_t *resp_hdrp;	/* for RESPONSE msg */
	uint8_t			resp_body[4];	/* response body if needed */
	uint8_t			*resp_msg;	/* response hdr+body */
	size_t			hdr_sz;		/* sizeof response hdr */
	uint8_t			orig_msg_type;	/* orig hdr's message type */

	ppp = hdrp;
	orig_msg_type = ppp->pp_msg_type;

	if (etm_debug_lvl >= 2) {
		etm_show_time(hdl, "ante resp send");
	}

	/* reuse the given header as a response header */

	resp_hdrp = hdrp;
	resp_hdrp->resp_code = resp_code;
	resp_hdrp->resp_len = 0;		/* default is empty body */

	if ((orig_msg_type == ETM_MSG_TYPE_CONTROL) &&
	    (ppp->pp_sub_type == ETM_CTL_SEL_VER_NEGOT_REQ)) {
		resp_body[0] = ETM_PROTO_V2;
		resp_body[1] = ETM_PROTO_V3;
		resp_body[2] = 0;
		resp_hdrp->resp_len = 3;
	} /* if should send our/negotiated proto ver in resp body */

	/* respond with the proto ver that was negotiated */

	resp_hdrp->resp_pp.pp_proto_ver = etm_resp_ver;
	resp_hdrp->resp_pp.pp_msg_type = ETM_MSG_TYPE_RESPONSE;
	resp_hdrp->resp_pp.pp_timeout = ETM_PROTO_V1_TIMEOUT_NONE;

	/*
	 * send the whole response msg in one write, header and body;
	 * avoid the alloc-and-copy if we can reuse the hdr as the msg,
	 * ie, if the body is empty. update the response stats.
	 */

	hdr_sz = sizeof (etm_proto_v1_resp_hdr_t);

	resp_msg = hdrp;
	if (resp_hdrp->resp_len > 0) {
		resp_msg = fmd_hdl_zalloc(hdl, hdr_sz + resp_hdrp->resp_len,
		    FMD_SLEEP);
		(void) memcpy(resp_msg, resp_hdrp, hdr_sz);
		(void) memcpy(resp_msg + hdr_sz, resp_body,
		    resp_hdrp->resp_len);
	}

	(void) pthread_mutex_lock(&etm_write_lock);
	rv = etm_io_op(hdl, "bad io write on resp msg", conn,
	    resp_msg, hdr_sz + resp_hdrp->resp_len, ETM_IO_OP_WR);
	(void) pthread_mutex_unlock(&etm_write_lock);
	if (rv < 0) {
		goto func_ret;
	}

	etm_stats.etm_wr_hdr_response.fmds_value.ui64++;
	etm_stats.etm_wr_body_response.fmds_value.ui64++;

	fmd_hdl_debug(hdl, "info: sent V%u RESPONSE msg to xport "
	    "xid 0x%x code %d len %u\n",
	    (unsigned int)resp_hdrp->resp_pp.pp_proto_ver,
	    resp_hdrp->resp_pp.pp_xid, resp_hdrp->resp_code,
	    resp_hdrp->resp_len);
func_ret:

	if (resp_hdrp->resp_len > 0) {
		fmd_hdl_free(hdl, resp_msg, hdr_sz + resp_hdrp->resp_len);
	}
	if (etm_debug_lvl >= 2) {
		etm_show_time(hdl, "post resp send");
	}
	return (rv);

} /* etm_send_response() */

/*
 * etm_reset_xport - reset the transport layer (via fini;init)
 *			presumably for an error condition we cannot
 *			otherwise recover from (ex: hung LDC channel)
 *
 * caveats - no checking/locking is done to ensure an existing connection
 *		is idle during an xport reset; we don't want to deadlock
 *		and presumably the transport is stuck/unusable anyway
 */

static void
etm_reset_xport(fmd_hdl_t *hdl)
{
	(void) etm_xport_fini(hdl);
	(void) etm_xport_init(hdl);
	etm_stats.etm_reset_xport.fmds_value.ui64++;

} /* etm_reset_xport() */

/*
 * etm_handle_new_conn - receive an ETM message sent from the other end via
 *			the given open connection, pull out any FMA events
 *			and post them to the local FMD (or handle any ETM
 *			control or response msg); when done, close the
 *			connection
 */

static void
etm_handle_new_conn(fmd_hdl_t *hdl, etm_xport_conn_t conn)
{
	etm_proto_v1_ev_hdr_t	*ev_hdrp;	/* for FMA_EVENT msg */
	etm_proto_v1_ctl_hdr_t	*ctl_hdrp;	/* for CONTROL msg */
	etm_proto_v1_resp_hdr_t *resp_hdrp;	/* for RESPONSE msg */
	etm_proto_v3_sa_hdr_t	*sa_hdrp;	/* for ALERT msg */
	etm_iosvc_t		*iosvc;		/* iosvc data structure */
	int32_t			resp_code;	/* response code */
	ssize_t			enq_rv;		/* resp_q enqueue status */
	size_t			hdr_sz;		/* sizeof header */
	size_t			evsz;		/* FMA event size */
	uint8_t			*body_buf;	/* msg body buffer */
	uint32_t		body_sz;	/* sizeof body_buf */
	uint32_t		ev_cnt;		/* count of FMA events */
	uint8_t			*bp;		/* byte ptr within body_buf */
	nvlist_t		*evp;		/* ptr to unpacked FMA event */
	char			*class;		/* FMA event class */
	ssize_t			i, n;		/* gen use */
	int			should_reset_xport; /* bool to reset xport */
	char			ldom_name[MAX_LDOM_NAME]; /* ldom name */
	int			rc;		/* return code */
	uint64_t		did;		/* domain id */


	if (etm_debug_lvl >= 2) {
		etm_show_time(hdl, "ante conn handle");
	}
	fmd_hdl_debug(hdl, "info: handling new conn %p\n", conn);

	should_reset_xport = 0;
	ev_hdrp = NULL;
	ctl_hdrp = NULL;
	resp_hdrp = NULL;
	sa_hdrp = NULL;
	body_buf = NULL;
	class = NULL;
	evp = NULL;
	resp_code = 0;	/* default is success */
	enq_rv = 0;	/* default is nop, ie, did not enqueue */

	/* read a network decoded message header from the connection */

	if ((ev_hdrp = etm_hdr_read(hdl, conn, &hdr_sz)) == NULL) {
		/* errno assumed set by above call */
		should_reset_xport = (errno == ENOTACTIVE);
		fmd_hdl_debug(hdl, "error: FMA event dropped: "
		    "bad hdr read errno %d\n", errno);
		etm_stats.etm_rd_drop_fmaevent.fmds_value.ui64++;
		goto func_ret;
	}

	/*
	 * handle the message based on its preamble pp_msg_type
	 * which is known to be valid from etm_hdr_read() checks
	 */

	if (ev_hdrp->ev_pp.pp_msg_type == ETM_MSG_TYPE_FMA_EVENT) {

		fmd_hdl_debug(hdl, "info: rcvd FMA_EVENT msg from xport\n");

		/* allocate buf large enough for whole body / all FMA events */

		body_sz = 0;
		for (i = 0; ev_hdrp->ev_lens[i] != 0; i++) {
			body_sz += ev_hdrp->ev_lens[i];
		} /* for summing sizes of all FMA events */
		if (i > etm_stats.etm_rd_max_ev_per_msg.fmds_value.ui64)
			etm_stats.etm_rd_max_ev_per_msg.fmds_value.ui64 = i;
		ev_cnt = i;

		if (etm_debug_lvl >= 1) {
			fmd_hdl_debug(hdl, "info: event lengths %u sum %u\n",
			    ev_cnt, body_sz);
		}

		body_buf = fmd_hdl_zalloc(hdl, body_sz, FMD_SLEEP);

		/* read all the FMA events at once */

		if ((n = etm_io_op(hdl, "FMA event dropped: "
		    "bad io read on event bodies", conn, body_buf, body_sz,
		    ETM_IO_OP_RD)) < 0) {
			should_reset_xport = (n == -ENOTACTIVE);
			etm_stats.etm_rd_drop_fmaevent.fmds_value.ui64++;
			goto func_ret;
		}

		etm_stats.etm_rd_xport_bytes.fmds_value.ui64 += body_sz;
		etm_stats.etm_rd_body_fmaevent.fmds_value.ui64 += ev_cnt;

		/*
		 * now that we've read the entire ETM msg from the conn,
		 * which avoids later ETM protocol framing errors if we didn't,
		 * check for dup msg/xid against last good FMD posting,
		 * if a dup then resend response but skip repost to FMD
		 */

		if (ev_hdrp->ev_pp.pp_xid == etm_xid_posted_logged_ev) {
			enq_rv = etm_maybe_enq_response(hdl, conn,
			    ev_hdrp, hdr_sz, 0);
			fmd_hdl_debug(hdl, "info: skipping dup FMA event post "
			    "xid 0x%x\n", etm_xid_posted_logged_ev);
			etm_stats.etm_rd_dup_fmaevent.fmds_value.ui64++;
			goto func_ret;
		}

		/* unpack each FMA event and post it to FMD */

		bp = body_buf;
		for (i = 0; i < ev_cnt; i++) {
			if ((n = nvlist_unpack((char *)bp,
			    ev_hdrp->ev_lens[i], &evp, 0)) != 0) {
				resp_code = (-n);
				enq_rv = etm_maybe_enq_response(hdl, conn,
				    ev_hdrp, hdr_sz, resp_code);
				fmd_hdl_error(hdl, "error: FMA event dropped: "
				    "bad event body unpack errno %d\n", n);
				if (etm_debug_lvl >= 2) {
					fmd_hdl_debug(hdl, "info: FMA event "
					    "hexdump %d bytes:\n",
					    ev_hdrp->ev_lens[i]);
					etm_hexdump(hdl, bp,
					    ev_hdrp->ev_lens[i]);
				}
				etm_stats.etm_os_nvlist_unpack_fail.fmds_value.
				    ui64++;
				etm_stats.etm_rd_drop_fmaevent.fmds_value.
				    ui64++;
				bp += ev_hdrp->ev_lens[i];
				continue;
			}

			if (etm_debug_lvl >= 1) {
				(void) nvlist_lookup_string(evp, FM_CLASS,
				    &class);
				if (class == NULL) {
					class = "NULL";
				}
				fmd_hdl_debug(hdl, "info: FMA event %p "
				    "class %s\n", evp, class);
			}

			rc = nvlist_size(evp, &evsz, NV_ENCODE_XDR);
			fmd_hdl_debug(hdl,
			    "info: evp size before pack ds msg %d\n", evsz);
			ldom_name[0] = '\0';
			rc = etm_filter_find_ldom_id(hdl, evp, ldom_name,
			    MAX_LDOM_NAME, &did);

			/*
			 * if rc is zero and the ldom_name is not "primary",
			 * the evp belongs to a root domain, put the evp in an
			 * outgoing etm queue,
			 * in all other cases, whether ldom_name is primary or
			 * can't find a ldom name, call etm_post_to_fmd
			 */
			if ((rc == 0) && strcmp(ldom_name, "primary") &&
			    strcmp(ldom_name, "")) {
				/*
				 * use the ldom_name, guaranteered at this point
				 * to be a valid ldom name/non-NULL, to find the
				 * iosvc data.
				 * add an iosvc struct if can not find one
				 */
				(void) pthread_mutex_unlock(&iosvc_list_lock);
				iosvc = etm_iosvc_lookup(hdl, ldom_name,
				    DS_INVALID_HDL, B_TRUE);
				(void) pthread_mutex_unlock(&iosvc_list_lock);
				if (iosvc == NULL) {
					fmd_hdl_debug(hdl,
					    "error: can't find iosvc for ldom "
					    "name %s\n", ldom_name);
				} else {
					resp_code = 0;
					(void) etm_pack_ds_msg(hdl, iosvc,
					    ev_hdrp, hdr_sz, evp,
					    SP_MSG, ETM_CKPT_SAVE);
					/*
					 * call the new fmd_xprt_log()
					 */
					fmd_xprt_log(hdl, etm_fmd_xprt, evp, 0);
					etm_xid_posted_logged_ev =
					    ev_hdrp->ev_pp.pp_xid;
				}
			} else {
				/*
				 * post the fma event to the control fmd
				 */
				resp_code = etm_post_to_fmd(hdl, etm_fmd_xprt,
				    evp);
				if (resp_code >= 0) {
					etm_xid_posted_logged_ev =
					    ev_hdrp->ev_pp.pp_xid;
				}
			}

			evp = NULL;
			enq_rv = etm_maybe_enq_response(hdl, conn,
			    ev_hdrp, hdr_sz, resp_code);
			bp += ev_hdrp->ev_lens[i];
		} /* foreach FMA event in the body buffer */

	} else if (ev_hdrp->ev_pp.pp_msg_type == ETM_MSG_TYPE_CONTROL) {

		ctl_hdrp = (void*)ev_hdrp;

		fmd_hdl_debug(hdl, "info: rcvd CONTROL msg from xport\n");
		if (etm_debug_lvl >= 1) {
			fmd_hdl_debug(hdl, "info: ctl sel %d xid 0x%x\n",
			    (int)ctl_hdrp->ctl_pp.pp_sub_type,
			    ctl_hdrp->ctl_pp.pp_xid);
		}

		/*
		 * if we have a VER_NEGOT_REQ read the body and validate
		 * the protocol version set contained therein,
		 * otherwise we have a PING_REQ (which has no body)
		 * and we [also] fall thru to the code which sends a
		 * response msg if the pp_timeout field requested one
		 */

		if (ctl_hdrp->ctl_pp.pp_sub_type == ETM_CTL_SEL_VER_NEGOT_REQ) {

			body_sz = ctl_hdrp->ctl_len;
			body_buf = fmd_hdl_zalloc(hdl, body_sz, FMD_SLEEP);

			if ((n = etm_io_op(hdl, "bad io read on ctl body",
			    conn, body_buf, body_sz, ETM_IO_OP_RD)) < 0) {
				should_reset_xport = (n == -ENOTACTIVE);
				goto func_ret;
			}

			/* complain if version set completely incompatible */

			for (i = 0; i < body_sz; i++) {
				if ((body_buf[i] == ETM_PROTO_V1) ||
				    (body_buf[i] == ETM_PROTO_V2) ||
				    (body_buf[i] == ETM_PROTO_V3)) {
					break;
				}
			}
			if (i >= body_sz) {
				etm_stats.etm_ver_bad.fmds_value.ui64++;
				resp_code = (-EPROTO);
			}

		} /* if got version set request */

		etm_stats.etm_rd_body_control.fmds_value.ui64++;

		enq_rv = etm_maybe_enq_response(hdl, conn,
		    ctl_hdrp, hdr_sz, resp_code);

	} else if (ev_hdrp->ev_pp.pp_msg_type == ETM_MSG_TYPE_RESPONSE) {

		resp_hdrp = (void*)ev_hdrp;

		fmd_hdl_debug(hdl, "info: rcvd RESPONSE msg from xport\n");
		if (etm_debug_lvl >= 1) {
			fmd_hdl_debug(hdl, "info: resp xid 0x%x\n",
			    (int)resp_hdrp->resp_pp.pp_xid);
		}

		body_sz = resp_hdrp->resp_len;
		body_buf = fmd_hdl_zalloc(hdl, body_sz, FMD_SLEEP);

		if ((n = etm_io_op(hdl, "bad io read on resp len",
		    conn, body_buf, body_sz, ETM_IO_OP_RD)) < 0) {
			should_reset_xport = (n == -ENOTACTIVE);
			goto func_ret;
		}

		etm_stats.etm_rd_body_response.fmds_value.ui64++;

		/*
		 * look up the xid to interpret the response body
		 *
		 * ping is a nop; for ver negot confirm that a supported
		 * protocol version was negotiated and remember which one
		 */

		if ((resp_hdrp->resp_pp.pp_xid != etm_xid_ping) &&
		    (resp_hdrp->resp_pp.pp_xid != etm_xid_ver_negot)) {
			etm_stats.etm_xid_bad.fmds_value.ui64++;
			goto func_ret;
		}

		if (resp_hdrp->resp_pp.pp_xid == etm_xid_ver_negot) {
			if ((body_buf[0] < ETM_PROTO_V1) ||
			    (body_buf[0] > ETM_PROTO_V3)) {
				etm_stats.etm_ver_bad.fmds_value.ui64++;
				goto func_ret;
			}
			etm_resp_ver = body_buf[0];
		} /* if have resp to last req to negotiate proto ver */

	} else if (ev_hdrp->ev_pp.pp_msg_type == ETM_MSG_TYPE_ALERT) {

		sa_hdrp = (void*)ev_hdrp;

		fmd_hdl_debug(hdl, "info: rcvd ALERT msg from xport\n");
		if (etm_debug_lvl >= 1) {
			fmd_hdl_debug(hdl, "info: sa sel %d xid 0x%x\n",
			    (int)sa_hdrp->sa_pp.pp_sub_type,
			    sa_hdrp->sa_pp.pp_xid);
		}

		body_sz = sa_hdrp->sa_len;
		body_buf = fmd_hdl_zalloc(hdl, body_sz, FMD_SLEEP);

		if ((n = etm_io_op(hdl, "bad io read on sa body",
		    conn, body_buf, body_sz, ETM_IO_OP_RD)) < 0) {
			should_reset_xport = (n == -ENOTACTIVE);
			goto func_ret;
		}

		etm_stats.etm_rd_body_alert.fmds_value.ui64++;

		/*
		 * now that we've read the entire ETM msg from the conn,
		 * which avoids later ETM protocol framing errors if we didn't,
		 * check for dup msg/xid against last good syslog posting,
		 * if a dup then resend response but skip repost to syslog
		 */

		if (sa_hdrp->sa_pp.pp_xid == etm_xid_posted_sa) {
			enq_rv = etm_maybe_enq_response(hdl, conn,
			    sa_hdrp, hdr_sz, 0);
			fmd_hdl_debug(hdl, "info: skipping dup ALERT post "
			    "xid 0x%x\n", etm_xid_posted_sa);
			etm_stats.etm_rd_dup_alert.fmds_value.ui64++;
			goto func_ret;
		}

		resp_code = etm_post_to_syslog(hdl, sa_hdrp->sa_priority,
		    body_sz, body_buf);
		if (resp_code >= 0) {
			etm_xid_posted_sa = sa_hdrp->sa_pp.pp_xid;
		}
		enq_rv = etm_maybe_enq_response(hdl, conn,
		    sa_hdrp, hdr_sz, resp_code);
	} /* whether we have a FMA_EVENT, CONTROL, RESPONSE or ALERT msg */

func_ret:

	if (etm_debug_lvl >= 2) {
		etm_show_time(hdl, "post conn handle");
	}

	/*
	 * if no responder ele was enqueued, close the conn now
	 * and free the ETM msg hdr; the ETM msg body is not needed
	 * by the responder thread and should always be freed here
	 */

	if (enq_rv <= 0) {
		(void) etm_conn_close(hdl, "bad conn close after msg recv",
		    conn);
		if (ev_hdrp != NULL) {
			fmd_hdl_free(hdl, ev_hdrp, hdr_sz);
		}
	}
	if (body_buf != NULL) {
		fmd_hdl_free(hdl, body_buf, body_sz);
	}
	if (should_reset_xport) {
		etm_reset_xport(hdl);
	}
} /* etm_handle_new_conn() */

/*
 * etm_handle_bad_accept - recover from a failed connection acceptance
 */

static void
etm_handle_bad_accept(fmd_hdl_t *hdl, int nev)
{
	int	should_reset_xport; /* bool to reset xport */

	should_reset_xport = (nev == -ENOTACTIVE);
	fmd_hdl_debug(hdl, "error: bad conn accept errno %d\n", (-nev));
	etm_stats.etm_xport_accept_fail.fmds_value.ui64++;
	(void) etm_sleep(etm_bad_acc_to_sec); /* avoid spinning CPU */
	if (should_reset_xport) {
		etm_reset_xport(hdl);
	}
} /* etm_handle_bad_accept() */

/*
 * etm_server - loop forever accepting new connections
 *		using the given FMD handle,
 *		handling any ETM msgs sent from the other side
 *		via each such connection
 */

static void
etm_server(void *arg)
{
	etm_xport_conn_t	conn;		/* connection handle */
	int			nev;		/* -errno val */
	fmd_hdl_t		*hdl;		/* FMD handle */

	hdl = arg;

	fmd_hdl_debug(hdl, "info: connection server starting\n");

	/*
	 * Restore the checkpointed events and dispatch them before starting to
	 * receive more events from the sp.
	 */
	etm_ckpt_recover(hdl);

	while (!etm_is_dying) {

		if ((conn = etm_xport_accept(hdl, NULL)) == NULL) {
			/* errno assumed set by above call */
			nev = (-errno);
			if (etm_is_dying) {
				break;
			}
			etm_handle_bad_accept(hdl, nev);
			continue;
		}

		/* handle the new message/connection, closing it when done */

		etm_handle_new_conn(hdl, conn);

	} /* while accepting new connections until ETM dies */

	/* ETM is dying (probably due to "fmadm unload etm") */

	fmd_hdl_debug(hdl, "info: connection server is dying\n");

} /* etm_server() */

/*
 * etm_responder - loop forever waiting for new responder queue elements
 *		to be enqueued, for each one constructing and sending
 *		an ETM response msg to the other side, and closing its
 *		associated connection when appropriate
 *
 *	this thread exists to ensure that the etm_server() thread
 *	never pends indefinitely waiting on the xport write lock, and is
 *	hence always available to accept new connections and handle
 *	incoming messages
 *
 *	this design relies on the fact that each connection accepted and
 *	returned by the ETM xport layer is unique, and each can be closed
 *	independently of the others while multiple connections are
 *	outstanding
 */

static void
etm_responder(void *arg)
{
	ssize_t			n;		/* gen use */
	fmd_hdl_t		*hdl;		/* FMD handle */
	etm_resp_q_ele_t	rqe;		/* responder queue ele */

	hdl = arg;

	fmd_hdl_debug(hdl, "info: responder server starting\n");

	while (!etm_is_dying) {

		(void) pthread_mutex_lock(&etm_resp_q_lock);

		while (etm_resp_q_cur_len == 0) {
			(void) pthread_cond_wait(&etm_resp_q_cv,
			    &etm_resp_q_lock);
			if (etm_is_dying) {
				(void) pthread_mutex_unlock(&etm_resp_q_lock);
				goto func_ret;
			}
		} /* while the responder queue is empty, wait to be nudged */

		/*
		 * for every responder ele that has been enqueued,
		 * dequeue and send it as an ETM response msg,
		 * closing its associated conn and freeing its hdr
		 *
		 * enter the queue draining loop holding the responder
		 * queue lock, but do not hold the lock indefinitely
		 * (the actual send may pend us indefinitely),
		 * so that other threads will never pend for long
		 * trying to enqueue a new element
		 */

		while (etm_resp_q_cur_len > 0) {

			(void) etm_resp_q_deq(hdl, &rqe);

			if ((etm_resp_q_cur_len + 1) == etm_resp_q_max_len)
				(void) pthread_cond_signal(&etm_resp_q_cv);

			(void) pthread_mutex_unlock(&etm_resp_q_lock);

			if ((n = etm_send_response(hdl, rqe.rqe_conn,
			    rqe.rqe_hdrp, rqe.rqe_resp_code)) < 0) {
				fmd_hdl_error(hdl, "error: bad resp send "
				    "errno %d\n", (-n));
			}

			(void) etm_conn_close(hdl, "bad conn close after resp",
			    rqe.rqe_conn);
			fmd_hdl_free(hdl, rqe.rqe_hdrp, rqe.rqe_hdr_sz);

			if (etm_is_dying) {
				goto func_ret;
			}
			(void) pthread_mutex_lock(&etm_resp_q_lock);

		} /* while draining the responder queue */

		(void) pthread_mutex_unlock(&etm_resp_q_lock);

	} /* while awaiting and sending resp msgs until ETM dies */

func_ret:

	/* ETM is dying (probably due to "fmadm unload etm") */

	fmd_hdl_debug(hdl, "info: responder server is dying\n");

	(void) pthread_mutex_lock(&etm_resp_q_lock);
	if (etm_resp_q_cur_len > 0) {
		fmd_hdl_error(hdl, "warning: %d response msgs dropped\n",
		    (int)etm_resp_q_cur_len);
		while (etm_resp_q_cur_len > 0) {
			(void) etm_resp_q_deq(hdl, &rqe);
			(void) etm_conn_close(hdl, "bad conn close after deq",
			    rqe.rqe_conn);
			fmd_hdl_free(hdl, rqe.rqe_hdrp, rqe.rqe_hdr_sz);
		}
	}
	(void) pthread_mutex_unlock(&etm_resp_q_lock);

} /* etm_responder() */

static void *
etm_init_alloc(size_t size)
{
	return (fmd_hdl_alloc(init_hdl, size, FMD_SLEEP));
}

static void
etm_init_free(void *addr, size_t size)
{
	fmd_hdl_free(init_hdl, addr, size);
}

/*
 * ---------------------root ldom support functions -----------------------
 */

/*
 * use a static array async_event_q instead of dynamicaly allocated mem  queue
 * for etm_async_q_enq and etm_async_q_deq.
 * This is not running in an fmd aux thread, can't use the fmd_hdl_* funcs.
 * caller needs to grab the mutex lock before calling this func.
 * return >0 for success, or -errno value
 */
static int
etm_async_q_enq(etm_async_event_ele_t *async_e)
{

	if (etm_async_q_cur_len >= etm_async_q_max_len) {
		/* etm_stats.etm_enq_drop_async_q.fmds_value.ui64++; */
		return (-E2BIG);
	}

	(void) memcpy(&async_event_q[etm_async_q_tail], async_e,
	    sizeof (*async_e));

	etm_async_q_tail++;
	if (etm_async_q_tail == etm_async_q_max_len) {
		etm_async_q_tail = 0;
	}
	etm_async_q_cur_len++;

/* etm_stats.etm_async_q_cur_len.fmds_value.ui64 = etm_async_q_cur_len; */

	return (1);

} /* etm_async_q_enq() */


static int
etm_async_q_deq(etm_async_event_ele_t *async_e)
{

	if (etm_async_q_cur_len == 0) {
		/* etm_stats.etm_deq_drop_async_q.fmds_value.ui64++; */
		return (-ENOENT);
	}

	(void) memcpy(async_e, &async_event_q[etm_async_q_head],
	    sizeof (*async_e));

	etm_async_q_head++;
	if (etm_async_q_head == etm_async_q_max_len) {
		etm_async_q_head = 0;
	}
	etm_async_q_cur_len--;

	return (1);
} /* etm_async_q_deq */


/*
 * setting up the fields in iosvc at DS_REG_CB time
 */
void
etm_iosvc_setup(fmd_hdl_t *fmd_hdl, etm_iosvc_t *iosvc,
    etm_async_event_ele_t *async_e)
{
	iosvc->ds_hdl = async_e->ds_hdl;
	iosvc->cur_send_xid = 0;
	iosvc->xid_posted_ev = 0;
	iosvc->start_sending_Q = 0;

	/*
	 * open the fmd xprt if it
	 * hasn't been previously opened
	 */
	fmd_hdl_debug(fmd_hdl,  "info: before fmd_xprt_open ldom_name is %s\n",
	    async_e->ldom_name);

	if (iosvc->fmd_xprt == NULL) {
		iosvc->fmd_xprt = fmd_xprt_open(fmd_hdl, flags, NULL, iosvc);
	}

	iosvc->thr_is_dying = 0;
	if (iosvc->recv_tid == 0) {
		iosvc->recv_tid = fmd_thr_create(fmd_hdl,
		    etm_recv_from_remote_root, iosvc);
	}
	if (iosvc->send_tid == 0) {
		iosvc->send_tid = fmd_thr_create(fmd_hdl,
		    etm_send_to_remote_root, iosvc);
	}
} /* etm_iosvc_setup() */


/*
 * ds userland interface ds_reg_cb  callback func
 */

/* ARGSUSED */
static void
etm_iosvc_reg_handler(ds_hdl_t ds_hdl, ds_cb_arg_t arg, ds_ver_t *ver,
    ds_domain_hdl_t dhdl)
{
	etm_async_event_ele_t	async_ele;


	/*
	 * do version check here.
	 * checked the ver received here against etm_iosvc_vers here
	 */
	if (etm_iosvc_vers[0].major != ver->major ||
	    etm_iosvc_vers[0].minor != ver->minor) {
		/*
		 * can't log an fmd debug msg,
		 * not running in an fmd aux thread
		 */
		return;
	}

	/*
	 * the callback should have a valid ldom_name
	 * can't log fmd debugging msg here since this is not in an fmd aux
	 * thread. log fmd debug msg in etm_async_event_handle()
	 */
	async_ele.ds_hdl = ds_hdl;
	async_ele.dhdl = dhdl;
	async_ele.ldom_name[0] = '\0';
	async_ele.event_type = ETM_ASYNC_EVENT_DS_REG_CB;
	(void) pthread_mutex_lock(&etm_async_event_q_lock);
	(void) etm_async_q_enq(&async_ele);
	if (etm_async_q_cur_len == 1)
		(void) pthread_cond_signal(&etm_async_event_q_cv);
	(void) pthread_mutex_unlock(&etm_async_event_q_lock);

} /* etm_iosvc_reg_handler */


/*
 * ds userland interface ds_unreg_cb  callback func
 */

/*ARGSUSED*/
static void
etm_iosvc_unreg_handler(ds_hdl_t hdl, ds_cb_arg_t arg)
{
	etm_async_event_ele_t	async_ele;

	/*
	 * fill in async_ele and enqueue async_ele
	 */
	async_ele.ldom_name[0] = '\0';
	async_ele.ds_hdl = hdl;
	async_ele.event_type = ETM_ASYNC_EVENT_DS_UNREG_CB;
	(void) pthread_mutex_lock(&etm_async_event_q_lock);
	(void) etm_async_q_enq(&async_ele);
	if (etm_async_q_cur_len == 1)
		(void) pthread_cond_signal(&etm_async_event_q_cv);
	(void) pthread_mutex_unlock(&etm_async_event_q_lock);
} /* etm_iosvc_unreg_handler */

/*
 * ldom event registration callback func
 */

/* ARGSUSED */
static void
ldom_event_handler(char *ldom_name, ldom_event_t event, ldom_cb_arg_t data)
{
	etm_async_event_ele_t	async_ele;

	/*
	 * the callback will have a valid ldom_name
	 */
	async_ele.ldom_name[0] = '\0';
	if (ldom_name)
		(void) strcpy(async_ele.ldom_name, ldom_name);
	async_ele.ds_hdl = DS_INVALID_HDL;

	/*
	 * fill in async_ele and enq async_ele
	 */
	switch (event) {
	case LDOM_EVENT_BIND:
		async_ele.event_type = ETM_ASYNC_EVENT_LDOM_BIND;
		break;
	case LDOM_EVENT_UNBIND:
		async_ele.event_type = ETM_ASYNC_EVENT_LDOM_UNBIND;
		break;
	case LDOM_EVENT_ADD:
		async_ele.event_type = ETM_ASYNC_EVENT_LDOM_ADD;
		break;
	case LDOM_EVENT_REMOVE:
		async_ele.event_type = ETM_ASYNC_EVENT_LDOM_REMOVE;
		break;
	default:
		/*
		 * for all other ldom events, do nothing
		 */
		return;
	} /* switch (event) */

	(void) pthread_mutex_lock(&etm_async_event_q_lock);
	(void) etm_async_q_enq(&async_ele);
	if (etm_async_q_cur_len == 1)
		(void) pthread_cond_signal(&etm_async_event_q_cv);
	(void) pthread_mutex_unlock(&etm_async_event_q_lock);

} /* ldom_event_handler */


/*
 * This is running as an fmd aux thread.
 * This is the func that actually handle the events, which include:
 * 1. ldom events. ldom events are  on Control Domain only
 * 2. any DS userland callback funcs
 * these events are already Q-ed in the async_event_ele_q
 * deQ and process the events accordingly
 */
static void
etm_async_event_handler(void *arg)
{

	fmd_hdl_t		*fmd_hdl = (fmd_hdl_t *)arg;
	etm_iosvc_t		*iosvc;		/* ptr 2 iosvc struct */
	etm_async_event_ele_t	async_e;

	fmd_hdl_debug(fmd_hdl, "info: etm_async_event_handler starting\n");
	/*
	 *  handle etm is not dying and Q len > 0
	 */
	while (!etm_is_dying) {
		/*
		 * grab the lock to check the Q len
		 */
		(void) pthread_mutex_lock(&etm_async_event_q_lock);
		fmd_hdl_debug(fmd_hdl, "info: etm_async_q_cur_len %d\n",
		    etm_async_q_cur_len);

		while (etm_async_q_cur_len > 0) {
			(void) etm_async_q_deq(&async_e);
			(void) pthread_mutex_unlock(&etm_async_event_q_lock);
			fmd_hdl_debug(fmd_hdl,
			    "info: processing an async event type %d ds_hdl"
			    " %d\n", async_e.event_type, async_e.ds_hdl);
			if (async_e.ldom_name[0] != '\0') {
				fmd_hdl_debug(fmd_hdl,
				    "info: procssing async evt ldom_name %s\n",
				    async_e.ldom_name);
			}

			/*
			 * at this point, if async_e.ldom_name is not NULL,
			 * we have a valid iosvc strcut ptr.
			 * the only time async_e.ldom_name is NULL is  at
			 * ds_unreg_cb()
			 */
			switch (async_e.event_type)  {
			case ETM_ASYNC_EVENT_LDOM_UNBIND:
			case ETM_ASYNC_EVENT_LDOM_REMOVE:
				/*
				 * we have a valid ldom_name,
				 * etm_lookup_struct(ldom_name)
				 * do nothing if can't find an iosvc
				 * no iosvc clean up to do
				 */
				(void) pthread_mutex_lock(
				    &iosvc_list_lock);
				iosvc = etm_iosvc_lookup(fmd_hdl,
				    async_e.ldom_name,
				    async_e.ds_hdl, B_FALSE);
				if (iosvc == NULL) {
					fmd_hdl_debug(fmd_hdl,
					    "error: can't find iosvc for ldom "
					    "name %s\n",
					    async_e.ldom_name);
					(void) pthread_mutex_unlock(
					    &iosvc_list_lock);
					break;
				}
				/*
				 * Clean up the queue, delete all messages and
				 * do not persist checkpointed fma events.
				 */
				etm_iosvc_cleanup(fmd_hdl, iosvc, B_TRUE,
				    B_TRUE);
				(void) pthread_mutex_unlock(
				    &iosvc_list_lock);
				break;

			case ETM_ASYNC_EVENT_LDOM_BIND:

				/*
				 * create iosvc if it has not been
				 * created
				 * async_e.ds_hdl is invalid
				 * async_e.ldom_name is valid ldom_name
				 */
				(void) pthread_mutex_lock(
				    &iosvc_list_lock);
				iosvc = etm_iosvc_lookup(fmd_hdl,
				    async_e.ldom_name,
				    async_e.ds_hdl, B_TRUE);
				if (iosvc == NULL) {
					fmd_hdl_debug(fmd_hdl,
					    "error: can't create iosvc for "
					    "async evnt %d\n",
					    async_e.event_type);
					(void) pthread_mutex_unlock(
					    &iosvc_list_lock);
					break;
				}
				(void) strcpy(iosvc->ldom_name,
				    async_e.ldom_name);
				iosvc->ds_hdl = async_e.ds_hdl;
				(void) pthread_mutex_unlock(
				    &iosvc_list_lock);
				break;

			case ETM_ASYNC_EVENT_DS_REG_CB:
				if (etm_ldom_type == LDOM_TYPE_CONTROL) {
					/*
					 * find the root ldom name from
					 * ldom domain hdl/id
					 */
					if (etm_filter_find_ldom_name(
					    fmd_hdl, async_e.dhdl,
					    async_e.ldom_name,
					    MAX_LDOM_NAME) != 0) {
						fmd_hdl_debug(fmd_hdl,
						    "error: can't find root "
						    "domain name from did %d\n",
						    async_e.dhdl);
						break;
					} else {
						fmd_hdl_debug(fmd_hdl,
						    "info: etm_filter_find_"
						    "ldom_name returned %s\n",
						    async_e.ldom_name);
					}
					/*
					 * now we should have a valid
					 * root domain name.
					 * lookup the iosvc struct
					 * associated with the ldom_name
					 * and init the iosvc struct
					 */
					(void) pthread_mutex_lock(
					    &iosvc_list_lock);
					iosvc = etm_iosvc_lookup(
					    fmd_hdl, async_e.ldom_name,
					    async_e.ds_hdl, B_TRUE);
					if (iosvc == NULL) {
						fmd_hdl_debug(fmd_hdl,
						    "error: can't create iosvc "
						    "for async evnt %d\n",
						    async_e.event_type);
						(void) pthread_mutex_unlock(
						    &iosvc_list_lock);
						break;
					}

					etm_iosvc_setup(fmd_hdl, iosvc,
					    &async_e);
					(void) pthread_mutex_unlock(
					    &iosvc_list_lock);
				} else {
					iosvc = &io_svc;
					(void) strcpy(iosvc->ldom_name,
					    async_e.ldom_name);

					etm_iosvc_setup(fmd_hdl, iosvc,
					    &async_e);
				}
				break;

			case ETM_ASYNC_EVENT_DS_UNREG_CB:
				/*
				 * decide which iosvc struct to perform
				 * this UNREG callback on.
				 */
				if (etm_ldom_type == LDOM_TYPE_CONTROL) {
					(void) pthread_mutex_lock(
					    &iosvc_list_lock);
					/*
					 * lookup the iosvc struct w/
					 * ds_hdl
					 */
					iosvc = etm_iosvc_lookup(
					    fmd_hdl, async_e.ldom_name,
					    async_e.ds_hdl, B_FALSE);
					if (iosvc == NULL) {
						fmd_hdl_debug(fmd_hdl,
						    "error: can't find iosvc "
						    "for async evnt %d\n",
						    async_e.event_type);
					(void) pthread_mutex_unlock(
					    &iosvc_list_lock);
						break;
					}

					/*
					 * ds_hdl and fmd_xprt_open
					 * go hand to hand together
					 * after unreg_cb,
					 * ds_hdl is INVALID and
					 * fmd_xprt is closed.
					 * the ldom name and the msg Q
					 * remains in iosvc_list
					 */
					if (iosvc->ldom_name != '\0')
						fmd_hdl_debug(fmd_hdl,
						    "info: iosvc  w/ ldom_name "
						    "%s \n", iosvc->ldom_name);

					/*
					 * destroy send/recv threads and
					 * other clean up on Control side.
					 */
					etm_iosvc_cleanup(fmd_hdl, iosvc,
					    B_FALSE, B_FALSE);
					(void) pthread_mutex_unlock(
					    &iosvc_list_lock);
				} else {
					iosvc = &io_svc;
					/*
					 * destroy send/recv threads and
					 * then clean up on Root side.
					 */
					etm_iosvc_cleanup(fmd_hdl, iosvc,
					    B_FALSE, B_FALSE);
				}
				break;

			default:
				/*
				 * for all other events, etm doesn't care.
				 * already logged an fmd info msg w/
				 * the event type. Do nothing here.
				 */
				break;
			} /* switch (async_e.event_type) */

			if (etm_ldom_type == LDOM_TYPE_CONTROL) {
				etm_filter_handle_ldom_event(fmd_hdl,
				    async_e.event_type, async_e.ldom_name);
			}

			/*
			 * grab the lock to check the q length again
			 */
			(void) pthread_mutex_lock(&etm_async_event_q_lock);

			if (etm_is_dying) {
				break;
			}
		}	/* etm_async_q_cur_len */

		/*
		 * we have the mutex lock at this point, whether
		 * . etm_is_dying  and/or
		 * . q_len == 0
		 */
		if (!etm_is_dying && etm_async_q_cur_len == 0) {
			fmd_hdl_debug(fmd_hdl,
			    "info: cond wait on async_event_q_cv\n");
			(void) pthread_cond_wait(&etm_async_event_q_cv,
			    &etm_async_event_q_lock);
			fmd_hdl_debug(fmd_hdl,
			    "info: cond wait on async_event_q_cv rtns\n");
		}
		(void) pthread_mutex_unlock(&etm_async_event_q_lock);
	} /* etm_is_dying */

	fmd_hdl_debug(fmd_hdl,
	    "info: etm async event handler thread exiting\n");

} /* etm_async_event_handler */

/*
 * deQ what's in iosvc msg Q
 * send iosvc_msgp to the remote io svc ldom by calling ds_send_msg()
 * the iosvc_msgp already has the packed msg, which is hdr + 1 fma event
 */
static void
etm_send_to_remote_root(void *arg)
{

	etm_iosvc_t		*iosvc = (etm_iosvc_t *)arg;	/* iosvc ptr */
	etm_iosvc_q_ele_t	msg_ele;	/* iosvc msg ele */
	etm_proto_v1_ev_hdr_t	*ev_hdrp;	/* hdr for FMA_EVENT */
	fmd_hdl_t		*fmd_hdl = init_hdl;	/* fmd handle */


	fmd_hdl_debug(fmd_hdl,
	    "info: send to remote iosvc starting w/ ldom_name %s\n",
	    iosvc->ldom_name);

	/*
	 *  loop forever until etm_is_dying or thr_is_dying
	 */
	while (!etm_is_dying && !iosvc->thr_is_dying) {
		if (iosvc->ds_hdl != DS_INVALID_HDL &&
		    iosvc->start_sending_Q > 0) {
			(void) pthread_mutex_lock(&iosvc->msg_q_lock);
			while (iosvc->msg_q_cur_len > 0 &&
			    iosvc->ds_hdl != DS_INVALID_HDL)  {
				(void) etm_iosvc_msg_deq(fmd_hdl, iosvc,
				    &msg_ele);
				if (etm_debug_lvl >= 3) {
					fmd_hdl_debug(fmd_hdl, "info: valid "
					    "ds_hdl before ds_send_msg \n");
				}
				(void) pthread_mutex_unlock(&iosvc->msg_q_lock);

				iosvc->ack_ok = 0;
				ev_hdrp = (etm_proto_v1_ev_hdr_t *)
				    ((ptrdiff_t)msg_ele.msg);
				ev_hdrp->ev_pp.pp_xid = iosvc->cur_send_xid + 1;
				while (!iosvc->ack_ok &&
				    iosvc->ds_hdl != DS_INVALID_HDL &&
				    !etm_is_dying) {
					/*
					 * call ds_send_msg() to send the msg,
					 * wait for the recv end to send the
					 * resp msg back.
					 * If resp msg is recv-ed, ack_ok
					 * will be set to 1.
					 * otherwise, retry.
					 */
					if (etm_send_ds_msg(fmd_hdl, B_TRUE,
					    iosvc, &msg_ele, ev_hdrp) < 0) {
						continue;
					}

					if (etm_is_dying || iosvc->thr_is_dying)
						break;
				}

				/*
				 * if out of the while loop but !ack_ok, ie,
				 * ds_hdl becomes invalid at some point
				 * while waiting the resp msg, we need to put
				 * the msg back to the head of the Q.
				 */
				if (!iosvc->ack_ok) {
					(void) pthread_mutex_lock(
					    &iosvc->msg_q_lock);
					/*
					 * put the msg back to the head of Q.
					 * If the Q is full at this point,
					 * drop the msg at the tail, enq this
					 * msg to the head.
					 */
					etm_msg_enq_head(fmd_hdl, iosvc,
					    &msg_ele);
					(void) pthread_mutex_unlock(
					    &iosvc->msg_q_lock);
				}

				/*
				 *
				 * grab the lock to check the Q len again
				 */
				(void) pthread_mutex_lock(&iosvc->msg_q_lock);
				if (etm_is_dying || iosvc->thr_is_dying) {
					break;
				}
			} /* while dequeing iosvc msgs to send */

			/*
			 * we have the mutex lock for msg_q_lock at this point
			 * we are here because
			 * 1) q_len == 0: then wait on the cv for Q to be filled
			 * 2) etm_is_dying
			 */
			if (!etm_is_dying && !iosvc->thr_is_dying &&
			    iosvc->msg_q_cur_len == 0) {
				fmd_hdl_debug(fmd_hdl,
				    "info: waiting on msg_q_cv\n");
				(void) pthread_cond_wait(&iosvc->msg_q_cv,
				    &iosvc->msg_q_lock);
			}
			(void) pthread_mutex_unlock(&iosvc->msg_q_lock);
			if (etm_is_dying || iosvc->thr_is_dying)  {
				break;
			}
		} else {
			(void) etm_sleep(1);
		} /* wait for the start_sendingQ > 0 */
	} /* etm_is_dying or thr_is_dying */
	fmd_hdl_debug(fmd_hdl, "info; etm send thread exiting \n");
} /* etm_send_to_remote_root */


/*
 * receive etm msgs from the remote root ldom by calling ds_recv_msg()
 * if FMA events/ereports, call fmd_xprt_post() to post to fmd
 * send ACK back by calling ds_send_msg()
 */
static void
etm_recv_from_remote_root(void *arg)
{
	etm_iosvc_t		*iosvc = (etm_iosvc_t *)arg;	/* iosvc ptr */
	etm_proto_v1_pp_t	*pp;		/* protocol preamble */
	etm_proto_v1_ev_hdr_t	*ev_hdrp;	/* for FMA_EVENT msg */
	etm_proto_v1_resp_hdr_t	*resp_hdrp;	/* for RESPONSE msg */
	int32_t			resp_code = 0;	/* default is success */
	int32_t			rc;		/* return value */
	size_t			maxlen = MAXLEN;
						/* max msg len */
	char			msgbuf[MAXLEN];	/* recv msg buf */
	size_t			msg_size;	/* recv msg size */
	size_t			hdr_sz;		/* sizeof *hdrp */
	size_t			evsz;		/* sizeof *evp */
	size_t			fma_event_size;	/* sizeof FMA event  */
	nvlist_t		*evp;		/* ptr to the nvlist */
	char			*buf;		/* ptr to the nvlist */
	static uint32_t		mem_alloc = 0;	/* indicate if alloc mem */
	char			*msg;		/* ptr to alloc mem */
	fmd_hdl_t		*fmd_hdl = init_hdl;



	fmd_hdl_debug(fmd_hdl,
	    "info: recv from remote iosvc starting with ldom name %s \n",
	    iosvc->ldom_name);

	/*
	 * loop forever until etm_is_dying or the thread is dying
	 */

	msg = msgbuf;
	while (!etm_is_dying && !iosvc->thr_is_dying) {
		if (iosvc->ds_hdl == DS_INVALID_HDL) {
			fmd_hdl_debug(fmd_hdl,
			    "info: ds_hdl is invalid in recv thr\n");
			(void) etm_sleep(1);
			continue;
		}

		/*
		 * for now, there are FMA_EVENT and ACK msg type.
		 * use FMA_EVENT buf as the maxlen, hdr+1 fma event.
		 * FMA_EVENT is big enough to hold an ACK msg.
		 * the actual msg size received is in msg_size.
		 */
		rc = (*etm_ds_recv_msg)(iosvc->ds_hdl, msg, maxlen, &msg_size);
		if (rc == EFBIG) {
			fmd_hdl_debug(fmd_hdl,
			    "info: ds_recv_msg needs mem the size of %d\n",
			    msg_size);
			msg = fmd_hdl_zalloc(fmd_hdl, msg_size, FMD_SLEEP);
			mem_alloc = 1;
		} else if (rc == 0) {
			fmd_hdl_debug(fmd_hdl,
			    "info: ds_recv_msg received a msg ok\n");
			/*
			 * check the magic # in  msg.hdr
			 */
			pp = (etm_proto_v1_pp_t *)((ptrdiff_t)msg);
			if (pp->pp_magic_num != ETM_PROTO_MAGIC_NUM) {
				fmd_hdl_debug(fmd_hdl,
				    "info: bad ds recv on magic\n");
				continue;
			}

			/*
			 * check the msg type against msg_size to be sure
			 * that received msg is not a truncated msg
			 */
			if (pp->pp_msg_type == ETM_MSG_TYPE_FMA_EVENT) {

				ev_hdrp = (etm_proto_v1_ev_hdr_t *)
				    ((ptrdiff_t)msg);
				fmd_hdl_debug(fmd_hdl, "info: ds received "
				    "FMA EVENT xid=%d msg_size=%d\n",
				    ev_hdrp->ev_pp.pp_xid, msg_size);
				hdr_sz = sizeof (*ev_hdrp) +
				    1*(sizeof (ev_hdrp->ev_lens[0]));
				fma_event_size = hdr_sz + ev_hdrp->ev_lens[0];
				if (fma_event_size != msg_size) {
					fmd_hdl_debug(fmd_hdl, "info: wrong "
					    "ev msg size received\n");
					continue;
					/*
					 * Simply  do nothing. The send side
					 * will timedcond_wait waiting on the
					 * resp msg will timeout and
					 * re-send the same msg.
					 */
				}
				if (etm_debug_lvl >= 3) {
					fmd_hdl_debug(fmd_hdl,  "info: recv msg"
					    " size %d hdrsz %d evp size %d\n",
					    msg_size, hdr_sz,
					    ev_hdrp->ev_lens[0]);
				}

				if (ev_hdrp->ev_pp.pp_xid !=
				    iosvc->xid_posted_ev) {
					/*
					 * different from last xid posted to
					 * fmd, post to fmd now.
					 */
					buf = msg + hdr_sz;
					rc = nvlist_unpack(buf,
					    ev_hdrp->ev_lens[0], &evp, 0);
					rc = nvlist_size(evp, &evsz,
					    NV_ENCODE_XDR);
					fmd_hdl_debug(fmd_hdl,
					    "info: evp size %d before fmd"
					    "post\n", evsz);

					if ((rc = etm_post_to_fmd(fmd_hdl,
					    iosvc->fmd_xprt, evp)) >= 0) {
						fmd_hdl_debug(fmd_hdl,
						    "info: xid posted to fmd %d"
						    "\n",
						    ev_hdrp->ev_pp.pp_xid);
						iosvc->xid_posted_ev =
						    ev_hdrp->ev_pp.pp_xid;
					}
				}

				/*
				 * ready to  send the RESPONSE msg back
				 * reuse the msg buffer as the response buffer
				 */
				resp_hdrp = (etm_proto_v1_resp_hdr_t *)
				    ((ptrdiff_t)msg);
				resp_hdrp->resp_pp.pp_msg_type =
				    ETM_MSG_TYPE_RESPONSE;

				resp_hdrp->resp_code = resp_code;
				resp_hdrp->resp_len = sizeof (*resp_hdrp);

				/*
				 * send the whole response msg in one send
				 */
				if ((*etm_ds_send_msg)(iosvc->ds_hdl, msg,
				    sizeof (*resp_hdrp)) != 0) {
					fmd_hdl_debug(fmd_hdl,
					    "info: send response msg failed\n");
				} else {
					fmd_hdl_debug(fmd_hdl,
					    "info: ds send resp msg ok"
					    "size %d\n", sizeof (*resp_hdrp));
				}
			} else if (pp->pp_msg_type == ETM_MSG_TYPE_RESPONSE) {
				fmd_hdl_debug(fmd_hdl,
				    "info: ds received respond msg xid=%d"
				    "msg_size=%d for ldom %s\n", pp->pp_xid,
				    msg_size, iosvc->ldom_name);
				if (sizeof (*resp_hdrp) != msg_size) {
					fmd_hdl_debug(fmd_hdl,
					    "info: wrong resp msg size"
					    "received\n");
					fmd_hdl_debug(fmd_hdl,
					    "info: resp msg size %d recv resp"
					    "msg size %d\n",
					    sizeof (*resp_hdrp), msg_size);
					continue;
				}
				/*
				 * is the pp.pp_xid == iosvc->cur_send_xid+1,
				 * if so, nudge the send routine to send next
				 */
				if (pp->pp_xid != iosvc->cur_send_xid+1) {
					fmd_hdl_debug(fmd_hdl,
					    "info: ds received resp msg xid=%d "
					    "doesn't match cur_send_id=%d\n",
					    pp->pp_xid, iosvc->cur_send_xid+1);
					continue;
				}
				(void) pthread_mutex_lock(&iosvc->msg_ack_lock);
				iosvc->ack_ok = 1;
				(void) pthread_cond_signal(&iosvc->msg_ack_cv);
				(void) pthread_mutex_unlock(
				    &iosvc->msg_ack_lock);
				fmd_hdl_debug(fmd_hdl,
				    "info: signaling msg_ack_cv\n");
			} else {
				/*
				 * place holder for future msg types
				 */
				fmd_hdl_debug(fmd_hdl,
				    "info: ds received unrecognized msg\n");
			}
			if (mem_alloc) {
				fmd_hdl_free(fmd_hdl, msg, msg_size);
				mem_alloc = 0;
				msg = msgbuf;
			}
		} else {
			if (etm_debug_lvl >= 3) {
				fmd_hdl_debug(fmd_hdl,
				    "info: ds_recv_msg() failed\n");
			}
		} /* ds_recv_msg() returns */
	} /* etm_is_dying */

	/*
	 * need to free the mem allocated in msg upon exiting the thread
	 */
	if (mem_alloc) {
		fmd_hdl_free(fmd_hdl, msg, msg_size);
		mem_alloc = 0;
		msg = msgbuf;
	}
	fmd_hdl_debug(fmd_hdl, "info; etm recv thread exiting \n");
} /* etm_recv_from_remote_root */



/*
 * etm_ds_init
 *		initialize DS services function pointers by calling
 *		dlopen() followed by  dlsym() for each ds func.
 *		if any dlopen() or dlsym() call fails, return -ENOENT
 *		return >0 for successs, -ENOENT for failure
 */
static int
etm_ds_init(fmd_hdl_t *hdl)
{
	int rc = 0;

	if ((etm_dl_hdl = dlopen(etm_dl_path, etm_dl_mode)) == NULL) {
		fmd_hdl_debug(hdl, "error: failed to dlopen %s\n", etm_dl_path);
		return (-ENOENT);
	}

	etm_ds_svc_reg = (int (*)(ds_capability_t *cap, ds_ops_t *ops))
	    dlsym(etm_dl_hdl, "ds_svc_reg");
	if (etm_ds_svc_reg == NULL) {
		fmd_hdl_debug(hdl,
		    "error: failed to dlsym ds_svc_reg() w/ error %s\n",
		    dlerror());
		rc = -ENOENT;
	}


	etm_ds_clnt_reg = (int (*)(ds_capability_t *cap, ds_ops_t *ops))
	    dlsym(etm_dl_hdl, "ds_clnt_reg");
	if (etm_ds_clnt_reg == NULL) {
		fmd_hdl_debug(hdl,
		    "error: dlsym(ds_clnt_reg) failed w/ errno %d\n", errno);
		rc = -ENOENT;
	}

	etm_ds_send_msg = (int (*)(ds_hdl_t hdl, void *buf, size_t buflen))
	    dlsym(etm_dl_hdl, "ds_send_msg");
	if (etm_ds_send_msg == NULL) {
		fmd_hdl_debug(hdl, "error: dlsym(ds_send_msg) failed\n");
		rc = -ENOENT;
	}

	etm_ds_recv_msg = (int (*)(ds_hdl_t hdl, void *buf, size_t buflen,
	    size_t *msglen))dlsym(etm_dl_hdl, "ds_recv_msg");
	if (etm_ds_recv_msg == NULL) {
		fmd_hdl_debug(hdl, "error: dlsym(ds_recv_msg) failed\n");
		rc = -ENOENT;
	}

	etm_ds_fini = (int (*)(void))dlsym(etm_dl_hdl, "ds_fini");
	if (etm_ds_fini == NULL) {
		fmd_hdl_debug(hdl, "error: dlsym(ds_fini) failed\n");
		rc = -ENOENT;
	}

	if (rc == -ENOENT) {
		(void) dlclose(etm_dl_hdl);
	}
	return (rc);

} /* etm_ds_init() */


/*
 * -------------------------- FMD entry points -------------------------------
 */

/*
 * _fmd_init - initialize the transport for use by ETM and start the
 *		server daemon to accept new connections to us
 *
 *		FMD will read our *.conf and subscribe us to FMA events
 */

void
_fmd_init(fmd_hdl_t *hdl)
{
	struct timeval		tmv;		/* timeval */
	ssize_t			n;		/* gen use */
	const struct facility	*fp;		/* syslog facility matching */
	char			*facname;	/* syslog facility property */
	uint32_t		type_mask;	/* type of the local host */
	int			rc;		/* funcs return code */


	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0) {
		return; /* invalid data in configuration file */
	}

	fmd_hdl_debug(hdl, "info: module initializing\n");

	init_hdl = hdl;
	etm_lhp = ldom_init(etm_init_alloc, etm_init_free);

	/*
	 * decide the ldom type, do initialization accordingly
	 */
	if ((rc = ldom_get_type(etm_lhp, &type_mask)) != 0) {
		fmd_hdl_debug(hdl, "error: can't decide ldom type\n");
		fmd_hdl_debug(hdl, "info: module unregistering\n");
		ldom_fini(etm_lhp);
		fmd_hdl_unregister(hdl);
		return;
	}

	if ((type_mask & LDOM_TYPE_LEGACY) || (type_mask & LDOM_TYPE_CONTROL)) {
		if (type_mask & LDOM_TYPE_LEGACY) {
			/*
			 * running on a legacy sun4v domain,
			 * act as the the old sun4v
			 */
			etm_ldom_type = LDOM_TYPE_LEGACY;
			fmd_hdl_debug(hdl, "info: running as the old sun4v\n");
			ldom_fini(etm_lhp);
		} else if (type_mask & LDOM_TYPE_CONTROL) {
			etm_ldom_type = LDOM_TYPE_CONTROL;
			fmd_hdl_debug(hdl, "info: running as control domain\n");

			/*
			 * looking for libds.so.1.
			 * If not found, don't do DS registration. As a result,
			 * there will be no DS callbacks or other DS services.
			 */
			if (etm_ds_init(hdl) >= 0) {
				etm_filter_init(hdl);
				etm_ckpt_init(hdl);

				flags = FMD_XPRT_RDWR | FMD_XPRT_ACCEPT;

				/*
				 * ds client registration
				 */
				if ((rc = (*etm_ds_clnt_reg)(&iosvc_caps,
				    &iosvc_ops))) {
					fmd_hdl_debug(hdl,
					"error: ds_clnt_reg(): errno %d\n", rc);
				}
			} else {
				fmd_hdl_debug(hdl, "error: dlopen() libds "
				    "failed, continue without the DS services");
			}

			/*
			 * register for ldom status events
			 */
			if ((rc = ldom_register_event(etm_lhp,
			    ldom_event_handler, hdl))) {
				fmd_hdl_debug(hdl,
				    "error: ldom_register_event():"
				    " errno %d\n", rc);
			}

			/*
			 * create the thread for handling both the ldom status
			 * change and service events
			 */
			etm_async_e_tid = fmd_thr_create(hdl,
			    etm_async_event_handler, hdl);
		}

		/* setup statistics and properties from FMD */

		(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC,
		    sizeof (etm_stats) / sizeof (fmd_stat_t),
		    (fmd_stat_t *)&etm_stats);

		etm_fma_resp_wait_time = fmd_prop_get_int32(hdl,
		    ETM_PROP_NM_FMA_RESP_WAIT_TIME);
		etm_debug_lvl = fmd_prop_get_int32(hdl, ETM_PROP_NM_DEBUG_LVL);
		etm_debug_max_ev_cnt = fmd_prop_get_int32(hdl,
		    ETM_PROP_NM_DEBUG_MAX_EV_CNT);
		fmd_hdl_debug(hdl, "info: etm_debug_lvl %d "
		    "etm_debug_max_ev_cnt %d\n", etm_debug_lvl,
		    etm_debug_max_ev_cnt);

		etm_resp_q_max_len = fmd_prop_get_int32(hdl,
		    ETM_PROP_NM_MAX_RESP_Q_LEN);
		etm_stats.etm_resp_q_max_len.fmds_value.ui64 =
		    etm_resp_q_max_len;
		etm_bad_acc_to_sec = fmd_prop_get_int32(hdl,
		    ETM_PROP_NM_BAD_ACC_TO_SEC);

		/*
		 * obtain an FMD transport handle so we can post
		 * FMA events later
		 */

		etm_fmd_xprt = fmd_xprt_open(hdl, FMD_XPRT_RDONLY, NULL, NULL);

		/*
		 * encourage protocol transaction id to be unique per module
		 * load
		 */

		(void) gettimeofday(&tmv, NULL);
		etm_xid_cur = (uint32_t)((tmv.tv_sec << 10) |
		    ((unsigned long)tmv.tv_usec >> 10));

		/* init the ETM transport */

		if ((n = etm_xport_init(hdl)) != 0) {
			fmd_hdl_error(hdl, "error: bad xport init errno %d\n",
			    (-n));
			fmd_hdl_unregister(hdl);
			return;
		}

		/*
		 * Cache any properties we use every time we receive an alert.
		 */
		syslog_file = fmd_prop_get_int32(hdl, ETM_PROP_NM_SYSLOGD);
		syslog_cons = fmd_prop_get_int32(hdl, ETM_PROP_NM_CONSOLE);

		if (syslog_file && (syslog_logfd = open("/dev/conslog",
		    O_WRONLY | O_NOCTTY)) == -1) {
			fmd_hdl_error(hdl,
			    "error: failed to open /dev/conslog");
			syslog_file = 0;
		}

		if (syslog_cons && (syslog_msgfd = open("/dev/sysmsg",
		    O_WRONLY | O_NOCTTY)) == -1) {
			fmd_hdl_error(hdl, "error: failed to open /dev/sysmsg");
			syslog_cons = 0;
		}

		if (syslog_file) {
			/*
			 * Look up the value of the "facility" property and
			 * use it to determine * what syslog LOG_* facility
			 * value we use to fill in our log_ctl_t.
			 */
			facname = fmd_prop_get_string(hdl,
			    ETM_PROP_NM_FACILITY);

			for (fp = syslog_facs; fp->fac_name != NULL; fp++) {
				if (strcmp(fp->fac_name, facname) == 0)
					break;
			}

			if (fp->fac_name == NULL) {
				fmd_hdl_error(hdl, "error: invalid 'facility'"
				    " setting: %s\n", facname);
				syslog_file = 0;
			} else {
				syslog_facility = fp->fac_value;
				syslog_ctl.flags = SL_CONSOLE | SL_LOGONLY;
			}

			fmd_prop_free_string(hdl, facname);
		}

		/*
		 * start the message responder and the connection acceptance
		 * server; request protocol version be negotiated after waiting
		 * a second for the receiver to be ready to start handshaking
		 */

		etm_resp_tid = fmd_thr_create(hdl, etm_responder, hdl);
		etm_svr_tid = fmd_thr_create(hdl, etm_server, hdl);

		(void) etm_sleep(ETM_SLEEP_QUIK);
		etm_req_ver_negot(hdl);

	} else if (type_mask & LDOM_TYPE_ROOT) {
		etm_ldom_type = LDOM_TYPE_ROOT;
		fmd_hdl_debug(hdl, "info: running as root domain\n");

		/*
		 * looking for libds.so.1.
		 * If not found, don't do DS registration. As a result,
		 * there will be no DS callbacks or other DS services.
		 */
		if (etm_ds_init(hdl) < 0) {
			fmd_hdl_debug(hdl,
			    "error: dlopen() libds failed, "
			    "module unregistering\n");
			ldom_fini(etm_lhp);
			fmd_hdl_unregister(hdl);
			return;
		}

		/*
		 * DS service registration
		 */
		if ((rc = (*etm_ds_svc_reg)(&iosvc_caps, &iosvc_ops))) {
			fmd_hdl_debug(hdl, "error: ds_svc_reg(): errno %d\n",
			    rc);
		}

		/*
		 * this thread is created for ds_reg_cb/ds_unreg_cb
		 */
		etm_async_e_tid = fmd_thr_create(hdl,
		    etm_async_event_handler, hdl);

		flags = FMD_XPRT_RDWR;
	} else if ((type_mask & LDOM_TYPE_IO) || (type_mask == 0)) {
		/*
		 * Do not load this module if it is
		 * . runing on a non-root ldom
		 * . the domain owns no io devices
		 */
		fmd_hdl_debug(hdl,
		    "info: non-root ldom, module unregistering\n");
		ldom_fini(etm_lhp);
		fmd_hdl_unregister(hdl);
		return;
	} else {
		/*
		 * place holder, all other cases. unload etm for now
		 */
		fmd_hdl_debug(hdl,
		    "info: other ldom type, module unregistering\n");
		ldom_fini(etm_lhp);
		fmd_hdl_unregister(hdl);
		return;
	}

	fmd_hdl_debug(hdl, "info: module initialized ok\n");

} /* _fmd_init() */

/*
 * etm_recv - receive an FMA event from FMD and transport it
 *		to the remote endpoint
 */

/*ARGSUSED*/
void
etm_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *evp, const char *class)
{
	etm_xport_addr_t	*addrv;	/* vector of transport addresses */
	etm_xport_conn_t	conn;	/* connection handle */
	etm_proto_v1_ev_hdr_t	*hdrp;	/* for FMA_EVENT msg */
	ssize_t			i, n;	/* gen use */
	size_t			sz;	/* header size */
	size_t			buflen;	/* size of packed FMA event */
	uint8_t			*buf;	/* tmp buffer for packed FMA event */

	/*
	 * if this is running on a Root Domain, ignore the events,
	 * return right away
	 */
	if (etm_ldom_type == LDOM_TYPE_ROOT)
		return;

	buflen = 0;
	if ((n = nvlist_size(evp, &buflen, NV_ENCODE_XDR)) != 0) {
		fmd_hdl_error(hdl, "error: FMA event dropped: "
		    "event size errno %d class %s\n", n, class);
		etm_stats.etm_os_nvlist_size_fail.fmds_value.ui64++;
		etm_stats.etm_wr_drop_fmaevent.fmds_value.ui64++;
		return;
	}

	fmd_hdl_debug(hdl, "info: rcvd event %p from FMD\n", evp);
	fmd_hdl_debug(hdl, "info: cnt %llu class %s\n",
	    etm_stats.etm_rd_fmd_fmaevent.fmds_value.ui64, class);

	etm_stats.etm_rd_fmd_bytes.fmds_value.ui64 += buflen;
	etm_stats.etm_rd_fmd_fmaevent.fmds_value.ui64++;

	/*
	 * if the debug limit has been set, avoid excessive traffic,
	 * for example, an infinite cycle using loopback nodes
	 */

	if ((etm_debug_max_ev_cnt >= 0) &&
	    (etm_stats.etm_rd_fmd_fmaevent.fmds_value.ui64 >
	    etm_debug_max_ev_cnt)) {
		fmd_hdl_debug(hdl, "warning: FMA event dropped: "
		    "event %p cnt %llu > debug max %d\n", evp,
		    etm_stats.etm_rd_fmd_fmaevent.fmds_value.ui64,
		    etm_debug_max_ev_cnt);
		etm_stats.etm_wr_drop_fmaevent.fmds_value.ui64++;
		return;
	}

	/* allocate a buffer for the FMA event and nvlist pack it */

	buf = fmd_hdl_zalloc(hdl, buflen, FMD_SLEEP);

	/*
	 * increment the ttl value if the event is from remote (a root domain)
	 * uncomment this when enabling fault forwarding from Root domains
	 * to Control domain.
	 *
	 * uint8_t			ttl;
	 * if (fmd_event_local(hdl, evp) != FMD_EVF_LOCAL) {
	 *	if (nvlist_lookup_uint8(evp, FMD_EVN_TTL, &ttl) == 0) {
	 *		(void) nvlist_remove(evp, FMD_EVN_TTL, DATA_TYPE_UINT8);
	 *		(void) nvlist_add_uint8(evp, FMD_EVN_TTL, ttl + 1);
	 *	}
	 * }
	 */

	if ((n = nvlist_pack(evp, (char **)&buf, &buflen,
	    NV_ENCODE_XDR, 0)) != 0) {
		fmd_hdl_error(hdl, "error: FMA event dropped: "
		    "event pack errno %d class %s\n", n, class);
		etm_stats.etm_os_nvlist_pack_fail.fmds_value.ui64++;
		etm_stats.etm_wr_drop_fmaevent.fmds_value.ui64++;
		fmd_hdl_free(hdl, buf, buflen);
		return;
	}

	/* get vector of dst addrs and send the FMA event to each one */

	if ((addrv = etm_xport_get_ev_addrv(hdl, evp)) == NULL) {
		fmd_hdl_error(hdl, "error: FMA event dropped: "
		    "bad event dst addrs errno %d\n", errno);
		etm_stats.etm_xport_get_ev_addrv_fail.fmds_value.ui64++;
		etm_stats.etm_wr_drop_fmaevent.fmds_value.ui64++;
		fmd_hdl_free(hdl, buf, buflen);
		return;
	}

	for (i = 0; addrv[i] != NULL; i++) {

		/* open a new connection to this dst addr */

		if ((n = etm_conn_open(hdl, "FMA event dropped: "
		    "bad conn open on new ev", addrv[i], &conn)) < 0) {
			etm_stats.etm_wr_drop_fmaevent.fmds_value.ui64++;
			continue;
		}

		(void) pthread_mutex_lock(&etm_write_lock);

		/* write the ETM message header */

		if ((hdrp = etm_hdr_write(hdl, conn, evp, NV_ENCODE_XDR,
		    &sz)) == NULL) {
			(void) pthread_mutex_unlock(&etm_write_lock);
			fmd_hdl_error(hdl, "error: FMA event dropped: "
			    "bad hdr write errno %d\n", errno);
			(void) etm_conn_close(hdl,
			    "bad conn close per bad hdr wr", conn);
			etm_stats.etm_wr_drop_fmaevent.fmds_value.ui64++;
			continue;
		}

		fmd_hdl_free(hdl, hdrp, sz);	/* header not needed */
		etm_stats.etm_wr_hdr_fmaevent.fmds_value.ui64++;
		fmd_hdl_debug(hdl, "info: hdr xport write ok for event %p\n",
		    evp);

		/* write the ETM message body, ie, the packed nvlist */

		if ((n = etm_io_op(hdl, "FMA event dropped: "
		    "bad io write on event", conn,
		    buf, buflen, ETM_IO_OP_WR)) < 0) {
			(void) pthread_mutex_unlock(&etm_write_lock);
			(void) etm_conn_close(hdl,
			    "bad conn close per bad body wr", conn);
			etm_stats.etm_wr_drop_fmaevent.fmds_value.ui64++;
			continue;
		}

		(void) pthread_mutex_unlock(&etm_write_lock);

		etm_stats.etm_wr_body_fmaevent.fmds_value.ui64++;
		etm_stats.etm_wr_xport_bytes.fmds_value.ui64 += buflen;
		fmd_hdl_debug(hdl, "info: body xport write ok for event %p\n",
		    evp);

		/* close the connection */

		(void) etm_conn_close(hdl, "bad conn close after event send",
		    conn);
	} /* foreach dst addr in the vector */

	etm_xport_free_addrv(hdl, addrv);
	fmd_hdl_free(hdl, buf, buflen);

} /* etm_recv() */


/*
 * etm_send -	receive an FMA event from FMD and enQ it in the iosvc.Q.
 *		etm_send_to_remote_root() deQ and xprt the FMA events to a
 *		remote root domain
 *		return FMD_SEND_SUCCESS for success,
 *		       FMD_SEND_FAILED for error
 */

/*ARGSUSED*/
int
etm_send(fmd_hdl_t *fmd_hdl, fmd_xprt_t *xp, fmd_event_t *ep, nvlist_t *nvl)
{
	uint32_t	pack_it;	/* whether to pack/enq the event */
	etm_pack_msg_type_t	msg_type;
					/* tell etm_pack_ds_msg() what to do */
	etm_iosvc_t	*iosvc;		/* ptr to cur iosvc struct */
	char		*class;		/* nvlist class name */

	pack_it = 1;
	msg_type = FMD_XPRT_OTHER_MSG;

	(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
	if (class == NULL) {
		pack_it = 0;
	} else  {
		if (etm_debug_lvl >= 1) {
			fmd_hdl_debug(fmd_hdl,
			    "info: evp class= %s in etm_send\n", class);
		}

		if (etm_ldom_type ==  LDOM_TYPE_CONTROL) {
			iosvc =
			    (etm_iosvc_t *)fmd_xprt_getspecific(fmd_hdl, xp);

			/*
			 * check the flag FORWARDING_FAULTS_TO_CONTROL to
			 * decide if or not to drop fault subscription
			 * control msgs
			 */
			if (strcmp(class, "resource.fm.xprt.subscribe") == 0) {
				pack_it = 0;
				/*
				 * if (FORWARDING_FAULTS_TO_CONTROL == 1) {
				 * (void) nvlist_lookup_string(nvl,
				 *    FM_RSRC_XPRT_SUBCLASS, &subclass);
				 * if (strcmp(subclass, "list.suspect")
				 *    == 0) {
				 *	pack_it = 1;
				 *	msg_action = FMD_XPRT_OTHER_MSG;
				 * }
				 * if (strcmp(subclass, "list.repaired")
				 *    == 0) {
				 *	pack_it = 1;
				 *	msg_action = FMD_XPRT_OTHER_MSG;
				 * }
				 * }
				 */
			}
			if (strcmp(class, "resource.fm.xprt.run") == 0) {
				pack_it = 1;
				msg_type = FMD_XPRT_RUN_MSG;
			}
		} else { /* has to be the root domain ldom */
			iosvc = &io_svc;
			/*
			 * drop all ereport and fault subscriptions
			 * are we dropping too much here, more than just ereport
			 * and fault subscriptions? need to check
			 */
			if (strcmp(class, "resource.fm.xprt.subscribe") == 0)
				pack_it = 0;
			if (strcmp(class, "resource.fm.xprt.run") == 0) {
				pack_it = 1;
				msg_type = FMD_XPRT_RUN_MSG;
			}
		}
	}

	if (pack_it)  {
		if (etm_debug_lvl >= 1) {
			fmd_hdl_debug(fmd_hdl,
			    "info: ldom name returned from xprt get specific="
			    "%s xprt=%lld\n", iosvc->ldom_name, xp);
		}
		/*
		 * pack the etm msg for the DS library and  enq in io_svc->Q
		 * when the hdrp is NULL, the packing func will use the static
		 * iosvc_hdr
		 */
		(void) etm_pack_ds_msg(fmd_hdl, iosvc, NULL, 0, nvl, msg_type,
		    ETM_CKPT_NOOP);
	}

	return (FMD_SEND_SUCCESS);

} /* etm_send() */



/*
 * _fmd_fini - stop the server daemon and teardown the transport
 */

void
_fmd_fini(fmd_hdl_t *hdl)
{
	ssize_t			n;		/* gen use */
	etm_iosvc_t		*iosvc;		/* ptr to insvc struct */
	etm_iosvc_q_ele_t	msg_ele;	/* iosvc msg ele */
	uint32_t		i;		/* for loop var */

	fmd_hdl_debug(hdl, "info: module finalizing\n");

	/* kill the connection server and responder ; wait for them to die */

	etm_is_dying = 1;

	if (etm_svr_tid != 0) {
		fmd_thr_signal(hdl, etm_svr_tid);
		fmd_thr_destroy(hdl, etm_svr_tid);
		etm_svr_tid = 0;
	} /* if server thread was successfully created */

	if (etm_resp_tid != 0) {
		fmd_thr_signal(hdl, etm_resp_tid);
		fmd_thr_destroy(hdl, etm_resp_tid);
		etm_resp_tid = 0;
	} /* if responder thread was successfully created */

	if (etm_async_e_tid != 0) {
		fmd_thr_signal(hdl, etm_async_e_tid);
		fmd_thr_destroy(hdl, etm_async_e_tid);
		etm_async_e_tid = 0;
	} /* if async event handler thread was successfully created */


	if ((etm_ldom_type == LDOM_TYPE_LEGACY) ||
	    (etm_ldom_type == LDOM_TYPE_CONTROL)) {

		/* teardown the transport and cleanup syslogging */
		if ((n = etm_xport_fini(hdl)) != 0) {
			fmd_hdl_error(hdl, "warning: xport fini errno %d\n",
			    (-n));
		}
		if (etm_fmd_xprt != NULL) {
			fmd_xprt_close(hdl, etm_fmd_xprt);
		}

		if (syslog_logfd != -1) {
			(void) close(syslog_logfd);
		}
		if (syslog_msgfd != -1) {
			(void) close(syslog_msgfd);
		}
	}

	if (etm_ldom_type == LDOM_TYPE_CONTROL)  {
		if (ldom_unregister_event(etm_lhp))
			fmd_hdl_debug(hdl, "ldom_unregister_event() failed\n");

		/*
		 * On control domain side, there may be multiple iosvc struct
		 * in use, one for each bound/active domain. Each struct
		 * manages a queue of fma events destined to the root domain.
		 * Need to go thru every iosvc struct to clean up its resources.
		 */
		for (i = 0; i < NUM_OF_ROOT_DOMAINS; i++) {
			if (iosvc_list[i].ldom_name[0] != '\0') {
				/*
				 * found an iosvc struct for a root domain
				 */
				iosvc = &iosvc_list[i];
				(void) pthread_mutex_lock(&iosvc_list_lock);
				etm_iosvc_cleanup(hdl, iosvc, B_TRUE, B_FALSE);
				(void) pthread_mutex_unlock(&iosvc_list_lock);

			} else {
				/*
				 * reach the end of existing iosvc structures
				 */
				continue;
			}
		} /* for i<NUM_OF_ROOT_DOMAINS */
		etm_ckpt_fini(hdl);
		etm_filter_fini(hdl);

		ldom_fini(etm_lhp);

	} else if (etm_ldom_type == LDOM_TYPE_ROOT) {
		/*
		 * On root domain side, there is only one iosvc struct in use.
		 */
		iosvc = &io_svc;
		if (iosvc->send_tid != 0) {
			fmd_thr_signal(hdl, iosvc->send_tid);
			fmd_thr_destroy(hdl, iosvc->send_tid);
			iosvc->send_tid = 0;
		} /* if io svc send thread was successfully created */

		if (iosvc->recv_tid != 0) {
			fmd_thr_signal(hdl, iosvc->recv_tid);
			fmd_thr_destroy(hdl, iosvc->recv_tid);
			iosvc->recv_tid = 0;
		} /* if io svc receive thread was successfully created */

		(void) pthread_mutex_lock(&iosvc->msg_q_lock);
		while (iosvc->msg_q_cur_len > 0) {
			(void) etm_iosvc_msg_deq(hdl, iosvc, &msg_ele);
			fmd_hdl_free(hdl, msg_ele.msg, msg_ele.msg_size);
		}
		(void) pthread_mutex_unlock(&iosvc->msg_q_lock);

		if (iosvc->fmd_xprt != NULL)
			fmd_xprt_close(hdl, iosvc->fmd_xprt);
		ldom_fini(etm_lhp);
	}
	if (etm_ds_fini) {
		(*etm_ds_fini)();
		(void) dlclose(etm_dl_hdl);
	}

	fmd_hdl_debug(hdl, "info: module finalized ok\n");

} /* _fmd_fini() */
