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
 *
 * UDAPL kernel agent
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/kstat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <sys/taskq.h>
#include <sys/open.h>
#include <sys/uio.h>
#include <sys/cpuvar.h>
#include <sys/atomic.h>
#include <sys/sysmacros.h>
#include <sys/esunddi.h>
#include <sys/avl.h>
#include <sys/cred.h>
#include <sys/note.h>
#include <sys/ib/ibtl/ibti.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <daplt_if.h>
#include <daplt.h>

/*
 * The following variables support the debug log buffer scheme.
 */
#ifdef	DEBUG
static char daplka_dbgbuf[0x80000];
#else /* DEBUG */
static char daplka_dbgbuf[0x4000];
#endif /* DEBUG */
static int daplka_dbgsize = sizeof (daplka_dbgbuf);
static size_t daplka_dbgnext;
static int daplka_dbginit = 0;
static kmutex_t daplka_dbglock;
_NOTE(MUTEX_PROTECTS_DATA(daplka_dbglock,
    daplka_dbgbuf
    daplka_dbgnext))

static int daplka_dbg = 0x0103;
static void daplka_console(const char *, ...);
static void daplka_debug(const char *, ...);
static int daplka_apm = 0x1;			/* default enable */
static int daplka_failback = 0x1;		/* default enable */
static int daplka_query_aft_setaltpath = 10;

#define	DERR				\
	if (daplka_dbg & 0x100) 	\
	    daplka_debug

#ifdef DEBUG

#define	DINFO				\
	daplka_console

#define	D1				\
	if (daplka_dbg & 0x01)		\
	    daplka_debug
#define	D2				\
	if (daplka_dbg & 0x02) 		\
	    daplka_debug
#define	D3				\
	if (daplka_dbg & 0x04) 		\
	    daplka_debug
#define	D4				\
	if (daplka_dbg & 0x08) 		\
	    daplka_debug

#else /* DEBUG */

#define	DINFO	if (0) printf
#define	D1	if (0) printf
#define	D2	if (0) printf
#define	D3	if (0) printf
#define	D4	if (0) printf

#endif /* DEBUG */

/*
 * driver entry points
 */
static int daplka_open(dev_t *, int, int, struct cred *);
static int daplka_close(dev_t, int, int, struct cred *);
static int daplka_attach(dev_info_t *, ddi_attach_cmd_t);
static int daplka_detach(dev_info_t *, ddi_detach_cmd_t);
static int daplka_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int daplka_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/*
 * types of ioctls
 */
static int daplka_common_ioctl(int, minor_t, intptr_t, int, cred_t *, int *);
static int daplka_misc_ioctl(int, daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_ep_ioctl(int, daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_evd_ioctl(int, daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_mr_ioctl(int, daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_cno_ioctl(int, daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_pd_ioctl(int, daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_sp_ioctl(int, daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_srq_ioctl(int, daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);

/*
 * common ioctls and supporting functions
 */
static int daplka_ia_create(minor_t, intptr_t, int, cred_t *, int *);
static int daplka_ia_destroy(daplka_resource_t *);

/*
 * EP ioctls and supporting functions
 */
static int daplka_ep_create(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_ep_modify(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_ep_free(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_ep_connect(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_ep_disconnect(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_ep_reinit(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_ep_destroy(daplka_resource_t *);
static void daplka_hash_ep_free(void *);
static int daplka_ep_failback(void *objp, void *arg);
static int daplka_ep_altpath(daplka_ep_resource_t *, ib_gid_t *);

static uint32_t daplka_ep_get_state(daplka_ep_resource_t *);
static void daplka_ep_set_state(daplka_ep_resource_t *, uint32_t, uint32_t);
static boolean_t daplka_ep_transition_is_valid(uint32_t, uint32_t);
static daplka_timer_info_t *daplka_timer_info_alloc(daplka_ep_resource_t *);
static void daplka_timer_info_free(daplka_timer_info_t *);
static void daplka_timer_handler(void *);
static void daplka_timer_dispatch(void *);
static void daplka_timer_thread(void *);
static int daplka_cancel_timer(daplka_ep_resource_t *);
static void daplka_hash_timer_free(void *);

/*
 * EVD ioctls and supporting functions
 */
static int daplka_evd_create(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_cq_resize(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_evd_free(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_event_poll(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_evd_destroy(daplka_resource_t *);
static void daplka_cq_handler(ibt_cq_hdl_t, void *);
static void daplka_evd_wakeup(daplka_evd_resource_t *,
    daplka_evd_event_list_t *, daplka_evd_event_t *);
static void daplka_evd_event_enqueue(daplka_evd_event_list_t *,
    daplka_evd_event_t *);
static daplka_evd_event_t *daplka_evd_event_dequeue(daplka_evd_event_list_t *);
static void daplka_hash_evd_free(void *);


/*
 * SRQ ioctls and supporting functions
 */
static int daplka_srq_create(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_srq_resize(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_srq_free(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_srq_destroy(daplka_resource_t *);
static void daplka_hash_srq_free(void *);

/*
 * Miscellaneous ioctls
 */
static int daplka_cr_accept(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_cr_reject(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_cr_handoff(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_ia_query(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);

/*
 * PD ioctls and supporting functions
 */
static int daplka_pd_alloc(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_pd_free(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_pd_destroy(daplka_resource_t *);
static void daplka_hash_pd_free(void *);

/*
 * SP ioctls and supporting functions
 */
static int daplka_service_register(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_service_deregister(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_sp_destroy(daplka_resource_t *);
static void daplka_hash_sp_free(void *);
static void daplka_hash_sp_unref(void *);

/*
 * MR ioctls and supporting functions
 */
static int daplka_mr_register(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_mr_register_lmr(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_mr_register_shared(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_mr_deregister(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_mr_sync(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_mr_destroy(daplka_resource_t *);
static void daplka_hash_mr_free(void *);
static void daplka_shared_mr_free(daplka_mr_resource_t *);

/*
 * MW ioctls and supporting functions
 */
static int daplka_mw_alloc(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_mw_free(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_mw_destroy(daplka_resource_t *);
static void daplka_hash_mw_free(void *);

/*
 * CNO ioctls and supporting functions
 */
static int daplka_cno_alloc(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_cno_free(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_cno_wait(daplka_ia_resource_t *, intptr_t, int,
    cred_t *, int *);
static int daplka_cno_destroy(daplka_resource_t *);
static void daplka_hash_cno_free(void *);

/*
 * CM handlers
 */
static  ibt_cm_status_t daplka_cm_rc_handler(void *, ibt_cm_event_t *,
    ibt_cm_return_args_t *, void *, ibt_priv_data_len_t);

static  ibt_cm_status_t daplka_cm_service_handler(void *, ibt_cm_event_t *,
    ibt_cm_return_args_t *, void *, ibt_priv_data_len_t);

static ibt_cm_status_t daplka_cm_service_req(daplka_sp_resource_t *,
    ibt_cm_event_t *, ibt_cm_return_args_t *, void *, ibt_priv_data_len_t);

/*
 * resource management routines
 */
static int daplka_resource_reserve(minor_t *);
static int daplka_resource_insert(minor_t, daplka_resource_t *);
static daplka_resource_t *daplka_resource_remove(minor_t rnum);
static daplka_resource_t *daplka_resource_lookup(minor_t);
static void daplka_resource_init(void);
static void daplka_resource_fini(void);
static struct daplka_resource_table daplka_resource;

/*
 * hash table routines
 */
static int daplka_hash_insert(daplka_hash_table_t *, uint64_t *, void *);
static int daplka_hash_remove(daplka_hash_table_t *, uint64_t, void **);
static void daplka_hash_walk(daplka_hash_table_t *, int (*)(void *, void *),
    void *, krw_t);
static void *daplka_hash_lookup(daplka_hash_table_t *, uint64_t);
static int daplka_hash_create(daplka_hash_table_t *, uint_t,
    void (*)(void *), void (*)(void *));
static void daplka_hash_destroy(daplka_hash_table_t *);
static uint32_t daplka_hash_getsize(daplka_hash_table_t *);
static void daplka_hash_generic_lookup(void *);

static uint32_t daplka_timer_hkey_gen();

/*
 * async event handlers
 */
static void daplka_async_event_create(ibt_async_code_t, ibt_async_event_t *,
    uint64_t, daplka_ia_resource_t *);
static void daplka_rc_async_handler(void *, ibt_hca_hdl_t, ibt_async_code_t,
    ibt_async_event_t *);
static void daplka_cq_async_handler(void *, ibt_hca_hdl_t, ibt_async_code_t,
    ibt_async_event_t *);
static void daplka_un_async_handler(void *, ibt_hca_hdl_t, ibt_async_code_t,
    ibt_async_event_t *);
static void daplka_async_handler(void *, ibt_hca_hdl_t, ibt_async_code_t,
    ibt_async_event_t *);
static void daplka_sm_notice_handler(void *, ib_gid_t, ibt_subnet_event_code_t,
    ibt_subnet_event_t *event);
static void daplka_sm_gid_avail(ib_gid_t *, ib_gid_t *);

/*
 * IBTF wrappers and default limits used for resource accounting
 */
static boolean_t	daplka_accounting_enabled = B_TRUE;
static uint32_t		daplka_max_qp_percent = 100;
static uint32_t		daplka_max_cq_percent = 100;
static uint32_t		daplka_max_pd_percent = 100;
static uint32_t		daplka_max_mw_percent = 100;
static uint32_t		daplka_max_mr_percent = 100;
static uint32_t		daplka_max_srq_percent = 100;

static ibt_status_t
daplka_ibt_alloc_rc_channel(daplka_ep_resource_t *, ibt_hca_hdl_t,
    ibt_chan_alloc_flags_t, ibt_rc_chan_alloc_args_t *,
    ibt_channel_hdl_t *, ibt_chan_sizes_t *);

static ibt_status_t
daplka_ibt_free_channel(daplka_ep_resource_t *, ibt_channel_hdl_t);

static ibt_status_t
daplka_ibt_alloc_cq(daplka_evd_resource_t *, ibt_hca_hdl_t,
    ibt_cq_attr_t *, ibt_cq_hdl_t *, uint_t *);

static ibt_status_t
daplka_ibt_free_cq(daplka_evd_resource_t *, ibt_cq_hdl_t);

static ibt_status_t
daplka_ibt_alloc_pd(daplka_pd_resource_t *, ibt_hca_hdl_t,
    ibt_pd_flags_t, ibt_pd_hdl_t *);

static ibt_status_t
daplka_ibt_free_pd(daplka_pd_resource_t *, ibt_hca_hdl_t, ibt_pd_hdl_t);

static ibt_status_t
daplka_ibt_alloc_mw(daplka_mw_resource_t *, ibt_hca_hdl_t, ibt_pd_hdl_t,
    ibt_mw_flags_t, ibt_mw_hdl_t *, ibt_rkey_t *);

static ibt_status_t
daplka_ibt_free_mw(daplka_mw_resource_t *, ibt_hca_hdl_t, ibt_mw_hdl_t);

static ibt_status_t
daplka_ibt_register_mr(daplka_mr_resource_t *, ibt_hca_hdl_t, ibt_pd_hdl_t,
    ibt_mr_attr_t *, ibt_mr_hdl_t *, ibt_mr_desc_t *);

static ibt_status_t
daplka_ibt_register_shared_mr(daplka_mr_resource_t *, ibt_hca_hdl_t,
    ibt_mr_hdl_t, ibt_pd_hdl_t, ibt_smr_attr_t *, ibt_mr_hdl_t *,
    ibt_mr_desc_t *);

static ibt_status_t
daplka_ibt_deregister_mr(daplka_mr_resource_t *, ibt_hca_hdl_t, ibt_mr_hdl_t);

static ibt_status_t
daplka_ibt_alloc_srq(daplka_srq_resource_t *, ibt_hca_hdl_t, ibt_srq_flags_t,
    ibt_pd_hdl_t, ibt_srq_sizes_t *, ibt_srq_hdl_t *, ibt_srq_sizes_t *);

static ibt_status_t
daplka_ibt_free_srq(daplka_srq_resource_t *, ibt_srq_hdl_t);

/*
 * macros for manipulating resource objects.
 * these macros can be used on objects that begin with a
 * daplka_resource_t header.
 */
#define	DAPLKA_RS_REFCNT(rp) ((rp)->header.rs_refcnt)

#define	DAPLKA_RS_REF(rp) {			\
	mutex_enter(&(rp)->header.rs_reflock);	\
	(rp)->header.rs_refcnt++;		\
	ASSERT((rp)->header.rs_refcnt != 0);	\
	mutex_exit(&(rp)->header.rs_reflock);	\
}

#define	DAPLKA_RS_UNREF(rp) {					\
	mutex_enter(&(rp)->header.rs_reflock);			\
	ASSERT((rp)->header.rs_refcnt != 0);			\
	if (--(rp)->header.rs_refcnt == 0) {			\
		ASSERT((rp)->header.rs_free != NULL);		\
		mutex_exit(&(rp)->header.rs_reflock);		\
		(rp)->header.rs_free((daplka_resource_t *)rp);	\
	} else {						\
		mutex_exit(&(rp)->header.rs_reflock);		\
	}							\
}

#define	DAPLKA_RS_INIT(rp, type, rnum, free_func) {	\
	(rp)->header.rs_refcnt = 1;			\
	(rp)->header.rs_type = (type);			\
	(rp)->header.rs_rnum = (rnum); 			\
	(rp)->header.rs_charged = 0;			\
	(rp)->header.rs_free = (free_func);		\
	mutex_init(&(rp)->header.rs_reflock, NULL,	\
	    MUTEX_DRIVER, NULL);			\
}

#define	DAPLKA_RS_FINI(rp) {				\
	mutex_destroy(&(rp)->header.rs_reflock);	\
}

#define	DAPLKA_RS_ACCT_INC(rp, cnt) {				\
	atomic_add_32(&(rp)->header.rs_charged, (cnt));		\
}
#define	DAPLKA_RS_ACCT_DEC(rp, cnt) {				\
	atomic_add_32(&(rp)->header.rs_charged, -(cnt));	\
}
#define	DAPLKA_RS_ACCT_CHARGED(rp) ((rp)->header.rs_charged)

#define	DAPLKA_RS_RNUM(rp) ((rp)->header.rs_rnum)
#define	DAPLKA_RS_TYPE(rp) ((rp)->header.rs_type)
#define	DAPLKA_RS_RESERVED(rp) ((intptr_t)(rp) == DAPLKA_RC_RESERVED)

/*
 * depending on the timeout value does a cv_wait_sig or cv_timedwait_sig
 */
#define	DAPLKA_EVD_WAIT(cvp, mp, timeout)			\
	((timeout) == LONG_MAX) ? cv_wait_sig((cvp), (mp)) :	\
	cv_timedwait_sig((cvp), (mp), (timeout))

#define	DAPLKA_HOLD_HCA_WITHOUT_LOCK(hca)	((hca)->hca_ref_cnt++)
#define	DAPLKA_RELE_HCA_WITHOUT_LOCK(hca)	((hca)->hca_ref_cnt--)

#define	DAPLKA_HOLD_HCA(dp, hca) {			\
	mutex_enter(&(dp)->daplka_mutex);		\
	DAPLKA_HOLD_HCA_WITHOUT_LOCK(hca);		\
	mutex_exit(&(dp)->daplka_mutex);		\
}

#define	DAPLKA_RELE_HCA(dp, hca) {			\
	mutex_enter(&(dp)->daplka_mutex);		\
	DAPLKA_RELE_HCA_WITHOUT_LOCK(hca);		\
	mutex_exit(&(dp)->daplka_mutex);		\
}

#define	DAPLKA_HCA_BUSY(hca)				\
	((hca)->hca_ref_cnt != 0 ||			\
	(hca)->hca_qp_count != 0 ||			\
	(hca)->hca_cq_count != 0 ||			\
	(hca)->hca_pd_count != 0 ||			\
	(hca)->hca_mw_count != 0 ||			\
	(hca)->hca_mr_count != 0)


static struct cb_ops daplka_cb_ops = {
	daplka_open,		/* cb_open */
	daplka_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	daplka_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	D_NEW | D_MP,		/* cb_flag */
	CB_REV,			/* rev */
	nodev,			/* int (*cb_aread)() */
	nodev			/* int (*cb_awrite)() */
};

static struct dev_ops daplka_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	daplka_info,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	daplka_attach,		/* devo_attach */
	daplka_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&daplka_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	nulldev,		/* power */
	ddi_quiesce_not_needed,	/* devo_quiesce */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,
	"uDAPL Service Driver",
	&daplka_ops,
};

static struct modlinkage modlinkage = {
#ifdef _LP64
	MODREV_1, { (void *) &modldrv, NULL, NULL, NULL, NULL, NULL, NULL }
#else
	MODREV_1, { (void *) &modldrv, NULL, NULL, NULL }
#endif
};

/*
 * daplka_dev holds global driver state and a list of HCAs
 */
static daplka_t *daplka_dev = NULL;
static void *daplka_state = NULL;

/*
 * global SP hash table
 */
static daplka_hash_table_t daplka_global_sp_htbl;

/*
 * timer_info hash table
 */
static daplka_hash_table_t daplka_timer_info_htbl;
static uint32_t daplka_timer_hkey = 0;

/*
 * shared MR avl tree
 */
static avl_tree_t daplka_shared_mr_tree;
static kmutex_t daplka_shared_mr_lock;
static int daplka_shared_mr_cmp(const void *, const void *);
_NOTE(MUTEX_PROTECTS_DATA(daplka_shared_mr_lock,
    daplka_shared_mr_tree))

/*
 * default kmem flags used by this driver
 */
static int daplka_km_flags = KM_SLEEP;

/*
 * taskq used for handling background tasks
 */
static taskq_t *daplka_taskq = NULL;

/*
 * daplka_cm_delay is the length of time the active
 * side needs to wait before timing out on the REP message.
 */
static clock_t daplka_cm_delay = 60000000;

/*
 * modunload will fail if pending_close is non-zero
 */
static uint32_t daplka_pending_close = 0;

static struct ibt_clnt_modinfo_s daplka_clnt_modinfo = {
	IBTI_V_CURR,
	IBT_USER,
	daplka_async_handler,
	NULL,
	DAPLKA_DRV_NAME
};

/*
 * Module Installation
 */
int
_init(void)
{
	int status;

	status = ddi_soft_state_init(&daplka_state, sizeof (daplka_t), 1);
	if (status != 0) {
		return (status);
	}

	mutex_init(&daplka_dbglock, NULL, MUTEX_DRIVER, NULL);
	bzero(daplka_dbgbuf, sizeof (daplka_dbgbuf));
	daplka_dbgnext = 0;
	daplka_dbginit = 1;

	daplka_resource_init();

	status = mod_install(&modlinkage);
	if (status != DDI_SUCCESS) {
		/* undo inits done before mod_install */
		daplka_resource_fini();
		mutex_destroy(&daplka_dbglock);
		ddi_soft_state_fini(&daplka_state);
	}
	return (status);
}

/*
 * Module Removal
 */
int
_fini(void)
{
	int	status;

	/*
	 * mod_remove causes detach to be called
	 */
	if ((status = mod_remove(&modlinkage)) != 0) {
		DERR("fini: mod_remove failed: 0x%x\n", status);
		return (status);
	}

	daplka_resource_fini();
	mutex_destroy(&daplka_dbglock);
	ddi_soft_state_fini(&daplka_state);

	return (status);
}

/*
 * Return Module Info.
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static void
daplka_enqueue_hca(daplka_t *dp, daplka_hca_t *hca)
{
	daplka_hca_t *h;

	ASSERT(mutex_owned(&dp->daplka_mutex));

	if (dp->daplka_hca_list_head == NULL) {
		dp->daplka_hca_list_head = hca;
	} else {
		h = dp->daplka_hca_list_head;
		while (h->hca_next != NULL)
			h = h->hca_next;

		h->hca_next = hca;
	}
}

static void
daplka_dequeue_hca(daplka_t *dp, daplka_hca_t *hca)
{
	daplka_hca_t *h;

	ASSERT(mutex_owned(&dp->daplka_mutex));

	if (dp->daplka_hca_list_head == hca)
		dp->daplka_hca_list_head = hca->hca_next;
	else {
		h = dp->daplka_hca_list_head;
		while (h->hca_next != hca)
			h = h->hca_next;
		h->hca_next = hca->hca_next;
	}
}

static int
daplka_init_hca(daplka_t *dp, ib_guid_t hca_guid)
{
	daplka_hca_t		*hca;
	ibt_hca_portinfo_t	*pinfop;
	uint_t			size;
	int			j;
	ibt_status_t		status;

	hca = kmem_zalloc(sizeof (daplka_hca_t), KM_SLEEP);

	hca->hca_guid = hca_guid;

	/*
	 * open the HCA for use
	 */
	status = ibt_open_hca(dp->daplka_clnt_hdl, hca_guid, &hca->hca_hdl);
	if (status != IBT_SUCCESS) {
		if (status == IBT_HCA_IN_USE) {
			DERR("ibt_open_hca() returned IBT_HCA_IN_USE\n");
		} else {
			DERR("ibt_open_hca() returned %d\n", status);
		}
		kmem_free(hca, sizeof (daplka_hca_t));
		return (status);
	}

	/*
	 * query HCA to get its info
	 */
	status = ibt_query_hca(hca->hca_hdl, &hca->hca_attr);
	if (status != IBT_SUCCESS) {
		DERR("ibt_query_hca returned %d (hca_guid 0x%llx)\n",
		    status, (longlong_t)hca_guid);
		goto out;
	}

	/*
	 * query HCA to get info of all ports
	 */
	status = ibt_query_hca_ports(hca->hca_hdl,
	    0, &pinfop, &hca->hca_nports, &size);
	if (status != IBT_SUCCESS) {
		DERR("ibt_query_all_ports returned %d "
		    "(hca_guid 0x%llx)\n", status,
		    (longlong_t)hca_guid);
		goto out;
	}
	hca->hca_ports = pinfop;
	hca->hca_pinfosz = size;

	DERR("hca guid 0x%llx, nports %d\n",
	    (longlong_t)hca_guid, hca->hca_nports);
	for (j = 0; j < hca->hca_nports; j++) {
		DERR("port %d: state %d prefix 0x%016llx "
		    "guid %016llx\n",
		    pinfop[j].p_port_num, pinfop[j].p_linkstate,
		    (longlong_t)pinfop[j].p_sgid_tbl[0].gid_prefix,
		    (longlong_t)pinfop[j].p_sgid_tbl[0].gid_guid);
	}

	mutex_enter(&dp->daplka_mutex);
	daplka_enqueue_hca(dp, hca);
	mutex_exit(&dp->daplka_mutex);

	return (IBT_SUCCESS);

out:
	(void) ibt_close_hca(hca->hca_hdl);
	kmem_free(hca, sizeof (daplka_hca_t));
	return (status);
}

/*
 * this function obtains the list of HCAs from IBTF.
 * the HCAs are then opened and the returned handles
 * and attributes are stored into the global daplka_dev
 * structure.
 */
static int
daplka_init_hcas(daplka_t *dp)
{
	int		i;
	ib_guid_t	*hca_guids;
	uint32_t	hca_count;

	/*
	 * get the num & list of HCAs present
	 */
	hca_count = ibt_get_hca_list(&hca_guids);
	DERR("No. of HCAs present %d\n", hca_count);

	if (hca_count != 0) {
		/*
		 * get the info for each available HCA
		 */
		for (i = 0; i < hca_count; i++)
			(void) daplka_init_hca(dp, hca_guids[i]);

		ibt_free_hca_list(hca_guids, hca_count);
	}

	if (dp->daplka_hca_list_head != NULL)
		return (IBT_SUCCESS);
	else
		return (IBT_FAILURE);
}

static int
daplka_fini_hca(daplka_t *dp, daplka_hca_t *hca)
{
	ibt_status_t	status;

	if (hca->hca_hdl != NULL) {
		status = ibt_close_hca(hca->hca_hdl);
		if (status != IBT_SUCCESS) {
			DERR("ibt_close_hca returned %d"
			    " (hca_guid 0x%llx)\n", status,
			    (longlong_t)hca->hca_guid);

			mutex_enter(&dp->daplka_mutex);
			daplka_enqueue_hca(dp, hca);
			mutex_exit(&dp->daplka_mutex);

			return (status);
		}
	}

	if (hca->hca_ports != NULL)
		ibt_free_portinfo(hca->hca_ports, hca->hca_pinfosz);

	kmem_free(hca, sizeof (daplka_hca_t));
	return (IBT_SUCCESS);
}

/*
 * closes all HCAs and frees up the HCA list
 */
static int
daplka_fini_hcas(daplka_t *dp)
{
	ibt_status_t	status;
	daplka_hca_t	*hca;

	mutex_enter(&daplka_dev->daplka_mutex);
	while ((hca = dp->daplka_hca_list_head) != NULL) {
		if (DAPLKA_HCA_BUSY(hca)) {
			mutex_exit(&daplka_dev->daplka_mutex);
			return (IBT_HCA_RESOURCES_NOT_FREED);
		}
		daplka_dequeue_hca(daplka_dev, hca);
		mutex_exit(&daplka_dev->daplka_mutex);

		if ((status = daplka_fini_hca(dp, hca)) != IBT_SUCCESS)
			return (status);

		mutex_enter(&daplka_dev->daplka_mutex);
	}
	mutex_exit(&daplka_dev->daplka_mutex);

	DERR("dapl kernel agent unloaded\n");
	return (IBT_SUCCESS);
}


/*
 * Attach the device, create and fill in daplka_dev
 */
static int
daplka_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	daplka_t	*dp;
	int		instance, retval, err;
	boolean_t	sp_htbl_allocated = B_FALSE;
	boolean_t	timer_htbl_allocated = B_FALSE;
	boolean_t	shared_mr_tree_allocated = B_FALSE;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	/*
	 * Allocate soft data structure
	 */
	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(daplka_state, instance) != DDI_SUCCESS) {
		DERR("attach: bad state zalloc\n");
		return (DDI_FAILURE);
	}

	dp = ddi_get_soft_state(daplka_state, instance);
	if (dp == NULL) {
		ddi_soft_state_free(daplka_state, instance);
		DERR("attach: cannot get soft state\n");
		return (DDI_FAILURE);
	}
	/*
	 * Stuff private info into dip.
	 */
	dp->daplka_dip = dip;
	ddi_set_driver_private(dip, dp);
	daplka_dev = dp;
	mutex_init(&dp->daplka_mutex, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Register driver with IBTF
	 */
	retval = ibt_attach(&daplka_clnt_modinfo, dip, dp,
	    &dp->daplka_clnt_hdl);
	if (retval != IBT_SUCCESS) {
		DERR("attach: ibt_attach failed: error = %d\n", retval);
		retval = DDI_FAILURE;
		goto error;
	}
	/* Register to receive SM events */
	ibt_register_subnet_notices(dp->daplka_clnt_hdl,
	    daplka_sm_notice_handler, NULL);

	retval = daplka_init_hcas(dp);
	if (retval != IBT_SUCCESS) {
		DERR("attach: hca_init failed: error = %d\n", retval);
		retval = DDI_FAILURE;
		goto error;
	}
	/*
	 * this table is used by cr_handoff
	 */
	retval = daplka_hash_create(&daplka_global_sp_htbl,
	    DAPLKA_G_SP_HTBL_SZ, daplka_hash_sp_unref,
	    daplka_hash_generic_lookup);
	if (retval != 0) {
		DERR("attach: cannot create sp hash table\n");
		retval = DDI_FAILURE;
		goto error;
	}
	sp_htbl_allocated = B_TRUE;

	/*
	 * this table stores per EP timer information.
	 * timer_info_t objects are inserted into this table whenever
	 * a EP timer is set. timers get removed when they expire
	 * or when they get cancelled.
	 */
	retval = daplka_hash_create(&daplka_timer_info_htbl,
	    DAPLKA_TIMER_HTBL_SZ, daplka_hash_timer_free, NULL);
	if (retval != 0) {
		DERR("attach: cannot create timer hash table\n");
		retval = DDI_FAILURE;
		goto error;
	}
	timer_htbl_allocated = B_TRUE;

	/*
	 * this taskq is currently only used for processing timers.
	 * other processing may also use this taskq in the future.
	 */
	daplka_taskq = taskq_create(DAPLKA_DRV_NAME, DAPLKA_TQ_NTHREADS,
	    maxclsyspri, 1, DAPLKA_TQ_NTHREADS, TASKQ_DYNAMIC);
	if (daplka_taskq == NULL) {
		DERR("attach: cannot create daplka_taskq\n");
		retval = DDI_FAILURE;
		goto error;
	}

	/*
	 * daplka_shared_mr_tree holds daplka_shared_mr_t objects that
	 * gets retrieved or created when daplka_mr_register_shared is
	 * called.
	 */
	mutex_init(&daplka_shared_mr_lock, NULL, MUTEX_DRIVER, NULL);

	avl_create(&daplka_shared_mr_tree, daplka_shared_mr_cmp,
	    sizeof (daplka_shared_mr_t),
	    offsetof(daplka_shared_mr_t, smr_node));
	shared_mr_tree_allocated = B_TRUE;

	/*
	 * Create the filesystem device node.
	 */
	if (ddi_create_minor_node(dip, DAPLKA_MINOR_NAME, S_IFCHR,
	    0, DDI_PSEUDO, NULL) != DDI_SUCCESS) {
		DERR("attach: bad create_minor_node\n");
		retval = DDI_FAILURE;
		goto error;
	}
	dp->daplka_status = DAPLKA_STATE_ATTACHED;
	ddi_report_dev(dip);
	return (DDI_SUCCESS);

error:
	if (shared_mr_tree_allocated) {
		avl_destroy(&daplka_shared_mr_tree);
		mutex_destroy(&daplka_shared_mr_lock);
	}

	if (daplka_taskq) {
		taskq_destroy(daplka_taskq);
		daplka_taskq = NULL;
	}

	if (timer_htbl_allocated) {
		daplka_hash_destroy(&daplka_timer_info_htbl);
	}

	if (sp_htbl_allocated) {
		daplka_hash_destroy(&daplka_global_sp_htbl);
	}

	err = daplka_fini_hcas(dp);
	if (err != IBT_SUCCESS) {
		DERR("attach: hca_fini returned %d\n", err);
	}

	if (dp->daplka_clnt_hdl != NULL) {
		/* unregister SM event notification */
		ibt_register_subnet_notices(dp->daplka_clnt_hdl,
		    (ibt_sm_notice_handler_t)NULL, NULL);
		err = ibt_detach(dp->daplka_clnt_hdl);

		if (err != IBT_SUCCESS) {
			DERR("attach: ibt_detach returned %d\n", err);
		}
	}
	mutex_destroy(&dp->daplka_mutex);

	if (dp->daplka_status == DAPLKA_STATE_ATTACHED) {
		ddi_remove_minor_node(dip, NULL);
	}
	ddi_soft_state_free(daplka_state, instance);
	return (retval);
}

/*
 * Detach - Free resources allocated in attach
 */
/* ARGSUSED */
static int
daplka_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance, err;
	void		*cookie = NULL;
	daplka_t	*dp;

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}
	if (daplka_resource.daplka_rc_cnt > 0 ||
	    daplka_pending_close > 0) {
		DERR("detach: driver in use\n");
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	dp = ddi_get_soft_state(daplka_state, instance);
	if (dp == NULL) {
		DERR("detach: cannot get soft state\n");
		return (DDI_FAILURE);
	}
	err = daplka_fini_hcas(dp);
	if (err != IBT_SUCCESS) {
		DERR("detach: hca_fini returned %d\n", err);
		return (DDI_FAILURE);
	}
	if (dp->daplka_clnt_hdl != NULL) {
		/* unregister SM event notification */
		ibt_register_subnet_notices(dp->daplka_clnt_hdl,
		    (ibt_sm_notice_handler_t)NULL, NULL);
		err = ibt_detach(dp->daplka_clnt_hdl);
		if (err != IBT_SUCCESS) {
			DERR("detach: ibt_detach returned %d\n", err);
			return (DDI_FAILURE);
		}
		dp->daplka_clnt_hdl = NULL;
	}
	mutex_destroy(&dp->daplka_mutex);
	if (dp->daplka_status == DAPLKA_STATE_ATTACHED) {
		ddi_remove_minor_node(dip, NULL);
	}
	dp->daplka_status = DAPLKA_STATE_DETACHED;
	ddi_soft_state_free(daplka_state, instance);
	daplka_dev = NULL;

	/*
	 * by the time we get here, all clients of dapl should
	 * have exited and completed their cleanup properly.
	 * we can assert that all global data structures are now
	 * empty.
	 */
	ASSERT(avl_destroy_nodes(&daplka_shared_mr_tree, &cookie) == NULL);
	avl_destroy(&daplka_shared_mr_tree);
	mutex_destroy(&daplka_shared_mr_lock);

	ASSERT(daplka_hash_getsize(&daplka_timer_info_htbl) == 0);
	daplka_hash_destroy(&daplka_timer_info_htbl);

	ASSERT(daplka_hash_getsize(&daplka_global_sp_htbl) == 0);
	daplka_hash_destroy(&daplka_global_sp_htbl);

	taskq_destroy(daplka_taskq);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
daplka_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (daplka_dev !=  NULL) {
			*result = daplka_dev->daplka_dip;
			return (DDI_SUCCESS);
		} else {
			return (DDI_FAILURE);
		}

	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*
 * creates a EP resource.
 * A EP resource contains a RC channel. A EP resource holds a
 * reference to a send_evd (for the send CQ), recv_evd (for the
 * recv CQ), a connection evd and a PD. These references ensure
 * that the referenced resources are not freed until the EP itself
 * gets freed.
 */
/* ARGSUSED */
static int
daplka_ep_create(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_ep_resource_t		*ep_rp;
	daplka_pd_resource_t		*pd_rp;
	dapl_ep_create_t		args;
	ibt_rc_chan_alloc_args_t	chan_args;
	ibt_chan_alloc_flags_t		achan_flags;
	ibt_chan_sizes_t		chan_real_sizes;
	ibt_hca_attr_t			*hca_attrp;
	uint64_t			ep_hkey = 0;
	boolean_t			inserted = B_FALSE;
	uint32_t			old_state, new_state;
	int				retval;
	ibt_status_t			status;

	D3("ep_create: enter\n");
	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_ep_create_t),
	    mode);
	if (retval != 0) {
		DERR("ep_create: copyin error %d\n", retval);
		return (EFAULT);
	}
	ep_rp = kmem_zalloc(sizeof (daplka_ep_resource_t), daplka_km_flags);
	if (ep_rp == NULL) {
		DERR("ep_create: cannot allocate ep_rp\n");
		return (ENOMEM);
	}
	DAPLKA_RS_INIT(ep_rp, DAPL_TYPE_EP,
	    DAPLKA_RS_RNUM(ia_rp), daplka_ep_destroy);

	mutex_init(&ep_rp->ep_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ep_rp->ep_cv, NULL, CV_DRIVER, NULL);
	ep_rp->ep_hca = ia_rp->ia_hca;
	ep_rp->ep_cookie = args.ep_cookie;
	ep_rp->ep_timer_hkey = 0;

	/*
	 * we don't have to use ep_get_state here because ep_rp is not in
	 * ep_htbl yet. refer to the description of daplka_ep_set_state
	 * for details about the EP state machine.
	 */
	ep_rp->ep_state = DAPLKA_EP_STATE_TRANSITIONING;
	new_state = old_state = DAPLKA_EP_STATE_CLOSED;

	/* get reference to send evd and get cq handle */
	ep_rp->ep_snd_evd = (daplka_evd_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_evd_htbl, args.ep_snd_evd_hkey);
	if (ep_rp->ep_snd_evd == NULL) {
		DERR("ep_create: ep_snd_evd %llx not found\n",
		    args.ep_snd_evd_hkey);
		retval = EINVAL;
		goto cleanup;
	}
	chan_args.rc_scq = ep_rp->ep_snd_evd->evd_cq_hdl;
	if (chan_args.rc_scq == NULL) {
		DERR("ep_create: ep_snd_evd cq invalid\n");
		retval = EINVAL;
		goto cleanup;
	}

	/* get reference to recv evd and get cq handle */
	ep_rp->ep_rcv_evd = (daplka_evd_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_evd_htbl, args.ep_rcv_evd_hkey);
	if (ep_rp->ep_rcv_evd == NULL) {
		DERR("ep_create: ep_rcv_evd %llx not found\n",
		    args.ep_rcv_evd_hkey);
		retval = EINVAL;
		goto cleanup;
	}
	chan_args.rc_rcq = ep_rp->ep_rcv_evd->evd_cq_hdl;
	if (chan_args.rc_rcq == NULL) {
		DERR("ep_create: ep_rcv_evd cq invalid\n");
		retval = EINVAL;
		goto cleanup;
	}

	/* get reference to conn evd */
	ep_rp->ep_conn_evd = (daplka_evd_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_evd_htbl, args.ep_conn_evd_hkey);
	if (ep_rp->ep_conn_evd == NULL) {
		DERR("ep_create: ep_conn_evd %llx not found\n",
		    args.ep_conn_evd_hkey);
		retval = EINVAL;
		goto cleanup;
	}

	/* get reference to SRQ if needed */
	if (args.ep_srq_attached) {
		ep_rp->ep_srq_res = (daplka_srq_resource_t *)daplka_hash_lookup(
		    &ia_rp->ia_srq_htbl, args.ep_srq_hkey);
		if (ep_rp->ep_srq_res == NULL) {
			DERR("ep_create: ep_srq %llx not found\n",
			    (longlong_t)args.ep_srq_hkey);
			retval = EINVAL;
			goto cleanup;
		}
		ASSERT(DAPLKA_RS_TYPE(ep_rp->ep_srq_res) == DAPL_TYPE_SRQ);
		D3("ep_create: ep_srq %p %llx\n", ep_rp->ep_srq_res,
		    (longlong_t)args.ep_srq_hkey);
	} else {
		ep_rp->ep_srq_res = NULL;
	}

	/* get pd handle */
	pd_rp = (daplka_pd_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_pd_htbl, args.ep_pd_hkey);
	if (pd_rp == NULL) {
		DERR("ep_create: cannot find pd resource\n");
		retval = EINVAL;
		goto cleanup;
	}
	ASSERT(DAPLKA_RS_TYPE(pd_rp) == DAPL_TYPE_PD);
	ep_rp->ep_pd_res = pd_rp;
	chan_args.rc_pd = pd_rp->pd_hdl;


	/*
	 * these checks ensure that the requested channel sizes
	 * are within the limits supported by the chosen HCA.
	 */
	hca_attrp = &ia_rp->ia_hca->hca_attr;
	if (args.ep_ch_sizes.dcs_sq_sgl > hca_attrp->hca_max_sgl) {
		DERR("ep_create: invalid cs_sq_sgl %d\n",
		    args.ep_ch_sizes.dcs_sq_sgl);
		retval = EINVAL;
		goto cleanup;
	}
	if (args.ep_ch_sizes.dcs_rq_sgl > hca_attrp->hca_max_sgl) {
		DERR("ep_create: invalid cs_rq_sgl %d\n",
		    args.ep_ch_sizes.dcs_rq_sgl);
		retval = EINVAL;
		goto cleanup;
	}
	if (args.ep_ch_sizes.dcs_sq > hca_attrp->hca_max_chan_sz) {
		DERR("ep_create: invalid cs_sq %d\n",
		    args.ep_ch_sizes.dcs_sq);
		retval = EINVAL;
		goto cleanup;
	}
	if (args.ep_ch_sizes.dcs_rq > hca_attrp->hca_max_chan_sz) {
		DERR("ep_create: invalid cs_rq %d\n",
		    args.ep_ch_sizes.dcs_rq);
		retval = EINVAL;
		goto cleanup;
	}

	chan_args.rc_sizes.cs_sq_sgl = args.ep_ch_sizes.dcs_sq_sgl;
	chan_args.rc_sizes.cs_rq_sgl = args.ep_ch_sizes.dcs_rq_sgl;
	chan_args.rc_sizes.cs_sq = args.ep_ch_sizes.dcs_sq;
	chan_args.rc_sizes.cs_rq = args.ep_ch_sizes.dcs_rq;
	chan_args.rc_flags = IBT_WR_SIGNALED;
	chan_args.rc_control = IBT_CEP_RDMA_RD | IBT_CEP_RDMA_WR;
	chan_args.rc_hca_port_num = ia_rp->ia_port_num;
	chan_args.rc_clone_chan = NULL;
	if (args.ep_srq_attached) {
		chan_args.rc_srq = ep_rp->ep_srq_res->srq_hdl;
	} else {
		chan_args.rc_srq = NULL;
	}

	D3("ep_create: sq_sgl %d, rq_sgl %d, sq %d, rq %d, "
	    "sig_type 0x%x, control 0x%x, portnum %d, clone_chan 0x%p\n",
	    args.ep_ch_sizes.dcs_sq_sgl, args.ep_ch_sizes.dcs_rq_sgl,
	    args.ep_ch_sizes.dcs_sq, args.ep_ch_sizes.dcs_rq,
	    chan_args.rc_flags, chan_args.rc_control,
	    chan_args.rc_hca_port_num, chan_args.rc_clone_chan);

	if (args.ep_srq_attached) {
		achan_flags = IBT_ACHAN_USER_MAP | IBT_ACHAN_USES_SRQ;
	} else {
		achan_flags = IBT_ACHAN_USER_MAP;
	}
	/* create rc channel */
	status = daplka_ibt_alloc_rc_channel(ep_rp, ia_rp->ia_hca_hdl,
	    achan_flags, &chan_args, &ep_rp->ep_chan_hdl,
	    &chan_real_sizes);
	if (status != IBT_SUCCESS) {
		DERR("ep_create: alloc_rc_channel returned %d\n", status);
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}

	args.ep_ch_real_sizes.dcs_sq = chan_real_sizes.cs_sq;
	args.ep_ch_real_sizes.dcs_rq = chan_real_sizes.cs_rq;
	args.ep_ch_real_sizes.dcs_sq_sgl = chan_real_sizes.cs_sq_sgl;
	args.ep_ch_real_sizes.dcs_rq_sgl = chan_real_sizes.cs_rq_sgl;

	/*
	 * store ep ptr with chan_hdl.
	 * this ep_ptr is used by the CM handlers (both active and
	 * passive)
	 * mutex is only needed for race of "destroy" and "async"
	 */
	mutex_enter(&daplka_dev->daplka_mutex);
	ibt_set_chan_private(ep_rp->ep_chan_hdl, (void *)ep_rp);
	mutex_exit(&daplka_dev->daplka_mutex);

	/* Get HCA-specific data_out info */
	status = ibt_ci_data_out(ia_rp->ia_hca_hdl,
	    IBT_CI_NO_FLAGS, IBT_HDL_CHANNEL, (void *)ep_rp->ep_chan_hdl,
	    &args.ep_qp_data_out, sizeof (args.ep_qp_data_out));

	if (status != IBT_SUCCESS) {
		DERR("ep_create: ibt_ci_data_out error(%d)\n",
		    status);
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}

	/* insert into ep hash table */
	retval = daplka_hash_insert(&ia_rp->ia_ep_htbl,
	    &ep_hkey, (void *)ep_rp);
	if (retval != 0) {
		DERR("ep_create: cannot insert ep resource into ep_htbl\n");
		goto cleanup;
	}
	inserted = B_TRUE;

	/*
	 * at this point, the ep_rp can be looked up by other threads
	 * if they manage to guess the correct hkey. but they are not
	 * permitted to operate on ep_rp until we transition to the
	 * CLOSED state.
	 */

	/* return hkey to library */
	args.ep_hkey = ep_hkey;

	retval = ddi_copyout(&args, (void *)arg, sizeof (dapl_ep_create_t),
	    mode);
	if (retval != 0) {
		DERR("ep_create: copyout error %d\n", retval);
		retval = EFAULT;
		goto cleanup;
	}

	daplka_ep_set_state(ep_rp, old_state, new_state);
	D3("ep_create: exit\n");
	return (0);

cleanup:
	if (inserted) {
		daplka_ep_resource_t *free_rp = NULL;

		(void) daplka_hash_remove(&ia_rp->ia_ep_htbl, ep_hkey,
		    (void **)&free_rp);
		if (free_rp != ep_rp) {
			/*
			 * this case is impossible because ep_free will
			 * wait until our state transition is complete.
			 */
			DERR("ep_create: cannot remove ep from hash table\n");
			ASSERT(B_FALSE);
			return (retval);
		}
	}
	new_state = DAPLKA_EP_STATE_FREED;
	daplka_ep_set_state(ep_rp, old_state, new_state);
	DAPLKA_RS_UNREF(ep_rp);
	return (retval);
}

/*
 * daplka_ep_get_state retrieves the current state of the EP and
 * sets the state to TRANSITIONING. if the current state is already
 * TRANSITIONING, this function will wait until the state becomes one
 * of the other EP states. Most of the EP related ioctls follow the
 * call sequence:
 *
 *	new_state = old_state = daplka_ep_get_state(ep_rp);
 *	...
 *	...some code that affects the EP
 *	...
 *	new_state = <NEW_STATE>;
 *	daplka_ep_set_state(ep_rp, old_state, new_state);
 *
 * this call sequence ensures that only one thread may access the EP
 * during the time ep_state is in TRANSITIONING. daplka_ep_set_state
 * transitions ep_state to new_state and wakes up any waiters blocking
 * on ep_cv.
 *
 */
static uint32_t
daplka_ep_get_state(daplka_ep_resource_t *ep_rp)
{
	uint32_t	old_state = 0;

	mutex_enter(&ep_rp->ep_lock);
	while (ep_rp->ep_state == DAPLKA_EP_STATE_TRANSITIONING) {
		D2("get_state: wait for state transition to complete\n");
		cv_wait(&ep_rp->ep_cv, &ep_rp->ep_lock);
		D2("get_state: done, curr state = %d\n", ep_rp->ep_state);
	}
	ASSERT(ep_rp->ep_state != DAPLKA_EP_STATE_TRANSITIONING);
	old_state = ep_rp->ep_state;

	/*
	 * an ep that is in the FREED state cannot transition
	 * back to any of the regular states
	 */
	if (old_state != DAPLKA_EP_STATE_FREED) {
		ep_rp->ep_state = DAPLKA_EP_STATE_TRANSITIONING;
	}
	mutex_exit(&ep_rp->ep_lock);
	return (old_state);
}

/*
 * EP state transition diagram
 *
 *              CLOSED<-------------------
 *                |                      |
 *                |                      |
 *     ------------------------          |
 *     |                      |          |
 *     |                      |          |
 *     v                      v          |
 *   CONNECTING       ACCEPTING          |
 *     |  |   |       |       |          |
 *     |  |   |       |       |          |
 *     |  |   |       |       |          |
 *     |  |   |_______|_______|          |
 *     |  |           |   |   |          |
 *     |  |___________|   |   |          |
 *     |        |         |   |          |
 *     |        v         |   |---->DISCONNECTED
 *     |     CONNECTED    |              ^
 *     v        |         |              |
 *    ABORTING  |---------|--------------|
 *     |        |         |              |
 *     |        |         v              |
 *     |        |-------->DISCONNECTING--|
 *     |                                 |
 *     |---------------------------------|
 *
 *	*not shown in this diagram:
 *	    -loopback transitions
 *	    -transitions to the FREED state
 */
static boolean_t
daplka_ep_transition_is_valid(uint32_t old_state, uint32_t new_state)
{
	boolean_t valid = B_FALSE;

	/*
	 * reseting to the same state is a no-op and is always
	 * permitted. transitioning to the FREED state indicates
	 * that the ep is about to be freed and no further operation
	 * is allowed on it. to support abrupt close, the ep is
	 * permitted to transition to the FREED state from any state.
	 */
	if (old_state == new_state ||
	    new_state == DAPLKA_EP_STATE_FREED) {
		return (B_TRUE);
	}

	switch (old_state) {
	case DAPLKA_EP_STATE_CLOSED:
		/*
		 * this is the initial ep_state.
		 * a transition to CONNECTING or ACCEPTING may occur
		 * upon calling daplka_ep_connect or daplka_cr_accept,
		 * respectively.
		 */
		if (new_state == DAPLKA_EP_STATE_CONNECTING ||
		    new_state == DAPLKA_EP_STATE_ACCEPTING) {
			valid = B_TRUE;
		}
		break;
	case DAPLKA_EP_STATE_CONNECTING:
		/*
		 * we transition to this state if daplka_ep_connect
		 * is successful. from this state, we can transition
		 * to CONNECTED if daplka_cm_rc_conn_est gets called;
		 * or to DISCONNECTED if daplka_cm_rc_conn_closed or
		 * daplka_cm_rc_event_failure gets called. If the
		 * client calls daplka_ep_disconnect, we transition
		 * to DISCONNECTING. If a timer was set at ep_connect
		 * time and if the timer expires prior to any of the
		 * CM callbacks, we transition to ABORTING and then
		 * to DISCONNECTED.
		 */
		if (new_state == DAPLKA_EP_STATE_CONNECTED ||
		    new_state == DAPLKA_EP_STATE_DISCONNECTING ||
		    new_state == DAPLKA_EP_STATE_DISCONNECTED ||
		    new_state == DAPLKA_EP_STATE_ABORTING) {
			valid = B_TRUE;
		}
		break;
	case DAPLKA_EP_STATE_ACCEPTING:
		/*
		 * we transition to this state if daplka_cr_accept
		 * is successful. from this state, we can transition
		 * to CONNECTED if daplka_cm_service_conn_est gets called;
		 * or to DISCONNECTED if daplka_cm_service_conn_closed or
		 * daplka_cm_service_event_failure gets called. If the
		 * client calls daplka_ep_disconnect, we transition to
		 * DISCONNECTING.
		 */
		if (new_state == DAPLKA_EP_STATE_CONNECTED ||
		    new_state == DAPLKA_EP_STATE_DISCONNECTING ||
		    new_state == DAPLKA_EP_STATE_DISCONNECTED) {
			valid = B_TRUE;
		}
		break;
	case DAPLKA_EP_STATE_CONNECTED:
		/*
		 * we transition to this state if a active or passive
		 * connection gets established. if the client calls
		 * daplka_ep_disconnect, we transition to the
		 * DISCONNECTING state. subsequent CM callbacks will
		 * cause ep_state to be set to DISCONNECTED. If the
		 * remote peer terminates the connection before we do,
		 * it is possible for us to transition directly from
		 * CONNECTED to DISCONNECTED.
		 */
		if (new_state == DAPLKA_EP_STATE_DISCONNECTING ||
		    new_state == DAPLKA_EP_STATE_DISCONNECTED) {
			valid = B_TRUE;
		}
		break;
	case DAPLKA_EP_STATE_DISCONNECTING:
		/*
		 * we transition to this state if the client calls
		 * daplka_ep_disconnect.
		 */
		if (new_state == DAPLKA_EP_STATE_DISCONNECTED) {
			valid = B_TRUE;
		}
		break;
	case DAPLKA_EP_STATE_ABORTING:
		/*
		 * we transition to this state if the active side
		 * EP timer has expired. this is only a transient
		 * state that is set during timer processing. when
		 * timer processing completes, ep_state will become
		 * DISCONNECTED.
		 */
		if (new_state == DAPLKA_EP_STATE_DISCONNECTED) {
			valid = B_TRUE;
		}
		break;
	case DAPLKA_EP_STATE_DISCONNECTED:
		/*
		 * we transition to this state if we get a closed
		 * or event_failure CM callback. an expired timer
		 * can also cause us to be in this state. this
		 * is the only state in which we permit the
		 * ep_reinit operation.
		 */
		if (new_state == DAPLKA_EP_STATE_CLOSED) {
			valid = B_TRUE;
		}
		break;
	default:
		break;
	}

	if (!valid) {
		DERR("ep_transition: invalid state change %d -> %d\n",
		    old_state, new_state);
	}
	return (valid);
}

/*
 * first check if the transition is valid. then set ep_state
 * to new_state and wake up all waiters.
 */
static void
daplka_ep_set_state(daplka_ep_resource_t *ep_rp, uint32_t old_state,
	uint32_t new_state)
{
	boolean_t	valid;

	ASSERT(new_state != DAPLKA_EP_STATE_TRANSITIONING);

	valid = daplka_ep_transition_is_valid(old_state, new_state);
	mutex_enter(&ep_rp->ep_lock);
	if (ep_rp->ep_state != DAPLKA_EP_STATE_FREED) {
		if (valid) {
			ep_rp->ep_state = new_state;
		} else {
			/*
			 * this case is impossible.
			 * we have a serious problem if we get here.
			 * instead of panicing, we reset the state to
			 * old_state. doing this would at least prevent
			 * threads from hanging due to ep_state being
			 * stuck in TRANSITIONING.
			 */
			ep_rp->ep_state = old_state;
			ASSERT(B_FALSE);
		}
	}
	cv_broadcast(&ep_rp->ep_cv);
	mutex_exit(&ep_rp->ep_lock);
}

/*
 * modifies RC channel attributes.
 * currently, only the rdma_in and rdma_out attributes may
 * be modified. the channel must be in quiescent state when
 * this function is called.
 */
/* ARGSUSED */
static int
daplka_ep_modify(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_ep_resource_t		*ep_rp = NULL;
	ibt_cep_modify_flags_t		good_flags;
	ibt_rc_chan_modify_attr_t	rcm_attr;
	ibt_hca_attr_t			*hca_attrp;
	dapl_ep_modify_t		args;
	ibt_status_t			status;
	uint32_t			old_state, new_state;
	int				retval = 0;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_ep_modify_t),
	    mode);
	if (retval != 0) {
		DERR("ep_modify: copyin error %d\n", retval);
		return (EFAULT);
	}
	ep_rp = (daplka_ep_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_ep_htbl, args.epm_hkey);
	if (ep_rp == NULL) {
		DERR("ep_modify: cannot find ep resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(ep_rp) == DAPL_TYPE_EP);
	new_state = old_state = daplka_ep_get_state(ep_rp);

	if (old_state != DAPLKA_EP_STATE_CLOSED &&
	    old_state != DAPLKA_EP_STATE_DISCONNECTED) {
		DERR("ep_modify: invalid state %d\n", old_state);
		retval = EINVAL;
		goto cleanup;
	}

	good_flags = IBT_CEP_SET_RDMARA_OUT | IBT_CEP_SET_RDMARA_IN;
	if ((args.epm_flags & ~good_flags) != 0) {
		DERR("ep_modify: invalid flags 0x%x\n", args.epm_flags);
		retval = EINVAL;
		goto cleanup;
	}

	hca_attrp = &ia_rp->ia_hca->hca_attr;

	bzero(&rcm_attr, sizeof (ibt_rc_chan_modify_attr_t));
	if ((args.epm_flags & IBT_CEP_SET_RDMARA_OUT) != 0) {
		if (args.epm_rdma_ra_out > hca_attrp->hca_max_rdma_out_chan) {
			DERR("ep_modify: invalid epm_rdma_ra_out %d\n",
			    args.epm_rdma_ra_out);
			retval = EINVAL;
			goto cleanup;
		}
		rcm_attr.rc_rdma_ra_out = args.epm_rdma_ra_out;
	}
	if ((args.epm_flags & IBT_CEP_SET_RDMARA_IN) != 0) {
		if (args.epm_rdma_ra_in > hca_attrp->hca_max_rdma_in_chan) {
			DERR("ep_modify: epm_rdma_ra_in %d\n",
			    args.epm_rdma_ra_in);
			retval = EINVAL;
			goto cleanup;
		}
		rcm_attr.rc_rdma_ra_in = args.epm_rdma_ra_in;
	}
	status = ibt_modify_rc_channel(ep_rp->ep_chan_hdl, args.epm_flags,
	    &rcm_attr, NULL);
	if (status != IBT_SUCCESS) {
		DERR("ep_modify: modify_rc_channel returned %d\n", status);
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}

	/*
	 * ep_modify does not change ep_state
	 */
cleanup:;
	daplka_ep_set_state(ep_rp, old_state, new_state);
	DAPLKA_RS_UNREF(ep_rp);
	return (retval);
}

/*
 * Frees a EP resource.
 * a EP may only be freed when it is in the CLOSED or
 * DISCONNECTED state.
 */
/* ARGSUSED */
static int
daplka_ep_free(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_ep_resource_t	*ep_rp = NULL;
	dapl_ep_free_t		args;
	uint32_t		old_state, new_state;
	int			retval;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_ep_free_t), mode);
	if (retval != 0) {
		DERR("ep_free: copyin error %d\n", retval);
		return (EFAULT);
	}
	ep_rp = (daplka_ep_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_ep_htbl, args.epf_hkey);
	if (ep_rp == NULL) {
		DERR("ep_free: cannot find ep resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(ep_rp) == DAPL_TYPE_EP);
	new_state = old_state = daplka_ep_get_state(ep_rp);

	/*
	 * ep cannot be freed if it is in an invalid state.
	 */
	if (old_state != DAPLKA_EP_STATE_CLOSED &&
	    old_state != DAPLKA_EP_STATE_DISCONNECTED) {
		DERR("ep_free: invalid state %d\n", old_state);
		retval = EINVAL;
		goto cleanup;
	}
	ep_rp = NULL;
	retval = daplka_hash_remove(&ia_rp->ia_ep_htbl,
	    args.epf_hkey, (void **)&ep_rp);
	if (retval != 0 || ep_rp == NULL) {
		/*
		 * this is only possible if we have two threads
		 * calling ep_free in parallel.
		 */
		DERR("ep_free: cannot find ep resource\n");
		goto cleanup;
	}
	/* there should not be any outstanding timers */
	ASSERT(ep_rp->ep_timer_hkey == 0);

	new_state = DAPLKA_EP_STATE_FREED;
	daplka_ep_set_state(ep_rp, old_state, new_state);

	/* remove reference obtained by lookup */
	DAPLKA_RS_UNREF(ep_rp);

	/* UNREF calls the actual free function when refcnt is zero */
	DAPLKA_RS_UNREF(ep_rp);
	return (0);

cleanup:;
	daplka_ep_set_state(ep_rp, old_state, new_state);

	/* remove reference obtained by lookup */
	DAPLKA_RS_UNREF(ep_rp);
	return (retval);
}

/*
 * The following routines supports the timeout feature of ep_connect.
 * Refer to the description of ep_connect for details.
 */

/*
 * this is the timer processing thread.
 */
static void
daplka_timer_thread(void *arg)
{
	daplka_timer_info_t	*timerp = (daplka_timer_info_t *)arg;
	daplka_ep_resource_t	*ep_rp;
	daplka_evd_event_t	*disc_ev = NULL;
	ibt_status_t		status;
	int			old_state, new_state;

	ep_rp = timerp->ti_ep_res;
	ASSERT(ep_rp != NULL);
	ASSERT(timerp->ti_tmo_id != 0);
	timerp->ti_tmo_id = 0;

	new_state = old_state = daplka_ep_get_state(ep_rp);
	if (old_state != DAPLKA_EP_STATE_CONNECTING) {
		/* unblock hash_ep_free */
		mutex_enter(&ep_rp->ep_lock);
		ASSERT(ep_rp->ep_timer_hkey != 0);
		ep_rp->ep_timer_hkey = 0;
		cv_broadcast(&ep_rp->ep_cv);
		mutex_exit(&ep_rp->ep_lock);

		/* reset state to original state */
		daplka_ep_set_state(ep_rp, old_state, new_state);

		/* this function will also unref ep_rp */
		daplka_timer_info_free(timerp);
		return;
	}

	ASSERT(ep_rp->ep_timer_hkey != 0);
	ep_rp->ep_timer_hkey = 0;

	/*
	 * we cannot keep ep_state in TRANSITIONING if we call
	 * ibt_close_rc_channel in blocking mode. this would cause
	 * a deadlock because the cm callbacks will be blocked and
	 * will not be able to wake us up.
	 */
	new_state = DAPLKA_EP_STATE_ABORTING;
	daplka_ep_set_state(ep_rp, old_state, new_state);

	/*
	 * when we return from close_rc_channel, all callbacks should have
	 * completed. we can also be certain that these callbacks did not
	 * enqueue any events to conn_evd.
	 */
	status = ibt_close_rc_channel(ep_rp->ep_chan_hdl, IBT_BLOCKING,
	    NULL, 0, NULL, NULL, NULL);
	if (status != IBT_SUCCESS) {
		DERR("timer_thread: ibt_close_rc_channel returned %d\n",
		    status);
	}
	old_state = daplka_ep_get_state(ep_rp);

	/*
	 * this is the only thread that can transition ep_state out
	 * of ABORTING. all other ep operations would fail when
	 * ep_state is in ABORTING.
	 */
	ASSERT(old_state == DAPLKA_EP_STATE_ABORTING);

	disc_ev = kmem_zalloc(sizeof (daplka_evd_event_t), KM_SLEEP);
	ASSERT(disc_ev != NULL);

	disc_ev->ee_cmev.ec_cm_ev_type = DAPL_IB_CME_TIMED_OUT;
	disc_ev->ee_cmev.ec_cm_cookie = ep_rp->ep_cookie;
	disc_ev->ee_cmev.ec_cm_is_passive = B_FALSE;
	disc_ev->ee_cmev.ec_cm_psep_cookie = 0;
	disc_ev->ee_cmev.ec_cm_ev_priv_data = NULL;
	disc_ev->ee_cmev.ec_cm_ev_priv_data_len = 0;

	D2("timer_thread: enqueue event(%p) evdp(%p)\n",
	    disc_ev, ep_rp->ep_conn_evd);

	new_state = DAPLKA_EP_STATE_DISCONNECTED;
	daplka_ep_set_state(ep_rp, old_state, new_state);

	daplka_evd_wakeup(ep_rp->ep_conn_evd,
	    &ep_rp->ep_conn_evd->evd_conn_events, disc_ev);

	/* this function will also unref ep_rp */
	daplka_timer_info_free(timerp);
}

/*
 * dispatches a thread to continue with timer processing.
 */
static void
daplka_timer_dispatch(void *arg)
{
	/*
	 * keep rescheduling this function until
	 * taskq_dispatch succeeds.
	 */
	if (taskq_dispatch(daplka_taskq,
	    daplka_timer_thread, arg, TQ_NOSLEEP) == 0) {
		DERR("timer_dispatch: taskq_dispatch failed, retrying...\n");
		(void) timeout(daplka_timer_dispatch, arg, 10);
	}
}

/*
 * this function is called by the kernel's callout thread.
 * we first attempt to remove the timer object from the
 * global timer table. if it is found, we dispatch a thread
 * to continue processing the timer object. if it is not
 * found, that means the timer has been cancelled by someone
 * else.
 */
static void
daplka_timer_handler(void *arg)
{
	uint64_t		timer_hkey = (uintptr_t)arg;
	daplka_timer_info_t	*timerp = NULL;

	D2("timer_handler: timer_hkey 0x%llx\n", (longlong_t)timer_hkey);

	(void) daplka_hash_remove(&daplka_timer_info_htbl,
	    timer_hkey, (void **)&timerp);
	if (timerp == NULL) {
		D2("timer_handler: timer already cancelled\n");
		return;
	}
	daplka_timer_dispatch((void *)timerp);
}

/*
 * allocates a timer_info object.
 * a reference to a EP is held by this object. this ensures
 * that the EP stays valid when a timer is outstanding.
 */
static daplka_timer_info_t *
daplka_timer_info_alloc(daplka_ep_resource_t *ep_rp)
{
	daplka_timer_info_t	*timerp;

	timerp = kmem_zalloc(sizeof (*timerp), daplka_km_flags);
	if (timerp == NULL) {
		DERR("timer_info_alloc: cannot allocate timer info\n");
		return (NULL);
	}
	timerp->ti_ep_res = ep_rp;
	timerp->ti_tmo_id = 0;

	return (timerp);
}

/*
 * Frees the timer_info object.
 * we release the EP reference before freeing the object.
 */
static void
daplka_timer_info_free(daplka_timer_info_t *timerp)
{
	ASSERT(timerp->ti_ep_res != NULL);
	DAPLKA_RS_UNREF(timerp->ti_ep_res);
	timerp->ti_ep_res = NULL;
	ASSERT(timerp->ti_tmo_id == 0);
	kmem_free(timerp, sizeof (*timerp));
}

/*
 * cancels the timer set by ep_connect.
 * returns -1 if timer handling is in progress
 * and 0 otherwise.
 */
static int
daplka_cancel_timer(daplka_ep_resource_t *ep_rp)
{
	/*
	 * this function can only be called when ep_state
	 * is frozen.
	 */
	ASSERT(ep_rp->ep_state == DAPLKA_EP_STATE_TRANSITIONING);
	if (ep_rp->ep_timer_hkey != 0) {
		daplka_timer_info_t	*timerp = NULL;

		(void) daplka_hash_remove(&daplka_timer_info_htbl,
		    ep_rp->ep_timer_hkey, (void **)&timerp);
		if (timerp == NULL) {
			/*
			 * this is possible if the timer_handler has
			 * removed the timerp but the taskq thread has
			 * not transitioned the ep_state to DISCONNECTED.
			 * we need to reset the ep_state to allow the
			 * taskq thread to continue with its work. the
			 * taskq thread will set the ep_timer_hkey to 0
			 * so we don't have to do it here.
			 */
			DERR("cancel_timer: timer is being processed\n");
			return (-1);
		}
		/*
		 * we got the timer object. if the handler fires at
		 * this point, it will not be able to find the object
		 * and will return immediately. normally, ti_tmo_id gets
		 * cleared when the handler fires.
		 */
		ASSERT(timerp->ti_tmo_id != 0);

		/*
		 * note that untimeout can possibly call the handler.
		 * we are safe because the handler will be a no-op.
		 */
		(void) untimeout(timerp->ti_tmo_id);
		timerp->ti_tmo_id = 0;
		daplka_timer_info_free(timerp);
		ep_rp->ep_timer_hkey = 0;
	}
	return (0);
}

/*
 * this function is called by daplka_hash_destroy for
 * freeing timer_info objects
 */
static void
daplka_hash_timer_free(void *obj)
{
	daplka_timer_info_free((daplka_timer_info_t *)obj);
}

/* ARGSUSED */
static uint16_t
daplka_hellomsg_cksum(DAPL_PRIVATE *dp)
{
	uint8_t *bp;
	int i;
	uint16_t cksum = 0;

	bp = (uint8_t *)dp;
	for (i = 0; i < sizeof (DAPL_PRIVATE); i++) {
		cksum += bp[i];
	}
	return (cksum);
}

/*
 * ep_connect is called by the client to initiate a connection to a
 * remote service point. It is a non-blocking call. If a non-zero
 * timeout is specified by the client, a timer will be set just before
 * returning from ep_connect. Upon a successful return from ep_connect,
 * the client will call evd_wait to wait for the connection to complete.
 * If the connection is rejected or has failed due to an error, the
 * client will be notified with an event containing the appropriate error
 * code. If the connection is accepted, the client will be notified with
 * the CONN_ESTABLISHED event. If the timer expires before either of the
 * above events (error or established), a TIMED_OUT event will be delivered
 * to the client.
 *
 * the complicated part of the timer logic is the handling of race
 * conditions with CM callbacks. we need to ensure that either the CM or
 * the timer thread gets to deliver an event, but not both. when the
 * CM callback is about to deliver an event, it always tries to cancel
 * the outstanding timer. if cancel_timer indicates a that the timer is
 * already being processed, the CM callback will simply return without
 * delivering an event. when the timer thread executes, it tries to check
 * if the EP is still in CONNECTING state (timers only work on the active
 * side). if the EP is not in this state, the timer thread will return
 * without delivering an event.
 */
/* ARGSUSED */
static int
daplka_ep_connect(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_ep_resource_t	*ep_rp = NULL;
	dapl_ep_connect_t	args;
	daplka_timer_info_t	*timerp = NULL;
	uint32_t		old_state, new_state;
	boolean_t		timer_inserted = B_FALSE;
	uint64_t		timer_hkey = 0;
	ibt_path_info_t		path_info;
	ibt_path_attr_t		path_attr;
	ibt_hca_attr_t		*hca_attrp;
	ibt_chan_open_args_t	chan_args;
	ibt_status_t		status = IBT_SUCCESS;
	uint8_t			num_paths;
	void			*priv_data;
	DAPL_PRIVATE		*dp;
	int			retval = 0;
	ib_gid_t		*sgid;
	ib_gid_t		*dgid;
	uint64_t		dgid_ored;
	ibt_ar_t		ar_query_s;
	ibt_ar_t		ar_result_s;
	ibt_path_flags_t	pathflags;

	D3("ep_connect: enter\n");
	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_ep_connect_t),
	    mode);
	if (retval != 0) {
		DERR("ep_connect: copyin error %d\n", retval);
		return (EFAULT);
	}
	ep_rp = (daplka_ep_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_ep_htbl, args.epc_hkey);
	if (ep_rp == NULL) {
		DERR("ep_connect: cannot find ep resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(ep_rp) == DAPL_TYPE_EP);

	new_state = old_state = daplka_ep_get_state(ep_rp);
	if (old_state != DAPLKA_EP_STATE_CLOSED) {
		DERR("ep_connect: invalid state %d\n", old_state);
		retval = EINVAL;
		goto cleanup;
	}
	if (args.epc_priv_sz > DAPL_MAX_PRIVATE_DATA_SIZE) {
		DERR("ep_connect: private data len (%d) exceeded "
		    "max size %d\n", args.epc_priv_sz,
		    DAPL_MAX_PRIVATE_DATA_SIZE);
		retval = EINVAL;
		goto cleanup;
	}

	/*
	 * check for remote ipaddress to dgid resolution needs ATS
	 */
	dgid = &args.epc_dgid;
	dgid_ored = dgid->gid_guid | dgid->gid_prefix;
#if defined(DAPLKA_DEBUG_FORCE_ATS)
	dgid_ored = 0ULL;
#endif /* DAPLKA_DEBUG_FORCE_ATS */
	/* check for unidentified dgid */
	if (dgid_ored == 0ULL) {
		/*
		 * setup for ibt_query_ar()
		 */
		sgid = &ia_rp->ia_hca_sgid;
		ar_query_s.ar_gid.gid_guid = 0ULL;
		ar_query_s.ar_gid.gid_prefix = 0ULL;
		ar_query_s.ar_pkey = 0;
		bcopy(args.epc_raddr_sadata.iad_sadata,
		    ar_query_s.ar_data, DAPL_ATS_NBYTES);
#define	UR(b) ar_query_s.ar_data[(b)]
		D3("daplka_ep_connect: SA[8] %d.%d.%d.%d\n",
		    UR(8), UR(9), UR(10), UR(11));
		D3("daplka_ep_connect: SA[12] %d.%d.%d.%d\n",
		    UR(12), UR(13), UR(14), UR(15));
		status = ibt_query_ar(sgid, &ar_query_s, &ar_result_s);
		if (status != IBT_SUCCESS) {
			DERR("ep_connect: ibt_query_ar returned %d\n", status);
			*rvalp = (int)status;
			retval = 0;
			goto cleanup;
		}
		/*
		 * dgid identified from SA record
		 */
		dgid = &ar_result_s.ar_gid;
		D2("daplka_ep_connect: ATS dgid=%llx:%llx\n",
		    (longlong_t)dgid->gid_prefix, (longlong_t)dgid->gid_guid);
	}

	bzero(&path_info, sizeof (ibt_path_info_t));
	bzero(&path_attr, sizeof (ibt_path_attr_t));
	bzero(&chan_args, sizeof (ibt_chan_open_args_t));

	path_attr.pa_dgids = dgid;
	path_attr.pa_num_dgids = 1;
	/*
	 * don't set sid in path_attr saves 1 SA query
	 * Also makes server side not to write the service record
	 */
	path_attr.pa_sgid = ia_rp->ia_hca_sgid;
	path_attr.pa_pkey = ia_rp->ia_port_pkey;

	/* save the connection ep  - struct copy */
	ep_rp->ep_sgid = ia_rp->ia_hca_sgid;
	ep_rp->ep_dgid = *dgid;

	num_paths = 0;
	pathflags = IBT_PATH_PKEY;
	/* enable APM on remote port but not on loopback case */
	if (daplka_apm && ((dgid->gid_prefix != path_attr.pa_sgid.gid_prefix) ||
	    (dgid->gid_guid != path_attr.pa_sgid.gid_guid))) {
		pathflags |= IBT_PATH_APM;
	}
	status = ibt_get_paths(daplka_dev->daplka_clnt_hdl,
	    pathflags, &path_attr, 1, &path_info, &num_paths);

	if (status != IBT_SUCCESS && status != IBT_INSUFF_DATA) {
		DERR("ep_connect: ibt_get_paths returned %d paths %d\n",
		    status, num_paths);
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}
	/* fill in the sid directly to path_info */
	path_info.pi_sid = args.epc_sid;
	hca_attrp = &ia_rp->ia_hca->hca_attr;

	/* fill in open channel args */
	chan_args.oc_path = &path_info;
	chan_args.oc_cm_handler = daplka_cm_rc_handler;
	chan_args.oc_cm_clnt_private = (void *)ep_rp;
	chan_args.oc_rdma_ra_out = hca_attrp->hca_max_rdma_out_chan;
	chan_args.oc_rdma_ra_in = hca_attrp->hca_max_rdma_in_chan;
	chan_args.oc_path_retry_cnt = 7;	/* 3-bit field */
	chan_args.oc_path_rnr_retry_cnt = IBT_RNR_INFINITE_RETRY;

	ASSERT(args.epc_priv_sz > 0);
	priv_data = (void *)args.epc_priv;

	chan_args.oc_priv_data_len = args.epc_priv_sz;
	chan_args.oc_priv_data = priv_data;

	/*
	 * calculate checksum value of hello message and
	 * put hello message in networking byte order
	 */
	dp = (DAPL_PRIVATE *)priv_data;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*dp))
	dp->hello_msg.hi_port = htons(dp->hello_msg.hi_port);
	dp->hello_msg.hi_checksum = 0;
	dp->hello_msg.hi_checksum = htons(daplka_hellomsg_cksum(dp));
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*dp))

	if (args.epc_timeout > 0) {
		/*
		 * increment refcnt before passing reference to
		 * timer_info_alloc.
		 */
		DAPLKA_RS_REF(ep_rp);
		timerp = daplka_timer_info_alloc(ep_rp);
		if (timerp == NULL) {
			DERR("ep_connect: cannot allocate timer\n");
			/*
			 * we need to remove the reference if
			 * allocation failed.
			 */
			DAPLKA_RS_UNREF(ep_rp);
			retval = ENOMEM;
			goto cleanup;
		}
		/*
		 * We generate our own hkeys so that timer_hkey can fit
		 * into a pointer and passed as an arg to timeout()
		 */
		timer_hkey = (uint64_t)daplka_timer_hkey_gen();
		retval = daplka_hash_insert(&daplka_timer_info_htbl,
		    &timer_hkey, (void *)timerp);
		if (retval != 0) {
			DERR("ep_connect: cannot insert timer info\n");
			goto cleanup;
		}
		ASSERT(ep_rp->ep_timer_hkey == 0);
		ep_rp->ep_timer_hkey = timer_hkey;
		timer_inserted = B_TRUE;
		D2("ep_connect: timer_hkey = 0x%llx\n",
		    (longlong_t)timer_hkey);
	}
	status = ibt_open_rc_channel(ep_rp->ep_chan_hdl, IBT_OCHAN_NO_FLAGS,
	    IBT_NONBLOCKING, &chan_args, NULL);

	if (status != IBT_SUCCESS) {
		DERR("ep_connect: ibt_open_rc_channel returned %d\n", status);
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}
	/*
	 * if a cm callback gets called at this point, it'll have to wait until
	 * ep_state becomes connecting (or some other state if another thread
	 * manages to get ahead of the callback). this guarantees that the
	 * callback will not touch the timer until it gets set.
	 */
	if (timerp != NULL) {
		clock_t		tmo;

		tmo = drv_usectohz((clock_t)args.epc_timeout);
		/*
		 * We generate our own 32 bit timer_hkey so that it can fit
		 * into a pointer
		 */
		ASSERT(timer_hkey != 0);
		timerp->ti_tmo_id = timeout(daplka_timer_handler,
		    (void *)(uintptr_t)timer_hkey, tmo);
	}
	new_state = DAPLKA_EP_STATE_CONNECTING;

cleanup:;
	if (timerp != NULL && (retval != 0 || status != IBT_SUCCESS)) {
		/*
		 * if ibt_open_rc_channel failed, the timerp must still
		 * be in daplka_timer_info_htbl because neither the cm
		 * callback nor the timer_handler will be called.
		 */
		if (timer_inserted) {
			daplka_timer_info_t	*new_timerp = NULL;

			ASSERT(timer_hkey != 0);
			(void) daplka_hash_remove(&daplka_timer_info_htbl,
			    timer_hkey, (void **)&new_timerp);
			ASSERT(new_timerp == timerp);
			ep_rp->ep_timer_hkey = 0;
		}
		daplka_timer_info_free(timerp);
	}
	daplka_ep_set_state(ep_rp, old_state, new_state);
	DAPLKA_RS_UNREF(ep_rp);
	D3("ep_connect: exit\n");
	return (retval);
}

/*
 * ep_disconnect closes a connection with a remote peer.
 * if a connection has not been established, ep_disconnect
 * will instead flush all recv bufs posted to this channel.
 * if the EP state is CONNECTED, CONNECTING or ACCEPTING upon
 * entry to ep_disconnect, the EP state will transition to
 * DISCONNECTING upon exit. the CM callbacks triggered by
 * ibt_close_rc_channel will cause EP state to become
 * DISCONNECTED. This function is a no-op if EP state is
 * DISCONNECTED.
 */
/* ARGSUSED */
static int
daplka_ep_disconnect(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_ep_resource_t	*ep_rp = NULL;
	dapl_ep_disconnect_t	args;
	ibt_status_t		status;
	uint32_t		old_state, new_state;
	int			retval = 0;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_ep_disconnect_t),
	    mode);
	if (retval != 0) {
		DERR("ep_disconnect: copyin error %d\n", retval);
		return (EFAULT);
	}
	ep_rp = (daplka_ep_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_ep_htbl, args.epd_hkey);
	if (ep_rp == NULL) {
		DERR("ep_disconnect: cannot find ep resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(ep_rp) == DAPL_TYPE_EP);

	new_state = old_state = daplka_ep_get_state(ep_rp);
	if (old_state != DAPLKA_EP_STATE_CONNECTED &&
	    old_state != DAPLKA_EP_STATE_CONNECTING &&
	    old_state != DAPLKA_EP_STATE_ACCEPTING &&
	    old_state != DAPLKA_EP_STATE_DISCONNECTED &&
	    old_state != DAPLKA_EP_STATE_DISCONNECTING &&
	    old_state != DAPLKA_EP_STATE_CLOSED) {
		DERR("ep_disconnect: invalid state %d\n", old_state);
		retval = EINVAL;
		goto cleanup;
	}

	if ((old_state == DAPLKA_EP_STATE_DISCONNECTED) ||
	    (old_state == DAPLKA_EP_STATE_DISCONNECTING)) {
		D2("ep_disconnect: ep already disconnected\n");
		retval = 0;
		/* we leave the state as DISCONNECTED */
		goto cleanup;
	}
	if (old_state == DAPLKA_EP_STATE_CONNECTING ||
	    old_state == DAPLKA_EP_STATE_ACCEPTING) {
		D2("ep_disconnect: aborting, old_state = %d\n", old_state);
	}

	/*
	 * according to the udapl spec, ep_disconnect should
	 * flush the channel if the channel is not CONNECTED.
	 */
	if (old_state == DAPLKA_EP_STATE_CLOSED) {
		status = ibt_flush_channel(ep_rp->ep_chan_hdl);
		if (status != IBT_SUCCESS) {
			DERR("ep_disconnect: ibt_flush_channel failed %d\n",
			    status);
			*rvalp = (int)status;
		}
		retval = 0;
		/* we leave the state as CLOSED */
		goto cleanup;
	}

	new_state = DAPLKA_EP_STATE_DISCONNECTING;
	daplka_ep_set_state(ep_rp, old_state, new_state);
	status = ibt_close_rc_channel(ep_rp->ep_chan_hdl, IBT_NONBLOCKING,
	    NULL, 0, NULL, NULL, NULL);

	if (status == IBT_SUCCESS) {
		DAPLKA_RS_UNREF(ep_rp);
		return (retval);
	} else {
		DERR("ep_disconnect: ibt_close_rc_channel returned %d\n",
		    status);
		*rvalp = (int)status;
		retval = 0;
		new_state = old_state;
	}

cleanup:;
	daplka_ep_set_state(ep_rp, old_state, new_state);
	DAPLKA_RS_UNREF(ep_rp);
	return (retval);
}

/*
 * this function resets the EP to a usable state (ie. from
 * DISCONNECTED to CLOSED). this function is best implemented using
 * the ibt_recycle_channel interface. until that is available, we will
 * instead clone and tear down the existing channel and replace the
 * existing channel with the cloned one.
 */
/* ARGSUSED */
static int
daplka_ep_reinit(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_ep_resource_t		*ep_rp = NULL;
	dapl_ep_reinit_t		args;
	ibt_status_t			status;
	uint32_t			old_state, new_state;
	int				retval = 0;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_ep_reinit_t),
	    mode);
	if (retval != 0) {
		DERR("reinit: copyin error %d\n", retval);
		return (EFAULT);
	}
	ep_rp = (daplka_ep_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_ep_htbl, args.epri_hkey);
	if (ep_rp == NULL) {
		DERR("reinit: cannot find ep resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(ep_rp) == DAPL_TYPE_EP);
	new_state = old_state = daplka_ep_get_state(ep_rp);
	if ((old_state != DAPLKA_EP_STATE_CLOSED) &&
	    (old_state != DAPLKA_EP_STATE_DISCONNECTED)) {
		DERR("reinit: invalid state %d\n", old_state);
		retval = EINVAL;
		goto cleanup;
	}

	status = ibt_recycle_rc(ep_rp->ep_chan_hdl,
	    IBT_CEP_RDMA_RD|IBT_CEP_RDMA_WR,
	    ia_rp->ia_port_num, NULL, NULL);
	if (status != IBT_SUCCESS) {
		DERR("reinit: unable to clone channel\n");
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}
	new_state = DAPLKA_EP_STATE_CLOSED;

cleanup:;
	daplka_ep_set_state(ep_rp, old_state, new_state);
	DAPLKA_RS_UNREF(ep_rp);
	return (retval);
}

/*
 * destroys a EP resource.
 * called when refcnt drops to zero.
 */
static int
daplka_ep_destroy(daplka_resource_t *gen_rp)
{
	daplka_ep_resource_t	*ep_rp = (daplka_ep_resource_t *)gen_rp;
	ibt_status_t		status;

	ASSERT(DAPLKA_RS_REFCNT(ep_rp) == 0);
	ASSERT(ep_rp->ep_state == DAPLKA_EP_STATE_FREED);

	/*
	 * by the time we get here, we can be sure that
	 * there is no outstanding timer.
	 */
	ASSERT(ep_rp->ep_timer_hkey == 0);

	D3("ep_destroy: entering, ep_rp 0x%p, rnum %d\n",
	    ep_rp, DAPLKA_RS_RNUM(ep_rp));
	/*
	 * free rc channel
	 */
	if (ep_rp->ep_chan_hdl != NULL) {
		mutex_enter(&daplka_dev->daplka_mutex);
		ibt_set_chan_private(ep_rp->ep_chan_hdl, NULL);
		mutex_exit(&daplka_dev->daplka_mutex);
		status = daplka_ibt_free_channel(ep_rp, ep_rp->ep_chan_hdl);
		if (status != IBT_SUCCESS) {
			DERR("ep_free: ibt_free_channel returned %d\n",
			    status);
		}
		ep_rp->ep_chan_hdl = NULL;
		D3("ep_destroy: qp freed, rnum %d\n", DAPLKA_RS_RNUM(ep_rp));
	}
	/*
	 * release all references
	 */
	if (ep_rp->ep_snd_evd != NULL) {
		DAPLKA_RS_UNREF(ep_rp->ep_snd_evd);
		ep_rp->ep_snd_evd = NULL;
	}
	if (ep_rp->ep_rcv_evd != NULL) {
		DAPLKA_RS_UNREF(ep_rp->ep_rcv_evd);
		ep_rp->ep_rcv_evd = NULL;
	}
	if (ep_rp->ep_conn_evd != NULL) {
		DAPLKA_RS_UNREF(ep_rp->ep_conn_evd);
		ep_rp->ep_conn_evd = NULL;
	}
	if (ep_rp->ep_srq_res != NULL) {
		DAPLKA_RS_UNREF(ep_rp->ep_srq_res);
		ep_rp->ep_srq_res = NULL;
	}
	if (ep_rp->ep_pd_res != NULL) {
		DAPLKA_RS_UNREF(ep_rp->ep_pd_res);
		ep_rp->ep_pd_res = NULL;
	}
	cv_destroy(&ep_rp->ep_cv);
	mutex_destroy(&ep_rp->ep_lock);

	DAPLKA_RS_FINI(ep_rp);
	kmem_free(ep_rp, sizeof (daplka_ep_resource_t));
	D3("ep_destroy: exiting, ep_rp 0x%p\n", ep_rp);
	return (0);
}

/*
 * this function is called by daplka_hash_destroy for
 * freeing EP resource objects
 */
static void
daplka_hash_ep_free(void *obj)
{
	daplka_ep_resource_t	*ep_rp = (daplka_ep_resource_t *)obj;
	ibt_status_t		status;
	uint32_t		old_state, new_state;
	int			retval;

	old_state = daplka_ep_get_state(ep_rp);
	retval = daplka_cancel_timer(ep_rp);
	new_state = DAPLKA_EP_STATE_FREED;
	daplka_ep_set_state(ep_rp, old_state, new_state);

	if (retval != 0) {
		D2("hash_ep_free: ep_rp 0x%p "
		    "timer is still being processed\n", ep_rp);
		mutex_enter(&ep_rp->ep_lock);
		if (ep_rp->ep_timer_hkey != 0) {
			D2("hash_ep_free: ep_rp 0x%p "
			    "waiting for timer_hkey to be 0\n", ep_rp);
			cv_wait(&ep_rp->ep_cv, &ep_rp->ep_lock);
		}
		mutex_exit(&ep_rp->ep_lock);
	}

	/* call ibt_close_rc_channel regardless of what state we are in */
	status = ibt_close_rc_channel(ep_rp->ep_chan_hdl, IBT_BLOCKING,
	    NULL, 0, NULL, NULL, NULL);
	if (status != IBT_SUCCESS) {
		if (old_state == DAPLKA_EP_STATE_CONNECTED ||
		    old_state == DAPLKA_EP_STATE_CONNECTING ||
		    old_state == DAPLKA_EP_STATE_ACCEPTING) {
			DERR("hash_ep_free: ep_rp 0x%p state %d "
			    "unexpected error %d from close_rc_channel\n",
			    ep_rp, old_state, status);
		}
		D2("hash_ep_free: close_rc_channel, status %d\n", status);
	}

	DAPLKA_RS_UNREF(ep_rp);
}

/*
 * creates a EVD resource.
 * a EVD is used by the client to wait for events from one
 * or more sources.
 */
/* ARGSUSED */
static int
daplka_evd_create(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_evd_resource_t		*evd_rp = NULL;
	daplka_async_evd_hkey_t		*async_evd;
	ibt_hca_attr_t			*hca_attrp;
	ibt_cq_attr_t			cq_attr;
	dapl_evd_create_t		args;
	uint64_t			evd_hkey = 0;
	boolean_t			inserted = B_FALSE;
	int				retval = 0;
	ibt_status_t			status;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_evd_create_t),
	    mode);
	if (retval != 0) {
		DERR("evd_create: copyin error %d", retval);
		return (EFAULT);
	}
	if ((args.evd_flags &
	    ~(DAT_EVD_DEFAULT_FLAG | DAT_EVD_SOFTWARE_FLAG)) != 0) {
		DERR("evd_create: invalid flags 0x%x\n", args.evd_flags);
		return (EINVAL);
	}

	evd_rp = kmem_zalloc(sizeof (daplka_evd_resource_t), daplka_km_flags);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*evd_rp))
	DAPLKA_RS_INIT(evd_rp, DAPL_TYPE_EVD,
	    DAPLKA_RS_RNUM(ia_rp), daplka_evd_destroy);

	mutex_init(&evd_rp->evd_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&evd_rp->evd_cv, NULL, CV_DRIVER, NULL);
	evd_rp->evd_hca = ia_rp->ia_hca;
	evd_rp->evd_flags = args.evd_flags;
	evd_rp->evd_hca_hdl = ia_rp->ia_hca_hdl;
	evd_rp->evd_cookie = args.evd_cookie;
	evd_rp->evd_cno_res = NULL;
	evd_rp->evd_cr_events.eel_event_type = DAPLKA_EVD_CM_EVENTS;
	evd_rp->evd_conn_events.eel_event_type = DAPLKA_EVD_CM_EVENTS;
	evd_rp->evd_async_events.eel_event_type = DAPLKA_EVD_ASYNC_EVENTS;

	/*
	 * if the client specified a non-zero cno_hkey, we
	 * lookup the cno and save the reference for later use.
	 */
	if (args.evd_cno_hkey > 0) {
		daplka_cno_resource_t *cno_rp;

		cno_rp = (daplka_cno_resource_t *)
		    daplka_hash_lookup(&ia_rp->ia_cno_htbl,
		    args.evd_cno_hkey);
		if (cno_rp == NULL) {
			DERR("evd_create: cannot find cno resource\n");
			goto cleanup;
		}
		ASSERT(DAPLKA_RS_TYPE(cno_rp) == DAPL_TYPE_CNO);
		evd_rp->evd_cno_res = cno_rp;
	}
	hca_attrp = &ia_rp->ia_hca->hca_attr;
	if ((evd_rp->evd_flags &
	    (DAT_EVD_DTO_FLAG | DAT_EVD_RMR_BIND_FLAG)) != 0) {
		if (args.evd_cq_size > hca_attrp->hca_max_cq_sz) {
			DERR("evd_create: invalid cq size %d",
			    args.evd_cq_size);
			retval = EINVAL;
			goto cleanup;
		}
		cq_attr.cq_size = args.evd_cq_size;
		cq_attr.cq_sched = NULL;
		cq_attr.cq_flags = IBT_CQ_USER_MAP;

		status = daplka_ibt_alloc_cq(evd_rp, evd_rp->evd_hca_hdl,
		    &cq_attr, &evd_rp->evd_cq_hdl, &evd_rp->evd_cq_real_size);

		if (status != IBT_SUCCESS) {
			DERR("evd_create: ibt_alloc_cq returned %d", status);
			*rvalp = (int)status;
			retval = 0;
			goto cleanup;
		}

		/*
		 * store evd ptr with cq_hdl
		 * mutex is only needed for race of "destroy" and "async"
		 */
		mutex_enter(&daplka_dev->daplka_mutex);
		ibt_set_cq_private(evd_rp->evd_cq_hdl, (void *)evd_rp);
		mutex_exit(&daplka_dev->daplka_mutex);

		/* Get HCA-specific data_out info */
		status = ibt_ci_data_out(evd_rp->evd_hca_hdl,
		    IBT_CI_NO_FLAGS, IBT_HDL_CQ, (void *)evd_rp->evd_cq_hdl,
		    &args.evd_cq_data_out, sizeof (args.evd_cq_data_out));

		if (status != IBT_SUCCESS) {
			DERR("evd_create: ibt_ci_data_out error(%d)", status);
			*rvalp = (int)status;
			retval = 0;
			goto cleanup;
		}

		args.evd_cq_real_size = evd_rp->evd_cq_real_size;

		ibt_set_cq_handler(evd_rp->evd_cq_hdl, daplka_cq_handler,
		    (void *)evd_rp);
	}

	retval = daplka_hash_insert(&ia_rp->ia_evd_htbl,
	    &evd_hkey, (void *)evd_rp);
	if (retval != 0) {
		DERR("evd_ceate: cannot insert evd %d\n", retval);
		goto cleanup;
	}
	inserted = B_TRUE;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*evd_rp))

	/*
	 * If this evd handles async events need to add to the IA resource
	 * async evd list
	 */
	if (evd_rp->evd_flags & DAT_EVD_ASYNC_FLAG) {
		async_evd = kmem_zalloc(sizeof (daplka_async_evd_hkey_t),
		    daplka_km_flags);
		/* add the evd to the head of the list */
		mutex_enter(&ia_rp->ia_lock);
		async_evd->aeh_evd_hkey = evd_hkey;
		async_evd->aeh_next = ia_rp->ia_async_evd_hkeys;
		ia_rp->ia_async_evd_hkeys = async_evd;
		mutex_exit(&ia_rp->ia_lock);
	}

	args.evd_hkey = evd_hkey;
	retval = copyout(&args, (void *)arg, sizeof (dapl_evd_create_t));
	if (retval != 0) {
		DERR("evd_create: copyout error %d\n", retval);
		retval = EFAULT;
		goto cleanup;
	}
	return (0);

cleanup:;
	if (inserted) {
		daplka_evd_resource_t *free_rp = NULL;

		(void) daplka_hash_remove(&ia_rp->ia_evd_htbl, evd_hkey,
		    (void **)&free_rp);
		if (free_rp != evd_rp) {
			DERR("evd_create: cannot remove evd\n");
			/*
			 * we can only get here if another thread
			 * has completed the cleanup in evd_free
			 */
			return (retval);
		}
	}
	DAPLKA_RS_UNREF(evd_rp);
	return (retval);
}

/*
 * resizes CQ and returns new mapping info to library.
 */
/* ARGSUSED */
static int
daplka_cq_resize(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_evd_resource_t		*evd_rp = NULL;
	ibt_hca_attr_t			*hca_attrp;
	dapl_cq_resize_t		args;
	ibt_status_t			status;
	int				retval = 0;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_cq_resize_t),
	    mode);
	if (retval != 0) {
		DERR("cq_resize: copyin error %d\n", retval);
		return (EFAULT);
	}

	/* get evd resource */
	evd_rp = (daplka_evd_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_evd_htbl, args.cqr_evd_hkey);
	if (evd_rp == NULL) {
		DERR("cq_resize: cannot find evd resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(evd_rp) == DAPL_TYPE_EVD);

	hca_attrp = &ia_rp->ia_hca->hca_attr;
	if (args.cqr_cq_new_size > hca_attrp->hca_max_cq_sz) {
		DERR("cq_resize: invalid cq size %d", args.cqr_cq_new_size);
		retval = EINVAL;
		goto cleanup;
	}
	/*
	 * If ibt_resize_cq fails that it is primarily due to resource
	 * shortage. Per IB spec resize will never loose events and
	 * a resize error leaves the CQ intact. Therefore even if the
	 * resize request fails we proceed and get the mapping data
	 * from the CQ so that the library can mmap it.
	 */
	status = ibt_resize_cq(evd_rp->evd_cq_hdl, args.cqr_cq_new_size,
	    &args.cqr_cq_real_size);
	if (status != IBT_SUCCESS) {
		/* we return the size of the old CQ if resize fails */
		args.cqr_cq_real_size = evd_rp->evd_cq_real_size;
		ASSERT(status != IBT_CQ_HDL_INVALID);
		DERR("cq_resize: ibt_resize_cq failed:%d\n", status);
	} else {
		mutex_enter(&evd_rp->evd_lock);
		evd_rp->evd_cq_real_size = args.cqr_cq_real_size;
		mutex_exit(&evd_rp->evd_lock);
	}

	D2("cq_resize(%d): done new_sz(%u) real_sz(%u)\n",
	    DAPLKA_RS_RNUM(evd_rp),
	    args.cqr_cq_new_size, args.cqr_cq_real_size);

	/* Get HCA-specific data_out info */
	status = ibt_ci_data_out(evd_rp->evd_hca_hdl,
	    IBT_CI_NO_FLAGS, IBT_HDL_CQ, (void *)evd_rp->evd_cq_hdl,
	    &args.cqr_cq_data_out, sizeof (args.cqr_cq_data_out));
	if (status != IBT_SUCCESS) {
		DERR("cq_resize: ibt_ci_data_out error(%d)\n", status);
		/* return ibt_ci_data_out status */
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}

	retval = ddi_copyout(&args, (void *)arg, sizeof (dapl_cq_resize_t),
	    mode);
	if (retval != 0) {
		DERR("cq_resize: copyout error %d\n", retval);
		retval = EFAULT;
		goto cleanup;
	}

cleanup:;
	if (evd_rp != NULL) {
		DAPLKA_RS_UNREF(evd_rp);
	}
	return (retval);
}

/*
 * Routine to copyin the event poll message so that 32 bit libraries
 * can be safely supported
 */
int
daplka_event_poll_copyin(intptr_t inarg, dapl_event_poll_t *outarg, int mode)
{
	int	retval;

#ifdef _MULTI_DATAMODEL
	if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
		dapl_event_poll32_t	args32;

		retval = ddi_copyin((void *)inarg, &args32,
		    sizeof (dapl_event_poll32_t), mode);
		if (retval != 0) {
			DERR("event_poll_copyin: 32bit error %d\n", retval);
			return (EFAULT);
		}

		outarg->evp_evd_hkey = args32.evp_evd_hkey;
		outarg->evp_threshold = args32.evp_threshold;
		outarg->evp_timeout = args32.evp_timeout;
		outarg->evp_ep = (dapl_ib_event_t *)(uintptr_t)args32.evp_ep;
		outarg->evp_num_ev = args32.evp_num_ev;
		outarg->evp_num_polled = args32.evp_num_polled;
		return (0);
	}
#endif
	retval = ddi_copyin((void *)inarg, outarg, sizeof (dapl_event_poll_t),
	    mode);
	if (retval != 0) {
		DERR("event_poll: copyin error %d\n", retval);
		return (EFAULT);
	}

	return (0);
}

/*
 * Routine to copyout the event poll message so that 32 bit libraries
 * can be safely supported
 */
int
daplka_event_poll_copyout(dapl_event_poll_t *inarg, intptr_t outarg, int mode)
{
	int	retval;

#ifdef _MULTI_DATAMODEL
	if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
		dapl_event_poll32_t	args32;

		args32.evp_evd_hkey = inarg->evp_evd_hkey;
		args32.evp_threshold = inarg->evp_threshold;
		args32.evp_timeout = inarg->evp_timeout;
		args32.evp_ep = (caddr32_t)(uintptr_t)inarg->evp_ep;
		args32.evp_num_ev = inarg->evp_num_ev;
		args32.evp_num_polled = inarg->evp_num_polled;

		retval = ddi_copyout((void *)&args32, (void *)outarg,
		    sizeof (dapl_event_poll32_t), mode);
		if (retval != 0) {
			DERR("event_poll_copyout: 32bit error %d\n", retval);
			return (EFAULT);
		}
		return (0);
	}
#endif
	retval = ddi_copyout((void *)inarg, (void *)outarg,
	    sizeof (dapl_event_poll_t), mode);
	if (retval != 0) {
		DERR("event_poll_copyout: error %d\n", retval);
		return (EFAULT);
	}

	return (0);
}

/*
 * fucntion to handle CM REQ RCV private data from Solaris or third parties
 */
/* ARGSUSED */
static void
daplka_crevent_privdata_post(daplka_ia_resource_t *ia_rp,
	dapl_ib_event_t *evd_rp, daplka_evd_event_t *cr_ev)
{
	DAPL_PRIVATE	*dp;
	ib_gid_t	*lgid;
	ibt_ar_t	ar_query_s;
	ibt_ar_t	ar_result_s;
	DAPL_HELLO_MSG	*hip;
	uint32_t	ipaddr_ord;
	ibt_priv_data_len_t clen;
	ibt_priv_data_len_t olen;
	ibt_status_t	status;
	uint16_t	cksum;

	/*
	 * get private data and len
	 */
	dp = (DAPL_PRIVATE *)cr_ev->ee_cmev.ec_cm_ev_priv_data;
	clen = cr_ev->ee_cmev.ec_cm_ev_priv_data_len;
#if defined(DAPLKA_DEBUG_FORCE_ATS)
	/* skip the DAPL_PRIVATE chekcsum check */
#else
	/* for remote connects */
	/* look up hello message in the CM private data area */
	if (clen >= sizeof (DAPL_PRIVATE) &&
	    (dp->hello_msg.hi_vers == DAPL_HELLO_MSG_VERS)) {
		cksum = ntohs(dp->hello_msg.hi_checksum);
		dp->hello_msg.hi_checksum = 0;
		if (daplka_hellomsg_cksum(dp) == cksum) {
			D2("daplka_crevent_privdata_post: Solaris msg\n");
			evd_rp->ibe_ce.ibce_priv_data_size = clen;
			dp->hello_msg.hi_checksum = DAPL_CHECKSUM;
			dp->hello_msg.hi_port = ntohs(dp->hello_msg.hi_port);
			bcopy(dp, evd_rp->ibe_ce.ibce_priv_data_ptr, clen);
			kmem_free(dp, clen);
			return;
		}
	}
#endif /* DAPLKA_DEBUG_FORCE_ATS */

	D2("daplka_crevent_privdata_post: 3rd party msg\n");
	/* transpose CM private data into hello message */
	if (clen) {
		olen = clen;
		if (clen > DAPL_CONSUMER_MAX_PRIVATE_DATA_SIZE) {
			clen = DAPL_CONSUMER_MAX_PRIVATE_DATA_SIZE;
		}
		bcopy(dp, evd_rp->ibe_ce.ibce_priv_data_ptr, clen);
		kmem_free(dp, olen);
	} else {
		bzero(evd_rp->ibe_ce.ibce_priv_data_ptr,
		    DAPL_CONSUMER_MAX_PRIVATE_DATA_SIZE);
	}
	evd_rp->ibe_ce.ibce_priv_data_size = sizeof (DAPL_PRIVATE);
	dp = (DAPL_PRIVATE *)evd_rp->ibe_ce.ibce_priv_data_ptr;
	/*
	 * fill in hello message
	 */
	hip = &dp->hello_msg;
	hip->hi_checksum = DAPL_CHECKSUM;
	hip->hi_clen = clen;
	hip->hi_mid = 0;
	hip->hi_vers = DAPL_HELLO_MSG_VERS;
	hip->hi_port = 0;

	/* assign sgid and dgid */
	lgid = &ia_rp->ia_hca_sgid;
	ar_query_s.ar_gid.gid_prefix =
	    cr_ev->ee_cmev.ec_cm_req_prim_addr.gid_prefix;
	ar_query_s.ar_gid.gid_guid =
	    cr_ev->ee_cmev.ec_cm_req_prim_addr.gid_guid;
	ar_query_s.ar_pkey = ia_rp->ia_port_pkey;
	bzero(ar_query_s.ar_data, DAPL_ATS_NBYTES);

	/* reverse ip address lookup through ATS */
	status = ibt_query_ar(lgid, &ar_query_s, &ar_result_s);
	if (status == IBT_SUCCESS) {
		bcopy(ar_result_s.ar_data, hip->hi_saaddr, DAPL_ATS_NBYTES);
		/* determine the address families */
		ipaddr_ord = hip->hi_v4pad[0] | hip->hi_v4pad[1] |
		    hip->hi_v4pad[2];
		if (ipaddr_ord == 0) {
			hip->hi_ipv = AF_INET;
		} else {
			hip->hi_ipv = AF_INET6;
		}

#define	UL(b) ar_result_s.ar_data[(b)]
		D3("daplka_privdata_post: family=%d :SA[8] %d.%d.%d.%d\n",
		    hip->hi_ipv, UL(8), UL(9), UL(10), UL(11));
		D3("daplka_privdata_post: SA[12] %d.%d.%d.%d\n",
		    UL(12), UL(13), UL(14), UL(15));
	} else {
		/* non-conformed third parties */
		hip->hi_ipv = AF_UNSPEC;
		bzero(hip->hi_saaddr, DAPL_ATS_NBYTES);
	}
}

/*
 * this function is called by evd_wait and evd_dequeue to wait for
 * connection events and CQ notifications. typically this function
 * is called when the userland CQ is empty and the client has
 * specified a non-zero timeout to evd_wait. if the client is
 * interested in CQ events, the CQ must be armed in userland prior
 * to calling this function.
 */
/* ARGSUSED */
static int
daplka_event_poll(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_evd_resource_t	*evd_rp = NULL;
	dapl_event_poll_t	args;
	daplka_evd_event_t	*head;
	dapl_ib_event_t		evp_arr[NUM_EVENTS_PER_POLL];
	dapl_ib_event_t		*evp;
	dapl_ib_event_t		*evp_start;
	size_t			evp_size;
	int			threshold;
	clock_t			timeout;
	uint32_t		max_events;
	uint32_t		num_events = 0;
	void			*pd;
	ibt_priv_data_len_t	n;
	int			retval = 0;
	int			rc;

	retval = daplka_event_poll_copyin(arg, &args, mode);
	if (retval != 0) {
		return (EFAULT);
	}

	if ((args.evp_num_ev > 0) && (args.evp_ep == NULL)) {
		DERR("event_poll: evp_ep cannot be NULL if num_wc=%d",
		    args.evp_num_ev);
		return (EINVAL);
	}
	/*
	 * Note: dequeue requests have a threshold = 0, timeout = 0
	 */
	threshold = args.evp_threshold;

	max_events = args.evp_num_ev;
	/* ensure library is passing sensible values */
	if (max_events < threshold) {
		DERR("event_poll: max_events(%d) < threshold(%d)\n",
		    max_events, threshold);
		return (EINVAL);
	}
	/* Do a sanity check to avoid excessive memory allocation */
	if (max_events > DAPL_EVD_MAX_EVENTS) {
		DERR("event_poll: max_events(%d) > %d",
		    max_events, DAPL_EVD_MAX_EVENTS);
		return (EINVAL);
	}
	D4("event_poll: threshold(%d) timeout(0x%llx) max_events(%d)\n",
	    threshold, (longlong_t)args.evp_timeout, max_events);

	/* get evd resource */
	evd_rp = (daplka_evd_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_evd_htbl, args.evp_evd_hkey);
	if (evd_rp == NULL) {
		DERR("event_poll: cannot find evd resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(evd_rp) == DAPL_TYPE_EVD);

	/*
	 * Use event array on the stack if possible
	 */
	if (max_events <= NUM_EVENTS_PER_POLL) {
		evp_start = evp = &evp_arr[0];
	} else {
		evp_size = max_events * sizeof (dapl_ib_event_t);
		evp_start = evp = kmem_zalloc(evp_size, daplka_km_flags);
		if (evp == NULL) {
			DERR("event_poll: kmem_zalloc failed, evp_size %d",
			    evp_size);
			retval = ENOMEM;
			goto cleanup;
		}
	}

	/*
	 * The Event poll algorithm is as follows -
	 * The library passes a buffer big enough to hold "max_events"
	 * events. max_events is >= threshold. If at any stage we get
	 * max_events no. of events we bail. The events are polled in
	 * the following order -
	 * 1) Check for CR events in the evd_cr_events list
	 * 2) Check for Connection events in the evd_connection_events list
	 *
	 * If after the above 2 steps we don't have enough(>= threshold) events
	 * we block for CQ notification and sleep. Upon being woken up we start
	 * at step 1 again.
	 */

	/*
	 * Note: this could be 0 or INFINITE or anyother value in microsec
	 */
	if (args.evp_timeout > 0) {
		if (args.evp_timeout >= LONG_MAX) {
			timeout = LONG_MAX;
		} else {
			clock_t	curr_time = ddi_get_lbolt();

			timeout = curr_time +
			    drv_usectohz((clock_t)args.evp_timeout);
			/*
			 * use the max value if we wrapped around
			 */
			if (timeout <= curr_time) {
				timeout = LONG_MAX;
			}
		}
	} else {
		timeout = 0;
	}

	mutex_enter(&evd_rp->evd_lock);
	for (;;) {
		/*
		 * If this evd is waiting for CM events check that now.
		 */
		if ((evd_rp->evd_flags & DAT_EVD_CR_FLAG) &&
		    (evd_rp->evd_cr_events.eel_num_elements > 0)) {
			/* dequeue events from evd_cr_events list */
			while (head = daplka_evd_event_dequeue(
			    &evd_rp->evd_cr_events)) {
				/*
				 * populate the evp array
				 */
				evp[num_events].ibe_ev_family = DAPL_CR_EVENTS;
				evp[num_events].ibe_ce.ibce_event =
				    head->ee_cmev.ec_cm_ev_type;
				evp[num_events].ibe_ce.ibce_cookie =
				    (uint64_t)head->ee_cmev.ec_cm_cookie;
				evp[num_events].ibe_ce.ibce_psep_cookie =
				    head->ee_cmev.ec_cm_psep_cookie;
				daplka_crevent_privdata_post(ia_rp,
				    &evp[num_events], head);
				kmem_free(head, sizeof (daplka_evd_event_t));

				if (++num_events == max_events) {
					mutex_exit(&evd_rp->evd_lock);
					goto maxevent_reached;
				}
			}
		}

		if ((evd_rp->evd_flags & DAT_EVD_CONNECTION_FLAG) &&
		    (evd_rp->evd_conn_events.eel_num_elements > 0)) {
			/* dequeue events from evd_connection_events list */
			while ((head = daplka_evd_event_dequeue
			    (&evd_rp->evd_conn_events))) {
				/*
				 * populate the evp array -
				 *
				 */
				if (head->ee_cmev.ec_cm_is_passive) {
					evp[num_events].ibe_ev_family =
					    DAPL_PASSIVE_CONNECTION_EVENTS;
				} else {
					evp[num_events].ibe_ev_family =
					    DAPL_ACTIVE_CONNECTION_EVENTS;
				}
				evp[num_events].ibe_ce.ibce_event =
				    head->ee_cmev.ec_cm_ev_type;
				evp[num_events].ibe_ce.ibce_cookie =
				    (uint64_t)head->ee_cmev.ec_cm_cookie;
				evp[num_events].ibe_ce.ibce_psep_cookie =
				    head->ee_cmev.ec_cm_psep_cookie;

				if (head->ee_cmev.ec_cm_ev_priv_data_len > 0) {
					pd = head->ee_cmev.ec_cm_ev_priv_data;
					n = head->
					    ee_cmev.ec_cm_ev_priv_data_len;
					bcopy(pd, (void *)evp[num_events].
					    ibe_ce.ibce_priv_data_ptr, n);
					evp[num_events].ibe_ce.
					    ibce_priv_data_size = n;
					kmem_free(pd, n);
				}

				kmem_free(head, sizeof (daplka_evd_event_t));

				if (++num_events == max_events) {
					mutex_exit(&evd_rp->evd_lock);
					goto maxevent_reached;
				}
			}
		}

		if ((evd_rp->evd_flags & DAT_EVD_ASYNC_FLAG) &&
		    (evd_rp->evd_async_events.eel_num_elements > 0)) {
			/* dequeue events from evd_async_events list */
			while (head = daplka_evd_event_dequeue(
			    &evd_rp->evd_async_events)) {
				/*
				 * populate the evp array
				 */
				evp[num_events].ibe_ev_family =
				    DAPL_ASYNC_EVENTS;
				evp[num_events].ibe_async.ibae_type =
				    head->ee_aev.ibae_type;
				evp[num_events].ibe_async.ibae_hca_guid =
				    head->ee_aev.ibae_hca_guid;
				evp[num_events].ibe_async.ibae_cookie =
				    head->ee_aev.ibae_cookie;
				evp[num_events].ibe_async.ibae_port =
				    head->ee_aev.ibae_port;

				kmem_free(head, sizeof (daplka_evd_event_t));

				if (++num_events == max_events) {
					break;
				}
			}
		}

		/*
		 * We have sufficient events for this call so no need to wait
		 */
		if ((threshold > 0) && (num_events >= threshold)) {
			mutex_exit(&evd_rp->evd_lock);
			break;
		}

		evd_rp->evd_waiters++;
		/*
		 * There are no new events and a timeout was specified.
		 * Note: for CQ events threshold is 0 but timeout is
		 * not necessarily 0.
		 */
		while ((evd_rp->evd_newevents == DAPLKA_EVD_NO_EVENTS) &&
		    timeout) {
			retval = DAPLKA_EVD_WAIT(&evd_rp->evd_cv,
			    &evd_rp->evd_lock, timeout);
			if (retval == 0) {
				retval = EINTR;
				break;
			} else if (retval == -1) {
				retval = ETIME;
				break;
			} else {
				retval = 0;
				continue;
			}
		}
		evd_rp->evd_waiters--;
		if (evd_rp->evd_newevents != DAPLKA_EVD_NO_EVENTS) {
			/*
			 * If we got woken up by the CQ handler due to events
			 * in the CQ. Need to go to userland to check for
			 * CQ events. Or if we were woken up due to S/W events
			 */

			/* check for userland events only */
			if (!(evd_rp->evd_newevents &
			    ~DAPLKA_EVD_ULAND_EVENTS)) {
				evd_rp->evd_newevents = DAPLKA_EVD_NO_EVENTS;
				mutex_exit(&evd_rp->evd_lock);
				break;
			}
			/*
			 * Clear newevents since we are going to loopback
			 * back and check for both CM and CQ events
			 */
			evd_rp->evd_newevents = DAPLKA_EVD_NO_EVENTS;
		} else { /* error */
			mutex_exit(&evd_rp->evd_lock);
			break;
		}
	}

maxevent_reached:
	args.evp_num_polled = num_events;

	/*
	 * At this point retval might have a value that we want to return
	 * back to the user. So the copyouts shouldn't tamper retval.
	 */
	if (args.evp_num_polled > 0) { /* copyout the events */
		rc = ddi_copyout(evp, args.evp_ep, args.evp_num_polled *
		    sizeof (dapl_ib_event_t), mode);
		if (rc != 0) { /* XXX: we are losing events here */
			DERR("event_poll: event array copyout error %d", rc);
			retval = EFAULT;
			goto cleanup;
		}
		rc = daplka_event_poll_copyout(&args, arg, mode);
		if (rc != 0) {  /* XXX: we are losing events here */
			DERR("event_poll: copyout error %d\n", rc);
			retval = EFAULT;
			goto cleanup;
		}
	}

cleanup:;
	if ((max_events > NUM_EVENTS_PER_POLL) && (evp_start != NULL)) {
		kmem_free(evp_start, evp_size);
	}

	if (evd_rp != NULL) {
		DAPLKA_RS_UNREF(evd_rp);
	}
	return (retval);
}

/* ARGSUSED */
static int
daplka_event_wakeup(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	dapl_event_wakeup_t	args;
	daplka_evd_resource_t	*evd_rp;
	int			retval;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_event_wakeup_t),
	    mode);
	if (retval != 0) {
		DERR("event_wakeup: copyin error %d\n", retval);
		return (EFAULT);
	}

	/* get evd resource */
	evd_rp = (daplka_evd_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_evd_htbl, args.evw_hkey);
	if (evd_rp == NULL) {
		DERR("event_wakeup: cannot find evd resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(evd_rp) == DAPL_TYPE_EVD);

	daplka_evd_wakeup(evd_rp, NULL, NULL);

	DAPLKA_RS_UNREF(evd_rp);

	return (retval);
}

/* ARGSUSED */
static int
daplka_evd_modify_cno(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	dapl_evd_modify_cno_t	args;
	daplka_evd_resource_t	*evd_rp;
	daplka_cno_resource_t	*cno_rp;
	daplka_cno_resource_t	*old_cno_rp;
	int			retval;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_evd_modify_cno_t),
	    mode);
	if (retval != 0) {
		DERR("evd_modify_cno: copyin error %d\n", retval);
		return (EFAULT);
	}

	/* get evd resource */
	evd_rp = (daplka_evd_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_evd_htbl, args.evmc_hkey);
	if (evd_rp == NULL) {
		DERR("evd_modify_cno: cannot find evd resource\n");
		retval = EINVAL;
		goto cleanup;
	}
	ASSERT(DAPLKA_RS_TYPE(evd_rp) == DAPL_TYPE_EVD);

	if (args.evmc_cno_hkey > 0) {
		/* get cno resource corresponding to the new CNO */
		cno_rp = (daplka_cno_resource_t *)
		    daplka_hash_lookup(&ia_rp->ia_cno_htbl,
		    args.evmc_cno_hkey);
		if (cno_rp == NULL) {
			DERR("evd_modify_cno: cannot find CNO resource\n");
			retval = EINVAL;
			goto cleanup;
		}
		ASSERT(DAPLKA_RS_TYPE(cno_rp) == DAPL_TYPE_CNO);
	} else {
		cno_rp = NULL;
	}

	mutex_enter(&evd_rp->evd_lock);
	old_cno_rp = evd_rp->evd_cno_res;
	evd_rp->evd_cno_res = cno_rp;
	mutex_exit(&evd_rp->evd_lock);

	/*
	 * drop the refcnt on the old CNO, the refcnt on the new CNO is
	 * retained since the evd holds a reference to it.
	 */
	if (old_cno_rp) {
		DAPLKA_RS_UNREF(old_cno_rp);
	}

cleanup:
	if (evd_rp) {
		DAPLKA_RS_UNREF(evd_rp);
	}

	return (retval);
}

/*
 * Frees the EVD and associated resources.
 * If there are other threads still using this EVD, the destruction
 * will defer until the EVD's refcnt drops to zero.
 */
/* ARGSUSED */
static int
daplka_evd_free(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_evd_resource_t	*evd_rp = NULL;
	daplka_async_evd_hkey_t	*curr;
	daplka_async_evd_hkey_t	*prev;
	dapl_evd_free_t		args;
	int			retval = 0;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_evd_free_t), mode);
	if (retval != 0) {
		DERR("evd_free: copyin error %d\n", retval);
		return (EFAULT);
	}
	retval = daplka_hash_remove(&ia_rp->ia_evd_htbl, args.evf_hkey,
	    (void **)&evd_rp);
	if (retval != 0 || evd_rp == NULL) {
		DERR("evd_free: cannot find evd resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(evd_rp) == DAPL_TYPE_EVD);

	/* If this is an async evd remove it from the IA's async evd list */
	if (evd_rp->evd_flags & DAT_EVD_ASYNC_FLAG) {
		mutex_enter(&ia_rp->ia_lock);
		curr = prev = ia_rp->ia_async_evd_hkeys;
		while (curr != NULL) {
			if (curr->aeh_evd_hkey == args.evf_hkey) {
				/* unlink curr from the list */
				if (curr == prev) {
					/*
					 * if first element in the list update
					 * the list head
					 */
					ia_rp->ia_async_evd_hkeys =
					    curr->aeh_next;
				} else {
					prev->aeh_next = curr->aeh_next;
				}
				break;
			}
			prev = curr;
			curr = curr->aeh_next;
		}
		mutex_exit(&ia_rp->ia_lock);
		/* free the curr entry */
		kmem_free(curr, sizeof (daplka_async_evd_hkey_t));
	}

	/* UNREF calls the actual free function when refcnt is zero */
	DAPLKA_RS_UNREF(evd_rp);
	return (0);
}

/*
 * destroys EVD resource.
 * called when refcnt drops to zero.
 */
static int
daplka_evd_destroy(daplka_resource_t *gen_rp)
{
	daplka_evd_resource_t	*evd_rp = (daplka_evd_resource_t *)gen_rp;
	ibt_status_t		status;
	daplka_evd_event_t	*evt;
	ibt_priv_data_len_t	len;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*evd_rp))
	D3("evd_destroy: entering, evd_rp 0x%p, rnum %d\n",
	    evd_rp, DAPLKA_RS_RNUM(evd_rp));
	/*
	 * free CQ
	 */
	if (evd_rp->evd_cq_hdl) {
		ibt_set_cq_handler(evd_rp->evd_cq_hdl, NULL, NULL);
		mutex_enter(&daplka_dev->daplka_mutex);
		ibt_set_cq_private(evd_rp->evd_cq_hdl, NULL);
		mutex_exit(&daplka_dev->daplka_mutex);

		status = daplka_ibt_free_cq(evd_rp, evd_rp->evd_cq_hdl);
		if (status != IBT_SUCCESS) {
			DERR("evd_destroy: ibt_free_cq returned %d\n", status);
		}
		evd_rp->evd_cq_hdl = NULL;
		D2("evd_destroy: cq freed, rnum %d\n", DAPLKA_RS_RNUM(evd_rp));
	}

	/*
	 * release reference on CNO
	 */
	if (evd_rp->evd_cno_res != NULL) {
		mutex_enter(&evd_rp->evd_cno_res->cno_lock);
		if (evd_rp->evd_cno_res->cno_evd_cookie ==
		    evd_rp->evd_cookie) {
			evd_rp->evd_cno_res->cno_evd_cookie = 0;
		}
		mutex_exit(&evd_rp->evd_cno_res->cno_lock);
		DAPLKA_RS_UNREF(evd_rp->evd_cno_res);
		evd_rp->evd_cno_res = NULL;
	}

	/*
	 * discard all remaining events
	 */
	mutex_enter(&evd_rp->evd_lock);
	while ((evt = daplka_evd_event_dequeue(&evd_rp->evd_cr_events))) {
		D2("evd_destroy: discarding CR event: %d\n",
		    evt->ee_cmev.ec_cm_ev_type);
		len = evt->ee_cmev.ec_cm_ev_priv_data_len;
		if (len > 0) {
			kmem_free(evt->ee_cmev.ec_cm_ev_priv_data, len);
			evt->ee_cmev.ec_cm_ev_priv_data = NULL;
			evt->ee_cmev.ec_cm_ev_priv_data_len = 0;
		}
		kmem_free(evt, sizeof (*evt));
	}
	ASSERT(evd_rp->evd_cr_events.eel_num_elements == 0);

	while ((evt = daplka_evd_event_dequeue(&evd_rp->evd_conn_events))) {
		D2("evd_destroy: discarding CONN event: %d\n",
		    evt->ee_cmev.ec_cm_ev_type);
		len = evt->ee_cmev.ec_cm_ev_priv_data_len;
		if (len > 0) {
			kmem_free(evt->ee_cmev.ec_cm_ev_priv_data, len);
			evt->ee_cmev.ec_cm_ev_priv_data = NULL;
			evt->ee_cmev.ec_cm_ev_priv_data_len = 0;
		}
		kmem_free(evt, sizeof (*evt));
	}
	ASSERT(evd_rp->evd_conn_events.eel_num_elements == 0);

	while ((evt = daplka_evd_event_dequeue(&evd_rp->evd_async_events))) {
		DERR("evd_destroy: discarding ASYNC event: %d\n",
		    evt->ee_aev.ibae_type);
		kmem_free(evt, sizeof (*evt));
	}
	ASSERT(evd_rp->evd_async_events.eel_num_elements == 0);
	mutex_exit(&evd_rp->evd_lock);

	mutex_destroy(&evd_rp->evd_lock);
	DAPLKA_RS_FINI(evd_rp);
	kmem_free(evd_rp, sizeof (daplka_evd_resource_t));
	D3("evd_destroy: exiting, evd_rp 0x%p\n", evd_rp);
	return (0);
}

static void
daplka_hash_evd_free(void *obj)
{
	daplka_evd_resource_t *evd_rp = (daplka_evd_resource_t *)obj;

	ASSERT(DAPLKA_RS_TYPE(evd_rp) == DAPL_TYPE_EVD);
	DAPLKA_RS_UNREF(evd_rp);
}

/*
 * this handler fires when new completions arrive.
 */
/* ARGSUSED */
static void
daplka_cq_handler(ibt_cq_hdl_t ibt_cq, void *arg)
{
	D3("cq_handler: fired setting evd_newevents\n");
	daplka_evd_wakeup((daplka_evd_resource_t *)arg, NULL, NULL);
}

/*
 * this routine wakes up a client from evd_wait. if evtq and evt
 * are non-null, the event evt will be enqueued prior to waking
 * up the client. if the evd is associated with a CNO and if there
 * are no waiters on the evd, the CNO will be notified.
 */
static void
daplka_evd_wakeup(daplka_evd_resource_t *evd_rp, daplka_evd_event_list_t *evtq,
	daplka_evd_event_t *evt)
{
	uint32_t waiters = 0;

	mutex_enter(&evd_rp->evd_lock);
	if (evtq != NULL && evt != NULL) {
		ASSERT(evtq == &evd_rp->evd_cr_events ||
		    evtq == &evd_rp->evd_conn_events ||
		    evtq == &evd_rp->evd_async_events);
		daplka_evd_event_enqueue(evtq, evt);
		ASSERT((evtq->eel_event_type == DAPLKA_EVD_CM_EVENTS) ||
		    (evtq->eel_event_type == DAPLKA_EVD_ASYNC_EVENTS));
		evd_rp->evd_newevents |= evtq->eel_event_type;
	} else {
		evd_rp->evd_newevents |= DAPLKA_EVD_ULAND_EVENTS;
	}
	waiters = evd_rp->evd_waiters;
	cv_broadcast(&evd_rp->evd_cv);
	mutex_exit(&evd_rp->evd_lock);

	/*
	 * only wakeup the CNO if there are no waiters on this evd.
	 */
	if (evd_rp->evd_cno_res != NULL && waiters == 0) {
		mutex_enter(&evd_rp->evd_cno_res->cno_lock);
		evd_rp->evd_cno_res->cno_evd_cookie = evd_rp->evd_cookie;
		cv_broadcast(&evd_rp->evd_cno_res->cno_cv);
		mutex_exit(&evd_rp->evd_cno_res->cno_lock);
	}
}

/*
 * daplka_evd_event_enqueue adds elem to the end of the event list
 * The caller is expected to acquire appropriate locks before
 * calling enqueue
 */
static void
daplka_evd_event_enqueue(daplka_evd_event_list_t *evlist,
    daplka_evd_event_t *elem)
{
	if (evlist->eel_tail) {
		evlist->eel_tail->ee_next = elem;
		evlist->eel_tail = elem;
	} else {
		/* list is empty */
		ASSERT(evlist->eel_head == NULL);
		evlist->eel_head = elem;
		evlist->eel_tail = elem;
	}
	evlist->eel_num_elements++;
}

/*
 * daplka_evd_event_dequeue removes and returns the first element of event
 * list. NULL is returned if the list is empty. The caller is expected to
 * acquire appropriate locks before calling enqueue.
 */
static daplka_evd_event_t *
daplka_evd_event_dequeue(daplka_evd_event_list_t *evlist)
{
	daplka_evd_event_t *head;

	head = evlist->eel_head;
	if (head == NULL) {
		return (NULL);
	}

	evlist->eel_head = head->ee_next;
	evlist->eel_num_elements--;
	/* if it was the last element update the tail pointer too */
	if (evlist->eel_head == NULL) {
		ASSERT(evlist->eel_num_elements == 0);
		evlist->eel_tail = NULL;
	}
	return (head);
}

/*
 * A CNO allows the client to wait for notifications from multiple EVDs.
 * To use a CNO, the client needs to follow the procedure below:
 * 1. allocate a CNO. this returns a cno_hkey that identifies the CNO.
 * 2. create one or more EVDs using the returned cno_hkey.
 * 3. call cno_wait. when one of the associated EVDs get notified, the
 *    CNO will also get notified. cno_wait will then return with a
 *    evd_cookie identifying the EVD that triggered the event.
 *
 * A note about cno_wait:
 * -unlike a EVD, a CNO does not maintain a queue of notifications. For
 *  example, suppose multiple EVDs triggered a CNO before the client calls
 *  cno_wait; when the client calls cno_wait, it will return with the
 *  evd_cookie that identifies the *last* EVD that triggered the CNO. It
 *  is the responsibility of the client, upon returning from cno_wait, to
 *  check on all EVDs that can potentially trigger the CNO. the returned
 *  evd_cookie is only meant to be a hint. there is no guarantee that the
 *  EVD identified by the evd_cookie still contains an event or still
 *  exists by the time cno_wait returns.
 */

/*
 * allocates a CNO.
 * the returned cno_hkey may subsequently be used in evd_create.
 */
/* ARGSUSED */
static int
daplka_cno_alloc(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	dapl_cno_alloc_t	args;
	daplka_cno_resource_t	*cno_rp = NULL;
	uint64_t		cno_hkey = 0;
	boolean_t		inserted = B_FALSE;
	int			retval = 0;

	cno_rp = kmem_zalloc(sizeof (*cno_rp), daplka_km_flags);
	if (cno_rp == NULL) {
		DERR("cno_alloc: cannot allocate cno resource\n");
		return (ENOMEM);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*cno_rp))
	DAPLKA_RS_INIT(cno_rp, DAPL_TYPE_CNO,
	    DAPLKA_RS_RNUM(ia_rp), daplka_cno_destroy);

	mutex_init(&cno_rp->cno_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&cno_rp->cno_cv, NULL, CV_DRIVER, NULL);
	cno_rp->cno_evd_cookie = 0;

	/* insert into cno hash table */
	retval = daplka_hash_insert(&ia_rp->ia_cno_htbl,
	    &cno_hkey, (void *)cno_rp);
	if (retval != 0) {
		DERR("cno_alloc: cannot insert cno resource\n");
		goto cleanup;
	}
	inserted = B_TRUE;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*cno_rp))

	/* return hkey to library */
	args.cno_hkey = cno_hkey;

	retval = ddi_copyout(&args, (void *)arg, sizeof (dapl_cno_alloc_t),
	    mode);
	if (retval != 0) {
		DERR("cno_alloc: copyout error %d\n", retval);
		retval = EFAULT;
		goto cleanup;
	}
	return (0);

cleanup:;
	if (inserted) {
		daplka_cno_resource_t *free_rp = NULL;

		(void) daplka_hash_remove(&ia_rp->ia_cno_htbl, cno_hkey,
		    (void **)&free_rp);
		if (free_rp != cno_rp) {
			DERR("cno_alloc: cannot remove cno\n");
			/*
			 * we can only get here if another thread
			 * has completed the cleanup in cno_free
			 */
			return (retval);
		}
	}
	DAPLKA_RS_UNREF(cno_rp);
	return (retval);
}

/*
 * destroys a CNO.
 * this gets called when a CNO resource's refcnt drops to zero.
 */
static int
daplka_cno_destroy(daplka_resource_t *gen_rp)
{
	daplka_cno_resource_t *cno_rp = (daplka_cno_resource_t *)gen_rp;

	ASSERT(DAPLKA_RS_REFCNT(cno_rp) == 0);
	D2("cno_destroy: entering, cno_rp %p, rnum %d\n",
	    cno_rp, DAPLKA_RS_RNUM(cno_rp));

	ASSERT(DAPLKA_RS_TYPE(cno_rp) == DAPL_TYPE_CNO);
	cv_destroy(&cno_rp->cno_cv);
	mutex_destroy(&cno_rp->cno_lock);

	DAPLKA_RS_FINI(cno_rp);
	kmem_free(cno_rp, sizeof (daplka_cno_resource_t));
	D2("cno_destroy: exiting, cno_rp %p\n", cno_rp);
	return (0);
}

static void
daplka_hash_cno_free(void *obj)
{
	daplka_cno_resource_t *cno_rp = (daplka_cno_resource_t *)obj;

	ASSERT(DAPLKA_RS_TYPE(cno_rp) == DAPL_TYPE_CNO);
	DAPLKA_RS_UNREF(cno_rp);
}

/*
 * removes the CNO from the cno hash table and frees the CNO
 * if there are no references to it. if there are references to
 * it, the CNO will be destroyed when the last of the references
 * is released. once the CNO is removed from the cno hash table,
 * the client will no longer be able to call cno_wait on the CNO.
 */
/* ARGSUSED */
static int
daplka_cno_free(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_cno_resource_t	*cno_rp = NULL;
	dapl_cno_free_t		args;
	int			retval = 0;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_cno_free_t), mode);
	if (retval != 0) {
		DERR("cno_free: copyin error %d\n", retval);
		return (EINVAL);
	}

	retval = daplka_hash_remove(&ia_rp->ia_cno_htbl,
	    args.cnf_hkey, (void **)&cno_rp);
	if (retval != 0 || cno_rp == NULL) {
		DERR("cno_free: cannot find cno resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(cno_rp) == DAPL_TYPE_CNO);

	/* UNREF calls the actual free function when refcnt is zero */
	DAPLKA_RS_UNREF(cno_rp);
	return (0);
}

/*
 * wait for a notification from one of the associated EVDs.
 */
/* ARGSUSED */
static int
daplka_cno_wait(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_cno_resource_t	*cno_rp = NULL;
	dapl_cno_wait_t		args;
	int			retval = 0;
	uint64_t		evd_cookie = 0;
	clock_t			timeout, curr_time;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_cno_wait_t), mode);
	if (retval != 0) {
		DERR("cno_wait: copyin error %d\n", retval);
		return (EINVAL);
	}
	/* get cno resource */
	cno_rp = (daplka_cno_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_cno_htbl, args.cnw_hkey);
	if (cno_rp == NULL) {
		DERR("cno_wait: cannot find cno resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(cno_rp) == DAPL_TYPE_CNO);

	curr_time = ddi_get_lbolt();
	timeout = curr_time + drv_usectohz(args.cnw_timeout);

	/*
	 * use the max value if we wrapped around
	 */
	if (args.cnw_timeout > 0 && timeout <= curr_time) {
		/*
		 * clock_t (size long) changes between 32 and 64-bit kernels
		 */
		timeout = LONG_MAX >> 4;
	}
	mutex_enter(&cno_rp->cno_lock);
	while (cno_rp->cno_evd_cookie == 0) {
		int rval = 0;

		rval = cv_timedwait_sig(&cno_rp->cno_cv,
		    &cno_rp->cno_lock, timeout);
		if (rval == 0) {
			DERR("cno_wait: interrupted\n");
			mutex_exit(&cno_rp->cno_lock);
			retval = EINTR;
			goto cleanup;
		} else if (rval == -1) {
			DERR("cno_wait: timed out\n");
			mutex_exit(&cno_rp->cno_lock);
			retval = ETIME;
			goto cleanup;
		}
	}
	evd_cookie = cno_rp->cno_evd_cookie;
	cno_rp->cno_evd_cookie = 0;
	mutex_exit(&cno_rp->cno_lock);

	ASSERT(evd_cookie != 0);
	D2("cno_wait: returning evd_cookie 0x%p\n",
	    (void *)(uintptr_t)evd_cookie);
	args.cnw_evd_cookie = evd_cookie;
	retval = ddi_copyout((void *)&args, (void *)arg,
	    sizeof (dapl_cno_wait_t), mode);
	if (retval != 0) {
		DERR("cno_wait: copyout error %d\n", retval);
		retval = EFAULT;
		goto cleanup;
	}

cleanup:;
	if (cno_rp != NULL) {
		DAPLKA_RS_UNREF(cno_rp);
	}
	return (retval);
}

/*
 * this function is called by the client when it decides to
 * accept a connection request. a connection request is generated
 * when the active side generates REQ MAD to a service point on
 * the destination node. this causes the CM service handler
 * (daplka_cm_service_req) on the passive side to be callee. This
 * handler will then enqueue this connection request to the backlog
 * array of the service point. A connection event containing the
 * backlog array index and connection request private data is passed
 * to the client's service point EVD (sp_evd_res). once the event
 * is passed up to the userland, the client may examine the request
 * to decide whether to call daplka_cr_accept or dapka_cr_reject.
 */
/* ARGSUSED */
static int
daplka_cr_accept(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_ep_resource_t		*ep_rp = NULL;
	daplka_sp_resource_t		*sp_rp = NULL;
	dapl_cr_accept_t		args;
	daplka_sp_conn_pend_t		*conn;
	ibt_cm_proceed_reply_t		proc_reply;
	ibt_status_t			status;
	uint16_t			bkl_index;
	uint32_t			old_state, new_state;
	int				retval = 0;
	void				*priv_data = NULL, *sid;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_cr_accept_t),
	    mode);
	if (retval != 0) {
		DERR("cr_accept: copyin error %d\n", retval);
		return (EFAULT);
	}
	if (args.cra_priv_sz > DAPL_MAX_PRIVATE_DATA_SIZE) {
		DERR("cr_accept: private data len (%d) exceeded "
		    "max size %d\n", args.cra_priv_sz,
		    DAPL_MAX_PRIVATE_DATA_SIZE);
		return (EINVAL);
	}
	priv_data = (args.cra_priv_sz > 0) ? (void *)args.cra_priv : NULL;

	D2("cr_accept: priv(0x%p) priv_len(%u) psep(0x%llx)\n", priv_data,
	    args.cra_priv_sz, (longlong_t)args.cra_bkl_cookie);

	/* get sp resource */
	sp_rp = (daplka_sp_resource_t *)daplka_hash_lookup(&ia_rp->ia_sp_htbl,
	    args.cra_sp_hkey);
	if (sp_rp == NULL) {
		DERR("cr_accept: cannot find sp resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(sp_rp) == DAPL_TYPE_SP);

	/* get ep resource */
	ep_rp = (daplka_ep_resource_t *)daplka_hash_lookup(&ia_rp->ia_ep_htbl,
	    args.cra_ep_hkey);
	if (ep_rp == NULL) {
		DERR("cr_accept: cannot find ep resource\n");
		retval = EINVAL;
		goto cleanup;
	}
	ASSERT(DAPLKA_RS_TYPE(ep_rp) == DAPL_TYPE_EP);

	/*
	 * accept is only allowed if ep_state is CLOSED.
	 * note that after this point, the ep_state is frozen
	 * (i.e. TRANSITIONING) until we transition ep_state
	 * to ACCEPTING or back to CLOSED if we get an error.
	 */
	new_state = old_state = daplka_ep_get_state(ep_rp);
	if (old_state != DAPLKA_EP_STATE_CLOSED) {
		DERR("cr_accept: invalid ep state %d\n", old_state);
		retval = EINVAL;
		goto cleanup;
	}

	mutex_enter(&sp_rp->sp_lock);
	bkl_index = DAPLKA_GET_PSEP_INDEX(args.cra_bkl_cookie);
	/*
	 * make sure the backlog index is not bogus.
	 */
	if (bkl_index >= sp_rp->sp_backlog_size) {
		DERR("cr_accept: invalid backlog index 0x%llx %d\n",
		    (longlong_t)args.cra_bkl_cookie, bkl_index);
		mutex_exit(&sp_rp->sp_lock);
		retval = EINVAL;
		goto cleanup;
	}
	/*
	 * make sure the backlog index indeed refers
	 * to a pending connection.
	 */
	conn = &sp_rp->sp_backlog[bkl_index];
	if (conn->spcp_state != DAPLKA_SPCP_PENDING) {
		DERR("cr_accept: invalid conn state %d\n",
		    conn->spcp_state);
		mutex_exit(&sp_rp->sp_lock);
		retval = EINVAL;
		goto cleanup;
	}
	if (conn->spcp_sid == NULL) {
		DERR("cr_accept: sid == NULL\n");
		mutex_exit(&sp_rp->sp_lock);
		retval = EINVAL;
		goto cleanup;
	}
	if (ep_rp->ep_chan_hdl == NULL) {
		/*
		 * a ep_rp with a NULL chan_hdl is impossible.
		 */
		DERR("cr_accept: ep_chan_hdl == NULL\n");
		mutex_exit(&sp_rp->sp_lock);
		ASSERT(B_FALSE);
		retval = EINVAL;
		goto cleanup;
	}
	proc_reply.rep.cm_channel = ep_rp->ep_chan_hdl;
	proc_reply.rep.cm_rdma_ra_out = conn->spcp_rdma_ra_out;
	proc_reply.rep.cm_rdma_ra_in = conn->spcp_rdma_ra_in;
	proc_reply.rep.cm_rnr_retry_cnt = IBT_RNR_INFINITE_RETRY;
	sid = conn->spcp_sid;

	/*
	 * this clears our slot in the backlog array.
	 * this slot may now be used by other pending connections.
	 */
	conn->spcp_sid = NULL;
	conn->spcp_state = DAPLKA_SPCP_INIT;
	conn->spcp_req_len = 0;
	mutex_exit(&sp_rp->sp_lock);

	/*
	 * Set the unique cookie corresponding to the CR to this EP
	 * so that is can be used in passive side CM callbacks
	 */
	ep_rp->ep_psep_cookie = args.cra_bkl_cookie;

	status = ibt_cm_proceed(IBT_CM_EVENT_REQ_RCV, sid, IBT_CM_ACCEPT,
	    &proc_reply, priv_data, (ibt_priv_data_len_t)args.cra_priv_sz);

	if (status != IBT_SUCCESS) {
		DERR("cr_accept: ibt_cm_proceed returned %d\n", status);
		*rvalp = (int)status;
		retval = 0;
	}
	/*
	 * note that the CM handler may actually be called at this
	 * point. but since ep_state is still in TRANSITIONING, the
	 * handler will wait until we transition to ACCEPTING. this
	 * prevents the case where we set ep_state to ACCEPTING after
	 * daplka_service_conn_est sets ep_state to CONNECTED.
	 */
	new_state = DAPLKA_EP_STATE_ACCEPTING;

cleanup:;
	if (sp_rp != NULL) {
		DAPLKA_RS_UNREF(sp_rp);
	}
	if (ep_rp != NULL) {
		daplka_ep_set_state(ep_rp, old_state, new_state);
		DAPLKA_RS_UNREF(ep_rp);
	}
	return (retval);
}

/*
 * this function is called by the client to reject a
 * connection request.
 */
/* ARGSUSED */
static int
daplka_cr_reject(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	dapl_cr_reject_t	args;
	daplka_sp_resource_t	*sp_rp = NULL;
	daplka_sp_conn_pend_t	*conn;
	ibt_cm_proceed_reply_t	proc_reply;
	ibt_cm_status_t		proc_status;
	ibt_status_t		status;
	uint16_t		bkl_index;
	int			retval = 0;
	void			*sid;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_cr_reject_t),
	    mode);
	if (retval != 0) {
		DERR("cr_reject: copyin error %d\n", retval);
		return (EFAULT);
	}
	/* get sp resource */
	sp_rp = (daplka_sp_resource_t *)daplka_hash_lookup(&ia_rp->ia_sp_htbl,
	    args.crr_sp_hkey);
	if (sp_rp == NULL) {
		DERR("cr_reject: cannot find sp resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(sp_rp) == DAPL_TYPE_SP);

	D2("cr_reject: psep(0x%llx)\n", (longlong_t)args.crr_bkl_cookie);

	mutex_enter(&sp_rp->sp_lock);
	bkl_index = DAPLKA_GET_PSEP_INDEX(args.crr_bkl_cookie);
	/*
	 * make sure the backlog index is not bogus.
	 */
	if (bkl_index >= sp_rp->sp_backlog_size) {
		DERR("cr_reject: invalid backlog index 0x%llx %d\n",
		    (longlong_t)args.crr_bkl_cookie, bkl_index);
		mutex_exit(&sp_rp->sp_lock);
		retval = EINVAL;
		goto cleanup;
	}
	/*
	 * make sure the backlog index indeed refers
	 * to a pending connection.
	 */
	conn = &sp_rp->sp_backlog[bkl_index];
	if (conn->spcp_state != DAPLKA_SPCP_PENDING) {
		DERR("cr_reject: invalid conn state %d\n",
		    conn->spcp_state);
		mutex_exit(&sp_rp->sp_lock);
		retval = EINVAL;
		goto cleanup;
	}
	if (conn->spcp_sid == NULL) {
		DERR("cr_reject: sid == NULL\n");
		mutex_exit(&sp_rp->sp_lock);
		retval = EINVAL;
		goto cleanup;
	}
	bzero(&proc_reply, sizeof (proc_reply));
	sid = conn->spcp_sid;

	/*
	 * this clears our slot in the backlog array.
	 * this slot may now be used by other pending connections.
	 */
	conn->spcp_sid = NULL;
	conn->spcp_state = DAPLKA_SPCP_INIT;
	conn->spcp_req_len = 0;

	switch (args.crr_reason) {
	case DAPL_IB_CM_REJ_REASON_CONSUMER_REJ:
		/* results in IBT_CM_CONSUMER as the reason for reject */
		proc_status = IBT_CM_REJECT;
		break;
	case DAPL_IB_CME_LOCAL_FAILURE:
		/*FALLTHRU*/
	case DAPL_IB_CME_DESTINATION_UNREACHABLE:
		/* results in IBT_CM_NO_RESC as the reason for reject */
		proc_status = IBT_CM_NO_RESOURCE;
		break;
	default:
		/* unexpect reason code */
		ASSERT(!"unexpected reject reason code");
		proc_status = IBT_CM_NO_RESOURCE;
		break;
	}

	mutex_exit(&sp_rp->sp_lock);

	status = ibt_cm_proceed(IBT_CM_EVENT_REQ_RCV, sid, proc_status,
	    &proc_reply, NULL, 0);

	if (status != IBT_SUCCESS) {
		DERR("cr_reject: ibt_cm_proceed returned %d\n", status);
		*rvalp = (int)status;
		retval = 0;
	}

cleanup:;
	if (sp_rp != NULL) {
		DAPLKA_RS_UNREF(sp_rp);
	}
	return (retval);
}


/*
 * daplka_sp_match is used by daplka_hash_walk for finding SPs
 */
typedef struct daplka_sp_match_s {
	uint64_t		spm_conn_qual;
	daplka_sp_resource_t	*spm_sp_rp;
} daplka_sp_match_t;
_NOTE(SCHEME_PROTECTS_DATA("daplka", daplka_sp_match_s::spm_sp_rp))

static int
daplka_sp_match(void *objp, void *arg)
{
	daplka_sp_resource_t	*sp_rp = (daplka_sp_resource_t *)objp;

	ASSERT(DAPLKA_RS_TYPE(sp_rp) == DAPL_TYPE_SP);
	if (sp_rp->sp_conn_qual ==
	    ((daplka_sp_match_t *)arg)->spm_conn_qual) {
		((daplka_sp_match_t *)arg)->spm_sp_rp = sp_rp;
		D2("daplka_sp_match: found sp, conn_qual %016llu\n",
		    (longlong_t)((daplka_sp_match_t *)arg)->spm_conn_qual);
		DAPLKA_RS_REF(sp_rp);
		return (1);
	}
	return (0);
}

/*
 * cr_handoff allows the client to handoff a connection request from
 * one service point to another.
 */
/* ARGSUSED */
static int
daplka_cr_handoff(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	dapl_cr_handoff_t		args;
	daplka_sp_resource_t		*sp_rp = NULL, *new_sp_rp = NULL;
	daplka_sp_conn_pend_t		*conn;
	daplka_sp_match_t		sp_match;
	ibt_cm_event_t			fake_event;
	ibt_cm_status_t			cm_status;
	ibt_status_t			status;
	uint16_t			bkl_index;
	void				*sid, *priv = NULL;
	int				retval = 0, priv_len = 0;

	D3("cr_handoff: entering\n");
	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_cr_handoff_t),
	    mode);
	if (retval != 0) {
		DERR("cr_handoff: copyin error %d\n", retval);
		return (EFAULT);
	}
	/* get sp resource */
	sp_rp = (daplka_sp_resource_t *)daplka_hash_lookup(&ia_rp->ia_sp_htbl,
	    args.crh_sp_hkey);
	if (sp_rp == NULL) {
		DERR("cr_handoff: cannot find sp resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(sp_rp) == DAPL_TYPE_SP);

	/*
	 * find the destination service point.
	 */
	sp_match.spm_conn_qual = args.crh_conn_qual;
	sp_match.spm_sp_rp = NULL;
	daplka_hash_walk(&daplka_global_sp_htbl, daplka_sp_match,
	    (void *)&sp_match, RW_READER);

	/*
	 * return if we cannot find the service point
	 */
	if (sp_match.spm_sp_rp == NULL) {
		DERR("cr_handoff: new sp not found, conn qual = %llu\n",
		    (longlong_t)args.crh_conn_qual);
		retval = EINVAL;
		goto cleanup;
	}
	new_sp_rp = sp_match.spm_sp_rp;

	/*
	 * the spec does not discuss the security implications of this
	 * function. to be safe, we currently only allow processes
	 * owned by the same user to handoff connection requests
	 * to each other.
	 */
	if (crgetruid(cred) != new_sp_rp->sp_ruid) {
		DERR("cr_handoff: permission denied\n");
		retval = EPERM;
		goto cleanup;
	}

	D2("cr_handoff: psep(0x%llx)\n", (longlong_t)args.crh_bkl_cookie);

	mutex_enter(&sp_rp->sp_lock);
	bkl_index = DAPLKA_GET_PSEP_INDEX(args.crh_bkl_cookie);
	/*
	 * make sure the backlog index is not bogus.
	 */
	if (bkl_index >= sp_rp->sp_backlog_size) {
		DERR("cr_handoff: invalid backlog index 0x%llx %d\n",
		    (longlong_t)args.crh_bkl_cookie, bkl_index);
		mutex_exit(&sp_rp->sp_lock);
		retval = EINVAL;
		goto cleanup;
	}
	/*
	 * make sure the backlog index indeed refers
	 * to a pending connection.
	 */
	conn = &sp_rp->sp_backlog[bkl_index];
	if (conn->spcp_state != DAPLKA_SPCP_PENDING) {
		DERR("cr_handoff: invalid conn state %d\n",
		    conn->spcp_state);
		mutex_exit(&sp_rp->sp_lock);
		retval = EINVAL;
		goto cleanup;
	}
	if (conn->spcp_sid == NULL) {
		DERR("cr_handoff: sid == NULL\n");
		mutex_exit(&sp_rp->sp_lock);
		retval = EINVAL;
		goto cleanup;
	}
	sid = conn->spcp_sid;
	priv = NULL;
	priv_len = conn->spcp_req_len;
	if (priv_len > 0) {
		priv = kmem_zalloc(priv_len, daplka_km_flags);
		if (priv == NULL) {
			mutex_exit(&sp_rp->sp_lock);
			retval = ENOMEM;
			goto cleanup;
		}
		bcopy(conn->spcp_req_data, priv, priv_len);
	}
	/*
	 * this clears our slot in the backlog array.
	 * this slot may now be used by other pending connections.
	 */
	conn->spcp_sid = NULL;
	conn->spcp_state = DAPLKA_SPCP_INIT;
	conn->spcp_req_len = 0;
	mutex_exit(&sp_rp->sp_lock);

	/* fill fake_event and call service_req handler */
	bzero(&fake_event, sizeof (fake_event));
	fake_event.cm_type = IBT_CM_EVENT_REQ_RCV;
	fake_event.cm_session_id = sid;
	fake_event.cm_priv_data_len = priv_len;
	fake_event.cm_priv_data = priv;

	cm_status = daplka_cm_service_req(new_sp_rp,
	    &fake_event, NULL, priv, (ibt_priv_data_len_t)priv_len);
	if (cm_status != IBT_CM_DEFER) {
		ibt_cm_proceed_reply_t	proc_reply;

		DERR("cr_handoff: service_req returned %d\n", cm_status);
		/*
		 * if for some reason cm_service_req failed, we
		 * reject the connection.
		 */
		bzero(&proc_reply, sizeof (proc_reply));

		status = ibt_cm_proceed(IBT_CM_EVENT_REQ_RCV, sid,
		    IBT_CM_NO_RESOURCE, &proc_reply, NULL, 0);
		if (status != IBT_SUCCESS) {
			DERR("cr_handoff: ibt_cm_proceed returned %d\n",
			    status);
		}
		*rvalp = (int)status;
		retval = 0;
	}

cleanup:;
	if (priv_len > 0 && priv != NULL) {
		kmem_free(priv, priv_len);
	}
	if (new_sp_rp != NULL) {
		DAPLKA_RS_UNREF(new_sp_rp);
	}
	if (sp_rp != NULL) {
		DAPLKA_RS_UNREF(sp_rp);
	}
	D3("cr_handoff: exiting\n");
	return (retval);
}

/*
 * returns a list of hca attributes
 */
/* ARGSUSED */
static int
daplka_ia_query(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	dapl_ia_query_t		args;
	int			retval;
	ibt_hca_attr_t		*hcap;

	hcap = &ia_rp->ia_hca->hca_attr;

	/*
	 * Take the ibt_hca_attr_t and stuff them into dapl_hca_attr_t
	 */
	args.hca_attr.dhca_vendor_id = hcap->hca_vendor_id;
	args.hca_attr.dhca_device_id = hcap->hca_device_id;
	args.hca_attr.dhca_version_id = hcap->hca_version_id;
	args.hca_attr.dhca_max_chans = hcap->hca_max_chans;
	args.hca_attr.dhca_max_chan_sz = hcap->hca_max_chan_sz;
	args.hca_attr.dhca_max_sgl = hcap->hca_max_sgl;
	args.hca_attr.dhca_max_cq = hcap->hca_max_cq;
	args.hca_attr.dhca_max_cq_sz = hcap->hca_max_cq_sz;
	args.hca_attr.dhca_max_memr = hcap->hca_max_memr;
	args.hca_attr.dhca_max_memr_len = hcap->hca_max_memr_len;
	args.hca_attr.dhca_max_mem_win = hcap->hca_max_mem_win;
	args.hca_attr.dhca_max_rdma_in_chan = hcap->hca_max_rdma_in_chan;
	args.hca_attr.dhca_max_rdma_out_chan = hcap->hca_max_rdma_out_chan;
	args.hca_attr.dhca_max_partitions  = hcap->hca_max_partitions;
	args.hca_attr.dhca_nports  = hcap->hca_nports;
	args.hca_attr.dhca_node_guid  = hcap->hca_node_guid;
	args.hca_attr.dhca_max_pd = hcap->hca_max_pd;
	args.hca_attr.dhca_max_srqs = hcap->hca_max_srqs;
	args.hca_attr.dhca_max_srqs_sz = hcap->hca_max_srqs_sz;
	args.hca_attr.dhca_max_srq_sgl = hcap->hca_max_srq_sgl;

	retval = ddi_copyout(&args, (void *)arg, sizeof (dapl_ia_query_t),
	    mode);
	if (retval != 0) {
		DERR("ia_query: copyout error %d\n", retval);
		return (EFAULT);
	}
	return (0);
}

/*
 * This routine is passed to hash walk in the daplka_pre_mr_cleanup_callback,
 * it frees the mw embedded in the mw resource object.
 */

/* ARGSUSED */
static int
daplka_mr_cb_freemw(void *objp, void *arg)
{
	daplka_mw_resource_t	*mw_rp = (daplka_mw_resource_t *)objp;
	ibt_mw_hdl_t		mw_hdl;
	ibt_status_t		status;

	D3("mr_cb_freemw: entering, mw_rp 0x%p\n", mw_rp);
	DAPLKA_RS_REF(mw_rp);

	mutex_enter(&mw_rp->mw_lock);
	mw_hdl = mw_rp->mw_hdl;
	/*
	 * we set mw_hdl to NULL so it won't get freed again
	 */
	mw_rp->mw_hdl = NULL;
	mutex_exit(&mw_rp->mw_lock);

	if (mw_hdl != NULL) {
		status = daplka_ibt_free_mw(mw_rp, mw_rp->mw_hca_hdl, mw_hdl);
		if (status != IBT_SUCCESS) {
			DERR("mr_cb_freemw: ibt_free_mw returned %d\n", status);
		}
		D3("mr_cb_freemw: mw freed\n");
	}

	DAPLKA_RS_UNREF(mw_rp);
	return (0);
}

/*
 * This routine is called from HCA driver's umem lock undo callback
 * when the memory associated with an MR is being unmapped. In this callback
 * we free all the MW associated with the IA and post an unaffiliated
 * async event to tell the app that there was a catastrophic event.
 * This allows the HCA to deregister the MR in its callback processing.
 */
static void
daplka_pre_mr_cleanup_callback(void *arg1, void *arg2 /*ARGSUSED*/)
{
	daplka_mr_resource_t	*mr_rp;
	daplka_ia_resource_t	*ia_rp;
#ifdef	_THROW_ASYNC_EVENT_FROM_MRUNLOCKCB
	ibt_async_event_t	event;
	ibt_hca_attr_t		*hca_attrp;
#endif
	minor_t			rnum;

	mr_rp = (daplka_mr_resource_t *)arg1;
	rnum = DAPLKA_RS_RNUM(mr_rp);
	daplka_shared_mr_free(mr_rp);

	ia_rp = (daplka_ia_resource_t *)daplka_resource_lookup(rnum);
	if (ia_rp == NULL) {
		DERR("daplka_mr_unlock_callback: resource not found, rnum %d\n",
		    rnum);
		return;
	}

	DERR("daplka_mr_unlock_callback: resource(%p) rnum(%d)\n", ia_rp, rnum);

	mutex_enter(&ia_rp->ia_lock);
	/*
	 * MW is being alloced OR MW freeze has already begun. In
	 * both these cases we wait for that to complete before
	 * continuing.
	 */
	while ((ia_rp->ia_state == DAPLKA_IA_MW_ALLOC_IN_PROGRESS) ||
	    (ia_rp->ia_state == DAPLKA_IA_MW_FREEZE_IN_PROGRESS)) {
		cv_wait(&ia_rp->ia_cv, &ia_rp->ia_lock);
	}

	switch (ia_rp->ia_state) {
	case DAPLKA_IA_INIT:
		ia_rp->ia_state = DAPLKA_IA_MW_FREEZE_IN_PROGRESS;
		mutex_exit(&ia_rp->ia_lock);
		break;
	case DAPLKA_IA_MW_FROZEN:
		/* the mw on this ia have been freed */
		D2("daplka_mr_unlock_callback: ia_state %d nothing to do\n",
		    ia_rp->ia_state);
		mutex_exit(&ia_rp->ia_lock);
		goto cleanup;
	default:
		ASSERT(!"daplka_mr_unlock_callback: IA state invalid");
		DERR("daplka_mr_unlock_callback: invalid ia_state %d\n",
		    ia_rp->ia_state);
		mutex_exit(&ia_rp->ia_lock);
		goto cleanup;
	}

	/*
	 * Walk the mw hash table and free the mws. Acquire a writer
	 * lock since we don't want anyone else traversing this tree
	 * while we are freeing the MW.
	 */
	daplka_hash_walk(&ia_rp->ia_mw_htbl, daplka_mr_cb_freemw, NULL,
	    RW_WRITER);

	mutex_enter(&ia_rp->ia_lock);
	ASSERT(ia_rp->ia_state == DAPLKA_IA_MW_FREEZE_IN_PROGRESS);
	ia_rp->ia_state = DAPLKA_IA_MW_FROZEN;
	cv_broadcast(&ia_rp->ia_cv);
	mutex_exit(&ia_rp->ia_lock);

	/*
	 * Currently commented out because Oracle skgxp is incapable
	 * of handling async events correctly.
	 */
#ifdef	_THROW_ASYNC_EVENT_FROM_MRUNLOCKCB
	/*
	 * Enqueue an unaffiliated async error event to indicate this
	 * IA has encountered a problem that caused the MW to freed up
	 */

	/* Create a fake event, only relevant field is the hca_guid */
	bzero(&event, sizeof (ibt_async_event_t));
	hca_attrp = &ia_rp->ia_hca->hca_attr;
	event.ev_hca_guid = hca_attrp->hca_node_guid;

	daplka_async_event_create(IBT_ERROR_LOCAL_CATASTROPHIC, &event, 0,
	    ia_rp);
#endif	/* _THROW_ASYNC_EVENT_FROM_MRUNLOCKCB */

cleanup:;
	D2("daplka_mr_unlock_callback: resource(%p) done\n", ia_rp);
	DAPLKA_RS_UNREF(ia_rp);
}

/*
 * registers a memory region.
 * memory locking will be done by the HCA driver.
 */
/* ARGSUSED */
static int
daplka_mr_register(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	boolean_t			inserted = B_FALSE;
	daplka_mr_resource_t		*mr_rp;
	daplka_pd_resource_t		*pd_rp;
	dapl_mr_register_t		args;
	ibt_mr_data_in_t		mr_cb_data_in;
	uint64_t			mr_hkey = 0;
	ibt_status_t			status;
	int				retval;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_mr_register_t),
	    mode);
	if (retval != 0) {
		DERR("mr_register: copyin error %d\n", retval);
		return (EINVAL);
	}
	mr_rp = kmem_zalloc(sizeof (daplka_mr_resource_t), daplka_km_flags);
	if (mr_rp == NULL) {
		DERR("mr_register: cannot allocate mr resource\n");
		return (ENOMEM);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr_rp))
	DAPLKA_RS_INIT(mr_rp, DAPL_TYPE_MR,
	    DAPLKA_RS_RNUM(ia_rp), daplka_mr_destroy);

	mutex_init(&mr_rp->mr_lock, NULL, MUTEX_DRIVER, NULL);
	mr_rp->mr_hca = ia_rp->ia_hca;
	mr_rp->mr_hca_hdl = ia_rp->ia_hca_hdl;
	mr_rp->mr_next = NULL;
	mr_rp->mr_shared_mr = NULL;

	/* get pd handle */
	pd_rp = (daplka_pd_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_pd_htbl, args.mr_pd_hkey);
	if (pd_rp == NULL) {
		DERR("mr_register: cannot find pd resource\n");
		retval = EINVAL;
		goto cleanup;
	}
	ASSERT(DAPLKA_RS_TYPE(pd_rp) == DAPL_TYPE_PD);
	mr_rp->mr_pd_res = pd_rp;

	mr_rp->mr_attr.mr_vaddr = args.mr_vaddr;
	mr_rp->mr_attr.mr_len = args.mr_len;
	mr_rp->mr_attr.mr_as = curproc->p_as;
	mr_rp->mr_attr.mr_flags = args.mr_flags | IBT_MR_NOSLEEP;

	D3("mr_register: mr_vaddr %p, mr_len %llu, mr_flags 0x%x\n",
	    (void *)(uintptr_t)mr_rp->mr_attr.mr_vaddr,
	    (longlong_t)mr_rp->mr_attr.mr_len,
	    mr_rp->mr_attr.mr_flags);

	status = daplka_ibt_register_mr(mr_rp, ia_rp->ia_hca_hdl,
	    mr_rp->mr_pd_res->pd_hdl, &mr_rp->mr_attr, &mr_rp->mr_hdl,
	    &mr_rp->mr_desc);

	if (status != IBT_SUCCESS) {
		DERR("mr_register: ibt_register_mr error %d\n", status);
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}

	mr_cb_data_in.mr_rev = IBT_MR_DATA_IN_IF_VERSION;
	mr_cb_data_in.mr_func = daplka_pre_mr_cleanup_callback;
	mr_cb_data_in.mr_arg1 = (void *)mr_rp;
	mr_cb_data_in.mr_arg2 = NULL;

	/* Pass the service driver mr cleanup handler to the hca driver */
	status = ibt_ci_data_in(ia_rp->ia_hca_hdl,
	    IBT_CI_NO_FLAGS, IBT_HDL_MR, (void *)mr_rp->mr_hdl,
	    &mr_cb_data_in, sizeof (mr_cb_data_in));

	if (status != IBT_SUCCESS) {
		DERR("mr_register: ibt_ci_data_in error(%d) ver(%d)",
		    status, mr_cb_data_in.mr_rev);
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}

	/* insert into mr hash table */
	retval = daplka_hash_insert(&ia_rp->ia_mr_htbl,
	    &mr_hkey, (void *)mr_rp);
	if (retval != 0) {
		DERR("mr_register: cannot insert mr resource into mr_htbl\n");
		goto cleanup;
	}
	inserted = B_TRUE;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*mr_rp))

	args.mr_lkey = mr_rp->mr_desc.md_lkey;
	args.mr_rkey = mr_rp->mr_desc.md_rkey;
	args.mr_hkey = mr_hkey;

	retval = ddi_copyout((void *)&args, (void *)arg,
	    sizeof (dapl_mr_register_t), mode);
	if (retval != 0) {
		DERR("mr_register: copyout error %d\n", retval);
		retval = EFAULT;
		goto cleanup;
	}
	return (0);

cleanup:;
	if (inserted) {
		daplka_mr_resource_t *free_rp = NULL;

		(void) daplka_hash_remove(&ia_rp->ia_mr_htbl, mr_hkey,
		    (void **)&free_rp);
		if (free_rp != mr_rp) {
			DERR("mr_register: cannot remove mr from hash table\n");
			/*
			 * we can only get here if another thread
			 * has completed the cleanup in mr_deregister
			 */
			return (retval);
		}
	}
	DAPLKA_RS_UNREF(mr_rp);
	return (retval);
}

/*
 * registers a shared memory region.
 * the client calls this function with the intention to share the memory
 * region with other clients. it is assumed that, prior to calling this
 * function, the client(s) are already sharing parts of their address
 * space using a mechanism such as SYSV shared memory. the first client
 * that calls this function will create and insert a daplka_shared_mr_t
 * object into the global daplka_shared_mr_tree. this shared mr object
 * will be identified by a unique 40-byte key and will maintain a list
 * of mr resources. every time this function gets called with the same
 * 40-byte key, a new mr resource (containing a new mr handle generated
 * by ibt_register_mr or ibt_register_shared_mr) is created and inserted
 * into this list. similarly, every time a shared mr gets deregistered
 * or invalidated by a callback, the mr resource gets removed from this
 * list. the shared mr object has a reference count. when it drops to
 * zero, the shared mr object will be removed from the global avl tree
 * and be freed.
 */
/* ARGSUSED */
static int
daplka_mr_register_shared(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	dapl_mr_register_shared_t	args;
	daplka_shared_mr_t		*smrp = NULL;
	daplka_shared_mr_t		tmp_smr;
	ibt_mr_data_in_t		mr_cb_data_in;
	avl_index_t			where;
	boolean_t			inserted = B_FALSE;
	daplka_mr_resource_t		*mr_rp = NULL;
	daplka_pd_resource_t		*pd_rp;
	uint64_t			mr_hkey = 0;
	ibt_status_t			status;
	int				retval;

	retval = ddi_copyin((void *)arg, &args,
	    sizeof (dapl_mr_register_shared_t), mode);
	if (retval != 0) {
		DERR("mr_register_shared: copyin error %d\n", retval);
		return (EINVAL);
	}

	mutex_enter(&daplka_shared_mr_lock);
	/*
	 * find smrp from the global avl tree.
	 * the 40-byte key is used as the lookup key.
	 */
	tmp_smr.smr_cookie = args.mrs_shm_cookie;
	smrp = (daplka_shared_mr_t *)
	    avl_find(&daplka_shared_mr_tree, &tmp_smr, &where);
	if (smrp != NULL) {
		D2("mr_register_shared: smrp 0x%p, found cookie:\n"
		    "0x%016llx%016llx%016llx%016llx%016llx\n", smrp,
		    (longlong_t)tmp_smr.smr_cookie.mc_uint_arr[4],
		    (longlong_t)tmp_smr.smr_cookie.mc_uint_arr[3],
		    (longlong_t)tmp_smr.smr_cookie.mc_uint_arr[2],
		    (longlong_t)tmp_smr.smr_cookie.mc_uint_arr[1],
		    (longlong_t)tmp_smr.smr_cookie.mc_uint_arr[0]);

		/*
		 * if the smrp exists, other threads could still be
		 * accessing it. we wait until they are done before
		 * we continue.
		 */
		smrp->smr_refcnt++;
		while (smrp->smr_state == DAPLKA_SMR_TRANSITIONING) {
			D2("mr_register_shared: smrp 0x%p, "
			    "waiting in transitioning state, refcnt %d\n",
			    smrp, smrp->smr_refcnt);
			cv_wait(&smrp->smr_cv, &daplka_shared_mr_lock);
		}
		ASSERT(smrp->smr_state == DAPLKA_SMR_READY);
		D2("mr_register_shared: smrp 0x%p, refcnt %d, ready\n",
		    smrp, smrp->smr_refcnt);

		/*
		 * we set smr_state to TRANSITIONING to temporarily
		 * prevent other threads from trying to access smrp.
		 */
		smrp->smr_state = DAPLKA_SMR_TRANSITIONING;
	} else {
		D2("mr_register_shared: cannot find cookie:\n"
		    "0x%016llx%016llx%016llx%016llx%016llx\n",
		    (longlong_t)tmp_smr.smr_cookie.mc_uint_arr[4],
		    (longlong_t)tmp_smr.smr_cookie.mc_uint_arr[3],
		    (longlong_t)tmp_smr.smr_cookie.mc_uint_arr[2],
		    (longlong_t)tmp_smr.smr_cookie.mc_uint_arr[1],
		    (longlong_t)tmp_smr.smr_cookie.mc_uint_arr[0]);

		/*
		 * if we cannot find smrp, we need to create and
		 * insert one into daplka_shared_mr_tree
		 */
		smrp = kmem_zalloc(sizeof (daplka_shared_mr_t),
		    daplka_km_flags);
		if (smrp == NULL) {
			retval = ENOMEM;
			mutex_exit(&daplka_shared_mr_lock);
			goto cleanup;
		}
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*smrp))
		smrp->smr_refcnt = 1;
		smrp->smr_cookie = args.mrs_shm_cookie;
		smrp->smr_state = DAPLKA_SMR_TRANSITIONING;
		smrp->smr_mr_list = NULL;
		cv_init(&smrp->smr_cv, NULL, CV_DRIVER, NULL);
		avl_insert(&daplka_shared_mr_tree, smrp, where);
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*smrp))
	}
	mutex_exit(&daplka_shared_mr_lock);

	mr_rp = kmem_zalloc(sizeof (daplka_mr_resource_t), daplka_km_flags);
	if (mr_rp == NULL) {
		DERR("mr_register_shared: cannot allocate mr resource\n");
		goto cleanup;
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr_rp))
	DAPLKA_RS_INIT(mr_rp, DAPL_TYPE_MR,
	    DAPLKA_RS_RNUM(ia_rp), daplka_mr_destroy);

	mutex_init(&mr_rp->mr_lock, NULL, MUTEX_DRIVER, NULL);
	mr_rp->mr_hca = ia_rp->ia_hca;
	mr_rp->mr_hca_hdl = ia_rp->ia_hca_hdl;
	mr_rp->mr_next = NULL;
	mr_rp->mr_shared_mr = NULL;

	/* get pd handle */
	pd_rp = (daplka_pd_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_pd_htbl, args.mrs_pd_hkey);
	if (pd_rp == NULL) {
		DERR("mr_register_shared: cannot find pd resource\n");
		retval = EINVAL;
		goto cleanup;
	}
	ASSERT(DAPLKA_RS_TYPE(pd_rp) == DAPL_TYPE_PD);
	mr_rp->mr_pd_res = pd_rp;

	mr_rp->mr_attr.mr_vaddr = args.mrs_vaddr;
	mr_rp->mr_attr.mr_len = args.mrs_len;
	mr_rp->mr_attr.mr_flags = args.mrs_flags | IBT_MR_NOSLEEP;
	mr_rp->mr_attr.mr_as = curproc->p_as;

	D2("mr_register_shared: mr_vaddr 0x%p, mr_len %llu, "
	    "mr_flags 0x%x, mr_as 0x%p, mr_exists %d, smrp 0x%p\n",
	    (void *)(uintptr_t)mr_rp->mr_attr.mr_vaddr,
	    (longlong_t)mr_rp->mr_attr.mr_len,
	    mr_rp->mr_attr.mr_flags, mr_rp->mr_attr.mr_as,
	    (int)(smrp->smr_mr_list != NULL), smrp);

	/*
	 * since we are in TRANSITIONING state, we are guaranteed
	 * that we have exclusive access to smr_mr_list.
	 */
	if (smrp->smr_mr_list != NULL) {
		ibt_smr_attr_t	mem_sattr;

		/*
		 * a non-null smr_mr_list indicates that someone
		 * else has already inserted an mr_resource into
		 * smr_mr_list. we use the mr_handle from the first
		 * element as an arg to ibt_register_shared_mr.
		 */
		mem_sattr.mr_vaddr = smrp->smr_mr_list->mr_desc.md_vaddr;
		mem_sattr.mr_flags = mr_rp->mr_attr.mr_flags;

		D2("mr_register_shared: mem_sattr vaddr 0x%p flags 0x%x\n",
		    (void *)(uintptr_t)mem_sattr.mr_vaddr, mem_sattr.mr_flags);
		status = daplka_ibt_register_shared_mr(mr_rp, ia_rp->ia_hca_hdl,
		    smrp->smr_mr_list->mr_hdl, mr_rp->mr_pd_res->pd_hdl,
		    &mem_sattr, &mr_rp->mr_hdl, &mr_rp->mr_desc);

		if (status != IBT_SUCCESS) {
			DERR("mr_register_shared: "
			    "ibt_register_shared_mr error %d\n", status);
			*rvalp = (int)status;
			retval = 0;
			goto cleanup;
		}
	} else {
		/*
		 * an mr does not exist yet. we need to create one
		 * using ibt_register_mr.
		 */
		status = daplka_ibt_register_mr(mr_rp, ia_rp->ia_hca_hdl,
		    mr_rp->mr_pd_res->pd_hdl, &mr_rp->mr_attr,
		    &mr_rp->mr_hdl, &mr_rp->mr_desc);

		if (status != IBT_SUCCESS) {
			DERR("mr_register_shared: "
			    "ibt_register_mr error %d\n", status);
			*rvalp = (int)status;
			retval = 0;
			goto cleanup;
		}
	}

	mr_cb_data_in.mr_rev = IBT_MR_DATA_IN_IF_VERSION;
	mr_cb_data_in.mr_func = daplka_pre_mr_cleanup_callback;
	mr_cb_data_in.mr_arg1 = (void *)mr_rp;
	mr_cb_data_in.mr_arg2 = NULL;

	/* Pass the service driver mr cleanup handler to the hca driver */
	status = ibt_ci_data_in(ia_rp->ia_hca_hdl,
	    IBT_CI_NO_FLAGS, IBT_HDL_MR, (void *)mr_rp->mr_hdl,
	    &mr_cb_data_in, sizeof (mr_cb_data_in));

	if (status != IBT_SUCCESS) {
		DERR("mr_register_shared: ibt_ci_data_in error(%d) ver(%d)",
		    status, mr_cb_data_in.mr_rev);
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}

	/*
	 * we bump reference of mr_rp and enqueue it onto smrp.
	 */
	DAPLKA_RS_REF(mr_rp);
	mr_rp->mr_next = smrp->smr_mr_list;
	smrp->smr_mr_list = mr_rp;
	mr_rp->mr_shared_mr = smrp;

	/* insert into mr hash table */
	retval = daplka_hash_insert(&ia_rp->ia_mr_htbl,
	    &mr_hkey, (void *)mr_rp);
	if (retval != 0) {
		DERR("mr_register_shared: cannot insert mr resource\n");
		goto cleanup;
	}
	inserted = B_TRUE;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*mr_rp))

	/*
	 * at this point, there are two references to our mr resource.
	 * one is kept in ia_mr_htbl. the other is kept in the list
	 * within this shared mr object (smrp). when we deregister this
	 * mr or when a callback invalidates this mr, the reference kept
	 * by this shared mr object will be removed.
	 */

	args.mrs_lkey = mr_rp->mr_desc.md_lkey;
	args.mrs_rkey = mr_rp->mr_desc.md_rkey;
	args.mrs_hkey = mr_hkey;

	retval = ddi_copyout((void *)&args, (void *)arg,
	    sizeof (dapl_mr_register_shared_t), mode);
	if (retval != 0) {
		DERR("mr_register_shared: copyout error %d\n", retval);
		retval = EFAULT;
		goto cleanup;
	}

	/*
	 * set the state to READY to allow others to continue
	 */
	mutex_enter(&daplka_shared_mr_lock);
	smrp->smr_state = DAPLKA_SMR_READY;
	cv_broadcast(&smrp->smr_cv);
	mutex_exit(&daplka_shared_mr_lock);
	return (0);

cleanup:;
	if (inserted) {
		daplka_mr_resource_t *free_rp = NULL;

		(void) daplka_hash_remove(&ia_rp->ia_mr_htbl, mr_hkey,
		    (void **)&free_rp);
		if (free_rp != mr_rp) {
			DERR("mr_register_shared: "
			    "cannot remove mr from hash table\n");
			/*
			 * we can only get here if another thread
			 * has completed the cleanup in mr_deregister
			 */
			return (retval);
		}
	}
	if (smrp != NULL) {
		mutex_enter(&daplka_shared_mr_lock);
		ASSERT(smrp->smr_refcnt > 0);
		smrp->smr_refcnt--;

		if (smrp->smr_refcnt == 0) {
			DERR("mr_register_shared: freeing smrp 0x%p\n", smrp);
			avl_remove(&daplka_shared_mr_tree, smrp);
			_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*smrp))
			if (smrp->smr_mr_list != NULL) {
				/*
				 * the refcnt is 0. if there is anything
				 * left on the list, it must be ours.
				 */
				_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr_rp))
				ASSERT(smrp->smr_mr_list == mr_rp);
				DAPLKA_RS_UNREF(mr_rp);
				smrp->smr_mr_list = NULL;
				ASSERT(mr_rp->mr_shared_mr == smrp);
				mr_rp->mr_shared_mr = NULL;
				ASSERT(mr_rp->mr_next == NULL);
			}
			smrp->smr_state = DAPLKA_SMR_FREED;
			cv_destroy(&smrp->smr_cv);
			kmem_free(smrp, sizeof (daplka_shared_mr_t));
		} else {
			DERR("mr_register_shared: resetting smr_state "
			    "smrp 0x%p, %d waiters remain\n", smrp,
			    smrp->smr_refcnt);
			ASSERT(smrp->smr_state == DAPLKA_SMR_TRANSITIONING);
			if (smrp->smr_mr_list != NULL && mr_rp != NULL) {
				daplka_mr_resource_t	**mpp;

				/*
				 * search and remove mr_rp from smr_mr_list
				 */
				_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr_rp))
				mpp = &smrp->smr_mr_list;
				while (*mpp != NULL) {
					if (*mpp == mr_rp) {
						*mpp = (*mpp)->mr_next;
						DAPLKA_RS_UNREF(mr_rp);
						ASSERT(mr_rp->mr_shared_mr ==
						    smrp);
						mr_rp->mr_shared_mr = NULL;
						mr_rp->mr_next = NULL;
						break;
					}
					mpp = &(*mpp)->mr_next;
				}
			}
			/*
			 * note that smr_state == READY does not necessarily
			 * mean that smr_mr_list is non empty. for this case,
			 * we are doing cleanup because of a failure. we set
			 * the state to READY to allow other threads to
			 * continue.
			 */
			smrp->smr_state = DAPLKA_SMR_READY;
			cv_broadcast(&smrp->smr_cv);
		}
		mutex_exit(&daplka_shared_mr_lock);
	}
	if (mr_rp != NULL) {
		DAPLKA_RS_UNREF(mr_rp);
	}
	return (retval);
}

/*
 * registers a memory region using the attributes of an
 * existing region.
 */
/* ARGSUSED */
static int
daplka_mr_register_lmr(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	boolean_t 			inserted = B_FALSE;
	dapl_mr_register_lmr_t		args;
	ibt_mr_data_in_t		mr_cb_data_in;
	daplka_mr_resource_t		*orig_mr_rp = NULL;
	daplka_mr_resource_t		*mr_rp;
	ibt_smr_attr_t			mem_sattr;
	uint64_t			mr_hkey = 0;
	ibt_status_t			status;
	int				retval;

	retval = ddi_copyin((void *)arg, &args,
	    sizeof (dapl_mr_register_lmr_t), mode);
	if (retval != 0) {
		DERR("mr_register_lmr: copyin error %d\n", retval);
		return (EINVAL);
	}
	orig_mr_rp = (daplka_mr_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_mr_htbl, args.mrl_orig_hkey);
	if (orig_mr_rp == NULL) {
		DERR("mr_register_lmr: cannot find mr resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(orig_mr_rp) == DAPL_TYPE_MR);

	mr_rp = kmem_zalloc(sizeof (daplka_mr_resource_t), daplka_km_flags);
	if (mr_rp == NULL) {
		DERR("mr_register_lmr: cannot allocate mr resource\n");
		retval = ENOMEM;
		goto cleanup;
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr_rp))
	DAPLKA_RS_INIT(mr_rp, DAPL_TYPE_MR,
	    DAPLKA_RS_RNUM(ia_rp), daplka_mr_destroy);

	mutex_init(&mr_rp->mr_lock, NULL, MUTEX_DRIVER, NULL);
	mr_rp->mr_hca = ia_rp->ia_hca;
	mr_rp->mr_hca_hdl = ia_rp->ia_hca_hdl;
	mr_rp->mr_next = NULL;
	mr_rp->mr_shared_mr = NULL;

	DAPLKA_RS_REF(orig_mr_rp->mr_pd_res);
	mr_rp->mr_pd_res = orig_mr_rp->mr_pd_res;
	mr_rp->mr_attr = orig_mr_rp->mr_attr;

	/* Pass the IO addr that was returned while allocating the orig MR */
	mem_sattr.mr_vaddr = orig_mr_rp->mr_desc.md_vaddr;
	mem_sattr.mr_flags = args.mrl_flags | IBT_MR_NOSLEEP;

	status = daplka_ibt_register_shared_mr(mr_rp, ia_rp->ia_hca_hdl,
	    orig_mr_rp->mr_hdl, mr_rp->mr_pd_res->pd_hdl, &mem_sattr,
	    &mr_rp->mr_hdl, &mr_rp->mr_desc);

	if (status != IBT_SUCCESS) {
		DERR("mr_register_lmr: ibt_register_shared_mr error %d\n",
		    status);
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}

	mr_cb_data_in.mr_rev = IBT_MR_DATA_IN_IF_VERSION;
	mr_cb_data_in.mr_func = daplka_pre_mr_cleanup_callback;
	mr_cb_data_in.mr_arg1 = (void *)mr_rp;
	mr_cb_data_in.mr_arg2 = NULL;

	/* Pass the service driver mr cleanup handler to the hca driver */
	status = ibt_ci_data_in(ia_rp->ia_hca_hdl,
	    IBT_CI_NO_FLAGS, IBT_HDL_MR, (void *)mr_rp->mr_hdl,
	    &mr_cb_data_in, sizeof (mr_cb_data_in));

	if (status != IBT_SUCCESS) {
		DERR("mr_register_lmr: ibt_ci_data_in error(%d) ver(%d)",
		    status, mr_cb_data_in.mr_rev);
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}
	mr_rp->mr_attr.mr_len = orig_mr_rp->mr_attr.mr_len;
	mr_rp->mr_attr.mr_flags = mem_sattr.mr_flags;

	/* insert into mr hash table */
	retval = daplka_hash_insert(&ia_rp->ia_mr_htbl, &mr_hkey,
	    (void *)mr_rp);
	if (retval != 0) {
		DERR("mr_register: cannot insert mr resource into mr_htbl\n");
		goto cleanup;
	}
	inserted = B_TRUE;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*mr_rp))

	args.mrl_lkey = mr_rp->mr_desc.md_lkey;
	args.mrl_rkey = mr_rp->mr_desc.md_rkey;
	args.mrl_hkey = mr_hkey;

	retval = ddi_copyout((void *)&args, (void *)arg,
	    sizeof (dapl_mr_register_lmr_t), mode);
	if (retval != 0) {
		DERR("mr_register_lmr: copyout error %d\n", retval);
		retval = EFAULT;
		goto cleanup;
	}
	if (orig_mr_rp != NULL) {
		DAPLKA_RS_UNREF(orig_mr_rp);
	}
	return (0);

cleanup:;
	if (inserted) {
		daplka_mr_resource_t *free_rp = NULL;

		(void) daplka_hash_remove(&ia_rp->ia_mr_htbl, mr_hkey,
		    (void **)&free_rp);
		if (free_rp != mr_rp) {
			DERR("mr_register: cannot remove mr from hash table\n");
			/*
			 * we can only get here if another thread
			 * has completed the cleanup in mr_deregister
			 */
			return (retval);
		}
	}
	if (orig_mr_rp != NULL) {
		DAPLKA_RS_UNREF(orig_mr_rp);
	}
	if (mr_rp != NULL) {
		DAPLKA_RS_UNREF(mr_rp);
	}
	return (retval);
}

/*
 * this function is called by mr_deregister and mr_cleanup_callback to
 * remove a mr resource from the shared mr object mr_rp->mr_shared_mr.
 * if mr_shared_mr is already NULL, that means the region being
 * deregistered or invalidated is not a shared mr region and we can
 * return immediately.
 */
static void
daplka_shared_mr_free(daplka_mr_resource_t *mr_rp)
{
	daplka_shared_mr_t	*smrp;

	/*
	 * we need a lock because mr_callback also checks this field.
	 * for the rare case that mr_deregister and mr_cleanup_callback
	 * gets called simultaneously, we are guaranteed that smrp won't
	 * be dereferenced twice because either function will find
	 * mr_shared_mr to be NULL.
	 */
	mutex_enter(&mr_rp->mr_lock);
	smrp = mr_rp->mr_shared_mr;
	mr_rp->mr_shared_mr = NULL;
	mutex_exit(&mr_rp->mr_lock);

	if (smrp != NULL) {
		daplka_mr_resource_t	**mpp;
		boolean_t		mr_found = B_FALSE;

		mutex_enter(&daplka_shared_mr_lock);
		ASSERT(smrp->smr_refcnt > 0);
		while (smrp->smr_state == DAPLKA_SMR_TRANSITIONING) {
			cv_wait(&smrp->smr_cv, &daplka_shared_mr_lock);
		}
		ASSERT(smrp->smr_state == DAPLKA_SMR_READY);
		smrp->smr_state = DAPLKA_SMR_TRANSITIONING;
		smrp->smr_refcnt--;

		/*
		 * search and remove mr_rp from smr_mr_list.
		 * also UNREF mr_rp because it is no longer
		 * on the list.
		 */
		mpp = &smrp->smr_mr_list;
		while (*mpp != NULL) {
			if (*mpp == mr_rp) {
				*mpp = (*mpp)->mr_next;
				DAPLKA_RS_UNREF(mr_rp);
				mr_rp->mr_next = NULL;
				mr_found = B_TRUE;
				break;
			}
			mpp = &(*mpp)->mr_next;
		}
		/*
		 * since mr_clean_callback may not touch smr_mr_list
		 * at this time (due to smr_state), we can be sure
		 * that we can find and remove mr_rp from smr_mr_list
		 */
		ASSERT(mr_found);
		if (smrp->smr_refcnt == 0) {
			D3("shared_mr_free: freeing smrp 0x%p\n", smrp);
			avl_remove(&daplka_shared_mr_tree, smrp);
			ASSERT(smrp->smr_mr_list == NULL);
			smrp->smr_state = DAPLKA_SMR_FREED;
			cv_destroy(&smrp->smr_cv);
			kmem_free(smrp, sizeof (daplka_shared_mr_t));
		} else {
			D3("shared_mr_free: smrp 0x%p, refcnt %d\n",
			    smrp, smrp->smr_refcnt);
			smrp->smr_state = DAPLKA_SMR_READY;
			cv_broadcast(&smrp->smr_cv);
		}
		mutex_exit(&daplka_shared_mr_lock);
	}
}

/*
 * deregisters a memory region.
 * if mr is shared, remove reference from global shared mr object.
 * release the initial reference to the mr. if the mr's refcnt is
 * zero, call mr_destroy to free mr.
 */
/* ARGSUSED */
static int
daplka_mr_deregister(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_mr_resource_t	*mr_rp;
	dapl_mr_deregister_t	args;
	int 			retval;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_mr_deregister_t),
	    mode);
	if (retval != 0) {
		DERR("mr_deregister: copyin error %d\n", retval);
		return (EINVAL);
	}
	retval = daplka_hash_remove(&ia_rp->ia_mr_htbl,
	    args.mrd_hkey, (void **)&mr_rp);
	if (retval != 0 || mr_rp == NULL) {
		DERR("mr_deregister: cannot find mr resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(mr_rp) == DAPL_TYPE_MR);

	daplka_shared_mr_free(mr_rp);
	DAPLKA_RS_UNREF(mr_rp);
	return (0);
}

/*
 * sync local memory regions on RDMA read or write.
 */
/* ARGSUSED */
static int
daplka_mr_sync(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	dapl_mr_sync_t	args;
	daplka_mr_resource_t *mr_rp[DAPL_MR_PER_SYNC];
	ibt_mr_sync_t	mrs[DAPL_MR_PER_SYNC];
	uint32_t	sync_direction_flags;
	ibt_status_t	status;
	int		i, j;
	int		retval;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_mr_sync_t), mode);
	if (retval != 0) {
		DERR("mr_sync: copyin error %d\n", retval);
		return (EFAULT);
	}

	/* number of segments bound check */
	if (args.mrs_numseg > DAPL_MR_PER_SYNC) {
		DERR("mr_sync: number of segments too large\n");
		return (EINVAL);
	}

	/* translate MR sync direction flag */
	if (args.mrs_flags == DAPL_MR_SYNC_RDMA_RD) {
		sync_direction_flags = IBT_SYNC_READ;
	} else if (args.mrs_flags == DAPL_MR_SYNC_RDMA_WR) {
		sync_direction_flags = IBT_SYNC_WRITE;
	} else {
		DERR("mr_sync: unknown flags\n");
		return (EINVAL);
	}

	/*
	 * all the segments are going to be sync'd by ibtl together
	 */
	for (i = 0; i < args.mrs_numseg; i++) {
		mr_rp[i] = (daplka_mr_resource_t *)daplka_hash_lookup(
		    &ia_rp->ia_mr_htbl, args.mrs_vec[i].mrsv_hkey);
		if (mr_rp[i] == NULL) {
			for (j = 0; j < i; j++) {
				DAPLKA_RS_UNREF(mr_rp[j]);
			}
			DERR("mr_sync: lookup error\n");
			return (EINVAL);
		}
		ASSERT(DAPLKA_RS_TYPE(mr_rp[i]) == DAPL_TYPE_MR);
		mrs[i].ms_handle = mr_rp[i]->mr_hdl;
		mrs[i].ms_vaddr = args.mrs_vec[i].mrsv_va;
		mrs[i].ms_len = args.mrs_vec[i].mrsv_len;
		mrs[i].ms_flags = sync_direction_flags;
	}

	status = ibt_sync_mr(ia_rp->ia_hca_hdl, mrs, args.mrs_numseg);
	if (status != IBT_SUCCESS) {
		DERR("mr_sync: ibt_sync_mr error %d\n", status);
		*rvalp = (int)status;
	}
	for (i = 0; i < args.mrs_numseg; i++) {
		DAPLKA_RS_UNREF(mr_rp[i]);
	}
	return (0);
}

/*
 * destroys a memory region.
 * called when refcnt drops to zero.
 */
static int
daplka_mr_destroy(daplka_resource_t *gen_rp)
{
	daplka_mr_resource_t	*mr_rp = (daplka_mr_resource_t *)gen_rp;
	ibt_status_t		status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr_rp))
	ASSERT(DAPLKA_RS_REFCNT(mr_rp) == 0);
	ASSERT(mr_rp->mr_shared_mr == NULL);
	D3("mr_destroy: entering, mr_rp 0x%p, rnum %d\n",
	    mr_rp, DAPLKA_RS_RNUM(mr_rp));

	/*
	 * deregister mr
	 */
	if (mr_rp->mr_hdl) {
		status = daplka_ibt_deregister_mr(mr_rp, mr_rp->mr_hca_hdl,
		    mr_rp->mr_hdl);
		if (status != IBT_SUCCESS) {
			DERR("mr_destroy: ibt_deregister_mr returned %d\n",
			    status);
		}
		mr_rp->mr_hdl = NULL;
		D3("mr_destroy: mr deregistered\n");
	}
	mr_rp->mr_attr.mr_vaddr = NULL;

	/*
	 * release reference on PD
	 */
	if (mr_rp->mr_pd_res != NULL) {
		DAPLKA_RS_UNREF(mr_rp->mr_pd_res);
		mr_rp->mr_pd_res = NULL;
	}
	mutex_destroy(&mr_rp->mr_lock);
	DAPLKA_RS_FINI(mr_rp);
	kmem_free(mr_rp, sizeof (daplka_mr_resource_t));
	D3("mr_destroy: exiting, mr_rp 0x%p\n", mr_rp);
	return (0);
}

/*
 * this function is called by daplka_hash_destroy for
 * freeing MR resource objects
 */
static void
daplka_hash_mr_free(void *obj)
{
	daplka_mr_resource_t	*mr_rp = (daplka_mr_resource_t *)obj;

	daplka_shared_mr_free(mr_rp);
	DAPLKA_RS_UNREF(mr_rp);
}

/*
 * comparison function used for finding a shared mr object
 * from the global shared mr avl tree.
 */
static int
daplka_shared_mr_cmp(const void *smr1, const void *smr2)
{
	daplka_shared_mr_t	*s1 = (daplka_shared_mr_t *)smr1;
	daplka_shared_mr_t	*s2 = (daplka_shared_mr_t *)smr2;
	int i;

	for (i = 4; i >= 0; i--) {
		if (s1->smr_cookie.mc_uint_arr[i] <
		    s2->smr_cookie.mc_uint_arr[i]) {
			return (-1);
		}
		if (s1->smr_cookie.mc_uint_arr[i] >
		    s2->smr_cookie.mc_uint_arr[i]) {
			return (1);
		}
	}
	return (0);
}

/*
 * allocates a protection domain.
 */
/* ARGSUSED */
static int
daplka_pd_alloc(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	dapl_pd_alloc_t		args;
	daplka_pd_resource_t	*pd_rp;
	ibt_status_t		status;
	uint64_t		pd_hkey = 0;
	boolean_t		inserted = B_FALSE;
	int			retval;

	pd_rp = kmem_zalloc(sizeof (*pd_rp), daplka_km_flags);
	if (pd_rp == NULL) {
		DERR("pd_alloc: cannot allocate pd resource\n");
		return (ENOMEM);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*pd_rp))
	DAPLKA_RS_INIT(pd_rp, DAPL_TYPE_PD,
	    DAPLKA_RS_RNUM(ia_rp), daplka_pd_destroy);

	pd_rp->pd_hca = ia_rp->ia_hca;
	pd_rp->pd_hca_hdl = ia_rp->ia_hca_hdl;
	status = daplka_ibt_alloc_pd(pd_rp, pd_rp->pd_hca_hdl,
	    IBT_PD_NO_FLAGS, &pd_rp->pd_hdl);
	if (status != IBT_SUCCESS) {
		DERR("pd_alloc: ibt_alloc_pd returned %d\n", status);
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}

	/* insert into pd hash table */
	retval = daplka_hash_insert(&ia_rp->ia_pd_htbl,
	    &pd_hkey, (void *)pd_rp);
	if (retval != 0) {
		DERR("pd_alloc: cannot insert pd resource into pd_htbl\n");
		goto cleanup;
	}
	inserted = B_TRUE;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*pd_rp))

	/* return hkey to library */
	args.pda_hkey = pd_hkey;

	retval = ddi_copyout(&args, (void *)arg, sizeof (dapl_pd_alloc_t),
	    mode);
	if (retval != 0) {
		DERR("pd_alloc: copyout error %d\n", retval);
		retval = EFAULT;
		goto cleanup;
	}
	return (0);

cleanup:;
	if (inserted) {
		daplka_pd_resource_t *free_rp = NULL;

		(void) daplka_hash_remove(&ia_rp->ia_pd_htbl, pd_hkey,
		    (void **)&free_rp);
		if (free_rp != pd_rp) {
			DERR("pd_alloc: cannot remove pd from hash table\n");
			/*
			 * we can only get here if another thread
			 * has completed the cleanup in pd_free
			 */
			return (retval);
		}
	}
	DAPLKA_RS_UNREF(pd_rp);
	return (retval);
}

/*
 * destroys a protection domain.
 * called when refcnt drops to zero.
 */
static int
daplka_pd_destroy(daplka_resource_t *gen_rp)
{
	daplka_pd_resource_t *pd_rp = (daplka_pd_resource_t *)gen_rp;
	ibt_status_t status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*pd_rp))
	ASSERT(DAPLKA_RS_REFCNT(pd_rp) == 0);
	D3("pd_destroy: entering, pd_rp %p, rnum %d\n",
	    pd_rp, DAPLKA_RS_RNUM(pd_rp));

	ASSERT(DAPLKA_RS_TYPE(pd_rp) == DAPL_TYPE_PD);
	if (pd_rp->pd_hdl != NULL) {
		status = daplka_ibt_free_pd(pd_rp, pd_rp->pd_hca_hdl,
		    pd_rp->pd_hdl);
		if (status != IBT_SUCCESS) {
			DERR("pd_destroy: ibt_free_pd returned %d\n", status);
		}
	}
	DAPLKA_RS_FINI(pd_rp);
	kmem_free(pd_rp, sizeof (daplka_pd_resource_t));
	D3("pd_destroy: exiting, pd_rp %p\n", pd_rp);
	return (0);
}

static void
daplka_hash_pd_free(void *obj)
{
	daplka_pd_resource_t *pd_rp = (daplka_pd_resource_t *)obj;

	ASSERT(DAPLKA_RS_TYPE(pd_rp) == DAPL_TYPE_PD);
	DAPLKA_RS_UNREF(pd_rp);
}

/*
 * removes the pd reference from ia_pd_htbl and releases the
 * initial reference to the pd. also destroys the pd if the refcnt
 * is zero.
 */
/* ARGSUSED */
static int
daplka_pd_free(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_pd_resource_t *pd_rp;
	dapl_pd_free_t args;
	int retval;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_pd_free_t), mode);
	if (retval != 0) {
		DERR("pd_free: copyin error %d\n", retval);
		return (EINVAL);
	}

	retval = daplka_hash_remove(&ia_rp->ia_pd_htbl,
	    args.pdf_hkey, (void **)&pd_rp);
	if (retval != 0 || pd_rp == NULL) {
		DERR("pd_free: cannot find pd resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(pd_rp) == DAPL_TYPE_PD);

	/* UNREF calls the actual free function when refcnt is zero */
	DAPLKA_RS_UNREF(pd_rp);
	return (0);
}

/*
 * allocates a memory window
 */
/* ARGSUSED */
static int
daplka_mw_alloc(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_pd_resource_t	*pd_rp;
	daplka_mw_resource_t	*mw_rp;
	dapl_mw_alloc_t		args;
	ibt_status_t		status;
	boolean_t		inserted = B_FALSE;
	uint64_t		mw_hkey;
	ibt_rkey_t		mw_rkey;
	int			retval;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_mw_alloc_t), mode);
	if (retval != 0) {
		DERR("mw_alloc: copyin error %d\n", retval);
		return (EFAULT);
	}

	/*
	 * Allocate and initialize a MW resource
	 */
	mw_rp = kmem_zalloc(sizeof (daplka_mw_resource_t), daplka_km_flags);
	if (mw_rp == NULL) {
		DERR("mw_alloc: cannot allocate mw resource\n");
		return (ENOMEM);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mw_rp))
	DAPLKA_RS_INIT(mw_rp, DAPL_TYPE_MW,
	    DAPLKA_RS_RNUM(ia_rp), daplka_mw_destroy);

	mutex_init(&mw_rp->mw_lock, NULL, MUTEX_DRIVER, NULL);
	mw_rp->mw_hca = ia_rp->ia_hca;
	mw_rp->mw_hca_hdl = ia_rp->ia_hca_hdl;

	/* get pd handle */
	pd_rp = (daplka_pd_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_pd_htbl, args.mw_pd_hkey);
	if (pd_rp == NULL) {
		DERR("mw_alloc: cannot find pd resource\n");
		goto cleanup;
	}
	ASSERT(DAPLKA_RS_TYPE(pd_rp) == DAPL_TYPE_PD);

	mw_rp->mw_pd_res = pd_rp;

	status = daplka_ibt_alloc_mw(mw_rp, mw_rp->mw_hca_hdl,
	    pd_rp->pd_hdl, IBT_MW_NOSLEEP, &mw_rp->mw_hdl, &mw_rkey);

	if (status != IBT_SUCCESS) {
		DERR("mw_alloc: ibt_alloc_mw returned %d\n", status);
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}

	mutex_enter(&ia_rp->ia_lock);
	switch (ia_rp->ia_state) {
	case DAPLKA_IA_INIT:
		ia_rp->ia_state = DAPLKA_IA_MW_ALLOC_IN_PROGRESS;
		ia_rp->ia_mw_alloccnt++;
		retval = 0;
		break;
	case DAPLKA_IA_MW_ALLOC_IN_PROGRESS:
		/* another mw_alloc is already in progress increase cnt */
		ia_rp->ia_mw_alloccnt++;
		retval = 0;
		break;
	case DAPLKA_IA_MW_FREEZE_IN_PROGRESS:
		/* FALLTHRU */
	case DAPLKA_IA_MW_FROZEN:
		/*
		 * IA is being or already frozen don't allow more MWs to be
		 * allocated.
		 */
		DERR("mw_alloc:	IA is freezing MWs (state=%d)\n",
		    ia_rp->ia_state);
		retval = EINVAL;
		break;
	default:
		ASSERT(!"Invalid IA state in mw_alloc");
		DERR("mw_alloc:	IA state=%d invalid\n", ia_rp->ia_state);
		retval = EINVAL;
		break;
	}
	mutex_exit(&ia_rp->ia_lock);
	/* retval is 0 when ia_mw_alloccnt is incremented */
	if (retval != 0) {
		goto cleanup;
	}

	/* insert into mw hash table */
	mw_hkey = 0;
	retval = daplka_hash_insert(&ia_rp->ia_mw_htbl, &mw_hkey,
	    (void *)mw_rp);
	if (retval != 0) {
		DERR("mw_alloc: cannot insert mw resource into mw_htbl\n");
		mutex_enter(&ia_rp->ia_lock);
		ASSERT(ia_rp->ia_state == DAPLKA_IA_MW_ALLOC_IN_PROGRESS);
		ia_rp->ia_mw_alloccnt--;
		if (ia_rp->ia_mw_alloccnt == 0) {
			ia_rp->ia_state = DAPLKA_IA_INIT;
			cv_broadcast(&ia_rp->ia_cv);
		}
		mutex_exit(&ia_rp->ia_lock);
		goto cleanup;
	}
	inserted = B_TRUE;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*mw_rp))

	D3("mw_alloc: ibt_alloc_mw mw_hdl(%p) mw_rkey(0x%llx)\n",
	    mw_rp->mw_hdl, (longlong_t)mw_rkey);

	mutex_enter(&ia_rp->ia_lock);
	/*
	 * We are done with mw_alloc if this was the last mw_alloc
	 * change state back to DAPLKA_IA_INIT and wake up waiters
	 * specifically the unlock callback.
	 */
	ASSERT(ia_rp->ia_state == DAPLKA_IA_MW_ALLOC_IN_PROGRESS);
	ia_rp->ia_mw_alloccnt--;
	if (ia_rp->ia_mw_alloccnt == 0) {
		ia_rp->ia_state = DAPLKA_IA_INIT;
		cv_broadcast(&ia_rp->ia_cv);
	}
	mutex_exit(&ia_rp->ia_lock);

	args.mw_hkey = mw_hkey;
	args.mw_rkey = mw_rkey;

	retval = ddi_copyout(&args, (void *)arg, sizeof (dapl_mw_alloc_t),
	    mode);
	if (retval != 0) {
		DERR("mw_alloc: copyout error %d\n", retval);
		retval = EFAULT;
		goto cleanup;
	}
	return (0);

cleanup:;
	if (inserted) {
		daplka_mw_resource_t *free_rp = NULL;

		(void) daplka_hash_remove(&ia_rp->ia_mw_htbl, mw_hkey,
		    (void **)&free_rp);
		if (free_rp != mw_rp) {
			DERR("mw_alloc: cannot remove mw from hash table\n");
			/*
			 * we can only get here if another thread
			 * has completed the cleanup in mw_free
			 */
			return (retval);
		}
	}
	DAPLKA_RS_UNREF(mw_rp);
	return (retval);
}

/*
 * removes the mw reference from ia_mw_htbl and releases the
 * initial reference to the mw. also destroys the mw if the refcnt
 * is zero.
 */
/* ARGSUSED */
static int
daplka_mw_free(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_mw_resource_t	*mw_rp = NULL;
	dapl_mw_free_t		args;
	int			retval = 0;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_mw_free_t), mode);
	if (retval != 0) {
		DERR("mw_free: copyin error %d\n", retval);
		return (EFAULT);
	}

	retval = daplka_hash_remove(&ia_rp->ia_mw_htbl, args.mw_hkey,
	    (void **)&mw_rp);
	if (retval != 0 || mw_rp == NULL) {
		DERR("mw_free: cannot find mw resrc (0x%llx)\n",
		    (longlong_t)args.mw_hkey);
		return (EINVAL);
	}

	ASSERT(DAPLKA_RS_TYPE(mw_rp) == DAPL_TYPE_MW);

	/* UNREF calls the actual free function when refcnt is zero */
	DAPLKA_RS_UNREF(mw_rp);
	return (retval);
}

/*
 * destroys the memory window.
 * called when refcnt drops to zero.
 */
static int
daplka_mw_destroy(daplka_resource_t *gen_rp)
{
	daplka_mw_resource_t	*mw_rp = (daplka_mw_resource_t *)gen_rp;
	ibt_status_t		status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mw_rp))
	ASSERT(DAPLKA_RS_REFCNT(mw_rp) == 0);
	D3("mw_destroy: entering, mw_rp 0x%p, rnum %d\n",
	    mw_rp, DAPLKA_RS_RNUM(mw_rp));

	/*
	 * free memory window
	 */
	if (mw_rp->mw_hdl) {
		status = daplka_ibt_free_mw(mw_rp, mw_rp->mw_hca_hdl,
		    mw_rp->mw_hdl);
		if (status != IBT_SUCCESS) {
			DERR("mw_destroy: ibt_free_mw returned %d\n", status);
		}
		mw_rp->mw_hdl = NULL;
		D3("mw_destroy: mw freed\n");
	}

	/*
	 * release reference on PD
	 */
	if (mw_rp->mw_pd_res != NULL) {
		DAPLKA_RS_UNREF(mw_rp->mw_pd_res);
		mw_rp->mw_pd_res = NULL;
	}
	mutex_destroy(&mw_rp->mw_lock);
	DAPLKA_RS_FINI(mw_rp);
	kmem_free(mw_rp, sizeof (daplka_mw_resource_t));
	D3("mw_destroy: exiting, mw_rp 0x%p\n", mw_rp);
	return (0);
}

static void
daplka_hash_mw_free(void *obj)
{
	daplka_mw_resource_t *mw_rp = (daplka_mw_resource_t *)obj;

	ASSERT(DAPLKA_RS_TYPE(mw_rp) == DAPL_TYPE_MW);
	DAPLKA_RS_UNREF(mw_rp);
}

/*
 * SRQ ioctls and supporting functions
 */
/* ARGSUSED */
static int
daplka_srq_create(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
    cred_t *cred, int *rvalp)
{
	daplka_srq_resource_t		*srq_rp;
	daplka_pd_resource_t		*pd_rp;
	dapl_srq_create_t		args;
	ibt_srq_sizes_t			srq_sizes;
	ibt_srq_sizes_t			srq_real_sizes;
	ibt_hca_attr_t			*hca_attrp;
	uint64_t			srq_hkey = 0;
	boolean_t			inserted = B_FALSE;
	int				retval;
	ibt_status_t			status;

	D3("srq_create: enter\n");
	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_srq_create_t),
	    mode);
	if (retval != 0) {
		DERR("srq_create: copyin error %d\n", retval);
		return (EFAULT);
	}
	srq_rp = kmem_zalloc(sizeof (daplka_srq_resource_t), daplka_km_flags);
	if (srq_rp == NULL) {
		DERR("srq_create: cannot allocate ep_rp\n");
		return (ENOMEM);
	}
	DAPLKA_RS_INIT(srq_rp, DAPL_TYPE_SRQ,
	    DAPLKA_RS_RNUM(ia_rp), daplka_srq_destroy);

	srq_rp->srq_hca = ia_rp->ia_hca;
	srq_rp->srq_hca_hdl = ia_rp->ia_hca_hdl;
	mutex_init(&srq_rp->srq_lock, NULL, MUTEX_DRIVER, NULL);

	/* get pd handle */
	pd_rp = (daplka_pd_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_pd_htbl, args.srqc_pd_hkey);
	if (pd_rp == NULL) {
		DERR("srq_create: cannot find pd resource\n");
		retval = EINVAL;
		goto cleanup;
	}
	ASSERT(DAPLKA_RS_TYPE(pd_rp) == DAPL_TYPE_PD);
	srq_rp->srq_pd_res = pd_rp;

	/*
	 * these checks ensure that the requested SRQ sizes
	 * are within the limits supported by the chosen HCA.
	 */
	hca_attrp = &ia_rp->ia_hca->hca_attr;
	if (args.srqc_sizes.srqs_sz > hca_attrp->hca_max_srqs_sz) {
		DERR("srq_create: invalid srqs_sz %d\n",
		    args.srqc_sizes.srqs_sz);
		retval = EINVAL;
		goto cleanup;
	}
	if (args.srqc_sizes.srqs_sgl > hca_attrp->hca_max_srq_sgl) {
		DERR("srq_create: invalid srqs_sgl %d\n",
		    args.srqc_sizes.srqs_sgl);
		retval = EINVAL;
		goto cleanup;
	}

	D3("srq_create: srq_sgl %d, srq_sz %d\n",
	    args.srqc_sizes.srqs_sgl, args.srqc_sizes.srqs_sz);

	srq_sizes.srq_wr_sz = args.srqc_sizes.srqs_sz;
	srq_sizes.srq_sgl_sz = args.srqc_sizes.srqs_sgl;

	/* create srq */
	status = daplka_ibt_alloc_srq(srq_rp, ia_rp->ia_hca_hdl,
	    IBT_SRQ_USER_MAP, pd_rp->pd_hdl, &srq_sizes, &srq_rp->srq_hdl,
	    &srq_real_sizes);
	if (status != IBT_SUCCESS) {
		DERR("srq_create: alloc_srq returned %d\n", status);
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}

	args.srqc_real_sizes.srqs_sz = srq_real_sizes.srq_wr_sz;
	args.srqc_real_sizes.srqs_sgl = srq_real_sizes.srq_sgl_sz;

	/* Get HCA-specific data_out info */
	status = ibt_ci_data_out(ia_rp->ia_hca_hdl,
	    IBT_CI_NO_FLAGS, IBT_HDL_SRQ, (void *)srq_rp->srq_hdl,
	    &args.srqc_data_out, sizeof (args.srqc_data_out));

	if (status != IBT_SUCCESS) {
		DERR("srq_create: ibt_ci_data_out error(%d)\n", status);
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}

	srq_rp->srq_real_size = srq_real_sizes.srq_wr_sz;

	/* preparing to copyout map_data back to the library */
	args.srqc_real_sizes.srqs_sz = srq_real_sizes.srq_wr_sz;
	args.srqc_real_sizes.srqs_sgl = srq_real_sizes.srq_sgl_sz;

	/* insert into srq hash table */
	retval = daplka_hash_insert(&ia_rp->ia_srq_htbl,
	    &srq_hkey, (void *)srq_rp);
	if (retval != 0) {
		DERR("srq_create: cannot insert srq resource into srq_htbl\n");
		goto cleanup;
	}
	inserted = B_TRUE;

	/* return hkey to library */
	args.srqc_hkey = srq_hkey;

	retval = ddi_copyout(&args, (void *)arg, sizeof (dapl_srq_create_t),
	    mode);
	if (retval != 0) {
		DERR("srq_create: copyout error %d\n", retval);
		retval = EFAULT;
		goto cleanup;
	}

	D3("srq_create: %p, 0x%llx\n", srq_rp->srq_hdl, (longlong_t)srq_hkey);
	D3("	sz(%d) sgl(%d)\n",
	    args.srqc_real_sizes.srqs_sz, args.srqc_real_sizes.srqs_sgl);
	D3("srq_create: exit\n");
	return (0);

cleanup:
	if (inserted) {
		daplka_srq_resource_t *free_rp = NULL;

		(void) daplka_hash_remove(&ia_rp->ia_srq_htbl, srq_hkey,
		    (void **)&free_rp);
		if (free_rp != srq_rp) {
			/*
			 * this case is impossible because ep_free will
			 * wait until our state transition is complete.
			 */
			DERR("srq_create: cannot remove srq from hash table\n");
			ASSERT(B_FALSE);
			return (retval);
		}
	}
	DAPLKA_RS_UNREF(srq_rp);
	return (retval);
}

/*
 * Resize an existing SRQ
 */
/* ARGSUSED */
static int
daplka_srq_resize(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
    cred_t *cred, int *rvalp)
{
	daplka_srq_resource_t		*srq_rp = NULL;
	ibt_hca_attr_t			*hca_attrp;
	dapl_srq_resize_t		args;
	ibt_status_t			status;
	int				retval = 0;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_srq_resize_t),
	    mode);
	if (retval != 0) {
		DERR("srq_resize: copyin error %d\n", retval);
		return (EFAULT);
	}

	/* get srq resource */
	srq_rp = (daplka_srq_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_srq_htbl, args.srqr_hkey);
	if (srq_rp == NULL) {
		DERR("srq_resize: cannot find srq resource\n");
		return (EINVAL);
	}
	ASSERT(DAPLKA_RS_TYPE(srq_rp) == DAPL_TYPE_SRQ);

	hca_attrp = &ia_rp->ia_hca->hca_attr;
	if (args.srqr_new_size > hca_attrp->hca_max_srqs_sz) {
		DERR("srq_resize: invalid srq size %d", args.srqr_new_size);
		retval = EINVAL;
		goto cleanup;
	}

	mutex_enter(&srq_rp->srq_lock);
	/*
	 * If ibt_resize_srq fails that it is primarily due to resource
	 * shortage. Per IB spec resize will never loose events and
	 * a resize error leaves the SRQ intact. Therefore even if the
	 * resize request fails we proceed and get the mapping data
	 * from the SRQ so that the library can mmap it.
	 */
	status = ibt_modify_srq(srq_rp->srq_hdl, IBT_SRQ_SET_SIZE,
	    args.srqr_new_size, 0, &args.srqr_real_size);
	if (status != IBT_SUCCESS) {
		/* we return the size of the old CQ if resize fails */
		args.srqr_real_size = srq_rp->srq_real_size;
		ASSERT(status != IBT_SRQ_HDL_INVALID);
		DERR("srq_resize: ibt_modify_srq failed:%d\n", status);
	} else {
		srq_rp->srq_real_size = args.srqr_real_size;
	}
	mutex_exit(&srq_rp->srq_lock);


	D2("srq_resize(%d): done new_sz(%u) real_sz(%u)\n",
	    DAPLKA_RS_RNUM(srq_rp), args.srqr_new_size, args.srqr_real_size);

	/* Get HCA-specific data_out info */
	status = ibt_ci_data_out(srq_rp->srq_hca_hdl,
	    IBT_CI_NO_FLAGS, IBT_HDL_SRQ, (void *)srq_rp->srq_hdl,
	    &args.srqr_data_out, sizeof (args.srqr_data_out));
	if (status != IBT_SUCCESS) {
		DERR("srq_resize: ibt_ci_data_out error(%d)\n", status);
		/* return ibt_ci_data_out status */
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}

	retval = ddi_copyout(&args, (void *)arg, sizeof (dapl_srq_resize_t),
	    mode);
	if (retval != 0) {
		DERR("srq_resize: copyout error %d\n", retval);
		retval = EFAULT;
		goto cleanup;
	}

cleanup:;
	if (srq_rp != NULL) {
		DAPLKA_RS_UNREF(srq_rp);
	}
	return (retval);
}

/*
 * Frees an SRQ resource.
 */
/* ARGSUSED */
static int
daplka_srq_free(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
    cred_t *cred, int *rvalp)
{
	daplka_srq_resource_t	*srq_rp = NULL;
	dapl_srq_free_t		args;
	int			retval;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_srq_free_t), mode);
	if (retval != 0) {
		DERR("srq_free: copyin error %d\n", retval);
		return (EFAULT);
	}

	retval = daplka_hash_remove(&ia_rp->ia_srq_htbl,
	    args.srqf_hkey, (void **)&srq_rp);
	if (retval != 0 || srq_rp == NULL) {
		/*
		 * this is only possible if we have two threads
		 * calling ep_free in parallel.
		 */
		DERR("srq_free: cannot find resource retval(%d) 0x%llx\n",
		    retval, args.srqf_hkey);
		return (EINVAL);
	}

	/* UNREF calls the actual free function when refcnt is zero */
	DAPLKA_RS_UNREF(srq_rp);
	return (0);
}

/*
 * destroys a SRQ resource.
 * called when refcnt drops to zero.
 */
static int
daplka_srq_destroy(daplka_resource_t *gen_rp)
{
	daplka_srq_resource_t	*srq_rp = (daplka_srq_resource_t *)gen_rp;
	ibt_status_t		status;

	ASSERT(DAPLKA_RS_REFCNT(srq_rp) == 0);

	D3("srq_destroy: entering, srq_rp 0x%p, rnum %d\n",
	    srq_rp, DAPLKA_RS_RNUM(srq_rp));
	/*
	 * destroy the srq
	 */
	if (srq_rp->srq_hdl != NULL) {
		status = daplka_ibt_free_srq(srq_rp, srq_rp->srq_hdl);
		if (status != IBT_SUCCESS) {
			DERR("srq_destroy: ibt_free_srq returned %d\n",
			    status);
		}
		srq_rp->srq_hdl = NULL;
		D3("srq_destroy: srq freed, rnum %d\n", DAPLKA_RS_RNUM(srq_rp));
	}
	/*
	 * release all references
	 */
	if (srq_rp->srq_pd_res != NULL) {
		DAPLKA_RS_UNREF(srq_rp->srq_pd_res);
		srq_rp->srq_pd_res = NULL;
	}

	mutex_destroy(&srq_rp->srq_lock);
	DAPLKA_RS_FINI(srq_rp);
	kmem_free(srq_rp, sizeof (daplka_srq_resource_t));
	D3("srq_destroy: exiting, srq_rp 0x%p\n", srq_rp);
	return (0);
}

static void
daplka_hash_srq_free(void *obj)
{
	daplka_srq_resource_t *srq_rp = (daplka_srq_resource_t *)obj;

	ASSERT(DAPLKA_RS_TYPE(srq_rp) == DAPL_TYPE_SRQ);
	DAPLKA_RS_UNREF(srq_rp);
}

/*
 * This function tells the CM to start listening on a service id.
 * It must be called by the passive side client before the client
 * can receive connection requests from remote endpoints. If the
 * client specifies a non-zero service id (connection qualifier in
 * dapl terms), this function will attempt to bind to this service
 * id and return an error if the id is already in use. If the client
 * specifies zero as the service id, this function will try to find
 * the next available service id and return it back to the client.
 * To support the cr_handoff function, this function will, in addition
 * to creating and inserting an SP resource into the per-IA SP hash
 * table, insert the SP resource into a global SP table. This table
 * maintains all active service points created by all dapl clients.
 * CR handoff locates the target SP by iterating through this global
 * table.
 */
/* ARGSUSED */
static int
daplka_service_register(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_evd_resource_t	*evd_rp = NULL;
	daplka_sp_resource_t	*sp_rp = NULL;
	dapl_service_register_t	args;
	ibt_srv_desc_t		sd_args;
	ibt_srv_bind_t		sb_args;
	ibt_status_t		status;
	ib_svc_id_t		retsid = 0;
	uint64_t		sp_hkey = 0;
	boolean_t		bumped = B_FALSE;
	int			backlog_size;
	int			retval = 0;

	retval = ddi_copyin((void *)arg, &args,
	    sizeof (dapl_service_register_t), mode);
	if (retval != 0) {
		DERR("service_register: copyin error %d\n", retval);
		return (EINVAL);
	}

	sp_rp = kmem_zalloc(sizeof (*sp_rp), daplka_km_flags);
	if (sp_rp == NULL) {
		DERR("service_register: cannot allocate sp resource\n");
		return (ENOMEM);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sp_rp))
	DAPLKA_RS_INIT(sp_rp, DAPL_TYPE_SP,
	    DAPLKA_RS_RNUM(ia_rp), daplka_sp_destroy);

	/* check if evd exists */
	evd_rp = (daplka_evd_resource_t *)
	    daplka_hash_lookup(&ia_rp->ia_evd_htbl, args.sr_evd_hkey);
	if (evd_rp == NULL) {
		DERR("service_register: evd resource not found\n");
		retval = EINVAL;
		goto cleanup;
	}
	/*
	 * initialize backlog size
	 */
	if (evd_rp && evd_rp->evd_cq_real_size > 0) {
		backlog_size = evd_rp->evd_cq_real_size + 1;
	} else {
		backlog_size = DAPLKA_DEFAULT_SP_BACKLOG;
	}
	D2("service_register: args.sr_sid = %llu\n", (longlong_t)args.sr_sid);

	/* save the userland sp ptr */
	sp_rp->sp_cookie = args.sr_sp_cookie;
	sp_rp->sp_backlog_size = backlog_size;
	D3("service_register: backlog set to %d\n", sp_rp->sp_backlog_size);
	sp_rp->sp_backlog = kmem_zalloc(sp_rp->sp_backlog_size *
	    sizeof (daplka_sp_conn_pend_t), daplka_km_flags);

	/* save evd resource pointer */
	sp_rp->sp_evd_res = evd_rp;

	/*
	 * save ruid here so that we can do a comparison later
	 * when someone does cr_handoff. the check will prevent
	 * a malicious app from passing a CR to us.
	 */
	sp_rp->sp_ruid = crgetruid(cred);

	/* fill in args for register_service */
	sd_args.sd_ud_handler = NULL;
	sd_args.sd_handler = daplka_cm_service_handler;
	sd_args.sd_flags = IBT_SRV_NO_FLAGS;

	status = ibt_register_service(daplka_dev->daplka_clnt_hdl,
	    &sd_args, args.sr_sid, 1, &sp_rp->sp_srv_hdl, &retsid);

	if (status != IBT_SUCCESS) {
		DERR("service_register: ibt_register_service returned %d\n",
		    status);
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}
	/* save returned sid */
	sp_rp->sp_conn_qual = retsid;
	args.sr_retsid = retsid;

	/* fill in args for bind_service */
	sb_args.sb_pkey = ia_rp->ia_port_pkey;
	sb_args.sb_lease = 0xffffffff;
	sb_args.sb_key[0] = 0x1234;
	sb_args.sb_key[1] = 0x5678;
	sb_args.sb_name = DAPLKA_DRV_NAME;

	D2("service_register: bind(0x%llx:0x%llx)\n",
	    (longlong_t)ia_rp->ia_hca_sgid.gid_prefix,
	    (longlong_t)ia_rp->ia_hca_sgid.gid_guid);

	status = ibt_bind_service(sp_rp->sp_srv_hdl, ia_rp->ia_hca_sgid,
	    &sb_args, (void *)sp_rp, &sp_rp->sp_bind_hdl);
	if (status != IBT_SUCCESS) {
		DERR("service_register: ibt_bind_service returned %d\n",
		    status);
		*rvalp = (int)status;
		retval = 0;
		goto cleanup;
	}

	/*
	 * need to bump refcnt because the global hash table will
	 * have a reference to sp_rp
	 */
	DAPLKA_RS_REF(sp_rp);
	bumped = B_TRUE;

	/* insert into global sp hash table */
	sp_rp->sp_global_hkey = 0;
	retval = daplka_hash_insert(&daplka_global_sp_htbl,
	    &sp_rp->sp_global_hkey, (void *)sp_rp);
	if (retval != 0) {
		DERR("service_register: cannot insert sp resource\n");
		goto cleanup;
	}
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*sp_rp))

	/* insert into per-IA sp hash table */
	retval = daplka_hash_insert(&ia_rp->ia_sp_htbl,
	    &sp_hkey, (void *)sp_rp);
	if (retval != 0) {
		DERR("service_register: cannot insert sp resource\n");
		goto cleanup;
	}

	/* pass index to application */
	args.sr_sp_hkey = sp_hkey;
	retval = ddi_copyout(&args, (void *)arg,
	    sizeof (dapl_service_register_t), mode);
	if (retval != 0) {
		DERR("service_register: copyout error %d\n", retval);
		retval = EFAULT;
		goto cleanup;
	}
	return (0);

cleanup:;
	ASSERT(sp_rp != NULL);
	/* remove from ia table */
	if (sp_hkey != 0) {
		daplka_sp_resource_t *free_rp = NULL;

		(void) daplka_hash_remove(&ia_rp->ia_sp_htbl,
		    sp_hkey, (void **)&free_rp);
		if (free_rp != sp_rp) {
			DERR("service_register: cannot remove sp\n");
			/*
			 * we can only get here if another thread
			 * has completed the cleanup in svc_deregister
			 */
			return (retval);
		}
	}

	/* remove from global table */
	if (sp_rp->sp_global_hkey != 0) {
		daplka_sp_resource_t *free_rp = NULL;

		/*
		 * we get here if either the hash_insert into
		 * ia_sp_htbl failed or the ddi_copyout failed.
		 * hash_insert failure implies that we are the
		 * only thread with a reference to sp. ddi_copyout
		 * failure implies that svc_deregister could have
		 * picked up the sp and destroyed it. but since
		 * we got to this point, we must have removed
		 * the sp ourselves in hash_remove above and
		 * that the sp can be destroyed by us.
		 */
		(void) daplka_hash_remove(&daplka_global_sp_htbl,
		    sp_rp->sp_global_hkey, (void **)&free_rp);
		if (free_rp != sp_rp) {
			DERR("service_register: cannot remove sp\n");
			/*
			 * this case is impossible. see explanation above.
			 */
			ASSERT(B_FALSE);
			return (retval);
		}
		sp_rp->sp_global_hkey = 0;
	}
	/* unreference sp */
	if (bumped) {
		DAPLKA_RS_UNREF(sp_rp);
	}

	/* destroy sp resource */
	DAPLKA_RS_UNREF(sp_rp);
	return (retval);
}

/*
 * deregisters the service and removes SP from the global table.
 */
/* ARGSUSED */
static int
daplka_service_deregister(daplka_ia_resource_t *ia_rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	dapl_service_deregister_t	args;
	daplka_sp_resource_t		*sp_rp = NULL, *g_sp_rp = NULL;
	int				retval;

	retval = ddi_copyin((void *)arg, &args,
	    sizeof (dapl_service_deregister_t), mode);

	if (retval != 0) {
		DERR("service_deregister: copyin error %d\n", retval);
		return (EINVAL);
	}

	retval = daplka_hash_remove(&ia_rp->ia_sp_htbl,
	    args.sdr_sp_hkey, (void **)&sp_rp);
	if (retval != 0 || sp_rp == NULL) {
		DERR("service_deregister: cannot find sp resource\n");
		return (EINVAL);
	}

	retval = daplka_hash_remove(&daplka_global_sp_htbl,
	    sp_rp->sp_global_hkey, (void **)&g_sp_rp);
	if (retval != 0 || g_sp_rp == NULL) {
		DERR("service_deregister: cannot find sp resource\n");
	}

	/* remove the global reference */
	if (g_sp_rp == sp_rp) {
		DAPLKA_RS_UNREF(g_sp_rp);
	}

	DAPLKA_RS_UNREF(sp_rp);
	return (0);
}

/*
 * destroys a service point.
 * called when the refcnt drops to zero.
 */
static int
daplka_sp_destroy(daplka_resource_t *gen_rp)
{
	daplka_sp_resource_t *sp_rp = (daplka_sp_resource_t *)gen_rp;
	ibt_status_t status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sp_rp))
	ASSERT(DAPLKA_RS_REFCNT(sp_rp) == 0);
	D3("sp_destroy: entering, sp_rp %p, rnum %d\n",
	    sp_rp, DAPLKA_RS_RNUM(sp_rp));

	/*
	 * it is possible for pending connections to remain
	 * on an SP. We need to clean them up here.
	 */
	if (sp_rp->sp_backlog != NULL) {
		ibt_cm_proceed_reply_t proc_reply;
		int i, cnt = 0;
		void *spcp_sidp;

		for (i = 0; i < sp_rp->sp_backlog_size; i++) {
			if (sp_rp->sp_backlog[i].spcp_state ==
			    DAPLKA_SPCP_PENDING) {
				cnt++;
				if (sp_rp->sp_backlog[i].spcp_sid == NULL) {
					DERR("sp_destroy: "
					    "spcp_sid == NULL!\n");
					continue;
				}
				mutex_enter(&sp_rp->sp_lock);
				spcp_sidp = sp_rp->sp_backlog[i].spcp_sid;
				sp_rp->sp_backlog[i].spcp_state =
				    DAPLKA_SPCP_INIT;
				sp_rp->sp_backlog[i].spcp_sid = NULL;
				sp_rp->sp_backlog[i].spcp_req_len = 0;
				mutex_exit(&sp_rp->sp_lock);
				status = ibt_cm_proceed(IBT_CM_EVENT_REQ_RCV,
				    spcp_sidp,
				    IBT_CM_NO_RESOURCE, &proc_reply, NULL, 0);
				if (status != IBT_SUCCESS) {
					DERR("sp_destroy: proceed failed %d\n",
					    status);
				}
			}
		}
		if (cnt > 0) {
			DERR("sp_destroy: found %d pending "
			    "connections\n", cnt);
		}
	}

	if (sp_rp->sp_srv_hdl != NULL && sp_rp->sp_bind_hdl != NULL) {
		status = ibt_unbind_service(sp_rp->sp_srv_hdl,
		    sp_rp->sp_bind_hdl);
		if (status != IBT_SUCCESS) {
			DERR("sp_destroy: ibt_unbind_service "
			    "failed: %d\n", status);
		}
	}

	if (sp_rp->sp_srv_hdl != NULL) {
		status = ibt_deregister_service(daplka_dev->daplka_clnt_hdl,
		    sp_rp->sp_srv_hdl);
		if (status != IBT_SUCCESS) {
			DERR("sp_destroy: ibt_deregister_service "
			    "failed: %d\n", status);
		}
	}
	if (sp_rp->sp_backlog != NULL) {
		kmem_free(sp_rp->sp_backlog,
		    sp_rp->sp_backlog_size * sizeof (daplka_sp_conn_pend_t));
		sp_rp->sp_backlog = NULL;
		sp_rp->sp_backlog_size = 0;
	}

	/*
	 * release reference to evd
	 */
	if (sp_rp->sp_evd_res != NULL) {
		DAPLKA_RS_UNREF(sp_rp->sp_evd_res);
	}
	sp_rp->sp_bind_hdl = NULL;
	sp_rp->sp_srv_hdl = NULL;
	DAPLKA_RS_FINI(sp_rp);
	kmem_free(sp_rp, sizeof (*sp_rp));
	D3("sp_destroy: exiting, sp_rp %p\n", sp_rp);
	return (0);
}

/*
 * this function is called by daplka_hash_destroy for
 * freeing SP resource objects
 */
static void
daplka_hash_sp_free(void *obj)
{
	daplka_sp_resource_t *sp_rp = (daplka_sp_resource_t *)obj;
	daplka_sp_resource_t *g_sp_rp;
	int retval;

	ASSERT(DAPLKA_RS_TYPE(sp_rp) == DAPL_TYPE_SP);

	retval = daplka_hash_remove(&daplka_global_sp_htbl,
	    sp_rp->sp_global_hkey, (void **)&g_sp_rp);
	if (retval != 0 || g_sp_rp == NULL) {
		DERR("sp_free: cannot find sp resource\n");
	}
	if (g_sp_rp == sp_rp) {
		DAPLKA_RS_UNREF(g_sp_rp);
	}

	DAPLKA_RS_UNREF(sp_rp);
}

static void
daplka_hash_sp_unref(void *obj)
{
	daplka_sp_resource_t *sp_rp = (daplka_sp_resource_t *)obj;

	ASSERT(DAPLKA_RS_TYPE(sp_rp) == DAPL_TYPE_SP);
	DAPLKA_RS_UNREF(sp_rp);
}

/*
 * Passive side CM handlers
 */

/*
 * processes the REQ_RCV event
 */
/* ARGSUSED */
static ibt_cm_status_t
daplka_cm_service_req(daplka_sp_resource_t *spp, ibt_cm_event_t *event,
    ibt_cm_return_args_t *ret_args, void *pr_data, ibt_priv_data_len_t pr_len)
{
	daplka_sp_conn_pend_t	*conn = NULL;
	daplka_evd_event_t	*cr_ev = NULL;
	ibt_cm_status_t		cm_status = IBT_CM_DEFAULT;
	uint16_t		bkl_index;
	ibt_status_t		status;

	/*
	 * acquire a slot in the connection backlog of this service point
	 */
	mutex_enter(&spp->sp_lock);
	for (bkl_index = 0; bkl_index < spp->sp_backlog_size; bkl_index++) {
		if (spp->sp_backlog[bkl_index].spcp_state == DAPLKA_SPCP_INIT) {
			conn = &spp->sp_backlog[bkl_index];
			ASSERT(conn->spcp_sid == NULL);
			conn->spcp_state = DAPLKA_SPCP_PENDING;
			conn->spcp_sid = event->cm_session_id;
			break;
		}
	}
	mutex_exit(&spp->sp_lock);

	/*
	 * too many pending connections
	 */
	if (bkl_index == spp->sp_backlog_size) {
		DERR("service_req: connection pending exceeded %d limit\n",
		    spp->sp_backlog_size);
		return (IBT_CM_NO_RESOURCE);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*conn))

	/*
	 * save data for cr_handoff
	 */
	if (pr_data != NULL && pr_len > 0) {
		int trunc_len = pr_len;

		if (trunc_len > DAPL_MAX_PRIVATE_DATA_SIZE) {
			DERR("service_req: private data truncated\n");
			trunc_len = DAPL_MAX_PRIVATE_DATA_SIZE;
		}
		conn->spcp_req_len = trunc_len;
		bcopy(pr_data, conn->spcp_req_data, trunc_len);
	} else {
		conn->spcp_req_len = 0;
	}
	conn->spcp_rdma_ra_in = event->cm_event.req.req_rdma_ra_in;
	conn->spcp_rdma_ra_out = event->cm_event.req.req_rdma_ra_out;

	/*
	 * create a CR event
	 */
	cr_ev = kmem_zalloc(sizeof (daplka_evd_event_t), KM_NOSLEEP);
	if (cr_ev == NULL) {
		DERR("service_req: could not alloc cr_ev\n");
		cm_status = IBT_CM_NO_RESOURCE;
		goto cleanup;
	}

	cr_ev->ee_next = NULL;
	cr_ev->ee_cmev.ec_cm_cookie = spp->sp_cookie;
	cr_ev->ee_cmev.ec_cm_is_passive = B_TRUE;
	cr_ev->ee_cmev.ec_cm_psep_cookie = DAPLKA_CREATE_PSEP_COOKIE(bkl_index);
	/*
	 * save the requestor gid
	 * daplka_event_poll needs this if this is a third party REQ_RCV
	 */
	cr_ev->ee_cmev.ec_cm_req_prim_addr.gid_prefix =
	    event->cm_event.req.req_prim_addr.av_dgid.gid_prefix;
	cr_ev->ee_cmev.ec_cm_req_prim_addr.gid_guid =
	    event->cm_event.req.req_prim_addr.av_dgid.gid_guid;

	/*
	 * set event type
	 */
	if (pr_len == 0) {
		cr_ev->ee_cmev.ec_cm_ev_type =
		    DAPL_IB_CME_CONNECTION_REQUEST_PENDING;
	} else {
		cr_ev->ee_cmev.ec_cm_ev_priv_data =
		    kmem_zalloc(pr_len, KM_NOSLEEP);
		if (cr_ev->ee_cmev.ec_cm_ev_priv_data == NULL) {
			DERR("service_req: could not alloc priv\n");
			cm_status = IBT_CM_NO_RESOURCE;
			goto cleanup;
		}
		bcopy(pr_data, cr_ev->ee_cmev.ec_cm_ev_priv_data, pr_len);
		cr_ev->ee_cmev.ec_cm_ev_type =
		    DAPL_IB_CME_CONNECTION_REQUEST_PENDING_PRIVATE_DATA;
	}
	cr_ev->ee_cmev.ec_cm_ev_priv_data_len = pr_len;

	/*
	 * tell the active side to expect the processing time to be
	 * at most equal to daplka_cm_delay
	 */
	status = ibt_cm_delay(IBT_CM_DELAY_REQ, event->cm_session_id,
	    daplka_cm_delay, NULL, 0);
	if (status != IBT_SUCCESS) {
		DERR("service_req: ibt_cm_delay failed %d\n", status);
		cm_status = IBT_CM_NO_RESOURCE;
		goto cleanup;
	}

	/*
	 * enqueue cr_ev onto the cr_events list of the EVD
	 * corresponding to the SP
	 */
	D2("service_req: enqueue event(%p) evdp(%p) priv_data(%p) "
	    "priv_len(%d) psep(0x%llx)\n", cr_ev, spp->sp_evd_res,
	    cr_ev->ee_cmev.ec_cm_ev_priv_data,
	    (int)cr_ev->ee_cmev.ec_cm_ev_priv_data_len,
	    (longlong_t)cr_ev->ee_cmev.ec_cm_psep_cookie);

	daplka_evd_wakeup(spp->sp_evd_res,
	    &spp->sp_evd_res->evd_cr_events, cr_ev);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*conn))
	return (IBT_CM_DEFER);

cleanup:;
	/*
	 * free the cr event
	 */
	if (cr_ev != NULL) {
		if (cr_ev->ee_cmev.ec_cm_ev_priv_data != NULL) {
			kmem_free(cr_ev->ee_cmev.ec_cm_ev_priv_data, pr_len);
			cr_ev->ee_cmev.ec_cm_ev_priv_data = NULL;
			cr_ev->ee_cmev.ec_cm_ev_priv_data_len = 0;
		}
		kmem_free(cr_ev, sizeof (daplka_evd_event_t));
	}
	/*
	 * release our slot in the backlog array
	 */
	if (conn != NULL) {
		mutex_enter(&spp->sp_lock);
		ASSERT(conn->spcp_state == DAPLKA_SPCP_PENDING);
		ASSERT(conn->spcp_sid == event->cm_session_id);
		conn->spcp_state = DAPLKA_SPCP_INIT;
		conn->spcp_req_len = 0;
		conn->spcp_sid = NULL;
		mutex_exit(&spp->sp_lock);
	}
	return (cm_status);
}

/*
 * processes the CONN_CLOSED event
 */
/* ARGSUSED */
static ibt_cm_status_t
daplka_cm_service_conn_closed(daplka_sp_resource_t *sp_rp,
    ibt_cm_event_t *event, ibt_cm_return_args_t *ret_args,
    void *priv_data, ibt_priv_data_len_t len)
{
	daplka_ep_resource_t	*ep_rp;
	daplka_evd_event_t	*disc_ev;
	uint32_t		old_state, new_state;

	ep_rp = (daplka_ep_resource_t *)
	    ibt_get_chan_private(event->cm_channel);
	if (ep_rp == NULL) {
		DERR("service_conn_closed: ep_rp == NULL\n");
		return (IBT_CM_ACCEPT);
	}

	/*
	 * verify that the ep_state is either CONNECTED or
	 * DISCONNECTING. if it is not in either states return
	 * without generating an event.
	 */
	new_state = old_state = daplka_ep_get_state(ep_rp);
	if (old_state != DAPLKA_EP_STATE_CONNECTED &&
	    old_state != DAPLKA_EP_STATE_DISCONNECTING) {
		/*
		 * we can get here if the connection is being aborted
		 */
		D2("service_conn_closed: conn aborted, state = %d, "
		    "closed = %d\n", old_state, (int)event->cm_event.closed);
		daplka_ep_set_state(ep_rp, old_state, new_state);
		return (IBT_CM_ACCEPT);
	}

	/*
	 * create a DAPL_IB_CME_DISCONNECTED event
	 */
	disc_ev = kmem_zalloc(sizeof (daplka_evd_event_t), KM_NOSLEEP);
	if (disc_ev == NULL) {
		DERR("service_conn_closed: cannot alloc disc_ev\n");
		daplka_ep_set_state(ep_rp, old_state, new_state);
		return (IBT_CM_ACCEPT);
	}

	disc_ev->ee_cmev.ec_cm_ev_type = DAPL_IB_CME_DISCONNECTED;
	disc_ev->ee_cmev.ec_cm_cookie = sp_rp->sp_cookie;
	disc_ev->ee_cmev.ec_cm_is_passive = B_TRUE;
	disc_ev->ee_cmev.ec_cm_psep_cookie = ep_rp->ep_psep_cookie;
	disc_ev->ee_cmev.ec_cm_ev_priv_data = NULL;
	disc_ev->ee_cmev.ec_cm_ev_priv_data_len = 0;

	D2("service_conn_closed: enqueue event(%p) evdp(%p) psep(0x%llx)\n",
	    disc_ev, sp_rp->sp_evd_res, (longlong_t)ep_rp->ep_psep_cookie);

	/*
	 * transition ep_state to DISCONNECTED
	 */
	new_state = DAPLKA_EP_STATE_DISCONNECTED;
	daplka_ep_set_state(ep_rp, old_state, new_state);

	/*
	 * enqueue event onto the conn_evd owned by ep_rp
	 */
	daplka_evd_wakeup(ep_rp->ep_conn_evd,
	    &ep_rp->ep_conn_evd->evd_conn_events, disc_ev);

	return (IBT_CM_ACCEPT);
}

/*
 * processes the CONN_EST event
 */
/* ARGSUSED */
static ibt_cm_status_t
daplka_cm_service_conn_est(daplka_sp_resource_t *sp_rp, ibt_cm_event_t *event,
    ibt_cm_return_args_t *ret_args, void *priv_data, ibt_priv_data_len_t len)
{
	daplka_ep_resource_t	*ep_rp;
	daplka_evd_event_t	*conn_ev;
	void			*pr_data = event->cm_priv_data;
	ibt_priv_data_len_t	pr_len = event->cm_priv_data_len;
	uint32_t		old_state, new_state;

	ep_rp = (daplka_ep_resource_t *)
	    ibt_get_chan_private(event->cm_channel);
	if (ep_rp == NULL) {
		DERR("service_conn_est: ep_rp == NULL\n");
		return (IBT_CM_ACCEPT);
	}

	/*
	 * verify that ep_state is ACCEPTING. if it is not in this
	 * state, return without generating an event.
	 */
	new_state = old_state = daplka_ep_get_state(ep_rp);
	if (old_state != DAPLKA_EP_STATE_ACCEPTING) {
		/*
		 * we can get here if the connection is being aborted
		 */
		DERR("service_conn_est: conn aborted, state = %d\n",
		    old_state);
		daplka_ep_set_state(ep_rp, old_state, new_state);
		return (IBT_CM_ACCEPT);
	}

	/*
	 * create a DAPL_IB_CME_CONNECTED event
	 */
	conn_ev = kmem_zalloc(sizeof (daplka_evd_event_t), KM_NOSLEEP);
	if (conn_ev == NULL) {
		DERR("service_conn_est: conn_ev alloc failed\n");
		daplka_ep_set_state(ep_rp, old_state, new_state);
		return (IBT_CM_ACCEPT);
	}

	conn_ev->ee_cmev.ec_cm_ev_type = DAPL_IB_CME_CONNECTED;
	conn_ev->ee_cmev.ec_cm_cookie = sp_rp->sp_cookie;
	conn_ev->ee_cmev.ec_cm_is_passive = B_TRUE;
	conn_ev->ee_cmev.ec_cm_psep_cookie = ep_rp->ep_psep_cookie;

	/*
	 * copy private data into event
	 */
	if (pr_len > 0) {
		conn_ev->ee_cmev.ec_cm_ev_priv_data =
		    kmem_zalloc(pr_len, KM_NOSLEEP);
		if (conn_ev->ee_cmev.ec_cm_ev_priv_data == NULL) {
			DERR("service_conn_est: pr_data alloc failed\n");
			daplka_ep_set_state(ep_rp, old_state, new_state);
			kmem_free(conn_ev, sizeof (daplka_evd_event_t));
			return (IBT_CM_ACCEPT);
		}
		bcopy(pr_data, conn_ev->ee_cmev.ec_cm_ev_priv_data, pr_len);
	}
	conn_ev->ee_cmev.ec_cm_ev_priv_data_len = pr_len;

	D2("service_conn_est: enqueue event(%p) evdp(%p)\n",
	    conn_ev, ep_rp->ep_conn_evd);

	/*
	 * transition ep_state to CONNECTED
	 */
	new_state = DAPLKA_EP_STATE_CONNECTED;
	daplka_ep_set_state(ep_rp, old_state, new_state);

	/*
	 * enqueue event onto the conn_evd owned by ep_rp
	 */
	daplka_evd_wakeup(ep_rp->ep_conn_evd,
	    &ep_rp->ep_conn_evd->evd_conn_events, conn_ev);

	return (IBT_CM_ACCEPT);
}

/*
 * processes the FAILURE event
 */
/* ARGSUSED */
static ibt_cm_status_t
daplka_cm_service_event_failure(daplka_sp_resource_t *sp_rp,
    ibt_cm_event_t *event, ibt_cm_return_args_t *ret_args, void *priv_data,
    ibt_priv_data_len_t len)
{
	daplka_evd_event_t	*disc_ev;
	daplka_ep_resource_t	*ep_rp;
	uint32_t		old_state, new_state;
	ibt_rc_chan_query_attr_t chan_attrs;
	ibt_status_t		status;

	/*
	 * check that we still have a valid cm_channel before continuing
	 */
	if (event->cm_channel == NULL) {
		DERR("serice_event_failure: event->cm_channel == NULL\n");
		return (IBT_CM_ACCEPT);
	}
	ep_rp = (daplka_ep_resource_t *)
	    ibt_get_chan_private(event->cm_channel);
	if (ep_rp == NULL) {
		DERR("service_event_failure: ep_rp == NULL\n");
		return (IBT_CM_ACCEPT);
	}

	/*
	 * verify that ep_state is ACCEPTING or DISCONNECTING. if it
	 * is not in either state, return without generating an event.
	 */
	new_state = old_state = daplka_ep_get_state(ep_rp);
	if (old_state != DAPLKA_EP_STATE_ACCEPTING &&
	    old_state != DAPLKA_EP_STATE_DISCONNECTING) {
		/*
		 * we can get here if the connection is being aborted
		 */
		DERR("service_event_failure: conn aborted, state = %d, "
		    "cf_code = %d, cf_msg = %d, cf_reason = %d\n", old_state,
		    (int)event->cm_event.failed.cf_code,
		    (int)event->cm_event.failed.cf_msg,
		    (int)event->cm_event.failed.cf_reason);

		daplka_ep_set_state(ep_rp, old_state, new_state);
		return (IBT_CM_ACCEPT);
	}

	bzero(&chan_attrs, sizeof (ibt_rc_chan_query_attr_t));
	status = ibt_query_rc_channel(ep_rp->ep_chan_hdl, &chan_attrs);

	if ((status == IBT_SUCCESS) &&
	    (chan_attrs.rc_state != IBT_STATE_ERROR)) {
		DERR("service_event_failure: conn abort qpn %d state %d\n",
		    chan_attrs.rc_qpn, chan_attrs.rc_state);

		/* explicit transition the QP to ERROR state */
		status = ibt_flush_channel(ep_rp->ep_chan_hdl);
	}

	/*
	 * create an event
	 */
	disc_ev = kmem_zalloc(sizeof (daplka_evd_event_t), KM_NOSLEEP);
	if (disc_ev == NULL) {
		DERR("service_event_failure: cannot alloc disc_ev\n");
		daplka_ep_set_state(ep_rp, old_state, new_state);
		return (IBT_CM_ACCEPT);
	}

	/*
	 * fill in the appropriate event type
	 */
	if (event->cm_event.failed.cf_code == IBT_CM_FAILURE_TIMEOUT) {
		disc_ev->ee_cmev.ec_cm_ev_type = DAPL_IB_CME_TIMED_OUT;
	} else if (event->cm_event.failed.cf_code == IBT_CM_FAILURE_REJ_RCV) {
		switch (event->cm_event.failed.cf_reason) {
		case IBT_CM_INVALID_CID:
			disc_ev->ee_cmev.ec_cm_ev_type =
			    DAPL_IB_CME_DESTINATION_REJECT;
			break;
		default:
			disc_ev->ee_cmev.ec_cm_ev_type =
			    DAPL_IB_CME_LOCAL_FAILURE;
			break;
		}
	} else {
		disc_ev->ee_cmev.ec_cm_ev_type = DAPL_IB_CME_LOCAL_FAILURE;
	}
	disc_ev->ee_cmev.ec_cm_cookie = sp_rp->sp_cookie;
	disc_ev->ee_cmev.ec_cm_is_passive = B_TRUE;
	disc_ev->ee_cmev.ec_cm_psep_cookie = ep_rp->ep_psep_cookie;
	disc_ev->ee_cmev.ec_cm_ev_priv_data_len = 0;
	disc_ev->ee_cmev.ec_cm_ev_priv_data = NULL;

	D2("service_event_failure: enqueue event(%p) evdp(%p) cf_code(%d) "
	    "cf_msg(%d) cf_reason(%d) psep(0x%llx)\n", disc_ev,
	    ep_rp->ep_conn_evd, (int)event->cm_event.failed.cf_code,
	    (int)event->cm_event.failed.cf_msg,
	    (int)event->cm_event.failed.cf_reason,
	    (longlong_t)ep_rp->ep_psep_cookie);

	/*
	 * transition ep_state to DISCONNECTED
	 */
	new_state = DAPLKA_EP_STATE_DISCONNECTED;
	daplka_ep_set_state(ep_rp, old_state, new_state);

	/*
	 * enqueue event onto the conn_evd owned by ep_rp
	 */
	daplka_evd_wakeup(ep_rp->ep_conn_evd,
	    &ep_rp->ep_conn_evd->evd_conn_events, disc_ev);

	return (IBT_CM_ACCEPT);
}

/*
 * this is the passive side CM handler. it gets registered
 * when an SP resource is created in daplka_service_register.
 */
static ibt_cm_status_t
daplka_cm_service_handler(void *cm_private, ibt_cm_event_t *event,
ibt_cm_return_args_t *ret_args, void *priv_data, ibt_priv_data_len_t len)
{
	daplka_sp_resource_t	*sp_rp = (daplka_sp_resource_t *)cm_private;

	if (sp_rp == NULL) {
		DERR("service_handler: sp_rp == NULL\n");
		return (IBT_CM_NO_RESOURCE);
	}
	/*
	 * default is not to return priv data
	 */
	if (ret_args != NULL) {
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ret_args))
		ret_args->cm_ret_len = 0;
	}

	switch (event->cm_type) {
	case IBT_CM_EVENT_REQ_RCV:
		D2("service_handler: IBT_CM_EVENT_REQ_RCV\n");
		return (daplka_cm_service_req(sp_rp, event, ret_args,
		    event->cm_priv_data, event->cm_priv_data_len));

	case IBT_CM_EVENT_REP_RCV:
		/* passive side should not receive this event */
		D2("service_handler: IBT_CM_EVENT_REP_RCV\n");
		return (IBT_CM_DEFAULT);

	case IBT_CM_EVENT_CONN_CLOSED:
		D2("service_handler: IBT_CM_EVENT_CONN_CLOSED %d\n",
		    event->cm_event.closed);
		return (daplka_cm_service_conn_closed(sp_rp, event, ret_args,
		    priv_data, len));

	case IBT_CM_EVENT_MRA_RCV:
		/* passive side does default processing MRA event */
		D2("service_handler: IBT_CM_EVENT_MRA_RCV\n");
		return (IBT_CM_DEFAULT);

	case IBT_CM_EVENT_CONN_EST:
		D2("service_handler: IBT_CM_EVENT_CONN_EST\n");
		return (daplka_cm_service_conn_est(sp_rp, event, ret_args,
		    priv_data, len));

	case IBT_CM_EVENT_FAILURE:
		D2("service_handler: IBT_CM_EVENT_FAILURE\n");
		return (daplka_cm_service_event_failure(sp_rp, event, ret_args,
		    priv_data, len));
	case IBT_CM_EVENT_LAP_RCV:
		/* active side had initiated a path migration operation */
		D2("service_handler: IBT_CM_EVENT_LAP_RCV\n");
		return (IBT_CM_ACCEPT);
	default:
		DERR("service_handler: invalid event %d\n", event->cm_type);
		break;
	}
	return (IBT_CM_DEFAULT);
}

/*
 * Active side CM handlers
 */

/*
 * Processes the REP_RCV event. When the passive side accepts the
 * connection, this handler is called. We make a copy of the private
 * data into the ep so that it can be passed back to userland in when
 * the CONN_EST event occurs.
 */
/* ARGSUSED */
static ibt_cm_status_t
daplka_cm_rc_rep_rcv(daplka_ep_resource_t *ep_rp, ibt_cm_event_t *event,
    ibt_cm_return_args_t *ret_args, void *priv_data, ibt_priv_data_len_t len)
{
	void			*pr_data = event->cm_priv_data;
	ibt_priv_data_len_t	pr_len = event->cm_priv_data_len;
	uint32_t		old_state, new_state;

	D2("rc_rep_rcv: pr_data(0x%p), pr_len(%d)\n", pr_data,
	    (int)pr_len);

	ASSERT(ep_rp != NULL);
	new_state = old_state = daplka_ep_get_state(ep_rp);
	if (old_state != DAPLKA_EP_STATE_CONNECTING) {
		/*
		 * we can get here if the connection is being aborted
		 */
		DERR("rc_rep_rcv: conn aborted, state = %d\n", old_state);
		daplka_ep_set_state(ep_rp, old_state, new_state);
		return (IBT_CM_NO_CHANNEL);
	}

	/*
	 * we do not cancel the timer here because the connection
	 * handshake is still in progress.
	 */

	/*
	 * save the private data. it will be passed up when
	 * the connection is established.
	 */
	if (pr_len > 0) {
		ep_rp->ep_priv_len = pr_len;
		bcopy(pr_data, ep_rp->ep_priv_data, (size_t)pr_len);
	}

	/*
	 * we do not actually transition to a different state.
	 * the state will change when we get a conn_est, failure,
	 * closed, or timeout event.
	 */
	daplka_ep_set_state(ep_rp, old_state, new_state);
	return (IBT_CM_ACCEPT);
}

/*
 * Processes the CONN_CLOSED event. This gets called when either
 * the active or passive side closes the rc channel.
 */
/* ARGSUSED */
static ibt_cm_status_t
daplka_cm_rc_conn_closed(daplka_ep_resource_t *ep_rp, ibt_cm_event_t *event,
    ibt_cm_return_args_t *ret_args, void *priv_data, ibt_priv_data_len_t len)
{
	daplka_evd_event_t	*disc_ev;
	uint32_t		old_state, new_state;

	ASSERT(ep_rp != NULL);
	old_state = new_state = daplka_ep_get_state(ep_rp);
	if (old_state != DAPLKA_EP_STATE_CONNECTED &&
	    old_state != DAPLKA_EP_STATE_DISCONNECTING) {
		/*
		 * we can get here if the connection is being aborted
		 */
		D2("rc_conn_closed: conn aborted, state = %d, "
		    "closed = %d\n", old_state, (int)event->cm_event.closed);
		daplka_ep_set_state(ep_rp, old_state, new_state);
		return (IBT_CM_ACCEPT);
	}

	/*
	 * it's ok for the timer to fire at this point. the
	 * taskq thread that processes the timer will just wait
	 * until we are done with our state transition.
	 */
	if (daplka_cancel_timer(ep_rp) != 0) {
		/*
		 * daplka_cancel_timer returns -1 if the timer is
		 * being processed and 0 for all other cases.
		 * we need to reset ep_state to allow timer processing
		 * to continue.
		 */
		DERR("rc_conn_closed: timer is being processed\n");
		daplka_ep_set_state(ep_rp, old_state, new_state);
		return (IBT_CM_ACCEPT);
	}

	/*
	 * create a DAPL_IB_CME_DISCONNECTED event
	 */
	disc_ev = kmem_zalloc(sizeof (daplka_evd_event_t), KM_NOSLEEP);
	if (disc_ev == NULL) {
		DERR("rc_conn_closed: could not alloc ev\n");
		daplka_ep_set_state(ep_rp, old_state, new_state);
		return (IBT_CM_ACCEPT);
	}

	disc_ev->ee_cmev.ec_cm_ev_type = DAPL_IB_CME_DISCONNECTED;
	disc_ev->ee_cmev.ec_cm_cookie = ep_rp->ep_cookie;
	disc_ev->ee_cmev.ec_cm_is_passive = B_FALSE;
	disc_ev->ee_cmev.ec_cm_psep_cookie = 0;
	disc_ev->ee_cmev.ec_cm_ev_priv_data = NULL;
	disc_ev->ee_cmev.ec_cm_ev_priv_data_len = 0;

	D2("rc_conn_closed: enqueue event(%p) evdp(%p) closed(%d)\n",
	    disc_ev, ep_rp->ep_conn_evd, (int)event->cm_event.closed);

	/*
	 * transition ep_state to DISCONNECTED
	 */
	new_state = DAPLKA_EP_STATE_DISCONNECTED;
	daplka_ep_set_state(ep_rp, old_state, new_state);

	/*
	 * enqueue event onto the conn_evd owned by ep_rp
	 */
	daplka_evd_wakeup(ep_rp->ep_conn_evd,
	    &ep_rp->ep_conn_evd->evd_conn_events, disc_ev);

	return (IBT_CM_ACCEPT);
}

/*
 * processes the CONN_EST event
 */
/* ARGSUSED */
static ibt_cm_status_t
daplka_cm_rc_conn_est(daplka_ep_resource_t *ep_rp, ibt_cm_event_t *event,
    ibt_cm_return_args_t *ret_args, void *priv_data, ibt_priv_data_len_t len)
{
	daplka_evd_event_t	*conn_ev;
	uint32_t		old_state, new_state;

	ASSERT(ep_rp != NULL);
	old_state = new_state = daplka_ep_get_state(ep_rp);
	if (old_state != DAPLKA_EP_STATE_CONNECTING) {
		/*
		 * we can get here if the connection is being aborted
		 */
		DERR("rc_conn_est: conn aborted, state = %d\n", old_state);
		daplka_ep_set_state(ep_rp, old_state, new_state);
		return (IBT_CM_ACCEPT);
	}

	/*
	 * it's ok for the timer to fire at this point. the
	 * taskq thread that processes the timer will just wait
	 * until we are done with our state transition.
	 */
	if (daplka_cancel_timer(ep_rp) != 0) {
		/*
		 * daplka_cancel_timer returns -1 if the timer is
		 * being processed and 0 for all other cases.
		 * we need to reset ep_state to allow timer processing
		 * to continue.
		 */
		DERR("rc_conn_est: timer is being processed\n");
		daplka_ep_set_state(ep_rp, old_state, new_state);
		return (IBT_CM_ACCEPT);
	}

	/*
	 * create a DAPL_IB_CME_CONNECTED event
	 */
	conn_ev = kmem_zalloc(sizeof (daplka_evd_event_t), KM_NOSLEEP);
	if (conn_ev == NULL) {
		DERR("rc_conn_est: could not alloc ev\n");
		daplka_ep_set_state(ep_rp, old_state, new_state);
		return (IBT_CM_ACCEPT);
	}

	conn_ev->ee_cmev.ec_cm_ev_type = DAPL_IB_CME_CONNECTED;
	conn_ev->ee_cmev.ec_cm_cookie = ep_rp->ep_cookie;
	conn_ev->ee_cmev.ec_cm_is_passive = B_FALSE;
	conn_ev->ee_cmev.ec_cm_psep_cookie = 0;

	/*
	 * The private data passed back in the connection established
	 * event is what was recvd in the daplka_cm_rc_rep_rcv handler and
	 * saved in ep resource structure.
	 */
	if (ep_rp->ep_priv_len > 0) {
		conn_ev->ee_cmev.ec_cm_ev_priv_data =
		    kmem_zalloc(ep_rp->ep_priv_len, KM_NOSLEEP);

		if (conn_ev->ee_cmev.ec_cm_ev_priv_data == NULL) {
			DERR("rc_conn_est: could not alloc pr_data\n");
			kmem_free(conn_ev, sizeof (daplka_evd_event_t));
			daplka_ep_set_state(ep_rp, old_state, new_state);
			return (IBT_CM_ACCEPT);
		}
		bcopy(ep_rp->ep_priv_data, conn_ev->ee_cmev.ec_cm_ev_priv_data,
		    ep_rp->ep_priv_len);
	}
	conn_ev->ee_cmev.ec_cm_ev_priv_data_len = ep_rp->ep_priv_len;

	D2("rc_conn_est: enqueue event(%p) evdp(%p) pr_data(0x%p), "
	    "pr_len(%d)\n", conn_ev, ep_rp->ep_conn_evd,
	    conn_ev->ee_cmev.ec_cm_ev_priv_data,
	    (int)conn_ev->ee_cmev.ec_cm_ev_priv_data_len);

	/*
	 * transition ep_state to CONNECTED
	 */
	new_state = DAPLKA_EP_STATE_CONNECTED;
	daplka_ep_set_state(ep_rp, old_state, new_state);

	/*
	 * enqueue event onto the conn_evd owned by ep_rp
	 */
	daplka_evd_wakeup(ep_rp->ep_conn_evd,
	    &ep_rp->ep_conn_evd->evd_conn_events, conn_ev);

	return (IBT_CM_ACCEPT);
}

/*
 * processes the FAILURE event
 */
/* ARGSUSED */
static ibt_cm_status_t
daplka_cm_rc_event_failure(daplka_ep_resource_t *ep_rp, ibt_cm_event_t *event,
    ibt_cm_return_args_t *ret_args, void *priv_data, ibt_priv_data_len_t len)
{
	daplka_evd_event_t	*disc_ev;
	ibt_priv_data_len_t	pr_len = event->cm_priv_data_len;
	void			*pr_data = event->cm_priv_data;
	uint32_t		old_state, new_state;
	ibt_rc_chan_query_attr_t chan_attrs;
	ibt_status_t		status;

	ASSERT(ep_rp != NULL);
	old_state = new_state = daplka_ep_get_state(ep_rp);
	if (old_state != DAPLKA_EP_STATE_CONNECTING &&
	    old_state != DAPLKA_EP_STATE_DISCONNECTING) {
		/*
		 * we can get here if the connection is being aborted
		 */
		DERR("rc_event_failure: conn aborted, state = %d, "
		    "cf_code = %d, cf_msg = %d, cf_reason = %d\n", old_state,
		    (int)event->cm_event.failed.cf_code,
		    (int)event->cm_event.failed.cf_msg,
		    (int)event->cm_event.failed.cf_reason);

		daplka_ep_set_state(ep_rp, old_state, new_state);
		return (IBT_CM_ACCEPT);
	}

	/*
	 * it's ok for the timer to fire at this point. the
	 * taskq thread that processes the timer will just wait
	 * until we are done with our state transition.
	 */
	if (daplka_cancel_timer(ep_rp) != 0) {
		/*
		 * daplka_cancel_timer returns -1 if the timer is
		 * being processed and 0 for all other cases.
		 * we need to reset ep_state to allow timer processing
		 * to continue.
		 */
		DERR("rc_event_failure: timer is being processed\n");
		daplka_ep_set_state(ep_rp, old_state, new_state);
		return (IBT_CM_ACCEPT);
	}

	bzero(&chan_attrs, sizeof (ibt_rc_chan_query_attr_t));
	status = ibt_query_rc_channel(ep_rp->ep_chan_hdl, &chan_attrs);

	if ((status == IBT_SUCCESS) &&
	    (chan_attrs.rc_state != IBT_STATE_ERROR)) {
		DERR("rc_event_failure: conn abort qpn %d state %d\n",
		    chan_attrs.rc_qpn, chan_attrs.rc_state);

		/* explicit transition the QP to ERROR state */
		status = ibt_flush_channel(ep_rp->ep_chan_hdl);
	}

	/*
	 * create an event
	 */
	disc_ev = kmem_zalloc(sizeof (daplka_evd_event_t), KM_NOSLEEP);
	if (disc_ev == NULL) {
		DERR("rc_event_failure: cannot alloc disc_ev\n");
		daplka_ep_set_state(ep_rp, old_state, new_state);
		return (IBT_CM_ACCEPT);
	}

	/*
	 * copy private data into event
	 */
	if (pr_len > 0) {
		disc_ev->ee_cmev.ec_cm_ev_priv_data =
		    kmem_zalloc(pr_len, KM_NOSLEEP);

		if (disc_ev->ee_cmev.ec_cm_ev_priv_data == NULL) {
			DERR("rc_event_failure: cannot alloc pr data\n");
			kmem_free(disc_ev, sizeof (daplka_evd_event_t));
			daplka_ep_set_state(ep_rp, old_state, new_state);
			return (IBT_CM_ACCEPT);
		}
		bcopy(pr_data, disc_ev->ee_cmev.ec_cm_ev_priv_data, pr_len);
	}
	disc_ev->ee_cmev.ec_cm_ev_priv_data_len = pr_len;

	/*
	 * fill in the appropriate event type
	 */
	if (event->cm_event.failed.cf_code == IBT_CM_FAILURE_REJ_RCV) {
		switch (event->cm_event.failed.cf_reason) {
		case IBT_CM_CONSUMER:
			disc_ev->ee_cmev.ec_cm_ev_type =
			    DAPL_IB_CME_DESTINATION_REJECT_PRIVATE_DATA;
			break;
		case IBT_CM_NO_CHAN:
		case IBT_CM_NO_RESC:
			disc_ev->ee_cmev.ec_cm_ev_type =
			    DAPL_IB_CME_DESTINATION_REJECT;
			break;
		default:
			disc_ev->ee_cmev.ec_cm_ev_type =
			    DAPL_IB_CME_DESTINATION_REJECT;
			break;
		}
	} else if (event->cm_event.failed.cf_code == IBT_CM_FAILURE_TIMEOUT) {
		disc_ev->ee_cmev.ec_cm_ev_type = DAPL_IB_CME_TIMED_OUT;
	} else {
		/* others we'll mark as local failure */
		disc_ev->ee_cmev.ec_cm_ev_type = DAPL_IB_CME_LOCAL_FAILURE;
	}
	disc_ev->ee_cmev.ec_cm_cookie = ep_rp->ep_cookie;
	disc_ev->ee_cmev.ec_cm_is_passive = B_FALSE;
	disc_ev->ee_cmev.ec_cm_psep_cookie = 0;

	D2("rc_event_failure: enqueue event(%p) evdp(%p) cf_code(%d) "
	    "cf_msg(%d) cf_reason(%d)\n", disc_ev, ep_rp->ep_conn_evd,
	    (int)event->cm_event.failed.cf_code,
	    (int)event->cm_event.failed.cf_msg,
	    (int)event->cm_event.failed.cf_reason);

	/*
	 * transition ep_state to DISCONNECTED
	 */
	new_state = DAPLKA_EP_STATE_DISCONNECTED;
	daplka_ep_set_state(ep_rp, old_state, new_state);

	/*
	 * enqueue event onto the conn_evd owned by ep_rp
	 */
	daplka_evd_wakeup(ep_rp->ep_conn_evd,
	    &ep_rp->ep_conn_evd->evd_conn_events, disc_ev);

	return (IBT_CM_ACCEPT);
}

/*
 * This is the active side CM handler. It gets registered when
 * ibt_open_rc_channel is called.
 */
static ibt_cm_status_t
daplka_cm_rc_handler(void *cm_private, ibt_cm_event_t *event,
    ibt_cm_return_args_t *ret_args, void *priv_data, ibt_priv_data_len_t len)
{
	daplka_ep_resource_t *ep_rp = (daplka_ep_resource_t *)cm_private;

	if (ep_rp == NULL) {
		DERR("rc_handler: ep_rp == NULL\n");
		return (IBT_CM_NO_CHANNEL);
	}
	/*
	 * default is not to return priv data
	 */
	if (ret_args != NULL) {
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ret_args))
		ret_args->cm_ret_len = 0;
	}

	switch (event->cm_type) {
	case IBT_CM_EVENT_REQ_RCV:
		/* active side should not receive this event */
		D2("rc_handler: IBT_CM_EVENT_REQ_RCV\n");
		break;

	case IBT_CM_EVENT_REP_RCV:
		/* connection accepted by passive side */
		D2("rc_handler: IBT_CM_EVENT_REP_RCV\n");
		return (daplka_cm_rc_rep_rcv(ep_rp, event, ret_args,
		    priv_data, len));

	case IBT_CM_EVENT_CONN_CLOSED:
		D2("rc_handler: IBT_CM_EVENT_CONN_CLOSED %d\n",
		    event->cm_event.closed);
		return (daplka_cm_rc_conn_closed(ep_rp, event, ret_args,
		    priv_data, len));

	case IBT_CM_EVENT_MRA_RCV:
		/* passive side does default processing MRA event */
		D2("rc_handler: IBT_CM_EVENT_MRA_RCV\n");
		return (IBT_CM_DEFAULT);

	case IBT_CM_EVENT_CONN_EST:
		D2("rc_handler: IBT_CM_EVENT_CONN_EST\n");
		return (daplka_cm_rc_conn_est(ep_rp, event, ret_args,
		    priv_data, len));

	case IBT_CM_EVENT_FAILURE:
		D2("rc_handler: IBT_CM_EVENT_FAILURE\n");
		return (daplka_cm_rc_event_failure(ep_rp, event, ret_args,
		    priv_data, len));

	default:
		D2("rc_handler: invalid event %d\n", event->cm_type);
		break;
	}
	return (IBT_CM_DEFAULT);
}

/*
 * creates an IA resource and inserts it into the global resource table.
 */
/* ARGSUSED */
static int
daplka_ia_create(minor_t rnum, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	daplka_ia_resource_t	*ia_rp, *tmp_rp;
	boolean_t		inserted = B_FALSE;
	dapl_ia_create_t	args;
	ibt_hca_hdl_t		hca_hdl;
	ibt_status_t		status;
	ib_gid_t		sgid;
	int			retval;
	ibt_hca_portinfo_t	*pinfop;
	uint_t			pinfon;
	uint_t			size;
	ibt_ar_t		ar_s;
	daplka_hca_t		*hca;

	retval = ddi_copyin((void *)arg, &args, sizeof (dapl_ia_create_t),
	    mode);
	if (retval != 0) {
		DERR("ia_create: copyin error %d\n", retval);
		return (EFAULT);
	}
	if (args.ia_version != DAPL_IF_VERSION) {
		DERR("ia_create: invalid version %d, expected version %d\n",
		    args.ia_version, DAPL_IF_VERSION);
		return (EINVAL);
	}

	/*
	 * find the hca with the matching guid
	 */
	mutex_enter(&daplka_dev->daplka_mutex);
	for (hca = daplka_dev->daplka_hca_list_head; hca != NULL;
	    hca = hca->hca_next) {
		if (hca->hca_guid == args.ia_guid) {
			DAPLKA_HOLD_HCA_WITHOUT_LOCK(hca);
			break;
		}
	}
	mutex_exit(&daplka_dev->daplka_mutex);

	if (hca == NULL) {
		DERR("ia_create: guid 0x%016llx not found\n",
		    (longlong_t)args.ia_guid);
		return (EINVAL);
	}

	/*
	 * check whether port number is valid and whether it is up
	 */
	if (args.ia_port > hca->hca_nports) {
		DERR("ia_create: invalid hca_port %d\n", args.ia_port);
		DAPLKA_RELE_HCA(daplka_dev, hca);
		return (EINVAL);
	}
	hca_hdl = hca->hca_hdl;
	if (hca_hdl == NULL) {
		DERR("ia_create: hca_hdl == NULL\n");
		DAPLKA_RELE_HCA(daplka_dev, hca);
		return (EINVAL);
	}
	status = ibt_query_hca_ports(hca_hdl, (uint8_t)args.ia_port,
	    &pinfop, &pinfon, &size);
	if (status != IBT_SUCCESS) {
		DERR("ia_create: ibt_query_hca_ports returned %d\n", status);
		*rvalp = (int)status;
		DAPLKA_RELE_HCA(daplka_dev, hca);
		return (0);
	}
	sgid = pinfop->p_sgid_tbl[0];
	ibt_free_portinfo(pinfop, size);

	ia_rp = kmem_zalloc(sizeof (daplka_ia_resource_t), daplka_km_flags);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ia_rp))
	DAPLKA_RS_INIT(ia_rp, DAPL_TYPE_IA, rnum, daplka_ia_destroy);

	mutex_init(&ia_rp->ia_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ia_rp->ia_cv, NULL, CV_DRIVER, NULL);
	ia_rp->ia_hca_hdl = hca_hdl;
	ia_rp->ia_hca_sgid = sgid;
	ia_rp->ia_hca = hca;
	ia_rp->ia_port_num = args.ia_port;
	ia_rp->ia_port_pkey = args.ia_pkey;
	ia_rp->ia_pid = ddi_get_pid();
	ia_rp->ia_async_evd_hkeys = NULL;
	ia_rp->ia_ar_registered = B_FALSE;
	bcopy(args.ia_sadata, ia_rp->ia_sadata, DAPL_ATS_NBYTES);

	/* register Address Record */
	ar_s.ar_gid = ia_rp->ia_hca_sgid;
	ar_s.ar_pkey = ia_rp->ia_port_pkey;
	bcopy(ia_rp->ia_sadata, ar_s.ar_data, DAPL_ATS_NBYTES);
#define	UC(b) ar_s.ar_data[(b)]
	D3("daplka_ia_create: SA[8] %d.%d.%d.%d\n",
	    UC(8), UC(9), UC(10), UC(11));
	D3("daplka_ia_create: SA[12] %d.%d.%d.%d\n",
	    UC(12), UC(13), UC(14), UC(15));
	retval = ibt_register_ar(daplka_dev->daplka_clnt_hdl, &ar_s);
	if (retval != IBT_SUCCESS) {
		DERR("ia_create: failed to register Address Record.\n");
		retval = EINVAL;
		goto cleanup;
	}
	ia_rp->ia_ar_registered = B_TRUE;

	/*
	 * create hash tables for all object types
	 */
	retval = daplka_hash_create(&ia_rp->ia_ep_htbl, DAPLKA_EP_HTBL_SZ,
	    daplka_hash_ep_free, daplka_hash_generic_lookup);
	if (retval != 0) {
		DERR("ia_create: cannot create ep hash table\n");
		goto cleanup;
	}
	retval = daplka_hash_create(&ia_rp->ia_mr_htbl, DAPLKA_MR_HTBL_SZ,
	    daplka_hash_mr_free, daplka_hash_generic_lookup);
	if (retval != 0) {
		DERR("ia_create: cannot create mr hash table\n");
		goto cleanup;
	}
	retval = daplka_hash_create(&ia_rp->ia_mw_htbl, DAPLKA_MW_HTBL_SZ,
	    daplka_hash_mw_free, daplka_hash_generic_lookup);
	if (retval != 0) {
		DERR("ia_create: cannot create mw hash table\n");
		goto cleanup;
	}
	retval = daplka_hash_create(&ia_rp->ia_pd_htbl, DAPLKA_PD_HTBL_SZ,
	    daplka_hash_pd_free, daplka_hash_generic_lookup);
	if (retval != 0) {
		DERR("ia_create: cannot create pd hash table\n");
		goto cleanup;
	}
	retval = daplka_hash_create(&ia_rp->ia_evd_htbl, DAPLKA_EVD_HTBL_SZ,
	    daplka_hash_evd_free, daplka_hash_generic_lookup);
	if (retval != 0) {
		DERR("ia_create: cannot create evd hash table\n");
		goto cleanup;
	}
	retval = daplka_hash_create(&ia_rp->ia_cno_htbl, DAPLKA_CNO_HTBL_SZ,
	    daplka_hash_cno_free, daplka_hash_generic_lookup);
	if (retval != 0) {
		DERR("ia_create: cannot create cno hash table\n");
		goto cleanup;
	}
	retval = daplka_hash_create(&ia_rp->ia_sp_htbl, DAPLKA_SP_HTBL_SZ,
	    daplka_hash_sp_free, daplka_hash_generic_lookup);
	if (retval != 0) {
		DERR("ia_create: cannot create sp hash table\n");
		goto cleanup;
	}
	retval = daplka_hash_create(&ia_rp->ia_srq_htbl, DAPLKA_SRQ_HTBL_SZ,
	    daplka_hash_srq_free, daplka_hash_generic_lookup);
	if (retval != 0) {
		DERR("ia_create: cannot create srq hash table\n");
		goto cleanup;
	}
	/*
	 * insert ia_rp into the global resource table
	 */
	retval = daplka_resource_insert(rnum, (daplka_resource_t *)ia_rp);
	if (retval != 0) {
		DERR("ia_create: cannot insert resource\n");
		goto cleanup;
	}
	inserted = B_TRUE;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*ia_rp))

	args.ia_resnum = rnum;
	retval = copyout(&args, (void *)arg, sizeof (dapl_ia_create_t));
	if (retval != 0) {
		DERR("ia_create: copyout error %d\n", retval);
		retval = EFAULT;
		goto cleanup;
	}
	return (0);

cleanup:;
	if (inserted) {
		tmp_rp = (daplka_ia_resource_t *)daplka_resource_remove(rnum);
		if (tmp_rp != ia_rp) {
			/*
			 * we can return here because another thread must
			 * have freed up the resource
			 */
			DERR("ia_create: cannot remove resource\n");
			return (retval);
		}
	}
	DAPLKA_RS_UNREF(ia_rp);
	return (retval);
}

/*
 * destroys an IA resource
 */
static int
daplka_ia_destroy(daplka_resource_t *gen_rp)
{
	daplka_ia_resource_t	*ia_rp = (daplka_ia_resource_t *)gen_rp;
	daplka_async_evd_hkey_t *hkp;
	int			cnt;
	ibt_ar_t		ar_s;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ia_rp))
	D3("ia_destroy: entering, ia_rp 0x%p\n", ia_rp);

	/* deregister Address Record */
	if (ia_rp->ia_ar_registered) {
		ar_s.ar_gid = ia_rp->ia_hca_sgid;
		ar_s.ar_pkey = ia_rp->ia_port_pkey;
		bcopy(ia_rp->ia_sadata, ar_s.ar_data, DAPL_ATS_NBYTES);
		(void) ibt_deregister_ar(daplka_dev->daplka_clnt_hdl, &ar_s);
		ia_rp->ia_ar_registered = B_FALSE;
	}

	/*
	 * destroy hash tables. make sure resources are
	 * destroyed in the correct order.
	 */
	daplka_hash_destroy(&ia_rp->ia_mw_htbl);
	daplka_hash_destroy(&ia_rp->ia_mr_htbl);
	daplka_hash_destroy(&ia_rp->ia_ep_htbl);
	daplka_hash_destroy(&ia_rp->ia_srq_htbl);
	daplka_hash_destroy(&ia_rp->ia_evd_htbl);
	daplka_hash_destroy(&ia_rp->ia_cno_htbl);
	daplka_hash_destroy(&ia_rp->ia_pd_htbl);
	daplka_hash_destroy(&ia_rp->ia_sp_htbl);

	/*
	 * free the async evd list
	 */
	cnt = 0;
	hkp = ia_rp->ia_async_evd_hkeys;
	while (hkp != NULL) {
		daplka_async_evd_hkey_t	*free_hkp;

		cnt++;
		free_hkp = hkp;
		hkp = hkp->aeh_next;
		kmem_free(free_hkp, sizeof (*free_hkp));
	}
	if (cnt > 0) {
		D3("ia_destroy: freed %d hkeys\n", cnt);
	}
	mutex_destroy(&ia_rp->ia_lock);
	cv_destroy(&ia_rp->ia_cv);
	ia_rp->ia_hca_hdl = NULL;

	DAPLKA_RS_FINI(ia_rp);

	if (ia_rp->ia_hca)
		DAPLKA_RELE_HCA(daplka_dev, ia_rp->ia_hca);

	kmem_free(ia_rp, sizeof (daplka_ia_resource_t));
	D3("ia_destroy: exiting, ia_rp 0x%p\n", ia_rp);
	return (0);
}

static void
daplka_async_event_create(ibt_async_code_t code, ibt_async_event_t *event,
    uint64_t cookie, daplka_ia_resource_t *ia_rp)
{
	daplka_evd_event_t	*evp;
	daplka_evd_resource_t	*async_evd;
	daplka_async_evd_hkey_t	*curr;

	mutex_enter(&ia_rp->ia_lock);
	curr = ia_rp->ia_async_evd_hkeys;
	while (curr != NULL) {
		/*
		 * Note: this allocation does not zero out the buffer
		 * since we init all the fields.
		 */
		evp = kmem_alloc(sizeof (daplka_evd_event_t), KM_NOSLEEP);
		if (evp == NULL) {
			DERR("async_event_enqueue: event alloc failed"
			    "!found\n", ia_rp, curr->aeh_evd_hkey);
			curr = curr->aeh_next;
			continue;
		}
		evp->ee_next = NULL;
		evp->ee_aev.ibae_type = code;
		evp->ee_aev.ibae_hca_guid = event->ev_hca_guid;
		evp->ee_aev.ibae_cookie = cookie;
		evp->ee_aev.ibae_port = event->ev_port;

		/*
		 * Lookup the async evd corresponding to this ia and enqueue
		 * evp and wakeup any waiter.
		 */
		async_evd = (daplka_evd_resource_t *)
		    daplka_hash_lookup(&ia_rp->ia_evd_htbl, curr->aeh_evd_hkey);
		if (async_evd == NULL) { /* async evd is being freed */
			DERR("async_event_enqueue: ia_rp(%p) asycn_evd %llx "
			    "!found\n", ia_rp, (longlong_t)curr->aeh_evd_hkey);
			kmem_free(evp, sizeof (daplka_evd_event_t));
			curr = curr->aeh_next;
			continue;
		}
		daplka_evd_wakeup(async_evd, &async_evd->evd_async_events, evp);

		/* decrement refcnt on async_evd */
		DAPLKA_RS_UNREF(async_evd);
		curr = curr->aeh_next;
	}
	mutex_exit(&ia_rp->ia_lock);
}
/*
 * This routine is called in kernel context
 */

/* ARGSUSED */
static void
daplka_rc_async_handler(void *clnt_private, ibt_hca_hdl_t hca_hdl,
    ibt_async_code_t code, ibt_async_event_t *event)
{
	daplka_ep_resource_t		*epp;
	daplka_ia_resource_t		*ia_rp;
	minor_t				ia_rnum;

	if (event->ev_chan_hdl == NULL) {
		DERR("daplka_rc_async_handler: ev_chan_hdl is NULL\n");
		return;
	}

	mutex_enter(&daplka_dev->daplka_mutex);
	epp = ibt_get_chan_private(event->ev_chan_hdl);
	if (epp == NULL) {
		mutex_exit(&daplka_dev->daplka_mutex);
		DERR("daplka_rc_async_handler: chan_private is NULL\n");
		return;
	}

	/* grab a reference to this ep */
	DAPLKA_RS_REF(epp);
	mutex_exit(&daplka_dev->daplka_mutex);

	/*
	 * The endpoint resource has the resource number corresponding to
	 * the IA resource. Use that to lookup the ia resource entry
	 */
	ia_rnum = DAPLKA_RS_RNUM(epp);
	ia_rp = (daplka_ia_resource_t *)daplka_resource_lookup(ia_rnum);
	if ((ia_rp == NULL) || DAPLKA_RS_RESERVED(ia_rp)) {
		D2("daplka_rc_async_handler: resource (%d) not found\n",
		    ia_rnum);
		DAPLKA_RS_UNREF(epp);
		return;
	}

	/*
	 * Create an async event and chain it to the async evd
	 */
	daplka_async_event_create(code, event, epp->ep_cookie, ia_rp);

	DAPLKA_RS_UNREF(ia_rp);
	DAPLKA_RS_UNREF(epp);
}

/*
 * This routine is called in kernel context
 */

/* ARGSUSED */
static void
daplka_cq_async_handler(void *clnt_private, ibt_hca_hdl_t hca_hdl,
    ibt_async_code_t code, ibt_async_event_t *event)
{
	daplka_evd_resource_t		*evdp;
	daplka_ia_resource_t		*ia_rp;
	minor_t				ia_rnum;

	if (event->ev_cq_hdl == NULL)
		return;

	mutex_enter(&daplka_dev->daplka_mutex);
	evdp = ibt_get_cq_private(event->ev_cq_hdl);
	if (evdp == NULL) {
		mutex_exit(&daplka_dev->daplka_mutex);
		DERR("daplka_cq_async_handler: get cq private(%p) failed\n",
		    event->ev_cq_hdl);
		return;
	}
	/* grab a reference to this evd resource */
	DAPLKA_RS_REF(evdp);
	mutex_exit(&daplka_dev->daplka_mutex);

	/*
	 * The endpoint resource has the resource number corresponding to
	 * the IA resource. Use that to lookup the ia resource entry
	 */
	ia_rnum = DAPLKA_RS_RNUM(evdp);
	ia_rp = (daplka_ia_resource_t *)daplka_resource_lookup(ia_rnum);
	if ((ia_rp == NULL) || DAPLKA_RS_RESERVED(ia_rp)) {
		DERR("daplka_cq_async_handler: resource (%d) not found\n",
		    ia_rnum);
		DAPLKA_RS_UNREF(evdp);
		return;
	}

	/*
	 * Create an async event and chain it to the async evd
	 */
	daplka_async_event_create(code, event, evdp->evd_cookie, ia_rp);

	/* release all the refcount that were acquired */
	DAPLKA_RS_UNREF(ia_rp);
	DAPLKA_RS_UNREF(evdp);
}

/*
 * This routine is called in kernel context, handles unaffiliated async errors
 */

/* ARGSUSED */
static void
daplka_un_async_handler(void *clnt_private, ibt_hca_hdl_t hca_hdl,
    ibt_async_code_t code, ibt_async_event_t *event)
{
	int			i, j;
	daplka_resource_blk_t	*blk;
	daplka_resource_t	*rp;
	daplka_ia_resource_t	*ia_rp;

	/*
	 * Walk the resource table looking for an ia that matches the
	 * hca_hdl.
	 */
	rw_enter(&daplka_resource.daplka_rct_lock, RW_READER);
	for (i = 0; i < daplka_resource.daplka_rc_len; i++) {
		blk = daplka_resource.daplka_rc_root[i];
		if (blk == NULL)
			continue;
		for (j = 0; j < DAPLKA_RC_BLKSZ; j++) {
			rp = blk->daplka_rcblk_blks[j];
			if ((rp == NULL) ||
			    ((intptr_t)rp == DAPLKA_RC_RESERVED) ||
			    (rp->rs_type != DAPL_TYPE_IA)) {
				continue;
			}
			/*
			 * rp is an IA resource check if it belongs
			 * to the hca/port for which we got the event
			 */
			ia_rp = (daplka_ia_resource_t *)rp;
			DAPLKA_RS_REF(ia_rp);
			if ((hca_hdl == ia_rp->ia_hca_hdl) &&
			    (event->ev_port == ia_rp->ia_port_num)) {
				/*
				 * walk the ep hash table. Acquire a
				 * reader lock. NULL dgid indicates
				 * local port up event.
				 */
				daplka_hash_walk(&ia_rp->ia_ep_htbl,
				    daplka_ep_failback, NULL, RW_READER);
			}
			DAPLKA_RS_UNREF(ia_rp);
		}
	}
	rw_exit(&daplka_resource.daplka_rct_lock);
}

static int
daplka_handle_hca_detach_event(ibt_async_event_t *event)
{
	daplka_hca_t	*hca;

	/*
	 * find the hca with the matching guid
	 */
	mutex_enter(&daplka_dev->daplka_mutex);
	for (hca = daplka_dev->daplka_hca_list_head; hca != NULL;
	    hca = hca->hca_next) {
		if (hca->hca_guid == event->ev_hca_guid) {
			if (DAPLKA_HCA_BUSY(hca)) {
				mutex_exit(&daplka_dev->daplka_mutex);
				return (IBT_HCA_RESOURCES_NOT_FREED);
			}
			daplka_dequeue_hca(daplka_dev, hca);
			break;
		}
	}
	mutex_exit(&daplka_dev->daplka_mutex);

	if (hca == NULL)
		return (IBT_FAILURE);

	return (daplka_fini_hca(daplka_dev, hca));
}

/*
 * This routine is called in kernel context
 */
static void
daplka_async_handler(void *clnt_private, ibt_hca_hdl_t hca_hdl,
    ibt_async_code_t code, ibt_async_event_t *event)
{
	switch (code) {
	case IBT_ERROR_CATASTROPHIC_CHAN:
	case IBT_ERROR_INVALID_REQUEST_CHAN:
	case IBT_ERROR_ACCESS_VIOLATION_CHAN:
	case IBT_ERROR_PATH_MIGRATE_REQ:
		D2("daplka_async_handler(): Channel affiliated=0x%x\n", code);
		/* These events are affiliated with a the RC channel */
		daplka_rc_async_handler(clnt_private, hca_hdl, code, event);
		break;
	case IBT_ERROR_CQ:
		/* This event is affiliated with a the CQ */
		D2("daplka_async_handler(): IBT_ERROR_CQ\n");
		daplka_cq_async_handler(clnt_private, hca_hdl, code, event);
		break;
	case IBT_ERROR_PORT_DOWN:
		D2("daplka_async_handler(): IBT_PORT_DOWN\n");
		break;
	case IBT_EVENT_PORT_UP:
		D2("daplka_async_handler(): IBT_PORT_UP\n");
		if (daplka_apm) {
			daplka_un_async_handler(clnt_private, hca_hdl, code,
			    event);
		}
		break;
	case IBT_HCA_ATTACH_EVENT:
		/*
		 * NOTE: In some error recovery paths, it is possible to
		 * receive IBT_HCA_ATTACH_EVENTs on already known HCAs.
		 */
		D2("daplka_async_handler(): IBT_HCA_ATTACH\n");
		(void) daplka_init_hca(daplka_dev, event->ev_hca_guid);
		break;
	case IBT_HCA_DETACH_EVENT:
		D2("daplka_async_handler(): IBT_HCA_DETACH\n");
		/* Free all hca resources and close the HCA. */
		(void) daplka_handle_hca_detach_event(event);
		break;
	case IBT_EVENT_PATH_MIGRATED:
		/* This event is affiliated with APM */
		D2("daplka_async_handler(): IBT_PATH_MIGRATED.\n");
		break;
	default:
		D2("daplka_async_handler(): unhandled code = 0x%x\n", code);
		break;
	}
}

/*
 * This routine is called in kernel context related to Subnet events
 */
/*ARGSUSED*/
static void
daplka_sm_notice_handler(void *arg, ib_gid_t gid, ibt_subnet_event_code_t code,
	ibt_subnet_event_t *event)
{
	ib_gid_t *sgid = &gid;
	ib_gid_t *dgid;

	dgid = &event->sm_notice_gid;
	switch (code) {
	case IBT_SM_EVENT_GID_AVAIL:
		/* This event is affiliated with remote port up */
		D2("daplka_sm_notice_handler(): IBT_SM_EVENT_GID_AVAIL\n");
		if (daplka_apm)
			daplka_sm_gid_avail(sgid, dgid);
		return;
	case IBT_SM_EVENT_GID_UNAVAIL:
		/* This event is affiliated with remote port down */
		D2("daplka_sm_notice_handler(): IBT_SM_EVENT_GID_UNAVAIL\n");
		return;
	default:
		D2("daplka_sm_notice_handler(): unhandled IBT_SM_EVENT_[%d]\n",
		    code);
		return;
	}
}

/*
 * This routine is called in kernel context, handles Subnet GID avail events
 * which correspond to remote port up. Setting up alternate path or path
 * migration (failback) has to be initiated from the active side of the
 * original connect.
 */
static void
daplka_sm_gid_avail(ib_gid_t *sgid, ib_gid_t *dgid)
{
	int			i, j;
	daplka_resource_blk_t	*blk;
	daplka_resource_t	*rp;
	daplka_ia_resource_t	*ia_rp;

	D2("daplka_sm_gid_avail: sgid=%llx:%llx dgid=%llx:%llx\n",
	    (longlong_t)sgid->gid_prefix, (longlong_t)sgid->gid_guid,
	    (longlong_t)dgid->gid_prefix, (longlong_t)dgid->gid_guid);

	/*
	 * Walk the resource table looking for an ia that matches the sgid
	 */
	rw_enter(&daplka_resource.daplka_rct_lock, RW_READER);
	for (i = 0; i < daplka_resource.daplka_rc_len; i++) {
		blk = daplka_resource.daplka_rc_root[i];
		if (blk == NULL)
			continue;
		for (j = 0; j < DAPLKA_RC_BLKSZ; j++) {
			rp = blk->daplka_rcblk_blks[j];
			if ((rp == NULL) ||
			    ((intptr_t)rp == DAPLKA_RC_RESERVED) ||
			    (rp->rs_type != DAPL_TYPE_IA)) {
				continue;
			}
			/*
			 * rp is an IA resource check if its gid
			 * matches with the calling sgid
			 */
			ia_rp = (daplka_ia_resource_t *)rp;
			DAPLKA_RS_REF(ia_rp);
			if ((sgid->gid_prefix ==
			    ia_rp->ia_hca_sgid.gid_prefix) &&
			    (sgid->gid_guid == ia_rp->ia_hca_sgid.gid_guid)) {
				/*
				 * walk the ep hash table. Acquire a
				 * reader lock.
				 */
				daplka_hash_walk(&ia_rp->ia_ep_htbl,
				    daplka_ep_failback,
				    (void *)dgid, RW_READER);
			}
			DAPLKA_RS_UNREF(ia_rp);
		}
	}
	rw_exit(&daplka_resource.daplka_rct_lock);
}

/*
 * This routine is called in kernel context to get and set an alternate path
 */
static int
daplka_ep_altpath(daplka_ep_resource_t *ep_rp, ib_gid_t *dgid)
{
	ibt_alt_path_info_t path_info;
	ibt_alt_path_attr_t path_attr;
	ibt_ap_returns_t ap_rets;
	ibt_status_t status;

	D2("daplka_ep_altpath : ibt_get_alt_path()\n");
	bzero(&path_info, sizeof (ibt_alt_path_info_t));
	bzero(&path_attr, sizeof (ibt_alt_path_attr_t));
	if (dgid != NULL) {
		path_attr.apa_sgid = ep_rp->ep_sgid;
		path_attr.apa_dgid = *dgid;
	}
	status = ibt_get_alt_path(ep_rp->ep_chan_hdl, IBT_PATH_AVAIL,
	    &path_attr, &path_info);
	if (status != IBT_SUCCESS) {
		DERR("daplka_ep_altpath : ibt_get_alt_path failed %d\n",
		    status);
		return (1);
	}

	D2("daplka_ep_altpath : ibt_set_alt_path()\n");
	bzero(&ap_rets, sizeof (ibt_ap_returns_t));
	status = ibt_set_alt_path(ep_rp->ep_chan_hdl, IBT_BLOCKING,
	    &path_info, NULL, 0, &ap_rets);
	if ((status != IBT_SUCCESS) ||
	    (ap_rets.ap_status != IBT_CM_AP_LOADED)) {
		DERR("daplka_ep_altpath : ibt_set_alt_path failed "
		    "status %d ap_status %d\n", status, ap_rets.ap_status);
		return (1);
	}
	return (0);
}

/*
 * This routine is called in kernel context to failback to the original path
 */
static int
daplka_ep_failback(void *objp, void *arg)
{
	daplka_ep_resource_t *ep_rp = (daplka_ep_resource_t *)objp;
	ib_gid_t *dgid;
	ibt_status_t status;
	ibt_rc_chan_query_attr_t chan_attrs;
	int i;

	ASSERT(DAPLKA_RS_TYPE(ep_rp) == DAPL_TYPE_EP);
	D2("daplka_ep_failback ep : sgid=%llx:%llx dgid=%llx:%llx\n",
	    (longlong_t)ep_rp->ep_sgid.gid_prefix,
	    (longlong_t)ep_rp->ep_sgid.gid_guid,
	    (longlong_t)ep_rp->ep_dgid.gid_prefix,
	    (longlong_t)ep_rp->ep_dgid.gid_guid);

	/*
	 * daplka_ep_failback is called from daplka_hash_walk
	 * which holds the read lock on hash table to protect
	 * the endpoint resource from removal
	 */
	mutex_enter(&ep_rp->ep_lock);
	/* check for unconnected endpoints */
	/* first check for ep state */
	if (ep_rp->ep_state != DAPLKA_EP_STATE_CONNECTED) {
		mutex_exit(&ep_rp->ep_lock);
		D2("daplka_ep_failback : endpoints not connected\n");
		return (0);
	}

	/* second check for gids */
	if (((ep_rp->ep_sgid.gid_prefix == 0) &&
	    (ep_rp->ep_sgid.gid_guid == 0)) ||
	    ((ep_rp->ep_dgid.gid_prefix == 0) &&
	    (ep_rp->ep_dgid.gid_guid == 0))) {
		mutex_exit(&ep_rp->ep_lock);
		D2("daplka_ep_failback : skip unconnected endpoints\n");
		return (0);
	}

	/*
	 * matching destination ep
	 * when dgid is NULL, the async event is a local port up.
	 * dgid becomes wild card, i.e. all endpoints match
	 */
	dgid = (ib_gid_t *)arg;
	if (dgid == NULL) {
		/* ignore loopback ep */
		if ((ep_rp->ep_sgid.gid_prefix == ep_rp->ep_dgid.gid_prefix) &&
		    (ep_rp->ep_sgid.gid_guid == ep_rp->ep_dgid.gid_guid)) {
			mutex_exit(&ep_rp->ep_lock);
			D2("daplka_ep_failback : skip loopback endpoints\n");
			return (0);
		}
	} else {
		/* matching remote ep */
		if ((ep_rp->ep_dgid.gid_prefix != dgid->gid_prefix) ||
		    (ep_rp->ep_dgid.gid_guid != dgid->gid_guid)) {
			mutex_exit(&ep_rp->ep_lock);
			D2("daplka_ep_failback : unrelated endpoints\n");
			return (0);
		}
	}

	/* call get and set altpath with original dgid used in ep_connect */
	if (daplka_ep_altpath(ep_rp, &ep_rp->ep_dgid)) {
		mutex_exit(&ep_rp->ep_lock);
		return (0);
	}

	/*
	 * wait for migration state to be ARMed
	 * e.g. a post_send msg will transit mig_state from REARM to ARM
	 */
	for (i = 0; i < daplka_query_aft_setaltpath; i++) {
		bzero(&chan_attrs, sizeof (ibt_rc_chan_query_attr_t));
		status = ibt_query_rc_channel(ep_rp->ep_chan_hdl, &chan_attrs);
		if (status != IBT_SUCCESS) {
			mutex_exit(&ep_rp->ep_lock);
			DERR("daplka_ep_altpath : ibt_query_rc_channel err\n");
			return (0);
		}
		if (chan_attrs.rc_mig_state == IBT_STATE_ARMED)
			break;
	}

	D2("daplka_ep_altpath : query[%d] mig_st=%d\n",
	    i, chan_attrs.rc_mig_state);
	D2("daplka_ep_altpath : P sgid=%llx:%llx dgid=%llx:%llx\n",
	    (longlong_t)
	    chan_attrs.rc_prim_path.cep_adds_vect.av_sgid.gid_prefix,
	    (longlong_t)chan_attrs.rc_prim_path.cep_adds_vect.av_sgid.gid_guid,
	    (longlong_t)
	    chan_attrs.rc_prim_path.cep_adds_vect.av_dgid.gid_prefix,
	    (longlong_t)chan_attrs.rc_prim_path.cep_adds_vect.av_dgid.gid_guid);
	D2("daplka_ep_altpath : A sgid=%llx:%llx dgid=%llx:%llx\n",
	    (longlong_t)chan_attrs.rc_alt_path.cep_adds_vect.av_sgid.gid_prefix,
	    (longlong_t)chan_attrs.rc_alt_path.cep_adds_vect.av_sgid.gid_guid,
	    (longlong_t)chan_attrs.rc_alt_path.cep_adds_vect.av_dgid.gid_prefix,
	    (longlong_t)chan_attrs.rc_alt_path.cep_adds_vect.av_dgid.gid_guid);

	/* skip failback on ARMed state not reached or env override */
	if ((i >= daplka_query_aft_setaltpath) || (daplka_failback == 0)) {
		mutex_exit(&ep_rp->ep_lock);
		DERR("daplka_ep_altpath : ARMed state not reached\n");
		return (0);
	}

	D2("daplka_ep_failback : ibt_migrate_path() to original ep\n");
	status = ibt_migrate_path(ep_rp->ep_chan_hdl);
	if (status != IBT_SUCCESS) {
		mutex_exit(&ep_rp->ep_lock);
		DERR("daplka_ep_failback : migration failed "
		    "status %d\n", status);
		return (0);
	}

	/* call get and altpath with NULL dgid to indicate unspecified dgid */
	(void) daplka_ep_altpath(ep_rp, NULL);
	mutex_exit(&ep_rp->ep_lock);
	return (0);
}

/*
 * IBTF wrappers used for resource accounting
 */
static ibt_status_t
daplka_ibt_alloc_rc_channel(daplka_ep_resource_t *ep_rp, ibt_hca_hdl_t hca_hdl,
    ibt_chan_alloc_flags_t flags, ibt_rc_chan_alloc_args_t *args,
    ibt_channel_hdl_t *chan_hdl_p, ibt_chan_sizes_t *sizes)
{
	daplka_hca_t	*hca_p;
	uint32_t	max_qps;
	boolean_t	acct_enabled;
	ibt_status_t	status;

	acct_enabled = daplka_accounting_enabled;
	hca_p = ep_rp->ep_hca;
	max_qps = daplka_max_qp_percent * hca_p->hca_attr.hca_max_chans / 100;

	if (acct_enabled) {
		if (daplka_max_qp_percent != 0 &&
		    max_qps <= hca_p->hca_qp_count) {
			DERR("ibt_alloc_rc_channel: resource limit exceeded "
			    "(limit %d, count %d)\n", max_qps,
			    hca_p->hca_qp_count);
			return (IBT_INSUFF_RESOURCE);
		}
		DAPLKA_RS_ACCT_INC(ep_rp, 1);
		atomic_inc_32(&hca_p->hca_qp_count);
	}
	status = ibt_alloc_rc_channel(hca_hdl, flags, args, chan_hdl_p, sizes);

	if (status != IBT_SUCCESS && acct_enabled) {
		DAPLKA_RS_ACCT_DEC(ep_rp, 1);
		atomic_dec_32(&hca_p->hca_qp_count);
	}
	return (status);
}

static ibt_status_t
daplka_ibt_free_channel(daplka_ep_resource_t *ep_rp, ibt_channel_hdl_t chan_hdl)
{
	daplka_hca_t	*hca_p;
	ibt_status_t	status;

	hca_p = ep_rp->ep_hca;

	status = ibt_free_channel(chan_hdl);
	if (status != IBT_SUCCESS) {
		return (status);
	}
	if (DAPLKA_RS_ACCT_CHARGED(ep_rp) > 0) {
		DAPLKA_RS_ACCT_DEC(ep_rp, 1);
		atomic_dec_32(&hca_p->hca_qp_count);
	}
	return (status);
}

static ibt_status_t
daplka_ibt_alloc_cq(daplka_evd_resource_t *evd_rp, ibt_hca_hdl_t hca_hdl,
    ibt_cq_attr_t *cq_attr, ibt_cq_hdl_t *ibt_cq_p, uint32_t *real_size)
{
	daplka_hca_t	*hca_p;
	uint32_t	max_cqs;
	boolean_t	acct_enabled;
	ibt_status_t	status;

	acct_enabled = daplka_accounting_enabled;
	hca_p = evd_rp->evd_hca;
	max_cqs = daplka_max_cq_percent * hca_p->hca_attr.hca_max_cq / 100;

	if (acct_enabled) {
		if (daplka_max_cq_percent != 0 &&
		    max_cqs <= hca_p->hca_cq_count) {
			DERR("ibt_alloc_cq: resource limit exceeded "
			    "(limit %d, count %d)\n", max_cqs,
			    hca_p->hca_cq_count);
			return (IBT_INSUFF_RESOURCE);
		}
		DAPLKA_RS_ACCT_INC(evd_rp, 1);
		atomic_inc_32(&hca_p->hca_cq_count);
	}
	status = ibt_alloc_cq(hca_hdl, cq_attr, ibt_cq_p, real_size);

	if (status != IBT_SUCCESS && acct_enabled) {
		DAPLKA_RS_ACCT_DEC(evd_rp, 1);
		atomic_dec_32(&hca_p->hca_cq_count);
	}
	return (status);
}

static ibt_status_t
daplka_ibt_free_cq(daplka_evd_resource_t *evd_rp, ibt_cq_hdl_t cq_hdl)
{
	daplka_hca_t	*hca_p;
	ibt_status_t	status;

	hca_p = evd_rp->evd_hca;

	status = ibt_free_cq(cq_hdl);
	if (status != IBT_SUCCESS) {
		return (status);
	}
	if (DAPLKA_RS_ACCT_CHARGED(evd_rp) > 0) {
		DAPLKA_RS_ACCT_DEC(evd_rp, 1);
		atomic_dec_32(&hca_p->hca_cq_count);
	}
	return (status);
}

static ibt_status_t
daplka_ibt_alloc_pd(daplka_pd_resource_t *pd_rp, ibt_hca_hdl_t hca_hdl,
    ibt_pd_flags_t flags, ibt_pd_hdl_t *pd_hdl_p)
{
	daplka_hca_t	*hca_p;
	uint32_t	max_pds;
	boolean_t	acct_enabled;
	ibt_status_t	status;

	acct_enabled = daplka_accounting_enabled;
	hca_p = pd_rp->pd_hca;
	max_pds = daplka_max_pd_percent * hca_p->hca_attr.hca_max_pd / 100;

	if (acct_enabled) {
		if (daplka_max_pd_percent != 0 &&
		    max_pds <= hca_p->hca_pd_count) {
			DERR("ibt_alloc_pd: resource limit exceeded "
			    "(limit %d, count %d)\n", max_pds,
			    hca_p->hca_pd_count);
			return (IBT_INSUFF_RESOURCE);
		}
		DAPLKA_RS_ACCT_INC(pd_rp, 1);
		atomic_inc_32(&hca_p->hca_pd_count);
	}
	status = ibt_alloc_pd(hca_hdl, flags, pd_hdl_p);

	if (status != IBT_SUCCESS && acct_enabled) {
		DAPLKA_RS_ACCT_DEC(pd_rp, 1);
		atomic_dec_32(&hca_p->hca_pd_count);
	}
	return (status);
}

static ibt_status_t
daplka_ibt_free_pd(daplka_pd_resource_t *pd_rp, ibt_hca_hdl_t hca_hdl,
    ibt_pd_hdl_t pd_hdl)
{
	daplka_hca_t	*hca_p;
	ibt_status_t	status;

	hca_p = pd_rp->pd_hca;

	status = ibt_free_pd(hca_hdl, pd_hdl);
	if (status != IBT_SUCCESS) {
		return (status);
	}
	if (DAPLKA_RS_ACCT_CHARGED(pd_rp) > 0) {
		DAPLKA_RS_ACCT_DEC(pd_rp, 1);
		atomic_dec_32(&hca_p->hca_pd_count);
	}
	return (status);
}

static ibt_status_t
daplka_ibt_alloc_mw(daplka_mw_resource_t *mw_rp, ibt_hca_hdl_t hca_hdl,
    ibt_pd_hdl_t pd_hdl, ibt_mw_flags_t flags, ibt_mw_hdl_t *mw_hdl_p,
    ibt_rkey_t *rkey_p)
{
	daplka_hca_t	*hca_p;
	uint32_t	max_mws;
	boolean_t	acct_enabled;
	ibt_status_t	status;

	acct_enabled = daplka_accounting_enabled;
	hca_p = mw_rp->mw_hca;
	max_mws = daplka_max_mw_percent * hca_p->hca_attr.hca_max_mem_win / 100;

	if (acct_enabled) {
		if (daplka_max_mw_percent != 0 &&
		    max_mws <= hca_p->hca_mw_count) {
			DERR("ibt_alloc_mw: resource limit exceeded "
			    "(limit %d, count %d)\n", max_mws,
			    hca_p->hca_mw_count);
			return (IBT_INSUFF_RESOURCE);
		}
		DAPLKA_RS_ACCT_INC(mw_rp, 1);
		atomic_inc_32(&hca_p->hca_mw_count);
	}
	status = ibt_alloc_mw(hca_hdl, pd_hdl, flags, mw_hdl_p, rkey_p);

	if (status != IBT_SUCCESS && acct_enabled) {
		DAPLKA_RS_ACCT_DEC(mw_rp, 1);
		atomic_dec_32(&hca_p->hca_mw_count);
	}
	return (status);
}

static ibt_status_t
daplka_ibt_free_mw(daplka_mw_resource_t *mw_rp, ibt_hca_hdl_t hca_hdl,
    ibt_mw_hdl_t mw_hdl)
{
	daplka_hca_t	*hca_p;
	ibt_status_t	status;

	hca_p = mw_rp->mw_hca;

	status = ibt_free_mw(hca_hdl, mw_hdl);
	if (status != IBT_SUCCESS) {
		return (status);
	}
	if (DAPLKA_RS_ACCT_CHARGED(mw_rp) > 0) {
		DAPLKA_RS_ACCT_DEC(mw_rp, 1);
		atomic_dec_32(&hca_p->hca_mw_count);
	}
	return (status);
}

static ibt_status_t
daplka_ibt_register_mr(daplka_mr_resource_t *mr_rp, ibt_hca_hdl_t hca_hdl,
    ibt_pd_hdl_t pd_hdl, ibt_mr_attr_t *mr_attr, ibt_mr_hdl_t *mr_hdl_p,
    ibt_mr_desc_t *mr_desc_p)
{
	daplka_hca_t	*hca_p;
	uint32_t	max_mrs;
	boolean_t	acct_enabled;
	ibt_status_t	status;

	acct_enabled = daplka_accounting_enabled;
	hca_p = mr_rp->mr_hca;
	max_mrs = daplka_max_mr_percent * hca_p->hca_attr.hca_max_memr / 100;

	if (acct_enabled) {
		if (daplka_max_mr_percent != 0 &&
		    max_mrs <= hca_p->hca_mr_count) {
			DERR("ibt_register_mr: resource limit exceeded "
			    "(limit %d, count %d)\n", max_mrs,
			    hca_p->hca_mr_count);
			return (IBT_INSUFF_RESOURCE);
		}
		DAPLKA_RS_ACCT_INC(mr_rp, 1);
		atomic_inc_32(&hca_p->hca_mr_count);
	}
	status = ibt_register_mr(hca_hdl, pd_hdl, mr_attr, mr_hdl_p, mr_desc_p);

	if (status != IBT_SUCCESS && acct_enabled) {
		DAPLKA_RS_ACCT_DEC(mr_rp, 1);
		atomic_dec_32(&hca_p->hca_mr_count);
	}
	return (status);
}

static ibt_status_t
daplka_ibt_register_shared_mr(daplka_mr_resource_t *mr_rp,
    ibt_hca_hdl_t hca_hdl, ibt_mr_hdl_t mr_hdl, ibt_pd_hdl_t pd_hdl,
    ibt_smr_attr_t *smr_attr_p, ibt_mr_hdl_t *mr_hdl_p,
    ibt_mr_desc_t *mr_desc_p)
{
	daplka_hca_t	*hca_p;
	uint32_t	max_mrs;
	boolean_t	acct_enabled;
	ibt_status_t	status;

	acct_enabled = daplka_accounting_enabled;
	hca_p = mr_rp->mr_hca;
	max_mrs = daplka_max_mr_percent * hca_p->hca_attr.hca_max_memr / 100;

	if (acct_enabled) {
		if (daplka_max_mr_percent != 0 &&
		    max_mrs <= hca_p->hca_mr_count) {
			DERR("ibt_register_shared_mr: resource limit exceeded "
			    "(limit %d, count %d)\n", max_mrs,
			    hca_p->hca_mr_count);
			return (IBT_INSUFF_RESOURCE);
		}
		DAPLKA_RS_ACCT_INC(mr_rp, 1);
		atomic_inc_32(&hca_p->hca_mr_count);
	}
	status = ibt_register_shared_mr(hca_hdl, mr_hdl, pd_hdl,
	    smr_attr_p, mr_hdl_p, mr_desc_p);

	if (status != IBT_SUCCESS && acct_enabled) {
		DAPLKA_RS_ACCT_DEC(mr_rp, 1);
		atomic_dec_32(&hca_p->hca_mr_count);
	}
	return (status);
}

static ibt_status_t
daplka_ibt_deregister_mr(daplka_mr_resource_t *mr_rp, ibt_hca_hdl_t hca_hdl,
    ibt_mr_hdl_t mr_hdl)
{
	daplka_hca_t	*hca_p;
	ibt_status_t	status;

	hca_p = mr_rp->mr_hca;

	status = ibt_deregister_mr(hca_hdl, mr_hdl);
	if (status != IBT_SUCCESS) {
		return (status);
	}
	if (DAPLKA_RS_ACCT_CHARGED(mr_rp) > 0) {
		DAPLKA_RS_ACCT_DEC(mr_rp, 1);
		atomic_dec_32(&hca_p->hca_mr_count);
	}
	return (status);
}

static ibt_status_t
daplka_ibt_alloc_srq(daplka_srq_resource_t *srq_rp, ibt_hca_hdl_t hca_hdl,
    ibt_srq_flags_t flags, ibt_pd_hdl_t pd, ibt_srq_sizes_t *reqsz,
    ibt_srq_hdl_t *srq_hdl_p, ibt_srq_sizes_t *realsz)
{
	daplka_hca_t	*hca_p;
	uint32_t	max_srqs;
	boolean_t	acct_enabled;
	ibt_status_t	status;

	acct_enabled = daplka_accounting_enabled;
	hca_p = srq_rp->srq_hca;
	max_srqs = daplka_max_srq_percent * hca_p->hca_attr.hca_max_srqs / 100;

	if (acct_enabled) {
		if (daplka_max_srq_percent != 0 &&
		    max_srqs <= hca_p->hca_srq_count) {
			DERR("ibt_alloc_srq: resource limit exceeded "
			    "(limit %d, count %d)\n", max_srqs,
			    hca_p->hca_srq_count);
			return (IBT_INSUFF_RESOURCE);
		}
		DAPLKA_RS_ACCT_INC(srq_rp, 1);
		atomic_inc_32(&hca_p->hca_srq_count);
	}
	status = ibt_alloc_srq(hca_hdl, flags, pd, reqsz, srq_hdl_p, realsz);

	if (status != IBT_SUCCESS && acct_enabled) {
		DAPLKA_RS_ACCT_DEC(srq_rp, 1);
		atomic_dec_32(&hca_p->hca_srq_count);
	}
	return (status);
}

static ibt_status_t
daplka_ibt_free_srq(daplka_srq_resource_t *srq_rp, ibt_srq_hdl_t srq_hdl)
{
	daplka_hca_t	*hca_p;
	ibt_status_t	status;

	hca_p = srq_rp->srq_hca;

	D3("ibt_free_srq: %p %p\n", srq_rp, srq_hdl);

	status = ibt_free_srq(srq_hdl);
	if (status != IBT_SUCCESS) {
		return (status);
	}
	if (DAPLKA_RS_ACCT_CHARGED(srq_rp) > 0) {
		DAPLKA_RS_ACCT_DEC(srq_rp, 1);
		atomic_dec_32(&hca_p->hca_srq_count);
	}
	return (status);
}


static int
daplka_common_ioctl(int cmd, minor_t rnum, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	int error;

	switch (cmd) {
	case DAPL_IA_CREATE:
		error = daplka_ia_create(rnum, arg, mode, cred, rvalp);
		break;

	/* can potentially add other commands here */

	default:
		DERR("daplka_common_ioctl: cmd not supported\n");
		error = DDI_FAILURE;
	}
	return (error);
}

static int
daplka_evd_ioctl(int cmd, daplka_ia_resource_t *rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	int error;

	switch (cmd) {
	case DAPL_EVD_CREATE:
		error = daplka_evd_create(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_CQ_RESIZE:
		error = daplka_cq_resize(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_EVENT_POLL:
		error = daplka_event_poll(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_EVENT_WAKEUP:
		error = daplka_event_wakeup(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_EVD_MODIFY_CNO:
		error = daplka_evd_modify_cno(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_EVD_FREE:
		error = daplka_evd_free(rp, arg, mode, cred, rvalp);
		break;

	default:
		DERR("daplka_evd_ioctl: cmd not supported\n");
		error = DDI_FAILURE;
	}
	return (error);
}

static int
daplka_ep_ioctl(int cmd, daplka_ia_resource_t *rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	int error;

	switch (cmd) {
	case DAPL_EP_MODIFY:
		error = daplka_ep_modify(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_EP_FREE:
		error = daplka_ep_free(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_EP_CONNECT:
		error = daplka_ep_connect(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_EP_DISCONNECT:
		error = daplka_ep_disconnect(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_EP_REINIT:
		error = daplka_ep_reinit(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_EP_CREATE:
		error = daplka_ep_create(rp, arg, mode, cred, rvalp);
		break;

	default:
		DERR("daplka_ep_ioctl: cmd not supported\n");
		error = DDI_FAILURE;
	}
	return (error);
}

static int
daplka_mr_ioctl(int cmd, daplka_ia_resource_t *rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	int error;

	switch (cmd) {
	case DAPL_MR_REGISTER:
		error = daplka_mr_register(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_MR_REGISTER_LMR:
		error = daplka_mr_register_lmr(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_MR_REGISTER_SHARED:
		error = daplka_mr_register_shared(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_MR_DEREGISTER:
		error = daplka_mr_deregister(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_MR_SYNC:
		error = daplka_mr_sync(rp, arg, mode, cred, rvalp);
		break;

	default:
		DERR("daplka_mr_ioctl: cmd not supported\n");
		error = DDI_FAILURE;
	}
	return (error);
}

static int
daplka_mw_ioctl(int cmd, daplka_ia_resource_t *rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	int error;

	switch (cmd) {
	case DAPL_MW_ALLOC:
		error = daplka_mw_alloc(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_MW_FREE:
		error = daplka_mw_free(rp, arg, mode, cred, rvalp);
		break;

	default:
		DERR("daplka_mw_ioctl: cmd not supported\n");
		error = DDI_FAILURE;
	}
	return (error);
}

static int
daplka_cno_ioctl(int cmd, daplka_ia_resource_t *rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	int error;

	switch (cmd) {
	case DAPL_CNO_ALLOC:
		error = daplka_cno_alloc(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_CNO_FREE:
		error = daplka_cno_free(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_CNO_WAIT:
		error = daplka_cno_wait(rp, arg, mode, cred, rvalp);
		break;

	default:
		DERR("daplka_cno_ioctl: cmd not supported\n");
		error = DDI_FAILURE;
	}
	return (error);
}

static int
daplka_pd_ioctl(int cmd, daplka_ia_resource_t *rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	int error;

	switch (cmd) {
	case DAPL_PD_ALLOC:
		error = daplka_pd_alloc(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_PD_FREE:
		error = daplka_pd_free(rp, arg, mode, cred, rvalp);
		break;

	default:
		DERR("daplka_pd_ioctl: cmd not supported\n");
		error = DDI_FAILURE;
	}
	return (error);
}

static int
daplka_sp_ioctl(int cmd, daplka_ia_resource_t *rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	int error;

	switch (cmd) {
	case DAPL_SERVICE_REGISTER:
		error = daplka_service_register(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_SERVICE_DEREGISTER:
		error = daplka_service_deregister(rp, arg, mode, cred, rvalp);
		break;

	default:
		DERR("daplka_sp_ioctl: cmd not supported\n");
		error = DDI_FAILURE;
	}
	return (error);
}

static int
daplka_srq_ioctl(int cmd, daplka_ia_resource_t *rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	int error;

	switch (cmd) {
	case DAPL_SRQ_CREATE:
		error = daplka_srq_create(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_SRQ_RESIZE:
		error = daplka_srq_resize(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_SRQ_FREE:
		error = daplka_srq_free(rp, arg, mode, cred, rvalp);
		break;

	default:
		DERR("daplka_srq_ioctl: cmd(%d) not supported\n", cmd);
		error = DDI_FAILURE;
		break;
	}
	return (error);
}

static int
daplka_misc_ioctl(int cmd, daplka_ia_resource_t *rp, intptr_t arg, int mode,
	cred_t *cred, int *rvalp)
{
	int error;

	switch (cmd) {
	case DAPL_CR_ACCEPT:
		error = daplka_cr_accept(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_CR_REJECT:
		error = daplka_cr_reject(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_IA_QUERY:
		error = daplka_ia_query(rp, arg, mode, cred, rvalp);
		break;

	case DAPL_CR_HANDOFF:
		error = daplka_cr_handoff(rp, arg, mode, cred, rvalp);
		break;

	default:
		DERR("daplka_misc_ioctl: cmd not supported\n");
		error = DDI_FAILURE;
	}
	return (error);
}

/*ARGSUSED*/
static int
daplka_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred,
	int *rvalp)
{
	daplka_ia_resource_t	*ia_rp;
	minor_t			rnum;
	int			error = 0;

	rnum = getminor(dev);
	ia_rp = (daplka_ia_resource_t *)daplka_resource_lookup(rnum);
	if (ia_rp == NULL) {
		DERR("ioctl: resource not found, rnum %d\n", rnum);
		return (ENXIO);
	}

	D4("ioctl: rnum = %d, cmd = 0x%x\n", rnum, cmd);
	if (DAPLKA_RS_RESERVED(ia_rp)) {
		error = daplka_common_ioctl(cmd, rnum, arg, mode, cred, rvalp);
		return (error);
	}
	if (DAPLKA_RS_TYPE(ia_rp) != DAPL_TYPE_IA) {
		DERR("ioctl: invalid type %d\n", DAPLKA_RS_TYPE(ia_rp));
		error = EINVAL;
		goto cleanup;
	}
	if (ia_rp->ia_pid != ddi_get_pid()) {
		DERR("ioctl: ia_pid %d != pid %d\n",
		    ia_rp->ia_pid, ddi_get_pid());
		error = EINVAL;
		goto cleanup;
	}

	switch (cmd & DAPL_TYPE_MASK) {
	case DAPL_TYPE_EVD:
		error = daplka_evd_ioctl(cmd, ia_rp, arg, mode, cred, rvalp);
		break;

	case DAPL_TYPE_EP:
		error = daplka_ep_ioctl(cmd, ia_rp, arg, mode, cred, rvalp);
		break;

	case DAPL_TYPE_MR:
		error = daplka_mr_ioctl(cmd, ia_rp, arg, mode, cred, rvalp);
		break;

	case DAPL_TYPE_MW:
		error = daplka_mw_ioctl(cmd, ia_rp, arg, mode, cred, rvalp);
		break;

	case DAPL_TYPE_PD:
		error = daplka_pd_ioctl(cmd, ia_rp, arg, mode, cred, rvalp);
		break;

	case DAPL_TYPE_SP:
		error = daplka_sp_ioctl(cmd, ia_rp, arg, mode, cred, rvalp);
		break;

	case DAPL_TYPE_CNO:
		error = daplka_cno_ioctl(cmd, ia_rp, arg, mode, cred, rvalp);
		break;

	case DAPL_TYPE_MISC:
		error = daplka_misc_ioctl(cmd, ia_rp, arg, mode, cred, rvalp);
		break;

	case DAPL_TYPE_SRQ:
		error = daplka_srq_ioctl(cmd, ia_rp, arg, mode, cred, rvalp);
		break;

	default:
		DERR("ioctl: invalid dapl type = %d\n", DAPLKA_RS_TYPE(ia_rp));
		error = DDI_FAILURE;
	}

cleanup:;
	DAPLKA_RS_UNREF(ia_rp);
	return (error);
}

/* ARGSUSED */
static int
daplka_open(dev_t *devp, int flag, int otyp, struct cred *cred)
{
	minor_t rnum;

	/*
	 * Char only
	 */
	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	/*
	 * Only zero can be opened, clones are used for resources.
	 */
	if (getminor(*devp) != DAPLKA_DRIVER_MINOR) {
		DERR("daplka_open: bad minor %d\n", getminor(*devp));
		return (ENODEV);
	}

	/*
	 * - allocate new minor number
	 * - update devp argument to new device
	 */
	if (daplka_resource_reserve(&rnum) == 0) {
		*devp = makedevice(getmajor(*devp), rnum);
	} else {
		return (ENOMEM);
	}

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
daplka_close(dev_t dev, int flag, int otyp, struct cred *cred)
{
	daplka_ia_resource_t	*ia_rp;
	minor_t			rnum = getminor(dev);

	/*
	 * Char only
	 */
	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}
	D2("daplka_close: closing rnum = %d\n", rnum);
	atomic_inc_32(&daplka_pending_close);

	/*
	 * remove from resource table.
	 */
	ia_rp = (daplka_ia_resource_t *)daplka_resource_remove(rnum);

	/*
	 * remove the initial reference
	 */
	if (ia_rp != NULL) {
		DAPLKA_RS_UNREF(ia_rp);
	}
	atomic_dec_32(&daplka_pending_close);
	return (DDI_SUCCESS);
}


/*
 * Resource management routines
 *
 * We start with no resource array. Each time we run out of slots, we
 * reallocate a new larger array and copy the pointer to the new array and
 * a new resource blk is allocated and added to the hash table.
 *
 * The resource control block contains:
 *      root    - array of pointer of resource blks
 *      sz      - current size of array.
 *      len     - last valid entry in array.
 *
 * A search operation based on a resource number is as follows:
 *      index = rnum / RESOURCE_BLKSZ;
 *      ASSERT(index < resource_block.len);
 *      ASSERT(index < resource_block.sz);
 *      offset = rnum % RESOURCE_BLKSZ;
 *      ASSERT(offset >= resource_block.root[index]->base);
 *      ASSERT(offset < resource_block.root[index]->base + RESOURCE_BLKSZ);
 *      return resource_block.root[index]->blks[offset];
 *
 * A resource blk is freed when its used count reaches zero.
 */

/*
 * initializes the global resource table
 */
static void
daplka_resource_init(void)
{
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(daplka_resource))
	rw_init(&daplka_resource.daplka_rct_lock, NULL, RW_DRIVER, NULL);
	daplka_resource.daplka_rc_len = 0;
	daplka_resource.daplka_rc_sz = 0;
	daplka_resource.daplka_rc_cnt = 0;
	daplka_resource.daplka_rc_flag = 0;
	daplka_resource.daplka_rc_root = NULL;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(daplka_resource))
}

/*
 * destroys the global resource table
 */
static void
daplka_resource_fini(void)
{
	int	i;

	rw_enter(&daplka_resource.daplka_rct_lock, RW_WRITER);
	for (i = 0; i < daplka_resource.daplka_rc_len; i++) {
		daplka_resource_blk_t	*blk;
		int			j;

		blk = daplka_resource.daplka_rc_root[i];
		if (blk == NULL) {
			continue;
		}
		for (j = 0; j < DAPLKA_RC_BLKSZ; j++) {
			if (blk->daplka_rcblk_blks[j] != NULL) {
				DERR("resource_fini: non-null slot %d, %p\n",
				    j, blk->daplka_rcblk_blks[j]);
			}
		}
		kmem_free(blk, sizeof (*blk));
		daplka_resource.daplka_rc_root[i] = NULL;
	}
	if (daplka_resource.daplka_rc_root != NULL) {
		uint_t	sz;

		sz = daplka_resource.daplka_rc_sz *
		    sizeof (daplka_resource_blk_t *);
		kmem_free(daplka_resource.daplka_rc_root, (uint_t)sz);
		daplka_resource.daplka_rc_root = NULL;
		daplka_resource.daplka_rc_len = 0;
		daplka_resource.daplka_rc_sz = 0;
	}
	rw_exit(&daplka_resource.daplka_rct_lock);
	rw_destroy(&daplka_resource.daplka_rct_lock);
}

/*
 * reserves a slot in the global resource table.
 * this is called by the open() syscall. it is needed because
 * at open() time, we do not have sufficient information to
 * create an IA resource. the library needs to subsequently
 * call daplka_ia_create to insert an IA resource into this
 * reserved slot.
 */
static int
daplka_resource_reserve(minor_t *rnum)
{
	int i, j, empty = -1;
	daplka_resource_blk_t *blk;

	rw_enter(&daplka_resource.daplka_rct_lock, RW_WRITER);
	/*
	 * Try to find an empty slot
	 */
	for (i = 0; i < daplka_resource.daplka_rc_len; i++) {
		blk = daplka_resource.daplka_rc_root[i];
		if (blk != NULL && blk->daplka_rcblk_avail > 0) {

			D3("resource_alloc: available blks %d\n",
			    blk->daplka_rcblk_avail);

			/*
			 * found an empty slot in this blk
			 */
			for (j = 0; j < DAPLKA_RC_BLKSZ; j++) {
				if (blk->daplka_rcblk_blks[j] == NULL) {
					*rnum = (minor_t)
					    (j + (i * DAPLKA_RC_BLKSZ));
					blk->daplka_rcblk_blks[j] =
					    (daplka_resource_t *)
					    DAPLKA_RC_RESERVED;
					blk->daplka_rcblk_avail--;
					daplka_resource.daplka_rc_cnt++;
					rw_exit(&daplka_resource.
					    daplka_rct_lock);
					return (0);
				}
			}
		} else if (blk == NULL && empty < 0) {
			/*
			 * remember first empty slot
			 */
			empty = i;
		}
	}

	/*
	 * Couldn't find anything, allocate a new blk
	 * Do we need to reallocate the root array
	 */
	if (empty < 0) {
		if (daplka_resource.daplka_rc_len ==
		    daplka_resource.daplka_rc_sz) {
			/*
			 * Allocate new array and copy current stuff into it
			 */
			daplka_resource_blk_t	**p;
			uint_t newsz = (uint_t)daplka_resource.daplka_rc_sz +
			    DAPLKA_RC_BLKSZ;

			D3("resource_alloc: increasing no. of buckets to %d\n",
			    newsz);

			p = kmem_zalloc(newsz * sizeof (*p), daplka_km_flags);

			if (daplka_resource.daplka_rc_root) {
				uint_t oldsz;

				oldsz = (uint_t)(daplka_resource.daplka_rc_sz *
				    (int)sizeof (*p));

				/*
				 * Copy old data into new space and
				 * free old stuff
				 */
				bcopy(daplka_resource.daplka_rc_root, p, oldsz);
				kmem_free(daplka_resource.daplka_rc_root,
				    oldsz);
			}

			daplka_resource.daplka_rc_root = p;
			daplka_resource.daplka_rc_sz = (int)newsz;
		}

		empty = daplka_resource.daplka_rc_len;
		daplka_resource.daplka_rc_len++;

		D3("resource_alloc: daplka_rc_len %d\n",
		    daplka_resource.daplka_rc_len);
	}

	/*
	 * Allocate a new blk
	 */
	blk = kmem_zalloc(sizeof (*blk), daplka_km_flags);
	ASSERT(daplka_resource.daplka_rc_root[empty] == NULL);
	daplka_resource.daplka_rc_root[empty] = blk;
	blk->daplka_rcblk_avail = DAPLKA_RC_BLKSZ - 1;

	/*
	 * Allocate slot
	 */
	*rnum = (minor_t)(empty * DAPLKA_RC_BLKSZ);
	blk->daplka_rcblk_blks[0] = (daplka_resource_t *)DAPLKA_RC_RESERVED;
	daplka_resource.daplka_rc_cnt++;
	rw_exit(&daplka_resource.daplka_rct_lock);

	return (0);
}

/*
 * removes resource from global resource table
 */
static daplka_resource_t *
daplka_resource_remove(minor_t rnum)
{
	int i, j;
	daplka_resource_blk_t *blk;
	daplka_resource_t *p;

	i = (int)(rnum / DAPLKA_RC_BLKSZ);
	j = (int)(rnum % DAPLKA_RC_BLKSZ);

	rw_enter(&daplka_resource.daplka_rct_lock, RW_WRITER);
	if (i >= daplka_resource.daplka_rc_len) {
		rw_exit(&daplka_resource.daplka_rct_lock);
		DERR("resource_remove: invalid rnum %d\n", rnum);
		return (NULL);
	}

	ASSERT(daplka_resource.daplka_rc_root);
	ASSERT(i < daplka_resource.daplka_rc_len);
	ASSERT(i < daplka_resource.daplka_rc_sz);
	blk = daplka_resource.daplka_rc_root[i];
	if (blk == NULL) {
		rw_exit(&daplka_resource.daplka_rct_lock);
		DERR("resource_remove: invalid rnum %d\n", rnum);
		return (NULL);
	}

	if (blk->daplka_rcblk_blks[j] == NULL) {
		rw_exit(&daplka_resource.daplka_rct_lock);
		DERR("resource_remove: blk->daplka_rcblk_blks[j] == NULL\n");
		return (NULL);
	}
	p = blk->daplka_rcblk_blks[j];
	blk->daplka_rcblk_blks[j] = NULL;
	blk->daplka_rcblk_avail++;
	if (blk->daplka_rcblk_avail == DAPLKA_RC_BLKSZ) {
		/*
		 * free this blk
		 */
		kmem_free(blk, sizeof (*blk));
		daplka_resource.daplka_rc_root[i] = NULL;
	}
	daplka_resource.daplka_rc_cnt--;
	rw_exit(&daplka_resource.daplka_rct_lock);

	if ((intptr_t)p == DAPLKA_RC_RESERVED) {
		return (NULL);
	} else {
		return (p);
	}
}

/*
 * inserts resource into the slot designated by rnum
 */
static int
daplka_resource_insert(minor_t rnum, daplka_resource_t *rp)
{
	int i, j, error = -1;
	daplka_resource_blk_t *blk;

	/*
	 * Find resource and lock it in WRITER mode
	 * search for available resource slot
	 */

	i = (int)(rnum / DAPLKA_RC_BLKSZ);
	j = (int)(rnum % DAPLKA_RC_BLKSZ);

	rw_enter(&daplka_resource.daplka_rct_lock, RW_WRITER);
	if (i >= daplka_resource.daplka_rc_len) {
		rw_exit(&daplka_resource.daplka_rct_lock);
		DERR("resource_insert: resource %d not found\n", rnum);
		return (-1);
	}

	blk = daplka_resource.daplka_rc_root[i];
	if (blk != NULL) {
		ASSERT(i < daplka_resource.daplka_rc_len);
		ASSERT(i < daplka_resource.daplka_rc_sz);

		if ((intptr_t)blk->daplka_rcblk_blks[j] == DAPLKA_RC_RESERVED) {
			blk->daplka_rcblk_blks[j] = rp;
			error = 0;
		} else {
			DERR("resource_insert: %d not reserved, blk = %p\n",
			    rnum, blk->daplka_rcblk_blks[j]);
		}
	} else {
		DERR("resource_insert: resource %d not found\n", rnum);
	}
	rw_exit(&daplka_resource.daplka_rct_lock);
	return (error);
}

/*
 * finds resource using minor device number
 */
static daplka_resource_t *
daplka_resource_lookup(minor_t rnum)
{
	int i, j;
	daplka_resource_blk_t *blk;
	daplka_resource_t *rp;

	/*
	 * Find resource and lock it in READER mode
	 * search for available resource slot
	 */

	i = (int)(rnum / DAPLKA_RC_BLKSZ);
	j = (int)(rnum % DAPLKA_RC_BLKSZ);

	rw_enter(&daplka_resource.daplka_rct_lock, RW_READER);
	if (i >= daplka_resource.daplka_rc_len) {
		rw_exit(&daplka_resource.daplka_rct_lock);
		DERR("resource_lookup: resource %d not found\n", rnum);
		return (NULL);
	}

	blk = daplka_resource.daplka_rc_root[i];
	if (blk != NULL) {
		ASSERT(i < daplka_resource.daplka_rc_len);
		ASSERT(i < daplka_resource.daplka_rc_sz);

		rp = blk->daplka_rcblk_blks[j];
		if (rp == NULL || (intptr_t)rp == DAPLKA_RC_RESERVED) {
			D3("resource_lookup: %d not found, blk = %p\n",
			    rnum, blk->daplka_rcblk_blks[j]);
		} else {
			DAPLKA_RS_REF((daplka_ia_resource_t *)rp);
		}
	} else {
		DERR("resource_lookup: resource %d not found\n", rnum);
		rp = NULL;
	}
	rw_exit(&daplka_resource.daplka_rct_lock);
	return (rp);
}

/*
 * generic hash table implementation
 */

/*
 * daplka_hash_create:
 *	initializes a hash table with the specified parameters
 *
 * input:
 *	htblp			pointer to hash table
 *
 *	nbuckets		number of buckets (must be power of 2)
 *
 *	free_func		this function is called on each hash
 *				table element when daplka_hash_destroy
 *				is called
 *
 *	lookup_func		if daplka_hash_lookup is able to find
 *				the desired object, this function is
 *				applied on the object before
 *				daplka_hash_lookup returns
 * output:
 *	none
 *
 * return value(s):
 *	EINVAL			nbuckets is not a power of 2
 *	ENOMEM			cannot allocate buckets
 *	0			success
 */
static int
daplka_hash_create(daplka_hash_table_t *htblp, uint_t nbuckets,
	void (*free_func)(void *), void (*lookup_func)(void *))
{
	int i;

	if ((nbuckets & ~(nbuckets - 1)) != nbuckets) {
		DERR("hash_create: nbuckets not power of 2\n");
		return (EINVAL);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*htblp))

	htblp->ht_buckets =
	    kmem_zalloc(sizeof (daplka_hash_bucket_t) * nbuckets,
	    daplka_km_flags);
	if (htblp->ht_buckets == NULL) {
		DERR("hash_create: cannot allocate buckets\n");
		return (ENOMEM);
	}
	for (i = 0; i < nbuckets; i++) {
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(htblp->ht_buckets[i]))
		htblp->ht_buckets[i].hb_count = 0;
		htblp->ht_buckets[i].hb_entries = NULL;
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(htblp->ht_buckets[i]))
	}
	rw_init(&htblp->ht_table_lock, NULL, RW_DRIVER, NULL);
	mutex_init(&htblp->ht_key_lock, NULL, MUTEX_DRIVER, NULL);

	htblp->ht_count = 0;
	htblp->ht_next_hkey = (uint64_t)gethrtime();
	htblp->ht_nbuckets = nbuckets;
	htblp->ht_free_func = free_func;
	htblp->ht_lookup_func = lookup_func;
	htblp->ht_initialized = B_TRUE;
	D3("hash_create: done, buckets = %d\n", nbuckets);
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*htblp))
	return (0);
}

/*
 * daplka_hash_insert:
 *	inserts an object into a hash table
 *
 * input:
 *	htblp			pointer to hash table
 *
 *	hkeyp			pointer to hash key.
 *				*hkeyp being non-zero means that the caller
 *				has generated its own hkey. if *hkeyp is zero,
 *				this function will generate an hkey for the
 *				caller. it is recommended that the caller
 *				leave the hkey generation to this function
 *				because the hkey is more likely to be evenly
 *				distributed.
 *
 *	objp			pointer to object to be inserted into
 *				hash table
 *
 * output:
 *	hkeyp			the generated hkey is returned via this pointer
 *
 * return value(s):
 *	EINVAL			invalid parameter
 *	ENOMEM			cannot allocate hash entry
 *	0			successful
 */
static int
daplka_hash_insert(daplka_hash_table_t *htblp, uint64_t *hkeyp, void *objp)
{
	daplka_hash_entry_t *hep, *curr_hep;
	daplka_hash_bucket_t *hbp;
	uint32_t bucket;
	uint64_t hkey;

	if (hkeyp == NULL) {
		DERR("hash_insert: hkeyp == NULL\n");
		return (EINVAL);
	}
	hep = kmem_zalloc(sizeof (*hep), daplka_km_flags);
	if (hep == NULL) {
		DERR("hash_insert: cannot alloc hash_entry\n");
		return (ENOMEM);
	}
	if (*hkeyp == 0) {
		/* generate a new key */
		mutex_enter(&htblp->ht_key_lock);
		hkey = ++htblp->ht_next_hkey;
		if (hkey == 0) {
			hkey = htblp->ht_next_hkey = (uint64_t)gethrtime();
		}
		mutex_exit(&htblp->ht_key_lock);
	} else {
		/* use user generated key */
		hkey = *hkeyp;
	}

	/* only works if ht_nbuckets is a power of 2 */
	bucket = (uint32_t)(hkey & (htblp->ht_nbuckets - 1));
	ASSERT(objp != NULL);
	ASSERT(bucket < htblp->ht_nbuckets);

	rw_enter(&htblp->ht_table_lock, RW_WRITER);
	hep->he_hkey = hkey;
	hep->he_objp = objp;

	/* look for duplicate entries */
	hbp = &htblp->ht_buckets[bucket];
	curr_hep = hbp->hb_entries;
	while (curr_hep != NULL) {
		if (curr_hep->he_hkey == hep->he_hkey) {
			break;
		}
		curr_hep = curr_hep->he_next;
	}
	if (curr_hep != NULL) {
		DERR("hash_insert: found duplicate hash entry: "
		    "bucket %d, hkey 0x%016llx\n",
		    bucket, (longlong_t)hep->he_hkey);
		kmem_free(hep, sizeof (*hep));
		rw_exit(&htblp->ht_table_lock);
		return (EINVAL);
	}
	hep->he_next = hbp->hb_entries;
	hbp->hb_entries = hep;
	hbp->hb_count++;
	htblp->ht_count++;
	rw_exit(&htblp->ht_table_lock);

	if (*hkeyp == 0) {
		*hkeyp = hkey;
		ASSERT(*hkeyp != 0);
	}
	D3("hash_insert: htblp 0x%p, hkey = 0x%016llx, bucket = %d\n",
	    htblp, (longlong_t)*hkeyp, bucket);
	return (0);
}

/*
 * daplka_hash_remove:
 *	removes object identified by hkey from hash table
 *
 * input:
 *	htblp			pointer to hash table
 *
 *	hkey			hkey that identifies the object to be removed
 *
 * output:
 *	objpp			pointer to pointer to object.
 *				if remove is successful, the removed object
 *				will be returned via *objpp.
 *
 * return value(s):
 *	EINVAL			cannot find hash entry
 *	0			successful
 */
static int
daplka_hash_remove(daplka_hash_table_t *htblp, uint64_t hkey, void **objpp)
{
	daplka_hash_entry_t	*free_hep, **curr_hepp;
	daplka_hash_bucket_t	*hbp;
	uint32_t		bucket;

	bucket = (uint32_t)(hkey & (htblp->ht_nbuckets - 1));

	rw_enter(&htblp->ht_table_lock, RW_WRITER);
	hbp = &htblp->ht_buckets[bucket];

	curr_hepp = &hbp->hb_entries;
	while (*curr_hepp != NULL) {
		if ((*curr_hepp)->he_hkey == hkey) {
			break;
		}
		curr_hepp = &(*curr_hepp)->he_next;
	}
	if (*curr_hepp == NULL) {
		DERR("hash_remove: cannot find hash entry: "
		    "bucket %d, hkey 0x%016llx\n", bucket, (longlong_t)hkey);
		rw_exit(&htblp->ht_table_lock);
		return (EINVAL);
	} else {
		if (objpp != NULL) {
			*objpp = (*curr_hepp)->he_objp;
		}
		free_hep = *curr_hepp;
		*curr_hepp = (*curr_hepp)->he_next;
		kmem_free(free_hep, sizeof (*free_hep));
	}
	hbp->hb_count--;
	htblp->ht_count--;
	D3("hash_remove: removed entry, hkey 0x%016llx, bucket %d, "
	    "hb_count %d, hb_count %d\n",
	    (longlong_t)hkey, bucket, hbp->hb_count, htblp->ht_count);
	rw_exit(&htblp->ht_table_lock);
	return (0);
}

/*
 * daplka_hash_walk:
 *	walks through the entire hash table. applying func on each of
 *	the inserted objects. stops walking if func returns non-zero.
 *
 * input:
 *	htblp			pointer to hash table
 *
 *	func			function to be applied on each object
 *
 *	farg			second argument to func
 *
 *	lockmode		can be RW_WRITER or RW_READER. this
 *				allows the caller to choose what type
 *				of lock to acquire before walking the
 *				table.
 *
 * output:
 *	none
 *
 * return value(s):
 *	none
 */
static void
daplka_hash_walk(daplka_hash_table_t *htblp, int (*func)(void *, void *),
	void *farg, krw_t lockmode)
{
	daplka_hash_entry_t *curr_hep;
	daplka_hash_bucket_t *hbp;
	uint32_t bucket, retval = 0;

	ASSERT(lockmode == RW_WRITER || lockmode == RW_READER);

	/* needed for warlock */
	if (lockmode == RW_WRITER) {
		rw_enter(&htblp->ht_table_lock, RW_WRITER);
	} else {
		rw_enter(&htblp->ht_table_lock, RW_READER);
	}
	for (bucket = 0; bucket < htblp->ht_nbuckets && retval == 0; bucket++) {
		hbp = &htblp->ht_buckets[bucket];
		curr_hep = hbp->hb_entries;
		while (curr_hep != NULL) {
			retval = (*func)(curr_hep->he_objp, farg);
			if (retval != 0) {
				break;
			}
			curr_hep = curr_hep->he_next;
		}
	}
	rw_exit(&htblp->ht_table_lock);
}

/*
 * daplka_hash_lookup:
 *	finds object from hkey
 *
 * input:
 *	htblp			pointer to hash table
 *
 *	hkey			hkey that identifies the object to be looked up
 *
 * output:
 *	none
 *
 * return value(s):
 *	NULL			if not found
 *	object pointer		if found
 */
static void *
daplka_hash_lookup(daplka_hash_table_t *htblp, uint64_t hkey)
{
	daplka_hash_entry_t *curr_hep;
	uint32_t bucket;
	void *objp;

	bucket = (uint32_t)(hkey & (htblp->ht_nbuckets - 1));

	rw_enter(&htblp->ht_table_lock, RW_READER);
	curr_hep = htblp->ht_buckets[bucket].hb_entries;
	while (curr_hep != NULL) {
		if (curr_hep->he_hkey == hkey) {
			break;
		}
		curr_hep = curr_hep->he_next;
	}
	if (curr_hep == NULL) {
		DERR("hash_lookup: cannot find hash entry: "
		    "bucket %d, hkey 0x%016llx\n", bucket, (longlong_t)hkey);
		rw_exit(&htblp->ht_table_lock);
		return (NULL);
	}
	objp = curr_hep->he_objp;
	ASSERT(objp != NULL);
	if (htblp->ht_lookup_func != NULL) {
		(*htblp->ht_lookup_func)(objp);
	}
	rw_exit(&htblp->ht_table_lock);
	return (objp);
}

/*
 * daplka_hash_destroy:
 *	destroys hash table. applies free_func on all inserted objects.
 *
 * input:
 *	htblp			pointer to hash table
 *
 * output:
 *	none
 *
 * return value(s):
 *	none
 */
static void
daplka_hash_destroy(daplka_hash_table_t *htblp)
{
	daplka_hash_entry_t *curr_hep, *free_hep;
	daplka_hash_entry_t *free_list = NULL;
	daplka_hash_bucket_t *hbp;
	uint32_t bucket, cnt, total = 0;

	if (!htblp->ht_initialized) {
		DERR("hash_destroy: not initialized\n");
		return;
	}
	/* free all elements from hash table */
	rw_enter(&htblp->ht_table_lock, RW_WRITER);
	for (bucket = 0; bucket < htblp->ht_nbuckets; bucket++) {
		hbp = &htblp->ht_buckets[bucket];

		/* build list of elements to be freed */
		curr_hep = hbp->hb_entries;
		cnt = 0;
		while (curr_hep != NULL) {
			cnt++;
			free_hep = curr_hep;
			curr_hep = curr_hep->he_next;

			free_hep->he_next = free_list;
			free_list = free_hep;
		}
		ASSERT(cnt == hbp->hb_count);
		total += cnt;
		hbp->hb_count = 0;
		hbp->hb_entries = NULL;
	}
	ASSERT(total == htblp->ht_count);
	D3("hash_destroy: htblp 0x%p, nbuckets %d, freed %d hash entries\n",
	    htblp, htblp->ht_nbuckets, total);
	rw_exit(&htblp->ht_table_lock);

	/* free all objects, now without holding the hash table lock */
	cnt = 0;
	while (free_list != NULL) {
		cnt++;
		free_hep = free_list;
		free_list = free_list->he_next;
		if (htblp->ht_free_func != NULL) {
			(*htblp->ht_free_func)(free_hep->he_objp);
		}
		kmem_free(free_hep, sizeof (*free_hep));
	}
	ASSERT(total == cnt);

	/* free hash buckets and destroy locks */
	kmem_free(htblp->ht_buckets,
	    sizeof (daplka_hash_bucket_t) * htblp->ht_nbuckets);

	rw_enter(&htblp->ht_table_lock, RW_WRITER);
	htblp->ht_buckets = NULL;
	htblp->ht_count = 0;
	htblp->ht_nbuckets = 0;
	htblp->ht_free_func = NULL;
	htblp->ht_lookup_func = NULL;
	htblp->ht_initialized = B_FALSE;
	rw_exit(&htblp->ht_table_lock);

	mutex_destroy(&htblp->ht_key_lock);
	rw_destroy(&htblp->ht_table_lock);
}

/*
 * daplka_hash_getsize:
 *	return the number of objects in hash table
 *
 * input:
 *	htblp			pointer to hash table
 *
 * output:
 *	none
 *
 * return value(s):
 *	number of objects in hash table
 */
static uint32_t
daplka_hash_getsize(daplka_hash_table_t *htblp)
{
	uint32_t sz;

	rw_enter(&htblp->ht_table_lock, RW_READER);
	sz = htblp->ht_count;
	rw_exit(&htblp->ht_table_lock);

	return (sz);
}

/*
 * this function is used as ht_lookup_func above when lookup is called.
 * other types of objs may use a more elaborate lookup_func.
 */
static void
daplka_hash_generic_lookup(void *obj)
{
	daplka_resource_t	*rp = (daplka_resource_t *)obj;

	mutex_enter(&rp->rs_reflock);
	rp->rs_refcnt++;
	ASSERT(rp->rs_refcnt != 0);
	mutex_exit(&rp->rs_reflock);
}

/*
 * Generates a non-zero 32 bit hash key used for the timer hash table.
 */
static uint32_t
daplka_timer_hkey_gen()
{
	uint32_t new_hkey;

	do {
		new_hkey = atomic_inc_32_nv(&daplka_timer_hkey);
	} while (new_hkey == 0);

	return (new_hkey);
}


/*
 * The DAPL KA debug logging routines
 */

/*
 * Add the string str to the end of the debug log, followed by a newline.
 */
static void
daplka_dbglog(char *str)
{
	size_t	length;
	size_t	remlen;

	/*
	 * If this is the first time we've written to the log, initialize it.
	 */
	if (!daplka_dbginit) {
		return;
	}
	mutex_enter(&daplka_dbglock);
	/*
	 * Note the log is circular; if this string would run over the end,
	 * we copy the first piece to the end and then the last piece to
	 * the beginning of the log.
	 */
	length = strlen(str);

	remlen = (size_t)sizeof (daplka_dbgbuf) - daplka_dbgnext - 1;

	if (length > remlen) {
		if (remlen)
			bcopy(str, daplka_dbgbuf + daplka_dbgnext, remlen);
		daplka_dbgbuf[sizeof (daplka_dbgbuf) - 1] = (char)NULL;
		str += remlen;
		length -= remlen;
		daplka_dbgnext = 0;
	}
	bcopy(str, daplka_dbgbuf + daplka_dbgnext, length);
	daplka_dbgnext += length;

	if (daplka_dbgnext >= sizeof (daplka_dbgbuf))
		daplka_dbgnext = 0;
	mutex_exit(&daplka_dbglock);
}


/*
 * Add a printf-style message to whichever debug logs we're currently using.
 */
static void
daplka_debug(const char *fmt, ...)
{
	char	buff[512];
	va_list	ap;
	/*
	 * The system prepends the thread id and high resolution time
	 * (nanoseconds are dropped and so are the upper digits)
	 * to the specified string.
	 * The unit for timestamp is 10 microseconds.
	 * It wraps around every 10000 seconds.
	 * Ex: gethrtime() = X ns = X/1000 us = X/10000 10 micro sec.
	 */
	int	micro_time = (int)((gethrtime() / 10000) % 1000000000);
	(void) sprintf(buff, "th %p tm %9d: ", (void *)curthread, micro_time);

	va_start(ap, fmt);
	(void) vsprintf(buff+strlen(buff), fmt, ap);
	va_end(ap);

	daplka_dbglog(buff);
}

static void
daplka_console(const char *fmt, ...)
{
	char buff[512];
	va_list ap;

	va_start(ap, fmt);
	(void) vsprintf(buff, fmt, ap);
	va_end(ap);

	cmn_err(CE_CONT, "%s", buff);
}
