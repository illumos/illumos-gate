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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/cpuvar.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/socket.h>
#include <inet/tcp.h>
#include <sys/sdt.h>

#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>
#include <sys/idm/idm.h>
#include <sys/idm/idm_so.h>
#include <sys/iscsit/iscsit_common.h>
#include <sys/iscsit/isns_protocol.h>
#include <sys/ksocket.h>

#include "iscsit.h"
#include "iscsit_isns.h"

/*
 * iscsit_isns.c -- isns client that is part of the iscsit server
 *
 * The COMSTAR iSCSI target uses four pieces of iSNS functionality:
 * - DevAttrReg to notify the iSNS server of our targets and portals.
 * - DeregDev to notify when a target goes away or we shut down
 * - DevAttrQry (self-query) to see if iSNS server still knows us.
 * - Request ESI probes from iSNS server as a keepalive mechanism
 *
 * We send only two kinds of DevAttrReg messages.
 *
 * REPLACE-ALL the info the iSNS server knows about us:
 *    Set Flag in PDU header to ISNS_FLAG_REPLACE_REG
 *    Set "source" to same iSCSI target each time
 *    EID (Entity Identifier) == our DNS name
 *    "Delimiter"
 *    Object operated on = EID
 *    "Entity Portals" owned by this "network entity"
 *    List of targets
 *     (Targets with TPGT are followed by PGT and PG portal info)
 *
 *   UPDATE-EXISTING - used to register/change one target at a time
 *    Flag for replace reg not set
 *    Source and EID and Delimiter and Object Operated On as above
 *    Single Target
 *      (Targets with TPGT are followed by PGT and PG portal info)
 *
 * Interfaces to iscsit
 *
 * iscsit_isns_init -- called when iscsi/target service goes online
 * iscsit_isns_fini -- called when iscsi/target service goes offline
 * iscsit_isns_register -- a new target comes online
 * iscsit_isns_deregister -- target goes offline
 * iscsit_isns_target_update -- called when a target is modified
 * iscsit_isns_portal_online -- called when defining a new portal
 * iscsit_isns_portal_offline -- no longer using a portal
 *
 * Copying Data Structures
 *
 * The above routines copy all the data they need, so iscsit can
 * proceed without interfering with us.  This is moving in the
 * direction of having this isns_client be a standalone user-mode
 * program. Specifically, we copy the target name, alias, and
 * tpgt+portal information.
 *
 * The iscsit_isns_mutex protects the shadow copies of target and portal
 * information.  The ISNS_GLOBAL_LOCK protects the iSNS run time structures
 * that the monitor thread uses. The routine isnst_copy_global_status_changes
 * has to acquire both locks and copy all the required information from the
 * global structs to the per-server structs.  Once it completes, the monitor
 * thread should run completely off the per-server copies.
 *
 * Global State vs Per-Server state
 * There is a global list of targets and portals that is kept updated
 * by iscsit.  Each svr keeps its own list of targets that have been
 * announced to the iSNS server.
 *
 * Invariants
 *
 * 1) If svr->svr_registered, then there is some itarget with
 *    itarget->target_registered.
 * 2) If itarget->target_delete_needed, then also itarget->target_registered.
 *    (Corollary: Any time you remove the last registered target, you have
 *    to send an unregister-all message.)
 * 3) If a target has a non-default portal, then the portal goes online
 *    before the target goes online, and comes offline afterwards.
 *    (This is enforced by the iscsit state machines.)
 */
/* local defines */
#define	MAX_XID			(2^16)
#define	ISNS_IDLE_TIME		60
#define	MAX_RETRY		(3)
#define	ISNS_RCV_TIMER_SECONDS	5

#define	VALID_NAME(NAME, LEN)	\
((LEN) > 0 && (NAME)[0] != 0 && (NAME)[(LEN) - 1] == 0)


#define	ISNST_LOG if (iscsit_isns_logging) cmn_err

static kmutex_t	isns_monitor_mutex;
volatile kthread_t	*isns_monitor_thr_id;
static kt_did_t		isns_monitor_thr_did;
static boolean_t	isns_monitor_thr_running;

static kcondvar_t	isns_idle_cv;

static uint16_t		xid;
#define	GET_XID()	atomic_inc_16_nv(&xid)

static clock_t		monitor_idle_interval;

/* The ISNS_GLOBAL_LOCK protects the per-server data structures */
#define	ISNS_GLOBAL_LOCK() \
	mutex_enter(&iscsit_global.global_isns_cfg.isns_mutex)

#define	ISNS_GLOBAL_LOCK_HELD() \
	MUTEX_HELD(&iscsit_global.global_isns_cfg.isns_mutex)

#define	ISNS_GLOBAL_UNLOCK() \
	mutex_exit(&iscsit_global.global_isns_cfg.isns_mutex)

/*
 * "Configurable" parameters (set in /etc/system for now).
 */
boolean_t iscsit_isns_logging = B_FALSE;


/*
 * If fail this many times to send an update to the server, then
 * declare the server non-responsive and reregister everything with
 * the server when we next connect.
 */
int	isns_max_retry = MAX_RETRY;

/*
 * The use of ESI probes to all active portals is not appropriate in
 * all network environments, since the iSNS server may not have
 * connectivity to all portals, so we turn it off by default.
 */
boolean_t	isns_use_esi = B_FALSE;

/*
 * Interval to request ESI probes at, in seconds.  The server is free
 * to specify a different frequency in its response.
 */
int	isns_default_esi_interval = ISNS_DEFAULT_ESI_INTERVAL;


/*
 * Registration Period -- we guarantee to check in with iSNS server at
 * least this often.  Used when ESI probes are turned off.
 */
int	isns_registration_period = ISNS_DEFAULT_REGISTRATION_PERIOD;

/*
 * Socket connect, PDU receive, and PDU send must complete
 * within this number of microseconds.
 */
uint32_t	isns_timeout_usec = ISNS_RCV_TIMER_SECONDS * 1000000;


/*
 * iSNS Message size -- we start with the max that can fit into one PDU.
 * If the message doesn't fit, we will expand at run time to a higher
 * value. This parameter could be set in /etc/system if some particular
 * installation knows it always goes over the standard limit.
 */
uint32_t	isns_message_buf_size = ISNSP_MAX_PDU_SIZE;

/*
 * Number of seconds to wait after isnst_monitor thread starts up
 * before sending first DevAttrReg message.
 */
int	isns_initial_delay = ISNS_INITIAL_DELAY;

/*
 * Because of a bug in the Solaris isns server (c 2009), we cannot send a
 * modify operation that changes the target's TPGTs. So just replace all.
 * If the iSNS server does not have this bug, clear this flag.
 * Changes take effect on each modify_target operation
 */
boolean_t isns_modify_must_replace = B_TRUE;

/* If PDU sizes ever go over the following, we need to rearchitect */
#define	ISNST_MAX_MSG_SIZE (16 * ISNSP_MAX_PDU_SIZE)

/*
 * iSNS ESI thread state
 */
static isns_esi_tinfo_t	esi;

/*
 * Our list of targets.  Kept in lock-step synch with iscsit.
 * The iscsit_isns_mutex protects the global data structures that are
 * kept in lock-step with iscsit.
 * NOTE: Now that isnst runs independently of iscsit, we could remove the
 * shadow copies of iscsit structures, such as isns_target_list and
 * isns_tpg_portals, and have isnst_copy_global_status_changes reconcile
 * isnst directly with the iscsit data structures.
 */
static kmutex_t		iscsit_isns_mutex;
static avl_tree_t	isns_target_list;
static boolean_t	isns_targets_changed;

/*
 * List of portals from TPGs.  Protected by iscsit_isns_mutex.
 */
static boolean_t	isns_portals_changed;
static avl_tree_t	isns_tpg_portals;
static boolean_t	default_portal_online;

/* List of all portals.  Protected by ISNS_GLOBAL_LOCK */
static avl_tree_t	isns_all_portals;
static int		num_default_portals;
static int		num_tpg_portals;

/*
 * Our entity identifier (fully-qualified hostname). Passed in from libiscsit.
 */
static char		*isns_eid = NULL;

/*
 * in6addr_any is currently all zeroes, but use the macro in case this
 * ever changes.
 */
static const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;

static void
isnst_start();

static void
isnst_stop();

static void
iscsit_set_isns(boolean_t state);

static void
iscsit_add_isns(it_portal_t *cfg_svr);

static void
isnst_mark_delete_isns(iscsit_isns_svr_t *svr);

static void
isnst_finish_delete_isns(iscsit_isns_svr_t *svr);

static iscsit_isns_svr_t *
iscsit_isns_svr_lookup(struct sockaddr_storage *sa);

static void
isnst_monitor(void *arg);

static int
isnst_monitor_one_server(iscsit_isns_svr_t *svr, boolean_t enabled);

static void
isnst_monitor_awaken(void);

static boolean_t
isnst_update_server_timestamp(struct sockaddr_storage *sa);

static void
isnst_copy_global_status_changes(void);

static void
isnst_mark_deleted_targets(iscsit_isns_svr_t *svr);

static  int
isnst_update_one_server(iscsit_isns_svr_t *svr, isns_target_t *target,
    isns_reg_type_t reg);

static boolean_t isnst_retry_registration(int rsp_status_code);

static int isnst_register(iscsit_isns_svr_t *svr, isns_target_t *itarget,
    isns_reg_type_t regtype);
static int isnst_deregister(iscsit_isns_svr_t *svr, isns_target_t *itarget);

static size_t
isnst_make_dereg_pdu(iscsit_isns_svr_t *svr, isns_pdu_t **pdu,
    isns_target_t *itarge);

static int isnst_keepalive(iscsit_isns_svr_t *svr);
static size_t
isnst_make_keepalive_pdu(iscsit_isns_svr_t *svr, isns_pdu_t **pdu);

static isns_target_t *
isnst_get_registered_source(iscsit_isns_svr_t *srv);
static isns_target_t *
isnst_get_registered_source_locked(iscsit_isns_svr_t *srv);

static int
isnst_verify_rsp(iscsit_isns_svr_t *svr, isns_pdu_t *pdu,
    isns_pdu_t *rsp, size_t rsp_size);

static uint16_t
isnst_pdu_get_op(isns_pdu_t *pdu, uint8_t **pp);

static size_t
isnst_make_reg_pdu(isns_pdu_t **pdu, isns_target_t *target,
    iscsit_isns_svr_t *svr, isns_reg_type_t regtype);

static int
isnst_reg_pdu_add_entity_portals(isns_pdu_t *pdu, size_t pdu_size);

static int
isnst_reg_pdu_add_pg(isns_pdu_t *pdu, size_t pdu_size, isns_target_t *target);

static int
isnst_add_default_pg(isns_pdu_t *pdu, size_t pdu_size,
    avl_tree_t *null_portal_list);

static int
isnst_add_tpg_pg(isns_pdu_t *pdu, size_t pdu_size,
    isns_tpgt_t *tig, avl_tree_t *null_portal_list);

static int
isnst_add_null_pg(isns_pdu_t *pdu, size_t pdu_size,
    avl_tree_t *null_portal_list);

static int
isnst_add_portal_attr(isns_pdu_t *pdu, size_t pdu_size,
    uint32_t ip_attr_id, uint32_t port_attr_id,
    struct sockaddr_storage *ss, boolean_t esi_info);

static size_t
isnst_create_pdu_header(uint16_t func_id, isns_pdu_t **pdu, uint16_t flags);

static int
isnst_add_attr(isns_pdu_t *pdu,
    size_t max_pdu_size,
    uint32_t attr_id,
    uint32_t attr_len,
    void *attr_data,
    uint32_t attr_numeric_data);

static int
isnst_send_pdu(void *so, isns_pdu_t *pdu);

static size_t
isnst_rcv_pdu(void *so, isns_pdu_t **pdu);

static void *
isnst_open_so(struct sockaddr_storage *sa);

static void
isnst_close_so(void *);

static void
isnst_esi_thread(void *arg);

static void
isnst_handle_esi_req(ksocket_t so, isns_pdu_t *pdu, size_t pl_size);

static void isnst_esi_start(void);
static void isnst_esi_stop(void);
static isns_target_t *isnst_latch_to_target_list(isns_target_t *target,
    avl_tree_t *list);
static void isnst_clear_target_list(iscsit_isns_svr_t *svr);
static void isnst_clear_from_target_list(isns_target_t *target,
    avl_tree_t *target_list);
static int isnst_tgt_avl_compare(const void *t1, const void *t2);
static void isnst_set_server_status(iscsit_isns_svr_t *svr,
    boolean_t registered);
static void isnst_monitor_start(void);
static void isnst_monitor_stop(void);

static void
isnst_monitor_default_portal_list(void);

static int
isnst_find_default_portals(idm_addr_list_t *alist);

static int
isnst_add_default_portals(idm_addr_list_t *alist);

static void
isnst_clear_default_portals(void);


static void
isnst_clear_portal_list(avl_tree_t *portal_list);

static void
isnst_copy_portal_list(avl_tree_t *t1, avl_tree_t *t2);

static isns_portal_t *
isnst_lookup_portal(struct sockaddr_storage *sa);

static isns_portal_t *
isnst_add_to_portal_list(struct sockaddr_storage *sa, avl_tree_t *portal_list);

static void
isnst_remove_from_portal_list(struct sockaddr_storage *sa,
    avl_tree_t *portal_list);

static int
isnst_portal_avl_compare(const void *t1, const void *t2);






it_cfg_status_t
isnst_config_merge(it_config_t *cfg)
{
	boolean_t		new_isns_state = B_FALSE;
	iscsit_isns_svr_t	*isns_svr, *next_isns_svr;
	it_portal_t		*cfg_isns_svr;

	ISNS_GLOBAL_LOCK();

	/*
	 * Determine whether iSNS is enabled in the new config.
	 * Isns property may not be set up yet.
	 */
	(void) nvlist_lookup_boolean_value(cfg->config_global_properties,
	    PROP_ISNS_ENABLED, &new_isns_state);

	/* Delete iSNS servers that are no longer part of the config */
	for (isns_svr = list_head(&iscsit_global.global_isns_cfg.isns_svrs);
	    isns_svr != NULL;
	    isns_svr = next_isns_svr) {
		next_isns_svr = list_next(
		    &iscsit_global.global_isns_cfg.isns_svrs, isns_svr);
		if (it_sns_svr_lookup(cfg, &isns_svr->svr_sa) == NULL)
			isnst_mark_delete_isns(isns_svr);
	}

	/* Add new iSNS servers */
	for (cfg_isns_svr = cfg->config_isns_svr_list;
	    cfg_isns_svr != NULL;
	    cfg_isns_svr = cfg_isns_svr->portal_next) {
		isns_svr = iscsit_isns_svr_lookup(&cfg_isns_svr->portal_addr);
		if (isns_svr == NULL) {
			iscsit_add_isns(cfg_isns_svr);
		} else if (isns_svr->svr_delete_needed) {
			/*
			 * If reactivating a server that was being
			 * deleted, turn it into a reset.
			 */
			isns_svr->svr_delete_needed = B_FALSE;
			isns_svr->svr_reset_needed = B_TRUE;
		}
	}

	/*
	 * There is no "modify case" since the user specifies a complete
	 * server list each time.  A modify is the same as a remove+add.
	 */

	/* Start/Stop iSNS if necessary */
	iscsit_set_isns(new_isns_state);

	ISNS_GLOBAL_UNLOCK();


	/* Wake up the monitor thread to complete the state change */
	isnst_monitor_awaken();

	return (0);
}

int
iscsit_isns_init(iscsit_hostinfo_t *hostinfo)
{
	mutex_init(&iscsit_global.global_isns_cfg.isns_mutex, NULL,
	    MUTEX_DEFAULT, NULL);

	ISNS_GLOBAL_LOCK();
	mutex_init(&iscsit_isns_mutex, NULL, MUTEX_DEFAULT, NULL);

	iscsit_global.global_isns_cfg.isns_state = B_FALSE;
	list_create(&iscsit_global.global_isns_cfg.isns_svrs,
	    sizeof (iscsit_isns_svr_t), offsetof(iscsit_isns_svr_t, svr_ln));
	avl_create(&isns_tpg_portals, isnst_portal_avl_compare,
	    sizeof (isns_portal_t), offsetof(isns_portal_t, portal_node));
	avl_create(&isns_all_portals, isnst_portal_avl_compare,
	    sizeof (isns_portal_t), offsetof(isns_portal_t, portal_node));
	num_default_portals = 0;
	if (hostinfo->length > ISCSIT_MAX_HOSTNAME_LEN)
		hostinfo->length = ISCSIT_MAX_HOSTNAME_LEN;
	isns_eid = kmem_alloc(hostinfo->length, KM_SLEEP);
	(void) strlcpy(isns_eid, hostinfo->fqhn, hostinfo->length);
	avl_create(&isns_target_list, isnst_tgt_avl_compare,
	    sizeof (isns_target_t), offsetof(isns_target_t, target_node));

	/* initialize isns client */
	mutex_init(&isns_monitor_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&esi.esi_mutex, NULL, MUTEX_DEFAULT, NULL);
	isns_monitor_thr_id = NULL;
	monitor_idle_interval = ISNS_IDLE_TIME * drv_usectohz(1000000);
	cv_init(&isns_idle_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&esi.esi_cv, NULL, CV_DEFAULT, NULL);
	xid = 0;
	ISNS_GLOBAL_UNLOCK();

	return (0);
}

void
iscsit_isns_fini()
{
	ISNS_GLOBAL_LOCK();

	/*
	 * The following call to iscsit_set_isns waits until all the
	 * iSNS servers have been fully deactivated and the monitor and esi
	 * threads have stopped.
	 */
	iscsit_set_isns(B_FALSE);

	/* Clean up data structures */
	mutex_destroy(&isns_monitor_mutex);
	cv_destroy(&isns_idle_cv);
	mutex_destroy(&esi.esi_mutex);
	cv_destroy(&esi.esi_cv);
	mutex_destroy(&iscsit_isns_mutex);

	/*
	 * Free our EID and target list.
	 */

	if (isns_eid) {
		kmem_free(isns_eid, strlen(isns_eid) + 1);
		isns_eid = NULL;
	}

	iscsit_global.global_isns_cfg.isns_state = B_FALSE;
	avl_destroy(&isns_target_list);
	list_destroy(&iscsit_global.global_isns_cfg.isns_svrs);
	avl_destroy(&isns_tpg_portals);
	avl_destroy(&isns_all_portals);
	num_default_portals = 0;
	ISNS_GLOBAL_UNLOCK();

	mutex_destroy(&iscsit_global.global_isns_cfg.isns_mutex);
}

static void
iscsit_set_isns(boolean_t state)
{
	iscsit_isns_svr_t	*svr;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	/*
	 * Update state and isns stop flag
	 */
	if (iscsit_global.global_isns_cfg.isns_state != state) {
		/* reset retry count for all servers */
		for (svr = list_head(&iscsit_global.global_isns_cfg.isns_svrs);
		    svr != NULL;
		    svr = list_next(&iscsit_global.global_isns_cfg.isns_svrs,
		    svr)) {
			svr->svr_retry_count = 0;
		}

		iscsit_global.global_isns_cfg.isns_state = state;

		if (state) {
			isnst_start();
		} else {
			isnst_stop();
		}
	}
}

void
iscsit_add_isns(it_portal_t *cfg_svr)
{
	iscsit_isns_svr_t *svr;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	svr = kmem_zalloc(sizeof (iscsit_isns_svr_t), KM_SLEEP);
	bcopy(&cfg_svr->portal_addr, &svr->svr_sa,
	    sizeof (struct sockaddr_storage));
	avl_create(&svr->svr_target_list, isnst_tgt_avl_compare,
	    sizeof (isns_target_t), offsetof(isns_target_t, target_node));
	svr->svr_esi_interval = isns_default_esi_interval;

	/* put it on the global isns server list */
	list_insert_tail(&iscsit_global.global_isns_cfg.isns_svrs, svr);
}

void
isnst_mark_delete_isns(iscsit_isns_svr_t *svr)
{
	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	/* If monitor thread not running, finish delete here */
	if (iscsit_global.global_isns_cfg.isns_state == B_FALSE) {
		isnst_finish_delete_isns(svr);
	} else {
		svr->svr_delete_needed = B_TRUE;
	}

}

void
isnst_finish_delete_isns(iscsit_isns_svr_t *svr)
{

	ASSERT(ISNS_GLOBAL_LOCK_HELD());
	isnst_clear_target_list(svr);

	list_remove(&iscsit_global.global_isns_cfg.isns_svrs, svr);
	/* free the memory */
	avl_destroy(&svr->svr_target_list);
	kmem_free(svr, sizeof (*svr));
}

static iscsit_isns_svr_t *
iscsit_isns_svr_lookup(struct sockaddr_storage *sa)
{
	iscsit_isns_svr_t	*svr;
	it_portal_t		portal1;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	bcopy(sa, &portal1.portal_addr, sizeof (struct sockaddr_storage));

	for (svr = list_head(&iscsit_global.global_isns_cfg.isns_svrs);
	    svr != NULL;
	    svr = list_next(&iscsit_global.global_isns_cfg.isns_svrs, svr)) {
		if (it_sa_compare(&svr->svr_sa, sa) == 0)
			return (svr);
	}

	return (NULL);
}

static isns_target_info_t *
isnst_create_target_info(iscsit_tgt_t *target)
{

	isns_target_info_t	*ti;
	isns_tpgt_t		*tig;
	isns_tpgt_addr_t	*tip;
	iscsit_tpgt_t		*tpgt;
	iscsit_tpg_t		*tpg;
	iscsit_portal_t		*tp;
	char			*str;

	/* Cannot hold the iscsit_isns_mutex here! */
	ASSERT(! mutex_owned(&iscsit_isns_mutex));

	ti = kmem_zalloc(sizeof (isns_target_info_t), KM_SLEEP);
	list_create(&ti->ti_tpgt_list,
	    sizeof (isns_tpgt_t), offsetof(isns_tpgt_t, ti_tpgt_ln));
	idm_refcnt_init(&ti->ti_refcnt, ti);

	mutex_enter(&target->target_mutex);
	(void) strncpy(ti->ti_tgt_name, target->target_name,
	    MAX_ISCSI_NODENAMELEN);


	if (nvlist_lookup_string(target->target_props, PROP_ALIAS,
	    &str) == 0) {
		(void) strncpy(ti->ti_tgt_alias, str, MAX_ISCSI_NODENAMELEN);
	}

	tpgt = avl_first(&target->target_tpgt_list);
	ASSERT(tpgt != NULL);
	do {
		tig = kmem_zalloc(sizeof (isns_tpgt_t), KM_SLEEP);
		list_create(&tig->ti_portal_list, sizeof (isns_tpgt_addr_t),
		    offsetof(isns_tpgt_addr_t, portal_ln));
		tig->ti_tpgt_tag = tpgt->tpgt_tag;

		/*
		 * Only need portal list for non-default portal.
		 */
		if (tpgt->tpgt_tag != ISCSIT_DEFAULT_TPGT) {
			tpg = tpgt->tpgt_tpg;

			mutex_enter(&tpg->tpg_mutex);

			tp = avl_first(&tpg->tpg_portal_list);
			do {
				tip = kmem_zalloc(sizeof (isns_tpgt_addr_t),
				    KM_SLEEP);
				bcopy(&tp->portal_addr, &tip->portal_addr,
				    sizeof (tip->portal_addr));
				list_insert_tail(&tig->ti_portal_list, tip);

				tp = AVL_NEXT(&tpg->tpg_portal_list, tp);
			} while (tp != NULL);
			mutex_exit(&tpg->tpg_mutex);
		}
		list_insert_tail(&ti->ti_tpgt_list, tig);
		tpgt = AVL_NEXT(&target->target_tpgt_list, tpgt);
	} while (tpgt != NULL);
	mutex_exit(&target->target_mutex);

	return (ti);
}

static void
isnst_clear_target_info_cb(void *arg)
{
	isns_target_info_t *ti = (isns_target_info_t *)arg;
	isns_tpgt_t	*tig;
	isns_tpgt_addr_t *tip;

	while ((tig = list_remove_head(&ti->ti_tpgt_list)) != NULL) {
		while ((tip = list_remove_head(&tig->ti_portal_list)) != NULL) {
			kmem_free(tip, sizeof (isns_tpgt_addr_t));
		}
		list_destroy(&tig->ti_portal_list);
		kmem_free(tig, sizeof (isns_tpgt_t));
	}
	list_destroy(&ti->ti_tpgt_list);
	idm_refcnt_destroy(&ti->ti_refcnt);
	kmem_free(ti, sizeof (isns_target_info_t));
}


/*
 * iscsit_isns_register
 * called by iscsit when a target goes online
 */
int
iscsit_isns_register(iscsit_tgt_t *target)
{
	isns_target_t		*itarget, tmptgt;
	avl_index_t		where;
	isns_target_info_t	*ti;

	/* Create TI struct outside of isns_mutex */
	ti = isnst_create_target_info(target);

	mutex_enter(&iscsit_isns_mutex);

	tmptgt.target = target;
	if ((itarget = (isns_target_t *)avl_find(&isns_target_list,
	    &tmptgt, &where)) == NULL) {
		itarget = kmem_zalloc(sizeof (isns_target_t), KM_SLEEP);

		itarget->target = target;
		avl_insert(&isns_target_list, (void *)itarget, where);
	} else {
		ASSERT(0);
	}

	/* Copy the target info so it will last beyond deregister */
	itarget->target_info = ti;
	idm_refcnt_hold(&ti->ti_refcnt);

	isns_targets_changed = B_TRUE;

	mutex_exit(&iscsit_isns_mutex);

	isnst_monitor_awaken();
	return (0);
}

/*
 * iscsit_isns_deregister
 * called by iscsit when a target goes offline
 */
int
iscsit_isns_deregister(iscsit_tgt_t *target)
{
	isns_target_t		*itarget, tmptgt;
	isns_target_info_t	*ti;

	tmptgt.target = target;

	mutex_enter(&iscsit_isns_mutex);

	itarget = avl_find(&isns_target_list, &tmptgt, NULL);
	ASSERT(itarget != NULL);
	ti = itarget->target_info;

	/*
	 * The main thread is done with the target_info object.
	 * Make sure the delete callback is called when
	 * all the svrs are done with it.
	 */
	idm_refcnt_rele(&ti->ti_refcnt);
	idm_refcnt_async_wait_ref(&ti->ti_refcnt,
	    (idm_refcnt_cb_t *)&isnst_clear_target_info_cb);

	itarget->target_info = NULL;
	avl_remove(&isns_target_list, itarget);
	kmem_free(itarget, sizeof (isns_target_t));

	isns_targets_changed = B_TRUE;

	mutex_exit(&iscsit_isns_mutex);

	isnst_monitor_awaken();
	return (0);
}

/*
 * iscsit_isns_target_update
 * This function is called by iscsit when a target's configuration
 * has changed.
 */

void
iscsit_isns_target_update(iscsit_tgt_t *target)
{
	isns_target_t		*itarget, tmptgt;
	isns_target_info_t	*ti;

	/* Create new TI struct outside of isns_mutex */
	ti = isnst_create_target_info(target);

	mutex_enter(&iscsit_isns_mutex);

	/*
	 * If iscsit calls us to modify a target, that target should
	 * already exist in the isns_svr_list.
	 */
	tmptgt.target = target;
	itarget = avl_find(&isns_target_list, &tmptgt, NULL);
	if (itarget == NULL) {
		/*
		 * If target-update gets called while the target is still
		 * offline, then there is nothing to do. The target will be
		 * completely registered when it comes online.
		 */
		mutex_exit(&iscsit_isns_mutex);
		/* Remove the target_info struct -- not needed */
		isnst_clear_target_info_cb(ti);
		return;
	}

	/* Remove the old target_info struct */
	idm_refcnt_rele(&itarget->target_info->ti_refcnt);
	idm_refcnt_async_wait_ref(&itarget->target_info->ti_refcnt,
	    (idm_refcnt_cb_t *)&isnst_clear_target_info_cb);

	/* Link to new target_info struct */
	itarget->target_info = ti;
	idm_refcnt_hold(&ti->ti_refcnt);

	itarget->target_update_needed = B_TRUE;

	isns_targets_changed = B_TRUE;

	mutex_exit(&iscsit_isns_mutex);

	isnst_monitor_awaken();
}

static void
isnst_start()
{
	ISNST_LOG(CE_NOTE, "**** isnst_start");

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	/*
	 * Start ESI thread(s)
	 */
	isnst_esi_start();

	/*
	 * Create a thread for monitoring server communications
	 */
	isnst_monitor_start();
}

static void
isnst_stop()
{
	ASSERT(ISNS_GLOBAL_LOCK_HELD());
	ISNST_LOG(CE_NOTE, "**** isnst_stop");


	ISNS_GLOBAL_UNLOCK();
	isnst_esi_stop();
	isnst_monitor_stop();
	ISNS_GLOBAL_LOCK();
}

static void
isnst_monitor_start(void)
{
	ISNST_LOG(CE_NOTE, "isnst_monitor_start");


	mutex_enter(&isns_monitor_mutex);
	ASSERT(!isns_monitor_thr_running);
	isns_monitor_thr_id = thread_create(NULL, 0,
	    isnst_monitor, NULL, 0, &p0, TS_RUN, minclsyspri);
	while (!isns_monitor_thr_running)
		cv_wait(&isns_idle_cv, &isns_monitor_mutex);
	mutex_exit(&isns_monitor_mutex);
}

static void
isnst_monitor_stop(void)
{
	ISNST_LOG(CE_NOTE, "isnst_monitor_stop");

	mutex_enter(&isns_monitor_mutex);
	if (isns_monitor_thr_running) {
		isns_monitor_thr_running = B_FALSE;
		cv_signal(&isns_idle_cv);
		mutex_exit(&isns_monitor_mutex);

		thread_join(isns_monitor_thr_did);
		return;
	}
	mutex_exit(&isns_monitor_mutex);
}

/*
 * isnst_update_server_timestamp
 *
 * When we receive an ESI request, update the timestamp for the server.
 * If we don't receive one for the specified period of time, we'll attempt
 * to re-register.
 *
 */
static boolean_t
isnst_update_server_timestamp(struct sockaddr_storage *ss)
{
	iscsit_isns_svr_t	*svr;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	/*
	 * Find the server and update the timestamp
	 */
	for (svr = list_head(&iscsit_global.global_isns_cfg.isns_svrs);
	    svr != NULL;
	    svr = list_next(&iscsit_global.global_isns_cfg.isns_svrs, svr)) {
		/*
		 * Note that the port number in incoming probe will be
		 * different than the iSNS server's port number.
		 */
		if (idm_ss_compare(ss, &svr->svr_sa,
		    B_TRUE /* v4_mapped_as_v4 */,
		    B_FALSE /* don't compare_ports */) == 0) {
			break;
		}
	}

	if (svr != NULL) {
		/* Update the timestamp we keep for this server */
		svr->svr_last_msg = ddi_get_lbolt();
		/*
		 * If we receive ESI probe from a server we are not
		 * registered to, then cause a re-reg attempt.
		 */
		if (!svr->svr_registered) {
			isnst_monitor_awaken();
		}
		return (B_TRUE);
	}

	return (B_FALSE);
}


/*
 * isnst_monitor_all_servers -- loop through all servers
 */


static void
isnst_monitor_all_servers()
{
	iscsit_isns_svr_t	*svr, *next_svr;
	boolean_t		enabled;
	list_t			*svr_list;
	int			rc;

	svr_list = &iscsit_global.global_isns_cfg.isns_svrs;

	ISNS_GLOBAL_LOCK();

	isnst_copy_global_status_changes();

	enabled = iscsit_global.global_isns_cfg.isns_state;
	for (svr = list_head(svr_list); svr != NULL; svr = next_svr) {

		svr->svr_monitor_hold = B_TRUE;
		/*
		 * isnst_monitor_one_server can release ISNS_GLOBAL_LOCK
		 * internally.  This allows isnst_config_merge to run
		 * even when messages to iSNS servers are pending.
		 */
		rc = isnst_monitor_one_server(svr, enabled);
		if (rc != 0) {
			svr->svr_retry_count++;
			if (svr->svr_registered &&
			    svr->svr_retry_count > isns_max_retry) {
				char	server_buf[IDM_SA_NTOP_BUFSIZ];

				if (! svr->svr_reset_needed) {
					ISNST_LOG(CE_WARN,
					    "isnst: iSNS server %s"
					    " not responding (rc=%d).",
					    idm_sa_ntop(&svr->svr_sa,
					    server_buf, sizeof (server_buf)),
					    rc);
					svr->svr_reset_needed = B_TRUE;
				}
			}
		} else {
			svr->svr_retry_count = 0;
		}
		/*
		 * If we have finished unregistering this server,
		 * it is now OK to delete it.
		 */
		svr->svr_monitor_hold = B_FALSE;
		next_svr = list_next(svr_list, svr);
		if (svr->svr_delete_needed == B_TRUE &&
		    svr->svr_registered == B_FALSE) {
			isnst_finish_delete_isns(svr);
		}
	}
	ISNS_GLOBAL_UNLOCK();
}

static void
isnst_monitor_awaken(void)
{
	mutex_enter(&isns_monitor_mutex);
	if (isns_monitor_thr_running) {
		DTRACE_PROBE(iscsit__isns__monitor__awaken);
		cv_signal(&isns_idle_cv);
	}
	mutex_exit(&isns_monitor_mutex);
}

/*
 * isnst_monitor -- the monitor thread for iSNS
 */
/*ARGSUSED*/
static void
isnst_monitor(void *arg)
{
	mutex_enter(&isns_monitor_mutex);
	isns_monitor_thr_did = curthread->t_did;
	isns_monitor_thr_running = B_TRUE;
	cv_signal(&isns_idle_cv);

	/*
	 * Start with a short pause (5 sec) to allow all targets
	 * to be registered before we send register-all.  This is
	 * purely an optimization to cut down on the number of
	 * messages we send to the iSNS server.
	 */
	mutex_exit(&isns_monitor_mutex);
	delay(drv_usectohz(isns_initial_delay * 1000000));
	mutex_enter(&isns_monitor_mutex);

	/* Force an initialization of isns_all_portals */
	mutex_enter(&iscsit_isns_mutex);
	isns_portals_changed = B_TRUE;
	mutex_exit(&iscsit_isns_mutex);

	while (isns_monitor_thr_running) {

		/* Update servers */
		mutex_exit(&isns_monitor_mutex);
		isnst_monitor_all_servers();
		mutex_enter(&isns_monitor_mutex);

		/* If something needs attention, go right to the top */
		mutex_enter(&iscsit_isns_mutex);
		if (isns_targets_changed || isns_portals_changed) {
			DTRACE_PROBE(iscsit__isns__monitor__reenter);
			mutex_exit(&iscsit_isns_mutex);
			/* isns_monitor_mutex still held */
			continue;
		}
		mutex_exit(&iscsit_isns_mutex);

		/*
		 * Keep running until isns_monitor_thr_running is set to
		 * B_FALSE.
		 */
		if (! isns_monitor_thr_running)
			break;

		DTRACE_PROBE(iscsit__isns__monitor__sleep);
		(void) cv_reltimedwait(&isns_idle_cv, &isns_monitor_mutex,
		    monitor_idle_interval, TR_CLOCK_TICK);
		DTRACE_PROBE1(iscsit__isns__monitor__wakeup,
		    boolean_t, isns_monitor_thr_running);
	}

	mutex_exit(&isns_monitor_mutex);

	/* Update the servers one last time for deregistration */
	isnst_monitor_all_servers();

	/* Clean up the all-portals list */
	ISNS_GLOBAL_LOCK();
	isnst_clear_default_portals();
	ISNS_GLOBAL_UNLOCK();

	/* terminate the thread at the last */
	thread_exit();
}

static int
isnst_monitor_one_server(iscsit_isns_svr_t *svr, boolean_t enabled)
{
	int		rc = 0;
	isns_target_t	*itarget;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	/*
	 * First, take care of the case where iSNS is no longer enabled.
	 *
	 */

	if (enabled == B_FALSE || svr->svr_delete_needed) {
		/*
		 * Just try one time to deregister all from server.
		 * Doesn't matter if this fails.  We're disabled.
		 */
		(void) isnst_update_one_server(svr, NULL, ISNS_DEREGISTER_ALL);
		isnst_set_server_status(svr, B_FALSE);
		return (0);
	}

retry_replace_all:
	/*
	 * If the server needs replace-all, check if it should
	 * be a DevDereg (i.e. if the last target is gone.)
	 */

	if (svr->svr_registered && svr->svr_reset_needed) {
		/* Send DevDereg if last registered target */
		isns_target_t	*jtarget;
		for (jtarget = avl_first(&svr->svr_target_list);
		    jtarget != NULL;
		    jtarget = AVL_NEXT(&svr->svr_target_list, jtarget)) {
			if (!jtarget->target_delete_needed) {
				break;
			}
		}
		/*
		 * jtarget is null IFF all tgts need deletion,
		 * and there are no new targets to register.
		 */
		if (jtarget == NULL) {
			rc = isnst_update_one_server(svr, NULL,
			    ISNS_DEREGISTER_ALL);
			if (rc != 0) {
				return (rc);
			}
			isnst_set_server_status(svr, B_FALSE);
			return (0);
		}
	}

	/*
	 * If the server is not yet registered, do the registration
	 */
	if (! svr->svr_registered || svr->svr_reset_needed) {

		if (avl_numnodes(&svr->svr_target_list) == 0) {
			/* If no targets, nothing to register */
			return (0);
		}
		if ((rc = isnst_update_one_server(svr, NULL,
		    ISNS_REGISTER_ALL)) != 0) {
			/* Registration failed */
			return (rc);
		}
		isnst_set_server_status(svr, B_TRUE);

	}

	/* The following checks are expensive, so only do them if needed */
	if (svr->svr_targets_changed) {
		isns_target_t	*next_target;
		/*
		 * If there is a target to be deleted, send the
		 * deletion request for one target at a time.
		 */
		for (itarget = avl_first(&svr->svr_target_list);
		    itarget != NULL;
		    itarget = next_target) {
			next_target = AVL_NEXT(&svr->svr_target_list, itarget);
			if (itarget->target_delete_needed) {
				/* See if last non-deleted target */
				isns_target_t	*jtarget;
				ASSERT(itarget->target_registered);
				for (jtarget =
				    avl_first(&svr->svr_target_list);
				    jtarget != NULL;
				    jtarget = AVL_NEXT(&svr->svr_target_list,
				    jtarget)) {
					if (jtarget->target_registered &&
					    !jtarget->target_delete_needed) {
						break;
					}
				}
				/* jtarget is null if last registered tgt */
				if (jtarget == NULL) {
					/*
					 * Removing last tgt -- deregister all.
					 * Doesn't matter if this fails.
					 * We're disabled.
					 */
					rc = isnst_update_one_server(svr,
					    NULL, ISNS_DEREGISTER_ALL);
					if (rc != 0) {
						return (rc);
					}
					isnst_set_server_status(svr, B_FALSE);
					return (0);
				}
				rc = isnst_update_one_server(svr,
				    itarget, ISNS_DEREGISTER_TARGET);
				if (rc != 0 && isnst_retry_registration(rc)) {
					/* Retryable code => try replace-all */
					svr->svr_reset_needed = B_TRUE;
					goto retry_replace_all;
				}

				if (rc != 0) {
					return (rc);
				}
				isnst_clear_from_target_list(itarget,
				    &svr->svr_target_list);
			}
		}

		/* If any target needs a register or an update, do so */
		itarget = avl_first(&svr->svr_target_list);
		while (itarget) {
			if (!itarget->target_registered ||
			    itarget->target_update_needed) {

				/*
				 * Because of a bug in the isns
				 * server, we cannot send a modify
				 * operation that changes the target's
				 * TPGTs. So just replace all.
				 */
				if (isns_modify_must_replace) {
					svr->svr_reset_needed = B_TRUE;
					goto retry_replace_all;
				}
				/* Try to update existing info for one tgt */
				rc = isnst_update_one_server(svr,
				    itarget,
				    ISNS_MODIFY_TARGET);
				if (rc != 0 && isnst_retry_registration(rc)) {
					/* Retryable code => try replace-all */
					svr->svr_reset_needed = B_TRUE;
					goto retry_replace_all;
				}
				if (rc != 0) {
					return (rc);
				}
				itarget->target_update_needed =
				    B_FALSE;
				itarget->target_registered = B_TRUE;
			}
			itarget = AVL_NEXT(&svr->svr_target_list,
			    itarget);
		}

		/*
		 * We have gone through all the cases -- this server
		 * is now up to date.
		 */
		svr->svr_targets_changed = B_FALSE;
	}


	if (isns_use_esi) {
		/*
		 * If using ESI, and no ESI request is received within
		 * MAX_ESI_INTERVALS (3) number of intervals, we'll
		 * try to re-register with the server. The server will
		 * delete our information if we fail to respond for 2
		 * ESI intervals.
		 */
		if (ddi_get_lbolt() >= (svr->svr_last_msg +
		    drv_usectohz(svr->svr_esi_interval * 1000000 *
		    MAX_ESI_INTERVALS))) {
			/* re-register everything */
			svr->svr_reset_needed = B_TRUE;
			goto retry_replace_all;
		}
	} else {
		/*
		 * If not using ESI, make sure to ping server during
		 * each registration period.  Do this at half the
		 * registration interval, so we won't get timed out.
		 */
		if (ddi_get_lbolt() >= (svr->svr_last_msg +
		    drv_usectohz(isns_registration_period * (1000000/3)))) {
			/* Send a self-query as a keepalive. */
			ISNS_GLOBAL_UNLOCK();
			rc = isnst_keepalive(svr);
			ISNS_GLOBAL_LOCK();
			if (rc != 0 && isnst_retry_registration(rc)) {
				/* Retryable code => try replace-all */
				svr->svr_reset_needed = B_TRUE;
				goto retry_replace_all;
			}
			if (rc != 0) {
				return (rc);
			}
		}
	}
	return (0);

}

/*
 * isnst_mark_deleted_target -- find tgt in svr list but not global list
 */
static void
isnst_mark_deleted_targets(iscsit_isns_svr_t *svr)
{
	isns_target_t *itarget, *nxt_target, tmptgt;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());
	ASSERT(mutex_owned(&iscsit_isns_mutex));

	for (itarget = avl_first(&svr->svr_target_list);
	    itarget != NULL;
	    itarget = nxt_target) {
		tmptgt.target = itarget->target;
		nxt_target = AVL_NEXT(&svr->svr_target_list, itarget);
		if (avl_find(&isns_target_list, &tmptgt, NULL) == NULL) {
			if (itarget->target_registered) {
				itarget->target_delete_needed = B_TRUE;
			} else {
				isnst_clear_from_target_list(itarget,
				    &svr->svr_target_list);
			}
		}
	}
}

static isns_target_t *
isnst_latch_to_target_list(isns_target_t *jtarget, avl_tree_t *target_list)
{
	isns_target_t *itarget, tmptgt;
	avl_index_t where;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());
	ASSERT(mutex_owned(&iscsit_isns_mutex));
	/*
	 * Make sure this target isn't already in our list.
	 */

	tmptgt.target = jtarget->target;
	if ((itarget = (isns_target_t *)avl_find(target_list,
	    &tmptgt, &where)) == NULL) {
		itarget = kmem_zalloc(sizeof (isns_target_t), KM_SLEEP);

		itarget->target = jtarget->target;
		itarget->target_info = jtarget->target_info;
		idm_refcnt_hold(&itarget->target_info->ti_refcnt);

		avl_insert(target_list, (void *)itarget, where);
	} else {
		ASSERT(0);
	}

	return (itarget);
}

static void
isnst_clear_target_list(iscsit_isns_svr_t *svr)
{
	isns_target_t	*itarget;

	while ((itarget = avl_first(&svr->svr_target_list)) != NULL) {
		isnst_clear_from_target_list(itarget,
		    &svr->svr_target_list);
	}
}

static void
isnst_clear_from_target_list(isns_target_t *jtarget, avl_tree_t *target_list)
{
	isns_target_t		*itarget, tmptgt;

	tmptgt.target = jtarget->target;

	if ((itarget = avl_find(target_list, &tmptgt, NULL))
	    != NULL) {

		avl_remove(target_list, itarget);
		idm_refcnt_rele(&itarget->target_info->ti_refcnt);
		kmem_free(itarget, sizeof (isns_target_t));
	} else {
		ASSERT(0);
	}
}

/*
 * isnst_copy_global_status_changes -- update svrs to match iscsit
 *
 * At the end of this routine svr->svr_target_list has all the entries
 * in the current isns_target_list plus any targets that are marked
 * for deletion.
 */
static void
isnst_copy_global_status_changes(void)
{
	isns_target_t		*ttarget, *itarget, tmptgt;
	iscsit_isns_svr_t	*svr;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	/*
	 * Copy info about recent transitions from global state to
	 * per-server state.  We use the global state so that iscsit
	 * functions can proceed without blocking on slow-to-release
	 * iSNS locks.
	 */
	mutex_enter(&iscsit_isns_mutex);

	/*
	 * Periodically check for changed IP addresses.  This function
	 * sets isns_all_portals to the current set, and sets
	 * isns_portals_changed if a portal is added or removed.
	 */
	isnst_monitor_default_portal_list();

	/* Initialize the per-server structs to some basic values */
	for (svr = list_head(&iscsit_global.global_isns_cfg.isns_svrs);
	    svr != NULL;
	    svr = list_next(&iscsit_global.global_isns_cfg.isns_svrs,
	    svr)) {
		if (isns_portals_changed && svr->svr_registered) {
			/*
			 * Cause re-register, for now, when portals change.
			 * Eventually, we should add new portals one by one
			 */
			svr->svr_reset_needed = B_TRUE;
		}
		if (!svr->svr_registered) {
			/* To re-register, start with empty target list */
			isnst_clear_target_list(svr);
			/* And set flag to add all current targets, below */
			isns_targets_changed = B_TRUE;
		} else if (isns_targets_changed || svr->svr_reset_needed) {
			/* Mark to look for target changes */
			isnst_mark_deleted_targets(svr);
			svr->svr_targets_changed = B_TRUE;
		}
	}

	/*
	 * If any target has been modified, tell all the svrs to
	 * update that target.
	 */
	if (isns_targets_changed) {
		ttarget = avl_first(&isns_target_list);
		while (ttarget) {
			for (svr = list_head(
			    &iscsit_global.global_isns_cfg.isns_svrs);
			    svr != NULL;
			    svr = list_next(
			    &iscsit_global.global_isns_cfg.isns_svrs,
			    svr)) {
				tmptgt.target = ttarget->target;
				itarget = avl_find(
				    &svr->svr_target_list,
				    &tmptgt, NULL);

				if (itarget == NULL) {
					/* Add a new target */
					(void) isnst_latch_to_target_list(
					    ttarget, &svr->svr_target_list);
				} else if (ttarget->target_update_needed) {
					/* Modify existing target */
					itarget->target_update_needed =
					    B_TRUE;
					/* Remove link to old target_info */
					idm_refcnt_rele(
					    &itarget->target_info->ti_refcnt);
					/* Link to new target_info struct */
					itarget->target_info =
					    ttarget->target_info;
					idm_refcnt_hold(
					    &itarget->target_info->ti_refcnt);
				}
			}
			ttarget->target_update_needed = B_FALSE;
			ttarget = AVL_NEXT(&isns_target_list, ttarget);
		}
	}

	/*
	 * Now we have updated the per-server state for all servers.
	 * Clear the global state flags
	 */
	isns_targets_changed = B_FALSE;
	isns_portals_changed = B_FALSE;
	mutex_exit(&iscsit_isns_mutex);
}

/*
 * isnst_update_one_server releases ISNS_GLOBAL_LOCK internally and
 * acquires it again as needed.  This allows isnst_config_merge and
 * isnst_esi_thread to run even while waiting for a response from the
 * iSNS server (or a dead iSNS server).
 */
static int
isnst_update_one_server(iscsit_isns_svr_t *svr, isns_target_t *itarget,
    isns_reg_type_t reg)
{
	int rc = 0;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());
	ISNS_GLOBAL_UNLOCK();

	switch (reg) {
	case ISNS_DEREGISTER_TARGET:
		rc = isnst_deregister(svr, itarget);
		break;

	case ISNS_DEREGISTER_ALL:
		rc = isnst_deregister(svr, NULL);
		break;

	case ISNS_MODIFY_TARGET:
	case ISNS_REGISTER_TARGET:
		rc = isnst_register(svr, itarget, reg);
		break;

	case ISNS_REGISTER_ALL:
		rc = isnst_register(svr, NULL, reg);
		break;

	default:
		ASSERT(0);
		/* NOTREACHED */
	}

	ISNS_GLOBAL_LOCK();
	return (rc);
}

/*
 * isnst_retry_registration
 *
 * This function checks the return value from a registration pdu and
 * determines whether or not we should retry this request.  If the
 * request is retried, it will do so as an "update", which means we
 * re-register everything.
 */

static boolean_t
isnst_retry_registration(int rsp_status_code)
{
	boolean_t retry;

	/*
	 * The following are the error codes that indicate isns-client
	 * and isns-server are out of synch.  E.g. No-Such-Entry can
	 * occur on a keepalive if the server has timed out our
	 * connection.  If we get one of these messages, we replace-all
	 * right away to get back in synch faster.
	 */
	switch (rsp_status_code) {
	case ISNS_RSP_INVALID_REGIS:
	case ISNS_RSP_SRC_UNAUTHORIZED:
	case ISNS_RSP_BUSY:
	case ISNS_RSP_INVALID_UPDATE:
	case ISNS_RSP_NO_SUCH_ENTRY:
		retry = B_TRUE;
		break;
	default:
		retry = B_FALSE;
		break;
	}

	return (retry);
}



static int
isnst_register(iscsit_isns_svr_t *svr, isns_target_t *itarget,
    isns_reg_type_t regtype)
{
	struct sonode	*so;
	int		rc = 0;
	isns_pdu_t	*pdu, *rsp;
	size_t		pdu_size, rsp_size;

	/* create TCP connection to the isns server */
	so = isnst_open_so(&svr->svr_sa);
	if (so == NULL) {
		return (-1);
	}

	pdu_size = isnst_make_reg_pdu(&pdu, itarget, svr, regtype);
	if (pdu_size == 0) {
		isnst_close_so(so);
		return (-1);
	}

	rc = isnst_send_pdu(so, pdu);
	if (rc != 0) {
		kmem_free(pdu, pdu_size);
		isnst_close_so(so);
		return (rc);
	}

	rsp_size = isnst_rcv_pdu(so, &rsp);
	if (rsp_size == 0) {
		kmem_free(pdu, pdu_size);
		isnst_close_so(so);
		return (-1);
	}

	rc = isnst_verify_rsp(svr, pdu, rsp, rsp_size);

	kmem_free(pdu, pdu_size);
	kmem_free(rsp, rsp_size);
	isnst_close_so(so);

	return (rc);
}

/*
 * isnst_make_reg_pdu:
 * Cases:
 *   initial registration of all targets (replace-all)
 *   initial registration of a single target (update-existing)
 *   modify an existing target (update-existing)
 */
static size_t
isnst_make_reg_pdu(isns_pdu_t **pdu, isns_target_t *itarget,
    iscsit_isns_svr_t *svr, isns_reg_type_t regtype)
{
	size_t			pdu_size;
	char			*str;
	int			len;
	isns_target_t		*src;
	boolean_t		reg_all = B_FALSE;
	uint16_t		flags = 0;

	ISNS_GLOBAL_LOCK();
	ASSERT(svr->svr_monitor_hold);
	/*
	 * svr could have an empty target list if svr was added
	 * by isnst_config_merge sometime after the last call to
	 * copy_global_status_changes.  Just skip this chance
	 * to reregister.  The next call to copy_global_status_changes
	 * will sort things out.
	 */
	if (avl_numnodes(&svr->svr_target_list) == 0) {
		/* If no targets, nothing to register */
		ISNS_GLOBAL_UNLOCK();
		return (0);
	}
	/*
	 * Find a source attribute for this registration.
	 *
	 * If updating a specific target for the first time, use that
	 * target.
	 * If already registered, use a registered target
	 * Otherwise, use the first target we are going to register.
	 */
	if (itarget != NULL && ! svr->svr_registered) {
		src = itarget;
	} else if (svr->svr_registered) {
		src = isnst_get_registered_source_locked(svr);
	} else {
		/*
		 * When registering to a server, and we don't know which
		 * of our targets the server might already know,
		 * cycle through each of our targets as source.  The server
		 * does source validation.  If the server knows any of our
		 * targets, it will eventually accept one of our registrations.
		 */
		int		i;
		isns_target_t	*jtarget;

		if (svr->svr_last_target_index >=
		    avl_numnodes(&svr->svr_target_list) - 1) {
			svr->svr_last_target_index = 0;
		} else {
			svr->svr_last_target_index++;
		}
		for (i = 0, jtarget = avl_first(&svr->svr_target_list);
		    i < svr->svr_last_target_index;
		    i++, jtarget = AVL_NEXT(&svr->svr_target_list, jtarget)) {
			ASSERT(jtarget != NULL);
		}
		src = jtarget;
		ASSERT(src != NULL);
	}

	/*
	 * Null target means we're replacing everything.
	 */
	if (itarget == NULL) {
		reg_all = B_TRUE;
		flags = ISNS_FLAG_REPLACE_REG;
		/* Reset itarget to the beginning of our list */
		itarget = (isns_target_t *)avl_first(&svr->svr_target_list);
	} else if (regtype == ISNS_REGISTER_TARGET) {
		flags = ISNS_FLAG_REPLACE_REG;
		ASSERT(!itarget->target_delete_needed);
	}

	pdu_size = isnst_create_pdu_header(ISNS_DEV_ATTR_REG, pdu, flags);
	if (pdu_size == 0) {
		ISNS_GLOBAL_UNLOCK();
		return (0);
	}

	/* Source Attribute */

	len = strlen(src->target_info->ti_tgt_name) + 1;
	if (isnst_add_attr(*pdu, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
	    len, src->target_info->ti_tgt_name, 0) != 0) {
		goto pdu_error;
	}

	/*
	 * Message Key Attributes - EID
	 */
	len = strlen(isns_eid) + 1;

	if (isnst_add_attr(*pdu, pdu_size, ISNS_EID_ATTR_ID,
	    len, isns_eid, 0) != 0) {
		goto pdu_error;
	}

	/* Delimiter */
	if (isnst_add_attr(*pdu, pdu_size, ISNS_DELIMITER_ATTR_ID,
	    0, 0, 0) != 0) {
		goto pdu_error;
	}

	/*
	 * Operating Attributes
	 */
	if (isnst_add_attr(*pdu, pdu_size, ISNS_EID_ATTR_ID, len,
	    isns_eid, 0) != 0) {
		goto pdu_error;
	}


	/* ENTITY Protocol - Section 6.2.2 */
	if (isnst_add_attr(*pdu, pdu_size,
	    ISNS_ENTITY_PROTOCOL_ATTR_ID,
	    4, 0, ISNS_ENTITY_PROTOCOL_ISCSI) != 0) {
		goto pdu_error;
	}

	if (reg_all) {
		/* Registration Period -- use if not using ESI */
		if (!isns_use_esi &&
		    isnst_add_attr(*pdu, pdu_size,
		    ISNS_ENTITY_REG_PERIOD_ATTR_ID, 4,
		    0, isns_registration_period) != 0) {
			goto pdu_error;
		}
		/*
		 * Network entity portal information - only when
		 * replacing all.  Since targets are only registered
		 * to iSNS when their portals are already registered
		 * to iSNS, we can assume entity portals exist.
		 */
		if (isnst_reg_pdu_add_entity_portals(*pdu, pdu_size) != 0) {
			goto pdu_error;
		}

		/*
		 * Skip over delete-pending tgts. There must be at
		 * least one non-deleted tgt, or it is an error.
		 */
		while (itarget->target_delete_needed) {
			itarget = AVL_NEXT(&svr->svr_target_list,
			    itarget);
			ASSERT(itarget != NULL);
		}
	}


	/* Add information about each target or one target */
	do {

		/* iSCSI Name - Section 6.4.1 */
		str = itarget->target_info->ti_tgt_name;
		len = strlen(str) + 1;
		if (isnst_add_attr(*pdu, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
		    len, str, 0) != 0) {
			goto pdu_error;
		}

		/* iSCSI Node Type */
		if (isnst_add_attr(*pdu, pdu_size,
		    ISNS_ISCSI_NODE_TYPE_ATTR_ID, 4, 0,
		    ISNS_TARGET_NODE_TYPE) != 0) {
			goto pdu_error;
		}

		/* iSCSI Alias */
		str = itarget->target_info->ti_tgt_alias;
		len = strnlen(str,
		    sizeof (itarget->target_info->ti_tgt_alias));
		if (len) {
			/* Found alias in property list */
			if (isnst_add_attr(*pdu, pdu_size,
			    ISNS_ISCSI_ALIAS_ATTR_ID, len+1, str, 0) != 0) {
				goto pdu_error;
			}
		}

		if (isnst_reg_pdu_add_pg(*pdu, pdu_size, itarget) != 0) {
			goto pdu_error;
		}

		/* If registering one target, then we are done. */
		if (!reg_all) {
			break;
		}

		/* Skip over delete-pending tgts */
		do {
			itarget = AVL_NEXT(&svr->svr_target_list, itarget);
		} while (itarget != NULL && itarget->target_delete_needed);

	} while (itarget != NULL);

	ISNS_GLOBAL_UNLOCK();
	return (pdu_size);

pdu_error:
	/* packet too large, no memory (or other error) */
	len = ntohs((*pdu)->payload_len);
	if (len + 1000 > isns_message_buf_size) {
		/* Increase the PDU size we will ask for next time */
		if (isns_message_buf_size * 2 <= ISNST_MAX_MSG_SIZE) {
			isns_message_buf_size *= 2;
			ISNST_LOG(CE_NOTE,
			    "Increasing isns_message_buf_size to %d",
			    isns_message_buf_size);
		} else {
			cmn_err(CE_WARN, "iscsit: isns: no space"
			    " to send required PDU");
		}
	}

	kmem_free(*pdu, pdu_size);
	*pdu = NULL;

	ISNS_GLOBAL_UNLOCK();
	return (0);
}

static int
isnst_reg_pdu_add_entity_portals(isns_pdu_t *pdu, size_t pdu_size)
{
	int			rc = 0;
	isns_portal_t		*iportal;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	iportal = (isns_portal_t *)avl_first(&isns_all_portals);
	while (iportal != NULL) {
		/* Do not include ESI port if not using ESI */
		if (isnst_add_portal_attr(pdu, pdu_size,
		    ISNS_PORTAL_IP_ADDR_ATTR_ID,
		    ISNS_PORTAL_PORT_ATTR_ID,
		    &iportal->portal_addr,
		    isns_use_esi /* ESI info */) != 0) {
			rc = -1;
			break;
		}
		iportal = AVL_NEXT(&isns_all_portals, iportal);
	}

	return (rc);
}


/*
 * isnst_reg_pdu_add_pg -- add the PG and PGT entries for one target.
 */
static int
isnst_reg_pdu_add_pg(isns_pdu_t *pdu, size_t pdu_size, isns_target_t *itarget)
{
	int			rval = 0;
	avl_tree_t		null_portals;
	isns_target_info_t	*ti;
	isns_tpgt_t		*tig;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	ti = itarget->target_info;

	/*
	 * If all registered targets only use the default TPGT, then
	 * we can skip sending PG info to the iSNS server.
	 */
	if (num_tpg_portals == 0)
		return (0);

	/*
	 * For each target, we start with the full portal list,
	 * and then remove portals as we add them to TPGTs for this target.
	 * At the end, all the remaining portals go into the "null pg".
	 * We use the "null_portals" list to track this.
	 */
	avl_create(&null_portals, isnst_portal_avl_compare,
	    sizeof (isns_portal_t), offsetof(isns_portal_t, portal_node));
	isnst_copy_portal_list(&isns_all_portals, &null_portals);

	for (tig = list_head(&ti->ti_tpgt_list);
	    tig != NULL;
	    tig = list_next(&ti->ti_tpgt_list, tig)) {

		if (tig->ti_tpgt_tag == ISCSIT_DEFAULT_TPGT) {
			/* Add portal info from list of default portals */
			if (isnst_add_default_pg(pdu, pdu_size,
			    &null_portals) != 0) {
				rval = 1;
				break;
			}
		} else {
			/* Add portal info from this TPGT's entries */
			if (isnst_add_tpg_pg(pdu, pdu_size, tig,
			    &null_portals) != 0) {
				rval = 1;
				break;
			}
		}
	}

	/* Add the remaining portals (if any) to the null PG */
	if (rval == 0 &&
	    isnst_add_null_pg(pdu, pdu_size, &null_portals) != 0) {
		rval = 1;
	}
	isnst_clear_portal_list(&null_portals);
	avl_destroy(&null_portals);
	return (rval);
}

/* Write one TPGT's info into the PDU */
static int
isnst_add_tpg_pg(isns_pdu_t *pdu, size_t pdu_size,
    isns_tpgt_t *tig, avl_tree_t *null_portal_list)
{
	isns_tpgt_addr_t	*tip;
	int			rval = 0;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());
	ASSERT(tig->ti_tpgt_tag != ISCSIT_DEFAULT_TPGT);

	/* Portal Group Tag */
	if (isnst_add_attr(pdu, pdu_size,
	    ISNS_PG_TAG_ATTR_ID, 4, 0, tig->ti_tpgt_tag) != 0) {
		rval = 1;
		goto pg_done;
	}

	tip = list_head(&tig->ti_portal_list);
	ASSERT(tip != NULL);
	do {
		/* PG Portal Addr and PG Portal Port */
		if (isnst_add_portal_attr(pdu, pdu_size,
		    ISNS_PG_PORTAL_IP_ADDR_ATTR_ID,
		    ISNS_PG_PORTAL_PORT_ATTR_ID,
		    &tip->portal_addr, B_FALSE /* ESI */) != 0) {
			rval = 1;
			goto pg_done;
		}
		isnst_remove_from_portal_list(&tip->portal_addr,
		    null_portal_list);

		tip = list_next(&tig->ti_portal_list, tip);
	} while (tip != NULL);

pg_done:
	return (rval);
}

static int
isnst_add_default_pg(isns_pdu_t *pdu, size_t pdu_size,
    avl_tree_t *null_portal_list)
{
	isns_portal_t *iportal;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	if (num_default_portals == 0) {
		/*
		 * It is OK for a target with default-portals to be
		 * online from an STMF perspective and yet all
		 * default portals are down.  if other (non-default)
		 * portals do exist, we will still announce the target
		 * to the isns server.  In this case, we will specify
		 * all the active non-default portals as NULL portals.
		 * This is an OK state.
		 *
		 * There is a corner case if non-default portals have
		 * been marked online but the targets that use them
		 * are not fully online yet, AND all the default portals
		 * are down.  In this case, the iSNS server will receive
		 * a DevAttrReg pdu that announces both non-default
		 * portals and default-portal-only targets.  In other
		 * words, there may be no target that has an active
		 * portal. The iSNS spec does not forbid this case.
		 *
		 * Both of the above cases are somewhat theoretical.
		 * If the default portals are down we probably cannot
		 * get any messages through to the iSNS server anyway.
		 */
		return (0);
	}

	/* Portal Group Tag */
	if (isnst_add_attr(pdu, pdu_size,
	    ISNS_PG_TAG_ATTR_ID, 4, 0, ISCSIT_DEFAULT_TPGT) != 0) {
		return (1);
	}

	for (iportal = avl_first(&isns_all_portals);
	    iportal != NULL;
	    iportal = AVL_NEXT(&isns_all_portals, iportal)) {
		if (iportal->portal_default) {
			/* PG Portal Addr and PG Portal Port */
			if (isnst_add_portal_attr(pdu, pdu_size,
			    ISNS_PG_PORTAL_IP_ADDR_ATTR_ID,
			    ISNS_PG_PORTAL_PORT_ATTR_ID,
			    &iportal->portal_addr, B_FALSE) != 0) {
				return (1);
			}
			isnst_remove_from_portal_list(&iportal->portal_addr,
			    null_portal_list);
		}
	}

	return (0);
}

static int
isnst_add_null_pg(isns_pdu_t *pdu, size_t pdu_size,
    avl_tree_t *null_portal_list)
{
	isns_portal_t *iportal;

	/* If all portals accounted for, no NULL PG needed */
	if (avl_numnodes(null_portal_list) == 0) {
		return (0);
	}

	/* NULL Portal Group Tag means no access via these portals. */
	if (isnst_add_attr(pdu, pdu_size,
	    ISNS_PG_TAG_ATTR_ID, 0, 0, 0) != 0) {
		return (1);
	}

	for (iportal = avl_first(null_portal_list);
	    iportal != NULL;
	    iportal = AVL_NEXT(null_portal_list, iportal)) {
		if (isnst_add_portal_attr(pdu, pdu_size,
		    ISNS_PG_PORTAL_IP_ADDR_ATTR_ID,
		    ISNS_PG_PORTAL_PORT_ATTR_ID,
		    &iportal->portal_addr, B_FALSE) != 0) {
			return (1);
		}
	}

	return (0);
}

static int
isnst_add_portal_attr(isns_pdu_t *pdu, size_t pdu_size,
    uint32_t ip_attr_id, uint32_t port_attr_id,
    struct sockaddr_storage *ss, boolean_t esi_info)
{
	struct sockaddr_in	*in;
	struct sockaddr_in6	*in6;
	uint32_t		attr_numeric_data;
	void			*inaddrp;

	in = (struct sockaddr_in *)ss;
	in6 = (struct sockaddr_in6 *)ss;

	ASSERT((ss->ss_family == AF_INET) || (ss->ss_family == AF_INET6));

	if (ss->ss_family == AF_INET) {
		attr_numeric_data = sizeof (in_addr_t);
		inaddrp = (void *)&in->sin_addr;
	} else if (ss->ss_family == AF_INET6) {
		attr_numeric_data = sizeof (in6_addr_t);
		inaddrp = (void *)&in6->sin6_addr;
	}

	/* Portal Group Portal IP Address */
	if (isnst_add_attr(pdu, pdu_size, ip_attr_id,
	    16, inaddrp, attr_numeric_data) != 0) {
		return (1);
	}

	/* Portal Group Portal Port */
	if (isnst_add_attr(pdu, pdu_size, port_attr_id,
	    4, 0, ntohs(in->sin_port)) != 0) {
		return (1);
	}

	mutex_enter(&esi.esi_mutex);
	if (esi_info && esi.esi_valid) {
		/* ESI interval and port */
		if (isnst_add_attr(pdu, pdu_size, ISNS_ESI_INTERVAL_ATTR_ID, 4,
		    NULL, isns_default_esi_interval) != 0) {
			return (1);
		}

		if (isnst_add_attr(pdu, pdu_size, ISNS_ESI_PORT_ATTR_ID, 4,
		    NULL, esi.esi_port) != 0) {
			return (1);
		}
	}
	mutex_exit(&esi.esi_mutex);

	return (0);
}

static int
isnst_deregister(iscsit_isns_svr_t *svr, isns_target_t *itarget)
{
	int		rc;
	isns_pdu_t	*pdu, *rsp;
	size_t		pdu_size, rsp_size;
	struct sonode	*so;

	so = isnst_open_so(&svr->svr_sa);

	if (so == NULL) {
		return (-1);
	}

	pdu_size = isnst_make_dereg_pdu(svr, &pdu, itarget);
	if (pdu_size == 0) {
		isnst_close_so(so);
		return (-1);
	}

	rc = isnst_send_pdu(so, pdu);
	if (rc != 0) {
		isnst_close_so(so);
		kmem_free(pdu, pdu_size);
		return (rc);
	}

	rsp_size = isnst_rcv_pdu(so, &rsp);
	if (rsp_size == 0) {
		isnst_close_so(so);
		kmem_free(pdu, pdu_size);
		return (-1);
	}

	rc = isnst_verify_rsp(svr, pdu, rsp, rsp_size);

	isnst_close_so(so);
	kmem_free(pdu, pdu_size);
	kmem_free(rsp, rsp_size);

	return (rc);
}

static int
isnst_keepalive(iscsit_isns_svr_t *svr)
{
	int		rc;
	isns_pdu_t	*pdu, *rsp;
	size_t		pdu_size, rsp_size;
	struct sonode	*so;

	so = isnst_open_so(&svr->svr_sa);

	if (so == NULL) {
		return (-1);
	}

	pdu_size = isnst_make_keepalive_pdu(svr, &pdu);
	if (pdu_size == 0) {
		isnst_close_so(so);
		return (-1);
	}

	rc = isnst_send_pdu(so, pdu);
	if (rc != 0) {
		isnst_close_so(so);
		kmem_free(pdu, pdu_size);
		return (rc);
	}

	rsp_size = isnst_rcv_pdu(so, &rsp);
	if (rsp_size == 0) {
		isnst_close_so(so);
		kmem_free(pdu, pdu_size);
		return (-1);
	}

	rc = isnst_verify_rsp(svr, pdu, rsp, rsp_size);

	isnst_close_so(so);
	kmem_free(pdu, pdu_size);
	kmem_free(rsp, rsp_size);

	return (rc);
}

static size_t
isnst_make_dereg_pdu(iscsit_isns_svr_t *svr, isns_pdu_t **pdu,
    isns_target_t *itarget)
{
	size_t		pdu_size;
	int		len;
	isns_target_t	*src;

	/*
	 * create DevDereg Message with all of target nodes
	 */
	pdu_size = isnst_create_pdu_header(ISNS_DEV_DEREG, pdu, 0);
	if (pdu_size == 0) {
		return (0);
	}

	/*
	 * Source attribute - Must be a storage node in the same
	 * network entity.
	 */
	if (svr->svr_registered) {
		src = isnst_get_registered_source(svr);
	} else if (itarget != NULL) {
		src = itarget;
	} else {
		goto dereg_pdu_error;
	}

	len = strlen(src->target_info->ti_tgt_name) + 1;
	if (isnst_add_attr(*pdu, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
	    len, src->target_info->ti_tgt_name, 0) != 0) {
		goto dereg_pdu_error;
	}


	/* Delimiter */
	if (isnst_add_attr(*pdu, pdu_size, ISNS_DELIMITER_ATTR_ID,
	    0, 0, 0) != 0) {
		goto dereg_pdu_error;
	}

	/*
	 * Operating attributes
	 */
	if (itarget == NULL) {
		/* dereg everything */
		len = strlen(isns_eid) + 1;
		if (isnst_add_attr(*pdu, pdu_size, ISNS_EID_ATTR_ID,
		    len, isns_eid, 0) != 0) {
			goto dereg_pdu_error;
		}
	} else {
		/* dereg one target only */
		len = strlen(itarget->target_info->ti_tgt_name) + 1;
		if (isnst_add_attr(*pdu, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
		    len, itarget->target_info->ti_tgt_name, 0) != 0) {
			goto dereg_pdu_error;
		}
	}

	return (pdu_size);

dereg_pdu_error:
	kmem_free(*pdu, pdu_size);
	*pdu = NULL;

	return (0);
}

static size_t
isnst_make_keepalive_pdu(iscsit_isns_svr_t *svr, isns_pdu_t **pdu)
{
	size_t		pdu_size;
	int		len;
	isns_target_t	*src;

	ASSERT(svr->svr_registered);

	/*
	 * create DevAttrQuery Message
	 */
	pdu_size = isnst_create_pdu_header(ISNS_DEV_ATTR_QRY, pdu, 0);
	if (pdu_size == 0) {
		return (0);
	}

	/*
	 * Source attribute - Must be a iscsi target in the same
	 * network entity.
	 */
	src = isnst_get_registered_source(svr);

	len = strlen(src->target_info->ti_tgt_name) + 1;
	if (isnst_add_attr(*pdu, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
	    len, src->target_info->ti_tgt_name, 0) != 0) {
		goto keepalive_pdu_error;
	}

	/* EID */
	len = strlen(isns_eid) + 1;
	if (isnst_add_attr(*pdu, pdu_size, ISNS_EID_ATTR_ID,
	    len, isns_eid, 0) != 0) {
		goto keepalive_pdu_error;
	}
	/* Delimiter */
	if (isnst_add_attr(*pdu, pdu_size, ISNS_DELIMITER_ATTR_ID,
	    0, 0, 0) != 0) {
		goto keepalive_pdu_error;
	}

	/* Values to Fetch -- EID */
	if (isnst_add_attr(*pdu, pdu_size, ISNS_EID_ATTR_ID,
	    0, 0, 0) != 0) {
		goto keepalive_pdu_error;
	}


	return (pdu_size);

keepalive_pdu_error:
	kmem_free(*pdu, pdu_size);
	*pdu = NULL;

	return (0);
}

static isns_target_t *
isnst_get_registered_source(iscsit_isns_svr_t *svr)
{
	isns_target_t	*itarget;

	/*
	 * If svr is registered, then there must be at least one
	 * target that is registered to that svr.
	 */
	ISNS_GLOBAL_LOCK();
	ASSERT(svr->svr_monitor_hold);
	itarget = isnst_get_registered_source_locked(svr);
	ISNS_GLOBAL_UNLOCK();
	return (itarget);
}

static isns_target_t *
isnst_get_registered_source_locked(iscsit_isns_svr_t *svr)
{
	isns_target_t	*itarget;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());
	ASSERT(svr->svr_registered);
	ASSERT((avl_numnodes(&svr->svr_target_list) != 0));

	itarget = avl_first(&svr->svr_target_list);
	do {
		if (itarget->target_registered == B_TRUE)
			break;
		itarget = AVL_NEXT(&svr->svr_target_list, itarget);
	} while (itarget != NULL);
	ASSERT(itarget != NULL);
	return (itarget);
}

static int
isnst_verify_rsp(iscsit_isns_svr_t *svr, isns_pdu_t *pdu,
    isns_pdu_t *rsp, size_t rsp_size)
{
	uint16_t	func_id;
	int		payload_len, rsp_payload_len;
	int		status;
	isns_resp_t	*resp;
	uint8_t		*pp;
	isns_tlv_t	*attr;
	uint32_t	attr_len, attr_id, esi_interval;

	/*
	 * Ensure we have at least a valid header (don't count the
	 * "payload" field.
	 */
	if (rsp_size < offsetof(isns_pdu_t, payload)) {
		ISNST_LOG(CE_WARN, "Invalid iSNS PDU header, %d of %d bytes",
		    (int)rsp_size, (int)offsetof(isns_pdu_t, payload));
		return (-1);
	}

	/* Make sure we have the amount of data that the header specifies */
	payload_len = ntohs(rsp->payload_len);
	if (rsp_size < (payload_len + offsetof(isns_pdu_t, payload))) {
		ISNST_LOG(CE_WARN, "Invalid iSNS response, %d of %d bytes",
		    (int)rsp_size,
		    (int)(payload_len + offsetof(isns_pdu_t, payload)));
		return (-1);
	}

	/* Find the start of all operational parameters */
	rsp_payload_len = isnst_pdu_get_op(rsp, &pp);
	/*
	 * Make sure isnst_pdu_get_op didn't encounter an error
	 * in the attributes.
	 */
	if (pp == NULL) {
		return (-1);
	}

	/* verify response transaction id */
	if (ntohs(rsp->xid) != ntohs(pdu->xid)) {
		return (-1);
	}

	/* check the error code */
	resp = (isns_resp_t *)((void *)&rsp->payload[0]);

	status = ntohl(resp->status);

	/* validate response function id */
	func_id = ntohs(rsp->func_id);
	switch (ntohs(pdu->func_id)) {
	case ISNS_DEV_ATTR_REG:
		if (func_id != ISNS_DEV_ATTR_REG_RSP) {
			return (-1);
		}

		/* Only look through response if msg status says OK */
		if (status != 0) {
			break;
		}
		/*
		 * Get the ESI interval returned by the server.  It could
		 * be different than what we asked for.  We never know which
		 * portal a request may come in on, and any server could demand
		 * any interval. We'll simply keep track of the largest
		 * interval for use in monitoring.
		 */

		attr = (isns_tlv_t *)((void *)pp);
		while (rsp_payload_len >= 8) {
			attr_len = ntohl(attr->attr_len);
			attr_id = ntohl(attr->attr_id);
			if (attr_id == ISNS_ESI_INTERVAL_ATTR_ID) {
				if (attr_len != 4 ||
				    attr_len > rsp_payload_len - 8) {
					/* Mal-formed packet */
					return (-1);
				}
				esi_interval =
				    ntohl(*((uint32_t *)
				    ((void *)(&attr->attr_value))));

				ISNS_GLOBAL_LOCK();
				ASSERT(svr->svr_monitor_hold);
				if (esi_interval > svr->svr_esi_interval)
					svr->svr_esi_interval = esi_interval;
				ISNS_GLOBAL_UNLOCK();

				break;
			}
			rsp_payload_len -= (8 + attr_len);
			attr = (isns_tlv_t *)
			    ((void *)((uint8_t *)attr + attr_len + 8));
		}

		break;
	case ISNS_DEV_DEREG:
		if (func_id != ISNS_DEV_DEREG_RSP) {
			return (-1);
		}
		break;
	case ISNS_DEV_ATTR_QRY:
		/* Keepalive Response */
		if (func_id != ISNS_DEV_ATTR_QRY_RSP) {
			return (-1);
		}

		if (status == 0) {
			boolean_t	found_eid = B_FALSE;

			/* Scan the operational parameters */
			attr = (isns_tlv_t *)((void *)pp);
			while (rsp_payload_len >= 8) {
				attr_len = ntohl(attr->attr_len);
				attr_id = ntohl(attr->attr_id);
				if (attr_id == ISNS_EID_ATTR_ID &&
				    attr_len > 0 &&
				    attr_len <= rsp_payload_len - 8) {
					/*
					 * If the isns server knows us, the
					 * response will include our EID in
					 * the operational parameters, i.e.
					 * after the delimiter.
					 * Just receiving this pattern
					 * is good enough to tell the isns
					 * server still knows us.
					 */
					found_eid = B_TRUE;
					break;
				}

				rsp_payload_len -= (8 + attr_len);
				attr = (isns_tlv_t *)
				    ((void *)((uint8_t *)attr + attr_len + 8));
			}
			if (! found_eid) {
				status = ISNS_RSP_NO_SUCH_ENTRY;
			}
		}
		if (status == ISNS_RSP_NO_SUCH_ENTRY) {
			char	server_buf[IDM_SA_NTOP_BUFSIZ];
			/*
			 * The iSNS server has forgotten about us.
			 * We will re-register everything.
			 * This can happen e.g. if ESI probes time out,
			 * or if the iSNS server does a factory reset.
			 */
			ISNST_LOG(CE_WARN, "iscsit: iSNS server %s"
			    " forgot about us and has to be reminded.",
			    idm_sa_ntop(&svr->svr_sa,
			    server_buf, sizeof (server_buf)));
			/* isnst_retry_registration will trigger the reset */
		}

		break;

	default:
		ASSERT(0);
		break;
	}

	/* Update the last time we heard from this server */
	if (status == 0) {
		ISNS_GLOBAL_LOCK();
		ASSERT(svr->svr_monitor_hold);
		svr->svr_last_msg = ddi_get_lbolt();
		ISNS_GLOBAL_UNLOCK();
	}



	return (status);
}

static uint16_t
isnst_pdu_get_op(isns_pdu_t *pdu, uint8_t **pp)
{
	uint8_t		*payload;
	uint16_t	payload_len;
	isns_resp_t	*resp;
	isns_tlv_t	*attr;
	uint32_t	attr_id;
	uint32_t	tlv_len;

	/* get payload */
	payload_len = ntohs(pdu->payload_len);
	resp = (isns_resp_t *)((void *)&pdu->payload[0]);

	/* find the operating attributes */
	if (payload_len < sizeof (resp->status)) {
		ISNST_LOG(CE_WARN, "Invalid iSNS response, %d payload bytes",
		    payload_len);
		*pp = NULL;
		return (0);
	}

	payload_len -= sizeof (resp->status);
	payload = &resp->data[0];

	while (payload_len >= (sizeof (isns_tlv_t) - 1)) {
		attr = (isns_tlv_t *)((void *)payload);
		tlv_len = offsetof(isns_tlv_t, attr_value) +
		    ntohl(attr->attr_len);
		if (payload_len >= tlv_len) {
			payload += tlv_len;
			payload_len -= tlv_len;
			attr_id = ntohl(attr->attr_id);
			if (attr_id == ISNS_DELIMITER_ATTR_ID) {
				break;
			}
		} else {
			/* mal-formed packet */
			payload = NULL;
			payload_len = 0;
		}
	}

	*pp = payload;

	return (payload_len);
}

static size_t
isnst_create_pdu_header(uint16_t func_id, isns_pdu_t **pdu, uint16_t flags)
{
	size_t	pdu_size = isns_message_buf_size;

	*pdu = (isns_pdu_t *)kmem_zalloc(pdu_size, KM_NOSLEEP);
	if (*pdu != NULL) {
		(*pdu)->version = htons((uint16_t)ISNSP_VERSION);
		(*pdu)->func_id = htons((uint16_t)func_id);
		(*pdu)->payload_len = htons(0);
		(*pdu)->flags = htons(flags);

		(*pdu)->xid = htons(GET_XID());
		(*pdu)->seq = htons(0);
	} else {
		pdu_size = 0;
	}

	return (pdu_size);
}

static int
isnst_add_attr(isns_pdu_t *pdu,
    size_t max_pdu_size,
    uint32_t attr_id,
    uint32_t attr_len,
    void *attr_data,
    uint32_t attr_numeric_data)
{
	isns_tlv_t	*attr_tlv;
	uint8_t		*payload_ptr;
	uint16_t	payload_len;
	uint32_t	normalized_attr_len;
	uint64_t	attr_tlv_len;

	/* The attribute length must be 4-byte aligned. Section 5.1.3. */
	normalized_attr_len = (attr_len % 4) == 0 ?
	    (attr_len) : (attr_len + (4 - (attr_len % 4)));
	attr_tlv_len = ISNS_TLV_ATTR_ID_LEN +
	    ISNS_TLV_ATTR_LEN_LEN + normalized_attr_len;

	/* Check if we are going to exceed the maximum PDU length. */
	payload_len = ntohs(pdu->payload_len);
	if ((payload_len + attr_tlv_len) > max_pdu_size) {
		return (1);
	}

	attr_tlv = (isns_tlv_t *)kmem_zalloc(attr_tlv_len, KM_SLEEP);

	attr_tlv->attr_id = htonl(attr_id);

	switch (attr_id) {
	case ISNS_DELIMITER_ATTR_ID:
		break;

	case ISNS_PORTAL_IP_ADDR_ATTR_ID:
	case ISNS_PG_PORTAL_IP_ADDR_ATTR_ID:
		if (attr_numeric_data == sizeof (in_addr_t)) {
			/* IPv4 */
			attr_tlv->attr_value[10] = 0xFF;
			attr_tlv->attr_value[11] = 0xFF;
			bcopy(attr_data, ((attr_tlv->attr_value) + 12),
			    sizeof (in_addr_t));
		} else if (attr_numeric_data == sizeof (in6_addr_t)) {
			/* IPv6 */
			bcopy(attr_data, attr_tlv->attr_value,
			    sizeof (in6_addr_t));
		} else if (attr_numeric_data == 0) {
			/* EMPTY */
			/* Do nothing */
		} else {
			kmem_free(attr_tlv, attr_tlv_len);
			attr_tlv = NULL;
			return (1);
		}
		break;

	case ISNS_EID_ATTR_ID:
	case ISNS_ISCSI_NAME_ATTR_ID:
	case ISNS_ISCSI_ALIAS_ATTR_ID:
	case ISNS_PG_ISCSI_NAME_ATTR_ID:
		if (attr_len && attr_data) {
			bcopy((char *)attr_data,
			    attr_tlv->attr_value, attr_len);
		}
		break;

	default:
		if (attr_len == 8) {
			*(uint64_t *)((void *)attr_tlv->attr_value) =
			    BE_64((uint64_t)attr_numeric_data);
		} else if (attr_len == 4) {
			*(uint32_t *)((void *)attr_tlv->attr_value) =
			    htonl((uint32_t)attr_numeric_data);
		}
		break;
	}

	attr_tlv->attr_len = htonl(normalized_attr_len);
	/*
	 * Convert the network byte ordered payload length to host byte
	 * ordered for local address calculation.
	 */
	payload_len = ntohs(pdu->payload_len);
	payload_ptr = pdu->payload + payload_len;
	bcopy(attr_tlv, payload_ptr, attr_tlv_len);
	payload_len += attr_tlv_len;

	/*
	 * Convert the host byte ordered payload length back to network
	 * byte ordered - it's now ready to be sent on the wire.
	 */
	pdu->payload_len = htons(payload_len);

	kmem_free(attr_tlv, attr_tlv_len);
	attr_tlv = NULL;

	return (0);
}

static void
isnst_so_timeout(void *so)
{
	/* Wake up any sosend or sorecv blocked on this socket */
	idm_soshutdown(so);
}

static int
isnst_send_pdu(void *so, isns_pdu_t *pdu)
{
	size_t		total_len, payload_len, send_len;
	uint8_t		*payload;
	uint16_t	flags, seq;
	timeout_id_t	send_timer;
	iovec_t		iov[2];
	int		rc;

	ASSERT(! ISNS_GLOBAL_LOCK_HELD());

	/* update pdu flags */
	flags  = ntohs(pdu->flags);
	flags |= ISNS_FLAG_CLIENT;
	flags |= ISNS_FLAG_FIRST_PDU;

	/* initalize sequence number */
	seq = 0;

	payload = pdu->payload;

	/* total payload length */
	total_len = ntohs(pdu->payload_len);

	/* fill in the pdu header */
	iov[0].iov_base = (void *)pdu;
	iov[0].iov_len = ISNSP_HEADER_SIZE;

	do {
		/* split the payload accordingly */
		if (total_len > ISNSP_MAX_PAYLOAD_SIZE) {
			payload_len = ISNSP_MAX_PAYLOAD_SIZE;
		} else {
			payload_len = total_len;
			/* set the last pdu flag */
			flags |= ISNS_FLAG_LAST_PDU;
		}

		/* set back the pdu flags */
		pdu->flags = htons(flags);
		/* set the sequence number */
		pdu->seq = htons(seq);
		/* set the payload length */
		pdu->payload_len = htons(payload_len);

		/* fill in the payload */
		iov[1].iov_base = (void *)payload;
		iov[1].iov_len = payload_len;

		DTRACE_PROBE3(isnst__pdu__send, uint16_t, ntohs(pdu->func_id),
		    uint16_t, ntohs(pdu->payload_len), caddr_t, pdu);

		/* send the pdu */
		send_len = ISNSP_HEADER_SIZE + payload_len;
		send_timer = timeout(isnst_so_timeout, so,
		    drv_usectohz(isns_timeout_usec));
		rc = idm_iov_sosend(so, &iov[0], 2, send_len);
		(void) untimeout(send_timer);

		flags &= ~ISNS_FLAG_FIRST_PDU;
		payload += payload_len;
		total_len -= payload_len;

		/* increase the sequence number */
		seq ++;

	} while (rc == 0 && total_len > 0);

	return (rc);
}

static size_t
isnst_rcv_pdu(void *so, isns_pdu_t **pdu)
{
	size_t		total_pdu_len;
	size_t		total_payload_len;
	size_t		payload_len;
	size_t		combined_len;
	isns_pdu_t	tmp_pdu_hdr;
	isns_pdu_t	*combined_pdu;
	uint8_t		*payload;
	uint8_t		*combined_payload;
	timeout_id_t	rcv_timer;
	uint16_t	flags;
	uint16_t	seq;

	ASSERT(! ISNS_GLOBAL_LOCK_HELD());

	*pdu = NULL;
	total_pdu_len = total_payload_len = 0;
	payload = NULL;
	seq = 0;

	do {
		/* receive the pdu header */
		rcv_timer = timeout(isnst_so_timeout, so,
		    drv_usectohz(isns_timeout_usec));
		if (idm_sorecv(so, &tmp_pdu_hdr, ISNSP_HEADER_SIZE) != 0 ||
		    ntohs(tmp_pdu_hdr.seq) != seq) {
			(void) untimeout(rcv_timer);
			goto rcv_error;
		}
		(void) untimeout(rcv_timer);

		/* receive the payload */
		payload_len = ntohs(tmp_pdu_hdr.payload_len);
		if (payload_len > ISNST_MAX_MSG_SIZE) {
			goto rcv_error;
		}
		payload = kmem_alloc(payload_len, KM_NOSLEEP);
		if (payload == NULL) {
			goto rcv_error;
		}
		rcv_timer = timeout(isnst_so_timeout, so,
		    drv_usectohz(ISNS_RCV_TIMER_SECONDS * 1000000));
		if (idm_sorecv(so, payload, payload_len) != 0) {
			(void) untimeout(rcv_timer);
			goto rcv_error;
		}
		(void) untimeout(rcv_timer);

		/* combine the pdu if it is not the first one */
		if (total_pdu_len > 0) {
			combined_len = total_pdu_len + payload_len;
			combined_pdu = kmem_alloc(combined_len, KM_SLEEP);
			if (combined_pdu == NULL) {
				goto rcv_error;
			}
			bcopy(*pdu, combined_pdu, total_pdu_len);
			combined_payload =
			    &combined_pdu->payload[total_payload_len];
			bcopy(payload, combined_payload, payload_len);
			kmem_free(*pdu, total_pdu_len);
			kmem_free(payload, payload_len);
			*pdu = combined_pdu;
			total_payload_len += payload_len;
			total_pdu_len += payload_len;
			(*pdu)->payload_len = htons(total_payload_len);
		} else {
			total_payload_len = payload_len;
			total_pdu_len = ISNSP_HEADER_SIZE + payload_len;
			*pdu = kmem_alloc(total_pdu_len, KM_NOSLEEP);
			if (*pdu == NULL) {
				goto rcv_error;
			}
			bcopy(&tmp_pdu_hdr, *pdu, ISNSP_HEADER_SIZE);
			bcopy(payload, &(*pdu)->payload[0], payload_len);
			kmem_free(payload, payload_len);
		}
		payload = NULL;

		/* the flags of pdu which is just received */
		flags = ntohs(tmp_pdu_hdr.flags);

		/* increase sequence number by one */
		seq ++;
	} while ((flags & ISNS_FLAG_LAST_PDU) == 0);

	DTRACE_PROBE3(isnst__pdu__recv, uint16_t, ntohs((*pdu)->func_id),
	    size_t, total_payload_len, caddr_t, *pdu);

	return (total_pdu_len);

rcv_error:
	if (*pdu != NULL) {
		kmem_free(*pdu, total_pdu_len);
		*pdu = NULL;
	}
	if (payload != NULL) {
		kmem_free(payload, payload_len);
	}
	return (0);
}

static void *
isnst_open_so(struct sockaddr_storage *sa)
{
	int sa_sz;
	ksocket_t so;

	ASSERT(! ISNS_GLOBAL_LOCK_HELD());

	/* determine local IP address */
	if (sa->ss_family == AF_INET) {
		/* IPv4 */
		sa_sz = sizeof (struct sockaddr_in);

		/* Create socket */
		so = idm_socreate(AF_INET, SOCK_STREAM, 0);
	} else {
		/* IPv6 */
		sa_sz = sizeof (struct sockaddr_in6);

		/* Create socket */
		so = idm_socreate(AF_INET6, SOCK_STREAM, 0);
	}

	if (so != NULL) {
		if (idm_so_timed_socket_connect(so, sa, sa_sz,
		    isns_timeout_usec) != 0) {
			/* not calling isnst_close_so() to */
			/* make dtrace output look clear */
			idm_soshutdown(so);
			idm_sodestroy(so);
			so = NULL;
		}
	}

	if (so == NULL) {
		char	server_buf[IDM_SA_NTOP_BUFSIZ];
		ISNST_LOG(CE_WARN, "open iSNS Server %s failed",
		    idm_sa_ntop(sa, server_buf,
		    sizeof (server_buf)));
		DTRACE_PROBE1(isnst__connect__fail,
		    struct sockaddr_storage *, sa);
	}

	return (so);
}

static void
isnst_close_so(void *so)
{
	idm_soshutdown(so);
	idm_sodestroy(so);
}

/*
 * ESI handling
 */

static void
isnst_esi_start(void)
{
	if (isns_use_esi == B_FALSE) {
		ISNST_LOG(CE_NOTE, "ESI disabled by isns_use_esi=FALSE");
		return;
	}

	ISNST_LOG(CE_NOTE, "isnst_esi_start");

	mutex_enter(&esi.esi_mutex);
	ASSERT(esi.esi_enabled == B_FALSE);
	ASSERT(esi.esi_thread_running == B_FALSE);

	esi.esi_enabled = B_TRUE;
	esi.esi_valid = B_FALSE;
	esi.esi_thread = thread_create(NULL, 0, isnst_esi_thread,
	    (void *)&esi, 0, &p0, TS_RUN, minclsyspri);

	/*
	 * Wait for the thread to start
	 */
	while (!esi.esi_thread_running) {
		cv_wait(&esi.esi_cv, &esi.esi_mutex);
	}
	mutex_exit(&esi.esi_mutex);
}

static void
isnst_esi_stop()
{
	boolean_t	need_offline = B_FALSE;

	ISNST_LOG(CE_NOTE, "isnst_esi_stop");

	/* Shutdown ESI listening socket, wait for thread to terminate */
	mutex_enter(&esi.esi_mutex);
	if (esi.esi_enabled) {
		esi.esi_enabled = B_FALSE;
		if (esi.esi_valid) {
			need_offline = B_TRUE;
		}
		mutex_exit(&esi.esi_mutex);
		if (need_offline) {
			idm_soshutdown(esi.esi_so);
			idm_sodestroy(esi.esi_so);
		}
		thread_join(esi.esi_thread_did);
	} else {
		mutex_exit(&esi.esi_mutex);
	}
}

/*
 * isnst_esi_thread
 *
 * This function listens on a socket for incoming connections from an
 * iSNS server until told to stop.
 */

/*ARGSUSED*/
static void
isnst_esi_thread(void *arg)
{
	ksocket_t		newso;
	struct sockaddr_in6	sin6;
	socklen_t		sin_addrlen;
	uint32_t		on = 1;
	int			rc;
	isns_pdu_t		*pdu;
	size_t			pl_size;

	bzero(&sin6, sizeof (struct sockaddr_in6));
	sin_addrlen = sizeof (struct sockaddr_in6);

	esi.esi_thread_did = curthread->t_did;

	mutex_enter(&esi.esi_mutex);

	/*
	 * Mark the thread as running and the portal as no longer new.
	 */
	esi.esi_thread_running = B_TRUE;
	cv_signal(&esi.esi_cv);

	while (esi.esi_enabled) {
		/*
		 * Create a socket to listen for requests from the iSNS server.
		 */
		if ((esi.esi_so = idm_socreate(PF_INET6, SOCK_STREAM, 0)) ==
		    NULL) {
			ISNST_LOG(CE_WARN,
			    "isnst_esi_thread: Unable to create socket");
			mutex_exit(&esi.esi_mutex);
			delay(drv_usectohz(1000000));
			mutex_enter(&esi.esi_mutex);
			continue;
		}

		/*
		 * Set options, bind, and listen until we're told to stop
		 */
		bzero(&sin6, sizeof (sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = htons(0);
		sin6.sin6_addr = in6addr_any;

		(void) ksocket_setsockopt(esi.esi_so, SOL_SOCKET,
		    SO_REUSEADDR, (char *)&on, sizeof (on), CRED());

		if (ksocket_bind(esi.esi_so, (struct sockaddr *)&sin6,
		    sizeof (sin6), CRED()) != 0) {
			ISNST_LOG(CE_WARN, "Unable to bind socket for ESI");
			idm_sodestroy(esi.esi_so);
			mutex_exit(&esi.esi_mutex);
			delay(drv_usectohz(1000000));
			mutex_enter(&esi.esi_mutex);
			continue;
		}

		/*
		 * Get the port (sin6 is meaningless at this point)
		 */
		(void) ksocket_getsockname(esi.esi_so,
		    (struct sockaddr *)(&sin6), &sin_addrlen, CRED());
		esi.esi_port =
		    ntohs(((struct sockaddr_in6 *)(&sin6))->sin6_port);

		if ((rc = ksocket_listen(esi.esi_so, 5, CRED())) != 0) {
			ISNST_LOG(CE_WARN, "isnst_esi_thread: listen "
			    "failure 0x%x", rc);
			idm_sodestroy(esi.esi_so);
			mutex_exit(&esi.esi_mutex);
			delay(drv_usectohz(1000000));
			mutex_enter(&esi.esi_mutex);
			continue;
		}

		ksocket_hold(esi.esi_so);
		esi.esi_valid = B_TRUE;
		while (esi.esi_enabled) {
			mutex_exit(&esi.esi_mutex);

			DTRACE_PROBE3(iscsit__isns__esi__accept__wait,
			    boolean_t, esi.esi_enabled,
			    ksocket_t, esi.esi_so,
			    struct sockaddr_in6, &sin6);
			if ((rc = ksocket_accept(esi.esi_so, NULL, NULL,
			    &newso, CRED())) != 0) {
				mutex_enter(&esi.esi_mutex);
				DTRACE_PROBE2(iscsit__isns__esi__accept__fail,
				    int, rc, boolean_t, esi.esi_enabled);
				/*
				 * If we were interrupted with EINTR
				 * it's not really a failure.
				 */
				ISNST_LOG(CE_WARN, "isnst_esi_thread: "
				    "accept failure (0x%x)", rc);

				if (rc == EINTR) {
					continue;
				} else {
					break;
				}
			}
			DTRACE_PROBE2(iscsit__isns__esi__accept,
			    boolean_t, esi.esi_enabled,
			    ksocket_t, newso);

			pl_size = isnst_rcv_pdu(newso, &pdu);
			if (pl_size == 0) {
				ISNST_LOG(CE_WARN, "isnst_esi_thread: "
				    "rcv_pdu failure");
				idm_soshutdown(newso);
				idm_sodestroy(newso);

				mutex_enter(&esi.esi_mutex);
				continue;
			}

			isnst_handle_esi_req(newso, pdu, pl_size);

			idm_soshutdown(newso);
			idm_sodestroy(newso);

			mutex_enter(&esi.esi_mutex);
		}

		idm_soshutdown(esi.esi_so);
		ksocket_rele(esi.esi_so);
		esi.esi_valid = B_FALSE;

		/*
		 * If we're going to try to re-establish the listener then
		 * destroy this socket.  Otherwise isnst_esi_stop already
		 * destroyed it.
		 */
		if (esi.esi_enabled)
			idm_sodestroy(esi.esi_so);
	}

	esi.esi_thread_running = B_FALSE;
	cv_signal(&esi.esi_cv);
	mutex_exit(&esi.esi_mutex);
esi_thread_exit:
	thread_exit();
}

/*
 * Handle an incoming ESI request
 */

static void
isnst_handle_esi_req(ksocket_t ks, isns_pdu_t *pdu, size_t pdu_size)
{
	isns_pdu_t		*rsp_pdu;
	isns_resp_t		*rsp;
	isns_tlv_t		*attr;
	uint32_t		attr_len, attr_id;
	size_t			req_pl_len, rsp_size, tlv_len;
	struct sockaddr_storage	portal_ss;
	struct sockaddr_storage	server_ss;
	struct sockaddr_in6	*portal_addr6;
	boolean_t		portal_addr_valid = B_FALSE;
	boolean_t		portal_port_valid = B_FALSE;
	uint32_t		esi_response = ISNS_RSP_SUCCESSFUL;
	isns_portal_t		*iportal;
	socklen_t		sa_len;


	if (ntohs(pdu->func_id) != ISNS_ESI) {
		ISNST_LOG(CE_WARN, "isnst_handle_esi_req: Unexpected func 0x%x",
		    pdu->func_id);
		kmem_free(pdu, pdu_size);
		return;
	}

	req_pl_len = ntohs(pdu->payload_len);
	if (req_pl_len + offsetof(isns_pdu_t, payload) > pdu_size) {
		ISNST_LOG(CE_WARN, "isnst_handle_esi_req: "
		    "payload exceeds PDU size (%d > %d)",
		    (int)(req_pl_len + offsetof(isns_pdu_t, payload)),
		    (int)pdu_size);
		/* Not all data is present -- ignore */
		kmem_free(pdu, pdu_size);
		return;
	}

	if (req_pl_len + sizeof (uint32_t) > ISNSP_MAX_PAYLOAD_SIZE) {
		ISNST_LOG(CE_WARN,
		    "isnst_handle_esi_req: PDU payload exceeds max (%ld bytes)",
		    req_pl_len + sizeof (uint32_t));
		kmem_free(pdu, pdu_size);
		return;
	}

	/*
	 * Check portal in ESI request and make sure it is valid.  Return
	 * esi_response of ISNS_RSP_SUCCESSFUL if valid, otherwise don't
	 * respond at all.  Get IP addr and port.  Format of ESI
	 * is:
	 *
	 * ISNS_TIMESTAMP_ATTR_ID,
	 * ISNS_EID_ATTR_ID,
	 * ISNS_PORTAL_IP_ADDR_ATTR_ID,
	 * ISNS_PORTAL_PORT_ATTR_ID
	 */
	bzero(&portal_ss, sizeof (struct sockaddr_storage));
	portal_ss.ss_family = AF_INET6;
	portal_addr6 = (struct sockaddr_in6 *)&portal_ss;
	attr = (isns_tlv_t *)((void *)&pdu->payload);
	attr_len = ntohl(attr->attr_len);
	attr_id = ntohl(attr->attr_id);
	tlv_len = attr_len + offsetof(isns_tlv_t, attr_value);
	while (tlv_len <= req_pl_len) {
		switch (attr_id) {
		case ISNS_TIMESTAMP_ATTR_ID:
			break;
		case ISNS_EID_ATTR_ID:
			break;
		case ISNS_PORTAL_IP_ADDR_ATTR_ID:
			if (attr_len > sizeof (struct in6_addr)) {
				/* Bad attribute format */
				esi_response = ISNS_RSP_MSG_FORMAT_ERROR;
			} else {
				portal_addr6->sin6_family = AF_INET6;
				attr_len = min(attr_len,
				    sizeof (portal_addr6->sin6_addr));
				bcopy(attr->attr_value,
				    portal_addr6->sin6_addr.s6_addr, attr_len);
				portal_addr_valid = B_TRUE;
			}
			break;
		case ISNS_PORTAL_PORT_ATTR_ID:
			if (attr_len > sizeof (uint32_t)) {
				/* Bad attribute format */
				esi_response = ISNS_RSP_MSG_FORMAT_ERROR;
			} else {
				portal_addr6->sin6_port =
				    htons((uint16_t)BE_IN32(attr->attr_value));
				portal_port_valid = B_TRUE;
			}
			break;
		default:
			/* Bad request format */
			esi_response = ISNS_RSP_MSG_FORMAT_ERROR;
			break;
		}

		/* If we've set an error then stop processing */
		if (esi_response != ISNS_RSP_SUCCESSFUL) {
			break;
		}

		/* Get next attribute */
		req_pl_len -= tlv_len;
		attr = (isns_tlv_t *)((void *)((uint8_t *)attr + tlv_len));
		attr_len = ntohl(attr->attr_len);
		attr_id = ntohl(attr->attr_id);
		tlv_len = attr_len + offsetof(isns_tlv_t, attr_value);
	}

	if (!portal_port_valid)
		portal_addr6->sin6_port = htons(ISCSI_LISTEN_PORT);

	if (!portal_addr_valid) {
		esi_response = ISNS_RSP_MSG_FORMAT_ERROR;
	}

	/*
	 * If we've detected an error or if the portal does not
	 * exist then drop the request.  The server will eventually
	 * timeout the portal and eliminate it from the list.
	 */

	if (esi_response != ISNS_RSP_SUCCESSFUL) {
		kmem_free(pdu, pdu_size);
		return;
	}

	/* Get the remote peer's IP address */
	bzero(&server_ss, sizeof (server_ss));
	sa_len = sizeof (server_ss);
	if (ksocket_getpeername(ks, (struct sockaddr *)&server_ss, &sa_len,
	    CRED())) {
		return;
	}

	if (iscsit_isns_logging) {
		char	server_buf[IDM_SA_NTOP_BUFSIZ];
		char	portal_buf[IDM_SA_NTOP_BUFSIZ];
		ISNST_LOG(CE_NOTE, "ESI: svr %s -> portal %s",
		    idm_sa_ntop(&server_ss, server_buf,
		    sizeof (server_buf)),
		    idm_sa_ntop(&portal_ss, portal_buf,
		    sizeof (portal_buf)));
	}


	ISNS_GLOBAL_LOCK();
	if (isnst_lookup_portal(&portal_ss) == NULL) {
		ISNST_LOG(CE_WARN, "ESI req to non-active portal");
		ISNS_GLOBAL_UNLOCK();
		kmem_free(pdu, pdu_size);
		return;
	}

	/*
	 * Update the server timestamp of how recently we have
	 * received an ESI request from this iSNS server.
	 * We ignore requests from servers we don't know.
	 */
	if (! isnst_update_server_timestamp(&server_ss)) {
		ISNST_LOG(CE_WARN, "ESI req from unknown server");
		kmem_free(pdu, pdu_size);
		ISNS_GLOBAL_UNLOCK();
		return;
	}

	/*
	 * Update ESI timestamps for all portals with same IP address.
	 */
	for (iportal = avl_first(&isns_all_portals);
	    iportal != NULL;
	    iportal = AVL_NEXT(&isns_all_portals, iportal)) {
		if (idm_ss_compare(&iportal->portal_addr, &portal_ss,
		    B_TRUE, B_FALSE)) {
			gethrestime(&iportal->portal_esi_timestamp);
		}
	}

	ISNS_GLOBAL_UNLOCK();


	/*
	 * Build response validating the portal
	 */
	rsp_size = isnst_create_pdu_header(ISNS_ESI_RSP, &rsp_pdu, 0);

	if (rsp_size == 0) {
		ISNST_LOG(CE_WARN, "isnst_handle_esi_req: Can't get rsp pdu");
		kmem_free(pdu, pdu_size);
		return;
	}

	rsp = (isns_resp_t *)((void *)(&rsp_pdu->payload[0]));

	/* Use xid from the request pdu */
	rsp_pdu->xid = pdu->xid;
	rsp->status = htonl(ISNS_RSP_SUCCESSFUL);

	/* Copy original data */
	req_pl_len = ntohs(pdu->payload_len);
	bcopy(pdu->payload, rsp->data, req_pl_len);
	rsp_pdu->payload_len = htons(req_pl_len + sizeof (uint32_t));

	if (isnst_send_pdu(ks, rsp_pdu) != 0) {
		ISNST_LOG(CE_WARN,
		    "isnst_handle_esi_req: Send response failed");
	}

	kmem_free(rsp_pdu, rsp_size);
	kmem_free(pdu, pdu_size);

}

static int
isnst_tgt_avl_compare(const void *t1, const void *t2)
{
	const isns_target_t	*tgt1 = t1;
	const isns_target_t	*tgt2 = t2;

	/*
	 * Sort by target (pointer to iscsit_tgt_t).
	 */

	if (tgt1->target < tgt2->target) {
		return (-1);
	} else if (tgt1->target > tgt2->target) {
		return (1);
	}

	return (0);
}

static void
isnst_set_server_status(iscsit_isns_svr_t *svr, boolean_t registered)
{
	isns_target_t		*itarget;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	svr->svr_reset_needed = B_FALSE;
	if (registered == B_TRUE) {
		svr->svr_registered = B_TRUE;
		svr->svr_last_msg = ddi_get_lbolt();
		itarget = avl_first(&svr->svr_target_list);
		while (itarget) {
			isns_target_t *next_target;
			next_target = AVL_NEXT(&svr->svr_target_list, itarget);
			if (itarget->target_delete_needed) {
				/* All deleted tgts removed */
				isnst_clear_from_target_list(itarget,
				    &svr->svr_target_list);
			} else {
				/* Other tgts marked registered */
				itarget->target_registered = B_TRUE;
				/* No updates needed -- clean slate */
				itarget->target_update_needed = B_FALSE;
			}
			itarget = next_target;
		}
		ASSERT(avl_numnodes(&svr->svr_target_list) > 0);
	} else {
		svr->svr_registered = B_FALSE;
		isnst_clear_target_list(svr);
	}
}

static void
isnst_monitor_default_portal_list(void)
{
	idm_addr_list_t		*new_portal_list = NULL;
	uint32_t		new_portal_list_size = 0;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());
	ASSERT(mutex_owned(&iscsit_isns_mutex));

	if (default_portal_online) {
		new_portal_list_size = idm_get_ipaddr(&new_portal_list);
	}

	/*
	 * We compute a new list of portals if
	 * a) Something in itadm has changed a portal
	 * b) there are new default portals
	 * c) the default portal has gone offline
	 */
	if (isns_portals_changed ||
	    ((new_portal_list_size != 0) &&
	    (isnst_find_default_portals(new_portal_list) !=
	    num_default_portals)) ||
	    ((new_portal_list_size == 0) && (num_default_portals > 0))) {

		isnst_clear_default_portals();
		isnst_copy_portal_list(&isns_tpg_portals,
		    &isns_all_portals);
		num_tpg_portals = avl_numnodes(&isns_all_portals);
		if (new_portal_list_size != 0) {
			num_default_portals =
			    isnst_add_default_portals(new_portal_list);
		}
	}

	/* Catch any case where we miss an update to TPG portals */
	ASSERT(num_tpg_portals == avl_numnodes(&isns_tpg_portals));

	if (new_portal_list != NULL) {
		kmem_free(new_portal_list, new_portal_list_size);
	}
}


static int
isnst_find_default_portals(idm_addr_list_t *alist)
{
	idm_addr_t		*dportal;
	isns_portal_t		*iportal;
	struct sockaddr_storage	sa;
	int			aidx;
	int			num_portals_found = 0;

	for (aidx = 0; aidx < alist->al_out_cnt; aidx++) {
		dportal = &alist->al_addrs[aidx];
		dportal->a_port = ISCSI_LISTEN_PORT;
		idm_addr_to_sa(dportal, &sa);
		iportal = isnst_lookup_portal(&sa);
		if (iportal == NULL) {
			/* Found a non-matching default portal */
			return (-1);
		}
		if (iportal->portal_default) {
			num_portals_found++;
		}
	}
	return (num_portals_found);
}

static void
isnst_clear_default_portals(void)
{
	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	isnst_clear_portal_list(&isns_all_portals);
	num_tpg_portals = 0;
	num_default_portals = 0;
}

static int
isnst_add_default_portals(idm_addr_list_t *alist)
{
	idm_addr_t		*dportal;
	isns_portal_t		*iportal;
	struct sockaddr_storage	sa;
	int			aidx;

	for (aidx = 0; aidx < alist->al_out_cnt; aidx++) {
		dportal = &alist->al_addrs[aidx];
		dportal->a_port = ISCSI_LISTEN_PORT;
		idm_addr_to_sa(dportal, &sa);
		iportal = isnst_add_to_portal_list(&sa, &isns_all_portals);
		iportal->portal_default = B_TRUE;
	}
	return (alist->al_out_cnt);
}


static int
isnst_portal_avl_compare(const void *p1, const void *p2)
{
	const isns_portal_t	*portal1 = p1;
	const isns_portal_t	*portal2 = p2;

	return (idm_ss_compare(&portal1->portal_addr, &portal2->portal_addr,
	    B_TRUE /* v4_mapped_as_v4 */, B_TRUE /* compare_ports */));
}

static void
isnst_clear_portal_list(avl_tree_t *portal_list)
{
	isns_portal_t	*iportal;
	void *cookie = NULL;

	while ((iportal = avl_destroy_nodes(portal_list, &cookie)) != NULL) {
		kmem_free(iportal, sizeof (isns_portal_t));
	}
}
static void
isnst_copy_portal_list(avl_tree_t *t1, avl_tree_t *t2)
{
	isns_portal_t		*iportal, *jportal;

	iportal = (isns_portal_t *)avl_first(t1);
	while (iportal) {
		jportal = isnst_add_to_portal_list(&iportal->portal_addr, t2);
		jportal->portal_iscsit = iportal->portal_iscsit;
		iportal = AVL_NEXT(t1, iportal);
	}
}


static isns_portal_t *
isnst_lookup_portal(struct sockaddr_storage *sa)
{
	isns_portal_t *iportal, tmp_portal;
	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	bcopy(sa, &tmp_portal.portal_addr, sizeof (*sa));
	iportal = avl_find(&isns_all_portals, &tmp_portal, NULL);
	return (iportal);
}

static isns_portal_t *
isnst_add_to_portal_list(struct sockaddr_storage *sa, avl_tree_t *portal_list)
{
	isns_portal_t		*iportal, tmp_portal;
	avl_index_t		where;
	/*
	 * Make sure this portal isn't already in our list.
	 */

	bcopy(sa, &tmp_portal.portal_addr, sizeof (*sa));

	if ((iportal = (isns_portal_t *)avl_find(portal_list,
	    &tmp_portal, &where)) == NULL) {
		iportal = kmem_zalloc(sizeof (isns_portal_t), KM_SLEEP);
		bcopy(sa, &iportal->portal_addr, sizeof (*sa));
		avl_insert(portal_list, (void *)iportal, where);
	}

	return (iportal);
}


static void
isnst_remove_from_portal_list(struct sockaddr_storage *sa,
    avl_tree_t *portal_list)
{
	isns_portal_t		*iportal, tmp_portal;

	bcopy(sa, &tmp_portal.portal_addr, sizeof (*sa));

	if ((iportal = avl_find(portal_list, &tmp_portal, NULL))
	    != NULL) {
		avl_remove(portal_list, iportal);
		kmem_free(iportal, sizeof (isns_portal_t));
	}
}

/*
 * These functions are called by iscsit proper when a portal comes online
 * or goes offline.
 */

void
iscsit_isns_portal_online(iscsit_portal_t *portal)
{
	isns_portal_t	*iportal;

	mutex_enter(&iscsit_isns_mutex);

	if (portal->portal_default) {
		/* Portals should only be onlined once */
		ASSERT(default_portal_online == B_FALSE);
		default_portal_online = B_TRUE;
	} else {
		iportal = isnst_add_to_portal_list(
		    &portal->portal_addr, &isns_tpg_portals);
		iportal->portal_iscsit = portal;
	}
	isns_portals_changed = B_TRUE;

	mutex_exit(&iscsit_isns_mutex);

	isnst_monitor_awaken();
}

void
iscsit_isns_portal_offline(iscsit_portal_t *portal)
{
	mutex_enter(&iscsit_isns_mutex);

	if (portal->portal_default) {
		/* Portals should only be offlined once */
		ASSERT(default_portal_online == B_TRUE);
		default_portal_online = B_FALSE;
	} else {
		isnst_remove_from_portal_list(&portal->portal_addr,
		    &isns_tpg_portals);
	}
	isns_portals_changed = B_TRUE;

	mutex_exit(&iscsit_isns_mutex);

	isnst_monitor_awaken();
}
