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
#include <iscsit.h>
#include <iscsit_isns.h>
#include <sys/ksocket.h>

/* local defines */
#define	MAX_XID			(2^16)
#define	ISNS_IDLE_TIME		60
#define	MAX_RETRY		(3)
#define	ISNS_RCV_TIMER_SECONDS	5

#define	VALID_NAME(NAME, LEN)	\
((LEN) > 0 && (NAME)[0] != 0 && (NAME)[(LEN) - 1] == 0)

static kmutex_t		isns_mutex;
static kthread_t	*isns_monitor_thr_id;
static kt_did_t		isns_monitor_thr_did;
static boolean_t	isns_monitor_thr_running;

static kcondvar_t	isns_idle_cv;

static uint16_t		xid;
#define	GET_XID()	atomic_inc_16_nv(&xid)

static clock_t		monitor_idle_interval;

#define	ISNS_GLOBAL_LOCK() \
	mutex_enter(&iscsit_global.global_isns_cfg.isns_mutex)

#define	ISNS_GLOBAL_LOCK_HELD() \
	MUTEX_HELD(&iscsit_global.global_isns_cfg.isns_mutex)

#define	ISNS_GLOBAL_UNLOCK() \
	mutex_exit(&iscsit_global.global_isns_cfg.isns_mutex)

/*
 * iSNS ESI thread state
 */

static kmutex_t		isns_esi_mutex;
static kcondvar_t	isns_esi_cv;
static list_t		esi_list;
static uint32_t		isns_esi_max_interval = 0;

/*
 * List of portals.
 */

static list_t		portal_list;
static uint32_t		portal_list_count = 0;

/* How many of our portals are not "default"? */
static uint32_t		nondefault_portals = 0;

/*
 * Our entity identifier (fully-qualified hostname)
 */
static char		*isns_eid = NULL;

/*
 * Our list of targets
 */
static avl_tree_t	isns_target_list;

static void
isnst_start();

static void
isnst_stop();

static void
iscsit_set_isns(boolean_t state);

static int
iscsit_add_isns(it_portal_t *cfg_svr);

static void
iscsit_delete_isns(iscsit_isns_svr_t *svr);

static iscsit_isns_svr_t *
iscsit_isns_svr_lookup(struct sockaddr_storage *sa);

static void
isnst_monitor(void *arg);

static int
isnst_monitor_one_server(iscsit_isns_svr_t *svr, boolean_t enabled);

static int
isnst_update_target(iscsit_tgt_t *target, isns_reg_type_t reg);

static  int
isnst_update_one_server(iscsit_isns_svr_t *svr, iscsit_tgt_t *target,
    isns_reg_type_t reg);

static int isnst_register(iscsit_isns_svr_t *svr, iscsit_tgt_t *target,
    isns_reg_type_t regtype);
static int isnst_deregister(iscsit_isns_svr_t *svr, char *node);

static size_t
isnst_make_dereg_pdu(isns_pdu_t **pdu, char *node);

static int
isnst_verify_rsp(isns_pdu_t *pdu, isns_pdu_t *rsp);

static uint16_t
isnst_pdu_get_op(isns_pdu_t *pdu, uint8_t **pp);

static size_t
isnst_make_reg_pdu(isns_pdu_t **pdu, iscsit_tgt_t *target,
    boolean_t svr_registered, isns_reg_type_t regtype);

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

static boolean_t
isnst_handle_esi_req(ksocket_t so, isns_pdu_t *pdu, size_t pl_size);

static void isnst_esi_start(isns_portal_list_t *portal);
static void isnst_esi_stop();
static void isnst_esi_stop_thread(isns_esi_tinfo_t *tinfop);
static void isnst_esi_check();
static void isnst_esi_start_thread(isns_esi_tinfo_t *tinfop);
static isns_target_t *isnst_add_to_target_list(iscsit_tgt_t *target);
int isnst_tgt_avl_compare(const void *t1, const void *t2);
static void isnst_get_target_list(void);
static void isnst_set_server_status(iscsit_isns_svr_t *svr,
    boolean_t registered);
static void isnst_monitor_stop(void);
static void isns_remove_portal(isns_portal_list_t *p);
static void isnst_add_default_portals();
static int isnst_add_default_portal_attrs(isns_pdu_t *pdu, size_t pdu_size);
static void isnst_remove_default_portals();
static boolean_t isnst_retry_registration(int rsp_status_code);

it_cfg_status_t
isnst_config_merge(it_config_t *cfg)
{
	boolean_t		new_isns_state = B_FALSE;
	iscsit_isns_svr_t	*isns_svr, *next_isns_svr;
	it_portal_t		*cfg_isns_svr;

	/*
	 * Determine whether iSNS is enabled in the new config.
	 * Isns property may not be set up yet.
	 */
	(void) nvlist_lookup_boolean_value(cfg->config_global_properties,
	    PROP_ISNS_ENABLED, &new_isns_state);

	ISNS_GLOBAL_LOCK();

	/* Delete iSNS servers that are no longer part of the config */
	for (isns_svr = list_head(&iscsit_global.global_isns_cfg.isns_svrs);
	    isns_svr != NULL;
	    isns_svr = next_isns_svr) {
		next_isns_svr = list_next(
		    &iscsit_global.global_isns_cfg.isns_svrs, isns_svr);
		if (it_sns_svr_lookup(cfg, &isns_svr->svr_sa) == NULL)
			iscsit_delete_isns(isns_svr);
	}

	/* Add new iSNS servers */
	for (cfg_isns_svr = cfg->config_isns_svr_list;
	    cfg_isns_svr != NULL;
	    cfg_isns_svr = cfg_isns_svr->next) {
		isns_svr = iscsit_isns_svr_lookup(&cfg_isns_svr->portal_addr);
		if (isns_svr == NULL) {
			if (iscsit_add_isns(cfg_isns_svr) != 0) {
				/* Shouldn't happen */
				ISNS_GLOBAL_UNLOCK();
				return (ITCFG_MISC_ERR);
			}
		}
	}

	/* Start/Stop iSNS if necessary */
	if (iscsit_global.global_isns_cfg.isns_state != new_isns_state) {
		iscsit_set_isns(new_isns_state);
	}

	ISNS_GLOBAL_UNLOCK();

	/*
	 * There is no "modify case" since the user specifies a complete
	 * server list each time.  A modify is the same as a remove+add.
	 */

	return (0);
}

int
iscsit_isns_init(iscsit_hostinfo_t *hostinfo)
{
	mutex_init(&iscsit_global.global_isns_cfg.isns_mutex, NULL,
	    MUTEX_DEFAULT, NULL);

	ISNS_GLOBAL_LOCK();
	iscsit_global.global_isns_cfg.isns_state = B_FALSE;
	list_create(&iscsit_global.global_isns_cfg.isns_svrs,
	    sizeof (iscsit_isns_svr_t), offsetof(iscsit_isns_svr_t, svr_ln));
	list_create(&portal_list, sizeof (isns_portal_list_t),
	    offsetof(isns_portal_list_t, portal_ln));
	list_create(&esi_list, sizeof (isns_esi_tinfo_t),
	    offsetof(isns_esi_tinfo_t, esi_ln));
	portal_list_count = 0;
	isns_eid = kmem_alloc(hostinfo->length, KM_SLEEP);
	if (hostinfo->length > ISCSIT_MAX_HOSTNAME_LEN)
		hostinfo->length = ISCSIT_MAX_HOSTNAME_LEN;
	(void) strlcpy(isns_eid, hostinfo->fqhn, hostinfo->length);
	avl_create(&isns_target_list, isnst_tgt_avl_compare,
	    sizeof (isns_target_t), offsetof(isns_target_t, target_node));
	/*
	 * The iscsi global lock is not held here, but it is held when
	 * isnst_start is called, so we need to acquire it only in this
	 * case.
	 */
	ISCSIT_GLOBAL_LOCK(RW_READER);
	isnst_get_target_list();
	ISCSIT_GLOBAL_UNLOCK();

	/* initialize isns client */
	mutex_init(&isns_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&isns_esi_mutex, NULL, MUTEX_DEFAULT, NULL);
	isns_monitor_thr_id = NULL;
	monitor_idle_interval = ISNS_IDLE_TIME * drv_usectohz(1000000);
	cv_init(&isns_idle_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&isns_esi_cv, NULL, CV_DEFAULT, NULL);
	xid = 0;
	ISNS_GLOBAL_UNLOCK();

	return (0);
}

static void
isnst_esi_stop_thread(isns_esi_tinfo_t *tinfop)
{
	ASSERT(ISNS_GLOBAL_LOCK_HELD());
	ASSERT(mutex_owned(&isns_esi_mutex));

	list_remove(&esi_list, tinfop);

	/*
	 * The only way to break a thread waiting in ksocket_accept() is to call
	 * ksocket_close.
	 */
	mutex_exit(&isns_esi_mutex);
	ISNS_GLOBAL_UNLOCK();
	idm_soshutdown(tinfop->esi_so);
	idm_sodestroy(tinfop->esi_so);
	thread_join(tinfop->esi_thread_did);
	ISNS_GLOBAL_LOCK();
	mutex_enter(&isns_esi_mutex);

	tinfop->esi_thread_running = B_FALSE;
	tinfop->esi_so = NULL;
	tinfop->esi_port = 0;
	tinfop->esi_registered = B_FALSE;
	cv_signal(&isns_esi_cv);
	tinfop->esi_portal->portal_esi = NULL;
	kmem_free(tinfop, sizeof (isns_esi_tinfo_t));
}

static void
isnst_esi_stop()
{
	/*
	 * Basically, we just wait for all the threads to stop.  They
	 * should already be in the process of shutting down.
	 */

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	ISNS_GLOBAL_UNLOCK();
	mutex_enter(&isns_esi_mutex);
	while (!list_is_empty(&esi_list)) {
		cv_wait(&isns_esi_cv, &isns_esi_mutex);
	}
	mutex_exit(&isns_esi_mutex);
	ISNS_GLOBAL_LOCK();
}

void
iscsit_isns_fini()
{
	ISNS_GLOBAL_LOCK();
	iscsit_set_isns(B_FALSE);
	mutex_destroy(&isns_mutex);
	cv_destroy(&isns_idle_cv);
	list_destroy(&esi_list);
	mutex_destroy(&isns_esi_mutex);
	cv_destroy(&isns_esi_cv);

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
	list_destroy(&portal_list);
	portal_list_count = 0;
	ISNS_GLOBAL_UNLOCK();

	mutex_destroy(&iscsit_global.global_isns_cfg.isns_mutex);
}

static void
iscsit_set_isns(boolean_t state)
{
	iscsit_isns_svr_t	*svr;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	/* reset retry count for all servers */
	for (svr = list_head(&iscsit_global.global_isns_cfg.isns_svrs);
	    svr != NULL;
	    svr = list_next(&iscsit_global.global_isns_cfg.isns_svrs, svr)) {
		svr->svr_retry_count = 0;
	}

	/*
	 * Update state and isns stop flag
	 */
	iscsit_global.global_isns_cfg.isns_state = state;

	if (state) {
		isnst_start();
	} else {
		isnst_stop();
	}
}

int
iscsit_add_isns(it_portal_t *cfg_svr)
{
	iscsit_isns_svr_t *svr;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	svr = kmem_zalloc(sizeof (iscsit_isns_svr_t), KM_SLEEP);
	bcopy(&cfg_svr->portal_addr, &svr->svr_sa,
	    sizeof (struct sockaddr_storage));

	/* put it on the global isns server list */
	list_insert_tail(&iscsit_global.global_isns_cfg.isns_svrs, svr);

	/*
	 * Register targets with this server if iSNS is enabled.
	 */

	if (iscsit_global.global_isns_cfg.isns_state &&
	    (isnst_update_one_server(svr, NULL, ISNS_REGISTER_ALL) == 0)) {
		isnst_set_server_status(svr, B_TRUE);
	}

	return (0);
}

void
iscsit_delete_isns(iscsit_isns_svr_t *svr)
{
	boolean_t	need_dereg;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	list_remove(&iscsit_global.global_isns_cfg.isns_svrs, svr);

	/* talk to this server if isns monitor is running */
	mutex_enter(&isns_mutex);
	if (isns_monitor_thr_id != NULL) {
		need_dereg = B_TRUE;
	} else {
		need_dereg = B_FALSE;
	}
	mutex_exit(&isns_mutex);

	if (need_dereg) {
		(void) isnst_monitor_one_server(svr, B_FALSE);
	}

	/* free the memory */
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

int
iscsit_isns_register(iscsit_tgt_t *target)
{
	int rc = 0;

	ISNS_GLOBAL_LOCK();

	(void) isnst_add_to_target_list(target);

	if (iscsit_global.global_isns_cfg.isns_state == B_FALSE) {
		ISNS_GLOBAL_UNLOCK();
		return (rc);
	}

	rc = isnst_update_target(target, ISNS_REGISTER_TARGET);

	ISNS_GLOBAL_UNLOCK();

	return (rc);
}

int
iscsit_isns_deregister(iscsit_tgt_t *target)
{
	void				*itarget;
	isns_target_t			tmptgt;
	iscsit_isns_svr_t		*svr;
	list_t				*global;

	ISNS_GLOBAL_LOCK();

	if (iscsit_global.global_isns_cfg.isns_state == B_FALSE) {
		tmptgt.target = target;

		if ((itarget = avl_find(&isns_target_list, &tmptgt, NULL))
		    != NULL) {
			avl_remove(&isns_target_list, itarget);
			kmem_free(itarget, sizeof (isns_target_t));
		}

		ISNS_GLOBAL_UNLOCK();
		return (0);
	}

	/*
	 * Don't worry about dereg failures.
	 */
	(void) isnst_update_target(target, ISNS_DEREGISTER_TARGET);

	/*
	 * Remove the target from the list regardless of the status.
	 */

	tmptgt.target = target;
	if ((itarget = avl_find(&isns_target_list, &tmptgt, NULL)) != NULL) {
		avl_remove(&isns_target_list, itarget);
		kmem_free(itarget, sizeof (isns_target_t));
	}

	/*
	 * If there are no more targets, mark the server as
	 * unregistered.
	 */

	if (avl_numnodes(&isns_target_list) == 0) {
		global = &iscsit_global.global_isns_cfg.isns_svrs;
		for (svr = list_head(global); svr != NULL;
		    svr = list_next(global, svr)) {
			isnst_set_server_status(svr, B_FALSE);
		}
	}

	ISNS_GLOBAL_UNLOCK();

	return (0);
}

/*
 * This function is called by iscsit when a target's configuration
 * has changed.
 */

void
iscsit_isns_target_update(iscsit_tgt_t *target)
{
	ISNS_GLOBAL_LOCK();

	if (iscsit_global.global_isns_cfg.isns_state == B_FALSE) {
		ISNS_GLOBAL_UNLOCK();
		return;
	}

	(void) isnst_update_target(target, ISNS_UPDATE_TARGET);

	ISNS_GLOBAL_UNLOCK();
}

static void
isnst_start()
{
	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	/*
	 * Get target and portal lists, then start ESI threads for each portal.
	 */

	isnst_get_target_list();
	isnst_add_default_portals();

	/*
	 * Create a thread for monitoring server communications
	 */
	mutex_enter(&isns_mutex);
	isns_monitor_thr_id = thread_create(NULL, 0,
	    isnst_monitor, NULL, 0, &p0, TS_RUN, minclsyspri);
	while (!isns_monitor_thr_running)
		cv_wait(&isns_idle_cv, &isns_mutex);
	mutex_exit(&isns_mutex);
}

static void
isnst_monitor_stop(void)
{
	mutex_enter(&isns_mutex);
	if (isns_monitor_thr_running) {
		isns_monitor_thr_running = B_FALSE;
		cv_signal(&isns_idle_cv);
		mutex_exit(&isns_mutex);

		thread_join(isns_monitor_thr_did);
		return;
	}
	mutex_exit(&isns_mutex);
}

static void
isnst_stop()
{
	isns_target_t *itarget;

	isnst_remove_default_portals();
	isnst_esi_stop();
	ISNS_GLOBAL_UNLOCK();
	isnst_monitor_stop();
	ISNS_GLOBAL_LOCK();
	while ((itarget = avl_first(&isns_target_list)) != NULL) {
		avl_remove(&isns_target_list, itarget);
		kmem_free(itarget, sizeof (isns_target_t));
	}
}

/*
 * isnst_update_server_timestamp
 *
 * When we receive an ESI request, update the timestamp for the server.
 * If we don't receive one for the specified period of time, we'll attempt
 * to re-register.
 */

static void
isnst_update_server_timestamp(ksocket_t so)
{
	iscsit_isns_svr_t	*svr;
	struct in_addr		*sin = NULL, *svr_in;
	struct in6_addr		*sin6 = NULL, *svr_in6;
	struct sockaddr_in6	t_addr;
	socklen_t		t_addrlen;

	bzero(&t_addr, sizeof (struct sockaddr_in6));
	t_addrlen = sizeof (struct sockaddr_in6);
	(void) ksocket_getpeername(so, (struct sockaddr *)&t_addr, &t_addrlen,
	    CRED());
	if (((struct sockaddr *)(&t_addr))->sa_family == AF_INET) {
		sin = &((struct sockaddr_in *)((void *)(&t_addr)))->sin_addr;
	} else {
		sin6 = &(&t_addr)->sin6_addr;
	}

	/*
	 * Find the server and update the timestamp
	 */

	ISNS_GLOBAL_LOCK();
	for (svr = list_head(&iscsit_global.global_isns_cfg.isns_svrs);
	    svr != NULL;
	    svr = list_next(&iscsit_global.global_isns_cfg.isns_svrs, svr)) {
		if (sin6 == NULL) {
			if (svr->svr_sa.ss_family == AF_INET) {
				svr_in = &((struct sockaddr_in *)&svr->svr_sa)->
				    sin_addr;
				if (bcmp(svr_in, sin, sizeof (in_addr_t))
				    == 0) {
					break;
				}
			}
		} else {
			if (svr->svr_sa.ss_family == AF_INET6) {
				svr_in6 = &((struct sockaddr_in6 *)
				    &svr->svr_sa)->sin6_addr;
				if (bcmp(svr_in6, sin6,
				    sizeof (in6_addr_t)) == 0) {
					break;
				}
			}
		}
	}

	if (svr != NULL) {
		svr->svr_last_msg = ddi_get_lbolt();
	}
	ISNS_GLOBAL_UNLOCK();
}

/*
 * isnst_monitor
 *
 * This function monitors registration status for each server.
 */


static void
isnst_monitor_all_servers()
{
	iscsit_isns_svr_t	*svr;
	boolean_t		enabled;
	list_t			*svr_list;

	svr_list = &iscsit_global.global_isns_cfg.isns_svrs;

	ISNS_GLOBAL_LOCK();
	enabled = iscsit_global.global_isns_cfg.isns_state;
	for (svr = list_head(svr_list); svr != NULL;
	    svr = list_next(svr_list, svr)) {
		if (isnst_monitor_one_server(svr, enabled) != 0) {
			svr->svr_retry_count++;
		} else {
			svr->svr_retry_count = 0;
		}
	}
	ISNS_GLOBAL_UNLOCK();
}

/*ARGSUSED*/
static void
isnst_monitor(void *arg)
{
	mutex_enter(&isns_mutex);
	cv_signal(&isns_idle_cv);
	isns_monitor_thr_did = curthread->t_did;
	isns_monitor_thr_running = B_TRUE;

	while (isns_monitor_thr_running) {
		mutex_exit(&isns_mutex);

		/* Update servers */
		isnst_monitor_all_servers();

		/*
		 * Keep running until isns_monitor_thr_running is set to
		 * B_FALSE.
		 */
		mutex_enter(&isns_mutex);
		DTRACE_PROBE(iscsit__isns__monitor__sleep);
		(void) cv_timedwait(&isns_idle_cv, &isns_mutex,
		    ddi_get_lbolt() + monitor_idle_interval);
		DTRACE_PROBE1(iscsit__isns__monitor__wakeup,
		    boolean_t, isns_monitor_thr_running);
	}

	mutex_exit(&isns_mutex);

	/* Update the servers one last time for deregistration */
	isnst_monitor_all_servers();

	/* terminate the thread at the last */
	thread_exit();
}

static int
isnst_monitor_one_server(iscsit_isns_svr_t *svr, boolean_t enabled)
{
	int		rc = 0;
	struct sonode	*so;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	/*
	 * First, take care of the case where iSNS is no longer enabled.
	 *
	 * If we're still registered, deregister.  Regardless, mark the
	 * server as not registered.
	 */

	if (enabled == B_FALSE) {
		if (svr->svr_registered == B_TRUE) {
			/*
			 * Doesn't matter if this fails.  We're disabled.
			 */
			so = isnst_open_so(&svr->svr_sa);
			if (so != NULL) {
				(void) isnst_update_one_server(svr, NULL,
				    ISNS_DEREGISTER_ALL);
				isnst_close_so(so);
			}
		}

		isnst_set_server_status(svr, B_FALSE);
		return (0);
	}

	/*
	 * If there are no targets, we're done.
	 */

	if (avl_numnodes(&isns_target_list) == 0) {
		return (0);
	}

	/*
	 * At this point, we know iSNS is enabled.
	 *
	 * If we've received an ESI request from the server recently
	 * (within MAX_ESI_INTERVALS * the max interval length),
	 * no need to continue.
	 */

	if (svr->svr_registered == B_TRUE) {
		if (ddi_get_lbolt() < (svr->svr_last_msg +
		    drv_usectohz(isns_esi_max_interval * 1000000 *
		    MAX_ESI_INTERVALS))) {
			return (0);
		}
	} else {
		/*
		 * We're not registered... Try to register now.
		 */
		if ((rc = isnst_update_one_server(svr, NULL,
		    ISNS_REGISTER_ALL)) == 0) {
			isnst_set_server_status(svr, B_TRUE);
		}
	}

	return (rc);
}

static int
isnst_update_target(iscsit_tgt_t *target, isns_reg_type_t reg)
{
	iscsit_isns_svr_t	*svr;
	int			rc = 0, curr_rc;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());
	ASSERT(iscsit_global.global_isns_cfg.isns_state == B_TRUE);

	for (svr = list_head(&iscsit_global.global_isns_cfg.isns_svrs);
	    svr != NULL;
	    svr = list_next(&iscsit_global.global_isns_cfg.isns_svrs, svr)) {
		/*
		 * Only return success if they all succeed.  Let the caller
		 * deal with any failure.
		 */

		curr_rc = isnst_update_one_server(svr, target, reg);

		if (curr_rc == 0) {
			if (reg == ISNS_REGISTER_TARGET) {
				isnst_set_server_status(svr, B_TRUE);
			}
		} else if (rc == 0) {
			rc = curr_rc;
		}
	}

	return (rc);
}

static int
isnst_update_one_server(iscsit_isns_svr_t *svr, iscsit_tgt_t *target,
    isns_reg_type_t reg)
{
	int rc = 0;

	switch (reg) {
	case ISNS_DEREGISTER_TARGET:
		rc = isnst_deregister(svr, target->target_name);
		break;

	case ISNS_DEREGISTER_ALL:
		rc = isnst_deregister(svr, NULL);
		break;

	case ISNS_UPDATE_TARGET:
	case ISNS_REGISTER_TARGET:
		rc = isnst_register(svr, target, reg);
		break;

	case ISNS_REGISTER_ALL:
		rc = isnst_register(svr, NULL, reg);
		break;

	default:
		ASSERT(0);
		/* NOTREACHED */
	}

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
	 * Currently, we will attempt to retry for "Invalid Registration",
	 * "Source Unauthorized", or "Busy" errors.  Any other errors should
	 * be handled by the caller if necessary.
	 */

	switch (rsp_status_code) {
	case ISNS_RSP_INVALID_REGIS:
	case ISNS_RSP_SRC_UNAUTHORIZED:
	case ISNS_RSP_BUSY:
		retry = B_TRUE;
		break;
	default:
		retry = B_FALSE;
		break;
	}

	return (retry);
}

static int
isnst_register(iscsit_isns_svr_t *svr, iscsit_tgt_t *target,
    isns_reg_type_t regtype)
{
	struct sonode	*so;
	int		rc = 0;
	isns_pdu_t	*pdu, *rsp;
	size_t		pdu_size, rsp_size;
	isns_target_t	*itarget, tmptgt;
	boolean_t	retry_reg = B_TRUE;

	/*
	 * Registration is a tricky thing.  In order to keep things simple,
	 * we don't want to keep track of which targets are registered to
	 * which server.  We rely on the target state machine to tell us
	 * when a target is online or offline, which prompts us to either
	 * register or deregister that target.
	 *
	 * When iscsit_isns_init is called, get a list of targets.  Those that
	 * are online will need to be registered.  In this case, target
	 * will be NULL.
	 *
	 * What this means is that if svr_registered == B_FALSE, that's
	 * when we'll register the network entity as well.
	 */

	if ((avl_numnodes(&isns_target_list) == 0) && (target == NULL)) {
		return (0);
	}

	/*
	 * If the target is already registered and we're not doing an
	 * update registration, just return.
	 */

	if (target != NULL) {
		tmptgt.target = target;
		itarget = avl_find(&isns_target_list, &tmptgt, NULL);
		ASSERT(itarget);
		if ((itarget->target_registered == B_TRUE) &&
		    (regtype != ISNS_UPDATE_TARGET)) {
			return (0);
		}
	}

	isnst_esi_check();

	/* create TCP connection to the isns server */
	so = isnst_open_so(&svr->svr_sa);

	if (so == NULL) {
		isnst_set_server_status(svr, B_FALSE);
		return (-1);
	}

	while (retry_reg) {
		pdu_size = isnst_make_reg_pdu(&pdu, target, svr->svr_registered,
		    regtype);
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

		rc = isnst_verify_rsp(pdu, rsp);

		/*
		 * If we got a registration error, the server may be out of
		 * sync.  In this case, we may re-try the registration as
		 * a "target update", which causes us to re-register everything.
		 */

		if ((retry_reg = isnst_retry_registration(rc)) == B_TRUE) {
			if (regtype == ISNS_UPDATE_TARGET) {
				/*
				 * If registration failed on an update, there
				 * is something terribly wrong, possibly with
				 * the server.
				 */
				rc = -1;
				retry_reg = B_FALSE;
				isnst_set_server_status(svr, B_FALSE);
			} else {
				regtype = ISNS_UPDATE_TARGET;
			}
		}

		kmem_free(pdu, pdu_size);
		kmem_free(rsp, rsp_size);
	}

	isnst_close_so(so);

	/*
	 * If it succeeded, mark all registered targets as such
	 */
	if (rc == 0) {
		if ((target != NULL) && (regtype != ISNS_UPDATE_TARGET)) {
			/* itarget initialized above */
			itarget->target_registered = B_TRUE;
		} else {
			itarget = avl_first(&isns_target_list);
			while (itarget) {
				itarget->target_registered = B_TRUE;
				itarget = AVL_NEXT(&isns_target_list, itarget);
			}
		}
	}

	return (rc);
}

static isns_portal_list_t *
isns_lookup_portal(struct sockaddr_storage *p)
{
	isns_portal_list_t *portal;

	portal = list_head(&portal_list);

	while (portal != NULL) {
		if (bcmp(p, &portal->portal_addr,
		    sizeof (struct sockaddr_storage)) == 0) {
			return (portal);
		}
		portal = list_next(&portal_list, portal);
	}

	return (NULL);
}

static void
isns_remove_portal(isns_portal_list_t *p)
{
	list_remove(&portal_list, p);
	kmem_free(p, sizeof (isns_portal_list_t));
	portal_list_count--;
}

static isns_target_t *
isnst_add_to_target_list(iscsit_tgt_t *target)
{
	isns_target_t *itarget, tmptgt;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	/*
	 * Make sure this target isn't already in our list.  If it is,
	 * perhaps it has just moved from offline to online.
	 */

	tmptgt.target = target;
	if ((itarget = (isns_target_t *)avl_find(&isns_target_list,
	    &tmptgt, NULL)) == NULL) {
		itarget = kmem_zalloc(sizeof (isns_target_t), KM_NOSLEEP);

		/*
		 * If we can't get memory, we're not going to be able to
		 * register this target.  This needs to be fixed up.
		 */
		if (itarget == NULL)
			return (NULL);

		itarget->target = target;
		avl_add(&isns_target_list, itarget);
	}

	return (itarget);
}

static int
isnst_add_default_portal_attrs(isns_pdu_t *pdu, size_t pdu_size)
{
	isns_portal_list_t	*portal;
	struct sockaddr_in	*in;
	struct sockaddr_in6	*in6;
	int			idx = 0;
	uint32_t		attr_data;
	void			*inaddrp;

	portal = list_head(&portal_list);

	while (portal) {
		if (idx == nondefault_portals) {
			break;
		}

		if (portal->portal_iscsit == NULL) {
			in = (struct sockaddr_in *)&portal->portal_addr;

			if (in->sin_family == AF_INET) {
				attr_data = sizeof (in_addr_t);
				inaddrp = (void *)&in->sin_addr;
			} else if (in->sin_family == AF_INET6) {
				in6 = (struct sockaddr_in6 *)
				    &portal->portal_addr;
				attr_data = sizeof (in6_addr_t);
				inaddrp = (void *)&in6->sin6_addr;
			} else {
				return (-1);
			}

			if (isnst_add_attr(pdu, pdu_size,
			    ISNS_PG_PORTAL_IP_ADDR_ATTR_ID, 16, inaddrp,
			    attr_data) != 0) {
				return (-1);
			}

			/* Portal Group Portal Port */
			if (isnst_add_attr(pdu, pdu_size,
			    ISNS_PG_PORTAL_PORT_ATTR_ID, 4, 0,
			    ntohs(in->sin_port)) != 0) {
				return (-1);
			}

			idx++;
		}

		portal = list_next(&portal_list, portal);
	}

	return (0);
}

static size_t
isnst_make_reg_pdu(isns_pdu_t **pdu, iscsit_tgt_t *target,
    boolean_t svr_registered, isns_reg_type_t regtype)
{
	size_t			pdu_size;
	iscsit_tpgt_t		*tpgt;
	iscsit_tpg_t		*tpg;
	iscsit_portal_t		*tp;
	char			*str;
	int			len;
	isns_portal_list_t	*portal;
	isns_esi_tinfo_t	*tinfop;
	isns_target_t		*itarget;
	iscsit_tgt_t		*src;
	boolean_t		reg_all = B_FALSE;
	uint16_t		flags = 0;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	/*
	 * Find a source attribute for this registration.
	 *
	 * If we're already registered, registering for the first time, or
	 * updating a target, we'll use the target_name of the first target
	 * in our list.
	 *
	 * The alternate case is that we're registering for the first time,
	 * but target is non-NULL.  In that case, we have no targets in our
	 * list yet, so we use the passed in target's name.
	 */

	if (svr_registered || (target == NULL) ||
	    (regtype == ISNS_UPDATE_TARGET)) {
		ASSERT(avl_numnodes(&isns_target_list) != 0);
		itarget = (isns_target_t *)avl_first(&isns_target_list);
		src = itarget->target;
	} else {
		src = target;
	}

	/*
	 * No target means we're registering everything.  A regtype of
	 * ISNS_UPDATE_TARGET means we're re-registering everything.
	 * Whether we're registering or re-registering depends on if
	 * we're already registered.
	 */

	if ((target == NULL) || (regtype == ISNS_UPDATE_TARGET)) {
		reg_all = B_TRUE;
		target = src;	/* This will be the 1st tgt in our list */

		/*
		 * If we're already registered, this will be a replacement
		 * registration.  In this case, we need to make sure our
		 * source attribute is an already registered target.
		 */
		if (svr_registered) {
			flags = ISNS_FLAG_REPLACE_REG;
			while (itarget->target_registered == B_FALSE) {
				itarget = AVL_NEXT(&isns_target_list,
				    itarget);
			}
			src = itarget->target;
			/* Reset itarget to the beginning of our list */
			itarget = (isns_target_t *)avl_first(&isns_target_list);
		}
	}

	pdu_size = isnst_create_pdu_header(ISNS_DEV_ATTR_REG, pdu, flags);
	if (pdu_size == 0) {
		return (0);
	}

	len = strlen(src->target_name) + 1;
	if (isnst_add_attr(*pdu, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
	    len, src->target_name, 0) != 0) {
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
	if (isnst_add_attr(*pdu, pdu_size, ISNS_ENTITY_PROTOCOL_ATTR_ID,
	    4, 0, ISNS_ENTITY_PROTOCOL_ISCSI) != 0) {
		goto pdu_error;
	}

	/*
	 * Network entity portal information - only on the first registration.
	 */

	if (svr_registered == B_FALSE) {
		struct sockaddr_in *sin;
		int addrsize;

		portal = list_head(&portal_list);

		while (portal != NULL) {
			sin = (struct sockaddr_in *)&portal->portal_addr;
			tinfop = portal->portal_esi;

			if (portal->portal_iscsit == NULL) {
				if (sin->sin_family == AF_INET) {
					addrsize = sizeof (struct in_addr);
				} else {
					addrsize = sizeof (struct in6_addr);
				}

				/* Portal IP Address */
				if (isnst_add_attr(*pdu, pdu_size,
				    ISNS_PORTAL_IP_ADDR_ATTR_ID, 16,
				    &sin->sin_addr, addrsize) != 0) {
					goto pdu_error;
				}

				/* Portal Port */
				if (isnst_add_attr(*pdu, pdu_size,
				    ISNS_PORTAL_PORT_ATTR_ID, 4, 0,
				    ntohs(sin->sin_port)) != 0) {
					goto pdu_error;
				}

				if (tinfop && tinfop->esi_port) {
					/* ESI interval and port */
					if (isnst_add_attr(*pdu, pdu_size,
					    ISNS_ESI_INTERVAL_ATTR_ID, 4,
					    NULL, 20) != 0) {
						goto pdu_error;
					}

					if (isnst_add_attr(*pdu, pdu_size,
					    ISNS_ESI_PORT_ATTR_ID, 4, NULL,
					    tinfop->esi_port) != 0) {
						goto pdu_error;
					}
				}
			}

			portal = list_next(&portal_list, portal);
		}
	}

	do {
		/* Hold the target mutex */
		mutex_enter(&target->target_mutex);

		/* iSCSI Name - Section 6.4.1 */
		str = target->target_name;
		len = strlen(str) + 1;
		if (isnst_add_attr(*pdu, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
		    len, str, 0) != 0) {
			mutex_exit(&target->target_mutex);
			goto pdu_error;
		}

		/* iSCSI Node Type */
		if (isnst_add_attr(*pdu, pdu_size,
		    ISNS_ISCSI_NODE_TYPE_ATTR_ID, 4, 0,
		    ISNS_TARGET_NODE_TYPE) != 0) {
			mutex_exit(&target->target_mutex);
			goto pdu_error;
		}

		/* iSCSI Alias */
#if 0
		str = target->target_alias;
#else
		str = "Solaris iSCSI Target";
#endif
		if (str != NULL) {
			len = strlen(str) + 1;
			if (isnst_add_attr(*pdu, pdu_size,
			    ISNS_ISCSI_ALIAS_ATTR_ID, len, str, 0) != 0) {
				mutex_exit(&target->target_mutex);
				goto pdu_error;
			}
		}

		/* for each target portal group (start)... */
		tpgt = avl_first(&target->target_tpgt_list);
		ASSERT(tpgt != NULL);
		do {
			/* no need to explicitly register default PG */
			if ((tpgt->tpgt_tag == ISCSIT_DEFAULT_TPGT) &&
			    (avl_numnodes(&target->target_tpgt_list) == 1)) {
				tpgt = AVL_NEXT(&target->target_tpgt_list,
				    tpgt);
				continue;
			}

			tpg = tpgt->tpgt_tpg;
			mutex_enter(&tpg->tpg_mutex);

			tp = avl_first(&tpg->tpg_portal_list);

			/* Portal Group Tag */
			if (isnst_add_attr(*pdu, pdu_size,
			    ISNS_PG_TAG_ATTR_ID, 4, 0, tpgt->tpgt_tag) != 0) {
				mutex_exit(&tpg->tpg_mutex);
				mutex_exit(&target->target_mutex);
				goto pdu_error;
			}

			ASSERT(tp != NULL);
			do {
				struct sockaddr_storage	*ss;
				struct sockaddr_in	*in;
				struct sockaddr_in6	*in6;
				uint32_t attr_numeric_data;
				void *inaddrp;

				ss = &tp->portal_addr;
				in = (struct sockaddr_in *)ss;
				in6 = (struct sockaddr_in6 *)ss;

				if (ss->ss_family == AF_INET) {
					attr_numeric_data = sizeof (in_addr_t);
					inaddrp = (void *)&in->sin_addr;
				} else if (ss->ss_family == AF_INET6) {
					attr_numeric_data = sizeof (in6_addr_t);
					inaddrp = (void *)&in6->sin6_addr;
				} else if (ss->ss_family == 0) {
					/*
					 * Need to add all default portals
					 */
					attr_numeric_data = 0;
				} else {
					cmn_err(CE_WARN, "Unknown address "
					    "family for portal %p", (void *)tp);
					mutex_exit(&tpg->tpg_mutex);
					mutex_exit(&target->target_mutex);
					goto pdu_error;
				}

				if (attr_numeric_data == 0) {
					if (isnst_add_default_portal_attrs(*pdu,
					    pdu_size) != 0) {
						mutex_exit(&tpg->tpg_mutex);
						mutex_exit(&target->
						    target_mutex);
						goto pdu_error;
					}
				} else {
					/* Portal Group Portal IP Address */
					if (isnst_add_attr(*pdu, pdu_size,
					    ISNS_PG_PORTAL_IP_ADDR_ATTR_ID, 16,
					    inaddrp, attr_numeric_data) != 0) {
						mutex_exit(&tpg->tpg_mutex);
						mutex_exit(&target->
						    target_mutex);
						goto pdu_error;
					}

					/* Portal Group Portal Port */
					if (isnst_add_attr(*pdu, pdu_size,
					    ISNS_PG_PORTAL_PORT_ATTR_ID,
					    4, 0, ntohs(in->sin_port)) != 0) {
						mutex_exit(&tpg->tpg_mutex);
						mutex_exit(&target->
						    target_mutex);
						goto pdu_error;
					}
				}

				tp = AVL_NEXT(&tpg->tpg_portal_list, tp);
			} while (tp != NULL);

			mutex_exit(&tpg->tpg_mutex);
			tpgt = AVL_NEXT(&target->target_tpgt_list, tpgt);
		} while (tpgt != NULL);
		/* for each target portal group (end)... */

		mutex_exit(&target->target_mutex);

		if (reg_all) {
			itarget = AVL_NEXT(&isns_target_list, itarget);
			if (itarget) {
				target = itarget->target;
			} else {
				target = NULL;
			}
		}
	} while ((reg_all == B_TRUE) && (target != NULL));

	return (pdu_size);

pdu_error:
	/* packet too large, no memory */
	kmem_free(*pdu, pdu_size);
	*pdu = NULL;

	return (0);
}

static int
isnst_deregister(iscsit_isns_svr_t *svr, char *node)
{
	int		rc;
	isns_pdu_t	*pdu, *rsp;
	size_t		pdu_size, rsp_size;
	struct sonode	*so;

	if ((svr->svr_registered == B_FALSE) ||
	    (avl_numnodes(&isns_target_list) == 0)) {
		return (0);
	}

	so = isnst_open_so(&svr->svr_sa);

	if (so == NULL) {
		return (-1);
	}

	pdu_size = isnst_make_dereg_pdu(&pdu, node);
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

	rc = isnst_verify_rsp(pdu, rsp);

	isnst_close_so(so);
	kmem_free(pdu, pdu_size);
	kmem_free(rsp, rsp_size);

	return (rc);
}

static size_t
isnst_make_dereg_pdu(isns_pdu_t **pdu, char *node)
{
	size_t		pdu_size;
	int		len;
	isns_target_t	*itarget;
	iscsit_tgt_t	*target;
	int		num_targets;

	/*
	 * create DevDereg Message with all of target nodes
	 */
	pdu_size = isnst_create_pdu_header(ISNS_DEV_DEREG, pdu, 0);
	if (pdu_size == 0) {
		return (0);
	}

	/*
	 * Source attribute - Must be a storage node in the same
	 * network entity.  We'll just grab the first one in the list.
	 * If it's the only online target, we turn this into a total
	 * deregistration regardless of the value of "node".
	 */

	num_targets = avl_numnodes(&isns_target_list);
	itarget = avl_first(&isns_target_list);
	target = itarget->target;

	len = strlen(target->target_name) + 1;
	if (isnst_add_attr(*pdu, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
	    len, target->target_name, 0) != 0) {
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
	if ((node == NULL) || (num_targets == 1)) {
		/* dereg everything */
		len = strlen(isns_eid) + 1;
		if (isnst_add_attr(*pdu, pdu_size, ISNS_EID_ATTR_ID,
		    len, isns_eid, 0) != 0) {
			goto dereg_pdu_error;
		}
	} else {
		/* dereg one target only */
		len = strlen(node) + 1;
		if (isnst_add_attr(*pdu, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
		    len, node, 0) != 0) {
			goto dereg_pdu_error;
		}
	}

	return (pdu_size);

dereg_pdu_error:
	kmem_free(*pdu, pdu_size);
	*pdu = NULL;

	return (0);
}

static int
isnst_verify_rsp(isns_pdu_t *pdu, isns_pdu_t *rsp)
{
	uint16_t	func_id;
	uint16_t	payload_len, rsp_payload_len;
	isns_resp_t	*resp;
	uint8_t		*pp;
	isns_tlv_t	*attr;
	uint32_t	attr_len, attr_id, esi_interval;

	/* validate response function id */
	func_id = ntohs(rsp->func_id);
	switch (ntohs(pdu->func_id)) {
	case ISNS_DEV_ATTR_REG:
		if (func_id != ISNS_DEV_ATTR_REG_RSP) {
			return (-1);
		}

		/*
		 * Get the ESI interval returned by the server.  It could
		 * be different than what we asked for.  We never know which
		 * portal a request may come in on, and any server could demand
		 * any interval. We'll simply keep track of the largest interval
		 * for use in monitoring.
		 */

		rsp_payload_len = isnst_pdu_get_op(rsp, &pp);
		attr = (isns_tlv_t *)((void *)pp);

		while (rsp_payload_len) {
			attr_len = ntohl(attr->attr_len);
			attr_id = ntohl(attr->attr_id);

			if (attr_id == ISNS_ESI_INTERVAL_ATTR_ID) {
				esi_interval =
				    ntohl(*((uint32_t *)
				    ((void *)(&attr->attr_value))));

				if (esi_interval > isns_esi_max_interval)
					isns_esi_max_interval = esi_interval;

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
	default:
		ASSERT(0);
		break;
	}

	/* verify response transaction id */
	if (ntohs(rsp->xid) != ntohs(pdu->xid)) {
		return (-1);
	}

	/* check the error code */
	payload_len = ntohs(rsp->payload_len);
	resp = (isns_resp_t *)((void *)&rsp->payload[0]);
	if (payload_len < 4) {
		return (-1);
	}

	return (ntohl(resp->status));
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
	ASSERT(payload_len >= 4);
	payload_len -= 4;
	payload = &resp->data[0];

	while (payload_len >= 8) {
		attr = (isns_tlv_t *)((void *)payload);
		tlv_len = 8 + ntohl(attr->attr_len);
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
	size_t	pdu_size = ISNSP_MAX_PDU_SIZE;

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
		    drv_usectohz(ISNS_RCV_TIMER_SECONDS * 1000000));
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

	*pdu = NULL;
	total_pdu_len = total_payload_len = 0;
	payload = NULL;
	seq = 0;

	do {
		/* receive the pdu header */
		rcv_timer = timeout(isnst_so_timeout, so,
		    drv_usectohz(ISNS_RCV_TIMER_SECONDS * 1000000));
		if (idm_sorecv(so, &tmp_pdu_hdr, ISNSP_HEADER_SIZE) != 0 ||
		    ntohs(tmp_pdu_hdr.seq) != seq) {
			(void) untimeout(rcv_timer);
			goto rcv_error;
		}
		(void) untimeout(rcv_timer);

		/* receive the payload */
		payload_len = ntohs(tmp_pdu_hdr.payload_len);
		payload = kmem_alloc(payload_len, KM_SLEEP);
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
			*pdu = kmem_alloc(total_pdu_len, KM_SLEEP);
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

	/* determin local IP address */
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
		if (ksocket_connect(so, (struct sockaddr *)sa, sa_sz, CRED())
		    != 0) {
			/* not calling isnst_close_so() to */
			/* make dtrace output look clear */
			idm_soshutdown(so);
			idm_sodestroy(so);
			so = NULL;
		}
	}

	if (so == NULL) {
		struct sockaddr_in *sin;
		struct sockaddr_in6 *sin6;
		char s[INET6_ADDRSTRLEN];
		void *ip;
		uint16_t port;
		sin = (struct sockaddr_in *)sa;
		port = ntohs(sin->sin_port);
		if (sa->ss_family == AF_INET) {
			ip = (void *)&sin->sin_addr.s_addr;
			(void) inet_ntop(AF_INET, ip, s, sizeof (s));
		} else {
			sin6 = (struct sockaddr_in6 *)sa;
			ip = (void *)&sin6->sin6_addr.s6_addr;
			(void) inet_ntop(AF_INET6, ip, s, sizeof (s));
		}
		cmn_err(CE_WARN, "open iSNS Server %s:%u failed", s, port);
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
isnst_esi_start_thread(isns_esi_tinfo_t *tinfop)
{
	tinfop->esi_thread_running = B_FALSE;
	tinfop->esi_thread_failed = B_FALSE;
	tinfop->esi_registered = B_FALSE;
	tinfop->esi_thread = thread_create(NULL, 0, isnst_esi_thread,
	    (void *)tinfop, 0, &p0, TS_RUN, minclsyspri);

	mutex_enter(&isns_esi_mutex);
	list_insert_tail(&esi_list, tinfop);

	/*
	 * Wait for the thread to start
	 */

	while (!tinfop->esi_thread_running && !tinfop->esi_thread_failed) {
		cv_wait(&isns_esi_cv, &isns_esi_mutex);
	}

	mutex_exit(&isns_esi_mutex);
}

static void
isnst_esi_start(isns_portal_list_t *portal)
{
	isns_esi_tinfo_t	*tinfop;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	/*
	 * Allocate our ESI thread info structure
	 */

	tinfop = (isns_esi_tinfo_t *)
	    kmem_zalloc(sizeof (isns_esi_tinfo_t), KM_NOSLEEP);

	if (tinfop == NULL) {
		cmn_err(CE_WARN, "isnst_esi_start: Cant alloc ESI");
		return;
	}

	tinfop->esi_portal = portal;
	portal->portal_esi = tinfop;
	isnst_esi_start_thread(tinfop);
}

/*
 * isnst_esi_check
 *
 * Verify that all the ESI threads are running and try to restart any that
 * failed for any reason.
 */

static void
isnst_esi_check()
{
	isns_portal_list_t	*portal;
	isns_esi_tinfo_t	*tinfop;

	/*
	 * Now, threads for new portals or those which stopped for some other
	 * reason will be started.
	 */

	portal = list_head(&portal_list);

	while (portal) {
		tinfop = portal->portal_esi;

		if (tinfop && (!tinfop->esi_thread_running ||
		    tinfop->esi_thread_failed)) {
			isnst_esi_start_thread(tinfop);
		}

		portal = list_next(&portal_list, portal);
	}
}

/*
 * isnst_esi_thread
 *
 * This function listens on a socket for incoming connections from an
 * iSNS server until told to stop.
 */

static void
isnst_esi_thread(void *arg)
{
	isns_esi_tinfo_t	*tinfop;
	ksocket_t		newso;
	struct sockaddr_in	sin;
	struct sockaddr_in6	sin6;
	uint32_t		on;
	int			rc;
	isns_pdu_t		*pdu;
	size_t			pl_size;
	int			family;
	struct sockaddr_in	t_addr;
	struct sockaddr_in6	t_addr6;
	socklen_t		t_addrlen;
	socklen_t		t_addrlen6;

	bzero(&t_addr, sizeof (struct sockaddr_in6));
	t_addrlen = sizeof (struct sockaddr_in);
	t_addrlen6 = sizeof (struct sockaddr_in6);

	tinfop = (isns_esi_tinfo_t *)arg;
	tinfop->esi_thread_did = curthread->t_did;

	/*
	 * Create a socket to listen for requests from the iSNS server.
	 */

	if (tinfop->esi_portal->portal_addr.ss_family == AF_INET) {
		family = AF_INET;
	} else {
		family = AF_INET6;
	}

	if ((tinfop->esi_so =
	    idm_socreate(family, SOCK_STREAM, 0)) == NULL) {
		cmn_err(CE_WARN,
		    "isnst_esi_thread: Unable to create socket");
		tinfop->esi_thread_failed = B_TRUE;
		mutex_enter(&isns_esi_mutex);
		cv_signal(&isns_esi_cv);
		mutex_exit(&isns_esi_mutex);
		thread_exit();
	}
	ksocket_hold(tinfop->esi_so);
	/*
	 * Set options, bind, and listen until we're told to stop
	 */

	switch (family) {
	case AF_INET:
		bzero(&sin, sizeof (sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(0);
		bcopy(((caddr_t)&tinfop->esi_portal->portal_addr +
		    offsetof(struct sockaddr_in, sin_addr)),
		    &sin.sin_addr.s_addr, sizeof (in_addr_t));
		on = 1;

		(void) ksocket_setsockopt(tinfop->esi_so, SOL_SOCKET,
		    SO_REUSEADDR, (char *)&on, sizeof (on), CRED());

		if (ksocket_bind(tinfop->esi_so, (struct sockaddr *)&sin,
		    sizeof (sin), CRED()) != 0) {
			idm_sodestroy(tinfop->esi_so);
			tinfop->esi_so = NULL;
			tinfop->esi_thread_failed = B_TRUE;
		} else {
			(void) ksocket_getsockname(tinfop->esi_so,
			    (struct sockaddr *)(&t_addr), &t_addrlen, CRED());
			tinfop->esi_port = ntohs(((struct sockaddr_in *)
			    (&t_addr))->sin_port);
		}

		break;

	case AF_INET6:
		bzero(&sin6, sizeof (sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = htons(0);
		bcopy(((caddr_t)&tinfop->esi_portal->portal_addr +
		    offsetof(struct sockaddr_in6, sin6_addr)),
		    &sin6.sin6_addr.s6_addr, sizeof (in6_addr_t));
		on = 1;

		(void) ksocket_setsockopt(tinfop->esi_so, SOL_SOCKET,
		    SO_REUSEADDR, (char *)&on, sizeof (on), CRED());

		if (ksocket_bind(tinfop->esi_so, (struct sockaddr *)&sin6,
		    sizeof (sin6), CRED()) != 0) {
			idm_sodestroy(tinfop->esi_so);
			tinfop->esi_so = NULL;
			tinfop->esi_thread_failed = B_TRUE;
		} else {
			(void) ksocket_getsockname(tinfop->esi_so,
			    (struct sockaddr *)(&t_addr6), &t_addrlen6, CRED());
			tinfop->esi_port = ntohs(((struct sockaddr_in6 *)
			    (&t_addr6))->sin6_port);
		}

		break;
	}

	if (tinfop->esi_thread_failed) {
		cmn_err(CE_WARN, "Unable to bind socket for ESI");
		goto esi_thread_exit;
	}

	if ((rc = ksocket_listen(tinfop->esi_so, 5, CRED())) != 0) {
		cmn_err(CE_WARN, "isnst_esi_thread: listen failure 0x%x", rc);
		goto esi_thread_exit;
	}

	mutex_enter(&isns_esi_mutex);
	/*
	 * Mark the thread as running and the portal as no longer new.
	 */
	tinfop->esi_thread_running = B_TRUE;
	cv_signal(&isns_esi_cv);

	while (tinfop->esi_thread_running && !tinfop->esi_thread_failed) {
		mutex_exit(&isns_esi_mutex);

		DTRACE_PROBE2(iscsit__isns__esi__accept__wait,
		    boolean_t, tinfop->esi_thread_running,
		    boolean_t, tinfop->esi_thread_failed);
		if ((rc = ksocket_accept(tinfop->esi_so, NULL, NULL,
		    &newso, CRED())) != 0) {
			mutex_enter(&isns_esi_mutex);
			DTRACE_PROBE2(iscsit__isns__esi__accept__fail,
			    boolean_t, tinfop->esi_thread_running,
			    boolean_t, tinfop->esi_thread_failed);
			/*
			 * If we were interrupted with EINTR
			 * it's not really a failure.
			 */
			if (rc != EINTR) {
				cmn_err(CE_WARN, "isnst_esi_thread: "
				    "accept failure (0x%x)", rc);
				tinfop->esi_thread_failed = B_TRUE;
			}
			tinfop->esi_thread_running = B_FALSE;
			continue;
		}
		DTRACE_PROBE3(iscsit__isns__esi__accept,
		    boolean_t, tinfop->esi_thread_running,
		    boolean_t, tinfop->esi_thread_failed,
		    struct sonode *, newso);

		mutex_enter(&isns_esi_mutex);

		pl_size = isnst_rcv_pdu(newso, &pdu);

		if (pl_size == 0) {
			cmn_err(CE_WARN, "isnst_esi_thread: rcv_pdu failure");
			tinfop->esi_thread_failed = B_TRUE;
			continue;
		}

		if (isnst_handle_esi_req(newso, pdu, pl_size) == B_TRUE) {
			tinfop->esi_registered = B_TRUE;
		}

		(void) ksocket_close(newso, CRED());

		/*
		 * Do not hold the esi mutex during server timestamp
		 * update.  It requires the isns global lock, which may
		 * be held during other functions that also require
		 * the esi_mutex (potential deadlock).
		 */
		mutex_exit(&isns_esi_mutex);
		isnst_update_server_timestamp(newso);
		mutex_enter(&isns_esi_mutex);
	}
	mutex_exit(&isns_esi_mutex);
esi_thread_exit:
	ksocket_rele(tinfop->esi_so);
	thread_exit();
}

/*
 * Handle an incoming ESI request
 */

static boolean_t
isnst_handle_esi_req(ksocket_t ks, isns_pdu_t *pdu, size_t pl_size)
{
	isns_pdu_t	*rsp_pdu;
	isns_resp_t	*rsp;
	size_t		pl_len, rsp_size;
	boolean_t	esirv = B_TRUE;

	if (ntohs(pdu->func_id) != ISNS_ESI) {
		cmn_err(CE_WARN, "isnst_handle_esi_req: Unexpected func 0x%x",
		    pdu->func_id);
		kmem_free(pdu, pl_size);
		return (B_FALSE);
	}

	pl_len = ntohs(pdu->payload_len) + 4 /* ISNS_STATUS_SZ */;

	if (pl_len > ISNSP_MAX_PAYLOAD_SIZE) {
		cmn_err(CE_WARN, "isnst_handle_esi_req: PDU payload too large "
		    " (%ld bytes)", pl_len);
		kmem_free(pdu, pl_size);
		return (B_FALSE);
	}

	rsp_size = isnst_create_pdu_header(ISNS_ESI_RSP, &rsp_pdu, 0);

	if (rsp_size == 0) {
		cmn_err(CE_WARN, "isnst_handle_esi_req: Can't get rsp pdu");
		kmem_free(pdu, pl_size);
		return (B_FALSE);
	}

	rsp = (isns_resp_t *)((void *)(&rsp_pdu->payload[0]));

	/* Use xid from the request pdu */
	rsp_pdu->xid = pdu->xid;
	rsp->status = htonl(ISNS_RSP_SUCCESSFUL);

	/* Copy original data */
	bcopy(pdu->payload, rsp->data, pl_len - 4);
	rsp_pdu->payload_len = htons(pl_len);

	if (isnst_send_pdu(ks, rsp_pdu) != 0) {
		cmn_err(CE_WARN, "isnst_handle_esi_req: Send response failed");
		esirv = B_FALSE;
	}

	kmem_free(rsp_pdu, rsp_size);
	kmem_free(pdu, pl_size);

	return (esirv);
}

int
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
isnst_get_target_list(void)
{
	iscsit_tgt_t	*tgt, *next_tgt;

	/*
	 * Initialize our list of targets with those from the global
	 * list that are online.
	 */

	for (tgt = avl_first(&iscsit_global.global_target_list); tgt != NULL;
	    tgt = next_tgt) {
		next_tgt = AVL_NEXT(&iscsit_global.global_target_list, tgt);
		if (tgt->target_state == TS_STMF_ONLINE) {
			(void) isnst_add_to_target_list(tgt);
		}
	}
}

static void
isnst_set_server_status(iscsit_isns_svr_t *svr, boolean_t registered)
{
	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	if (registered == B_TRUE) {
		svr->svr_registered = B_TRUE;
		svr->svr_last_msg = ddi_get_lbolt();
	} else {
		svr->svr_registered = B_FALSE;
	}
}

static void
isnst_add_default_portals()
{
	idm_addr_list_t		*default_portal_list;
	idm_addr_t		*dportal;
	isns_portal_list_t	*portal;
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	uint32_t		dpl_size, idx;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	dpl_size = idm_get_ipaddr(&default_portal_list);

	if (dpl_size == 0) {
		cmn_err(CE_WARN, "isnst_add_default_portals: "
		    "No default portals");
		return;
	}

	for (idx = 0; idx < default_portal_list->al_out_cnt; idx++) {
		dportal = &default_portal_list->al_addrs[idx];

		if (dportal->a_addr.i_insize == 0) {
			continue;
		}

		portal = kmem_zalloc(sizeof (isns_portal_list_t), KM_SLEEP);
		portal->portal_iscsit = NULL;	/* Default portal */

		if (dportal->a_addr.i_insize == sizeof (struct in_addr)) {
			sin = (struct sockaddr_in *)&portal->portal_addr;
			sin->sin_family = AF_INET;
			sin->sin_port = htons(ISCSI_LISTEN_PORT);
			sin->sin_addr = dportal->a_addr.i_addr.in4;
		} else {
			sin6 = (struct sockaddr_in6 *)&portal->portal_addr;
			sin->sin_family = AF_INET6;
			sin6->sin6_port = htons(ISCSI_LISTEN_PORT);
			sin6->sin6_addr = dportal->a_addr.i_addr.in6;
		}

		list_insert_tail(&portal_list, portal);
		isnst_esi_start(portal);
	}

	kmem_free(default_portal_list, dpl_size);
}

static void
isnst_remove_default_portals()
{
	isns_portal_list_t	*portal, *next;

	ASSERT(ISNS_GLOBAL_LOCK_HELD());

	portal = list_head(&portal_list);

	while (portal) {
		next = list_next(&portal_list, portal);

		if (portal->portal_iscsit == NULL) {
			mutex_enter(&isns_esi_mutex);
			isnst_esi_stop_thread(portal->portal_esi);
			mutex_exit(&isns_esi_mutex);
			isns_remove_portal(portal);
		}

		portal = next;
	}
}

/*
 * These functions are called by iscsit proper when a portal comes online
 * or goes offline.
 */

void
iscsit_isns_portal_online(iscsit_portal_t *portal)
{
	isns_portal_list_t	*iportal, *new_portal;
	struct sockaddr_in	*sin;

	ISNS_GLOBAL_LOCK();

	iportal = isns_lookup_portal(&portal->portal_addr);
	sin = (struct sockaddr_in *)&portal->portal_addr;

	/*
	 * If sin_family is 0, it's a "default" portal.  It's possible
	 * sin_family may be non-zero, so check portal_iscsit.  If it's NULL,
	 * it's a default portal as well.
	 */

	if ((sin->sin_family == 0) ||
	    (iportal && (iportal->portal_iscsit == NULL))) {
		ISNS_GLOBAL_UNLOCK();
		return;
	}

	ASSERT(iportal == NULL);

	new_portal = kmem_zalloc(sizeof (isns_portal_list_t), KM_SLEEP);
	new_portal->portal_addr = portal->portal_addr;
	sin = (struct sockaddr_in *)&new_portal->portal_addr;
	new_portal->portal_iscsit = portal;
	list_insert_tail(&portal_list, new_portal);
	portal_list_count++;
	nondefault_portals++;

	ISNS_GLOBAL_UNLOCK();
}

void
iscsit_isns_portal_offline(iscsit_portal_t *portal)
{
	isns_portal_list_t	*iportal = NULL;
	struct sockaddr_in	*sin;
	boolean_t		default_portals = B_FALSE;

	ISNS_GLOBAL_LOCK();

	/*
	 * Stop the ESI thread for this portal
	 */

	iportal = isns_lookup_portal(&portal->portal_addr);
	sin = (struct sockaddr_in *)&portal->portal_addr;

	if ((sin->sin_family == 0) ||
	    (iportal && (iportal->portal_iscsit == NULL))) {
		default_portals = B_TRUE;
	} else {
		iportal = isns_lookup_portal(&portal->portal_addr);
		ASSERT(iportal);
	}

	if (!default_portals) {
		isns_remove_portal(iportal);
		nondefault_portals--;
	}

	ISNS_GLOBAL_UNLOCK();
}
