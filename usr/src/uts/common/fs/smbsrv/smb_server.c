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
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * General Structures Layout
 * -------------------------
 *
 * This is a simplified diagram showing the relationship between most of the
 * main structures.
 *
 * +-------------------+
 * |     SMB_SERVER    |
 * +-------------------+
 *          |
 *          |
 *          v
 * +-------------------+       +-------------------+      +-------------------+
 * |     SESSION       |<----->|     SESSION       |......|      SESSION      |
 * +-------------------+       +-------------------+      +-------------------+
 *          |
 *          |
 *          v
 * +-------------------+       +-------------------+      +-------------------+
 * |       USER        |<----->|       USER        |......|       USER        |
 * +-------------------+       +-------------------+      +-------------------+
 *          |
 *          |
 *          v
 * +-------------------+       +-------------------+      +-------------------+
 * |       TREE        |<----->|       TREE        |......|       TREE        |
 * +-------------------+       +-------------------+      +-------------------+
 *      |         |
 *      |         |
 *      |         v
 *      |     +-------+       +-------+      +-------+
 *      |     | OFILE |<----->| OFILE |......| OFILE |
 *      |     +-------+       +-------+      +-------+
 *      |
 *      |
 *      v
 *  +-------+       +------+      +------+
 *  | ODIR  |<----->| ODIR |......| ODIR |
 *  +-------+       +------+      +------+
 *
 *
 * Module Interface Overview
 * -------------------------
 *
 *
 *	    +===================================+
 *	    |		 smbd daemon		|
 *	    +===================================+
 *	      |		     |		      ^
 *	      |		     |		      |
 * User	      |		     |		      |
 * -----------|--------------|----------------|--------------------------------
 * Kernel     |		     |		      |
 *            |		     |		      |
 *	      |		     |		      |
 *  +=========|==============|================|=================+
 *  |	      v		     v		      |			|
 *  | +-----------+ +--------------------+ +------------------+ |
 *  | |     IO    | | Kernel Door Server | | User Door Servers|	|
 *  | | Interface | |     Interface      | |   Interface      | |
 *  | +-----------+ +--------------------+ +------------------+ |
 *  |		|	     |		      ^		^	|
 *  |		v	     v		      |		|	|    +=========+
 *  |	     +-----------------------------------+	|	|    |	       |
 *  |	     + SMB Server Management (this file) |<------------------|	 ZFS   |
 *  |	     +-----------------------------------+	|	|    |	       |
 *  |							|	|    |  Module |
 *  |	     +-----------------------------------+	|	|    |	       |
 *  |	     +     SMB Server Internal Layers    |------+	|    +=========+
 *  |	     +-----------------------------------+		|
 *  |								|
 *  |								|
 *  +===========================================================+
 *
 *
 * Server State Machine
 * --------------------
 *                                  |
 *                                  | T0
 *                                  |
 *                                  v
 *                    +-----------------------------+
 *		      |   SMB_SERVER_STATE_CREATED  |
 *		      +-----------------------------+
 *				    |
 *				    | T1
 *				    |
 *				    v
 *		      +-----------------------------+
 *		      | SMB_SERVER_STATE_CONFIGURED |
 *		      +-----------------------------+
 *				    |
 *				    | T2
 *				    |
 *				    v
 *		      +-----------------------------+
 *		      |  SMB_SERVER_STATE_RUNNING / |
 *		      |  SMB_SERVER_STATE_STOPPING  |
 *		      +-----------------------------+
 *				    |
 *				    | T3
 *				    |
 *				    v
 *		      +-----------------------------+
 *		      |  SMB_SERVER_STATE_DELETING  |
 *                    +-----------------------------+
 *				    |
 *				    |
 *				    |
 *				    v
 *
 * States
 * ------
 *
 * SMB_SERVER_STATE_CREATED
 *
 *    This is the state of the server just after creation.
 *
 * SMB_SERVER_STATE_CONFIGURED
 *
 *    The server has been configured.
 *
 * SMB_SERVER_STATE_RUNNING
 *
 *    The server has been started. While in this state the threads listening on
 *    the sockets are started.
 *
 *    When a client establishes a connection the thread listening dispatches
 *    a task with the new session as an argument. If the dispatch fails the new
 *    session context is destroyed.
 *
 * SMB_SERVER_STATE_STOPPING
 *
 *    The threads listening on the NBT and TCP sockets are being terminated.
 *
 *
 * Transitions
 * -----------
 *
 * Transition T0
 *
 *    The daemon smbd triggers its creation by opening the smbsrv device. If
 *    the zone where the daemon lives doesn't have an smb server yet it is
 *    created.
 *
 *		smb_drv_open() --> smb_server_create()
 *
 * Transition T1
 *
 *    This transition occurs in smb_server_configure(). It is triggered by the
 *    daemon through an Ioctl.
 *
 *	smb_drv_ioctl(SMB_IOC_CONFIG) --> smb_server_configure()
 *
 * Transition T2
 *
 *    This transition occurs in smb_server_start(). It is triggered by the
 *    daemon through an Ioctl.
 *
 *	smb_drv_ioctl(SMB_IOC_START) --> smb_server_start()
 *
 * Transition T3
 *
 *    This transition occurs in smb_server_delete(). It is triggered by the
 *    daemon when closing the smbsrv device
 *
 *		smb_drv_close() --> smb_server_delete()
 *
 * Comments
 * --------
 *
 * This files assumes that there will one SMB server per zone. For now the
 * smb server works only in global zone. There's nothing in this file preventing
 * an smb server from being created in a non global zone. That limitation is
 * enforced in user space.
 */

#include <sys/strsubr.h>
#include <sys/cmn_err.h>
#include <sys/priv.h>
#include <sys/socketvar.h>
#include <sys/zone.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/string.h>
#include <smbsrv/netbios.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smb_share.h>
#include <smbsrv/smb_door.h>
#include <smbsrv/smb_kstat.h>

extern void smb_reply_notify_change_request(smb_request_t *);

typedef struct {
	smb_listener_daemon_t	*ra_listener;
	smb_session_t		*ra_session;
} smb_receiver_arg_t;

static void smb_server_kstat_init(smb_server_t *);
static void smb_server_kstat_fini(smb_server_t *);
static void smb_server_timers(smb_thread_t *, void *);
int smb_server_lookup(smb_server_t **);
void smb_server_release(smb_server_t *);
static void smb_server_store_cfg(smb_server_t *, smb_ioc_cfg_t *);
static void smb_server_shutdown(smb_server_t *);
static int smb_server_fsop_start(smb_server_t *);
static void smb_server_fsop_stop(smb_server_t *);
static void smb_event_cancel(smb_server_t *, uint32_t);
static uint32_t smb_event_alloc_txid(void);

static void smb_server_disconnect_share(smb_llist_t *, const char *);
static void smb_server_enum_users(smb_llist_t *, smb_svcenum_t *);
static void smb_server_enum_trees(smb_llist_t *, smb_svcenum_t *);
static int smb_server_session_disconnect(smb_llist_t *, const char *,
    const char *);
static int smb_server_fclose(smb_llist_t *, uint32_t);
static int smb_server_kstat_update(kstat_t *, int);
static int smb_server_legacy_kstat_update(kstat_t *, int);
static void smb_server_listener_init(smb_server_t *, smb_listener_daemon_t *,
    char *, in_port_t, int);
static void smb_server_listener_destroy(smb_listener_daemon_t *);
static int smb_server_listener_start(smb_listener_daemon_t *);
static void smb_server_listener_stop(smb_listener_daemon_t *);
static void smb_server_listener(smb_thread_t *, void *);
static void smb_server_receiver(void *);
static void smb_server_create_session(smb_listener_daemon_t *, ksocket_t);
static void smb_server_destroy_session(smb_listener_daemon_t *,
    smb_session_t *);
static uint16_t smb_spool_get_fid(smb_server_t *);
static boolean_t smb_spool_lookup_doc_byfid(smb_server_t *, uint16_t,
    smb_kspooldoc_t *);

int smb_event_debug = 0;

static smb_llist_t	smb_servers;

/*
 * *****************************************************************************
 * **************** Functions called from the device interface *****************
 * *****************************************************************************
 *
 * These functions typically have to determine the relevant smb server
 * to which the call applies.
 */

/*
 * smb_server_svc_init
 *
 * This function must be called from smb_drv_attach().
 */
int
smb_server_svc_init(void)
{
	int	rc = 0;

	while (rc == 0) {
		if (rc = smb_mbc_init())
			continue;
		if (rc = smb_vop_init())
			continue;
		if (rc = smb_node_init())
			continue;
		if (rc = smb_oplock_init())
			continue;
		if (rc = smb_fem_init())
			continue;
		if (rc = smb_net_init())
			continue;
		smb_llist_init();
		smb_llist_constructor(&smb_servers, sizeof (smb_server_t),
		    offsetof(smb_server_t, sv_lnd));
		return (0);
	}

	smb_llist_fini();
	smb_net_fini();
	smb_fem_fini();
	smb_node_fini();
	smb_vop_fini();
	smb_mbc_fini();
	return (rc);
}

/*
 * smb_server_svc_fini
 *
 * This function must called from smb_drv_detach(). It will fail if servers
 * still exist.
 */
int
smb_server_svc_fini(void)
{
	int	rc = EBUSY;

	if (smb_llist_get_count(&smb_servers) == 0) {
		smb_llist_fini();
		smb_net_fini();
		smb_fem_fini();
		smb_node_fini();
		smb_oplock_fini();
		smb_vop_fini();
		smb_mbc_fini();
		smb_llist_destructor(&smb_servers);
		rc = 0;
	}
	return (rc);
}

/*
 * smb_server_create
 *
 * This function will fail if there's already a server associated with the
 * caller's zone.
 */
int
smb_server_create(void)
{
	zoneid_t	zid;
	smb_server_t	*sv;

	zid = getzoneid();

	smb_llist_enter(&smb_servers, RW_WRITER);
	sv = smb_llist_head(&smb_servers);
	while (sv) {
		SMB_SERVER_VALID(sv);
		if (sv->sv_zid == zid) {
			smb_llist_exit(&smb_servers);
			return (EPERM);
		}
		sv = smb_llist_next(&smb_servers, sv);
	}

	sv = kmem_zalloc(sizeof (smb_server_t), KM_NOSLEEP);
	if (sv == NULL) {
		smb_llist_exit(&smb_servers);
		return (ENOMEM);
	}

	smb_llist_constructor(&sv->sv_opipe_list, sizeof (smb_opipe_t),
	    offsetof(smb_opipe_t, p_lnd));

	smb_llist_constructor(&sv->sv_event_list, sizeof (smb_event_t),
	    offsetof(smb_event_t, se_lnd));

	smb_llist_constructor(&sv->sp_info.sp_list, sizeof (smb_kspooldoc_t),
	    offsetof(smb_kspooldoc_t, sd_lnd));

	smb_llist_constructor(&sv->sp_info.sp_fidlist,
	    sizeof (smb_spoolfid_t), offsetof(smb_spoolfid_t, sf_lnd));

	sv->si_cache_request = kmem_cache_create("smb_request_cache",
	    sizeof (smb_request_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
	sv->si_cache_session = kmem_cache_create("smb_session_cache",
	    sizeof (smb_session_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
	sv->si_cache_user = kmem_cache_create("smb_user_cache",
	    sizeof (smb_user_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
	sv->si_cache_tree = kmem_cache_create("smb_tree_cache",
	    sizeof (smb_tree_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
	sv->si_cache_ofile = kmem_cache_create("smb_ofile_cache",
	    sizeof (smb_ofile_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
	sv->si_cache_odir = kmem_cache_create("smb_odir_cache",
	    sizeof (smb_odir_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
	sv->si_cache_opipe = kmem_cache_create("smb_opipe_cache",
	    sizeof (smb_opipe_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
	sv->si_cache_event = kmem_cache_create("smb_event_cache",
	    sizeof (smb_event_t), 8, NULL, NULL, NULL, NULL, NULL, 0);

	smb_thread_init(&sv->si_thread_timers,
	    "smb_timers", smb_server_timers, sv);

	sv->sv_pid = curproc->p_pid;
	smb_srqueue_init(&sv->sv_srqueue);

	smb_kdoor_init();
	smb_opipe_door_init();
	smb_server_kstat_init(sv);

	mutex_init(&sv->sv_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sv->sv_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&sv->sp_info.sp_cv, NULL, CV_DEFAULT, NULL);

	sv->sv_state = SMB_SERVER_STATE_CREATED;
	sv->sv_magic = SMB_SERVER_MAGIC;
	sv->sv_zid = zid;

	smb_llist_insert_tail(&smb_servers, sv);
	smb_llist_exit(&smb_servers);

	smb_threshold_init(&sv->sv_ssetup_ct, SMB_SSETUP_CMD,
	    smb_ssetup_threshold, smb_ssetup_timeout);
	smb_threshold_init(&sv->sv_tcon_ct, SMB_TCON_CMD, smb_tcon_threshold,
	    smb_tcon_timeout);
	smb_threshold_init(&sv->sv_opipe_ct, SMB_OPIPE_CMD, smb_opipe_threshold,
	    smb_opipe_timeout);

	return (0);
}

/*
 * smb_server_delete
 *
 * This function will delete the server passed in. It will make sure that all
 * activity associated that server has ceased before destroying it.
 */
int
smb_server_delete(void)
{
	smb_server_t	*sv;
	int		rc;

	rc = smb_server_lookup(&sv);
	if (rc != 0)
		return (rc);

	smb_threshold_fini(&sv->sv_ssetup_ct);
	smb_threshold_fini(&sv->sv_tcon_ct);
	smb_threshold_fini(&sv->sv_opipe_ct);

	mutex_enter(&sv->sv_mutex);
	switch (sv->sv_state) {
	case SMB_SERVER_STATE_RUNNING:
		sv->sv_state = SMB_SERVER_STATE_STOPPING;
		mutex_exit(&sv->sv_mutex);
		smb_server_shutdown(sv);
		mutex_enter(&sv->sv_mutex);
		cv_broadcast(&sv->sp_info.sp_cv);
		sv->sv_state = SMB_SERVER_STATE_DELETING;
		break;
	case SMB_SERVER_STATE_STOPPING:
		sv->sv_state = SMB_SERVER_STATE_DELETING;
		break;
	case SMB_SERVER_STATE_CONFIGURED:
	case SMB_SERVER_STATE_CREATED:
		sv->sv_state = SMB_SERVER_STATE_DELETING;
		break;
	default:
		SMB_SERVER_STATE_VALID(sv->sv_state);
		mutex_exit(&sv->sv_mutex);
		smb_server_release(sv);
		return (ENOTTY);
	}

	ASSERT(sv->sv_state == SMB_SERVER_STATE_DELETING);

	sv->sv_refcnt--;
	while (sv->sv_refcnt)
		cv_wait(&sv->sv_cv, &sv->sv_mutex);

	mutex_exit(&sv->sv_mutex);

	smb_llist_enter(&smb_servers, RW_WRITER);
	smb_llist_remove(&smb_servers, sv);
	smb_llist_exit(&smb_servers);

	smb_server_listener_destroy(&sv->sv_nbt_daemon);
	smb_server_listener_destroy(&sv->sv_tcp_daemon);
	rw_destroy(&sv->sv_cfg_lock);
	smb_opipe_door_fini();
	smb_kdoor_fini();
	smb_server_kstat_fini(sv);
	smb_llist_destructor(&sv->sv_opipe_list);
	smb_llist_destructor(&sv->sv_event_list);

	kmem_cache_destroy(sv->si_cache_request);
	kmem_cache_destroy(sv->si_cache_session);
	kmem_cache_destroy(sv->si_cache_user);
	kmem_cache_destroy(sv->si_cache_tree);
	kmem_cache_destroy(sv->si_cache_ofile);
	kmem_cache_destroy(sv->si_cache_odir);
	kmem_cache_destroy(sv->si_cache_opipe);
	kmem_cache_destroy(sv->si_cache_event);

	smb_srqueue_destroy(&sv->sv_srqueue);

	smb_thread_destroy(&sv->si_thread_timers);
	mutex_destroy(&sv->sv_mutex);
	cv_destroy(&sv->sv_cv);
	sv->sv_magic = 0;
	kmem_free(sv, sizeof (smb_server_t));

	return (0);
}

/*
 * smb_server_configure
 */
int
smb_server_configure(smb_ioc_cfg_t *ioc)
{
	int		rc = 0;
	smb_server_t	*sv;

	rc = smb_server_lookup(&sv);
	if (rc)
		return (rc);

	mutex_enter(&sv->sv_mutex);
	switch (sv->sv_state) {
	case SMB_SERVER_STATE_CREATED:
		smb_server_store_cfg(sv, ioc);
		sv->sv_state = SMB_SERVER_STATE_CONFIGURED;
		break;

	case SMB_SERVER_STATE_CONFIGURED:
		smb_server_store_cfg(sv, ioc);
		break;

	case SMB_SERVER_STATE_RUNNING:
	case SMB_SERVER_STATE_STOPPING:
		rw_enter(&sv->sv_cfg_lock, RW_WRITER);
		smb_server_store_cfg(sv, ioc);
		rw_exit(&sv->sv_cfg_lock);
		break;

	default:
		SMB_SERVER_STATE_VALID(sv->sv_state);
		rc = EFAULT;
		break;
	}
	mutex_exit(&sv->sv_mutex);

	smb_server_release(sv);

	return (rc);
}

/*
 * smb_server_start
 */
int
smb_server_start(smb_ioc_start_t *ioc)
{
	int		rc = 0;
	int		family;
	smb_server_t	*sv;

	rc = smb_server_lookup(&sv);
	if (rc)
		return (rc);

	mutex_enter(&sv->sv_mutex);
	switch (sv->sv_state) {
	case SMB_SERVER_STATE_CONFIGURED:
		smb_codepage_init();

		sv->sv_worker_pool = taskq_create("smb_workers",
		    sv->sv_cfg.skc_maxworkers, SMB_WORKER_PRIORITY,
		    sv->sv_cfg.skc_maxworkers, INT_MAX,
		    TASKQ_DYNAMIC|TASKQ_PREPOPULATE);

		sv->sv_receiver_pool = taskq_create("smb_receivers",
		    sv->sv_cfg.skc_maxconnections, SMB_WORKER_PRIORITY,
		    sv->sv_cfg.skc_maxconnections, INT_MAX,
		    TASKQ_DYNAMIC);

		sv->sv_session = smb_session_create(NULL, 0, sv, 0);

		if (sv->sv_worker_pool == NULL || sv->sv_session == NULL) {
			rc = ENOMEM;
			break;
		}

		if (rc = smb_server_fsop_start(sv))
			break;
		ASSERT(sv->sv_lmshrd == NULL);
		sv->sv_lmshrd = smb_kshare_door_init(ioc->lmshrd);
		if (sv->sv_lmshrd == NULL)
			break;
		if (rc = smb_kdoor_open(ioc->udoor)) {
			cmn_err(CE_WARN, "Cannot open smbd door");
			break;
		}
		if (rc = smb_opipe_door_open(ioc->opipe)) {
			cmn_err(CE_WARN, "Cannot open opipe door");
			break;
		}
		if (rc = smb_thread_start(&sv->si_thread_timers))
			break;

		family = AF_INET;
		smb_server_listener_init(sv, &sv->sv_nbt_daemon,
		    "smb_nbt_listener", IPPORT_NETBIOS_SSN, family);
		if (sv->sv_cfg.skc_ipv6_enable)
			family = AF_INET6;
		smb_server_listener_init(sv, &sv->sv_tcp_daemon,
		    "smb_tcp_listener", IPPORT_SMB, family);
		rc = smb_server_listener_start(&sv->sv_nbt_daemon);
		if (rc != 0)
			break;
		rc = smb_server_listener_start(&sv->sv_tcp_daemon);
		if (rc != 0)
			break;

		sv->sv_state = SMB_SERVER_STATE_RUNNING;
		sv->sv_start_time = gethrtime();
		mutex_exit(&sv->sv_mutex);
		smb_server_release(sv);
		smb_export_start();
		return (0);
	default:
		SMB_SERVER_STATE_VALID(sv->sv_state);
		mutex_exit(&sv->sv_mutex);
		smb_server_release(sv);
		return (ENOTTY);
	}

	mutex_exit(&sv->sv_mutex);
	smb_server_shutdown(sv);
	smb_server_release(sv);
	return (rc);
}

/*
 * An smbd is shutting down.
 */
int
smb_server_stop(void)
{
	smb_server_t	*sv;
	int		rc;

	if ((rc = smb_server_lookup(&sv)) != 0)
		return (rc);

	mutex_enter(&sv->sv_mutex);
	switch (sv->sv_state) {
	case SMB_SERVER_STATE_RUNNING:
		sv->sv_state = SMB_SERVER_STATE_STOPPING;
		mutex_exit(&sv->sv_mutex);
		smb_server_shutdown(sv);
		mutex_enter(&sv->sv_mutex);
		cv_broadcast(&sv->sp_info.sp_cv);
		break;
	default:
		SMB_SERVER_STATE_VALID(sv->sv_state);
		break;
	}
	mutex_exit(&sv->sv_mutex);

	smb_server_release(sv);
	return (0);
}

boolean_t
smb_server_is_stopping(void)
{
	smb_server_t    *sv;
	boolean_t	status;

	if (smb_server_lookup(&sv) != 0)
		return (B_TRUE);

	SMB_SERVER_VALID(sv);

	mutex_enter(&sv->sv_mutex);

	switch (sv->sv_state) {
	case SMB_SERVER_STATE_STOPPING:
	case SMB_SERVER_STATE_DELETING:
		status = B_TRUE;
		break;
	default:
		status = B_FALSE;
		break;
	}

	mutex_exit(&sv->sv_mutex);
	smb_server_release(sv);
	return (status);
}

int
smb_server_cancel_event(uint32_t txid)
{
	smb_server_t	*sv;
	int		rc;

	if ((rc = smb_server_lookup(&sv)) == 0) {
		smb_event_cancel(sv, txid);
		smb_server_release(sv);
	}

	return (rc);
}

int
smb_server_notify_event(smb_ioc_event_t *ioc)
{
	smb_server_t	*sv;
	int		rc;

	if ((rc = smb_server_lookup(&sv)) == 0) {
		smb_event_notify(sv, ioc->txid);
		smb_server_release(sv);
	}

	return (rc);
}

/*
 * smb_server_spooldoc
 *
 * Waits for print file close broadcast.
 * Gets the head of the fid list,
 * then searches the spooldoc list and returns
 * this info via the ioctl to user land.
 *
 * rc - 0 success
 */

int
smb_server_spooldoc(smb_ioc_spooldoc_t *ioc)
{
	smb_server_t	*sv;
	int		rc;
	smb_kspooldoc_t *spdoc;
	uint16_t	fid;

	if ((rc = smb_server_lookup(&sv)) != 0)
		return (rc);

	if (sv->sv_cfg.skc_print_enable == 0) {
		rc = ENOTTY;
		goto out;
	}

	mutex_enter(&sv->sv_mutex);
	for (;;) {
		if (sv->sv_state != SMB_SERVER_STATE_RUNNING) {
			rc = ECANCELED;
			break;
		}
		if ((fid = smb_spool_get_fid(sv)) != 0) {
			rc = 0;
			break;
		}
		if (cv_wait_sig(&sv->sp_info.sp_cv, &sv->sv_mutex) == 0) {
			rc = EINTR;
			break;
		}
	}
	mutex_exit(&sv->sv_mutex);
	if (rc != 0)
		goto out;

	spdoc = kmem_zalloc(sizeof (*spdoc), KM_SLEEP);
	if (smb_spool_lookup_doc_byfid(sv, fid, spdoc)) {
		ioc->spool_num = spdoc->sd_spool_num;
		ioc->ipaddr = spdoc->sd_ipaddr;
		(void) strlcpy(ioc->path, spdoc->sd_path,
		    MAXPATHLEN);
		(void) strlcpy(ioc->username,
		    spdoc->sd_username, MAXNAMELEN);
	} else {
		/* Did not find that print job. */
		rc = EAGAIN;
	}
	kmem_free(spdoc, sizeof (*spdoc));

out:
	smb_server_release(sv);
	return (rc);
}

int
smb_server_set_gmtoff(smb_ioc_gmt_t *ioc)
{
	int		rc;
	smb_server_t	*sv;

	if ((rc = smb_server_lookup(&sv)) == 0) {
		sv->si_gmtoff = ioc->offset;
		smb_server_release(sv);
	}

	return (rc);
}

int
smb_server_numopen(smb_ioc_opennum_t *ioc)
{
	smb_server_t	*sv;
	int		rc;

	if ((rc = smb_server_lookup(&sv)) == 0) {
		ioc->open_users = sv->sv_users;
		ioc->open_trees = sv->sv_trees;
		ioc->open_files = sv->sv_files + sv->sv_pipes;
		smb_server_release(sv);
	}
	return (rc);
}

/*
 * Enumerate objects within the server.  The svcenum provides the
 * enumeration context, i.e. what the caller want to get back.
 */
int
smb_server_enum(smb_ioc_svcenum_t *ioc)
{
	smb_svcenum_t	*svcenum = &ioc->svcenum;
	smb_server_t	*sv;
	int		rc;

	if ((rc = smb_server_lookup(&sv)) != 0)
		return (rc);

	svcenum->se_bavail = svcenum->se_buflen;
	svcenum->se_bused = 0;
	svcenum->se_nitems = 0;

	switch (svcenum->se_type) {
	case SMB_SVCENUM_TYPE_USER:
		smb_server_enum_users(&sv->sv_nbt_daemon.ld_session_list,
		    svcenum);
		smb_server_enum_users(&sv->sv_tcp_daemon.ld_session_list,
		    svcenum);
		break;
	case SMB_SVCENUM_TYPE_TREE:
	case SMB_SVCENUM_TYPE_FILE:
		smb_server_enum_trees(&sv->sv_nbt_daemon.ld_session_list,
		    svcenum);
		smb_server_enum_trees(&sv->sv_tcp_daemon.ld_session_list,
		    svcenum);
		break;
	default:
		rc = EINVAL;
	}

	smb_server_release(sv);
	return (rc);
}

/*
 * Look for sessions to disconnect by client and user name.
 */
int
smb_server_session_close(smb_ioc_session_t *ioc)
{
	smb_llist_t	*ll;
	smb_server_t	*sv;
	int		nbt_cnt;
	int		tcp_cnt;
	int		rc;

	if ((rc = smb_server_lookup(&sv)) != 0)
		return (rc);

	ll = &sv->sv_nbt_daemon.ld_session_list;
	nbt_cnt = smb_server_session_disconnect(ll, ioc->client, ioc->username);

	ll = &sv->sv_tcp_daemon.ld_session_list;
	tcp_cnt = smb_server_session_disconnect(ll, ioc->client, ioc->username);

	smb_server_release(sv);

	if ((nbt_cnt == 0) && (tcp_cnt == 0))
		return (ENOENT);
	return (0);
}

/*
 * Close a file by uniqid.
 */
int
smb_server_file_close(smb_ioc_fileid_t *ioc)
{
	uint32_t	uniqid = ioc->uniqid;
	smb_llist_t	*ll;
	smb_server_t	*sv;
	int		rc;

	if ((rc = smb_server_lookup(&sv)) != 0)
		return (rc);

	ll = &sv->sv_nbt_daemon.ld_session_list;
	rc = smb_server_fclose(ll, uniqid);

	if (rc == ENOENT) {
		ll = &sv->sv_tcp_daemon.ld_session_list;
		rc = smb_server_fclose(ll, uniqid);
	}

	smb_server_release(sv);
	return (rc);
}

/*
 * These functions determine the relevant smb server to which the call apply.
 */

uint32_t
smb_server_get_session_count(void)
{
	smb_server_t	*sv;
	uint32_t	counter = 0;

	if (smb_server_lookup(&sv))
		return (0);

	counter = smb_llist_get_count(&sv->sv_nbt_daemon.ld_session_list);
	counter += smb_llist_get_count(&sv->sv_tcp_daemon.ld_session_list);

	smb_server_release(sv);

	return (counter);
}

/*
 * Gets the vnode of the specified share path.
 *
 * A hold on the returned vnode pointer is taken so the caller
 * must call VN_RELE.
 */
int
smb_server_sharevp(const char *shr_path, vnode_t **vp)
{
	smb_server_t	*sv;
	smb_request_t	*sr;
	smb_node_t	*fnode = NULL;
	smb_node_t	*dnode;
	char		last_comp[MAXNAMELEN];
	int		rc = 0;

	ASSERT(shr_path);

	if ((rc = smb_server_lookup(&sv)))
		return (rc);

	mutex_enter(&sv->sv_mutex);
	switch (sv->sv_state) {
	case SMB_SERVER_STATE_RUNNING:
		break;
	default:
		mutex_exit(&sv->sv_mutex);
		smb_server_release(sv);
		return (ENOTACTIVE);
	}
	mutex_exit(&sv->sv_mutex);

	if ((sr = smb_request_alloc(sv->sv_session, 0)) == NULL) {
		smb_server_release(sv);
		return (ENOMEM);
	}
	sr->user_cr = kcred;

	rc = smb_pathname_reduce(sr, sr->user_cr, shr_path,
	    NULL, NULL, &dnode, last_comp);

	if (rc == 0) {
		rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS,
		    sv->si_root_smb_node, dnode, last_comp, &fnode);
		smb_node_release(dnode);
	}

	smb_request_free(sr);
	smb_server_release(sv);

	if (rc != 0)
		return (rc);

	ASSERT(fnode->vp && fnode->vp->v_vfsp);

	VN_HOLD(fnode->vp);
	*vp = fnode->vp;

	smb_node_release(fnode);

	return (0);
}


/*
 * This is a special interface that will be utilized by ZFS to cause a share to
 * be added/removed.
 *
 * arg is either a lmshare_info_t or share_name from userspace.
 * It will need to be copied into the kernel.   It is lmshare_info_t
 * for add operations and share_name for delete operations.
 */
int
smb_server_share(void *arg, boolean_t add_share)
{
	smb_server_t	*sv;
	int		rc;

	if ((rc = smb_server_lookup(&sv)) == 0) {
		mutex_enter(&sv->sv_mutex);
		switch (sv->sv_state) {
		case SMB_SERVER_STATE_RUNNING:
			mutex_exit(&sv->sv_mutex);
			(void) smb_kshare_upcall(sv->sv_lmshrd, arg, add_share);
			break;
		default:
			mutex_exit(&sv->sv_mutex);
			break;
		}
		smb_server_release(sv);
	}

	return (rc);
}

int
smb_server_unshare(const char *sharename)
{
	smb_server_t	*sv;
	smb_llist_t	*ll;
	int		rc;

	if ((rc = smb_server_lookup(&sv)))
		return (rc);

	mutex_enter(&sv->sv_mutex);
	switch (sv->sv_state) {
	case SMB_SERVER_STATE_RUNNING:
	case SMB_SERVER_STATE_STOPPING:
		break;
	default:
		mutex_exit(&sv->sv_mutex);
		smb_server_release(sv);
		return (ENOTACTIVE);
	}
	mutex_exit(&sv->sv_mutex);

	ll = &sv->sv_nbt_daemon.ld_session_list;
	smb_server_disconnect_share(ll, sharename);

	ll = &sv->sv_tcp_daemon.ld_session_list;
	smb_server_disconnect_share(ll, sharename);

	smb_server_release(sv);
	return (0);
}

/*
 * Disconnect the specified share.
 * Typically called when a share has been removed.
 */
static void
smb_server_disconnect_share(smb_llist_t *ll, const char *sharename)
{
	smb_session_t	*session;

	smb_llist_enter(ll, RW_READER);

	session = smb_llist_head(ll);
	while (session) {
		SMB_SESSION_VALID(session);
		smb_rwx_rwenter(&session->s_lock, RW_READER);
		switch (session->s_state) {
		case SMB_SESSION_STATE_NEGOTIATED:
		case SMB_SESSION_STATE_OPLOCK_BREAKING:
		case SMB_SESSION_STATE_WRITE_RAW_ACTIVE:
			smb_session_disconnect_share(session, sharename);
			break;
		default:
			break;
		}
		smb_rwx_rwexit(&session->s_lock);
		session = smb_llist_next(ll, session);
	}

	smb_llist_exit(ll);
}

/*
 * *****************************************************************************
 * **************** Functions called from the internal layers ******************
 * *****************************************************************************
 *
 * These functions are provided the relevant smb server by the caller.
 */

void
smb_server_get_cfg(smb_server_t *sv, smb_kmod_cfg_t *cfg)
{
	rw_enter(&sv->sv_cfg_lock, RW_READER);
	bcopy(&sv->sv_cfg, cfg, sizeof (*cfg));
	rw_exit(&sv->sv_cfg_lock);
}

/*
 *
 */
void
smb_server_inc_nbt_sess(smb_server_t *sv)
{
	SMB_SERVER_VALID(sv);
	atomic_inc_32(&sv->sv_nbt_sess);
}

void
smb_server_dec_nbt_sess(smb_server_t *sv)
{
	SMB_SERVER_VALID(sv);
	atomic_dec_32(&sv->sv_nbt_sess);
}

void
smb_server_inc_tcp_sess(smb_server_t *sv)
{
	SMB_SERVER_VALID(sv);
	atomic_inc_32(&sv->sv_tcp_sess);
}

void
smb_server_dec_tcp_sess(smb_server_t *sv)
{
	SMB_SERVER_VALID(sv);
	atomic_dec_32(&sv->sv_tcp_sess);
}

void
smb_server_inc_users(smb_server_t *sv)
{
	SMB_SERVER_VALID(sv);
	atomic_inc_32(&sv->sv_users);
}

void
smb_server_dec_users(smb_server_t *sv)
{
	SMB_SERVER_VALID(sv);
	atomic_dec_32(&sv->sv_users);
}

void
smb_server_inc_trees(smb_server_t *sv)
{
	SMB_SERVER_VALID(sv);
	atomic_inc_32(&sv->sv_trees);
}

void
smb_server_dec_trees(smb_server_t *sv)
{
	SMB_SERVER_VALID(sv);
	atomic_dec_32(&sv->sv_trees);
}

void
smb_server_inc_files(smb_server_t *sv)
{
	SMB_SERVER_VALID(sv);
	atomic_inc_32(&sv->sv_files);
}

void
smb_server_dec_files(smb_server_t *sv)
{
	SMB_SERVER_VALID(sv);
	atomic_dec_32(&sv->sv_files);
}

void
smb_server_inc_pipes(smb_server_t *sv)
{
	SMB_SERVER_VALID(sv);
	atomic_inc_32(&sv->sv_pipes);
}

void
smb_server_dec_pipes(smb_server_t *sv)
{
	SMB_SERVER_VALID(sv);
	atomic_dec_32(&sv->sv_pipes);
}

void
smb_server_add_rxb(smb_server_t *sv, int64_t value)
{
	SMB_SERVER_VALID(sv);
	atomic_add_64(&sv->sv_rxb, value);
}

void
smb_server_add_txb(smb_server_t *sv, int64_t value)
{
	SMB_SERVER_VALID(sv);
	atomic_add_64(&sv->sv_txb, value);
}

void
smb_server_inc_req(smb_server_t *sv)
{
	SMB_SERVER_VALID(sv);
	atomic_inc_64(&sv->sv_nreq);
}

/*
 * *****************************************************************************
 * *************************** Static Functions ********************************
 * *****************************************************************************
 */

static void
smb_server_timers(smb_thread_t *thread, void *arg)
{
	smb_server_t	*sv = (smb_server_t *)arg;

	ASSERT(sv != NULL);

	while (smb_thread_continue_timedwait(thread, 1 /* Seconds */)) {
		smb_session_timers(&sv->sv_nbt_daemon.ld_session_list);
		smb_session_timers(&sv->sv_tcp_daemon.ld_session_list);
	}
}

/*
 * smb_server_kstat_init
 */
static void
smb_server_kstat_init(smb_server_t *sv)
{
	char	name[KSTAT_STRLEN];

	sv->sv_ksp = kstat_create_zone(SMBSRV_KSTAT_MODULE, sv->sv_zid,
	    SMBSRV_KSTAT_STATISTICS, SMBSRV_KSTAT_CLASS, KSTAT_TYPE_RAW,
	    sizeof (smbsrv_kstats_t), 0, sv->sv_zid);

	if (sv->sv_ksp != NULL) {
		sv->sv_ksp->ks_update = smb_server_kstat_update;
		sv->sv_ksp->ks_private = sv;
		((smbsrv_kstats_t *)sv->sv_ksp->ks_data)->ks_start_time =
		    sv->sv_start_time;
		smb_dispatch_stats_init(
		    ((smbsrv_kstats_t *)sv->sv_ksp->ks_data)->ks_reqs);
		kstat_install(sv->sv_ksp);
	} else {
		cmn_err(CE_WARN, "SMB Server: Statistics unavailable");
	}

	(void) snprintf(name, sizeof (name), "%s%d",
	    SMBSRV_KSTAT_NAME, sv->sv_zid);

	sv->sv_legacy_ksp = kstat_create(SMBSRV_KSTAT_MODULE, sv->sv_zid,
	    name, SMBSRV_KSTAT_CLASS, KSTAT_TYPE_NAMED,
	    sizeof (smb_server_legacy_kstat_t) / sizeof (kstat_named_t), 0);

	if (sv->sv_legacy_ksp != NULL) {
		smb_server_legacy_kstat_t *ksd;

		ksd = sv->sv_legacy_ksp->ks_data;

		(void) strlcpy(ksd->ls_files.name, "open_files",
		    sizeof (ksd->ls_files.name));
		ksd->ls_files.data_type = KSTAT_DATA_UINT32;

		(void) strlcpy(ksd->ls_trees.name, "connections",
		    sizeof (ksd->ls_trees.name));
		ksd->ls_trees.data_type = KSTAT_DATA_UINT32;

		(void) strlcpy(ksd->ls_users.name, "connections",
		    sizeof (ksd->ls_users.name));
		ksd->ls_users.data_type = KSTAT_DATA_UINT32;

		mutex_init(&sv->sv_legacy_ksmtx, NULL, MUTEX_DEFAULT, NULL);
		sv->sv_legacy_ksp->ks_lock = &sv->sv_legacy_ksmtx;
		sv->sv_legacy_ksp->ks_update = smb_server_legacy_kstat_update;
		kstat_install(sv->sv_legacy_ksp);
	}
}

/*
 * smb_server_kstat_fini
 */
static void
smb_server_kstat_fini(smb_server_t *sv)
{
	if (sv->sv_legacy_ksp != NULL) {
		kstat_delete(sv->sv_legacy_ksp);
		mutex_destroy(&sv->sv_legacy_ksmtx);
		sv->sv_legacy_ksp = NULL;
	}

	if (sv->sv_ksp != NULL) {
		kstat_delete(sv->sv_ksp);
		sv->sv_ksp = NULL;
		smb_dispatch_stats_fini();
	}
}

/*
 * smb_server_kstat_update
 */
static int
smb_server_kstat_update(kstat_t *ksp, int rw)
{
	smb_server_t	*sv;
	smbsrv_kstats_t	*ksd;

	if (rw == KSTAT_READ) {
		sv = ksp->ks_private;
		SMB_SERVER_VALID(sv);
		ksd = (smbsrv_kstats_t *)ksp->ks_data;
		/*
		 * Counters
		 */
		ksd->ks_nbt_sess = sv->sv_nbt_sess;
		ksd->ks_tcp_sess = sv->sv_tcp_sess;
		ksd->ks_users = sv->sv_users;
		ksd->ks_trees = sv->sv_trees;
		ksd->ks_files = sv->sv_files;
		ksd->ks_pipes = sv->sv_pipes;
		/*
		 * Throughput
		 */
		ksd->ks_txb = sv->sv_txb;
		ksd->ks_rxb = sv->sv_rxb;
		ksd->ks_nreq = sv->sv_nreq;
		/*
		 * Busyness
		 */
		ksd->ks_maxreqs = sv->sv_cfg.skc_maxworkers;
		smb_srqueue_update(&sv->sv_srqueue,
		    &ksd->ks_utilization);
		/*
		 * Latency & Throughput of the requests
		 */
		smb_dispatch_stats_update(ksd->ks_reqs, 0, SMB_COM_NUM);
		return (0);
	}
	if (rw == KSTAT_WRITE)
		return (EACCES);

	return (EIO);
}

static int
smb_server_legacy_kstat_update(kstat_t *ksp, int rw)
{
	smb_server_t			*sv;
	smb_server_legacy_kstat_t	*ksd;
	int				rc;

	switch (rw) {
	case KSTAT_WRITE:
		rc = EACCES;
		break;
	case KSTAT_READ:
		if (!smb_server_lookup(&sv)) {
			ASSERT(MUTEX_HELD(ksp->ks_lock));
			ASSERT(sv->sv_legacy_ksp == ksp);
			ksd = (smb_server_legacy_kstat_t *)ksp->ks_data;
			ksd->ls_files.value.ui32 = sv->sv_files + sv->sv_pipes;
			ksd->ls_trees.value.ui32 = sv->sv_trees;
			ksd->ls_users.value.ui32 = sv->sv_users;
			smb_server_release(sv);
			rc = 0;
			break;
		}
		_NOTE(FALLTHRU)
	default:
		rc = EIO;
		break;
	}
	return (rc);

}

/*
 * smb_server_shutdown
 */
static void
smb_server_shutdown(smb_server_t *sv)
{
	SMB_SERVER_VALID(sv);

	smb_opipe_door_close();
	smb_thread_stop(&sv->si_thread_timers);
	smb_kdoor_close();
	smb_kshare_door_fini(sv->sv_lmshrd);
	sv->sv_lmshrd = NULL;
	smb_export_stop();
	smb_server_fsop_stop(sv);

	smb_server_listener_stop(&sv->sv_nbt_daemon);
	smb_server_listener_stop(&sv->sv_tcp_daemon);

	if (sv->sv_session != NULL) {
		/*
		 * smb_kshare_export may have a request on here.
		 * Normal sessions do this in smb_session_cancel()
		 * but this is a "fake" session used only for the
		 * requests used by the kshare thread(s).
		 */
		smb_slist_wait_for_empty(&sv->sv_session->s_req_list);

		smb_session_delete(sv->sv_session);
		sv->sv_session = NULL;
	}

	if (sv->sv_receiver_pool != NULL) {
		taskq_destroy(sv->sv_receiver_pool);
		sv->sv_receiver_pool = NULL;
	}

	if (sv->sv_worker_pool != NULL) {
		taskq_destroy(sv->sv_worker_pool);
		sv->sv_worker_pool = NULL;
	}
}

/*
 * smb_server_listener_init
 *
 * Initializes listener contexts.
 */
static void
smb_server_listener_init(
    smb_server_t		*sv,
    smb_listener_daemon_t	*ld,
    char			*name,
    in_port_t			port,
    int				family)
{
	ASSERT(ld->ld_magic != SMB_LISTENER_MAGIC);

	bzero(ld, sizeof (*ld));

	ld->ld_sv = sv;
	ld->ld_family = family;
	ld->ld_port = port;

	if (family == AF_INET) {
		ld->ld_sin.sin_family = (uint32_t)family;
		ld->ld_sin.sin_port = htons(port);
		ld->ld_sin.sin_addr.s_addr = htonl(INADDR_ANY);
	} else {
		ld->ld_sin6.sin6_family = (uint32_t)family;
		ld->ld_sin6.sin6_port = htons(port);
		(void) memset(&ld->ld_sin6.sin6_addr.s6_addr, 0,
		    sizeof (ld->ld_sin6.sin6_addr.s6_addr));
	}

	smb_llist_constructor(&ld->ld_session_list, sizeof (smb_session_t),
	    offsetof(smb_session_t, s_lnd));
	smb_thread_init(&ld->ld_thread, name, smb_server_listener, ld);
	ld->ld_magic = SMB_LISTENER_MAGIC;
}

/*
 * smb_server_listener_destroy
 *
 * Destroyes listener contexts.
 */
static void
smb_server_listener_destroy(smb_listener_daemon_t *ld)
{
	SMB_LISTENER_VALID(ld);
	ASSERT(ld->ld_so == NULL);
	smb_thread_destroy(&ld->ld_thread);
	smb_llist_destructor(&ld->ld_session_list);
	ld->ld_magic = 0;
}

/*
 * smb_server_listener_start
 *
 * Starts the listener associated with the context passed in.
 *
 * Return:	0	Success
 *		not 0	Failure
 */
static int
smb_server_listener_start(smb_listener_daemon_t *ld)
{
	int		rc;
	uint32_t	on;
	uint32_t	off;

	SMB_LISTENER_VALID(ld);

	if (ld->ld_so != NULL)
		return (EINVAL);

	ld->ld_so = smb_socreate(ld->ld_family, SOCK_STREAM, 0);
	if (ld->ld_so == NULL) {
		cmn_err(CE_WARN, "port %d: socket create failed", ld->ld_port);
		return (ENOMEM);
	}

	off = 0;
	(void) ksocket_setsockopt(ld->ld_so, SOL_SOCKET,
	    SO_MAC_EXEMPT, &off, sizeof (off), CRED());

	on = 1;
	(void) ksocket_setsockopt(ld->ld_so, SOL_SOCKET,
	    SO_REUSEADDR, &on, sizeof (on), CRED());

	if (ld->ld_family == AF_INET) {
		rc = ksocket_bind(ld->ld_so,
		    (struct sockaddr *)&ld->ld_sin,
		    sizeof (ld->ld_sin), CRED());
	} else {
		rc = ksocket_bind(ld->ld_so,
		    (struct sockaddr *)&ld->ld_sin6,
		    sizeof (ld->ld_sin6), CRED());
	}

	if (rc != 0) {
		cmn_err(CE_WARN, "port %d: bind failed", ld->ld_port);
		return (rc);
	}

	rc =  ksocket_listen(ld->ld_so, 20, CRED());
	if (rc < 0) {
		cmn_err(CE_WARN, "port %d: listen failed", ld->ld_port);
		return (rc);
	}

	ksocket_hold(ld->ld_so);
	rc = smb_thread_start(&ld->ld_thread);
	if (rc != 0) {
		ksocket_rele(ld->ld_so);
		cmn_err(CE_WARN, "port %d: listener failed to start",
		    ld->ld_port);
		return (rc);
	}
	return (0);
}

/*
 * smb_server_listener_stop
 *
 * Stops the listener associated with the context passed in.
 */
static void
smb_server_listener_stop(smb_listener_daemon_t *ld)
{
	SMB_LISTENER_VALID(ld);

	if (ld->ld_so != NULL) {
		smb_soshutdown(ld->ld_so);
		smb_sodestroy(ld->ld_so);
		smb_thread_stop(&ld->ld_thread);
		ld->ld_so = NULL;
	}
}

/*
 * smb_server_listener
 *
 * Entry point of the listeners.
 */
static void
smb_server_listener(smb_thread_t *thread, void *arg)
{
	_NOTE(ARGUNUSED(thread))
	smb_listener_daemon_t	*ld;
	smb_session_t		*session;
	ksocket_t		s_so;
	int			on;
	int			txbuf_size;

	ld = (smb_listener_daemon_t *)arg;

	SMB_LISTENER_VALID(ld);

	DTRACE_PROBE1(so__wait__accept, struct sonode *, ld->ld_so);

	while (ksocket_accept(ld->ld_so, NULL, NULL, &s_so, CRED())
	    == 0) {
		DTRACE_PROBE1(so__accept, struct sonode *, s_so);

		on = 1;
		(void) ksocket_setsockopt(s_so, IPPROTO_TCP, TCP_NODELAY,
		    &on, sizeof (on), CRED());

		on = 1;
		(void) ksocket_setsockopt(s_so, SOL_SOCKET, SO_KEEPALIVE,
		    &on, sizeof (on), CRED());

		txbuf_size = 128*1024;
		(void) ksocket_setsockopt(s_so, SOL_SOCKET, SO_SNDBUF,
		    (const void *)&txbuf_size, sizeof (txbuf_size), CRED());

		/*
		 * Create a session for this connection.
		 */
		smb_server_create_session(ld, s_so);
	}
	/* Disconnect all the sessions this listener created. */
	smb_llist_enter(&ld->ld_session_list, RW_READER);
	session = smb_llist_head(&ld->ld_session_list);
	while (session != NULL) {
		smb_session_disconnect(session);
		session = smb_llist_next(&ld->ld_session_list, session);
	}
	smb_llist_exit(&ld->ld_session_list);
	ksocket_rele(ld->ld_so);
}

/*
 * smb_server_receiver
 *
 * Entry point of the receiver threads.
 */
static void
smb_server_receiver(void *arg)
{
	smb_listener_daemon_t	*ld;
	smb_session_t		*session;

	ld = ((smb_receiver_arg_t *)arg)->ra_listener;
	session = ((smb_receiver_arg_t *)arg)->ra_session;
	smb_mem_free(arg);
	smb_session_receiver(session);
	smb_server_destroy_session(ld, session);
}

/*
 * smb_server_lookup
 *
 * This function tries to find the server associated with the zone of the
 * caller.
 */
int
smb_server_lookup(smb_server_t **psv)
{
	zoneid_t	zid;
	smb_server_t	*sv;

	zid = getzoneid();

	smb_llist_enter(&smb_servers, RW_READER);
	sv = smb_llist_head(&smb_servers);
	while (sv) {
		SMB_SERVER_VALID(sv);
		if (sv->sv_zid == zid) {
			mutex_enter(&sv->sv_mutex);
			if (sv->sv_state != SMB_SERVER_STATE_DELETING) {
				sv->sv_refcnt++;
				mutex_exit(&sv->sv_mutex);
				smb_llist_exit(&smb_servers);
				*psv = sv;
				return (0);
			}
			mutex_exit(&sv->sv_mutex);
			break;
		}
		sv = smb_llist_next(&smb_servers, sv);
	}
	smb_llist_exit(&smb_servers);
	return (EPERM);
}

/*
 * smb_server_release
 *
 * This function decrements the reference count of the server and signals its
 * condition variable if the state of the server is SMB_SERVER_STATE_DELETING.
 */
void
smb_server_release(smb_server_t *sv)
{
	SMB_SERVER_VALID(sv);

	mutex_enter(&sv->sv_mutex);
	ASSERT(sv->sv_refcnt);
	sv->sv_refcnt--;
	if ((sv->sv_refcnt == 0) && (sv->sv_state == SMB_SERVER_STATE_DELETING))
		cv_signal(&sv->sv_cv);
	mutex_exit(&sv->sv_mutex);
}

/*
 * Enumerate the users associated with a session list.
 */
static void
smb_server_enum_users(smb_llist_t *ll, smb_svcenum_t *svcenum)
{
	smb_session_t	*sn;
	smb_llist_t	*ulist;
	smb_user_t	*user;
	int		rc = 0;

	smb_llist_enter(ll, RW_READER);
	sn = smb_llist_head(ll);

	while (sn != NULL) {
		SMB_SESSION_VALID(sn);
		ulist = &sn->s_user_list;
		smb_llist_enter(ulist, RW_READER);
		user = smb_llist_head(ulist);

		while (user != NULL) {
			if (smb_user_hold(user)) {
				rc = smb_user_enum(user, svcenum);
				smb_user_release(user);
				if (rc != 0)
					break;
			}

			user = smb_llist_next(ulist, user);
		}

		smb_llist_exit(ulist);

		if (rc != 0)
			break;

		sn = smb_llist_next(ll, sn);
	}

	smb_llist_exit(ll);
}

/*
 * Enumerate the trees/files associated with a session list.
 */
static void
smb_server_enum_trees(smb_llist_t *ll, smb_svcenum_t *svcenum)
{
	smb_session_t	*sn;
	smb_llist_t	*tlist;
	smb_tree_t	*tree;
	int		rc = 0;

	smb_llist_enter(ll, RW_READER);
	sn = smb_llist_head(ll);

	while (sn != NULL) {
		SMB_SESSION_VALID(sn);
		tlist = &sn->s_tree_list;
		smb_llist_enter(tlist, RW_READER);
		tree = smb_llist_head(tlist);

		while (tree != NULL) {
			if (smb_tree_hold(tree)) {
				rc = smb_tree_enum(tree, svcenum);
				smb_tree_release(tree);
				if (rc != 0)
					break;
			}

			tree = smb_llist_next(tlist, tree);
		}

		smb_llist_exit(tlist);

		if (rc != 0)
			break;

		sn = smb_llist_next(ll, sn);
	}

	smb_llist_exit(ll);
}

/*
 * Disconnect sessions associated with the specified client and username.
 * Empty strings are treated as wildcards.
 */
static int
smb_server_session_disconnect(smb_llist_t *ll,
    const char *client, const char *name)
{
	smb_session_t	*sn;
	smb_llist_t	*ulist;
	smb_user_t	*user;
	boolean_t	match;
	int		count = 0;

	smb_llist_enter(ll, RW_READER);
	sn = smb_llist_head(ll);

	while (sn != NULL) {
		SMB_SESSION_VALID(sn);

		if ((*client != '\0') && (!smb_session_isclient(sn, client))) {
			sn = smb_llist_next(ll, sn);
			continue;
		}

		ulist = &sn->s_user_list;
		smb_llist_enter(ulist, RW_READER);
		user = smb_llist_head(ulist);

		while (user != NULL) {
			if (smb_user_hold(user)) {
				match = (*name == '\0');
				if (!match)
					match = smb_user_namecmp(user, name);

				if (match) {
					smb_llist_exit(ulist);
					smb_user_logoff(user);
					++count;
					smb_user_release(user);
					smb_llist_enter(ulist, RW_READER);
					user = smb_llist_head(ulist);
					continue;
				}

				smb_user_release(user);
			}

			user = smb_llist_next(ulist, user);
		}

		smb_llist_exit(ulist);
		sn = smb_llist_next(ll, sn);
	}

	smb_llist_exit(ll);
	return (count);
}

/*
 * Close a file by its unique id.
 */
static int
smb_server_fclose(smb_llist_t *ll, uint32_t uniqid)
{
	smb_session_t	*sn;
	smb_llist_t	*tlist;
	smb_tree_t	*tree;
	int		rc = ENOENT;

	smb_llist_enter(ll, RW_READER);
	sn = smb_llist_head(ll);

	while ((sn != NULL) && (rc == ENOENT)) {
		SMB_SESSION_VALID(sn);
		tlist = &sn->s_tree_list;
		smb_llist_enter(tlist, RW_READER);
		tree = smb_llist_head(tlist);

		while ((tree != NULL) && (rc == ENOENT)) {
			if (smb_tree_hold(tree)) {
				rc = smb_tree_fclose(tree, uniqid);
				smb_tree_release(tree);
			}

			tree = smb_llist_next(tlist, tree);
		}

		smb_llist_exit(tlist);
		sn = smb_llist_next(ll, sn);
	}

	smb_llist_exit(ll);
	return (rc);
}

static void
smb_server_store_cfg(smb_server_t *sv, smb_ioc_cfg_t *ioc)
{
	if (ioc->maxconnections == 0)
		ioc->maxconnections = 0xFFFFFFFF;

	smb_session_correct_keep_alive_values(
	    &sv->sv_nbt_daemon.ld_session_list, ioc->keepalive);
	smb_session_correct_keep_alive_values(
	    &sv->sv_tcp_daemon.ld_session_list, ioc->keepalive);

	sv->sv_cfg.skc_maxworkers = ioc->maxworkers;
	sv->sv_cfg.skc_maxconnections = ioc->maxconnections;
	sv->sv_cfg.skc_keepalive = ioc->keepalive;
	sv->sv_cfg.skc_restrict_anon = ioc->restrict_anon;
	sv->sv_cfg.skc_signing_enable = ioc->signing_enable;
	sv->sv_cfg.skc_signing_required = ioc->signing_required;
	sv->sv_cfg.skc_oplock_enable = ioc->oplock_enable;
	sv->sv_cfg.skc_sync_enable = ioc->sync_enable;
	sv->sv_cfg.skc_secmode = ioc->secmode;
	sv->sv_cfg.skc_ipv6_enable = ioc->ipv6_enable;
	sv->sv_cfg.skc_print_enable = ioc->print_enable;
	sv->sv_cfg.skc_traverse_mounts = ioc->traverse_mounts;
	sv->sv_cfg.skc_execflags = ioc->exec_flags;
	sv->sv_cfg.skc_version = ioc->version;
	(void) strlcpy(sv->sv_cfg.skc_nbdomain, ioc->nbdomain,
	    sizeof (sv->sv_cfg.skc_nbdomain));
	(void) strlcpy(sv->sv_cfg.skc_fqdn, ioc->fqdn,
	    sizeof (sv->sv_cfg.skc_fqdn));
	(void) strlcpy(sv->sv_cfg.skc_hostname, ioc->hostname,
	    sizeof (sv->sv_cfg.skc_hostname));
	(void) strlcpy(sv->sv_cfg.skc_system_comment, ioc->system_comment,
	    sizeof (sv->sv_cfg.skc_system_comment));

	if (sv->sv_cfg.skc_oplock_enable && smb_raw_mode) {
		/*
		 * Note that these two optional protocol features
		 * (oplocks, raw_mode) have unfortunate interactions.
		 * Since raw_mode is only wanted by ancient clients,
		 * we just turn it off (that's what MS recommends).
		 * Leave some evidence in the log if someone has
		 * patched smb_raw_mode to enable it.
		 */
		cmn_err(CE_NOTE,
		    "Raw mode enabled: Disabling opportunistic locks");
		sv->sv_cfg.skc_oplock_enable = 0;
	}
}

static int
smb_server_fsop_start(smb_server_t *sv)
{
	int	error;

	error = smb_node_root_init(rootdir, sv, &sv->si_root_smb_node);
	if (error != 0)
		sv->si_root_smb_node = NULL;

	return (error);
}

static void
smb_server_fsop_stop(smb_server_t *sv)
{
	if (sv->si_root_smb_node != NULL) {
		smb_node_release(sv->si_root_smb_node);
		sv->si_root_smb_node = NULL;
	}
}

smb_event_t *
smb_event_create(int timeout)
{
	smb_server_t	*sv;
	smb_event_t	*event;

	if (smb_server_is_stopping())
		return (NULL);

	if (smb_server_lookup(&sv) != 0) {
		cmn_err(CE_NOTE, "smb_event_create failed");
		return (NULL);
	}

	event = kmem_cache_alloc(sv->si_cache_event, KM_SLEEP);

	bzero(event, sizeof (smb_event_t));
	mutex_init(&event->se_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&event->se_cv, NULL, CV_DEFAULT, NULL);
	event->se_magic = SMB_EVENT_MAGIC;
	event->se_txid = smb_event_alloc_txid();
	event->se_server = sv;
	event->se_timeout = timeout;

	smb_llist_enter(&sv->sv_event_list, RW_WRITER);
	smb_llist_insert_tail(&sv->sv_event_list, event);
	smb_llist_exit(&sv->sv_event_list);

	smb_server_release(sv);
	return (event);
}

void
smb_event_destroy(smb_event_t *event)
{
	smb_server_t	*sv;

	if (event == NULL)
		return;

	SMB_EVENT_VALID(event);
	ASSERT(event->se_waittime == 0);

	if (smb_server_lookup(&sv) != 0)
		return;

	smb_llist_enter(&sv->sv_event_list, RW_WRITER);
	smb_llist_remove(&sv->sv_event_list, event);
	smb_llist_exit(&sv->sv_event_list);

	event->se_magic = (uint32_t)~SMB_EVENT_MAGIC;
	cv_destroy(&event->se_cv);
	mutex_destroy(&event->se_mutex);

	kmem_cache_free(sv->si_cache_event, event);
	smb_server_release(sv);
}

/*
 * Get the txid for the specified event.
 */
uint32_t
smb_event_txid(smb_event_t *event)
{
	if (event != NULL) {
		SMB_EVENT_VALID(event);
		return (event->se_txid);
	}

	cmn_err(CE_NOTE, "smb_event_txid failed");
	return ((uint32_t)-1);
}

/*
 * Wait for event notification.
 */
int
smb_event_wait(smb_event_t *event)
{
	int	seconds = 1;
	int	ticks;

	if (event == NULL)
		return (EINVAL);

	SMB_EVENT_VALID(event);

	mutex_enter(&event->se_mutex);
	event->se_waittime = 1;
	event->se_errno = 0;

	while (!(event->se_notified)) {
		if (smb_event_debug && ((event->se_waittime % 30) == 0))
			cmn_err(CE_NOTE, "smb_event_wait[%d] (%d sec)",
			    event->se_txid, event->se_waittime);

		if (event->se_errno != 0)
			break;

		if (event->se_waittime > event->se_timeout) {
			event->se_errno = ETIME;
			break;
		}

		ticks = SEC_TO_TICK(seconds);
		(void) cv_reltimedwait(&event->se_cv,
		    &event->se_mutex, (clock_t)ticks, TR_CLOCK_TICK);
		++event->se_waittime;
	}

	event->se_waittime = 0;
	event->se_notified = B_FALSE;
	cv_signal(&event->se_cv);
	mutex_exit(&event->se_mutex);
	return (event->se_errno);
}

/*
 * If txid is non-zero, cancel the specified event.
 * Otherwise, cancel all events.
 */
static void
smb_event_cancel(smb_server_t *sv, uint32_t txid)
{
	smb_event_t	*event;
	smb_llist_t	*event_list;

	SMB_SERVER_VALID(sv);

	event_list = &sv->sv_event_list;
	smb_llist_enter(event_list, RW_WRITER);

	event = smb_llist_head(event_list);
	while (event) {
		SMB_EVENT_VALID(event);

		if (txid == 0 || event->se_txid == txid) {
			mutex_enter(&event->se_mutex);
			event->se_errno = ECANCELED;
			event->se_notified = B_TRUE;
			cv_signal(&event->se_cv);
			mutex_exit(&event->se_mutex);

			if (txid != 0)
				break;
		}

		event = smb_llist_next(event_list, event);
	}

	smb_llist_exit(event_list);
}

/*
 * If txid is non-zero, notify the specified event.
 * Otherwise, notify all events.
 */
void
smb_event_notify(smb_server_t *sv, uint32_t txid)
{
	smb_event_t	*event;
	smb_llist_t	*event_list;

	SMB_SERVER_VALID(sv);

	event_list = &sv->sv_event_list;
	smb_llist_enter(event_list, RW_READER);

	event = smb_llist_head(event_list);
	while (event) {
		SMB_EVENT_VALID(event);

		if (txid == 0 || event->se_txid == txid) {
			mutex_enter(&event->se_mutex);
			event->se_notified = B_TRUE;
			cv_signal(&event->se_cv);
			mutex_exit(&event->se_mutex);

			if (txid != 0)
				break;
		}

		event = smb_llist_next(event_list, event);
	}

	smb_llist_exit(event_list);
}

/*
 * Allocate a new transaction id (txid).
 *
 * 0 or -1 are not assigned because they are used to detect invalid
 * conditions or to indicate all open id's.
 */
static uint32_t
smb_event_alloc_txid(void)
{
	static kmutex_t	txmutex;
	static uint32_t	txid;
	uint32_t	txid_ret;

	mutex_enter(&txmutex);

	if (txid == 0)
		txid = ddi_get_lbolt() << 11;

	do {
		++txid;
	} while (txid == 0 || txid == (uint32_t)-1);

	txid_ret = txid;
	mutex_exit(&txmutex);

	return (txid_ret);
}

/*
 * Called by the ioctl to find the corresponding
 * spooldoc node.  removes node on success
 *
 * Return values
 * rc
 * B_FALSE - not found
 * B_TRUE  - found
 *
 */

static boolean_t
smb_spool_lookup_doc_byfid(smb_server_t *sv, uint16_t fid,
    smb_kspooldoc_t *spdoc)
{
	smb_kspooldoc_t *sp;
	smb_llist_t	*splist;

	splist = &sv->sp_info.sp_list;
	smb_llist_enter(splist, RW_WRITER);
	sp = smb_llist_head(splist);
	while (sp != NULL) {
		/*
		 * check for a matching fid
		 */
		if (sp->sd_fid == fid) {
			*spdoc = *sp;
			smb_llist_remove(splist, sp);
			smb_llist_exit(splist);
			kmem_free(sp, sizeof (smb_kspooldoc_t));
			return (B_TRUE);
		}
		sp = smb_llist_next(splist, sp);
	}
	cmn_err(CE_WARN, "smb_spool_lookup_user_byfid: no fid:%d", fid);
	smb_llist_exit(splist);
	return (B_FALSE);
}

/*
 * Adds the spool fid to a linked list to be used
 * as a search key in the spooldoc queue
 *
 * Return values
 *      rc non-zero error
 *	rc zero success
 *
 */

void
smb_spool_add_fid(smb_server_t *sv, uint16_t fid)
{
	smb_llist_t	*fidlist;
	smb_spoolfid_t  *sf;

	if (sv->sv_cfg.skc_print_enable == 0)
		return;

	sf = kmem_zalloc(sizeof (smb_spoolfid_t), KM_SLEEP);
	fidlist = &sv->sp_info.sp_fidlist;
	smb_llist_enter(fidlist, RW_WRITER);
	sf->sf_fid = fid;
	smb_llist_insert_tail(fidlist, sf);
	smb_llist_exit(fidlist);
	cv_broadcast(&sv->sp_info.sp_cv);
}

/*
 * Called by the ioctl to get and remove the head of the fid list
 *
 * Return values
 * int fd
 * greater than 0 success
 * 0 - error
 *
 */

static uint16_t
smb_spool_get_fid(smb_server_t *sv)
{
	smb_spoolfid_t	*spfid;
	smb_llist_t	*splist;
	uint16_t	fid;

	splist = &sv->sp_info.sp_fidlist;
	smb_llist_enter(splist, RW_WRITER);
	spfid = smb_llist_head(splist);
	if (spfid != NULL) {
		fid = spfid->sf_fid;
		smb_llist_remove(&sv->sp_info.sp_fidlist, spfid);
		kmem_free(spfid, sizeof (smb_spoolfid_t));
	} else {
		fid = 0;
	}
	smb_llist_exit(splist);
	return (fid);
}

/*
 * Adds the spooldoc to the tail of the spooldoc list
 *
 * Return values
 *      rc non-zero error
 *	rc zero success
 */
int
smb_spool_add_doc(smb_kspooldoc_t *sp)
{
	smb_llist_t	*splist;
	smb_server_t	*sv;
	int rc = 0;

	rc = smb_server_lookup(&sv);
	if (rc)
		return (rc);

	splist = &sv->sp_info.sp_list;
	smb_llist_enter(splist, RW_WRITER);
	sp->sd_spool_num = atomic_inc_32_nv(&sv->sp_info.sp_cnt);
	smb_llist_insert_tail(splist, sp);
	smb_llist_exit(splist);
	smb_server_release(sv);
	return (rc);
}

/*
 * smb_server_create_session
 */
static void
smb_server_create_session(smb_listener_daemon_t *ld, ksocket_t s_so)
{
	smb_session_t		*session;
	smb_receiver_arg_t	*rarg;

	session = smb_session_create(s_so, ld->ld_port, ld->ld_sv,
	    ld->ld_family);

	if (session != NULL) {
		smb_llist_enter(&ld->ld_session_list, RW_WRITER);
		smb_llist_insert_tail(&ld->ld_session_list, session);
		smb_llist_exit(&ld->ld_session_list);

		rarg = (smb_receiver_arg_t *)smb_mem_alloc(
		    sizeof (smb_receiver_arg_t));
		rarg->ra_listener = ld;
		rarg->ra_session = session;

		if (taskq_dispatch(ld->ld_sv->sv_receiver_pool,
		    smb_server_receiver, rarg, TQ_NOQUEUE) != 0)
			return;

		smb_mem_free(rarg);
		smb_session_disconnect(session);
		smb_server_destroy_session(ld, session);
	} else {
		smb_soshutdown(s_so);
		smb_sodestroy(s_so);
	}
	cmn_err(CE_WARN, "SMB Session: creation failed");
}

static void
smb_server_destroy_session(smb_listener_daemon_t *ld, smb_session_t *session)
{
	smb_llist_enter(&ld->ld_session_list, RW_WRITER);
	smb_llist_remove(&ld->ld_session_list, session);
	smb_llist_exit(&ld->ld_session_list);
	smb_session_delete(session);
}
