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
 *    the sockets car be started. The smbd daemon does so through an Ioctl:
 *
 *	smb_drv_ioctl(SMB_IOC_NBT_LISTEN) --> smb_server_nbt_listen()
 *	smb_drv_ioctl(SMB_IOC_TCP_LISTEN) --> smb_server_nbt_listen()
 *
 *    When a client establishes a connection the thread listening leaves
 *    temporarily the kernel. While in user space it creates a thread for the
 *    new session. It then returns to kernel with the result of the thread
 *    creation. If the creation failed the new session context is destroyed
 *    before returning listening.
 *
 *    The new created thread enters the kernel though an Ioctl:
 *
 *	smb_drv_ioctl(SMB_IOC_NBT_RECEIVE) --> smb_server_nbt_receive()
 *	smb_drv_ioctl(SMB_IOC_TCP_RECEIVE) --> smb_server_tcp_receive()
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

#define	SMB_EVENT_TIMEOUT		45	/* seconds */

#define	SMB_REAPER_RATE_DEFAULT		4

extern void smb_dispatch_kstat_init(void);
extern void smb_dispatch_kstat_fini(void);
extern void smb_reply_notify_change_request(smb_request_t *);

static int smb_server_kstat_init(smb_server_t *);
static void smb_server_kstat_fini(smb_server_t *);
static int smb_server_kstat_update_info(kstat_t *, int);
static void smb_server_timers(smb_thread_t *, void *);
static int smb_server_listen(smb_server_t *, smb_listener_daemon_t *,
    in_port_t, int, int);
static void smb_server_listen_fini(smb_listener_daemon_t *);
static kt_did_t smb_server_listener_tid(smb_listener_daemon_t *);
static int smb_server_lookup(smb_server_t **);
static void smb_server_release(smb_server_t *);
static void smb_server_store_cfg(smb_server_t *, smb_ioc_cfg_t *);
static void smb_server_shutdown(smb_server_t *);
static int smb_server_fsop_start(smb_server_t *);
static void smb_server_fsop_stop(smb_server_t *);
static void smb_server_signal_listeners(smb_server_t *);
static void smb_event_cancel(smb_server_t *, uint32_t);
static void smb_event_notify(smb_server_t *, uint32_t);
static uint32_t smb_event_alloc_txid(void);

static void smb_server_disconnect_share(smb_session_list_t *, const char *);
static void smb_server_thread_unexport(smb_thread_t *, void *);
static void smb_server_enum_private(smb_session_list_t *, smb_svcenum_t *);
static int smb_server_sesion_disconnect(smb_session_list_t *, const char *,
    const char *);
static int smb_server_fclose(smb_session_list_t *, uint32_t);

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
		if (rc = smb_fem_init())
			continue;
		if (rc = smb_user_init())
			continue;
		if (rc = smb_notify_init())
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
	smb_notify_fini();
	smb_user_fini();
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
		smb_notify_fini();
		smb_user_fini();
		smb_fem_fini();
		smb_node_fini();
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

	smb_llist_constructor(&sv->sv_vfs_list, sizeof (smb_vfs_t),
	    offsetof(smb_vfs_t, sv_lnd));

	smb_llist_constructor(&sv->sv_opipe_list, sizeof (smb_opipe_t),
	    offsetof(smb_opipe_t, p_lnd));

	smb_llist_constructor(&sv->sv_event_list, sizeof (smb_event_t),
	    offsetof(smb_event_t, se_lnd));

	smb_slist_constructor(&sv->sv_unexport_list, sizeof (smb_unexport_t),
	    offsetof(smb_unexport_t, ux_lnd));

	smb_session_list_constructor(&sv->sv_nbt_daemon.ld_session_list);
	smb_session_list_constructor(&sv->sv_tcp_daemon.ld_session_list);

	sv->si_cache_unexport = kmem_cache_create("smb_unexport_cache",
	    sizeof (smb_unexport_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
	sv->si_cache_vfs = kmem_cache_create("smb_vfs_cache",
	    sizeof (smb_vfs_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
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
	    "smb_timers", smb_server_timers, sv,
	    NULL, NULL);

	smb_thread_init(&sv->si_thread_unexport, "smb_thread_unexport",
	    smb_server_thread_unexport, sv, NULL, NULL);

	sv->sv_pid = curproc->p_pid;

	smb_kdoor_init();
	smb_opipe_door_init();
	(void) smb_server_kstat_init(sv);

	mutex_init(&sv->sv_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sv->sv_cv, NULL, CV_DEFAULT, NULL);
	sv->sv_state = SMB_SERVER_STATE_CREATED;
	sv->sv_magic = SMB_SERVER_MAGIC;
	sv->sv_zid = zid;

	smb_llist_insert_tail(&smb_servers, sv);
	smb_llist_exit(&smb_servers);
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
	smb_unexport_t	*ux;
	kt_did_t	nbt_tid;
	kt_did_t	tcp_tid;
	int		rc;

	rc = smb_server_lookup(&sv);
	if (rc != 0)
		return (rc);

	mutex_enter(&sv->sv_mutex);
	switch (sv->sv_state) {
	case SMB_SERVER_STATE_RUNNING:
	case SMB_SERVER_STATE_STOPPING:
		sv->sv_state = SMB_SERVER_STATE_STOPPING;
		smb_server_signal_listeners(sv);
		nbt_tid = smb_server_listener_tid(&sv->sv_nbt_daemon);
		tcp_tid = smb_server_listener_tid(&sv->sv_tcp_daemon);

		sv->sv_state = SMB_SERVER_STATE_DELETING;
		mutex_exit(&sv->sv_mutex);

		if (nbt_tid != 0)
			thread_join(nbt_tid);
		if (tcp_tid != 0)
			thread_join(tcp_tid);

		smb_server_listen_fini(&sv->sv_nbt_daemon);
		smb_server_listen_fini(&sv->sv_tcp_daemon);
		mutex_enter(&sv->sv_mutex);
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

	smb_server_shutdown(sv);
	rw_destroy(&sv->sv_cfg_lock);
	smb_opipe_door_fini();
	smb_kdoor_fini();
	smb_server_kstat_fini(sv);
	smb_llist_destructor(&sv->sv_vfs_list);
	smb_llist_destructor(&sv->sv_opipe_list);
	smb_llist_destructor(&sv->sv_event_list);

	while ((ux = list_head(&sv->sv_unexport_list.sl_list)) != NULL) {
		smb_slist_remove(&sv->sv_unexport_list, ux);
		kmem_cache_free(sv->si_cache_unexport, ux);
	}
	smb_slist_destructor(&sv->sv_unexport_list);

	kmem_cache_destroy(sv->si_cache_unexport);
	kmem_cache_destroy(sv->si_cache_vfs);
	kmem_cache_destroy(sv->si_cache_request);
	kmem_cache_destroy(sv->si_cache_session);
	kmem_cache_destroy(sv->si_cache_user);
	kmem_cache_destroy(sv->si_cache_tree);
	kmem_cache_destroy(sv->si_cache_ofile);
	kmem_cache_destroy(sv->si_cache_odir);
	kmem_cache_destroy(sv->si_cache_opipe);
	kmem_cache_destroy(sv->si_cache_event);

	smb_thread_destroy(&sv->si_thread_timers);
	smb_thread_destroy(&sv->si_thread_unexport);
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
	smb_server_t	*sv;

	rc = smb_server_lookup(&sv);
	if (rc)
		return (rc);

	mutex_enter(&sv->sv_mutex);
	switch (sv->sv_state) {
	case SMB_SERVER_STATE_CONFIGURED:
		smb_codepage_init();

		sv->sv_thread_pool = taskq_create("smb_workers",
		    sv->sv_cfg.skc_maxworkers, SMB_WORKER_PRIORITY,
		    sv->sv_cfg.skc_maxworkers, INT_MAX,
		    TASKQ_DYNAMIC|TASKQ_PREPOPULATE);

		sv->sv_session = smb_session_create(NULL, 0, sv, 0);

		if (sv->sv_thread_pool == NULL || sv->sv_session == NULL) {
			rc = ENOMEM;
			break;
		}

		if (rc = smb_server_fsop_start(sv))
			break;
		ASSERT(sv->sv_lmshrd == NULL);
		sv->sv_lmshrd = smb_kshare_init(ioc->lmshrd);
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
		if (rc = smb_thread_start(&sv->si_thread_unexport))
			break;
		sv->sv_state = SMB_SERVER_STATE_RUNNING;
		mutex_exit(&sv->sv_mutex);
		smb_server_release(sv);
		return (0);
	default:
		SMB_SERVER_STATE_VALID(sv->sv_state);
		mutex_exit(&sv->sv_mutex);
		smb_server_release(sv);
		return (ENOTTY);
	}

	smb_server_shutdown(sv);
	mutex_exit(&sv->sv_mutex);
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
		smb_server_signal_listeners(sv);
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
	smb_server_t	*sv;
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
 * SMB-over-NetBIOS (port 139)
 *
 * Traditional SMB service over NetBIOS, which requires that a NetBIOS
 * session be established.
 */
int
smb_server_nbt_listen(smb_ioc_listen_t *ioc)
{
	smb_server_t	*sv;
	int		rc;

	rc = smb_server_lookup(&sv);
	if (rc)
		return (rc);

	mutex_enter(&sv->sv_mutex);
	switch (sv->sv_state) {
	case SMB_SERVER_STATE_RUNNING:
		if ((sv->sv_nbt_daemon.ld_kth != NULL) &&
		    (sv->sv_nbt_daemon.ld_kth != curthread)) {
			mutex_exit(&sv->sv_mutex);
			smb_server_release(sv);
			return (EACCES);
		} else {
			sv->sv_nbt_daemon.ld_kth = curthread;
			sv->sv_nbt_daemon.ld_ktdid = curthread->t_did;
		}
		break;
	case SMB_SERVER_STATE_STOPPING:
		mutex_exit(&sv->sv_mutex);
		smb_server_release(sv);
		return (ECANCELED);
	default:
		SMB_SERVER_STATE_VALID(sv->sv_state);
		mutex_exit(&sv->sv_mutex);
		smb_server_release(sv);
		return (EFAULT);
	}
	mutex_exit(&sv->sv_mutex);

	/*
	 * netbios must be ipv4
	 */
	rc = smb_server_listen(sv, &sv->sv_nbt_daemon, IPPORT_NETBIOS_SSN,
	    AF_INET, ioc->error);

	mutex_enter(&sv->sv_mutex);
	sv->sv_nbt_daemon.ld_kth = NULL;

	mutex_exit(&sv->sv_mutex);

	smb_server_release(sv);
	return (rc);
}

/*
 *  SMB-over-TCP (port 445)
 */
int
smb_server_tcp_listen(smb_ioc_listen_t *ioc)
{
	smb_server_t	*sv;
	int		rc;

	rc = smb_server_lookup(&sv);
	if (rc)
		return (rc);

	mutex_enter(&sv->sv_mutex);
	switch (sv->sv_state) {
	case SMB_SERVER_STATE_RUNNING:
		if ((sv->sv_tcp_daemon.ld_kth != NULL) &&
		    (sv->sv_tcp_daemon.ld_kth != curthread)) {
			mutex_exit(&sv->sv_mutex);
			smb_server_release(sv);
			return (EACCES);
		} else {
			sv->sv_tcp_daemon.ld_kth = curthread;
			sv->sv_tcp_daemon.ld_ktdid = curthread->t_did;
		}
		break;
	case SMB_SERVER_STATE_STOPPING:
		mutex_exit(&sv->sv_mutex);
		smb_server_release(sv);
		return (ECANCELED);
	default:
		SMB_SERVER_STATE_VALID(sv->sv_state);
		mutex_exit(&sv->sv_mutex);
		smb_server_release(sv);
		return (EFAULT);
	}
	mutex_exit(&sv->sv_mutex);

	if (sv->sv_cfg.skc_ipv6_enable)
		rc = smb_server_listen(sv, &sv->sv_tcp_daemon,
		    IPPORT_SMB, AF_INET6, ioc->error);
	else
		rc = smb_server_listen(sv, &sv->sv_tcp_daemon,
		    IPPORT_SMB, AF_INET, ioc->error);

	mutex_enter(&sv->sv_mutex);
	sv->sv_tcp_daemon.ld_kth = NULL;

	mutex_exit(&sv->sv_mutex);

	smb_server_release(sv);
	return (rc);
}

/*
 * smb_server_nbt_receive
 */
int
smb_server_nbt_receive(void)
{
	int		rc;
	smb_server_t	*sv;

	if ((rc = smb_server_lookup(&sv)) == 0) {
		rc = smb_session_daemon(&sv->sv_nbt_daemon.ld_session_list);
		smb_server_release(sv);
	}

	return (rc);
}

/*
 * smb_server_tcp_receive
 */
int
smb_server_tcp_receive(void)
{
	int		rc;
	smb_server_t	*sv;

	if ((rc = smb_server_lookup(&sv)) == 0) {
		rc = smb_session_daemon(&sv->sv_tcp_daemon.ld_session_list);
		smb_server_release(sv);
	}

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
		ioc->open_users = sv->sv_open_users;
		ioc->open_trees = sv->sv_open_trees;
		ioc->open_files = sv->sv_open_files;
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
	smb_svcenum_t		*svcenum = &ioc->svcenum;
	smb_server_t		*sv;
	smb_session_list_t	*se;
	int			rc;

	switch (svcenum->se_type) {
	case SMB_SVCENUM_TYPE_USER:
	case SMB_SVCENUM_TYPE_TREE:
	case SMB_SVCENUM_TYPE_FILE:
		break;
	default:
		return (EINVAL);
	}

	if ((rc = smb_server_lookup(&sv)) != 0)
		return (rc);

	svcenum->se_bavail = svcenum->se_buflen;
	svcenum->se_bused = 0;
	svcenum->se_nitems = 0;

	se = &sv->sv_nbt_daemon.ld_session_list;
	smb_server_enum_private(se, svcenum);

	se = &sv->sv_tcp_daemon.ld_session_list;
	smb_server_enum_private(se, svcenum);

	smb_server_release(sv);
	return (0);
}

/*
 * Look for sessions to disconnect by client and user name.
 */
int
smb_server_session_close(smb_ioc_session_t *ioc)
{
	smb_session_list_t	*se;
	smb_server_t		*sv;
	int			nbt_cnt;
	int			tcp_cnt;
	int			rc;

	if ((rc = smb_server_lookup(&sv)) != 0)
		return (rc);

	se = &sv->sv_nbt_daemon.ld_session_list;
	nbt_cnt = smb_server_sesion_disconnect(se, ioc->client, ioc->username);

	se = &sv->sv_tcp_daemon.ld_session_list;
	tcp_cnt = smb_server_sesion_disconnect(se, ioc->client, ioc->username);

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
	uint32_t		uniqid = ioc->uniqid;
	smb_session_list_t	*se;
	smb_server_t		*sv;
	int			rc;

	if ((rc = smb_server_lookup(&sv)) != 0)
		return (rc);

	se = &sv->sv_nbt_daemon.ld_session_list;
	rc = smb_server_fclose(se, uniqid);

	if (rc == ENOENT) {
		se = &sv->sv_tcp_daemon.ld_session_list;
		rc = smb_server_fclose(se, uniqid);
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

	rw_enter(&sv->sv_nbt_daemon.ld_session_list.se_lock, RW_READER);
	counter = sv->sv_nbt_daemon.ld_session_list.se_act.count;
	rw_exit(&sv->sv_nbt_daemon.ld_session_list.se_lock);
	rw_enter(&sv->sv_tcp_daemon.ld_session_list.se_lock, RW_READER);
	counter += sv->sv_tcp_daemon.ld_session_list.se_act.count;
	rw_exit(&sv->sv_tcp_daemon.ld_session_list.se_lock);

	smb_server_release(sv);

	return (counter);
}

/*
 * Disconnect the specified share.
 * Typically called when a share has been removed.
 */
static void
smb_server_disconnect_share(smb_session_list_t *slist, const char *sharename)
{
	smb_session_t		*session;

	rw_enter(&slist->se_lock, RW_READER);

	session = list_head(&slist->se_act.lst);
	while (session) {
		ASSERT(session->s_magic == SMB_SESSION_MAGIC);
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
		session = list_next(&slist->se_act.lst, session);
	}

	rw_exit(&slist->se_lock);
}

/*
 * smb_server_share_export()
 *
 * This function handles kernel processing at share enable time.
 *
 * At share-enable time (LMSHRD_ADD), the file system corresponding to
 * the share is checked for characteristics that are required for SMB
 * sharing.  If this check passes, then a hold is taken on the root vnode
 * of the file system (or a reference count on the corresponding smb_vfs_t
 * is bumped), preventing an unmount.  (See smb_vfs_hold()).
 */

int
smb_server_share_export(smb_ioc_share_t *ioc)
{
	smb_server_t	*sv;
	int		error = 0;
	smb_node_t	*fnode = NULL;
	smb_node_t	*dnode;
	char		last_comp[MAXNAMELEN];
	smb_request_t	*sr;

	if (smb_server_lookup(&sv))
		return (EINVAL);

	mutex_enter(&sv->sv_mutex);
	switch (sv->sv_state) {
	case SMB_SERVER_STATE_RUNNING:
	case SMB_SERVER_STATE_STOPPING:
		break;
	default:
		mutex_exit(&sv->sv_mutex);
		return (ENOTACTIVE);
	}
	mutex_exit(&sv->sv_mutex);

	sr = smb_request_alloc(sv->sv_session, 0);
	if (sr == NULL) {
		smb_server_release(sv);
		return (ENOMEM);
	}

	sr->user_cr = kcred;

	error = smb_pathname_reduce(sr, kcred, ioc->path,
	    NULL, NULL, &dnode, last_comp);

	if (error) {
		smb_request_free(sr);
		smb_server_release(sv);
		return (error);
	}

	error = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS,
	    sv->si_root_smb_node, dnode, last_comp, &fnode);

	smb_node_release(dnode);

	if (error) {
		smb_request_free(sr);
		smb_server_release(sv);
		return (error);
	}

	ASSERT(fnode->vp && fnode->vp->v_vfsp);

#ifdef SMB_ENFORCE_NODEV
	if (vfs_optionisset(fnode->vp->v_vfsp, MNTOPT_NODEVICES, NULL) == 0) {
		smb_node_release(fnode);
		smb_request_free(sr);
		smb_server_release(sv);
		return (EINVAL);
	}
#endif /* SMB_ENFORCE_NODEV */

	if (!smb_vfs_hold(sv, fnode->vp->v_vfsp))
		error = ENOMEM;

	/*
	 * The refcount on the smb_vfs has been incremented.
	 * If it wasn't already, a hold has also been taken
	 * on the root vnode of the file system.
	 */

	smb_node_release(fnode);
	smb_request_free(sr);
	smb_server_release(sv);
	return (error);
}

/*
 * smb_server_share_unexport()
 *
 * This function is invoked when a share is disabled to disconnect trees
 * and close files.  Cleaning up may involve VOP and/or VFS calls, which
 * may conflict/deadlock with stuck threads if something is amiss with the
 * file system.  Queueing the request for asynchronous processing allows the
 * call to return immediately so that, if the unshare is being done in the
 * context of a forced unmount, the forced unmount will always be able to
 * proceed (unblocking stuck I/O and eventually allowing all blocked unshare
 * processes to complete).
 *
 * The path lookup to find the root vnode of the VFS in question and the
 * release of this vnode are done synchronously prior to any associated
 * unmount.  Doing these asynchronous to an associated unmount could run
 * the risk of a spurious EBUSY for a standard unmount or an EIO during
 * the path lookup due to a forced unmount finishing first.
 */

int
smb_server_share_unexport(smb_ioc_share_t *ioc)
{
	smb_server_t	*sv;
	smb_request_t	*sr;
	smb_unexport_t	*ux;
	smb_node_t	*fnode = NULL;
	smb_node_t	*dnode;
	char		last_comp[MAXNAMELEN];
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
		return (ENOTACTIVE);
	}
	mutex_exit(&sv->sv_mutex);

	sr = smb_request_alloc(sv->sv_session, 0);

	if (sr == NULL) {
		smb_server_release(sv);
		return (ENOMEM);
	}

	sr->user_cr = kcred;

	rc = smb_pathname_reduce(sr, kcred, ioc->path, NULL, NULL,
	    &dnode, last_comp);

	if (rc) {
		smb_request_free(sr);
		smb_server_release(sv);
		return (rc);
	}

	rc = smb_fsop_lookup(sr, kcred, SMB_FOLLOW_LINKS, sv->si_root_smb_node,
	    dnode, last_comp, &fnode);

	smb_node_release(dnode);
	smb_request_free(sr);

	if (rc) {
		smb_server_release(sv);
		return (rc);
	}

	ASSERT(fnode->vp && fnode->vp->v_vfsp);

	smb_vfs_rele(sv, fnode->vp->v_vfsp);

	smb_node_release(fnode);

	ux = kmem_cache_alloc(sv->si_cache_unexport, KM_SLEEP);

	(void) strlcpy(ux->ux_sharename, ioc->name, MAXNAMELEN);

	smb_slist_insert_tail(&sv->sv_unexport_list, ux);
	smb_thread_signal(&sv->si_thread_unexport);

	smb_server_release(sv);
	return (0);
}

/*
 * smb_server_thread_unexport
 *
 * This function processes the unexport event list and disconnects shares
 * asynchronously.  The function executes as a zone-specific thread.
 *
 * The server arg passed in is safe to use without a reference count, because
 * the server cannot be deleted until smb_thread_stop()/destroy() return,
 * which is also when the thread exits.
 */

static void
smb_server_thread_unexport(smb_thread_t *thread, void *arg)
{
	smb_server_t		*sv = (smb_server_t *)arg;
	smb_unexport_t		*ux;
	smb_session_list_t	*slist;

	while (smb_thread_continue(thread)) {
		while ((ux = list_head(&sv->sv_unexport_list.sl_list))
		    != NULL) {
			smb_slist_remove(&sv->sv_unexport_list, ux);

			slist = &sv->sv_nbt_daemon.ld_session_list;
			smb_server_disconnect_share(slist, ux->ux_sharename);

			slist = &sv->sv_tcp_daemon.ld_session_list;
			smb_server_disconnect_share(slist, ux->ux_sharename);

			kmem_cache_free(sv->si_cache_unexport, ux);
		}
	}
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

	rc = smb_server_lookup(&sv);
	if (rc == 0) {
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
	return (0);
}

/*
 * *****************************************************************************
 * **************** Functions called from the internal layers ******************
 * *****************************************************************************
 *
 * These functions are provided the relevant smb server by the caller.
 */

void
smb_server_reconnection_check(smb_server_t *sv, smb_session_t *session)
{
	ASSERT(sv == session->s_server);

	smb_session_reconnection_check(&sv->sv_nbt_daemon.ld_session_list,
	    session);
	smb_session_reconnection_check(&sv->sv_tcp_daemon.ld_session_list,
	    session);
}

void
smb_server_get_cfg(smb_server_t *sv, smb_kmod_cfg_t *cfg)
{
	rw_enter(&sv->sv_cfg_lock, RW_READER);
	bcopy(&sv->sv_cfg, cfg, sizeof (*cfg));
	rw_exit(&sv->sv_cfg_lock);
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
static int
smb_server_kstat_init(smb_server_t *sv)
{
	(void) snprintf(sv->sv_ksp_name, sizeof (sv->sv_ksp_name), "%s%d",
	    SMBSRV_KSTAT_NAME, sv->sv_zid);

	sv->sv_ksp = kstat_create(SMBSRV_KSTAT_MODULE, 0, sv->sv_ksp_name,
	    SMBSRV_KSTAT_CLASS, KSTAT_TYPE_NAMED,
	    sizeof (sv->sv_ks_data) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (sv->sv_ksp) {
		(void) strlcpy(sv->sv_ks_data.open_files.name, "open_files",
		    sizeof (sv->sv_ks_data.open_files.name));
		sv->sv_ks_data.open_files.data_type = KSTAT_DATA_UINT32;
		(void) strlcpy(sv->sv_ks_data.open_trees.name, "connections",
		    sizeof (sv->sv_ks_data.open_trees.name));
		sv->sv_ks_data.open_trees.data_type = KSTAT_DATA_UINT32;
		(void) strlcpy(sv->sv_ks_data.open_users.name, "sessions",
		    sizeof (sv->sv_ks_data.open_users.name));
		sv->sv_ks_data.open_users.data_type = KSTAT_DATA_UINT32;

		mutex_init(&sv->sv_ksp_mutex, NULL, MUTEX_DEFAULT, NULL);
		sv->sv_ksp->ks_lock = &sv->sv_ksp_mutex;
		sv->sv_ksp->ks_data = (void *)&sv->sv_ks_data;
		sv->sv_ksp->ks_update = smb_server_kstat_update_info;
		kstat_install(sv->sv_ksp);
	}

	/* create and initialize smb kstats - smb_dispatch stats */
	smb_dispatch_kstat_init();

	return (0);
}

/*
 * smb_server_kstat_fini
 */
static void
smb_server_kstat_fini(smb_server_t *sv)
{
	if (sv->sv_ksp) {
		kstat_delete(sv->sv_ksp);
		mutex_destroy(&sv->sv_ksp_mutex);
		sv->sv_ksp = NULL;
	}
	smb_dispatch_kstat_fini();
}

/* ARGSUSED */
static int
smb_server_kstat_update_info(kstat_t *ksp, int rw)
{
	smb_server_t	*sv;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	} else {
		ASSERT(MUTEX_HELD(ksp->ks_lock));

		_NOTE(LINTED("pointer cast may result in improper alignment"))
		sv = (smb_server_t *)((uint8_t *)(ksp->ks_data) -
		    offsetof(smb_server_t, sv_ks_data));

		SMB_SERVER_VALID(sv);

		sv->sv_ks_data.open_files.value.ui32 = sv->sv_open_files;
		sv->sv_ks_data.open_trees.value.ui32 = sv->sv_open_trees;
		sv->sv_ks_data.open_users.value.ui32 = sv->sv_open_users;
	}
	return (0);
}

/*
 * The mutex of the server must have been entered before calling this function.
 */
static void
smb_server_shutdown(smb_server_t *sv)
{
	SMB_SERVER_VALID(sv);

	smb_opipe_door_close();
	smb_thread_stop(&sv->si_thread_timers);
	smb_thread_stop(&sv->si_thread_unexport);
	smb_kdoor_close();
	smb_kshare_fini(sv->sv_lmshrd);
	sv->sv_lmshrd = NULL;
	smb_server_fsop_stop(sv);

	if (sv->sv_session) {
		smb_session_delete(sv->sv_session);
		sv->sv_session = NULL;
	}

	if (sv->sv_thread_pool) {
		taskq_destroy(sv->sv_thread_pool);
		sv->sv_thread_pool = NULL;
	}
}

static int
smb_server_listen(
    smb_server_t		*sv,
    smb_listener_daemon_t	*ld,
    in_port_t			port,
    int				family,
    int				pthread_create_error)
{
	int			rc = 0;
	ksocket_t		s_so;
	uint32_t		on;
	uint32_t		off;
	uint32_t		txbuf_size;
	smb_session_t		*session;

	if (pthread_create_error) {
		/*
		 * Delete the last session created. The user space thread
		 * creation failed.
		 */
		smb_session_list_delete_tail(&ld->ld_session_list);
	}

	if (ld->ld_so == NULL) {
		/* First time listener */
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

		ld->ld_so = smb_socreate(family, SOCK_STREAM, 0);
		if (ld->ld_so == NULL) {
			cmn_err(CE_WARN, "port %d: socket create failed", port);
			return (ENOMEM);
		}

		off = 0;
		(void) ksocket_setsockopt(ld->ld_so, SOL_SOCKET,
		    SO_MAC_EXEMPT, &off, sizeof (off), CRED());

		on = 1;
		(void) ksocket_setsockopt(ld->ld_so, SOL_SOCKET,
		    SO_REUSEADDR, &on, sizeof (on), CRED());

		if (family == AF_INET) {
			rc = ksocket_bind(ld->ld_so,
			    (struct sockaddr *)&ld->ld_sin,
			    sizeof (ld->ld_sin), CRED());
		} else {
			rc = ksocket_bind(ld->ld_so,
			    (struct sockaddr *)&ld->ld_sin6,
			    sizeof (ld->ld_sin6), CRED());
		}

		if (rc != 0) {
			cmn_err(CE_WARN, "port %d: bind failed (%d)", port, rc);
			smb_server_listen_fini(ld);
			return (rc);
		}

		rc =  ksocket_listen(ld->ld_so, 20, CRED());
		if (rc < 0) {
			cmn_err(CE_WARN, "port %d: listen failed", port);
			smb_server_listen_fini(ld);
			return (rc);
		}
	}

	DTRACE_PROBE1(so__wait__accept, struct sonode *, ld->ld_so);

	for (;;) {
		if (smb_server_is_stopping()) {
			rc = ECANCELED;
			break;
		}

		rc = ksocket_accept(ld->ld_so, NULL, NULL, &s_so, CRED());
		if (rc != 0)
			break;

		if (smb_server_is_stopping()) {
			smb_soshutdown(s_so);
			smb_sodestroy(s_so);
			rc = ECANCELED;
			break;
		}

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
		session = smb_session_create(s_so, port, sv, family);
		if (session) {
			smb_session_list_append(&ld->ld_session_list, session);
			rc = 0;
			break;
		} else {
			smb_soshutdown(s_so);
			smb_sodestroy(s_so);
		}
	}

	if (rc != 0)
		smb_server_listen_fini(ld);

	return (rc);
}

static void
smb_server_listen_fini(smb_listener_daemon_t *ld)
{
	if (ld->ld_so != NULL) {
		smb_session_list_signal(&ld->ld_session_list);
		smb_soshutdown(ld->ld_so);
		smb_sodestroy(ld->ld_so);
		ld->ld_so = NULL;
	}
}

static kt_did_t
smb_server_listener_tid(smb_listener_daemon_t *ld)
{
	kt_did_t	tid;

	if (ld->ld_ktdid != 0) {
		tid = ld->ld_ktdid;
		ld->ld_ktdid = 0;
	}

	return (tid);
}

/*
 * smb_server_lookup
 *
 * This function tries to find the server associated with the zone of the
 * caller.
 */
static int
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
static void
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
smb_server_enum_private(smb_session_list_t *se, smb_svcenum_t *svcenum)
{
	smb_session_t	*sn;
	smb_llist_t	*ulist;
	smb_user_t	*user;
	int		rc = 0;

	rw_enter(&se->se_lock, RW_READER);
	sn = list_head(&se->se_act.lst);

	while (sn != NULL) {
		ASSERT(sn->s_magic == SMB_SESSION_MAGIC);
		ulist = &sn->s_user_list;
		smb_llist_enter(ulist, RW_READER);
		user = smb_llist_head(ulist);

		while (user != NULL) {
			if (smb_user_hold(user)) {
				rc = smb_user_enum(user, svcenum);
				smb_user_release(user);
			}

			user = smb_llist_next(ulist, user);
		}

		smb_llist_exit(ulist);

		if (rc != 0)
			break;

		sn = list_next(&se->se_act.lst, sn);
	}

	rw_exit(&se->se_lock);
}

/*
 * Disconnect sessions associated with the specified client and username.
 * Empty strings are treated as wildcards.
 */
static int
smb_server_sesion_disconnect(smb_session_list_t *se,
    const char *client, const char *name)
{
	smb_session_t	*sn;
	smb_llist_t	*ulist;
	smb_user_t	*user;
	boolean_t	match;
	int		count = 0;

	rw_enter(&se->se_lock, RW_READER);
	sn = list_head(&se->se_act.lst);

	while (sn != NULL) {
		ASSERT(sn->s_magic == SMB_SESSION_MAGIC);

		if ((*client != '\0') && (!smb_session_isclient(sn, client))) {
			sn = list_next(&se->se_act.lst, sn);
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
		sn = list_next(&se->se_act.lst, sn);
	}

	rw_exit(&se->se_lock);
	return (count);
}

/*
 * Close a file by its unique id.
 */
static int
smb_server_fclose(smb_session_list_t *se, uint32_t uniqid)
{
	smb_session_t	*sn;
	smb_llist_t	*ulist;
	smb_user_t	*user;
	int		rc = ENOENT;

	rw_enter(&se->se_lock, RW_READER);
	sn = list_head(&se->se_act.lst);

	while ((sn != NULL) && (rc == ENOENT)) {
		ASSERT(sn->s_magic == SMB_SESSION_MAGIC);
		ulist = &sn->s_user_list;
		smb_llist_enter(ulist, RW_READER);
		user = smb_llist_head(ulist);

		while ((user != NULL) && (rc == ENOENT)) {
			if (smb_user_hold(user)) {
				rc = smb_user_fclose(user, uniqid);
				smb_user_release(user);
			}

			user = smb_llist_next(ulist, user);
		}

		smb_llist_exit(ulist);
		sn = list_next(&se->se_act.lst, sn);
	}

	rw_exit(&se->se_lock);
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
	(void) strlcpy(sv->sv_cfg.skc_nbdomain, ioc->nbdomain,
	    sizeof (sv->sv_cfg.skc_nbdomain));
	(void) strlcpy(sv->sv_cfg.skc_fqdn, ioc->fqdn,
	    sizeof (sv->sv_cfg.skc_fqdn));
	(void) strlcpy(sv->sv_cfg.skc_hostname, ioc->hostname,
	    sizeof (sv->sv_cfg.skc_hostname));
	(void) strlcpy(sv->sv_cfg.skc_system_comment, ioc->system_comment,
	    sizeof (sv->sv_cfg.skc_system_comment));
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
		smb_vfs_rele_all(sv);
		smb_node_release(sv->si_root_smb_node);
		sv->si_root_smb_node = NULL;
	}
}

static void
smb_server_signal_listeners(smb_server_t *sv)
{
	SMB_SERVER_VALID(sv);
	ASSERT(sv->sv_state == SMB_SERVER_STATE_STOPPING);
	ASSERT(MUTEX_HELD(&sv->sv_mutex));

	smb_event_cancel(sv, 0);

	if (sv->sv_nbt_daemon.ld_kth != NULL) {
		tsignal(sv->sv_nbt_daemon.ld_kth, SIGINT);
		sv->sv_nbt_daemon.ld_kth = NULL;
	}

	if (sv->sv_tcp_daemon.ld_kth != NULL) {
		tsignal(sv->sv_tcp_daemon.ld_kth, SIGINT);
		sv->sv_tcp_daemon.ld_kth = NULL;
	}
}

smb_event_t *
smb_event_create(void)
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
		if (smb_event_debug && ((event->se_waittime % 10) == 0))
			cmn_err(CE_NOTE, "smb_event_wait[%d] (%d sec)",
			    event->se_txid, event->se_waittime);

		if (event->se_errno != 0)
			break;

		if (event->se_waittime > SMB_EVENT_TIMEOUT) {
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
static void
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
