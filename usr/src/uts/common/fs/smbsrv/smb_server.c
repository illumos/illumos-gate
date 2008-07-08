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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 *		      |  SMB_SERVER_STATE_RUNNING   |
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
#include <smbsrv/smb_kproto.h>
#include <smbsrv/netbios.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/cifs.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smb_share.h>
#include <smbsrv/smb_door_svc.h>
#include <smbsrv/smb_kstat.h>

extern void smb_dispatch_kstat_init(void);
extern void smb_dispatch_kstat_fini(void);
extern void smb_reply_notify_change_request(smb_request_t *);

static int smb_server_kstat_init(smb_server_t *);
static void smb_server_kstat_fini(smb_server_t *);
static int smb_server_kstat_update_info(kstat_t *, int);
static void smb_server_timers(smb_thread_t *, void *);
static int smb_server_listen(smb_server_t *, smb_listener_daemon_t *,
    in_port_t, int);
static int smb_server_lookup(smb_server_t **);
static void smb_server_release(smb_server_t *);
static int smb_server_ulist_geti(smb_session_list_t *, int,
    smb_opipe_context_t *, int);
static void smb_server_store_cfg(smb_server_t *, smb_kmod_cfg_t *);
static void smb_server_stop(smb_server_t *);
static int smb_server_fsop_start(smb_server_t *);
static void smb_server_fsop_stop(smb_server_t *);

static smb_llist_t	smb_servers;

/*
 * *****************************************************************************
 * **************** Functions called from the device interface *****************
 * *****************************************************************************
 *
 * These functions determine the relevant smb server to which the call apply.
 */

/*
 * smb_server_svc_init
 *
 * This function must called from smb_drv_attach().
 */
int
smb_server_svc_init(void)
{
	int	rc = 0;

	while (rc == 0) {
		if (rc = smb_vop_init())
			continue;
		if (rc = smb_node_init())
			continue;
		if (rc = smb_fem_init())
			continue;
		if (rc = smb_notify_init())
			continue;
		if (rc = smb_net_init())
			continue;
		if (rc = smb_kdoor_srv_start())
			continue;
		smb_llist_constructor(&smb_servers, sizeof (smb_server_t),
		    offsetof(smb_server_t, sv_lnd));
		return (0);
	}
	smb_net_fini();
	smb_notify_fini();
	smb_fem_fini();
	smb_node_fini();
	smb_vop_fini();
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
		smb_kdoor_srv_stop();
		smb_net_fini();
		smb_notify_fini();
		smb_fem_fini();
		smb_node_fini();
		smb_vop_fini();
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
		ASSERT(sv->sv_magic == SMB_SERVER_MAGIC);
		if (sv->sv_zid == zid) {
			smb_llist_exit(&smb_servers);
			return (EEXIST);
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

	smb_session_list_constructor(&sv->sv_nbt_daemon.ld_session_list);
	smb_session_list_constructor(&sv->sv_tcp_daemon.ld_session_list);

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
	sv->si_cache_node = kmem_cache_create("smb_node_cache",
	    sizeof (smb_node_t), 8, NULL, NULL, NULL, NULL, NULL, 0);

	smb_thread_init(&sv->si_thread_timers,
	    "smb_timers", smb_server_timers, sv,
	    NULL, NULL);

	sv->sv_pid = curproc->p_pid;

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
	int		rc;

	rc = smb_server_lookup(&sv);
	if (rc != 0)
		return (rc);

	mutex_enter(&sv->sv_mutex);
	switch (sv->sv_state) {
	case SMB_SERVER_STATE_RUNNING:
	{
		boolean_t	nbt = B_FALSE;
		boolean_t	tcp = B_FALSE;

		if (sv->sv_nbt_daemon.ld_kth) {
			tsignal(sv->sv_nbt_daemon.ld_kth, SIGINT);
			nbt = B_TRUE;
		}
		if (sv->sv_tcp_daemon.ld_kth) {
			tsignal(sv->sv_tcp_daemon.ld_kth, SIGINT);
			tcp = B_TRUE;
		}
		sv->sv_state = SMB_SERVER_STATE_DELETING;
		mutex_exit(&sv->sv_mutex);
		if (nbt)
			thread_join(sv->sv_nbt_daemon.ld_ktdid);
		if (tcp)
			thread_join(sv->sv_tcp_daemon.ld_ktdid);
		mutex_enter(&sv->sv_mutex);
		break;
	}
	case SMB_SERVER_STATE_CONFIGURED:
	case SMB_SERVER_STATE_CREATED:
		sv->sv_state = SMB_SERVER_STATE_DELETING;
		break;
	default:
		ASSERT(sv->sv_state == SMB_SERVER_STATE_DELETING);
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

	smb_server_stop(sv);
	rw_destroy(&sv->sv_cfg_lock);
	smb_opipe_door_fini();
	smb_server_kstat_fini(sv);
	smb_llist_destructor(&sv->sv_vfs_list);
	kmem_cache_destroy(sv->si_cache_vfs);
	kmem_cache_destroy(sv->si_cache_request);
	kmem_cache_destroy(sv->si_cache_session);
	kmem_cache_destroy(sv->si_cache_user);
	kmem_cache_destroy(sv->si_cache_tree);
	kmem_cache_destroy(sv->si_cache_ofile);
	kmem_cache_destroy(sv->si_cache_odir);
	kmem_cache_destroy(sv->si_cache_node);

	taskq_destroy(sv->sv_thread_pool);
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
smb_server_configure(smb_kmod_cfg_t *cfg)
{
	int		rc = 0;
	smb_server_t	*sv;

	rc = smb_server_lookup(&sv);
	if (rc)
		return (rc);

	mutex_enter(&sv->sv_mutex);
	switch (sv->sv_state) {
	case SMB_SERVER_STATE_CREATED:
		smb_server_store_cfg(sv, cfg);
		sv->sv_state = SMB_SERVER_STATE_CONFIGURED;
		break;

	case SMB_SERVER_STATE_CONFIGURED:
		smb_server_store_cfg(sv, cfg);
		break;

	case SMB_SERVER_STATE_RUNNING:
		rw_enter(&sv->sv_cfg_lock, RW_WRITER);
		smb_server_store_cfg(sv, cfg);
		rw_exit(&sv->sv_cfg_lock);
		break;

	default:
		ASSERT(sv->sv_state == SMB_SERVER_STATE_DELETING);
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
smb_server_start(struct smb_io_start *io_start)
{
	int		rc = 0;
	smb_server_t	*sv;

	rc = smb_server_lookup(&sv);
	if (rc)
		return (rc);

	mutex_enter(&sv->sv_mutex);
	switch (sv->sv_state) {
	case SMB_SERVER_STATE_CONFIGURED:

		sv->sv_thread_pool = taskq_create("smb_workers",
		    sv->sv_cfg.skc_maxworkers, SMB_WORKER_PRIORITY,
		    sv->sv_cfg.skc_maxworkers, INT_MAX,
		    TASKQ_DYNAMIC|TASKQ_PREPOPULATE);

		sv->sv_session = smb_session_create(NULL, 0, sv);
		if (sv->sv_session == NULL) {
			rc = ENOMEM;
			break;
		}

		if (rc = smb_server_fsop_start(sv))
			break;
		ASSERT(sv->sv_lmshrd == NULL);
		sv->sv_lmshrd = smb_kshare_init(io_start->lmshrd);
		if (sv->sv_lmshrd == NULL)
			break;
		if (rc = smb_kdoor_clnt_start(io_start->udoor))
			break;
		if (rc = smb_kdoor_srv_set_dwncall())
			break;
		if (rc = smb_thread_start(&sv->si_thread_timers))
			break;
		/*
		 * XXX We give up the NET_MAC_AWARE privilege because it keeps
		 * us from re-opening the connection when there are leftover TCP
		 * connections in TCPS_TIME_WAIT state.  There seem to be some
		 * security ramifications around reestablishing a connection
		 * while possessing the NET_MAC_AWARE privilege.
		 *
		 * This approach may cause problems when we try to support
		 * zones.  An alternative would be to retry the connection setup
		 * for a fixed period of time until the stale connections clear
		 * up but that implies we would be offline for a couple minutes
		 * every time the service is restarted with active connections.
		 */
		rc = setpflags(NET_MAC_AWARE, 0, CRED());
		if (rc) {
			cmn_err(CE_WARN,
			    "Cannot remove NET_MAC_AWARE privilege");
			break;
		}
		if (rc = smb_opipe_door_open(io_start->opipe)) {
			cmn_err(CE_WARN, "Cannot open opipe door");
			break;
		}
		sv->sv_state = SMB_SERVER_STATE_RUNNING;
		mutex_exit(&sv->sv_mutex);
		smb_server_release(sv);
		return (0);
	default:
		ASSERT((sv->sv_state == SMB_SERVER_STATE_CREATED) ||
		    (sv->sv_state == SMB_SERVER_STATE_RUNNING) ||
		    (sv->sv_state == SMB_SERVER_STATE_DELETING));
		mutex_exit(&sv->sv_mutex);
		smb_server_release(sv);
		return (ENOTTY);
	}

	smb_server_stop(sv);
	mutex_exit(&sv->sv_mutex);
	smb_server_release(sv);
	return (rc);
}

/*
 * smb_server_nbt_listen: SMB-over-NetBIOS service
 *
 * Traditional SMB service over NetBIOS (port 139), which requires
 * that a NetBIOS session be established.
 */
int
smb_server_nbt_listen(int error)
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
			return (EACCES);
		} else {
			sv->sv_nbt_daemon.ld_kth = curthread;
			sv->sv_nbt_daemon.ld_ktdid = curthread->t_did;
		}
		break;
	default:
		ASSERT((sv->sv_state == SMB_SERVER_STATE_CREATED) ||
		    (sv->sv_state == SMB_SERVER_STATE_CONFIGURED) ||
		    (sv->sv_state == SMB_SERVER_STATE_DELETING));
		mutex_exit(&sv->sv_mutex);
		smb_server_release(sv);
		return (EFAULT);
	}
	mutex_exit(&sv->sv_mutex);

	rc = smb_server_listen(sv, &sv->sv_nbt_daemon, SSN_SRVC_TCP_PORT,
	    error);

	if (rc) {
		mutex_enter(&sv->sv_mutex);
		sv->sv_nbt_daemon.ld_kth = NULL;
		mutex_exit(&sv->sv_mutex);
	}

	smb_server_release(sv);

	return (rc);
}

int
smb_server_tcp_listen(int error)
{
	smb_server_t	*sv;
	int		rc;

	rc = smb_server_lookup(&sv);
	if (rc)
		return (rc);

	mutex_enter(&sv->sv_mutex);
	switch (sv->sv_state) {
	case SMB_SERVER_STATE_RUNNING:
		if ((sv->sv_tcp_daemon.ld_kth) &&
		    (sv->sv_tcp_daemon.ld_kth != curthread)) {
			mutex_exit(&sv->sv_mutex);
			return (EACCES);
		} else {
			sv->sv_tcp_daemon.ld_kth = curthread;
			sv->sv_tcp_daemon.ld_ktdid = curthread->t_did;
		}
		break;
	default:
		ASSERT((sv->sv_state == SMB_SERVER_STATE_CREATED) ||
		    (sv->sv_state == SMB_SERVER_STATE_CONFIGURED) ||
		    (sv->sv_state == SMB_SERVER_STATE_DELETING));
		mutex_exit(&sv->sv_mutex);
		return (EFAULT);
	}
	mutex_exit(&sv->sv_mutex);

	rc = smb_server_listen(sv, &sv->sv_tcp_daemon, SMB_SRVC_TCP_PORT,
	    error);

	if (rc) {
		mutex_enter(&sv->sv_mutex);
		sv->sv_tcp_daemon.ld_kth = NULL;
		mutex_exit(&sv->sv_mutex);
	}

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

	rc = smb_server_lookup(&sv);
	if (rc)
		return (rc);

	rc = smb_session_daemon(&sv->sv_nbt_daemon.ld_session_list);

	smb_server_release(sv);

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

	rc = smb_server_lookup(&sv);
	if (rc)
		return (rc);

	rc = smb_session_daemon(&sv->sv_tcp_daemon.ld_session_list);

	smb_server_release(sv);

	return (rc);
}

int
smb_server_set_gmtoff(uint32_t goff)
{
	int		rc;
	smb_server_t	*sv;


	rc = smb_server_lookup(&sv);
	if (rc)
		return (rc);

	sv->si_gmtoff = goff;

	smb_server_release(sv);

	return (rc);
}

/*
 * *****************************************************************************
 * ****************** Functions called from the door interface *****************
 * *****************************************************************************
 *
 * These functions determine the relevant smb server to which the call apply.
 */

uint32_t
smb_server_get_user_count(void)
{
	smb_server_t	*sv;
	uint32_t	counter = 0;

	if (smb_server_lookup(&sv))
		return (0);

	counter = (uint32_t)sv->sv_open_users;

	smb_server_release(sv);

	return (counter);
}

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
 * smb_session_disconnect_share
 *
 * Disconnects the specified share. This function should be called after the
 * share passed in has been made unavailable by the "share manager".
 */
void
smb_server_disconnect_share(char *sharename)
{
	smb_server_t	*sv;

	if (smb_server_lookup(&sv))
		return;

	smb_session_disconnect_share(&sv->sv_nbt_daemon.ld_session_list,
	    sharename);
	smb_session_disconnect_share(&sv->sv_tcp_daemon.ld_session_list,
	    sharename);

	smb_server_release(sv);
}

void
smb_server_disconnect_volume(fs_desc_t *fsd)
{
	smb_server_t	*sv;

	if (smb_server_lookup(&sv))
		return;

	smb_session_disconnect_volume(&sv->sv_nbt_daemon.ld_session_list, fsd);
	smb_session_disconnect_volume(&sv->sv_tcp_daemon.ld_session_list, fsd);

	smb_server_release(sv);
}

int
smb_server_dr_ulist_get(int offset, smb_dr_ulist_t *dr_ulist, int max_cnt)
{
	smb_server_t	*sv;

	if (!dr_ulist)
		return (-1);

	if (smb_server_lookup(&sv))
		return (-1);

	dr_ulist->dul_cnt =
	    smb_server_ulist_geti(&sv->sv_nbt_daemon.ld_session_list,
	    offset, dr_ulist->dul_users, max_cnt);
	dr_ulist->dul_cnt +=
	    smb_server_ulist_geti(&sv->sv_tcp_daemon.ld_session_list,
	    offset - dr_ulist->dul_cnt, &dr_ulist->dul_users[dr_ulist->dul_cnt],
	    max_cnt);

	return (dr_ulist->dul_cnt);
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
smb_server_share_export(char *path)
{
	smb_server_t	*sv;
	int		error;
	smb_node_t	*fnode = NULL;
	smb_node_t	*dnode;
	smb_attr_t	ret_attr;
	char		last_comp[MAXNAMELEN];
	smb_request_t	*sr;

	if (smb_server_lookup(&sv))
		return (EINVAL);

	sr = smb_request_alloc(sv->sv_session, 0);
	if (sr == NULL) {
		smb_server_release(sv);
		return (ENOMEM);
	}

	sr->user_cr = kcred;

	error = smb_pathname_reduce(sr, kcred, path, NULL, NULL, &dnode,
	    last_comp);

	if (error) {
		smb_request_free(sr);
		smb_server_release(sv);
		return (error);
	}

	error = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS, NULL, dnode,
	    last_comp, &fnode, &ret_attr, NULL, NULL);

	smb_node_release(dnode);

	if (error) {
		smb_request_free(sr);
		smb_server_release(sv);
		return (error);
	}

	ASSERT(fnode->vp && fnode->vp->v_vfsp);

#ifdef SMB_ENFORCE_NODEV
	if (vfs_optionisset(fnode->vp->v_vfsp, MNTOPT_NODEVICES, NULL) == 0)
		return (EINVAL);
#endif /* SMB_ENFORCE_NODEV */

	if (!smb_vfs_hold(sv, fnode->vp->v_vfsp)) {
		smb_node_release(fnode);
		smb_request_free(sr);
		smb_server_release(sv);
		return (ENOMEM);
	}

	/*
	 * The refcount on the smb_vfs has been incremented.
	 * If it wasn't already, a hold has also been taken
	 * on the root vnode of the file system.
	 */

	smb_node_release(fnode);
	smb_request_free(sr);
	smb_server_release(sv);
	return (0);
}



/*
 * smb_server_share_unexport()
 *
 * This function handles kernel processing at share disable time.
 *
 * At share-disable time (LMSHRD_DELETE), the reference count on the
 * corresponding smb_vfs_t is decremented.  If this is the last share
 * on the file system, the hold on the root vnode of the file system
 * will be released.  (See smb_vfs_rele().)
 */

int
smb_server_share_unexport(char *path, char *sharename)
{
	smb_server_t	*sv;
	int		error;
	smb_node_t	*fnode = NULL;
	smb_node_t	*dnode;
	smb_attr_t	ret_attr;
	char		last_comp[MAXNAMELEN];
	smb_request_t	*sr;

	if (smb_server_lookup(&sv))
		return (EINVAL);

	sr = smb_request_alloc(sv->sv_session, 0);
	if (sr == NULL) {
		smb_server_release(sv);
		return (ENOMEM);
	}
	sr->user_cr = kcred;

	error = smb_pathname_reduce(sr, kcred, path, NULL, NULL, &dnode,
	    last_comp);

	if (error) {
		smb_request_free(sr);
		smb_server_release(sv);
		return (error);
	}

	error = smb_fsop_lookup(sr, kcred, SMB_FOLLOW_LINKS, NULL, dnode,
	    last_comp, &fnode, &ret_attr, NULL, NULL);

	smb_node_release(dnode);

	if (error) {
		smb_request_free(sr);
		smb_server_release(sv);
		return (error);
	}

	ASSERT(fnode->vp && fnode->vp->v_vfsp);

	smb_session_disconnect_share(&sv->sv_nbt_daemon.ld_session_list,
	    sharename);
	smb_session_disconnect_share(&sv->sv_tcp_daemon.ld_session_list,
	    sharename);
	smb_vfs_rele(sv, fnode->vp->v_vfsp);
	smb_node_release(fnode);
	smb_request_free(sr);
	smb_server_release(sv);
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

	rc = smb_server_lookup(&sv);
	if (rc == 0) {
		mutex_enter(&sv->sv_mutex);
		if (sv->sv_state == SMB_SERVER_STATE_RUNNING) {
			mutex_exit(&sv->sv_mutex);
			rc = smb_kshare_upcall(sv->sv_lmshrd, arg, add_share);
		} else {
			mutex_exit(&sv->sv_mutex);
			rc = EPERM;
		}
		smb_server_release(sv);
	}
	return (rc);
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
		(void) strlcpy(sv->sv_ks_data.state.name, "state",
		    sizeof (sv->sv_ks_data.state.name));
		sv->sv_ks_data.state.data_type = KSTAT_DATA_UINT32;
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

		ASSERT(sv->sv_magic == SMB_SERVER_MAGIC);

		sv->sv_ks_data.state.value.ui32 = sv->sv_state;
		sv->sv_ks_data.open_files.value.ui32 = sv->sv_open_files;
		sv->sv_ks_data.open_trees.value.ui32 = sv->sv_open_trees;
		sv->sv_ks_data.open_users.value.ui32 = sv->sv_open_users;
	}
	return (0);
}

/*
 * smb_server_stop
 *
 * The mutex of the server must have been entered before calling this function.
 */
static void
smb_server_stop(smb_server_t *sv)
{
	ASSERT(sv->sv_magic == SMB_SERVER_MAGIC);

	smb_opipe_door_close();
	smb_thread_stop(&sv->si_thread_timers);
	smb_kdoor_clnt_stop();
	smb_kshare_fini(sv->sv_lmshrd);
	sv->sv_lmshrd = NULL;
	smb_server_fsop_stop(sv);
	if (sv->sv_session) {
		smb_session_delete(sv->sv_session);
		sv->sv_session = NULL;
	}
}

static int
smb_server_listen(
    smb_server_t		*sv,
    smb_listener_daemon_t	*ld,
    in_port_t			port,
    int				pthread_create_error)
{
	int			rc;
	struct sonode		*s_so;
	uint32_t		on = 1;
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
		ld->ld_sin.sin_family = AF_INET;
		ld->ld_sin.sin_port = htons(port);
		ld->ld_sin.sin_addr.s_addr = htonl(INADDR_ANY);
		ld->ld_so = smb_socreate(AF_INET, SOCK_STREAM, 0);

		if (ld->ld_so) {

			(void) sosetsockopt(ld->ld_so, SOL_SOCKET,
			    SO_REUSEADDR, (const void *)&on, sizeof (on));

			rc = sobind(ld->ld_so, (struct sockaddr *)&ld->ld_sin,
			    sizeof (ld->ld_sin), 0, 0);

			if (rc == 0) {
				rc =  solisten(ld->ld_so, 20);
				if (rc < 0) {
					cmn_err(CE_WARN,
					    "Port %d: listen failed", port);
					smb_soshutdown(ld->ld_so);
					smb_sodestroy(ld->ld_so);
					ld->ld_so = NULL;
					return (rc);
				}
			} else {
				cmn_err(CE_WARN,
				    "Port %d: bind failed", port);
				smb_soshutdown(ld->ld_so);
				smb_sodestroy(ld->ld_so);
				ld->ld_so = NULL;
				return (rc);
			}
		} else {
			cmn_err(CE_WARN,
			    "Port %d: socket create failed", port);
			return (ENOMEM);
		}
	}

	DTRACE_PROBE1(so__wait__accept, struct sonode *, ld->ld_so);

	for (;;) {
		rc = soaccept(ld->ld_so, 0, &s_so);
		if (rc == 0) {
			uint32_t	txbuf_size = 128*1024;
			uint32_t	on = 1;

			DTRACE_PROBE1(so__accept, struct sonode *, s_so);

			(void) sosetsockopt(s_so, IPPROTO_TCP, TCP_NODELAY,
			    (const void *)&on, sizeof (on));
			(void) sosetsockopt(s_so, SOL_SOCKET, SO_KEEPALIVE,
			    (const void *)&on, sizeof (on));
			(void) sosetsockopt(s_so, SOL_SOCKET, SO_SNDBUF,
			    (const void *)&txbuf_size, sizeof (txbuf_size));
			/*
			 * Create a session for this connection.
			 */
			session = smb_session_create(s_so, port, sv);
			if (session) {
				smb_session_list_append(&ld->ld_session_list,
				    session);
				break;
			} else {
				smb_soshutdown(s_so);
				smb_sodestroy(s_so);
			}
			continue;
		}
		smb_session_list_signal(&ld->ld_session_list);
		smb_soshutdown(ld->ld_so);
		smb_sodestroy(ld->ld_so);
		ld->ld_so = NULL;
		break;
	}

	return (rc);
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
		ASSERT(sv->sv_magic == SMB_SERVER_MAGIC);
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
	ASSERT(sv->sv_magic == SMB_SERVER_MAGIC);

	mutex_enter(&sv->sv_mutex);
	ASSERT(sv->sv_refcnt);
	sv->sv_refcnt--;
	if ((sv->sv_refcnt == 0) && (sv->sv_state == SMB_SERVER_STATE_DELETING))
		cv_signal(&sv->sv_cv);
	mutex_exit(&sv->sv_mutex);
}

static int
smb_server_ulist_geti(
    smb_session_list_t	*se,
    int			offset,
    smb_opipe_context_t	*ctx,
    int			max_cnt)
{
	smb_session_t	*sn = NULL;
	smb_user_t	*user;
	smb_llist_t	*ulist;
	int		cnt = 0, skip = 0;

	rw_enter(&se->se_lock, RW_READER);
	sn = list_head(&se->se_act.lst);
	while (sn && (cnt < max_cnt)) {
		ASSERT(sn->s_magic == SMB_SESSION_MAGIC);
		ulist = &sn->s_user_list;
		smb_llist_enter(ulist, RW_READER);
		user = smb_llist_head(ulist);
		while (user && (cnt < max_cnt)) {
			ASSERT(user->u_magic == SMB_USER_MAGIC);
			mutex_enter(&user->u_mutex);
			if (user->u_state == SMB_USER_STATE_LOGGED_IN) {
				if (skip++ < offset) {
					mutex_exit(&user->u_mutex);
					user = smb_llist_next(ulist, user);
					continue;
				}

				smb_user_context_init(user, ctx);
				ctx++;
				cnt++;
			}
			mutex_exit(&user->u_mutex);
			user = smb_llist_next(ulist, user);
		}
		smb_llist_exit(ulist);
	}
	rw_exit(&se->se_lock);
	return (cnt);
}

static void
smb_server_store_cfg(smb_server_t *sv, smb_kmod_cfg_t *cfg)
{
	if (cfg->skc_maxconnections == 0)
		cfg->skc_maxconnections = 0xFFFFFFFF;

	smb_session_correct_keep_alive_values(
	    &sv->sv_nbt_daemon.ld_session_list, cfg->skc_keepalive);
	smb_session_correct_keep_alive_values(
	    &sv->sv_tcp_daemon.ld_session_list, cfg->skc_keepalive);

	bcopy(cfg, &sv->sv_cfg, sizeof (sv->sv_cfg));
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
