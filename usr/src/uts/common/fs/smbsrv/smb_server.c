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
 * Copyright (c) 2017 by Delphix. All rights reserved.
 * Copyright 2019 Nexenta by DDN, Inc. All rights reserved.
 * Copyright 2022 RackTop Systems, Inc.
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

#include <sys/cmn_err.h>
#include <sys/priv.h>
#include <sys/zone.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <smbsrv/smb2_kproto.h>
#include <smbsrv/string.h>
#include <smbsrv/netbios.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smb_share.h>
#include <smbsrv/smb_door.h>
#include <smbsrv/smb_kstat.h>

static void smb_server_kstat_init(smb_server_t *);
static void smb_server_kstat_fini(smb_server_t *);
static void smb_server_timers(smb_thread_t *, void *);
static void smb_server_store_cfg(smb_server_t *, smb_ioc_cfg_t *);
static void smb_server_shutdown(smb_server_t *);
static int smb_server_fsop_start(smb_server_t *);
static void smb_server_fsop_stop(smb_server_t *);
static void smb_event_cancel(smb_server_t *, uint32_t);
static uint32_t smb_event_alloc_txid(void);

static void smb_server_disconnect_share(smb_server_t *, const char *);
static void smb_server_enum_users(smb_server_t *, smb_svcenum_t *);
static void smb_server_enum_trees(smb_server_t *, smb_svcenum_t *);
static int smb_server_session_disconnect(smb_server_t *, const char *,
    const char *);
static int smb_server_fclose(smb_server_t *, uint32_t);
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
static void smb_server_destroy_session(smb_session_t *);
static uint16_t smb_spool_get_fid(smb_server_t *);
static boolean_t smb_spool_lookup_doc_byfid(smb_server_t *, uint16_t,
    smb_kspooldoc_t *);

/*
 * How many "buckets" should our hash tables use?  On a "real" server,
 * make them much larger than the number of CPUs we're likely to have.
 * On "fksmbd" make it smaller so dtrace logs are shorter.
 * These must be powers of two.
 */
#ifdef	_KERNEL
#define	DEFAULT_HASH_NBUCKETS	256	/* real server */
#else
#define	DEFAULT_HASH_NBUCKETS	16	/* for "fksmbd" */
#endif
uint32_t SMB_OFILE_HASH_NBUCKETS = DEFAULT_HASH_NBUCKETS;
uint32_t SMB_LEASE_HASH_NBUCKETS = DEFAULT_HASH_NBUCKETS;

int smb_event_debug = 0;

static smb_llist_t	smb_servers;

/* for smb_server_destroy_session() */
static smb_llist_t smb_server_session_zombies;

kmem_cache_t		*smb_cache_request;
kmem_cache_t		*smb_cache_session;
kmem_cache_t		*smb_cache_user;
kmem_cache_t		*smb_cache_tree;
kmem_cache_t		*smb_cache_ofile;
kmem_cache_t		*smb_cache_odir;
kmem_cache_t		*smb_cache_opipe;
kmem_cache_t		*smb_cache_event;
kmem_cache_t		*smb_cache_lock;

/*
 * *****************************************************************************
 * **************** Functions called from the device interface *****************
 * *****************************************************************************
 *
 * These functions typically have to determine the relevant smb server
 * to which the call applies.
 */

/*
 * How many zones have an SMB server active?
 */
int
smb_server_get_count(void)
{
	return (smb_llist_get_count(&smb_servers));
}

/*
 * smb_server_g_init
 *
 * This function must be called from smb_drv_attach().
 */
int
smb_server_g_init(void)
{
	int rc;

	if ((rc = smb_vop_init()) != 0)
		goto errout;
	if ((rc = smb_fem_init()) != 0)
		goto errout;

	smb_kshare_g_init();
	smb_codepage_init();
	smb_mbc_init();		/* smb_mbc_cache */
	smb_node_init();	/* smb_node_cache, lists */
	smb2_lease_init();

	smb_cache_request = kmem_cache_create("smb_request_cache",
	    sizeof (smb_request_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
	smb_cache_session = kmem_cache_create("smb_session_cache",
	    sizeof (smb_session_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
	smb_cache_user = kmem_cache_create("smb_user_cache",
	    sizeof (smb_user_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
	smb_cache_tree = kmem_cache_create("smb_tree_cache",
	    sizeof (smb_tree_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
	smb_cache_ofile = kmem_cache_create("smb_ofile_cache",
	    sizeof (smb_ofile_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
	smb_cache_odir = kmem_cache_create("smb_odir_cache",
	    sizeof (smb_odir_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
	smb_cache_opipe = kmem_cache_create("smb_opipe_cache",
	    sizeof (smb_opipe_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
	smb_cache_event = kmem_cache_create("smb_event_cache",
	    sizeof (smb_event_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
	smb_cache_lock = kmem_cache_create("smb_lock_cache",
	    sizeof (smb_lock_t), 8, NULL, NULL, NULL, NULL, NULL, 0);

	smb_llist_init();
	smb_llist_constructor(&smb_servers, sizeof (smb_server_t),
	    offsetof(smb_server_t, sv_lnd));

	smb_llist_constructor(&smb_server_session_zombies,
	    sizeof (smb_session_t), offsetof(smb_session_t, s_lnd));

	return (0);

errout:
	smb_fem_fini();
	smb_vop_fini();
	return (rc);
}

/*
 * smb_server_g_fini
 *
 * This function must called from smb_drv_detach(). It will fail if servers
 * still exist.
 */
void
smb_server_g_fini(void)
{

	ASSERT(smb_llist_get_count(&smb_servers) == 0);

	smb_llist_fini();

	kmem_cache_destroy(smb_cache_request);
	kmem_cache_destroy(smb_cache_session);
	kmem_cache_destroy(smb_cache_user);
	kmem_cache_destroy(smb_cache_tree);
	kmem_cache_destroy(smb_cache_ofile);
	kmem_cache_destroy(smb_cache_odir);
	kmem_cache_destroy(smb_cache_opipe);
	kmem_cache_destroy(smb_cache_event);
	kmem_cache_destroy(smb_cache_lock);

	smb2_lease_fini();
	smb_node_fini();
	smb_mbc_fini();
	smb_codepage_fini();
	smb_kshare_g_fini();

	smb_fem_fini();
	smb_vop_fini();

	smb_llist_destructor(&smb_servers);
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

	sv = kmem_zalloc(sizeof (smb_server_t), KM_SLEEP);

	sv->sv_magic = SMB_SERVER_MAGIC;
	sv->sv_state = SMB_SERVER_STATE_CREATED;
	sv->sv_zid = zid;
	sv->sv_pid = ddi_get_pid();

	mutex_init(&sv->sv_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sv->sv_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&sv->sp_info.sp_cv, NULL, CV_DEFAULT, NULL);

	sv->sv_persistid_ht = smb_hash_create(sizeof (smb_ofile_t),
	    offsetof(smb_ofile_t, f_dh_lnd), SMB_OFILE_HASH_NBUCKETS);

	sv->sv_lease_ht = smb_hash_create(sizeof (smb_lease_t),
	    offsetof(smb_lease_t, ls_lnd), SMB_LEASE_HASH_NBUCKETS);

	smb_llist_constructor(&sv->sv_session_list, sizeof (smb_session_t),
	    offsetof(smb_session_t, s_lnd));

	smb_llist_constructor(&sv->sv_event_list, sizeof (smb_event_t),
	    offsetof(smb_event_t, se_lnd));

	smb_llist_constructor(&sv->sp_info.sp_list, sizeof (smb_kspooldoc_t),
	    offsetof(smb_kspooldoc_t, sd_lnd));

	smb_llist_constructor(&sv->sp_info.sp_fidlist,
	    sizeof (smb_spoolfid_t), offsetof(smb_spoolfid_t, sf_lnd));

	sv->sv_disp_stats1 = kmem_zalloc(SMB_COM_NUM *
	    sizeof (smb_disp_stats_t), KM_SLEEP);

	sv->sv_disp_stats2 = kmem_zalloc(SMB2__NCMDS *
	    sizeof (smb_disp_stats_t), KM_SLEEP);

	smb_thread_init(&sv->si_thread_timers, "smb_timers",
	    smb_server_timers, sv, smbsrv_timer_pri);

	smb_srqueue_init(&sv->sv_srqueue);

	smb_kdoor_init(sv);
	smb_kshare_init(sv);
	smb_server_kstat_init(sv);

	smb_threshold_init(&sv->sv_ssetup_ct, SMB_SSETUP_CMD,
	    smb_ssetup_threshold, smb_ssetup_timeout);
	smb_threshold_init(&sv->sv_tcon_ct, SMB_TCON_CMD,
	    smb_tcon_threshold, smb_tcon_timeout);
	smb_threshold_init(&sv->sv_opipe_ct, SMB_OPIPE_CMD,
	    smb_opipe_threshold, smb_opipe_timeout);

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
smb_server_delete(smb_server_t	*sv)
{

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

	smb_threshold_fini(&sv->sv_ssetup_ct);
	smb_threshold_fini(&sv->sv_tcon_ct);
	smb_threshold_fini(&sv->sv_opipe_ct);

	smb_server_listener_destroy(&sv->sv_nbt_daemon);
	smb_server_listener_destroy(&sv->sv_tcp_daemon);
	rw_destroy(&sv->sv_cfg_lock);
	smb_server_kstat_fini(sv);
	smb_kshare_fini(sv);
	smb_kdoor_fini(sv);
	smb_llist_destructor(&sv->sv_event_list);
	smb_llist_destructor(&sv->sv_session_list);

	kmem_free(sv->sv_disp_stats1,
	    SMB_COM_NUM * sizeof (smb_disp_stats_t));

	kmem_free(sv->sv_disp_stats2,
	    SMB2__NCMDS * sizeof (smb_disp_stats_t));

	smb_srqueue_destroy(&sv->sv_srqueue);
	smb_thread_destroy(&sv->si_thread_timers);

	mutex_destroy(&sv->sv_mutex);
	smb_hash_destroy(sv->sv_lease_ht);
	smb_hash_destroy(sv->sv_persistid_ht);
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

	/*
	 * Reality check negotiation token length vs. #define'd maximum.
	 */
	if (ioc->negtok_len > SMB_PI_MAX_NEGTOK)
		return (EINVAL);

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
	cred_t		*ucr;

	rc = smb_server_lookup(&sv);
	if (rc)
		return (rc);

	mutex_enter(&sv->sv_mutex);
	switch (sv->sv_state) {
	case SMB_SERVER_STATE_CONFIGURED:

		if ((rc = smb_server_fsop_start(sv)) != 0)
			break;

		/*
		 * Note: smb_kshare_start needs sv_session.
		 */
		sv->sv_session = smb_session_create(NULL, 0, sv, 0);
		if (sv->sv_session == NULL) {
			rc = ENOMEM;
			break;
		}

		/*
		 * Create a logon on the server session,
		 * used when importing CA shares.
		 */
		sv->sv_rootuser = smb_user_new(sv->sv_session);
		ucr = smb_kcred_create();
		rc = smb_user_logon(sv->sv_rootuser, ucr, "", "root",
		    SMB_USER_FLAG_ADMIN, 0, 0);
		crfree(ucr);
		ucr = NULL;
		if (rc != 0) {
			cmn_err(CE_NOTE, "smb_server_start: "
			    "failed to create root user");
			break;
		}

		if ((rc = smb_kshare_start(sv)) != 0)
			break;

		/*
		 * NB: the proc passed here has to be a "system" one.
		 * Normally that's p0, or the NGZ eqivalent.
		 */
		sv->sv_worker_pool = taskq_create_proc("smb_workers",
		    sv->sv_cfg.skc_maxworkers, smbsrv_worker_pri,
		    sv->sv_cfg.skc_maxworkers, INT_MAX,
		    curzone->zone_zsched, TASKQ_DYNAMIC);

		sv->sv_receiver_pool = taskq_create_proc("smb_receivers",
		    sv->sv_cfg.skc_maxconnections, smbsrv_receive_pri,
		    sv->sv_cfg.skc_maxconnections, INT_MAX,
		    curzone->zone_zsched, TASKQ_DYNAMIC);

		if (sv->sv_worker_pool == NULL ||
		    sv->sv_receiver_pool == NULL) {
			rc = ENOMEM;
			break;
		}

#ifdef	_KERNEL
		ASSERT(sv->sv_lmshrd == NULL);
		sv->sv_lmshrd = smb_kshare_door_init(ioc->lmshrd);
		if (sv->sv_lmshrd == NULL)
			break;
		if ((rc = smb_kdoor_open(sv, ioc->udoor)) != 0) {
			cmn_err(CE_WARN, "Cannot open smbd door");
			break;
		}
#else	/* _KERNEL */
		/* Fake kernel does not use the kshare_door */
		fksmb_kdoor_open(sv, ioc->udoor_func);
#endif	/* _KERNEL */

		if ((rc = smb_thread_start(&sv->si_thread_timers)) != 0)
			break;

		family = AF_INET;
		smb_server_listener_init(sv, &sv->sv_nbt_daemon,
		    "smb_nbt_listener", IPPORT_NETBIOS_SSN, family);
		if (sv->sv_cfg.skc_ipv6_enable)
			family = AF_INET6;
		smb_server_listener_init(sv, &sv->sv_tcp_daemon,
		    "smb_tcp_listener", IPPORT_SMB, family);
		rc = smb_server_listener_start(&sv->sv_tcp_daemon);
		if (rc != 0)
			break;
		if (sv->sv_cfg.skc_netbios_enable)
			(void) smb_server_listener_start(&sv->sv_nbt_daemon);

		sv->sv_state = SMB_SERVER_STATE_RUNNING;
		sv->sv_start_time = gethrtime();
		mutex_exit(&sv->sv_mutex);
		smb_server_release(sv);
		smb_export_start(sv);
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
smb_server_is_stopping(smb_server_t *sv)
{
	boolean_t	status;

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
	return (status);
}

void
smb_server_cancel_event(smb_server_t *sv, uint32_t txid)
{
	smb_event_cancel(sv, txid);
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
	uint32_t	buflen_adjusted;

	/*
	 * Reality check that the buffer-length insize the enum doesn't
	 * overrun the ioctl's total length.
	 *
	 * NOTE: Assume se_buf is at the end of smb_svcenum_t.
	 */
	buflen_adjusted = svcenum->se_buflen +
	    offsetof(smb_svcenum_t, se_buf) + sizeof (ioc->hdr);
	if (buflen_adjusted < svcenum->se_buflen ||	/* Overflow check 1, */
	    buflen_adjusted < offsetof(smb_svcenum_t, se_buf) || /* check 2, */
	    buflen_adjusted < sizeof (ioc->hdr) ||	/* check 3. */
	    buflen_adjusted > ioc->hdr.len) {
		return (EINVAL);
	}

	/*
	 * Reality check that the buffer-length insize the enum doesn't
	 * overrun the ioctl's total length.
	 */
	if (svcenum->se_buflen + sizeof (*ioc) > ioc->hdr.len)
		return (EINVAL);

	if ((rc = smb_server_lookup(&sv)) != 0)
		return (rc);

	svcenum->se_bavail = svcenum->se_buflen;
	svcenum->se_bused = 0;
	svcenum->se_nitems = 0;

	switch (svcenum->se_type) {
	case SMB_SVCENUM_TYPE_USER:
		smb_server_enum_users(sv, svcenum);
		break;
	case SMB_SVCENUM_TYPE_TREE:
	case SMB_SVCENUM_TYPE_FILE:
		smb_server_enum_trees(sv, svcenum);
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
	smb_server_t	*sv;
	int		cnt;
	int		rc;

	if ((rc = smb_server_lookup(&sv)) != 0)
		return (rc);

	cnt = smb_server_session_disconnect(sv, ioc->client, ioc->username);

	smb_server_release(sv);

	if (cnt == 0)
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
	smb_server_t	*sv;
	int		rc;

	if ((rc = smb_server_lookup(&sv)) != 0)
		return (rc);

	rc = smb_server_fclose(sv, uniqid);

	smb_server_release(sv);
	return (rc);
}

/*
 * These functions determine the relevant smb server to which the call apply.
 */

uint32_t
smb_server_get_session_count(smb_server_t *sv)
{
	uint32_t	counter = 0;

	counter = smb_llist_get_count(&sv->sv_session_list);

	return (counter);
}

/*
 * Gets the smb_node of the specified share path.
 * Node is returned held (caller must rele.)
 */
int
smb_server_share_lookup(smb_server_t *sv, const char *shr_path,
    smb_node_t **nodepp)
{
	smb_request_t	*sr;
	smb_node_t	*fnode = NULL;
	smb_node_t	*dnode = NULL;
	char		last_comp[MAXNAMELEN];
	int		rc = 0;

	ASSERT(shr_path);

	mutex_enter(&sv->sv_mutex);
	switch (sv->sv_state) {
	case SMB_SERVER_STATE_RUNNING:
		break;
	default:
		mutex_exit(&sv->sv_mutex);
		return (ENOTACTIVE);
	}
	mutex_exit(&sv->sv_mutex);

	if ((sr = smb_request_alloc(sv->sv_session, 0)) == NULL) {
		return (ENOTCONN);
	}
	sr->user_cr = zone_kcred();

	rc = smb_pathname_reduce(sr, sr->user_cr, shr_path,
	    NULL, NULL, &dnode, last_comp);

	if (rc == 0) {
		rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS,
		    sv->si_root_smb_node, dnode, last_comp, &fnode);
		smb_node_release(dnode);
	}

	smb_request_free(sr);

	if (rc != 0)
		return (rc);

	ASSERT(fnode->vp && fnode->vp->v_vfsp);

	*nodepp = fnode;

	return (0);
}

#ifdef	_KERNEL
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
#endif	/* _KERNEL */

int
smb_server_unshare(const char *sharename)
{
	smb_server_t	*sv;
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

	smb_server_disconnect_share(sv, sharename);

	smb_server_release(sv);
	return (0);
}

/*
 * Disconnect the specified share.
 * Typically called when a share has been removed.
 */
static void
smb_server_disconnect_share(smb_server_t *sv, const char *sharename)
{
	smb_llist_t	*ll;
	smb_session_t	*session;

	ll = &sv->sv_session_list;
	smb_llist_enter(ll, RW_READER);

	session = smb_llist_head(ll);
	while (session) {
		SMB_SESSION_VALID(session);
		smb_rwx_rwenter(&session->s_lock, RW_READER);
		switch (session->s_state) {
		case SMB_SESSION_STATE_NEGOTIATED:
			smb_rwx_rwexit(&session->s_lock);
			smb_session_disconnect_share(session, sharename);
			break;
		default:
			smb_rwx_rwexit(&session->s_lock);
			break;
		}
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

	/*
	 * This kills old inactive sessions and expired durable
	 * handles. The session code expects one call per minute.
	 */
	while (smb_thread_continue_timedwait(thread, 60 /* Seconds */)) {
		if (sv->sv_cfg.skc_keepalive != 0)
			smb_session_timers(sv);
		smb2_durable_timers(sv);
	}
}

/*
 * smb_server_kstat_init
 */
static void
smb_server_kstat_init(smb_server_t *sv)
{

	sv->sv_ksp = kstat_create_zone(SMBSRV_KSTAT_MODULE, 0,
	    SMBSRV_KSTAT_STATISTICS, SMBSRV_KSTAT_CLASS, KSTAT_TYPE_RAW,
	    sizeof (smbsrv_kstats_t), 0, sv->sv_zid);

	if (sv->sv_ksp != NULL) {
		sv->sv_ksp->ks_update = smb_server_kstat_update;
		sv->sv_ksp->ks_private = sv;
		((smbsrv_kstats_t *)sv->sv_ksp->ks_data)->ks_start_time =
		    sv->sv_start_time;
		smb_dispatch_stats_init(sv);
		smb2_dispatch_stats_init(sv);
		kstat_install(sv->sv_ksp);
	} else {
		cmn_err(CE_WARN, "SMB Server: Statistics unavailable");
	}

	sv->sv_legacy_ksp = kstat_create_zone(SMBSRV_KSTAT_MODULE, 0,
	    SMBSRV_KSTAT_NAME, SMBSRV_KSTAT_CLASS, KSTAT_TYPE_NAMED,
	    sizeof (smb_server_legacy_kstat_t) / sizeof (kstat_named_t),
	    0, sv->sv_zid);

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
		smb_dispatch_stats_fini(sv);
		smb2_dispatch_stats_fini(sv);
	}
}

/*
 * Verify the defines in smb_kstat.h used by ks_reqs1 ks_reqs2
 */
CTASSERT(SMBSRV_KS_NREQS1 == SMB_COM_NUM);
CTASSERT(SMBSRV_KS_NREQS2 == SMB2__NCMDS);

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
		smb_dispatch_stats_update(sv, ksd->ks_reqs1, 0, SMB_COM_NUM);
		smb2_dispatch_stats_update(sv, ksd->ks_reqs2, 0, SMB2__NCMDS);
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
		/* FALLTHROUGH */
	default:
		rc = EIO;
		break;
	}
	return (rc);

}

int smb_server_shutdown_wait1 = 15;	/* seconds */

/*
 * smb_server_shutdown
 */
static void
smb_server_shutdown(smb_server_t *sv)
{
	smb_llist_t *sl = &sv->sv_session_list;
	smb_session_t *session;
	clock_t	time0, time1, time2;

	SMB_SERVER_VALID(sv);

	/*
	 * Stop the listeners first, so we can't get any more
	 * new sessions while we're trying to shut down.
	 */
	smb_server_listener_stop(&sv->sv_nbt_daemon);
	smb_server_listener_stop(&sv->sv_tcp_daemon);

	/*
	 * Disconnect all of the sessions. This causes all the
	 * smb_server_receiver threads to see a disconnect and
	 * begin tear-down (in parallel) in smb_session_cancel.
	 */
	smb_llist_enter(sl, RW_READER);
	session = smb_llist_head(sl);
	while (session != NULL) {
		smb_session_disconnect(session);
		session = smb_llist_next(sl, session);
	}
	smb_llist_exit(sl);

	/*
	 * Wake up any threads we might have blocked.
	 * Must precede kdoor_close etc. because those will
	 * wait for such threads to get out.
	 */
	smb_event_cancel(sv, 0);
	smb_threshold_wake_all(&sv->sv_ssetup_ct);
	smb_threshold_wake_all(&sv->sv_tcon_ct);
	smb_threshold_wake_all(&sv->sv_opipe_ct);

	/*
	 * Wait for the session list to empty.
	 * (cv_signal in smb_server_destroy_session)
	 *
	 * We must wait for all the SMB session readers to finish, or
	 * we could proceed here while there might be worker threads
	 * running in any of those sessions.  See smb_session_logoff
	 * for timeouts applied to session tear-down. If this takes
	 * longer than expected, make some noise, and fire a dtrace
	 * probe one might use to investigate.
	 */
	time0 = ddi_get_lbolt();
	time1 = SEC_TO_TICK(smb_server_shutdown_wait1) + time0;
	mutex_enter(&sv->sv_mutex);
	while (sv->sv_session_list.ll_count != 0) {
		if (cv_timedwait(&sv->sv_cv, &sv->sv_mutex, time1) < 0) {
			cmn_err(CE_NOTE, "!shutdown waited %d seconds"
			    " with %d sessions still remaining",
			    smb_server_shutdown_wait1,
			    sv->sv_session_list.ll_count);
			DTRACE_PROBE1(max__wait, smb_server_t *, sv);
			break;
		}
	}
	while (sv->sv_session_list.ll_count != 0) {
		cv_wait(&sv->sv_cv, &sv->sv_mutex);
	}
	mutex_exit(&sv->sv_mutex);

	time2 = ddi_get_lbolt();
	if (time2 > time1) {
		cmn_err(CE_NOTE, "!shutdown waited %d seconds"
		    " for all sessions to finish",
		    (int)TICK_TO_SEC(time2 - time0));
	}

	smb_kdoor_close(sv);
#ifdef	_KERNEL
	smb_kshare_door_fini(sv->sv_lmshrd);
#endif	/* _KERNEL */
	sv->sv_lmshrd = NULL;

	smb_export_stop(sv);
	smb_kshare_stop(sv);
	smb_thread_stop(&sv->si_thread_timers);

	/*
	 * Both kshare and the oplock break sub-systems may have
	 * taskq jobs on the spcial "server" session, until we've
	 * closed all ofiles and stopped the kshare exporter.
	 * Now it's safe to destroy the server session, but first
	 * wait for any requests on it to finish.  Note that for
	 * normal sessions, this happens in smb_session_cancel,
	 * but that's not called for the server session.
	 */
	if (sv->sv_rootuser != NULL) {
		smb_user_logoff(sv->sv_rootuser);
		smb_user_release(sv->sv_rootuser);
		sv->sv_rootuser = NULL;
	}
	if (sv->sv_session != NULL) {
		smb_session_cancel_requests(sv->sv_session, NULL, NULL);
		smb_slist_wait_for_empty(&sv->sv_session->s_req_list);

		/* Just in case import left users and trees */
		smb_session_logoff(sv->sv_session);

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

	/*
	 * Clean out any durable handles.  After this we should
	 * have no ofiles remaining (and no more oplock breaks).
	 */
	smb2_dh_shutdown(sv);

	smb_server_fsop_stop(sv);
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

	smb_thread_init(&ld->ld_thread, name, smb_server_listener, ld,
	    smbsrv_listen_pri);
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
	/*
	 * Note that if startup fails early, we can legitimately
	 * get here with an all-zeros object.
	 */
	if (ld->ld_magic == 0)
		return;

	SMB_LISTENER_VALID(ld);
	ASSERT(ld->ld_so == NULL);
	smb_thread_destroy(&ld->ld_thread);
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
	ksocket_t		s_so;
	int			on;
	int			txbuf_size;

	ld = (smb_listener_daemon_t *)arg;

	SMB_LISTENER_VALID(ld);

	DTRACE_PROBE1(so__wait__accept, struct sonode *, ld->ld_so);

	while (smb_thread_continue_nowait(&ld->ld_thread) &&
	    ld->ld_sv->sv_state != SMB_SERVER_STATE_STOPPING) {
		int ret = ksocket_accept(ld->ld_so, NULL, NULL, &s_so, CRED());

		switch (ret) {
		case 0:
			break;
		case ECONNABORTED:
			continue;

		case EINTR:
		case EBADF:
		case ENOTSOCK:
			/* These are normal during shutdown. Silence. */
			if (ld->ld_sv->sv_state == SMB_SERVER_STATE_STOPPING)
				goto out;
			/* FALLTHROUGH */
		default:
			cmn_err(CE_WARN,
			    "smb_server_listener: ksocket_accept failed (%d)",
			    ret);
			/* avoid a tight CPU-burn loop here */
			delay(MSEC_TO_TICK(10));
			continue;
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
		smb_server_create_session(ld, s_so);
	}
out:
	ksocket_rele(ld->ld_so);
}

/*
 * smb_server_receiver
 *
 * Entry point of the receiver threads.
 * Also does cleanup when socket disconnected.
 */
static void
smb_server_receiver(void *arg)
{
	smb_session_t	*session;

	session = (smb_session_t *)arg;

	/* We stay in here until socket disconnect. */
	smb_session_receiver(session);

	smb_server_destroy_session(session);
}

/*
 * smb_server_lookup
 *
 * This function finds the server associated with the zone of the
 * caller.  Note: requires a fix in the dynamic taskq code:
 * 1501 taskq_create_proc ... TQ_DYNAMIC puts tasks in p0
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
smb_server_enum_users(smb_server_t *sv, smb_svcenum_t *svcenum)
{
	smb_llist_t	*ll = &sv->sv_session_list;
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
smb_server_enum_trees(smb_server_t *sv, smb_svcenum_t *svcenum)
{
	smb_llist_t	*ll = &sv->sv_session_list;
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
smb_server_session_disconnect(smb_server_t *sv,
    const char *client, const char *name)
{
	smb_llist_t	*ll = &sv->sv_session_list;
	smb_session_t	*sn;
	smb_llist_t	*ulist;
	smb_user_t	*user;
	int		count = 0;

	smb_llist_enter(ll, RW_READER);

	for (sn = smb_llist_head(ll);
	    sn != NULL;
	    sn = smb_llist_next(ll, sn)) {
		SMB_SESSION_VALID(sn);

		if (*client != '\0' && !smb_session_isclient(sn, client))
			continue;

		ulist = &sn->s_user_list;
		smb_llist_enter(ulist, RW_READER);

		for (user = smb_llist_head(ulist);
		    user != NULL;
		    user = smb_llist_next(ulist, user)) {

			if (smb_user_hold(user)) {

				if (*name == '\0' ||
				    smb_user_namecmp(user, name)) {
					smb_user_logoff(user);
					count++;
				}

				smb_user_release(user);
			}
		}

		smb_llist_exit(ulist);
	}

	smb_llist_exit(ll);
	return (count);
}

/*
 * Close a file by its unique id.
 */
static int
smb_server_fclose(smb_server_t *sv, uint32_t uniqid)
{
	smb_llist_t	*ll;
	smb_session_t	*sn;
	smb_llist_t	*tlist;
	smb_tree_t	*tree;
	int		rc = ENOENT;

	ll = &sv->sv_session_list;
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

/*
 * This is used by SMB2 session setup to logoff a previous session,
 * so it can force a logoff that we haven't noticed yet.
 * This is not called frequently, so we just walk the list of
 * connections searching for the user.
 *
 * Note that this must wait for any durable handles (ofiles)
 * owned by this user to become "orphaned", so that a reconnect
 * that may immediately follow can find and use such ofiles.
 */
void
smb_server_logoff_ssnid(smb_request_t *sr, uint64_t ssnid)
{
	smb_server_t	*sv = sr->sr_server;
	smb_llist_t	*sess_list;
	smb_session_t	*sess;
	smb_user_t	*user = NULL;

	SMB_SERVER_VALID(sv);

	if (sv->sv_state != SMB_SERVER_STATE_RUNNING)
		return;

	sess_list = &sv->sv_session_list;
	smb_llist_enter(sess_list, RW_READER);

	for (sess = smb_llist_head(sess_list);
	    sess != NULL;
	    sess = smb_llist_next(sess_list, sess)) {

		SMB_SESSION_VALID(sess);

		if (sess->dialect < SMB_VERS_2_BASE)
			continue;

		switch (sess->s_state) {
		case SMB_SESSION_STATE_NEGOTIATED:
		case SMB_SESSION_STATE_TERMINATED:
		case SMB_SESSION_STATE_DISCONNECTED:
			break;
		default:
			continue;
		}

		/*
		 * Normal situation is to find a LOGGED_ON user.
		 */
		user = smb_session_lookup_uid_st(sess, ssnid, 0,
		    SMB_USER_STATE_LOGGED_ON);
		if (user != NULL) {

			if (smb_is_same_user(user->u_cred, sr->user_cr)) {
				/* Treat this as if we lost the connection */
				user->preserve_opens = SMB2_DH_PRESERVE_SOME;
				smb_user_logoff(user);
				break;
			}
			smb_user_release(user);
			user = NULL;
		}

		/*
		 * If we raced with disconnect, may find LOGGING_OFF,
		 * in which case we want to just wait for it.
		 */
		user = smb_session_lookup_uid_st(sess, ssnid, 0,
		    SMB_USER_STATE_LOGGING_OFF);
		if (user != NULL) {
			if (smb_is_same_user(user->u_cred, sr->user_cr))
				break;
			smb_user_release(user);
			user = NULL;
		}
	}

	smb_llist_exit(sess_list);

	if (user != NULL) {
		/*
		 * Wait for durable handles to be orphaned.
		 * Note: not holding the sess list rwlock.
		 */
		smb_user_wait_trees(user);

		/*
		 * Could be doing the last release on a user below,
		 * which can leave work on the delete queues for
		 * s_user_list or s_tree_list so flush those.
		 * Must hold the session list after the user release
		 * so that the session can't go away while we flush.
		 */
		smb_llist_enter(sess_list, RW_READER);

		sess = user->u_session;
		smb_user_release(user);

		smb_llist_flush(&sess->s_tree_list);
		smb_llist_flush(&sess->s_user_list);

		smb_llist_exit(sess_list);
	}
}

/* See also: libsmb smb_kmod_setcfg */
static void
smb_server_store_cfg(smb_server_t *sv, smb_ioc_cfg_t *ioc)
{
	if (ioc->maxconnections == 0)
		ioc->maxconnections = 0xFFFFFFFF;

	if (ioc->encrypt == SMB_CONFIG_REQUIRED &&
	    ioc->max_protocol < SMB_VERS_3_0) {
		cmn_err(CE_WARN, "Server set to require encryption; "
		    "forcing max_protocol to 3.0");
		ioc->max_protocol = SMB_VERS_3_0;
	}
	sv->sv_cfg.skc_maxworkers = ioc->maxworkers;
	sv->sv_cfg.skc_maxconnections = ioc->maxconnections;
	sv->sv_cfg.skc_keepalive = ioc->keepalive;
	sv->sv_cfg.skc_restrict_anon = ioc->restrict_anon;
	sv->sv_cfg.skc_signing_enable = ioc->signing_enable;
	sv->sv_cfg.skc_signing_required = ioc->signing_required;
	sv->sv_cfg.skc_oplock_enable = ioc->oplock_enable;
	sv->sv_cfg.skc_sync_enable = ioc->sync_enable;
	sv->sv_cfg.skc_secmode = ioc->secmode;
	sv->sv_cfg.skc_netbios_enable = ioc->netbios_enable;
	sv->sv_cfg.skc_ipv6_enable = ioc->ipv6_enable;
	sv->sv_cfg.skc_print_enable = ioc->print_enable;
	sv->sv_cfg.skc_traverse_mounts = ioc->traverse_mounts;
	sv->sv_cfg.skc_short_names = ioc->short_names;
	sv->sv_cfg.skc_max_protocol = ioc->max_protocol;
	sv->sv_cfg.skc_min_protocol = ioc->min_protocol;
	sv->sv_cfg.skc_encrypt = ioc->encrypt;
	sv->sv_cfg.skc_encrypt_ciphers = ioc->encrypt_ciphers;
	sv->sv_cfg.skc_execflags = ioc->exec_flags;
	sv->sv_cfg.skc_negtok_len = ioc->negtok_len;
	sv->sv_cfg.skc_max_opens = ioc->max_opens;
	sv->sv_cfg.skc_version = ioc->version;
	sv->sv_cfg.skc_initial_credits = ioc->initial_credits;
	sv->sv_cfg.skc_maximum_credits = ioc->maximum_credits;

	(void) memcpy(sv->sv_cfg.skc_machine_uuid, ioc->machine_uuid,
	    sizeof (uuid_t));
	(void) memcpy(sv->sv_cfg.skc_negtok, ioc->negtok,
	    sizeof (sv->sv_cfg.skc_negtok));
	(void) memcpy(sv->sv_cfg.skc_native_os, ioc->native_os,
	    sizeof (sv->sv_cfg.skc_native_os));
	(void) memcpy(sv->sv_cfg.skc_native_lm, ioc->native_lm,
	    sizeof (sv->sv_cfg.skc_native_lm));

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

	error = smb_node_root_init(sv, &sv->si_root_smb_node);
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
smb_event_create(smb_server_t *sv, int timeout)
{
	smb_event_t	*event;

	if (smb_server_is_stopping(sv))
		return (NULL);

	event = kmem_cache_alloc(smb_cache_event, KM_SLEEP);

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
	sv = event->se_server;
	SMB_SERVER_VALID(sv);

	smb_llist_enter(&sv->sv_event_list, RW_WRITER);
	smb_llist_remove(&sv->sv_event_list, event);
	smb_llist_exit(&sv->sv_event_list);

	event->se_magic = (uint32_t)~SMB_EVENT_MAGIC;
	cv_destroy(&event->se_cv);
	mutex_destroy(&event->se_mutex);

	kmem_cache_free(smb_cache_event, event);
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
	int	err;

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

	err = event->se_errno;
	event->se_waittime = 0;
	event->se_notified = B_FALSE;
	cv_signal(&event->se_cv);
	mutex_exit(&event->se_mutex);
	return (err);
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
smb_spool_add_doc(smb_tree_t *tree, smb_kspooldoc_t *sp)
{
	smb_llist_t	*splist;
	smb_server_t	*sv = tree->t_server;
	int rc = 0;

	splist = &sv->sp_info.sp_list;
	smb_llist_enter(splist, RW_WRITER);
	sp->sd_spool_num = atomic_inc_32_nv(&sv->sp_info.sp_cnt);
	smb_llist_insert_tail(splist, sp);
	smb_llist_exit(splist);

	return (rc);
}

/*
 * smb_server_create_session
 */
static void
smb_server_create_session(smb_listener_daemon_t *ld, ksocket_t s_so)
{
	smb_server_t		*sv = ld->ld_sv;
	smb_session_t		*session;
	smb_llist_t		*sl;
	taskqid_t		tqid;
	clock_t			now;

	session = smb_session_create(s_so, ld->ld_port, sv,
	    ld->ld_family);

	if (session == NULL) {
		/* This should be rare (create sleeps) */
		smb_soshutdown(s_so);
		smb_sodestroy(s_so);
		cmn_err(CE_WARN, "SMB Session: alloc failed");
		return;
	}

	sl = &sv->sv_session_list;
	smb_llist_enter(sl, RW_WRITER);
	if (smb_llist_get_count(sl) >= sv->sv_cfg.skc_maxconnections) {
		/*
		 * New session not in sv_session_list, so we can just
		 * delete it directly.
		 */
		smb_llist_exit(sl);
		DTRACE_PROBE1(maxconn, smb_session_t *, session);
		smb_soshutdown(session->sock);
		smb_session_delete(session);
		goto logmaxconn;
	}
	smb_llist_insert_tail(sl, session);
	smb_llist_exit(sl);

	/*
	 * These taskq entries must run independently of one another,
	 * so TQ_NOQUEUE.  TQ_SLEEP (==0) just for clarity.
	 */
	tqid = taskq_dispatch(sv->sv_receiver_pool,
	    smb_server_receiver, session, TQ_NOQUEUE | TQ_SLEEP);
	if (tqid != TASKQID_INVALID) {
		/* Success */
		return;
	}

	/*
	 * Have: tqid == TASKQID_INVALID
	 * We never entered smb_server_receiver()
	 * so need to do its return cleanup
	 */
	DTRACE_PROBE1(maxconn, smb_session_t *, session);
	smb_session_disconnect(session);
	smb_session_logoff(session);
	smb_server_destroy_session(session);

logmaxconn:
	/*
	 * If we hit max_connections, log something so an admin
	 * can find out why new connections are failing, but
	 * log this no more than once a minute.
	 */
	now = ddi_get_lbolt();
	if (now > ld->ld_quiet) {
		ld->ld_quiet = now + SEC_TO_TICK(60);
		cmn_err(CE_WARN, "SMB can't create session: "
		    "Would exceed max_connections.");
	}
}

static void
smb_server_destroy_session(smb_session_t *session)
{
	smb_server_t *sv;
	smb_llist_t *ll;
	uint32_t count;

	ASSERT(session->s_server != NULL);
	sv = session->s_server;
	ll = &sv->sv_session_list;

	smb_llist_flush(&session->s_tree_list);
	smb_llist_flush(&session->s_user_list);

	smb_llist_enter(ll, RW_WRITER);
	smb_llist_remove(ll, session);
	count = ll->ll_count;
	smb_llist_exit(ll);

	/*
	 * Normally, the session should have state SHUTDOWN here.
	 * If the session has any ofiles remaining, eg. due to
	 * forgotten ofile references or something, the state
	 * will be _DISCONNECTED or _TERMINATED.  Keep such
	 * sessions in the list of zombies (for debugging).
	 */
	if (session->s_state == SMB_SESSION_STATE_SHUTDOWN) {
		smb_session_delete(session);
	} else {
		cmn_err(CE_NOTE, "!Leaked session: 0x%p", (void *)session);
		DTRACE_PROBE1(new__zombie, smb_session_t *, session);
		smb_llist_enter(&smb_server_session_zombies, RW_WRITER);
		smb_llist_insert_head(&smb_server_session_zombies, session);
		smb_llist_exit(&smb_server_session_zombies);
	}

	if (count == 0) {
		/* See smb_server_shutdown */
		cv_signal(&sv->sv_cv);
	}
}
