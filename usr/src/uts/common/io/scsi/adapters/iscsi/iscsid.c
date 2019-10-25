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
 * Copyright 2019 Joshua M. Clulow <josh@sysmgr.org>
 */

/*
 * ISCSID --
 *
 * Discovery of targets and access to the persistent storage starts here.
 */

#include <sys/thread.h>
#include <sys/types.h>
#include <sys/proc.h>		/* declares:    p0 */
#include <sys/cmn_err.h>
#include <sys/scsi/adapters/iscsi_if.h>
#include <netinet/in.h>
#include "iscsi_targetparam.h"
#include "isns_client.h"
#include "isns_protocol.h"
#include "persistent.h"
#include "iscsi.h"
#include <sys/ethernet.h>
#include <sys/bootprops.h>

/*
 * local function prototypes
 */
static boolean_t iscsid_init_config(iscsi_hba_t *ihp);
static boolean_t iscsid_init_targets(iscsi_hba_t *ihp);
static void iscsid_thread_static(iscsi_thread_t *thread, void *p);
static void iscsid_thread_sendtgts(iscsi_thread_t *thread, void *p);
static void iscsid_thread_isns(iscsi_thread_t *thread, void *p);
static void iscsid_thread_slp(iscsi_thread_t *thread, void *p);
static void iscsid_thread_boot_wd(iscsi_thread_t *thread, void *p);
static void iscsid_threads_create(iscsi_hba_t *ihp);
static void iscsid_threads_destroy(void);
static int iscsid_copyto_param_set(uint32_t param_id,
    iscsi_login_params_t *params, iscsi_param_set_t *ipsp);
static void iscsid_add_pg_list_to_cache(iscsi_hba_t *ihp,
    isns_portal_group_list_t *pg_list);
static void iscsid_remove_target_param(char *name);
static boolean_t iscsid_add(iscsi_hba_t *ihp, iSCSIDiscoveryMethod_t method,
    struct sockaddr *addr_dsc, char *target_name, int tpgt,
    struct sockaddr *addr_tgt);
static void iscsi_discovery_event(iscsi_hba_t *ihp,
    iSCSIDiscoveryMethod_t m, boolean_t start);
static boolean_t iscsid_boot_init_config(iscsi_hba_t *ihp);
static iscsi_sess_t *iscsi_add_boot_sess(iscsi_hba_t *ihp, int isid);
static boolean_t iscsid_make_entry(ib_boot_prop_t *boot_prop_entry,
    entry_t *entry);
static boolean_t iscsid_check_active_boot_conn(iscsi_hba_t *ihp);

extern int modrootloaded;
int iscsi_configroot_retry = 20;
static boolean_t iscsi_configroot_printed = FALSE;
static int iscsi_net_up = 0;
extern ib_boot_prop_t   *iscsiboot_prop;

#define	ISCSI_CONFIGROOT_DELAY	1

/*
 * iSCSI target discovery thread table
 */
typedef struct iscsid_thr_table {
	void			(*func_start)(iscsi_thread_t *, void *);
	iscsi_thread_t		*thr_id;
	iSCSIDiscoveryMethod_t	method;
	char			*name;
} iscsid_thr_table;

static iscsid_thr_table iscsid_thr[] = {
	{ iscsid_thread_static, NULL,
	    iSCSIDiscoveryMethodStatic,
	    "Static" },
	{ iscsid_thread_sendtgts, NULL,
	    iSCSIDiscoveryMethodSendTargets,
	    "SendTarget" },
	{ iscsid_thread_slp, NULL,
	    iSCSIDiscoveryMethodSLP,
	    "SLP" },
	{ iscsid_thread_isns, NULL,
	    iSCSIDiscoveryMethodISNS,
	    "iSNS" },
	{ NULL, NULL,
	    iSCSIDiscoveryMethodUnknown,
	    NULL }
};

/*
 * discovery method event table
 */
iSCSIDiscoveryMethod_t	for_failure[] = {
	iSCSIDiscoveryMethodStatic,
	iSCSIDiscoveryMethodSLP,
	iSCSIDiscoveryMethodISNS,
	iSCSIDiscoveryMethodSendTargets,
	iSCSIDiscoveryMethodUnknown /* terminating value */
};

/*
 * The following private tunable, set in /etc/system, e.g.,
 *      set iscsi:iscsi_boot_max_delay = 360
 * , provides with customer a max wait time in
 * seconds to wait for boot lun online during iscsi boot.
 * Defaults to 180s.
 */
int iscsi_boot_max_delay = ISCSI_BOOT_DEFAULT_MAX_DELAY;

/*
 * discovery configuration semaphore
 */
ksema_t iscsid_config_semaphore;

static iscsi_thread_t	*iscsi_boot_wd_handle = NULL;

#define	CHECK_METHOD(v) ((dm & v) ? B_TRUE : B_FALSE)

/*
 * Check if IP is valid
 */
static boolean_t
iscsid_ip_check(char *ip)
{
	int	i	= 0;

	if (!ip)
		return (B_FALSE);
	for (; (ip[i] == 0) && (i < IB_IP_BUFLEN); i++) {}
	if (i == IB_IP_BUFLEN) {
		/* invalid IP address */
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Make an entry for the boot target.
 * return B_TRUE upon success
 *        B_FALSE if fail
 */
static boolean_t
iscsid_make_entry(ib_boot_prop_t *boot_prop_entry, entry_t *entry)
{
	if (entry == NULL || boot_prop_entry == NULL) {
		return (B_FALSE);
	}

	if (!iscsid_ip_check(
	    (char *)&boot_prop_entry->boot_tgt.tgt_ip_u))
		return (B_FALSE);

	if (boot_prop_entry->boot_tgt.sin_family != AF_INET &&
	    boot_prop_entry->boot_tgt.sin_family != AF_INET6)
		return (B_FALSE);

	entry->e_vers = ISCSI_INTERFACE_VERSION;

	mutex_enter(&iscsi_oid_mutex);
	entry->e_oid = iscsi_oid++;
	mutex_exit(&iscsi_oid_mutex);

	entry->e_tpgt = ISCSI_DEFAULT_TPGT;

	if (boot_prop_entry->boot_tgt.sin_family == AF_INET) {
		entry->e_u.u_in4.s_addr =
		    boot_prop_entry->boot_tgt.tgt_ip_u.u_in4.s_addr;
		entry->e_insize = sizeof (struct in_addr);
	} else {
		(void) bcopy(
		    &boot_prop_entry->boot_tgt.tgt_ip_u.u_in6.s6_addr,
		    entry->e_u.u_in6.s6_addr, 16);
		entry->e_insize = sizeof (struct in6_addr);
	}

	entry->e_port = boot_prop_entry->boot_tgt.tgt_port;
	entry->e_boot = B_TRUE;
	return (B_TRUE);
}

/*
 * Create the boot session
 */
static void
iscsi_boot_session_create(iscsi_hba_t *ihp,
    ib_boot_prop_t	*boot_prop_table)
{
	iSCSIDiscoveryMethod_t  dm;
	entry_t			e;
	iscsi_sockaddr_t	addr_dsc;

	if (ihp == NULL || boot_prop_table == NULL) {
		return;
	}

	if (!iscsid_ip_check(
	    (char *)&boot_prop_table->boot_tgt.tgt_ip_u)) {
		return;
	}

	if (boot_prop_table->boot_tgt.tgt_name != NULL) {
		dm = iSCSIDiscoveryMethodStatic |
		    iSCSIDiscoveryMethodBoot;
		if (!iscsid_make_entry(boot_prop_table, &e))
			return;
		iscsid_addr_to_sockaddr(e.e_insize, &e.e_u,
		    e.e_port, &addr_dsc.sin);

		(void) iscsid_add(ihp, dm, &addr_dsc.sin,
		    (char *)boot_prop_table->boot_tgt.tgt_name,
		    e.e_tpgt, &addr_dsc.sin);
	} else {
		dm = iSCSIDiscoveryMethodSendTargets |
		    iSCSIDiscoveryMethodBoot;
		if (!iscsid_make_entry(boot_prop_table, &e))
			return;
		iscsid_addr_to_sockaddr(e.e_insize, &e.e_u,
		    e.e_port, &addr_dsc.sin);
		iscsid_do_sendtgts(&e);
		(void) iscsid_login_tgt(ihp, NULL, dm,
		    &addr_dsc.sin);
	}
}

/*
 * iscsid_init -- to initialize stuffs related to iscsi daemon,
 * and to create boot session if needed
 */
boolean_t
iscsid_init(iscsi_hba_t *ihp)
{
	boolean_t		rval = B_TRUE;

	sema_init(&iscsid_config_semaphore, 1, NULL,
	    SEMA_DRIVER, NULL);
	persistent_init();
	iscsid_threads_create(ihp);

	if (modrootloaded) {
		/*
		 * The root file system is available so we can load the
		 * persistent store.
		 */
		if (persistent_load() == B_TRUE) {
			ihp->hba_persistent_loaded = B_TRUE;
		} else {
			return (B_FALSE);
		}
	} else {
		/*
		 * If the root file system is not yet mounted then we _must_ be
		 * booting from an iSCSI device.  If not, we want to fail to
		 * attach so that we can try again after the VFS root is
		 * available.
		 */
		if (iscsiboot_prop == NULL) {
			return (B_FALSE);
		}

		if (!iscsid_boot_init_config(ihp)) {
			rval = B_FALSE;
		} else {
			iscsi_boot_session_create(ihp, iscsiboot_prop);
			iscsi_boot_wd_handle =
			    iscsi_thread_create(ihp->hba_dip,
			    "BootWD", iscsid_thread_boot_wd, ihp);
			if (iscsi_boot_wd_handle != NULL) {
				rval = iscsi_thread_start(
				    iscsi_boot_wd_handle);
			} else {
				rval = B_FALSE;
			}
		}
		if (rval == B_FALSE) {
			cmn_err(CE_NOTE, "Initializaton of iscsi boot session"
			    " partially failed");
		}
	}

	return (rval);
}

/*
 * iscsid_start -- start the iscsi initiator daemon, actually this code
 * is just to enable discovery methods which are set enabled in
 * persistent store, as an economic way to present the 'daemon' funtionality
 */
boolean_t
iscsid_start(iscsi_hba_t *ihp)
{
	boolean_t		rval = B_FALSE;
	iSCSIDiscoveryMethod_t	dm;
	iSCSIDiscoveryMethod_t	*fdm;

	rval = iscsid_init_config(ihp);
	if (rval == B_TRUE) {
		rval = iscsid_init_targets(ihp);
	}

	if (rval == B_TRUE) {
		dm = persistent_disc_meth_get();
		rval = iscsid_enable_discovery(ihp, dm, B_TRUE);
		if (rval == B_TRUE) {
			iscsid_poke_discovery(ihp,
			    iSCSIDiscoveryMethodUnknown);
			(void) iscsid_login_tgt(ihp, NULL,
			    iSCSIDiscoveryMethodUnknown, NULL);
		}
	}

	if (rval == B_FALSE) {
		/*
		 * In case of failure the events still need to be sent
		 * because the door daemon will pause until all these
		 * events have occurred.
		 */
		for (fdm = &for_failure[0]; *fdm !=
		    iSCSIDiscoveryMethodUnknown; fdm++) {
			/* ---- Send both start and end events ---- */
			iscsi_discovery_event(ihp, *fdm, B_TRUE);
			iscsi_discovery_event(ihp, *fdm, B_FALSE);
		}
	}

	return (rval);
}

/*
 * iscsid_stop -- stop the iscsi initiator daemon, by disabling
 * all the discovery methods first, and then try to stop all
 * related threads. This is a try-best effort, leave any 'busy' device
 * (and therefore session) there and just return.
 */
boolean_t
iscsid_stop(iscsi_hba_t *ihp)
{
	boolean_t		rval = B_FALSE;
	iscsi_sess_t		*isp = NULL;

	(void) iscsid_disable_discovery(ihp, ISCSI_ALL_DISCOVERY_METHODS);

	/* final check */
	rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
	if (ihp->hba_sess_list == NULL) {
		rval = B_TRUE;
	} else {
		/*
		 * If only boot session is left, that is OK.
		 * Otherwise, we should report that some sessions are left.
		 */
		rval = B_TRUE;
		for (isp = ihp->hba_sess_list; isp != NULL;
		    isp = isp->sess_next) {
			if (isp->sess_boot == B_FALSE) {
				rval = B_FALSE;
				break;
			}
		}
	}
	rw_exit(&ihp->hba_sess_list_rwlock);

	return (rval);
}

/*
 * iscsid_fini -- do whatever is required to clean up
 */
/* ARGSUSED */
void
iscsid_fini()
{
	if (iscsi_boot_wd_handle != NULL) {
		iscsi_thread_destroy(iscsi_boot_wd_handle);
		iscsi_boot_wd_handle = NULL;
	}
	iscsid_threads_destroy();
	persistent_fini();
	sema_destroy(&iscsid_config_semaphore);
}

/*
 * iscsid_props -- returns discovery thread information, used by ioctl code
 */
void
iscsid_props(iSCSIDiscoveryProperties_t *props)
{
	iSCSIDiscoveryMethod_t  dm;

	dm = persistent_disc_meth_get();

	props->vers = ISCSI_INTERFACE_VERSION;

	/* ---- change once thread is implemented ---- */
	props->iSNSDiscoverySettable		= B_FALSE;
	props->SLPDiscoverySettable		= B_FALSE;
	props->StaticDiscoverySettable		= B_TRUE;
	props->SendTargetsDiscoverySettable	= B_TRUE;
	props->iSNSDiscoveryMethod		= iSNSDiscoveryMethodStatic;

	props->iSNSDiscoveryEnabled = CHECK_METHOD(iSCSIDiscoveryMethodISNS);
	props->StaticDiscoveryEnabled =
	    CHECK_METHOD(iSCSIDiscoveryMethodStatic);
	props->SendTargetsDiscoveryEnabled =
	    CHECK_METHOD(iSCSIDiscoveryMethodSendTargets);
	props->SLPDiscoveryEnabled = CHECK_METHOD(iSCSIDiscoveryMethodSLP);
}

/*
 * iscsid_enable_discovery - start specified discovery methods
 */
/* ARGSUSED */
boolean_t
iscsid_enable_discovery(iscsi_hba_t *ihp, iSCSIDiscoveryMethod_t idm,
    boolean_t poke)
{
	boolean_t		rval = B_TRUE;
	iscsid_thr_table	*dt;

	/*
	 * start the specified discovery method(s)
	 */
	for (dt = &iscsid_thr[0]; dt->method != iSCSIDiscoveryMethodUnknown;
	    dt++) {
		if (idm & dt->method) {
			if (dt->thr_id != NULL) {
				rval = iscsi_thread_start(dt->thr_id);
				if (rval == B_FALSE) {
					break;
				}
				if (poke == B_TRUE) {
					(void) iscsi_thread_send_wakeup(
					    dt->thr_id);
				}
			} else {
				/*
				 * unexpected condition.  The threads for each
				 * discovery method should have started at
				 * initialization
				 */
				ASSERT(B_FALSE);
			}
		}
	} /* END for() */

	return (rval);
}


/*
 * iscsid_disable_discovery - stop specified discovery methods
 */
boolean_t
iscsid_disable_discovery(iscsi_hba_t *ihp, iSCSIDiscoveryMethod_t idm)
{
	boolean_t		rval = B_TRUE;
	iscsid_thr_table	*dt;

	/*
	 * stop the specified discovery method(s)
	 */
	for (dt = &iscsid_thr[0]; dt->method != iSCSIDiscoveryMethodUnknown;
	    dt++) {
		if (idm & dt->method) {

			/* signal discovery event change - begin */
			iscsi_discovery_event(ihp, dt->method, B_TRUE);

			/* Attempt to logout of all associated targets */
			rval = iscsid_del(ihp, NULL, dt->method, NULL);
			if (rval == B_TRUE) {
				/* Successfully logged out of targets */
				if (dt->thr_id != NULL) {
					rval = iscsi_thread_stop(dt->thr_id);
					if (rval == B_FALSE) {
						/*
						 * signal discovery
						 * event change - end
						 */
						iscsi_discovery_event(ihp,
						    dt->method, B_FALSE);
						break;
					}

				} else {
					/*
					 * unexpected condition.  The threads
					 * for each discovery method should
					 * have started at initialization
					 */
					ASSERT(B_FALSE);
				}
			}

			/* signal discovery event change - end */
			iscsi_discovery_event(ihp, dt->method, B_FALSE);

		}
	} /* END for() */

	return (rval);
}

/*
 * iscsid_poke_discovery - wakeup discovery methods to find any new targets
 * and wait for all discovery processes to complete.
 */
void
iscsid_poke_discovery(iscsi_hba_t *ihp, iSCSIDiscoveryMethod_t method)
{
#define	ISCSI_DISCOVERY_DELAY	1

	iSCSIDiscoveryMethod_t	dm;
	iscsid_thr_table	*dt;
	boolean_t		send_wakeup;

	ASSERT(ihp != NULL);

	/* reset discovery flags */
	mutex_enter(&ihp->hba_discovery_events_mutex);
	ihp->hba_discovery_in_progress = B_TRUE;
	ihp->hba_discovery_events = iSCSIDiscoveryMethodUnknown;
	mutex_exit(&ihp->hba_discovery_events_mutex);

	/* start all enabled discovery methods */
	dm = persistent_disc_meth_get();
	for (dt = &iscsid_thr[0]; dt->method != iSCSIDiscoveryMethodUnknown;
	    dt++) {
		send_wakeup = B_FALSE;

		if ((method == iSCSIDiscoveryMethodUnknown) ||
		    (method == dt->method)) {
			if ((dm & dt->method) && (dt->thr_id != NULL)) {
				if (iscsi_thread_send_wakeup(dt->thr_id) ==
				    B_TRUE) {
					send_wakeup = B_TRUE;
				}
			}
		}

		if (send_wakeup == B_FALSE) {
			iscsi_discovery_event(ihp, dt->method, B_TRUE);
			iscsi_discovery_event(ihp, dt->method, B_FALSE);
		}
	}

	mutex_enter(&ihp->hba_discovery_events_mutex);
	while (ihp->hba_discovery_events != ISCSI_ALL_DISCOVERY_METHODS) {
		mutex_exit(&ihp->hba_discovery_events_mutex);
		delay(SEC_TO_TICK(ISCSI_DISCOVERY_DELAY));
		mutex_enter(&ihp->hba_discovery_events_mutex);
	}
	ihp->hba_discovery_in_progress = B_FALSE;
	mutex_exit(&ihp->hba_discovery_events_mutex);

}

/*
 * iscsid_do_sendtgts - issue send targets command to the given discovery
 * address and then add the discovered targets to the discovery queue
 */
void
iscsid_do_sendtgts(entry_t *disc_addr)
{

#define	SENDTGTS_DEFAULT_NUM_TARGETS    10

	int			stl_sz;
	int			stl_num_tgts = SENDTGTS_DEFAULT_NUM_TARGETS;
	iscsi_sendtgts_list_t	*stl_hdr = NULL;
	boolean_t		retry = B_TRUE;
	char			inp_buf[INET6_ADDRSTRLEN];
	const char		*ip;
	int			ctr;
	int			rc;
	iscsi_hba_t		*ihp;
	iSCSIDiscoveryMethod_t  dm = iSCSIDiscoveryMethodSendTargets;

	/* allocate and initialize sendtargets list header */
	stl_sz = sizeof (*stl_hdr) + ((stl_num_tgts - 1) *
	    sizeof (iscsi_sendtgts_entry_t));
	stl_hdr = kmem_zalloc(stl_sz, KM_SLEEP);

retry_sendtgts:
	stl_hdr->stl_in_cnt = stl_num_tgts;
	bcopy(disc_addr, &(stl_hdr->stl_entry),
	    sizeof (stl_hdr->stl_entry));
	stl_hdr->stl_entry.e_vers = ISCSI_INTERFACE_VERSION;

	/* lock interface so only one SendTargets operation occurs */
	if ((ihp = (iscsi_hba_t *)ddi_get_soft_state(iscsi_state, 0)) == NULL) {
		cmn_err(CE_NOTE, "!iscsi discovery failure - SendTargets. "
		    "failure to get soft state");
		kmem_free(stl_hdr, stl_sz);
		return;
	}
	sema_p(&ihp->hba_sendtgts_semaphore);
	rc = iscsi_ioctl_sendtgts_get(ihp, stl_hdr);
	sema_v(&ihp->hba_sendtgts_semaphore);
	if (rc) {
		ip = inet_ntop((disc_addr->e_insize ==
		    sizeof (struct in_addr) ? AF_INET : AF_INET6),
		    &disc_addr->e_u, inp_buf, sizeof (inp_buf));
		cmn_err(CE_NOTE,
		    "iscsi discovery failure - SendTargets (%s)\n", ip);
		kmem_free(stl_hdr, stl_sz);
		return;
	}

	/* check if all targets received */
	if (stl_hdr->stl_in_cnt < stl_hdr->stl_out_cnt) {
		if (retry == B_TRUE) {
			stl_num_tgts = stl_hdr->stl_out_cnt;
			kmem_free(stl_hdr, stl_sz);
			stl_sz = sizeof (*stl_hdr) +
			    ((stl_num_tgts - 1) *
			    sizeof (iscsi_sendtgts_entry_t));
			stl_hdr = kmem_zalloc(stl_sz, KM_SLEEP);
			retry = B_FALSE;
			goto retry_sendtgts;
		} else {
			ip = inet_ntop((disc_addr->e_insize ==
			    sizeof (struct in_addr) ?
			    AF_INET : AF_INET6), &disc_addr->e_u,
			    inp_buf, sizeof (inp_buf));
			cmn_err(CE_NOTE, "iscsi discovery failure - "
			    "SendTargets overflow (%s)\n", ip);
			kmem_free(stl_hdr, stl_sz);
			return;
		}
	}

	for (ctr = 0; ctr < stl_hdr->stl_out_cnt; ctr++) {
		iscsi_sockaddr_t addr_dsc;
		iscsi_sockaddr_t addr_tgt;

		iscsid_addr_to_sockaddr(disc_addr->e_insize,
		    &disc_addr->e_u, disc_addr->e_port, &addr_dsc.sin);
		iscsid_addr_to_sockaddr(
		    stl_hdr->stl_list[ctr].ste_ipaddr.a_addr.i_insize,
		    &(stl_hdr->stl_list[ctr].ste_ipaddr.a_addr.i_addr),
		    stl_hdr->stl_list[ctr].ste_ipaddr.a_port,
		    &addr_tgt.sin);
		if (disc_addr->e_boot == B_TRUE) {
			dm = dm | iSCSIDiscoveryMethodBoot;
		}
		(void) iscsid_add(ihp, dm,
		    &addr_dsc.sin, (char *)stl_hdr->stl_list[ctr].ste_name,
		    stl_hdr->stl_list[ctr].ste_tpgt,
		    &addr_tgt.sin);
	}
	kmem_free(stl_hdr, stl_sz);
}

void
iscsid_do_isns_query_one_server(iscsi_hba_t *ihp, entry_t *isns_server)
{
	int pg_sz, query_status;
	iscsi_addr_t *ap;
	isns_portal_group_list_t *pg_list;

	ap = (iscsi_addr_t *)kmem_zalloc(sizeof (iscsi_addr_t), KM_SLEEP);
	ap->a_port = isns_server->e_port;
	ap->a_addr.i_insize = isns_server->e_insize;

	if (isns_server->e_insize == sizeof (struct in_addr)) {
		ap->a_addr.i_addr.in4.s_addr = (isns_server->e_u.u_in4.s_addr);
	} else if (isns_server->e_insize == sizeof (struct in6_addr)) {
		bcopy(&(isns_server->e_u.u_in6.s6_addr),
		    ap->a_addr.i_addr.in6.s6_addr, 16);
	} else {
		kmem_free(ap, sizeof (iscsi_addr_t));
		return;
	}

	pg_list = NULL;
	query_status = isns_query_one_server(
	    ap, ihp->hba_isid,
	    ihp->hba_name, ihp->hba_alias,
	    ISNS_INITIATOR_NODE_TYPE, &pg_list);
	kmem_free(ap, sizeof (iscsi_addr_t));
	if (query_status != isns_ok || pg_list == NULL) {
		DTRACE_PROBE1(iscsid_do_isns_query_one_server_status,
		    int, query_status);
		return;
	}

	iscsid_add_pg_list_to_cache(ihp, pg_list);
	pg_sz = sizeof (isns_portal_group_list_t);
	if (pg_list->pg_out_cnt > 0) {
		pg_sz += (pg_list->pg_out_cnt - 1) *
		    sizeof (isns_portal_group_t);
	}
	kmem_free(pg_list, pg_sz);
}

void
iscsid_do_isns_query(iscsi_hba_t *ihp)
{
	int pg_sz, query_status;
	isns_portal_group_list_t *pg_list;

	pg_list = NULL;
	query_status = isns_query(ihp->hba_isid,
	    ihp->hba_name,
	    ihp->hba_alias,
	    ISNS_INITIATOR_NODE_TYPE,
	    &pg_list);

	if (pg_list == NULL) {
		DTRACE_PROBE1(iscsid_do_isns_query_status,
		    int, query_status);
		return;
	}

	if ((query_status != isns_ok &&
	    query_status != isns_op_partially_failed)) {
		DTRACE_PROBE1(iscsid_do_isns_query_status,
		    int, query_status);
		pg_sz = sizeof (isns_portal_group_list_t);
		if (pg_list->pg_out_cnt > 0) {
			pg_sz += (pg_list->pg_out_cnt - 1) *
			    sizeof (isns_portal_group_t);
		}
		kmem_free(pg_list, pg_sz);
		return;
	}

	iscsid_add_pg_list_to_cache(ihp, pg_list);

	pg_sz = sizeof (isns_portal_group_list_t);
	if (pg_list->pg_out_cnt > 0) {
		pg_sz += (pg_list->pg_out_cnt - 1) *
		    sizeof (isns_portal_group_t);
	}
	kmem_free(pg_list, pg_sz);
}

/*
 * iscsid_config_one - for the given target name, attempt
 * to login to all targets associated with name.  If target
 * name is not found in discovery queue, reset the discovery
 * queue, kick the discovery processes, and then retry.
 *
 * NOTE: The caller of this function must hold the
 *	iscsid_config_semaphore across this call.
 */
void
iscsid_config_one(iscsi_hba_t *ihp, char *name, boolean_t protect)
{
	boolean_t	rc	    =	B_FALSE;
	int		retry	    =	0;
	int		lun_online  =	0;
	int		cur_sec	    =	0;

	if (!modrootloaded && (iscsiboot_prop != NULL)) {
		if (!iscsi_configroot_printed) {
			cmn_err(CE_NOTE, "Configuring"
			    " iSCSI boot session...");
			iscsi_configroot_printed = B_TRUE;
		}
		if (iscsi_net_up == 0) {
			if (iscsi_net_interface(B_FALSE) ==
			    ISCSI_STATUS_SUCCESS) {
				iscsi_net_up = 1;
			} else {
				cmn_err(CE_WARN, "Failed to configure interface"
				    " for iSCSI boot session");
				return;
			}
		}
		while (rc == B_FALSE && retry <
		    iscsi_configroot_retry) {
			rc = iscsid_login_tgt(ihp, name,
			    iSCSIDiscoveryMethodBoot, NULL);
			if (rc == B_FALSE) {
				/*
				 * create boot session
				 */
				iscsi_boot_session_create(ihp,
				    iscsiboot_prop);
				retry++;
				continue;
			}
			rc = iscsid_check_active_boot_conn(ihp);
			if (rc == B_FALSE) {
				/*
				 * no active connection for the boot
				 * session, retry the login until
				 * one is found or the retry count
				 * is exceeded
				 */
				delay(SEC_TO_TICK(ISCSI_CONFIGROOT_DELAY));
				retry++;
				continue;
			}
			/*
			 * The boot session has been created with active
			 * connection. If the target lun has not been online,
			 * we should wait here for a while
			 */
			do {
				lun_online =
				    iscsiboot_prop->boot_tgt.lun_online;
				if (lun_online == 0) {
					delay(SEC_TO_TICK(
					    ISCSI_CONFIGROOT_DELAY));
					cur_sec++;
				}
			} while ((lun_online == 0) &&
			    (cur_sec < iscsi_boot_max_delay));
			retry++;
		}
		if (!rc) {
			cmn_err(CE_WARN, "Failed to configure iSCSI"
			    " boot session");
		}
	} else {
		rc = iscsid_login_tgt(ihp, name, iSCSIDiscoveryMethodUnknown,
		    NULL);
		/*
		 * If we didn't login to the device we might have
		 * to update our discovery information and attempt
		 * the login again.
		 */
		if (rc == B_FALSE) {
			/*
			 * Stale /dev links can cause us to get floods
			 * of config requests.  Prevent these repeated
			 * requests from causing unneeded discovery updates
			 * if ISCSI_CONFIG_STORM_PROTECT is set.
			 */
			if ((protect == B_FALSE) ||
			    (ddi_get_lbolt() > ihp->hba_config_lbolt +
			    SEC_TO_TICK(ihp->hba_config_storm_delay))) {
				ihp->hba_config_lbolt = ddi_get_lbolt();
				iscsid_poke_discovery(ihp,
				    iSCSIDiscoveryMethodUnknown);
				(void) iscsid_login_tgt(ihp, name,
				    iSCSIDiscoveryMethodUnknown, NULL);
			}
		}
	}
}

/*
 * iscsid_config_all - reset the discovery queue, kick the
 * discovery processes, and login to all targets found
 *
 * NOTE: The caller of this function must hold the
 *	iscsid_config_semaphore across this call.
 */
void
iscsid_config_all(iscsi_hba_t *ihp, boolean_t protect)
{
	boolean_t	rc		= B_FALSE;
	int		retry	= 0;
	int		lun_online  = 0;
	int		cur_sec	= 0;

	if (!modrootloaded && iscsiboot_prop != NULL) {
		if (!iscsi_configroot_printed) {
			cmn_err(CE_NOTE, "Configuring"
			    " iSCSI boot session...");
			iscsi_configroot_printed = B_TRUE;
		}
		if (iscsi_net_up == 0) {
			if (iscsi_net_interface(B_FALSE) ==
			    ISCSI_STATUS_SUCCESS) {
				iscsi_net_up = 1;
			}
		}
		while (rc == B_FALSE && retry <
		    iscsi_configroot_retry) {
			rc = iscsid_login_tgt(ihp, NULL,
			    iSCSIDiscoveryMethodBoot, NULL);
			if (rc == B_FALSE) {
				/*
				 * No boot session has been created.
				 * We would like to create the boot
				 * Session first.
				 */
				iscsi_boot_session_create(ihp,
				    iscsiboot_prop);
				retry++;
				continue;
			}
			rc = iscsid_check_active_boot_conn(ihp);
			if (rc == B_FALSE) {
				/*
				 * no active connection for the boot
				 * session, retry the login until
				 * one is found or the retry count
				 * is exceeded
				 */
				delay(SEC_TO_TICK(ISCSI_CONFIGROOT_DELAY));
				retry++;
				continue;
			}
			/*
			 * The boot session has been created with active
			 * connection. If the target lun has not been online,
			 * we should wait here for a while
			 */
			do {
				lun_online =
				    iscsiboot_prop->boot_tgt.lun_online;
				if (lun_online == 0) {
					delay(SEC_TO_TICK(
					    ISCSI_CONFIGROOT_DELAY));
					cur_sec++;
				}
			} while ((lun_online == 0) &&
			    (cur_sec < iscsi_boot_max_delay));
			retry++;
		}
		if (!rc) {
			cmn_err(CE_WARN, "Failed to configure"
			    " boot session");
		}
	} else {
		/*
		 * Stale /dev links can cause us to get floods
		 * of config requests.  Prevent these repeated
		 * requests from causing unneeded discovery updates
		 * if ISCSI_CONFIG_STORM_PROTECT is set.
		 */
		if ((protect == B_FALSE) ||
		    (ddi_get_lbolt() > ihp->hba_config_lbolt +
		    SEC_TO_TICK(ihp->hba_config_storm_delay))) {
			ihp->hba_config_lbolt = ddi_get_lbolt();
			iscsid_poke_discovery(ihp,
			    iSCSIDiscoveryMethodUnknown);
		}
		(void) iscsid_login_tgt(ihp, NULL,
		    iSCSIDiscoveryMethodUnknown, NULL);
	}
}

/*
 * isns_scn_callback - iSNS client received an SCN
 *
 * This code processes the iSNS client SCN events.  These
 * could relate to the addition, removal, or update of a
 * logical unit.
 */
void
isns_scn_callback(void *arg)
{
	int				i, pg_sz;
	int				qry_status;
	isns_portal_group_list_t	*pg_list;
	uint32_t			scn_type;
	iscsi_hba_t			*ihp;

	if (arg == NULL) {
		/* No argument */
		return;
	}

	if ((ihp = (iscsi_hba_t *)ddi_get_soft_state(iscsi_state, 0)) == NULL) {
		kmem_free(arg, sizeof (isns_scn_callback_arg_t));
		return;
	}

	/*
	 * All isns callbacks are from a standalone taskq
	 * therefore the blocking here doesn't affect the enable/disable
	 * of isns discovery method
	 */
	if (iscsi_client_request_service(ihp) == B_FALSE) {
		kmem_free(arg, sizeof (isns_scn_callback_arg_t));
		return;
	}

	scn_type = ((isns_scn_callback_arg_t *)arg)->scn_type;
	DTRACE_PROBE1(isns_scn_callback_scn_type, int, scn_type);
	switch (scn_type) {
	/*
	 * ISNS_OBJ_ADDED - An object has been added.
	 */
	case ISNS_OBJ_ADDED:
		/* Query iSNS server for contact information */
		pg_list = NULL;
		qry_status = isns_query_one_node(
		    ((isns_scn_callback_arg_t *)arg)->source_key_attr,
		    ihp->hba_isid,
		    ihp->hba_name,
		    (uint8_t *)"",
		    ISNS_INITIATOR_NODE_TYPE,
		    &pg_list);

		/* Verify portal group is found */
		if ((qry_status != isns_ok &&
		    qry_status != isns_op_partially_failed) ||
		    pg_list == NULL) {
			break;
		}

		DTRACE_PROBE1(pg_list,
		    isns_portal_group_list_t *, pg_list);

		/* Add all portals for logical unit to discovery cache */
		for (i = 0; i < pg_list->pg_out_cnt; i++) {
			iscsi_sockaddr_t addr_dsc;
			iscsi_sockaddr_t addr_tgt;

			iscsid_addr_to_sockaddr(
			    pg_list->pg_list[i].isns_server_ip.i_insize,
			    &pg_list->pg_list[i].isns_server_ip.i_addr,
			    pg_list->pg_list[i].isns_server_port,
			    &addr_dsc.sin);
			iscsid_addr_to_sockaddr(pg_list->pg_list[i].insize,
			    &pg_list->pg_list[i].pg_ip_addr,
			    pg_list->pg_list[i].pg_port, &addr_tgt.sin);

			(void) iscsid_add(ihp, iSCSIDiscoveryMethodISNS,
			    &addr_dsc.sin, (char *)pg_list->pg_list[i].
			    pg_iscsi_name, pg_list->pg_list[i].pg_tag,
			    &addr_tgt.sin);

			/* Force target to login */
			(void) iscsid_login_tgt(ihp, (char *)pg_list->
			    pg_list[i].pg_iscsi_name, iSCSIDiscoveryMethodISNS,
			    NULL);
		}

		if (pg_list != NULL) {
			pg_sz = sizeof (isns_portal_group_list_t);
			if (pg_list->pg_out_cnt > 0) {
				pg_sz += (pg_list->pg_out_cnt - 1) *
				    sizeof (isns_portal_group_t);
			}
			kmem_free(pg_list, pg_sz);
		}
		break;

	/*
	 * ISNS_OBJ_REMOVED - logical unit has been removed
	 */
	case ISNS_OBJ_REMOVED:
		if (iscsid_del(ihp,
		    (char *)((isns_scn_callback_arg_t *)arg)->
		    source_key_attr, iSCSIDiscoveryMethodISNS, NULL) !=
		    B_TRUE) {
			cmn_err(CE_NOTE, "iscsi initiator - "
			    "isns remove scn failed for target %s\n",
			    (char *)((isns_scn_callback_arg_t *)arg)->
			    source_key_attr);

		}
		break;

	/*
	 * ISNS_OBJ_UPDATED - logical unit has changed
	 */
	case ISNS_OBJ_UPDATED:
		cmn_err(CE_NOTE, "iscsi initiator - "
		    "received iSNS update SCN for %s\n",
		    (char *)((isns_scn_callback_arg_t *)arg)->
		    source_key_attr);
		break;

	/*
	 * ISNS_OBJ_UNKNOWN -
	 */
	default:
		cmn_err(CE_NOTE, "iscsi initiator - "
		    "received unknown iSNS SCN type 0x%x\n", scn_type);
		break;
	}

	iscsi_client_release_service(ihp);
	kmem_free(arg, sizeof (isns_scn_callback_arg_t));
}


/*
 * iscsid_add - Creates discovered session and connection
 */
static boolean_t
iscsid_add(iscsi_hba_t *ihp, iSCSIDiscoveryMethod_t method,
    struct sockaddr *addr_dsc, char *target_name, int tpgt,
    struct sockaddr *addr_tgt)
{
	boolean_t	    rtn = B_TRUE;
	iscsi_sess_t	    *isp;
	iscsi_conn_t	    *icp;
	uint_t		    oid;
	int		    idx;
	int		    isid;
	iscsi_config_sess_t *ics;
	int		    size;
	char		    *tmp;

	ASSERT(ihp != NULL);
	ASSERT(addr_dsc != NULL);
	ASSERT(target_name != NULL);
	ASSERT(addr_tgt != NULL);

	/* setup initial buffer for configured session information */
	size = sizeof (*ics);
	ics = kmem_zalloc(size, KM_SLEEP);
	ics->ics_in = 1;

	/* get configured sessions information */
	tmp = target_name;
	if (persistent_get_config_session(tmp, ics) == B_FALSE) {
		/*
		 * No target information available check for
		 * initiator information.
		 */
		tmp = (char *)ihp->hba_name;
		if (persistent_get_config_session(tmp, ics) == B_FALSE) {
			/*
			 * No hba information is
			 * found.  So assume default
			 * one session unbound behavior.
			 */
			ics->ics_out = 1;
			ics->ics_bound = B_TRUE;
		}
	}

	if (iscsiboot_prop && (ics->ics_out > 1) &&
	    !iscsi_chk_bootlun_mpxio(ihp)) {
		/*
		 * iscsi boot with mpxio disabled
		 * no need to search configured boot session
		 */

		if (iscsi_cmp_boot_ini_name(tmp) ||
		    iscsi_cmp_boot_tgt_name(tmp)) {
			ics->ics_out = 1;
			ics->ics_bound = B_FALSE;
		}
	}
	/* Check to see if we need to get more information */
	if (ics->ics_out > 1) {
		/* record new size and free last buffer */
		idx = ics->ics_out;
		size = ISCSI_SESSION_CONFIG_SIZE(ics->ics_out);
		kmem_free(ics, sizeof (*ics));

		/* allocate new buffer */
		ics = kmem_zalloc(size, KM_SLEEP);
		ics->ics_in = idx;

		/* get configured sessions information */
		if (persistent_get_config_session(tmp, ics) != B_TRUE) {
			cmn_err(CE_NOTE, "iscsi session(%s) - "
			    "unable to get configured session information\n",
			    target_name);
			kmem_free(ics, size);
			return (B_FALSE);
		}
	}

	/* loop for all configured sessions */
	rw_enter(&ihp->hba_sess_list_rwlock, RW_WRITER);
	for (isid = 0; isid < ics->ics_out; isid++) {
		/* create or find matching session */
		isp = iscsi_sess_create(ihp, method, addr_dsc, target_name,
		    tpgt, isid, ISCSI_SESS_TYPE_NORMAL, &oid);
		if (isp == NULL) {
			rtn = B_FALSE;
			break;
		}

		/* create or find matching connection */
		if (!ISCSI_SUCCESS(iscsi_conn_create(addr_tgt, isp, &icp))) {
			/*
			 * Teardown the session we just created.  It can't
			 * have any luns or connections associated with it
			 * so this should always succeed (luckily since what
			 * would we do if it failed?)
			 */
			(void) iscsi_sess_destroy(isp);
			rtn = B_FALSE;
			break;
		}
	}
	rw_exit(&ihp->hba_sess_list_rwlock);
	kmem_free(ics, size);
	return (rtn);
}

/*
 * iscsid_del - Attempts to delete all associated sessions
 */
boolean_t
iscsid_del(iscsi_hba_t *ihp, char *target_name,
    iSCSIDiscoveryMethod_t method, struct sockaddr *addr_dsc)
{
	boolean_t	rtn = B_TRUE;
	iscsi_status_t	status;
	iscsi_sess_t	*isp;
	char		name[ISCSI_MAX_NAME_LEN];

	ASSERT(ihp != NULL);
	/* target name can be NULL or !NULL */
	/* addr_dsc can be NULL or !NULL */

	rw_enter(&ihp->hba_sess_list_rwlock, RW_WRITER);
	isp = ihp->hba_sess_list;
	while (isp != NULL) {
		/*
		 * If no target_name is listed (meaning all targets)
		 * or this specific target was listed. And the same
		 * discovery method discovered this target then
		 * continue evaulation.  Otherwise fail.
		 */
		if (((target_name == NULL) ||
		    (strcmp((char *)isp->sess_name, target_name) == 0)) &&
		    (isp->sess_discovered_by == method)) {
			boolean_t try_destroy;

			/*
			 * If iSNS, SendTargets, or Static then special
			 * handling for disc_addr.
			 */
			if ((method == iSCSIDiscoveryMethodISNS) ||
			    (method == iSCSIDiscoveryMethodSendTargets)) {
				/*
				 * If NULL addr_dsc (meaning all disc_addr)
				 * or matching discovered addr.
				 */
				if ((addr_dsc == NULL) ||
				    (bcmp(addr_dsc, &isp->sess_discovered_addr,
				    SIZEOF_SOCKADDR(
				    &isp->sess_discovered_addr.sin)) == 0)) {
					try_destroy = B_TRUE;
				} else {
					try_destroy = B_FALSE;
				}
			} else if (method == iSCSIDiscoveryMethodStatic) {
				/*
				 * If NULL addr_dsc (meaning all disc_addr)
				 * or matching active connection.
				 */
				if ((addr_dsc == NULL) ||
				    ((isp->sess_conn_act != NULL) &&
				    (bcmp(addr_dsc,
				    &isp->sess_conn_act->conn_base_addr.sin,
				    SIZEOF_SOCKADDR(
				    &isp->sess_conn_act->conn_base_addr.sin))
				    == 0))) {
					try_destroy = B_TRUE;
				} else {
					try_destroy = B_FALSE;
				}
			} else {
				/* Unknown discovery specified */
				try_destroy = B_TRUE;
			}

			if (try_destroy == B_TRUE &&
			    isp->sess_boot == B_FALSE) {
				(void) strcpy(name, (char *)isp->sess_name);
				status = iscsi_sess_destroy(isp);
				if (ISCSI_SUCCESS(status)) {
					iscsid_remove_target_param(name);
					isp = ihp->hba_sess_list;
				} else if (status == ISCSI_STATUS_BUSY) {
					/*
					 * The most likely destroy failure
					 * is that ndi/mdi offline failed.
					 * This means that the resource is
					 * in_use/busy.
					 */
					cmn_err(CE_NOTE, "iscsi session(%d) - "
					    "resource is in use\n",
					    isp->sess_oid);
					isp = isp->sess_next;
					rtn = B_FALSE;
				} else {
					cmn_err(CE_NOTE, "iscsi session(%d) - "
					    "session logout failed (%d)\n",
					    isp->sess_oid, status);
					isp = isp->sess_next;
					rtn = B_FALSE;
				}
			} else {
				isp = isp->sess_next;
			}
		} else {
			isp = isp->sess_next;
		}
	}
	rw_exit(&ihp->hba_sess_list_rwlock);
	return (rtn);
}


/*
 * iscsid_login_tgt - request target(s) to login
 */
boolean_t
iscsid_login_tgt(iscsi_hba_t *ihp, char *target_name,
    iSCSIDiscoveryMethod_t method, struct sockaddr *addr_dsc)
{
	boolean_t		rtn		= B_FALSE;
	iscsi_sess_t		*isp		= NULL;
	iscsi_sess_list_t	*isp_list	= NULL;
	iscsi_sess_list_t	*last_sess	= NULL;
	iscsi_sess_list_t	*cur_sess	= NULL;
	int			total		= 0;
	ddi_taskq_t		*login_taskq	= NULL;
	char			taskq_name[ISCSI_TH_MAX_NAME_LEN] = {0};
	time_t			time_stamp;

	ASSERT(ihp != NULL);

	rw_enter(&ihp->hba_sess_list_rwlock, RW_WRITER);
	/* Loop thru sessions */
	isp = ihp->hba_sess_list;
	while (isp != NULL) {
		boolean_t try_online;
		if (!(method & iSCSIDiscoveryMethodBoot)) {
			if (target_name == NULL) {
				if (method == iSCSIDiscoveryMethodUnknown) {
					/* unknown method mean login to all */
					try_online = B_TRUE;
				} else if (isp->sess_discovered_by & method) {
					if ((method ==
					    iSCSIDiscoveryMethodISNS) ||
					    (method ==
					    iSCSIDiscoveryMethodSendTargets)) {
#define	SESS_DISC_ADDR	isp->sess_discovered_addr.sin
						if ((addr_dsc == NULL) ||
						    (bcmp(
						    &isp->sess_discovered_addr,
						    addr_dsc, SIZEOF_SOCKADDR(
						    &SESS_DISC_ADDR))
						    == 0)) {
							/*
							 * iSNS or sendtarget
							 * discovery and
							 * discovery address
							 * is NULL or match
							 */
							try_online = B_TRUE;
						} else {
						/* addr_dsc not a match */
							try_online = B_FALSE;
						}
#undef SESS_DISC_ADDR
					} else {
						/* static configuration */
						try_online = B_TRUE;
					}
				} else {
					/* method not a match */
					try_online = B_FALSE;
				}
			} else if (strcmp(target_name,
			    (char *)isp->sess_name) == 0) {
				/* target_name match */
				try_online = B_TRUE;
			} else {
				/* target_name not a match */
				try_online = B_FALSE;
			}
		} else {
			/*
			 * online the boot session.
			 */
			if (isp->sess_boot == B_TRUE) {
				try_online = B_TRUE;
			}
		}

		if (try_online == B_TRUE &&
		    isp->sess_type == ISCSI_SESS_TYPE_NORMAL) {
			total++;
			/* Copy these sessions to the list. */
			if (isp_list == NULL) {
				isp_list =
				    (iscsi_sess_list_t *)kmem_zalloc(
				    sizeof (iscsi_sess_list_t), KM_SLEEP);
				last_sess = isp_list;
				last_sess->session = isp;
				last_sess->next = NULL;
			} else {
				last_sess->next =
				    (iscsi_sess_list_t *)kmem_zalloc(
				    sizeof (iscsi_sess_list_t), KM_SLEEP);
				last_sess->next->session = isp;
				last_sess->next->next = NULL;
				last_sess = last_sess->next;
			}
			rtn = B_TRUE;
		}

		isp = isp->sess_next;
	}

	if (total > 0) {
		time_stamp = ddi_get_time();
		(void) snprintf(taskq_name, (ISCSI_TH_MAX_NAME_LEN - 1),
		    "login_queue.%lx", time_stamp);

		login_taskq = ddi_taskq_create(ihp->hba_dip,
		    taskq_name, total, TASKQ_DEFAULTPRI, 0);
		if (login_taskq == NULL) {
			while (isp_list != NULL) {
				cur_sess = isp_list;
				isp_list = isp_list->next;
				kmem_free(cur_sess, sizeof (iscsi_sess_list_t));
			}
			rtn = B_FALSE;
			rw_exit(&ihp->hba_sess_list_rwlock);
			return (rtn);
		}

		for (cur_sess = isp_list; cur_sess != NULL;
		    cur_sess = cur_sess->next) {
			if (ddi_taskq_dispatch(login_taskq,
			    iscsi_sess_online, (void *)cur_sess->session,
			    DDI_SLEEP) != DDI_SUCCESS) {
				cmn_err(CE_NOTE, "Can't dispatch the task "
				    "for login to the target: %s",
				    cur_sess->session->sess_name);
			}
		}

		ddi_taskq_wait(login_taskq);
		ddi_taskq_destroy(login_taskq);
		while (isp_list != NULL) {
			cur_sess = isp_list;
			isp_list = isp_list->next;
			kmem_free(cur_sess, sizeof (iscsi_sess_list_t));
		}

	}

	rw_exit(&ihp->hba_sess_list_rwlock);
	return (rtn);
}

/*
 * +--------------------------------------------------------------------+
 * | Local Helper Functions                                             |
 * +--------------------------------------------------------------------+
 */

/*
 * iscsid_init_config -- initialize configuration parameters of iSCSI initiator
 */
static boolean_t
iscsid_init_config(iscsi_hba_t *ihp)
{
	iscsi_param_set_t	ips;
	void *v = NULL;
	char *name;
	char *initiatorName;
	persistent_param_t	pp;
	persistent_tunable_param_t pparam;
	uint32_t		param_id;
	int			rc;

	/* allocate memory to hold initiator names */
	initiatorName = kmem_zalloc(ISCSI_MAX_NAME_LEN, KM_SLEEP);

	/*
	 * initialize iSCSI initiator name
	 */
	bzero(&ips, sizeof (ips));
	if (persistent_initiator_name_get(initiatorName,
	    ISCSI_MAX_NAME_LEN) == B_TRUE) {
		ips.s_vers	= ISCSI_INTERFACE_VERSION;
		ips.s_param	= ISCSI_LOGIN_PARAM_INITIATOR_NAME;

		if (iscsiboot_prop && !iscsi_cmp_boot_ini_name(initiatorName)) {
			(void) strncpy(initiatorName,
			    (const char *)iscsiboot_prop->boot_init.ini_name,
			    ISCSI_MAX_NAME_LEN);
			(void) strncpy((char *)ips.s_value.v_name,
			    (const char *)iscsiboot_prop->boot_init.ini_name,
			    sizeof (ips.s_value.v_name));
			(void) iscsi_set_params(&ips, ihp, B_TRUE);
			/* use default tunable value */
			ihp->hba_tunable_params.recv_login_rsp_timeout =
			    ISCSI_DEFAULT_RX_TIMEOUT_VALUE;
			ihp->hba_tunable_params.polling_login_delay =
			    ISCSI_DEFAULT_LOGIN_POLLING_DELAY;
			ihp->hba_tunable_params.conn_login_max =
			    ISCSI_DEFAULT_CONN_DEFAULT_LOGIN_MAX;
			cmn_err(CE_NOTE, "Set initiator's name"
			    " from firmware");
		} else {
			(void) strncpy((char *)ips.s_value.v_name,
			    initiatorName, sizeof (ips.s_value.v_name));

			(void) iscsi_set_params(&ips, ihp, B_FALSE);
			if (persistent_get_tunable_param(initiatorName,
			    &pparam) == B_FALSE) {
				/* use default value */
				pparam.p_params.recv_login_rsp_timeout =
				    ISCSI_DEFAULT_RX_TIMEOUT_VALUE;
				pparam.p_params.polling_login_delay =
				    ISCSI_DEFAULT_LOGIN_POLLING_DELAY;
				pparam.p_params.conn_login_max =
				    ISCSI_DEFAULT_CONN_DEFAULT_LOGIN_MAX;
			}
			bcopy(&pparam.p_params, &ihp->hba_tunable_params,
			    sizeof (iscsi_tunable_params_t));
		}
	} else {
		/*
		 * if no initiator-node name available it is most
		 * likely due to a fresh install, or the persistent
		 * store is not working correctly. Set
		 * a default initiator name so that the initiator can
		 * be brought up properly.
		 */
		iscsid_set_default_initiator_node_settings(ihp, B_FALSE);
		(void) strncpy(initiatorName, (const char *)ihp->hba_name,
		    ISCSI_MAX_NAME_LEN);
	}

	/*
	 * initialize iSCSI initiator alias (if any)
	 */
	bzero(&ips, sizeof (ips));
	if (persistent_alias_name_get((char *)ips.s_value.v_name,
	    sizeof (ips.s_value.v_name)) == B_TRUE) {
		ips.s_param	= ISCSI_LOGIN_PARAM_INITIATOR_ALIAS;
		(void) iscsi_set_params(&ips, ihp, B_FALSE);
	} else {
		/* EMPTY */
		/* No alias defined - not a problem. */
	}

	/*
	 * load up the overriden iSCSI initiator parameters
	 */
	name = kmem_zalloc(ISCSI_MAX_NAME_LEN, KM_SLEEP);
	persistent_param_lock();
	v = NULL;
	while (persistent_param_next(&v, name, &pp) == B_TRUE) {
		if (strncmp(name, initiatorName, ISCSI_MAX_NAME_LEN) == 0) {
			ips.s_oid = ihp->hba_oid;
			ips.s_vers = ISCSI_INTERFACE_VERSION;
			for (param_id = 0; param_id < ISCSI_NUM_LOGIN_PARAM;
			    param_id++) {
				if (pp.p_bitmap & (1 << param_id)) {
					rc = iscsid_copyto_param_set(param_id,
					    &pp.p_params, &ips);
					if (rc == 0) {
						rc = iscsi_set_params(&ips,
						    ihp, B_FALSE);
					}
					if (rc != 0) {
						/* note error but continue  */
						cmn_err(CE_NOTE,
						    "Failed to set "
						    "param %d for OID %d",
						    ips.s_param, ips.s_oid);
					}
				}
			} /* END for() */
			if (iscsiboot_prop &&
			    iscsi_chk_bootlun_mpxio(ihp)) {
				(void) iscsi_reconfig_boot_sess(ihp);
			}
			break;
		}
	} /* END while() */
	persistent_param_unlock();

	kmem_free(initiatorName, ISCSI_MAX_NAME_LEN);
	kmem_free(name, ISCSI_MAX_NAME_LEN);
	return (B_TRUE);
}


/*
 * iscsid_init_targets -- Load up the driver with known static targets and
 * targets whose parameters have been modified.
 *
 * This is done so that the CLI can find a list of targets the driver
 * currently knows about.
 *
 * The driver doesn't need to log into these targets.  Log in is done based
 * upon the enabled discovery methods.
 */
static boolean_t
iscsid_init_targets(iscsi_hba_t *ihp)
{
	void			*v = NULL;
	char			*name;
	iscsi_param_set_t	ips;
	persistent_param_t	pp;
	char			*iname;
	uint32_t		param_id;
	int			rc;

	ASSERT(ihp != NULL);

	/* allocate memory to hold target names */
	name = kmem_zalloc(ISCSI_MAX_NAME_LEN, KM_SLEEP);

	/*
	 * load up targets whose parameters have been overriden
	 */

	/* ---- only need to be set once ---- */
	bzero(&ips, sizeof (ips));
	ips.s_vers = ISCSI_INTERFACE_VERSION;

	/* allocate memory to hold initiator name */
	iname = kmem_zalloc(ISCSI_MAX_NAME_LEN, KM_SLEEP);
	(void) persistent_initiator_name_get(iname, ISCSI_MAX_NAME_LEN);

	persistent_param_lock();
	v = NULL;
	while (persistent_param_next(&v, name, &pp) == B_TRUE) {

		if (strncmp(iname, name, ISCSI_MAX_NAME_LEN) == 0) {
			/*
			 * target name matched initiator's name so,
			 * continue to next target.  Initiator's
			 * parmeters have already been set.
			 */
			continue;
		}

		if (iscsiboot_prop && iscsi_cmp_boot_tgt_name(name) &&
		    !iscsi_chk_bootlun_mpxio(ihp)) {
			/*
			 * boot target is not mpxio enabled
			 * simply ignore these overriden parameters
			 */
			continue;
		}

		ips.s_oid = iscsi_targetparam_get_oid((unsigned char *)name);

		for (param_id = 0; param_id < ISCSI_NUM_LOGIN_PARAM;
		    param_id++) {
			if (pp.p_bitmap & (1 << param_id)) {
				rc = iscsid_copyto_param_set(param_id,
				    &pp.p_params, &ips);
				if (rc == 0) {
					rc = iscsi_set_params(&ips,
					    ihp, B_FALSE);
				}
				if (rc != 0) {
					/* note error but continue  ---- */
					cmn_err(CE_NOTE, "Failed to set "
					    "param %d for OID %d",
					    ips.s_param, ips.s_oid);
				}
			}
		} /* END for() */
		if (iscsiboot_prop && iscsi_cmp_boot_tgt_name(name) &&
		    iscsi_chk_bootlun_mpxio(ihp)) {
			(void) iscsi_reconfig_boot_sess(ihp);
		}
	} /* END while() */
	persistent_param_unlock();

	kmem_free(iname, ISCSI_MAX_NAME_LEN);
	kmem_free(name, ISCSI_MAX_NAME_LEN);

	return (B_TRUE);
}


/*
 * iscsid_thread_static -- If static discovery is enabled, this routine obtains
 * all statically configured targets from the peristent store and issues a
 * login request to the driver.
 */
/* ARGSUSED */
static void
iscsid_thread_static(iscsi_thread_t *thread, void *p)
{
	iSCSIDiscoveryMethod_t	dm;
	entry_t			entry;
	char			name[ISCSI_MAX_NAME_LEN];
	void			*v = NULL;
	iscsi_hba_t		*ihp = (iscsi_hba_t *)p;

	while (iscsi_thread_wait(thread, -1) != 0) {
		iscsi_discovery_event(ihp, iSCSIDiscoveryMethodStatic, B_TRUE);

		/* ---- ensure static target discovery is enabled ---- */
		dm = persistent_disc_meth_get();
		if ((dm & iSCSIDiscoveryMethodStatic) == 0) {
			cmn_err(CE_NOTE,
			    "iscsi discovery failure - "
			    "StaticTargets method is not enabled");
			iscsi_discovery_event(ihp,
			    iSCSIDiscoveryMethodStatic, B_FALSE);
			continue;
		}

		/*
		 * walk list of the statically configured targets from the
		 * persistent store
		 */
		v = NULL;
		persistent_static_addr_lock();
		while (persistent_static_addr_next(&v, name, &entry) ==
		    B_TRUE) {
			iscsi_sockaddr_t addr;

			iscsid_addr_to_sockaddr(entry.e_insize,
			    &(entry.e_u), entry.e_port, &addr.sin);

			(void) iscsid_add(ihp, iSCSIDiscoveryMethodStatic,
			    &addr.sin, name, entry.e_tpgt, &addr.sin);
		}
		persistent_static_addr_unlock();
		iscsi_discovery_event(ihp, iSCSIDiscoveryMethodStatic, B_FALSE);
	}
}


/*
 * iscsid_thread_sendtgts -- If SendTargets discovery is enabled, this routine
 * obtains all target discovery addresses configured from the peristent store
 * and probe the IP/port addresses for possible targets.  It will then issue
 * a login request to the driver for all discoveryed targets.
 */
static void
iscsid_thread_sendtgts(iscsi_thread_t *thread, void *p)
{
	iscsi_hba_t		*ihp = (iscsi_hba_t *)p;
	iSCSIDiscoveryMethod_t	dm;
	entry_t			entry;
	void			*v = NULL;

	while (iscsi_thread_wait(thread, -1) != 0) {
		iscsi_discovery_event(ihp, iSCSIDiscoveryMethodSendTargets,
		    B_TRUE);

		/* ---- ensure SendTargets discovery is enabled ---- */
		dm = persistent_disc_meth_get();
		if ((dm & iSCSIDiscoveryMethodSendTargets) == 0) {
			cmn_err(CE_NOTE,
			    "iscsi discovery failure - "
			    "SendTargets method is not enabled");
			iscsi_discovery_event(ihp,
			    iSCSIDiscoveryMethodSendTargets, B_FALSE);
			continue;
		}
		/*
		 * walk list of the SendTarget discovery addresses from the
		 * persistent store
		 */
		v = NULL;
		persistent_disc_addr_lock();
		while (persistent_disc_addr_next(&v, &entry) == B_TRUE) {
			iscsid_do_sendtgts(&entry);
		}
		persistent_disc_addr_unlock();

		iscsi_discovery_event(ihp, iSCSIDiscoveryMethodSendTargets,
		    B_FALSE);
	}
}

/*
 * iscsid_thread_slp -- If SLP discovery is enabled,  this routine provides
 * the SLP discovery service.
 */
static void
iscsid_thread_slp(iscsi_thread_t *thread, void *p)
{
	iscsi_hba_t  *ihp = (iscsi_hba_t *)p;

	do {
		/*
		 * Even though we don't have support for SLP at this point
		 * we'll send the events if someone has enabled this thread.
		 * If this is not done the daemon waiting for discovery to
		 * complete will pause forever holding up the boot process.
		 */
		iscsi_discovery_event(ihp, iSCSIDiscoveryMethodSLP, B_TRUE);
		iscsi_discovery_event(ihp, iSCSIDiscoveryMethodSLP, B_FALSE);
	} while (iscsi_thread_wait(thread, -1) != 0);
}

/*
 * iscsid_thread_isns --
 */
static void
iscsid_thread_isns(iscsi_thread_t *thread, void *ptr)
{
	iscsi_hba_t		*ihp = (iscsi_hba_t *)ptr;
	iSCSIDiscoveryMethod_t	dm;

	while (iscsi_thread_wait(thread, -1) != 0) {
		iscsi_discovery_event(ihp, iSCSIDiscoveryMethodISNS, B_TRUE);

		/* ---- ensure iSNS discovery is enabled ---- */
		dm = persistent_disc_meth_get();
		if ((dm & iSCSIDiscoveryMethodISNS) == 0) {
			cmn_err(CE_NOTE,
			    "iscsi discovery failure - "
			    "iSNS method is not enabled");
			iscsi_discovery_event(ihp,
			    iSCSIDiscoveryMethodISNS, B_FALSE);
			continue;
		}

		(void) isns_reg(ihp->hba_isid,
		    ihp->hba_name,
		    ISCSI_MAX_NAME_LEN,
		    ihp->hba_alias,
		    ISCSI_MAX_NAME_LEN,
		    ISNS_INITIATOR_NODE_TYPE,
		    isns_scn_callback);
		iscsid_do_isns_query(ihp);
		iscsi_discovery_event(ihp, iSCSIDiscoveryMethodISNS, B_FALSE);
	}

	/* Thread stopped. Deregister from iSNS servers(s). */
	(void) isns_dereg(ihp->hba_isid, ihp->hba_name);
}


/*
 * iscsid_threads_create -- Creates all the discovery threads.
 */
static void
iscsid_threads_create(iscsi_hba_t *ihp)
{
	iscsid_thr_table	*t;

	/*
	 * start a thread for each discovery method
	 */
	for (t = &iscsid_thr[0]; t->method != iSCSIDiscoveryMethodUnknown;
	    t++) {
		if (t->thr_id == NULL) {
			t->thr_id = iscsi_thread_create(ihp->hba_dip, t->name,
			    t->func_start, ihp);
		}
	}
}

/*
 * iscsid_threads_destroy -- Destroys all the discovery threads.
 */
static void
iscsid_threads_destroy(void)
{
	iscsid_thr_table	*t;

	for (t = &iscsid_thr[0]; t->method != iSCSIDiscoveryMethodUnknown;
	    t++) {
		if (t->thr_id != NULL) {
			iscsi_thread_destroy(t->thr_id);
			t->thr_id = NULL;
		}
	}
}

/*
 * iscsid_copyto_param_set - helper function for iscsid_init_params.
 */
static int
iscsid_copyto_param_set(uint32_t param_id, iscsi_login_params_t *params,
    iscsi_param_set_t *ipsp)
{
	int rtn = 0;

	if (param_id >= ISCSI_NUM_LOGIN_PARAM) {
		return (EINVAL);
	}

	switch (param_id) {

	/*
	 * Boolean parameters
	 */
	case ISCSI_LOGIN_PARAM_DATA_SEQUENCE_IN_ORDER:
		ipsp->s_value.v_bool = params->data_pdu_in_order;
		break;
	case ISCSI_LOGIN_PARAM_IMMEDIATE_DATA:
		ipsp->s_value.v_bool = params->immediate_data;
		break;
	case ISCSI_LOGIN_PARAM_INITIAL_R2T:
		ipsp->s_value.v_bool = params->initial_r2t;
		break;
	case ISCSI_LOGIN_PARAM_DATA_PDU_IN_ORDER:
		ipsp->s_value.v_bool = params->data_pdu_in_order;
		break;

	/*
	 * Integer parameters
	 */
	case ISCSI_LOGIN_PARAM_HEADER_DIGEST:
		ipsp->s_value.v_integer = params->header_digest;
		break;
	case ISCSI_LOGIN_PARAM_DATA_DIGEST:
		ipsp->s_value.v_integer = params->data_digest;
		break;
	case ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_RETAIN:
		ipsp->s_value.v_integer = params->default_time_to_retain;
		break;
	case ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_WAIT:
		ipsp->s_value.v_integer = params->default_time_to_wait;
		break;
	case ISCSI_LOGIN_PARAM_MAX_RECV_DATA_SEGMENT_LENGTH:
		ipsp->s_value.v_integer = params->max_recv_data_seg_len;
		break;
	case ISCSI_LOGIN_PARAM_FIRST_BURST_LENGTH:
		ipsp->s_value.v_integer = params->first_burst_length;
		break;
	case ISCSI_LOGIN_PARAM_MAX_BURST_LENGTH:
		ipsp->s_value.v_integer =  params->max_burst_length;
		break;

	/*
	 * Integer parameters which currently are unsettable
	 */
	case ISCSI_LOGIN_PARAM_MAX_CONNECTIONS:
	case ISCSI_LOGIN_PARAM_OUTSTANDING_R2T:
	case ISCSI_LOGIN_PARAM_ERROR_RECOVERY_LEVEL:
	/* ---- drop through to default case ---- */
	default:
		rtn = EINVAL;
		break;
	}

	/* if all is well, set the parameter identifier */
	if (rtn == 0) {
		ipsp->s_param = param_id;
	}

	return (rtn);
}

/*
 * iscsid_add_pg_list_to_cache - Add portal groups in the list to the
 * discovery cache.
 */
static void
iscsid_add_pg_list_to_cache(iscsi_hba_t *ihp,
    isns_portal_group_list_t *pg_list)
{
	int		    i;

	for (i = 0; i < pg_list->pg_out_cnt; i++) {
		iscsi_sockaddr_t addr_dsc;
		iscsi_sockaddr_t addr_tgt;

		iscsid_addr_to_sockaddr(
		    pg_list->pg_list[i].isns_server_ip.i_insize,
		    &pg_list->pg_list[i].isns_server_ip.i_addr,
		    pg_list->pg_list[i].isns_server_port,
		    &addr_dsc.sin);
		iscsid_addr_to_sockaddr(
		    pg_list->pg_list[i].insize,
		    &pg_list->pg_list[i].pg_ip_addr,
		    pg_list->pg_list[i].pg_port,
		    &addr_tgt.sin);

		(void) iscsid_add(ihp, iSCSIDiscoveryMethodISNS, &addr_dsc.sin,
		    (char *)pg_list->pg_list[i].pg_iscsi_name,
		    pg_list->pg_list[i].pg_tag, &addr_tgt.sin);
	}
}

/*
 * set_initiator_name - set default initiator name and alias.
 *
 * This sets the default initiator name and alias.  The
 * initiator name is composed of sun's reverse domain name
 * and registration followed and a unique classifier.  This
 * classifier is the mac address of the first NIC in the
 * host and a timestamp to make sure the classifier is
 * unique if the NIC is moved between hosts.  The alias
 * is just the hostname.
 */
void
iscsid_set_default_initiator_node_settings(iscsi_hba_t *ihp, boolean_t minimal)
{
	int		    i;
	time_t		    x;
	struct ether_addr   eaddr;
	char		    val[10];
	iscsi_chap_props_t  *chap = NULL;

	/* Set default initiator-node name */
	if (iscsiboot_prop && iscsiboot_prop->boot_init.ini_name != NULL) {
		(void) strncpy((char *)ihp->hba_name,
		    (const char *)iscsiboot_prop->boot_init.ini_name,
		    ISCSI_MAX_NAME_LEN);
	} else {
		(void) snprintf((char *)ihp->hba_name,
		    ISCSI_MAX_NAME_LEN,
		    "iqn.1986-03.com.sun:01:");

		(void) localetheraddr(NULL, &eaddr);
		for (i = 0; i <  ETHERADDRL; i++) {
			(void) snprintf(val, sizeof (val), "%02x",
			    eaddr.ether_addr_octet[i]);
			(void) strncat((char *)ihp->hba_name, val,
			    ISCSI_MAX_NAME_LEN);
		}

		/* Set default initiator-node alias */
		x = ddi_get_time();
		(void) snprintf(val, sizeof (val), ".%lx", x);
		(void) strncat((char *)ihp->hba_name, val, ISCSI_MAX_NAME_LEN);

		if (ihp->hba_alias[0] == '\0') {
			(void) strncpy((char *)ihp->hba_alias,
			    utsname.nodename, ISCSI_MAX_NAME_LEN);
			ihp->hba_alias_length = strlen((char *)ihp->hba_alias);
			if (minimal == B_FALSE) {
				(void) persistent_alias_name_set(
				    (char *)ihp->hba_alias);
			}
		}
	}

	if (minimal == B_TRUE) {
		return;
	}

	(void) persistent_initiator_name_set((char *)ihp->hba_name);

	/* Set default initiator-node CHAP settings */
	if (persistent_initiator_name_get((char *)ihp->hba_name,
	    ISCSI_MAX_NAME_LEN) == B_TRUE) {
		chap = (iscsi_chap_props_t *)kmem_zalloc(sizeof (*chap),
		    KM_SLEEP);
		if (persistent_chap_get((char *)ihp->hba_name, chap) ==
		    B_FALSE) {
			bcopy((char *)ihp->hba_name, chap->c_user,
			    strlen((char *)ihp->hba_name));
			chap->c_user_len = strlen((char *)ihp->hba_name);
			(void) persistent_chap_set((char *)ihp->hba_name, chap);
		}
		kmem_free(chap, sizeof (*chap));
	}
}

static void
iscsid_remove_target_param(char *name)
{
	persistent_param_t  *pparam;
	uint32_t	    t_oid;
	iscsi_config_sess_t *ics;

	ASSERT(name != NULL);

	/*
	 * Remove target-param <-> target mapping.
	 * Only remove if there is not any overridden
	 * parameters in the persistent store
	 */
	pparam = (persistent_param_t *)kmem_zalloc(sizeof (*pparam), KM_SLEEP);

	/*
	 * setup initial buffer for configured session
	 * information
	 */
	ics = (iscsi_config_sess_t *)kmem_zalloc(sizeof (*ics), KM_SLEEP);
	ics->ics_in = 1;

	if ((persistent_param_get(name, pparam) == B_FALSE) &&
	    (persistent_get_config_session(name, ics) == B_FALSE))  {
		t_oid = iscsi_targetparam_get_oid((uchar_t *)name);
		(void) iscsi_targetparam_remove_target(t_oid);
	}

	kmem_free(pparam, sizeof (*pparam));
	pparam = NULL;
	kmem_free(ics, sizeof (*ics));
	ics = NULL;
}

/*
 * iscsid_addr_to_sockaddr - convert other types to struct sockaddr
 */
void
iscsid_addr_to_sockaddr(int src_insize, void *src_addr, int src_port,
    struct sockaddr *dst_addr)
{
	ASSERT((src_insize == sizeof (struct in_addr)) ||
	    (src_insize == sizeof (struct in6_addr)));
	ASSERT(src_addr != NULL);
	ASSERT(dst_addr != NULL);

	bzero(dst_addr, sizeof (*dst_addr));

	/* translate discovery information */
	if (src_insize == sizeof (struct in_addr)) {
		struct sockaddr_in *addr_in =
		    (struct sockaddr_in *)dst_addr;
		addr_in->sin_family = AF_INET;
		bcopy(src_addr, &addr_in->sin_addr.s_addr,
		    sizeof (struct in_addr));
		addr_in->sin_port = htons(src_port);
	} else {
		struct sockaddr_in6 *addr_in6 =
		    (struct sockaddr_in6 *)dst_addr;
		addr_in6->sin6_family = AF_INET6;
		bcopy(src_addr, &addr_in6->sin6_addr.s6_addr,
		    sizeof (struct in6_addr));
		addr_in6->sin6_port = htons(src_port);
	}
}

/*
 * iscsi_discovery_event -- send event associated with discovery operations
 *
 * Each discovery event has a start and end event. Which is sent is based
 * on the boolean argument start with the obvious results.
 */
static void
iscsi_discovery_event(iscsi_hba_t *ihp, iSCSIDiscoveryMethod_t m,
    boolean_t start)
{
	char	*subclass = NULL;

	mutex_enter(&ihp->hba_discovery_events_mutex);
	switch (m) {
	case iSCSIDiscoveryMethodStatic:
		if (start == B_TRUE) {
			subclass = ESC_ISCSI_STATIC_START;
		} else {
			ihp->hba_discovery_events |= iSCSIDiscoveryMethodStatic;
			subclass = ESC_ISCSI_STATIC_END;
		}
		break;

	case iSCSIDiscoveryMethodSendTargets:
		if (start == B_TRUE) {
			subclass = ESC_ISCSI_SEND_TARGETS_START;
		} else {
			ihp->hba_discovery_events |=
			    iSCSIDiscoveryMethodSendTargets;
			subclass = ESC_ISCSI_SEND_TARGETS_END;
		}
		break;

	case iSCSIDiscoveryMethodSLP:
		if (start == B_TRUE) {
			subclass = ESC_ISCSI_SLP_START;
		} else {
			ihp->hba_discovery_events |= iSCSIDiscoveryMethodSLP;
			subclass = ESC_ISCSI_SLP_END;
		}
		break;

	case iSCSIDiscoveryMethodISNS:
		if (start == B_TRUE) {
			subclass = ESC_ISCSI_ISNS_START;
		} else {
			ihp->hba_discovery_events |= iSCSIDiscoveryMethodISNS;
			subclass = ESC_ISCSI_ISNS_END;
		}
		break;
	}
	mutex_exit(&ihp->hba_discovery_events_mutex);
	iscsi_send_sysevent(ihp, EC_ISCSI, subclass, NULL);
}

/*
 * iscsi_send_sysevent -- send sysevent using specified class
 */
void
iscsi_send_sysevent(
    iscsi_hba_t	*ihp,
    char	*eventclass,
    char	*subclass,
    nvlist_t	*np)
{
	(void) ddi_log_sysevent(ihp->hba_dip, DDI_VENDOR_SUNW, eventclass,
	    subclass, np, NULL, DDI_SLEEP);
}

static boolean_t
iscsid_boot_init_config(iscsi_hba_t *ihp)
{
	if (strlen((const char *)iscsiboot_prop->boot_init.ini_name) != 0) {
		bcopy(iscsiboot_prop->boot_init.ini_name,
		    ihp->hba_name,
		    strlen((const char *)iscsiboot_prop->boot_init.ini_name));
	}
	/* or using default login param for boot session */
	return (B_TRUE);
}

boolean_t
iscsi_reconfig_boot_sess(iscsi_hba_t *ihp)
{
	iscsi_config_sess_t	*ics;
	int			idx;
	iscsi_sess_t		*isp, *t_isp;
	int			isid, size;
	char			*name;
	boolean_t		rtn = B_TRUE;
	uint32_t		event_count;

	if (iscsiboot_prop == NULL) {
		return (B_FALSE);
	}
	size = sizeof (*ics);
	ics = kmem_zalloc(size, KM_SLEEP);
	ics->ics_in = 1;

	/* get information of number of sessions to be configured */
	name = (char *)iscsiboot_prop->boot_tgt.tgt_name;
	if (persistent_get_config_session(name, ics) == B_FALSE) {
		/*
		 * No target information available to check
		 * initiator information. Assume one session
		 * by default.
		 */
		name = (char *)iscsiboot_prop->boot_init.ini_name;
		if (persistent_get_config_session(name, ics) == B_FALSE) {
			ics->ics_out = 1;
			ics->ics_bound = B_TRUE;
		}
	}

	/* get necessary information */
	if (ics->ics_out > 1) {
		idx = ics->ics_out;
		size = ISCSI_SESSION_CONFIG_SIZE(ics->ics_out);
		kmem_free(ics, sizeof (*ics));

		ics = kmem_zalloc(size, KM_SLEEP);
		ics->ics_in = idx;

		/* get configured sessions information */
		if (persistent_get_config_session((char *)name,
		    ics) != B_TRUE) {
			cmn_err(CE_NOTE, "session(%s) - "
			    "failed to setup multiple sessions",
			    name);
			kmem_free(ics, size);
			return (B_FALSE);
		}
	}

	/* create a temporary session to keep boot session connective */
	t_isp = iscsi_add_boot_sess(ihp, ISCSI_MAX_CONFIG_SESSIONS);
	if (t_isp == NULL) {
		cmn_err(CE_NOTE, "session(%s) - "
		    "failed to setup multiple sessions", name);
		rw_exit(&ihp->hba_sess_list_rwlock);
		kmem_free(ics, size);
		return (B_FALSE);
	}

	/* destroy all old boot sessions */
	rw_enter(&ihp->hba_sess_list_rwlock, RW_WRITER);
	isp = ihp->hba_sess_list;
	while (isp != NULL) {
		if (iscsi_chk_bootlun_mpxio(ihp) && isp->sess_boot) {
			if (isp->sess_isid[5] != ISCSI_MAX_CONFIG_SESSIONS) {
				/*
				 * destroy all stale sessions
				 * except temporary boot session
				 */
				if (ISCSI_SUCCESS(iscsi_sess_destroy(
				    isp))) {
					isp = ihp->hba_sess_list;
				} else {
					/*
					 * couldn't destroy stale sessions
					 * at least poke it to disconnect
					 */
					event_count = atomic_inc_32_nv(
					    &isp->sess_state_event_count);
					iscsi_sess_enter_state_zone(isp);
					iscsi_sess_state_machine(isp,
					    ISCSI_SESS_EVENT_N7, event_count);
					iscsi_sess_exit_state_zone(isp);

					isp = isp->sess_next;
					cmn_err(CE_NOTE, "session(%s) - "
					    "failed to setup multiple"
					    " sessions", name);
				}
			} else {
				isp = isp->sess_next;
			}
		} else {
			isp = isp->sess_next;
		}
	}
	rw_exit(&ihp->hba_sess_list_rwlock);

	for (isid = 0; isid < ics->ics_out; isid++) {
		isp = iscsi_add_boot_sess(ihp, isid);
		if (isp == NULL) {
			cmn_err(CE_NOTE, "session(%s) - failed to setup"
			    " multiple sessions", name);
			rtn = B_FALSE;
			break;
		}
	}
	if (!rtn && (isid == 0)) {
		/*
		 * fail to create any new boot session
		 * so only the temporary session is alive
		 * quit without destroying it
		 */
		kmem_free(ics, size);
		return (rtn);
	}

	rw_enter(&ihp->hba_sess_list_rwlock, RW_WRITER);
	if (!ISCSI_SUCCESS(iscsi_sess_destroy(t_isp))) {
		/* couldn't destroy temp boot session */
		cmn_err(CE_NOTE, "session(%s) - "
		    "failed to setup multiple sessions", name);
		rw_exit(&ihp->hba_sess_list_rwlock);
		rtn = B_FALSE;
	}
	rw_exit(&ihp->hba_sess_list_rwlock);

	kmem_free(ics, size);
	return (rtn);
}

static iscsi_sess_t *
iscsi_add_boot_sess(iscsi_hba_t *ihp, int isid)
{
	iscsi_sess_t	*isp;
	iscsi_conn_t    *icp;
	uint_t		oid;

	iscsi_sockaddr_t	addr_dst;

	addr_dst.sin.sa_family = iscsiboot_prop->boot_tgt.sin_family;
	if (addr_dst.sin.sa_family == AF_INET) {
		bcopy(&iscsiboot_prop->boot_tgt.tgt_ip_u.u_in4.s_addr,
		    &addr_dst.sin4.sin_addr.s_addr, sizeof (struct in_addr));
		addr_dst.sin4.sin_port =
		    htons(iscsiboot_prop->boot_tgt.tgt_port);
	} else {
		bcopy(&iscsiboot_prop->boot_tgt.tgt_ip_u.u_in6.s6_addr,
		    &addr_dst.sin6.sin6_addr.s6_addr,
		    sizeof (struct in6_addr));
		addr_dst.sin6.sin6_port =
		    htons(iscsiboot_prop->boot_tgt.tgt_port);
	}

	rw_enter(&ihp->hba_sess_list_rwlock, RW_WRITER);
	isp = iscsi_sess_create(ihp,
	    iSCSIDiscoveryMethodBoot|iSCSIDiscoveryMethodStatic,
	    (struct sockaddr *)&addr_dst,
	    (char *)iscsiboot_prop->boot_tgt.tgt_name,
	    ISCSI_DEFAULT_TPGT, isid, ISCSI_SESS_TYPE_NORMAL, &oid);
	if (isp == NULL) {
		/* create temp booting session failed */
		rw_exit(&ihp->hba_sess_list_rwlock);
		return (NULL);
	}
	isp->sess_boot = B_TRUE;

	if (!ISCSI_SUCCESS(iscsi_conn_create((struct sockaddr *)&addr_dst,
	    isp, &icp))) {
		rw_exit(&ihp->hba_sess_list_rwlock);
		return (NULL);
	}

	rw_exit(&ihp->hba_sess_list_rwlock);
	/* now online created session */
	if (iscsid_login_tgt(ihp, (char *)iscsiboot_prop->boot_tgt.tgt_name,
	    iSCSIDiscoveryMethodBoot|iSCSIDiscoveryMethodStatic,
	    (struct sockaddr *)&addr_dst) == B_FALSE) {
		return (NULL);
	}

	return (isp);
}

static void
iscsid_thread_boot_wd(iscsi_thread_t *thread, void *p)
{
	int			rc = 1;
	iscsi_hba_t		*ihp = (iscsi_hba_t *)p;
	boolean_t		reconfigured = B_FALSE;

	while (rc != 0) {
		if (iscsiboot_prop && (modrootloaded == 1)) {
			if (ihp->hba_persistent_loaded == B_FALSE) {
				if (persistent_load() == B_TRUE) {
					ihp->hba_persistent_loaded = B_TRUE;
				}
			}
			if ((ihp->hba_persistent_loaded == B_TRUE) &&
			    (reconfigured == B_FALSE)) {
				if (iscsi_chk_bootlun_mpxio(ihp) == B_TRUE) {
					(void) iscsi_reconfig_boot_sess(ihp);
					iscsid_poke_discovery(ihp,
					    iSCSIDiscoveryMethodUnknown);
					(void) iscsid_login_tgt(ihp, NULL,
					    iSCSIDiscoveryMethodUnknown, NULL);
				}
				reconfigured = B_TRUE;
			}
			break;
		}
		rc = iscsi_thread_wait(thread, SEC_TO_TICK(1));
	}
}

boolean_t
iscsi_cmp_boot_tgt_name(char *name)
{
	if (iscsiboot_prop && (strncmp((const char *)name,
	    (const char *)iscsiboot_prop->boot_tgt.tgt_name,
	    ISCSI_MAX_NAME_LEN) == 0)) {
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}

boolean_t
iscsi_cmp_boot_ini_name(char *name)
{
	if (iscsiboot_prop && (strncmp((const char *)name,
	    (const char *)iscsiboot_prop->boot_init.ini_name,
	    ISCSI_MAX_NAME_LEN) == 0)) {
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}

boolean_t
iscsi_chk_bootlun_mpxio(iscsi_hba_t *ihp)
{
	iscsi_sess_t    *isp;
	iscsi_lun_t	*ilp;
	isp = ihp->hba_sess_list;
	boolean_t	tgt_mpxio_enabled = B_FALSE;
	boolean_t	bootlun_found = B_FALSE;
	uint16_t    lun_num;

	if (iscsiboot_prop == NULL) {
		return (B_FALSE);
	}

	if (!ihp->hba_mpxio_enabled) {
		return (B_FALSE);
	}

	lun_num = *((uint64_t *)(iscsiboot_prop->boot_tgt.tgt_boot_lun));

	while (isp != NULL) {
		if ((strncmp((char *)isp->sess_name,
		    (const char *)iscsiboot_prop->boot_tgt.tgt_name,
		    ISCSI_MAX_NAME_LEN) == 0) &&
		    (isp->sess_boot == B_TRUE)) {
			/*
			 * found boot session.
			 * check its mdi path info is null or not
			 */
			ilp = isp->sess_lun_list;
			while (ilp != NULL) {
				if (lun_num == ilp->lun_num) {
					if (ilp->lun_pip) {
						tgt_mpxio_enabled = B_TRUE;
					}
					bootlun_found = B_TRUE;
				}
				ilp = ilp->lun_next;
			}
		}
		isp = isp->sess_next;
	}
	if (bootlun_found) {
		return (tgt_mpxio_enabled);
	} else {
		/*
		 * iscsiboot_prop not NULL while no boot lun found
		 * in most cases this is none iscsi boot while iscsiboot_prop
		 * is not NULL, in this scenario return iscsi HBA's mpxio config
		 */
		return (ihp->hba_mpxio_enabled);
	}
}

static boolean_t
iscsid_check_active_boot_conn(iscsi_hba_t *ihp)
{
	iscsi_sess_t	*isp = NULL;
	iscsi_conn_t	*icp = NULL;

	rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
	isp = ihp->hba_sess_list;
	while (isp != NULL) {
		if (isp->sess_boot == B_TRUE) {
			rw_enter(&isp->sess_conn_list_rwlock, RW_READER);
			icp = isp->sess_conn_list;
			while (icp != NULL) {
				if (icp->conn_state ==
				    ISCSI_CONN_STATE_LOGGED_IN) {
					rw_exit(&isp->sess_conn_list_rwlock);
					rw_exit(&ihp->hba_sess_list_rwlock);
					return (B_TRUE);
				}
				icp = icp->conn_next;
			}
			rw_exit(&isp->sess_conn_list_rwlock);
		}
		isp = isp->sess_next;
	}
	rw_exit(&ihp->hba_sess_list_rwlock);

	return (B_FALSE);
}
