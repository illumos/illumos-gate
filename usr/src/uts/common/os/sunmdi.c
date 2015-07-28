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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2014 Nexenta Systems Inc. All rights reserved.
 */

/*
 * Multipath driver interface (MDI) implementation; see mdi_impldefs.h for a
 * more detailed discussion of the overall mpxio architecture.
 *
 * Default locking order:
 *
 * _NOTE(LOCK_ORDER(mdi_mutex, mdi_vhci:vh_phci_mutex);
 * _NOTE(LOCK_ORDER(mdi_mutex, mdi_vhci:vh_client_mutex);
 * _NOTE(LOCK_ORDER(mdi_vhci:vh_phci_mutex, mdi_phci::ph_mutex);
 * _NOTE(LOCK_ORDER(mdi_vhci:vh_client_mutex, mdi_client::ct_mutex);
 * _NOTE(LOCK_ORDER(mdi_phci::ph_mutex mdi_pathinfo::pi_mutex))
 * _NOTE(LOCK_ORDER(mdi_phci::ph_mutex mdi_client::ct_mutex))
 * _NOTE(LOCK_ORDER(mdi_client::ct_mutex mdi_pathinfo::pi_mutex))
 */

#include <sys/note.h>
#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/poll.h>
#include <sys/conf.h>
#include <sys/bootconf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddipropdefs.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/promif.h>
#include <sys/sunmdi.h>
#include <sys/mdi_impldefs.h>
#include <sys/taskq.h>
#include <sys/epm.h>
#include <sys/sunpm.h>
#include <sys/modhash.h>
#include <sys/disp.h>
#include <sys/autoconf.h>
#include <sys/sysmacros.h>

#ifdef	DEBUG
#include <sys/debug.h>
int	mdi_debug = 1;
int	mdi_debug_logonly = 0;
#define	MDI_DEBUG(dbglevel, pargs) if (mdi_debug >= (dbglevel))	i_mdi_log pargs
#define	MDI_WARN	CE_WARN, __func__
#define	MDI_NOTE	CE_NOTE, __func__
#define	MDI_CONT	CE_CONT, __func__
static void i_mdi_log(int, const char *, dev_info_t *, const char *, ...);
#else	/* !DEBUG */
#define	MDI_DEBUG(dbglevel, pargs)
#endif	/* DEBUG */
int	mdi_debug_consoleonly = 0;
int	mdi_delay = 3;

extern pri_t	minclsyspri;
extern int	modrootloaded;

/*
 * Global mutex:
 * Protects vHCI list and structure members.
 */
kmutex_t	mdi_mutex;

/*
 * Registered vHCI class driver lists
 */
int		mdi_vhci_count;
mdi_vhci_t	*mdi_vhci_head;
mdi_vhci_t	*mdi_vhci_tail;

/*
 * Client Hash Table size
 */
static int	mdi_client_table_size = CLIENT_HASH_TABLE_SIZE;

/*
 * taskq interface definitions
 */
#define	MDI_TASKQ_N_THREADS	8
#define	MDI_TASKQ_PRI		minclsyspri
#define	MDI_TASKQ_MINALLOC	(4*mdi_taskq_n_threads)
#define	MDI_TASKQ_MAXALLOC	(500*mdi_taskq_n_threads)

taskq_t				*mdi_taskq;
static uint_t			mdi_taskq_n_threads = MDI_TASKQ_N_THREADS;

#define	TICKS_PER_SECOND	(drv_usectohz(1000000))

/*
 * The data should be "quiet" for this interval (in seconds) before the
 * vhci cached data is flushed to the disk.
 */
static int mdi_vhcache_flush_delay = 10;

/* number of seconds the vhcache flush daemon will sleep idle before exiting */
static int mdi_vhcache_flush_daemon_idle_time = 60;

/*
 * MDI falls back to discovery of all paths when a bus_config_one fails.
 * The following parameters can be used to tune this operation.
 *
 * mdi_path_discovery_boot
 *	Number of times path discovery will be attempted during early boot.
 *	Probably there is no reason to ever set this value to greater than one.
 *
 * mdi_path_discovery_postboot
 *	Number of times path discovery will be attempted after early boot.
 *	Set it to a minimum of two to allow for discovery of iscsi paths which
 *	may happen very late during booting.
 *
 * mdi_path_discovery_interval
 *	Minimum number of seconds MDI will wait between successive discovery
 *	of all paths. Set it to -1 to disable discovery of all paths.
 */
static int mdi_path_discovery_boot = 1;
static int mdi_path_discovery_postboot = 2;
static int mdi_path_discovery_interval = 10;

/*
 * number of seconds the asynchronous configuration thread will sleep idle
 * before exiting.
 */
static int mdi_async_config_idle_time = 600;

static int mdi_bus_config_cache_hash_size = 256;

/* turns off multithreaded configuration for certain operations */
static int mdi_mtc_off = 0;

/*
 * The "path" to a pathinfo node is identical to the /devices path to a
 * devinfo node had the device been enumerated under a pHCI instead of
 * a vHCI.  This pathinfo "path" is associated with a 'path_instance'.
 * This association persists across create/delete of the pathinfo nodes,
 * but not across reboot.
 */
static uint_t		mdi_pathmap_instance = 1;	/* 0 -> any path */
static int		mdi_pathmap_hash_size = 256;
static kmutex_t		mdi_pathmap_mutex;
static mod_hash_t	*mdi_pathmap_bypath;		/* "path"->instance */
static mod_hash_t	*mdi_pathmap_byinstance;	/* instance->"path" */
static mod_hash_t	*mdi_pathmap_sbyinstance;	/* inst->shortpath */

/*
 * MDI component property name/value string definitions
 */
const char 		*mdi_component_prop = "mpxio-component";
const char		*mdi_component_prop_vhci = "vhci";
const char		*mdi_component_prop_phci = "phci";
const char		*mdi_component_prop_client = "client";

/*
 * MDI client global unique identifier property name
 */
const char		*mdi_client_guid_prop = "client-guid";

/*
 * MDI client load balancing property name/value string definitions
 */
const char		*mdi_load_balance = "load-balance";
const char		*mdi_load_balance_none = "none";
const char		*mdi_load_balance_rr = "round-robin";
const char		*mdi_load_balance_lba = "logical-block";

/*
 * Obsolete vHCI class definition; to be removed after Leadville update
 */
const char *mdi_vhci_class_scsi = MDI_HCI_CLASS_SCSI;

static char vhci_greeting[] =
	"\tThere already exists one vHCI driver for class %s\n"
	"\tOnly one vHCI driver for each class is allowed\n";

/*
 * Static function prototypes
 */
static int		i_mdi_phci_offline(dev_info_t *, uint_t);
static int		i_mdi_client_offline(dev_info_t *, uint_t);
static int		i_mdi_phci_pre_detach(dev_info_t *, ddi_detach_cmd_t);
static void		i_mdi_phci_post_detach(dev_info_t *,
			    ddi_detach_cmd_t, int);
static int		i_mdi_client_pre_detach(dev_info_t *,
			    ddi_detach_cmd_t);
static void		i_mdi_client_post_detach(dev_info_t *,
			    ddi_detach_cmd_t, int);
static void		i_mdi_pm_hold_pip(mdi_pathinfo_t *);
static void		i_mdi_pm_rele_pip(mdi_pathinfo_t *);
static int 		i_mdi_lba_lb(mdi_client_t *ct,
			    mdi_pathinfo_t **ret_pip, struct buf *buf);
static void		i_mdi_pm_hold_client(mdi_client_t *, int);
static void		i_mdi_pm_rele_client(mdi_client_t *, int);
static void		i_mdi_pm_reset_client(mdi_client_t *);
static int		i_mdi_power_all_phci(mdi_client_t *);
static void		i_mdi_log_sysevent(dev_info_t *, char *, char *);


/*
 * Internal mdi_pathinfo node functions
 */
static void		i_mdi_pi_kstat_destroy(mdi_pathinfo_t *);

static mdi_vhci_t	*i_mdi_vhci_class2vhci(char *);
static mdi_vhci_t	*i_devi_get_vhci(dev_info_t *);
static mdi_phci_t	*i_devi_get_phci(dev_info_t *);
static void		i_mdi_phci_lock(mdi_phci_t *, mdi_pathinfo_t *);
static void		i_mdi_phci_unlock(mdi_phci_t *);
static mdi_pathinfo_t	*i_mdi_pi_alloc(mdi_phci_t *, char *, mdi_client_t *);
static void		i_mdi_phci_add_path(mdi_phci_t *, mdi_pathinfo_t *);
static void		i_mdi_client_add_path(mdi_client_t *, mdi_pathinfo_t *);
static void		i_mdi_pi_free(mdi_phci_t *ph, mdi_pathinfo_t *,
			    mdi_client_t *);
static void		i_mdi_phci_remove_path(mdi_phci_t *, mdi_pathinfo_t *);
static void		i_mdi_client_remove_path(mdi_client_t *,
			    mdi_pathinfo_t *);

static int		i_mdi_pi_state_change(mdi_pathinfo_t *,
			    mdi_pathinfo_state_t, int);
static int		i_mdi_pi_offline(mdi_pathinfo_t *, int);
static dev_info_t	*i_mdi_devinfo_create(mdi_vhci_t *, char *, char *,
			    char **, int);
static dev_info_t	*i_mdi_devinfo_find(mdi_vhci_t *, char *, char *);
static int		i_mdi_devinfo_remove(dev_info_t *, dev_info_t *, int);
static int		i_mdi_is_child_present(dev_info_t *, dev_info_t *);
static mdi_client_t	*i_mdi_client_alloc(mdi_vhci_t *, char *, char *);
static void		i_mdi_client_enlist_table(mdi_vhci_t *, mdi_client_t *);
static void		i_mdi_client_delist_table(mdi_vhci_t *, mdi_client_t *);
static mdi_client_t	*i_mdi_client_find(mdi_vhci_t *, char *, char *);
static void		i_mdi_client_update_state(mdi_client_t *);
static int		i_mdi_client_compute_state(mdi_client_t *,
			    mdi_phci_t *);
static void		i_mdi_client_lock(mdi_client_t *, mdi_pathinfo_t *);
static void		i_mdi_client_unlock(mdi_client_t *);
static int		i_mdi_client_free(mdi_vhci_t *, mdi_client_t *);
static mdi_client_t	*i_devi_get_client(dev_info_t *);
/*
 * NOTE: this will be removed once the NWS files are changed to use the new
 * mdi_{enable,disable}_path interfaces
 */
static int		i_mdi_pi_enable_disable(dev_info_t *, dev_info_t *,
				int, int);
static mdi_pathinfo_t 	*i_mdi_enable_disable_path(mdi_pathinfo_t *pip,
				mdi_vhci_t *vh, int flags, int op);
/*
 * Failover related function prototypes
 */
static int		i_mdi_failover(void *);

/*
 * misc internal functions
 */
static int		i_mdi_get_hash_key(char *);
static int		i_map_nvlist_error_to_mdi(int);
static void		i_mdi_report_path_state(mdi_client_t *,
			    mdi_pathinfo_t *);

static void		setup_vhci_cache(mdi_vhci_t *);
static int		destroy_vhci_cache(mdi_vhci_t *);
static int		stop_vhcache_async_threads(mdi_vhci_config_t *);
static boolean_t	stop_vhcache_flush_thread(void *, int);
static void		free_string_array(char **, int);
static void		free_vhcache_phci(mdi_vhcache_phci_t *);
static void		free_vhcache_pathinfo(mdi_vhcache_pathinfo_t *);
static void		free_vhcache_client(mdi_vhcache_client_t *);
static int		mainnvl_to_vhcache(mdi_vhci_cache_t *, nvlist_t *);
static nvlist_t		*vhcache_to_mainnvl(mdi_vhci_cache_t *);
static void		vhcache_phci_add(mdi_vhci_config_t *, mdi_phci_t *);
static void		vhcache_phci_remove(mdi_vhci_config_t *, mdi_phci_t *);
static void		vhcache_pi_add(mdi_vhci_config_t *,
			    struct mdi_pathinfo *);
static void		vhcache_pi_remove(mdi_vhci_config_t *,
			    struct mdi_pathinfo *);
static void		free_phclient_path_list(mdi_phys_path_t *);
static void		sort_vhcache_paths(mdi_vhcache_client_t *);
static int		flush_vhcache(mdi_vhci_config_t *, int);
static void		vhcache_dirty(mdi_vhci_config_t *);
static void		free_async_client_config(mdi_async_client_config_t *);
static void		single_threaded_vhconfig_enter(mdi_vhci_config_t *);
static void		single_threaded_vhconfig_exit(mdi_vhci_config_t *);
static nvlist_t		*read_on_disk_vhci_cache(char *);
extern int		fread_nvlist(char *, nvlist_t **);
extern int		fwrite_nvlist(char *, nvlist_t *);

/* called once when first vhci registers with mdi */
static void
i_mdi_init()
{
	static int initialized = 0;

	if (initialized)
		return;
	initialized = 1;

	mutex_init(&mdi_mutex, NULL, MUTEX_DEFAULT, NULL);

	/* Create our taskq resources */
	mdi_taskq = taskq_create("mdi_taskq", mdi_taskq_n_threads,
	    MDI_TASKQ_PRI, MDI_TASKQ_MINALLOC, MDI_TASKQ_MAXALLOC,
	    TASKQ_PREPOPULATE | TASKQ_CPR_SAFE);
	ASSERT(mdi_taskq != NULL);	/* taskq_create never fails */

	/* Allocate ['path_instance' <-> "path"] maps */
	mutex_init(&mdi_pathmap_mutex, NULL, MUTEX_DRIVER, NULL);
	mdi_pathmap_bypath = mod_hash_create_strhash(
	    "mdi_pathmap_bypath", mdi_pathmap_hash_size,
	    mod_hash_null_valdtor);
	mdi_pathmap_byinstance = mod_hash_create_idhash(
	    "mdi_pathmap_byinstance", mdi_pathmap_hash_size,
	    mod_hash_null_valdtor);
	mdi_pathmap_sbyinstance = mod_hash_create_idhash(
	    "mdi_pathmap_sbyinstance", mdi_pathmap_hash_size,
	    mod_hash_null_valdtor);
}

/*
 * mdi_get_component_type():
 *		Return mpxio component type
 * Return Values:
 *		MDI_COMPONENT_NONE
 *		MDI_COMPONENT_VHCI
 *		MDI_COMPONENT_PHCI
 *		MDI_COMPONENT_CLIENT
 * XXX This doesn't work under multi-level MPxIO and should be
 *	removed when clients migrate mdi_component_is_*() interfaces.
 */
int
mdi_get_component_type(dev_info_t *dip)
{
	return (DEVI(dip)->devi_mdi_component);
}

/*
 * mdi_vhci_register():
 *		Register a vHCI module with the mpxio framework
 *		mdi_vhci_register() is called by vHCI drivers to register the
 *		'class_driver' vHCI driver and its MDI entrypoints with the
 *		mpxio framework.  The vHCI driver must call this interface as
 *		part of its attach(9e) handler.
 *		Competing threads may try to attach mdi_vhci_register() as
 *		the vHCI drivers are loaded and attached as a result of pHCI
 *		driver instance registration (mdi_phci_register()) with the
 *		framework.
 * Return Values:
 *		MDI_SUCCESS
 *		MDI_FAILURE
 */
/*ARGSUSED*/
int
mdi_vhci_register(char *class, dev_info_t *vdip, mdi_vhci_ops_t *vops,
    int flags)
{
	mdi_vhci_t		*vh = NULL;

	/* Registrant can't be older */
	ASSERT(vops->vo_revision <= MDI_VHCI_OPS_REV);

#ifdef DEBUG
	/*
	 * IB nexus driver is loaded only when IB hardware is present.
	 * In order to be able to do this there is a need to drive the loading
	 * and attaching of the IB nexus driver (especially when an IB hardware
	 * is dynamically plugged in) when an IB HCA driver (PHCI)
	 * is being attached. Unfortunately this gets into the limitations
	 * of devfs as there seems to be no clean way to drive configuration
	 * of a subtree from another subtree of a devfs. Hence, do not ASSERT
	 * for IB.
	 */
	if (strcmp(class, MDI_HCI_CLASS_IB) != 0)
		ASSERT(DEVI_BUSY_OWNED(ddi_get_parent(vdip)));
#endif

	i_mdi_init();

	mutex_enter(&mdi_mutex);
	/*
	 * Scan for already registered vhci
	 */
	for (vh = mdi_vhci_head; vh != NULL; vh = vh->vh_next) {
		if (strcmp(vh->vh_class, class) == 0) {
			/*
			 * vHCI has already been created.  Check for valid
			 * vHCI ops registration.  We only support one vHCI
			 * module per class
			 */
			if (vh->vh_ops != NULL) {
				mutex_exit(&mdi_mutex);
				cmn_err(CE_NOTE, vhci_greeting, class);
				return (MDI_FAILURE);
			}
			break;
		}
	}

	/*
	 * if not yet created, create the vHCI component
	 */
	if (vh == NULL) {
		struct client_hash	*hash = NULL;
		char			*load_balance;

		/*
		 * Allocate and initialize the mdi extensions
		 */
		vh = kmem_zalloc(sizeof (mdi_vhci_t), KM_SLEEP);
		hash = kmem_zalloc(mdi_client_table_size * sizeof (*hash),
		    KM_SLEEP);
		vh->vh_client_table = hash;
		vh->vh_class = kmem_zalloc(strlen(class) + 1, KM_SLEEP);
		(void) strcpy(vh->vh_class, class);
		vh->vh_lb = LOAD_BALANCE_RR;
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, vdip,
		    0, LOAD_BALANCE_PROP, &load_balance) == DDI_SUCCESS) {
			if (strcmp(load_balance, LOAD_BALANCE_PROP_NONE) == 0) {
				vh->vh_lb = LOAD_BALANCE_NONE;
			} else if (strcmp(load_balance, LOAD_BALANCE_PROP_LBA)
				    == 0) {
				vh->vh_lb = LOAD_BALANCE_LBA;
			}
			ddi_prop_free(load_balance);
		}

		mutex_init(&vh->vh_phci_mutex, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&vh->vh_client_mutex, NULL, MUTEX_DEFAULT, NULL);

		/*
		 * Store the vHCI ops vectors
		 */
		vh->vh_dip = vdip;
		vh->vh_ops = vops;

		setup_vhci_cache(vh);

		if (mdi_vhci_head == NULL) {
			mdi_vhci_head = vh;
		}
		if (mdi_vhci_tail) {
			mdi_vhci_tail->vh_next = vh;
		}
		mdi_vhci_tail = vh;
		mdi_vhci_count++;
	}

	/*
	 * Claim the devfs node as a vhci component
	 */
	DEVI(vdip)->devi_mdi_component |= MDI_COMPONENT_VHCI;

	/*
	 * Initialize our back reference from dev_info node
	 */
	DEVI(vdip)->devi_mdi_xhci = (caddr_t)vh;
	mutex_exit(&mdi_mutex);
	return (MDI_SUCCESS);
}

/*
 * mdi_vhci_unregister():
 *		Unregister a vHCI module from mpxio framework
 *		mdi_vhci_unregister() is called from the detach(9E) entrypoint
 * 		of a vhci to unregister it from the framework.
 * Return Values:
 *		MDI_SUCCESS
 *		MDI_FAILURE
 */
/*ARGSUSED*/
int
mdi_vhci_unregister(dev_info_t *vdip, int flags)
{
	mdi_vhci_t	*found, *vh, *prev = NULL;

	ASSERT(DEVI_BUSY_OWNED(ddi_get_parent(vdip)));

	/*
	 * Check for invalid VHCI
	 */
	if ((vh = i_devi_get_vhci(vdip)) == NULL)
		return (MDI_FAILURE);

	/*
	 * Scan the list of registered vHCIs for a match
	 */
	mutex_enter(&mdi_mutex);
	for (found = mdi_vhci_head; found != NULL; found = found->vh_next) {
		if (found == vh)
			break;
		prev = found;
	}

	if (found == NULL) {
		mutex_exit(&mdi_mutex);
		return (MDI_FAILURE);
	}

	/*
	 * Check the vHCI, pHCI and client count. All the pHCIs and clients
	 * should have been unregistered, before a vHCI can be
	 * unregistered.
	 */
	MDI_VHCI_PHCI_LOCK(vh);
	if (vh->vh_refcnt || vh->vh_phci_count || vh->vh_client_count) {
		MDI_VHCI_PHCI_UNLOCK(vh);
		mutex_exit(&mdi_mutex);
		return (MDI_FAILURE);
	}
	MDI_VHCI_PHCI_UNLOCK(vh);

	if (destroy_vhci_cache(vh) != MDI_SUCCESS) {
		mutex_exit(&mdi_mutex);
		return (MDI_FAILURE);
	}

	/*
	 * Remove the vHCI from the global list
	 */
	if (vh == mdi_vhci_head) {
		mdi_vhci_head = vh->vh_next;
	} else {
		prev->vh_next = vh->vh_next;
	}
	if (vh == mdi_vhci_tail) {
		mdi_vhci_tail = prev;
	}
	mdi_vhci_count--;
	mutex_exit(&mdi_mutex);

	vh->vh_ops = NULL;
	DEVI(vdip)->devi_mdi_component &= ~MDI_COMPONENT_VHCI;
	DEVI(vdip)->devi_mdi_xhci = NULL;
	kmem_free(vh->vh_class, strlen(vh->vh_class)+1);
	kmem_free(vh->vh_client_table,
	    mdi_client_table_size * sizeof (struct client_hash));
	mutex_destroy(&vh->vh_phci_mutex);
	mutex_destroy(&vh->vh_client_mutex);

	kmem_free(vh, sizeof (mdi_vhci_t));
	return (MDI_SUCCESS);
}

/*
 * i_mdi_vhci_class2vhci():
 *		Look for a matching vHCI module given a vHCI class name
 * Return Values:
 *		Handle to a vHCI component
 *		NULL
 */
static mdi_vhci_t *
i_mdi_vhci_class2vhci(char *class)
{
	mdi_vhci_t	*vh = NULL;

	ASSERT(!MUTEX_HELD(&mdi_mutex));

	mutex_enter(&mdi_mutex);
	for (vh = mdi_vhci_head; vh != NULL; vh = vh->vh_next) {
		if (strcmp(vh->vh_class, class) == 0) {
			break;
		}
	}
	mutex_exit(&mdi_mutex);
	return (vh);
}

/*
 * i_devi_get_vhci():
 *		Utility function to get the handle to a vHCI component
 * Return Values:
 *		Handle to a vHCI component
 *		NULL
 */
mdi_vhci_t *
i_devi_get_vhci(dev_info_t *vdip)
{
	mdi_vhci_t	*vh = NULL;
	if (MDI_VHCI(vdip)) {
		vh = (mdi_vhci_t *)DEVI(vdip)->devi_mdi_xhci;
	}
	return (vh);
}

/*
 * mdi_phci_register():
 *		Register a pHCI module with mpxio framework
 *		mdi_phci_register() is called by pHCI drivers to register with
 *		the mpxio framework and a specific 'class_driver' vHCI.  The
 *		pHCI driver must call this interface as part of its attach(9e)
 *		handler.
 * Return Values:
 *		MDI_SUCCESS
 *		MDI_FAILURE
 */
/*ARGSUSED*/
int
mdi_phci_register(char *class, dev_info_t *pdip, int flags)
{
	mdi_phci_t		*ph;
	mdi_vhci_t		*vh;
	char			*data;

	/*
	 * Some subsystems, like fcp, perform pHCI registration from a
	 * different thread than the one doing the pHCI attach(9E) - the
	 * driver attach code is waiting for this other thread to complete.
	 * This means we can only ASSERT DEVI_BUSY_CHANGING of parent
	 * (indicating that some thread has done an ndi_devi_enter of parent)
	 * not DEVI_BUSY_OWNED (which would indicate that we did the enter).
	 */
	ASSERT(DEVI_BUSY_CHANGING(ddi_get_parent(pdip)));

	/*
	 * Check for mpxio-disable property. Enable mpxio if the property is
	 * missing or not set to "yes".
	 * If the property is set to "yes" then emit a brief message.
	 */
	if ((ddi_prop_lookup_string(DDI_DEV_T_ANY, pdip, 0, "mpxio-disable",
	    &data) == DDI_SUCCESS)) {
		if (strcmp(data, "yes") == 0) {
			MDI_DEBUG(1, (MDI_CONT, pdip,
			    "?multipath capabilities disabled via %s.conf.",
			    ddi_driver_name(pdip)));
			ddi_prop_free(data);
			return (MDI_FAILURE);
		}
		ddi_prop_free(data);
	}

	/*
	 * Search for a matching vHCI
	 */
	vh = (mdi_vhci_t *)i_mdi_vhci_class2vhci(class);
	if (vh == NULL) {
		return (MDI_FAILURE);
	}

	ph = kmem_zalloc(sizeof (mdi_phci_t), KM_SLEEP);
	mutex_init(&ph->ph_mutex, NULL, MUTEX_DEFAULT, NULL);
	ph->ph_dip = pdip;
	ph->ph_vhci = vh;
	ph->ph_next = NULL;
	ph->ph_unstable = 0;
	ph->ph_vprivate = 0;
	cv_init(&ph->ph_unstable_cv, NULL, CV_DRIVER, NULL);

	MDI_PHCI_LOCK(ph);
	MDI_PHCI_SET_POWER_UP(ph);
	MDI_PHCI_UNLOCK(ph);
	DEVI(pdip)->devi_mdi_component |= MDI_COMPONENT_PHCI;
	DEVI(pdip)->devi_mdi_xhci = (caddr_t)ph;

	vhcache_phci_add(vh->vh_config, ph);

	MDI_VHCI_PHCI_LOCK(vh);
	if (vh->vh_phci_head == NULL) {
		vh->vh_phci_head = ph;
	}
	if (vh->vh_phci_tail) {
		vh->vh_phci_tail->ph_next = ph;
	}
	vh->vh_phci_tail = ph;
	vh->vh_phci_count++;
	MDI_VHCI_PHCI_UNLOCK(vh);

	i_mdi_log_sysevent(pdip, class, ESC_DDI_INITIATOR_REGISTER);
	return (MDI_SUCCESS);
}

/*
 * mdi_phci_unregister():
 *		Unregister a pHCI module from mpxio framework
 *		mdi_phci_unregister() is called by the pHCI drivers from their
 *		detach(9E) handler to unregister their instances from the
 *		framework.
 * Return Values:
 *		MDI_SUCCESS
 *		MDI_FAILURE
 */
/*ARGSUSED*/
int
mdi_phci_unregister(dev_info_t *pdip, int flags)
{
	mdi_vhci_t		*vh;
	mdi_phci_t		*ph;
	mdi_phci_t		*tmp;
	mdi_phci_t		*prev = NULL;
	mdi_pathinfo_t		*pip;

	ASSERT(DEVI_BUSY_CHANGING(ddi_get_parent(pdip)));

	ph = i_devi_get_phci(pdip);
	if (ph == NULL) {
		MDI_DEBUG(1, (MDI_WARN, pdip, "!not a valid pHCI"));
		return (MDI_FAILURE);
	}

	vh = ph->ph_vhci;
	ASSERT(vh != NULL);
	if (vh == NULL) {
		MDI_DEBUG(1, (MDI_WARN, pdip, "!not a valid vHCI"));
		return (MDI_FAILURE);
	}

	MDI_VHCI_PHCI_LOCK(vh);
	tmp = vh->vh_phci_head;
	while (tmp) {
		if (tmp == ph) {
			break;
		}
		prev = tmp;
		tmp = tmp->ph_next;
	}

	if (ph == vh->vh_phci_head) {
		vh->vh_phci_head = ph->ph_next;
	} else {
		prev->ph_next = ph->ph_next;
	}

	if (ph == vh->vh_phci_tail) {
		vh->vh_phci_tail = prev;
	}

	vh->vh_phci_count--;
	MDI_VHCI_PHCI_UNLOCK(vh);

	/* Walk remaining pathinfo nodes and disassociate them from pHCI */
	MDI_PHCI_LOCK(ph);
	for (pip = (mdi_pathinfo_t *)ph->ph_path_head; pip;
	    pip = (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link)
		MDI_PI(pip)->pi_phci = NULL;
	MDI_PHCI_UNLOCK(ph);

	i_mdi_log_sysevent(pdip, ph->ph_vhci->vh_class,
	    ESC_DDI_INITIATOR_UNREGISTER);
	vhcache_phci_remove(vh->vh_config, ph);
	cv_destroy(&ph->ph_unstable_cv);
	mutex_destroy(&ph->ph_mutex);
	kmem_free(ph, sizeof (mdi_phci_t));
	DEVI(pdip)->devi_mdi_component &= ~MDI_COMPONENT_PHCI;
	DEVI(pdip)->devi_mdi_xhci = NULL;
	return (MDI_SUCCESS);
}

/*
 * i_devi_get_phci():
 * 		Utility function to return the phci extensions.
 */
static mdi_phci_t *
i_devi_get_phci(dev_info_t *pdip)
{
	mdi_phci_t	*ph = NULL;

	if (MDI_PHCI(pdip)) {
		ph = (mdi_phci_t *)DEVI(pdip)->devi_mdi_xhci;
	}
	return (ph);
}

/*
 * Single thread mdi entry into devinfo node for modifying its children.
 * If necessary we perform an ndi_devi_enter of the vHCI before doing
 * an ndi_devi_enter of 'dip'.  We maintain circular in two parts: one
 * for the vHCI and one for the pHCI.
 */
void
mdi_devi_enter(dev_info_t *phci_dip, int *circular)
{
	dev_info_t	*vdip;
	int		vcircular, pcircular;

	/* Verify calling context */
	ASSERT(MDI_PHCI(phci_dip));
	vdip = mdi_devi_get_vdip(phci_dip);
	ASSERT(vdip);			/* A pHCI always has a vHCI */

	/*
	 * If pHCI is detaching then the framework has already entered the
	 * vHCI on a threads that went down the code path leading to
	 * detach_node().  This framework enter of the vHCI during pHCI
	 * detach is done to avoid deadlock with vHCI power management
	 * operations which enter the vHCI and the enter down the path
	 * to the pHCI. If pHCI is detaching then we piggyback this calls
	 * enter of the vHCI on frameworks vHCI enter that has already
	 * occurred - this is OK because we know that the framework thread
	 * doing detach is waiting for our completion.
	 *
	 * We should DEVI_IS_DETACHING under an enter of the parent to avoid
	 * race with detach - but we can't do that because the framework has
	 * already entered the parent, so we have some complexity instead.
	 */
	for (;;) {
		if (ndi_devi_tryenter(vdip, &vcircular)) {
			ASSERT(vcircular != -1);
			if (DEVI_IS_DETACHING(phci_dip)) {
				ndi_devi_exit(vdip, vcircular);
				vcircular = -1;
			}
			break;
		} else if (DEVI_IS_DETACHING(phci_dip)) {
			vcircular = -1;
			break;
		} else if (servicing_interrupt()) {
			/*
			 * Don't delay an interrupt (and ensure adaptive
			 * mutex inversion support).
			 */
			ndi_devi_enter(vdip, &vcircular);
			break;
		} else {
			delay_random(mdi_delay);
		}
	}

	ndi_devi_enter(phci_dip, &pcircular);
	*circular = (vcircular << 16) | (pcircular & 0xFFFF);
}

/*
 * Attempt to mdi_devi_enter.
 */
int
mdi_devi_tryenter(dev_info_t *phci_dip, int *circular)
{
	dev_info_t	*vdip;
	int		vcircular, pcircular;

	/* Verify calling context */
	ASSERT(MDI_PHCI(phci_dip));
	vdip = mdi_devi_get_vdip(phci_dip);
	ASSERT(vdip);			/* A pHCI always has a vHCI */

	if (ndi_devi_tryenter(vdip, &vcircular)) {
		if (ndi_devi_tryenter(phci_dip, &pcircular)) {
			*circular = (vcircular << 16) | (pcircular & 0xFFFF);
			return (1);	/* locked */
		}
		ndi_devi_exit(vdip, vcircular);
	}
	return (0);			/* busy */
}

/*
 * Release mdi_devi_enter or successful mdi_devi_tryenter.
 */
void
mdi_devi_exit(dev_info_t *phci_dip, int circular)
{
	dev_info_t	*vdip;
	int		vcircular, pcircular;

	/* Verify calling context */
	ASSERT(MDI_PHCI(phci_dip));
	vdip = mdi_devi_get_vdip(phci_dip);
	ASSERT(vdip);			/* A pHCI always has a vHCI */

	/* extract two circular recursion values from single int */
	pcircular = (short)(circular & 0xFFFF);
	vcircular = (short)((circular >> 16) & 0xFFFF);

	ndi_devi_exit(phci_dip, pcircular);
	if (vcircular != -1)
		ndi_devi_exit(vdip, vcircular);
}

/*
 * The functions mdi_devi_exit_phci() and mdi_devi_enter_phci() are used
 * around a pHCI drivers calls to mdi_pi_online/offline, after holding
 * the pathinfo node via mdi_hold_path/mdi_rele_path, to avoid deadlock
 * with vHCI power management code during path online/offline.  Each
 * mdi_devi_exit_phci must have a matching mdi_devi_enter_phci, and both must
 * occur within the scope of an active mdi_devi_enter that establishes the
 * circular value.
 */
void
mdi_devi_exit_phci(dev_info_t *phci_dip, int circular)
{
	int		pcircular;

	/* Verify calling context */
	ASSERT(MDI_PHCI(phci_dip));

	/* Keep hold on pHCI until we reenter in mdi_devi_enter_phci */
	ndi_hold_devi(phci_dip);

	pcircular = (short)(circular & 0xFFFF);
	ndi_devi_exit(phci_dip, pcircular);
}

void
mdi_devi_enter_phci(dev_info_t *phci_dip, int *circular)
{
	int		pcircular;

	/* Verify calling context */
	ASSERT(MDI_PHCI(phci_dip));

	ndi_devi_enter(phci_dip, &pcircular);

	/* Drop hold from mdi_devi_exit_phci. */
	ndi_rele_devi(phci_dip);

	/* verify matching mdi_devi_exit_phci/mdi_devi_enter_phci use */
	ASSERT(pcircular == ((short)(*circular & 0xFFFF)));
}

/*
 * mdi_devi_get_vdip():
 *		given a pHCI dip return vHCI dip
 */
dev_info_t *
mdi_devi_get_vdip(dev_info_t *pdip)
{
	mdi_phci_t	*ph;

	ph = i_devi_get_phci(pdip);
	if (ph && ph->ph_vhci)
		return (ph->ph_vhci->vh_dip);
	return (NULL);
}

/*
 * mdi_devi_pdip_entered():
 *		Return 1 if we are vHCI and have done an ndi_devi_enter
 *		of a pHCI
 */
int
mdi_devi_pdip_entered(dev_info_t *vdip)
{
	mdi_vhci_t	*vh;
	mdi_phci_t	*ph;

	vh = i_devi_get_vhci(vdip);
	if (vh == NULL)
		return (0);

	MDI_VHCI_PHCI_LOCK(vh);
	ph = vh->vh_phci_head;
	while (ph) {
		if (ph->ph_dip && DEVI_BUSY_OWNED(ph->ph_dip)) {
			MDI_VHCI_PHCI_UNLOCK(vh);
			return (1);
		}
		ph = ph->ph_next;
	}
	MDI_VHCI_PHCI_UNLOCK(vh);
	return (0);
}

/*
 * mdi_phci_path2devinfo():
 * 		Utility function to search for a valid phci device given
 *		the devfs pathname.
 */
dev_info_t *
mdi_phci_path2devinfo(dev_info_t *vdip, caddr_t pathname)
{
	char		*temp_pathname;
	mdi_vhci_t	*vh;
	mdi_phci_t	*ph;
	dev_info_t 	*pdip = NULL;

	vh = i_devi_get_vhci(vdip);
	ASSERT(vh != NULL);

	if (vh == NULL) {
		/*
		 * Invalid vHCI component, return failure
		 */
		return (NULL);
	}

	temp_pathname = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	MDI_VHCI_PHCI_LOCK(vh);
	ph = vh->vh_phci_head;
	while (ph != NULL) {
		pdip = ph->ph_dip;
		ASSERT(pdip != NULL);
		*temp_pathname = '\0';
		(void) ddi_pathname(pdip, temp_pathname);
		if (strcmp(temp_pathname, pathname) == 0) {
			break;
		}
		ph = ph->ph_next;
	}
	if (ph == NULL) {
		pdip = NULL;
	}
	MDI_VHCI_PHCI_UNLOCK(vh);
	kmem_free(temp_pathname, MAXPATHLEN);
	return (pdip);
}

/*
 * mdi_phci_get_path_count():
 * 		get number of path information nodes associated with a given
 *		pHCI device.
 */
int
mdi_phci_get_path_count(dev_info_t *pdip)
{
	mdi_phci_t	*ph;
	int		count = 0;

	ph = i_devi_get_phci(pdip);
	if (ph != NULL) {
		count = ph->ph_path_count;
	}
	return (count);
}

/*
 * i_mdi_phci_lock():
 *		Lock a pHCI device
 * Return Values:
 *		None
 * Note:
 *		The default locking order is:
 *		_NOTE(LOCK_ORDER(mdi_phci::ph_mutex mdi_pathinfo::pi_mutex))
 *		But there are number of situations where locks need to be
 *		grabbed in reverse order.  This routine implements try and lock
 *		mechanism depending on the requested parameter option.
 */
static void
i_mdi_phci_lock(mdi_phci_t *ph, mdi_pathinfo_t *pip)
{
	if (pip) {
		/* Reverse locking is requested. */
		while (MDI_PHCI_TRYLOCK(ph) == 0) {
			if (servicing_interrupt()) {
				MDI_PI_HOLD(pip);
				MDI_PI_UNLOCK(pip);
				MDI_PHCI_LOCK(ph);
				MDI_PI_LOCK(pip);
				MDI_PI_RELE(pip);
				break;
			} else {
				/*
				 * tryenter failed. Try to grab again
				 * after a small delay
				 */
				MDI_PI_HOLD(pip);
				MDI_PI_UNLOCK(pip);
				delay_random(mdi_delay);
				MDI_PI_LOCK(pip);
				MDI_PI_RELE(pip);
			}
		}
	} else {
		MDI_PHCI_LOCK(ph);
	}
}

/*
 * i_mdi_phci_unlock():
 *		Unlock the pHCI component
 */
static void
i_mdi_phci_unlock(mdi_phci_t *ph)
{
	MDI_PHCI_UNLOCK(ph);
}

/*
 * i_mdi_devinfo_create():
 *		create client device's devinfo node
 * Return Values:
 *		dev_info
 *		NULL
 * Notes:
 */
static dev_info_t *
i_mdi_devinfo_create(mdi_vhci_t *vh, char *name, char *guid,
	char **compatible, int ncompatible)
{
	dev_info_t *cdip = NULL;

	ASSERT(MDI_VHCI_CLIENT_LOCKED(vh));

	/* Verify for duplicate entry */
	cdip = i_mdi_devinfo_find(vh, name, guid);
	ASSERT(cdip == NULL);
	if (cdip) {
		cmn_err(CE_WARN,
		    "i_mdi_devinfo_create: client %s@%s already exists",
			name ? name : "", guid ? guid : "");
	}

	ndi_devi_alloc_sleep(vh->vh_dip, name, DEVI_SID_NODEID, &cdip);
	if (cdip == NULL)
		goto fail;

	/*
	 * Create component type and Global unique identifier
	 * properties
	 */
	if (ndi_prop_update_string(DDI_DEV_T_NONE, cdip,
	    MDI_CLIENT_GUID_PROP, guid) != DDI_PROP_SUCCESS) {
		goto fail;
	}

	/* Decorate the node with compatible property */
	if (compatible &&
	    (ndi_prop_update_string_array(DDI_DEV_T_NONE, cdip,
	    "compatible", compatible, ncompatible) != DDI_PROP_SUCCESS)) {
		goto fail;
	}

	return (cdip);

fail:
	if (cdip) {
		(void) ndi_prop_remove_all(cdip);
		(void) ndi_devi_free(cdip);
	}
	return (NULL);
}

/*
 * i_mdi_devinfo_find():
 *		Find a matching devinfo node for given client node name
 *		and its guid.
 * Return Values:
 *		Handle to a dev_info node or NULL
 */
static dev_info_t *
i_mdi_devinfo_find(mdi_vhci_t *vh, caddr_t name, char *guid)
{
	char			*data;
	dev_info_t 		*cdip = NULL;
	dev_info_t 		*ndip = NULL;
	int			circular;

	ndi_devi_enter(vh->vh_dip, &circular);
	ndip = (dev_info_t *)DEVI(vh->vh_dip)->devi_child;
	while ((cdip = ndip) != NULL) {
		ndip = (dev_info_t *)DEVI(cdip)->devi_sibling;

		if (strcmp(DEVI(cdip)->devi_node_name, name)) {
			continue;
		}

		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, cdip,
		    DDI_PROP_DONTPASS, MDI_CLIENT_GUID_PROP,
		    &data) != DDI_PROP_SUCCESS) {
			continue;
		}

		if (strcmp(data, guid) != 0) {
			ddi_prop_free(data);
			continue;
		}
		ddi_prop_free(data);
		break;
	}
	ndi_devi_exit(vh->vh_dip, circular);
	return (cdip);
}

/*
 * i_mdi_devinfo_remove():
 *		Remove a client device node
 */
static int
i_mdi_devinfo_remove(dev_info_t *vdip, dev_info_t *cdip, int flags)
{
	int	rv = MDI_SUCCESS;

	if (i_mdi_is_child_present(vdip, cdip) == MDI_SUCCESS ||
	    (flags & MDI_CLIENT_FLAGS_DEV_NOT_SUPPORTED)) {
		rv = ndi_devi_offline(cdip, NDI_DEVFS_CLEAN | NDI_DEVI_REMOVE);
		if (rv != NDI_SUCCESS) {
			MDI_DEBUG(1, (MDI_NOTE, cdip,
			    "!failed: cdip %p", (void *)cdip));
		}
		/*
		 * Convert to MDI error code
		 */
		switch (rv) {
		case NDI_SUCCESS:
			rv = MDI_SUCCESS;
			break;
		case NDI_BUSY:
			rv = MDI_BUSY;
			break;
		default:
			rv = MDI_FAILURE;
			break;
		}
	}
	return (rv);
}

/*
 * i_devi_get_client()
 *		Utility function to get mpxio component extensions
 */
static mdi_client_t *
i_devi_get_client(dev_info_t *cdip)
{
	mdi_client_t	*ct = NULL;

	if (MDI_CLIENT(cdip)) {
		ct = (mdi_client_t *)DEVI(cdip)->devi_mdi_client;
	}
	return (ct);
}

/*
 * i_mdi_is_child_present():
 *		Search for the presence of client device dev_info node
 */
static int
i_mdi_is_child_present(dev_info_t *vdip, dev_info_t *cdip)
{
	int		rv = MDI_FAILURE;
	struct dev_info	*dip;
	int		circular;

	ndi_devi_enter(vdip, &circular);
	dip = DEVI(vdip)->devi_child;
	while (dip) {
		if (dip == DEVI(cdip)) {
			rv = MDI_SUCCESS;
			break;
		}
		dip = dip->devi_sibling;
	}
	ndi_devi_exit(vdip, circular);
	return (rv);
}


/*
 * i_mdi_client_lock():
 *		Grab client component lock
 * Return Values:
 *		None
 * Note:
 *		The default locking order is:
 *		_NOTE(LOCK_ORDER(mdi_client::ct_mutex mdi_pathinfo::pi_mutex))
 *		But there are number of situations where locks need to be
 *		grabbed in reverse order.  This routine implements try and lock
 *		mechanism depending on the requested parameter option.
 */
static void
i_mdi_client_lock(mdi_client_t *ct, mdi_pathinfo_t *pip)
{
	if (pip) {
		/*
		 * Reverse locking is requested.
		 */
		while (MDI_CLIENT_TRYLOCK(ct) == 0) {
			if (servicing_interrupt()) {
				MDI_PI_HOLD(pip);
				MDI_PI_UNLOCK(pip);
				MDI_CLIENT_LOCK(ct);
				MDI_PI_LOCK(pip);
				MDI_PI_RELE(pip);
				break;
			} else {
				/*
				 * tryenter failed. Try to grab again
				 * after a small delay
				 */
				MDI_PI_HOLD(pip);
				MDI_PI_UNLOCK(pip);
				delay_random(mdi_delay);
				MDI_PI_LOCK(pip);
				MDI_PI_RELE(pip);
			}
		}
	} else {
		MDI_CLIENT_LOCK(ct);
	}
}

/*
 * i_mdi_client_unlock():
 *		Unlock a client component
 */
static void
i_mdi_client_unlock(mdi_client_t *ct)
{
	MDI_CLIENT_UNLOCK(ct);
}

/*
 * i_mdi_client_alloc():
 * 		Allocate and initialize a client structure.  Caller should
 *		hold the vhci client lock.
 * Return Values:
 *		Handle to a client component
 */
/*ARGSUSED*/
static mdi_client_t *
i_mdi_client_alloc(mdi_vhci_t *vh, char *name, char *lguid)
{
	mdi_client_t	*ct;

	ASSERT(MDI_VHCI_CLIENT_LOCKED(vh));

	/*
	 * Allocate and initialize a component structure.
	 */
	ct = kmem_zalloc(sizeof (*ct), KM_SLEEP);
	mutex_init(&ct->ct_mutex, NULL, MUTEX_DEFAULT, NULL);
	ct->ct_hnext = NULL;
	ct->ct_hprev = NULL;
	ct->ct_dip = NULL;
	ct->ct_vhci = vh;
	ct->ct_drvname = kmem_alloc(strlen(name) + 1, KM_SLEEP);
	(void) strcpy(ct->ct_drvname, name);
	ct->ct_guid = kmem_alloc(strlen(lguid) + 1, KM_SLEEP);
	(void) strcpy(ct->ct_guid, lguid);
	ct->ct_cprivate = NULL;
	ct->ct_vprivate = NULL;
	ct->ct_flags = 0;
	ct->ct_state = MDI_CLIENT_STATE_FAILED;
	MDI_CLIENT_LOCK(ct);
	MDI_CLIENT_SET_OFFLINE(ct);
	MDI_CLIENT_SET_DETACH(ct);
	MDI_CLIENT_SET_POWER_UP(ct);
	MDI_CLIENT_UNLOCK(ct);
	ct->ct_failover_flags = 0;
	ct->ct_failover_status = 0;
	cv_init(&ct->ct_failover_cv, NULL, CV_DRIVER, NULL);
	ct->ct_unstable = 0;
	cv_init(&ct->ct_unstable_cv, NULL, CV_DRIVER, NULL);
	cv_init(&ct->ct_powerchange_cv, NULL, CV_DRIVER, NULL);
	ct->ct_lb = vh->vh_lb;
	ct->ct_lb_args =  kmem_zalloc(sizeof (client_lb_args_t), KM_SLEEP);
	ct->ct_lb_args->region_size = LOAD_BALANCE_DEFAULT_REGION_SIZE;
	ct->ct_path_count = 0;
	ct->ct_path_head = NULL;
	ct->ct_path_tail = NULL;
	ct->ct_path_last = NULL;

	/*
	 * Add this client component to our client hash queue
	 */
	i_mdi_client_enlist_table(vh, ct);
	return (ct);
}

/*
 * i_mdi_client_enlist_table():
 *		Attach the client device to the client hash table. Caller
 *		should hold the vhci client lock.
 */
static void
i_mdi_client_enlist_table(mdi_vhci_t *vh, mdi_client_t *ct)
{
	int 			index;
	struct client_hash	*head;

	ASSERT(MDI_VHCI_CLIENT_LOCKED(vh));

	index = i_mdi_get_hash_key(ct->ct_guid);
	head = &vh->vh_client_table[index];
	ct->ct_hnext = (mdi_client_t *)head->ct_hash_head;
	head->ct_hash_head = ct;
	head->ct_hash_count++;
	vh->vh_client_count++;
}

/*
 * i_mdi_client_delist_table():
 *		Attach the client device to the client hash table.
 *		Caller should hold the vhci client lock.
 */
static void
i_mdi_client_delist_table(mdi_vhci_t *vh, mdi_client_t *ct)
{
	int			index;
	char			*guid;
	struct client_hash 	*head;
	mdi_client_t		*next;
	mdi_client_t		*last;

	ASSERT(MDI_VHCI_CLIENT_LOCKED(vh));

	guid = ct->ct_guid;
	index = i_mdi_get_hash_key(guid);
	head = &vh->vh_client_table[index];

	last = NULL;
	next = (mdi_client_t *)head->ct_hash_head;
	while (next != NULL) {
		if (next == ct) {
			break;
		}
		last = next;
		next = next->ct_hnext;
	}

	if (next) {
		head->ct_hash_count--;
		if (last == NULL) {
			head->ct_hash_head = ct->ct_hnext;
		} else {
			last->ct_hnext = ct->ct_hnext;
		}
		ct->ct_hnext = NULL;
		vh->vh_client_count--;
	}
}


/*
 * i_mdi_client_free():
 *		Free a client component
 */
static int
i_mdi_client_free(mdi_vhci_t *vh, mdi_client_t *ct)
{
	int		rv = MDI_SUCCESS;
	int		flags = ct->ct_flags;
	dev_info_t	*cdip;
	dev_info_t	*vdip;

	ASSERT(MDI_VHCI_CLIENT_LOCKED(vh));

	vdip = vh->vh_dip;
	cdip = ct->ct_dip;

	(void) ndi_prop_remove(DDI_DEV_T_NONE, cdip, MDI_CLIENT_GUID_PROP);
	DEVI(cdip)->devi_mdi_component &= ~MDI_COMPONENT_CLIENT;
	DEVI(cdip)->devi_mdi_client = NULL;

	/*
	 * Clear out back ref. to dev_info_t node
	 */
	ct->ct_dip = NULL;

	/*
	 * Remove this client from our hash queue
	 */
	i_mdi_client_delist_table(vh, ct);

	/*
	 * Uninitialize and free the component
	 */
	kmem_free(ct->ct_drvname, strlen(ct->ct_drvname) + 1);
	kmem_free(ct->ct_guid, strlen(ct->ct_guid) + 1);
	kmem_free(ct->ct_lb_args, sizeof (client_lb_args_t));
	cv_destroy(&ct->ct_failover_cv);
	cv_destroy(&ct->ct_unstable_cv);
	cv_destroy(&ct->ct_powerchange_cv);
	mutex_destroy(&ct->ct_mutex);
	kmem_free(ct, sizeof (*ct));

	if (cdip != NULL) {
		MDI_VHCI_CLIENT_UNLOCK(vh);
		(void) i_mdi_devinfo_remove(vdip, cdip, flags);
		MDI_VHCI_CLIENT_LOCK(vh);
	}
	return (rv);
}

/*
 * i_mdi_client_find():
 * 		Find the client structure corresponding to a given guid
 *		Caller should hold the vhci client lock.
 */
static mdi_client_t *
i_mdi_client_find(mdi_vhci_t *vh, char *cname, char *guid)
{
	int			index;
	struct client_hash	*head;
	mdi_client_t		*ct;

	ASSERT(MDI_VHCI_CLIENT_LOCKED(vh));

	index = i_mdi_get_hash_key(guid);
	head = &vh->vh_client_table[index];

	ct = head->ct_hash_head;
	while (ct != NULL) {
		if (strcmp(ct->ct_guid, guid) == 0 &&
		    (cname == NULL || strcmp(ct->ct_drvname, cname) == 0)) {
			break;
		}
		ct = ct->ct_hnext;
	}
	return (ct);
}

/*
 * i_mdi_client_update_state():
 *		Compute and update client device state
 * Notes:
 *		A client device can be in any of three possible states:
 *
 *		MDI_CLIENT_STATE_OPTIMAL - Client in optimal state with more
 *		one online/standby paths. Can tolerate failures.
 *		MDI_CLIENT_STATE_DEGRADED - Client device in degraded state with
 *		no alternate paths available as standby. A failure on the online
 *		would result in loss of access to device data.
 *		MDI_CLIENT_STATE_FAILED - Client device in failed state with
 *		no paths available to access the device.
 */
static void
i_mdi_client_update_state(mdi_client_t *ct)
{
	int state;

	ASSERT(MDI_CLIENT_LOCKED(ct));
	state = i_mdi_client_compute_state(ct, NULL);
	MDI_CLIENT_SET_STATE(ct, state);
}

/*
 * i_mdi_client_compute_state():
 *		Compute client device state
 *
 *		mdi_phci_t *	Pointer to pHCI structure which should
 *				while computing the new value.  Used by
 *				i_mdi_phci_offline() to find the new
 *				client state after DR of a pHCI.
 */
static int
i_mdi_client_compute_state(mdi_client_t *ct, mdi_phci_t *ph)
{
	int		state;
	int		online_count = 0;
	int		standby_count = 0;
	mdi_pathinfo_t	*pip, *next;

	ASSERT(MDI_CLIENT_LOCKED(ct));
	pip = ct->ct_path_head;
	while (pip != NULL) {
		MDI_PI_LOCK(pip);
		next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_client_link;
		if (MDI_PI(pip)->pi_phci == ph) {
			MDI_PI_UNLOCK(pip);
			pip = next;
			continue;
		}

		if ((MDI_PI(pip)->pi_state & MDI_PATHINFO_STATE_MASK)
				== MDI_PATHINFO_STATE_ONLINE)
			online_count++;
		else if ((MDI_PI(pip)->pi_state & MDI_PATHINFO_STATE_MASK)
				== MDI_PATHINFO_STATE_STANDBY)
			standby_count++;
		MDI_PI_UNLOCK(pip);
		pip = next;
	}

	if (online_count == 0) {
		if (standby_count == 0) {
			state = MDI_CLIENT_STATE_FAILED;
			MDI_DEBUG(2, (MDI_NOTE, ct->ct_dip,
			    "client state failed: ct = %p", (void *)ct));
		} else if (standby_count == 1) {
			state = MDI_CLIENT_STATE_DEGRADED;
		} else {
			state = MDI_CLIENT_STATE_OPTIMAL;
		}
	} else if (online_count == 1) {
		if (standby_count == 0) {
			state = MDI_CLIENT_STATE_DEGRADED;
		} else {
			state = MDI_CLIENT_STATE_OPTIMAL;
		}
	} else {
		state = MDI_CLIENT_STATE_OPTIMAL;
	}
	return (state);
}

/*
 * i_mdi_client2devinfo():
 *		Utility function
 */
dev_info_t *
i_mdi_client2devinfo(mdi_client_t *ct)
{
	return (ct->ct_dip);
}

/*
 * mdi_client_path2_devinfo():
 * 		Given the parent devinfo and child devfs pathname, search for
 *		a valid devfs node handle.
 */
dev_info_t *
mdi_client_path2devinfo(dev_info_t *vdip, char *pathname)
{
	dev_info_t 	*cdip = NULL;
	dev_info_t 	*ndip = NULL;
	char		*temp_pathname;
	int		circular;

	/*
	 * Allocate temp buffer
	 */
	temp_pathname = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

	/*
	 * Lock parent against changes
	 */
	ndi_devi_enter(vdip, &circular);
	ndip = (dev_info_t *)DEVI(vdip)->devi_child;
	while ((cdip = ndip) != NULL) {
		ndip = (dev_info_t *)DEVI(cdip)->devi_sibling;

		*temp_pathname = '\0';
		(void) ddi_pathname(cdip, temp_pathname);
		if (strcmp(temp_pathname, pathname) == 0) {
			break;
		}
	}
	/*
	 * Release devinfo lock
	 */
	ndi_devi_exit(vdip, circular);

	/*
	 * Free the temp buffer
	 */
	kmem_free(temp_pathname, MAXPATHLEN);
	return (cdip);
}

/*
 * mdi_client_get_path_count():
 * 		Utility function to get number of path information nodes
 *		associated with a given client device.
 */
int
mdi_client_get_path_count(dev_info_t *cdip)
{
	mdi_client_t	*ct;
	int		count = 0;

	ct = i_devi_get_client(cdip);
	if (ct != NULL) {
		count = ct->ct_path_count;
	}
	return (count);
}


/*
 * i_mdi_get_hash_key():
 * 		Create a hash using strings as keys
 *
 */
static int
i_mdi_get_hash_key(char *str)
{
	uint32_t	g, hash = 0;
	char		*p;

	for (p = str; *p != '\0'; p++) {
		g = *p;
		hash += g;
	}
	return (hash % (CLIENT_HASH_TABLE_SIZE - 1));
}

/*
 * mdi_get_lb_policy():
 * 		Get current load balancing policy for a given client device
 */
client_lb_t
mdi_get_lb_policy(dev_info_t *cdip)
{
	client_lb_t	lb = LOAD_BALANCE_NONE;
	mdi_client_t	*ct;

	ct = i_devi_get_client(cdip);
	if (ct != NULL) {
		lb = ct->ct_lb;
	}
	return (lb);
}

/*
 * mdi_set_lb_region_size():
 * 		Set current region size for the load-balance
 */
int
mdi_set_lb_region_size(dev_info_t *cdip, int region_size)
{
	mdi_client_t	*ct;
	int		rv = MDI_FAILURE;

	ct = i_devi_get_client(cdip);
	if (ct != NULL && ct->ct_lb_args != NULL) {
		ct->ct_lb_args->region_size = region_size;
		rv = MDI_SUCCESS;
	}
	return (rv);
}

/*
 * mdi_Set_lb_policy():
 * 		Set current load balancing policy for a given client device
 */
int
mdi_set_lb_policy(dev_info_t *cdip, client_lb_t lb)
{
	mdi_client_t	*ct;
	int		rv = MDI_FAILURE;

	ct = i_devi_get_client(cdip);
	if (ct != NULL) {
		ct->ct_lb = lb;
		rv = MDI_SUCCESS;
	}
	return (rv);
}

/*
 * mdi_failover():
 *		failover function called by the vHCI drivers to initiate
 *		a failover operation.  This is typically due to non-availability
 *		of online paths to route I/O requests.  Failover can be
 *		triggered through user application also.
 *
 *		The vHCI driver calls mdi_failover() to initiate a failover
 *		operation. mdi_failover() calls back into the vHCI driver's
 *		vo_failover() entry point to perform the actual failover
 *		operation.  The reason for requiring the vHCI driver to
 *		initiate failover by calling mdi_failover(), instead of directly
 *		executing vo_failover() itself, is to ensure that the mdi
 *		framework can keep track of the client state properly.
 *		Additionally, mdi_failover() provides as a convenience the
 *		option of performing the failover operation synchronously or
 *		asynchronously
 *
 *		Upon successful completion of the failover operation, the
 *		paths that were previously ONLINE will be in the STANDBY state,
 *		and the newly activated paths will be in the ONLINE state.
 *
 *		The flags modifier determines whether the activation is done
 *		synchronously: MDI_FAILOVER_SYNC
 * Return Values:
 *		MDI_SUCCESS
 *		MDI_FAILURE
 *		MDI_BUSY
 */
/*ARGSUSED*/
int
mdi_failover(dev_info_t *vdip, dev_info_t *cdip, int flags)
{
	int			rv;
	mdi_client_t		*ct;

	ct = i_devi_get_client(cdip);
	ASSERT(ct != NULL);
	if (ct == NULL) {
		/* cdip is not a valid client device. Nothing more to do. */
		return (MDI_FAILURE);
	}

	MDI_CLIENT_LOCK(ct);

	if (MDI_CLIENT_IS_PATH_FREE_IN_PROGRESS(ct)) {
		/* A path to the client is being freed */
		MDI_CLIENT_UNLOCK(ct);
		return (MDI_BUSY);
	}


	if (MDI_CLIENT_IS_FAILED(ct)) {
		/*
		 * Client is in failed state. Nothing more to do.
		 */
		MDI_CLIENT_UNLOCK(ct);
		return (MDI_FAILURE);
	}

	if (MDI_CLIENT_IS_FAILOVER_IN_PROGRESS(ct)) {
		/*
		 * Failover is already in progress; return BUSY
		 */
		MDI_CLIENT_UNLOCK(ct);
		return (MDI_BUSY);
	}
	/*
	 * Make sure that mdi_pathinfo node state changes are processed.
	 * We do not allow failovers to progress while client path state
	 * changes are in progress
	 */
	if (ct->ct_unstable) {
		if (flags == MDI_FAILOVER_ASYNC) {
			MDI_CLIENT_UNLOCK(ct);
			return (MDI_BUSY);
		} else {
			while (ct->ct_unstable)
				cv_wait(&ct->ct_unstable_cv, &ct->ct_mutex);
		}
	}

	/*
	 * Client device is in stable state. Before proceeding, perform sanity
	 * checks again.
	 */
	if ((MDI_CLIENT_IS_DETACHED(ct)) || (MDI_CLIENT_IS_FAILED(ct)) ||
	    (!i_ddi_devi_attached(cdip))) {
		/*
		 * Client is in failed state. Nothing more to do.
		 */
		MDI_CLIENT_UNLOCK(ct);
		return (MDI_FAILURE);
	}

	/*
	 * Set the client state as failover in progress.
	 */
	MDI_CLIENT_SET_FAILOVER_IN_PROGRESS(ct);
	ct->ct_failover_flags = flags;
	MDI_CLIENT_UNLOCK(ct);

	if (flags == MDI_FAILOVER_ASYNC) {
		/*
		 * Submit the initiate failover request via CPR safe
		 * taskq threads.
		 */
		(void) taskq_dispatch(mdi_taskq, (task_func_t *)i_mdi_failover,
		    ct, KM_SLEEP);
		return (MDI_ACCEPT);
	} else {
		/*
		 * Synchronous failover mode.  Typically invoked from the user
		 * land.
		 */
		rv = i_mdi_failover(ct);
	}
	return (rv);
}

/*
 * i_mdi_failover():
 *		internal failover function. Invokes vHCI drivers failover
 *		callback function and process the failover status
 * Return Values:
 *		None
 *
 * Note: A client device in failover state can not be detached or freed.
 */
static int
i_mdi_failover(void *arg)
{
	int		rv = MDI_SUCCESS;
	mdi_client_t	*ct = (mdi_client_t *)arg;
	mdi_vhci_t	*vh = ct->ct_vhci;

	ASSERT(!MDI_CLIENT_LOCKED(ct));

	if (vh->vh_ops->vo_failover != NULL) {
		/*
		 * Call vHCI drivers callback routine
		 */
		rv = (*vh->vh_ops->vo_failover)(vh->vh_dip, ct->ct_dip,
		    ct->ct_failover_flags);
	}

	MDI_CLIENT_LOCK(ct);
	MDI_CLIENT_CLEAR_FAILOVER_IN_PROGRESS(ct);

	/*
	 * Save the failover return status
	 */
	ct->ct_failover_status = rv;

	/*
	 * As a result of failover, client status would have been changed.
	 * Update the client state and wake up anyone waiting on this client
	 * device.
	 */
	i_mdi_client_update_state(ct);

	cv_broadcast(&ct->ct_failover_cv);
	MDI_CLIENT_UNLOCK(ct);
	return (rv);
}

/*
 * Load balancing is logical block.
 * IOs within the range described by region_size
 * would go on the same path. This would improve the
 * performance by cache-hit on some of the RAID devices.
 * Search only for online paths(At some point we
 * may want to balance across target ports).
 * If no paths are found then default to round-robin.
 */
static int
i_mdi_lba_lb(mdi_client_t *ct, mdi_pathinfo_t **ret_pip, struct buf *bp)
{
	int		path_index = -1;
	int		online_path_count = 0;
	int		online_nonpref_path_count = 0;
	int 		region_size = ct->ct_lb_args->region_size;
	mdi_pathinfo_t	*pip;
	mdi_pathinfo_t	*next;
	int		preferred, path_cnt;

	pip = ct->ct_path_head;
	while (pip) {
		MDI_PI_LOCK(pip);
		if (MDI_PI(pip)->pi_state ==
		    MDI_PATHINFO_STATE_ONLINE && MDI_PI(pip)->pi_preferred) {
			online_path_count++;
		} else if (MDI_PI(pip)->pi_state ==
		    MDI_PATHINFO_STATE_ONLINE && !MDI_PI(pip)->pi_preferred) {
			online_nonpref_path_count++;
		}
		next = (mdi_pathinfo_t *)
		    MDI_PI(pip)->pi_client_link;
		MDI_PI_UNLOCK(pip);
		pip = next;
	}
	/* if found any online/preferred then use this type */
	if (online_path_count > 0) {
		path_cnt = online_path_count;
		preferred = 1;
	} else if (online_nonpref_path_count > 0) {
		path_cnt = online_nonpref_path_count;
		preferred = 0;
	} else {
		path_cnt = 0;
	}
	if (path_cnt) {
		path_index = (bp->b_blkno >> region_size) % path_cnt;
		pip = ct->ct_path_head;
		while (pip && path_index != -1) {
			MDI_PI_LOCK(pip);
			if (path_index == 0 &&
			    (MDI_PI(pip)->pi_state ==
			    MDI_PATHINFO_STATE_ONLINE) &&
				MDI_PI(pip)->pi_preferred == preferred) {
				MDI_PI_HOLD(pip);
				MDI_PI_UNLOCK(pip);
				*ret_pip = pip;
				return (MDI_SUCCESS);
			}
			path_index --;
			next = (mdi_pathinfo_t *)
			    MDI_PI(pip)->pi_client_link;
			MDI_PI_UNLOCK(pip);
			pip = next;
		}
		MDI_DEBUG(4, (MDI_NOTE, ct->ct_dip,
		    "lba %llx: path %s %p",
		    bp->b_lblkno, mdi_pi_spathname(pip), (void *)pip));
	}
	return (MDI_FAILURE);
}

/*
 * mdi_select_path():
 *		select a path to access a client device.
 *
 *		mdi_select_path() function is called by the vHCI drivers to
 *		select a path to route the I/O request to.  The caller passes
 *		the block I/O data transfer structure ("buf") as one of the
 *		parameters.  The mpxio framework uses the buf structure
 *		contents to maintain per path statistics (total I/O size /
 *		count pending).  If more than one online paths are available to
 *		select, the framework automatically selects a suitable path
 *		for routing I/O request. If a failover operation is active for
 *		this client device the call shall be failed with MDI_BUSY error
 *		code.
 *
 *		By default this function returns a suitable path in online
 *		state based on the current load balancing policy.  Currently
 *		we support LOAD_BALANCE_NONE (Previously selected online path
 *		will continue to be used till the path is usable) and
 *		LOAD_BALANCE_RR (Online paths will be selected in a round
 *		robin fashion), LOAD_BALANCE_LB(Online paths will be selected
 *		based on the logical block).  The load balancing
 *		through vHCI drivers configuration file (driver.conf).
 *
 *		vHCI drivers may override this default behavior by specifying
 *		appropriate flags.  The meaning of the thrid argument depends
 *		on the flags specified. If MDI_SELECT_PATH_INSTANCE is set
 *		then the argument is the "path instance" of the path to select.
 *		If MDI_SELECT_PATH_INSTANCE is not set then the argument is
 *		"start_pip". A non NULL "start_pip" is the starting point to
 *		walk and find the next appropriate path.  The following values
 *		are currently defined: MDI_SELECT_ONLINE_PATH (to select an
 *		ONLINE path) and/or MDI_SELECT_STANDBY_PATH (to select an
 *		STANDBY path).
 *
 *		The non-standard behavior is used by the scsi_vhci driver,
 *		whenever it has to use a STANDBY/FAULTED path.  Eg. during
 *		attach of client devices (to avoid an unnecessary failover
 *		when the STANDBY path comes up first), during failover
 *		(to activate a STANDBY path as ONLINE).
 *
 *		The selected path is returned in a a mdi_hold_path() state
 *		(pi_ref_cnt). Caller should release the hold by calling
 *		mdi_rele_path().
 *
 * Return Values:
 *		MDI_SUCCESS	- Completed successfully
 *		MDI_BUSY 	- Client device is busy failing over
 *		MDI_NOPATH	- Client device is online, but no valid path are
 *				  available to access this client device
 *		MDI_FAILURE	- Invalid client device or state
 *		MDI_DEVI_ONLINING
 *				- Client device (struct dev_info state) is in
 *				  onlining state.
 */

/*ARGSUSED*/
int
mdi_select_path(dev_info_t *cdip, struct buf *bp, int flags,
    void *arg, mdi_pathinfo_t **ret_pip)
{
	mdi_client_t	*ct;
	mdi_pathinfo_t	*pip;
	mdi_pathinfo_t	*next;
	mdi_pathinfo_t	*head;
	mdi_pathinfo_t	*start;
	client_lb_t	lbp;	/* load balancing policy */
	int		sb = 1;	/* standard behavior */
	int		preferred = 1;	/* preferred path */
	int		cond, cont = 1;
	int		retry = 0;
	mdi_pathinfo_t	*start_pip;	/* request starting pathinfo */
	int		path_instance;	/* request specific path instance */

	/* determine type of arg based on flags */
	if (flags & MDI_SELECT_PATH_INSTANCE) {
		path_instance = (int)(intptr_t)arg;
		start_pip = NULL;
	} else {
		path_instance = 0;
		start_pip = (mdi_pathinfo_t *)arg;
	}

	if (flags != 0) {
		/*
		 * disable default behavior
		 */
		sb = 0;
	}

	*ret_pip = NULL;
	ct = i_devi_get_client(cdip);
	if (ct == NULL) {
		/* mdi extensions are NULL, Nothing more to do */
		return (MDI_FAILURE);
	}

	MDI_CLIENT_LOCK(ct);

	if (sb) {
		if (MDI_CLIENT_IS_FAILED(ct)) {
			/*
			 * Client is not ready to accept any I/O requests.
			 * Fail this request.
			 */
			MDI_DEBUG(2, (MDI_NOTE, cdip,
			    "client state offline ct = %p", (void *)ct));
			MDI_CLIENT_UNLOCK(ct);
			return (MDI_FAILURE);
		}

		if (MDI_CLIENT_IS_FAILOVER_IN_PROGRESS(ct)) {
			/*
			 * Check for Failover is in progress. If so tell the
			 * caller that this device is busy.
			 */
			MDI_DEBUG(2, (MDI_NOTE, cdip,
			    "client failover in progress ct = %p",
			    (void *)ct));
			MDI_CLIENT_UNLOCK(ct);
			return (MDI_BUSY);
		}

		/*
		 * Check to see whether the client device is attached.
		 * If not so, let the vHCI driver manually select a path
		 * (standby) and let the probe/attach process to continue.
		 */
		if (MDI_CLIENT_IS_DETACHED(ct) || !i_ddi_devi_attached(cdip)) {
			MDI_DEBUG(4, (MDI_NOTE, cdip,
			    "devi is onlining ct = %p", (void *)ct));
			MDI_CLIENT_UNLOCK(ct);
			return (MDI_DEVI_ONLINING);
		}
	}

	/*
	 * Cache in the client list head.  If head of the list is NULL
	 * return MDI_NOPATH
	 */
	head = ct->ct_path_head;
	if (head == NULL) {
		MDI_CLIENT_UNLOCK(ct);
		return (MDI_NOPATH);
	}

	/* Caller is specifying a specific pathinfo path by path_instance */
	if (path_instance) {
		/* search for pathinfo with correct path_instance */
		for (pip = head;
		    pip && (mdi_pi_get_path_instance(pip) != path_instance);
		    pip = (mdi_pathinfo_t *)MDI_PI(pip)->pi_client_link)
			;

		/* If path can't be selected then MDI_NOPATH is returned. */
		if (pip == NULL) {
			MDI_CLIENT_UNLOCK(ct);
			return (MDI_NOPATH);
		}

		/*
		 * Verify state of path. When asked to select a specific
		 * path_instance, we select the requested path in any
		 * state (ONLINE, OFFLINE, STANDBY, FAULT) other than INIT.
		 * We don't however select paths where the pHCI has detached.
		 * NOTE: last pathinfo node of an opened client device may
		 * exist in an OFFLINE state after the pHCI associated with
		 * that path has detached (but pi_phci will be NULL if that
		 * has occurred).
		 */
		MDI_PI_LOCK(pip);
		if ((MDI_PI(pip)->pi_state == MDI_PATHINFO_STATE_INIT) ||
		    (MDI_PI(pip)->pi_phci == NULL)) {
			MDI_PI_UNLOCK(pip);
			MDI_CLIENT_UNLOCK(ct);
			return (MDI_FAILURE);
		}

		/* Return MDI_BUSY if we have a transient condition */
		if (MDI_PI_IS_TRANSIENT(pip)) {
			MDI_PI_UNLOCK(pip);
			MDI_CLIENT_UNLOCK(ct);
			return (MDI_BUSY);
		}

		/*
		 * Return the path in hold state. Caller should release the
		 * lock by calling mdi_rele_path()
		 */
		MDI_PI_HOLD(pip);
		MDI_PI_UNLOCK(pip);
		*ret_pip = pip;
		MDI_CLIENT_UNLOCK(ct);
		return (MDI_SUCCESS);
	}

	/*
	 * for non default behavior, bypass current
	 * load balancing policy and always use LOAD_BALANCE_RR
	 * except that the start point will be adjusted based
	 * on the provided start_pip
	 */
	lbp = sb ? ct->ct_lb : LOAD_BALANCE_RR;

	switch (lbp) {
	case LOAD_BALANCE_NONE:
		/*
		 * Load balancing is None  or Alternate path mode
		 * Start looking for a online mdi_pathinfo node starting from
		 * last known selected path
		 */
		preferred = 1;
		pip = (mdi_pathinfo_t *)ct->ct_path_last;
		if (pip == NULL) {
			pip = head;
		}
		start = pip;
		do {
			MDI_PI_LOCK(pip);
			/*
			 * No need to explicitly check if the path is disabled.
			 * Since we are checking for state == ONLINE and the
			 * same variable is used for DISABLE/ENABLE information.
			 */
			if ((MDI_PI(pip)->pi_state  ==
				MDI_PATHINFO_STATE_ONLINE) &&
				preferred == MDI_PI(pip)->pi_preferred) {
				/*
				 * Return the path in hold state. Caller should
				 * release the lock by calling mdi_rele_path()
				 */
				MDI_PI_HOLD(pip);
				MDI_PI_UNLOCK(pip);
				ct->ct_path_last = pip;
				*ret_pip = pip;
				MDI_CLIENT_UNLOCK(ct);
				return (MDI_SUCCESS);
			}

			/*
			 * Path is busy.
			 */
			if (MDI_PI_IS_DRV_DISABLE_TRANSIENT(pip) ||
			    MDI_PI_IS_TRANSIENT(pip))
				retry = 1;
			/*
			 * Keep looking for a next available online path
			 */
			next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_client_link;
			if (next == NULL) {
				next = head;
			}
			MDI_PI_UNLOCK(pip);
			pip = next;
			if (start == pip && preferred) {
				preferred = 0;
			} else if (start == pip && !preferred) {
				cont = 0;
			}
		} while (cont);
		break;

	case LOAD_BALANCE_LBA:
		/*
		 * Make sure we are looking
		 * for an online path. Otherwise, if it is for a STANDBY
		 * path request, it will go through and fetch an ONLINE
		 * path which is not desirable.
		 */
		if ((ct->ct_lb_args != NULL) &&
			    (ct->ct_lb_args->region_size) && bp &&
				(sb || (flags == MDI_SELECT_ONLINE_PATH))) {
			if (i_mdi_lba_lb(ct, ret_pip, bp)
				    == MDI_SUCCESS) {
				MDI_CLIENT_UNLOCK(ct);
				return (MDI_SUCCESS);
			}
		}
		/* FALLTHROUGH */
	case LOAD_BALANCE_RR:
		/*
		 * Load balancing is Round Robin. Start looking for a online
		 * mdi_pathinfo node starting from last known selected path
		 * as the start point.  If override flags are specified,
		 * process accordingly.
		 * If the search is already in effect(start_pip not null),
		 * then lets just use the same path preference to continue the
		 * traversal.
		 */

		if (start_pip != NULL) {
			preferred = MDI_PI(start_pip)->pi_preferred;
		} else {
			preferred = 1;
		}

		start = sb ? (mdi_pathinfo_t *)ct->ct_path_last : start_pip;
		if (start == NULL) {
			pip = head;
		} else {
			pip = (mdi_pathinfo_t *)MDI_PI(start)->pi_client_link;
			if (pip == NULL) {
				if ( flags & MDI_SELECT_NO_PREFERRED) {
					/*
					 * Return since we hit the end of list
					 */
					MDI_CLIENT_UNLOCK(ct);
					return (MDI_NOPATH);
				}

				if (!sb) {
					if (preferred == 0) {
						/*
						 * Looks like we have completed
						 * the traversal as preferred
						 * value is 0. Time to bail out.
						 */
						*ret_pip = NULL;
						MDI_CLIENT_UNLOCK(ct);
						return (MDI_NOPATH);
					} else {
						/*
						 * Looks like we reached the
						 * end of the list. Lets enable
						 * traversal of non preferred
						 * paths.
						 */
						preferred = 0;
					}
				}
				pip = head;
			}
		}
		start = pip;
		do {
			MDI_PI_LOCK(pip);
			if (sb) {
				cond = ((MDI_PI(pip)->pi_state ==
				    MDI_PATHINFO_STATE_ONLINE &&
					MDI_PI(pip)->pi_preferred ==
						preferred) ? 1 : 0);
			} else {
				if (flags == MDI_SELECT_ONLINE_PATH) {
					cond = ((MDI_PI(pip)->pi_state ==
					    MDI_PATHINFO_STATE_ONLINE &&
						MDI_PI(pip)->pi_preferred ==
						preferred) ? 1 : 0);
				} else if (flags == MDI_SELECT_STANDBY_PATH) {
					cond = ((MDI_PI(pip)->pi_state ==
					    MDI_PATHINFO_STATE_STANDBY &&
						MDI_PI(pip)->pi_preferred ==
						preferred) ? 1 : 0);
				} else if (flags == (MDI_SELECT_ONLINE_PATH |
				    MDI_SELECT_STANDBY_PATH)) {
					cond = (((MDI_PI(pip)->pi_state ==
					    MDI_PATHINFO_STATE_ONLINE ||
					    (MDI_PI(pip)->pi_state ==
					    MDI_PATHINFO_STATE_STANDBY)) &&
						MDI_PI(pip)->pi_preferred ==
						preferred) ? 1 : 0);
				} else if (flags ==
					(MDI_SELECT_STANDBY_PATH |
					MDI_SELECT_ONLINE_PATH |
					MDI_SELECT_USER_DISABLE_PATH)) {
					cond = (((MDI_PI(pip)->pi_state ==
					    MDI_PATHINFO_STATE_ONLINE ||
					    (MDI_PI(pip)->pi_state ==
					    MDI_PATHINFO_STATE_STANDBY) ||
						(MDI_PI(pip)->pi_state ==
					    (MDI_PATHINFO_STATE_ONLINE|
					    MDI_PATHINFO_STATE_USER_DISABLE)) ||
						(MDI_PI(pip)->pi_state ==
					    (MDI_PATHINFO_STATE_STANDBY |
					    MDI_PATHINFO_STATE_USER_DISABLE)))&&
						MDI_PI(pip)->pi_preferred ==
						preferred) ? 1 : 0);
				} else if (flags ==
				    (MDI_SELECT_STANDBY_PATH |
				    MDI_SELECT_ONLINE_PATH |
				    MDI_SELECT_NO_PREFERRED)) {
					cond = (((MDI_PI(pip)->pi_state ==
					    MDI_PATHINFO_STATE_ONLINE) ||
					    (MDI_PI(pip)->pi_state ==
					    MDI_PATHINFO_STATE_STANDBY))
					    ? 1 : 0);
				} else {
					cond = 0;
				}
			}
			/*
			 * No need to explicitly check if the path is disabled.
			 * Since we are checking for state == ONLINE and the
			 * same variable is used for DISABLE/ENABLE information.
			 */
			if (cond) {
				/*
				 * Return the path in hold state. Caller should
				 * release the lock by calling mdi_rele_path()
				 */
				MDI_PI_HOLD(pip);
				MDI_PI_UNLOCK(pip);
				if (sb)
					ct->ct_path_last = pip;
				*ret_pip = pip;
				MDI_CLIENT_UNLOCK(ct);
				return (MDI_SUCCESS);
			}
			/*
			 * Path is busy.
			 */
			if (MDI_PI_IS_DRV_DISABLE_TRANSIENT(pip) ||
			    MDI_PI_IS_TRANSIENT(pip))
				retry = 1;

			/*
			 * Keep looking for a next available online path
			 */
do_again:
			next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_client_link;
			if (next == NULL) {
				if ( flags & MDI_SELECT_NO_PREFERRED) {
					/*
					 * Bail out since we hit the end of list
					 */
					MDI_PI_UNLOCK(pip);
					break;
				}

				if (!sb) {
					if (preferred == 1) {
						/*
						 * Looks like we reached the
						 * end of the list. Lets enable
						 * traversal of non preferred
						 * paths.
						 */
						preferred = 0;
						next = head;
					} else {
						/*
						 * We have done both the passes
						 * Preferred as well as for
						 * Non-preferred. Bail out now.
						 */
						cont = 0;
					}
				} else {
					/*
					 * Standard behavior case.
					 */
					next = head;
				}
			}
			MDI_PI_UNLOCK(pip);
			if (cont == 0) {
				break;
			}
			pip = next;

			if (!sb) {
				/*
				 * We need to handle the selection of
				 * non-preferred path in the following
				 * case:
				 *
				 * +------+   +------+   +------+   +-----+
				 * | A : 1| - | B : 1| - | C : 0| - |NULL |
				 * +------+   +------+   +------+   +-----+
				 *
				 * If we start the search with B, we need to
				 * skip beyond B to pick C which is non -
				 * preferred in the second pass. The following
				 * test, if true, will allow us to skip over
				 * the 'start'(B in the example) to select
				 * other non preferred elements.
				 */
				if ((start_pip != NULL) && (start_pip == pip) &&
				    (MDI_PI(start_pip)->pi_preferred
				    != preferred)) {
					/*
					 * try again after going past the start
					 * pip
					 */
					MDI_PI_LOCK(pip);
					goto do_again;
				}
			} else {
				/*
				 * Standard behavior case
				 */
				if (start == pip && preferred) {
					/* look for nonpreferred paths */
					preferred = 0;
				} else if (start == pip && !preferred) {
					/*
					 * Exit condition
					 */
					cont = 0;
				}
			}
		} while (cont);
		break;
	}

	MDI_CLIENT_UNLOCK(ct);
	if (retry == 1) {
		return (MDI_BUSY);
	} else {
		return (MDI_NOPATH);
	}
}

/*
 * For a client, return the next available path to any phci
 *
 * Note:
 *		Caller should hold the branch's devinfo node to get a consistent
 *		snap shot of the mdi_pathinfo nodes.
 *
 *		Please note that even the list is stable the mdi_pathinfo
 *		node state and properties are volatile.  The caller should lock
 *		and unlock the nodes by calling mdi_pi_lock() and
 *		mdi_pi_unlock() functions to get a stable properties.
 *
 *		If there is a need to use the nodes beyond the hold of the
 *		devinfo node period (For ex. I/O), then mdi_pathinfo node
 *		need to be held against unexpected removal by calling
 *		mdi_hold_path() and should be released by calling
 *		mdi_rele_path() on completion.
 */
mdi_pathinfo_t *
mdi_get_next_phci_path(dev_info_t *ct_dip, mdi_pathinfo_t *pip)
{
	mdi_client_t *ct;

	if (!MDI_CLIENT(ct_dip))
		return (NULL);

	/*
	 * Walk through client link
	 */
	ct = (mdi_client_t *)DEVI(ct_dip)->devi_mdi_client;
	ASSERT(ct != NULL);

	if (pip == NULL)
		return ((mdi_pathinfo_t *)ct->ct_path_head);

	return ((mdi_pathinfo_t *)MDI_PI(pip)->pi_client_link);
}

/*
 * For a phci, return the next available path to any client
 * Note: ditto mdi_get_next_phci_path()
 */
mdi_pathinfo_t *
mdi_get_next_client_path(dev_info_t *ph_dip, mdi_pathinfo_t *pip)
{
	mdi_phci_t *ph;

	if (!MDI_PHCI(ph_dip))
		return (NULL);

	/*
	 * Walk through pHCI link
	 */
	ph = (mdi_phci_t *)DEVI(ph_dip)->devi_mdi_xhci;
	ASSERT(ph != NULL);

	if (pip == NULL)
		return ((mdi_pathinfo_t *)ph->ph_path_head);

	return ((mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link);
}

/*
 * mdi_hold_path():
 *		Hold the mdi_pathinfo node against unwanted unexpected free.
 * Return Values:
 *		None
 */
void
mdi_hold_path(mdi_pathinfo_t *pip)
{
	if (pip) {
		MDI_PI_LOCK(pip);
		MDI_PI_HOLD(pip);
		MDI_PI_UNLOCK(pip);
	}
}


/*
 * mdi_rele_path():
 *		Release the mdi_pathinfo node which was selected
 *		through mdi_select_path() mechanism or manually held by
 *		calling mdi_hold_path().
 * Return Values:
 *		None
 */
void
mdi_rele_path(mdi_pathinfo_t *pip)
{
	if (pip) {
		MDI_PI_LOCK(pip);
		MDI_PI_RELE(pip);
		if (MDI_PI(pip)->pi_ref_cnt == 0) {
			cv_broadcast(&MDI_PI(pip)->pi_ref_cv);
		}
		MDI_PI_UNLOCK(pip);
	}
}

/*
 * mdi_pi_lock():
 * 		Lock the mdi_pathinfo node.
 * Note:
 *		The caller should release the lock by calling mdi_pi_unlock()
 */
void
mdi_pi_lock(mdi_pathinfo_t *pip)
{
	ASSERT(pip != NULL);
	if (pip) {
		MDI_PI_LOCK(pip);
	}
}


/*
 * mdi_pi_unlock():
 * 		Unlock the mdi_pathinfo node.
 * Note:
 *		The mdi_pathinfo node should have been locked with mdi_pi_lock()
 */
void
mdi_pi_unlock(mdi_pathinfo_t *pip)
{
	ASSERT(pip != NULL);
	if (pip) {
		MDI_PI_UNLOCK(pip);
	}
}

/*
 * mdi_pi_find():
 *		Search the list of mdi_pathinfo nodes attached to the
 *		pHCI/Client device node whose path address matches "paddr".
 *		Returns a pointer to the mdi_pathinfo node if a matching node is
 *		found.
 * Return Values:
 *		mdi_pathinfo node handle
 *		NULL
 * Notes:
 *		Caller need not hold any locks to call this function.
 */
mdi_pathinfo_t *
mdi_pi_find(dev_info_t *pdip, char *caddr, char *paddr)
{
	mdi_phci_t		*ph;
	mdi_vhci_t		*vh;
	mdi_client_t		*ct;
	mdi_pathinfo_t		*pip = NULL;

	MDI_DEBUG(2, (MDI_NOTE, pdip,
	    "caddr@%s paddr@%s", caddr ? caddr : "", paddr ? paddr : ""));
	if ((pdip == NULL) || (paddr == NULL)) {
		return (NULL);
	}
	ph = i_devi_get_phci(pdip);
	if (ph == NULL) {
		/*
		 * Invalid pHCI device, Nothing more to do.
		 */
		MDI_DEBUG(2, (MDI_WARN, pdip, "invalid phci"));
		return (NULL);
	}

	vh = ph->ph_vhci;
	if (vh == NULL) {
		/*
		 * Invalid vHCI device, Nothing more to do.
		 */
		MDI_DEBUG(2, (MDI_WARN, pdip, "invalid vhci"));
		return (NULL);
	}

	/*
	 * Look for pathinfo node identified by paddr.
	 */
	if (caddr == NULL) {
		/*
		 * Find a mdi_pathinfo node under pHCI list for a matching
		 * unit address.
		 */
		MDI_PHCI_LOCK(ph);
		if (MDI_PHCI_IS_OFFLINE(ph)) {
			MDI_DEBUG(2, (MDI_WARN, pdip,
			    "offline phci %p", (void *)ph));
			MDI_PHCI_UNLOCK(ph);
			return (NULL);
		}
		pip = (mdi_pathinfo_t *)ph->ph_path_head;

		while (pip != NULL) {
			if (strcmp(MDI_PI(pip)->pi_addr, paddr) == 0) {
				break;
			}
			pip = (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;
		}
		MDI_PHCI_UNLOCK(ph);
		MDI_DEBUG(2, (MDI_NOTE, pdip,
		    "found %s %p", mdi_pi_spathname(pip), (void *)pip));
		return (pip);
	}

	/*
	 * XXX - Is the rest of the code in this function really necessary?
	 * The consumers of mdi_pi_find() can search for the desired pathinfo
	 * node by calling mdi_pi_find(pdip, NULL, paddr). Irrespective of
	 * whether the search is based on the pathinfo nodes attached to
	 * the pHCI or the client node, the result will be the same.
	 */

	/*
	 * Find the client device corresponding to 'caddr'
	 */
	MDI_VHCI_CLIENT_LOCK(vh);

	/*
	 * XXX - Passing NULL to the following function works as long as the
	 * the client addresses (caddr) are unique per vhci basis.
	 */
	ct = i_mdi_client_find(vh, NULL, caddr);
	if (ct == NULL) {
		/*
		 * Client not found, Obviously mdi_pathinfo node has not been
		 * created yet.
		 */
		MDI_VHCI_CLIENT_UNLOCK(vh);
		MDI_DEBUG(2, (MDI_NOTE, pdip,
		    "client not found for caddr @%s", caddr ? caddr : ""));
		return (NULL);
	}

	/*
	 * Hold the client lock and look for a mdi_pathinfo node with matching
	 * pHCI and paddr
	 */
	MDI_CLIENT_LOCK(ct);

	/*
	 * Release the global mutex as it is no more needed. Note: We always
	 * respect the locking order while acquiring.
	 */
	MDI_VHCI_CLIENT_UNLOCK(vh);

	pip = (mdi_pathinfo_t *)ct->ct_path_head;
	while (pip != NULL) {
		/*
		 * Compare the unit address
		 */
		if ((MDI_PI(pip)->pi_phci == ph) &&
		    strcmp(MDI_PI(pip)->pi_addr, paddr) == 0) {
			break;
		}
		pip = (mdi_pathinfo_t *)MDI_PI(pip)->pi_client_link;
	}
	MDI_CLIENT_UNLOCK(ct);
	MDI_DEBUG(2, (MDI_NOTE, pdip,
	    "found: %s %p", mdi_pi_spathname(pip), (void *)pip));
	return (pip);
}

/*
 * mdi_pi_alloc():
 *		Allocate and initialize a new instance of a mdi_pathinfo node.
 *		The mdi_pathinfo node returned by this function identifies a
 *		unique device path is capable of having properties attached
 *		and passed to mdi_pi_online() to fully attach and online the
 *		path and client device node.
 *		The mdi_pathinfo node returned by this function must be
 *		destroyed using mdi_pi_free() if the path is no longer
 *		operational or if the caller fails to attach a client device
 *		node when calling mdi_pi_online(). The framework will not free
 *		the resources allocated.
 *		This function can be called from both interrupt and kernel
 *		contexts.  DDI_NOSLEEP flag should be used while calling
 *		from interrupt contexts.
 * Return Values:
 *		MDI_SUCCESS
 *		MDI_FAILURE
 *		MDI_NOMEM
 */
/*ARGSUSED*/
int
mdi_pi_alloc_compatible(dev_info_t *pdip, char *cname, char *caddr, char *paddr,
    char **compatible, int ncompatible, int flags, mdi_pathinfo_t **ret_pip)
{
	mdi_vhci_t	*vh;
	mdi_phci_t	*ph;
	mdi_client_t	*ct;
	mdi_pathinfo_t	*pip = NULL;
	dev_info_t	*cdip;
	int		rv = MDI_NOMEM;
	int		path_allocated = 0;

	MDI_DEBUG(2, (MDI_NOTE, pdip,
	    "cname %s: caddr@%s paddr@%s",
	    cname ? cname : "", caddr ? caddr : "", paddr ? paddr : ""));

	if (pdip == NULL || cname == NULL || caddr == NULL || paddr == NULL ||
	    ret_pip == NULL) {
		/* Nothing more to do */
		return (MDI_FAILURE);
	}

	*ret_pip = NULL;

	/* No allocations on detaching pHCI */
	if (DEVI_IS_DETACHING(pdip)) {
		/* Invalid pHCI device, return failure */
		MDI_DEBUG(1, (MDI_WARN, pdip,
		    "!detaching pHCI=%p", (void *)pdip));
		return (MDI_FAILURE);
	}

	ph = i_devi_get_phci(pdip);
	ASSERT(ph != NULL);
	if (ph == NULL) {
		/* Invalid pHCI device, return failure */
		MDI_DEBUG(1, (MDI_WARN, pdip,
		    "!invalid pHCI=%p", (void *)pdip));
		return (MDI_FAILURE);
	}

	MDI_PHCI_LOCK(ph);
	vh = ph->ph_vhci;
	if (vh == NULL) {
		/* Invalid vHCI device, return failure */
		MDI_DEBUG(1, (MDI_WARN, pdip,
		    "!invalid vHCI=%p", (void *)pdip));
		MDI_PHCI_UNLOCK(ph);
		return (MDI_FAILURE);
	}

	if (MDI_PHCI_IS_READY(ph) == 0) {
		/*
		 * Do not allow new node creation when pHCI is in
		 * offline/suspended states
		 */
		MDI_DEBUG(1, (MDI_WARN, pdip,
		    "pHCI=%p is not ready", (void *)ph));
		MDI_PHCI_UNLOCK(ph);
		return (MDI_BUSY);
	}
	MDI_PHCI_UNSTABLE(ph);
	MDI_PHCI_UNLOCK(ph);

	/* look for a matching client, create one if not found */
	MDI_VHCI_CLIENT_LOCK(vh);
	ct = i_mdi_client_find(vh, cname, caddr);
	if (ct == NULL) {
		ct = i_mdi_client_alloc(vh, cname, caddr);
		ASSERT(ct != NULL);
	}

	if (ct->ct_dip == NULL) {
		/*
		 * Allocate a devinfo node
		 */
		ct->ct_dip = i_mdi_devinfo_create(vh, cname, caddr,
		    compatible, ncompatible);
		if (ct->ct_dip == NULL) {
			(void) i_mdi_client_free(vh, ct);
			goto fail;
		}
	}
	cdip = ct->ct_dip;

	DEVI(cdip)->devi_mdi_component |= MDI_COMPONENT_CLIENT;
	DEVI(cdip)->devi_mdi_client = (caddr_t)ct;

	MDI_CLIENT_LOCK(ct);
	pip = (mdi_pathinfo_t *)ct->ct_path_head;
	while (pip != NULL) {
		/*
		 * Compare the unit address
		 */
		if ((MDI_PI(pip)->pi_phci == ph) &&
		    strcmp(MDI_PI(pip)->pi_addr, paddr) == 0) {
			break;
		}
		pip = (mdi_pathinfo_t *)MDI_PI(pip)->pi_client_link;
	}
	MDI_CLIENT_UNLOCK(ct);

	if (pip == NULL) {
		/*
		 * This is a new path for this client device.  Allocate and
		 * initialize a new pathinfo node
		 */
		pip = i_mdi_pi_alloc(ph, paddr, ct);
		ASSERT(pip != NULL);
		path_allocated = 1;
	}
	rv = MDI_SUCCESS;

fail:
	/*
	 * Release the global mutex.
	 */
	MDI_VHCI_CLIENT_UNLOCK(vh);

	/*
	 * Mark the pHCI as stable
	 */
	MDI_PHCI_LOCK(ph);
	MDI_PHCI_STABLE(ph);
	MDI_PHCI_UNLOCK(ph);
	*ret_pip = pip;

	MDI_DEBUG(2, (MDI_NOTE, pdip,
	    "alloc %s %p", mdi_pi_spathname(pip), (void *)pip));

	if (path_allocated)
		vhcache_pi_add(vh->vh_config, MDI_PI(pip));

	return (rv);
}

/*ARGSUSED*/
int
mdi_pi_alloc(dev_info_t *pdip, char *cname, char *caddr, char *paddr,
    int flags, mdi_pathinfo_t **ret_pip)
{
	return (mdi_pi_alloc_compatible(pdip, cname, caddr, paddr, NULL, 0,
	    flags, ret_pip));
}

/*
 * i_mdi_pi_alloc():
 *		Allocate a mdi_pathinfo node and add to the pHCI path list
 * Return Values:
 *		mdi_pathinfo
 */
/*ARGSUSED*/
static mdi_pathinfo_t *
i_mdi_pi_alloc(mdi_phci_t *ph, char *paddr, mdi_client_t *ct)
{
	mdi_pathinfo_t	*pip;
	int		ct_circular;
	int		ph_circular;
	static char	path[MAXPATHLEN];	/* mdi_pathmap_mutex protects */
	char		*path_persistent;
	int		path_instance;
	mod_hash_val_t	hv;

	ASSERT(MDI_VHCI_CLIENT_LOCKED(ph->ph_vhci));

	pip = kmem_zalloc(sizeof (struct mdi_pathinfo), KM_SLEEP);
	mutex_init(&MDI_PI(pip)->pi_mutex, NULL, MUTEX_DEFAULT, NULL);
	MDI_PI(pip)->pi_state = MDI_PATHINFO_STATE_INIT |
	    MDI_PATHINFO_STATE_TRANSIENT;

	if (MDI_PHCI_IS_USER_DISABLED(ph))
		MDI_PI_SET_USER_DISABLE(pip);

	if (MDI_PHCI_IS_DRV_DISABLED_TRANSIENT(ph))
		MDI_PI_SET_DRV_DISABLE_TRANS(pip);

	if (MDI_PHCI_IS_DRV_DISABLED(ph))
		MDI_PI_SET_DRV_DISABLE(pip);

	MDI_PI(pip)->pi_old_state = MDI_PATHINFO_STATE_INIT;
	cv_init(&MDI_PI(pip)->pi_state_cv, NULL, CV_DEFAULT, NULL);
	MDI_PI(pip)->pi_client = ct;
	MDI_PI(pip)->pi_phci = ph;
	MDI_PI(pip)->pi_addr = kmem_alloc(strlen(paddr) + 1, KM_SLEEP);
	(void) strcpy(MDI_PI(pip)->pi_addr, paddr);

        /*
	 * We form the "path" to the pathinfo node, and see if we have
	 * already allocated a 'path_instance' for that "path".  If so,
	 * we use the already allocated 'path_instance'.  If not, we
	 * allocate a new 'path_instance' and associate it with a copy of
	 * the "path" string (which is never freed). The association
	 * between a 'path_instance' this "path" string persists until
	 * reboot.
	 */
        mutex_enter(&mdi_pathmap_mutex);
	(void) ddi_pathname(ph->ph_dip, path);
	(void) sprintf(path + strlen(path), "/%s@%s",
	    mdi_pi_get_node_name(pip), mdi_pi_get_addr(pip));
        if (mod_hash_find(mdi_pathmap_bypath, (mod_hash_key_t)path, &hv) == 0) {
                path_instance = (uint_t)(intptr_t)hv;
        } else {
		/* allocate a new 'path_instance' and persistent "path" */
		path_instance = mdi_pathmap_instance++;
		path_persistent = i_ddi_strdup(path, KM_SLEEP);
                (void) mod_hash_insert(mdi_pathmap_bypath,
                    (mod_hash_key_t)path_persistent,
                    (mod_hash_val_t)(intptr_t)path_instance);
		(void) mod_hash_insert(mdi_pathmap_byinstance,
		    (mod_hash_key_t)(intptr_t)path_instance,
		    (mod_hash_val_t)path_persistent);

		/* create shortpath name */
		(void) snprintf(path, sizeof(path), "%s%d/%s@%s",
		    ddi_driver_name(ph->ph_dip), ddi_get_instance(ph->ph_dip),
		    mdi_pi_get_node_name(pip), mdi_pi_get_addr(pip));
		path_persistent = i_ddi_strdup(path, KM_SLEEP);
		(void) mod_hash_insert(mdi_pathmap_sbyinstance,
		    (mod_hash_key_t)(intptr_t)path_instance,
		    (mod_hash_val_t)path_persistent);
        }
        mutex_exit(&mdi_pathmap_mutex);
	MDI_PI(pip)->pi_path_instance = path_instance;

	(void) nvlist_alloc(&MDI_PI(pip)->pi_prop, NV_UNIQUE_NAME, KM_SLEEP);
	ASSERT(MDI_PI(pip)->pi_prop != NULL);
	MDI_PI(pip)->pi_pprivate = NULL;
	MDI_PI(pip)->pi_cprivate = NULL;
	MDI_PI(pip)->pi_vprivate = NULL;
	MDI_PI(pip)->pi_client_link = NULL;
	MDI_PI(pip)->pi_phci_link = NULL;
	MDI_PI(pip)->pi_ref_cnt = 0;
	MDI_PI(pip)->pi_kstats = NULL;
	MDI_PI(pip)->pi_preferred = 1;
	cv_init(&MDI_PI(pip)->pi_ref_cv, NULL, CV_DEFAULT, NULL);

	/*
	 * Lock both dev_info nodes against changes in parallel.
	 *
	 * The ndi_devi_enter(Client), is atypical since the client is a leaf.
	 * This atypical operation is done to synchronize pathinfo nodes
	 * during devinfo snapshot (see di_register_pip) by 'pretending' that
	 * the pathinfo nodes are children of the Client.
	 */
	ndi_devi_enter(ct->ct_dip, &ct_circular);
	ndi_devi_enter(ph->ph_dip, &ph_circular);

	i_mdi_phci_add_path(ph, pip);
	i_mdi_client_add_path(ct, pip);

	ndi_devi_exit(ph->ph_dip, ph_circular);
	ndi_devi_exit(ct->ct_dip, ct_circular);

	return (pip);
}

/*
 * mdi_pi_pathname_by_instance():
 *	Lookup of "path" by 'path_instance'. Return "path".
 *	NOTE: returned "path" remains valid forever (until reboot).
 */
char *
mdi_pi_pathname_by_instance(int path_instance)
{
	char		*path;
	mod_hash_val_t	hv;

	/* mdi_pathmap lookup of "path" by 'path_instance' */
	mutex_enter(&mdi_pathmap_mutex);
	if (mod_hash_find(mdi_pathmap_byinstance,
	    (mod_hash_key_t)(intptr_t)path_instance, &hv) == 0)
		path = (char *)hv;
	else
		path = NULL;
	mutex_exit(&mdi_pathmap_mutex);
	return (path);
}

/*
 * mdi_pi_spathname_by_instance():
 *	Lookup of "shortpath" by 'path_instance'. Return "shortpath".
 *	NOTE: returned "shortpath" remains valid forever (until reboot).
 */
char *
mdi_pi_spathname_by_instance(int path_instance)
{
	char		*path;
	mod_hash_val_t	hv;

	/* mdi_pathmap lookup of "path" by 'path_instance' */
	mutex_enter(&mdi_pathmap_mutex);
	if (mod_hash_find(mdi_pathmap_sbyinstance,
	    (mod_hash_key_t)(intptr_t)path_instance, &hv) == 0)
		path = (char *)hv;
	else
		path = NULL;
	mutex_exit(&mdi_pathmap_mutex);
	return (path);
}


/*
 * i_mdi_phci_add_path():
 * 		Add a mdi_pathinfo node to pHCI list.
 * Notes:
 *		Caller should per-pHCI mutex
 */
static void
i_mdi_phci_add_path(mdi_phci_t *ph, mdi_pathinfo_t *pip)
{
	ASSERT(DEVI_BUSY_OWNED(ph->ph_dip));

	MDI_PHCI_LOCK(ph);
	if (ph->ph_path_head == NULL) {
		ph->ph_path_head = pip;
	} else {
		MDI_PI(ph->ph_path_tail)->pi_phci_link = MDI_PI(pip);
	}
	ph->ph_path_tail = pip;
	ph->ph_path_count++;
	MDI_PHCI_UNLOCK(ph);
}

/*
 * i_mdi_client_add_path():
 *		Add mdi_pathinfo node to client list
 */
static void
i_mdi_client_add_path(mdi_client_t *ct, mdi_pathinfo_t *pip)
{
	ASSERT(DEVI_BUSY_OWNED(ct->ct_dip));

	MDI_CLIENT_LOCK(ct);
	if (ct->ct_path_head == NULL) {
		ct->ct_path_head = pip;
	} else {
		MDI_PI(ct->ct_path_tail)->pi_client_link = MDI_PI(pip);
	}
	ct->ct_path_tail = pip;
	ct->ct_path_count++;
	MDI_CLIENT_UNLOCK(ct);
}

/*
 * mdi_pi_free():
 *		Free the mdi_pathinfo node and also client device node if this
 *		is the last path to the device
 * Return Values:
 *		MDI_SUCCESS
 *		MDI_FAILURE
 *		MDI_BUSY
 */
/*ARGSUSED*/
int
mdi_pi_free(mdi_pathinfo_t *pip, int flags)
{
	int		rv;
	mdi_vhci_t	*vh;
	mdi_phci_t	*ph;
	mdi_client_t	*ct;
	int		(*f)();
	int		client_held = 0;

	MDI_PI_LOCK(pip);
	ph = MDI_PI(pip)->pi_phci;
	ASSERT(ph != NULL);
	if (ph == NULL) {
		/*
		 * Invalid pHCI device, return failure
		 */
		MDI_DEBUG(1, (MDI_WARN, NULL,
		    "!invalid pHCI: pip %s %p",
		    mdi_pi_spathname(pip), (void *)pip));
		MDI_PI_UNLOCK(pip);
		return (MDI_FAILURE);
	}

	vh = ph->ph_vhci;
	ASSERT(vh != NULL);
	if (vh == NULL) {
		/* Invalid pHCI device, return failure */
		MDI_DEBUG(1, (MDI_WARN, ph->ph_dip,
		    "!invalid vHCI: pip %s %p",
		    mdi_pi_spathname(pip), (void *)pip));
		MDI_PI_UNLOCK(pip);
		return (MDI_FAILURE);
	}

	ct = MDI_PI(pip)->pi_client;
	ASSERT(ct != NULL);
	if (ct == NULL) {
		/*
		 * Invalid Client device, return failure
		 */
		MDI_DEBUG(1, (MDI_WARN, ph->ph_dip,
		    "!invalid client: pip %s %p",
		    mdi_pi_spathname(pip), (void *)pip));
		MDI_PI_UNLOCK(pip);
		return (MDI_FAILURE);
	}

	/*
	 * Check to see for busy condition.  A mdi_pathinfo can only be freed
	 * if the node state is either offline or init and the reference count
	 * is zero.
	 */
	if (!(MDI_PI_IS_OFFLINE(pip) || MDI_PI_IS_INIT(pip) ||
	    MDI_PI_IS_INITING(pip))) {
		/*
		 * Node is busy
		 */
		MDI_DEBUG(1, (MDI_WARN, ct->ct_dip,
		    "!busy: pip %s %p", mdi_pi_spathname(pip), (void *)pip));
		MDI_PI_UNLOCK(pip);
		return (MDI_BUSY);
	}

	while (MDI_PI(pip)->pi_ref_cnt != 0) {
		/*
		 * Give a chance for pending I/Os to complete.
		 */
		MDI_DEBUG(1, (MDI_NOTE, ct->ct_dip,
		    "!%d cmds still pending on path: %s %p",
		    MDI_PI(pip)->pi_ref_cnt,
		    mdi_pi_spathname(pip), (void *)pip));
		if (cv_reltimedwait(&MDI_PI(pip)->pi_ref_cv,
		    &MDI_PI(pip)->pi_mutex, drv_usectohz(60 * 1000000),
		    TR_CLOCK_TICK) == -1) {
			/*
			 * The timeout time reached without ref_cnt being zero
			 * being signaled.
			 */
			MDI_DEBUG(1, (MDI_NOTE, ct->ct_dip,
			    "!Timeout reached on path %s %p without the cond",
			    mdi_pi_spathname(pip), (void *)pip));
			MDI_DEBUG(1, (MDI_NOTE, ct->ct_dip,
			    "!%d cmds still pending on path %s %p",
			    MDI_PI(pip)->pi_ref_cnt,
			    mdi_pi_spathname(pip), (void *)pip));
			MDI_PI_UNLOCK(pip);
			return (MDI_BUSY);
		}
	}
	if (MDI_PI(pip)->pi_pm_held) {
		client_held = 1;
	}
	MDI_PI_UNLOCK(pip);

	vhcache_pi_remove(vh->vh_config, MDI_PI(pip));

	MDI_CLIENT_LOCK(ct);

	/* Prevent further failovers till MDI_VHCI_CLIENT_LOCK is held */
	MDI_CLIENT_SET_PATH_FREE_IN_PROGRESS(ct);

	/*
	 * Wait till failover is complete before removing this node.
	 */
	while (MDI_CLIENT_IS_FAILOVER_IN_PROGRESS(ct))
		cv_wait(&ct->ct_failover_cv, &ct->ct_mutex);

	MDI_CLIENT_UNLOCK(ct);
	MDI_VHCI_CLIENT_LOCK(vh);
	MDI_CLIENT_LOCK(ct);
	MDI_CLIENT_CLEAR_PATH_FREE_IN_PROGRESS(ct);

	if (!MDI_PI_IS_INITING(pip)) {
		f = vh->vh_ops->vo_pi_uninit;
		if (f != NULL) {
			rv = (*f)(vh->vh_dip, pip, 0);
		}
	} else
		rv = MDI_SUCCESS;

	/*
	 * If vo_pi_uninit() completed successfully.
	 */
	if (rv == MDI_SUCCESS) {
		if (client_held) {
			MDI_DEBUG(4, (MDI_NOTE, ct->ct_dip,
			    "i_mdi_pm_rele_client\n"));
			i_mdi_pm_rele_client(ct, 1);
		}
		i_mdi_pi_free(ph, pip, ct);
		if (ct->ct_path_count == 0) {
			/*
			 * Client lost its last path.
			 * Clean up the client device
			 */
			MDI_CLIENT_UNLOCK(ct);
			(void) i_mdi_client_free(ct->ct_vhci, ct);
			MDI_VHCI_CLIENT_UNLOCK(vh);
			return (rv);
		}
	}
	MDI_CLIENT_UNLOCK(ct);
	MDI_VHCI_CLIENT_UNLOCK(vh);

	if (rv == MDI_FAILURE)
		vhcache_pi_add(vh->vh_config, MDI_PI(pip));

	return (rv);
}

/*
 * i_mdi_pi_free():
 *		Free the mdi_pathinfo node
 */
static void
i_mdi_pi_free(mdi_phci_t *ph, mdi_pathinfo_t *pip, mdi_client_t *ct)
{
	int	ct_circular;
	int	ph_circular;

	ASSERT(MDI_CLIENT_LOCKED(ct));

	/*
	 * remove any per-path kstats
	 */
	i_mdi_pi_kstat_destroy(pip);

	/* See comments in i_mdi_pi_alloc() */
	ndi_devi_enter(ct->ct_dip, &ct_circular);
	ndi_devi_enter(ph->ph_dip, &ph_circular);

	i_mdi_client_remove_path(ct, pip);
	i_mdi_phci_remove_path(ph, pip);

	ndi_devi_exit(ph->ph_dip, ph_circular);
	ndi_devi_exit(ct->ct_dip, ct_circular);

	mutex_destroy(&MDI_PI(pip)->pi_mutex);
	cv_destroy(&MDI_PI(pip)->pi_state_cv);
	cv_destroy(&MDI_PI(pip)->pi_ref_cv);
	if (MDI_PI(pip)->pi_addr) {
		kmem_free(MDI_PI(pip)->pi_addr,
		    strlen(MDI_PI(pip)->pi_addr) + 1);
		MDI_PI(pip)->pi_addr = NULL;
	}

	if (MDI_PI(pip)->pi_prop) {
		(void) nvlist_free(MDI_PI(pip)->pi_prop);
		MDI_PI(pip)->pi_prop = NULL;
	}
	kmem_free(pip, sizeof (struct mdi_pathinfo));
}


/*
 * i_mdi_phci_remove_path():
 * 		Remove a mdi_pathinfo node from pHCI list.
 * Notes:
 *		Caller should hold per-pHCI mutex
 */
static void
i_mdi_phci_remove_path(mdi_phci_t *ph, mdi_pathinfo_t *pip)
{
	mdi_pathinfo_t	*prev = NULL;
	mdi_pathinfo_t	*path = NULL;

	ASSERT(DEVI_BUSY_OWNED(ph->ph_dip));

	MDI_PHCI_LOCK(ph);
	path = ph->ph_path_head;
	while (path != NULL) {
		if (path == pip) {
			break;
		}
		prev = path;
		path = (mdi_pathinfo_t *)MDI_PI(path)->pi_phci_link;
	}

	if (path) {
		ph->ph_path_count--;
		if (prev) {
			MDI_PI(prev)->pi_phci_link = MDI_PI(path)->pi_phci_link;
		} else {
			ph->ph_path_head =
			    (mdi_pathinfo_t *)MDI_PI(path)->pi_phci_link;
		}
		if (ph->ph_path_tail == path) {
			ph->ph_path_tail = prev;
		}
	}

	/*
	 * Clear the pHCI link
	 */
	MDI_PI(pip)->pi_phci_link = NULL;
	MDI_PI(pip)->pi_phci = NULL;
	MDI_PHCI_UNLOCK(ph);
}

/*
 * i_mdi_client_remove_path():
 * 		Remove a mdi_pathinfo node from client path list.
 */
static void
i_mdi_client_remove_path(mdi_client_t *ct, mdi_pathinfo_t *pip)
{
	mdi_pathinfo_t	*prev = NULL;
	mdi_pathinfo_t	*path;

	ASSERT(DEVI_BUSY_OWNED(ct->ct_dip));

	ASSERT(MDI_CLIENT_LOCKED(ct));
	path = ct->ct_path_head;
	while (path != NULL) {
		if (path == pip) {
			break;
		}
		prev = path;
		path = (mdi_pathinfo_t *)MDI_PI(path)->pi_client_link;
	}

	if (path) {
		ct->ct_path_count--;
		if (prev) {
			MDI_PI(prev)->pi_client_link =
			    MDI_PI(path)->pi_client_link;
		} else {
			ct->ct_path_head =
			    (mdi_pathinfo_t *)MDI_PI(path)->pi_client_link;
		}
		if (ct->ct_path_tail == path) {
			ct->ct_path_tail = prev;
		}
		if (ct->ct_path_last == path) {
			ct->ct_path_last = ct->ct_path_head;
		}
	}
	MDI_PI(pip)->pi_client_link = NULL;
	MDI_PI(pip)->pi_client = NULL;
}

/*
 * i_mdi_pi_state_change():
 *		online a mdi_pathinfo node
 *
 * Return Values:
 *		MDI_SUCCESS
 *		MDI_FAILURE
 */
/*ARGSUSED*/
static int
i_mdi_pi_state_change(mdi_pathinfo_t *pip, mdi_pathinfo_state_t state, int flag)
{
	int		rv = MDI_SUCCESS;
	mdi_vhci_t	*vh;
	mdi_phci_t	*ph;
	mdi_client_t	*ct;
	int		(*f)();
	dev_info_t	*cdip;

	MDI_PI_LOCK(pip);

	ph = MDI_PI(pip)->pi_phci;
	ASSERT(ph);
	if (ph == NULL) {
		/*
		 * Invalid pHCI device, fail the request
		 */
		MDI_PI_UNLOCK(pip);
		MDI_DEBUG(1, (MDI_WARN, NULL,
		    "!invalid phci: pip %s %p",
		    mdi_pi_spathname(pip), (void *)pip));
		return (MDI_FAILURE);
	}

	vh = ph->ph_vhci;
	ASSERT(vh);
	if (vh == NULL) {
		/*
		 * Invalid vHCI device, fail the request
		 */
		MDI_PI_UNLOCK(pip);
		MDI_DEBUG(1, (MDI_WARN, ph->ph_dip,
		    "!invalid vhci: pip %s %p",
		    mdi_pi_spathname(pip), (void *)pip));
		return (MDI_FAILURE);
	}

	ct = MDI_PI(pip)->pi_client;
	ASSERT(ct != NULL);
	if (ct == NULL) {
		/*
		 * Invalid client device, fail the request
		 */
		MDI_PI_UNLOCK(pip);
		MDI_DEBUG(1, (MDI_WARN, ph->ph_dip,
		    "!invalid client: pip %s %p",
		    mdi_pi_spathname(pip), (void *)pip));
		return (MDI_FAILURE);
	}

	/*
	 * If this path has not been initialized yet, Callback vHCI driver's
	 * pathinfo node initialize entry point
	 */

	if (MDI_PI_IS_INITING(pip)) {
		MDI_PI_UNLOCK(pip);
		f = vh->vh_ops->vo_pi_init;
		if (f != NULL) {
			rv = (*f)(vh->vh_dip, pip, 0);
			if (rv != MDI_SUCCESS) {
				MDI_DEBUG(1, (MDI_WARN, ct->ct_dip,
				    "!vo_pi_init failed: vHCI %p, pip %s %p",
				    (void *)vh, mdi_pi_spathname(pip),
				    (void *)pip));
				return (MDI_FAILURE);
			}
		}
		MDI_PI_LOCK(pip);
		MDI_PI_CLEAR_TRANSIENT(pip);
	}

	/*
	 * Do not allow state transition when pHCI is in offline/suspended
	 * states
	 */
	i_mdi_phci_lock(ph, pip);
	if (MDI_PHCI_IS_READY(ph) == 0) {
		MDI_DEBUG(1, (MDI_WARN, ct->ct_dip,
		    "!pHCI not ready, pHCI=%p", (void *)ph));
		MDI_PI_UNLOCK(pip);
		i_mdi_phci_unlock(ph);
		return (MDI_BUSY);
	}
	MDI_PHCI_UNSTABLE(ph);
	i_mdi_phci_unlock(ph);

	/*
	 * Check if mdi_pathinfo state is in transient state.
	 * If yes, offlining is in progress and wait till transient state is
	 * cleared.
	 */
	if (MDI_PI_IS_TRANSIENT(pip)) {
		while (MDI_PI_IS_TRANSIENT(pip)) {
			cv_wait(&MDI_PI(pip)->pi_state_cv,
			    &MDI_PI(pip)->pi_mutex);
		}
	}

	/*
	 * Grab the client lock in reverse order sequence and release the
	 * mdi_pathinfo mutex.
	 */
	i_mdi_client_lock(ct, pip);
	MDI_PI_UNLOCK(pip);

	/*
	 * Wait till failover state is cleared
	 */
	while (MDI_CLIENT_IS_FAILOVER_IN_PROGRESS(ct))
		cv_wait(&ct->ct_failover_cv, &ct->ct_mutex);

	/*
	 * Mark the mdi_pathinfo node state as transient
	 */
	MDI_PI_LOCK(pip);
	switch (state) {
	case MDI_PATHINFO_STATE_ONLINE:
		MDI_PI_SET_ONLINING(pip);
		break;

	case MDI_PATHINFO_STATE_STANDBY:
		MDI_PI_SET_STANDBYING(pip);
		break;

	case MDI_PATHINFO_STATE_FAULT:
		/*
		 * Mark the pathinfo state as FAULTED
		 */
		MDI_PI_SET_FAULTING(pip);
		MDI_PI_ERRSTAT(pip, MDI_PI_HARDERR);
		break;

	case MDI_PATHINFO_STATE_OFFLINE:
		/*
		 * ndi_devi_offline() cannot hold pip or ct locks.
		 */
		MDI_PI_UNLOCK(pip);

		/*
		 * If this is a user initiated path online->offline operation
		 * who's success would transition a client from DEGRADED to
		 * FAILED then only proceed if we can offline the client first.
		 */
		cdip = ct->ct_dip;
		if ((flag & NDI_USER_REQ) &&
		    MDI_PI_IS_ONLINE(pip) &&
		    (MDI_CLIENT_STATE(ct) == MDI_CLIENT_STATE_DEGRADED)) {
			i_mdi_client_unlock(ct);
			rv = ndi_devi_offline(cdip, NDI_DEVFS_CLEAN);
			if (rv != NDI_SUCCESS) {
				/*
				 * Convert to MDI error code
				 */
				switch (rv) {
				case NDI_BUSY:
					rv = MDI_BUSY;
					break;
				default:
					rv = MDI_FAILURE;
					break;
				}
				goto state_change_exit;
			} else {
				i_mdi_client_lock(ct, NULL);
			}
		}
		/*
		 * Mark the mdi_pathinfo node state as transient
		 */
		MDI_PI_LOCK(pip);
		MDI_PI_SET_OFFLINING(pip);
		break;
	}
	MDI_PI_UNLOCK(pip);
	MDI_CLIENT_UNSTABLE(ct);
	i_mdi_client_unlock(ct);

	f = vh->vh_ops->vo_pi_state_change;
	if (f != NULL)
		rv = (*f)(vh->vh_dip, pip, state, 0, flag);

	MDI_CLIENT_LOCK(ct);
	MDI_PI_LOCK(pip);
	if (rv == MDI_NOT_SUPPORTED) {
		MDI_CLIENT_SET_DEV_NOT_SUPPORTED(ct);
	}
	if (rv != MDI_SUCCESS) {
		MDI_DEBUG(2, (MDI_WARN, ct->ct_dip,
		    "vo_pi_state_change failed: rv %x", rv));
	}
	if (MDI_PI_IS_TRANSIENT(pip)) {
		if (rv == MDI_SUCCESS) {
			MDI_PI_CLEAR_TRANSIENT(pip);
		} else {
			MDI_PI(pip)->pi_state = MDI_PI_OLD_STATE(pip);
		}
	}

	/*
	 * Wake anyone waiting for this mdi_pathinfo node
	 */
	cv_broadcast(&MDI_PI(pip)->pi_state_cv);
	MDI_PI_UNLOCK(pip);

	/*
	 * Mark the client device as stable
	 */
	MDI_CLIENT_STABLE(ct);
	if (rv == MDI_SUCCESS) {
		if (ct->ct_unstable == 0) {
			cdip = ct->ct_dip;

			/*
			 * Onlining the mdi_pathinfo node will impact the
			 * client state Update the client and dev_info node
			 * state accordingly
			 */
			rv = NDI_SUCCESS;
			i_mdi_client_update_state(ct);
			switch (MDI_CLIENT_STATE(ct)) {
			case MDI_CLIENT_STATE_OPTIMAL:
			case MDI_CLIENT_STATE_DEGRADED:
				if (cdip && !i_ddi_devi_attached(cdip) &&
				    ((state == MDI_PATHINFO_STATE_ONLINE) ||
				    (state == MDI_PATHINFO_STATE_STANDBY))) {

					/*
					 * Must do ndi_devi_online() through
					 * hotplug thread for deferred
					 * attach mechanism to work
					 */
					MDI_CLIENT_UNLOCK(ct);
					rv = ndi_devi_online(cdip, 0);
					MDI_CLIENT_LOCK(ct);
					if ((rv != NDI_SUCCESS) &&
					    (MDI_CLIENT_STATE(ct) ==
					    MDI_CLIENT_STATE_DEGRADED)) {
						MDI_DEBUG(1, (MDI_WARN, cdip,
						    "!ndi_devi_online failed "
						    "error %x", rv));
					}
					rv = NDI_SUCCESS;
				}
				break;

			case MDI_CLIENT_STATE_FAILED:
				/*
				 * This is the last path case for
				 * non-user initiated events.
				 */
				if (((flag & NDI_USER_REQ) == 0) &&
				    cdip && (i_ddi_node_state(cdip) >=
				    DS_INITIALIZED)) {
					MDI_CLIENT_UNLOCK(ct);
					rv = ndi_devi_offline(cdip,
					    NDI_DEVFS_CLEAN);
					MDI_CLIENT_LOCK(ct);

					if (rv != NDI_SUCCESS) {
						/*
						 * ndi_devi_offline failed.
						 * Reset client flags to
						 * online as the path could not
						 * be offlined.
						 */
						MDI_DEBUG(1, (MDI_WARN, cdip,
						    "!ndi_devi_offline failed: "
						    "error %x", rv));
						MDI_CLIENT_SET_ONLINE(ct);
					}
				}
				break;
			}
			/*
			 * Convert to MDI error code
			 */
			switch (rv) {
			case NDI_SUCCESS:
				MDI_CLIENT_SET_REPORT_DEV_NEEDED(ct);
				i_mdi_report_path_state(ct, pip);
				rv = MDI_SUCCESS;
				break;
			case NDI_BUSY:
				rv = MDI_BUSY;
				break;
			default:
				rv = MDI_FAILURE;
				break;
			}
		}
	}
	MDI_CLIENT_UNLOCK(ct);

state_change_exit:
	/*
	 * Mark the pHCI as stable again.
	 */
	MDI_PHCI_LOCK(ph);
	MDI_PHCI_STABLE(ph);
	MDI_PHCI_UNLOCK(ph);
	return (rv);
}

/*
 * mdi_pi_online():
 *		Place the path_info node in the online state.  The path is
 *		now available to be selected by mdi_select_path() for
 *		transporting I/O requests to client devices.
 * Return Values:
 *		MDI_SUCCESS
 *		MDI_FAILURE
 */
int
mdi_pi_online(mdi_pathinfo_t *pip, int flags)
{
	mdi_client_t	*ct = MDI_PI(pip)->pi_client;
	int		client_held = 0;
	int		rv;

	ASSERT(ct != NULL);
	rv = i_mdi_pi_state_change(pip, MDI_PATHINFO_STATE_ONLINE, flags);
	if (rv != MDI_SUCCESS)
		return (rv);

	MDI_PI_LOCK(pip);
	if (MDI_PI(pip)->pi_pm_held == 0) {
		MDI_DEBUG(4, (MDI_NOTE, ct->ct_dip,
		    "i_mdi_pm_hold_pip %p", (void *)pip));
		i_mdi_pm_hold_pip(pip);
		client_held = 1;
	}
	MDI_PI_UNLOCK(pip);

	if (client_held) {
		MDI_CLIENT_LOCK(ct);
		if (ct->ct_power_cnt == 0) {
			rv = i_mdi_power_all_phci(ct);
		}

		MDI_DEBUG(4, (MDI_NOTE, ct->ct_dip,
		    "i_mdi_pm_hold_client %p", (void *)ct));
		i_mdi_pm_hold_client(ct, 1);
		MDI_CLIENT_UNLOCK(ct);
	}

	return (rv);
}

/*
 * mdi_pi_standby():
 *		Place the mdi_pathinfo node in standby state
 *
 * Return Values:
 *		MDI_SUCCESS
 *		MDI_FAILURE
 */
int
mdi_pi_standby(mdi_pathinfo_t *pip, int flags)
{
	return (i_mdi_pi_state_change(pip, MDI_PATHINFO_STATE_STANDBY, flags));
}

/*
 * mdi_pi_fault():
 *		Place the mdi_pathinfo node in fault'ed state
 * Return Values:
 *		MDI_SUCCESS
 *		MDI_FAILURE
 */
int
mdi_pi_fault(mdi_pathinfo_t *pip, int flags)
{
	return (i_mdi_pi_state_change(pip, MDI_PATHINFO_STATE_FAULT, flags));
}

/*
 * mdi_pi_offline():
 *		Offline a mdi_pathinfo node.
 * Return Values:
 *		MDI_SUCCESS
 *		MDI_FAILURE
 */
int
mdi_pi_offline(mdi_pathinfo_t *pip, int flags)
{
	int	ret, client_held = 0;
	mdi_client_t	*ct;

	/*
	 * Original code overloaded NDI_DEVI_REMOVE to this interface, and
	 * used it to mean "user initiated operation" (i.e. devctl). Callers
	 * should now just use NDI_USER_REQ.
	 */
	if (flags & NDI_DEVI_REMOVE) {
		flags &= ~NDI_DEVI_REMOVE;
		flags |= NDI_USER_REQ;
	}

	ret = i_mdi_pi_state_change(pip, MDI_PATHINFO_STATE_OFFLINE, flags);

	if (ret == MDI_SUCCESS) {
		MDI_PI_LOCK(pip);
		if (MDI_PI(pip)->pi_pm_held) {
			client_held = 1;
		}
		MDI_PI_UNLOCK(pip);

		if (client_held) {
			ct = MDI_PI(pip)->pi_client;
			MDI_CLIENT_LOCK(ct);
			MDI_DEBUG(4, (MDI_NOTE, ct->ct_dip,
			    "i_mdi_pm_rele_client\n"));
			i_mdi_pm_rele_client(ct, 1);
			MDI_CLIENT_UNLOCK(ct);
		}
	}

	return (ret);
}

/*
 * i_mdi_pi_offline():
 *		Offline a mdi_pathinfo node and call the vHCI driver's callback
 */
static int
i_mdi_pi_offline(mdi_pathinfo_t *pip, int flags)
{
	dev_info_t	*vdip = NULL;
	mdi_vhci_t	*vh = NULL;
	mdi_client_t	*ct = NULL;
	int		(*f)();
	int		rv;

	MDI_PI_LOCK(pip);
	ct = MDI_PI(pip)->pi_client;
	ASSERT(ct != NULL);

	while (MDI_PI(pip)->pi_ref_cnt != 0) {
		/*
		 * Give a chance for pending I/Os to complete.
		 */
		MDI_DEBUG(1, (MDI_NOTE, ct->ct_dip,
		    "!%d cmds still pending on path %s %p",
		    MDI_PI(pip)->pi_ref_cnt, mdi_pi_spathname(pip),
		    (void *)pip));
		if (cv_reltimedwait(&MDI_PI(pip)->pi_ref_cv,
		    &MDI_PI(pip)->pi_mutex, drv_usectohz(60 * 1000000),
		    TR_CLOCK_TICK) == -1) {
			/*
			 * The timeout time reached without ref_cnt being zero
			 * being signaled.
			 */
			MDI_DEBUG(1, (MDI_NOTE, ct->ct_dip,
			    "!Timeout reached on path %s %p without the cond",
			    mdi_pi_spathname(pip), (void *)pip));
			MDI_DEBUG(1, (MDI_NOTE, ct->ct_dip,
			    "!%d cmds still pending on path %s %p",
			    MDI_PI(pip)->pi_ref_cnt,
			    mdi_pi_spathname(pip), (void *)pip));
		}
	}
	vh = ct->ct_vhci;
	vdip = vh->vh_dip;

	/*
	 * Notify vHCI that has registered this event
	 */
	ASSERT(vh->vh_ops);
	f = vh->vh_ops->vo_pi_state_change;

	if (f != NULL) {
		MDI_PI_UNLOCK(pip);
		if ((rv = (*f)(vdip, pip, MDI_PATHINFO_STATE_OFFLINE, 0,
		    flags)) != MDI_SUCCESS) {
			MDI_DEBUG(1, (MDI_WARN, ct->ct_dip,
			    "!vo_path_offline failed: vdip %s%d %p: path %s %p",
			    ddi_driver_name(vdip), ddi_get_instance(vdip),
			    (void *)vdip, mdi_pi_spathname(pip), (void *)pip));
		}
		MDI_PI_LOCK(pip);
	}

	/*
	 * Set the mdi_pathinfo node state and clear the transient condition
	 */
	MDI_PI_SET_OFFLINE(pip);
	cv_broadcast(&MDI_PI(pip)->pi_state_cv);
	MDI_PI_UNLOCK(pip);

	MDI_CLIENT_LOCK(ct);
	if (rv == MDI_SUCCESS) {
		if (ct->ct_unstable == 0) {
			dev_info_t	*cdip = ct->ct_dip;

			/*
			 * Onlining the mdi_pathinfo node will impact the
			 * client state Update the client and dev_info node
			 * state accordingly
			 */
			i_mdi_client_update_state(ct);
			rv = NDI_SUCCESS;
			if (MDI_CLIENT_STATE(ct) == MDI_CLIENT_STATE_FAILED) {
				if (cdip &&
				    (i_ddi_node_state(cdip) >=
				    DS_INITIALIZED)) {
					MDI_CLIENT_UNLOCK(ct);
					rv = ndi_devi_offline(cdip,
					    NDI_DEVFS_CLEAN);
					MDI_CLIENT_LOCK(ct);
					if (rv != NDI_SUCCESS) {
						/*
						 * ndi_devi_offline failed.
						 * Reset client flags to
						 * online.
						 */
						MDI_DEBUG(4, (MDI_WARN, cdip,
						    "ndi_devi_offline failed: "
						    "error %x", rv));
						MDI_CLIENT_SET_ONLINE(ct);
					}
				}
			}
			/*
			 * Convert to MDI error code
			 */
			switch (rv) {
			case NDI_SUCCESS:
				rv = MDI_SUCCESS;
				break;
			case NDI_BUSY:
				rv = MDI_BUSY;
				break;
			default:
				rv = MDI_FAILURE;
				break;
			}
		}
		MDI_CLIENT_SET_REPORT_DEV_NEEDED(ct);
		i_mdi_report_path_state(ct, pip);
	}

	MDI_CLIENT_UNLOCK(ct);

	/*
	 * Change in the mdi_pathinfo node state will impact the client state
	 */
	MDI_DEBUG(2, (MDI_NOTE, ct->ct_dip,
	    "ct = %p pip = %p", (void *)ct, (void *)pip));
	return (rv);
}

/*
 * i_mdi_pi_online():
 *		Online a mdi_pathinfo node and call the vHCI driver's callback
 */
static int
i_mdi_pi_online(mdi_pathinfo_t *pip, int flags)
{
	mdi_vhci_t	*vh = NULL;
	mdi_client_t	*ct = NULL;
	mdi_phci_t	*ph;
	int		(*f)();
	int		rv;

	MDI_PI_LOCK(pip);
	ph = MDI_PI(pip)->pi_phci;
	vh = ph->ph_vhci;
	ct = MDI_PI(pip)->pi_client;
	MDI_PI_SET_ONLINING(pip)
	MDI_PI_UNLOCK(pip);
	f = vh->vh_ops->vo_pi_state_change;
	if (f != NULL)
		rv = (*f)(vh->vh_dip, pip, MDI_PATHINFO_STATE_ONLINE, 0,
		    flags);
	MDI_CLIENT_LOCK(ct);
	MDI_PI_LOCK(pip);
	cv_broadcast(&MDI_PI(pip)->pi_state_cv);
	MDI_PI_UNLOCK(pip);
	if (rv == MDI_SUCCESS) {
		dev_info_t	*cdip = ct->ct_dip;

		rv = MDI_SUCCESS;
		i_mdi_client_update_state(ct);
		if (MDI_CLIENT_STATE(ct) == MDI_CLIENT_STATE_OPTIMAL ||
		    MDI_CLIENT_STATE(ct) == MDI_CLIENT_STATE_DEGRADED) {
			if (cdip && !i_ddi_devi_attached(cdip)) {
				MDI_CLIENT_UNLOCK(ct);
				rv = ndi_devi_online(cdip, 0);
				MDI_CLIENT_LOCK(ct);
				if ((rv != NDI_SUCCESS) &&
				    (MDI_CLIENT_STATE(ct) ==
				    MDI_CLIENT_STATE_DEGRADED)) {
					MDI_CLIENT_SET_OFFLINE(ct);
				}
				if (rv != NDI_SUCCESS) {
					/* Reset the path state */
					MDI_PI_LOCK(pip);
					MDI_PI(pip)->pi_state =
					    MDI_PI_OLD_STATE(pip);
					MDI_PI_UNLOCK(pip);
				}
			}
		}
		switch (rv) {
		case NDI_SUCCESS:
			MDI_CLIENT_SET_REPORT_DEV_NEEDED(ct);
			i_mdi_report_path_state(ct, pip);
			rv = MDI_SUCCESS;
			break;
		case NDI_BUSY:
			rv = MDI_BUSY;
			break;
		default:
			rv = MDI_FAILURE;
			break;
		}
	} else {
		/* Reset the path state */
		MDI_PI_LOCK(pip);
		MDI_PI(pip)->pi_state = MDI_PI_OLD_STATE(pip);
		MDI_PI_UNLOCK(pip);
	}
	MDI_CLIENT_UNLOCK(ct);
	return (rv);
}

/*
 * mdi_pi_get_node_name():
 *              Get the name associated with a mdi_pathinfo node.
 *              Since pathinfo nodes are not directly named, we
 *              return the node_name of the client.
 *
 * Return Values:
 *              char *
 */
char *
mdi_pi_get_node_name(mdi_pathinfo_t *pip)
{
	mdi_client_t    *ct;

	if (pip == NULL)
		return (NULL);
	ct = MDI_PI(pip)->pi_client;
	if ((ct == NULL) || (ct->ct_dip == NULL))
		return (NULL);
	return (ddi_node_name(ct->ct_dip));
}

/*
 * mdi_pi_get_addr():
 *		Get the unit address associated with a mdi_pathinfo node
 *
 * Return Values:
 *		char *
 */
char *
mdi_pi_get_addr(mdi_pathinfo_t *pip)
{
	if (pip == NULL)
		return (NULL);

	return (MDI_PI(pip)->pi_addr);
}

/*
 * mdi_pi_get_path_instance():
 *		Get the 'path_instance' of a mdi_pathinfo node
 *
 * Return Values:
 *		path_instance
 */
int
mdi_pi_get_path_instance(mdi_pathinfo_t *pip)
{
	if (pip == NULL)
		return (0);

	return (MDI_PI(pip)->pi_path_instance);
}

/*
 * mdi_pi_pathname():
 *		Return pointer to path to pathinfo node.
 */
char *
mdi_pi_pathname(mdi_pathinfo_t *pip)
{
	if (pip == NULL)
		return (NULL);
	return (mdi_pi_pathname_by_instance(mdi_pi_get_path_instance(pip)));
}

/*
 * mdi_pi_spathname():
 *		Return pointer to shortpath to pathinfo node. Used for debug
 *		messages, so return "" instead of NULL when unknown.
 */
char *
mdi_pi_spathname(mdi_pathinfo_t *pip)
{
	char	*spath = "";

	if (pip) {
		spath = mdi_pi_spathname_by_instance(
		    mdi_pi_get_path_instance(pip));
		if (spath == NULL)
			spath = "";
	}
	return (spath);
}

char *
mdi_pi_pathname_obp(mdi_pathinfo_t *pip, char *path)
{
	char *obp_path = NULL;
	if ((pip == NULL) || (path == NULL))
		return (NULL);

	if (mdi_prop_lookup_string(pip, "obp-path", &obp_path) == MDI_SUCCESS) {
		(void) strcpy(path, obp_path);
		(void) mdi_prop_free(obp_path);
	} else {
		path = NULL;
	}
	return (path);
}

int
mdi_pi_pathname_obp_set(mdi_pathinfo_t *pip, char *component)
{
	dev_info_t *pdip;
	char *obp_path = NULL;
	int rc = MDI_FAILURE;

	if (pip == NULL)
		return (MDI_FAILURE);

	pdip = mdi_pi_get_phci(pip);
	if (pdip == NULL)
		return (MDI_FAILURE);

	obp_path = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

	if (ddi_pathname_obp(pdip, obp_path) == NULL) {
		(void) ddi_pathname(pdip, obp_path);
	}

	if (component) {
		(void) strncat(obp_path, "/", MAXPATHLEN);
		(void) strncat(obp_path, component, MAXPATHLEN);
	}
	rc = mdi_prop_update_string(pip, "obp-path", obp_path);

	if (obp_path)
		kmem_free(obp_path, MAXPATHLEN);
	return (rc);
}

/*
 * mdi_pi_get_client():
 *		Get the client devinfo associated with a mdi_pathinfo node
 *
 * Return Values:
 *		Handle to client device dev_info node
 */
dev_info_t *
mdi_pi_get_client(mdi_pathinfo_t *pip)
{
	dev_info_t	*dip = NULL;
	if (pip) {
		dip = MDI_PI(pip)->pi_client->ct_dip;
	}
	return (dip);
}

/*
 * mdi_pi_get_phci():
 *		Get the pHCI devinfo associated with the mdi_pathinfo node
 * Return Values:
 *		Handle to dev_info node
 */
dev_info_t *
mdi_pi_get_phci(mdi_pathinfo_t *pip)
{
	dev_info_t	*dip = NULL;
	mdi_phci_t	*ph;

	if (pip) {
		ph = MDI_PI(pip)->pi_phci;
		if (ph)
			dip = ph->ph_dip;
	}
	return (dip);
}

/*
 * mdi_pi_get_client_private():
 *		Get the client private information associated with the
 *		mdi_pathinfo node
 */
void *
mdi_pi_get_client_private(mdi_pathinfo_t *pip)
{
	void *cprivate = NULL;
	if (pip) {
		cprivate = MDI_PI(pip)->pi_cprivate;
	}
	return (cprivate);
}

/*
 * mdi_pi_set_client_private():
 *		Set the client private information in the mdi_pathinfo node
 */
void
mdi_pi_set_client_private(mdi_pathinfo_t *pip, void *priv)
{
	if (pip) {
		MDI_PI(pip)->pi_cprivate = priv;
	}
}

/*
 * mdi_pi_get_phci_private():
 *		Get the pHCI private information associated with the
 *		mdi_pathinfo node
 */
caddr_t
mdi_pi_get_phci_private(mdi_pathinfo_t *pip)
{
	caddr_t	pprivate = NULL;

	if (pip) {
		pprivate = MDI_PI(pip)->pi_pprivate;
	}
	return (pprivate);
}

/*
 * mdi_pi_set_phci_private():
 *		Set the pHCI private information in the mdi_pathinfo node
 */
void
mdi_pi_set_phci_private(mdi_pathinfo_t *pip, caddr_t priv)
{
	if (pip) {
		MDI_PI(pip)->pi_pprivate = priv;
	}
}

/*
 * mdi_pi_get_state():
 *		Get the mdi_pathinfo node state. Transient states are internal
 *		and not provided to the users
 */
mdi_pathinfo_state_t
mdi_pi_get_state(mdi_pathinfo_t *pip)
{
	mdi_pathinfo_state_t    state = MDI_PATHINFO_STATE_INIT;

	if (pip) {
		if (MDI_PI_IS_TRANSIENT(pip)) {
			/*
			 * mdi_pathinfo is in state transition.  Return the
			 * last good state.
			 */
			state = MDI_PI_OLD_STATE(pip);
		} else {
			state = MDI_PI_STATE(pip);
		}
	}
	return (state);
}

/*
 * mdi_pi_get_flags():
 *		Get the mdi_pathinfo node flags.
 */
uint_t
mdi_pi_get_flags(mdi_pathinfo_t *pip)
{
	return (pip ? MDI_PI(pip)->pi_flags : 0);
}

/*
 * Note that the following function needs to be the new interface for
 * mdi_pi_get_state when mpxio gets integrated to ON.
 */
int
mdi_pi_get_state2(mdi_pathinfo_t *pip, mdi_pathinfo_state_t *state,
		uint32_t *ext_state)
{
	*state = MDI_PATHINFO_STATE_INIT;

	if (pip) {
		if (MDI_PI_IS_TRANSIENT(pip)) {
			/*
			 * mdi_pathinfo is in state transition.  Return the
			 * last good state.
			 */
			*state = MDI_PI_OLD_STATE(pip);
			*ext_state = MDI_PI_OLD_EXT_STATE(pip);
		} else {
			*state = MDI_PI_STATE(pip);
			*ext_state = MDI_PI_EXT_STATE(pip);
		}
	}
	return (MDI_SUCCESS);
}

/*
 * mdi_pi_get_preferred:
 *	Get the preferred path flag
 */
int
mdi_pi_get_preferred(mdi_pathinfo_t *pip)
{
	if (pip) {
		return (MDI_PI(pip)->pi_preferred);
	}
	return (0);
}

/*
 * mdi_pi_set_preferred:
 *	Set the preferred path flag
 */
void
mdi_pi_set_preferred(mdi_pathinfo_t *pip, int preferred)
{
	if (pip) {
		MDI_PI(pip)->pi_preferred = preferred;
	}
}

/*
 * mdi_pi_set_state():
 *		Set the mdi_pathinfo node state
 */
void
mdi_pi_set_state(mdi_pathinfo_t *pip, mdi_pathinfo_state_t state)
{
	uint32_t	ext_state;

	if (pip) {
		ext_state = MDI_PI(pip)->pi_state & MDI_PATHINFO_EXT_STATE_MASK;
		MDI_PI(pip)->pi_state = state;
		MDI_PI(pip)->pi_state |= ext_state;

		/* Path has changed state, invalidate DINFOCACHE snap shot. */
		i_ddi_di_cache_invalidate();
	}
}

/*
 * Property functions:
 */
int
i_map_nvlist_error_to_mdi(int val)
{
	int rv;

	switch (val) {
	case 0:
		rv = DDI_PROP_SUCCESS;
		break;
	case EINVAL:
	case ENOTSUP:
		rv = DDI_PROP_INVAL_ARG;
		break;
	case ENOMEM:
		rv = DDI_PROP_NO_MEMORY;
		break;
	default:
		rv = DDI_PROP_NOT_FOUND;
		break;
	}
	return (rv);
}

/*
 * mdi_pi_get_next_prop():
 * 		Property walk function.  The caller should hold mdi_pi_lock()
 *		and release by calling mdi_pi_unlock() at the end of walk to
 *		get a consistent value.
 */
nvpair_t *
mdi_pi_get_next_prop(mdi_pathinfo_t *pip, nvpair_t *prev)
{
	if ((pip == NULL) || (MDI_PI(pip)->pi_prop == NULL)) {
		return (NULL);
	}
	ASSERT(MDI_PI_LOCKED(pip));
	return (nvlist_next_nvpair(MDI_PI(pip)->pi_prop, prev));
}

/*
 * mdi_prop_remove():
 * 		Remove the named property from the named list.
 */
int
mdi_prop_remove(mdi_pathinfo_t *pip, char *name)
{
	if (pip == NULL) {
		return (DDI_PROP_NOT_FOUND);
	}
	ASSERT(!MDI_PI_LOCKED(pip));
	MDI_PI_LOCK(pip);
	if (MDI_PI(pip)->pi_prop == NULL) {
		MDI_PI_UNLOCK(pip);
		return (DDI_PROP_NOT_FOUND);
	}
	if (name) {
		(void) nvlist_remove_all(MDI_PI(pip)->pi_prop, name);
	} else {
		char		nvp_name[MAXNAMELEN];
		nvpair_t	*nvp;
		nvp = nvlist_next_nvpair(MDI_PI(pip)->pi_prop, NULL);
		while (nvp) {
			nvpair_t	*next;
			next = nvlist_next_nvpair(MDI_PI(pip)->pi_prop, nvp);
			(void) snprintf(nvp_name, sizeof(nvp_name), "%s",
			    nvpair_name(nvp));
			(void) nvlist_remove_all(MDI_PI(pip)->pi_prop,
			    nvp_name);
			nvp = next;
		}
	}
	MDI_PI_UNLOCK(pip);
	return (DDI_PROP_SUCCESS);
}

/*
 * mdi_prop_size():
 * 		Get buffer size needed to pack the property data.
 * 		Caller should hold the mdi_pathinfo_t lock to get a consistent
 *		buffer size.
 */
int
mdi_prop_size(mdi_pathinfo_t *pip, size_t *buflenp)
{
	int	rv;
	size_t	bufsize;

	*buflenp = 0;
	if ((pip == NULL) || (MDI_PI(pip)->pi_prop == NULL)) {
		return (DDI_PROP_NOT_FOUND);
	}
	ASSERT(MDI_PI_LOCKED(pip));
	rv = nvlist_size(MDI_PI(pip)->pi_prop,
	    &bufsize, NV_ENCODE_NATIVE);
	*buflenp = bufsize;
	return (i_map_nvlist_error_to_mdi(rv));
}

/*
 * mdi_prop_pack():
 * 		pack the property list.  The caller should hold the
 *		mdi_pathinfo_t node to get a consistent data
 */
int
mdi_prop_pack(mdi_pathinfo_t *pip, char **bufp, uint_t buflen)
{
	int	rv;
	size_t	bufsize;

	if ((pip == NULL) || MDI_PI(pip)->pi_prop == NULL) {
		return (DDI_PROP_NOT_FOUND);
	}

	ASSERT(MDI_PI_LOCKED(pip));

	bufsize = buflen;
	rv = nvlist_pack(MDI_PI(pip)->pi_prop, bufp, (size_t *)&bufsize,
	    NV_ENCODE_NATIVE, KM_SLEEP);

	return (i_map_nvlist_error_to_mdi(rv));
}

/*
 * mdi_prop_update_byte():
 *		Create/Update a byte property
 */
int
mdi_prop_update_byte(mdi_pathinfo_t *pip, char *name, uchar_t data)
{
	int rv;

	if (pip == NULL) {
		return (DDI_PROP_INVAL_ARG);
	}
	ASSERT(!MDI_PI_LOCKED(pip));
	MDI_PI_LOCK(pip);
	if (MDI_PI(pip)->pi_prop == NULL) {
		MDI_PI_UNLOCK(pip);
		return (DDI_PROP_NOT_FOUND);
	}
	rv = nvlist_add_byte(MDI_PI(pip)->pi_prop, name, data);
	MDI_PI_UNLOCK(pip);
	return (i_map_nvlist_error_to_mdi(rv));
}

/*
 * mdi_prop_update_byte_array():
 *		Create/Update a byte array property
 */
int
mdi_prop_update_byte_array(mdi_pathinfo_t *pip, char *name, uchar_t *data,
    uint_t nelements)
{
	int rv;

	if (pip == NULL) {
		return (DDI_PROP_INVAL_ARG);
	}
	ASSERT(!MDI_PI_LOCKED(pip));
	MDI_PI_LOCK(pip);
	if (MDI_PI(pip)->pi_prop == NULL) {
		MDI_PI_UNLOCK(pip);
		return (DDI_PROP_NOT_FOUND);
	}
	rv = nvlist_add_byte_array(MDI_PI(pip)->pi_prop, name, data, nelements);
	MDI_PI_UNLOCK(pip);
	return (i_map_nvlist_error_to_mdi(rv));
}

/*
 * mdi_prop_update_int():
 *		Create/Update a 32 bit integer property
 */
int
mdi_prop_update_int(mdi_pathinfo_t *pip, char *name, int data)
{
	int rv;

	if (pip == NULL) {
		return (DDI_PROP_INVAL_ARG);
	}
	ASSERT(!MDI_PI_LOCKED(pip));
	MDI_PI_LOCK(pip);
	if (MDI_PI(pip)->pi_prop == NULL) {
		MDI_PI_UNLOCK(pip);
		return (DDI_PROP_NOT_FOUND);
	}
	rv = nvlist_add_int32(MDI_PI(pip)->pi_prop, name, (int32_t)data);
	MDI_PI_UNLOCK(pip);
	return (i_map_nvlist_error_to_mdi(rv));
}

/*
 * mdi_prop_update_int64():
 *		Create/Update a 64 bit integer property
 */
int
mdi_prop_update_int64(mdi_pathinfo_t *pip, char *name, int64_t data)
{
	int rv;

	if (pip == NULL) {
		return (DDI_PROP_INVAL_ARG);
	}
	ASSERT(!MDI_PI_LOCKED(pip));
	MDI_PI_LOCK(pip);
	if (MDI_PI(pip)->pi_prop == NULL) {
		MDI_PI_UNLOCK(pip);
		return (DDI_PROP_NOT_FOUND);
	}
	rv = nvlist_add_int64(MDI_PI(pip)->pi_prop, name, data);
	MDI_PI_UNLOCK(pip);
	return (i_map_nvlist_error_to_mdi(rv));
}

/*
 * mdi_prop_update_int_array():
 *		Create/Update a int array property
 */
int
mdi_prop_update_int_array(mdi_pathinfo_t *pip, char *name, int *data,
	    uint_t nelements)
{
	int rv;

	if (pip == NULL) {
		return (DDI_PROP_INVAL_ARG);
	}
	ASSERT(!MDI_PI_LOCKED(pip));
	MDI_PI_LOCK(pip);
	if (MDI_PI(pip)->pi_prop == NULL) {
		MDI_PI_UNLOCK(pip);
		return (DDI_PROP_NOT_FOUND);
	}
	rv = nvlist_add_int32_array(MDI_PI(pip)->pi_prop, name, (int32_t *)data,
	    nelements);
	MDI_PI_UNLOCK(pip);
	return (i_map_nvlist_error_to_mdi(rv));
}

/*
 * mdi_prop_update_string():
 *		Create/Update a string property
 */
int
mdi_prop_update_string(mdi_pathinfo_t *pip, char *name, char *data)
{
	int rv;

	if (pip == NULL) {
		return (DDI_PROP_INVAL_ARG);
	}
	ASSERT(!MDI_PI_LOCKED(pip));
	MDI_PI_LOCK(pip);
	if (MDI_PI(pip)->pi_prop == NULL) {
		MDI_PI_UNLOCK(pip);
		return (DDI_PROP_NOT_FOUND);
	}
	rv = nvlist_add_string(MDI_PI(pip)->pi_prop, name, data);
	MDI_PI_UNLOCK(pip);
	return (i_map_nvlist_error_to_mdi(rv));
}

/*
 * mdi_prop_update_string_array():
 *		Create/Update a string array property
 */
int
mdi_prop_update_string_array(mdi_pathinfo_t *pip, char *name, char **data,
    uint_t nelements)
{
	int rv;

	if (pip == NULL) {
		return (DDI_PROP_INVAL_ARG);
	}
	ASSERT(!MDI_PI_LOCKED(pip));
	MDI_PI_LOCK(pip);
	if (MDI_PI(pip)->pi_prop == NULL) {
		MDI_PI_UNLOCK(pip);
		return (DDI_PROP_NOT_FOUND);
	}
	rv = nvlist_add_string_array(MDI_PI(pip)->pi_prop, name, data,
	    nelements);
	MDI_PI_UNLOCK(pip);
	return (i_map_nvlist_error_to_mdi(rv));
}

/*
 * mdi_prop_lookup_byte():
 * 		Look for byte property identified by name.  The data returned
 *		is the actual property and valid as long as mdi_pathinfo_t node
 *		is alive.
 */
int
mdi_prop_lookup_byte(mdi_pathinfo_t *pip, char *name, uchar_t *data)
{
	int rv;

	if ((pip == NULL) || (MDI_PI(pip)->pi_prop == NULL)) {
		return (DDI_PROP_NOT_FOUND);
	}
	rv = nvlist_lookup_byte(MDI_PI(pip)->pi_prop, name, data);
	return (i_map_nvlist_error_to_mdi(rv));
}


/*
 * mdi_prop_lookup_byte_array():
 * 		Look for byte array property identified by name.  The data
 *		returned is the actual property and valid as long as
 *		mdi_pathinfo_t node is alive.
 */
int
mdi_prop_lookup_byte_array(mdi_pathinfo_t *pip, char *name, uchar_t **data,
    uint_t *nelements)
{
	int rv;

	if ((pip == NULL) || (MDI_PI(pip)->pi_prop == NULL)) {
		return (DDI_PROP_NOT_FOUND);
	}
	rv = nvlist_lookup_byte_array(MDI_PI(pip)->pi_prop, name, data,
	    nelements);
	return (i_map_nvlist_error_to_mdi(rv));
}

/*
 * mdi_prop_lookup_int():
 * 		Look for int property identified by name.  The data returned
 *		is the actual property and valid as long as mdi_pathinfo_t
 *		node is alive.
 */
int
mdi_prop_lookup_int(mdi_pathinfo_t *pip, char *name, int *data)
{
	int rv;

	if ((pip == NULL) || (MDI_PI(pip)->pi_prop == NULL)) {
		return (DDI_PROP_NOT_FOUND);
	}
	rv = nvlist_lookup_int32(MDI_PI(pip)->pi_prop, name, (int32_t *)data);
	return (i_map_nvlist_error_to_mdi(rv));
}

/*
 * mdi_prop_lookup_int64():
 * 		Look for int64 property identified by name.  The data returned
 *		is the actual property and valid as long as mdi_pathinfo_t node
 *		is alive.
 */
int
mdi_prop_lookup_int64(mdi_pathinfo_t *pip, char *name, int64_t *data)
{
	int rv;
	if ((pip == NULL) || (MDI_PI(pip)->pi_prop == NULL)) {
		return (DDI_PROP_NOT_FOUND);
	}
	rv = nvlist_lookup_int64(MDI_PI(pip)->pi_prop, name, data);
	return (i_map_nvlist_error_to_mdi(rv));
}

/*
 * mdi_prop_lookup_int_array():
 * 		Look for int array property identified by name.  The data
 *		returned is the actual property and valid as long as
 *		mdi_pathinfo_t node is alive.
 */
int
mdi_prop_lookup_int_array(mdi_pathinfo_t *pip, char *name, int **data,
    uint_t *nelements)
{
	int rv;

	if ((pip == NULL) || (MDI_PI(pip)->pi_prop == NULL)) {
		return (DDI_PROP_NOT_FOUND);
	}
	rv = nvlist_lookup_int32_array(MDI_PI(pip)->pi_prop, name,
	    (int32_t **)data, nelements);
	return (i_map_nvlist_error_to_mdi(rv));
}

/*
 * mdi_prop_lookup_string():
 * 		Look for string property identified by name.  The data
 *		returned is the actual property and valid as long as
 *		mdi_pathinfo_t node is alive.
 */
int
mdi_prop_lookup_string(mdi_pathinfo_t *pip, char *name, char **data)
{
	int rv;

	if ((pip == NULL) || (MDI_PI(pip)->pi_prop == NULL)) {
		return (DDI_PROP_NOT_FOUND);
	}
	rv = nvlist_lookup_string(MDI_PI(pip)->pi_prop, name, data);
	return (i_map_nvlist_error_to_mdi(rv));
}

/*
 * mdi_prop_lookup_string_array():
 * 		Look for string array property identified by name.  The data
 *		returned is the actual property and valid as long as
 *		mdi_pathinfo_t node is alive.
 */
int
mdi_prop_lookup_string_array(mdi_pathinfo_t *pip, char *name, char ***data,
    uint_t *nelements)
{
	int rv;

	if ((pip == NULL) || (MDI_PI(pip)->pi_prop == NULL)) {
		return (DDI_PROP_NOT_FOUND);
	}
	rv = nvlist_lookup_string_array(MDI_PI(pip)->pi_prop, name, data,
	    nelements);
	return (i_map_nvlist_error_to_mdi(rv));
}

/*
 * mdi_prop_free():
 * 		Symmetrical function to ddi_prop_free(). nvlist_lookup_xx()
 *		functions return the pointer to actual property data and not a
 *		copy of it.  So the data returned is valid as long as
 *		mdi_pathinfo_t node is valid.
 */
/*ARGSUSED*/
int
mdi_prop_free(void *data)
{
	return (DDI_PROP_SUCCESS);
}

/*ARGSUSED*/
static void
i_mdi_report_path_state(mdi_client_t *ct, mdi_pathinfo_t *pip)
{
	char		*ct_path;
	char		*ct_status;
	char		*status;
	dev_info_t	*cdip = ct->ct_dip;
	char		lb_buf[64];
	int		report_lb_c = 0, report_lb_p = 0;

	ASSERT(MDI_CLIENT_LOCKED(ct));
	if ((cdip == NULL) || (ddi_get_instance(cdip) == -1) ||
	    (MDI_CLIENT_IS_REPORT_DEV_NEEDED(ct) == 0)) {
		return;
	}
	if (MDI_CLIENT_STATE(ct) == MDI_CLIENT_STATE_OPTIMAL) {
		ct_status = "optimal";
		report_lb_c = 1;
	} else if (MDI_CLIENT_STATE(ct) == MDI_CLIENT_STATE_DEGRADED) {
		ct_status = "degraded";
	} else if (MDI_CLIENT_STATE(ct) == MDI_CLIENT_STATE_FAILED) {
		ct_status = "failed";
	} else {
		ct_status = "unknown";
	}

	lb_buf[0] = 0;		/* not interested in load balancing config */

	if (MDI_PI_FLAGS_IS_DEVICE_REMOVED(pip)) {
		status = "removed";
	} else if (MDI_PI_IS_OFFLINE(pip)) {
		status = "offline";
	} else if (MDI_PI_IS_ONLINE(pip)) {
		status = "online";
		report_lb_p = 1;
	} else if (MDI_PI_IS_STANDBY(pip)) {
		status = "standby";
	} else if (MDI_PI_IS_FAULT(pip)) {
		status = "faulted";
	} else {
		status = "unknown";
	}

	if (cdip) {
		ct_path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		/*
		 * NOTE: Keeping "multipath status: %s" and
		 * "Load balancing: %s" format unchanged in case someone
		 * scrubs /var/adm/messages looking for these messages.
		 */
		if (report_lb_c && report_lb_p) {
			if (ct->ct_lb == LOAD_BALANCE_LBA) {
				(void) snprintf(lb_buf, sizeof (lb_buf),
				    "%s, region-size: %d", mdi_load_balance_lba,
				    ct->ct_lb_args->region_size);
			} else if (ct->ct_lb == LOAD_BALANCE_NONE) {
				(void) snprintf(lb_buf, sizeof (lb_buf),
				    "%s", mdi_load_balance_none);
			} else {
				(void) snprintf(lb_buf, sizeof (lb_buf), "%s",
				    mdi_load_balance_rr);
			}

			cmn_err(mdi_debug_consoleonly ? CE_NOTE : CE_CONT,
			    "?%s (%s%d) multipath status: %s: "
			    "path %d %s is %s: Load balancing: %s\n",
			    ddi_pathname(cdip, ct_path), ddi_driver_name(cdip),
			    ddi_get_instance(cdip), ct_status,
			    mdi_pi_get_path_instance(pip),
			    mdi_pi_spathname(pip), status, lb_buf);
		} else {
			cmn_err(mdi_debug_consoleonly ? CE_NOTE : CE_CONT,
			    "?%s (%s%d) multipath status: %s: "
			    "path %d %s is %s\n",
			    ddi_pathname(cdip, ct_path), ddi_driver_name(cdip),
			    ddi_get_instance(cdip), ct_status,
			    mdi_pi_get_path_instance(pip),
			    mdi_pi_spathname(pip), status);
		}

		kmem_free(ct_path, MAXPATHLEN);
		MDI_CLIENT_CLEAR_REPORT_DEV_NEEDED(ct);
	}
}

#ifdef	DEBUG
/*
 * i_mdi_log():
 *		Utility function for error message management
 *
 *		NOTE: Implementation takes care of trailing \n for cmn_err,
 *		MDI_DEBUG should not terminate fmt strings with \n.
 *
 *		NOTE: If the level is >= 2, and there is no leading !?^
 *		then a leading ! is implied (but can be overriden via
 *		mdi_debug_consoleonly). If you are using kmdb on the console,
 *		consider setting mdi_debug_consoleonly to 1 as an aid.
 */
/*PRINTFLIKE4*/
static void
i_mdi_log(int level, const char *func, dev_info_t *dip, const char *fmt, ...)
{
	char		name[MAXNAMELEN];
	char		buf[512];
	char		*bp;
	va_list		ap;
	int		log_only = 0;
	int		boot_only = 0;
	int		console_only = 0;

	if (dip) {
		(void) snprintf(name, sizeof(name), "%s%d: ",
		    ddi_driver_name(dip), ddi_get_instance(dip));
	} else {
		name[0] = 0;
	}

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	switch (buf[0]) {
	case '!':
		bp = &buf[1];
		log_only = 1;
		break;
	case '?':
		bp = &buf[1];
		boot_only = 1;
		break;
	case '^':
		bp = &buf[1];
		console_only = 1;
		break;
	default:
		if (level >= 2)
			log_only = 1;		/* ! implied */
		bp = buf;
		break;
	}
	if (mdi_debug_logonly) {
		log_only = 1;
		boot_only = 0;
		console_only = 0;
	}
	if (mdi_debug_consoleonly) {
		log_only = 0;
		boot_only = 0;
		console_only = 1;
		level = CE_NOTE;
		goto console;
	}

	switch (level) {
	case CE_NOTE:
		level = CE_CONT;
		/* FALLTHROUGH */
	case CE_CONT:
		if (boot_only) {
			cmn_err(level, "?mdi: %s%s: %s\n", name, func, bp);
		} else if (console_only) {
			cmn_err(level, "^mdi: %s%s: %s\n", name, func, bp);
		} else if (log_only) {
			cmn_err(level, "!mdi: %s%s: %s\n", name, func, bp);
		} else {
			cmn_err(level, "mdi: %s%s: %s\n", name, func, bp);
		}
		break;

	case CE_WARN:
	case CE_PANIC:
	console:
		if (boot_only) {
			cmn_err(level, "?mdi: %s%s: %s", name, func, bp);
		} else if (console_only) {
			cmn_err(level, "^mdi: %s%s: %s", name, func, bp);
		} else if (log_only) {
			cmn_err(level, "!mdi: %s%s: %s", name, func, bp);
		} else {
			cmn_err(level, "mdi: %s%s: %s", name, func, bp);
		}
		break;
	default:
		cmn_err(level, "mdi: %s%s", name, bp);
		break;
	}
}
#endif	/* DEBUG */

void
i_mdi_client_online(dev_info_t *ct_dip)
{
	mdi_client_t	*ct;

	/*
	 * Client online notification. Mark client state as online
	 * restore our binding with dev_info node
	 */
	ct = i_devi_get_client(ct_dip);
	ASSERT(ct != NULL);
	MDI_CLIENT_LOCK(ct);
	MDI_CLIENT_SET_ONLINE(ct);
	/* catch for any memory leaks */
	ASSERT((ct->ct_dip == NULL) || (ct->ct_dip == ct_dip));
	ct->ct_dip = ct_dip;

	if (ct->ct_power_cnt == 0)
		(void) i_mdi_power_all_phci(ct);

	MDI_DEBUG(4, (MDI_NOTE, ct_dip,
	    "i_mdi_pm_hold_client %p", (void *)ct));
	i_mdi_pm_hold_client(ct, 1);

	MDI_CLIENT_UNLOCK(ct);
}

void
i_mdi_phci_online(dev_info_t *ph_dip)
{
	mdi_phci_t	*ph;

	/* pHCI online notification. Mark state accordingly */
	ph = i_devi_get_phci(ph_dip);
	ASSERT(ph != NULL);
	MDI_PHCI_LOCK(ph);
	MDI_PHCI_SET_ONLINE(ph);
	MDI_PHCI_UNLOCK(ph);
}

/*
 * mdi_devi_online():
 * 		Online notification from NDI framework on pHCI/client
 *		device online.
 * Return Values:
 *		NDI_SUCCESS
 *		MDI_FAILURE
 */
/*ARGSUSED*/
int
mdi_devi_online(dev_info_t *dip, uint_t flags)
{
	if (MDI_PHCI(dip)) {
		i_mdi_phci_online(dip);
	}

	if (MDI_CLIENT(dip)) {
		i_mdi_client_online(dip);
	}
	return (NDI_SUCCESS);
}

/*
 * mdi_devi_offline():
 * 		Offline notification from NDI framework on pHCI/Client device
 *		offline.
 *
 * Return Values:
 *		NDI_SUCCESS
 *		NDI_FAILURE
 */
/*ARGSUSED*/
int
mdi_devi_offline(dev_info_t *dip, uint_t flags)
{
	int		rv = NDI_SUCCESS;

	if (MDI_CLIENT(dip)) {
		rv = i_mdi_client_offline(dip, flags);
		if (rv != NDI_SUCCESS)
			return (rv);
	}

	if (MDI_PHCI(dip)) {
		rv = i_mdi_phci_offline(dip, flags);

		if ((rv != NDI_SUCCESS) && MDI_CLIENT(dip)) {
			/* set client back online */
			i_mdi_client_online(dip);
		}
	}

	return (rv);
}

/*ARGSUSED*/
static int
i_mdi_phci_offline(dev_info_t *dip, uint_t flags)
{
	int		rv = NDI_SUCCESS;
	mdi_phci_t	*ph;
	mdi_client_t	*ct;
	mdi_pathinfo_t	*pip;
	mdi_pathinfo_t	*next;
	mdi_pathinfo_t	*failed_pip = NULL;
	dev_info_t	*cdip;

	/*
	 * pHCI component offline notification
	 * Make sure that this pHCI instance is free to be offlined.
	 * If it is OK to proceed, Offline and remove all the child
	 * mdi_pathinfo nodes.  This process automatically offlines
	 * corresponding client devices, for which this pHCI provides
	 * critical services.
	 */
	ph = i_devi_get_phci(dip);
	MDI_DEBUG(2, (MDI_NOTE, dip,
	    "called %p %p", (void *)dip, (void *)ph));
	if (ph == NULL) {
		return (rv);
	}

	MDI_PHCI_LOCK(ph);

	if (MDI_PHCI_IS_OFFLINE(ph)) {
		MDI_DEBUG(1, (MDI_WARN, dip,
		    "!pHCI already offlined: %p", (void *)dip));
		MDI_PHCI_UNLOCK(ph);
		return (NDI_SUCCESS);
	}

	/*
	 * Check to see if the pHCI can be offlined
	 */
	if (ph->ph_unstable) {
		MDI_DEBUG(1, (MDI_WARN, dip,
		    "!One or more target devices are in transient state. "
		    "This device can not be removed at this moment. "
		    "Please try again later."));
		MDI_PHCI_UNLOCK(ph);
		return (NDI_BUSY);
	}

	pip = ph->ph_path_head;
	while (pip != NULL) {
		MDI_PI_LOCK(pip);
		next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;

		/*
		 * The mdi_pathinfo state is OK. Check the client state.
		 * If failover in progress fail the pHCI from offlining
		 */
		ct = MDI_PI(pip)->pi_client;
		i_mdi_client_lock(ct, pip);
		if ((MDI_CLIENT_IS_FAILOVER_IN_PROGRESS(ct)) ||
		    (ct->ct_unstable)) {
			/*
			 * Failover is in progress, Fail the DR
			 */
			MDI_DEBUG(1, (MDI_WARN, dip,
			    "!pHCI device is busy. "
			    "This device can not be removed at this moment. "
			    "Please try again later."));
			MDI_PI_UNLOCK(pip);
			i_mdi_client_unlock(ct);
			MDI_PHCI_UNLOCK(ph);
			return (NDI_BUSY);
		}
		MDI_PI_UNLOCK(pip);

		/*
		 * Check to see of we are removing the last path of this
		 * client device...
		 */
		cdip = ct->ct_dip;
		if (cdip && (i_ddi_node_state(cdip) >= DS_INITIALIZED) &&
		    (i_mdi_client_compute_state(ct, ph) ==
		    MDI_CLIENT_STATE_FAILED)) {
			i_mdi_client_unlock(ct);
			MDI_PHCI_UNLOCK(ph);
			if (ndi_devi_offline(cdip,
			    NDI_DEVFS_CLEAN) != NDI_SUCCESS) {
				/*
				 * ndi_devi_offline() failed.
				 * This pHCI provides the critical path
				 * to one or more client devices.
				 * Return busy.
				 */
				MDI_PHCI_LOCK(ph);
				MDI_DEBUG(1, (MDI_WARN, dip,
				    "!pHCI device is busy. "
				    "This device can not be removed at this "
				    "moment. Please try again later."));
				failed_pip = pip;
				break;
			} else {
				MDI_PHCI_LOCK(ph);
				pip = next;
			}
		} else {
			i_mdi_client_unlock(ct);
			pip = next;
		}
	}

	if (failed_pip) {
		pip = ph->ph_path_head;
		while (pip != failed_pip) {
			MDI_PI_LOCK(pip);
			next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;
			ct = MDI_PI(pip)->pi_client;
			i_mdi_client_lock(ct, pip);
			cdip = ct->ct_dip;
			switch (MDI_CLIENT_STATE(ct)) {
			case MDI_CLIENT_STATE_OPTIMAL:
			case MDI_CLIENT_STATE_DEGRADED:
				if (cdip) {
					MDI_PI_UNLOCK(pip);
					i_mdi_client_unlock(ct);
					MDI_PHCI_UNLOCK(ph);
					(void) ndi_devi_online(cdip, 0);
					MDI_PHCI_LOCK(ph);
					pip = next;
					continue;
				}
				break;

			case MDI_CLIENT_STATE_FAILED:
				if (cdip) {
					MDI_PI_UNLOCK(pip);
					i_mdi_client_unlock(ct);
					MDI_PHCI_UNLOCK(ph);
					(void) ndi_devi_offline(cdip,
						NDI_DEVFS_CLEAN);
					MDI_PHCI_LOCK(ph);
					pip = next;
					continue;
				}
				break;
			}
			MDI_PI_UNLOCK(pip);
			i_mdi_client_unlock(ct);
			pip = next;
		}
		MDI_PHCI_UNLOCK(ph);
		return (NDI_BUSY);
	}

	/*
	 * Mark the pHCI as offline
	 */
	MDI_PHCI_SET_OFFLINE(ph);

	/*
	 * Mark the child mdi_pathinfo nodes as transient
	 */
	pip = ph->ph_path_head;
	while (pip != NULL) {
		MDI_PI_LOCK(pip);
		next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;
		MDI_PI_SET_OFFLINING(pip);
		MDI_PI_UNLOCK(pip);
		pip = next;
	}
	MDI_PHCI_UNLOCK(ph);
	/*
	 * Give a chance for any pending commands to execute
	 */
	delay_random(mdi_delay);
	MDI_PHCI_LOCK(ph);
	pip = ph->ph_path_head;
	while (pip != NULL) {
		next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;
		(void) i_mdi_pi_offline(pip, flags);
		MDI_PI_LOCK(pip);
		ct = MDI_PI(pip)->pi_client;
		if (!MDI_PI_IS_OFFLINE(pip)) {
			MDI_DEBUG(1, (MDI_WARN, dip,
			    "!pHCI device is busy. "
			    "This device can not be removed at this moment. "
			    "Please try again later."));
			MDI_PI_UNLOCK(pip);
			MDI_PHCI_SET_ONLINE(ph);
			MDI_PHCI_UNLOCK(ph);
			return (NDI_BUSY);
		}
		MDI_PI_UNLOCK(pip);
		pip = next;
	}
	MDI_PHCI_UNLOCK(ph);

	return (rv);
}

void
mdi_phci_mark_retiring(dev_info_t *dip, char **cons_array)
{
	mdi_phci_t	*ph;
	mdi_client_t	*ct;
	mdi_pathinfo_t	*pip;
	mdi_pathinfo_t	*next;
	dev_info_t	*cdip;

	if (!MDI_PHCI(dip))
		return;

	ph = i_devi_get_phci(dip);
	if (ph == NULL) {
		return;
	}

	MDI_PHCI_LOCK(ph);

	if (MDI_PHCI_IS_OFFLINE(ph)) {
		/* has no last path */
		MDI_PHCI_UNLOCK(ph);
		return;
	}

	pip = ph->ph_path_head;
	while (pip != NULL) {
		MDI_PI_LOCK(pip);
		next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;

		ct = MDI_PI(pip)->pi_client;
		i_mdi_client_lock(ct, pip);
		MDI_PI_UNLOCK(pip);

		cdip = ct->ct_dip;
		if (cdip && (i_ddi_node_state(cdip) >= DS_INITIALIZED) &&
		    (i_mdi_client_compute_state(ct, ph) ==
		    MDI_CLIENT_STATE_FAILED)) {
			/* Last path. Mark client dip as retiring */
			i_mdi_client_unlock(ct);
			MDI_PHCI_UNLOCK(ph);
			(void) e_ddi_mark_retiring(cdip, cons_array);
			MDI_PHCI_LOCK(ph);
			pip = next;
		} else {
			i_mdi_client_unlock(ct);
			pip = next;
		}
	}

	MDI_PHCI_UNLOCK(ph);

	return;
}

void
mdi_phci_retire_notify(dev_info_t *dip, int *constraint)
{
	mdi_phci_t	*ph;
	mdi_client_t	*ct;
	mdi_pathinfo_t	*pip;
	mdi_pathinfo_t	*next;
	dev_info_t	*cdip;

	if (!MDI_PHCI(dip))
		return;

	ph = i_devi_get_phci(dip);
	if (ph == NULL)
		return;

	MDI_PHCI_LOCK(ph);

	if (MDI_PHCI_IS_OFFLINE(ph)) {
		MDI_PHCI_UNLOCK(ph);
		/* not last path */
		return;
	}

	if (ph->ph_unstable) {
		MDI_PHCI_UNLOCK(ph);
		/* can't check for constraints */
		*constraint = 0;
		return;
	}

	pip = ph->ph_path_head;
	while (pip != NULL) {
		MDI_PI_LOCK(pip);
		next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;

		/*
		 * The mdi_pathinfo state is OK. Check the client state.
		 * If failover in progress fail the pHCI from offlining
		 */
		ct = MDI_PI(pip)->pi_client;
		i_mdi_client_lock(ct, pip);
		if ((MDI_CLIENT_IS_FAILOVER_IN_PROGRESS(ct)) ||
		    (ct->ct_unstable)) {
			/*
			 * Failover is in progress, can't check for constraints
			 */
			MDI_PI_UNLOCK(pip);
			i_mdi_client_unlock(ct);
			MDI_PHCI_UNLOCK(ph);
			*constraint = 0;
			return;
		}
		MDI_PI_UNLOCK(pip);

		/*
		 * Check to see of we are retiring the last path of this
		 * client device...
		 */
		cdip = ct->ct_dip;
		if (cdip && (i_ddi_node_state(cdip) >= DS_INITIALIZED) &&
		    (i_mdi_client_compute_state(ct, ph) ==
		    MDI_CLIENT_STATE_FAILED)) {
			i_mdi_client_unlock(ct);
			MDI_PHCI_UNLOCK(ph);
			(void) e_ddi_retire_notify(cdip, constraint);
			MDI_PHCI_LOCK(ph);
			pip = next;
		} else {
			i_mdi_client_unlock(ct);
			pip = next;
		}
	}

	MDI_PHCI_UNLOCK(ph);

	return;
}

/*
 * offline the path(s) hanging off the pHCI. If the
 * last path to any client, check that constraints
 * have been applied.
 *
 * If constraint is 0, we aren't going to retire the
 * pHCI. However we still need to go through the paths
 * calling e_ddi_retire_finalize() to clear their
 * contract barriers.
 */
void
mdi_phci_retire_finalize(dev_info_t *dip, int phci_only, void *constraint)
{
	mdi_phci_t	*ph;
	mdi_client_t	*ct;
	mdi_pathinfo_t	*pip;
	mdi_pathinfo_t	*next;
	dev_info_t	*cdip;
	int		unstable = 0;
	int		tmp_constraint;

	if (!MDI_PHCI(dip))
		return;

	ph = i_devi_get_phci(dip);
	if (ph == NULL) {
		/* no last path and no pips */
		return;
	}

	MDI_PHCI_LOCK(ph);

	if (MDI_PHCI_IS_OFFLINE(ph)) {
		MDI_PHCI_UNLOCK(ph);
		/* no last path and no pips */
		return;
	}

	/*
	 * Check to see if the pHCI can be offlined
	 */
	if (ph->ph_unstable) {
		unstable = 1;
	}

	pip = ph->ph_path_head;
	while (pip != NULL) {
		MDI_PI_LOCK(pip);
		next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;

		/*
		 * if failover in progress fail the pHCI from offlining
		 */
		ct = MDI_PI(pip)->pi_client;
		i_mdi_client_lock(ct, pip);
		if ((MDI_CLIENT_IS_FAILOVER_IN_PROGRESS(ct)) ||
		    (ct->ct_unstable)) {
			unstable = 1;
		}
		MDI_PI_UNLOCK(pip);

		/*
		 * Check to see of we are removing the last path of this
		 * client device...
		 */
		cdip = ct->ct_dip;
		if (!phci_only && cdip &&
		    (i_ddi_node_state(cdip) >= DS_INITIALIZED) &&
		    (i_mdi_client_compute_state(ct, ph) ==
		    MDI_CLIENT_STATE_FAILED)) {
			i_mdi_client_unlock(ct);
			MDI_PHCI_UNLOCK(ph);
			/*
			 * This is the last path to this client.
			 *
			 * Constraint will only be set to 1 if this client can
			 * be retired (as already determined by
			 * mdi_phci_retire_notify). However we don't actually
			 * need to retire the client (we just retire the last
			 * path - MPXIO will then fail all I/Os to the client).
			 * But we still need to call e_ddi_retire_finalize so
			 * the contract barriers can be cleared. Therefore we
			 * temporarily set constraint = 0 so that the client
			 * dip is not retired.
			 */
			tmp_constraint = 0;
			(void) e_ddi_retire_finalize(cdip, &tmp_constraint);
			MDI_PHCI_LOCK(ph);
			pip = next;
		} else {
			i_mdi_client_unlock(ct);
			pip = next;
		}
	}

	if (!phci_only && *((int *)constraint) == 0) {
		MDI_PHCI_UNLOCK(ph);
		return;
	}

	/*
	 * Cannot offline pip(s)
	 */
	if (unstable) {
		cmn_err(CE_WARN, "%s%d: mdi_phci_retire_finalize: "
		    "pHCI in transient state, cannot retire",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		MDI_PHCI_UNLOCK(ph);
		return;
	}

	/*
	 * Mark the pHCI as offline
	 */
	MDI_PHCI_SET_OFFLINE(ph);

	/*
	 * Mark the child mdi_pathinfo nodes as transient
	 */
	pip = ph->ph_path_head;
	while (pip != NULL) {
		MDI_PI_LOCK(pip);
		next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;
		MDI_PI_SET_OFFLINING(pip);
		MDI_PI_UNLOCK(pip);
		pip = next;
	}
	MDI_PHCI_UNLOCK(ph);
	/*
	 * Give a chance for any pending commands to execute
	 */
	delay_random(mdi_delay);
	MDI_PHCI_LOCK(ph);
	pip = ph->ph_path_head;
	while (pip != NULL) {
		next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;
		(void) i_mdi_pi_offline(pip, 0);
		MDI_PI_LOCK(pip);
		ct = MDI_PI(pip)->pi_client;
		if (!MDI_PI_IS_OFFLINE(pip)) {
			cmn_err(CE_WARN, "mdi_phci_retire_finalize: "
			    "path %d %s busy, cannot offline",
			    mdi_pi_get_path_instance(pip),
			    mdi_pi_spathname(pip));
			MDI_PI_UNLOCK(pip);
			MDI_PHCI_SET_ONLINE(ph);
			MDI_PHCI_UNLOCK(ph);
			return;
		}
		MDI_PI_UNLOCK(pip);
		pip = next;
	}
	MDI_PHCI_UNLOCK(ph);

	return;
}

void
mdi_phci_unretire(dev_info_t *dip)
{
	mdi_phci_t	*ph;
	mdi_pathinfo_t	*pip;
	mdi_pathinfo_t	*next;

	ASSERT(MDI_PHCI(dip));

	/*
	 * Online the phci
	 */
	i_mdi_phci_online(dip);

	ph = i_devi_get_phci(dip);
	MDI_PHCI_LOCK(ph);
	pip = ph->ph_path_head;
	while (pip != NULL) {
		MDI_PI_LOCK(pip);
		next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;
		MDI_PI_UNLOCK(pip);
		(void) i_mdi_pi_online(pip, 0);
		pip = next;
	}
	MDI_PHCI_UNLOCK(ph);
}

/*ARGSUSED*/
static int
i_mdi_client_offline(dev_info_t *dip, uint_t flags)
{
	int		rv = NDI_SUCCESS;
	mdi_client_t	*ct;

	/*
	 * Client component to go offline.  Make sure that we are
	 * not in failing over state and update client state
	 * accordingly
	 */
	ct = i_devi_get_client(dip);
	MDI_DEBUG(2, (MDI_NOTE, dip,
	    "called %p %p", (void *)dip, (void *)ct));
	if (ct != NULL) {
		MDI_CLIENT_LOCK(ct);
		if (ct->ct_unstable) {
			/*
			 * One or more paths are in transient state,
			 * Dont allow offline of a client device
			 */
			MDI_DEBUG(1, (MDI_WARN, dip,
			    "!One or more paths to "
			    "this device are in transient state. "
			    "This device can not be removed at this moment. "
			    "Please try again later."));
			MDI_CLIENT_UNLOCK(ct);
			return (NDI_BUSY);
		}
		if (MDI_CLIENT_IS_FAILOVER_IN_PROGRESS(ct)) {
			/*
			 * Failover is in progress, Dont allow DR of
			 * a client device
			 */
			MDI_DEBUG(1, (MDI_WARN, dip,
			    "!Client device is Busy. "
			    "This device can not be removed at this moment. "
			    "Please try again later."));
			MDI_CLIENT_UNLOCK(ct);
			return (NDI_BUSY);
		}
		MDI_CLIENT_SET_OFFLINE(ct);

		/*
		 * Unbind our relationship with the dev_info node
		 */
		if (flags & NDI_DEVI_REMOVE) {
			ct->ct_dip = NULL;
		}
		MDI_CLIENT_UNLOCK(ct);
	}
	return (rv);
}

/*
 * mdi_pre_attach():
 *		Pre attach() notification handler
 */
/*ARGSUSED*/
int
mdi_pre_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	/* don't support old DDI_PM_RESUME */
	if ((DEVI(dip)->devi_mdi_component != MDI_COMPONENT_NONE) &&
	    (cmd == DDI_PM_RESUME))
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

/*
 * mdi_post_attach():
 *		Post attach() notification handler
 */
/*ARGSUSED*/
void
mdi_post_attach(dev_info_t *dip, ddi_attach_cmd_t cmd, int error)
{
	mdi_phci_t	*ph;
	mdi_client_t	*ct;
	mdi_vhci_t	*vh;

	if (MDI_PHCI(dip)) {
		ph = i_devi_get_phci(dip);
		ASSERT(ph != NULL);

		MDI_PHCI_LOCK(ph);
		switch (cmd) {
		case DDI_ATTACH:
			MDI_DEBUG(2, (MDI_NOTE, dip,
			    "phci post_attach called %p", (void *)ph));
			if (error == DDI_SUCCESS) {
				MDI_PHCI_SET_ATTACH(ph);
			} else {
				MDI_DEBUG(1, (MDI_NOTE, dip,
				    "!pHCI post_attach failed: error %d",
				    error));
				MDI_PHCI_SET_DETACH(ph);
			}
			break;

		case DDI_RESUME:
			MDI_DEBUG(2, (MDI_NOTE, dip,
			    "pHCI post_resume: called %p", (void *)ph));
			if (error == DDI_SUCCESS) {
				MDI_PHCI_SET_RESUME(ph);
			} else {
				MDI_DEBUG(1, (MDI_NOTE, dip,
				    "!pHCI post_resume failed: error %d",
				    error));
				MDI_PHCI_SET_SUSPEND(ph);
			}
			break;
		}
		MDI_PHCI_UNLOCK(ph);
	}

	if (MDI_CLIENT(dip)) {
		ct = i_devi_get_client(dip);
		ASSERT(ct != NULL);

		MDI_CLIENT_LOCK(ct);
		switch (cmd) {
		case DDI_ATTACH:
			MDI_DEBUG(2, (MDI_NOTE, dip,
			    "client post_attach called %p", (void *)ct));
			if (error != DDI_SUCCESS) {
				MDI_DEBUG(1, (MDI_NOTE, dip,
				    "!client post_attach failed: error %d",
				    error));
				MDI_CLIENT_SET_DETACH(ct);
				MDI_DEBUG(4, (MDI_WARN, dip,
				    "i_mdi_pm_reset_client"));
				i_mdi_pm_reset_client(ct);
				break;
			}

			/*
			 * Client device has successfully attached, inform
			 * the vhci.
			 */
			vh = ct->ct_vhci;
			if (vh->vh_ops->vo_client_attached)
				(*vh->vh_ops->vo_client_attached)(dip);

			MDI_CLIENT_SET_ATTACH(ct);
			break;

		case DDI_RESUME:
			MDI_DEBUG(2, (MDI_NOTE, dip,
			    "client post_attach: called %p", (void *)ct));
			if (error == DDI_SUCCESS) {
				MDI_CLIENT_SET_RESUME(ct);
			} else {
				MDI_DEBUG(1, (MDI_NOTE, dip,
				    "!client post_resume failed: error %d",
				    error));
				MDI_CLIENT_SET_SUSPEND(ct);
			}
			break;
		}
		MDI_CLIENT_UNLOCK(ct);
	}
}

/*
 * mdi_pre_detach():
 *		Pre detach notification handler
 */
/*ARGSUSED*/
int
mdi_pre_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int rv = DDI_SUCCESS;

	if (MDI_CLIENT(dip)) {
		(void) i_mdi_client_pre_detach(dip, cmd);
	}

	if (MDI_PHCI(dip)) {
		rv = i_mdi_phci_pre_detach(dip, cmd);
	}

	return (rv);
}

/*ARGSUSED*/
static int
i_mdi_phci_pre_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		rv = DDI_SUCCESS;
	mdi_phci_t	*ph;
	mdi_client_t	*ct;
	mdi_pathinfo_t	*pip;
	mdi_pathinfo_t	*failed_pip = NULL;
	mdi_pathinfo_t	*next;

	ph = i_devi_get_phci(dip);
	if (ph == NULL) {
		return (rv);
	}

	MDI_PHCI_LOCK(ph);
	switch (cmd) {
	case DDI_DETACH:
		MDI_DEBUG(2, (MDI_NOTE, dip,
		    "pHCI pre_detach: called %p", (void *)ph));
		if (!MDI_PHCI_IS_OFFLINE(ph)) {
			/*
			 * mdi_pathinfo nodes are still attached to
			 * this pHCI. Fail the detach for this pHCI.
			 */
			MDI_DEBUG(2, (MDI_WARN, dip,
			    "pHCI pre_detach: paths are still attached %p",
			    (void *)ph));
			rv = DDI_FAILURE;
			break;
		}
		MDI_PHCI_SET_DETACH(ph);
		break;

	case DDI_SUSPEND:
		/*
		 * pHCI is getting suspended.  Since mpxio client
		 * devices may not be suspended at this point, to avoid
		 * a potential stack overflow, it is important to suspend
		 * client devices before pHCI can be suspended.
		 */

		MDI_DEBUG(2, (MDI_NOTE, dip,
		    "pHCI pre_suspend: called %p", (void *)ph));
		/*
		 * Suspend all the client devices accessible through this pHCI
		 */
		pip = ph->ph_path_head;
		while (pip != NULL && rv == DDI_SUCCESS) {
			dev_info_t *cdip;
			MDI_PI_LOCK(pip);
			next =
			    (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;
			ct = MDI_PI(pip)->pi_client;
			i_mdi_client_lock(ct, pip);
			cdip = ct->ct_dip;
			MDI_PI_UNLOCK(pip);
			if ((MDI_CLIENT_IS_DETACHED(ct) == 0) &&
			    MDI_CLIENT_IS_SUSPENDED(ct) == 0) {
				i_mdi_client_unlock(ct);
				if ((rv = devi_detach(cdip, DDI_SUSPEND)) !=
				    DDI_SUCCESS) {
					/*
					 * Suspend of one of the client
					 * device has failed.
					 */
					MDI_DEBUG(1, (MDI_WARN, dip,
					    "!suspend of device (%s%d) failed.",
					    ddi_driver_name(cdip),
					    ddi_get_instance(cdip)));
					failed_pip = pip;
					break;
				}
			} else {
				i_mdi_client_unlock(ct);
			}
			pip = next;
		}

		if (rv == DDI_SUCCESS) {
			/*
			 * Suspend of client devices is complete. Proceed
			 * with pHCI suspend.
			 */
			MDI_PHCI_SET_SUSPEND(ph);
		} else {
			/*
			 * Revert back all the suspended client device states
			 * to converse.
			 */
			pip = ph->ph_path_head;
			while (pip != failed_pip) {
				dev_info_t *cdip;
				MDI_PI_LOCK(pip);
				next =
				    (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;
				ct = MDI_PI(pip)->pi_client;
				i_mdi_client_lock(ct, pip);
				cdip = ct->ct_dip;
				MDI_PI_UNLOCK(pip);
				if (MDI_CLIENT_IS_SUSPENDED(ct)) {
					i_mdi_client_unlock(ct);
					(void) devi_attach(cdip, DDI_RESUME);
				} else {
					i_mdi_client_unlock(ct);
				}
				pip = next;
			}
		}
		break;

	default:
		rv = DDI_FAILURE;
		break;
	}
	MDI_PHCI_UNLOCK(ph);
	return (rv);
}

/*ARGSUSED*/
static int
i_mdi_client_pre_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		rv = DDI_SUCCESS;
	mdi_client_t	*ct;

	ct = i_devi_get_client(dip);
	if (ct == NULL) {
		return (rv);
	}

	MDI_CLIENT_LOCK(ct);
	switch (cmd) {
	case DDI_DETACH:
		MDI_DEBUG(2, (MDI_NOTE, dip,
		    "client pre_detach: called %p",
		     (void *)ct));
		MDI_CLIENT_SET_DETACH(ct);
		break;

	case DDI_SUSPEND:
		MDI_DEBUG(2, (MDI_NOTE, dip,
		    "client pre_suspend: called %p",
		    (void *)ct));
		MDI_CLIENT_SET_SUSPEND(ct);
		break;

	default:
		rv = DDI_FAILURE;
		break;
	}
	MDI_CLIENT_UNLOCK(ct);
	return (rv);
}

/*
 * mdi_post_detach():
 *		Post detach notification handler
 */
/*ARGSUSED*/
void
mdi_post_detach(dev_info_t *dip, ddi_detach_cmd_t cmd, int error)
{
	/*
	 * Detach/Suspend of mpxio component failed. Update our state
	 * too
	 */
	if (MDI_PHCI(dip))
		i_mdi_phci_post_detach(dip, cmd, error);

	if (MDI_CLIENT(dip))
		i_mdi_client_post_detach(dip, cmd, error);
}

/*ARGSUSED*/
static void
i_mdi_phci_post_detach(dev_info_t *dip, ddi_detach_cmd_t cmd, int error)
{
	mdi_phci_t	*ph;

	/*
	 * Detach/Suspend of phci component failed. Update our state
	 * too
	 */
	ph = i_devi_get_phci(dip);
	if (ph == NULL) {
		return;
	}

	MDI_PHCI_LOCK(ph);
	/*
	 * Detach of pHCI failed. Restore back converse
	 * state
	 */
	switch (cmd) {
	case DDI_DETACH:
		MDI_DEBUG(2, (MDI_NOTE, dip,
		    "pHCI post_detach: called %p",
		    (void *)ph));
		if (error != DDI_SUCCESS)
			MDI_PHCI_SET_ATTACH(ph);
		break;

	case DDI_SUSPEND:
		MDI_DEBUG(2, (MDI_NOTE, dip,
		    "pHCI post_suspend: called %p",
		    (void *)ph));
		if (error != DDI_SUCCESS)
			MDI_PHCI_SET_RESUME(ph);
		break;
	}
	MDI_PHCI_UNLOCK(ph);
}

/*ARGSUSED*/
static void
i_mdi_client_post_detach(dev_info_t *dip, ddi_detach_cmd_t cmd, int error)
{
	mdi_client_t	*ct;

	ct = i_devi_get_client(dip);
	if (ct == NULL) {
		return;
	}
	MDI_CLIENT_LOCK(ct);
	/*
	 * Detach of Client failed. Restore back converse
	 * state
	 */
	switch (cmd) {
	case DDI_DETACH:
		MDI_DEBUG(2, (MDI_NOTE, dip,
		    "client post_detach: called %p", (void *)ct));
		if (DEVI_IS_ATTACHING(dip)) {
			MDI_DEBUG(4, (MDI_NOTE, dip,
			    "i_mdi_pm_rele_client\n"));
			i_mdi_pm_rele_client(ct, ct->ct_path_count);
		} else {
			MDI_DEBUG(4, (MDI_NOTE, dip,
			    "i_mdi_pm_reset_client\n"));
			i_mdi_pm_reset_client(ct);
		}
		if (error != DDI_SUCCESS)
			MDI_CLIENT_SET_ATTACH(ct);
		break;

	case DDI_SUSPEND:
		MDI_DEBUG(2, (MDI_NOTE, dip,
		    "called %p", (void *)ct));
		if (error != DDI_SUCCESS)
			MDI_CLIENT_SET_RESUME(ct);
		break;
	}
	MDI_CLIENT_UNLOCK(ct);
}

int
mdi_pi_kstat_exists(mdi_pathinfo_t *pip)
{
	return (MDI_PI(pip)->pi_kstats ? 1 : 0);
}

/*
 * create and install per-path (client - pHCI) statistics
 * I/O stats supported: nread, nwritten, reads, and writes
 * Error stats - hard errors, soft errors, & transport errors
 */
int
mdi_pi_kstat_create(mdi_pathinfo_t *pip, char *ksname)
{
	kstat_t			*kiosp, *kerrsp;
	struct pi_errs		*nsp;
	struct mdi_pi_kstats	*mdi_statp;

	if (MDI_PI(pip)->pi_kstats != NULL)
		return (MDI_SUCCESS);

	if ((kiosp = kstat_create("mdi", 0, ksname, "iopath",
	    KSTAT_TYPE_IO, 1, KSTAT_FLAG_PERSISTENT)) == NULL) {
		return (MDI_FAILURE);
	}

	(void) strcat(ksname, ",err");
	kerrsp = kstat_create("mdi", 0, ksname, "iopath_errors",
	    KSTAT_TYPE_NAMED,
	    sizeof (struct pi_errs) / sizeof (kstat_named_t), 0);
	if (kerrsp == NULL) {
		kstat_delete(kiosp);
		return (MDI_FAILURE);
	}

	nsp = (struct pi_errs *)kerrsp->ks_data;
	kstat_named_init(&nsp->pi_softerrs, "Soft Errors", KSTAT_DATA_UINT32);
	kstat_named_init(&nsp->pi_harderrs, "Hard Errors", KSTAT_DATA_UINT32);
	kstat_named_init(&nsp->pi_transerrs, "Transport Errors",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&nsp->pi_icnt_busy, "Interconnect Busy",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&nsp->pi_icnt_errors, "Interconnect Errors",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&nsp->pi_phci_rsrc, "pHCI No Resources",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&nsp->pi_phci_localerr, "pHCI Local Errors",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&nsp->pi_phci_invstate, "pHCI Invalid State",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&nsp->pi_failedfrom, "Failed From",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&nsp->pi_failedto, "Failed To", KSTAT_DATA_UINT32);

	mdi_statp = kmem_alloc(sizeof (*mdi_statp), KM_SLEEP);
	mdi_statp->pi_kstat_ref = 1;
	mdi_statp->pi_kstat_iostats = kiosp;
	mdi_statp->pi_kstat_errstats = kerrsp;
	kstat_install(kiosp);
	kstat_install(kerrsp);
	MDI_PI(pip)->pi_kstats = mdi_statp;
	return (MDI_SUCCESS);
}

/*
 * destroy per-path properties
 */
static void
i_mdi_pi_kstat_destroy(mdi_pathinfo_t *pip)
{

	struct mdi_pi_kstats *mdi_statp;

	if (MDI_PI(pip)->pi_kstats == NULL)
		return;
	if ((mdi_statp = MDI_PI(pip)->pi_kstats) == NULL)
		return;

	MDI_PI(pip)->pi_kstats = NULL;

	/*
	 * the kstat may be shared between multiple pathinfo nodes
	 * decrement this pathinfo's usage, removing the kstats
	 * themselves when the last pathinfo reference is removed.
	 */
	ASSERT(mdi_statp->pi_kstat_ref > 0);
	if (--mdi_statp->pi_kstat_ref != 0)
		return;

	kstat_delete(mdi_statp->pi_kstat_iostats);
	kstat_delete(mdi_statp->pi_kstat_errstats);
	kmem_free(mdi_statp, sizeof (*mdi_statp));
}

/*
 * update I/O paths KSTATS
 */
void
mdi_pi_kstat_iosupdate(mdi_pathinfo_t *pip, struct buf *bp)
{
	kstat_t *iostatp;
	size_t xfer_cnt;

	ASSERT(pip != NULL);

	/*
	 * I/O can be driven across a path prior to having path
	 * statistics available, i.e. probe(9e).
	 */
	if (bp != NULL && MDI_PI(pip)->pi_kstats != NULL) {
		iostatp = MDI_PI(pip)->pi_kstats->pi_kstat_iostats;
		xfer_cnt = bp->b_bcount - bp->b_resid;
		if (bp->b_flags & B_READ) {
			KSTAT_IO_PTR(iostatp)->reads++;
			KSTAT_IO_PTR(iostatp)->nread += xfer_cnt;
		} else {
			KSTAT_IO_PTR(iostatp)->writes++;
			KSTAT_IO_PTR(iostatp)->nwritten += xfer_cnt;
		}
	}
}

/*
 * Enable the path(specific client/target/initiator)
 * Enabling a path means that MPxIO may select the enabled path for routing
 * future I/O requests, subject to other path state constraints.
 */
int
mdi_pi_enable_path(mdi_pathinfo_t *pip, int flags)
{
	mdi_phci_t	*ph;

	ph = MDI_PI(pip)->pi_phci;
	if (ph == NULL) {
		MDI_DEBUG(1, (MDI_NOTE, mdi_pi_get_phci(pip),
		    "!failed: path %s %p: NULL ph",
		    mdi_pi_spathname(pip), (void *)pip));
		return (MDI_FAILURE);
	}

	(void) i_mdi_enable_disable_path(pip, ph->ph_vhci, flags,
		MDI_ENABLE_OP);
	MDI_DEBUG(5, (MDI_NOTE, ph->ph_dip,
	    "!returning success pip = %p. ph = %p",
	    (void *)pip, (void *)ph));
	return (MDI_SUCCESS);

}

/*
 * Disable the path (specific client/target/initiator)
 * Disabling a path means that MPxIO will not select the disabled path for
 * routing any new I/O requests.
 */
int
mdi_pi_disable_path(mdi_pathinfo_t *pip, int flags)
{
	mdi_phci_t	*ph;

	ph = MDI_PI(pip)->pi_phci;
	if (ph == NULL) {
		MDI_DEBUG(1, (MDI_NOTE, mdi_pi_get_phci(pip),
		    "!failed: path %s %p: NULL ph",
		    mdi_pi_spathname(pip), (void *)pip));
		return (MDI_FAILURE);
	}

	(void) i_mdi_enable_disable_path(pip,
	    ph->ph_vhci, flags, MDI_DISABLE_OP);
	MDI_DEBUG(5, (MDI_NOTE, ph->ph_dip,
	    "!returning success pip = %p. ph = %p",
	    (void *)pip, (void *)ph));
	return (MDI_SUCCESS);
}

/*
 * disable the path to a particular pHCI (pHCI specified in the phci_path
 * argument) for a particular client (specified in the client_path argument).
 * Disabling a path means that MPxIO will not select the disabled path for
 * routing any new I/O requests.
 * NOTE: this will be removed once the NWS files are changed to use the new
 * mdi_{enable,disable}_path interfaces
 */
int
mdi_pi_disable(dev_info_t *cdip, dev_info_t *pdip, int flags)
{
	return (i_mdi_pi_enable_disable(cdip, pdip, flags, MDI_DISABLE_OP));
}

/*
 * Enable the path to a particular pHCI (pHCI specified in the phci_path
 * argument) for a particular client (specified in the client_path argument).
 * Enabling a path means that MPxIO may select the enabled path for routing
 * future I/O requests, subject to other path state constraints.
 * NOTE: this will be removed once the NWS files are changed to use the new
 * mdi_{enable,disable}_path interfaces
 */

int
mdi_pi_enable(dev_info_t *cdip, dev_info_t *pdip, int flags)
{
	return (i_mdi_pi_enable_disable(cdip, pdip, flags, MDI_ENABLE_OP));
}

/*
 * Common routine for doing enable/disable.
 */
static mdi_pathinfo_t *
i_mdi_enable_disable_path(mdi_pathinfo_t *pip, mdi_vhci_t *vh, int flags,
		int op)
{
	int		sync_flag = 0;
	int		rv;
	mdi_pathinfo_t 	*next;
	int		(*f)() = NULL;

	/*
	 * Check to make sure the path is not already in the
	 * requested state. If it is just return the next path
	 * as we have nothing to do here.
	 */
	if ((MDI_PI_IS_DISABLE(pip) && op == MDI_DISABLE_OP) ||
	    (!MDI_PI_IS_DISABLE(pip) && op == MDI_ENABLE_OP)) {
		MDI_PI_LOCK(pip);
		next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;
		MDI_PI_UNLOCK(pip);
		return (next);
	}

	f = vh->vh_ops->vo_pi_state_change;

	sync_flag = (flags << 8) & 0xf00;

	/*
	 * Do a callback into the mdi consumer to let it
	 * know that path is about to get enabled/disabled.
	 */
	if (f != NULL) {
		rv = (*f)(vh->vh_dip, pip, 0,
			MDI_PI_EXT_STATE(pip),
			MDI_EXT_STATE_CHANGE | sync_flag |
			op | MDI_BEFORE_STATE_CHANGE);
		if (rv != MDI_SUCCESS) {
			MDI_DEBUG(2, (MDI_WARN, vh->vh_dip,
			    "vo_pi_state_change: failed rv = %x", rv));
		}
	}
	MDI_PI_LOCK(pip);
	next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;

	switch (flags) {
		case USER_DISABLE:
			if (op == MDI_DISABLE_OP) {
				MDI_PI_SET_USER_DISABLE(pip);
			} else {
				MDI_PI_SET_USER_ENABLE(pip);
			}
			break;
		case DRIVER_DISABLE:
			if (op == MDI_DISABLE_OP) {
				MDI_PI_SET_DRV_DISABLE(pip);
			} else {
				MDI_PI_SET_DRV_ENABLE(pip);
			}
			break;
		case DRIVER_DISABLE_TRANSIENT:
			if (op == MDI_DISABLE_OP && rv == MDI_SUCCESS) {
				MDI_PI_SET_DRV_DISABLE_TRANS(pip);
			} else {
				MDI_PI_SET_DRV_ENABLE_TRANS(pip);
			}
			break;
	}
	MDI_PI_UNLOCK(pip);
	/*
	 * Do a callback into the mdi consumer to let it
	 * know that path is now enabled/disabled.
	 */
	if (f != NULL) {
		rv = (*f)(vh->vh_dip, pip, 0,
			MDI_PI_EXT_STATE(pip),
			MDI_EXT_STATE_CHANGE | sync_flag |
			op | MDI_AFTER_STATE_CHANGE);
		if (rv != MDI_SUCCESS) {
			MDI_DEBUG(2, (MDI_WARN, vh->vh_dip,
			    "vo_pi_state_change failed: rv = %x", rv));
		}
	}
	return (next);
}

/*
 * Common routine for doing enable/disable.
 * NOTE: this will be removed once the NWS files are changed to use the new
 * mdi_{enable,disable}_path has been putback
 */
int
i_mdi_pi_enable_disable(dev_info_t *cdip, dev_info_t *pdip, int flags, int op)
{

	mdi_phci_t	*ph;
	mdi_vhci_t	*vh = NULL;
	mdi_client_t	*ct;
	mdi_pathinfo_t	*next, *pip;
	int		found_it;

	ph = i_devi_get_phci(pdip);
	MDI_DEBUG(5, (MDI_NOTE, cdip ? cdip : pdip,
	    "!op = %d pdip = %p cdip = %p", op, (void *)pdip,
	    (void *)cdip));
	if (ph == NULL) {
		MDI_DEBUG(1, (MDI_NOTE, cdip ? cdip : pdip,
		    "!failed: operation %d: NULL ph", op));
		return (MDI_FAILURE);
	}

	if ((op != MDI_ENABLE_OP) && (op != MDI_DISABLE_OP)) {
		MDI_DEBUG(1, (MDI_NOTE, cdip ? cdip : pdip,
		    "!failed: invalid operation %d", op));
		return (MDI_FAILURE);
	}

	vh = ph->ph_vhci;

	if (cdip == NULL) {
		/*
		 * Need to mark the Phci as enabled/disabled.
		 */
		MDI_DEBUG(4, (MDI_NOTE, cdip ? cdip : pdip,
		    "op %d for the phci", op));
		MDI_PHCI_LOCK(ph);
		switch (flags) {
			case USER_DISABLE:
				if (op == MDI_DISABLE_OP) {
					MDI_PHCI_SET_USER_DISABLE(ph);
				} else {
					MDI_PHCI_SET_USER_ENABLE(ph);
				}
				break;
			case DRIVER_DISABLE:
				if (op == MDI_DISABLE_OP) {
					MDI_PHCI_SET_DRV_DISABLE(ph);
				} else {
					MDI_PHCI_SET_DRV_ENABLE(ph);
				}
				break;
			case DRIVER_DISABLE_TRANSIENT:
				if (op == MDI_DISABLE_OP) {
					MDI_PHCI_SET_DRV_DISABLE_TRANSIENT(ph);
				} else {
					MDI_PHCI_SET_DRV_ENABLE_TRANSIENT(ph);
				}
				break;
			default:
				MDI_PHCI_UNLOCK(ph);
				MDI_DEBUG(1, (MDI_NOTE, cdip ? cdip : pdip,
				    "!invalid flag argument= %d", flags));
		}

		/*
		 * Phci has been disabled. Now try to enable/disable
		 * path info's to each client.
		 */
		pip = ph->ph_path_head;
		while (pip != NULL) {
			pip = i_mdi_enable_disable_path(pip, vh, flags, op);
		}
		MDI_PHCI_UNLOCK(ph);
	} else {

		/*
		 * Disable a specific client.
		 */
		ct = i_devi_get_client(cdip);
		if (ct == NULL) {
			MDI_DEBUG(1, (MDI_NOTE, cdip ? cdip : pdip,
			    "!failed: operation = %d: NULL ct", op));
			return (MDI_FAILURE);
		}

		MDI_CLIENT_LOCK(ct);
		pip = ct->ct_path_head;
		found_it = 0;
		while (pip != NULL) {
			MDI_PI_LOCK(pip);
			next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_client_link;
			if (MDI_PI(pip)->pi_phci == ph) {
				MDI_PI_UNLOCK(pip);
				found_it = 1;
				break;
			}
			MDI_PI_UNLOCK(pip);
			pip = next;
		}


		MDI_CLIENT_UNLOCK(ct);
		if (found_it == 0) {
			MDI_DEBUG(1, (MDI_NOTE, cdip ? cdip : pdip,
			    "!failed. Could not find corresponding pip\n"));
			return (MDI_FAILURE);
		}

		(void) i_mdi_enable_disable_path(pip, vh, flags, op);
	}

	MDI_DEBUG(5, (MDI_NOTE, cdip ? cdip : pdip,
	    "!op %d returning success pdip = %p cdip = %p",
	    op, (void *)pdip, (void *)cdip));
	return (MDI_SUCCESS);
}

/*
 * Ensure phci powered up
 */
static void
i_mdi_pm_hold_pip(mdi_pathinfo_t *pip)
{
	dev_info_t	*ph_dip;

	ASSERT(pip != NULL);
	ASSERT(MDI_PI_LOCKED(pip));

	if (MDI_PI(pip)->pi_pm_held) {
		return;
	}

	ph_dip = mdi_pi_get_phci(pip);
	MDI_DEBUG(4, (MDI_NOTE, ph_dip,
	    "%s %p", mdi_pi_spathname(pip), (void *)pip));
	if (ph_dip == NULL) {
		return;
	}

	MDI_PI_UNLOCK(pip);
	MDI_DEBUG(4, (MDI_NOTE, ph_dip, "kidsupcnt was %d",
	    DEVI(ph_dip)->devi_pm_kidsupcnt));
	pm_hold_power(ph_dip);
	MDI_DEBUG(4, (MDI_NOTE, ph_dip, "kidsupcnt is %d",
	    DEVI(ph_dip)->devi_pm_kidsupcnt));
	MDI_PI_LOCK(pip);

	/* If PM_GET_PM_INFO is NULL the pm_hold_power above was a noop */
	if (DEVI(ph_dip)->devi_pm_info)
		MDI_PI(pip)->pi_pm_held = 1;
}

/*
 * Allow phci powered down
 */
static void
i_mdi_pm_rele_pip(mdi_pathinfo_t *pip)
{
	dev_info_t	*ph_dip = NULL;

	ASSERT(pip != NULL);
	ASSERT(MDI_PI_LOCKED(pip));

	if (MDI_PI(pip)->pi_pm_held == 0) {
		return;
	}

	ph_dip = mdi_pi_get_phci(pip);
	ASSERT(ph_dip != NULL);

	MDI_DEBUG(4, (MDI_NOTE, ph_dip,
	    "%s %p", mdi_pi_spathname(pip), (void *)pip));

	MDI_PI_UNLOCK(pip);
	MDI_DEBUG(4, (MDI_NOTE, ph_dip,
	    "kidsupcnt was %d", DEVI(ph_dip)->devi_pm_kidsupcnt));
	pm_rele_power(ph_dip);
	MDI_DEBUG(4, (MDI_NOTE, ph_dip,
	    "kidsupcnt is %d", DEVI(ph_dip)->devi_pm_kidsupcnt));
	MDI_PI_LOCK(pip);

	MDI_PI(pip)->pi_pm_held = 0;
}

static void
i_mdi_pm_hold_client(mdi_client_t *ct, int incr)
{
	ASSERT(MDI_CLIENT_LOCKED(ct));

	ct->ct_power_cnt += incr;
	MDI_DEBUG(4, (MDI_NOTE, ct->ct_dip,
	    "%p ct_power_cnt = %d incr = %d",
	    (void *)ct, ct->ct_power_cnt, incr));
	ASSERT(ct->ct_power_cnt >= 0);
}

static void
i_mdi_rele_all_phci(mdi_client_t *ct)
{
	mdi_pathinfo_t  *pip;

	ASSERT(MDI_CLIENT_LOCKED(ct));
	pip = (mdi_pathinfo_t *)ct->ct_path_head;
	while (pip != NULL) {
		mdi_hold_path(pip);
		MDI_PI_LOCK(pip);
		i_mdi_pm_rele_pip(pip);
		MDI_PI_UNLOCK(pip);
		mdi_rele_path(pip);
		pip = (mdi_pathinfo_t *)MDI_PI(pip)->pi_client_link;
	}
}

static void
i_mdi_pm_rele_client(mdi_client_t *ct, int decr)
{
	ASSERT(MDI_CLIENT_LOCKED(ct));

	if (i_ddi_devi_attached(ct->ct_dip)) {
		ct->ct_power_cnt -= decr;
		MDI_DEBUG(4, (MDI_NOTE, ct->ct_dip,
		    "%p ct_power_cnt = %d decr = %d",
		    (void *)ct, ct->ct_power_cnt, decr));
	}

	ASSERT(ct->ct_power_cnt >= 0);
	if (ct->ct_power_cnt == 0) {
		i_mdi_rele_all_phci(ct);
		return;
	}
}

static void
i_mdi_pm_reset_client(mdi_client_t *ct)
{
	MDI_DEBUG(4, (MDI_NOTE, ct->ct_dip,
	    "%p ct_power_cnt = %d", (void *)ct, ct->ct_power_cnt));
	ASSERT(MDI_CLIENT_LOCKED(ct));
	ct->ct_power_cnt = 0;
	i_mdi_rele_all_phci(ct);
	ct->ct_powercnt_config = 0;
	ct->ct_powercnt_unconfig = 0;
	ct->ct_powercnt_reset = 1;
}

static int
i_mdi_power_one_phci(mdi_pathinfo_t *pip)
{
	int		ret;
	dev_info_t	*ph_dip;

	MDI_PI_LOCK(pip);
	i_mdi_pm_hold_pip(pip);

	ph_dip = mdi_pi_get_phci(pip);
	MDI_PI_UNLOCK(pip);

	/* bring all components of phci to full power */
	MDI_DEBUG(4, (MDI_NOTE, ph_dip,
	    "pm_powerup for %s%d %p", ddi_driver_name(ph_dip),
	    ddi_get_instance(ph_dip), (void *)pip));

	ret = pm_powerup(ph_dip);

	if (ret == DDI_FAILURE) {
		MDI_DEBUG(4, (MDI_NOTE, ph_dip,
		    "pm_powerup FAILED for %s%d %p",
		    ddi_driver_name(ph_dip), ddi_get_instance(ph_dip),
		    (void *)pip));

		MDI_PI_LOCK(pip);
		i_mdi_pm_rele_pip(pip);
		MDI_PI_UNLOCK(pip);
		return (MDI_FAILURE);
	}

	return (MDI_SUCCESS);
}

static int
i_mdi_power_all_phci(mdi_client_t *ct)
{
	mdi_pathinfo_t  *pip;
	int		succeeded = 0;

	ASSERT(MDI_CLIENT_LOCKED(ct));
	pip = (mdi_pathinfo_t *)ct->ct_path_head;
	while (pip != NULL) {
		/*
		 * Don't power if MDI_PATHINFO_STATE_FAULT
		 * or MDI_PATHINFO_STATE_OFFLINE.
		 */
		if (MDI_PI_IS_INIT(pip) ||
		    MDI_PI_IS_ONLINE(pip) || MDI_PI_IS_STANDBY(pip)) {
			mdi_hold_path(pip);
			MDI_CLIENT_UNLOCK(ct);
			if (i_mdi_power_one_phci(pip) == MDI_SUCCESS)
				succeeded = 1;

			ASSERT(ct == MDI_PI(pip)->pi_client);
			MDI_CLIENT_LOCK(ct);
			mdi_rele_path(pip);
		}
		pip = (mdi_pathinfo_t *)MDI_PI(pip)->pi_client_link;
	}

	return (succeeded ? MDI_SUCCESS : MDI_FAILURE);
}

/*
 * mdi_bus_power():
 *		1. Place the phci(s) into powered up state so that
 *		   client can do power management
 *		2. Ensure phci powered up as client power managing
 * Return Values:
 *		MDI_SUCCESS
 *		MDI_FAILURE
 */
int
mdi_bus_power(dev_info_t *parent, void *impl_arg, pm_bus_power_op_t op,
    void *arg, void *result)
{
	int			ret = MDI_SUCCESS;
	pm_bp_child_pwrchg_t	*bpc;
	mdi_client_t		*ct;
	dev_info_t		*cdip;
	pm_bp_has_changed_t	*bphc;

	/*
	 * BUS_POWER_NOINVOL not supported
	 */
	if (op == BUS_POWER_NOINVOL)
		return (MDI_FAILURE);

	/*
	 * ignore other OPs.
	 * return quickly to save cou cycles on the ct processing
	 */
	switch (op) {
	case BUS_POWER_PRE_NOTIFICATION:
	case BUS_POWER_POST_NOTIFICATION:
		bpc = (pm_bp_child_pwrchg_t *)arg;
		cdip = bpc->bpc_dip;
		break;
	case BUS_POWER_HAS_CHANGED:
		bphc = (pm_bp_has_changed_t *)arg;
		cdip = bphc->bphc_dip;
		break;
	default:
		return (pm_busop_bus_power(parent, impl_arg, op, arg, result));
	}

	ASSERT(MDI_CLIENT(cdip));

	ct = i_devi_get_client(cdip);
	if (ct == NULL)
		return (MDI_FAILURE);

	/*
	 * wait till the mdi_pathinfo node state change are processed
	 */
	MDI_CLIENT_LOCK(ct);
	switch (op) {
	case BUS_POWER_PRE_NOTIFICATION:
		MDI_DEBUG(4, (MDI_NOTE, bpc->bpc_dip,
		    "BUS_POWER_PRE_NOTIFICATION:"
		    "%s@%s, olevel=%d, nlevel=%d, comp=%d",
		    ddi_node_name(bpc->bpc_dip), PM_ADDR(bpc->bpc_dip),
		    bpc->bpc_olevel, bpc->bpc_nlevel, bpc->bpc_comp));

		/* serialize power level change per client */
		while (MDI_CLIENT_IS_POWER_TRANSITION(ct))
			cv_wait(&ct->ct_powerchange_cv, &ct->ct_mutex);

		MDI_CLIENT_SET_POWER_TRANSITION(ct);

		if (ct->ct_power_cnt == 0) {
			ret = i_mdi_power_all_phci(ct);
		}

		/*
		 * if new_level > 0:
		 *	- hold phci(s)
		 *	- power up phci(s) if not already
		 * ignore power down
		 */
		if (bpc->bpc_nlevel > 0) {
			if (!DEVI_IS_ATTACHING(ct->ct_dip)) {
				MDI_DEBUG(4, (MDI_NOTE, bpc->bpc_dip,
				    "i_mdi_pm_hold_client\n"));
				i_mdi_pm_hold_client(ct, ct->ct_path_count);
			}
		}
		break;
	case BUS_POWER_POST_NOTIFICATION:
		MDI_DEBUG(4, (MDI_NOTE, bpc->bpc_dip,
		    "BUS_POWER_POST_NOTIFICATION:"
		    "%s@%s, olevel=%d, nlevel=%d, comp=%d result=%d",
		    ddi_node_name(bpc->bpc_dip), PM_ADDR(bpc->bpc_dip),
		    bpc->bpc_olevel, bpc->bpc_nlevel, bpc->bpc_comp,
		    *(int *)result));

		if (*(int *)result == DDI_SUCCESS) {
			if (bpc->bpc_nlevel > 0) {
				MDI_CLIENT_SET_POWER_UP(ct);
			} else {
				MDI_CLIENT_SET_POWER_DOWN(ct);
			}
		}

		/* release the hold we did in pre-notification */
		if (bpc->bpc_nlevel > 0 && (*(int *)result != DDI_SUCCESS) &&
		    !DEVI_IS_ATTACHING(ct->ct_dip)) {
			MDI_DEBUG(4, (MDI_NOTE, bpc->bpc_dip,
			    "i_mdi_pm_rele_client\n"));
			i_mdi_pm_rele_client(ct, ct->ct_path_count);
		}

		if (bpc->bpc_nlevel == 0 && (*(int *)result == DDI_SUCCESS)) {
			/* another thread might started attaching */
			if (DEVI_IS_ATTACHING(ct->ct_dip)) {
				MDI_DEBUG(4, (MDI_NOTE, bpc->bpc_dip,
				    "i_mdi_pm_rele_client\n"));
				i_mdi_pm_rele_client(ct, ct->ct_path_count);
			/* detaching has been taken care in pm_post_unconfig */
			} else if (!DEVI_IS_DETACHING(ct->ct_dip)) {
				MDI_DEBUG(4, (MDI_NOTE, bpc->bpc_dip,
				    "i_mdi_pm_reset_client\n"));
				i_mdi_pm_reset_client(ct);
			}
		}

		MDI_CLIENT_CLEAR_POWER_TRANSITION(ct);
		cv_broadcast(&ct->ct_powerchange_cv);

		break;

	/* need to do more */
	case BUS_POWER_HAS_CHANGED:
		MDI_DEBUG(4, (MDI_NOTE, bphc->bphc_dip,
		    "BUS_POWER_HAS_CHANGED:"
		    "%s@%s, olevel=%d, nlevel=%d, comp=%d",
		    ddi_node_name(bphc->bphc_dip), PM_ADDR(bphc->bphc_dip),
		    bphc->bphc_olevel, bphc->bphc_nlevel, bphc->bphc_comp));

		if (bphc->bphc_nlevel > 0 &&
		    bphc->bphc_nlevel > bphc->bphc_olevel) {
			if (ct->ct_power_cnt == 0) {
				ret = i_mdi_power_all_phci(ct);
			}
			MDI_DEBUG(4, (MDI_NOTE, bphc->bphc_dip,
			    "i_mdi_pm_hold_client\n"));
			i_mdi_pm_hold_client(ct, ct->ct_path_count);
		}

		if (bphc->bphc_nlevel == 0 && bphc->bphc_olevel != -1) {
			MDI_DEBUG(4, (MDI_NOTE, bphc->bphc_dip,
			    "i_mdi_pm_rele_client\n"));
			i_mdi_pm_rele_client(ct, ct->ct_path_count);
		}
		break;
	}

	MDI_CLIENT_UNLOCK(ct);
	return (ret);
}

static int
i_mdi_pm_pre_config_one(dev_info_t *child)
{
	int		ret = MDI_SUCCESS;
	mdi_client_t	*ct;

	ct = i_devi_get_client(child);
	if (ct == NULL)
		return (MDI_FAILURE);

	MDI_CLIENT_LOCK(ct);
	while (MDI_CLIENT_IS_POWER_TRANSITION(ct))
		cv_wait(&ct->ct_powerchange_cv, &ct->ct_mutex);

	if (!MDI_CLIENT_IS_FAILED(ct)) {
		MDI_CLIENT_UNLOCK(ct);
		MDI_DEBUG(4, (MDI_NOTE, child, "already configured\n"));
		return (MDI_SUCCESS);
	}

	if (ct->ct_powercnt_config) {
		MDI_CLIENT_UNLOCK(ct);
		MDI_DEBUG(4, (MDI_NOTE, child, "already held\n"));
		return (MDI_SUCCESS);
	}

	if (ct->ct_power_cnt == 0) {
		ret = i_mdi_power_all_phci(ct);
	}
	MDI_DEBUG(4, (MDI_NOTE, child, "i_mdi_pm_hold_client\n"));
	i_mdi_pm_hold_client(ct, ct->ct_path_count);
	ct->ct_powercnt_config = 1;
	ct->ct_powercnt_reset = 0;
	MDI_CLIENT_UNLOCK(ct);
	return (ret);
}

static int
i_mdi_pm_pre_config(dev_info_t *vdip, dev_info_t *child)
{
	int			ret = MDI_SUCCESS;
	dev_info_t		*cdip;
	int			circ;

	ASSERT(MDI_VHCI(vdip));

	/* ndi_devi_config_one */
	if (child) {
		ASSERT(DEVI_BUSY_OWNED(vdip));
		return (i_mdi_pm_pre_config_one(child));
	}

	/* devi_config_common */
	ndi_devi_enter(vdip, &circ);
	cdip = ddi_get_child(vdip);
	while (cdip) {
		dev_info_t *next = ddi_get_next_sibling(cdip);

		ret = i_mdi_pm_pre_config_one(cdip);
		if (ret != MDI_SUCCESS)
			break;
		cdip = next;
	}
	ndi_devi_exit(vdip, circ);
	return (ret);
}

static int
i_mdi_pm_pre_unconfig_one(dev_info_t *child, int *held, int flags)
{
	int		ret = MDI_SUCCESS;
	mdi_client_t	*ct;

	ct = i_devi_get_client(child);
	if (ct == NULL)
		return (MDI_FAILURE);

	MDI_CLIENT_LOCK(ct);
	while (MDI_CLIENT_IS_POWER_TRANSITION(ct))
		cv_wait(&ct->ct_powerchange_cv, &ct->ct_mutex);

	if (!i_ddi_devi_attached(child)) {
		MDI_DEBUG(4, (MDI_NOTE, child, "node detached already\n"));
		MDI_CLIENT_UNLOCK(ct);
		return (MDI_SUCCESS);
	}

	if (MDI_CLIENT_IS_POWERED_DOWN(ct) &&
	    (flags & NDI_AUTODETACH)) {
		MDI_DEBUG(4, (MDI_NOTE, child, "auto-modunload\n"));
		MDI_CLIENT_UNLOCK(ct);
		return (MDI_FAILURE);
	}

	if (ct->ct_powercnt_unconfig) {
		MDI_DEBUG(4, (MDI_NOTE, child, "ct_powercnt_held\n"));
		MDI_CLIENT_UNLOCK(ct);
		*held = 1;
		return (MDI_SUCCESS);
	}

	if (ct->ct_power_cnt == 0) {
		ret = i_mdi_power_all_phci(ct);
	}
	MDI_DEBUG(4, (MDI_NOTE, child, "i_mdi_pm_hold_client\n"));
	i_mdi_pm_hold_client(ct, ct->ct_path_count);
	ct->ct_powercnt_unconfig = 1;
	ct->ct_powercnt_reset = 0;
	MDI_CLIENT_UNLOCK(ct);
	if (ret == MDI_SUCCESS)
		*held = 1;
	return (ret);
}

static int
i_mdi_pm_pre_unconfig(dev_info_t *vdip, dev_info_t *child, int *held,
    int flags)
{
	int			ret = MDI_SUCCESS;
	dev_info_t		*cdip;
	int			circ;

	ASSERT(MDI_VHCI(vdip));
	*held = 0;

	/* ndi_devi_unconfig_one */
	if (child) {
		ASSERT(DEVI_BUSY_OWNED(vdip));
		return (i_mdi_pm_pre_unconfig_one(child, held, flags));
	}

	/* devi_unconfig_common */
	ndi_devi_enter(vdip, &circ);
	cdip = ddi_get_child(vdip);
	while (cdip) {
		dev_info_t *next = ddi_get_next_sibling(cdip);

		ret = i_mdi_pm_pre_unconfig_one(cdip, held, flags);
		cdip = next;
	}
	ndi_devi_exit(vdip, circ);

	if (*held)
		ret = MDI_SUCCESS;

	return (ret);
}

static void
i_mdi_pm_post_config_one(dev_info_t *child)
{
	mdi_client_t	*ct;

	ct = i_devi_get_client(child);
	if (ct == NULL)
		return;

	MDI_CLIENT_LOCK(ct);
	while (MDI_CLIENT_IS_POWER_TRANSITION(ct))
		cv_wait(&ct->ct_powerchange_cv, &ct->ct_mutex);

	if (ct->ct_powercnt_reset || !ct->ct_powercnt_config) {
		MDI_DEBUG(4, (MDI_NOTE, child, "not configured\n"));
		MDI_CLIENT_UNLOCK(ct);
		return;
	}

	/* client has not been updated */
	if (MDI_CLIENT_IS_FAILED(ct)) {
		MDI_DEBUG(4, (MDI_NOTE, child, "client failed\n"));
		MDI_CLIENT_UNLOCK(ct);
		return;
	}

	/* another thread might have powered it down or detached it */
	if ((MDI_CLIENT_IS_POWERED_DOWN(ct) &&
	    !DEVI_IS_ATTACHING(child)) ||
	    (!i_ddi_devi_attached(child) &&
	    !DEVI_IS_ATTACHING(child))) {
		MDI_DEBUG(4, (MDI_NOTE, child, "i_mdi_pm_reset_client\n"));
		i_mdi_pm_reset_client(ct);
	} else {
		mdi_pathinfo_t  *pip, *next;
		int	valid_path_count = 0;

		MDI_DEBUG(4, (MDI_NOTE, child, "i_mdi_pm_rele_client\n"));
		pip = ct->ct_path_head;
		while (pip != NULL) {
			MDI_PI_LOCK(pip);
			next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_client_link;
			if (MDI_PI_IS_ONLINE(pip) || MDI_PI_IS_STANDBY(pip))
				valid_path_count ++;
			MDI_PI_UNLOCK(pip);
			pip = next;
		}
		i_mdi_pm_rele_client(ct, valid_path_count);
	}
	ct->ct_powercnt_config = 0;
	MDI_CLIENT_UNLOCK(ct);
}

static void
i_mdi_pm_post_config(dev_info_t *vdip, dev_info_t *child)
{
	int		circ;
	dev_info_t	*cdip;

	ASSERT(MDI_VHCI(vdip));

	/* ndi_devi_config_one */
	if (child) {
		ASSERT(DEVI_BUSY_OWNED(vdip));
		i_mdi_pm_post_config_one(child);
		return;
	}

	/* devi_config_common */
	ndi_devi_enter(vdip, &circ);
	cdip = ddi_get_child(vdip);
	while (cdip) {
		dev_info_t *next = ddi_get_next_sibling(cdip);

		i_mdi_pm_post_config_one(cdip);
		cdip = next;
	}
	ndi_devi_exit(vdip, circ);
}

static void
i_mdi_pm_post_unconfig_one(dev_info_t *child)
{
	mdi_client_t	*ct;

	ct = i_devi_get_client(child);
	if (ct == NULL)
		return;

	MDI_CLIENT_LOCK(ct);
	while (MDI_CLIENT_IS_POWER_TRANSITION(ct))
		cv_wait(&ct->ct_powerchange_cv, &ct->ct_mutex);

	if (!ct->ct_powercnt_unconfig || ct->ct_powercnt_reset) {
		MDI_DEBUG(4, (MDI_NOTE, child, "not held\n"));
		MDI_CLIENT_UNLOCK(ct);
		return;
	}

	/* failure detaching or another thread just attached it */
	if ((MDI_CLIENT_IS_POWERED_DOWN(ct) &&
	    i_ddi_devi_attached(child)) ||
	    (!i_ddi_devi_attached(child) &&
	    !DEVI_IS_ATTACHING(child))) {
		MDI_DEBUG(4, (MDI_NOTE, child, "i_mdi_pm_reset_client\n"));
		i_mdi_pm_reset_client(ct);
	} else {
		mdi_pathinfo_t  *pip, *next;
		int	valid_path_count = 0;

		MDI_DEBUG(4, (MDI_NOTE, child, "i_mdi_pm_rele_client\n"));
		pip = ct->ct_path_head;
		while (pip != NULL) {
			MDI_PI_LOCK(pip);
			next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_client_link;
			if (MDI_PI_IS_ONLINE(pip) || MDI_PI_IS_STANDBY(pip))
				valid_path_count ++;
			MDI_PI_UNLOCK(pip);
			pip = next;
		}
		i_mdi_pm_rele_client(ct, valid_path_count);
		ct->ct_powercnt_unconfig = 0;
	}

	MDI_CLIENT_UNLOCK(ct);
}

static void
i_mdi_pm_post_unconfig(dev_info_t *vdip, dev_info_t *child, int held)
{
	int			circ;
	dev_info_t		*cdip;

	ASSERT(MDI_VHCI(vdip));

	if (!held) {
		MDI_DEBUG(4, (MDI_NOTE, vdip, "held = %d", held));
		return;
	}

	if (child) {
		ASSERT(DEVI_BUSY_OWNED(vdip));
		i_mdi_pm_post_unconfig_one(child);
		return;
	}

	ndi_devi_enter(vdip, &circ);
	cdip = ddi_get_child(vdip);
	while (cdip) {
		dev_info_t *next = ddi_get_next_sibling(cdip);

		i_mdi_pm_post_unconfig_one(cdip);
		cdip = next;
	}
	ndi_devi_exit(vdip, circ);
}

int
mdi_power(dev_info_t *vdip, mdi_pm_op_t op, void *args, char *devnm, int flags)
{
	int			circ, ret = MDI_SUCCESS;
	dev_info_t		*client_dip = NULL;
	mdi_client_t		*ct;

	/*
	 * Handling ndi_devi_config_one and ndi_devi_unconfig_one.
	 * Power up pHCI for the named client device.
	 * Note: Before the client is enumerated under vhci by phci,
	 * client_dip can be NULL. Then proceed to power up all the
	 * pHCIs.
	 */
	if (devnm != NULL) {
		ndi_devi_enter(vdip, &circ);
		client_dip = ndi_devi_findchild(vdip, devnm);
	}

	MDI_DEBUG(4, (MDI_NOTE, vdip,
	    "op = %d %s %p", op, devnm ? devnm : "", (void *)client_dip));

	switch (op) {
	case MDI_PM_PRE_CONFIG:
		ret = i_mdi_pm_pre_config(vdip, client_dip);
		break;

	case MDI_PM_PRE_UNCONFIG:
		ret = i_mdi_pm_pre_unconfig(vdip, client_dip, (int *)args,
		    flags);
		break;

	case MDI_PM_POST_CONFIG:
		i_mdi_pm_post_config(vdip, client_dip);
		break;

	case MDI_PM_POST_UNCONFIG:
		i_mdi_pm_post_unconfig(vdip, client_dip, *(int *)args);
		break;

	case MDI_PM_HOLD_POWER:
	case MDI_PM_RELE_POWER:
		ASSERT(args);

		client_dip = (dev_info_t *)args;
		ASSERT(MDI_CLIENT(client_dip));

		ct = i_devi_get_client(client_dip);
		MDI_CLIENT_LOCK(ct);

		if (op == MDI_PM_HOLD_POWER) {
			if (ct->ct_power_cnt == 0) {
				(void) i_mdi_power_all_phci(ct);
				MDI_DEBUG(4, (MDI_NOTE, client_dip,
				    "i_mdi_pm_hold_client\n"));
				i_mdi_pm_hold_client(ct, ct->ct_path_count);
			}
		} else {
			if (DEVI_IS_ATTACHING(client_dip)) {
				MDI_DEBUG(4, (MDI_NOTE, client_dip,
				    "i_mdi_pm_rele_client\n"));
				i_mdi_pm_rele_client(ct, ct->ct_path_count);
			} else {
				MDI_DEBUG(4, (MDI_NOTE, client_dip,
				    "i_mdi_pm_reset_client\n"));
				i_mdi_pm_reset_client(ct);
			}
		}

		MDI_CLIENT_UNLOCK(ct);
		break;

	default:
		break;
	}

	if (devnm)
		ndi_devi_exit(vdip, circ);

	return (ret);
}

int
mdi_component_is_vhci(dev_info_t *dip, const char **mdi_class)
{
	mdi_vhci_t *vhci;

	if (!MDI_VHCI(dip))
		return (MDI_FAILURE);

	if (mdi_class) {
		vhci = DEVI(dip)->devi_mdi_xhci;
		ASSERT(vhci);
		*mdi_class = vhci->vh_class;
	}

	return (MDI_SUCCESS);
}

int
mdi_component_is_phci(dev_info_t *dip, const char **mdi_class)
{
	mdi_phci_t *phci;

	if (!MDI_PHCI(dip))
		return (MDI_FAILURE);

	if (mdi_class) {
		phci = DEVI(dip)->devi_mdi_xhci;
		ASSERT(phci);
		*mdi_class = phci->ph_vhci->vh_class;
	}

	return (MDI_SUCCESS);
}

int
mdi_component_is_client(dev_info_t *dip, const char **mdi_class)
{
	mdi_client_t *client;

	if (!MDI_CLIENT(dip))
		return (MDI_FAILURE);

	if (mdi_class) {
		client = DEVI(dip)->devi_mdi_client;
		ASSERT(client);
		*mdi_class = client->ct_vhci->vh_class;
	}

	return (MDI_SUCCESS);
}

void *
mdi_client_get_vhci_private(dev_info_t *dip)
{
	ASSERT(mdi_component_is_client(dip, NULL) == MDI_SUCCESS);
	if (mdi_component_is_client(dip, NULL) == MDI_SUCCESS) {
		mdi_client_t	*ct;
		ct = i_devi_get_client(dip);
		return (ct->ct_vprivate);
	}
	return (NULL);
}

void
mdi_client_set_vhci_private(dev_info_t *dip, void *data)
{
	ASSERT(mdi_component_is_client(dip, NULL) == MDI_SUCCESS);
	if (mdi_component_is_client(dip, NULL) == MDI_SUCCESS) {
		mdi_client_t	*ct;
		ct = i_devi_get_client(dip);
		ct->ct_vprivate = data;
	}
}
/*
 * mdi_pi_get_vhci_private():
 *		Get the vhci private information associated with the
 *		mdi_pathinfo node
 */
void *
mdi_pi_get_vhci_private(mdi_pathinfo_t *pip)
{
	caddr_t	vprivate = NULL;
	if (pip) {
		vprivate = MDI_PI(pip)->pi_vprivate;
	}
	return (vprivate);
}

/*
 * mdi_pi_set_vhci_private():
 *		Set the vhci private information in the mdi_pathinfo node
 */
void
mdi_pi_set_vhci_private(mdi_pathinfo_t *pip, void *priv)
{
	if (pip) {
		MDI_PI(pip)->pi_vprivate = priv;
	}
}

/*
 * mdi_phci_get_vhci_private():
 *		Get the vhci private information associated with the
 *		mdi_phci node
 */
void *
mdi_phci_get_vhci_private(dev_info_t *dip)
{
	ASSERT(mdi_component_is_phci(dip, NULL) == MDI_SUCCESS);
	if (mdi_component_is_phci(dip, NULL) == MDI_SUCCESS) {
		mdi_phci_t	*ph;
		ph = i_devi_get_phci(dip);
		return (ph->ph_vprivate);
	}
	return (NULL);
}

/*
 * mdi_phci_set_vhci_private():
 *		Set the vhci private information in the mdi_phci node
 */
void
mdi_phci_set_vhci_private(dev_info_t *dip, void *priv)
{
	ASSERT(mdi_component_is_phci(dip, NULL) == MDI_SUCCESS);
	if (mdi_component_is_phci(dip, NULL) == MDI_SUCCESS) {
		mdi_phci_t	*ph;
		ph = i_devi_get_phci(dip);
		ph->ph_vprivate = priv;
	}
}

int
mdi_pi_ishidden(mdi_pathinfo_t *pip)
{
	return (MDI_PI_FLAGS_IS_HIDDEN(pip));
}

int
mdi_pi_device_isremoved(mdi_pathinfo_t *pip)
{
	return (MDI_PI_FLAGS_IS_DEVICE_REMOVED(pip));
}

/* Return 1 if all client paths are device_removed */
static int
i_mdi_client_all_devices_removed(mdi_client_t *ct)
{
	mdi_pathinfo_t  *pip;
	int		all_devices_removed = 1;

	MDI_CLIENT_LOCK(ct);
	for (pip = ct->ct_path_head; pip;
	    pip = (mdi_pathinfo_t *)MDI_PI(pip)->pi_client_link) {
		if (!mdi_pi_device_isremoved(pip)) {
			all_devices_removed = 0;
			break;
		}
	}
	MDI_CLIENT_UNLOCK(ct);
	return (all_devices_removed);
}

/*
 * When processing path hotunplug, represent device removal.
 */
int
mdi_pi_device_remove(mdi_pathinfo_t *pip)
{
	mdi_client_t	*ct;

	MDI_PI_LOCK(pip);
	if (mdi_pi_device_isremoved(pip)) {
		MDI_PI_UNLOCK(pip);
		return (0);
	}
	MDI_PI_FLAGS_SET_DEVICE_REMOVED(pip);
	MDI_PI_FLAGS_SET_HIDDEN(pip);
	MDI_PI_UNLOCK(pip);

	/*
	 * If all paths associated with the client are now DEVICE_REMOVED,
	 * reflect DEVICE_REMOVED in the client.
	 */
	ct = MDI_PI(pip)->pi_client;
	if (ct && ct->ct_dip && i_mdi_client_all_devices_removed(ct))
		(void) ndi_devi_device_remove(ct->ct_dip);
	else
		i_ddi_di_cache_invalidate();

	return (1);
}

/*
 * When processing hotplug, if a path marked mdi_pi_device_isremoved()
 * is now accessible then this interfaces is used to represent device insertion.
 */
int
mdi_pi_device_insert(mdi_pathinfo_t *pip)
{
	MDI_PI_LOCK(pip);
	if (!mdi_pi_device_isremoved(pip)) {
		MDI_PI_UNLOCK(pip);
		return (0);
	}
	MDI_PI_FLAGS_CLR_DEVICE_REMOVED(pip);
	MDI_PI_FLAGS_CLR_HIDDEN(pip);
	MDI_PI_UNLOCK(pip);

	i_ddi_di_cache_invalidate();

	return (1);
}

/*
 * List of vhci class names:
 * A vhci class name must be in this list only if the corresponding vhci
 * driver intends to use the mdi provided bus config implementation
 * (i.e., mdi_vhci_bus_config()).
 */
static char *vhci_class_list[] = { MDI_HCI_CLASS_SCSI, MDI_HCI_CLASS_IB };
#define	N_VHCI_CLASSES	(sizeof (vhci_class_list) / sizeof (char *))

/*
 * During boot time, the on-disk vhci cache for every vhci class is read
 * in the form of an nvlist and stored here.
 */
static nvlist_t *vhcache_nvl[N_VHCI_CLASSES];

/* nvpair names in vhci cache nvlist */
#define	MDI_VHCI_CACHE_VERSION	1
#define	MDI_NVPNAME_VERSION	"version"
#define	MDI_NVPNAME_PHCIS	"phcis"
#define	MDI_NVPNAME_CTADDRMAP	"clientaddrmap"

/*
 * Given vhci class name, return its on-disk vhci cache filename.
 * Memory for the returned filename which includes the full path is allocated
 * by this function.
 */
static char *
vhclass2vhcache_filename(char *vhclass)
{
	char *filename;
	int len;
	static char *fmt = "/etc/devices/mdi_%s_cache";

	/*
	 * fmt contains the on-disk vhci cache file name format;
	 * for scsi_vhci the filename is "/etc/devices/mdi_scsi_vhci_cache".
	 */

	/* the -1 below is to account for "%s" in the format string */
	len = strlen(fmt) + strlen(vhclass) - 1;
	filename = kmem_alloc(len, KM_SLEEP);
	(void) snprintf(filename, len, fmt, vhclass);
	ASSERT(len == (strlen(filename) + 1));
	return (filename);
}

/*
 * initialize the vhci cache related data structures and read the on-disk
 * vhci cached data into memory.
 */
static void
setup_vhci_cache(mdi_vhci_t *vh)
{
	mdi_vhci_config_t *vhc;
	mdi_vhci_cache_t *vhcache;
	int i;
	nvlist_t *nvl = NULL;

	vhc = kmem_zalloc(sizeof (mdi_vhci_config_t), KM_SLEEP);
	vh->vh_config = vhc;
	vhcache = &vhc->vhc_vhcache;

	vhc->vhc_vhcache_filename = vhclass2vhcache_filename(vh->vh_class);

	mutex_init(&vhc->vhc_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&vhc->vhc_cv, NULL, CV_DRIVER, NULL);

	rw_init(&vhcache->vhcache_lock, NULL, RW_DRIVER, NULL);

	/*
	 * Create string hash; same as mod_hash_create_strhash() except that
	 * we use NULL key destructor.
	 */
	vhcache->vhcache_client_hash = mod_hash_create_extended(vh->vh_class,
	    mdi_bus_config_cache_hash_size,
	    mod_hash_null_keydtor, mod_hash_null_valdtor,
	    mod_hash_bystr, NULL, mod_hash_strkey_cmp, KM_SLEEP);

	/*
	 * The on-disk vhci cache is read during booting prior to the
	 * lights-out period by mdi_read_devices_files().
	 */
	for (i = 0; i < N_VHCI_CLASSES; i++) {
		if (strcmp(vhci_class_list[i], vh->vh_class) == 0) {
			nvl = vhcache_nvl[i];
			vhcache_nvl[i] = NULL;
			break;
		}
	}

	/*
	 * this is to cover the case of some one manually causing unloading
	 * (or detaching) and reloading (or attaching) of a vhci driver.
	 */
	if (nvl == NULL && modrootloaded)
		nvl = read_on_disk_vhci_cache(vh->vh_class);

	if (nvl != NULL) {
		rw_enter(&vhcache->vhcache_lock, RW_WRITER);
		if (mainnvl_to_vhcache(vhcache, nvl) == MDI_SUCCESS)
			vhcache->vhcache_flags |= MDI_VHCI_CACHE_SETUP_DONE;
		else  {
			cmn_err(CE_WARN,
			    "%s: data file corrupted, will recreate",
			    vhc->vhc_vhcache_filename);
		}
		rw_exit(&vhcache->vhcache_lock);
		nvlist_free(nvl);
	}

	vhc->vhc_cbid = callb_add(stop_vhcache_flush_thread, vhc,
	    CB_CL_UADMIN_PRE_VFS, "mdi_vhcache_flush");

	vhc->vhc_path_discovery_boot = mdi_path_discovery_boot;
	vhc->vhc_path_discovery_postboot = mdi_path_discovery_postboot;
}

/*
 * free all vhci cache related resources
 */
static int
destroy_vhci_cache(mdi_vhci_t *vh)
{
	mdi_vhci_config_t *vhc = vh->vh_config;
	mdi_vhci_cache_t *vhcache = &vhc->vhc_vhcache;
	mdi_vhcache_phci_t *cphci, *cphci_next;
	mdi_vhcache_client_t *cct, *cct_next;
	mdi_vhcache_pathinfo_t *cpi, *cpi_next;

	if (stop_vhcache_async_threads(vhc) != MDI_SUCCESS)
		return (MDI_FAILURE);

	kmem_free(vhc->vhc_vhcache_filename,
	    strlen(vhc->vhc_vhcache_filename) + 1);

	mod_hash_destroy_strhash(vhcache->vhcache_client_hash);

	for (cphci = vhcache->vhcache_phci_head; cphci != NULL;
	    cphci = cphci_next) {
		cphci_next = cphci->cphci_next;
		free_vhcache_phci(cphci);
	}

	for (cct = vhcache->vhcache_client_head; cct != NULL; cct = cct_next) {
		cct_next = cct->cct_next;
		for (cpi = cct->cct_cpi_head; cpi != NULL; cpi = cpi_next) {
			cpi_next = cpi->cpi_next;
			free_vhcache_pathinfo(cpi);
		}
		free_vhcache_client(cct);
	}

	rw_destroy(&vhcache->vhcache_lock);

	mutex_destroy(&vhc->vhc_lock);
	cv_destroy(&vhc->vhc_cv);
	kmem_free(vhc, sizeof (mdi_vhci_config_t));
	return (MDI_SUCCESS);
}

/*
 * Stop all vhci cache related async threads and free their resources.
 */
static int
stop_vhcache_async_threads(mdi_vhci_config_t *vhc)
{
	mdi_async_client_config_t *acc, *acc_next;

	mutex_enter(&vhc->vhc_lock);
	vhc->vhc_flags |= MDI_VHC_EXIT;
	ASSERT(vhc->vhc_acc_thrcount >= 0);
	cv_broadcast(&vhc->vhc_cv);

	while ((vhc->vhc_flags & MDI_VHC_VHCACHE_FLUSH_THREAD) ||
	    vhc->vhc_acc_thrcount != 0) {
		mutex_exit(&vhc->vhc_lock);
		delay_random(mdi_delay);
		mutex_enter(&vhc->vhc_lock);
	}

	vhc->vhc_flags &= ~MDI_VHC_EXIT;

	for (acc = vhc->vhc_acc_list_head; acc != NULL; acc = acc_next) {
		acc_next = acc->acc_next;
		free_async_client_config(acc);
	}
	vhc->vhc_acc_list_head = NULL;
	vhc->vhc_acc_list_tail = NULL;
	vhc->vhc_acc_count = 0;

	if (vhc->vhc_flags & MDI_VHC_VHCACHE_DIRTY) {
		vhc->vhc_flags &= ~MDI_VHC_VHCACHE_DIRTY;
		mutex_exit(&vhc->vhc_lock);
		if (flush_vhcache(vhc, 0) != MDI_SUCCESS) {
			vhcache_dirty(vhc);
			return (MDI_FAILURE);
		}
	} else
		mutex_exit(&vhc->vhc_lock);

	if (callb_delete(vhc->vhc_cbid) != 0)
		return (MDI_FAILURE);

	return (MDI_SUCCESS);
}

/*
 * Stop vhci cache flush thread
 */
/* ARGSUSED */
static boolean_t
stop_vhcache_flush_thread(void *arg, int code)
{
	mdi_vhci_config_t *vhc = (mdi_vhci_config_t *)arg;

	mutex_enter(&vhc->vhc_lock);
	vhc->vhc_flags |= MDI_VHC_EXIT;
	cv_broadcast(&vhc->vhc_cv);

	while (vhc->vhc_flags & MDI_VHC_VHCACHE_FLUSH_THREAD) {
		mutex_exit(&vhc->vhc_lock);
		delay_random(mdi_delay);
		mutex_enter(&vhc->vhc_lock);
	}

	if (vhc->vhc_flags & MDI_VHC_VHCACHE_DIRTY) {
		vhc->vhc_flags &= ~MDI_VHC_VHCACHE_DIRTY;
		mutex_exit(&vhc->vhc_lock);
		(void) flush_vhcache(vhc, 1);
	} else
		mutex_exit(&vhc->vhc_lock);

	return (B_TRUE);
}

/*
 * Enqueue the vhcache phci (cphci) at the tail of the list
 */
static void
enqueue_vhcache_phci(mdi_vhci_cache_t *vhcache, mdi_vhcache_phci_t *cphci)
{
	cphci->cphci_next = NULL;
	if (vhcache->vhcache_phci_head == NULL)
		vhcache->vhcache_phci_head = cphci;
	else
		vhcache->vhcache_phci_tail->cphci_next = cphci;
	vhcache->vhcache_phci_tail = cphci;
}

/*
 * Enqueue the vhcache pathinfo (cpi) at the tail of the list
 */
static void
enqueue_tail_vhcache_pathinfo(mdi_vhcache_client_t *cct,
    mdi_vhcache_pathinfo_t *cpi)
{
	cpi->cpi_next = NULL;
	if (cct->cct_cpi_head == NULL)
		cct->cct_cpi_head = cpi;
	else
		cct->cct_cpi_tail->cpi_next = cpi;
	cct->cct_cpi_tail = cpi;
}

/*
 * Enqueue the vhcache pathinfo (cpi) at the correct location in the
 * ordered list. All cpis which do not have MDI_CPI_HINT_PATH_DOES_NOT_EXIST
 * flag set come at the beginning of the list. All cpis which have this
 * flag set come at the end of the list.
 */
static void
enqueue_vhcache_pathinfo(mdi_vhcache_client_t *cct,
    mdi_vhcache_pathinfo_t *newcpi)
{
	mdi_vhcache_pathinfo_t *cpi, *prev_cpi;

	if (cct->cct_cpi_head == NULL ||
	    (newcpi->cpi_flags & MDI_CPI_HINT_PATH_DOES_NOT_EXIST))
		enqueue_tail_vhcache_pathinfo(cct, newcpi);
	else {
		for (cpi = cct->cct_cpi_head, prev_cpi = NULL; cpi != NULL &&
		    !(cpi->cpi_flags & MDI_CPI_HINT_PATH_DOES_NOT_EXIST);
		    prev_cpi = cpi, cpi = cpi->cpi_next)
			;

		if (prev_cpi == NULL)
			cct->cct_cpi_head = newcpi;
		else
			prev_cpi->cpi_next = newcpi;

		newcpi->cpi_next = cpi;

		if (cpi == NULL)
			cct->cct_cpi_tail = newcpi;
	}
}

/*
 * Enqueue the vhcache client (cct) at the tail of the list
 */
static void
enqueue_vhcache_client(mdi_vhci_cache_t *vhcache,
    mdi_vhcache_client_t *cct)
{
	cct->cct_next = NULL;
	if (vhcache->vhcache_client_head == NULL)
		vhcache->vhcache_client_head = cct;
	else
		vhcache->vhcache_client_tail->cct_next = cct;
	vhcache->vhcache_client_tail = cct;
}

static void
free_string_array(char **str, int nelem)
{
	int i;

	if (str) {
		for (i = 0; i < nelem; i++) {
			if (str[i])
				kmem_free(str[i], strlen(str[i]) + 1);
		}
		kmem_free(str, sizeof (char *) * nelem);
	}
}

static void
free_vhcache_phci(mdi_vhcache_phci_t *cphci)
{
	kmem_free(cphci->cphci_path, strlen(cphci->cphci_path) + 1);
	kmem_free(cphci, sizeof (*cphci));
}

static void
free_vhcache_pathinfo(mdi_vhcache_pathinfo_t *cpi)
{
	kmem_free(cpi->cpi_addr, strlen(cpi->cpi_addr) + 1);
	kmem_free(cpi, sizeof (*cpi));
}

static void
free_vhcache_client(mdi_vhcache_client_t *cct)
{
	kmem_free(cct->cct_name_addr, strlen(cct->cct_name_addr) + 1);
	kmem_free(cct, sizeof (*cct));
}

static char *
vhcache_mknameaddr(char *ct_name, char *ct_addr, int *ret_len)
{
	char *name_addr;
	int len;

	len = strlen(ct_name) + strlen(ct_addr) + 2;
	name_addr = kmem_alloc(len, KM_SLEEP);
	(void) snprintf(name_addr, len, "%s@%s", ct_name, ct_addr);

	if (ret_len)
		*ret_len = len;
	return (name_addr);
}

/*
 * Copy the contents of paddrnvl to vhci cache.
 * paddrnvl nvlist contains path information for a vhci client.
 * See the comment in mainnvl_to_vhcache() for the format of this nvlist.
 */
static void
paddrnvl_to_vhcache(nvlist_t *nvl, mdi_vhcache_phci_t *cphci_list[],
    mdi_vhcache_client_t *cct)
{
	nvpair_t *nvp = NULL;
	mdi_vhcache_pathinfo_t *cpi;
	uint_t nelem;
	uint32_t *val;

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		ASSERT(nvpair_type(nvp) == DATA_TYPE_UINT32_ARRAY);
		cpi = kmem_zalloc(sizeof (*cpi), KM_SLEEP);
		cpi->cpi_addr = i_ddi_strdup(nvpair_name(nvp), KM_SLEEP);
		(void) nvpair_value_uint32_array(nvp, &val, &nelem);
		ASSERT(nelem == 2);
		cpi->cpi_cphci = cphci_list[val[0]];
		cpi->cpi_flags = val[1];
		enqueue_tail_vhcache_pathinfo(cct, cpi);
	}
}

/*
 * Copy the contents of caddrmapnvl to vhci cache.
 * caddrmapnvl nvlist contains vhci client address to phci client address
 * mappings. See the comment in mainnvl_to_vhcache() for the format of
 * this nvlist.
 */
static void
caddrmapnvl_to_vhcache(mdi_vhci_cache_t *vhcache, nvlist_t *nvl,
    mdi_vhcache_phci_t *cphci_list[])
{
	nvpair_t *nvp = NULL;
	nvlist_t *paddrnvl;
	mdi_vhcache_client_t *cct;

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		ASSERT(nvpair_type(nvp) == DATA_TYPE_NVLIST);
		cct = kmem_zalloc(sizeof (*cct), KM_SLEEP);
		cct->cct_name_addr = i_ddi_strdup(nvpair_name(nvp), KM_SLEEP);
		(void) nvpair_value_nvlist(nvp, &paddrnvl);
		paddrnvl_to_vhcache(paddrnvl, cphci_list, cct);
		/* the client must contain at least one path */
		ASSERT(cct->cct_cpi_head != NULL);

		enqueue_vhcache_client(vhcache, cct);
		(void) mod_hash_insert(vhcache->vhcache_client_hash,
		    (mod_hash_key_t)cct->cct_name_addr, (mod_hash_val_t)cct);
	}
}

/*
 * Copy the contents of the main nvlist to vhci cache.
 *
 * VHCI busconfig cached data is stored in the form of a nvlist on the disk.
 * The nvlist contains the mappings between the vhci client addresses and
 * their corresponding phci client addresses.
 *
 * The structure of the nvlist is as follows:
 *
 * Main nvlist:
 *	NAME		TYPE		DATA
 *	version		int32		version number
 *	phcis		string array	array of phci paths
 *	clientaddrmap	nvlist_t	c2paddrs_nvl (see below)
 *
 * structure of c2paddrs_nvl:
 *	NAME		TYPE		DATA
 *	caddr1		nvlist_t	paddrs_nvl1
 *	caddr2		nvlist_t	paddrs_nvl2
 *	...
 * where caddr1, caddr2, ... are vhci client name and addresses in the
 * form of "<clientname>@<clientaddress>".
 * (for example: "ssd@2000002037cd9f72");
 * paddrs_nvl1, paddrs_nvl2, .. are nvlists that contain path information.
 *
 * structure of paddrs_nvl:
 *	NAME		TYPE		DATA
 *	pi_addr1	uint32_array	(phci-id, cpi_flags)
 *	pi_addr2	uint32_array	(phci-id, cpi_flags)
 *	...
 * where pi_addr1, pi_addr2, ... are bus specific addresses of pathinfo nodes
 * (so called pi_addrs, for example: "w2100002037cd9f72,0");
 * phci-ids are integers that identify pHCIs to which the
 * the bus specific address belongs to. These integers are used as an index
 * into to the phcis string array in the main nvlist to get the pHCI path.
 */
static int
mainnvl_to_vhcache(mdi_vhci_cache_t *vhcache, nvlist_t *nvl)
{
	char **phcis, **phci_namep;
	uint_t nphcis;
	mdi_vhcache_phci_t *cphci, **cphci_list;
	nvlist_t *caddrmapnvl;
	int32_t ver;
	int i;
	size_t cphci_list_size;

	ASSERT(RW_WRITE_HELD(&vhcache->vhcache_lock));

	if (nvlist_lookup_int32(nvl, MDI_NVPNAME_VERSION, &ver) != 0 ||
	    ver != MDI_VHCI_CACHE_VERSION)
		return (MDI_FAILURE);

	if (nvlist_lookup_string_array(nvl, MDI_NVPNAME_PHCIS, &phcis,
	    &nphcis) != 0)
		return (MDI_SUCCESS);

	ASSERT(nphcis > 0);

	cphci_list_size = sizeof (mdi_vhcache_phci_t *) * nphcis;
	cphci_list = kmem_alloc(cphci_list_size, KM_SLEEP);
	for (i = 0, phci_namep = phcis; i < nphcis; i++, phci_namep++) {
		cphci = kmem_zalloc(sizeof (mdi_vhcache_phci_t), KM_SLEEP);
		cphci->cphci_path = i_ddi_strdup(*phci_namep, KM_SLEEP);
		enqueue_vhcache_phci(vhcache, cphci);
		cphci_list[i] = cphci;
	}

	ASSERT(vhcache->vhcache_phci_head != NULL);

	if (nvlist_lookup_nvlist(nvl, MDI_NVPNAME_CTADDRMAP, &caddrmapnvl) == 0)
		caddrmapnvl_to_vhcache(vhcache, caddrmapnvl, cphci_list);

	kmem_free(cphci_list, cphci_list_size);
	return (MDI_SUCCESS);
}

/*
 * Build paddrnvl for the specified client using the information in the
 * vhci cache and add it to the caddrmapnnvl.
 * Returns 0 on success, errno on failure.
 */
static int
vhcache_to_paddrnvl(mdi_vhci_cache_t *vhcache, mdi_vhcache_client_t *cct,
    nvlist_t *caddrmapnvl)
{
	mdi_vhcache_pathinfo_t *cpi;
	nvlist_t *nvl;
	int err;
	uint32_t val[2];

	ASSERT(RW_LOCK_HELD(&vhcache->vhcache_lock));

	if ((err = nvlist_alloc(&nvl, 0, KM_SLEEP)) != 0)
		return (err);

	for (cpi = cct->cct_cpi_head; cpi != NULL; cpi = cpi->cpi_next) {
		val[0] = cpi->cpi_cphci->cphci_id;
		val[1] = cpi->cpi_flags;
		if ((err = nvlist_add_uint32_array(nvl, cpi->cpi_addr, val, 2))
		    != 0)
			goto out;
	}

	err = nvlist_add_nvlist(caddrmapnvl, cct->cct_name_addr, nvl);
out:
	nvlist_free(nvl);
	return (err);
}

/*
 * Build caddrmapnvl using the information in the vhci cache
 * and add it to the mainnvl.
 * Returns 0 on success, errno on failure.
 */
static int
vhcache_to_caddrmapnvl(mdi_vhci_cache_t *vhcache, nvlist_t *mainnvl)
{
	mdi_vhcache_client_t *cct;
	nvlist_t *nvl;
	int err;

	ASSERT(RW_LOCK_HELD(&vhcache->vhcache_lock));

	if ((err = nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP)) != 0)
		return (err);

	for (cct = vhcache->vhcache_client_head; cct != NULL;
	    cct = cct->cct_next) {
		if ((err = vhcache_to_paddrnvl(vhcache, cct, nvl)) != 0)
			goto out;
	}

	err = nvlist_add_nvlist(mainnvl, MDI_NVPNAME_CTADDRMAP, nvl);
out:
	nvlist_free(nvl);
	return (err);
}

/*
 * Build nvlist using the information in the vhci cache.
 * See the comment in mainnvl_to_vhcache() for the format of the nvlist.
 * Returns nvl on success, NULL on failure.
 */
static nvlist_t *
vhcache_to_mainnvl(mdi_vhci_cache_t *vhcache)
{
	mdi_vhcache_phci_t *cphci;
	uint_t phci_count;
	char **phcis;
	nvlist_t *nvl;
	int err, i;

	if ((err = nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP)) != 0) {
		nvl = NULL;
		goto out;
	}

	if ((err = nvlist_add_int32(nvl, MDI_NVPNAME_VERSION,
	    MDI_VHCI_CACHE_VERSION)) != 0)
		goto out;

	rw_enter(&vhcache->vhcache_lock, RW_READER);
	if (vhcache->vhcache_phci_head == NULL) {
		rw_exit(&vhcache->vhcache_lock);
		return (nvl);
	}

	phci_count = 0;
	for (cphci = vhcache->vhcache_phci_head; cphci != NULL;
	    cphci = cphci->cphci_next)
		cphci->cphci_id = phci_count++;

	/* build phci pathname list */
	phcis = kmem_alloc(sizeof (char *) * phci_count, KM_SLEEP);
	for (cphci = vhcache->vhcache_phci_head, i = 0; cphci != NULL;
	    cphci = cphci->cphci_next, i++)
		phcis[i] = i_ddi_strdup(cphci->cphci_path, KM_SLEEP);

	err = nvlist_add_string_array(nvl, MDI_NVPNAME_PHCIS, phcis,
	    phci_count);
	free_string_array(phcis, phci_count);

	if (err == 0 &&
	    (err = vhcache_to_caddrmapnvl(vhcache, nvl)) == 0) {
		rw_exit(&vhcache->vhcache_lock);
		return (nvl);
	}

	rw_exit(&vhcache->vhcache_lock);
out:
	if (nvl)
		nvlist_free(nvl);
	return (NULL);
}

/*
 * Lookup vhcache phci structure for the specified phci path.
 */
static mdi_vhcache_phci_t *
lookup_vhcache_phci_by_name(mdi_vhci_cache_t *vhcache, char *phci_path)
{
	mdi_vhcache_phci_t *cphci;

	ASSERT(RW_LOCK_HELD(&vhcache->vhcache_lock));

	for (cphci = vhcache->vhcache_phci_head; cphci != NULL;
	    cphci = cphci->cphci_next) {
		if (strcmp(cphci->cphci_path, phci_path) == 0)
			return (cphci);
	}

	return (NULL);
}

/*
 * Lookup vhcache phci structure for the specified phci.
 */
static mdi_vhcache_phci_t *
lookup_vhcache_phci_by_addr(mdi_vhci_cache_t *vhcache, mdi_phci_t *ph)
{
	mdi_vhcache_phci_t *cphci;

	ASSERT(RW_LOCK_HELD(&vhcache->vhcache_lock));

	for (cphci = vhcache->vhcache_phci_head; cphci != NULL;
	    cphci = cphci->cphci_next) {
		if (cphci->cphci_phci == ph)
			return (cphci);
	}

	return (NULL);
}

/*
 * Add the specified phci to the vhci cache if not already present.
 */
static void
vhcache_phci_add(mdi_vhci_config_t *vhc, mdi_phci_t *ph)
{
	mdi_vhci_cache_t *vhcache = &vhc->vhc_vhcache;
	mdi_vhcache_phci_t *cphci;
	char *pathname;
	int cache_updated;

	rw_enter(&vhcache->vhcache_lock, RW_WRITER);

	pathname = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(ph->ph_dip, pathname);
	if ((cphci = lookup_vhcache_phci_by_name(vhcache, pathname))
	    != NULL) {
		cphci->cphci_phci = ph;
		cache_updated = 0;
	} else {
		cphci = kmem_zalloc(sizeof (*cphci), KM_SLEEP);
		cphci->cphci_path = i_ddi_strdup(pathname, KM_SLEEP);
		cphci->cphci_phci = ph;
		enqueue_vhcache_phci(vhcache, cphci);
		cache_updated = 1;
	}

	rw_exit(&vhcache->vhcache_lock);

	/*
	 * Since a new phci has been added, reset
	 * vhc_path_discovery_cutoff_time to allow for discovery of paths
	 * during next vhcache_discover_paths().
	 */
	mutex_enter(&vhc->vhc_lock);
	vhc->vhc_path_discovery_cutoff_time = 0;
	mutex_exit(&vhc->vhc_lock);

	kmem_free(pathname, MAXPATHLEN);
	if (cache_updated)
		vhcache_dirty(vhc);
}

/*
 * Remove the reference to the specified phci from the vhci cache.
 */
static void
vhcache_phci_remove(mdi_vhci_config_t *vhc, mdi_phci_t *ph)
{
	mdi_vhci_cache_t *vhcache = &vhc->vhc_vhcache;
	mdi_vhcache_phci_t *cphci;

	rw_enter(&vhcache->vhcache_lock, RW_WRITER);
	if ((cphci = lookup_vhcache_phci_by_addr(vhcache, ph)) != NULL) {
		/* do not remove the actual mdi_vhcache_phci structure */
		cphci->cphci_phci = NULL;
	}
	rw_exit(&vhcache->vhcache_lock);
}

static void
init_vhcache_lookup_token(mdi_vhcache_lookup_token_t *dst,
    mdi_vhcache_lookup_token_t *src)
{
	if (src == NULL) {
		dst->lt_cct = NULL;
		dst->lt_cct_lookup_time = 0;
	} else {
		dst->lt_cct = src->lt_cct;
		dst->lt_cct_lookup_time = src->lt_cct_lookup_time;
	}
}

/*
 * Look up vhcache client for the specified client.
 */
static mdi_vhcache_client_t *
lookup_vhcache_client(mdi_vhci_cache_t *vhcache, char *ct_name, char *ct_addr,
    mdi_vhcache_lookup_token_t *token)
{
	mod_hash_val_t hv;
	char *name_addr;
	int len;

	ASSERT(RW_LOCK_HELD(&vhcache->vhcache_lock));

	/*
	 * If no vhcache clean occurred since the last lookup, we can
	 * simply return the cct from the last lookup operation.
	 * It works because ccts are never freed except during the vhcache
	 * cleanup operation.
	 */
	if (token != NULL &&
	    vhcache->vhcache_clean_time < token->lt_cct_lookup_time)
		return (token->lt_cct);

	name_addr = vhcache_mknameaddr(ct_name, ct_addr, &len);
	if (mod_hash_find(vhcache->vhcache_client_hash,
	    (mod_hash_key_t)name_addr, &hv) == 0) {
		if (token) {
			token->lt_cct = (mdi_vhcache_client_t *)hv;
			token->lt_cct_lookup_time = ddi_get_lbolt64();
		}
	} else {
		if (token) {
			token->lt_cct = NULL;
			token->lt_cct_lookup_time = 0;
		}
		hv = NULL;
	}
	kmem_free(name_addr, len);
	return ((mdi_vhcache_client_t *)hv);
}

/*
 * Add the specified path to the vhci cache if not already present.
 * Also add the vhcache client for the client corresponding to this path
 * if it doesn't already exist.
 */
static void
vhcache_pi_add(mdi_vhci_config_t *vhc, struct mdi_pathinfo *pip)
{
	mdi_vhci_cache_t *vhcache = &vhc->vhc_vhcache;
	mdi_vhcache_client_t *cct;
	mdi_vhcache_pathinfo_t *cpi;
	mdi_phci_t *ph = pip->pi_phci;
	mdi_client_t *ct = pip->pi_client;
	int cache_updated = 0;

	rw_enter(&vhcache->vhcache_lock, RW_WRITER);

	/* if vhcache client for this pip doesn't already exist, add it */
	if ((cct = lookup_vhcache_client(vhcache, ct->ct_drvname, ct->ct_guid,
	    NULL)) == NULL) {
		cct = kmem_zalloc(sizeof (*cct), KM_SLEEP);
		cct->cct_name_addr = vhcache_mknameaddr(ct->ct_drvname,
		    ct->ct_guid, NULL);
		enqueue_vhcache_client(vhcache, cct);
		(void) mod_hash_insert(vhcache->vhcache_client_hash,
		    (mod_hash_key_t)cct->cct_name_addr, (mod_hash_val_t)cct);
		cache_updated = 1;
	}

	for (cpi = cct->cct_cpi_head; cpi != NULL; cpi = cpi->cpi_next) {
		if (cpi->cpi_cphci->cphci_phci == ph &&
		    strcmp(cpi->cpi_addr, pip->pi_addr) == 0) {
			cpi->cpi_pip = pip;
			if (cpi->cpi_flags & MDI_CPI_HINT_PATH_DOES_NOT_EXIST) {
				cpi->cpi_flags &=
				    ~MDI_CPI_HINT_PATH_DOES_NOT_EXIST;
				sort_vhcache_paths(cct);
				cache_updated = 1;
			}
			break;
		}
	}

	if (cpi == NULL) {
		cpi = kmem_zalloc(sizeof (*cpi), KM_SLEEP);
		cpi->cpi_addr = i_ddi_strdup(pip->pi_addr, KM_SLEEP);
		cpi->cpi_cphci = lookup_vhcache_phci_by_addr(vhcache, ph);
		ASSERT(cpi->cpi_cphci != NULL);
		cpi->cpi_pip = pip;
		enqueue_vhcache_pathinfo(cct, cpi);
		cache_updated = 1;
	}

	rw_exit(&vhcache->vhcache_lock);

	if (cache_updated)
		vhcache_dirty(vhc);
}

/*
 * Remove the reference to the specified path from the vhci cache.
 */
static void
vhcache_pi_remove(mdi_vhci_config_t *vhc, struct mdi_pathinfo *pip)
{
	mdi_vhci_cache_t *vhcache = &vhc->vhc_vhcache;
	mdi_client_t *ct = pip->pi_client;
	mdi_vhcache_client_t *cct;
	mdi_vhcache_pathinfo_t *cpi;

	rw_enter(&vhcache->vhcache_lock, RW_WRITER);
	if ((cct = lookup_vhcache_client(vhcache, ct->ct_drvname, ct->ct_guid,
	    NULL)) != NULL) {
		for (cpi = cct->cct_cpi_head; cpi != NULL;
		    cpi = cpi->cpi_next) {
			if (cpi->cpi_pip == pip) {
				cpi->cpi_pip = NULL;
				break;
			}
		}
	}
	rw_exit(&vhcache->vhcache_lock);
}

/*
 * Flush the vhci cache to disk.
 * Returns MDI_SUCCESS on success, MDI_FAILURE on failure.
 */
static int
flush_vhcache(mdi_vhci_config_t *vhc, int force_flag)
{
	nvlist_t *nvl;
	int err;
	int rv;

	/*
	 * It is possible that the system may shutdown before
	 * i_ddi_io_initialized (during stmsboot for example). To allow for
	 * flushing the cache in this case do not check for
	 * i_ddi_io_initialized when force flag is set.
	 */
	if (force_flag == 0 && !i_ddi_io_initialized())
		return (MDI_FAILURE);

	if ((nvl = vhcache_to_mainnvl(&vhc->vhc_vhcache)) != NULL) {
		err = fwrite_nvlist(vhc->vhc_vhcache_filename, nvl);
		nvlist_free(nvl);
	} else
		err = EFAULT;

	rv = MDI_SUCCESS;
	mutex_enter(&vhc->vhc_lock);
	if (err != 0) {
		if (err == EROFS) {
			vhc->vhc_flags |= MDI_VHC_READONLY_FS;
			vhc->vhc_flags &= ~(MDI_VHC_VHCACHE_FLUSH_ERROR |
			    MDI_VHC_VHCACHE_DIRTY);
		} else {
			if (!(vhc->vhc_flags & MDI_VHC_VHCACHE_FLUSH_ERROR)) {
				cmn_err(CE_CONT, "%s: update failed\n",
				    vhc->vhc_vhcache_filename);
				vhc->vhc_flags |= MDI_VHC_VHCACHE_FLUSH_ERROR;
			}
			rv = MDI_FAILURE;
		}
	} else if (vhc->vhc_flags & MDI_VHC_VHCACHE_FLUSH_ERROR) {
		cmn_err(CE_CONT,
		    "%s: update now ok\n", vhc->vhc_vhcache_filename);
		vhc->vhc_flags &= ~MDI_VHC_VHCACHE_FLUSH_ERROR;
	}
	mutex_exit(&vhc->vhc_lock);

	return (rv);
}

/*
 * Call flush_vhcache() to flush the vhci cache at the scheduled time.
 * Exits itself if left idle for the idle timeout period.
 */
static void
vhcache_flush_thread(void *arg)
{
	mdi_vhci_config_t *vhc = (mdi_vhci_config_t *)arg;
	clock_t idle_time, quit_at_ticks;
	callb_cpr_t cprinfo;

	/* number of seconds to sleep idle before exiting */
	idle_time = mdi_vhcache_flush_daemon_idle_time * TICKS_PER_SECOND;

	CALLB_CPR_INIT(&cprinfo, &vhc->vhc_lock, callb_generic_cpr,
	    "mdi_vhcache_flush");
	mutex_enter(&vhc->vhc_lock);
	for (; ; ) {
		while (!(vhc->vhc_flags & MDI_VHC_EXIT) &&
		    (vhc->vhc_flags & MDI_VHC_VHCACHE_DIRTY)) {
			if (ddi_get_lbolt() < vhc->vhc_flush_at_ticks) {
				CALLB_CPR_SAFE_BEGIN(&cprinfo);
				(void) cv_timedwait(&vhc->vhc_cv,
				    &vhc->vhc_lock, vhc->vhc_flush_at_ticks);
				CALLB_CPR_SAFE_END(&cprinfo, &vhc->vhc_lock);
			} else {
				vhc->vhc_flags &= ~MDI_VHC_VHCACHE_DIRTY;
				mutex_exit(&vhc->vhc_lock);

				if (flush_vhcache(vhc, 0) != MDI_SUCCESS)
					vhcache_dirty(vhc);

				mutex_enter(&vhc->vhc_lock);
			}
		}

		quit_at_ticks = ddi_get_lbolt() + idle_time;

		while (!(vhc->vhc_flags & MDI_VHC_EXIT) &&
		    !(vhc->vhc_flags & MDI_VHC_VHCACHE_DIRTY) &&
		    ddi_get_lbolt() < quit_at_ticks) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			(void) cv_timedwait(&vhc->vhc_cv, &vhc->vhc_lock,
			    quit_at_ticks);
			CALLB_CPR_SAFE_END(&cprinfo, &vhc->vhc_lock);
		}

		if ((vhc->vhc_flags & MDI_VHC_EXIT) ||
		    !(vhc->vhc_flags & MDI_VHC_VHCACHE_DIRTY))
			goto out;
	}

out:
	vhc->vhc_flags &= ~MDI_VHC_VHCACHE_FLUSH_THREAD;
	/* CALLB_CPR_EXIT releases the vhc->vhc_lock */
	CALLB_CPR_EXIT(&cprinfo);
}

/*
 * Make vhci cache dirty and schedule flushing by vhcache flush thread.
 */
static void
vhcache_dirty(mdi_vhci_config_t *vhc)
{
	mdi_vhci_cache_t *vhcache = &vhc->vhc_vhcache;
	int create_thread;

	rw_enter(&vhcache->vhcache_lock, RW_READER);
	/* do not flush cache until the cache is fully built */
	if (!(vhcache->vhcache_flags & MDI_VHCI_CACHE_SETUP_DONE)) {
		rw_exit(&vhcache->vhcache_lock);
		return;
	}
	rw_exit(&vhcache->vhcache_lock);

	mutex_enter(&vhc->vhc_lock);
	if (vhc->vhc_flags & MDI_VHC_READONLY_FS) {
		mutex_exit(&vhc->vhc_lock);
		return;
	}

	vhc->vhc_flags |= MDI_VHC_VHCACHE_DIRTY;
	vhc->vhc_flush_at_ticks = ddi_get_lbolt() +
	    mdi_vhcache_flush_delay * TICKS_PER_SECOND;
	if (vhc->vhc_flags & MDI_VHC_VHCACHE_FLUSH_THREAD) {
		cv_broadcast(&vhc->vhc_cv);
		create_thread = 0;
	} else {
		vhc->vhc_flags |= MDI_VHC_VHCACHE_FLUSH_THREAD;
		create_thread = 1;
	}
	mutex_exit(&vhc->vhc_lock);

	if (create_thread)
		(void) thread_create(NULL, 0, vhcache_flush_thread, vhc,
		    0, &p0, TS_RUN, minclsyspri);
}

/*
 * phci bus config structure - one for for each phci bus config operation that
 * we initiate on behalf of a vhci.
 */
typedef struct mdi_phci_bus_config_s {
	char *phbc_phci_path;
	struct mdi_vhci_bus_config_s *phbc_vhbusconfig;	/* vhci bus config */
	struct mdi_phci_bus_config_s *phbc_next;
} mdi_phci_bus_config_t;

/* vhci bus config structure - one for each vhci bus config operation */
typedef struct mdi_vhci_bus_config_s {
	ddi_bus_config_op_t vhbc_op;	/* bus config op */
	major_t vhbc_op_major;		/* bus config op major */
	uint_t vhbc_op_flags;		/* bus config op flags */
	kmutex_t vhbc_lock;
	kcondvar_t vhbc_cv;
	int vhbc_thr_count;
} mdi_vhci_bus_config_t;

/*
 * bus config the specified phci
 */
static void
bus_config_phci(void *arg)
{
	mdi_phci_bus_config_t *phbc = (mdi_phci_bus_config_t *)arg;
	mdi_vhci_bus_config_t *vhbc = phbc->phbc_vhbusconfig;
	dev_info_t *ph_dip;

	/*
	 * first configure all path components upto phci and then configure
	 * the phci children.
	 */
	if ((ph_dip = e_ddi_hold_devi_by_path(phbc->phbc_phci_path, 0))
	    != NULL) {
		if (vhbc->vhbc_op == BUS_CONFIG_DRIVER ||
		    vhbc->vhbc_op == BUS_UNCONFIG_DRIVER) {
			(void) ndi_devi_config_driver(ph_dip,
			    vhbc->vhbc_op_flags,
			    vhbc->vhbc_op_major);
		} else
			(void) ndi_devi_config(ph_dip,
			    vhbc->vhbc_op_flags);

		/* release the hold that e_ddi_hold_devi_by_path() placed */
		ndi_rele_devi(ph_dip);
	}

	kmem_free(phbc->phbc_phci_path, strlen(phbc->phbc_phci_path) + 1);
	kmem_free(phbc, sizeof (*phbc));

	mutex_enter(&vhbc->vhbc_lock);
	vhbc->vhbc_thr_count--;
	if (vhbc->vhbc_thr_count == 0)
		cv_broadcast(&vhbc->vhbc_cv);
	mutex_exit(&vhbc->vhbc_lock);
}

/*
 * Bus config all phcis associated with the vhci in parallel.
 * op must be BUS_CONFIG_DRIVER or BUS_CONFIG_ALL.
 */
static void
bus_config_all_phcis(mdi_vhci_cache_t *vhcache, uint_t flags,
    ddi_bus_config_op_t op, major_t maj)
{
	mdi_phci_bus_config_t *phbc_head = NULL, *phbc, *phbc_next;
	mdi_vhci_bus_config_t *vhbc;
	mdi_vhcache_phci_t *cphci;

	rw_enter(&vhcache->vhcache_lock, RW_READER);
	if (vhcache->vhcache_phci_head == NULL) {
		rw_exit(&vhcache->vhcache_lock);
		return;
	}

	vhbc = kmem_zalloc(sizeof (*vhbc), KM_SLEEP);

	for (cphci = vhcache->vhcache_phci_head; cphci != NULL;
	    cphci = cphci->cphci_next) {
		/* skip phcis that haven't attached before root is available */
		if (!modrootloaded && (cphci->cphci_phci == NULL))
			continue;
		phbc = kmem_zalloc(sizeof (*phbc), KM_SLEEP);
		phbc->phbc_phci_path = i_ddi_strdup(cphci->cphci_path,
		    KM_SLEEP);
		phbc->phbc_vhbusconfig = vhbc;
		phbc->phbc_next = phbc_head;
		phbc_head = phbc;
		vhbc->vhbc_thr_count++;
	}
	rw_exit(&vhcache->vhcache_lock);

	vhbc->vhbc_op = op;
	vhbc->vhbc_op_major = maj;
	vhbc->vhbc_op_flags = NDI_NO_EVENT |
	    (flags & (NDI_CONFIG_REPROBE | NDI_DRV_CONF_REPROBE));
	mutex_init(&vhbc->vhbc_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&vhbc->vhbc_cv, NULL, CV_DRIVER, NULL);

	/* now create threads to initiate bus config on all phcis in parallel */
	for (phbc = phbc_head; phbc != NULL; phbc = phbc_next) {
		phbc_next = phbc->phbc_next;
		if (mdi_mtc_off)
			bus_config_phci((void *)phbc);
		else
			(void) thread_create(NULL, 0, bus_config_phci, phbc,
			    0, &p0, TS_RUN, minclsyspri);
	}

	mutex_enter(&vhbc->vhbc_lock);
	/* wait until all threads exit */
	while (vhbc->vhbc_thr_count > 0)
		cv_wait(&vhbc->vhbc_cv, &vhbc->vhbc_lock);
	mutex_exit(&vhbc->vhbc_lock);

	mutex_destroy(&vhbc->vhbc_lock);
	cv_destroy(&vhbc->vhbc_cv);
	kmem_free(vhbc, sizeof (*vhbc));
}

/*
 * Single threaded version of bus_config_all_phcis()
 */
static void
st_bus_config_all_phcis(mdi_vhci_config_t *vhc, uint_t flags,
    ddi_bus_config_op_t op, major_t maj)
{
	mdi_vhci_cache_t *vhcache = &vhc->vhc_vhcache;

	single_threaded_vhconfig_enter(vhc);
	bus_config_all_phcis(vhcache, flags, op, maj);
	single_threaded_vhconfig_exit(vhc);
}

/*
 * Perform BUS_CONFIG_ONE on the specified child of the phci.
 * The path includes the child component in addition to the phci path.
 */
static int
bus_config_one_phci_child(char *path)
{
	dev_info_t *ph_dip, *child;
	char *devnm;
	int rv = MDI_FAILURE;

	/* extract the child component of the phci */
	devnm = strrchr(path, '/');
	*devnm++ = '\0';

	/*
	 * first configure all path components upto phci and then
	 * configure the phci child.
	 */
	if ((ph_dip = e_ddi_hold_devi_by_path(path, 0)) != NULL) {
		if (ndi_devi_config_one(ph_dip, devnm, &child, NDI_NO_EVENT) ==
		    NDI_SUCCESS) {
			/*
			 * release the hold that ndi_devi_config_one() placed
			 */
			ndi_rele_devi(child);
			rv = MDI_SUCCESS;
		}

		/* release the hold that e_ddi_hold_devi_by_path() placed */
		ndi_rele_devi(ph_dip);
	}

	devnm--;
	*devnm = '/';
	return (rv);
}

/*
 * Build a list of phci client paths for the specified vhci client.
 * The list includes only those phci client paths which aren't configured yet.
 */
static mdi_phys_path_t *
build_phclient_path_list(mdi_vhcache_client_t *cct, char *ct_name)
{
	mdi_vhcache_pathinfo_t *cpi;
	mdi_phys_path_t *pp_head = NULL, *pp_tail = NULL, *pp;
	int config_path, len;

	for (cpi = cct->cct_cpi_head; cpi != NULL; cpi = cpi->cpi_next) {
		/*
		 * include only those paths that aren't configured.
		 */
		config_path = 0;
		if (cpi->cpi_pip == NULL)
			config_path = 1;
		else {
			MDI_PI_LOCK(cpi->cpi_pip);
			if (MDI_PI_IS_INIT(cpi->cpi_pip))
				config_path = 1;
			MDI_PI_UNLOCK(cpi->cpi_pip);
		}

		if (config_path) {
			pp = kmem_alloc(sizeof (*pp), KM_SLEEP);
			len = strlen(cpi->cpi_cphci->cphci_path) +
			    strlen(ct_name) + strlen(cpi->cpi_addr) + 3;
			pp->phys_path = kmem_alloc(len, KM_SLEEP);
			(void) snprintf(pp->phys_path, len, "%s/%s@%s",
			    cpi->cpi_cphci->cphci_path, ct_name,
			    cpi->cpi_addr);
			pp->phys_path_next = NULL;

			if (pp_head == NULL)
				pp_head = pp;
			else
				pp_tail->phys_path_next = pp;
			pp_tail = pp;
		}
	}

	return (pp_head);
}

/*
 * Free the memory allocated for phci client path list.
 */
static void
free_phclient_path_list(mdi_phys_path_t *pp_head)
{
	mdi_phys_path_t *pp, *pp_next;

	for (pp = pp_head; pp != NULL; pp = pp_next) {
		pp_next = pp->phys_path_next;
		kmem_free(pp->phys_path, strlen(pp->phys_path) + 1);
		kmem_free(pp, sizeof (*pp));
	}
}

/*
 * Allocated async client structure and initialize with the specified values.
 */
static mdi_async_client_config_t *
alloc_async_client_config(char *ct_name, char *ct_addr,
    mdi_phys_path_t *pp_head, mdi_vhcache_lookup_token_t *tok)
{
	mdi_async_client_config_t *acc;

	acc = kmem_alloc(sizeof (*acc), KM_SLEEP);
	acc->acc_ct_name = i_ddi_strdup(ct_name, KM_SLEEP);
	acc->acc_ct_addr = i_ddi_strdup(ct_addr, KM_SLEEP);
	acc->acc_phclient_path_list_head = pp_head;
	init_vhcache_lookup_token(&acc->acc_token, tok);
	acc->acc_next = NULL;
	return (acc);
}

/*
 * Free the memory allocated for the async client structure and their members.
 */
static void
free_async_client_config(mdi_async_client_config_t *acc)
{
	if (acc->acc_phclient_path_list_head)
		free_phclient_path_list(acc->acc_phclient_path_list_head);
	kmem_free(acc->acc_ct_name, strlen(acc->acc_ct_name) + 1);
	kmem_free(acc->acc_ct_addr, strlen(acc->acc_ct_addr) + 1);
	kmem_free(acc, sizeof (*acc));
}

/*
 * Sort vhcache pathinfos (cpis) of the specified client.
 * All cpis which do not have MDI_CPI_HINT_PATH_DOES_NOT_EXIST
 * flag set come at the beginning of the list. All cpis which have this
 * flag set come at the end of the list.
 */
static void
sort_vhcache_paths(mdi_vhcache_client_t *cct)
{
	mdi_vhcache_pathinfo_t *cpi, *cpi_next, *cpi_head;

	cpi_head = cct->cct_cpi_head;
	cct->cct_cpi_head = cct->cct_cpi_tail = NULL;
	for (cpi = cpi_head; cpi != NULL; cpi = cpi_next) {
		cpi_next = cpi->cpi_next;
		enqueue_vhcache_pathinfo(cct, cpi);
	}
}

/*
 * Verify whether MDI_CPI_HINT_PATH_DOES_NOT_EXIST flag setting is correct for
 * every vhcache pathinfo of the specified client. If not adjust the flag
 * setting appropriately.
 *
 * Note that MDI_CPI_HINT_PATH_DOES_NOT_EXIST flag is persisted in the
 * on-disk vhci cache. So every time this flag is updated the cache must be
 * flushed.
 */
static void
adjust_sort_vhcache_paths(mdi_vhci_config_t *vhc, char *ct_name, char *ct_addr,
    mdi_vhcache_lookup_token_t *tok)
{
	mdi_vhci_cache_t *vhcache = &vhc->vhc_vhcache;
	mdi_vhcache_client_t *cct;
	mdi_vhcache_pathinfo_t *cpi;

	rw_enter(&vhcache->vhcache_lock, RW_READER);
	if ((cct = lookup_vhcache_client(vhcache, ct_name, ct_addr, tok))
	    == NULL) {
		rw_exit(&vhcache->vhcache_lock);
		return;
	}

	/*
	 * to avoid unnecessary on-disk cache updates, first check if an
	 * update is really needed. If no update is needed simply return.
	 */
	for (cpi = cct->cct_cpi_head; cpi != NULL; cpi = cpi->cpi_next) {
		if ((cpi->cpi_pip != NULL &&
		    (cpi->cpi_flags & MDI_CPI_HINT_PATH_DOES_NOT_EXIST)) ||
		    (cpi->cpi_pip == NULL &&
		    !(cpi->cpi_flags & MDI_CPI_HINT_PATH_DOES_NOT_EXIST))) {
			break;
		}
	}
	if (cpi == NULL) {
		rw_exit(&vhcache->vhcache_lock);
		return;
	}

	if (rw_tryupgrade(&vhcache->vhcache_lock) == 0) {
		rw_exit(&vhcache->vhcache_lock);
		rw_enter(&vhcache->vhcache_lock, RW_WRITER);
		if ((cct = lookup_vhcache_client(vhcache, ct_name, ct_addr,
		    tok)) == NULL) {
			rw_exit(&vhcache->vhcache_lock);
			return;
		}
	}

	for (cpi = cct->cct_cpi_head; cpi != NULL; cpi = cpi->cpi_next) {
		if (cpi->cpi_pip != NULL)
			cpi->cpi_flags &= ~MDI_CPI_HINT_PATH_DOES_NOT_EXIST;
		else
			cpi->cpi_flags |= MDI_CPI_HINT_PATH_DOES_NOT_EXIST;
	}
	sort_vhcache_paths(cct);

	rw_exit(&vhcache->vhcache_lock);
	vhcache_dirty(vhc);
}

/*
 * Configure all specified paths of the client.
 */
static void
config_client_paths_sync(mdi_vhci_config_t *vhc, char *ct_name, char *ct_addr,
    mdi_phys_path_t *pp_head, mdi_vhcache_lookup_token_t *tok)
{
	mdi_phys_path_t *pp;

	for (pp = pp_head; pp != NULL; pp = pp->phys_path_next)
		(void) bus_config_one_phci_child(pp->phys_path);
	adjust_sort_vhcache_paths(vhc, ct_name, ct_addr, tok);
}

/*
 * Dequeue elements from vhci async client config list and bus configure
 * their corresponding phci clients.
 */
static void
config_client_paths_thread(void *arg)
{
	mdi_vhci_config_t *vhc = (mdi_vhci_config_t *)arg;
	mdi_async_client_config_t *acc;
	clock_t quit_at_ticks;
	clock_t idle_time = mdi_async_config_idle_time * TICKS_PER_SECOND;
	callb_cpr_t cprinfo;

	CALLB_CPR_INIT(&cprinfo, &vhc->vhc_lock, callb_generic_cpr,
	    "mdi_config_client_paths");

	for (; ; ) {
		quit_at_ticks = ddi_get_lbolt() + idle_time;

		mutex_enter(&vhc->vhc_lock);
		while (!(vhc->vhc_flags & MDI_VHC_EXIT) &&
		    vhc->vhc_acc_list_head == NULL &&
		    ddi_get_lbolt() < quit_at_ticks) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			(void) cv_timedwait(&vhc->vhc_cv, &vhc->vhc_lock,
			    quit_at_ticks);
			CALLB_CPR_SAFE_END(&cprinfo, &vhc->vhc_lock);
		}

		if ((vhc->vhc_flags & MDI_VHC_EXIT) ||
		    vhc->vhc_acc_list_head == NULL)
			goto out;

		acc = vhc->vhc_acc_list_head;
		vhc->vhc_acc_list_head = acc->acc_next;
		if (vhc->vhc_acc_list_head == NULL)
			vhc->vhc_acc_list_tail = NULL;
		vhc->vhc_acc_count--;
		mutex_exit(&vhc->vhc_lock);

		config_client_paths_sync(vhc, acc->acc_ct_name,
		    acc->acc_ct_addr, acc->acc_phclient_path_list_head,
		    &acc->acc_token);

		free_async_client_config(acc);
	}

out:
	vhc->vhc_acc_thrcount--;
	/* CALLB_CPR_EXIT releases the vhc->vhc_lock */
	CALLB_CPR_EXIT(&cprinfo);
}

/*
 * Arrange for all the phci client paths (pp_head) for the specified client
 * to be bus configured asynchronously by a thread.
 */
static void
config_client_paths_async(mdi_vhci_config_t *vhc, char *ct_name, char *ct_addr,
    mdi_phys_path_t *pp_head, mdi_vhcache_lookup_token_t *tok)
{
	mdi_async_client_config_t *acc, *newacc;
	int create_thread;

	if (pp_head == NULL)
		return;

	if (mdi_mtc_off) {
		config_client_paths_sync(vhc, ct_name, ct_addr, pp_head, tok);
		free_phclient_path_list(pp_head);
		return;
	}

	newacc = alloc_async_client_config(ct_name, ct_addr, pp_head, tok);
	ASSERT(newacc);

	mutex_enter(&vhc->vhc_lock);
	for (acc = vhc->vhc_acc_list_head; acc != NULL; acc = acc->acc_next) {
		if (strcmp(ct_name, acc->acc_ct_name) == 0 &&
		    strcmp(ct_addr, acc->acc_ct_addr) == 0) {
			free_async_client_config(newacc);
			mutex_exit(&vhc->vhc_lock);
			return;
		}
	}

	if (vhc->vhc_acc_list_head == NULL)
		vhc->vhc_acc_list_head = newacc;
	else
		vhc->vhc_acc_list_tail->acc_next = newacc;
	vhc->vhc_acc_list_tail = newacc;
	vhc->vhc_acc_count++;
	if (vhc->vhc_acc_count <= vhc->vhc_acc_thrcount) {
		cv_broadcast(&vhc->vhc_cv);
		create_thread = 0;
	} else {
		vhc->vhc_acc_thrcount++;
		create_thread = 1;
	}
	mutex_exit(&vhc->vhc_lock);

	if (create_thread)
		(void) thread_create(NULL, 0, config_client_paths_thread, vhc,
		    0, &p0, TS_RUN, minclsyspri);
}

/*
 * Return number of online paths for the specified client.
 */
static int
nonline_paths(mdi_vhcache_client_t *cct)
{
	mdi_vhcache_pathinfo_t *cpi;
	int online_count = 0;

	for (cpi = cct->cct_cpi_head; cpi != NULL; cpi = cpi->cpi_next) {
		if (cpi->cpi_pip != NULL) {
			MDI_PI_LOCK(cpi->cpi_pip);
			if (cpi->cpi_pip->pi_state == MDI_PATHINFO_STATE_ONLINE)
				online_count++;
			MDI_PI_UNLOCK(cpi->cpi_pip);
		}
	}

	return (online_count);
}

/*
 * Bus configure all paths for the specified vhci client.
 * If at least one path for the client is already online, the remaining paths
 * will be configured asynchronously. Otherwise, it synchronously configures
 * the paths until at least one path is online and then rest of the paths
 * will be configured asynchronously.
 */
static void
config_client_paths(mdi_vhci_config_t *vhc, char *ct_name, char *ct_addr)
{
	mdi_vhci_cache_t *vhcache = &vhc->vhc_vhcache;
	mdi_phys_path_t *pp_head, *pp;
	mdi_vhcache_client_t *cct;
	mdi_vhcache_lookup_token_t tok;

	ASSERT(RW_LOCK_HELD(&vhcache->vhcache_lock));

	init_vhcache_lookup_token(&tok, NULL);

	if (ct_name == NULL || ct_addr == NULL ||
	    (cct = lookup_vhcache_client(vhcache, ct_name, ct_addr, &tok))
	    == NULL ||
	    (pp_head = build_phclient_path_list(cct, ct_name)) == NULL) {
		rw_exit(&vhcache->vhcache_lock);
		return;
	}

	/* if at least one path is online, configure the rest asynchronously */
	if (nonline_paths(cct) > 0) {
		rw_exit(&vhcache->vhcache_lock);
		config_client_paths_async(vhc, ct_name, ct_addr, pp_head, &tok);
		return;
	}

	rw_exit(&vhcache->vhcache_lock);

	for (pp = pp_head; pp != NULL; pp = pp->phys_path_next) {
		if (bus_config_one_phci_child(pp->phys_path) == MDI_SUCCESS) {
			rw_enter(&vhcache->vhcache_lock, RW_READER);

			if ((cct = lookup_vhcache_client(vhcache, ct_name,
			    ct_addr, &tok)) == NULL) {
				rw_exit(&vhcache->vhcache_lock);
				goto out;
			}

			if (nonline_paths(cct) > 0 &&
			    pp->phys_path_next != NULL) {
				rw_exit(&vhcache->vhcache_lock);
				config_client_paths_async(vhc, ct_name, ct_addr,
				    pp->phys_path_next, &tok);
				pp->phys_path_next = NULL;
				goto out;
			}

			rw_exit(&vhcache->vhcache_lock);
		}
	}

	adjust_sort_vhcache_paths(vhc, ct_name, ct_addr, &tok);
out:
	free_phclient_path_list(pp_head);
}

static void
single_threaded_vhconfig_enter(mdi_vhci_config_t *vhc)
{
	mutex_enter(&vhc->vhc_lock);
	while (vhc->vhc_flags & MDI_VHC_SINGLE_THREADED)
		cv_wait(&vhc->vhc_cv, &vhc->vhc_lock);
	vhc->vhc_flags |= MDI_VHC_SINGLE_THREADED;
	mutex_exit(&vhc->vhc_lock);
}

static void
single_threaded_vhconfig_exit(mdi_vhci_config_t *vhc)
{
	mutex_enter(&vhc->vhc_lock);
	vhc->vhc_flags &= ~MDI_VHC_SINGLE_THREADED;
	cv_broadcast(&vhc->vhc_cv);
	mutex_exit(&vhc->vhc_lock);
}

typedef struct mdi_phci_driver_info {
	char	*phdriver_name;	/* name of the phci driver */

	/* set to non zero if the phci driver supports root device */
	int	phdriver_root_support;
} mdi_phci_driver_info_t;

/*
 * vhci class and root support capability of a phci driver can be
 * specified using ddi-vhci-class and ddi-no-root-support properties in the
 * phci driver.conf file. The built-in tables below contain this information
 * for those phci drivers whose driver.conf files don't yet contain this info.
 *
 * All phci drivers expect iscsi have root device support.
 */
static mdi_phci_driver_info_t scsi_phci_driver_list[] = {
	{ "fp", 1 },
	{ "iscsi", 0 },
	{ "ibsrp", 1 }
	};

static mdi_phci_driver_info_t ib_phci_driver_list[] = { "tavor", 1 };

static void *
mdi_realloc(void *old_ptr, size_t old_size, size_t new_size)
{
	void *new_ptr;

	new_ptr = kmem_zalloc(new_size, KM_SLEEP);
	if (old_ptr) {
		bcopy(old_ptr, new_ptr, MIN(old_size, new_size));
		kmem_free(old_ptr, old_size);
	}
	return (new_ptr);
}

static void
add_to_phci_list(char ***driver_list, int **root_support_list,
    int *cur_elements, int *max_elements, char *driver_name, int root_support)
{
	ASSERT(*cur_elements <= *max_elements);
	if (*cur_elements == *max_elements) {
		*max_elements += 10;
		*driver_list = mdi_realloc(*driver_list,
		    sizeof (char *) * (*cur_elements),
		    sizeof (char *) * (*max_elements));
		*root_support_list = mdi_realloc(*root_support_list,
		    sizeof (int) * (*cur_elements),
		    sizeof (int) * (*max_elements));
	}
	(*driver_list)[*cur_elements] = i_ddi_strdup(driver_name, KM_SLEEP);
	(*root_support_list)[*cur_elements] = root_support;
	(*cur_elements)++;
}

static void
get_phci_driver_list(char *vhci_class, char ***driver_list,
    int **root_support_list, int *cur_elements, int *max_elements)
{
	mdi_phci_driver_info_t	*st_driver_list, *p;
	int		st_ndrivers, root_support, i, j, driver_conf_count;
	major_t		m;
	struct devnames	*dnp;
	ddi_prop_t	*propp;

	*driver_list = NULL;
	*root_support_list = NULL;
	*cur_elements = 0;
	*max_elements = 0;

	/* add the phci drivers derived from the phci driver.conf files */
	for (m = 0; m < devcnt; m++) {
		dnp = &devnamesp[m];

		if (dnp->dn_flags & DN_PHCI_DRIVER) {
			LOCK_DEV_OPS(&dnp->dn_lock);
			if (dnp->dn_global_prop_ptr != NULL &&
			    (propp = i_ddi_prop_search(DDI_DEV_T_ANY,
			    DDI_VHCI_CLASS, DDI_PROP_TYPE_STRING,
			    &dnp->dn_global_prop_ptr->prop_list)) != NULL &&
			    strcmp(propp->prop_val, vhci_class) == 0) {

				root_support = (i_ddi_prop_search(DDI_DEV_T_ANY,
				    DDI_NO_ROOT_SUPPORT, DDI_PROP_TYPE_INT,
				    &dnp->dn_global_prop_ptr->prop_list)
				    == NULL) ? 1 : 0;

				add_to_phci_list(driver_list, root_support_list,
				    cur_elements, max_elements, dnp->dn_name,
				    root_support);

				UNLOCK_DEV_OPS(&dnp->dn_lock);
			} else
				UNLOCK_DEV_OPS(&dnp->dn_lock);
		}
	}

	driver_conf_count = *cur_elements;

	/* add the phci drivers specified in the built-in tables */
	if (strcmp(vhci_class, MDI_HCI_CLASS_SCSI) == 0) {
		st_driver_list = scsi_phci_driver_list;
		st_ndrivers = sizeof (scsi_phci_driver_list) /
		    sizeof (mdi_phci_driver_info_t);
	} else if (strcmp(vhci_class, MDI_HCI_CLASS_IB) == 0) {
		st_driver_list = ib_phci_driver_list;
		st_ndrivers = sizeof (ib_phci_driver_list) /
		    sizeof (mdi_phci_driver_info_t);
	} else {
		st_driver_list = NULL;
		st_ndrivers = 0;
	}

	for (i = 0, p = st_driver_list; i < st_ndrivers; i++, p++) {
		/* add this phci driver if not already added before */
		for (j = 0; j < driver_conf_count; j++) {
			if (strcmp((*driver_list)[j], p->phdriver_name) == 0)
				break;
		}
		if (j == driver_conf_count) {
			add_to_phci_list(driver_list, root_support_list,
			    cur_elements, max_elements, p->phdriver_name,
			    p->phdriver_root_support);
		}
	}
}

/*
 * Attach the phci driver instances associated with the specified vhci class.
 * If root is mounted attach all phci driver instances.
 * If root is not mounted, attach the instances of only those phci
 * drivers that have the root support.
 */
static void
attach_phci_drivers(char *vhci_class)
{
	char	**driver_list, **p;
	int	*root_support_list;
	int	cur_elements, max_elements, i;
	major_t	m;

	get_phci_driver_list(vhci_class, &driver_list, &root_support_list,
	    &cur_elements, &max_elements);

	for (i = 0; i < cur_elements; i++) {
		if (modrootloaded || root_support_list[i]) {
			m = ddi_name_to_major(driver_list[i]);
			if (m != DDI_MAJOR_T_NONE &&
			    ddi_hold_installed_driver(m))
				ddi_rele_driver(m);
		}
	}

	if (driver_list) {
		for (i = 0, p = driver_list; i < cur_elements; i++, p++)
			kmem_free(*p, strlen(*p) + 1);
		kmem_free(driver_list, sizeof (char *) * max_elements);
		kmem_free(root_support_list, sizeof (int) * max_elements);
	}
}

/*
 * Build vhci cache:
 *
 * Attach phci driver instances and then drive BUS_CONFIG_ALL on
 * the phci driver instances. During this process the cache gets built.
 *
 * Cache is built fully if the root is mounted.
 * If the root is not mounted, phci drivers that do not have root support
 * are not attached. As a result the cache is built partially. The entries
 * in the cache reflect only those phci drivers that have root support.
 */
static int
build_vhci_cache(mdi_vhci_t *vh)
{
	mdi_vhci_config_t *vhc = vh->vh_config;
	mdi_vhci_cache_t *vhcache = &vhc->vhc_vhcache;

	single_threaded_vhconfig_enter(vhc);

	rw_enter(&vhcache->vhcache_lock, RW_READER);
	if (vhcache->vhcache_flags & MDI_VHCI_CACHE_SETUP_DONE) {
		rw_exit(&vhcache->vhcache_lock);
		single_threaded_vhconfig_exit(vhc);
		return (0);
	}
	rw_exit(&vhcache->vhcache_lock);

	attach_phci_drivers(vh->vh_class);
	bus_config_all_phcis(vhcache, NDI_DRV_CONF_REPROBE | NDI_NO_EVENT,
	    BUS_CONFIG_ALL, DDI_MAJOR_T_NONE);

	rw_enter(&vhcache->vhcache_lock, RW_WRITER);
	vhcache->vhcache_flags |= MDI_VHCI_CACHE_SETUP_DONE;
	rw_exit(&vhcache->vhcache_lock);

	single_threaded_vhconfig_exit(vhc);
	vhcache_dirty(vhc);
	return (1);
}

/*
 * Determine if discovery of paths is needed.
 */
static int
vhcache_do_discovery(mdi_vhci_config_t *vhc)
{
	int rv = 1;

	mutex_enter(&vhc->vhc_lock);
	if (i_ddi_io_initialized() == 0) {
		if (vhc->vhc_path_discovery_boot > 0) {
			vhc->vhc_path_discovery_boot--;
			goto out;
		}
	} else {
		if (vhc->vhc_path_discovery_postboot > 0) {
			vhc->vhc_path_discovery_postboot--;
			goto out;
		}
	}

	/*
	 * Do full path discovery at most once per mdi_path_discovery_interval.
	 * This is to avoid a series of full path discoveries when opening
	 * stale /dev/[r]dsk links.
	 */
	if (mdi_path_discovery_interval != -1 &&
	    ddi_get_lbolt64() >= vhc->vhc_path_discovery_cutoff_time)
		goto out;

	rv = 0;
out:
	mutex_exit(&vhc->vhc_lock);
	return (rv);
}

/*
 * Discover all paths:
 *
 * Attach phci driver instances and then drive BUS_CONFIG_ALL on all the phci
 * driver instances. During this process all paths will be discovered.
 */
static int
vhcache_discover_paths(mdi_vhci_t *vh)
{
	mdi_vhci_config_t *vhc = vh->vh_config;
	mdi_vhci_cache_t *vhcache = &vhc->vhc_vhcache;
	int rv = 0;

	single_threaded_vhconfig_enter(vhc);

	if (vhcache_do_discovery(vhc)) {
		attach_phci_drivers(vh->vh_class);
		bus_config_all_phcis(vhcache, NDI_DRV_CONF_REPROBE |
		    NDI_NO_EVENT, BUS_CONFIG_ALL, DDI_MAJOR_T_NONE);

		mutex_enter(&vhc->vhc_lock);
		vhc->vhc_path_discovery_cutoff_time = ddi_get_lbolt64() +
		    mdi_path_discovery_interval * TICKS_PER_SECOND;
		mutex_exit(&vhc->vhc_lock);
		rv = 1;
	}

	single_threaded_vhconfig_exit(vhc);
	return (rv);
}

/*
 * Generic vhci bus config implementation:
 *
 * Parameters
 *	vdip	vhci dip
 *	flags	bus config flags
 *	op	bus config operation
 *	The remaining parameters are bus config operation specific
 *
 * for BUS_CONFIG_ONE
 *	arg	pointer to name@addr
 *	child	upon successful return from this function, *child will be
 *		set to the configured and held devinfo child node of vdip.
 *	ct_addr	pointer to client address (i.e. GUID)
 *
 * for BUS_CONFIG_DRIVER
 *	arg	major number of the driver
 *	child and ct_addr parameters are ignored
 *
 * for BUS_CONFIG_ALL
 *	arg, child, and ct_addr parameters are ignored
 *
 * Note that for the rest of the bus config operations, this function simply
 * calls the framework provided default bus config routine.
 */
int
mdi_vhci_bus_config(dev_info_t *vdip, uint_t flags, ddi_bus_config_op_t op,
    void *arg, dev_info_t **child, char *ct_addr)
{
	mdi_vhci_t *vh = i_devi_get_vhci(vdip);
	mdi_vhci_config_t *vhc = vh->vh_config;
	mdi_vhci_cache_t *vhcache = &vhc->vhc_vhcache;
	int rv = 0;
	int params_valid = 0;
	char *cp;

	/*
	 * To bus config vhcis we relay operation, possibly using another
	 * thread, to phcis. The phci driver then interacts with MDI to cause
	 * vhci child nodes to be enumerated under the vhci node.  Adding a
	 * vhci child requires an ndi_devi_enter of the vhci. Since another
	 * thread may be adding the child, to avoid deadlock we can't wait
	 * for the relayed operations to complete if we have already entered
	 * the vhci node.
	 */
	if (DEVI_BUSY_OWNED(vdip)) {
		MDI_DEBUG(2, (MDI_NOTE, vdip,
		    "vhci dip is busy owned %p", (void *)vdip));
		goto default_bus_config;
	}

	rw_enter(&vhcache->vhcache_lock, RW_READER);
	if (!(vhcache->vhcache_flags & MDI_VHCI_CACHE_SETUP_DONE)) {
		rw_exit(&vhcache->vhcache_lock);
		rv = build_vhci_cache(vh);
		rw_enter(&vhcache->vhcache_lock, RW_READER);
	}

	switch (op) {
	case BUS_CONFIG_ONE:
		if (arg != NULL && ct_addr != NULL) {
			/* extract node name */
			cp = (char *)arg;
			while (*cp != '\0' && *cp != '@')
				cp++;
			if (*cp == '@') {
				params_valid = 1;
				*cp = '\0';
				config_client_paths(vhc, (char *)arg, ct_addr);
				/* config_client_paths() releases cache_lock */
				*cp = '@';
				break;
			}
		}

		rw_exit(&vhcache->vhcache_lock);
		break;

	case BUS_CONFIG_DRIVER:
		rw_exit(&vhcache->vhcache_lock);
		if (rv == 0)
			st_bus_config_all_phcis(vhc, flags, op,
			    (major_t)(uintptr_t)arg);
		break;

	case BUS_CONFIG_ALL:
		rw_exit(&vhcache->vhcache_lock);
		if (rv == 0)
			st_bus_config_all_phcis(vhc, flags, op, -1);
		break;

	default:
		rw_exit(&vhcache->vhcache_lock);
		break;
	}


default_bus_config:
	/*
	 * All requested child nodes are enumerated under the vhci.
	 * Now configure them.
	 */
	if (ndi_busop_bus_config(vdip, flags, op, arg, child, 0) ==
	    NDI_SUCCESS) {
		return (MDI_SUCCESS);
	} else if (op == BUS_CONFIG_ONE && rv == 0 && params_valid) {
		/* discover all paths and try configuring again */
		if (vhcache_discover_paths(vh) &&
		    ndi_busop_bus_config(vdip, flags, op, arg, child, 0) ==
		    NDI_SUCCESS)
			return (MDI_SUCCESS);
	}

	return (MDI_FAILURE);
}

/*
 * Read the on-disk vhci cache into an nvlist for the specified vhci class.
 */
static nvlist_t *
read_on_disk_vhci_cache(char *vhci_class)
{
	nvlist_t *nvl;
	int err;
	char *filename;

	filename = vhclass2vhcache_filename(vhci_class);

	if ((err = fread_nvlist(filename, &nvl)) == 0) {
		kmem_free(filename, strlen(filename) + 1);
		return (nvl);
	} else if (err == EIO)
		cmn_err(CE_WARN, "%s: I/O error, will recreate", filename);
	else if (err == EINVAL)
		cmn_err(CE_WARN,
		    "%s: data file corrupted, will recreate", filename);

	kmem_free(filename, strlen(filename) + 1);
	return (NULL);
}

/*
 * Read on-disk vhci cache into nvlists for all vhci classes.
 * Called during booting by i_ddi_read_devices_files().
 */
void
mdi_read_devices_files(void)
{
	int i;

	for (i = 0; i < N_VHCI_CLASSES; i++)
		vhcache_nvl[i] = read_on_disk_vhci_cache(vhci_class_list[i]);
}

/*
 * Remove all stale entries from vhci cache.
 */
static void
clean_vhcache(mdi_vhci_config_t *vhc)
{
	mdi_vhci_cache_t	*vhcache = &vhc->vhc_vhcache;
	mdi_vhcache_phci_t	*phci, *nxt_phci;
	mdi_vhcache_client_t	*client, *nxt_client;
	mdi_vhcache_pathinfo_t	*path, *nxt_path;

	rw_enter(&vhcache->vhcache_lock, RW_WRITER);

	client = vhcache->vhcache_client_head;
	vhcache->vhcache_client_head = vhcache->vhcache_client_tail = NULL;
	for ( ; client != NULL; client = nxt_client) {
		nxt_client = client->cct_next;

		path = client->cct_cpi_head;
		client->cct_cpi_head = client->cct_cpi_tail = NULL;
		for ( ; path != NULL; path = nxt_path) {
			nxt_path = path->cpi_next;
			if ((path->cpi_cphci->cphci_phci != NULL) &&
			    (path->cpi_pip != NULL)) {
				enqueue_tail_vhcache_pathinfo(client, path);
			} else if (path->cpi_pip != NULL) {
				/* Not valid to have a path without a phci. */
				free_vhcache_pathinfo(path);
			}
		}

		if (client->cct_cpi_head != NULL)
			enqueue_vhcache_client(vhcache, client);
		else {
			(void) mod_hash_destroy(vhcache->vhcache_client_hash,
			    (mod_hash_key_t)client->cct_name_addr);
			free_vhcache_client(client);
		}
	}

	phci = vhcache->vhcache_phci_head;
	vhcache->vhcache_phci_head = vhcache->vhcache_phci_tail = NULL;
	for ( ; phci != NULL; phci = nxt_phci) {

		nxt_phci = phci->cphci_next;
		if (phci->cphci_phci != NULL)
			enqueue_vhcache_phci(vhcache, phci);
		else
			free_vhcache_phci(phci);
	}

	vhcache->vhcache_clean_time = ddi_get_lbolt64();
	rw_exit(&vhcache->vhcache_lock);
	vhcache_dirty(vhc);
}

/*
 * Remove all stale entries from vhci cache.
 * Called by i_ddi_clean_devices_files() during the execution of devfsadm -C
 */
void
mdi_clean_vhcache(void)
{
	mdi_vhci_t *vh;

	mutex_enter(&mdi_mutex);
	for (vh = mdi_vhci_head; vh != NULL; vh = vh->vh_next) {
		vh->vh_refcnt++;
		mutex_exit(&mdi_mutex);
		clean_vhcache(vh->vh_config);
		mutex_enter(&mdi_mutex);
		vh->vh_refcnt--;
	}
	mutex_exit(&mdi_mutex);
}

/*
 * mdi_vhci_walk_clients():
 *		Walker routine to traverse client dev_info nodes
 * ddi_walk_devs(ddi_get_child(vdip), f, arg) returns the entire tree
 * below the client, including nexus devices, which we dont want.
 * So we just traverse the immediate siblings, starting from 1st client.
 */
void
mdi_vhci_walk_clients(dev_info_t *vdip,
    int (*f)(dev_info_t *, void *), void *arg)
{
	mdi_vhci_t	*vh = i_devi_get_vhci(vdip);
	dev_info_t	*cdip;
	mdi_client_t	*ct;

	MDI_VHCI_CLIENT_LOCK(vh);
	cdip = ddi_get_child(vdip);
	while (cdip) {
		ct = i_devi_get_client(cdip);
		MDI_CLIENT_LOCK(ct);

		if (((*f)(cdip, arg)) == DDI_WALK_CONTINUE)
			cdip = ddi_get_next_sibling(cdip);
		else
			cdip = NULL;

		MDI_CLIENT_UNLOCK(ct);
	}
	MDI_VHCI_CLIENT_UNLOCK(vh);
}

/*
 * mdi_vhci_walk_phcis():
 *		Walker routine to traverse phci dev_info nodes
 */
void
mdi_vhci_walk_phcis(dev_info_t *vdip,
    int (*f)(dev_info_t *, void *), void *arg)
{
	mdi_vhci_t	*vh = i_devi_get_vhci(vdip);
	mdi_phci_t	*ph, *next;

	MDI_VHCI_PHCI_LOCK(vh);
	ph = vh->vh_phci_head;
	while (ph) {
		MDI_PHCI_LOCK(ph);

		if (((*f)(ph->ph_dip, arg)) == DDI_WALK_CONTINUE)
			next = ph->ph_next;
		else
			next = NULL;

		MDI_PHCI_UNLOCK(ph);
		ph = next;
	}
	MDI_VHCI_PHCI_UNLOCK(vh);
}


/*
 * mdi_walk_vhcis():
 *		Walker routine to traverse vhci dev_info nodes
 */
void
mdi_walk_vhcis(int (*f)(dev_info_t *, void *), void *arg)
{
	mdi_vhci_t	*vh = NULL;

	mutex_enter(&mdi_mutex);
	/*
	 * Scan for already registered vhci
	 */
	for (vh = mdi_vhci_head; vh != NULL; vh = vh->vh_next) {
		vh->vh_refcnt++;
		mutex_exit(&mdi_mutex);
		if (((*f)(vh->vh_dip, arg)) != DDI_WALK_CONTINUE) {
			mutex_enter(&mdi_mutex);
			vh->vh_refcnt--;
			break;
		} else {
			mutex_enter(&mdi_mutex);
			vh->vh_refcnt--;
		}
	}

	mutex_exit(&mdi_mutex);
}

/*
 * i_mdi_log_sysevent():
 *		Logs events for pickup by syseventd
 */
static void
i_mdi_log_sysevent(dev_info_t *dip, char *ph_vh_class, char *subclass)
{
	char		*path_name;
	nvlist_t	*attr_list;

	if (nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE,
	    KM_SLEEP) != DDI_SUCCESS) {
		goto alloc_failed;
	}

	path_name = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, path_name);

	if (nvlist_add_string(attr_list, DDI_DRIVER_NAME,
	    ddi_driver_name(dip)) != DDI_SUCCESS) {
		goto error;
	}

	if (nvlist_add_int32(attr_list, DDI_DRIVER_MAJOR,
	    (int32_t)ddi_driver_major(dip)) != DDI_SUCCESS) {
		goto error;
	}

	if (nvlist_add_int32(attr_list, DDI_INSTANCE,
	    (int32_t)ddi_get_instance(dip)) != DDI_SUCCESS) {
		goto error;
	}

	if (nvlist_add_string(attr_list, DDI_PATHNAME,
	    path_name) != DDI_SUCCESS) {
		goto error;
	}

	if (nvlist_add_string(attr_list, DDI_CLASS,
	    ph_vh_class) != DDI_SUCCESS) {
		goto error;
	}

	(void) ddi_log_sysevent(dip, DDI_VENDOR_SUNW, EC_DDI, subclass,
	    attr_list, NULL, DDI_SLEEP);

error:
	kmem_free(path_name, MAXPATHLEN);
	nvlist_free(attr_list);
	return;

alloc_failed:
	MDI_DEBUG(1, (MDI_WARN, dip, "!unable to send sysevent"));
}

char **
mdi_get_phci_driver_list(char *vhci_class, int	*ndrivers)
{
	char	**driver_list, **ret_driver_list = NULL;
	int	*root_support_list;
	int	cur_elements, max_elements;

	get_phci_driver_list(vhci_class, &driver_list, &root_support_list,
	    &cur_elements, &max_elements);


	if (driver_list) {
		kmem_free(root_support_list, sizeof (int) * max_elements);
		ret_driver_list = mdi_realloc(driver_list, sizeof (char *)
		    * max_elements, sizeof (char *) * cur_elements);
	}
	*ndrivers = cur_elements;

	return (ret_driver_list);

}

void
mdi_free_phci_driver_list(char **driver_list, int ndrivers)
{
	char	**p;
	int	i;

	if (driver_list) {
		for (i = 0, p = driver_list; i < ndrivers; i++, p++)
			kmem_free(*p, strlen(*p) + 1);
		kmem_free(driver_list, sizeof (char *) * ndrivers);
	}
}

/*
 * mdi_is_dev_supported():
 *		function called by pHCI bus config operation to determine if a
 *		device should be represented as a child of the vHCI or the
 *		pHCI.  This decision is made by the vHCI, using cinfo idenity
 *		information passed by the pHCI - specifics of the cinfo
 *		representation are by agreement between the pHCI and vHCI.
 * Return Values:
 *		MDI_SUCCESS
 *		MDI_FAILURE
 */
int
mdi_is_dev_supported(char *class, dev_info_t *pdip, void *cinfo)
{
	mdi_vhci_t	*vh;

	ASSERT(class && pdip);

	/*
	 * For dev_supported, mdi_phci_register() must have established pdip as
	 * a pHCI.
	 *
	 * NOTE: mdi_phci_register() does "mpxio-disable" processing, and
	 * MDI_PHCI(pdip) will return false if mpxio is disabled.
	 */
	if (!MDI_PHCI(pdip))
		return (MDI_FAILURE);

	/* Return MDI_FAILURE if vHCI does not support asking the question. */
	vh = (mdi_vhci_t *)i_mdi_vhci_class2vhci(class);
	if ((vh == NULL) || (vh->vh_ops->vo_is_dev_supported == NULL)) {
		return (MDI_FAILURE);
	}

	/* Return vHCI answer */
	return (vh->vh_ops->vo_is_dev_supported(vh->vh_dip, pdip, cinfo));
}

int
mdi_dc_return_dev_state(mdi_pathinfo_t *pip, struct devctl_iocdata *dcp)
{
	uint_t devstate = 0;
	dev_info_t *cdip;

	if ((pip == NULL) || (dcp == NULL))
		return (MDI_FAILURE);

	cdip = mdi_pi_get_client(pip);

	switch (mdi_pi_get_state(pip)) {
	case MDI_PATHINFO_STATE_INIT:
		devstate = DEVICE_DOWN;
		break;
	case MDI_PATHINFO_STATE_ONLINE:
		devstate = DEVICE_ONLINE;
		if ((cdip) && (devi_stillreferenced(cdip) == DEVI_REFERENCED))
			devstate |= DEVICE_BUSY;
		break;
	case MDI_PATHINFO_STATE_STANDBY:
		devstate = DEVICE_ONLINE;
		break;
	case MDI_PATHINFO_STATE_FAULT:
		devstate = DEVICE_DOWN;
		break;
	case MDI_PATHINFO_STATE_OFFLINE:
		devstate = DEVICE_OFFLINE;
		break;
	default:
		ASSERT(MDI_PI(pip)->pi_state);
	}

	if (copyout(&devstate, dcp->cpyout_buf, sizeof (uint_t)) != 0)
		return (MDI_FAILURE);

	return (MDI_SUCCESS);
}
