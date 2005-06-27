/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Multipath driver interface (MDI) implementation; see mdi_impl.h for a more
 * detailed discussion of the overall mpxio architecture.
 *
 * Default locking order:
 *
 * _NOTE(LOCK_ORDER(mdi_mutex, mdi_phci::ph_mutex))
 * _NOTE(LOCK_ORDER(mdi_mutex, mdi_client::ct_mutex))
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

#ifdef	DEBUG
#include <sys/debug.h>
int	mdi_debug = 1;
#define	MDI_DEBUG(level, stmnt) \
	    if (mdi_debug >= (level)) i_mdi_log stmnt
static void i_mdi_log(int, dev_info_t *, const char *fmt, ...);
#else	/* !DEBUG */
#define	MDI_DEBUG(level, stmnt)
#endif	/* DEBUG */

extern pri_t	minclsyspri;
extern int	modrootloaded;

/*
 * Global mutex:
 * Protects vHCI list and structure members, pHCI and Client lists.
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

static int		mdi_max_bus_config_threads = 100;
/*
 * To reduce unnecessary BUS_CONFIG_ALLs, do not BUS_CONFIG_ALL phcis in the
 * context of a BUS_CONFIG_ONE if a BUS_CONFIG_ALL has already been performed
 * in the last mdi_bus_config_timeout seconds.
 */
static int		mdi_bus_config_timeout = 60;	/* in seconds */

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
static void		i_mdi_pm_hold_all_phci(mdi_client_t *);
static int		i_mdi_power_all_phci(mdi_client_t *);


/*
 * Internal mdi_pathinfo node functions
 */
static int		i_mdi_pi_kstat_create(mdi_pathinfo_t *);
static void		i_mdi_pi_kstat_destroy(mdi_pathinfo_t *);

static mdi_vhci_t	*i_mdi_vhci_class2vhci(char *);
static mdi_vhci_t	*i_devi_get_vhci(dev_info_t *);
static mdi_phci_t	*i_devi_get_phci(dev_info_t *);
static void		i_mdi_phci_lock(mdi_phci_t *, mdi_pathinfo_t *);
static void		i_mdi_phci_get_client_lock(mdi_phci_t *,
			    mdi_client_t *);
static void		i_mdi_phci_unlock(mdi_phci_t *);
static mdi_pathinfo_t	*i_mdi_pi_alloc(mdi_phci_t *, char *,
			    mdi_client_t *, int);
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
			    char **, int, int);
static dev_info_t	*i_mdi_devinfo_find(mdi_vhci_t *, char *, char *);
static int		i_mdi_devinfo_remove(dev_info_t *, dev_info_t *, int);
static int		i_mdi_is_child_present(dev_info_t *, dev_info_t *);
static mdi_client_t	*i_mdi_client_alloc(mdi_vhci_t *, char *, char *, int);
static void		i_mdi_client_enlist_table(mdi_vhci_t *, mdi_client_t *);
static void		i_mdi_client_delist_table(mdi_vhci_t *, mdi_client_t *);
static mdi_client_t	*i_mdi_client_find(mdi_vhci_t *, char *);
static void		i_mdi_client_update_state(mdi_client_t *);
static int		i_mdi_client_compute_state(mdi_client_t *,
			    mdi_phci_t *);
static void		i_mdi_client_lock(mdi_client_t *, mdi_pathinfo_t *);
static void		i_mdi_client_unlock(mdi_client_t *);
static int		i_mdi_client_free(mdi_vhci_t *, mdi_client_t *);
static mdi_client_t	*i_devi_get_client(dev_info_t *);
static int		i_mdi_pi_enable_disable(dev_info_t *, dev_info_t *, int,
			int);
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

/* called once when first vhci registers with mdi */
static void
i_mdi_init()
{
	static int initialized = 0;

	if (initialized)
		return;
	initialized = 1;

	mutex_init(&mdi_mutex, NULL, MUTEX_DEFAULT, NULL);
	/*
	 * Create our taskq resources
	 */
	mdi_taskq = taskq_create("mdi_taskq", mdi_taskq_n_threads,
	    MDI_TASKQ_PRI, MDI_TASKQ_MINALLOC, MDI_TASKQ_MAXALLOC,
	    TASKQ_PREPOPULATE | TASKQ_CPR_SAFE);
	ASSERT(mdi_taskq != NULL);	/* taskq_create never fails */
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
 *	removed when clients migrate mdi_is_*() interfaces.
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

	ASSERT(vops->vo_revision == MDI_VHCI_OPS_REV);

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

		/*
		 * Store the vHCI ops vectors
		 */
		vh->vh_dip = vdip;
		vh->vh_ops = vops;

		/*
		 * other members of vh_bus_config are initialized by
		 * the above kmem_zalloc of the vhci structure.
		 */
		cv_init(&vh->vh_bus_config.vhc_cv, NULL, CV_DRIVER, NULL);

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
	mdi_phci_config_t *phc, *next_phc;

	/*
	 * Check for invalid VHCI
	 */
	if ((vh = i_devi_get_vhci(vdip)) == NULL)
		return (MDI_FAILURE);

	mutex_enter(&mdi_mutex);

	/*
	 * Scan the list of registered vHCIs for a match
	 */
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
	 * Check the pHCI and client count. All the pHCIs and clients
	 * should have been unregistered, before a vHCI can be
	 * unregistered.
	 */
	if (vh->vh_phci_count || vh->vh_client_count) {
		MDI_DEBUG(1, (CE_NOTE, NULL,
		    "!mdi_vhci_unregister: pHCI in registered state.\n"));
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

	vh->vh_ops = NULL;
	mdi_vhci_count--;
	mutex_exit(&mdi_mutex);
	DEVI(vdip)->devi_mdi_component &= ~MDI_COMPONENT_VHCI;
	DEVI(vdip)->devi_mdi_xhci = NULL;
	kmem_free(vh->vh_class, strlen(vh->vh_class)+1);
	kmem_free(vh->vh_client_table,
	    mdi_client_table_size * sizeof (struct client_hash));

	/*
	 * there must be no more tasks on the bus config taskq as the vhci
	 * driver can not be detached while bus config is in progress.
	 */
	ASSERT(vh->vh_bus_config.vhc_start_time == 0);

	if (vh->vh_bus_config.vhc_taskq != NULL)
		taskq_destroy(vh->vh_bus_config.vhc_taskq);

	for (phc = vh->vh_bus_config.vhc_phc; phc != NULL; phc = next_phc) {
		next_phc = phc->phc_next;
		kmem_free(phc, sizeof (*phc));
	}

	cv_destroy(&vh->vh_bus_config.vhc_cv);

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
	char			*pathname;

	pathname = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(pdip, pathname);

	/*
	 * Check for mpxio-disable property. Enable mpxio if the property is
	 * missing or not set to "yes".
	 * If the property is set to "yes" then emit a brief message.
	 */
	if ((ddi_prop_lookup_string(DDI_DEV_T_ANY, pdip, 0, "mpxio-disable",
	    &data) == DDI_SUCCESS)) {
		if (strcmp(data, "yes") == 0) {
			MDI_DEBUG(1, (CE_CONT, pdip,
			    "?%s (%s%d) multipath capabilities "
			    "disabled via %s.conf.\n", pathname,
			    ddi_driver_name(pdip), ddi_get_instance(pdip),
			    ddi_driver_name(pdip)));
			ddi_prop_free(data);
			kmem_free(pathname, MAXPATHLEN);
			return (MDI_FAILURE);
		}
		ddi_prop_free(data);
	}

	kmem_free(pathname, MAXPATHLEN);

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
	cv_init(&ph->ph_powerchange_cv, NULL, CV_DRIVER, NULL);

	MDI_PHCI_SET_POWER_UP(ph);
	DEVI(pdip)->devi_mdi_component |= MDI_COMPONENT_PHCI;
	DEVI(pdip)->devi_mdi_xhci = (caddr_t)ph;

	mutex_enter(&mdi_mutex);
	if (vh->vh_phci_head == NULL) {
		vh->vh_phci_head = ph;
	}
	if (vh->vh_phci_tail) {
		vh->vh_phci_tail->ph_next = ph;
	}
	vh->vh_phci_tail = ph;
	vh->vh_phci_count++;
	/* to force discovery of all phci children during busconfig */
	vh->vh_bus_config.vhc_cutoff_time = -1;
	mutex_exit(&mdi_mutex);
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

	ph = i_devi_get_phci(pdip);
	if (ph == NULL) {
		MDI_DEBUG(1, (CE_WARN, pdip,
		    "!pHCI unregister: Not a valid pHCI"));
		return (MDI_FAILURE);
	}

	vh = ph->ph_vhci;
	ASSERT(vh != NULL);
	if (vh == NULL) {
		MDI_DEBUG(1, (CE_WARN, pdip,
		    "!pHCI unregister: Not a valid vHCI"));
		return (MDI_FAILURE);
	}

	mutex_enter(&mdi_mutex);
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

	/*
	 * If no busconfig is in progress, release the phci busconfig resources.
	 * We only need vh->vh_phci_count of busconfig resources.
	 */
	if (vh->vh_bus_config.vhc_start_time == 0 &&
	    vh->vh_bus_config.vhc_phc_cnt > vh->vh_phci_count) {
		int count;

		count = vh->vh_bus_config.vhc_phc_cnt - vh->vh_phci_count;
		while (count--) {
			mdi_phci_config_t *phc;

			phc = vh->vh_bus_config.vhc_phc;
			vh->vh_bus_config.vhc_phc = phc->phc_next;
			kmem_free(phc, sizeof (*phc));
		}
		vh->vh_bus_config.vhc_phc_cnt = vh->vh_phci_count;
	}

	mutex_exit(&mdi_mutex);

	cv_destroy(&ph->ph_unstable_cv);
	cv_destroy(&ph->ph_powerchange_cv);
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
	mutex_enter(&mdi_mutex);
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
	mutex_exit(&mdi_mutex);
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
			/*
			 * tryenter failed. Try to grab again
			 * after a small delay
			 */
			MDI_PI_HOLD(pip);
			MDI_PI_UNLOCK(pip);
			delay(1);
			MDI_PI_LOCK(pip);
			MDI_PI_RELE(pip);
		}
	} else {
		MDI_PHCI_LOCK(ph);
	}
}

/*
 * i_mdi_phci_get_client_lock():
 *		Lock a pHCI device
 * Return Values:
 *		None
 * Note:
 *		The default locking order is:
 *		_NOTE(LOCK_ORDER(mdi_phci::ph_mutex mdi_client::ct_mutex))
 *		But there are number of situations where locks need to be
 *		grabbed in reverse order.  This routine implements try and lock
 *		mechanism depending on the requested parameter option.
 */
static void
i_mdi_phci_get_client_lock(mdi_phci_t *ph, mdi_client_t *ct)
{
	if (ct) {
		/* Reverse locking is requested. */
		while (MDI_PHCI_TRYLOCK(ph) == 0) {
			/*
			 * tryenter failed. Try to grab again
			 * after a small delay
			 */
			MDI_CLIENT_UNLOCK(ct);
			delay(1);
			MDI_CLIENT_LOCK(ct);
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
	char **compatible, int ncompatible, int flags)
{
	dev_info_t *cdip = NULL;

	ASSERT(MUTEX_HELD(&mdi_mutex));

	/* Verify for duplicate entry */
	cdip = i_mdi_devinfo_find(vh, name, guid);
	ASSERT(cdip == NULL);
	if (cdip) {
		cmn_err(CE_WARN,
		    "i_mdi_devinfo_create: client dip %p already exists",
			(void *)cdip);
	}

	if (flags == DDI_SLEEP) {
		ndi_devi_alloc_sleep(vh->vh_dip, name,
		    DEVI_SID_NODEID, &cdip);
	} else {
		(void) ndi_devi_alloc(vh->vh_dip, name,
		    DEVI_SID_NODEID, &cdip);
	}
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
		rv = ndi_devi_offline(cdip, NDI_DEVI_REMOVE);
		if (rv != NDI_SUCCESS) {
			MDI_DEBUG(1, (CE_NOTE, NULL, "!i_mdi_devinfo_remove:"
			    " failed. cdip = %p\n", cdip));
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
			/*
			 * tryenter failed. Try to grab again
			 * after a small delay
			 */
			MDI_PI_HOLD(pip);
			MDI_PI_UNLOCK(pip);
			delay(1);
			MDI_PI_LOCK(pip);
			MDI_PI_RELE(pip);
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
 *		hold the global mdi_mutex.
 * Return Values:
 *		Handle to a client component
 */
/*ARGSUSED*/
static mdi_client_t *
i_mdi_client_alloc(mdi_vhci_t *vh, char *name, char *lguid, int flags)
{
	mdi_client_t	*ct;
	char		*drvname = NULL;
	char		*guid = NULL;
	client_lb_args_t 	*lb_args = NULL;

	ASSERT(MUTEX_HELD(&mdi_mutex));

	/*
	 * Allocate and initialize a component structure.
	 */
	ct = kmem_zalloc(sizeof (*ct),
	    (flags == DDI_SLEEP) ? KM_SLEEP : KM_NOSLEEP);
	if (ct == NULL)
		goto fail;
	mutex_init(&ct->ct_mutex, NULL, MUTEX_DEFAULT, NULL);
	ct->ct_hnext = NULL;
	ct->ct_hprev = NULL;
	ct->ct_dip = NULL;
	ct->ct_vhci = vh;
	drvname = kmem_alloc(strlen(name) + 1,
	    (flags == DDI_SLEEP) ? KM_SLEEP : KM_NOSLEEP);
	if (drvname == NULL)
		goto fail;
	ct->ct_drvname = drvname;
	(void) strcpy(ct->ct_drvname, name);
	guid = kmem_alloc(strlen(lguid) + 1,
	    (flags == DDI_SLEEP) ? KM_SLEEP : KM_NOSLEEP);
	if (guid == NULL)
		goto fail;
	ct->ct_guid = guid;
	(void) strcpy(ct->ct_guid, lguid);
	ct->ct_cprivate = NULL;
	ct->ct_vprivate = NULL;
	ct->ct_flags = 0;
	ct->ct_state = MDI_CLIENT_STATE_FAILED;
	MDI_CLIENT_SET_OFFLINE(ct);
	MDI_CLIENT_SET_DETACH(ct);
	MDI_CLIENT_SET_POWER_UP(ct);
	ct->ct_failover_flags = 0;
	ct->ct_failover_status = 0;
	cv_init(&ct->ct_failover_cv, NULL, CV_DRIVER, NULL);
	ct->ct_unstable = 0;
	cv_init(&ct->ct_unstable_cv, NULL, CV_DRIVER, NULL);
	cv_init(&ct->ct_powerchange_cv, NULL, CV_DRIVER, NULL);
	ct->ct_lb = vh->vh_lb;
	lb_args =  kmem_zalloc(sizeof (client_lb_args_t),
		(flags == DDI_SLEEP) ? KM_SLEEP : KM_NOSLEEP);
	if (lb_args == NULL)
		goto fail;
	ct->ct_lb_args = lb_args;
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

fail:
	if (guid)
		kmem_free(guid, strlen(lguid) + 1);
	if (drvname)
		kmem_free(drvname, strlen(name) + 1);
	if (lb_args)
		kmem_free(lb_args, sizeof (client_lb_args_t));
	kmem_free(ct, sizeof (*ct));
	return (NULL);
}

/*
 * i_mdi_client_enlist_table():
 *		Attach the client device to the client hash table. Caller
 *		should hold the mdi_mutex
 */

static void
i_mdi_client_enlist_table(mdi_vhci_t *vh, mdi_client_t *ct)
{
	int 			index;
	struct client_hash	*head;

	ASSERT(MUTEX_HELD(&mdi_mutex));
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
 *		Caller should hold the mdi_mutex
 */

static void
i_mdi_client_delist_table(mdi_vhci_t *vh, mdi_client_t *ct)
{
	int			index;
	char			*guid;
	struct client_hash 	*head;
	mdi_client_t		*next;
	mdi_client_t		*last;

	ASSERT(MUTEX_HELD(&mdi_mutex));
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

	ASSERT(MUTEX_HELD(&mdi_mutex));
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
		mutex_exit(&mdi_mutex);
		(void) i_mdi_devinfo_remove(vdip, cdip, flags);
		mutex_enter(&mdi_mutex);
	}
	return (rv);
}

/*
 * i_mdi_client_find():
 * 		Find the client structure corresponding to a given guid
 *		Caller should hold the mdi_mutex
 */
static mdi_client_t *
i_mdi_client_find(mdi_vhci_t *vh, char *guid)
{
	int			index;
	struct client_hash	*head;
	mdi_client_t		*ct;

	ASSERT(MUTEX_HELD(&mdi_mutex));
	index = i_mdi_get_hash_key(guid);
	head = &vh->vh_client_table[index];

	ct = head->ct_hash_head;
	while (ct != NULL) {
		if (strcmp(ct->ct_guid, guid) == 0) {
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
	ASSERT(MUTEX_HELD(&ct->ct_mutex));
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

	ASSERT(MUTEX_HELD(&ct->ct_mutex));
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
			MDI_DEBUG(2, (CE_NOTE, NULL, "!client state: failed"
			    " ct = %p\n", ct));
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
	    (i_ddi_node_state(ct->ct_dip) < DS_READY)) {
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

	ASSERT(!MUTEX_HELD(&ct->ct_mutex));

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
		if (pip == NULL) {
			MDI_DEBUG(4, (CE_NOTE, NULL,
			    "!lba %p, no pip !!\n",
				bp->b_blkno));
		} else {
			MDI_DEBUG(4, (CE_NOTE, NULL,
			    "!lba %p, no pip for path_index, "
			    "pip %p\n", pip));
		}
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
 *		appropriate flags.  If start_pip is specified (non NULL) is
 *		used as start point to walk and find the next appropriate path.
 *		The following values are currently defined:
 *		MDI_SELECT_ONLINE_PATH (to select an ONLINE path) and/or
 *		MDI_SELECT_STANDBY_PATH (to select an STANDBY path).
 *
 *		The non-standard behavior is used by the scsi_vhci driver,
 *		whenever it has to use a STANDBY/FAULTED path.  Eg. during
 *		attach of client devices (to avoid an unnecessary failover
 *		when the STANDBY path comes up first), during failover
 *		(to activate a STANDBY path as ONLINE).
 *
 *		The selected path in returned in a held state (ref_cnt).
 *		Caller should release the hold by calling mdi_rele_path().
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
    mdi_pathinfo_t *start_pip, mdi_pathinfo_t **ret_pip)
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
			MDI_DEBUG(2, (CE_NOTE, cdip, "!mdi_select_path: "
			    "client state offline ct = %p\n", ct));
			MDI_CLIENT_UNLOCK(ct);
			return (MDI_FAILURE);
		}

		if (MDI_CLIENT_IS_FAILOVER_IN_PROGRESS(ct)) {
			/*
			 * Check for Failover is in progress. If so tell the
			 * caller that this device is busy.
			 */
			MDI_DEBUG(2, (CE_NOTE, cdip, "!mdi_select_path: "
			    "client failover in progress ct = %p\n", ct));
			MDI_CLIENT_UNLOCK(ct);
			return (MDI_BUSY);
		}

		/*
		 * Check to see whether the client device is attached.
		 * If not so, let the vHCI driver manually select a path
		 * (standby) and let the probe/attach process to continue.
		 */
		if ((MDI_CLIENT_IS_DETACHED(ct)) ||
		    i_ddi_node_state(cdip) < DS_READY) {
			MDI_DEBUG(4, (CE_NOTE, cdip, "!Devi is onlining\n"));
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
			 * same veriable is used for DISABLE/ENABLE information.
			 */
			if (MDI_PI(pip)->pi_state  ==
				MDI_PATHINFO_STATE_ONLINE &&
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
		/*  FALLTHROUGH */
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
				} else {
					cond = 0;
				}
			}
			/*
			 * No need to explicitly check if the path is disabled.
			 * Since we are checking for state == ONLINE and the
			 * same veriable is used for DISABLE/ENABLE information.
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
 * mdi_get_nextpath():
 *		mdi_pathinfo node walker function.  Get the next node from the
 *		client or pHCI device list.
 *
 * XXX This is wrapper function for compatibility purposes only.
 *
 *	It doesn't work under Multi-level MPxIO, where a dip
 *	is both client and phci (which link should next_path follow?).
 *	Once Leadville is modified to call mdi_get_next_phci/client_path,
 *	this interface should be removed.
 */
void
mdi_get_next_path(dev_info_t *dip, mdi_pathinfo_t *pip,
    mdi_pathinfo_t **ret_pip)
{
	if (MDI_CLIENT(dip)) {
		*ret_pip = mdi_get_next_phci_path(dip, pip);
	} else if (MDI_PHCI(dip)) {
		*ret_pip = mdi_get_next_client_path(dip, pip);
	} else {
		*ret_pip = NULL;
	}
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

	if ((pdip == NULL) || (paddr == NULL)) {
		return (NULL);
	}
	ph = i_devi_get_phci(pdip);
	if (ph == NULL) {
		/*
		 * Invalid pHCI device, Nothing more to do.
		 */
		MDI_DEBUG(2, (CE_WARN, NULL,
		    "!mdi_pi_find: invalid phci"));
		return (NULL);
	}

	vh = ph->ph_vhci;
	if (vh == NULL) {
		/*
		 * Invalid vHCI device, Nothing more to do.
		 */
		MDI_DEBUG(2, (CE_WARN, NULL,
		    "!mdi_pi_find: invalid phci"));
		return (NULL);
	}

	/*
	 * Look for client device identified by caddr (guid)
	 */
	if (caddr == NULL) {
		/*
		 * Find a mdi_pathinfo node under pHCI list for a matching
		 * unit address.
		 */
		mutex_enter(&ph->ph_mutex);
		pip = (mdi_pathinfo_t *)ph->ph_path_head;

		while (pip != NULL) {
			if (strcmp(MDI_PI(pip)->pi_addr, paddr) == 0) {
				break;
			}
			pip = (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;
		}
		mutex_exit(&ph->ph_mutex);
		return (pip);
	}

	/*
	 * Find the client device corresponding to 'caddr'
	 */
	mutex_enter(&mdi_mutex);
	ct = i_mdi_client_find(vh, caddr);
	if (ct == NULL) {
		/*
		 * Client not found, Obviously mdi_pathinfo node has not been
		 * created yet.
		 */
		mutex_exit(&mdi_mutex);
		return (pip);
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
	mutex_exit(&mdi_mutex);

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

	if (pdip == NULL || cname == NULL || caddr == NULL || paddr == NULL ||
	    ret_pip == NULL) {
		/* Nothing more to do */
		return (MDI_FAILURE);
	}

	*ret_pip = NULL;
	ph = i_devi_get_phci(pdip);
	ASSERT(ph != NULL);
	if (ph == NULL) {
		/* Invalid pHCI device, return failure */
		MDI_DEBUG(1, (CE_WARN, NULL,
		    "!mdi_pi_alloc: invalid pHCI=%p", pdip));
		return (MDI_FAILURE);
	}

	MDI_PHCI_LOCK(ph);
	vh = ph->ph_vhci;
	if (vh == NULL) {
		/* Invalid vHCI device, return failure */
		MDI_DEBUG(1, (CE_WARN, NULL,
		    "!mdi_pi_alloc: invalid pHCI=%p", pdip));
		MDI_PHCI_UNLOCK(ph);
		return (MDI_FAILURE);
	}

	if (MDI_PHCI_IS_READY(ph) == 0) {
		/*
		 * Do not allow new node creation when pHCI is in
		 * offline/suspended states
		 */
		MDI_DEBUG(1, (CE_WARN, NULL,
		    "mdi_pi_alloc: pHCI=%p is not ready", ph));
		MDI_PHCI_UNLOCK(ph);
		return (MDI_BUSY);
	}
	MDI_PHCI_UNSTABLE(ph);
	MDI_PHCI_UNLOCK(ph);

	/*
	 * Look for a client device with matching guid identified by caddr,
	 * If not found create one
	 */
	mutex_enter(&mdi_mutex);
	ct = i_mdi_client_find(vh, caddr);
	if (ct == NULL) {
		ct = i_mdi_client_alloc(vh, cname, caddr, flags);
		if (ct == NULL)
			goto fail;
	}

	if (ct->ct_dip == NULL) {
		/*
		 * Allocate a devinfo node
		 */
		ct->ct_dip = i_mdi_devinfo_create(vh, cname, caddr,
		    compatible, ncompatible, flags);
		if (ct->ct_dip == NULL) {
			(void) i_mdi_client_free(vh, ct);
			goto fail;
		}
	}
	cdip = ct->ct_dip;

	DEVI(cdip)->devi_mdi_component |= MDI_COMPONENT_CLIENT;
	DEVI(cdip)->devi_mdi_client = (caddr_t)ct;

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

	if (pip == NULL) {
		/*
		 * This is a new path for this client device.  Allocate and
		 * initialize a new pathinfo node
		 */
		pip = i_mdi_pi_alloc(ph, paddr, ct, flags);
		if (pip == NULL) {
			(void) i_mdi_client_free(vh, ct);
			goto fail;
		}
	}
	rv = MDI_SUCCESS;

fail:
	/*
	 * Release the global mutex.
	 */
	mutex_exit(&mdi_mutex);

	/*
	 * Mark the pHCI as stable
	 */
	MDI_PHCI_LOCK(ph);
	MDI_PHCI_STABLE(ph);
	MDI_PHCI_UNLOCK(ph);
	*ret_pip = pip;
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
i_mdi_pi_alloc(mdi_phci_t *ph, char *paddr, mdi_client_t *ct, int flags)
{
	mdi_pathinfo_t	*pip = NULL;
	char		*pi_addr = NULL;
	nvlist_t	*pi_prop = NULL;

	int		ct_circular;
	int		ph_circular;

	pip = kmem_zalloc(sizeof (struct mdi_pathinfo),
	    (flags == DDI_SLEEP) ? KM_SLEEP : KM_NOSLEEP);
	if (pip == NULL)
		goto fail;
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
	pi_addr =
	    MDI_PI(pip)->pi_addr = kmem_alloc(strlen(paddr) + 1,
	    (flags == DDI_SLEEP) ? KM_SLEEP : KM_NOSLEEP);
	if (pi_addr == NULL)
		goto fail;
	(void) strcpy(MDI_PI(pip)->pi_addr, paddr);
	(void) nvlist_alloc(&pi_prop, NV_UNIQUE_NAME,
	    (flags == DDI_SLEEP) ? KM_SLEEP : KM_NOSLEEP);
	if (pi_prop == NULL)
		goto fail;
	MDI_PI(pip)->pi_prop = pi_prop;
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
	 */
	ndi_devi_enter(ct->ct_dip, &ct_circular);
	ndi_devi_enter(ph->ph_dip, &ph_circular);

	i_mdi_phci_add_path(ph, pip);
	i_mdi_client_add_path(ct, pip);

	ndi_devi_exit(ph->ph_dip, ph_circular);
	ndi_devi_exit(ct->ct_dip, ct_circular);

	return (pip);

fail:
	if (pi_prop)
		(void) nvlist_free(pi_prop);
	if (pi_addr)
		kmem_free(pi_addr, strlen(paddr) + 1);
	kmem_free(pip, sizeof (struct mdi_pathinfo));
	return (NULL);
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

	if (ph->ph_path_head == NULL) {
		ph->ph_path_head = pip;
	} else {
		MDI_PI(ph->ph_path_tail)->pi_phci_link = MDI_PI(pip);
	}
	ph->ph_path_tail = pip;
	ph->ph_path_count++;
}

/*
 * i_mdi_client_add_path():
 *		Add mdi_pathinfo node to client list
 */

static void
i_mdi_client_add_path(mdi_client_t *ct, mdi_pathinfo_t *pip)
{
	ASSERT(DEVI_BUSY_OWNED(ct->ct_dip));

	if (ct->ct_path_head == NULL) {
		ct->ct_path_head = pip;
	} else {
		MDI_PI(ct->ct_path_tail)->pi_client_link = MDI_PI(pip);
	}
	ct->ct_path_tail = pip;
	ct->ct_path_count++;
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
	int		rv = MDI_SUCCESS;
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
		MDI_DEBUG(1, (CE_WARN, NULL,
		    "!mdi_pi_free: invalid pHCI"));
		MDI_PI_UNLOCK(pip);
		return (MDI_FAILURE);
	}

	vh = ph->ph_vhci;
	ASSERT(vh != NULL);
	if (vh == NULL) {
		/* Invalid pHCI device, return failure */
		MDI_DEBUG(1, (CE_WARN, NULL,
		    "!mdi_pi_free: invalid vHCI"));
		MDI_PI_UNLOCK(pip);
		return (MDI_FAILURE);
	}

	ct = MDI_PI(pip)->pi_client;
	ASSERT(ct != NULL);
	if (ct == NULL) {
		/*
		 * Invalid Client device, return failure
		 */
		MDI_DEBUG(1, (CE_WARN, NULL,
		    "!mdi_pi_free: invalid client"));
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
		MDI_DEBUG(1, (CE_WARN, NULL,
		    "!mdi_pi_free: pathinfo node is busy pip=%p", pip));
		MDI_PI_UNLOCK(pip);
		return (MDI_BUSY);
	}

	while (MDI_PI(pip)->pi_ref_cnt != 0) {
		/*
		 * Give a chance for pending I/Os to complete.
		 */
		MDI_DEBUG(1, (CE_NOTE, ct->ct_vhci->vh_dip, "!i_mdi_pi_free: "
		    "%d cmds still pending on path: %p\n",
		    MDI_PI(pip)->pi_ref_cnt, pip));
		if (cv_timedwait(&MDI_PI(pip)->pi_ref_cv,
		    &MDI_PI(pip)->pi_mutex,
		    ddi_get_lbolt() + drv_usectohz(60 * 1000000)) == -1) {
			/*
			 * The timeout time reached without ref_cnt being zero
			 * being signaled.
			 */
			MDI_DEBUG(1, (CE_NOTE, ct->ct_vhci->vh_dip,
			    "!i_mdi_pi_free: "
			    "Timeout reached on path %p without the cond\n",
			    pip));
			MDI_DEBUG(1, (CE_NOTE, ct->ct_vhci->vh_dip,
			    "!i_mdi_pi_free: "
			    "%d cmds still pending on path: %p\n",
			    MDI_PI(pip)->pi_ref_cnt, pip));
			MDI_PI_UNLOCK(pip);
			return (MDI_BUSY);
		}
	}
	if (MDI_PI(pip)->pi_pm_held) {
		client_held = 1;
	}
	MDI_PI_UNLOCK(pip);

	MDI_CLIENT_LOCK(ct);

	/* Prevent further failovers till mdi_mutex is held */
	MDI_CLIENT_SET_PATH_FREE_IN_PROGRESS(ct);

	/*
	 * Wait till failover is complete before removing this node.
	 */
	while (MDI_CLIENT_IS_FAILOVER_IN_PROGRESS(ct))
		cv_wait(&ct->ct_failover_cv, &ct->ct_mutex);

	MDI_CLIENT_UNLOCK(ct);
	mutex_enter(&mdi_mutex);
	MDI_CLIENT_LOCK(ct);
	MDI_CLIENT_CLEAR_PATH_FREE_IN_PROGRESS(ct);

	if (!MDI_PI_IS_INITING(pip)) {
		f = vh->vh_ops->vo_pi_uninit;
		if (f != NULL) {
			rv = (*f)(vh->vh_dip, pip, 0);
		}
	}
	/*
	 * If vo_pi_uninit() completed successfully.
	 */
	if (rv == MDI_SUCCESS) {
		if (client_held) {
			MDI_DEBUG(4, (CE_NOTE, ct->ct_dip, "mdi_pi_free "
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
			mutex_exit(&mdi_mutex);
			return (rv);
		}
	}
	MDI_CLIENT_UNLOCK(ct);
	mutex_exit(&mdi_mutex);
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

	/*
	 * remove any per-path kstats
	 */
	i_mdi_pi_kstat_destroy(pip);

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
		MDI_DEBUG(1, (CE_WARN, NULL,
		    "!mdi_pi_state_change: invalid phci"));
		return (MDI_FAILURE);
	}

	vh = ph->ph_vhci;
	ASSERT(vh);
	if (vh == NULL) {
		/*
		 * Invalid vHCI device, fail the request
		 */
		MDI_PI_UNLOCK(pip);
		MDI_DEBUG(1, (CE_WARN, NULL,
		    "!mdi_pi_state_change: invalid vhci"));
		return (MDI_FAILURE);
	}

	ct = MDI_PI(pip)->pi_client;
	ASSERT(ct != NULL);
	if (ct == NULL) {
		/*
		 * Invalid client device, fail the request
		 */
		MDI_PI_UNLOCK(pip);
		MDI_DEBUG(1, (CE_WARN, NULL,
		    "!mdi_pi_state_change: invalid client"));
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
				MDI_DEBUG(1, (CE_WARN, vh->vh_dip,
				    "!vo_pi_init: failed vHCI=0x%p, pip=0x%p",
				    vh, pip));
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
		MDI_DEBUG(1, (CE_WARN, NULL,
		    "!mdi_pi_state_change: pHCI not ready, pHCI=%p", ph));
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
		 * Do not offline if path will become last path and path
		 * is busy for user initiated events.
		 */
		cdip = ct->ct_dip;
		if ((flag & NDI_DEVI_REMOVE) &&
		    (MDI_CLIENT_STATE(ct) == MDI_CLIENT_STATE_DEGRADED)) {
			i_mdi_client_unlock(ct);
			rv = ndi_devi_offline(cdip, 0);
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
	if (f != NULL) {
		rv = (*f)(vh->vh_dip, pip, state, 0, flag);
		if (rv == MDI_NOT_SUPPORTED) {
			MDI_CLIENT_SET_DEV_NOT_SUPPORTED(ct);
		}
		if (rv != MDI_SUCCESS) {
			MDI_DEBUG(2, (CE_WARN, vh->vh_dip,
			    "!vo_pi_state_change: failed rv = %x", rv));
		}
	}
	MDI_CLIENT_LOCK(ct);
	MDI_PI_LOCK(pip);
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
				if (cdip &&
				    (i_ddi_node_state(cdip) < DS_READY) &&
				    ((state == MDI_PATHINFO_STATE_ONLINE) ||
				    (state == MDI_PATHINFO_STATE_STANDBY))) {

					i_mdi_client_unlock(ct);
					/*
					 * Must do ndi_devi_online() through
					 * hotplug thread for deferred
					 * attach mechanism to work
					 */
					rv = ndi_devi_online(cdip, 0);
					i_mdi_client_lock(ct, NULL);
					if ((rv != NDI_SUCCESS) &&
					    (MDI_CLIENT_STATE(ct) ==
					    MDI_CLIENT_STATE_DEGRADED)) {
						/*
						 * ndi_devi_online failed.
						 * Reset client flags to
						 * offline.
						 */
						MDI_DEBUG(1, (CE_WARN, cdip,
						    "!ndi_devi_online: failed "
						    " Error: %x", rv));
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
				break;

			case MDI_CLIENT_STATE_FAILED:
				/*
				 * This is the last path case for
				 * non-user initiated events.
				 */
				if (((flag & NDI_DEVI_REMOVE) == 0) &&
				    cdip && (i_ddi_node_state(cdip) >=
				    DS_INITIALIZED)) {
					i_mdi_client_unlock(ct);
					rv = ndi_devi_offline(cdip, 0);
					i_mdi_client_lock(ct, NULL);

					if (rv != NDI_SUCCESS) {
						/*
						 * ndi_devi_offline failed.
						 * Reset client flags to
						 * online as the path could not
						 * be offlined.
						 */
						MDI_DEBUG(1, (CE_WARN, cdip,
						    "!ndi_devi_offline: failed "
						    " Error: %x", rv));
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
	mdi_client_t *ct = MDI_PI(pip)->pi_client;
	dev_info_t *cdip;
	int		client_held = 0;
	int rv;

	ASSERT(ct != NULL);
	rv = i_mdi_pi_state_change(pip, MDI_PATHINFO_STATE_ONLINE, flags);
	if (rv != MDI_SUCCESS)
		return (rv);

	MDI_PI_LOCK(pip);
	if (MDI_PI(pip)->pi_pm_held == 0) {
		MDI_DEBUG(4, (CE_NOTE, ct->ct_dip, "mdi_pi_online "
		    "i_mdi_pm_hold_pip\n"));
		i_mdi_pm_hold_pip(pip);
		client_held = 1;
	}
	MDI_PI_UNLOCK(pip);

	if (client_held) {
		MDI_CLIENT_LOCK(ct);
		if (ct->ct_power_cnt == 0) {
			rv = i_mdi_power_all_phci(ct);
		}

		MDI_DEBUG(4, (CE_NOTE, ct->ct_dip, "mdi_pi_online "
		    "i_mdi_pm_hold_client\n"));
		i_mdi_pm_hold_client(ct, 1);
		MDI_CLIENT_UNLOCK(ct);
	}

	/*
	 * Create the per-path (pathinfo) IO and error kstats which
	 * are reported via iostat(1m).
	 *
	 * Defer creating the per-path kstats if device is not yet
	 * attached;  the names of the kstats are constructed in part
	 * using the devices instance number which is assigned during
	 * process of attaching the client device.
	 *
	 * The framework post_attach handler, mdi_post_attach(), is
	 * is responsible for initializing the client's pathinfo list
	 * once successfully attached.
	 */
	cdip = ct->ct_dip;
	ASSERT(cdip);
	if (cdip == NULL || (i_ddi_node_state(cdip) < DS_ATTACHED))
		return (rv);

	MDI_CLIENT_LOCK(ct);
	rv = i_mdi_pi_kstat_create(pip);
	MDI_CLIENT_UNLOCK(ct);
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
			MDI_DEBUG(4, (CE_NOTE, ct->ct_dip,
			    "mdi_pi_offline i_mdi_pm_rele_client\n"));
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
		MDI_DEBUG(1, (CE_NOTE, vdip, "!i_mdi_pi_offline: "
		    "%d cmds still pending on path: %p\n",
		    MDI_PI(pip)->pi_ref_cnt, pip));
		if (cv_timedwait(&MDI_PI(pip)->pi_ref_cv,
		    &MDI_PI(pip)->pi_mutex,
		    ddi_get_lbolt() + drv_usectohz(60 * 1000000)) == -1) {
			/*
			 * The timeout time reached without ref_cnt being zero
			 * being signaled.
			 */
			MDI_DEBUG(1, (CE_NOTE, vdip, "!i_mdi_pi_offline: "
			    "Timeout reached on path %p without the cond\n",
			    pip));
			MDI_DEBUG(1, (CE_NOTE, vdip, "!i_mdi_pi_offline: "
			    "%d cmds still pending on path: %p\n",
			    MDI_PI(pip)->pi_ref_cnt, pip));
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
			MDI_DEBUG(1, (CE_WARN, vdip, "!vo_path_offline failed "
			    "vdip 0x%x, pip 0x%x", vdip, pip));
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
					rv = ndi_devi_offline(cdip, 0);
					MDI_CLIENT_LOCK(ct);
					if (rv != NDI_SUCCESS) {
						/*
						 * ndi_devi_offline failed.
						 * Reset client flags to
						 * online.
						 */
						MDI_DEBUG(4, (CE_WARN, cdip,
						    "!ndi_devi_offline: failed "
						    " Error: %x", rv));
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
	MDI_DEBUG(2, (CE_NOTE, NULL, "!i_mdi_pi_offline ct = %p pip = %p",
	    ct, pip));
	return (rv);
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
	if (pip) {
		dip = MDI_PI(pip)->pi_phci->ph_dip;
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
	ASSERT(MUTEX_HELD(&MDI_PI(pip)->pi_mutex));
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
	ASSERT(!MUTEX_HELD(&MDI_PI(pip)->pi_mutex));
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
			(void) snprintf(nvp_name, MAXNAMELEN, "%s",
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
	ASSERT(MUTEX_HELD(&MDI_PI(pip)->pi_mutex));
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

	ASSERT(MUTEX_HELD(&MDI_PI(pip)->pi_mutex));

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
	ASSERT(!MUTEX_HELD(&MDI_PI(pip)->pi_mutex));
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
	ASSERT(!MUTEX_HELD(&MDI_PI(pip)->pi_mutex));
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
	ASSERT(!MUTEX_HELD(&MDI_PI(pip)->pi_mutex));
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
	ASSERT(!MUTEX_HELD(&MDI_PI(pip)->pi_mutex));
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
	ASSERT(!MUTEX_HELD(&MDI_PI(pip)->pi_mutex));
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
	ASSERT(!MUTEX_HELD(&MDI_PI(pip)->pi_mutex));
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
	ASSERT(!MUTEX_HELD(&MDI_PI(pip)->pi_mutex));
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
	char		*phci_path, *ct_path;
	char		*ct_status;
	char		*status;
	dev_info_t	*dip = ct->ct_dip;
	char		lb_buf[64];

	ASSERT(MUTEX_HELD(&ct->ct_mutex));
	if ((dip == NULL) || (ddi_get_instance(dip) == -1) ||
	    (MDI_CLIENT_IS_REPORT_DEV_NEEDED(ct) == 0)) {
		return;
	}
	if (MDI_CLIENT_STATE(ct) == MDI_CLIENT_STATE_OPTIMAL) {
		ct_status = "optimal";
	} else if (MDI_CLIENT_STATE(ct) == MDI_CLIENT_STATE_DEGRADED) {
		ct_status = "degraded";
	} else if (MDI_CLIENT_STATE(ct) == MDI_CLIENT_STATE_FAILED) {
		ct_status = "failed";
	} else {
		ct_status = "unknown";
	}

	if (MDI_PI_IS_OFFLINE(pip)) {
		status = "offline";
	} else if (MDI_PI_IS_ONLINE(pip)) {
		status = "online";
	} else if (MDI_PI_IS_STANDBY(pip)) {
		status = "standby";
	} else if (MDI_PI_IS_FAULT(pip)) {
		status = "faulted";
	} else {
		status = "unknown";
	}

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

	if (dip) {
		ct_path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		phci_path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		cmn_err(CE_CONT, "?%s (%s%d) multipath status: %s, "
		    "path %s (%s%d) to target address: %s is %s"
		    " Load balancing: %s\n",
		    ddi_pathname(dip, ct_path), ddi_driver_name(dip),
		    ddi_get_instance(dip), ct_status,
		    ddi_pathname(MDI_PI(pip)->pi_phci->ph_dip, phci_path),
		    ddi_driver_name(MDI_PI(pip)->pi_phci->ph_dip),
		    ddi_get_instance(MDI_PI(pip)->pi_phci->ph_dip),
		    MDI_PI(pip)->pi_addr, status, lb_buf);
		kmem_free(phci_path, MAXPATHLEN);
		kmem_free(ct_path, MAXPATHLEN);
		MDI_CLIENT_CLEAR_REPORT_DEV_NEEDED(ct);
	}
}

#ifdef	DEBUG
/*
 * i_mdi_log():
 *		Utility function for error message management
 *
 */

/*VARARGS3*/
static void
i_mdi_log(int level, dev_info_t *dip, const char *fmt, ...)
{
	char		buf[MAXNAMELEN];
	char		name[MAXNAMELEN];
	va_list		ap;
	int		log_only = 0;
	int		boot_only = 0;
	int		console_only = 0;

	if (dip) {
		if (level == CE_PANIC || level == CE_WARN || level == CE_NOTE) {
			(void) snprintf(name, MAXNAMELEN, "%s%d:\n",
			    ddi_node_name(dip), ddi_get_instance(dip));
		} else {
			(void) snprintf(name, MAXNAMELEN, "%s%d:",
			    ddi_node_name(dip), ddi_get_instance(dip));
		}
	} else {
		name[0] = '\0';
	}

	va_start(ap, fmt);
	(void) vsnprintf(buf, MAXNAMELEN, fmt, ap);
	va_end(ap);

	switch (buf[0]) {
	case '!':
		log_only = 1;
		break;
	case '?':
		boot_only = 1;
		break;
	case '^':
		console_only = 1;
		break;
	}

	switch (level) {
	case CE_NOTE:
		level = CE_CONT;
		/* FALLTHROUGH */
	case CE_CONT:
	case CE_WARN:
	case CE_PANIC:
		if (boot_only) {
			cmn_err(level, "?%s\t%s", name, &buf[1]);
		} else if (console_only) {
			cmn_err(level, "^%s\t%s", name, &buf[1]);
		} else if (log_only) {
			cmn_err(level, "!%s\t%s", name, &buf[1]);
		} else {
			cmn_err(level, "%s\t%s", name, buf);
		}
		break;
	default:
		cmn_err(level, "%s\t%s", name, buf);
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

	MDI_DEBUG(4, (CE_NOTE, ct_dip, "i_mdi_client_online "
	    "i_mdi_pm_hold_client\n"));
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
	MDI_DEBUG(2, (CE_NOTE, dip, "!mdi_phci_offline called %p\n",
	    dip));

	ph = i_devi_get_phci(dip);
	if (ph == NULL) {
		return (rv);
	}

	MDI_PHCI_LOCK(ph);

	if (MDI_PHCI_IS_OFFLINE(ph)) {
		MDI_DEBUG(1, (CE_WARN, dip, "!pHCI %p already offlined", ph));
		MDI_PHCI_UNLOCK(ph);
		return (NDI_SUCCESS);
	}

	/*
	 * Check to see if the pHCI can be offlined
	 */
	if (ph->ph_unstable) {
		MDI_DEBUG(1, (CE_WARN, dip,
		    "!One or more target devices are in transient "
		    "state. This device can not be removed at "
		    "this moment. Please try again later."));
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
			MDI_DEBUG(1, (CE_WARN, dip,
			    "!pHCI device (%s%d) is Busy. %s",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    "This device can not be removed at "
			    "this moment. Please try again later."));
			MDI_PI_UNLOCK(pip);
			MDI_CLIENT_UNLOCK(ct);
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
			if (ndi_devi_offline(cdip, 0) != NDI_SUCCESS) {
				/*
				 * ndi_devi_offline() failed.
				 * This pHCI provides the critical path
				 * to one or more client devices.
				 * Return busy.
				 */
				MDI_PHCI_LOCK(ph);
				MDI_DEBUG(1, (CE_WARN, dip,
				    "!pHCI device (%s%d) is Busy. %s",
				    ddi_driver_name(dip), ddi_get_instance(dip),
				    "This device can not be removed at "
				    "this moment. Please try again later."));
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
					(void) ndi_devi_offline(cdip, 0);
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
	delay(1);
	MDI_PHCI_LOCK(ph);
	pip = ph->ph_path_head;
	while (pip != NULL) {
		next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;
		(void) i_mdi_pi_offline(pip, flags);
		MDI_PI_LOCK(pip);
		ct = MDI_PI(pip)->pi_client;
		if (!MDI_PI_IS_OFFLINE(pip)) {
			MDI_DEBUG(1, (CE_WARN, dip,
			    "!pHCI device (%s%d) is Busy. %s",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    "This device can not be removed at "
			    "this moment. Please try again later."));
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
	MDI_DEBUG(2, (CE_NOTE, dip, "!i_mdi_client_offline called %p\n",
	    dip));
	ct = i_devi_get_client(dip);
	if (ct != NULL) {
		MDI_CLIENT_LOCK(ct);
		if (ct->ct_unstable) {
			/*
			 * One or more paths are in transient state,
			 * Dont allow offline of a client device
			 */
			MDI_DEBUG(1, (CE_WARN, dip,
			    "!One or more paths to this device is "
			    "in transient state. This device can not "
			    "be removed at this moment. "
			    "Please try again later."));
			MDI_CLIENT_UNLOCK(ct);
			return (NDI_BUSY);
		}
		if (MDI_CLIENT_IS_FAILOVER_IN_PROGRESS(ct)) {
			/*
			 * Failover is in progress, Dont allow DR of
			 * a client device
			 */
			MDI_DEBUG(1, (CE_WARN, dip,
			    "!Client device (%s%d) is Busy. %s",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    "This device can not be removed at "
			    "this moment. Please try again later."));
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
	mdi_pathinfo_t	*pip;

	if (MDI_PHCI(dip)) {
		ph = i_devi_get_phci(dip);
		ASSERT(ph != NULL);

		MDI_PHCI_LOCK(ph);
		switch (cmd) {
		case DDI_ATTACH:
			MDI_DEBUG(2, (CE_NOTE, dip,
			    "!pHCI post_attach: called %p\n", ph));
			if (error == DDI_SUCCESS) {
				MDI_PHCI_SET_ATTACH(ph);
			} else {
				MDI_DEBUG(1, (CE_NOTE, dip,
				    "!pHCI post_attach: failed error=%d\n",
				    error));
				MDI_PHCI_SET_DETACH(ph);
			}
			break;

		case DDI_RESUME:
			MDI_DEBUG(2, (CE_NOTE, dip,
			    "!pHCI post_resume: called %p\n", ph));
			if (error == DDI_SUCCESS) {
				MDI_PHCI_SET_RESUME(ph);
			} else {
				MDI_DEBUG(1, (CE_NOTE, dip,
				    "!pHCI post_resume: failed error=%d\n",
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
			MDI_DEBUG(2, (CE_NOTE, dip,
			    "!Client post_attach: called %p\n", ct));
			if (error != DDI_SUCCESS) {
				MDI_DEBUG(1, (CE_NOTE, dip,
				    "!Client post_attach: failed error=%d\n",
				    error));
				MDI_CLIENT_SET_DETACH(ct);
				MDI_DEBUG(4, (CE_WARN, dip,
				    "mdi_post_attach i_mdi_pm_reset_client\n"));
				i_mdi_pm_reset_client(ct);
				break;
			}

			/*
			 * Client device has successfully attached.
			 * Create kstats for any pathinfo structures
			 * initially associated with this client.
			 */
			for (pip = ct->ct_path_head; pip != NULL;
			    pip = (mdi_pathinfo_t *)
			    MDI_PI(pip)->pi_client_link) {
				(void) i_mdi_pi_kstat_create(pip);
				i_mdi_report_path_state(ct, pip);
			}
			MDI_CLIENT_SET_ATTACH(ct);
			break;

		case DDI_RESUME:
			MDI_DEBUG(2, (CE_NOTE, dip,
			    "!Client post_attach: called %p\n", ct));
			if (error == DDI_SUCCESS) {
				MDI_CLIENT_SET_RESUME(ct);
			} else {
				MDI_DEBUG(1, (CE_NOTE, dip,
				    "!Client post_resume: failed error=%d\n",
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
		MDI_DEBUG(2, (CE_NOTE, dip,
		    "!pHCI pre_detach: called %p\n", ph));
		if (!MDI_PHCI_IS_OFFLINE(ph)) {
			/*
			 * mdi_pathinfo nodes are still attached to
			 * this pHCI. Fail the detach for this pHCI.
			 */
			MDI_DEBUG(2, (CE_WARN, dip,
			    "!pHCI pre_detach: "
			    "mdi_pathinfo nodes are still attached "
			    "%p\n", ph));
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

		MDI_DEBUG(2, (CE_NOTE, dip,
		    "!pHCI pre_suspend: called %p\n", ph));
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
					MDI_DEBUG(1, (CE_WARN, dip,
					    "!Suspend of device (%s%d) failed.",
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
		MDI_DEBUG(2, (CE_NOTE, dip,
		    "!Client pre_detach: called %p\n", ct));
		MDI_CLIENT_SET_DETACH(ct);
		break;

	case DDI_SUSPEND:
		MDI_DEBUG(2, (CE_NOTE, dip,
		    "!Client pre_suspend: called %p\n", ct));
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
		MDI_DEBUG(2, (CE_NOTE, dip,
		    "!pHCI post_detach: called %p\n", ph));
		if (error != DDI_SUCCESS)
			MDI_PHCI_SET_ATTACH(ph);
		break;

	case DDI_SUSPEND:
		MDI_DEBUG(2, (CE_NOTE, dip,
		    "!pHCI post_suspend: called %p\n", ph));
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
		MDI_DEBUG(2, (CE_NOTE, dip,
		    "!Client post_detach: called %p\n", ct));
		if (DEVI_IS_ATTACHING(ct->ct_dip)) {
			MDI_DEBUG(4, (CE_NOTE, dip, "i_mdi_client_post_detach "
			    "i_mdi_pm_rele_client\n"));
			i_mdi_pm_rele_client(ct, ct->ct_path_count);
		} else {
			MDI_DEBUG(4, (CE_NOTE, dip, "i_mdi_client_post_detach "
			    "i_mdi_pm_reset_client\n"));
			i_mdi_pm_reset_client(ct);
		}
		if (error != DDI_SUCCESS)
			MDI_CLIENT_SET_ATTACH(ct);
		break;

	case DDI_SUSPEND:
		MDI_DEBUG(2, (CE_NOTE, dip,
		    "!Client post_suspend: called %p\n", ct));
		if (error != DDI_SUCCESS)
			MDI_CLIENT_SET_RESUME(ct);
		break;
	}
	MDI_CLIENT_UNLOCK(ct);
}

/*
 * create and install per-path (client - pHCI) statistics
 * I/O stats supported: nread, nwritten, reads, and writes
 * Error stats - hard errors, soft errors, & transport errors
 */
static int
i_mdi_pi_kstat_create(mdi_pathinfo_t *pip)
{

	dev_info_t *client = MDI_PI(pip)->pi_client->ct_dip;
	dev_info_t *ppath = MDI_PI(pip)->pi_phci->ph_dip;
	char ksname[KSTAT_STRLEN];
	mdi_pathinfo_t *cpip;
	const char *err_postfix = ",err";
	kstat_t	*kiosp, *kerrsp;
	struct pi_errs	*nsp;
	struct mdi_pi_kstats *mdi_statp;

	ASSERT(client != NULL && ppath != NULL);

	ASSERT(mutex_owned(&(MDI_PI(pip)->pi_client->ct_mutex)));

	if (MDI_PI(pip)->pi_kstats != NULL)
		return (MDI_SUCCESS);

	for (cpip = MDI_PI(pip)->pi_client->ct_path_head; cpip != NULL;
	    cpip = (mdi_pathinfo_t *)(MDI_PI(cpip)->pi_client_link)) {
		if (cpip == pip)
			continue;
		/*
		 * We have found a different path with same parent
		 * kstats for a given client-pHCI are common
		 */
		if ((MDI_PI(cpip)->pi_phci->ph_dip == ppath) &&
		    (MDI_PI(cpip)->pi_kstats != NULL)) {
			MDI_PI(cpip)->pi_kstats->pi_kstat_ref++;
			MDI_PI(pip)->pi_kstats = MDI_PI(cpip)->pi_kstats;
			return (MDI_SUCCESS);
		}
	}

	/*
	 * stats are named as follows: TGTx.HBAy, e.g. "ssd0.fp0"
	 * clamp length of name against max length of error kstat name
	 */
	if (snprintf(ksname, KSTAT_STRLEN, "%s%d.%s%d",
	    ddi_driver_name(client), ddi_get_instance(client),
	    ddi_driver_name(ppath), ddi_get_instance(ppath)) >
	    (KSTAT_STRLEN - strlen(err_postfix))) {
		return (MDI_FAILURE);
	}
	if ((kiosp = kstat_create("mdi", 0, ksname, "iopath",
	    KSTAT_TYPE_IO, 1, 0)) == NULL) {
		return (MDI_FAILURE);
	}

	(void) strcat(ksname, err_postfix);
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
 * disable the path to a particular pHCI (pHCI specified in the phci_path
 * argument) for a particular client (specified in the client_path argument).
 * Disabling a path means that MPxIO will not select the disabled path for
 * routing any new I/O requests.
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
 */

int
mdi_pi_enable(dev_info_t *cdip, dev_info_t *pdip, int flags)
{
	return (i_mdi_pi_enable_disable(cdip, pdip, flags, MDI_ENABLE_OP));
}


/*
 * Common routine for doing enable/disable.
 */
int
i_mdi_pi_enable_disable(dev_info_t *cdip, dev_info_t *pdip, int flags, int op)
{

	mdi_phci_t	*ph;
	mdi_vhci_t	*vh = NULL;
	mdi_client_t	*ct;
	mdi_pathinfo_t	*next, *pip;
	int		found_it;
	int		(*f)() = NULL;
	int		rv;
	int		sync_flag = 0;

	ph = i_devi_get_phci(pdip);
	MDI_DEBUG(5, (CE_NOTE, NULL, "!i_mdi_pi_enable_disable:"
		" Operation = %d pdip = %p cdip = %p\n", op, pdip, cdip));
	if (ph == NULL) {
		MDI_DEBUG(1, (CE_NOTE, NULL, "!i_mdi_pi_enable_disable:"
			" failed. ph = NULL operation = %d\n", op));
		return (MDI_FAILURE);
	}

	if ((op != MDI_ENABLE_OP) && (op != MDI_DISABLE_OP)) {
		MDI_DEBUG(1, (CE_NOTE, NULL, "!i_mdi_pi_enable_disable:"
			" Invalid operation = %d\n", op));
		return (MDI_FAILURE);
	}

	sync_flag = (flags << 8) & 0xf00;

	vh = ph->ph_vhci;
	f = vh->vh_ops->vo_pi_state_change;

	if (cdip == NULL) {
		/*
		 * Need to mark the Phci as enabled/disabled.
		 */
		MDI_DEBUG(3, (CE_NOTE, NULL, "!i_mdi_pi_enable_disable:"
		"Operation %d for the phci\n", op));
		MDI_PHCI_LOCK(ph);
		switch (flags) {
			case USER_DISABLE:
				if (op == MDI_DISABLE_OP)
					MDI_PHCI_SET_USER_DISABLE(ph);
				else
					MDI_PHCI_SET_USER_ENABLE(ph);
				break;
			case DRIVER_DISABLE:
				if (op == MDI_DISABLE_OP)
					MDI_PHCI_SET_DRV_DISABLE(ph);
				else
					MDI_PHCI_SET_DRV_ENABLE(ph);
				break;
			case DRIVER_DISABLE_TRANSIENT:
				if (op == MDI_DISABLE_OP)
					MDI_PHCI_SET_DRV_DISABLE_TRANSIENT(ph);
				else
					MDI_PHCI_SET_DRV_ENABLE_TRANSIENT(ph);
				break;
			default:
				MDI_PHCI_UNLOCK(ph);
				MDI_DEBUG(1, (CE_NOTE, NULL,
				"!i_mdi_pi_enable_disable:"
				" Invalid flag argument= %d\n", flags));
		}

		/*
		 * Phci has been disabled. Now try to enable/disable
		 * path info's to each client.
		 */
		pip = ph->ph_path_head;
		while (pip != NULL) {
			/*
			 * Do a callback into the mdi consumer to let it
			 * know that path is about to be enabled/disabled.
			 */
			if (f != NULL) {
				rv = (*f)(vh->vh_dip, pip, 0,
					MDI_PI_EXT_STATE(pip),
					MDI_EXT_STATE_CHANGE | sync_flag |
					op | MDI_BEFORE_STATE_CHANGE);
				if (rv != MDI_SUCCESS) {
				MDI_DEBUG(2, (CE_WARN, vh->vh_dip,
				"!vo_pi_state_change: failed rv = %x", rv));
				}
			}

			MDI_PI_LOCK(pip);
			next =
				(mdi_pathinfo_t *)MDI_PI(pip)->pi_phci_link;
			switch (flags) {
			case USER_DISABLE:
				if (op == MDI_DISABLE_OP)
					MDI_PI_SET_USER_DISABLE(pip);
				else
					MDI_PI_SET_USER_ENABLE(pip);
				break;
			case DRIVER_DISABLE:
				if (op == MDI_DISABLE_OP)
					MDI_PI_SET_DRV_DISABLE(pip);
				else
					MDI_PI_SET_DRV_ENABLE(pip);
				break;
			case DRIVER_DISABLE_TRANSIENT:
				if (op == MDI_DISABLE_OP && rv == MDI_SUCCESS)
					MDI_PI_SET_DRV_DISABLE_TRANS(pip);
				else
					MDI_PI_SET_DRV_ENABLE_TRANS(pip);
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
				MDI_DEBUG(2, (CE_WARN, vh->vh_dip,
				"!vo_pi_state_change: failed rv = %x", rv));
				}
			}
			pip = next;
		}
		MDI_PHCI_UNLOCK(ph);
	} else {

		/*
		 * Disable a specific client.
		 */
		ct = i_devi_get_client(cdip);
		if (ct == NULL) {
			MDI_DEBUG(1, (CE_NOTE, NULL,
			"!i_mdi_pi_enable_disable:"
			" failed. ct = NULL operation = %d\n", op));
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
			MDI_DEBUG(1, (CE_NOTE, NULL,
			"!i_mdi_pi_enable_disable:"
			" failed. Could not find corresponding pip\n"));
			return (MDI_FAILURE);
		}
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
				MDI_DEBUG(2, (CE_WARN, vh->vh_dip,
				"!vo_pi_state_change: failed rv = %x", rv));
			}
		}
		MDI_PI_LOCK(pip);
		switch (flags) {
			case USER_DISABLE:
				if (op == MDI_DISABLE_OP)
					MDI_PI_SET_USER_DISABLE(pip);
				else
					MDI_PI_SET_USER_ENABLE(pip);
				break;
			case DRIVER_DISABLE:
				if (op == MDI_DISABLE_OP)
					MDI_PI_SET_DRV_DISABLE(pip);
				else
					MDI_PI_SET_DRV_ENABLE(pip);
				break;
			case DRIVER_DISABLE_TRANSIENT:
				if (op == MDI_DISABLE_OP && rv == MDI_SUCCESS)
					MDI_PI_SET_DRV_DISABLE_TRANS(pip);
				else
					MDI_PI_SET_DRV_ENABLE_TRANS(pip);
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
				MDI_DEBUG(2, (CE_WARN, vh->vh_dip,
				"!vo_pi_state_change: failed rv = %x", rv));
			}
		}
	}

	MDI_DEBUG(5, (CE_NOTE, NULL, "!i_mdi_pi_enable_disable:"
		" Returning success pdip = %p cdip = %p\n", op, pdip, cdip));
	return (MDI_SUCCESS);
}

/*ARGSUSED3*/
int
mdi_devi_config_one(dev_info_t *pdip, char *devnm, dev_info_t **cdipp,
    int flags, clock_t timeout)
{
	mdi_pathinfo_t *pip;
	dev_info_t *dip;
	clock_t interval = drv_usectohz(100000);	/* 0.1 sec */
	char *paddr;

	MDI_DEBUG(2, (CE_NOTE, NULL, "configure device %s", devnm));

	if (!MDI_PHCI(pdip))
		return (MDI_FAILURE);

	paddr = strchr(devnm, '@');
	if (paddr == NULL)
		return (MDI_FAILURE);

	paddr++;	/* skip '@' */
	pip = mdi_pi_find(pdip, NULL, paddr);
	while (pip == NULL && timeout > 0) {
		if (interval > timeout)
			interval = timeout;
		if (flags & NDI_DEVI_DEBUG) {
			cmn_err(CE_CONT, "%s%d: %s timeout %ld %ld\n",
			    ddi_driver_name(pdip), ddi_get_instance(pdip),
			    paddr, interval, timeout);
		}
		delay(interval);
		timeout -= interval;
		interval += interval;
		pip = mdi_pi_find(pdip, NULL, paddr);
	}

	if (pip == NULL)
		return (MDI_FAILURE);
	dip = mdi_pi_get_client(pip);
	if (ndi_devi_online(dip, flags) != NDI_SUCCESS)
		return (MDI_FAILURE);
	*cdipp = dip;

	/* TODO: holding should happen inside search functions */
	ndi_hold_devi(dip);
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
	ASSERT(MUTEX_HELD(&MDI_PI(pip)->pi_mutex));

	if (MDI_PI(pip)->pi_pm_held) {
		return;
	}

	ph_dip = mdi_pi_get_phci(pip);
	MDI_DEBUG(4, (CE_NOTE, ph_dip, "i_mdi_pm_hold_pip for %s%d\n",
	    ddi_get_name(ph_dip), ddi_get_instance(ph_dip)));
	if (ph_dip == NULL) {
		return;
	}

	MDI_PI_UNLOCK(pip);
	MDI_DEBUG(4, (CE_NOTE, ph_dip, "kidsupcnt was %d\n",
	    DEVI(ph_dip)->devi_pm_kidsupcnt));
	pm_hold_power(ph_dip);
	MDI_DEBUG(4, (CE_NOTE, ph_dip, "kidsupcnt is %d\n",
	    DEVI(ph_dip)->devi_pm_kidsupcnt));
	MDI_PI_LOCK(pip);

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
	ASSERT(MUTEX_HELD(&MDI_PI(pip)->pi_mutex));

	if (MDI_PI(pip)->pi_pm_held == 0) {
		return;
	}

	ph_dip = mdi_pi_get_phci(pip);
	ASSERT(ph_dip != NULL);

	MDI_PI_UNLOCK(pip);
	MDI_DEBUG(4, (CE_NOTE, ph_dip, "i_mdi_pm_rele_pip for %s%d\n",
	    ddi_get_name(ph_dip), ddi_get_instance(ph_dip)));

	MDI_DEBUG(4, (CE_NOTE, ph_dip, "kidsupcnt was %d\n",
	    DEVI(ph_dip)->devi_pm_kidsupcnt));
	pm_rele_power(ph_dip);
	MDI_DEBUG(4, (CE_NOTE, ph_dip, "kidsupcnt is %d\n",
	    DEVI(ph_dip)->devi_pm_kidsupcnt));

	MDI_PI_LOCK(pip);
	MDI_PI(pip)->pi_pm_held = 0;
}

static void
i_mdi_pm_hold_client(mdi_client_t *ct, int incr)
{
	ASSERT(ct);

	ct->ct_power_cnt += incr;
	MDI_DEBUG(4, (CE_NOTE, ct->ct_dip, "i_mdi_pm_hold_client "
	    "ct_power_cnt = %d incr = %d\n", ct->ct_power_cnt, incr));
	ASSERT(ct->ct_power_cnt >= 0);
}

static void
i_mdi_rele_all_phci(mdi_client_t *ct)
{
	mdi_pathinfo_t  *pip;

	ASSERT(mutex_owned(&ct->ct_mutex));
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
	ASSERT(ct);

	if (i_ddi_node_state(ct->ct_dip) >= DS_READY) {
		ct->ct_power_cnt -= decr;
		MDI_DEBUG(4, (CE_NOTE, ct->ct_dip, "i_mdi_pm_rele_client "
		    "ct_power_cnt = %d decr = %d\n", ct->ct_power_cnt, decr));
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
	MDI_DEBUG(4, (CE_NOTE, ct->ct_dip, "i_mdi_pm_reset_client "
	    "ct_power_cnt = %d\n", ct->ct_power_cnt));
	ct->ct_power_cnt = 0;
	i_mdi_rele_all_phci(ct);
	ct->ct_powercnt_reset = 1;
	ct->ct_powercnt_held = 0;
}

static void
i_mdi_pm_hold_all_phci(mdi_client_t *ct)
{
	mdi_pathinfo_t  *pip;
	ASSERT(mutex_owned(&ct->ct_mutex));

	pip = (mdi_pathinfo_t *)ct->ct_path_head;
	while (pip != NULL) {
		mdi_hold_path(pip);
		MDI_PI_LOCK(pip);
		i_mdi_pm_hold_pip(pip);
		MDI_PI_UNLOCK(pip);
		mdi_rele_path(pip);
		pip = (mdi_pathinfo_t *)MDI_PI(pip)->pi_client_link;
	}
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
	MDI_DEBUG(4, (CE_NOTE, ph_dip, "i_mdi_power_one_phci "
	    "pm_powerup for %s%d\n", ddi_get_name(ph_dip),
	    ddi_get_instance(ph_dip)));

	ret = pm_powerup(ph_dip);

	if (ret == DDI_FAILURE) {
		MDI_DEBUG(4, (CE_NOTE, ph_dip, "i_mdi_power_one_phci "
		    "pm_powerup FAILED for %s%d\n",
		    ddi_get_name(ph_dip), ddi_get_instance(ph_dip)));

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

	pip = (mdi_pathinfo_t *)ct->ct_path_head;
	while (pip != NULL) {
		mdi_hold_path(pip);
		MDI_CLIENT_UNLOCK(ct);
		if (i_mdi_power_one_phci(pip) == MDI_SUCCESS)
			succeeded = 1;

		ASSERT(ct == MDI_PI(pip)->pi_client);
		MDI_CLIENT_LOCK(ct);
		mdi_rele_path(pip);
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
		MDI_DEBUG(4, (CE_NOTE, bpc->bpc_dip, "mdi_bus_power "
		    "BUS_POWER_PRE_NOTIFICATION:"
		    "%s@%s, olevel=%d, nlevel=%d, comp=%d\n",
		    PM_NAME(bpc->bpc_dip), PM_ADDR(bpc->bpc_dip),
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
				MDI_DEBUG(4, (CE_NOTE, bpc->bpc_dip,
				    "mdi_bus_power i_mdi_pm_hold_client\n"));
				i_mdi_pm_hold_client(ct, ct->ct_path_count);
			}
		}
		break;
	case BUS_POWER_POST_NOTIFICATION:
		MDI_DEBUG(4, (CE_NOTE, bpc->bpc_dip, "mdi_bus_power "
		    "BUS_POWER_POST_NOTIFICATION:"
		    "%s@%s, olevel=%d, nlevel=%d, comp=%d result=%d\n",
		    PM_NAME(bpc->bpc_dip), PM_ADDR(bpc->bpc_dip),
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
			MDI_DEBUG(4, (CE_NOTE, bpc->bpc_dip,
			    "mdi_bus_power i_mdi_pm_rele_client\n"));
			i_mdi_pm_rele_client(ct, ct->ct_path_count);
		}

		if (bpc->bpc_nlevel == 0 && (*(int *)result == DDI_SUCCESS)) {
			/* another thread might started attaching */
			if (DEVI_IS_ATTACHING(ct->ct_dip)) {
				MDI_DEBUG(4, (CE_NOTE, bpc->bpc_dip,
				    "mdi_bus_power i_mdi_pm_rele_client\n"));
				i_mdi_pm_rele_client(ct, ct->ct_path_count);
			/* detaching has been taken care in pm_post_unconfig */
			} else if (!DEVI_IS_DETACHING(ct->ct_dip)) {
				MDI_DEBUG(4, (CE_NOTE, bpc->bpc_dip,
				    "mdi_bus_power i_mdi_pm_reset_client\n"));
				i_mdi_pm_reset_client(ct);
			}
		}

		MDI_CLIENT_CLEAR_POWER_TRANSITION(ct);
		cv_broadcast(&ct->ct_powerchange_cv);

		break;

	/* need to do more */
	case BUS_POWER_HAS_CHANGED:
		MDI_DEBUG(4, (CE_NOTE, bphc->bphc_dip, "mdi_bus_power "
		    "BUS_POWER_HAS_CHANGED:"
		    "%s@%s, olevel=%d, nlevel=%d, comp=%d\n",
		    PM_NAME(bphc->bphc_dip), PM_ADDR(bphc->bphc_dip),
		    bphc->bphc_olevel, bphc->bphc_nlevel, bphc->bphc_comp));

		if (bphc->bphc_nlevel > 0 &&
		    bphc->bphc_nlevel > bphc->bphc_olevel) {
			if (ct->ct_power_cnt == 0) {
				ret = i_mdi_power_all_phci(ct);
			}
			MDI_DEBUG(4, (CE_NOTE, bphc->bphc_dip,
			    "mdi_bus_power i_mdi_pm_hold_client\n"));
			i_mdi_pm_hold_client(ct, ct->ct_path_count);
		}

		if (bphc->bphc_nlevel == 0 && bphc->bphc_olevel != -1) {
			MDI_DEBUG(4, (CE_NOTE, bphc->bphc_dip,
			    "mdi_bus_power i_mdi_pm_rele_client\n"));
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
		MDI_DEBUG(4, (CE_NOTE, child,
		    "i_mdi_pm_pre_config_one already configured\n"));
		return (MDI_SUCCESS);
	}

	if (ct->ct_powercnt_held) {
		MDI_CLIENT_UNLOCK(ct);
		MDI_DEBUG(4, (CE_NOTE, child,
		    "i_mdi_pm_pre_config_one ALREADY held\n"));
		return (MDI_SUCCESS);
	}

	if (ct->ct_power_cnt == 0) {
		ret = i_mdi_power_all_phci(ct);
	}
	MDI_DEBUG(4, (CE_NOTE, child,
	    "i_mdi_pm_pre_config_one i_mdi_pm_hold_client\n"));
	i_mdi_pm_hold_client(ct, ct->ct_path_count);
	ct->ct_powercnt_held = 1;
	ct->ct_powercnt_reset = 0;
	MDI_CLIENT_UNLOCK(ct);
	return (ret);
}

static int
i_mdi_pm_pre_config(dev_info_t *parent, dev_info_t *child)
{
	int			ret = MDI_SUCCESS;
	dev_info_t		*cdip;
	int			circ;

	ASSERT(MDI_VHCI(parent));

	/* ndi_devi_config_one */
	if (child) {
		return (i_mdi_pm_pre_config_one(child));
	}

	/* devi_config_common */
	ndi_devi_enter(parent, &circ);
	cdip = ddi_get_child(parent);
	while (cdip) {
		dev_info_t *next = ddi_get_next_sibling(cdip);

		ret = i_mdi_pm_pre_config_one(cdip);
		if (ret != MDI_SUCCESS)
			break;
		cdip = next;
	}
	ndi_devi_exit(parent, circ);
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

	if (i_ddi_node_state(ct->ct_dip) < DS_READY) {
		MDI_DEBUG(4, (CE_NOTE, child,
		    "i_mdi_pm_pre_unconfig node detached already\n"));
		MDI_CLIENT_UNLOCK(ct);
		return (MDI_SUCCESS);
	}

	if (MDI_CLIENT_IS_POWERED_DOWN(ct) &&
	    (flags & NDI_AUTODETACH)) {
		MDI_DEBUG(4, (CE_NOTE, child,
		    "i_mdi_pm_pre_unconfig auto-modunload\n"));
		MDI_CLIENT_UNLOCK(ct);
		return (MDI_FAILURE);
	}

	if (ct->ct_powercnt_held) {
		MDI_DEBUG(4, (CE_NOTE, child,
		    "i_mdi_pm_pre_unconfig ct_powercnt_held\n"));
		MDI_CLIENT_UNLOCK(ct);
		*held = 1;
		return (MDI_SUCCESS);
	}

	if (ct->ct_power_cnt == 0) {
		ret = i_mdi_power_all_phci(ct);
	}
	MDI_DEBUG(4, (CE_NOTE, child,
	    "i_mdi_pm_pre_unconfig i_mdi_pm_hold_client\n"));
	i_mdi_pm_hold_client(ct, ct->ct_path_count);
	ct->ct_powercnt_held = 1;
	ct->ct_powercnt_reset = 0;
	MDI_CLIENT_UNLOCK(ct);
	if (ret == MDI_SUCCESS)
		*held = 1;
	return (ret);
}

static int
i_mdi_pm_pre_unconfig(dev_info_t *parent, dev_info_t *child, int *held,
    int flags)
{
	int			ret = MDI_SUCCESS;
	dev_info_t		*cdip;
	int			circ;

	ASSERT(MDI_VHCI(parent));
	*held = 0;

	/* ndi_devi_unconfig_one */
	if (child) {
		return (i_mdi_pm_pre_unconfig_one(child, held, flags));
	}

	/* devi_unconfig_common */
	ndi_devi_enter(parent, &circ);
	cdip = ddi_get_child(parent);
	while (cdip) {
		dev_info_t *next = ddi_get_next_sibling(cdip);

		ret = i_mdi_pm_pre_unconfig_one(cdip, held, flags);
		cdip = next;
	}
	ndi_devi_exit(parent, circ);

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

	if (ct->ct_powercnt_reset || !ct->ct_powercnt_held) {
		MDI_DEBUG(4, (CE_NOTE, child,
		    "i_mdi_pm_post_config_one NOT held\n"));
		MDI_CLIENT_UNLOCK(ct);
		return;
	}

	/* client has not been updated */
	if (MDI_CLIENT_IS_FAILED(ct)) {
		MDI_DEBUG(4, (CE_NOTE, child,
		    "i_mdi_pm_post_config_one NOT configured\n"));
		MDI_CLIENT_UNLOCK(ct);
		return;
	}

	/* another thread might have powered it down or detached it */
	if ((MDI_CLIENT_IS_POWERED_DOWN(ct) &&
	    !DEVI_IS_ATTACHING(ct->ct_dip)) ||
	    (i_ddi_node_state(ct->ct_dip) < DS_READY &&
	    !DEVI_IS_ATTACHING(ct->ct_dip))) {
		MDI_DEBUG(4, (CE_NOTE, child,
		    "i_mdi_pm_post_config i_mdi_pm_reset_client\n"));
		i_mdi_pm_reset_client(ct);
	} else {
		mdi_pathinfo_t	*pip, *next;
		int	valid_path_count = 0;

		MDI_DEBUG(4, (CE_NOTE, child,
		    "i_mdi_pm_post_config i_mdi_pm_rele_client\n"));
		pip = ct->ct_path_head;
		while (pip != NULL) {
			MDI_PI_LOCK(pip);
			next = (mdi_pathinfo_t *)MDI_PI(pip)->pi_client_link;
			if ((MDI_PI(pip)->pi_state & MDI_PATHINFO_STATE_MASK)
				== MDI_PATHINFO_STATE_ONLINE ||
			    (MDI_PI(pip)->pi_state & MDI_PATHINFO_STATE_MASK)
				== MDI_PATHINFO_STATE_STANDBY)
				valid_path_count ++;
			MDI_PI_UNLOCK(pip);
			pip = next;
		}
		i_mdi_pm_rele_client(ct, valid_path_count);
	}
	ct->ct_powercnt_held = 0;
	MDI_CLIENT_UNLOCK(ct);
}

static void
i_mdi_pm_post_config(dev_info_t *parent, dev_info_t *child)
{
	int		circ;
	dev_info_t	*cdip;
	ASSERT(MDI_VHCI(parent));

	/* ndi_devi_config_one */
	if (child) {
		i_mdi_pm_post_config_one(child);
		return;
	}

	/* devi_config_common */
	ndi_devi_enter(parent, &circ);
	cdip = ddi_get_child(parent);
	while (cdip) {
		dev_info_t *next = ddi_get_next_sibling(cdip);

		i_mdi_pm_post_config_one(cdip);
		cdip = next;
	}
	ndi_devi_exit(parent, circ);
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

	if (!ct->ct_powercnt_held) {
		MDI_DEBUG(4, (CE_NOTE, child,
		    "i_mdi_pm_post_unconfig NOT held\n"));
		MDI_CLIENT_UNLOCK(ct);
		return;
	}

	/* failure detaching or another thread just attached it */
	if ((MDI_CLIENT_IS_POWERED_DOWN(ct) &&
	    i_ddi_node_state(ct->ct_dip) == DS_READY) ||
	    (i_ddi_node_state(ct->ct_dip) != DS_READY &&
	    !DEVI_IS_ATTACHING(ct->ct_dip))) {
		MDI_DEBUG(4, (CE_NOTE, child,
		    "i_mdi_pm_post_unconfig i_mdi_pm_reset_client\n"));
		i_mdi_pm_reset_client(ct);
	}

	MDI_DEBUG(4, (CE_NOTE, child,
	    "i_mdi_pm_post_unconfig not changed\n"));
	MDI_CLIENT_UNLOCK(ct);
}

static void
i_mdi_pm_post_unconfig(dev_info_t *parent, dev_info_t *child, int held)
{
	int			circ;
	dev_info_t		*cdip;

	ASSERT(MDI_VHCI(parent));

	if (!held) {
		MDI_DEBUG(4, (CE_NOTE, parent,
		    "i_mdi_pm_post_unconfig held = %d\n", held));
		return;
	}

	if (child) {
		i_mdi_pm_post_unconfig_one(child);
		return;
	}

	ndi_devi_enter(parent, &circ);
	cdip = ddi_get_child(parent);
	while (cdip) {
		dev_info_t *next = ddi_get_next_sibling(cdip);

		i_mdi_pm_post_unconfig_one(cdip);
		cdip = next;
	}
	ndi_devi_exit(parent, circ);
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
		ndi_devi_exit(vdip, circ);
	}

	MDI_DEBUG(4, (CE_NOTE, vdip, "mdi_power op = %d\n", op));

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
				MDI_DEBUG(4, (CE_NOTE, client_dip,
				    "mdi_power i_mdi_pm_hold_client\n"));
				i_mdi_pm_hold_client(ct, ct->ct_path_count);
			}
		} else {
			if (DEVI_IS_ATTACHING(ct->ct_dip)) {
				MDI_DEBUG(4, (CE_NOTE, client_dip,
				    "mdi_power i_mdi_pm_rele_client\n"));
				i_mdi_pm_rele_client(ct, ct->ct_path_count);
			} else {
				MDI_DEBUG(4, (CE_NOTE, client_dip,
				    "mdi_power i_mdi_pm_reset_client\n"));
				i_mdi_pm_reset_client(ct);
			}
		}

		MDI_CLIENT_UNLOCK(ct);
		break;
	default:
		break;
	}

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

/*
 * XXX This list should include all phci drivers needed during boot time
 * though it currently contains "fp" only.
 * Hopefully, the mechanism provided here will be replaced with a better
 * mechanism by vhci driven enumeration project.
 */
static char *phci_driver_list[] = { "fp" };
#define	N_PHCI_DRIVERS	(sizeof (phci_driver_list) / sizeof (char *))

static void
i_mdi_attach_phci_drivers()
{
	int  i;
	major_t m;

	for (i = 0; i < N_PHCI_DRIVERS; i++) {
		m = ddi_name_to_major(phci_driver_list[i]);
		if (m != (major_t)-1) {
			if (ddi_hold_installed_driver(m) != NULL)
				ddi_rele_driver(m);
		}
	}
}

/* bus config the specified phci */
static void
i_mdi_phci_bus_config(void *arg)
{
	mdi_phci_config_t *phc = (mdi_phci_config_t *)arg;
	mdi_vhci_config_t *vhc;
	dev_info_t	*ph_dip;
	int		rv;

	ASSERT(phc);
	vhc = phc->phc_vhc;
	ASSERT(vhc->vhc_op == BUS_CONFIG_ALL ||
	    vhc->vhc_op == BUS_CONFIG_DRIVER);

	/*
	 * Must have already held the phci parent in
	 * i_mdi_bus_config_all_phcis().
	 * First configure the phci itself.
	 */
	rv = ndi_devi_config_one(phc->phc_parent_dip, phc->phc_devnm + 1,
	    &ph_dip, vhc->vhc_flags);

	/* release the hold that i_mdi_bus_config_all_phcis() placed */
	ndi_rele_devi(phc->phc_parent_dip);

	if (rv == NDI_SUCCESS) {
		/* now bus config the phci */
		if (vhc->vhc_op == BUS_CONFIG_DRIVER) {
			(void) ndi_devi_config_driver(ph_dip, vhc->vhc_flags,
				vhc->vhc_major);
		} else
			(void) ndi_devi_config(ph_dip, vhc->vhc_flags);

		/* release the hold that ndi_devi_config_one() placed */
		ndi_rele_devi(ph_dip);
	}
}

/*
 * Bus config all registered phcis associated with the vhci in parallel.
 * This process guarantees that the child nodes are enumerated under the vhci,
 * but not necessarily attached.
 * op must be BUS_CONFIG_DRIVER or BUS_CONFIG_ALL.
 */
static int
i_mdi_bus_config_all_phcis(dev_info_t *vdip, uint_t flags,
    ddi_bus_config_op_t op, major_t maj, int optimize)
{
	mdi_vhci_t		*vh;
	mdi_phci_t		*ph;
	mdi_phci_config_t	*phc;
	int64_t			req_time;
	int			phci_count, rv;
	static int		first_time = 1;

	ASSERT(op == BUS_CONFIG_ALL || op == BUS_CONFIG_DRIVER);
	ASSERT(!DEVI_BUSY_OWNED(vdip));

	MDI_DEBUG(2, (CE_NOTE, vdip,
	    "!MDI: %s on all phcis: major = %d, flags = 0x%x, optimize = %d\n",
	    (op == BUS_CONFIG_DRIVER) ? "BUS_CONFIG_DRIVER" : "BUS_CONFIG_ALL",
	    (int)maj, flags, optimize));

	vh = i_devi_get_vhci(vdip);
	ASSERT(vh);

	mutex_enter(&mdi_mutex);

	req_time = lbolt64;

	/*
	 * Reduce unnecessary BUS_CONFIG_ALLs when opening stale
	 * /dev/[r]dsk links.
	 */
	if (optimize && (req_time < vh->vh_bus_config.vhc_cutoff_time)) {
		mutex_exit(&mdi_mutex);
		return (MDI_SUCCESS);
	}

	/*
	 * To initiate bus configs on all phcis in parallel, create a taskq
	 * with multiple threads. Since creation of a taskq is a heavy weight
	 * operation, taskq is created once per vhci and destroyed only when
	 * vhci unregisters with mdi.
	 *
	 * If multiple bus config requests arrive at a time, bus configs on
	 * phcis are initiated on behalf of one of the requests. Other requests
	 * wait until the bus configs on phcis is done.
	 *
	 * When a BUS_CONFIG_ALL on phcis completes, the following is done
	 * to avoid more of unnecessary bus configs.
	 *
	 *	o all BUS_CONFIG_ALL requests currently waiting with optimize
	 *	flag set are returned, i.e., no new BUS_CONFIG_ALL is initiated
	 *	on phcis on behalf of these requests.
	 *
	 *	o all BUS_CONFIG_ALL or BUS_CONFIG_DRIVER requests currently
	 *	waiting but have arrived prior to initiating BUS_CONFIG_ALL on
	 *	phcis are also returned.
	 *
	 * In other cases a new BUS_CONFIG_ALL or BUS_CONFIG_DRIVER is
	 * initiated on phcis on behalf of a new request.
	 */

	/* check if a bus config on phcis is in progress */
	while (vh->vh_bus_config.vhc_start_time != 0) {
		ddi_bus_config_op_t current_op;
		int64_t start_time;

		current_op = vh->vh_bus_config.vhc_op;
		start_time = vh->vh_bus_config.vhc_start_time;

		/* wait until the current bus configs on phcis are done */
		while (vh->vh_bus_config.vhc_start_time == start_time)
			cv_wait(&vh->vh_bus_config.vhc_cv, &mdi_mutex);

		if (current_op == BUS_CONFIG_ALL &&
		    vh->vh_bus_config.vhc_cutoff_time > 0 && (optimize ||
		    req_time < start_time)) {
			mutex_exit(&mdi_mutex);
			return (MDI_SUCCESS);
		}
	}

	/*
	 * At this point we are single threaded until vh_bus_config.start_time
	 * is reset to 0 at the end of this function.
	 */

	vh->vh_bus_config.vhc_op = op;
	vh->vh_bus_config.vhc_major = maj;
	vh->vh_bus_config.vhc_flags = flags;
	vh->vh_bus_config.vhc_start_time = lbolt64;

	if (first_time && strcmp(vh->vh_class, MDI_HCI_CLASS_SCSI) == 0) {
		mutex_exit(&mdi_mutex);
		i_mdi_attach_phci_drivers();
		mutex_enter(&mdi_mutex);
		first_time = 0;
	}

	ASSERT(vh->vh_phci_count >= 0);
	if (vh->vh_phci_count == 0) {
		rv = MDI_SUCCESS;
		goto out1;
	}

	/*
	 * Create a taskq to initiate bus configs in parallel on phcis.
	 * Taskq allocation can be done in mdi_vhci_register() routine
	 * instead of here. For most systems, doing it here on demand saves
	 * resources as this code path is never called most of the times.
	 */
	if (vh->vh_bus_config.vhc_taskq == NULL) {
		/*
		 * it is ok even if vh->vh_phci_count changes after we release
		 * the mdi_mutex as phci_count is used just as an
		 * advisory number to taskq_create.
		 */
		phci_count = vh->vh_phci_count;
		mutex_exit(&mdi_mutex);

		/*
		 * As we are single threaded, it is ok to access the
		 * vh_bus_config.taskq member of vh outside of mdi_mutex
		 */
		if ((vh->vh_bus_config.vhc_taskq = taskq_create(
		    "mdi_bus_config_taskq", mdi_max_bus_config_threads,
		    MDI_TASKQ_PRI, phci_count, INT_MAX,
		    TASKQ_PREPOPULATE | TASKQ_DYNAMIC)) == NULL) {
			rv = MDI_FAILURE;
			goto out;
		}

		mutex_enter(&mdi_mutex);
	}

	/* allocate at least vh->vh_phci_count phci bus config structures */
	while (vh->vh_bus_config.vhc_phc_cnt < vh->vh_phci_count) {
		int count;

		count = vh->vh_phci_count - vh->vh_bus_config.vhc_phc_cnt;
		mutex_exit(&mdi_mutex);
		while (count--) {
			phc = kmem_alloc(sizeof (*phc), KM_SLEEP);
			phc->phc_vhc = &vh->vh_bus_config;
			/*
			 * there is no need to hold a lock here as we
			 * are single threaded and no one else manipulates
			 * the list while we are here.
			 */
			phc->phc_next = vh->vh_bus_config.vhc_phc;
			vh->vh_bus_config.vhc_phc = phc;
			vh->vh_bus_config.vhc_phc_cnt++;
		}
		mutex_enter(&mdi_mutex);
		/*
		 * as new phcis could register with mdi after we dropped
		 * the mdi_mutex, we need to recheck the vh->vh_phci_count.
		 * Hence the while loop.
		 */
	}

	for (ph = vh->vh_phci_head, phc = vh->vh_bus_config.vhc_phc;
	    ph != NULL; ph = ph->ph_next, phc = phc->phc_next) {

		ASSERT(phc != NULL);

		/* build a phci config handle to be passed to a taskq thread */
		MDI_PHCI_LOCK(ph);
		ASSERT(ph->ph_dip);

		/*
		 * We need to hold the phci dip before bus configuring the phci.
		 * But placing a hold on the phci dip is not safe here due to
		 * the race with phci detach. To get around this race,
		 * we place a hold on the phci dip's parent and note down
		 * the phci's name@addr. Later, in i_mdi_phci_bus_config(),
		 * we'll first configure the phci itself before bus
		 * configuring the phci.
		 */
		phc->phc_parent_dip = ddi_get_parent(ph->ph_dip);
		ndi_hold_devi(phc->phc_parent_dip);
		(void) ddi_deviname(ph->ph_dip, phc->phc_devnm);
		MDI_PHCI_UNLOCK(ph);
	}

	phci_count = vh->vh_phci_count;
	if (vh->vh_bus_config.vhc_cutoff_time == -1)
		vh->vh_bus_config.vhc_cutoff_time = 0;
	mutex_exit(&mdi_mutex);

	MDI_DEBUG(2, (CE_NOTE, vdip,
	    "!MDI: initiating %s on all phcis, major = %d, flags = 0x%x\n",
	    (op == BUS_CONFIG_DRIVER) ? "BUS_CONFIG_DRIVER" : "BUS_CONFIG_ALL",
	    (int)maj, flags));

	/*
	 * again, no need to hold a lock here as we are single threaded and
	 * no one else manipulates the list while we are here.
	 */
	for (phc = vh->vh_bus_config.vhc_phc; phci_count--;
	    phc = phc->phc_next) {
		(void) taskq_dispatch(vh->vh_bus_config.vhc_taskq,
		    i_mdi_phci_bus_config, phc, TQ_SLEEP);
	}

	/* wait until all phci bus configs are done */
	taskq_wait(vh->vh_bus_config.vhc_taskq);
	rv = MDI_SUCCESS;

out:
	mutex_enter(&mdi_mutex);
out1:
	vh->vh_bus_config.vhc_start_time = 0;
	if (op == BUS_CONFIG_ALL && vh->vh_bus_config.vhc_cutoff_time != -1) {
		vh->vh_bus_config.vhc_cutoff_time = lbolt64 +
		    (int64_t)drv_usectohz(mdi_bus_config_timeout * 1000000);
	}
	cv_broadcast(&vh->vh_bus_config.vhc_cv);
	mutex_exit(&mdi_mutex);

	MDI_DEBUG(2, (CE_NOTE, vdip, "!MDI: %s on all phcis %s\n",
	    (op == BUS_CONFIG_DRIVER) ? "BUS_CONFIG_DRIVER" : "BUS_CONFIG_ALL",
	    (rv == MDI_SUCCESS) ? "successful" : "failed"));

	return (rv);
}

/*
 * A simple bus config implementation for vhcis with the assumption that all
 * phcis are always registered with MDI.
 *
 * BUS_CONFIG_ALL
 *
 * 	Do BUS_CONFIG_ALL on all phcis associated with the vhci.
 *
 * BUS_CONFIG_DRIVER
 *
 * 	Do BUS_CONFIG_DRIVER on all phcis associated with the vhci.
 *
 * BUS_CONFIG_ONE
 *
 *	If the requested child has already been enumerated under the vhci
 *	configure the child and return. Otherwise do BUS_CONFIG_ALL on all
 *	phcis associated with the vhci.
 */
int
mdi_vhci_bus_config(dev_info_t *vdip, uint_t flags, ddi_bus_config_op_t op,
    void *arg, dev_info_t **child)
{
	int rv = MDI_SUCCESS;

	/*
	 * While bus configuring phcis, the phci driver interactions with MDI
	 * cause child nodes to be enumerated under the vhci node for which
	 * they need to ndi_devi_enter the vhci node.
	 *
	 * Unfortunately, to avoid the deadlock, we ourself can not wait for
	 * for the bus config operations on phcis to finish while holding the
	 * ndi_devi_enter lock. To avoid this deadlock, skip bus configs on
	 * phcis and call the default framework provided bus config function
	 * if we are called with ndi_devi_enter lock held.
	 */
	if (DEVI_BUSY_OWNED(vdip)) {
		MDI_DEBUG(2, (CE_NOTE, vdip,
		    "!MDI: vhci bus config: vhci dip is busy owned\n"));
		goto default_bus_config;
	}

	switch (op) {
	case BUS_CONFIG_ONE:
		/*
		 * First try to directly configure the requested child.
		 * This will work only if the requested child has already
		 * been enumerated under vhci, which is usually the most common
		 * case.
		 */
		if (ndi_busop_bus_config(vdip, flags, op, arg, child, 0) ==
		    NDI_SUCCESS) {
			return (MDI_SUCCESS);
		}

		MDI_DEBUG(2, (CE_NOTE, vdip, "!MDI: BUS_CONFIG_ONE on %s: "
		    "will do BUS_CONFIG_ALL on all phcis\n", (char *)arg));

		/* now do BUS_CONFIG_ALL on all phcis */
		rv = i_mdi_bus_config_all_phcis(vdip, flags,
		    BUS_CONFIG_ALL, -1, 1);
		break;

	case BUS_CONFIG_DRIVER:
		rv = i_mdi_bus_config_all_phcis(vdip, flags, op,
		    (major_t)(uintptr_t)arg, 0);
		break;

	case BUS_CONFIG_ALL:
		rv = i_mdi_bus_config_all_phcis(vdip, flags, op, -1, 0);
		break;

	default:
		break;
	}

default_bus_config:
	/*
	 * i_mdi_bus_config_all_phcis() guarantees that child nodes are
	 * enumerated under the vhci, but not necessarily attached.
	 * Now configure the appropriate child nodes.
	 */
	if (rv == MDI_SUCCESS &&
	    ndi_busop_bus_config(vdip, flags, op, arg, child, 0) ==
	    NDI_SUCCESS) {
		return (MDI_SUCCESS);
	}

	return (MDI_FAILURE);
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
