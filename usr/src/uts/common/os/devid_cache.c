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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/note.h>
#include <sys/t_lock.h>
#include <sys/cmn_err.h>
#include <sys/instance.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/hwconf.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sunmdi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/kobj.h>
#include <sys/devcache.h>
#include <sys/devid_cache.h>
#include <sys/sysmacros.h>

/*
 * Discovery refers to the heroic effort made to discover a device which
 * cannot be accessed at the physical path where it once resided.  Discovery
 * involves walking the entire device tree attaching all possible disk
 * instances, to search for the device referenced by a devid.  Obviously,
 * full device discovery is something to be avoided where possible.
 * Note that simply invoking devfsadm(1M) is equivalent to running full
 * discovery at the devid cache level.
 *
 * Reasons why a disk may not be accessible:
 *	disk powered off
 *	disk removed or cable disconnected
 *	disk or adapter broken
 *
 * Note that discovery is not needed and cannot succeed in any of these
 * cases.
 *
 * When discovery may succeed:
 *	Discovery will result in success when a device has been moved
 *	to a different address.  Note that it's recommended that
 *	devfsadm(1M) be invoked (no arguments required) whenever a system's
 *	h/w configuration has been updated.  Alternatively, a
 *	reconfiguration boot can be used to accomplish the same result.
 *
 * Note that discovery is not necessary to be able to correct an access
 * failure for a device which was powered off.  Assuming the cache has an
 * entry for such a device, simply powering it on should permit the system
 * to access it.  If problems persist after powering it on, invoke
 * devfsadm(1M).
 *
 * Discovery prior to mounting root is only of interest when booting
 * from a filesystem which accesses devices by device id, which of
 * not all do.
 *
 * Tunables
 *
 * devid_discovery_boot (default 1)
 *	Number of times discovery will be attempted prior to mounting root.
 *	Must be done at least once to recover from corrupted or missing
 *	devid cache backing store.  Probably there's no reason to ever
 *	set this to greater than one as a missing device will remain
 *	unavailable no matter how often the system searches for it.
 *
 * devid_discovery_postboot (default 1)
 *	Number of times discovery will be attempted after mounting root.
 *	This must be performed at least once to discover any devices
 *	needed after root is mounted which may have been powered
 *	off and moved before booting.
 *	Setting this to a larger positive number will introduce
 *	some inconsistency in system operation.  Searching for a device
 *	will take an indeterminate amount of time, sometimes slower,
 *	sometimes faster.  In addition, the system will sometimes
 *	discover a newly powered on device, sometimes it won't.
 *	Use of this option is not therefore recommended.
 *
 * devid_discovery_postboot_always (default 0)
 *	Set to 1, the system will always attempt full discovery.
 *
 * devid_discovery_secs (default 0)
 *	Set to a positive value, the system will attempt full discovery
 *	but with a minimum delay between attempts.  A device search
 *	within the period of time specified will result in failure.
 *
 * devid_cache_read_disable (default 0)
 *	Set to 1 to disable reading /etc/devices/devid_cache.
 *	Devid cache will continue to operate normally but
 *	at least one discovery attempt will be required.
 *
 * devid_cache_write_disable (default 0)
 *	Set to 1 to disable updates to /etc/devices/devid_cache.
 *	Any updates to the devid cache will not be preserved across a reboot.
 *
 * devid_report_error (default 0)
 *	Set to 1 to enable some error messages related to devid
 *	cache failures.
 *
 * The devid is packed in the cache file as a byte array.  For
 * portability, this could be done in the encoded string format.
 */


int devid_discovery_boot = 1;
int devid_discovery_postboot = 1;
int devid_discovery_postboot_always = 0;
int devid_discovery_secs = 0;

int devid_cache_read_disable = 0;
int devid_cache_write_disable = 0;

int devid_report_error = 0;


/*
 * State to manage discovery of devices providing a devid
 */
static int		devid_discovery_busy = 0;
static kmutex_t		devid_discovery_mutex;
static kcondvar_t	devid_discovery_cv;
static clock_t		devid_last_discovery = 0;


#ifdef	DEBUG
int nvp_devid_debug = 0;
int devid_debug = 0;
int devid_log_registers = 0;
int devid_log_finds = 0;
int devid_log_lookups = 0;
int devid_log_discovery = 0;
int devid_log_matches = 0;
int devid_log_paths = 0;
int devid_log_failures = 0;
int devid_log_hold = 0;
int devid_log_unregisters = 0;
int devid_log_removes = 0;
int devid_register_debug = 0;
int devid_log_stale = 0;
int devid_log_detaches = 0;
#endif	/* DEBUG */

/*
 * devid cache file registration for cache reads and updates
 */
static nvf_ops_t devid_cache_ops = {
	"/etc/devices/devid_cache",		/* path to cache */
	devid_cache_unpack_nvlist,		/* read: nvlist to nvp */
	devid_cache_pack_list,			/* write: nvp to nvlist */
	devid_list_free,			/* free data list */
	NULL					/* write complete callback */
};

/*
 * handle to registered devid cache handlers
 */
nvf_handle_t	dcfd_handle;


/*
 * Initialize devid cache file management
 */
void
devid_cache_init(void)
{
	dcfd_handle = nvf_register_file(&devid_cache_ops);
	ASSERT(dcfd_handle);

	list_create(nvf_list(dcfd_handle), sizeof (nvp_devid_t),
	    offsetof(nvp_devid_t, nvp_link));

	mutex_init(&devid_discovery_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&devid_discovery_cv, NULL, CV_DRIVER, NULL);
}

/*
 * Read and initialize the devid cache from the persistent store
 */
void
devid_cache_read(void)
{
	if (!devid_cache_read_disable) {
		rw_enter(nvf_lock(dcfd_handle), RW_WRITER);
		ASSERT(list_head(nvf_list(dcfd_handle)) == NULL);
		(void) nvf_read_file(dcfd_handle);
		rw_exit(nvf_lock(dcfd_handle));
	}
}

static void
devid_nvp_free(nvp_devid_t *dp)
{
	if (dp->nvp_devpath)
		kmem_free(dp->nvp_devpath, strlen(dp->nvp_devpath)+1);
	if (dp->nvp_devid)
		kmem_free(dp->nvp_devid, ddi_devid_sizeof(dp->nvp_devid));

	kmem_free(dp, sizeof (nvp_devid_t));
}

static void
devid_list_free(nvf_handle_t fd)
{
	list_t		*listp;
	nvp_devid_t	*np;

	ASSERT(RW_WRITE_HELD(nvf_lock(dcfd_handle)));

	listp = nvf_list(fd);
	while (np = list_head(listp)) {
		list_remove(listp, np);
		devid_nvp_free(np);
	}
}

/*
 * Free an nvp element in a list
 */
static void
devid_nvp_unlink_and_free(nvf_handle_t fd, nvp_devid_t *np)
{
	list_remove(nvf_list(fd), np);
	devid_nvp_free(np);
}

/*
 * Unpack a device path/nvlist pair to the list of devid cache elements.
 * Used to parse the nvlist format when reading
 * /etc/devices/devid_cache
 */
static int
devid_cache_unpack_nvlist(nvf_handle_t fd, nvlist_t *nvl, char *name)
{
	nvp_devid_t *np;
	ddi_devid_t devidp;
	int rval;
	uint_t n;

	NVP_DEVID_DEBUG_PATH((name));
	ASSERT(RW_WRITE_HELD(nvf_lock(dcfd_handle)));

	/*
	 * check path for a devid
	 */
	rval = nvlist_lookup_byte_array(nvl,
	    DP_DEVID_ID, (uchar_t **)&devidp, &n);
	if (rval == 0) {
		if (ddi_devid_valid(devidp) == DDI_SUCCESS) {
			ASSERT(n == ddi_devid_sizeof(devidp));
			np = kmem_zalloc(sizeof (nvp_devid_t), KM_SLEEP);
			np->nvp_devpath = i_ddi_strdup(name, KM_SLEEP);
			np->nvp_devid = kmem_alloc(n, KM_SLEEP);
			(void) bcopy(devidp, np->nvp_devid, n);
			list_insert_tail(nvf_list(fd), np);
			NVP_DEVID_DEBUG_DEVID((np->nvp_devid));
		} else {
			DEVIDERR((CE_CONT,
			    "%s: invalid devid\n", name));
		}
	} else {
		DEVIDERR((CE_CONT,
		    "%s: devid not available\n", name));
	}

	return (0);
}

/*
 * Pack the list of devid cache elements into a single nvlist
 * Used when writing the nvlist file.
 */
static int
devid_cache_pack_list(nvf_handle_t fd, nvlist_t **ret_nvl)
{
	nvlist_t	*nvl, *sub_nvl;
	nvp_devid_t	*np;
	int		rval;
	list_t		*listp;

	ASSERT(RW_WRITE_HELD(nvf_lock(dcfd_handle)));

	rval = nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP);
	if (rval != 0) {
		nvf_error("%s: nvlist alloc error %d\n",
		    nvf_cache_name(fd), rval);
		return (DDI_FAILURE);
	}

	listp = nvf_list(fd);
	for (np = list_head(listp); np; np = list_next(listp, np)) {
		if (np->nvp_devid == NULL)
			continue;
		NVP_DEVID_DEBUG_PATH(np->nvp_devpath);
		rval = nvlist_alloc(&sub_nvl, NV_UNIQUE_NAME, KM_SLEEP);
		if (rval != 0) {
			nvf_error("%s: nvlist alloc error %d\n",
			    nvf_cache_name(fd), rval);
			sub_nvl = NULL;
			goto err;
		}

		rval = nvlist_add_byte_array(sub_nvl, DP_DEVID_ID,
		    (uchar_t *)np->nvp_devid,
		    ddi_devid_sizeof(np->nvp_devid));
		if (rval == 0) {
			NVP_DEVID_DEBUG_DEVID(np->nvp_devid);
		} else {
			nvf_error(
			    "%s: nvlist add error %d (devid)\n",
			    nvf_cache_name(fd), rval);
			goto err;
		}

		rval = nvlist_add_nvlist(nvl, np->nvp_devpath, sub_nvl);
		if (rval != 0) {
			nvf_error("%s: nvlist add error %d (sublist)\n",
			    nvf_cache_name(fd), rval);
			goto err;
		}
		nvlist_free(sub_nvl);
	}

	*ret_nvl = nvl;
	return (DDI_SUCCESS);

err:
	nvlist_free(sub_nvl);
	nvlist_free(nvl);
	*ret_nvl = NULL;
	return (DDI_FAILURE);
}

static int
e_devid_do_discovery(void)
{
	ASSERT(mutex_owned(&devid_discovery_mutex));

	if (i_ddi_io_initialized() == 0) {
		if (devid_discovery_boot > 0) {
			devid_discovery_boot--;
			return (1);
		}
	} else {
		if (devid_discovery_postboot_always > 0)
			return (1);
		if (devid_discovery_postboot > 0) {
			devid_discovery_postboot--;
			return (1);
		}
		if (devid_discovery_secs > 0) {
			if ((ddi_get_lbolt() - devid_last_discovery) >
			    drv_usectohz(devid_discovery_secs * MICROSEC)) {
				return (1);
			}
		}
	}

	DEVID_LOG_DISC((CE_CONT, "devid_discovery: no discovery\n"));
	return (0);
}

static void
e_ddi_devid_hold_by_major(major_t major)
{
	DEVID_LOG_DISC((CE_CONT,
	    "devid_discovery: ddi_hold_installed_driver %d\n", major));

	if (ddi_hold_installed_driver(major) == NULL)
		return;

	ddi_rele_driver(major);
}

/* legacy support - see below */
static char *e_ddi_devid_hold_driver_list[] = { "sd", "ssd" };

#define	N_DRIVERS_TO_HOLD	\
	(sizeof (e_ddi_devid_hold_driver_list) / sizeof (char *))

static void
e_ddi_devid_hold_installed_driver(ddi_devid_t devid)
{
	impl_devid_t	*id = (impl_devid_t *)devid;
	major_t		major, hint_major;
	char		hint[DEVID_HINT_SIZE + 1];
	struct devnames	*dnp;
	char		**drvp;
	int		i;

	/* Count non-null bytes */
	for (i = 0; i < DEVID_HINT_SIZE; i++)
		if (id->did_driver[i] == '\0')
			break;

	/* Make a copy of the driver hint */
	bcopy(id->did_driver, hint, i);
	hint[i] = '\0';

	/* search for the devid using the hint driver */
	hint_major = ddi_name_to_major(hint);
	if (hint_major != DDI_MAJOR_T_NONE) {
		e_ddi_devid_hold_by_major(hint_major);
	}

	/*
	 * search for the devid with each driver declaring
	 * itself as a devid registrant.
	 */
	for (major = 0; major < devcnt; major++) {
		if (major == hint_major)
			continue;
		dnp = &devnamesp[major];
		if (dnp->dn_flags & DN_DEVID_REGISTRANT) {
			e_ddi_devid_hold_by_major(major);
		}
	}

	/*
	 * Legacy support: may be removed once an upgrade mechanism
	 * for driver conf files is available.
	 */
	drvp = e_ddi_devid_hold_driver_list;
	for (i = 0; i < N_DRIVERS_TO_HOLD; i++, drvp++) {
		major = ddi_name_to_major(*drvp);
		if (major != DDI_MAJOR_T_NONE && major != hint_major) {
			e_ddi_devid_hold_by_major(major);
		}
	}
}

/*
 * Return success if discovery was attempted, to indicate
 * that the desired device may now be available.
 */
int
e_ddi_devid_discovery(ddi_devid_t devid)
{
	int flags;
	int rval = DDI_SUCCESS;

	mutex_enter(&devid_discovery_mutex);

	if (devid_discovery_busy) {
		DEVID_LOG_DISC((CE_CONT, "devid_discovery: busy\n"));
		while (devid_discovery_busy) {
			cv_wait(&devid_discovery_cv, &devid_discovery_mutex);
		}
	} else if (e_devid_do_discovery()) {
		devid_discovery_busy = 1;
		mutex_exit(&devid_discovery_mutex);

		if (i_ddi_io_initialized() == 0) {
			e_ddi_devid_hold_installed_driver(devid);
		} else {
			DEVID_LOG_DISC((CE_CONT,
			    "devid_discovery: ndi_devi_config\n"));
			flags = NDI_DEVI_PERSIST | NDI_CONFIG | NDI_NO_EVENT;
			if (i_ddi_io_initialized())
				flags |= NDI_DRV_CONF_REPROBE;
			(void) ndi_devi_config(ddi_root_node(), flags);
		}

		mutex_enter(&devid_discovery_mutex);
		devid_discovery_busy = 0;
		cv_broadcast(&devid_discovery_cv);
		if (devid_discovery_secs > 0)
			devid_last_discovery = ddi_get_lbolt();
		DEVID_LOG_DISC((CE_CONT, "devid_discovery: done\n"));
	} else {
		rval = DDI_FAILURE;
		DEVID_LOG_DISC((CE_CONT, "no devid discovery\n"));
	}

	mutex_exit(&devid_discovery_mutex);

	return (rval);
}

/*
 * As part of registering a devid for a device,
 * update the devid cache with this device/devid pair
 * or note that this combination has registered.
 *
 * If a devpath is provided it will be used as the path to register the
 * devid against, otherwise we use ddi_pathname(dip).  In both cases
 * we duplicate the path string so that it can be cached/freed indepdently
 * of the original owner.
 */
static int
e_devid_cache_register_cmn(dev_info_t *dip, ddi_devid_t devid, char *devpath)
{
	nvp_devid_t *np;
	nvp_devid_t *new_nvp;
	ddi_devid_t new_devid;
	int new_devid_size;
	char *path, *fullpath;
	ddi_devid_t free_devid = NULL;
	int pathlen;
	list_t *listp;
	int is_dirty = 0;


	ASSERT(ddi_devid_valid(devid) == DDI_SUCCESS);

	if (devpath) {
		pathlen = strlen(devpath) + 1;
		path = kmem_alloc(pathlen, KM_SLEEP);
		bcopy(devpath, path, pathlen);
	} else {
		/*
		 * We are willing to accept DS_BOUND nodes if we can form a full
		 * ddi_pathname (i.e. the node is part way to becomming
		 * DS_INITIALIZED and devi_addr/ddi_get_name_addr are non-NULL).
		 */
		if (ddi_get_name_addr(dip) == NULL)
			return (DDI_FAILURE);

		fullpath = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		(void) ddi_pathname(dip, fullpath);
		pathlen = strlen(fullpath) + 1;
		path = kmem_alloc(pathlen, KM_SLEEP);
		bcopy(fullpath, path, pathlen);
		kmem_free(fullpath, MAXPATHLEN);
	}

	DEVID_LOG_REG(("register", devid, path));

	new_nvp = kmem_zalloc(sizeof (nvp_devid_t), KM_SLEEP);
	new_devid_size = ddi_devid_sizeof(devid);
	new_devid = kmem_alloc(new_devid_size, KM_SLEEP);
	(void) bcopy(devid, new_devid, new_devid_size);

	rw_enter(nvf_lock(dcfd_handle), RW_WRITER);

	listp = nvf_list(dcfd_handle);
	for (np = list_head(listp); np; np = list_next(listp, np)) {
		if (strcmp(path, np->nvp_devpath) == 0) {
			DEVID_DEBUG2((CE_CONT,
			    "register: %s path match\n", path));
			if (np->nvp_devid == NULL) {
replace:			np->nvp_devid = new_devid;
				np->nvp_flags |=
				    NVP_DEVID_DIP | NVP_DEVID_REGISTERED;
				np->nvp_dip = dip;
				if (!devid_cache_write_disable) {
					nvf_mark_dirty(dcfd_handle);
					is_dirty = 1;
				}
				rw_exit(nvf_lock(dcfd_handle));
				kmem_free(new_nvp, sizeof (nvp_devid_t));
				kmem_free(path, pathlen);
				goto exit;
			}
			if (ddi_devid_valid(np->nvp_devid) != DDI_SUCCESS) {
				/* replace invalid devid */
				free_devid = np->nvp_devid;
				goto replace;
			}
			/*
			 * We're registering an already-cached path
			 * Does the device's devid match the cache?
			 */
			if (ddi_devid_compare(devid, np->nvp_devid) != 0) {
				DEVID_DEBUG((CE_CONT, "devid register: "
				    "devid %s does not match\n", path));
				/*
				 * Replace cached devid for this path
				 * with newly registered devid.  A devid
				 * may map to multiple paths but one path
				 * should only map to one devid.
				 */
				devid_nvp_unlink_and_free(dcfd_handle, np);
				np = NULL;
				break;
			} else {
				DEVID_DEBUG2((CE_CONT,
				    "devid register: %s devid match\n", path));
				np->nvp_flags |=
				    NVP_DEVID_DIP | NVP_DEVID_REGISTERED;
				np->nvp_dip = dip;
				rw_exit(nvf_lock(dcfd_handle));
				kmem_free(new_nvp, sizeof (nvp_devid_t));
				kmem_free(path, pathlen);
				kmem_free(new_devid, new_devid_size);
				return (DDI_SUCCESS);
			}
		}
	}

	/*
	 * Add newly registered devid to the cache
	 */
	ASSERT(np == NULL);

	new_nvp->nvp_devpath = path;
	new_nvp->nvp_flags = NVP_DEVID_DIP | NVP_DEVID_REGISTERED;
	new_nvp->nvp_dip = dip;
	new_nvp->nvp_devid = new_devid;

	if (!devid_cache_write_disable) {
		is_dirty = 1;
		nvf_mark_dirty(dcfd_handle);
	}
	list_insert_tail(nvf_list(dcfd_handle), new_nvp);

	rw_exit(nvf_lock(dcfd_handle));

exit:
	if (free_devid)
		kmem_free(free_devid, ddi_devid_sizeof(free_devid));

	if (is_dirty)
		nvf_wake_daemon();

	return (DDI_SUCCESS);
}

int
e_devid_cache_register(dev_info_t *dip, ddi_devid_t devid)
{
	return (e_devid_cache_register_cmn(dip, devid, NULL));
}

/*
 * Unregister a device's devid; the devinfo may hit on multiple entries
 * arising from both pHCI and vHCI paths.
 * Called as an instance detachs.
 * Invalidate the devid's devinfo reference.
 * Devid-path remains in the cache.
 */

void
e_devid_cache_unregister(dev_info_t *dip)
{
	nvp_devid_t *np;
	list_t *listp;

	rw_enter(nvf_lock(dcfd_handle), RW_WRITER);

	listp = nvf_list(dcfd_handle);
	for (np = list_head(listp); np; np = list_next(listp, np)) {
		if (np->nvp_devid == NULL)
			continue;
		if ((np->nvp_flags & NVP_DEVID_DIP) && np->nvp_dip == dip) {
			DEVID_LOG_UNREG((CE_CONT,
			    "unregister: %s\n", np->nvp_devpath));
			np->nvp_flags &= ~NVP_DEVID_DIP;
			np->nvp_dip = NULL;
		}
	}

	rw_exit(nvf_lock(dcfd_handle));
}

int
e_devid_cache_pathinfo(mdi_pathinfo_t *pip, ddi_devid_t devid)
{
	char *path = mdi_pi_pathname(pip);

	return (e_devid_cache_register_cmn(mdi_pi_get_client(pip), devid,
	    path));
}

/*
 * Purge devid cache of stale devids
 */
void
devid_cache_cleanup(void)
{
	nvp_devid_t *np, *next;
	list_t *listp;
	int is_dirty = 0;

	rw_enter(nvf_lock(dcfd_handle), RW_WRITER);

	listp = nvf_list(dcfd_handle);
	for (np = list_head(listp); np; np = next) {
		next = list_next(listp, np);
		if (np->nvp_devid == NULL)
			continue;
		if ((np->nvp_flags & NVP_DEVID_REGISTERED) == 0) {
			DEVID_LOG_REMOVE((CE_CONT,
			    "cleanup: %s\n", np->nvp_devpath));
			if (!devid_cache_write_disable) {
				nvf_mark_dirty(dcfd_handle);
				is_dirty = 0;
			}
			devid_nvp_unlink_and_free(dcfd_handle, np);
		}
	}

	rw_exit(nvf_lock(dcfd_handle));

	if (is_dirty)
		nvf_wake_daemon();
}


/*
 * Build a list of dev_t's for a device/devid
 *
 * The effect of this function is cumulative, adding dev_t's
 * for the device to the list of all dev_t's for a given
 * devid.
 */
static void
e_devid_minor_to_devlist(
	dev_info_t	*dip,
	char		*minor_name,
	int		ndevts_alloced,
	int		*devtcntp,
	dev_t		*devtsp)
{
	int			circ;
	struct ddi_minor_data	*dmdp;
	int			minor_all = 0;
	int			ndevts = *devtcntp;

	ASSERT(i_ddi_devi_attached(dip));

	/* are we looking for a set of minor nodes? */
	if ((minor_name == DEVID_MINOR_NAME_ALL) ||
	    (minor_name == DEVID_MINOR_NAME_ALL_CHR) ||
	    (minor_name == DEVID_MINOR_NAME_ALL_BLK))
		minor_all = 1;

	/* Find matching minor names */
	ndi_devi_enter(dip, &circ);
	for (dmdp = DEVI(dip)->devi_minor; dmdp; dmdp = dmdp->next) {

		/* Skip non-minors, and non matching minor names */
		if ((dmdp->type != DDM_MINOR) || ((minor_all == 0) &&
		    strcmp(dmdp->ddm_name, minor_name)))
			continue;

		/* filter out minor_all mismatches */
		if (minor_all &&
		    (((minor_name == DEVID_MINOR_NAME_ALL_CHR) &&
		    (dmdp->ddm_spec_type != S_IFCHR)) ||
		    ((minor_name == DEVID_MINOR_NAME_ALL_BLK) &&
		    (dmdp->ddm_spec_type != S_IFBLK))))
			continue;

		if (ndevts < ndevts_alloced)
			devtsp[ndevts] = dmdp->ddm_dev;
		ndevts++;
	}
	ndi_devi_exit(dip, circ);

	*devtcntp = ndevts;
}

/*
 * Search for cached entries matching a devid
 * Return two lists:
 *	a list of dev_info nodes, for those devices in the attached state
 *	a list of pathnames whose instances registered the given devid
 * If the lists passed in are not sufficient to return the matching
 * references, return the size of lists required.
 * The dev_info nodes are returned with a hold that the caller must release.
 */
static int
e_devid_cache_devi_path_lists(ddi_devid_t devid, int retmax,
	int *retndevis, dev_info_t **retdevis, int *retnpaths, char **retpaths)
{
	nvp_devid_t *np;
	int ndevis, npaths;
	dev_info_t *dip, *pdip;
	int circ;
	int maxdevis = 0;
	int maxpaths = 0;
	list_t *listp;

	ndevis = 0;
	npaths = 0;
	listp = nvf_list(dcfd_handle);
	for (np = list_head(listp); np; np = list_next(listp, np)) {
		if (np->nvp_devid == NULL)
			continue;
		if (ddi_devid_valid(np->nvp_devid) != DDI_SUCCESS) {
			DEVIDERR((CE_CONT,
			    "find: invalid devid %s\n",
			    np->nvp_devpath));
			continue;
		}
		if (ddi_devid_compare(devid, np->nvp_devid) == 0) {
			DEVID_DEBUG2((CE_CONT,
			    "find: devid match: %s 0x%x\n",
			    np->nvp_devpath, np->nvp_flags));
			DEVID_LOG_MATCH(("find", devid, np->nvp_devpath));
			DEVID_LOG_PATHS((CE_CONT, "%s\n", np->nvp_devpath));

			/*
			 * Check if we have a cached devinfo reference for this
			 * devid.  Place a hold on it to prevent detach
			 * Otherwise, use the path instead.
			 * Note: returns with a hold on each dev_info
			 * node in the list.
			 */
			dip = NULL;
			if (np->nvp_flags & NVP_DEVID_DIP) {
				pdip = ddi_get_parent(np->nvp_dip);
				if (ndi_devi_tryenter(pdip, &circ)) {
					dip = np->nvp_dip;
					ndi_hold_devi(dip);
					ndi_devi_exit(pdip, circ);
					ASSERT(!DEVI_IS_ATTACHING(dip));
					ASSERT(!DEVI_IS_DETACHING(dip));
				} else {
					DEVID_LOG_DETACH((CE_CONT,
					    "may be detaching: %s\n",
					    np->nvp_devpath));
				}
			}

			if (dip) {
				if (ndevis < retmax) {
					retdevis[ndevis++] = dip;
				} else {
					ndi_rele_devi(dip);
				}
				maxdevis++;
			} else {
				if (npaths < retmax)
					retpaths[npaths++] = np->nvp_devpath;
				maxpaths++;
			}
		}
	}

	*retndevis = ndevis;
	*retnpaths = npaths;
	return (maxdevis > maxpaths ? maxdevis : maxpaths);
}


/*
 * Search the devid cache, returning dev_t list for all
 * device paths mapping to the device identified by the
 * given devid.
 *
 * Primary interface used by ddi_lyr_devid_to_devlist()
 */
int
e_devid_cache_to_devt_list(ddi_devid_t devid, char *minor_name,
	int *retndevts, dev_t **retdevts)
{
	char		*path, **paths;
	int		i, j, n;
	dev_t		*devts, *udevts;
	dev_t		tdevt;
	int		ndevts, undevts, ndevts_alloced;
	dev_info_t	*devi, **devis;
	int		ndevis, npaths, nalloced;
	ddi_devid_t	match_devid;

	DEVID_LOG_FIND(("find", devid, NULL));

	ASSERT(ddi_devid_valid(devid) == DDI_SUCCESS);
	if (ddi_devid_valid(devid) != DDI_SUCCESS) {
		DEVID_LOG_ERR(("invalid devid", devid, NULL));
		return (DDI_FAILURE);
	}

	nalloced = 128;

	for (;;) {
		paths = kmem_zalloc(nalloced * sizeof (char *), KM_SLEEP);
		devis = kmem_zalloc(nalloced * sizeof (dev_info_t *), KM_SLEEP);

		rw_enter(nvf_lock(dcfd_handle), RW_READER);
		n = e_devid_cache_devi_path_lists(devid, nalloced,
		    &ndevis, devis, &npaths, paths);
		if (n <= nalloced)
			break;
		rw_exit(nvf_lock(dcfd_handle));
		for (i = 0; i < ndevis; i++)
			ndi_rele_devi(devis[i]);
		kmem_free(paths, nalloced * sizeof (char *));
		kmem_free(devis, nalloced * sizeof (dev_info_t *));
		nalloced = n + 128;
	}

	for (i = 0; i < npaths; i++) {
		path = i_ddi_strdup(paths[i], KM_SLEEP);
		paths[i] = path;
	}
	rw_exit(nvf_lock(dcfd_handle));

	if (ndevis == 0 && npaths == 0) {
		DEVID_LOG_ERR(("no devid found", devid, NULL));
		kmem_free(paths, nalloced * sizeof (char *));
		kmem_free(devis, nalloced * sizeof (dev_info_t *));
		return (DDI_FAILURE);
	}

	ndevts_alloced = 128;
restart:
	ndevts = 0;
	devts = kmem_alloc(ndevts_alloced * sizeof (dev_t), KM_SLEEP);
	for (i = 0; i < ndevis; i++) {
		ASSERT(!DEVI_IS_ATTACHING(devis[i]));
		ASSERT(!DEVI_IS_DETACHING(devis[i]));
		e_devid_minor_to_devlist(devis[i], minor_name,
		    ndevts_alloced, &ndevts, devts);
		if (ndevts > ndevts_alloced) {
			kmem_free(devts, ndevts_alloced * sizeof (dev_t));
			ndevts_alloced += 128;
			goto restart;
		}
	}
	for (i = 0; i < npaths; i++) {
		DEVID_LOG_LOOKUP((CE_CONT, "lookup %s\n", paths[i]));
		devi = e_ddi_hold_devi_by_path(paths[i], 0);
		if (devi == NULL) {
			DEVID_LOG_STALE(("stale device reference",
			    devid, paths[i]));
			continue;
		}
		/*
		 * Verify the newly attached device registered a matching devid
		 */
		if (i_ddi_devi_get_devid(DDI_DEV_T_ANY, devi,
		    &match_devid) != DDI_SUCCESS) {
			DEVIDERR((CE_CONT,
			    "%s: no devid registered on attach\n",
			    paths[i]));
			ddi_release_devi(devi);
			continue;
		}

		if (ddi_devid_compare(devid, match_devid) != 0) {
			DEVID_LOG_STALE(("new devid registered",
			    devid, paths[i]));
			ddi_release_devi(devi);
			ddi_devid_free(match_devid);
			continue;
		}
		ddi_devid_free(match_devid);

		e_devid_minor_to_devlist(devi, minor_name,
		    ndevts_alloced, &ndevts, devts);
		ddi_release_devi(devi);
		if (ndevts > ndevts_alloced) {
			kmem_free(devts,
			    ndevts_alloced * sizeof (dev_t));
			ndevts_alloced += 128;
			goto restart;
		}
	}

	/* drop hold from e_devid_cache_devi_path_lists */
	for (i = 0; i < ndevis; i++) {
		ndi_rele_devi(devis[i]);
	}
	for (i = 0; i < npaths; i++) {
		kmem_free(paths[i], strlen(paths[i]) + 1);
	}
	kmem_free(paths, nalloced * sizeof (char *));
	kmem_free(devis, nalloced * sizeof (dev_info_t *));

	if (ndevts == 0) {
		DEVID_LOG_ERR(("no devid found", devid, NULL));
		kmem_free(devts, ndevts_alloced * sizeof (dev_t));
		return (DDI_FAILURE);
	}

	/*
	 * Build the final list of sorted dev_t's with duplicates collapsed so
	 * returned results are consistent. This prevents implementation
	 * artifacts from causing unnecessary changes in SVM namespace.
	 */
	/* bubble sort */
	for (i = 0; i < (ndevts - 1); i++) {
		for (j = 0; j < ((ndevts - 1) - i); j++) {
			if (devts[j + 1] < devts[j]) {
				tdevt = devts[j];
				devts[j] = devts[j + 1];
				devts[j + 1] = tdevt;
			}
		}
	}

	/* determine number of unique values */
	for (undevts = ndevts, i = 1; i < ndevts; i++) {
		if (devts[i - 1] == devts[i])
			undevts--;
	}

	/* allocate unique */
	udevts = kmem_alloc(undevts * sizeof (dev_t), KM_SLEEP);

	/* copy unique */
	udevts[0] = devts[0];
	for (i = 1, j = 1; i < ndevts; i++) {
		if (devts[i - 1] != devts[i])
			udevts[j++] = devts[i];
	}
	ASSERT(j == undevts);

	kmem_free(devts, ndevts_alloced * sizeof (dev_t));

	*retndevts = undevts;
	*retdevts = udevts;

	return (DDI_SUCCESS);
}

void
e_devid_cache_free_devt_list(int ndevts, dev_t *devt_list)
{
	kmem_free(devt_list, ndevts * sizeof (dev_t *));
}

/*
 * If given a full path and NULL ua, search for a cache entry
 * whose path matches the full path.  On a cache hit duplicate the
 * devid of the matched entry into the given devid (caller
 * must free);  nodenamebuf is not touched for this usage.
 *
 * Given a path and a non-NULL unit address, search the cache for any entry
 * matching "<path>/%@<unit-address>" where '%' is a wildcard meaning
 * any node name.  The path should not end a '/'.  On a cache hit
 * duplicate the devid as before (caller must free) and copy into
 * the caller-provided nodenamebuf (if not NULL) the nodename of the
 * matched entry.
 *
 * We must not make use of nvp_dip since that may be NULL for cached
 * entries that are not present in the current tree.
 */
int
e_devid_cache_path_to_devid(char *path, char *ua,
    char *nodenamebuf, ddi_devid_t *devidp)
{
	size_t pathlen, ualen;
	int rv = DDI_FAILURE;
	nvp_devid_t *np;
	list_t *listp;
	char *cand;

	if (path == NULL || *path == '\0' || (ua && *ua == '\0') ||
	    devidp == NULL)
		return (DDI_FAILURE);

	*devidp = NULL;

	if (ua) {
		pathlen = strlen(path);
		ualen = strlen(ua);
	}

	rw_enter(nvf_lock(dcfd_handle), RW_READER);

	listp = nvf_list(dcfd_handle);
	for (np = list_head(listp); np; np = list_next(listp, np)) {
		size_t nodelen, candlen, n;
		ddi_devid_t devid_dup;
		char *uasep, *node;

		if (np->nvp_devid == NULL)
			continue;

		if (ddi_devid_valid(np->nvp_devid) != DDI_SUCCESS) {
			DEVIDERR((CE_CONT,
			    "pathsearch: invalid devid %s\n",
			    np->nvp_devpath));
			continue;
		}

		cand = np->nvp_devpath;		/* candidate path */

		/* If a full pathname was provided the compare is easy */
		if (ua == NULL) {
			if (strcmp(cand, path) == 0)
				goto match;
			else
				continue;
		}

		/*
		 * The compare for initial path plus ua and unknown nodename
		 * is trickier.
		 *
		 * Does the initial path component match 'path'?
		 */
		if (strncmp(path, cand, pathlen) != 0)
			continue;

		candlen = strlen(cand);

		/*
		 * The next character must be a '/' and there must be no
		 * further '/' thereafter.  Begin by checking that the
		 * candidate is long enough to include at mininum a
		 * "/<nodename>@<ua>" after the initial portion already
		 * matched assuming a nodename length of 1.
		 */
		if (candlen < pathlen + 1 + 1 + 1 + ualen ||
		    cand[pathlen] != '/' ||
		    strchr(cand + pathlen + 1, '/') != NULL)
			continue;

		node = cand + pathlen + 1;	/* <node>@<ua> string */

		/*
		 * Find the '@' before the unit address.  Check for
		 * unit address match.
		 */
		if ((uasep = strchr(node, '@')) == NULL)
			continue;

		/*
		 * Check we still have enough length and that ua matches
		 */
		nodelen = (uintptr_t)uasep - (uintptr_t)node;
		if (candlen < pathlen + 1 + nodelen + 1 + ualen ||
		    strncmp(ua, uasep + 1, ualen) != 0)
			continue;
match:
		n = ddi_devid_sizeof(np->nvp_devid);
		devid_dup = kmem_alloc(n, KM_SLEEP);	/* caller must free */
		(void) bcopy(np->nvp_devid, devid_dup, n);
		*devidp = devid_dup;

		if (ua && nodenamebuf) {
			(void) strncpy(nodenamebuf, node, nodelen);
			nodenamebuf[nodelen] = '\0';
		}

		rv = DDI_SUCCESS;
		break;
	}

	rw_exit(nvf_lock(dcfd_handle));

	return (rv);
}

#ifdef	DEBUG
static void
devid_log(char *fmt, ddi_devid_t devid, char *path)
{
	char *devidstr = ddi_devid_str_encode(devid, NULL);
	if (path) {
		cmn_err(CE_CONT, "%s: %s %s\n", fmt, path, devidstr);
	} else {
		cmn_err(CE_CONT, "%s: %s\n", fmt, devidstr);
	}
	ddi_devid_str_free(devidstr);
}
#endif	/* DEBUG */
