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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_implfuncs.h>
#include <sys/list.h>
#include <sys/reboot.h>
#include <sys/sysmacros.h>
#include <sys/console.h>
#include <sys/devcache.h>

/*
 * The nvpair name in the I/O retire specific sub-nvlist
 */
#define	RIO_STORE_VERSION_STR	"rio-store-version"
#define	RIO_STORE_MAGIC_STR	"rio-store-magic"
#define	RIO_STORE_FLAGS_STR	"rio-store-flags"

#define	RIO_STORE_VERSION_1	1
#define	RIO_STORE_VERSION	RIO_STORE_VERSION_1

/*
 * decoded retire list element
 */

typedef enum rio_store_flags {
	RIO_STORE_F_INVAL = 0,
	RIO_STORE_F_RETIRED = 1,
	RIO_STORE_F_BYPASS = 2
} rio_store_flags_t;

typedef struct rio_store {
	char			*rst_devpath;
	rio_store_flags_t	rst_flags;
	list_node_t		rst_next;
} rio_store_t;

#define	RIO_STORE_MAGIC		0x601fcace	/* retire */

static int rio_store_decode(nvf_handle_t nvfh, nvlist_t *line_nvl, char *name);
static int rio_store_encode(nvf_handle_t nvfh, nvlist_t **ret_nvl);
static void retire_list_free(nvf_handle_t  nvfh);


/*
 * Retire I/O persistent store registration info
 */
static nvf_ops_t rio_store_ops = {
	"/etc/devices/retire_store",	/* path to store */
	rio_store_decode,		/* decode nvlist into retire_list */
	rio_store_encode,		/* encode retire_list into nvlist */
	retire_list_free,		/* free retire_list */
	NULL				/* write complete callback */
};

static nvf_handle_t	rio_store_handle;
static char		store_path[MAXPATHLEN];
static int		store_debug = 0;
static int		bypass_msg = 0;
static int		retire_msg = 0;

#define	STORE_DEBUG	0x0001
#define	STORE_TRACE	0x0002

#define	STORE_DBG(args)		if (store_debug & STORE_DEBUG)	cmn_err args
#define	STORE_TRC(args)		if (store_debug & STORE_TRACE)	cmn_err args

/*
 * We don't use the simple read disable offered by the
 * caching framework (see devcache.c) as it will not
 * have the desired effect of bypassing the persistent
 * store. A simple read disable will
 *
 *	1. cause any additions to the cache to destroy the
 *	   existing on-disk cache
 *
 *	2. prevent deletions from the existing on-disk
 *	   cache which is needed for recovery from bad
 *	   retire decisions.
 *
 * Use the following tunable instead
 *
 */
int	ddi_retire_store_bypass = 0;



/*
 * Initialize retire store data structures
 */
void
retire_store_init(void)
{
	if (boothowto & RB_ASKNAME) {

		printf("Retire store [%s] (/dev/null to bypass): ",
		    rio_store_ops.nvfr_cache_path);
		console_gets(store_path, sizeof (store_path) - 1);
		store_path[sizeof (store_path) - 1] = '\0';

		if (strcmp(store_path, "/dev/null") == 0) {
			ddi_retire_store_bypass = 1;
		} else if (store_path[0] != '\0') {
			if (store_path[0] != '/') {
				printf("Invalid store path: %s. Using default"
				    "\n", store_path);
			} else {
				rio_store_ops.nvfr_cache_path = store_path;
			}
		}
	}

	rio_store_handle = nvf_register_file(&rio_store_ops);

	list_create(nvf_list(rio_store_handle), sizeof (rio_store_t),
	    offsetof(rio_store_t, rst_next));
}

/*
 * Read and populate the in-core retire store
 */
void
retire_store_read(void)
{
	rw_enter(nvf_lock(rio_store_handle), RW_WRITER);
	ASSERT(list_head(nvf_list(rio_store_handle)) == NULL);
	(void) nvf_read_file(rio_store_handle);
	rw_exit(nvf_lock(rio_store_handle));
	STORE_DBG((CE_NOTE, "Read on-disk retire store"));
}

static void
rio_store_free(rio_store_t *rsp)
{
	int flag_mask = RIO_STORE_F_RETIRED|RIO_STORE_F_BYPASS;

	ASSERT(rsp);
	ASSERT(rsp->rst_devpath);
	ASSERT(rsp->rst_flags & RIO_STORE_F_RETIRED);
	ASSERT(!(rsp->rst_flags & ~flag_mask));

	STORE_TRC((CE_NOTE, "store: freed path: %s", rsp->rst_devpath));

	kmem_free(rsp->rst_devpath, strlen(rsp->rst_devpath) + 1);
	kmem_free(rsp, sizeof (*rsp));
}

static void
retire_list_free(nvf_handle_t  nvfh)
{
	list_t		*listp;
	rio_store_t	*rsp;

	ASSERT(nvfh == rio_store_handle);
	ASSERT(RW_WRITE_HELD(nvf_lock(nvfh)));

	listp = nvf_list(nvfh);
	while (rsp = list_head(listp)) {
		list_remove(listp, rsp);
		rio_store_free(rsp);
	}

	STORE_DBG((CE_NOTE, "store: freed retire list"));
}

static int
rio_store_decode(nvf_handle_t nvfh, nvlist_t *line_nvl, char *name)
{
	rio_store_t	*rsp;
	int32_t		version;
	int32_t		magic;
	int32_t		flags;
	int		rval;

	ASSERT(nvfh == rio_store_handle);
	ASSERT(RW_WRITE_HELD(nvf_lock(nvfh)));
	ASSERT(name);

	version = 0;
	rval = nvlist_lookup_int32(line_nvl, RIO_STORE_VERSION_STR, &version);
	if (rval != 0 || version != RIO_STORE_VERSION) {
		return (EINVAL);
	}

	magic = 0;
	rval = nvlist_lookup_int32(line_nvl, RIO_STORE_MAGIC_STR, &magic);
	if (rval != 0 || magic != RIO_STORE_MAGIC) {
		return (EINVAL);
	}

	flags = 0;
	rval = nvlist_lookup_int32(line_nvl, RIO_STORE_FLAGS_STR, &flags);
	if (rval != 0 || flags != RIO_STORE_F_RETIRED) {
		return (EINVAL);
	}

	if (ddi_retire_store_bypass) {
		flags |= RIO_STORE_F_BYPASS;
		if (!bypass_msg) {
			bypass_msg = 1;
			cmn_err(CE_WARN,
			    "Bypassing retire store /etc/devices/retire_store");
		}
	}

	rsp = kmem_zalloc(sizeof (rio_store_t), KM_SLEEP);
	rsp->rst_devpath = i_ddi_strdup(name, KM_SLEEP);
	rsp->rst_flags = flags;
	list_insert_tail(nvf_list(nvfh), rsp);

	STORE_TRC((CE_NOTE, "store: added to retire list: %s", name));
	if (!retire_msg) {
		retire_msg = 1;
		cmn_err(CE_NOTE, "One or more I/O devices have been retired");
	}

	return (0);
}

static int
rio_store_encode(nvf_handle_t nvfh, nvlist_t **ret_nvl)
{
	nvlist_t	*nvl;
	nvlist_t	*line_nvl;
	list_t		*listp;
	rio_store_t	*rsp;
	int		rval;

	ASSERT(nvfh == rio_store_handle);
	ASSERT(RW_WRITE_HELD(nvf_lock(nvfh)));

	*ret_nvl = NULL;

	nvl = NULL;
	rval = nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP);
	if (rval != 0) {
		return (DDI_FAILURE);
	}

	listp = nvf_list(nvfh);
	for (rsp = list_head(listp); rsp; rsp = list_next(listp, rsp)) {
		int flag_mask = RIO_STORE_F_RETIRED|RIO_STORE_F_BYPASS;
		int flags;
		ASSERT(rsp->rst_devpath);
		ASSERT(!(rsp->rst_flags & ~flag_mask));

		line_nvl = NULL;
		rval = nvlist_alloc(&line_nvl, NV_UNIQUE_NAME, KM_SLEEP);
		if (rval != 0) {
			line_nvl = NULL;
			goto error;
		}

		rval = nvlist_add_int32(line_nvl, RIO_STORE_VERSION_STR,
			RIO_STORE_VERSION);
		if (rval != 0) {
			goto error;
		}
		rval = nvlist_add_int32(line_nvl, RIO_STORE_MAGIC_STR,
			RIO_STORE_MAGIC);
		if (rval != 0) {
			goto error;
		}

		/* don't save the bypass flag */
		flags = RIO_STORE_F_RETIRED;
		rval = nvlist_add_int32(line_nvl, RIO_STORE_FLAGS_STR,
			flags);
		if (rval != 0) {
			goto error;
		}

		rval = nvlist_add_nvlist(nvl, rsp->rst_devpath, line_nvl);
		if (rval != 0) {
			goto error;
		}
		nvlist_free(line_nvl);
		line_nvl = NULL;
	}

	*ret_nvl = nvl;
	STORE_DBG((CE_NOTE, "packed retire list into nvlist"));
	return (DDI_SUCCESS);

error:
	nvlist_free(line_nvl);
	ASSERT(nvl);
	nvlist_free(nvl);
	return (DDI_FAILURE);
}

int
e_ddi_retire_persist(char *devpath)
{
	rio_store_t	*rsp;
	rio_store_t	*new_rsp;
	list_t		*listp;
	char		*new_path;

	STORE_DBG((CE_NOTE, "e_ddi_retire_persist: entered: %s", devpath));

	new_rsp = kmem_zalloc(sizeof (*new_rsp), KM_SLEEP);
	new_rsp->rst_devpath = new_path = i_ddi_strdup(devpath, KM_SLEEP);
	new_rsp->rst_flags = RIO_STORE_F_RETIRED;

	rw_enter(nvf_lock(rio_store_handle), RW_WRITER);

	listp = nvf_list(rio_store_handle);
	for (rsp = list_head(listp); rsp; rsp = list_next(listp, rsp)) {
		int flag_mask = RIO_STORE_F_RETIRED|RIO_STORE_F_BYPASS;
		ASSERT(!(rsp->rst_flags & ~flag_mask));

		/* already there */
		if (strcmp(devpath, rsp->rst_devpath) == 0) {
			/* explicit retire, clear bypass flag (if any) */
			rsp->rst_flags &= ~RIO_STORE_F_BYPASS;
			ASSERT(rsp->rst_flags == RIO_STORE_F_RETIRED);
			rw_exit(nvf_lock(rio_store_handle));
			kmem_free(new_path, strlen(new_path) + 1);
			kmem_free(new_rsp, sizeof (*new_rsp));
			STORE_DBG((CE_NOTE, "store: already in. Clear bypass "
			    ": %s", devpath));
			return (0);
		}

	}

	ASSERT(rsp == NULL);
	list_insert_tail(listp, new_rsp);

	nvf_mark_dirty(rio_store_handle);

	rw_exit(nvf_lock(rio_store_handle));

	nvf_wake_daemon();

	STORE_DBG((CE_NOTE, "store: New, added to list, dirty: %s", devpath));

	return (0);
}

int
e_ddi_retire_unpersist(char *devpath)
{
	rio_store_t	*rsp;
	rio_store_t	*next;
	list_t		*listp;
	int		is_dirty = 0;

	STORE_DBG((CE_NOTE, "e_ddi_retire_unpersist: entered: %s", devpath));

	rw_enter(nvf_lock(rio_store_handle), RW_WRITER);

	listp = nvf_list(rio_store_handle);
	for (rsp = list_head(listp); rsp; rsp = next) {
		next = list_next(listp, rsp);
		if (strcmp(devpath, rsp->rst_devpath) != 0)
			continue;

		list_remove(listp, rsp);
		rio_store_free(rsp);

		STORE_DBG((CE_NOTE, "store: found in list. Freed: %s",
		    devpath));

		nvf_mark_dirty(rio_store_handle);
		is_dirty = 1;
	}

	rw_exit(nvf_lock(rio_store_handle));

	if (is_dirty)
		nvf_wake_daemon();

	return (is_dirty);
}

int
e_ddi_device_retired(char *devpath)
{
	list_t		*listp;
	rio_store_t	*rsp;
	size_t		len;
	int		retired;

	retired = 0;

	rw_enter(nvf_lock(rio_store_handle), RW_READER);

	listp = nvf_list(rio_store_handle);
	for (rsp = list_head(listp); rsp; rsp = list_next(listp, rsp)) {
		int flag_mask = RIO_STORE_F_RETIRED|RIO_STORE_F_BYPASS;
		ASSERT(!(rsp->rst_flags & ~flag_mask));

		/*
		 * If the "bypass" flag is set, then the device
		 * is *not* retired for the current boot of the
		 * system. It indicates that the retire store
		 * was read but the devices in the retire store
		 * were not retired i.e. effectively the store
		 * was bypassed. For why we bother to even read
		 * the store when we bypass it, see the comments
		 * for the tunable ddi_retire_store_bypass.
		 */
		if (rsp->rst_flags & RIO_STORE_F_BYPASS) {
			STORE_TRC((CE_NOTE, "store: found & bypassed: %s",
			    rsp->rst_devpath));
			continue;
		}

		/*
		 * device is retired, if it or a parent exists
		 * in the in-core list
		 */
		len = strlen(rsp->rst_devpath);
		if (strncmp(devpath, rsp->rst_devpath, len) != 0)
			continue;
		if (devpath[len] == '\0' || devpath[len] == '/') {
			/* exact match or a child */
			retired = 1;
			STORE_TRC((CE_NOTE, "store: found & !bypassed: %s",
			    devpath));
			break;
		}
	}
	rw_exit(nvf_lock(rio_store_handle));

	return (retired);
}
