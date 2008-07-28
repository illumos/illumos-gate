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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <meta.h>
#include <sys/lvm/mdio.h>
#include <sys/lvm/md_sp.h>
#include <sdssc.h>

#include "rcm_module.h"

/*
 * This module is the RCM Module for SVM. The policy adopted by this module
 * is to block offline requests for any SVM resource that is in use. A
 * resource is considered to be in use if it contains a metadb or if it is
 * a non-errored component of a metadevice that is open.
 *
 * The module uses the library libmeta to access the current state of the
 * metadevices. On entry, and when svm_register() is called, the module
 * builds a cache of all of the SVM resources and their dependencies. Each
 * metadevice has an entry of type deventry_t which is accessed by a hash
 * function. When the cache is built each SVM resource is registered with
 * the RCM framework.  The check_device code path uses meta_invalidate_name to
 * ensure that the caching in libmeta will not conflict with the cache
 * we build within this code.
 *
 * When an RCM operation occurs that affects a registered SVM resource, the RCM
 * framework will call the appropriate routine in this module. The cache
 * entry will be found and if the resource has dependants, a callback will
 * be made into the RCM framework to pass the request on to the dependants,
 * which may themselves by SVM resources.
 *
 * Locking:
 *      The cache is protected by a mutex
 */

/*
 * Private constants
 */

/*
 * Generic Messages
 */
#define	MSG_UNRECOGNIZED	gettext("SVM: \"%s\" is not a SVM resource")
#define	MSG_NODEPS		gettext("SVM: can't find dependents")
#define	MSG_NORECACHE		gettext("SVM: WARNING: couldn't re-cache.")
#define	MSG_OPENERR		gettext("SVM: can't open \"%s\"")
#define	MSG_CACHEFAIL		gettext("SVM: can't malloc cache")

#define	ERR_UNRECOGNIZED	gettext("unrecognized SVM resource")
#define	ERR_NODEPS		gettext("can't find SVM resource dependents")

/*
 * Macros to produce a quoted string containing the value of a preprocessor
 * macro. For example, if SIZE is defined to be 256, VAL2STR(SIZE) is "256".
 * This is used to construct format strings for scanf-family functions below.
 */
#define	QUOTE(x)	#x
#define	VAL2STR(x)	QUOTE(x)

typedef enum {
    SVM_SLICE = 0,
    SVM_STRIPE,
    SVM_CONCAT,
    SVM_MIRROR,
    SVM_RAID,
    SVM_TRANS,
    SVM_SOFTPART,
    SVM_HS
} svm_type_t;

/* Hash table parameters */
#define	HASH_DEFAULT	251

/* Hot spare pool users */
typedef struct hspuser {
	struct hspuser  *next;		/* next user */
	char		*hspusername;	/* name */
	dev_t		hspuserkey;	/* key */
} hspuser_t;

/* Hot spare pool entry */
typedef struct hspentry {
	struct hspentry *link;		/* link through all hsp entries */
	struct hspentry *next;		/* next hsp entry for a slice */
	char		*hspname;	/* name */
	hspuser_t	*hspuser;	/* first hsp user */
} hspentry_t;

/* Hash table entry */
typedef struct deventry {
	struct deventry		*next;		/* next entry with same hash */
	svm_type_t		devtype;	/* device type */
	dev_t			devkey;		/* key */
	char			*devname;	/* name in /dev */
	char			*devicesname;	/* name in /devices */
	struct deventry		*dependent;	/* 1st dependent */
	struct deventry		*next_dep;	/* next dependent */
	struct deventry		*antecedent;	/* antecedent */
	hspentry_t		*hsp_list;	/* list of hot spare pools */
	int			flags;		/* flags */
} deventry_t;

/* flag values */
#define	 REMOVED	0x1
#define	 IN_HSP		0x2
#define	 TRANS_LOG	0x4
#define	 CONT_SOFTPART	0x8
#define	 CONT_METADB	0x10

/*
 * Device redundancy flags. If the device can be removed from the
 * metadevice configuration then it is considered a redundant device,
 * otherwise not.
 */
#define	NOTINDEVICE	-1
#define	NOTREDUNDANT	0
#define	REDUNDANT	1

/* Cache */
typedef struct cache {
	deventry_t	**hashline;	/* hash table */
	int32_t		size;		/* sizer of hash table */
	uint32_t	registered;	/* cache regsitered */
} cache_t;

/*
 * Forward declarations of private functions
 */

static int svm_register(rcm_handle_t *hd);
static int svm_unregister(rcm_handle_t *hd);
static int svm_unregister_device(rcm_handle_t *hd, deventry_t *d);
static deventry_t *cache_dependent(cache_t *cache, char *devname, int devflags,
    deventry_t *dependents);
static deventry_t *cache_device(cache_t *cache, char *devname,
    svm_type_t devtype, md_dev64_t devkey, int devflags);
static hspentry_t *find_hsp(char *hspname);
static hspuser_t *add_hsp_user(char *hspname, deventry_t *deventry);
static hspentry_t *add_hsp(char *hspname, deventry_t *deventry);
static void free_names(mdnamelist_t *nlp);
static int cache_all_devices(cache_t *cache);
static int cache_hsp(cache_t *cache, mdhspnamelist_t *nlp, md_hsp_t *hsp);
static int cache_trans(cache_t *cache, mdnamelist_t *nlp, md_trans_t *trans);
static int cache_mirror(cache_t *cache, mdnamelist_t *nlp,
    md_mirror_t *mirror);
static int cache_raid(cache_t *cache, mdnamelist_t *nlp, md_raid_t *raid);
static int cache_stripe(cache_t *cache, mdnamelist_t *nlp,
    md_stripe_t *stripe);
static int cache_sp(cache_t *cache, mdnamelist_t *nlp, md_sp_t *soft_part);
static int cache_all_devices_in_set(cache_t *cache, mdsetname_t *sp);
static cache_t  *create_cache();
static deventry_t *create_deventry(char *devname, svm_type_t devtype,
    md_dev64_t devkey, int devflags);
static void cache_remove(cache_t *cache, deventry_t *deventry);
static deventry_t *cache_lookup(cache_t *cache, char *devname);
static void cache_sync(rcm_handle_t *hd, cache_t **cachep);
static char *cache_walk(cache_t *cache, uint32_t *i, deventry_t **hashline);
static void free_cache(cache_t **cache);
static void free_deventry(deventry_t **deventry);
static uint32_t hash(uint32_t h, char *s);
static void svm_register_device(rcm_handle_t *hd, char *devname);
static int add_dep(int *ndeps, char ***depsp, deventry_t *deventry);
static int get_dependents(deventry_t *deventry, char *** dependentsp);
char *add_to_usage(char ** usagep, char *string);
char *add_to_usage_fmt(char **usagep, char *fmt, char *string);
static int is_open(dev_t devkey);
static int svm_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **infop);
static int svm_online(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **infop);
static int svm_get_info(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **usagep, char **errorp, nvlist_t *props, rcm_info_t **infop);
static int svm_suspend(rcm_handle_t *hd, char *rsrc, id_t id,
    timespec_t *interval, uint_t flags, char **errorp,
    rcm_info_t **infop);
static int svm_resume(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **infop);
static int svm_remove(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **infop);
static int check_device(deventry_t *deventry);
static int check_mirror(mdsetname_t *sp, mdname_t *np, md_error_t *ep);

/*
 * Module-Private data
 */
static struct rcm_mod_ops svm_ops =
{
	RCM_MOD_OPS_VERSION,
	svm_register,
	svm_unregister,
	svm_get_info,
	svm_suspend,
	svm_resume,
	svm_offline,
	svm_online,
	svm_remove,
	NULL,
	NULL,
	NULL
};

static cache_t *svm_cache = NULL;
static mutex_t svm_cache_lock;
static hspentry_t *hsp_head = NULL;

/*
 * Module Interface Routines
 */

/*
 *      rcm_mod_init()
 *
 *      Create a cache, and return the ops structure.
 *      Input: None
 *      Return: rcm_mod_ops structure
 */
struct rcm_mod_ops *
rcm_mod_init()
{
	/* initialize the lock mutex */
	if (mutex_init(&svm_cache_lock, USYNC_THREAD, NULL)) {
		rcm_log_message(RCM_ERROR,
		    gettext("SVM: can't init mutex"));
		return (NULL);
	}

	/* need to initialize the cluster library to avoid seg faults */
	if (sdssc_bind_library() == SDSSC_ERROR) {
		rcm_log_message(RCM_ERROR,
			gettext("SVM: Interface error with libsds_sc.so,"
			    " aborting."));
		return (NULL);
	}

	/* Create a cache */
	if ((svm_cache = create_cache()) == NULL) {
		rcm_log_message(RCM_ERROR,
			gettext("SVM: module can't function, aborting."));
		return (NULL);
	}

	/* Return the ops vectors */
	return (&svm_ops);
}

/*
 *	rcm_mod_info()
 *
 *	Return a string describing this module.
 *	Input: None
 *	Return: String
 *	Locking: None
 */
const char *
rcm_mod_info()
{
	return (gettext("Solaris Volume Manager module 1.9"));
}

/*
 *	rcm_mod_fini()
 *
 *	Destroy the cache and mutex
 *	Input: None
 *	Return: RCM_SUCCESS
 *	Locking: None
 */
int
rcm_mod_fini()
{
	(void) mutex_lock(&svm_cache_lock);
	if (svm_cache) {
		free_cache(&svm_cache);
	}
	(void) mutex_unlock(&svm_cache_lock);
	(void) mutex_destroy(&svm_cache_lock);
	return (RCM_SUCCESS);
}

/*
 *	svm_register()
 *
 *	Make sure the cache is properly sync'ed, and its registrations are in
 *	order.
 *
 *	Input:
 *		rcm_handle_t	*hd
 *	Return:
 *		RCM_SUCCESS
 *      Locking: the cache is locked throughout the execution of this routine
 *      because it reads and possibly modifies cache links continuously.
 */
static int
svm_register(rcm_handle_t *hd)
{
	uint32_t i = 0;
	deventry_t *l = NULL;
	char    *devicename;


	rcm_log_message(RCM_TRACE1, "SVM: register\n");
	/* Guard against bad arguments */
	assert(hd != NULL);

	/* Lock the cache */
	(void) mutex_lock(&svm_cache_lock);

	/* If the cache has already been registered, then just sync it.  */
	if (svm_cache && svm_cache->registered) {
		cache_sync(hd, &svm_cache);
		(void) mutex_unlock(&svm_cache_lock);
		return (RCM_SUCCESS);
	}

	/* If not, register the whole cache and mark it as registered. */
	while ((devicename = cache_walk(svm_cache, &i, &l)) != NULL) {
			svm_register_device(hd, devicename);
	}
	svm_cache->registered = 1;

	/* Unlock the cache */
	(void) mutex_unlock(&svm_cache_lock);

	return (RCM_SUCCESS);
}

/*
 *	svm_unregister()
 *
 *	Manually walk through the cache, unregistering all the special files and
 *	mount points.
 *
 *	Input:
 *		rcm_handle_t	*hd
 *	Return:
 *		RCM_SUCCESS
 *      Locking: the cache is locked throughout the execution of this routine
 *      because it reads and modifies cache links continuously.
 */
static int
svm_unregister(rcm_handle_t *hd)
{
	deventry_t *l = NULL;
	uint32_t i = 0;

	rcm_log_message(RCM_TRACE1, "SVM: unregister\n");
	/* Guard against bad arguments */
	assert(hd != NULL);

	/* Walk the cache, unregistering everything */
	(void) mutex_lock(&svm_cache_lock);
	if (svm_cache != NULL) {
		while (cache_walk(svm_cache, &i, &l) != NULL) {
			(void) svm_unregister_device(hd, l);
		}
		svm_cache->registered = 0;
	}
	(void) mutex_unlock(&svm_cache_lock);
	return (RCM_SUCCESS);
}

/*
 *      svm_offline()
 *
 *      Determine dependents of the resource being offlined, and offline
 *      them all.
 *
 *      Input:
 *		rcm_handle_t	*hd		handle
 *		char*		*rsrc		resource name
 *		id_t		id		0
 *		char		**errorp	ptr to error message
 *		rcm_info_t	**infop		ptr to info string
 *      Output:
 *		char		**errorp	pass back error message
 *      Return:
 *		int		RCM_SUCCESS or RCM_FAILURE
 *      Locking: the cache is locked for most of this routine, except while
 *      processing dependents.
 */
/*ARGSUSED*/
static int
svm_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **infop)
{
	int		rv = RCM_SUCCESS;
	int		ret;
	char		**dependents;
	deventry_t	*deventry;
	hspentry_t	*hspentry;
	hspuser_t	*hspuser;

	/* Guard against bad arguments */
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(errorp != NULL);

	/* Trace */
	rcm_log_message(RCM_TRACE1, "SVM: offline(%s), flags(%d)\n",
	    rsrc, flags);

	/* Lock the cache */
	(void) mutex_lock(&svm_cache_lock);

	/* Lookup the resource in the cache. */
	if ((deventry = cache_lookup(svm_cache, rsrc)) == NULL) {
		rcm_log_message(RCM_ERROR, MSG_UNRECOGNIZED);
		*errorp = strdup(ERR_UNRECOGNIZED);
		(void) mutex_unlock(&svm_cache_lock);
		rv = RCM_FAILURE;
		rcm_log_message(RCM_TRACE1, "SVM: svm_offline(%s) exit %d\n",
		    rsrc, rv);
		return (rv);
	}
	/* If it is a TRANS device, do not allow the offline */
	if (deventry->devtype == SVM_TRANS) {
		rv = RCM_FAILURE;
		(void) mutex_unlock(&svm_cache_lock);
		goto exit;
	}

	if (deventry->flags&IN_HSP) {
		/*
		 * If this is in a hot spare pool, check to see
		 * if any of the hot spare pool users are open
		 */
		hspentry = deventry->hsp_list;
		while (hspentry) {
			hspuser = hspentry->hspuser;
			while (hspuser) {
				/* Check if open */
				if (is_open(hspuser->hspuserkey)) {
					rv = RCM_FAILURE;
					(void) mutex_unlock(&svm_cache_lock);
					goto exit;
				}
				hspuser = hspuser->next;
			}
			hspentry = hspentry->next;
		}
	}

	/* Fail if the device contains a metadb replica */
	if (deventry->flags&CONT_METADB) {
		/*
		 * The user should delete the replica before continuing,
		 * so force the error.
		 */
		rcm_log_message(RCM_TRACE1, "SVM: %s has a replica\n",
		    deventry->devname);
		rv = RCM_FAILURE;
		(void) mutex_unlock(&svm_cache_lock);
		goto exit;
	}

	/* Get dependents */
	if (get_dependents(deventry, &dependents) != 0) {
		rcm_log_message(RCM_ERROR, MSG_NODEPS);
		rv = RCM_FAILURE;
		(void) mutex_unlock(&svm_cache_lock);
		goto exit;
	}

	if (dependents) {
		/* Check if the device is broken (needs maintanence). */
		if (check_device(deventry) == REDUNDANT) {
			/*
			 * The device is broken, the offline request should
			 * succeed, so ignore any of the dependents.
			 */
			rcm_log_message(RCM_TRACE1,
			    "SVM: ignoring dependents\n");
			(void) mutex_unlock(&svm_cache_lock);
			free(dependents);
			goto exit;
		}
		(void) mutex_unlock(&svm_cache_lock);
		ret = rcm_request_offline_list(hd, dependents, flags, infop);
		if (ret != RCM_SUCCESS) {
			rv = ret;
		}
		free(dependents);
	} else {
		/* If no dependents, check if the metadevice is open */
		if ((deventry->devkey) && (is_open(deventry->devkey))) {
			rv = RCM_FAILURE;
			(void) mutex_unlock(&svm_cache_lock);
			goto exit;
		}
		(void) mutex_unlock(&svm_cache_lock);
	}
exit:
	rcm_log_message(RCM_TRACE1, "SVM: svm_offline(%s) exit %d\n", rsrc, rv);
	if (rv != RCM_SUCCESS)
		*errorp = strdup(gettext("unable to offline"));
	return (rv);
}

/*
 *      svm_online()
 *
 *      Just pass the online notification on to the dependents of this resource
 *
 *      Input:
 *		rcm_handle_t	*hd		handle
 *		char*		*rsrc		resource name
 *		id_t		id		0
 *		char		**errorp	ptr to error message
 *		rcm_info_t	**infop		ptr to info string
 *      Output:
 *		char		**errorp	pass back error message
 *      Return:
 *		int		RCM_SUCCESS or RCM_FAILURE
 *      Locking: the cache is locked for most of this routine, except while
 *      processing dependents.
 */
/*ARGSUSED*/
static int
svm_online(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags, char **errorp,
    rcm_info_t **infop)
{
	int		rv = RCM_SUCCESS;
	char		**dependents;
	deventry_t	*deventry;

	/* Guard against bad arguments */
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);

	/* Trace */
	rcm_log_message(RCM_TRACE1, "SVM: online(%s)\n", rsrc);

	/* Lookup this resource in the cache (cache gets locked) */
	(void) mutex_lock(&svm_cache_lock);
	deventry = cache_lookup(svm_cache, rsrc);
	if (deventry == NULL) {
		(void) mutex_unlock(&svm_cache_lock);
		rcm_log_message(RCM_ERROR, MSG_UNRECOGNIZED, rsrc);
		*errorp = strdup(ERR_UNRECOGNIZED);
		return (RCM_FAILURE);
	}

	/* Get dependents */
	if (get_dependents(deventry, &dependents) != 0) {
		(void) mutex_unlock(&svm_cache_lock);
		rcm_log_message(RCM_ERROR, MSG_NODEPS);
		*errorp = strdup(ERR_NODEPS);
		return (RCM_FAILURE);
	}
	(void) mutex_unlock(&svm_cache_lock);

	if (dependents) {
		rv = rcm_notify_online_list(hd, dependents, flags, infop);
		if (rv != RCM_SUCCESS)
			*errorp = strdup(gettext("unable to online"));
		free(dependents);
	}

	return (rv);
}

/*
 *      svm_get_info()
 *
 *      Gather usage information for this resource.
 *
 *      Input:
 *		rcm_handle_t	*hd		handle
 *		char*		*rsrc		resource name
 *		id_t		id		0
 *		char		**errorp	ptr to error message
 *		nvlist_t	*props		Not used
 *		rcm_info_t	**infop		ptr to info string
 *      Output:
 *		char		**infop		pass back info string
 *      Return:
 *		int		RCM_SUCCESS or RCM_FAILURE
 *      Locking: the cache is locked  throughout the whole function
 */
/*ARGSUSED*/
static int
svm_get_info(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags, char **usagep,
    char **errorp, nvlist_t *props, rcm_info_t **infop)
{
	int 		rv = RCM_SUCCESS;
	deventry_t	*deventry;
	deventry_t	*dependent;
	hspentry_t	*hspentry;
	char		**dependents;

	/* Guard against bad arguments */
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(usagep != NULL);
	assert(errorp != NULL);

	/* Trace */
	rcm_log_message(RCM_TRACE1, "SVM: get_info(%s)\n", rsrc);

	/* Lookup this resource in the cache (cache gets locked) */
	(void) mutex_lock(&svm_cache_lock);
	deventry = cache_lookup(svm_cache, rsrc);
	if (deventry == NULL) {
		(void) mutex_unlock(&svm_cache_lock);
		rcm_log_message(RCM_ERROR, MSG_UNRECOGNIZED, rsrc);
		*errorp = strdup(ERR_UNRECOGNIZED);
		return (RCM_FAILURE);
	}

	*usagep = NULL; /* Initialise usage string */
	if (deventry->flags&CONT_METADB) {
		*usagep = add_to_usage(usagep, gettext("contains metadb(s)"));
	}
	if (deventry->flags&CONT_SOFTPART) {
		*usagep = add_to_usage(usagep,
		    gettext("contains soft partition(s)"));
	}
	if (deventry->devtype == SVM_SOFTPART) {
		*usagep = add_to_usage_fmt(usagep,
		    gettext("soft partition based on \"%s\""),
		    deventry->antecedent->devname);
	}

	if (deventry->flags&IN_HSP) {
		int	hspflag = 0;
		hspentry = deventry->hsp_list;
		while (hspentry) {
			if (hspflag == 0) {
				*usagep = add_to_usage(usagep,
				    gettext("member of hot spare pool"));
				hspflag = 1;
			}
			*usagep = add_to_usage_fmt(usagep, "\"%s\"",
			    hspentry->hspname);
			hspentry = hspentry->next;
		}
	} else {
		dependent = deventry->dependent;
		while (dependent) {
			/* Resource has dependents */
			switch (dependent->devtype) {
			case SVM_STRIPE:
				*usagep = add_to_usage_fmt(usagep,
				    gettext("component of stripe \"%s\""),
				    dependent->devname);
				break;
			case SVM_CONCAT:
				*usagep = add_to_usage_fmt(usagep,
				    gettext("component of concat \"%s\""),
				    dependent->devname);
				break;
			case SVM_MIRROR:
				*usagep = add_to_usage_fmt(usagep,
				    gettext("submirror of \"%s\""),
				    dependent->devname);
				break;
			case SVM_RAID:
				*usagep = add_to_usage_fmt(usagep,
				    gettext("component of RAID \"%s\""),
				    dependent->devname);
				break;
			case SVM_TRANS:
				if (deventry->flags&TRANS_LOG) {
					*usagep = add_to_usage_fmt(usagep,
					    gettext("trans log for \"%s\""),
					    dependent->devname);
				} else {
					*usagep = add_to_usage_fmt(usagep,
					    gettext("trans master for \"%s\""),
					    dependent->devname);
				}
				break;
			case SVM_SOFTPART:
				/* Contains soft parts, already processed */
				break;
			default:
				rcm_log_message(RCM_ERROR,
				    gettext("Unknown type %d\n"),
				    dependent->devtype);
			}
			dependent = dependent->next_dep;
		}
	}

	/* Get dependents  and recurse if necessary */
	if (get_dependents(deventry, &dependents) != 0) {
		(void) mutex_unlock(&svm_cache_lock);
		rcm_log_message(RCM_ERROR, MSG_NODEPS);
		*errorp = strdup(ERR_NODEPS);
		return (RCM_FAILURE);
	}
	(void) mutex_unlock(&svm_cache_lock);

	if ((flags & RCM_INCLUDE_DEPENDENT) && (dependents != NULL)) {
		rv = rcm_get_info_list(hd, dependents, flags, infop);
		if (rv != RCM_SUCCESS)
			*errorp = strdup(gettext("unable to get info"));
	}
	free(dependents);

	if (*usagep != NULL)
		rcm_log_message(RCM_TRACE1, "SVM: usage = %s\n", *usagep);
	return (rv);
}

/*
 *      svm_suspend()
 *
 *      Notify all dependents that the resource is being suspended.
 *      Since no real operation is involved, QUERY or not doesn't matter.
 *
 *      Input:
 *		rcm_handle_t	*hd		handle
 *		char*		*rsrc		resource name
 *		id_t		id		0
 *		char		**errorp	ptr to error message
 *		rcm_info_t	**infop		ptr to info string
 *      Output:
 *		char		**errorp	pass back error message
 *      Return:
 *		int		RCM_SUCCESS or RCM_FAILURE
 *      Locking: the cache is locked for most of this routine, except while
 *      processing dependents.
 */
static int
svm_suspend(rcm_handle_t *hd, char *rsrc, id_t id, timespec_t *interval,
    uint_t flags, char **errorp, rcm_info_t **infop)
{
	int		rv = RCM_SUCCESS;
	deventry_t	*deventry;
	char		**dependents;

	/* Guard against bad arguments */
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(interval != NULL);
	assert(errorp != NULL);

	/* Trace */
	rcm_log_message(RCM_TRACE1, "SVM: suspend(%s)\n", rsrc);

	/* Lock the cache and extract information about this resource.  */
	(void) mutex_lock(&svm_cache_lock);
	if ((deventry = cache_lookup(svm_cache, rsrc)) == NULL) {
		(void) mutex_unlock(&svm_cache_lock);
		rcm_log_message(RCM_ERROR, MSG_UNRECOGNIZED, rsrc);
		*errorp = strdup(ERR_UNRECOGNIZED);
		return (RCM_SUCCESS);
	}

	/* Get dependents */
	if (get_dependents(deventry, &dependents) != 0) {
		(void) mutex_unlock(&svm_cache_lock);
		rcm_log_message(RCM_ERROR, MSG_NODEPS);
		*errorp = strdup(ERR_NODEPS);
		return (RCM_FAILURE);
	}
	(void) mutex_unlock(&svm_cache_lock);

	if (dependents) {
		rv = rcm_request_suspend_list(hd, dependents, flags,
		    interval, infop);
		if (rv != RCM_SUCCESS)
			*errorp = strdup(gettext("unable to suspend"));
		free(dependents);
	}

	return (rv);
}

/*
 *      svm_resume()
 *
 *      Notify all dependents that the resource is being resumed.
 *
 *      Input:
 *		rcm_handle_t	*hd		handle
 *		char*		*rsrc		resource name
 *		id_t		id		0
 *		char		**errorp	ptr to error message
 *		rcm_info_t	**infop		ptr to info string
 *      Output:
 *		char		**errorp	pass back error message
 *      Return:
 *		int		RCM_SUCCESS or RCM_FAILURE
 *      Locking: the cache is locked for most of this routine, except while
 *      processing dependents.
 *
 */
static int
svm_resume(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags, char **errorp,
    rcm_info_t **infop)
{
	int		rv = RCM_SUCCESS;
	deventry_t	*deventry;
	char		**dependents;

	/* Guard against bad arguments */
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(errorp != NULL);

	/* Trace */
	rcm_log_message(RCM_TRACE1, "SVM: resume(%s)\n", rsrc);

	/*
	 * Lock the cache just long enough to extract information about this
	 * resource.
	 */
	(void) mutex_lock(&svm_cache_lock);
	if ((deventry = cache_lookup(svm_cache, rsrc)) == NULL) {
		(void) mutex_unlock(&svm_cache_lock);
		rcm_log_message(RCM_ERROR, MSG_UNRECOGNIZED, rsrc);
		*errorp = strdup(ERR_UNRECOGNIZED);
		return (RCM_SUCCESS);
	}

	/* Get dependents */

	if (get_dependents(deventry, &dependents) != 0) {
		(void) mutex_unlock(&svm_cache_lock);
		rcm_log_message(RCM_ERROR, MSG_NODEPS);
		*errorp = strdup(ERR_NODEPS);
		return (RCM_FAILURE);
	}

	(void) mutex_unlock(&svm_cache_lock);
	if (dependents) {
		rv = rcm_notify_resume_list(hd, dependents, flags, infop);
		if (rv != RCM_SUCCESS)
			*errorp = strdup(gettext("unable to resume"));
		free(dependents);
	}

	return (rv);
}


/*
 *	svm_remove()
 *
 *      Remove the resource from the cache and notify all dependents that
 *      the resource has been removed.
 *
 *      Input:
 *		rcm_handle_t	*hd		handle
 *		char*		*rsrc		resource name
 *		id_t		id		0
 *		char		**errorp	ptr to error message
 *		rcm_info_t	**infop		ptr to info string
 *      Output:
 *		char		**errorp	pass back error message
 *      Return:
 *		int		RCM_SUCCESS or RCM_FAILURE
 *      Locking: the cache is locked for most of this routine, except while
 *      processing dependents.
 */
static int
svm_remove(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags, char **errorp,
    rcm_info_t **infop)
{
	int		rv = RCM_SUCCESS;
	char		**dependents;
	deventry_t	*deventry;

	/* Guard against bad arguments */
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);

	/* Trace */
	rcm_log_message(RCM_TRACE1, "SVM: svm_remove(%s)\n", rsrc);

	/* Lock the cache while removing resource */
	(void) mutex_lock(&svm_cache_lock);
	if ((deventry = cache_lookup(svm_cache, rsrc)) == NULL) {
		(void) mutex_unlock(&svm_cache_lock);
		return (RCM_SUCCESS);
	}

	/* Get dependents */
	if (get_dependents(deventry, &dependents) != 0) {
		(void) mutex_unlock(&svm_cache_lock);
		rcm_log_message(RCM_ERROR, MSG_NODEPS);
		deventry->flags |= REMOVED;
		*errorp = strdup(ERR_NODEPS);
		return (RCM_FAILURE);
	}

	if (dependents) {
		(void) mutex_unlock(&svm_cache_lock);
		rv = rcm_notify_remove_list(hd, dependents, flags, infop);
		(void) mutex_lock(&svm_cache_lock);
		if (rv != RCM_SUCCESS)
			*errorp = strdup(gettext("unable to remove"));
		free(dependents);
	}

	/* Mark entry as removed */
	deventry->flags |= REMOVED;

	(void) mutex_unlock(&svm_cache_lock);
	rcm_log_message(RCM_TRACE1, "SVM: exit svm_remove(%s)\n", rsrc);
	/* Clean up and return success */
	return (RCM_SUCCESS);
}

/*
 * Definitions of private functions
 *
 */

/*
 *	find_hsp()
 *
 *	Find the hot spare entry from the linked list of all hotspare pools
 *
 *	Input:
 *		char		*hspname	name of hot spare pool
 *	Return:
 *		hspentry_t	hot spare entry
 */
static hspentry_t *
find_hsp(char *hspname)
{
	hspentry_t	*hspentry = hsp_head;

	while (hspentry) {
		if (strcmp(hspname, hspentry->hspname) == 0)
			return (hspentry);
		hspentry = hspentry->link;
	}
	return (NULL);
}

/*
 *      add_hsp_user()
 *
 *      Add a hot spare pool user to the list for the hsp specfied by
 *	hspname. The memory allocated here will be freed by free_cache()
 *
 *      Input:
 *		char		*hspname	hot spare pool name
 *		deventry_t	*deventry	specified hsp user
 *      Return:
 *		hspuser_t	entry in hsp user list
 */
static hspuser_t *
add_hsp_user(char *hspname, deventry_t *deventry)
{
	hspuser_t	*newhspuser;
	char		*newhspusername;
	hspuser_t	*previous;
	hspentry_t	*hspentry;

	hspentry = find_hsp(hspname);
	if (hspentry == NULL)
		return (NULL);
	rcm_log_message(RCM_TRACE1, "SVM: Enter add_hsp_user %s, %x, %x\n",
	    hspname, hspentry, hspentry->hspuser);

	newhspuser = (hspuser_t *)malloc(sizeof (*newhspuser));
	if (newhspuser == NULL) {
		rcm_log_message(RCM_ERROR,
		    gettext("SVM: can't malloc hspuser"));
		return (NULL);
	}
	(void) memset((char *)newhspuser, 0, sizeof (*newhspuser));

	newhspusername = strdup(deventry->devname);
	if (newhspusername == NULL) {
		rcm_log_message(RCM_ERROR,
		    gettext("SVM: can't malloc hspusername"));
		free(newhspuser);
		return (NULL);
	}
	newhspuser->hspusername = newhspusername;
	newhspuser->hspuserkey = deventry->devkey;

	if ((previous = hspentry->hspuser) == NULL) {
		hspentry->hspuser = newhspuser;
	} else {
		hspuser_t	*temp = previous->next;
		previous->next = newhspuser;
		newhspuser->next = temp;
	}
	rcm_log_message(RCM_TRACE1, "SVM: Added hsp_user %s (dev %x) to %s\n",
	    newhspusername, newhspuser->hspuserkey, hspname);
	return (newhspuser);
}

/*
 *      add_hsp()
 *
 *      Add a hot spare pool entry to the list for the slice, deventry.
 *      Also add to the linked list of all hsp pools
 *	The memory alllocated here will be freed by free_cache()
 *
 *      Input:
 *		char		*hspname	name of hsp pool entry
 *		deventry_t	*deventry	device entry for the slice
 *      Return:
 *		hspentry_t	end of hsp list
 *      Locking: None
 */
static hspentry_t *
add_hsp(char *hspname, deventry_t *deventry)
{
	hspentry_t	*newhspentry;
	hspentry_t	*previous;
	char		*newhspname;

	rcm_log_message(RCM_TRACE1, "SVM: Enter add_hsp %s\n",
	    hspname);
	newhspentry = (hspentry_t *)malloc(sizeof (*newhspentry));
	if (newhspentry == NULL) {
		rcm_log_message(RCM_ERROR,
		    gettext("SVM: can't malloc hspentry"));
		return (NULL);
	}
	(void) memset((char *)newhspentry, 0, sizeof (*newhspentry));

	newhspname = strdup(hspname);
	if (newhspname == NULL) {
		rcm_log_message(RCM_ERROR,
		    gettext("SVM: can't malloc hspname"));
		free(newhspentry);
		return (NULL);
	}
	newhspentry->hspname = newhspname;

	/* Add to linked list of all hotspare pools */
	newhspentry->link = hsp_head;
	hsp_head = newhspentry;

	/* Add to list of hotspare pools containing this slice */
	if ((previous = deventry->hsp_list) == NULL) {
		deventry->hsp_list = newhspentry;
	} else {
		hspentry_t	*temp = previous->next;
		previous->next = newhspentry;
		newhspentry->next = temp;
	}
	rcm_log_message(RCM_TRACE1, "SVM: Exit add_hsp %s\n",
	    hspname);
	return (newhspentry);
}

/*
 *      cache_dependent()
 *
 *      Add a dependent for a deventry to the cache and return the cache entry
 *	If the name is not in the cache, we assume that it a SLICE. If it
 *	turns out to be any other type of metadevice, when it is processed
 *	in cache_all_devices_in_set(), cache_device() will be called to
 *	set the type to the actual value.
 *
 *      Input:
 *		cache_t		*cache		cache
 *		char		*devname	metadevice name
 *		int		devflags	metadevice flags
 *		deventry_t	*dependent	dependent of this metadevice
 *      Return:
 *		deventry_t	metadevice entry added to cache
 *      Locking: None
 */
static deventry_t *
cache_dependent(cache_t *cache, char *devname, int devflags,
    deventry_t *dependent)
{

	deventry_t	*newdeventry = NULL;
	deventry_t	*hashprev = NULL;
	deventry_t	*deventry = NULL;
	deventry_t	*previous = NULL;
	uint32_t	hash_index;
	int		comp;

	rcm_log_message(RCM_TRACE1, "SVM: Enter cache_dep %s, %x, %s\n",
	    devname, devflags, dependent->devname);

	hash_index = hash(cache->size, devname);
	if (hash_index >= cache->size) {
		rcm_log_message(RCM_ERROR,
		    gettext("SVM: can't hash device."));
		return (NULL);
	}

	deventry = cache->hashline[hash_index];

	/* if the hash table slot is empty, then this is easy */
	if (deventry == NULL) {
		deventry = create_deventry(devname, SVM_SLICE, 0, devflags);
		cache->hashline[hash_index] = deventry;
	} else {
	/* if the hash table slot isn't empty, find the immediate successor */
		hashprev = NULL;
		while ((comp = strcmp(deventry->devname, devname)) < 0 &&
		    deventry->next != NULL) {
			hashprev = deventry;
			deventry = deventry->next;
		}

		if (comp == 0) {
			/* if already in cache, just update the flags */
			deventry->flags |= devflags;
		} else {
			/* insert the entry if it's not already there */
			if ((newdeventry = create_deventry(devname,
			    SVM_SLICE, 0, devflags)) == NULL) {
				rcm_log_message(RCM_ERROR,
				    gettext("SVM: can't create hash line."));
				return (NULL);
			}
			if (comp > 0) {
				newdeventry->next = deventry;
				if (hashprev)
					hashprev->next = newdeventry;
				else
					cache->hashline[hash_index] =
					    newdeventry;
			} else if (comp < 0) {
				newdeventry->next = deventry->next;
				deventry->next = newdeventry;
			}
			deventry = newdeventry;
		}
	}
	/* complete deventry by linking the dependent to it */
	dependent->antecedent = deventry;
	if ((previous = deventry->dependent) != NULL) {
		deventry_t *temp = previous->next_dep;
		previous->next_dep = dependent;
		dependent->next_dep = temp;
	} else deventry->dependent = dependent;
	return (deventry);

}

/*
 *      cache_device()
 *
 *      Add an entry to the cache for devname
 *
 *      Input:
 *		cache_t		*cache		cache
 *		char		*devname	metadevice named
 *		svm_type_t	devtype		metadevice type
 *		md_dev64_t	devkey		dev_t of device
 *		int		devflags	device flags
 *      Return:
 *		deventry_t	metadevice added to cache
 *      Locking: None
 */
static deventry_t *
cache_device(cache_t *cache, char *devname, svm_type_t devtype,
    md_dev64_t devkey, int devflags)
{
	deventry_t	*newdeventry = NULL;
	deventry_t	*previous = NULL;
	deventry_t	*deventry = NULL;
	uint32_t	hash_index;
	int		comp;

	rcm_log_message(RCM_TRACE1, "SVM: Enter cache_device %s, %x, %lx, %x\n",
	    devname, devtype, devkey, devflags);

	hash_index = hash(cache->size, devname);
	if (hash_index >= cache->size) {
		rcm_log_message(RCM_ERROR,
		    gettext("SVM: can't hash device."));
		return (NULL);
	}

	deventry = cache->hashline[hash_index];

	/* if the hash table slot is empty, then this is easy */
	if (deventry == NULL) {
		deventry = create_deventry(devname, devtype, devkey,
		    devflags);
		cache->hashline[hash_index] = deventry;
	} else {
	/* if the hash table slot isn't empty, find the immediate successor */
		previous = NULL;
		while ((comp = strcmp(deventry->devname, devname)) < 0 &&
		    deventry->next != NULL) {
			previous = deventry;
			deventry = deventry->next;
		}

		if (comp == 0) {
			/*
			 * If entry already exists, just set the type, key
			 * and flags
			 */
			deventry->devtype = devtype;
			deventry->devkey = meta_cmpldev(devkey);
			deventry->flags |= devflags;
		} else {
			/* insert the entry if it's not already there */
			if ((newdeventry = create_deventry(devname, devtype,
			    devkey, devflags)) == NULL) {
				rcm_log_message(RCM_ERROR,
				    gettext("SVM: can't create hash line."));
			}
			if (comp > 0) {
				newdeventry->next = deventry;
				if (previous)
					previous->next = newdeventry;
				else
					cache->hashline[hash_index] =
					    newdeventry;
			} else if (comp < 0) {
				newdeventry->next = deventry->next;
				deventry->next = newdeventry;
			}
			deventry = newdeventry;
		}
	}
	return (deventry);
}
/*
 *	free_names()
 *
 *	Free all name list entries
 *
 *	Input:
 *		mdnamelist_t		*np		namelist pointer
 *	Return: None
 */

static void
free_names(mdnamelist_t *nlp)
{
	mdnamelist_t *p;

	for (p = nlp; p != NULL; p = p->next) {
	    meta_invalidate_name(p->namep);
	    p->namep = NULL;
	}
	metafreenamelist(nlp);
}

/*
 * cache_hsp()
 *
 *	Add an entry to the cache for each slice in the hot spare
 *	pool. Call add_hsp() to add the hot spare pool to the list
 *	of all hot spare pools.
 *
 *	Input:
 *		cache_t		*cache	cache
 *		mdnamelist_t	*nlp	pointer to hsp name
 *		md_hsp_t	*hsp
 *	Return:
 *		0 if successful or error code
 */
static int
cache_hsp(cache_t *cache, mdhspnamelist_t *nlp, md_hsp_t *hsp)
{
	int		i;
	deventry_t	*deventry;
	md_hs_t		*hs;

	for (i = 0; i < hsp->hotspares.hotspares_len; i++) {
		hs = &hsp->hotspares.hotspares_val[i];
		if ((deventry = cache_device(cache, hs->hsnamep->bname,
		    SVM_SLICE, hs->hsnamep->dev,
		    IN_HSP)) == NULL) {
			return (ENOMEM);
		}
		if (add_hsp(nlp->hspnamep->hspname, deventry) == NULL) {
			return (ENOMEM);
		}
	}
	return (0);
}

/*
 * cache_trans()
 *
 *	Add an entry to the cache for trans metadevice, the master
 *	and the log. Call cache_dependent() to link that master and
 *	the log to the trans metadevice.
 *
 *	Input:
 *		cache_t		*cache	cache
 *		mdnamelist_t	*nlp	pointer to trans name
 *		md_trans_t	*trans
 *	Return:
 *		0 if successful or error code
 *
 */
static int
cache_trans(cache_t *cache, mdnamelist_t *nlp, md_trans_t *trans)
{
	deventry_t	*antecedent;

	if ((antecedent = cache_device(cache, nlp->namep->bname, SVM_TRANS,
	    nlp->namep->dev, 0)) == NULL) {
		return (ENOMEM);
	}

	if (cache_device(cache, trans->masternamep->bname, SVM_SLICE,
	    trans->masternamep->dev, 0) == NULL) {
		return (ENOMEM);
	}

	if (cache_dependent(cache, trans->masternamep->bname, 0,
	    antecedent) == NULL) {
		return (ENOMEM);
	}

	if (trans->lognamep != NULL) {
		if (cache_device(cache, trans->lognamep->bname, SVM_SLICE,
		    trans->lognamep->dev, TRANS_LOG) == NULL) {
			return (ENOMEM);
		}

		if (cache_dependent(cache, trans->lognamep->bname, 0,
		    antecedent) == NULL) {
			return (ENOMEM);
		}
	}
	return (0);
}

/*
 * cache_mirror()
 *
 *	Add an entry to the cache for the mirror. For each
 *	submirror, call cache_dependent() to add an entry to the
 *	cache and to link it to mirror entry.
 *
 *	Input:
 *		cache_t		*cache	cache
 *		mdnamelist_t	*nlp	pointer to mirror name
 *		md_mirror_t	*mirror
 *	Return:
 *		0 if successful or error code
 *
 */
static int
cache_mirror(cache_t *cache, mdnamelist_t *nlp, md_mirror_t *mirror)
{
	int i;
	deventry_t	*antecedent;

	if ((antecedent = cache_device(cache, nlp->namep->bname, SVM_MIRROR,
	    nlp->namep->dev, 0)) == NULL) {
		return (ENOMEM);
	}
	for (i = 0; i <  NMIRROR; i++) {
		md_submirror_t	*submirror;

		submirror = &mirror->submirrors[i];
		if (submirror->state == SMS_UNUSED)
			continue;

		if (!submirror->submirnamep)
			continue;

		if (cache_dependent(cache, submirror->submirnamep->bname,
		    0, antecedent) == NULL) {
			return (ENOMEM);
		}
	}
	return (0);
}

/*
 * cache_raid()
 *
 *	Add an entry to the cache for the RAID metadevice. For
 *	each component of the RAID call cache_dependent() to add
 *	add it to the cache and to link it to the RAID metadevice.
 *
 *	Input:
 *		cache_t		*cache	cache
 *		mdnamelist_t	*nlp	pointer to raid name
 *		md_raid_t	*raid	mirror
 *	Return:
 *		0 if successful or error code
 */
static int
cache_raid(cache_t *cache, mdnamelist_t *nlp, md_raid_t *raid)
{
	int i;
	deventry_t	*antecedent;

	if ((antecedent = cache_device(cache, nlp->namep->bname, SVM_RAID,
	    nlp->namep->dev, 0)) == NULL) {
		return (ENOMEM);
	}
	if (raid->hspnamep) {
		if (add_hsp_user(raid->hspnamep->hspname,
		    antecedent) == NULL) {
			return (ENOMEM);
		}
	}
	for (i = 0; i < raid->cols.cols_len; i++) {
		if (cache_dependent(cache,
		    raid->cols.cols_val[i].colnamep->bname, 0,
		    antecedent) == NULL) {
			return (ENOMEM);
		}
	}
	return (0);
}

/*
 * cache_stripe()
 *
 *	Add a CONCAT or a STRIPE entry entry to the cache for the
 *	metadevice and call cache_dependent() to add each
 *	component to the cache.
 *
 *	Input:
 *		cache_t		*cache	cache
 *		mdnamelist_t	*nlp	pointer to stripe name
 *		md_stripe_t	*stripe
 *	Return:
 *		0 if successful or error code
 *
 */
static int
cache_stripe(cache_t *cache, mdnamelist_t *nlp, md_stripe_t *stripe)
{
	int i;
	deventry_t	*antecedent;

	if ((antecedent = cache_device(cache, nlp->namep->bname, SVM_CONCAT,
	    nlp->namep->dev, 0)) == NULL) {
		return (ENOMEM);
	}

	if (stripe->hspnamep) {
		if (add_hsp_user(stripe->hspnamep->hspname,
		    antecedent) == NULL) {
			return (ENOMEM);
		}
	}
	for (i = 0; i < stripe->rows.rows_len; i++) {
		md_row_t	*rowp;
		int		j;

		rowp = &stripe->rows.rows_val[i];
		if (stripe->rows.rows_len == 1 && rowp->comps.comps_len > 1) {
			if ((void*) cache_device(cache, nlp->namep->bname,
			    SVM_STRIPE, nlp->namep->dev, 0) == NULL)
				return (ENOMEM);
		}
		for (j = 0; j < rowp->comps.comps_len; j++) {
			md_comp_t	*component;

			component = &rowp->comps.comps_val[j];
			if (cache_dependent(cache,
			    component->compnamep->bname, 0,
			    antecedent) == NULL) {
				return (ENOMEM);
			}
		}
	}
	return (0);
}

/*
 * cache_sp()
 *
 *	Add an entry to the cache for the softpart and also call
 *	cache_dependent() to set the CONT_SOFTPART flag in the
 *	cache entry for the metadevice that contains the softpart.
 *
 *	Input:
 *		cache_t		*cache	cache
 *		mdnamelist_t	*nlp	pointer to soft part name
 *		md_sp_t		*soft_part
 *	Return:
 *		0 if successful or error code
 *
 */
static int
cache_sp(cache_t *cache, mdnamelist_t *nlp, md_sp_t *soft_part)
{
	deventry_t	*antecedent;

	if ((antecedent = cache_device(cache, nlp->namep->bname,
	    SVM_SOFTPART, nlp->namep->dev, 0)) == NULL) {
			    return (ENOMEM);
	}
	if (cache_dependent(cache, soft_part->compnamep->bname,
	    CONT_SOFTPART, antecedent) == NULL) {
		return (ENOMEM);
	}
	return (0);
}

/*
 *      cache_all_devices_in_set()
 *
 *      Add all of the metadevices and mddb replicas in the set to the
 *	cache
 *
 *      Input:
 *		cache_t		*cache		cache
 *		mdsetname_t	*sp		setname
 *      Return:
 *		0 if successful or error code
 */

static int
cache_all_devices_in_set(cache_t *cache, mdsetname_t *sp)
{
	md_error_t		error = mdnullerror;
	md_replicalist_t	*replica_list = NULL;
	md_replicalist_t	*mdbp;
	mdnamelist_t		*nlp;
	mdnamelist_t		*trans_list = NULL;
	mdnamelist_t		*mirror_list = NULL;
	mdnamelist_t		*raid_list = NULL;
	mdnamelist_t		*stripe_list = NULL;
	mdnamelist_t		*sp_list = NULL;
	mdhspnamelist_t		*hsp_list = NULL;

	rcm_log_message(RCM_TRACE1, "SVM: cache_all_devices_in_set\n");

	/* Add each mddb replica to the cache */
	if (metareplicalist(sp, MD_BASICNAME_OK, &replica_list, &error) < 0) {
	    /* there are no metadb's; that is ok, no need to check the rest */
	    mdclrerror(&error);
	    return (0);
	}

	for (mdbp = replica_list; mdbp != NULL; mdbp = mdbp->rl_next) {
		if (cache_device(cache, mdbp->rl_repp->r_namep->bname,
		    SVM_SLICE, mdbp->rl_repp->r_namep->dev,
		    CONT_METADB) == NULL) {
			metafreereplicalist(replica_list);
			return (ENOMEM);
		}
	}
	metafreereplicalist(replica_list);

	/* Process Hot Spare pools */
	if (meta_get_hsp_names(sp, &hsp_list, 0, &error) >= 0) {
	    mdhspnamelist_t *nlp;

		for (nlp = hsp_list; nlp != NULL; nlp = nlp->next) {
			md_hsp_t	*hsp;

			hsp = meta_get_hsp(sp, nlp->hspnamep, &error);
			if (hsp != NULL) {
				if (cache_hsp(cache, nlp, hsp) != 0) {
					metafreehspnamelist(hsp_list);
					return (ENOMEM);
				}
			}
			meta_invalidate_hsp(nlp->hspnamep);
		}
		metafreehspnamelist(hsp_list);
	}

	/* Process Trans devices */
	if (meta_get_trans_names(sp, &trans_list, 0, &error) >= 0) {
		for (nlp = trans_list; nlp != NULL; nlp = nlp->next) {
			mdname_t	*mdn;
			md_trans_t	*trans;

			mdn = metaname(&sp, nlp->namep->cname, META_DEVICE,
			    &error);
			if (mdn == NULL) {
				continue;
			}

			trans = meta_get_trans(sp, mdn, &error);

			if (trans != NULL && trans->masternamep != NULL) {
				if (cache_trans(cache, nlp, trans) != NULL) {
					free_names(trans_list);
					return (ENOMEM);
				}
			}
		}
		free_names(trans_list);
	}

	/* Process Mirrors */
	if (meta_get_mirror_names(sp, &mirror_list, 0, &error) >= 0) {
		for (nlp = mirror_list; nlp != NULL; nlp = nlp->next) {
			mdname_t	*mdn;
			md_mirror_t	*mirror;

			mdn = metaname(&sp, nlp->namep->cname, META_DEVICE,
			    &error);
			if (mdn == NULL) {
				continue;
			}

			mirror = meta_get_mirror(sp, mdn, &error);

			if (mirror != NULL) {
				if (cache_mirror(cache, nlp, mirror) != 0) {
					free_names(mirror_list);
					return (ENOMEM);
				}
			}
		}
		free_names(mirror_list);
	}

	/* Process Raid devices */
	if (meta_get_raid_names(sp, &raid_list, 0, &error) >= 0) {
		for (nlp = raid_list; nlp != NULL; nlp = nlp->next) {
			mdname_t	*mdn;
			md_raid_t	*raid;

			mdn = metaname(&sp, nlp->namep->cname, META_DEVICE,
			    &error);
			if (mdn == NULL) {
				continue;
			}

			raid = meta_get_raid(sp, mdn, &error);

			if (raid != NULL) {
				if (cache_raid(cache, nlp, raid) != 0) {
					free_names(raid_list);
					return (ENOMEM);
				}
			}
		}
		free_names(raid_list);
	}

	/* Process Slices */
	if (meta_get_stripe_names(sp, &stripe_list, 0, &error) >= 0) {
		for (nlp = stripe_list; nlp != NULL; nlp = nlp->next) {
			mdname_t	*mdn;
			md_stripe_t	*stripe;

			mdn = metaname(&sp, nlp->namep->cname, META_DEVICE,
			    &error);
			if (mdn == NULL) {
				continue;
			}

			stripe = meta_get_stripe(sp, mdn, &error);

			if (stripe != NULL) {
				if (cache_stripe(cache, nlp, stripe) != 0) {
					free_names(stripe_list);
					return (ENOMEM);
				}
			}
		}
		free_names(stripe_list);
	}

	/* Process Soft partitions */
	if (meta_get_sp_names(sp, &sp_list, 0, &error) >= 0) {
		for (nlp = sp_list; nlp != NULL; nlp = nlp->next) {
			mdname_t	*mdn;
			md_sp_t		*soft_part;

			mdn = metaname(&sp, nlp->namep->cname, META_DEVICE,
			    &error);
			if (mdn == NULL) {
				continue;
			}

			soft_part = meta_get_sp(sp, mdn, &error);

			if (soft_part != NULL) {
				if (cache_sp(cache, nlp, soft_part) != 0) {
					free_names(sp_list);
					return (ENOMEM);
				}
			}
		}
		free_names(sp_list);
	}
	mdclrerror(&error);
	return (0);
}

/*
 *      create_all_devices()
 *
 *      Cache all devices in all sets
 *
 *      Input:
 *		cache_t		cache
 *      Return:
 *		0 if successful, error code if not
 *      Locking: None
 */
static int
cache_all_devices(cache_t *cache)
{
	int		max_sets;
	md_error_t	error = mdnullerror;
	int		i;

	if ((max_sets = get_max_sets(&error)) == 0) {
		return (0);
	}
	if (!mdisok(&error)) {
		mdclrerror(&error);
		return (0);
	}

	rcm_log_message(RCM_TRACE1,
	    "SVM: cache_all_devices,max sets = %d\n", max_sets);
	/* for each possible set number, see if we really have a diskset */
	for (i = 0; i < max_sets; i++) {
		mdsetname_t	*sp;

		if ((sp = metasetnosetname(i, &error)) == NULL) {
			rcm_log_message(RCM_TRACE1,
			    "SVM: cache_all_devices no set: setno %d\n", i);
			if (!mdisok(&error) &&
			    ((error.info.errclass == MDEC_RPC) ||
			    (mdiserror(&error, MDE_SMF_NO_SERVICE)))) {
				/*
				 * metad rpc program not available
				 * - no metasets.  metad rpc not available
				 * is indicated either by an RPC error or
				 * the fact that the service is not
				 * enabled.
				 */
				break;
			}

			continue;
		}

		if (cache_all_devices_in_set(cache, sp)) {
			metaflushsetname(sp);
			return (ENOMEM);
		}
		metaflushsetname(sp);
	}
	mdclrerror(&error);
	rcm_log_message(RCM_TRACE1, "SVM: exit cache_all_devices\n");
	return (0);
}

/*
 *      create_cache()
 *
 *      Create an empty cache
 *	If the function fails free_cache() will be called to free any
 *	allocated memory.
 *
 *      Input: None
 *      Return:
 *		cache_t		cache created
 *      Locking: None
 */
static cache_t *
create_cache()
{
	cache_t		*cache;
	uint32_t	size;
	int		ret;

	size = HASH_DEFAULT;
	/* try allocating storage for a new, empty cache */
	if ((cache = (cache_t *)malloc(sizeof (cache_t))) == NULL) {
		rcm_log_message(RCM_ERROR, MSG_CACHEFAIL);
		return (NULL);
	}

	(void) memset((char *)cache, 0, sizeof (*cache));
	cache->hashline = (deventry_t **)calloc(size, sizeof (deventry_t *));
	if (cache->hashline == NULL) {
		rcm_log_message(RCM_ERROR, MSG_CACHEFAIL);
		free(cache);
		return (NULL);
	}
	cache->size = size;

	/* Initialise linked list of hsp entries */
	hsp_head = NULL;

	/* add entries to cache */
	ret = cache_all_devices(cache);
	if (ret != 0) {
		free_cache(&cache);
		return (NULL);
	}

	/* Mark the cache as new */
	cache->registered = 0;

	/* Finished - return the new cache */
	return (cache);
}

/*
 *      create_deventry()
 *
 *      Create a new deventry entry for device with name devname
 *	The memory alllocated here will be freed by free_cache()
 *
 *      Input:
 *		char		*devname	device name
 *		svm_type_t	devtype		metadevice type
 *		md_dev64_t	devkey		device key
 *		int		devflags	device flags
 *      Return:
 *		deventry_t	New deventry
 *      Locking: None
 */
static deventry_t *
create_deventry(char *devname, svm_type_t devtype, md_dev64_t devkey,
    int devflags)
{
	const char	*devprefix = "/dev/";
	deventry_t	*newdeventry = NULL;
	char		*newdevname = NULL;
	char		*devicesname = NULL;

	newdeventry = (deventry_t *)malloc(sizeof (*newdeventry));
	if (newdeventry == NULL) {
		rcm_log_message(RCM_ERROR,
		    gettext("SVM: can't malloc deventrys"));
		goto errout;
	}
	(void) memset((char *)newdeventry, 0, sizeof (*newdeventry));

	newdevname = strdup(devname);
	if (newdevname == NULL) {
		rcm_log_message(RCM_ERROR,
		    gettext("SVM: can't malloc devname"));
		goto errout;
	}

	/*
	 * When we register interest in a name starting with /dev/, RCM
	 * will use realpath to convert the name to a /devices name before
	 * storing it.  metaclear removes both the /dev and the /devices
	 * form of the name of a metadevice from the file system.  Thus,
	 * when we later call rcm_unregister_interest to get rid of a
	 * metacleared device, RCM will not be able to derive the /devices
	 * name for the /dev name.  Thus, to unregister we will need to use
	 * the /devices name.  We will save it now, so that we have it when
	 * it comes time to unregister.
	 */
	if (strncmp(devname, devprefix, strlen(devprefix)) == 0) {
		devicesname = (char *)malloc(PATH_MAX);
		if (devicesname == NULL) {
			rcm_log_message(RCM_ERROR,
			    gettext("SVM: can't malloc PATH_MAX bytes"));
			goto errout;
		}
		if (realpath(devname, devicesname) == NULL) {
			free(devicesname);
			devicesname = NULL;
		}
	}
	newdeventry->devname = newdevname;
	newdeventry->devicesname = devicesname;
	newdeventry->devtype = devtype;
	newdeventry->devkey = meta_cmpldev(devkey);
	newdeventry->flags = devflags;
	if (newdeventry->devicesname == NULL) {
		rcm_log_message(RCM_TRACE1,
			"SVM created deventry for %s\n", newdeventry->devname);
	} else {
		rcm_log_message(RCM_TRACE1,
			"SVM created deventry for %s (%s)\n",
			newdeventry->devname, newdeventry->devicesname);
	}
	return (newdeventry);

errout:
	if (devicesname != NULL)
		free(devicesname);
	if (newdevname != NULL)
		free(newdevname);
	if (newdeventry != NULL)
		free(newdeventry);
	return (NULL);
}

/*
 *      cache_remove()
 *
 *      Given a cache and a deventry, the deventry is
 *      removed from the cache's tables and memory for the deventry is
 *      free'ed.
 *
 *      Input:
 *		cache_t		*cache		cache
 *		deventry_t	*deventry	deventry to be removed
 *      Return: None
 *      Locking: The cache must be locked by the caller prior to calling
 *      this routine.
 */
static void
cache_remove(cache_t *cache, deventry_t *deventry)
{
	deventry_t	*olddeventry;
	deventry_t	*previous;
	hspentry_t	*hspentry;
	hspentry_t	*oldhspentry;
	hspuser_t	*hspuser;
	hspuser_t	*oldhspuser;
	uint32_t	hash_index;

	/* sanity check */
	if (cache == NULL || deventry == NULL || deventry->devname == NULL)
		return;


	/* If this is in the hash table, remove it from there */
	hash_index = hash(cache->size, deventry->devname);
	if (hash_index >= cache->size) {
		rcm_log_message(RCM_ERROR,
		    gettext("SVM: can't hash device."));
		return;
	}
	olddeventry = cache->hashline[hash_index];
	previous = NULL;
	while (olddeventry) {
		if (olddeventry->devname &&
		    strcmp(olddeventry->devname, deventry->devname) == 0) {
			break;
		}
		previous = olddeventry;
		olddeventry = olddeventry->next;
	}
	if (olddeventry) {
		if (previous)
			previous->next = olddeventry->next;
		else
			cache->hashline[hash_index] = olddeventry->next;

		if (olddeventry->flags&IN_HSP) {
			/*
			 * If this is in a hot spare pool, remove the list
			 * of hot spare pools that it is in along with
			 * all of the volumes that are users of the pool
			 */
			hspentry = olddeventry->hsp_list;
			while (hspentry) {
				oldhspentry = hspentry;
				hspuser = hspentry->hspuser;
				while (hspuser) {
					oldhspuser = hspuser;
					free(hspuser->hspusername);
					hspuser = hspuser->next;
					free(oldhspuser);
				}
				free(hspentry->hspname);
				hspentry = hspentry->next;
				free(oldhspentry);
			}
		}
		free(olddeventry->devname);
		free(olddeventry);
	}

}

/*
 *      cache_lookup()
 *
 *      Return the deventry corresponding to devname from the cache
 *      Input:
 *		cache_t		cache		cache
 *		char		*devname	name to lookup in cache
 *      Return:
 *		deventry_t	deventry of name, NULL if not found
 *      Locking: cache lock held on entry and on exit
 */
static deventry_t *
cache_lookup(cache_t *cache, char *devname)
{
	int		comp;
	uint32_t	hash_index;
	deventry_t	*deventry;

	hash_index = hash(cache->size, devname);
	if (hash_index >= cache->size) {
		rcm_log_message(RCM_ERROR,
		    gettext("SVM: can't hash resource."));
		return (NULL);
	}

	deventry = cache->hashline[hash_index];
	while (deventry) {
		comp = strcmp(deventry->devname, devname);
		if (comp == 0)
			return (deventry);
		if (comp > 0)
			return (NULL);
		deventry = deventry->next;
	}
	return (NULL);
}

/*
 *      cache_sync()
 *
 *	Resync cache with the svm database.  First a new cache is created
 *	that represents the current state of the SVM database.  The
 *	function walks the new cache to look for new entries that must be
 *	registered.  The new entries are kept in a list, because we cannot
 *	register them at this point.  Entries that appear in both caches
 *	are removed from the old cache.  Because of this at the end of the
 *	walk, the old cache will only contain devices that have been
 *	removed and need to be unregistered.
 *
 *	Next the old cache is walked, so that we can unregister the devices
 *	that are no longer present.
 *
 *	Finally, we process the list of new devices that must be
 *	registered.  There is a reason why we must unregister the removed
 *	(metacleared) devices before registering the new ones.  It has to
 *	do with the fact that rcm_register_interest calls realpath(3C) to
 *	convert a /dev name to a /devices name.  It uses the /devices name
 *	for storing the device information.
 *
 *	It can happen that between cache_syncs that the administrator
 *	metaclears one metadevice and metacreates a new one.  For example,
 *
 *		metaclear acct
 *		metainit engr 1 1 c1t12d0s0
 *
 *	The metaclear operation frees up the minor number that was being
 *	used by acct.  The metainit operation can then reuse the minor
 *	number.  This means that both metadevices would have the same
 *	/devices name even though they had different /dev names.  Since
 *	rcm_register_interest uses /devices names for storing records, we
 *	need to unregister acct before registering engr.  Otherwise we
 *	would get an EALREADY errno and a failed registration.  This is why
 *	cache_sync creates a list of devices to be registered after all the
 *	removed devices have been unregistered.
 *
 *      Input:
 *		rcm_handle_t	*hd		rcm handle
 *		cache_t		**cachep	pointer to cache
 *      Return:
 *		cache_t		**cachep	pointer to new cache
 *      Return: None
 *      Locking: The cache must be locked prior to entry
 */
static void
cache_sync(rcm_handle_t *hd, cache_t **cachep)
{
	char		*devicename;
	deventry_t	*deventry;
	cache_t		*new_cache;
	cache_t		*old_cache = *cachep;
	deventry_t	*hashline = NULL;
	deventry_t	**register_list = NULL;
	deventry_t	*register_this;
	uint32_t	register_count = 0;	/* # entrys in register_list */
	uint32_t	allocated = 0;		/* # entrys allocated in */
						/* register_list */
	uint32_t	allocate_incr = 16;
	uint32_t	i = 0;

	/* Get a new cache */
	if ((new_cache = create_cache()) == NULL) {
		rcm_log_message(RCM_WARNING, MSG_NORECACHE);
		return;
	}

	/* For every entry in the new cache... */
	while ((devicename = cache_walk(new_cache, &i, &hashline)) != NULL) {
		register_this = NULL;

		/* Look for this entry in the old cache */
		deventry = cache_lookup(old_cache, devicename);
		/*
		 * If no entry in old cache, register the resource. If there
		 * is an entry, but it is marked as removed, register it
		 * again and remove it from the old cache
		 */
		if (deventry == NULL) {
			register_this = hashline;
		} else {
			if (deventry->flags&REMOVED)
				register_this = hashline;
			cache_remove(old_cache, deventry);
		}

		/* Save this entry if we need to register it later. */
		if (register_this) {
			if (register_count >= allocated) {
				/* Need to extend our array */
				allocated += allocate_incr;
				register_list =
					(deventry_t **)realloc(register_list,
					allocated * sizeof (*register_list));
				if (register_list == NULL) {
					/* Out of memory.  Give up. */
					rcm_log_message(RCM_WARNING,
						MSG_NORECACHE);
					free(new_cache);
					return;
				}
			}
			*(register_list + register_count) = register_this;
			register_count++;
		}
	}

	/*
	 * For every device left in the old cache, just unregister if
	 * it has not already been removed
	 */
	i = 0;
	hashline = NULL;
	while ((devicename = cache_walk(old_cache, &i, &hashline)) != NULL) {
		if (!(hashline->flags&REMOVED)) {
			(void) svm_unregister_device(hd, hashline);
		}
	}

	/* Register the new devices. */
	for (i = 0; i < register_count; i++) {
		deventry = *(register_list + i);
		svm_register_device(hd, deventry->devname);
	}
	if (register_list)
		free(register_list);

	/* Swap pointers */
	*cachep = new_cache;

	/* Destroy old cache */
	free_cache(&old_cache);

	/* Mark the new cache as registered */
	new_cache-> registered = 1;
}

/*
 * cache_walk()
 *
 *      Perform one step of a walk through the cache.  The i and hashline
 *      parameters are updated to store progress of the walk for future steps.
 *      They must all be initialized for the beginning of the walk
 *      (i = 0, line = NULL). Initialize variables to these values for these
 *      parameters, and then pass in the address of each of the variables
 *      along with the cache.  A NULL return value will be given to indicate
 *      when there are no more cached items to be returned.
 *
 *      Input:
 *		cache_t		*cache		cache
 *		uint32_t	*i		hash table index of prev entry
 *		deventry_t	**line		ptr to previous device entry
 *      Output:
 *		uint32_t	*i		updated hash table index
 *		deventry_t	**line		ptr to device entry
 *      Return:
 *		char*		device name (NULL for end of cache)
 *      Locking: The cache must be locked prior to calling this routine.
 */
static char *
cache_walk(cache_t *cache, uint32_t *i, deventry_t **line)
{
	uint32_t	j;

	/* sanity check */
	if (cache == NULL || i == NULL || line == NULL ||
	    *i >= cache->size)
		return (NULL);

	/* if initial values were given, look for the first entry */
	if (*i == 0 && *line == NULL) {
		for (j = 0; j < cache->size; j++) {
			if (cache->hashline[j]) {
				*i = j;
				*line = cache->hashline[j];
				return ((*line)->devname);
			}
		}
	} else {
		/* otherwise, look for the next entry for this hash value */
		if (*line && (*line)->next) {
			*line = (*line)->next;
			return ((*line)->devname);
		} else {
		/* next look further down in the hash table */
			for (j = (*i) + 1; j < cache->size; j++) {
				if (cache->hashline[j]) {
					*i = j;
					*line = cache->hashline[j];
					return ((*line)->devname);
				}
			}
		}
	}

	/*
	 * We would have returned somewhere above if there were any more
	 * entries.  So set the sentinel values and return a NULL.
	 */
	*i = cache->size;
	*line = NULL;
	return (NULL);
}

/*
 *      free_cache()
 *
 *      Given a pointer to a cache structure, this routine will free all
 *      of the memory allocated within the cache.
 *
 *      Input:
 *		cache_t		**cache		ptr to cache
 *      Return: None
 *      Locking: cache lock held on entry
 */
static void
free_cache(cache_t **cache)
{
	uint32_t	index;
	cache_t		*realcache;

	/* sanity check */
	if (cache == NULL || *cache == NULL)
		return;

	/* de-reference the cache pointer */
	realcache = *cache;

	/* free the hash table */
	for (index = 0; index < realcache->size; index++) {
		free_deventry(&realcache->hashline[index]);
	}
	free(realcache->hashline);
	realcache->hashline = NULL;

	free(realcache);
	*cache = NULL;
}

/*
 *      free_deventry()
 *
 *      This routine frees all of the memory allocated within a node of a
 *      deventry.
 *
 *      Input:
 *		deventry_t	**deventry	ptr to deventry
 *      Return: None
 *      Locking: cache lock held on entry
 */
static void
free_deventry(deventry_t **deventry)
{
	deventry_t	*olddeventry;
	hspentry_t	*hspentry;
	hspentry_t	*oldhspentry;
	hspuser_t	*hspuser;
	hspuser_t	*oldhspuser;

	if (deventry != NULL) {
		while (*deventry != NULL) {
			olddeventry = (*deventry)->next;
			if ((*deventry)->flags&IN_HSP) {
				/*
				 * If this is in a hot spare pool, remove the
				 * memory allocated to hot spare pools and
				 * the users of the pool
				 */
				hspentry = (*deventry)->hsp_list;
				while (hspentry) {
					oldhspentry = hspentry;
					hspuser = hspentry->hspuser;
					while (hspuser) {
						oldhspuser = hspuser;
						free(hspuser->hspusername);
						hspuser = hspuser->next;
						free(oldhspuser);
					}
					free(hspentry->hspname);
					hspentry = hspentry->next;
					free(oldhspentry);
				}
			}
			if ((*deventry)->devicesname)
				free((*deventry)->devicesname);
			free((*deventry)->devname);
			free (*deventry);
			*deventry = olddeventry;
		}
	}
}

/*
 *      hash()
 *
 *	A rotating hashing function that converts a string 's' to an index
 *      in a hash table of size 'h'.
 *
 *      Input:
 *		uint32_t	h		hash table size
 *		char		*s		string to be hashed
 *      Return:
 *		uint32_t	hash value
 *      Locking: None
 */
static uint32_t
hash(uint32_t h, char *s)
{

	int	len;
	int	hash, i;

	len = strlen(s);

	for (hash = len, i = 0; i < len; ++i) {
		hash = (hash<<4)^(hash>>28)^s[i];
	}
	return (hash % h);
}

/*
 *      svm_register_device()
 *
 *      Register a device
 *
 *      Input:
 *		rcm_handle_t	*hd		rcm handle
 *		char		*devname	device name
 *      Return: None
 *      Locking: None
 */
static void
svm_register_device(rcm_handle_t *hd, char *devname)
{
	/* Sanity check */
	if (devname == NULL)
		return;

	rcm_log_message(RCM_TRACE1, "SVM: Registering %s(%d)\n", devname,
		devname);

	if (rcm_register_interest(hd, devname, 0, NULL) != RCM_SUCCESS) {
		rcm_log_message(RCM_ERROR,
		    gettext("SVM: failed to register \"%s\"\n"), devname);
	}
}

/*
 *      add_dep()
 *
 *      Add an entry to an array of dependent names for a device. Used to
 *      build an array to call the rcm framework with when passing on a
 *      DR request.
 *
 *      Input:
 *		int		*ndeps		ptr to current number of deps
 *		char		***depsp	ptr to current dependent array
 *		deventry_t	*deventry	deventry of device to be added
 *      Output:
 *		int		*ndeps		ptr to updated no of deps
 *		char		***depsp	ptr to new dependant array
 *      Return:
 *		int		0, of ok, -1 if failed to allocate memory
 *      Locking: None
 */
static int
add_dep(int *ndeps, char ***depsp, deventry_t *deventry)
{
	char	**deps_new;

	*ndeps += 1;
	deps_new = realloc(*depsp, ((*ndeps) + 1) * sizeof (char  *));
	if (deps_new == NULL) {
		rcm_log_message(RCM_ERROR,
		    gettext("SVM: cannot allocate dependent array (%s).\n"),
		    strerror(errno));
		return (-1);
	}
	deps_new[(*ndeps-1)] = deventry->devname;
	deps_new[(*ndeps)] = NULL;
	*depsp = deps_new;
	return (0);
}


/*
 *      get_dependent()
 *
 *      Create a list of all dependents of a device
 *      Do not add dependent if it is marked as removed
 *
 *      Input:
 *		deventry_t	*deventry	device entry
 *      Output:
 *		char		***dependentsp	pty to dependent list
 *      Return:
 *		int		0, if ok, -1 if failed
 *      Locking: None
 */
static int
get_dependents(deventry_t *deventry, char *** dependentsp)
{
	int		ndeps = 0;
	deventry_t	*dependent;
	char		**deps = NULL;


	dependent = deventry->dependent;
	if (dependent == NULL) {
		*dependentsp = NULL;
		return (0);
	}
	while (dependent != NULL) {
		/*
		 * do not add dependent if we have
		 * already received a remove notifification
		 */
		if (!(dependent->flags&REMOVED))
			if (add_dep(&ndeps, &deps, dependent) < 0)
				return (-1);
		dependent = dependent->next_dep;
	}
	if (ndeps == 0) {
		*dependentsp = NULL;
	} else {
		*dependentsp = deps;
	}
	return (0);
}

/*
 *      add_to_usage()
 *      Add string to the usage string pointed at by usagep. Allocate memory
 *      for the new usage string and free the memory used by the original
 *      usage string
 *
 *      Input:
 *		char	**usagep	ptr to usage string
 *		char	*string		string to be added to usage
 *      Return:
 *		char	ptr to new usage string
 *      Locking: None
 */
char *
add_to_usage(char ** usagep, char *string)
{
	int	len;
	char	*new_usage = NULL;

	if (*usagep == NULL) {
		len = 0;
	} else {
		len = strlen(*usagep) + 2; /* allow space for comma */
	}
	len += strlen(string) + 1;
	if (new_usage = calloc(1, len)) {
		if (*usagep) {
			(void) strcpy(new_usage, *usagep);
			free(*usagep);
			(void) strcat(new_usage, ", ");
		}
		(void) strcat(new_usage, string);
	}
	return (new_usage);
}

/*
 *      add_to_usage_fmt()
 *
 *      Add a formatted string , of the form "blah %s" to the usage string
 *      pointed at by usagep. Allocate memory for the new usage string and free
 *      the memory used by the original usage string.
 *
 *      Input:
 *		char		**usagep	ptr to current usage string
 *		char		*fmt		format string
 *		char		*string		string to be added
 *      Return:
 *		char*		new usage string
 *      Locking: None
 */
/*PRINTFLIKE2*/
char *
add_to_usage_fmt(char **usagep, char *fmt, char *string)
{
	int	len;
	char	*usage;
	char	*new_usage = NULL;

	len = strlen(fmt)
	    + strlen(string) + 1;
	if (usage = calloc(1, len)) {
		(void) sprintf(usage, fmt, string);
		new_usage = add_to_usage(usagep, usage);
		free(usage);
	}
	return (new_usage);
}

/*
 *      is_open()
 *
 *      Make ioctl call to find if a device is open
 *
 *      Input:
 *		dev_t 		devkey	dev_t for device
 *      Return:
 *		int		0 if not open,  !=0 if open
 *      Locking: None
 */
static int
is_open(dev_t devkey)
{
	int		fd;
	md_isopen_t	isopen_ioc;

	/* Open admin device */
	if ((fd = open(ADMSPECIAL, O_RDONLY, 0)) < 0) {
		rcm_log_message(RCM_ERROR, MSG_OPENERR, ADMSPECIAL);
		return (0);
	}

	(void) memset(&isopen_ioc, 0, sizeof (isopen_ioc));
	isopen_ioc.dev = devkey;
	if (ioctl(fd, MD_IOCISOPEN, &isopen_ioc) < 0) {
		(void) close(fd);
		return (0);
	}
	(void) close(fd);
	return (isopen_ioc.isopen);
}

/*
 *	check_softpart()
 *
 *	Check the status of the passed in device within the softpartition.
 *
 *	Input:
 *		mdsetname_t *	the name of the set
 *		mdname_t *	the softpartition device that is being examined
 *		char *		the device which needs to be checked
 *		md_error_t *	error pointer (not used)
 *	Return:
 *		int		REDUNDANT    - device is redundant and can be
 *					       removed
 *				NOTREDUNDANT - device cannot be removed
 *				NOTINDEVICE  - device is not part of this
 *					       component
 */
static int
check_softpart(mdsetname_t *sp, mdname_t *np, char *uname, md_error_t *ep)
{
	md_sp_t	*softp = NULL;

	rcm_log_message(RCM_TRACE1, "SVM: softpart checking %s %s\n",
	    np->bname, uname);

	softp = meta_get_sp(sp, np, ep);

	/* softp cannot be NULL, if it is then the RCM cache is corrupt */
	assert(softp != NULL);

	/*
	 * if the softpartition is not a parent then nothing can be done, user
	 * must close the device and then fix the under lying devices.
	 */
	if (!(MD_HAS_PARENT(softp->common.parent))) {
		rcm_log_message(RCM_TRACE1,
		    "SVM: softpart is a top level device\n");
		return (NOTREDUNDANT);
	}

	if (strcmp(softp->compnamep->bname, uname) != 0) {
		/*
		 * This can occur if this function has been called by the
		 * check_raid5 code as it is cycling through each column
		 * in turn.
		 */
		rcm_log_message(RCM_TRACE1,
		    "SVM: %s is not in softpart (%s)\n",
		    uname, softp->compnamep->bname);
		return (NOTINDEVICE);
	}

	/*
	 * Check the status of the soft partition this only moves from
	 * an okay state if the underlying devices fails while the soft
	 * partition is open.
	 */
	if (softp->status != MD_SP_OK) {
		rcm_log_message(RCM_TRACE1,
		    "SVM: softpart is broken (state: 0x%x)\n",
		    softp->status);
		return (REDUNDANT);
	}

	return (NOTREDUNDANT);
}

/*
 *	check_raid5()
 *
 *	Check the status of the passed in device within the raid5 in question.
 *
 *	Input:
 *		mdsetname_t *	the name of the set
 *		mdname_t *	the raid5 device that is being examined
 *		char *		the device which needs to be checked
 *		md_error_t *	error pointer (not used)
 *	Return:
 *		int		REDUNDANT    - device is redundant and can be
 *					       removed
 *				NOTREDUNDANT - device cannot be removed
 */
static int
check_raid5(mdsetname_t *sp, mdname_t *np, char *uname, md_error_t *ep)
{
	md_raid_t	*raidp = NULL;
	md_raidcol_t	*colp = NULL;
	int		i;
	int		rval = 0;

	rcm_log_message(RCM_TRACE1, "SVM: raid5 checking %s %s\n",
	    np->bname, uname);

	raidp = meta_get_raid(sp, np, ep);

	/* raidp cannot be NULL, if it is then the RCM cache is corrupt */
	assert(raidp != NULL);

	/*
	 * Now check each column in the device. We cannot rely upon the state
	 * of the device because if a hotspare is in use all the states are
	 * set to Okay, both at the metadevice layer and the column layer.
	 */
	for (i = 0; (i < raidp->cols.cols_len); i++) {
		colp = &raidp->cols.cols_val[i];
		np = colp->colnamep;

		rcm_log_message(RCM_TRACE1,
		    "SVM: raid5 checking %s state %s 0x%x\n",
		    np->bname, raid_col_state_to_name(colp, NULL, 0),
		    colp->state);

		/*
		 * It is possible for the column to be a softpartition,
		 * so need to check the softpartiton if this is the
		 * case. It is *not* valid for the column to be a
		 * stripe/concat/mirror, and so no check to see what
		 * type of metadevice is being used.
		 */
		if (metaismeta(np)) {
			/* this is a metadevice ie a softpartiton */
			rval = check_softpart(sp, np, uname, ep);
			if (rval == REDUNDANT) {
				rcm_log_message(RCM_TRACE1,
				    "SVM: raid5 %s is broken\n", uname);
				meta_invalidate_name(np);
				return (REDUNDANT);
			} else if (rval == NOTREDUNDANT &&
			    colp->hsnamep != NULL) {
				rcm_log_message(RCM_TRACE1,
				    "SVM: raid5 device is broken, hotspared\n");
				meta_invalidate_name(np);
				return (REDUNDANT);
			}
			meta_invalidate_name(np);
			continue;
		}
		meta_invalidate_name(np);

		if (strcmp(uname, np->bname) != 0)
			continue;

		/*
		 * Found the device. Check if it is broken or hotspared.
		 */
		if (colp->state & RUS_ERRED) {
			rcm_log_message(RCM_TRACE1,
			    "SVM: raid5 column device is broken\n");
			return (REDUNDANT);
		}

		if (colp->hsnamep != NULL) {
			rcm_log_message(RCM_TRACE1,
			    "SVM: raid5 column device is broken, hotspared\n");
			return (REDUNDANT);
		}
	}
	return (NOTREDUNDANT);
}

/*
 *	check_stripe()
 *
 *	Check the status of the passed in device within the stripe in question.
 *
 *	Input:
 *		mdsetname_t *	the name of the set
 *		mdname_t *	the stripe that is being examined
 *		char *		the device which needs to be checked
 *		md_error_t *	error pointer (not used)
 *	Return:
 *		int		REDUNDANT    - device is redundant and can be
 *					       removed
 *				NOTREDUNDANT - device cannot be removed
 *				NOTINDEVICE  - device is not part of this
 *					       component
 */
static int
check_stripe(mdsetname_t *sp, mdname_t *np, char *uname, md_error_t *ep)
{
	md_stripe_t	*stripep = NULL;
	md_row_t	*mrp = NULL;
	md_comp_t	*mcp;
	mdname_t	*pnp;
	char		*miscname;
	int		row;
	int		col;

	rcm_log_message(RCM_TRACE1, "SVM: concat/stripe checking %s %s\n",
	    np->bname, uname);
	stripep = meta_get_stripe(sp, np, ep);

	/* stripep cannot be NULL, if it is then the RCM cache is corrupt */
	assert(stripep != NULL);

	/*
	 * If the stripe is not a parent then nothing can be done, user
	 * must close the device and then fix the devices.
	 */
	if (!(MD_HAS_PARENT(stripep->common.parent))) {
		rcm_log_message(RCM_TRACE1,
		    "SVM: stripe is a top level device\n");
		return (NOTREDUNDANT);
	}

	pnp = metamnumname(&sp, stripep->common.parent, 0, ep);

	if (pnp == NULL) {
		/*
		 * Only NULL when the replicas are in an inconsistant state
		 * ie the device says it is the parent of X but X does not
		 * exist.
		 */
		rcm_log_message(RCM_TRACE1, "SVM: parent is not configured\n");
		return (NOTREDUNDANT);
	}

	/*
	 * Get the type of the parent and make sure that it is a mirror,
	 * if it is then need to find out the number of submirrors, and
	 * if it is not a mirror then this is not a REDUNDANT device.
	 */
	if ((miscname = metagetmiscname(pnp, ep)) == NULL) {
		/*
		 * Again something is wrong with the configuration.
		 */
		rcm_log_message(RCM_TRACE1,
		    "SVM: unable to find the type of %s\n", pnp->cname);
		meta_invalidate_name(pnp);
		return (NOTREDUNDANT);
	}

	if (!(strcmp(miscname, MD_MIRROR) == 0 &&
	    check_mirror(sp, pnp, ep) == REDUNDANT)) {
		rcm_log_message(RCM_TRACE1,
		    "SVM: %s is a %s and not redundant\n",
		    pnp->cname, miscname);
		meta_invalidate_name(pnp);
		return (NOTREDUNDANT);
	}

	meta_invalidate_name(pnp);

	for (row = 0; row < stripep->rows.rows_len; row++) {
		mrp = &stripep->rows.rows_val[row];

		/* now the components in the row */
		for (col = 0; col < mrp->comps.comps_len; col++) {
			mcp = &mrp->comps.comps_val[col];

			rcm_log_message(RCM_TRACE1,
			    "SVM: stripe comp %s check\n",
			    mcp->compnamep->bname);

			if (strcmp(mcp->compnamep->bname, uname) != 0)
				continue;

			rcm_log_message(RCM_TRACE1,
			    "SVM: component state: %s\n",
			    comp_state_to_name(mcp, NULL, 0));

			if (mcp->hsnamep != NULL) {
				/* device is broken and hotspared */
				rcm_log_message(RCM_TRACE1,
				    "SVM: stripe %s broken, hotspare active\n",
				    uname);
				return (REDUNDANT);
			}

			/*
			 * LAST_ERRED is a special case.  If the state of a
			 * component is CS_LAST_ERRED then this is the last
			 * copy of the data and we need to keep using it, even
			 * though we had errors.  Thus, we must block the DR
			 * request.  If you follow the documented procedure for
			 * fixing each component (fix devs in maintenance
			 * before last erred) then the mirror will
			 * automatically transition Last Erred components to
			 * the Erred state after which they can be DRed out.
			 */
			if (mcp->state == CS_ERRED) {
				/* device is broken */
				rcm_log_message(RCM_TRACE1,
				    "SVM: stripe %s is broken\n", uname);
				return (REDUNDANT);
			}

			/*
			 * Short circuit - if here the component has been
			 * found in the column so no further processing is
			 * required here.
			 */
			return (NOTREDUNDANT);
		}
	}

	/*
	 * Only get to this point if the device (uname) has not been
	 * found in the stripe. This means that there is something
	 * wrong with the device dependency list.
	 */
	rcm_log_message(RCM_TRACE1,
	    "SVM: component %s is not part of %s\n",
	    uname, np->bname);

	return (NOTINDEVICE);
}

/*
 *	check_mirror()
 *
 *	Make sure that the mirror > 1 submirror.
 *
 *	Input:
 *		mdsetname_t *	the name of the set
 *		mdname_t *	the stripe that is being examined
 *	Return:
 *		int		REDUNDANT    - mirror > 1 submirrors
 *				NOTREDUNDANT - mirror has 1 submirror
 */
static int
check_mirror(mdsetname_t *sp, mdname_t *np, md_error_t *ep)
{
	uint_t		nsm = 0;	/* number of submirrors */
	uint_t		smi = 0;	/* index into submirror array */
	md_mirror_t	*mirrorp = NULL;

	rcm_log_message(RCM_TRACE1, "SVM: mirror checking %s\n", np->bname);
	mirrorp = meta_get_mirror(sp, np, ep);

	/* mirrorp cannot be NULL, if it is then the RCM cache is corrupt */
	assert(mirrorp != NULL);

	/*
	 * Need to check how many submirrors that the mirror has.
	 */
	for (smi = 0, nsm = 0; (smi < NMIRROR); ++smi) {
		md_submirror_t	*mdsp = &mirrorp->submirrors[smi];
		mdname_t	*submirnamep = mdsp->submirnamep;

		/* Is this submirror being used ?  No, then continue */
		if (submirnamep == NULL)
			continue;
		nsm++;
	}

	/*
	 * If there is only one submirror then there is no redundancy
	 * in the configuration and the user needs to take some other
	 * action before using cfgadm on the device ie close the metadevice.
	 */
	if (nsm == 1) {
		rcm_log_message(RCM_TRACE1,
		    "SVM: only one submirror unable to allow action\n");
		return (NOTREDUNDANT);
	}

	return (REDUNDANT);
}

/*
 *	check_device()
 *
 *	Check the current status of the underlying device.
 *
 *	Input:
 *		deventry_t *	the device that is being checked
 *	Return:
 *		int		REDUNDANT    - device is redundant and can be
 *					       removed
 *				NOTREDUNDANT - device cannot be removed
 *	Locking:
 *		None
 *
 * The check_device code path (the functions called by check_device) use
 * libmeta calls directly to determine if the specified device is
 * redundant or not.  The can lead to conflicts between data cached in
 * libmeta and data that is being cached by this rcm module.  Since the
 * rcm cache is our primary source of information here, we need to make
 * sure that we are not getting stale data from the libmeta caches.
 * We use meta_invalidate_name throughout this code path to clear the
 * cached data in libmeta in order to ensure that we are not using stale data.
 */
static int
check_device(deventry_t *deventry)
{
	mdsetname_t	*sp;
	md_error_t	error = mdnullerror;
	char		sname[BUFSIZ+1];
	mdname_t	*np;
	deventry_t	*dependent;
	int		rval = NOTREDUNDANT;
	int		ret;

	dependent = deventry->dependent;

	rcm_log_message(RCM_TRACE1, "SVM: check_device(%s)\n",
	    deventry->devname);
	/*
	 * should not be null because the caller has already figured out
	 * there are dependent devices.
	 */
	assert(dependent != NULL);

	do {

		rcm_log_message(RCM_TRACE1, "SVM: check dependent: %s\n",
		    dependent->devname);

		if (dependent->flags & REMOVED) {
			dependent = dependent->next_dep;
			continue;
		}

		/*
		 * The device *should* be a metadevice and so need to see if
		 * it contains a setname.
		 */
		ret = sscanf(dependent->devname,
		    "/dev/md/%" VAL2STR(BUFSIZ) "[^/]/dsk/",
		    sname);

		if (ret != 1)
			(void) strcpy(sname, MD_LOCAL_NAME);

		if ((sp = metasetname(sname, &error)) == NULL) {
			rcm_log_message(RCM_TRACE1,
			    "SVM: unable to get setname for \"%s\", error %s\n",
			    sname, mde_sperror(&error, ""));
			break;
		}

		rcm_log_message(RCM_TRACE1, "SVM: processing: %s\n",
		    dependent->devname);

		np = metaname(&sp, dependent->devname, META_DEVICE, &error);

		switch (dependent->devtype) {
		case SVM_TRANS:
			/*
			 * No code to check trans devices because ufs logging
			 * should be being used.
			 */
			rcm_log_message(RCM_TRACE1,
			    "SVM: Use UFS logging instead of trans devices\n");
			break;
		case SVM_SLICE:
		case SVM_STRIPE:
		case SVM_CONCAT:
			rval = check_stripe(sp, np, deventry->devname, &error);
			break;
		case SVM_MIRROR:
			/*
			 * No check here as this is performed by the one
			 * above when the submirror is checked.
			 */
			rcm_log_message(RCM_TRACE1,
			    "SVM: Mirror check is done by the stripe check\n");
			break;
		case SVM_RAID:
			/*
			 * Raid5 devices can be built on soft partitions or
			 * slices and so the check here is for the raid5
			 * device built on top of slices. Note, a raid5 cannot
			 * be built on a stripe/concat.
			 */
			rval = check_raid5(sp, np, deventry->devname, &error);
			break;
		case SVM_SOFTPART:
			/*
			 * Raid5 devices can be built on top of soft partitions
			 * and so they have to be checked.
			 */
			rval = check_softpart(sp, np, deventry->devname,
			    &error);
			break;
		default:
			rcm_log_message(RCM_TRACE1,
			    "SVM: unknown devtype: %d\n", dependent->devtype);
			break;
		}

		meta_invalidate_name(np);

		if (rval == REDUNDANT)
			break;
	} while ((dependent = dependent->next_dep) != NULL);

	rcm_log_message(RCM_TRACE1, "SVM: check_device return %d\n", rval);
	return (rval);
}

/*
 *	svm_unregister_device
 *
 *	Unregister the device specified by the deventry
 *
 *	Input:
 *		rcm_handle_t *	information for RCM
 *		deventry_t *	description of the device to be
 *				unregistered
 *
 *	Return:
 *		int		0	- successfully unregistered
 *				!= 0	- failed to unregister
 *
 *	Locking:
 *		None
 *
 * If the deventry_t has a devicesname, we will first attempt to unregister
 * using that name.  If that fails then we'll attempt to unregister using
 * devname.  The reason for this strategy has to do with the way that
 * rcm_register_interest works.  If passed a /dev/ name,
 * rcm_register_interest uses realpath() to convert it to a /devices name.
 * Thus, we are more likely to succeed if we use devicesname first.
 */

static int
svm_unregister_device(rcm_handle_t *hd, deventry_t *d)
{
	int	deleted;

	if (d->devicesname) {
		rcm_log_message(RCM_TRACE1, "SVM: unregister_device %s (%s)\n",
			d->devname, d->devicesname);
	} else {
		rcm_log_message(RCM_TRACE1, "SVM: unregister_device %s\n",
			d->devname);
	}
	deleted = -1;
	if (d->devicesname != NULL) {
		/*
		 * Try to unregister via the /devices entry first.  RCM
		 * converts /dev/ entries to /devices entries before
		 * storing them.  Thus, if this item has a /devices name
		 * available, we should use it for unregistering.
		 */
		deleted = rcm_unregister_interest(hd,
			d->devicesname, 0);
	}
	if (deleted != 0) {
		/*
		 * Either we did not have a /devices name or the attempt to
		 * unregister using the /devices name failed.  Either way
		 * we'll now try to unregister using the conventional name.
		 */
		deleted = rcm_unregister_interest(hd, d->devname, 0);
	}
	if (deleted != 0) {
		rcm_log_message(RCM_TRACE1, "SVM: unregister_device failed "
			"for %s\n", d->devname);
	}
	return (deleted);
}
