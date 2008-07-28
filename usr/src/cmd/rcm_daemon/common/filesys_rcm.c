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
 * This module adds support to the RCM framework for mounted filesystems.
 *
 * The module provides this functionality:
 * 	1) reports device usage for mounted filesystems
 *	2) prevents offline operations for mounted resources
 *	3) prevents suspend operations (unless forced) of those filesystems
 *	   deemed critical for the continued operation of the OS
 *	4) propagates RCM operations from mounted resources to the consumers
 *	   of files within the mounted filesystems
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <synch.h>
#include <libintl.h>
#include <errno.h>
#include <sys/mnttab.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/utssys.h>
#include <unistd.h>
#include <limits.h>

#include "rcm_module.h"

/* Definitions */

#define	HASH_DEFAULT		4
#define	HASH_THRESHOLD		256

#define	OPT_IGNORE		"ignore"

#define	MSG_HDR_STD		gettext("mounted filesystem")
#define	MSG_HDR_STD_MULTI	gettext("mounted filesystems")
#define	MSG_HDR_CRIT		gettext("cannot suspend filesystem")
#define	MSG_HDR_CRIT_MULTI	gettext("cannot suspend filesystems")
#define	MSG_SEPARATOR		gettext(", ")
#define	MSG_FAIL_USAGE		gettext("failed to construct usage string.")
#define	MSG_FAIL_DEPENDENTS	gettext("failed while calling dependents.")
#define	MSG_FAIL_REMOVE		gettext("filesystems cannot be removed.")
#define	MSG_FAIL_INTERNAL	gettext("internal processing failure.")

typedef struct hashentry {
	int n_mounts;
	char *special;
	char *fstype;
	char **mountps;
	struct hashentry *next;
} hashentry_t;

typedef struct {
	time_t timestamp;
	uint32_t hash_size;
	hashentry_t **mounts;
} cache_t;

/* Forward Declarations */

/* module interface routines */
static int mnt_register(rcm_handle_t *);
static int mnt_unregister(rcm_handle_t *);
static int mnt_getinfo(rcm_handle_t *, char *, id_t, uint_t, char **, char **,
    nvlist_t *, rcm_info_t **);
static int mnt_suspend(rcm_handle_t *, char *, id_t, timespec_t *,
    uint_t, char **, rcm_info_t **);
static int mnt_resume(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int mnt_offline(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int mnt_online(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int mnt_remove(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);

/* cache functions */
static cache_t *cache_create();
static int cache_insert(cache_t *, struct mnttab *);
static int cache_sync(rcm_handle_t *, cache_t **);
static hashentry_t *cache_lookup(cache_t *, char *);
static void free_cache(cache_t **);
static void free_entry(hashentry_t **);
static void free_list(char **);

/* miscellaneous functions */
static uint32_t hash(uint32_t, char *);
static void register_rsrc(rcm_handle_t *, char *);
static void unregister_rsrc(rcm_handle_t *, char *);
static char *create_message(char *, char *, char **);
static int detect_critical_failure(char **, uint_t, char **);
static int is_critical(char *);
static int use_cache(char *, char **, char ***);
static void prune_dependents(char **, char *);
static char **create_dependents(hashentry_t *);

/* Module-Private data */

static struct rcm_mod_ops mnt_ops =
{
	RCM_MOD_OPS_VERSION,
	mnt_register,
	mnt_unregister,
	mnt_getinfo,
	mnt_suspend,
	mnt_resume,
	mnt_offline,
	mnt_online,
	mnt_remove
};

static cache_t *mnt_cache;
static mutex_t cache_lock;

/* Module Interface Routines */

/*
 * rcm_mod_init()
 *
 *	Called when module is loaded.  Returns the ops vector.
 */
struct rcm_mod_ops *
rcm_mod_init()
{
	return (&mnt_ops);
}

/*
 * rcm_mod_info()
 *
 *	Returns a string identifying this module.
 */
const char *
rcm_mod_info()
{
	return ("File system module 1.9");
}

/*
 * rcm_mod_fini()
 *
 *	Called when module is unloaded.  Frees up all used memory.
 *
 *	Locking: the cache is locked for the duration of this function.
 */
int
rcm_mod_fini()
{
	(void) mutex_lock(&cache_lock);
	free_cache(&mnt_cache);
	(void) mutex_unlock(&cache_lock);

	return (RCM_SUCCESS);
}

/*
 * mnt_register()
 *
 *	Called to synchronize the module's registrations.  Results in the
 *	construction of a new cache, destruction of any old cache data,
 *	and a full synchronization of the module's registrations.
 *
 *	Locking: the cache is locked for the duration of this function.
 */
int
mnt_register(rcm_handle_t *hd)
{
	assert(hd != NULL);

	rcm_log_message(RCM_TRACE1, "FILESYS: register()\n");

	(void) mutex_lock(&cache_lock);

	/* cache_sync() does all of the necessary work */
	if (cache_sync(hd, &mnt_cache) < 0) {
		rcm_log_message(RCM_ERROR,
		    "FILESYS: failed to synchronize cache (%s).\n",
		    strerror(errno));
		(void) mutex_unlock(&cache_lock);
		return (RCM_FAILURE);
	}

	(void) mutex_unlock(&cache_lock);

	return (RCM_SUCCESS);
}

/*
 * mnt_unregister()
 *
 *	Manually walk through the cache, unregistering all the special
 *	files and mount points.
 *
 *	Locking: the cache is locked throughout the execution of this
 *	routine because it reads and modifies cache links continuously.
 */
int
mnt_unregister(rcm_handle_t *hd)
{
	uint32_t index;
	hashentry_t *entry;

	assert(hd != NULL);

	rcm_log_message(RCM_TRACE1, "FILESYS: unregister()\n");

	(void) mutex_lock(&cache_lock);

	/* Unregister everything in the cache */
	if (mnt_cache) {
		for (index = 0; index < mnt_cache->hash_size; index++) {
			for (entry = mnt_cache->mounts[index]; entry != NULL;
			    entry = entry->next) {
				unregister_rsrc(hd, entry->special);
			}
		}
	}

	/* Destroy the cache */
	free_cache(&mnt_cache);

	(void) mutex_unlock(&cache_lock);

	return (RCM_SUCCESS);
}

/*
 * mnt_offline()
 *
 *	Filesystem resources cannot be offlined. They can however be retired
 *	if they don't provide a critical service. The offline entry point
 *	checks if this is a retire operation and if it is and the filesystem
 *	doesn't provide a critical service, the entry point returns success
 *	For all other cases, failure is returned.
 *	Since no real action is taken, QUERY or not doesn't matter.
 */
int
mnt_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **dependent_info)
{
	char **dependents;
	hashentry_t *entry;
	int retval;
	int i;

	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(errorp != NULL);

	*errorp = NULL;

	rcm_log_message(RCM_TRACE1, "FILESYS: offline(%s)\n", rsrc);

	/* Retrieve necessary info from the cache */
	if (use_cache(rsrc, errorp, &dependents) < 0) {
		if (flags & RCM_RETIRE_REQUEST)
			return (RCM_NO_CONSTRAINT);
		else
			return (RCM_FAILURE);
	}

	if (flags & RCM_RETIRE_REQUEST) {
		(void) mutex_lock(&cache_lock);
		if ((entry = cache_lookup(mnt_cache, rsrc)) == NULL) {
			rcm_log_message(RCM_ERROR, "FILESYS: "
			    "failed to look up \"%s\" in cache (%s).\n",
			    rsrc, strerror(errno));
			(void) mutex_unlock(&cache_lock);
			retval = RCM_NO_CONSTRAINT;
			goto out;
		}

		if (strcmp(entry->fstype, "zfs") == 0) {
			retval = RCM_NO_CONSTRAINT;
			rcm_log_message(RCM_TRACE1,
			    "FILESYS: zfs: NO_CONSTRAINT: %s\n", rsrc);
		} else {
			retval = RCM_SUCCESS;
			for (i = 0; dependents[i] != NULL; i++) {
				if (is_critical(dependents[i])) {
					retval = RCM_FAILURE;
					rcm_log_message(RCM_TRACE1, "FILESYS: "
					    "CRITICAL %s\n", rsrc);
					break;
				}
			}
		}
		(void) mutex_unlock(&cache_lock);
		goto out;
	}

	retval = RCM_FAILURE;

	/* Convert the gathered dependents into an error message */
	*errorp = create_message(MSG_HDR_STD, MSG_HDR_STD_MULTI, dependents);
	if (*errorp == NULL) {
		rcm_log_message(RCM_ERROR,
		    "FILESYS: failed to construct offline message (%s).\n",
		    strerror(errno));
	}

out:
	free_list(dependents);
	return (retval);
}

/*
 * mnt_online()
 *
 *	Filesystem resources aren't offlined, so there's really nothing to do
 *	here.
 */
int
mnt_online(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flag, char **errorp,
    rcm_info_t **dependent_reason)
{
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(errorp != NULL);

	rcm_log_message(RCM_TRACE1, "FILESYS: online(%s)\n", rsrc);

	return (RCM_SUCCESS);
}

/*
 * mnt_getinfo()
 *
 *	Report how a given resource is in use by this module.  And also
 *	possibly include dependent consumers of the mounted filesystems.
 */
int
mnt_getinfo(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flag, char **usagep,
    char **errorp, nvlist_t *props, rcm_info_t **depend_info)
{
	int rv = RCM_SUCCESS;
	char **dependents;

	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(usagep != NULL);
	assert(errorp != NULL);
	assert(props != NULL);

	rcm_log_message(RCM_TRACE1, "FILESYS: getinfo(%s)\n", rsrc);

	/* Retrieve necessary info from the cache */
	if (use_cache(rsrc, errorp, &dependents) < 0)
		return (RCM_FAILURE);

	/* Convert the gathered dependents into a usage message */
	*usagep = create_message(MSG_HDR_STD, MSG_HDR_STD_MULTI, dependents);
	if (*usagep == NULL) {
		rcm_log_message(RCM_ERROR,
		    "FILESYS: failed to construct usage message (%s).\n",
		    strerror(errno));
		*errorp = strdup(MSG_FAIL_USAGE);
		free_list(dependents);
		return (RCM_FAILURE);
	}

	/* Recurse on dependents if necessary */
	if ((flag & RCM_INCLUDE_DEPENDENT) && (dependents != NULL)) {
		prune_dependents(dependents, rsrc);
		if (dependents[0] != NULL) {
			if ((rv = rcm_get_info_list(hd, dependents, flag,
			    depend_info)) != RCM_SUCCESS) {
				*errorp = strdup(MSG_FAIL_DEPENDENTS);
			}
		}
	}

	/* Free up info retrieved from the cache */
	free_list(dependents);

	return (rv);
}

/*
 * mnt_suspend()
 *
 *	Notify all dependents that the resource is being suspended.
 *	Since no real action is taken, QUERY or not doesn't matter.
 */
int
mnt_suspend(rcm_handle_t *hd, char *rsrc, id_t id, timespec_t *interval,
    uint_t flag, char **errorp, rcm_info_t **depend_info)
{
	int rv = RCM_SUCCESS;
	char **dependents;

	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(interval != NULL);
	assert(errorp != NULL);

	rcm_log_message(RCM_TRACE1, "FILESYS: suspend(%s)\n", rsrc);

	/* Retrieve necessary info from the cache */
	if (use_cache(rsrc, errorp, &dependents) < 0)
		return (RCM_FAILURE);

	/* Unforced suspensions fail if any of the dependents are critical */
	if (detect_critical_failure(errorp, flag, dependents)) {
		free_list(dependents);
		return (RCM_FAILURE);
	}

	/* Recurse on dependents if necessary */
	if ((flag & RCM_INCLUDE_DEPENDENT) && (dependents != NULL)) {
		prune_dependents(dependents, rsrc);
		if (dependents[0] != NULL)
			if ((rv = rcm_request_suspend_list(hd, dependents, flag,
			    interval, depend_info)) != RCM_SUCCESS) {
				*errorp = strdup(MSG_FAIL_DEPENDENTS);
			}
	}
	free_list(dependents);

	return (rv);
}

/*
 * mnt_resume()
 *
 *	Resume all the dependents of a suspended filesystem.
 */
int
mnt_resume(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flag, char **errorp,
    rcm_info_t **depend_info)
{
	int rv = RCM_SUCCESS;
	char **dependents;

	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(errorp != NULL);

	rcm_log_message(RCM_TRACE1, "FILESYS: resume(%s)\n", rsrc);

	/* Retrieve necessary info from the cache */
	if (use_cache(rsrc, errorp, &dependents) < 0)
		return (RCM_FAILURE);

	/* Recurse on dependents if necessary */
	if ((flag & RCM_INCLUDE_DEPENDENT) && (dependents != NULL)) {
		prune_dependents(dependents, rsrc);
		if (dependents[0] != NULL) {
			if ((rv = rcm_notify_resume_list(hd, dependents, flag,
			    depend_info)) != RCM_SUCCESS) {
				*errorp = strdup(MSG_FAIL_DEPENDENTS);
			}
		}
	}
	free_list(dependents);

	return (rv);
}

static int
get_spec(char *line, char *spec, size_t ssz)
{
	char	*cp;
	char	*start;

	if (strlcpy(spec, line, ssz) >= ssz) {
		rcm_log_message(RCM_ERROR, "FILESYS: get_spec() failed: "
		    "line: %s\n", line);
		return (-1);
	}

	cp = spec;
	while (*cp == ' ' || *cp == '\t')
		cp++;

	if (*cp == '#')
		return (-1);

	start = cp;

	while (*cp != ' ' && *cp != '\t' && *cp != '\0')
		cp++;
	*cp = '\0';

	(void) memmove(spec, start, strlen(start) + 1);

	return (0);
}

static int
path_match(char *rsrc, char *spec)
{
	char r[PATH_MAX];
	char s[PATH_MAX];
	size_t len;

	if (realpath(rsrc, r) == NULL)
		goto error;

	if (realpath(spec, s) == NULL)
		goto error;

	len = strlen("/devices/");

	if (strncmp(r, "/devices/", len) != 0) {
		errno = ENXIO;
		goto error;
	}

	if (strncmp(s, "/devices/", len) != 0) {
		errno = ENXIO;
		goto error;
	}

	len = strlen(r);
	if (strncmp(r, s, len) == 0 && (s[len] == '\0' || s[len] == ':'))
		return (0);
	else
		return (1);

error:
	rcm_log_message(RCM_DEBUG, "FILESYS: path_match() failed "
	    "rsrc=%s spec=%s: %s\n", rsrc, spec, strerror(errno));
	return (-1);
}

#define	VFSTAB		"/etc/vfstab"
#define	RETIRED_PREFIX	"## RETIRED ##"

static int
disable_vfstab_entry(char *rsrc)
{
	FILE	*vfp;
	FILE	*tfp;
	int	retval;
	int	update;
	char	tmp[PATH_MAX];
	char	line[MNT_LINE_MAX + 1];

	vfp = fopen(VFSTAB, "r");
	if (vfp == NULL) {
		rcm_log_message(RCM_ERROR, "FILESYS: failed to open /etc/vfstab"
		    " for reading: %s\n", strerror(errno));
		return (RCM_FAILURE);
	}

	(void) snprintf(tmp, sizeof (tmp), "/etc/vfstab.retire.%lu", getpid());

	tfp = fopen(tmp, "w");
	if (tfp == NULL) {
		rcm_log_message(RCM_ERROR, "FILESYS: failed to open "
		    "/etc/vfstab.retire for writing: %s\n", strerror(errno));
		(void) fclose(vfp);
		return (RCM_FAILURE);
	}

	retval = RCM_SUCCESS;
	update = 0;
	while (fgets(line, sizeof (line), vfp)) {

		char	spec[MNT_LINE_MAX + 1];
		char	newline[MNT_LINE_MAX + 1];
		char	*l;

		if (get_spec(line, spec, sizeof (spec)) == -1) {
			l = line;
			goto foot;
		}

		if (path_match(rsrc, spec) != 0) {
			l = line;
			goto foot;
		}

		update = 1;

		/* Paths match. Disable this entry */
		(void) snprintf(newline, sizeof (newline), "%s %s",
		    RETIRED_PREFIX, line);

		rcm_log_message(RCM_TRACE1, "FILESYS: disabling line\n\t%s\n",
		    line);

		l = newline;
foot:
		if (fputs(l, tfp) == EOF) {
			rcm_log_message(RCM_ERROR, "FILESYS: failed to write "
			    "new vfstab: %s\n", strerror(errno));
			update = 0;
			retval = RCM_FAILURE;
			break;
		}
	}

	if (vfp)
		(void) fclose(vfp);
	if (tfp)
		(void) fclose(tfp);

	if (update) {
		if (rename(tmp, VFSTAB) != 0) {
			rcm_log_message(RCM_ERROR, "FILESYS: vfstab rename "
			    "failed: %s\n", strerror(errno));
			retval = RCM_FAILURE;
		}
	}

	(void) unlink(tmp);

	return (retval);
}

/*
 * mnt_remove()
 *
 *	Remove will only be called in the retire case i.e. if RCM_RETIRE_NOTIFY
 *	flag is set.
 *
 *	If the flag is not set, then return failure and log the mistake if a
 *	remove is ever received for a mounted filesystem resource.
 */
int
mnt_remove(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flag, char **errorp,
    rcm_info_t **depend_info)
{
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(errorp != NULL);

	rcm_log_message(RCM_TRACE1, "FILESYS: remove(%s)\n", rsrc);

	if (!(flag & RCM_RETIRE_NOTIFY)) {
		/* Log the mistake */
		rcm_log_message(RCM_ERROR, "FILESYS: invalid remove of "
		    "\"%s\"\n", rsrc);
		*errorp = strdup(MSG_FAIL_REMOVE);
		return (RCM_FAILURE);
	}

	return (disable_vfstab_entry(rsrc));
}

/*
 * Cache management routines
 */

/*
 * cache_create()
 *
 *	This routine constructs a new cache of the current mnttab file.
 *
 *	Locking: the cache must be locked prior to calling this function.
 *
 *	Return Values: NULL with errno set on failure, new cache point on
 *	success.
 */
static cache_t *
cache_create()
{
	FILE *fp;
	cache_t *cache;
	int i;
	uint32_t size;
	struct stat st;
	struct mnttab mt;

	/*
	 * To keep the hash table relatively sparse, default values are
	 * used for smaller mnttab files and these values are scaled up
	 * as a fraction of the total mnttab file size for larger ones.
	 */
	if (stat(MNTTAB, &st) < 0) {
		rcm_log_message(RCM_ERROR,
		    "FILESYS: failed to stat \"%s\" (%s).\n", MNTTAB,
		    strerror(errno));
		errno = EBADF;
		return (NULL);
	}
	if (st.st_size > HASH_THRESHOLD) {
		size = st.st_size / HASH_THRESHOLD;
		for (i = 0; size > 1; i++, size >>= 1);
		for (; i > -1; i--, size <<= 1);
	} else {
		size = HASH_DEFAULT;
	}

	/* Allocate a new empty cache */
	if ((cache = (cache_t *)calloc(1, sizeof (cache_t))) == NULL) {
		rcm_log_message(RCM_ERROR,
		    "FILESYS: failed to allocate cache (%s).\n",
		    strerror(errno));
		errno = ENOMEM;
		return (NULL);
	}
	cache->hash_size = size;
	cache->timestamp = st.st_mtime;

	/* Allocate an empty hash table for the registered special devices */
	cache->mounts = (hashentry_t **)calloc(size, sizeof (hashentry_t *));
	if (cache->mounts == NULL) {
		rcm_log_message(RCM_ERROR,
		    "FILESYS: failed to allocate mount table (%s).\n",
		    strerror(errno));
		free_cache(&cache);
		errno = ENOMEM;
		return (NULL);
	}

	/* Open the mnttab file */
	if ((fp = fopen(MNTTAB, "r")) == NULL) {
		rcm_log_message(RCM_ERROR,
		    "FILESYS: failed to open \"%s\" (%s).\n", MNTTAB,
		    strerror(errno));
		free_cache(&cache);
		errno = EIO;
		return (NULL);
	}

	/* Insert each mnttab entry into the cache */
	while (getmntent(fp, &mt) == 0) {

		/* Well, not each entry... some are meant to be ignored */
		if ((mt.mnt_mntopts != NULL) &&
		    (hasmntopt(&mt, OPT_IGNORE) != NULL))
			continue;

		if (cache_insert(cache, &mt) < 0) {
			rcm_log_message(RCM_ERROR,
			    "FILESYS: cache insertion failure (%s).\n",
			    strerror(errno));
			free_cache(&cache);
			(void) fclose(fp);
			errno = EFAULT;
			return (NULL);
		}
	}

	/* Close the mnttab file */
	(void) fclose(fp);

	return (cache);
}

/*
 * free_cache()
 *
 *	Free up all the memory associated with a cache.
 *
 *	Locking: the cache must be locked before calling this function.
 */
static void
free_cache(cache_t **cachep)
{
	uint32_t index;
	hashentry_t *entry;
	hashentry_t *entry_tmp;

	/* Do nothing with empty caches */
	if ((cachep == NULL) || (*cachep == NULL))
		return;

	if ((*cachep)->mounts) {
		/* Walk through the hashtable, emptying it */
		for (index = 0; index < (*cachep)->hash_size; index++) {
			entry = (*cachep)->mounts[index];
			while (entry) {
				entry_tmp = entry->next;
				free_entry(&entry);
				entry = entry_tmp;
			}
		}
		free((*cachep)->mounts);
	}

	free(*cachep);
	*cachep = NULL;
}

/*
 * free_entry()
 *
 *	Free up memory associated with a hashtable entry.
 *
 *	Locking: the cache must be locked before calling this function.
 */
static void
free_entry(hashentry_t **entryp)
{
	if (entryp) {
		if (*entryp) {
			if ((*entryp)->special)
				free((*entryp)->special);
			if ((*entryp)->fstype)
				free((*entryp)->fstype);
			free_list((*entryp)->mountps);
			free(*entryp);
		}
		*entryp = NULL;
	}
}

/*
 * free_list()
 *
 *	Free up memory associated with a null terminated list of names.
 */
static void
free_list(char **list)
{
	int i;

	if (list) {
		for (i = 0; list[i] != NULL; i++)
			free(list[i]);
		free(list);
	}
}

/*
 * cache_sync()
 *
 *	Resynchronize the mnttab cache with the mnttab file.
 *
 *	Locking: the cache must be locked before calling this function.
 *
 *	Return Values: -1 with errno set on failure, 0 on success.
 */
static int
cache_sync(rcm_handle_t *hd, cache_t **cachep)
{
	uint32_t index;
	cache_t *new_cache;
	cache_t *old_cache;
	hashentry_t *entry;
	struct stat st;

	/* Only accept valid arguments */
	if ((hd == NULL) || (cachep == NULL)) {
		rcm_log_message(RCM_ERROR,
		    "FILESYS: invalid arguments to cache_sync().\n");
		errno = EINVAL;
		return (-1);
	}

	/* Do nothing if there's already an up-to-date cache */
	old_cache = *cachep;
	if (old_cache) {
		if (stat(MNTTAB, &st) == 0) {
			if (old_cache->timestamp >= st.st_mtime) {
				return (0);
			}
		} else {
			rcm_log_message(RCM_WARNING,
			    "FILESYS: failed to stat \"%s\", cache is stale "
			    "(%s).\n", MNTTAB, strerror(errno));
			errno = EIO;
			return (-1);
		}
	}

	/* Create a new cache based on the new mnttab file.  */
	if ((new_cache = cache_create()) == NULL) {
		rcm_log_message(RCM_WARNING,
		    "FILESYS: failed creating cache, cache is stale (%s).\n",
		    strerror(errno));
		errno = EIO;
		return (-1);
	}

	/* Register any specials found in the new cache but not the old one */
	for (index = 0; index < new_cache->hash_size; index++) {
		for (entry = new_cache->mounts[index]; entry != NULL;
		    entry = entry->next) {
			if (cache_lookup(old_cache, entry->special) == NULL) {
				register_rsrc(hd, entry->special);
			}
		}
	}

	/* Pass the new cache pointer to the calling function */
	*cachep = new_cache;

	/* If there wasn't an old cache, return successfully now */
	if (old_cache == NULL)
		return (0);

	/*
	 * If there was an old cache, then unregister whatever specials it
	 * contains that aren't in the new cache.  And then destroy the old
	 * cache.
	 */
	for (index = 0; index < old_cache->hash_size; index++) {
		for (entry = old_cache->mounts[index]; entry != NULL;
		    entry = entry->next) {
			if (cache_lookup(new_cache, entry->special) == NULL) {
				unregister_rsrc(hd, entry->special);
			}
		}
	}
	free_cache(&old_cache);

	return (0);
}

/*
 * cache_insert()
 *
 *	Given a cache and a mnttab entry, this routine inserts that entry in
 *	the cache.  The mnttab entry's special device and filesystem type
 *	is added to the 'mounts' hashtable of the cache, and the entry's
 *	mountp value is added to the list of associated mountpoints for the
 *	corresponding hashtable entry.
 *
 *	Locking: the cache must be locked before calling this function.
 *
 *	Return Values: -1 with errno set on failure, 0 on success.
 */
static int
cache_insert(cache_t *cache, struct mnttab *mt)
{
	uint32_t index;
	hashentry_t *entry;
	char **mountps;

	/* Only accept valid arguments */
	if ((cache == NULL) ||
	    (cache->mounts == NULL) ||
	    (mt == NULL) ||
	    (mt->mnt_special == NULL) ||
	    (mt->mnt_mountp == NULL) ||
	    (mt->mnt_fstype == NULL)) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Disregard any non-loopback mounts whose special device names
	 * don't begin with "/dev".
	 */
	if ((strncmp(mt->mnt_special, "/dev", strlen("/dev")) != 0) &&
	    (strcmp(mt->mnt_fstype, "lofs") != 0))
		return (0);

	/*
	 * Find the special device's entry in the mounts hashtable, allocating
	 * a new entry if necessary.
	 */
	index = hash(cache->hash_size, mt->mnt_special);
	for (entry = cache->mounts[index]; entry != NULL; entry = entry->next) {
		if (strcmp(entry->special, mt->mnt_special) == 0)
			break;
	}
	if (entry == NULL) {
		entry = (hashentry_t *)calloc(1, sizeof (hashentry_t));
		if ((entry == NULL) ||
		    ((entry->special = strdup(mt->mnt_special)) == NULL) ||
		    ((entry->fstype = strdup(mt->mnt_fstype)) == NULL)) {
			rcm_log_message(RCM_ERROR,
			    "FILESYS: failed to allocate special device name "
			    "or filesystem type: (%s).\n", strerror(errno));
			free_entry(&entry);
			errno = ENOMEM;
			return (-1);
		}
		entry->next = cache->mounts[index];
		cache->mounts[index] = entry;
	}

	/*
	 * Keep entries in the list of mounts unique, so exit early if the
	 * mount is already in the list.
	 */
	for (index = 0; index < entry->n_mounts; index++) {
		if (strcmp(entry->mountps[index], mt->mnt_mountp) == 0)
			return (0);
	}

	/*
	 * Add this mountpoint to the list of mounts associated with the
	 * special device.
	 */
	mountps = (char **)realloc(entry->mountps,
	    (entry->n_mounts + 2) * sizeof (char *));
	if ((mountps == NULL) ||
	    ((mountps[entry->n_mounts] = strdup(mt->mnt_mountp)) == NULL)) {
		rcm_log_message(RCM_ERROR,
		    "FILESYS: failed to allocate mountpoint name (%s).\n",
		    strerror(errno));
		if (entry->n_mounts == 0) {
			cache->mounts[index] = entry->next;
			free_entry(&entry);
		}
		errno = ENOMEM;
		return (-1);
	}
	mountps[entry->n_mounts + 1] = NULL;
	entry->n_mounts++;
	entry->mountps = mountps;

	return (0);
}

/*
 * cache_lookup()
 *
 *	Searches the cached table of mounts for a special device entry.
 *
 *	Locking: the cache must be locked before calling this function.
 *
 *	Return Value: NULL with errno set if failure, pointer to existing
 *	cache entry when successful.
 */
static hashentry_t *
cache_lookup(cache_t *cache, char *rsrc)
{
	uint32_t index;
	hashentry_t *entry;

	/* Only accept valid arguments */
	if ((cache == NULL) || (cache->mounts == NULL) || (rsrc == NULL)) {
		errno = EINVAL;
		return (NULL);
	}

	/* Search the cached mounts table for the resource's entry */
	index = hash(cache->hash_size, rsrc);
	if (cache->mounts[index]) {
		for (entry = cache->mounts[index]; entry != NULL;
		    entry = entry->next) {
			if (strcmp(entry->special, rsrc) == 0)
				return (entry);
		}
	}

	errno = ENOENT;
	return (NULL);
}

/*
 * Miscellaneous Functions
 */

/*
 * hash()
 *
 *	A naive hashing function that converts a string 's' to an index in a
 * 	hash table of size 'h'.  It seems to spread entries around well enough.
 */
static uint32_t
hash(uint32_t h, char *s)
{
	uint32_t sum = 0;
	unsigned char *byte;

	if ((byte = (unsigned char *)s) != NULL) {
		while (*byte) {
			sum += 0x3F & (uint32_t)*byte;
			byte++;
		}
	}

	return (sum % h);
}

/*
 * register_rsrc()
 *
 *	Registers for any given resource, unless it's "/".
 */
static void
register_rsrc(rcm_handle_t *hd, char *rsrc)
{
	/* Only accept valid arguments */
	if ((hd == NULL) || (rsrc == NULL))
		return;

	/*
	 * Register any resource other than "/" or "/devices"
	 */
	if ((strcmp(rsrc, "/") != 0) && (strcmp(rsrc, "/devices") != 0)) {
		rcm_log_message(RCM_DEBUG, "FILESYS: registering %s\n", rsrc);
		if (rcm_register_interest(hd, rsrc, 0, NULL) != RCM_SUCCESS) {
			rcm_log_message(RCM_WARNING,
			    "FILESYS: failed to register %s\n", rsrc);
		}
	}

}

/*
 * unregister_rsrc()
 *
 *	Unregister a resource.  This does a little filtering since we know
 *	"/" can't be registered, so we never bother unregistering for it.
 */
static void
unregister_rsrc(rcm_handle_t *hd, char *rsrc)
{
	assert(hd != NULL);
	assert(rsrc != NULL);

	/* Unregister any resource other than "/" */
	if (strcmp(rsrc, "/") != 0) {
		rcm_log_message(RCM_DEBUG, "FILESYS: unregistering %s\n", rsrc);
		(void) rcm_unregister_interest(hd, rsrc, 0);
	}
}

/*
 * create_message()
 *
 *	Given some header strings and a list of dependent names, this
 *	constructs a single string.  If there's only one dependent, the
 *	string consists of the first header and the only dependent appended
 *	to the end of the string enclosed in quotemarks.  If there are
 *	multiple dependents, then the string uses the second header and the
 *	full list of dependents is appended at the end as a comma separated
 *	list of names enclosed in quotemarks.
 */
static char *
create_message(char *header, char *header_multi, char **dependents)
{
	int i;
	size_t len;
	int ndependents;
	char *msg_buf;
	char *msg_header;
	char *separator = MSG_SEPARATOR;

	assert(header != NULL);
	assert(header_multi != NULL);
	assert(dependents != NULL);

	/* Count the number of dependents */
	for (ndependents = 0; dependents[ndependents] != NULL; ndependents++);

	/* If there are no dependents, fail */
	if (ndependents == 0) {
		errno = ENOENT;
		return (NULL);
	}

	/* Pick the appropriate header to use based on amount of dependents */
	if (ndependents == 1) {
		msg_header = header;
	} else {
		msg_header = header_multi;
	}

	/* Compute the size required for the message buffer */
	len = strlen(msg_header) + 2;	/* +2 for the space and a NULL */
	for (i = 0; dependents[i] != NULL; i++)
		len += strlen(dependents[i]) + 2;	/* +2 for quotemarks */
	len += strlen(separator) * (ndependents - 1);

	/* Allocate the message buffer */
	if ((msg_buf = (char *)calloc(len, sizeof (char))) == NULL) {
		rcm_log_message(RCM_ERROR,
		    "FILESYS: failed to allocate message buffer (%s).\n",
		    strerror(errno));
		errno = ENOMEM;
		return (NULL);
	}

	/* Fill in the message buffer */
	(void) snprintf(msg_buf, len, "%s ", msg_header);
	for (i = 0; dependents[i] != NULL; i++) {
		(void) strlcat(msg_buf, "\"", len);
		(void) strlcat(msg_buf, dependents[i], len);
		(void) strlcat(msg_buf, "\"", len);
		if ((i + 1) < ndependents)
			(void) strlcat(msg_buf, separator, len);
	}

	return (msg_buf);
}

/*
 * create_dependents()
 *
 *	Creates a copy of the list of dependent mounts associated with a
 *	given hashtable entry from the cache.
 *
 *	Return Values: NULL with errno set on failure, the resulting list of
 *	dependent resources when successful.
 */
static char **
create_dependents(hashentry_t *entry)
{
	int i;
	char **dependents;

	if (entry == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	if (entry->n_mounts == 0) {
		errno = ENOENT;
		return (NULL);
	}

	/* Allocate space for the full dependency list */
	dependents = (char **)calloc(entry->n_mounts + 1, sizeof (char *));
	if (dependents == NULL) {
		rcm_log_message(RCM_ERROR,
		    "FILESYS: failed to allocate dependents (%s).\n",
		    strerror(errno));
		errno = ENOMEM;
		return (NULL);
	}

	/* Copy all the dependent names into the new list of dependents */
	for (i = 0; i < entry->n_mounts; i++) {
		if ((dependents[i] = strdup(entry->mountps[i])) == NULL) {
			rcm_log_message(RCM_ERROR,
			    "FILESYS: failed to allocate dependent \"%s\" "
			    "(%s).\n", entry->mountps[i], strerror(errno));
			free_list(dependents);
			errno = ENOMEM;
			return (NULL);
		}
	}

	return (dependents);
}

/*
 * detect_critical_failure()
 *
 *	Given a list of dependents, a place to store an error message, and
 *	the flags associated with an operation, this function detects whether
 *	or not the operation should fail due to the presence of any critical
 *	filesystem resources.  When a failure is detected, an appropriate
 *	error message is constructed and passed back to the caller.  This is
 *	called during a suspend request operation.
 *
 *	Return Values: 0 when a critical resource failure shouldn't prevent
 *	the operation, and 1 when such a failure condition does exist.
 */
static int
detect_critical_failure(char **errorp, uint_t flags, char **dependents)
{
	int i;
	int n_critical;
	char *tmp;

	/* Do nothing if the operation is forced or there are no dependents */
	if ((errorp == NULL) || (flags & RCM_FORCE) || (dependents == NULL))
		return (0);

	/*
	 * Count how many of the dependents are critical, and shift the
	 * critical resources to the head of the list.
	 */
	if (dependents) {
		for (i = 0, n_critical = 0; dependents[i] != NULL; i++) {
			if (is_critical(dependents[i])) {
				if (n_critical != i) {
					tmp = dependents[n_critical];
					dependents[n_critical] = dependents[i];
					dependents[i] = tmp;
				}
				n_critical++;
			}
		}
	}

	/* If no criticals were found, do nothing and return */
	if (n_critical == 0)
		return (0);

	/*
	 * Criticals were found.  Prune the list appropriately and construct
	 * an error message.
	 */

	/* Prune non-criticals out of the list */
	for (i = n_critical; dependents[i] != NULL; i++) {
		free(dependents[i]);
		dependents[i] = NULL;
	}

	/* Construct the critical resource error message */
	*errorp = create_message(MSG_HDR_CRIT, MSG_HDR_CRIT_MULTI, dependents);

	return (1);
}

/*
 * is_critical()
 *
 *	Test a resource to determine if it's critical to the system and thus
 *	cannot be suspended.
 *
 *	Return Values: 1 if the named resource is critical, 0 if not.
 */
static int
is_critical(char *rsrc)
{
	assert(rsrc != NULL);

	if ((strcmp(rsrc, "/") == 0) ||
	    (strcmp(rsrc, "/usr") == 0) ||
	    (strcmp(rsrc, "/lib") == 0) ||
	    (strcmp(rsrc, "/usr/lib") == 0) ||
	    (strcmp(rsrc, "/bin") == 0) ||
	    (strcmp(rsrc, "/usr/bin") == 0) ||
	    (strcmp(rsrc, "/tmp") == 0) ||
	    (strcmp(rsrc, "/var") == 0) ||
	    (strcmp(rsrc, "/var/run") == 0) ||
	    (strcmp(rsrc, "/etc") == 0) ||
	    (strcmp(rsrc, "/etc/mnttab") == 0) ||
	    (strcmp(rsrc, "/platform") == 0) ||
	    (strcmp(rsrc, "/usr/platform") == 0) ||
	    (strcmp(rsrc, "/sbin") == 0) ||
	    (strcmp(rsrc, "/usr/sbin") == 0))
		return (1);

	return (0);
}


/*
 * use_cache()
 *
 *	This routine handles all the tasks necessary to lookup a resource
 *	in the cache and extract a separate list of dependents for that
 *	entry.  If an error occurs while doing this, an appropriate error
 *	message is passed back to the caller.
 *
 *	Locking: the cache is locked for the whole duration of this function.
 */
static int
use_cache(char *rsrc, char **errorp, char ***dependentsp)
{
	hashentry_t *entry;

	(void) mutex_lock(&cache_lock);
	if ((entry = cache_lookup(mnt_cache, rsrc)) == NULL) {
		rcm_log_message(RCM_ERROR,
		    "FILESYS: failed looking up \"%s\" in cache (%s).\n",
		    rsrc, strerror(errno));
		*errorp = strdup(MSG_FAIL_INTERNAL);
		(void) mutex_unlock(&cache_lock);
		return (-1);
	}
	*dependentsp = create_dependents(entry);
	(void) mutex_unlock(&cache_lock);

	return (0);
}

/*
 * prune_dependents()
 *
 *	Before calling back into RCM with a list of dependents, the list
 *	must be cleaned up a little.  To avoid infinite recursion, "/" and
 *	the named resource must be pruned out of the list.
 */
static void
prune_dependents(char **dependents, char *rsrc)
{
	int i;
	int n;

	if (dependents) {

		/* Set 'n' to the total length of the list */
		for (n = 0; dependents[n] != NULL; n++);

		/*
		 * Move offending dependents to the tail of the list and
		 * then truncate the list.
		 */
		for (i = 0; dependents[i] != NULL; i++) {
			if ((strcmp(dependents[i], rsrc) == 0) ||
			    (strcmp(dependents[i], "/") == 0)) {
				free(dependents[i]);
				dependents[i] = dependents[n - 1];
				dependents[n] = NULL;
				i--;
				n--;
			}
		}
	}
}
