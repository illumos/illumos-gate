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
 * RCM module providing support for swap areas
 * during reconfiguration operations.
 */
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <thread.h>
#include <synch.h>
#include <strings.h>
#include <assert.h>
#include <errno.h>
#include <libintl.h>
#include <sys/types.h>
#include <sys/swap.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/dumpadm.h>
#include <sys/wait.h>
#include "rcm_module.h"

/* cache flags */
#define	SWAP_CACHE_NEW		0x01
#define	SWAP_CACHE_STALE	0x02
#define	SWAP_CACHE_OFFLINED	0x04

#define	SWAP_CMD		"/usr/sbin/swap"
#define	SWAP_DELETE		SWAP_CMD" -d %s %ld"
#define	SWAP_ADD		SWAP_CMD" -a %s %ld %ld"

/* LP64 hard code */
#define	MAXOFFSET_STRLEN	20

typedef struct swap_file {
	char			path[MAXPATHLEN];
	int			cache_flags;
	struct swap_area	*areas;
	struct swap_file	*next;
	struct swap_file	*prev;
} swap_file_t;

/* swap file may have multiple swap areas */
typedef struct swap_area {
	off_t			start;
	off_t			len;
	int			cache_flags;
	struct swap_area	*next;
	struct swap_area	*prev;
} swap_area_t;

static swap_file_t	*cache;
static mutex_t		cache_lock;

static int		swap_register(rcm_handle_t *);
static int		swap_unregister(rcm_handle_t *);
static int		swap_getinfo(rcm_handle_t *, char *, id_t, uint_t,
			    char **, char **, nvlist_t *, rcm_info_t **);
static int		swap_suspend(rcm_handle_t *, char *, id_t, timespec_t *,
			    uint_t, char **, rcm_info_t **);
static int		swap_resume(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		swap_offline(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		swap_online(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		swap_remove(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);

static int		alloc_usage(char **);
static void		cache_insert(swap_file_t *);
static swap_file_t	*cache_lookup(char *);
static void		cache_remove(swap_file_t *);
static void		free_cache(void);
static int		get_dumpdev(char []);
static void		log_cmd_status(int);
static int		swap_add(swap_file_t *, char **);
static void		swap_area_add(swap_file_t *, swap_area_t *);
static swap_area_t	*swap_area_alloc(swapent_t *);
static swap_area_t	*swap_area_lookup(swap_file_t *, swapent_t *);
static void		swap_area_remove(swap_file_t *, swap_area_t *);
static int		swap_delete(swap_file_t *, char **);
static swap_file_t	*swap_file_alloc(char *);
static void		swap_file_free(swap_file_t *);
static swaptbl_t	*sys_swaptbl(void);
static int		update_cache(rcm_handle_t *);

static struct rcm_mod_ops swap_ops =
{
	RCM_MOD_OPS_VERSION,
	swap_register,
	swap_unregister,
	swap_getinfo,
	swap_suspend,
	swap_resume,
	swap_offline,
	swap_online,
	swap_remove,
	NULL,
	NULL,
	NULL
};

struct rcm_mod_ops *
rcm_mod_init()
{
	return (&swap_ops);
}

const char *
rcm_mod_info()
{
	return ("RCM Swap module 1.5");
}

int
rcm_mod_fini()
{
	free_cache();
	(void) mutex_destroy(&cache_lock);

	return (RCM_SUCCESS);
}

static int
swap_register(rcm_handle_t *hdl)
{
	return (update_cache(hdl));
}

static int
swap_unregister(rcm_handle_t *hdl)
{
	swap_file_t	*sf;

	(void) mutex_lock(&cache_lock);
	while ((sf = cache) != NULL) {
		cache = cache->next;
		(void) rcm_unregister_interest(hdl, sf->path, 0);
		swap_file_free(sf);
	}
	(void) mutex_unlock(&cache_lock);

	return (RCM_SUCCESS);
}

/*ARGSUSED*/
static int
swap_getinfo(rcm_handle_t *hdl, char *rsrcname, id_t id, uint_t flags,
    char **infostr, char **errstr, nvlist_t *props, rcm_info_t **dependent)
{
	assert(rsrcname != NULL && infostr != NULL);

	(void) mutex_lock(&cache_lock);
	if (cache_lookup(rsrcname) == NULL) {
		rcm_log_message(RCM_ERROR, "unknown resource: %s\n",
		    rsrcname);
		(void) mutex_unlock(&cache_lock);
		return (RCM_FAILURE);
	}
	(void) mutex_unlock(&cache_lock);
	(void) alloc_usage(infostr);

	return (RCM_SUCCESS);
}

/*
 * Remove swap space to maintain availability of anonymous pages
 * during device suspension. Swap will be reconfigured upon resume.
 * Fail if operation will unconfigure dump device.
 */
/*ARGSUSED*/
static int
swap_suspend(rcm_handle_t *hdl, char *rsrcname, id_t id, timespec_t *interval,
    uint_t flags, char **errstr, rcm_info_t **dependent)
{
	swap_file_t	*sf;
	int		rv;

	assert(rsrcname != NULL && errstr != NULL);

	if (flags & RCM_QUERY)
		return (RCM_SUCCESS);

	(void) mutex_lock(&cache_lock);
	if ((sf = cache_lookup(rsrcname)) == NULL) {
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	rv = swap_delete(sf, errstr);
	(void) mutex_unlock(&cache_lock);

	return (rv);
}

/*ARGSUSED*/
static int
swap_resume(rcm_handle_t *hdl, char *rsrcname, id_t id, uint_t flags,
    char **errstr, rcm_info_t **dependent)
{
	swap_file_t	*sf;
	int		rv;

	assert(rsrcname != NULL && errstr != NULL);

	(void) mutex_lock(&cache_lock);
	if ((sf = cache_lookup(rsrcname)) == NULL) {
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	rv = swap_add(sf, errstr);
	(void) mutex_unlock(&cache_lock);

	return (rv);
}

/*
 * By default, reject offline request. If forced, attempt to
 * delete swap. Fail if operation will unconfigure dump device.
 */
/*ARGSUSED*/
static int
swap_offline(rcm_handle_t *hdl, char *rsrcname, id_t id, uint_t flags,
    char **errstr, rcm_info_t **dependent)
{
	swap_file_t	*sf;
	int		rv;

	assert(rsrcname != NULL && errstr != NULL);

	if ((flags & RCM_FORCE) && (flags & RCM_QUERY))
		return (RCM_SUCCESS);

	(void) mutex_lock(&cache_lock);
	if ((sf = cache_lookup(rsrcname)) == NULL) {
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	if (flags & RCM_FORCE) {
		rv = swap_delete(sf, errstr);
		(void) mutex_unlock(&cache_lock);
		return (rv);
	}
	/* default reject */
	(void) mutex_unlock(&cache_lock);
	(void) alloc_usage(errstr);

	return (RCM_FAILURE);
}

/*ARGSUSED*/
static int
swap_online(rcm_handle_t *hdl, char *rsrcname, id_t id, uint_t flags,
    char **errstr, rcm_info_t **dependent)
{
	swap_file_t	*sf;
	int		rv;

	assert(rsrcname != NULL && errstr != NULL);

	(void) mutex_lock(&cache_lock);
	if ((sf = cache_lookup(rsrcname)) == NULL) {
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	rv = swap_add(sf, errstr);
	(void) mutex_unlock(&cache_lock);

	return (rv);
}

/*ARGSUSED*/
static int
swap_remove(rcm_handle_t *hdl, char *rsrcname, id_t id, uint_t flags,
    char **errstr, rcm_info_t **dependent)
{
	swap_file_t	*sf;

	assert(rsrcname != NULL);

	(void) mutex_lock(&cache_lock);
	if ((sf = cache_lookup(rsrcname)) == NULL) {
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}
	/* RCM framework handles unregistration */
	cache_remove(sf);
	swap_file_free(sf);
	(void) mutex_unlock(&cache_lock);

	return (RCM_SUCCESS);
}

/*
 * Delete all swap areas for swap file.
 * Invoke swap(1M) instead of swapctl(2) to
 * handle relocation of dump device.
 * If dump device is configured, fail if
 * unable to relocate dump.
 *
 * Call with cache_lock held.
 */
static int
swap_delete(swap_file_t *sf, char **errstr)
{
	swap_area_t	*sa;
	char		cmd[sizeof (SWAP_DELETE) + MAXPATHLEN +
			    MAXOFFSET_STRLEN];
	char		dumpdev[MAXPATHLEN];
	int		have_dump = 1;
	int		stat;
	int		rv = RCM_SUCCESS;

	if (get_dumpdev(dumpdev) == 0 && dumpdev[0] == '\0')
		have_dump = 0;

	for (sa = sf->areas; sa != NULL; sa = sa->next) {
		/* swap(1M) is not idempotent */
		if (sa->cache_flags & SWAP_CACHE_OFFLINED) {
			continue;
		}

		(void) snprintf(cmd, sizeof (cmd), SWAP_DELETE, sf->path,
		    sa->start);
		rcm_log_message(RCM_TRACE1, "%s\n", cmd);
		if ((stat = rcm_exec_cmd(cmd)) != 0) {
			log_cmd_status(stat);
			*errstr = strdup(gettext("unable to delete swap"));
			rv = RCM_FAILURE;
			goto out;
		}
		sa->cache_flags |= SWAP_CACHE_OFFLINED;

		/*
		 * Fail on removal of dump device.
		 */
		if (have_dump == 0)
			continue;

		if (get_dumpdev(dumpdev) != 0) {
			rcm_log_message(RCM_WARNING, "unable to "
			    "check for removal of dump device\n");
		} else if (dumpdev[0] == '\0') {
			rcm_log_message(RCM_DEBUG, "removed dump: "
			    "attempting recovery\n");

			/*
			 * Restore dump
			 */
			(void) snprintf(cmd, sizeof (cmd), SWAP_ADD,
				sf->path, sa->start, sa->len);
			rcm_log_message(RCM_TRACE1, "%s\n", cmd);
			if ((stat = rcm_exec_cmd(cmd)) != 0) {
				log_cmd_status(stat);
				rcm_log_message(RCM_ERROR,
				    "failed to restore dump\n");
			} else {
				sa->cache_flags &= ~SWAP_CACHE_OFFLINED;
				rcm_log_message(RCM_DEBUG, "dump restored\n");
			}
			*errstr = strdup(gettext("unable to relocate dump"));
			rv = RCM_FAILURE;
			goto out;
		}
	}
	sf->cache_flags |= SWAP_CACHE_OFFLINED;
out:
	return (rv);
}

/*
 * Invoke swap(1M) to add each registered swap area.
 *
 * Call with cache_lock held.
 */
static int
swap_add(swap_file_t *sf, char **errstr)
{
	swap_area_t	*sa;
	char		cmd[sizeof (SWAP_ADD) + MAXPATHLEN +
			    (2 * MAXOFFSET_STRLEN)];
	int		stat;
	int		rv = RCM_SUCCESS;

	for (sa = sf->areas; sa != NULL; sa = sa->next) {
		/* swap(1M) is not idempotent */
		if (!(sa->cache_flags & SWAP_CACHE_OFFLINED)) {
			continue;
		}

		(void) snprintf(cmd, sizeof (cmd),
			SWAP_ADD, sf->path, sa->start, sa->len);
		rcm_log_message(RCM_TRACE1, "%s\n", cmd);
		if ((stat = rcm_exec_cmd(cmd)) != 0) {
			log_cmd_status(stat);
			*errstr = strdup(gettext("unable to add swap"));
			rv = RCM_FAILURE;
			break;
		} else {
			sa->cache_flags &= ~SWAP_CACHE_OFFLINED;
			sf->cache_flags &= ~SWAP_CACHE_OFFLINED;
		}
	}

	return (rv);
}

static int
update_cache(rcm_handle_t *hdl)
{
	swaptbl_t	*swt;
	swap_file_t	*sf, *stale_sf;
	swap_area_t	*sa, *stale_sa;
	int		i;
	int		rv = RCM_SUCCESS;

	if ((swt = sys_swaptbl()) == NULL) {
		rcm_log_message(RCM_ERROR, "failed to read "
		    "current swap configuration\n");
		return (RCM_FAILURE);
	}

	(void) mutex_lock(&cache_lock);

	/*
	 * cache pass 1 - mark everyone stale
	 */
	for (sf = cache; sf != NULL; sf = sf->next) {
		sf->cache_flags |= SWAP_CACHE_STALE;
		for (sa = sf->areas; sa != NULL; sa = sa->next) {
			sa->cache_flags |= SWAP_CACHE_STALE;
		}
	}

	/*
	 * add new entries
	 */
	for (i = 0; i < swt->swt_n; i++) {
		if (swt->swt_ent[i].ste_flags & (ST_INDEL|ST_DOINGDEL)) {
			continue;
		}

		/*
		 * assure swap_file_t
		 */
		if ((sf = cache_lookup(swt->swt_ent[i].ste_path)) == NULL) {
			if ((sf = swap_file_alloc(swt->swt_ent[i].ste_path)) ==
			    NULL) {
				free(swt);
				return (RCM_FAILURE);
			}
			sf->cache_flags |= SWAP_CACHE_NEW;
			cache_insert(sf);
		} else {
			sf->cache_flags &= ~SWAP_CACHE_STALE;
		}

		/*
		 * assure swap_area_t
		 */
		if ((sa = swap_area_lookup(sf, &swt->swt_ent[i])) == NULL) {
			if ((sa = swap_area_alloc(&swt->swt_ent[i])) == NULL) {
				free(swt);
				return (RCM_FAILURE);
			}
			swap_area_add(sf, sa);
		} else {
			sa->cache_flags &= ~SWAP_CACHE_STALE;
		}
	}

	free(swt);

	/*
	 * cache pass 2
	 *
	 * swap_file_t - skip offlined, register new, unregister/remove stale
	 * swap_area_t - skip offlined, remove stale
	 */
	sf = cache;
	while (sf != NULL) {
		sa = sf->areas;
		while (sa != NULL) {
			if (sa->cache_flags & SWAP_CACHE_OFFLINED) {
				sa->cache_flags &= ~SWAP_CACHE_STALE;
				sa = sa->next;
				continue;
			}
			if (sa->cache_flags & SWAP_CACHE_STALE) {
				stale_sa = sa;
				sa = sa->next;
				swap_area_remove(sf, stale_sa);
				free(stale_sa);
				continue;
			}
			sa = sa->next;
		}

		if (sf->cache_flags & SWAP_CACHE_OFFLINED) {
			sf->cache_flags &= ~SWAP_CACHE_STALE;
			sf = sf->next;
			continue;
		}

		if (sf->cache_flags & SWAP_CACHE_STALE) {
			if (rcm_unregister_interest(hdl, sf->path, 0) !=
			    RCM_SUCCESS) {
				rcm_log_message(RCM_ERROR, "failed to register "
				    "%s\n", sf->path);
			}
			stale_sf = sf;
			sf = sf->next;
			cache_remove(stale_sf);
			swap_file_free(stale_sf);
			continue;
		}

		if (!(sf->cache_flags & SWAP_CACHE_NEW)) {
			sf = sf->next;
			continue;
		}

		if (rcm_register_interest(hdl, sf->path, 0, NULL) !=
		    RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR, "failed to register %s\n",
			    sf->path);
			rv = RCM_FAILURE;
		} else {
			rcm_log_message(RCM_DEBUG, "registered %s\n",
			    sf->path);
			sf->cache_flags &= ~SWAP_CACHE_NEW;
		}
		sf = sf->next;
	}
	(void) mutex_unlock(&cache_lock);

	return (rv);
}

/*
 * Returns system swap table.
 */
static swaptbl_t *
sys_swaptbl()
{
	swaptbl_t	*swt;
	char		*cp;
	int		i, n;
	size_t		tbl_size;

	if ((n = swapctl(SC_GETNSWP, NULL)) == -1)
		return (NULL);

	tbl_size = sizeof (int) + n * sizeof (swapent_t) + n * MAXPATHLEN;
	if ((swt = (swaptbl_t *)malloc(tbl_size)) == NULL)
		return (NULL);

	swt->swt_n = n;
	cp = (char *)swt + (sizeof (int) + n * sizeof (swapent_t));
	for (i = 0; i < n; i++) {
		swt->swt_ent[i].ste_path = cp;
		cp += MAXPATHLEN;
	}

	if ((n = swapctl(SC_LIST, swt)) == -1) {
		free(swt);
		return (NULL);
	}

	if (n != swt->swt_n) {
		/* mismatch, try again */
		free(swt);
		return (sys_swaptbl());
	}

	return (swt);
}

static int
get_dumpdev(char dumpdev[])
{
	int	fd;
	int	rv = 0;
	char	*err;

	if ((fd = open("/dev/dump", O_RDONLY)) == -1) {
		rcm_log_message(RCM_ERROR, "failed to open /dev/dump\n");
		return (-1);
	}

	if (ioctl(fd, DIOCGETDEV, dumpdev) == -1) {
		if (errno == ENODEV) {
			dumpdev[0] = '\0';
		} else {
			rcm_log_message(RCM_ERROR, "ioctl: %s\n",
			    ((err = strerror(errno)) == NULL) ? "" : err);
			rv = -1;
		}
	}
	(void) close(fd);

	return (rv);
}

static void
free_cache(void)
{
	swap_file_t	*sf;

	(void) mutex_lock(&cache_lock);
	while ((sf = cache) != NULL) {
		cache = cache->next;
		swap_file_free(sf);
	}
	(void) mutex_unlock(&cache_lock);

}

/*
 * Call with cache_lock held.
 */
static void
swap_file_free(swap_file_t *sf)
{
	swap_area_t	*sa;

	assert(sf != NULL);

	while ((sa = sf->areas) != NULL) {
		sf->areas = sf->areas->next;
		free(sa);
	}
	free(sf);
}

/*
 * Call with cache_lock held.
 */
static void
cache_insert(swap_file_t *ent)
{
	ent->next = cache;
	if (ent->next)
		ent->next->prev = ent;
	ent->prev = NULL;
	cache = ent;
}

/*
 * Call with cache_lock held.
 */
static swap_file_t *
cache_lookup(char *rsrc)
{
	swap_file_t	*sf;

	for (sf = cache; sf != NULL; sf = sf->next) {
		if (strcmp(rsrc, sf->path) == 0) {
			return (sf);
		}
	}
	return (NULL);
}

/*
 * Call with cache_lock held.
 */
static void
cache_remove(swap_file_t *ent)
{
	assert(ent != NULL);

	if (ent->next != NULL) {
		ent->next->prev = ent->prev;
	}
	if (ent->prev != NULL) {
		ent->prev->next = ent->next;
	} else {
		cache = ent->next;
	}
	ent->next = NULL;
	ent->prev = NULL;
}

/*
 * Call with cache_lock held.
 */
static void
swap_area_add(swap_file_t *sf, swap_area_t *sa)
{
	sa->next = sf->areas;
	if (sa->next)
		sa->next->prev = sa;
	sa->prev = NULL;
	sf->areas = sa;
}

/*
 * Call with cache_lock held.
 */
static void
swap_area_remove(swap_file_t *sf, swap_area_t *ent)
{
	assert(sf != NULL && ent != NULL);

	if (ent->next != NULL) {
		ent->next->prev = ent->prev;
	}
	if (ent->prev != NULL) {
		ent->prev->next = ent->next;
	} else {
		sf->areas = ent->next;
	}
	ent->next = NULL;
	ent->prev = NULL;
}

static swap_file_t *
swap_file_alloc(char *rsrc)
{
	swap_file_t	*sf;

	if ((sf = calloc(1, sizeof (*sf))) == NULL) {
		rcm_log_message(RCM_ERROR, "calloc failure\n");
		return (NULL);
	}
	(void) strlcpy(sf->path, rsrc, sizeof (sf->path));

	return (sf);
}

static swap_area_t *
swap_area_alloc(swapent_t *swt_ent)
{
	swap_area_t	*sa;

	if ((sa = calloc(1, sizeof (*sa))) == NULL) {
		rcm_log_message(RCM_ERROR, "calloc failure\n");
		return (NULL);
	}
	sa->start = swt_ent->ste_start;
	sa->len = swt_ent->ste_length;

	return (sa);
}

/*
 * Call with cache_lock held.
 */
static swap_area_t *
swap_area_lookup(swap_file_t *sf, swapent_t *swt_ent)
{
	swap_area_t	*sa;

	assert(sf != NULL && swt_ent != NULL);
	assert(strcmp(sf->path, swt_ent->ste_path) == 0);

	for (sa = sf->areas; sa != NULL; sa = sa->next) {
		if (sa->start == swt_ent->ste_start &&
		    sa->len == swt_ent->ste_length) {
			return (sa);
		}
	}
	return (NULL);
}

/*
 * All-purpose usage string.
 */
static int
alloc_usage(char **cpp)
{
	if ((*cpp = strdup(gettext("swap area"))) == NULL) {
		rcm_log_message(RCM_ERROR, "strdup failure\n");
		return (-1);
	}
	return (0);
}

static void
log_cmd_status(int stat)
{
	char	*err;

	if (stat == -1) {
		rcm_log_message(RCM_ERROR, "wait: %s\n",
		    ((err = strerror(errno)) == NULL) ? "" : err);
	} else if (WIFEXITED(stat)) {
		rcm_log_message(RCM_ERROR, "exit status: %d\n",
		    WEXITSTATUS(stat));
	} else {
		rcm_log_message(RCM_ERROR, "wait status: %d\n", stat);
	}
}
