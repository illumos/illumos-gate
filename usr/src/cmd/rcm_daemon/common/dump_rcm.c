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

/*
 * RCM module for managing dump device during dynamic
 * reconfiguration.
 */
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <thread.h>
#include <synch.h>
#include <assert.h>
#include <errno.h>
#include <libintl.h>
#include <sys/dumpadm.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "rcm_module.h"

/* cache flags */
#define	DUMP_CACHE_NEW		0x01
#define	DUMP_CACHE_STALE	0x02
#define	DUMP_CACHE_OFFLINED	0x04

#define	DUMPADM			"/usr/sbin/dumpadm -d "
#define	DUMPADM_SWAP		DUMPADM"swap"

typedef struct dump_conf {
	char		device[MAXPATHLEN];
	int		conf_flags;		/* defs in <sys/dumpadm.h> */
	int		cache_flags;
	struct dump_conf *next;
	struct dump_conf *prev;
} dump_conf_t;

/*
 * Registration cache.
 *
 * N.B.	Although we currently only support a single
 *	dump device, the cache is multi-entry since there
 *	may be multiple outstanding registrations.
 */
static dump_conf_t	*cache;
static mutex_t		cache_lock;

static int		dump_register(rcm_handle_t *);
static int		dump_unregister(rcm_handle_t *);
static int		dump_getinfo(rcm_handle_t *, char *, id_t, uint_t,
			    char **, char **, nvlist_t *, rcm_info_t **);
static int		dump_suspend(rcm_handle_t *, char *, id_t, timespec_t *,
			    uint_t, char **, rcm_info_t **);
static int		dump_resume(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		dump_offline(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		dump_online(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		dump_remove(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);

static int		alloc_usage(char **, int);
static void		cache_insert(dump_conf_t *);
static dump_conf_t	*cache_lookup(char *);
static void		cache_remove(dump_conf_t *);
static dump_conf_t	*dump_conf_alloc(void);
static int		dump_configure(dump_conf_t *, char **);
static int		dump_relocate(dump_conf_t *, char **);
static void		free_cache(void);
static void		log_cmd_status(int);
static int		update_cache(rcm_handle_t *);

static struct rcm_mod_ops dump_ops =
{
	RCM_MOD_OPS_VERSION,
	dump_register,
	dump_unregister,
	dump_getinfo,
	dump_suspend,
	dump_resume,
	dump_offline,
	dump_online,
	dump_remove,
	NULL,
	NULL,
	NULL
};

struct rcm_mod_ops *
rcm_mod_init()
{
	return (&dump_ops);
}

const char *
rcm_mod_info()
{
	return ("RCM Dump module 1.3");
}

int
rcm_mod_fini()
{
	free_cache();
	(void) mutex_destroy(&cache_lock);

	return (RCM_SUCCESS);
}

static int
dump_register(rcm_handle_t *hdl)
{
	return (update_cache(hdl));
}

static int
dump_unregister(rcm_handle_t *hdl)
{
	dump_conf_t	*dc;

	(void) mutex_lock(&cache_lock);
	while ((dc = cache) != NULL) {
		cache = cache->next;
		(void) rcm_unregister_interest(hdl, dc->device, 0);
		free(dc);
	}
	(void) mutex_unlock(&cache_lock);

	return (RCM_SUCCESS);
}

/*ARGSUSED*/
static int
dump_getinfo(rcm_handle_t *hdl, char *rsrcname, id_t id, uint_t flags,
    char **infostr, char **errstr, nvlist_t *props, rcm_info_t **dependent)
{
	dump_conf_t	*dc;
	int		conf_flags;

	assert(rsrcname != NULL && infostr != NULL);

	(void) mutex_lock(&cache_lock);
	if ((dc = cache_lookup(rsrcname)) == NULL) {
		(void) mutex_unlock(&cache_lock);
		rcm_log_message(RCM_ERROR, "unknown resource: %s\n",
		    rsrcname);
		return (RCM_FAILURE);
	}
	conf_flags = dc->conf_flags;
	(void) mutex_unlock(&cache_lock);

	return ((alloc_usage(infostr, conf_flags) == 0) ?
	    RCM_SUCCESS : RCM_FAILURE);
}

/*
 * Relocate dump device to maintain availability during suspension.
 * Fail request if unable to relocate.
 */
/*ARGSUSED*/
static int
dump_suspend(rcm_handle_t *hdl, char *rsrcname, id_t id, timespec_t *interval,
    uint_t flags, char **errstr, rcm_info_t **dependent)
{
	dump_conf_t	*dc;
	int		rv;

	assert(rsrcname != NULL && errstr != NULL);

	if (flags & RCM_QUERY)
		return (RCM_SUCCESS);

	(void) mutex_lock(&cache_lock);
	if ((dc = cache_lookup(rsrcname)) == NULL) {
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	rv = dump_relocate(dc, errstr);
	(void) mutex_unlock(&cache_lock);

	return (rv);
}

/*ARGSUSED*/
static int
dump_resume(rcm_handle_t *hdl, char *rsrcname, id_t id, uint_t flags,
    char **errstr, rcm_info_t **dependent)
{
	dump_conf_t	*dc;
	int		rv;

	assert(rsrcname != NULL && errstr != NULL);

	(void) mutex_lock(&cache_lock);
	if ((dc = cache_lookup(rsrcname)) == NULL) {
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	rv = dump_configure(dc, errstr);
	(void) mutex_unlock(&cache_lock);

	return (rv);
}

/*
 * By default, reject offline. If offline request is
 * forced, attempt to relocate the dump device.
 */
/*ARGSUSED*/
static int
dump_offline(rcm_handle_t *hdl, char *rsrcname, id_t id, uint_t flags,
    char **errstr, rcm_info_t **dependent)
{
	dump_conf_t	*dc;
	int		conf_flags;
	int		rv;

	assert(rsrcname != NULL && errstr != NULL);

	if ((flags & RCM_FORCE) && (flags & RCM_QUERY))
		return (RCM_SUCCESS);

	(void) mutex_lock(&cache_lock);
	if ((dc = cache_lookup(rsrcname)) == NULL) {
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	if (flags & RCM_FORCE) {
		rv = dump_relocate(dc, errstr);
		(void) mutex_unlock(&cache_lock);
		return (rv);
	}

	/* default */
	conf_flags = dc->conf_flags;
	(void) mutex_unlock(&cache_lock);
	(void) alloc_usage(errstr, conf_flags);

	return (RCM_FAILURE);
}

/*ARGSUSED*/
static int
dump_online(rcm_handle_t *hdl, char *rsrcname, id_t id, uint_t flags,
    char  **errstr, rcm_info_t **dependent)
{
	dump_conf_t	*dc;
	int		rv;

	assert(rsrcname != NULL && errstr != NULL);

	(void) mutex_lock(&cache_lock);
	if ((dc = cache_lookup(rsrcname)) == NULL) {
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	rv = dump_configure(dc, errstr);
	(void) mutex_unlock(&cache_lock);

	return (rv);
}

/*ARGSUSED*/
static int
dump_remove(rcm_handle_t *hdl, char *rsrcname, id_t id, uint_t flags,
    char **errstr, rcm_info_t **dependent)
{
	dump_conf_t	*dc;

	assert(rsrcname != NULL && errstr != NULL);

	(void) mutex_lock(&cache_lock);
	if ((dc = cache_lookup(rsrcname)) == NULL) {
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}
	cache_remove(dc);
	free(dc);
	(void) mutex_unlock(&cache_lock);

	return (RCM_SUCCESS);
}

/*
 * For dedicated dump devices, invoke dumpadm(8)
 * to relocate dump to swap. For dump device on
 * swap, this is a no-op as the RCM swap module
 * will relocate by invoking swap(8).
 *
 * Call with cache_lock held.
 */
static int
dump_relocate(dump_conf_t *dc, char **errstr)
{
	int		stat;

	/*
	 * This state may get out of sync for a dump device on swap,
	 * since we will will not know if the swap module succeeds.
	 * Worst case is we end up invoking dumpadm to configure
	 * the same device during a rollback.
	 */
	dc->cache_flags |= DUMP_CACHE_OFFLINED;

	/* RCM swap module will handle non-dedicated */
	if (!(dc->conf_flags & DUMP_EXCL))
		return (RCM_SUCCESS);

	rcm_log_message(RCM_TRACE1, "%s\n", DUMPADM_SWAP);
	if ((stat = rcm_exec_cmd(DUMPADM_SWAP)) != 0) {
		log_cmd_status(stat);
		*errstr = strdup(gettext("unable to relocate dump device"));
		dc->cache_flags &= ~DUMP_CACHE_OFFLINED;
		return (RCM_FAILURE);
	}

	return (RCM_SUCCESS);
}

/*
 * (Re)Configure dump device.
 * Call with cache_lock held.
 */
static int
dump_configure(dump_conf_t *dc, char **errstr)
{
	char		cmd[sizeof (DUMPADM) + MAXPATHLEN];
	int		stat;

	assert(dc != NULL && dc->device != NULL);

	/* minor optimization */
	if (!(dc->cache_flags & DUMP_CACHE_OFFLINED))
		return (RCM_SUCCESS);

	(void) snprintf(cmd, sizeof (cmd), "%s%s", DUMPADM, dc->device);
	rcm_log_message(RCM_TRACE1, "%s\n", cmd);
	if ((stat = rcm_exec_cmd(cmd)) != 0) {
		log_cmd_status(stat);
		*errstr = strdup(gettext("unable to configure dump device"));
		return (RCM_FAILURE);
	}
	dc->cache_flags &= ~DUMP_CACHE_OFFLINED;

	return (RCM_SUCCESS);
}

/*
 * Returns current dump configuration
 */
static dump_conf_t *
dump_conf_alloc(void)
{
	dump_conf_t	*dc;
	struct stat	sbuf;
	int		fd;
	char		*err;

	if ((dc = calloc(1, sizeof (*dc))) == NULL) {
		rcm_log_message(RCM_ERROR, "calloc failure\n");
		return (NULL);
	}

	if ((fd = open("/dev/dump", O_RDONLY)) == -1) {
		/*
		 * Suppress reporting if no logical link.
		 */
		if (stat("/dev/dump", &sbuf) == 0 &&
		    (fd = open("/dev/dump", O_RDONLY)) == -1) {
			rcm_log_message(RCM_ERROR,
			    "failed to open /dev/dump: %s\n",
			    ((err = strerror(errno)) == NULL) ? "" : err);
		}

		if (fd == -1) {
			free(dc);
			return (NULL);
		}
	}

	if (ioctl(fd, DIOCGETDEV, dc->device) == -1) {
		if (errno == ENODEV) {
			dc->device[0] = '\0';
		} else {
			rcm_log_message(RCM_ERROR, "ioctl: %s\n",
			    ((err = strerror(errno)) == NULL) ? "" : err);
			(void) close(fd);
			free(dc);
			return (NULL);
		}
	}

	if (dc->device[0] != '\0')  {
		if ((dc->conf_flags = ioctl(fd, DIOCGETCONF, 0)) == -1) {
			rcm_log_message(RCM_ERROR, "ioctl: %s\n",
			    ((err = strerror(errno)) == NULL) ? "" : err);
			(void) close(fd);
			free(dc);
			return (NULL);
		}
	}
	(void) close(fd);

	return (dc);
}

static int
update_cache(rcm_handle_t *hdl)
{
	dump_conf_t	*ent, *curr_dump, *tmp;
	int		rv = RCM_SUCCESS;

	if ((curr_dump = dump_conf_alloc()) == NULL)
		return (RCM_FAILURE);

	(void) mutex_lock(&cache_lock);

	/*
	 * pass 1 -  mark all current registrations stale
	 */
	for (ent = cache; ent != NULL; ent = ent->next) {
		ent->cache_flags |= DUMP_CACHE_STALE;
	}

	/*
	 * update current dump conf
	 */
	if (curr_dump->device[0] == '\0') {
		free(curr_dump);
	} else if ((ent = cache_lookup(curr_dump->device)) != NULL) {
		ent->cache_flags &= ~DUMP_CACHE_STALE;
		ent->conf_flags = curr_dump->conf_flags;
		free(curr_dump);
	} else {
		curr_dump->cache_flags |= DUMP_CACHE_NEW;
		cache_insert(curr_dump);
	}

	/*
	 * pass 2 - register, unregister, or no-op based on cache flags
	 */
	ent = cache;
	while (ent != NULL) {
		if (ent->cache_flags & DUMP_CACHE_OFFLINED) {
			ent = ent->next;
			continue;
		}

		if (ent->cache_flags & DUMP_CACHE_STALE) {
			if (rcm_unregister_interest(hdl, ent->device, 0) !=
			    RCM_SUCCESS) {
				rcm_log_message(RCM_ERROR, "failed to "
				    "unregister %s\n", ent->device);
			}
			tmp = ent;
			ent = ent->next;
			cache_remove(tmp);
			free(tmp);
			continue;
		}

		if (!(ent->cache_flags & DUMP_CACHE_NEW)) {
			ent = ent->next;
			continue;
		}

		if (rcm_register_interest(hdl, ent->device, 0, NULL) !=
		    RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR, "failed to register "
			    "%s\n", ent->device);
			rv = RCM_FAILURE;
		} else {
			rcm_log_message(RCM_DEBUG, "registered %s\n",
			    ent->device);
			ent->cache_flags &= ~DUMP_CACHE_NEW;
		}
		ent = ent->next;
	}
	(void) mutex_unlock(&cache_lock);

	return (rv);
}

/*
 * Call with cache_lock held.
 */
static dump_conf_t *
cache_lookup(char *rsrc)
{
	dump_conf_t	*dc;

	for (dc = cache; dc != NULL; dc = dc->next) {
		if (strcmp(rsrc, dc->device) == 0) {
			return (dc);
		}
	}
	return (NULL);
}

/*
 * Link to front of list.
 * Call with cache_lock held.
 */
static void
cache_insert(dump_conf_t *ent)
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
static void
cache_remove(dump_conf_t *ent)
{
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

static void
free_cache(void)
{
	dump_conf_t	*dc;

	(void) mutex_lock(&cache_lock);
	while ((dc = cache) != NULL) {
		cache = cache->next;
		free(dc);
	}
	(void) mutex_unlock(&cache_lock);
}

static int
alloc_usage(char **cpp, int conf_flags)
{
	/* simplifies message translation */
	if (conf_flags & DUMP_EXCL) {
		*cpp = strdup(gettext("dump device (dedicated)"));
	} else {
		*cpp = strdup(gettext("dump device (swap)"));
	}

	if (*cpp == NULL) {
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
		    ((err =  strerror(errno)) == NULL) ? "" : err);
	} else if (WIFEXITED(stat)) {
		rcm_log_message(RCM_ERROR, "exit status: %d\n",
		    WEXITSTATUS(stat));
	} else {
		rcm_log_message(RCM_ERROR, "wait status: %d\n", stat);
	}
}
