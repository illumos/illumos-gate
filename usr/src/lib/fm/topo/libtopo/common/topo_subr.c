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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <alloca.h>
#include <ctype.h>
#include <limits.h>
#include <syslog.h>
#include <strings.h>
#include <unistd.h>

#include <topo_error.h>
#include <topo_subr.h>

struct _rwlock;
struct _lwp_mutex;

int
topo_rw_read_held(pthread_rwlock_t *lock)
{
	extern int _rw_read_held(struct _rwlock *);
	return (_rw_read_held((struct _rwlock *)lock));
}

int
topo_rw_write_held(pthread_rwlock_t *lock)
{
	extern int _rw_write_held(struct _rwlock *);
	return (_rw_write_held((struct _rwlock *)lock));
}

int
topo_mutex_held(pthread_mutex_t *lock)
{
	extern int _mutex_held(struct _lwp_mutex *);
	return (_mutex_held((struct _lwp_mutex *)lock));
}

void
topo_hdl_lock(topo_hdl_t *thp)
{
	(void) pthread_mutex_lock(&thp->th_lock);
}

void
topo_hdl_unlock(topo_hdl_t *thp)
{
	(void) pthread_mutex_unlock(&thp->th_lock);
}

const char *
topo_stability2name(topo_stability_t s)
{
	switch (s) {
	case TOPO_STABILITY_INTERNAL:	return (TOPO_STABSTR_INTERNAL);
	case TOPO_STABILITY_PRIVATE:	return (TOPO_STABSTR_PRIVATE);
	case TOPO_STABILITY_OBSOLETE:	return (TOPO_STABSTR_OBSOLETE);
	case TOPO_STABILITY_EXTERNAL:	return (TOPO_STABSTR_EXTERNAL);
	case TOPO_STABILITY_UNSTABLE:	return (TOPO_STABSTR_UNSTABLE);
	case TOPO_STABILITY_EVOLVING:	return (TOPO_STABSTR_EVOLVING);
	case TOPO_STABILITY_STABLE:	return (TOPO_STABSTR_STABLE);
	case TOPO_STABILITY_STANDARD:	return (TOPO_STABSTR_STANDARD);
	default:			return (TOPO_STABSTR_UNKNOWN);
	}
}

topo_stability_t
topo_name2stability(const char *name)
{
	if (strcmp(name, TOPO_STABSTR_INTERNAL) == 0)
		return (TOPO_STABILITY_INTERNAL);
	else if (strcmp(name, TOPO_STABSTR_PRIVATE) == 0)
		return (TOPO_STABILITY_PRIVATE);
	else if (strcmp(name, TOPO_STABSTR_OBSOLETE) == 0)
		return (TOPO_STABILITY_OBSOLETE);
	else if (strcmp(name, TOPO_STABSTR_EXTERNAL) == 0)
		return (TOPO_STABILITY_EXTERNAL);
	else if (strcmp(name, TOPO_STABSTR_UNSTABLE) == 0)
		return (TOPO_STABILITY_UNSTABLE);
	else if (strcmp(name, TOPO_STABSTR_EVOLVING) == 0)
		return (TOPO_STABILITY_EVOLVING);
	else if (strcmp(name, TOPO_STABSTR_STABLE) == 0)
		return (TOPO_STABILITY_STABLE);
	else if (strcmp(name, TOPO_STABSTR_STANDARD) == 0)
		return (TOPO_STABILITY_STANDARD);

	return (TOPO_STABILITY_UNKNOWN);
}

static const topo_debug_mode_t _topo_dbout_modes[] = {
	{ "stderr", "send debug messages to stderr", TOPO_DBOUT_STDERR },
	{ "syslog", "send debug messages to syslog", TOPO_DBOUT_SYSLOG },
	{ NULL, NULL, 0 }
};

static const topo_debug_mode_t _topo_dbflag_modes[] = {
	{ "error", "error handling debug messages enabled", TOPO_DBG_ERR },
	{ "module", "module debug messages enabled", TOPO_DBG_MOD },
	{ "modulesvc", "module services debug messages enabled",
	    TOPO_DBG_MODSVC },
	{ "walk", "walker subsystem debug messages enabled", TOPO_DBG_WALK },
	{ "xml", "xml file parsing messages enabled", TOPO_DBG_XML },
	{ "all", "all debug modes enabled", TOPO_DBG_ALL},
	{ NULL, NULL, 0 }
};

void
env_process_value(topo_hdl_t *thp, const char *begin, const char *end)
{
	char buf[MAXNAMELEN];
	size_t count;
	topo_debug_mode_t *dbp;

	while (begin < end && isspace(*begin))
		begin++;

	while (begin < end && isspace(*(end - 1)))
		end--;

	if (begin >= end)
		return;

	count = end - begin;
	count += 1;

	if (count > sizeof (buf))
		return;

	(void) snprintf(buf, count, "%s", begin);

	for (dbp = (topo_debug_mode_t *)_topo_dbflag_modes;
	    dbp->tdm_name != NULL; ++dbp) {
		if (strcmp(buf, dbp->tdm_name) == 0)
			thp->th_debug |= dbp->tdm_mode;
	}
}

void
topo_debug_set(topo_hdl_t *thp, const char *dbmode, const char *dout)
{
	char *end, *value, *next;
	topo_debug_mode_t *dbp;

	topo_hdl_lock(thp);
	value = (char *)dbmode;

	for (end = (char *)dbmode; *end != '\0'; value = next) {
		end = strchr(value, ',');
		if (end != NULL)
			next = end + 1;	/* skip the comma */
		else
			next = end = value + strlen(value);

		env_process_value(thp, value, end);
	}

	if (dout == NULL) {
		topo_hdl_unlock(thp);
		return;
	}

	for (dbp = (topo_debug_mode_t *)_topo_dbout_modes;
	    dbp->tdm_name != NULL; ++dbp) {
		if (strcmp(dout, dbp->tdm_name) == 0)
		thp->th_dbout = dbp->tdm_mode;
	}
	topo_hdl_unlock(thp);
}

void
topo_vdprintf(topo_hdl_t *thp, int mask, const char *mod, const char *format,
    va_list ap)
{
	char *msg;
	size_t len;
	char c;

	if (!(thp->th_debug & mask))
		return;

	len = vsnprintf(&c, 1, format, ap);
	msg = alloca(len + 2);
	(void) vsnprintf(msg, len + 1, format, ap);

	if (msg[len - 1] != '\n')
		(void) strcpy(&msg[len], "\n");

	if (thp->th_dbout == TOPO_DBOUT_SYSLOG) {
		if (mod == NULL) {
			syslog(LOG_DEBUG | LOG_USER, "libtopo DEBUG: %s", msg);
		} else {
			syslog(LOG_DEBUG | LOG_USER, "libtopo DEBUG: %s: %s",
			    mod, msg);
		}
	} else {
		if (mod == NULL) {
			(void) fprintf(stderr, "libtopo DEBUG: %s", msg);
		} else {
			(void) fprintf(stderr, "libtopo DEBUG: %s: %s", mod,
			    msg);
		}
	}
}

/*PRINTFLIKE3*/
void
topo_dprintf(topo_hdl_t *thp, int mask, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	topo_vdprintf(thp, mask, NULL, format, ap);
	va_end(ap);
}

tnode_t *
topo_hdl_root(topo_hdl_t *thp, const char *scheme)
{
	ttree_t *tp;

	for (tp = topo_list_next(&thp->th_trees); tp != NULL;
	    tp = topo_list_next(tp)) {
		if (strcmp(scheme, tp->tt_scheme) == 0)
			return (tp->tt_root);
	}

	return (NULL);
}

/*
 * buf_append -- Append str to buf (if it's non-NULL).  Place prepend
 * in buf in front of str and append behind it (if they're non-NULL).
 * Continue to update size even if we run out of space to actually
 * stuff characters in the buffer.
 */
void
topo_fmristr_build(ssize_t *sz, char *buf, size_t buflen, char *str,
    char *prepend, char *append)
{
	ssize_t left;

	if (str == NULL)
		return;

	if (buflen == 0 || (left = buflen - *sz) < 0)
		left = 0;

	if (buf != NULL && left != 0)
		buf += *sz;

	if (prepend == NULL && append == NULL)
		*sz += snprintf(buf, left, "%s", str);
	else if (append == NULL)
		*sz += snprintf(buf, left, "%s%s", prepend, str);
	else if (prepend == NULL)
		*sz += snprintf(buf, left, "%s%s", str, append);
	else
		*sz += snprintf(buf, left, "%s%s%s", prepend, str, append);
}

#define	TOPO_PLATFORM_PATH	"%s/usr/platform/%s/lib/fm/topo/%s"
#define	TOPO_COMMON_PATH	"%s/usr/lib/fm/topo/%s"

char *
topo_search_path(topo_mod_t *mod, const char *rootdir, const char *file)
{
	char *pp, sp[PATH_MAX];
	topo_hdl_t *thp = mod->tm_hdl;

	/*
	 * Search for file name in order of platform, machine and common
	 * topo directories
	 */
	(void) snprintf(sp, PATH_MAX, TOPO_PLATFORM_PATH, rootdir,
	    thp->th_platform, file);
	if (access(sp, F_OK) != 0) {
		(void) snprintf(sp, PATH_MAX, TOPO_PLATFORM_PATH,
		    thp->th_rootdir, thp->th_machine, file);
		if (access(sp, F_OK) != 0) {
			(void) snprintf(sp, PATH_MAX, TOPO_COMMON_PATH,
			    thp->th_rootdir, file);
			if (access(sp, F_OK) != 0) {
				return (NULL);
			}
		}
	}

	pp = topo_mod_strdup(mod, sp);

	return (pp);
}

/*
 * SMBIOS serial numbers can contain characters (particularly ':' and ' ')
 * that are invalid for the authority and can break FMRI parsing.  We translate
 * any invalid characters to a safe '-', as well as trimming any leading or
 * trailing whitespace.  Similarly, '/' can be found in some product names
 * so we translate that to '-'.
 */
char *
topo_cleanup_auth_str(topo_hdl_t *thp, char *begin)
{
	char buf[MAXNAMELEN];
	size_t count;
	char *str, *end, *pp;

	end = begin + strlen(begin);

	while (begin < end && isspace(*begin))
		begin++;
	while (begin < end && isspace(*(end - 1)))
		end--;

	if (begin >= end)
		return (NULL);

	count = end - begin;
	count += 1;

	if (count > sizeof (buf))
		return (NULL);

	(void) snprintf(buf, count, "%s", begin);
	while ((str = strpbrk(buf, " :=/")) != NULL)
		*str = '-';

	pp = topo_hdl_strdup(thp, buf);
	return (pp);
}
