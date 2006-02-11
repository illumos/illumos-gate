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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <alloca.h>
#include <syslog.h>
#include <strings.h>

#include <topo_error.h>
#include <topo_subr.h>

struct _rwlock;
struct _lwp_mutex;

int _topo_debug = 0;	/* debug messages enabled (off) */
int _topo_dbout = 0;	/* debug messages output mode */

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
topo_stability_name(topo_stability_t s)
{
	switch (s) {
	case TOPO_STABILITY_INTERNAL:	return ("Internal");
	case TOPO_STABILITY_PRIVATE:	return ("Private");
	case TOPO_STABILITY_OBSOLETE:	return ("Obsolete");
	case TOPO_STABILITY_EXTERNAL:	return ("External");
	case TOPO_STABILITY_UNSTABLE:	return ("Unstable");
	case TOPO_STABILITY_EVOLVING:	return ("Evolving");
	case TOPO_STABILITY_STABLE:	return ("Stable");
	case TOPO_STABILITY_STANDARD:	return ("Standard");
	default:			return (NULL);
	}
}

static const topo_debug_mode_t _topo_dbout_modes[] = {
	{ "stderr", "send debug messages to stderr", TOPO_DBOUT_STDERR },
	{ "syslog", "send debug messages to syslog", TOPO_DBOUT_SYSLOG },
	{ NULL, NULL, 0 }
};

void
topo_debug_set(topo_hdl_t *thp, int mask, char *dout)
{
	int i;

	for (i = 0; i < 2; ++i) {
		if (strcmp(_topo_dbout_modes[i].tdm_name, dout) == 0) {
			thp->th_dbout = _topo_dbout =
			    _topo_dbout_modes[i].tdm_mode;
			thp->th_debug = _topo_debug = mask;
			topo_dprintf(mask, _topo_dbout_modes[i].tdm_desc);
		}
	}
}

void
topo_vdprintf(int mask, const char *format, va_list ap)
{
	char *msg;
	size_t len;
	char c;

	if (!(_topo_debug & mask))
		return;

	len = vsnprintf(&c, 1, format, ap);
	msg = alloca(len + 2);
	(void) vsnprintf(msg, len + 1, format, ap);

	if (msg[len - 1] != '\n')
		(void) strcpy(&msg[len], "\n");

	if (_topo_dbout == TOPO_DBOUT_STDERR)
		(void) fprintf(stderr, "libtopo DEBUG: %s", msg);

	if (_topo_dbout == TOPO_DBOUT_SYSLOG)
		syslog(LOG_DEBUG | LOG_USER, "libtopo DEBUG: %s", msg);
}

/*PRINTFLIKE2*/
void
topo_dprintf(int mask, const char *format, ...)
{
	va_list ap;

	if (!(_topo_debug & mask))
		return;

	va_start(ap, format);
	topo_vdprintf(mask, format, ap);
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
