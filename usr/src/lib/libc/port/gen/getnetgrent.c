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
 * getnetgrent.c
 *
 *	- name-service switch frontend routines for the netgroup API.
 *
 * Policy decision:
 *	If netgroup A refers to netgroup B, both must occur in the same
 *	source (any other choice gives very confusing semantics).  This
 *	assumption is deeply embedded in the code below and in the backends.
 *
 * innetgr() is implemented on top of something called __multi_innetgr(),
 * which replaces each (char *) argument of innetgr() with a counted vector
 * of (char *).  The semantics are the same as an OR of the results of
 * innetgr() operations on each possible 4-tuple picked from the arguments,
 * but it's possible to implement some cases more efficiently.  This is
 * important for mountd, which used to read YP netgroup.byhost directly in
 * order to determine efficiently whether a given host belonged to any one
 * of a long list of netgroups.  Wildcarded arguments are indicated by a
 * count of zero.
 */

#include "lint.h"
#include <string.h>
#include <synch.h>
#include <nss_dbdefs.h>
#include <mtlib.h>
#include <libc.h>

static DEFINE_NSS_DB_ROOT(db_root);

void
_nss_initf_netgroup(p)
	nss_db_params_t	*p;
{
	p->name	= NSS_DBNAM_NETGROUP;
	p->default_config = NSS_DEFCONF_NETGROUP;
}

/*
 * The netgroup routines aren't quite like the majority of the switch clients.
 *   innetgr() more-or-less fits the getXXXbyYYY mould, but for the others:
 *	- setnetgrent("netgroup") is really a getXXXbyYYY routine, i.e. it
 *	  searches the sources until it finds an entry with the given name.
 *	  Rather than returning the (potentially large) entry, it simply
 *	  initializes a cursor, and then...
 *      - getnetgrent(...) is repeatedly invoked by the user to extract the
 *	  contents of the entry found by setnetgrent().
 *	- endnetgrent() is almost like a real endXXXent routine.
 * The behaviour in NSS was:
 *  If we were certain that all the backends could provide netgroup information
 *  in a common form, we could make the setnetgrent() backend return the entire
 *  entry to the frontend, then implement getnetgrent() and endnetgrent()
 *  strictly in the frontend (aka here).  But we're not certain, so we won't.
 * In NSS2:
 *  Since nscd returns the results, and it is nscd that accumulates
 *  the results, then we can return the entire result on the setnetgrent.
 *
 * NOTE:
 *	In the SunOS 4.x (YP) version of this code, innetgr() did not
 *	affect the state of {set,get,end}netgrent().  Somewhere out
 *	there probably lurks a program that depends on this behaviour,
 *	so this version (both frontend and backends) had better
 *	behave the same way.
 */

/* ===> ?? fix "__" name */
int
__multi_innetgr(ngroup,	pgroup,
		nhost,	phost,
		nuser,	puser,
		ndomain, pdomain)
	nss_innetgr_argc	ngroup, nhost, nuser, ndomain;
	nss_innetgr_argv	pgroup, phost, puser, pdomain;
{
	struct nss_innetgr_args	ia;

	if (ngroup == 0) {
		return (0);	/* One thing fewer to worry backends */
	}

	ia.groups.argc			= ngroup;
	ia.groups.argv			= pgroup;
	ia.arg[NSS_NETGR_MACHINE].argc	= nhost;
	ia.arg[NSS_NETGR_MACHINE].argv	= phost;
	ia.arg[NSS_NETGR_USER].argc	= nuser;
	ia.arg[NSS_NETGR_USER].argv	= puser;
	ia.arg[NSS_NETGR_DOMAIN].argc	= ndomain;
	ia.arg[NSS_NETGR_DOMAIN].argv	= pdomain;
	ia.status			= NSS_NETGR_NO;

	(void) nss_search(&db_root, _nss_initf_netgroup,
	    NSS_DBOP_NETGROUP_IN, &ia);
	return (ia.status == NSS_NETGR_FOUND);
}

int
innetgr(group, host, user, domain)
	const char *group, *host, *user, *domain;
{
#define	IA(charp)	\
	(nss_innetgr_argc)((charp) != 0), (nss_innetgr_argv)(&(charp))

	return (__multi_innetgr(IA(group), IA(host), IA(user), IA(domain)));
}

/*
 * Context for setnetgrent()/getnetgrent().  If the user is being sensible
 * the requests will be serialized anyway, but let's play safe and
 * serialize them ourselves (anything to prevent a coredump)...
 * We can't use lmutex_lock() here because we don't know what the backends
 * that we call may call in turn.  They might call malloc()/free().
 * So we use the brute-force callout_lock_enter() instead.
 */
static nss_backend_t	*getnetgrent_backend;

int
setnetgrent(const char *netgroup)
{
	nss_backend_t	*be;

	if (netgroup == NULL) {
		/* Prevent coredump, otherwise don't do anything profound */
		netgroup = "";
	}

	callout_lock_enter();
	be = getnetgrent_backend;
	if (be != NULL && NSS_INVOKE_DBOP(be, NSS_DBOP_SETENT,
	    (void *)netgroup) != NSS_SUCCESS) {
		(void) NSS_INVOKE_DBOP(be, NSS_DBOP_DESTRUCTOR, 0);
		be = NULL;
	}
	if (be == NULL) {
		struct nss_setnetgrent_args	args;

		args.netgroup	= netgroup;
		args.iterator	= 0;
		(void) nss_search(&db_root, _nss_initf_netgroup,
		    NSS_DBOP_NETGROUP_SET, &args);
		be = args.iterator;
	}
	getnetgrent_backend = be;
	callout_lock_exit();
	return (0);
}

int
getnetgrent_r(machinep, namep, domainp, buffer, buflen)
	char		**machinep;
	char		**namep;
	char		**domainp;
	char		*buffer;
	int		buflen;
{
	struct nss_getnetgrent_args	args;

	args.buffer	= buffer;
	args.buflen	= buflen;
	args.status	= NSS_NETGR_NO;

	callout_lock_enter();
	if (getnetgrent_backend != 0) {
		(void) NSS_INVOKE_DBOP(getnetgrent_backend,
			NSS_DBOP_GETENT, &args);
	}
	callout_lock_exit();

	if (args.status == NSS_NETGR_FOUND) {
		*machinep = args.retp[NSS_NETGR_MACHINE];
		*namep	  = args.retp[NSS_NETGR_USER];
		*domainp  = args.retp[NSS_NETGR_DOMAIN];
		return (1);
	} else {
		return (0);
	}
}

static nss_XbyY_buf_t *buf;

int
getnetgrent(machinep, namep, domainp)
	char		**machinep;
	char		**namep;
	char		**domainp;
{
	(void) NSS_XbyY_ALLOC(&buf, 0, NSS_BUFLEN_NETGROUP);
	return (getnetgrent_r(machinep, namep, domainp,
	    buf->buffer, buf->buflen));
}

int
endnetgrent()
{
	callout_lock_enter();
	if (getnetgrent_backend != 0) {
		(void) NSS_INVOKE_DBOP(getnetgrent_backend,
		    NSS_DBOP_DESTRUCTOR, 0);
		getnetgrent_backend = 0;
	}
	callout_lock_exit();
	nss_delete(&db_root);	/* === ? */
	NSS_XbyY_FREE(&buf);
	return (0);
}
