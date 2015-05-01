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
 * Copyright 2015 Gary Mills
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#pragma weak _getprivimplinfo	= getprivimplinfo
#pragma weak _priv_addset	= priv_addset
#pragma weak _priv_allocset	= priv_allocset
#pragma weak _priv_copyset	= priv_copyset
#pragma weak _priv_delset	= priv_delset
#pragma weak _priv_emptyset	= priv_emptyset
#pragma weak _priv_basicset	= priv_basicset
#pragma weak _priv_fillset	= priv_fillset
#pragma weak _priv_freeset	= priv_freeset
#pragma weak _priv_getbyname	= priv_getbyname
#pragma weak _priv_getbynum	= priv_getbynum
#pragma weak _priv_getsetbyname	= priv_getsetbyname
#pragma weak _priv_getsetbynum	= priv_getsetbynum
#pragma weak _priv_ineffect	= priv_ineffect
#pragma weak _priv_intersect	= priv_intersect
#pragma weak _priv_inverse	= priv_inverse
#pragma weak _priv_isemptyset	= priv_isemptyset
#pragma weak _priv_isequalset	= priv_isequalset
#pragma weak _priv_isfullset	= priv_isfullset
#pragma weak _priv_ismember	= priv_ismember
#pragma weak _priv_issubset	= priv_issubset
#pragma weak _priv_set		= priv_set
#pragma weak _priv_union	= priv_union

#include "lint.h"

#define	_STRUCTURED_PROC	1

#include "priv_private.h"
#include "mtlib.h"
#include "libc.h"
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <synch.h>
#include <alloca.h>
#include <atomic.h>
#include <sys/ucred.h>
#include <sys/procfs.h>
#include <sys/param.h>
#include <sys/corectl.h>
#include <priv_utils.h>
#include <zone.h>

/* Include each string only once - until the compiler/linker are fixed */
static const char *permitted	= PRIV_PERMITTED;
static const char *effective	= PRIV_EFFECTIVE;
static const char *limit	= PRIV_LIMIT;
static const char *inheritable	= PRIV_INHERITABLE;
/*
 * Data independent privilege set operations.
 *
 * Only a few functions are provided that do not default to
 * the system implementation of privileges.  A limited set of
 * interfaces is provided that accepts a priv_data_t *
 * argument; this set of interfaces is a private interface between libc
 * and libproc.  It is delivered in order to interpret privilege sets
 * in debuggers in a implementation independent way.  As such, we
 * don't need to provide the bulk of the interfaces, only a few
 * boolean tests (isfull, isempty) the name<->num mappings and
 * set pretty print functions.   The boolean tests are only needed for
 * the latter, so those aren't provided externally.
 *
 * Additionally, we provide the function that maps the kernel implementation
 * structure into a libc private data structure.
 */

priv_data_t *privdata;

static mutex_t pd_lock = DEFAULTMUTEX;

static int
parseninfo(priv_info_names_t *na, char ***buf, int *cp)
{
	char *q;
	int i;

	*buf = libc_malloc(sizeof (char *) * na->cnt);

	if (*buf == NULL)
		return (-1);

	q = na->names;

	for (i = 0; i < na->cnt; i++) {
		int l = strlen(q);

		(*buf)[i] = q;
		q += l + 1;
	}
	*cp = na->cnt;
	return (0);
}

struct strint {
	char *name;
	int rank;
};

static int
strintcmp(const void *a, const void *b)
{
	const struct strint *ap = a;
	const struct strint *bp = b;

	return (strcasecmp(ap->name, bp->name));
}

priv_data_t *
__priv_parse_info(priv_impl_info_t *ip)
{
	priv_data_t *tmp;
	char *x;
	size_t size = PRIV_IMPL_INFO_SIZE(ip);
	int i;

	tmp = libc_malloc(sizeof (*tmp));

	if (tmp == NULL)
		return (NULL);

	(void) memset(tmp, 0, sizeof (*tmp));

	tmp->pd_pinfo = ip;
	tmp->pd_setsize = sizeof (priv_chunk_t) * ip->priv_setsize;
	tmp->pd_ucredsize = UCRED_SIZE(ip);

	x = (char *)ip;
	x += ip->priv_headersize;

	while (x < ((char *)ip) + size) {
		/* LINTED: alignment */
		priv_info_names_t *na = (priv_info_names_t *)x;
		/* LINTED: alignment */
		priv_info_set_t *st = (priv_info_set_t *)x;
		struct strint *tmparr;

		switch (na->info.priv_info_type) {
		case PRIV_INFO_SETNAMES:
			if (parseninfo(na, &tmp->pd_setnames, &tmp->pd_nsets))
				goto out;
			break;
		case PRIV_INFO_PRIVNAMES:
			if (parseninfo(na, &tmp->pd_privnames, &tmp->pd_nprivs))
				goto out;
			/*
			 * We compute a sorted index which allows us
			 * to present a sorted list of privileges
			 * without actually having to sort it each time.
			 */
			tmp->pd_setsort = libc_malloc(tmp->pd_nprivs *
			    sizeof (int));
			if (tmp->pd_setsort == NULL)
				goto out;

			tmparr = libc_malloc(tmp->pd_nprivs *
			    sizeof (struct strint));

			if (tmparr == NULL)
				goto out;

			for (i = 0; i < tmp->pd_nprivs; i++) {
				tmparr[i].rank = i;
				tmparr[i].name = tmp->pd_privnames[i];
			}
			qsort(tmparr, tmp->pd_nprivs, sizeof (struct strint),
			    strintcmp);
			for (i = 0; i < tmp->pd_nprivs; i++)
				tmp->pd_setsort[i] = tmparr[i].rank;
			libc_free(tmparr);
			break;
		case PRIV_INFO_BASICPRIVS:
			tmp->pd_basicset = (priv_set_t *)&st->set[0];
			break;
		default:
			/* unknown, ignore */
			break;
		}
		x += na->info.priv_info_size;
	}
	return (tmp);
out:
	libc_free(tmp->pd_setnames);
	libc_free(tmp->pd_privnames);
	libc_free(tmp->pd_setsort);
	libc_free(tmp);
	return (NULL);
}

/*
 * Caller must have allocated d->pd_pinfo and should free it,
 * if necessary.
 */
void
__priv_free_info(priv_data_t *d)
{
	libc_free(d->pd_setnames);
	libc_free(d->pd_privnames);
	libc_free(d->pd_setsort);
	libc_free(d);
}

/*
 * Return with the pd_lock held and data loaded or indicate failure.
 */
int
lock_data(void)
{
	if (__priv_getdata() == NULL)
		return (-1);

	lmutex_lock(&pd_lock);
	return (0);
}

boolean_t
refresh_data(void)
{
	priv_impl_info_t *ip, ii;
	priv_data_t *tmp;
	char *p0, *q0;
	int oldn, newn;
	int i;

	if (getprivinfo(&ii, sizeof (ii)) != 0 ||
	    ii.priv_max == privdata->pd_nprivs)
		return (B_FALSE);

	ip = alloca(PRIV_IMPL_INFO_SIZE(&ii));

	(void) getprivinfo(ip, PRIV_IMPL_INFO_SIZE(&ii));

	/* Parse the info; then copy the additional bits */
	tmp = __priv_parse_info(ip);
	if (tmp == NULL)
		return (B_FALSE);

	oldn = privdata->pd_nprivs;
	p0 = privdata->pd_privnames[0];

	newn = tmp->pd_nprivs;
	q0 = tmp->pd_privnames[0];

	/* copy the extra information to the old datastructure */
	(void) memcpy((char *)privdata->pd_pinfo + sizeof (priv_impl_info_t),
	    (char *)ip + sizeof (priv_impl_info_t),
	    PRIV_IMPL_INFO_SIZE(ip) - sizeof (priv_impl_info_t));

	/* Copy the first oldn pointers */
	(void) memcpy(tmp->pd_privnames, privdata->pd_privnames,
	    oldn * sizeof (char *));

	/* Adjust the rest */
	for (i = oldn; i < newn; i++)
		tmp->pd_privnames[i] += p0 - q0;

	/* Install the larger arrays */
	libc_free(privdata->pd_privnames);
	privdata->pd_privnames = tmp->pd_privnames;
	tmp->pd_privnames = NULL;

	libc_free(privdata->pd_setsort);
	privdata->pd_setsort = tmp->pd_setsort;
	tmp->pd_setsort = NULL;

	/* Copy the rest of the data */
	*privdata->pd_pinfo = *ip;

	privdata->pd_nprivs = newn;

	__priv_free_info(tmp);
	return (B_TRUE);
}

void
unlock_data(void)
{
	lmutex_unlock(&pd_lock);
}

static priv_set_t *__priv_allocset(priv_data_t *);

priv_data_t *
__priv_getdata(void)
{
	if (privdata == NULL) {
		lmutex_lock(&pd_lock);
		if (privdata == NULL) {
			priv_data_t *tmp;
			priv_impl_info_t *ip;
			size_t size = sizeof (priv_impl_info_t) + 2048;
			size_t realsize;
			priv_impl_info_t *aip = alloca(size);

			if (getprivinfo(aip, size) != 0)
				goto out;

			realsize = PRIV_IMPL_INFO_SIZE(aip);

			ip = libc_malloc(realsize);

			if (ip == NULL)
				goto out;

			if (realsize <= size) {
				(void) memcpy(ip, aip, realsize);
			} else if (getprivinfo(ip, realsize) != 0) {
				libc_free(ip);
				goto out;
			}

			if ((tmp = __priv_parse_info(ip)) == NULL) {
				libc_free(ip);
				goto out;
			}

			/* Allocate the zoneset just once, here */
			tmp->pd_zoneset = __priv_allocset(tmp);
			if (tmp->pd_zoneset == NULL)
				goto clean;

			if (zone_getattr(getzoneid(), ZONE_ATTR_PRIVSET,
			    tmp->pd_zoneset, tmp->pd_setsize)
			    == tmp->pd_setsize) {
				membar_producer();
				privdata = tmp;
				goto out;
			}

			priv_freeset(tmp->pd_zoneset);
clean:
			__priv_free_info(tmp);
			libc_free(ip);
		}
out:
		lmutex_unlock(&pd_lock);
	}
	membar_consumer();
	return (privdata);
}

const priv_impl_info_t *
getprivimplinfo(void)
{
	priv_data_t *d;

	LOADPRIVDATA(d);

	return (d->pd_pinfo);
}

static priv_set_t *
priv_vlist(va_list ap)
{
	priv_set_t *pset = priv_allocset();
	const char *priv;

	if (pset == NULL)
		return (NULL);

	priv_emptyset(pset);

	while ((priv = va_arg(ap, const char *)) != NULL) {
		if (priv_addset(pset, priv) < 0) {
			priv_freeset(pset);
			return (NULL);
		}
	}
	return (pset);
}

/*
 * priv_set(op, set, priv_id1, priv_id2, ..., NULL)
 *
 * Library routine to enable a user process to set a specific
 * privilege set appropriately using a single call.  User is
 * required to terminate the list of privileges with NULL.
 */
int
priv_set(priv_op_t op, priv_ptype_t setname, ...)
{
	va_list ap;
	priv_set_t *pset;
	int ret;

	va_start(ap, setname);

	pset = priv_vlist(ap);

	va_end(ap);

	if (pset == NULL)
		return (-1);

	/* All sets */
	if (setname == NULL) {
		priv_data_t *d;
		int set;

		LOADPRIVDATA(d);

		for (set = 0; set < d->pd_nsets; set++)
			if ((ret = syscall(SYS_privsys, PRIVSYS_SETPPRIV, op,
			    set, (void *)pset, d->pd_setsize)) != 0)
				break;
	} else {
		ret = setppriv(op, setname, pset);
	}

	priv_freeset(pset);
	return (ret);
}

/*
 * priv_ineffect(privilege).
 * tests the existence of a privilege against the effective set.
 */
boolean_t
priv_ineffect(const char *priv)
{
	priv_set_t *curset;
	boolean_t res;

	curset = priv_allocset();

	if (curset == NULL)
		return (B_FALSE);

	if (getppriv(effective, curset) != 0 ||
	    !priv_ismember(curset, priv))
		res = B_FALSE;
	else
		res = B_TRUE;

	priv_freeset(curset);

	return (res);
}

/*
 * The routine __init_daemon_priv() is private to Solaris and is
 * used by daemons to limit the privileges they can use and
 * to set the uid they run under.
 */

static const char root_cp[] = "/core.%f.%t";
static const char daemon_cp[] = "/var/tmp/core.%f.%t";

int
__init_daemon_priv(int flags, uid_t uid, gid_t gid, ...)
{
	priv_set_t *nset;
	priv_set_t *perm = NULL;
	va_list pa;
	priv_data_t *d;
	int ret = -1;
	char buf[1024];

	LOADPRIVDATA(d);

	va_start(pa, gid);

	nset = priv_vlist(pa);

	va_end(pa);

	if (nset == NULL)
		return (-1);

	/* Always add the basic set */
	if (d->pd_basicset != NULL)
		priv_union(d->pd_basicset, nset);

	/*
	 * This is not a significant failure: it allows us to start programs
	 * with sufficient privileges and with the proper uid.   We don't
	 * care enough about the extra groups in that case.
	 */
	if (flags & PU_RESETGROUPS)
		(void) setgroups(0, NULL);

	if (gid != (gid_t)-1 && setgid(gid) != 0)
		goto end;

	perm = priv_allocset();
	if (perm == NULL)
		goto end;

	/* E = P */
	(void) getppriv(permitted, perm);
	(void) setppriv(PRIV_SET, effective, perm);

	/* Now reset suid and euid */
	if (uid != (uid_t)-1 && setreuid(uid, uid) != 0)
		goto end;

	/* Check for the limit privs */
	if ((flags & PU_LIMITPRIVS) &&
	    setppriv(PRIV_SET, limit, nset) != 0)
		goto end;

	if (flags & PU_CLEARLIMITSET) {
		priv_emptyset(perm);
		if (setppriv(PRIV_SET, limit, perm) != 0)
			goto end;
	}

	/* Remove the privileges from all the other sets */
	if (setppriv(PRIV_SET, permitted, nset) != 0)
		goto end;

	if (!(flags & PU_INHERITPRIVS))
		priv_emptyset(nset);

	ret = setppriv(PRIV_SET, inheritable, nset);
end:
	priv_freeset(nset);
	priv_freeset(perm);

	if (core_get_process_path(buf, sizeof (buf), getpid()) == 0 &&
	    strcmp(buf, "core") == 0) {

		if ((uid == (uid_t)-1 ? geteuid() : uid) == 0) {
			(void) core_set_process_path(root_cp, sizeof (root_cp),
			    getpid());
		} else {
			(void) core_set_process_path(daemon_cp,
			    sizeof (daemon_cp), getpid());
		}
	}
	(void) setpflags(__PROC_PROTECT, 0);

	return (ret);
}

/*
 * The routine __fini_daemon_priv() is private to Solaris and is
 * used by daemons to clear remaining unwanted privileges and
 * reenable core dumps.
 */
void
__fini_daemon_priv(const char *priv, ...)
{
	priv_set_t *nset;
	va_list pa;

	if (priv != NULL) {

		va_start(pa, priv);
		nset = priv_vlist(pa);
		va_end(pa);

		if (nset == NULL)
			return;

		(void) priv_addset(nset, priv);
		(void) setppriv(PRIV_OFF, permitted, nset);
		priv_freeset(nset);
	}

	(void) setpflags(__PROC_PROTECT, 0);
}

/*
 * The routine __init_suid_priv() is private to Solaris and is
 * used by set-uid root programs to limit the privileges acquired
 * to those actually needed.
 */

static priv_set_t *bracketpriv;

int
__init_suid_priv(int flags, ...)
{
	priv_set_t *nset = NULL;
	priv_set_t *tmpset = NULL;
	va_list pa;
	int r = -1;
	uid_t ruid, euid;

	euid = geteuid();

	/* If we're not set-uid root, don't reset the uid */
	if (euid == 0) {
		ruid = getuid();
		/* If we're running as root, keep everything */
		if (ruid == 0)
			return (0);
	}

	/* Can call this only once */
	if (bracketpriv != NULL)
		return (-1);

	va_start(pa, flags);

	nset = priv_vlist(pa);

	va_end(pa);

	if (nset == NULL)
		goto end;

	tmpset = priv_allocset();

	if (tmpset == NULL)
		goto end;

	/* We cannot grow our privileges beyond P, so start there */
	(void) getppriv(permitted, tmpset);

	/* Is the privilege we need even in P? */
	if (!priv_issubset(nset, tmpset))
		goto end;

	bracketpriv = priv_allocset();
	if (bracketpriv == NULL)
		goto end;

	priv_copyset(nset, bracketpriv);

	/* Always add the basic set */
	priv_union(priv_basic(), nset);

	/* But don't add what we don't have */
	priv_intersect(tmpset, nset);

	(void) getppriv(inheritable, tmpset);

	/* And stir in the inheritable privileges */
	priv_union(tmpset, nset);

	if ((r = setppriv(PRIV_SET, effective, tmpset)) != 0)
		goto end;

	if ((r = setppriv(PRIV_SET, permitted, nset)) != 0)
		goto end;

	if (flags & PU_CLEARLIMITSET)
		priv_emptyset(nset);

	if ((flags & (PU_LIMITPRIVS|PU_CLEARLIMITSET)) != 0 &&
	    (r = setppriv(PRIV_SET, limit, nset)) != 0)
		goto end;

	if (euid == 0)
		r = setreuid(ruid, ruid);

end:
	priv_freeset(tmpset);
	priv_freeset(nset);
	if (r != 0) {
		/* Fail without leaving uid 0 around */
		if (euid == 0)
			(void) setreuid(ruid, ruid);
		priv_freeset(bracketpriv);
		bracketpriv = NULL;
	}

	return (r);
}

/*
 * Toggle privileges on/off in the effective set.
 */
int
__priv_bracket(priv_op_t op)
{
	/* We're running fully privileged or didn't check errors first time */
	if (bracketpriv == NULL)
		return (0);

	/* Only PRIV_ON and PRIV_OFF are valid */
	if (op == PRIV_SET)
		return (-1);

	return (setppriv(op, effective, bracketpriv));
}

/*
 * Remove privileges from E & P.
 */
void
__priv_relinquish(void)
{
	if (bracketpriv != NULL) {
		(void) setppriv(PRIV_OFF, permitted, bracketpriv);
		priv_freeset(bracketpriv);
		bracketpriv = NULL;
	}
}

/*
 * Use binary search on the ordered list.
 */
int
__priv_getbyname(const priv_data_t *d, const char *name)
{
	char *const *list;
	const int *order;
	int lo = 0;
	int hi;

	if (d == NULL)
		return (-1);

	list = d->pd_privnames;
	order = d->pd_setsort;
	hi = d->pd_nprivs - 1;

	if (strncasecmp(name, "priv_", 5) == 0)
		name += 5;

	do {
		int mid = (lo + hi) / 2;
		int res = strcasecmp(name, list[order[mid]]);

		if (res == 0)
			return (order[mid]);
		else if (res < 0)
			hi = mid - 1;
		else
			lo = mid + 1;
	} while (lo <= hi);

	errno = EINVAL;
	return (-1);
}

int
priv_getbyname(const char *name)
{
	WITHPRIVLOCKED(int, -1, __priv_getbyname(GETPRIVDATA(), name))
}

int
__priv_getsetbyname(const priv_data_t *d, const char *name)
{
	int i;
	int n = d->pd_nsets;
	char *const *list = d->pd_setnames;

	if (strncasecmp(name, "priv_", 5) == 0)
		name += 5;

	for (i = 0; i < n; i++) {
		if (strcasecmp(list[i], name) == 0)
			return (i);
	}

	errno = EINVAL;
	return (-1);
}

int
priv_getsetbyname(const char *name)
{
	/* Not locked: sets don't change */
	return (__priv_getsetbyname(GETPRIVDATA(), name));
}

static const char *
priv_bynum(int i, int n, char **list)
{
	if (i < 0 || i >= n)
		return (NULL);

	return (list[i]);
}

const char *
__priv_getbynum(const priv_data_t *d, int num)
{
	if (d == NULL)
		return (NULL);
	return (priv_bynum(num, d->pd_nprivs, d->pd_privnames));
}

const char *
priv_getbynum(int num)
{
	WITHPRIVLOCKED(const char *, NULL, __priv_getbynum(GETPRIVDATA(), num))
}

const char *
__priv_getsetbynum(const priv_data_t *d, int num)
{
	if (d == NULL)
		return (NULL);
	return (priv_bynum(num, d->pd_nsets, d->pd_setnames));
}

const char *
priv_getsetbynum(int num)
{
	return (__priv_getsetbynum(GETPRIVDATA(), num));
}


/*
 * Privilege manipulation functions
 *
 * Without knowing the details of the privilege set implementation,
 * opaque pointers can be used to manipulate sets at will.
 */

static priv_set_t *
__priv_allocset(priv_data_t *d)
{
	if (d == NULL)
		return (NULL);

	return (libc_malloc(d->pd_setsize));
}

priv_set_t *
priv_allocset(void)
{
	return (__priv_allocset(GETPRIVDATA()));
}

void
priv_freeset(priv_set_t *p)
{
	int er = errno;

	libc_free(p);
	errno = er;
}

void
__priv_emptyset(priv_data_t *d, priv_set_t *set)
{
	(void) memset(set, 0, d->pd_setsize);
}

void
priv_emptyset(priv_set_t *set)
{
	__priv_emptyset(GETPRIVDATA(), set);
}

void
priv_basicset(priv_set_t *set)
{
	priv_copyset(priv_basic(), set);
}

void
__priv_fillset(priv_data_t *d, priv_set_t *set)
{
	(void) memset(set, ~0, d->pd_setsize);
}

void
priv_fillset(priv_set_t *set)
{
	__priv_fillset(GETPRIVDATA(), set);
}


#define	PRIV_TEST_BODY_D(d, test) \
	int i; \
\
	for (i = d->pd_pinfo->priv_setsize; i-- > 0; ) \
		if (!(test)) \
			return (B_FALSE); \
\
	return (B_TRUE)

boolean_t
priv_isequalset(const priv_set_t *a, const priv_set_t *b)
{
	priv_data_t *d;

	LOADPRIVDATA(d);

	return ((boolean_t)(memcmp(a, b, d->pd_setsize) == 0));
}

boolean_t
__priv_isemptyset(priv_data_t *d, const priv_set_t *set)
{
	PRIV_TEST_BODY_D(d, ((priv_chunk_t *)set)[i] == 0);
}

boolean_t
priv_isemptyset(const priv_set_t *set)
{
	return (__priv_isemptyset(GETPRIVDATA(), set));
}

boolean_t
__priv_isfullset(priv_data_t *d, const priv_set_t *set)
{
	PRIV_TEST_BODY_D(d, ((priv_chunk_t *)set)[i] == ~(priv_chunk_t)0);
}

boolean_t
priv_isfullset(const priv_set_t *set)
{
	return (__priv_isfullset(GETPRIVDATA(), set));
}

/*
 * Return true if a is a subset of b
 */
boolean_t
__priv_issubset(priv_data_t *d, const priv_set_t *a, const priv_set_t *b)
{
	PRIV_TEST_BODY_D(d, (((priv_chunk_t *)a)[i] | ((priv_chunk_t *)b)[i]) ==
	    ((priv_chunk_t *)b)[i]);
}

boolean_t
priv_issubset(const priv_set_t *a, const priv_set_t *b)
{
	return (__priv_issubset(GETPRIVDATA(), a, b));
}

#define	PRIV_CHANGE_BODY(a, op, b) \
	int i; \
	priv_data_t *d; \
\
	LOADPRIVDATA(d); \
\
	for (i = 0; i < d->pd_pinfo->priv_setsize; i++) \
		((priv_chunk_t *)a)[i] op \
			((priv_chunk_t *)b)[i]

/* B = A ^ B */
void
priv_intersect(const priv_set_t *a, priv_set_t *b)
{
	/* CSTYLED */
	PRIV_CHANGE_BODY(b, &=, a);
}

/* B = A */
void
priv_copyset(const priv_set_t *a, priv_set_t *b)
{
	/* CSTYLED */
	PRIV_CHANGE_BODY(b, =, a);
}

/* B = A v B */
void
priv_union(const priv_set_t *a, priv_set_t *b)
{
	/* CSTYLED */
	PRIV_CHANGE_BODY(b, |=, a);
}

/* A = ! A */
void
priv_inverse(priv_set_t *a)
{
	PRIV_CHANGE_BODY(a, = ~, a);
}

/*
 * Manipulating single privileges.
 */

int
priv_addset(priv_set_t *a, const char *p)
{
	int priv = priv_getbyname(p);

	if (priv < 0)
		return (-1);

	PRIV_ADDSET(a, priv);

	return (0);
}

int
priv_delset(priv_set_t *a, const char *p)
{
	int priv = priv_getbyname(p);

	if (priv < 0)
		return (-1);

	PRIV_DELSET(a, priv);
	return (0);
}

boolean_t
priv_ismember(const priv_set_t *a, const char *p)
{
	int priv = priv_getbyname(p);

	if (priv < 0)
		return (B_FALSE);

	return ((boolean_t)PRIV_ISMEMBER(a, priv));
}
