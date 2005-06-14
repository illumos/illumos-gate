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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak endgrent = _endgrent
#pragma weak setgrent = _setgrent

#pragma weak getgrnam_r = _getgrnam_r
#pragma weak getgrgid_r = _getgrgid_r
#pragma weak getgrent_r = _getgrent_r
#pragma weak fgetgrent_r = _fgetgrent_r

#include "synonyms.h"
#include <mtlib.h>
#include <sys/types.h>
#include <grp.h>
#include <memory.h>
#include <nsswitch.h>
#include <nss_dbdefs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <synch.h>
#include <sys/param.h>
#include <sys/mman.h>

#define	__NSS_PRIVATE_INTERFACE
#include "nsswitch_priv.h"
#undef	__NSS_PRIVATE_INTERFACE

extern int _getgroupsbymember(const char *, gid_t[], int, int);
int str2group(const char *, int, void *,
	char *, int);

static DEFINE_NSS_DB_ROOT(db_root);
static DEFINE_NSS_GETENT(context);

#define	USE_NETID_STR	"NETID_AUTHORITATIVE=TRUE"

void
_nss_initf_group(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_GROUP;
	p->default_config = NSS_DEFCONF_GROUP;
}

#include <getxby_door.h>
#include <sys/door.h>

static struct group *
process_getgr(struct group *result, char *buffer, int buflen,
    nsc_data_t *sptr, int ndata);

struct group *
_uncached_getgrnam_r(const char *name, struct group *result, char *buffer,
    int buflen);

struct group *
_uncached_getgrgid_r(gid_t gid, struct group *result, char *buffer, int buflen);

/*
 * POSIX.1c Draft-6 version of the function getgrnam_r.
 * It was implemented by Solaris 2.3.
 */
struct group *
_getgrnam_r(const char *name, struct group *result, char *buffer, int buflen)
{
	/*
	 * allocate room on the stack for the nscd to return
	 * group and group member information
	 */
	union {
		nsc_data_t	s_d;
		char		s_b[8192];
	} space;
	nsc_data_t	*sptr;
	int		ndata;
	int		adata;
	struct group	*resptr = NULL;

	if ((name == (const char *)NULL) ||
	    (strlen(name) >= (sizeof (space) - sizeof (nsc_data_t)))) {
		errno = ERANGE;
		return (NULL);
	}

	ndata = sizeof (space);
	adata = strlen(name) + sizeof (nsc_call_t) + 1;
	space.s_d.nsc_call.nsc_callnumber = GETGRNAM;
	(void) strcpy(space.s_d.nsc_call.nsc_u.name, name);
	sptr = &space.s_d;

	switch (_nsc_trydoorcall(&sptr, &ndata, &adata)) {
	case SUCCESS:	/* positive cache hit */
		break;
	case NOTFOUND:	/* negative cache hit */
		return (NULL);
	default:
		return ((struct group *)_uncached_getgrnam_r(name, result,
		    buffer, buflen));
	}

	resptr = process_getgr(result, buffer, buflen, sptr, ndata);

	/*
	 * check to see if doors reallocated memory underneath us
	 * if they did munmap the memory or suffer a memory leak
	 */

	if (sptr != &space.s_d)
		munmap((void *)sptr, ndata);

	return (resptr);
}

/*
 * POSIX.1c Draft-6 version of the function getgrgid_r.
 * It was implemented by Solaris 2.3.
 */
struct group *
_getgrgid_r(gid_t gid, struct group *result, char *buffer, int buflen)
{
	/*
	 * allocate room on the stack for the nscd to return
	 * group and group member information
	 */
	union {
		nsc_data_t	s_d;
		char		s_b[8192];
	} space;
	nsc_data_t	*sptr;
	int		ndata;
	int		adata;
	struct group	*resptr = NULL;

	ndata = sizeof (space);
	adata = sizeof (nsc_call_t) + 1;
	space.s_d.nsc_call.nsc_callnumber = GETGRGID;
	space.s_d.nsc_call.nsc_u.gid = gid;
	sptr = &space.s_d;

	switch (_nsc_trydoorcall(&sptr, &ndata, &adata)) {
	case SUCCESS:	/* positive cache hit */
		break;
	case NOTFOUND:	/* negative cache hit */
		return (NULL);
	default:
		return ((struct group *)_uncached_getgrgid_r(gid, result,
		    buffer, buflen));
	}

	resptr = process_getgr(result, buffer, buflen, sptr, ndata);

	/*
	 * check to see if doors reallocated memory underneath us
	 * if they did munmap the memory or suffer a memory leak
	 */

	if (sptr != &space.s_d)
		munmap((void *)sptr, ndata);

	return (resptr);
}
/*
 *  This routine should be rewritten - there's no reason it
 *  cannot be the same code for 32 and 64 bit w/ a bit of care.
 */
/* ARGSUSED4 */
static struct group *
process_getgr(struct group *result, char *buffer, int buflen,
    nsc_data_t *sptr, int ndata)
{
	int i;
	char *fixed;
#ifdef	_LP64
	char	*buffer32;
	char	**gr_mem32;
	uptr32_t	index;
	struct group	group64;
#endif	/*	_LP64	*/

/* align buffer on a pointer boundry 4bytes in 32bits and 8 bytes in 64bits */
#ifdef	_LP64
	fixed = (char *)(((uintptr_t)buffer + 7) & ~7);
#else
	fixed = (char *)(((uintptr_t)buffer + 3) & ~3);
#endif	/*	_LP64	*/

	if (buflen <= fixed - buffer) { /* watch out for wrap-around */
		errno = ERANGE;
		return (NULL);
	}

	buflen -= fixed - buffer;

	buffer = fixed;

#ifdef	_LP64
	/*
	 * this is just a rationality check; we need to make
	 * sure that there's enough space for the gr_mem array
	 * as well... easiest place to do that is when we copy
	 * them in place.
	 */

	if (sptr->nsc_ret.nsc_bufferbytesused +
		/*
		 * ^^^ number of bytes from nscd
		 */
	    (sizeof (char **)) +
		/*
		 * ^^^ we need 8 bytes for gr_mem
		 */
	    (sizeof (char *) - 1) -
		/*
		 * ^^^ plus space for pssibly fixing aligment of gr_mem
		 */
	    sizeof (group32_t)
		/*
		 * ^^^ because we don't put this in the usr buffer
		 */
	    > buflen) {
#else
	if (sptr->nsc_ret.nsc_bufferbytesused - sizeof (struct group)
	    > buflen) {
#endif	/*	_LP64	*/
		errno = ERANGE;
		return (NULL);
	}

	if (sptr->nsc_ret.nsc_return_code != SUCCESS)
		return (NULL);

/*
 * ncsd is a 32bit application, so use 32bit data items if we are in 64bit mode
 */
#ifdef	_LP64

	(void) memcpy(buffer,
	    (sptr->nsc_ret.nsc_u.buff + sizeof (group32_t)),
	    (sptr->nsc_ret.nsc_bufferbytesused - sizeof (group32_t)));

	group64.gr_name = (char *)(sptr->nsc_ret.nsc_u.grp.gr_name +
				(uintptr_t)buffer);
	group64.gr_passwd = (char *)(sptr->nsc_ret.nsc_u.grp.gr_passwd +
				(uintptr_t)buffer);
	group64.gr_gid = sptr->nsc_ret.nsc_u.grp.gr_gid;

	group64.gr_mem = (char **)((uintptr_t)buffer +
			sptr->nsc_ret.nsc_bufferbytesused - sizeof (group32_t));
	group64.gr_mem = (char **)(((uintptr_t)group64.gr_mem + 7) & ~7);

	gr_mem32 = (char **)(uintptr_t)sptr->nsc_ret.nsc_u.grp.gr_mem;
	buffer32 = buffer;

	for (i = 0; ; i++) {
		index = *((uptr32_t *)
		    ((uintptr_t)gr_mem32 + (uintptr_t)buffer32));

		/*
		 * make sure there's enough space to copy the pointer...
		 */
		if (&group64.gr_mem[i + 1] >
		    (char **)((uintptr_t)buffer + buflen)) {
			errno = ERANGE;
			return (NULL);
		}

		if (index == 0)
			break;

		group64.gr_mem[i] = (char *)(index + buffer);
		buffer32 += sizeof (uptr32_t);

	}
	group64.gr_mem[i] = NULL;

	*result = group64;
#else

	(void) memcpy(buffer,
	    (sptr->nsc_ret.nsc_u.buff + sizeof (struct group)),
	    (sptr->nsc_ret.nsc_bufferbytesused - sizeof (struct group)));

	sptr->nsc_ret.nsc_u.grp.gr_name += (uintptr_t)buffer;
	sptr->nsc_ret.nsc_u.grp.gr_passwd += (uintptr_t)buffer;

	sptr->nsc_ret.nsc_u.grp.gr_mem =
	    (char **)((uintptr_t)sptr->nsc_ret.nsc_u.grp.gr_mem +
		(uintptr_t)buffer);

	i = 0;
	while (sptr->nsc_ret.nsc_u.grp.gr_mem[i]) {
		sptr->nsc_ret.nsc_u.grp.gr_mem[i] += (uintptr_t)buffer;
		i++;
	}

	*result = sptr->nsc_ret.nsc_u.grp;

#endif	/*	_LP64	*/

	return (result);
}

struct group *
_uncached_getgrgid_r(gid_t gid, struct group *result, char *buffer,
    int buflen)
{
	nss_XbyY_args_t arg;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2group);
	arg.key.gid = gid;
	(void) nss_search(&db_root, _nss_initf_group,
				NSS_DBOP_GROUP_BYGID, &arg);
	return ((struct group *)NSS_XbyY_FINI(&arg));
}

/*
 * POSIX.1c standard version of the function getgrgid_r.
 * User gets it via static getgrgid_r from the header file.
 */
int
__posix_getgrgid_r(gid_t gid, struct group *grp, char *buffer,
    size_t bufsize, struct group **result)
{
	int nerrno = 0;
	int oerrno = errno;

	errno = 0;
	if ((*result = _getgrgid_r(gid, grp, buffer, (uintptr_t)bufsize))
		== NULL) {
			nerrno = errno;
	}
	errno = oerrno;
	return (nerrno);
}

extern struct group *
_getgrnam_r(const char *name, struct group *result, char *buffer,
	int buflen);

struct group *
_uncached_getgrnam_r(const char *name, struct group *result, char *buffer,
	int buflen)
{
	nss_XbyY_args_t arg;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2group);
	arg.key.name = name;
	(void) nss_search(&db_root, _nss_initf_group,
			NSS_DBOP_GROUP_BYNAME, &arg);
	return ((struct group *)NSS_XbyY_FINI(&arg));
}

/*
 * POSIX.1c standard version of the function getgrnam_r.
 * User gets it via static getgrnam_r from the header file.
 */
int
__posix_getgrnam_r(const char *name, struct group *grp, char *buffer,
    size_t bufsize, struct group **result)
{
	int nerrno = 0;
	int oerrno = errno;

	if ((*result = _getgrnam_r(name, grp, buffer, (uintptr_t)bufsize))
		== NULL) {
			nerrno = errno;
	}
	errno = oerrno;
	return (nerrno);
}

void
setgrent(void)
{
	nss_setent(&db_root, _nss_initf_group, &context);
}

void
endgrent(void)
{
	nss_endent(&db_root, _nss_initf_group, &context);
	nss_delete(&db_root);
}

struct group *
getgrent_r(struct group *result, char *buffer, int buflen)
{
	nss_XbyY_args_t arg;
	char		*nam;

	/* In getXXent_r(), protect the unsuspecting caller from +/- entries */

	do {
		NSS_XbyY_INIT(&arg, result, buffer, buflen, str2group);
		/* No key to fill in */
		(void) nss_getent(&db_root, _nss_initf_group, &context, &arg);
	} while (arg.returnval != 0 &&
		(nam = ((struct group *)arg.returnval)->gr_name) != 0 &&
		(*nam == '+' || *nam == '-'));

	return ((struct group *)NSS_XbyY_FINI(&arg));
}

struct group *
fgetgrent_r(FILE *f, struct group *result, char *buffer, int buflen)
{
	extern void	_nss_XbyY_fgets(FILE *, nss_XbyY_args_t *);
	nss_XbyY_args_t	arg;

	/* ... but in fgetXXent_r, the caller deserves any +/- entry he gets */

	/* No key to fill in */
	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2group);
	_nss_XbyY_fgets(f, &arg);
	return ((struct group *)NSS_XbyY_FINI(&arg));
}

/*
 * _getgroupsbymember(uname, gid_array, maxgids, numgids):
 *	Private interface for initgroups().  It returns the group ids of
 *	groups of which the specified user is a member.
 *
 * Arguments:
 *   username	Username of the putative member
 *   gid_array	Space in which to return the gids.  The first [numgids]
 *		elements are assumed to already contain valid gids.
 *   maxgids	Maximum number of elements in gid_array.
 *   numgids	Number of elements (normally 0 or 1) that already contain
 *		valid gids.
 * Return value:
 *   number of valid gids in gid_array (may be zero)
 *	or
 *   -1 (and errno set appropriately) on errors (none currently defined)
 */

static nss_status_t process_cstr(const char *, int, struct nss_groupsbymem *);

int
_getgroupsbymember(const char *username, gid_t gid_array[],
    int maxgids, int numgids)
{
	struct nss_groupsbymem	arg;
	char defval[BUFSIZ];
	__NSL_FILE *defl;

	arg.username	= username;
	arg.gid_array	= gid_array;
	arg.maxgids	= maxgids;
	arg.numgids	= numgids;
	arg.str2ent	= str2group;
	arg.process_cstr = process_cstr;

	/*
	 * The old value being provided here was 0, ie do the quick
	 * way.  Given that this was never actually used under NIS
	 * and had the wrong (now corrected) meaning for NIS+ we need
	 * to change the default to be 1 (TRUE) as we now need the
	 * admin to decided to use netid, setting NETID_AUTHORITATIVE
	 * in /etc/default/nss to TRUE gets us a value of 0 for
	 * force_slow_way - don't you just love double negatives ;-)
	 *
	 * We need to do this to preserve the behaviour seen when the
	 * admin makes no changes.
	 */
	arg.force_slow_way = 1;

	/*
	 * The "easy" way to do /etc/default/nss is to use the defread()
	 * stuff from libcmd, but since we are in libc we don't want to
	 * link ourselfs against libcmd, so instead we just do it by hand
	 */

	if ((defl = __nsl_c_fopen(__NSW_DEFAULT_FILE, "r")) != NULL) {
		while (__nsl_c_fgets(defval, sizeof (defval), defl) != NULL) {
			if (strncmp(USE_NETID_STR, defval,
			    sizeof (USE_NETID_STR) - 1) == 0) {
				arg.force_slow_way = 0;
				break;
			}
		}
		(void) __nsl_c_fclose(defl);
	}

	(void) nss_search(&db_root, _nss_initf_group,
			NSS_DBOP_GROUP_BYMEMBER, &arg);

#ifdef	undef
	/*
	 * Only do this if there's existing code somewhere that relies on
	 *   initgroups() doing an endgrent() -- most unlikely.
	 */
	endgrent();
#endif	/* undef */

	return (arg.numgids);
}


static char *
gettok(char **nextpp, char sep)
{
	char	*p = *nextpp;
	char	*q = p;
	char	c;

	if (p == 0)
		return (0);

	while ((c = *q) != '\0' && c != sep)
		q++;

	if (c == '\0')
		*nextpp = 0;
	else {
		*q++ = '\0';
		*nextpp = q;
	}
	return (p);
}

/*
 * Return values: 0 = success, 1 = parse error, 2 = erange ...
 * The structure pointer passed in is a structure in the caller's space
 * wherein the field pointers would be set to areas in the buffer if
 * need be. instring and buffer should be separate areas.
 */
int
str2group(const char *instr, int lenstr, void *ent, char *buffer, int buflen)
{
	struct group		*group	= (struct group *)ent;
	char			*p, *next;
	int			black_magic;	/* "+" or "-" entry */
	char			**memlist, **limit;

	if (lenstr + 1 > buflen)
		return (NSS_STR_PARSE_ERANGE);

	/*
	 * We copy the input string into the output buffer and
	 * operate on it in place.
	 */
	(void) memcpy(buffer, instr, lenstr);
	buffer[lenstr] = '\0';

	next = buffer;

	/*
	 * Parsers for passwd and group have always been pretty rigid;
	 * we wouldn't want to buck a Unix tradition
	 */

	group->gr_name = p = gettok(&next, ':');
	if (*p == '\0') {
		/* Empty group-name;  not allowed */
		return (NSS_STR_PARSE_PARSE);
	}

	/* Always return at least an empty gr_mem list */
	memlist	= (char **)ROUND_UP(buffer + lenstr + 1, sizeof (char *));
	limit	= (char **)ROUND_DOWN(buffer + buflen, sizeof (char *));
	*memlist = 0;
	group->gr_mem = memlist;

	black_magic = (*p == '+' || *p == '-');
	if (black_magic) {
		/* Then the rest of the group entry is optional */
		group->gr_passwd = 0;
		group->gr_gid = 0;
	}

	group->gr_passwd = p = gettok(&next, ':');
	if (p == 0) {
		if (black_magic)
			return (NSS_STR_PARSE_SUCCESS);
		else
			return (NSS_STR_PARSE_PARSE);
	}

	p = next;					/* gid */
	if (p == 0 || *p == '\0') {
		if (black_magic)
			return (NSS_STR_PARSE_SUCCESS);
		else
			return (NSS_STR_PARSE_PARSE);
	}
	if (!black_magic) {
		group->gr_gid = (gid_t)strtol(p, &next, 10);
		if (next == p) {
			/* gid field should be nonempty */
			return (NSS_STR_PARSE_PARSE);
		}
		/*
		 * gids should be non-negative; anything else
		 * is administrative policy.
		 */
		if (group->gr_gid < 0)
			group->gr_gid = GID_NOBODY;
	}
	if (*next++ != ':') {
		/* Parse error, even for a '+' entry (which should have	*/
		/*   an empty gid field, since it's always overridden)	*/
		return (NSS_STR_PARSE_PARSE);
	}

	/* === Could check and complain if there are any extra colons */
	while (memlist < limit) {
		p = gettok(&next, ',');
		if (p == 0 || *p == '\0') {
			*memlist = 0;
			/* Successfully parsed and stored */
			return (NSS_STR_PARSE_SUCCESS);
		}
		*memlist++ = p;
	}
	/* Out of space;  error even for black_magic */
	return (NSS_STR_PARSE_ERANGE);
}

static nss_status_t
process_cstr(const char *instr, int instr_len, struct nss_groupsbymem *gbm)
{
	/*
	 * It's possible to do a much less inefficient version of this by
	 * selectively duplicating code from str2group().  For now,
	 * however, we'll take the easy way out and implement this on
	 * top of str2group().
	 */

	const char		*username = gbm->username;
	nss_XbyY_buf_t		*buf;
	struct group		*grp;
	char			**memp;
	char			*mem;
	int	parsestat;

	buf = _nss_XbyY_buf_alloc(sizeof (struct group), NSS_BUFLEN_GROUP);
	if (buf == 0)
		return (NSS_UNAVAIL);

	grp = (struct group *)buf->result;

	parsestat = (*gbm->str2ent)(instr, instr_len,
				    grp, buf->buffer, buf->buflen);

	if (parsestat != NSS_STR_PARSE_SUCCESS) {
		_nss_XbyY_buf_free(buf);
		return (NSS_NOTFOUND);	/* === ? */
	}

	if (grp->gr_mem) {
		for (memp = grp->gr_mem; (memp) && ((mem = *memp) != 0);
								memp++) {
			if (strcmp(mem, username) == 0) {
				gid_t	gid 	= grp->gr_gid;
				gid_t	*gidp	= gbm->gid_array;
				int	numgids	= gbm->numgids;
				int	i;

				_nss_XbyY_buf_free(buf);

				for (i = 0; i < numgids && *gidp != gid; i++,
								gidp++) {
					;
				}
				if (i >= numgids) {
					if (i >= gbm->maxgids) {
					/* Filled the array;  stop searching */
						return (NSS_SUCCESS);
					}
					*gidp = gid;
					gbm->numgids = numgids + 1;
				}
				return (NSS_NOTFOUND);	/* Explained in   */
							/* <nss_dbdefs.h> */
			}
		}
	}
	_nss_XbyY_buf_free(buf);
	return (NSS_NOTFOUND);
}
