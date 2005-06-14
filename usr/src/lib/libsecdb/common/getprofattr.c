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

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <nss_dbdefs.h>
#include <prof_attr.h>
#include <getxby_door.h>
#include <sys/mman.h>


/* Externs from libnsl */
extern profstr_t *_getprofnam(const char *, profstr_t *, char *, int, int *);
extern profstr_t *_getprofattr(profstr_t *, char *, int, int *);
extern void _setprofattr(void);
extern void _endprofattr(void);

static profattr_t *profstr2attr(profstr_t *);
static profstr_t *process_getprof(profstr_t *, char *, int, nsc_data_t *);


profattr_t *
getprofattr()
{
	int		err = 0;
	char		buf[NSS_BUFLEN_PROFATTR];
	profstr_t	prof;
	profstr_t	*tmp;

	tmp = _getprofattr(&prof, buf, NSS_BUFLEN_PROFATTR, &err);
	return (profstr2attr(tmp));
}


profattr_t *
getprofnam(const char *name)
{
	int		err = 0;
	int		ndata = 0;
	int		adata = 0;
	char		buf[NSS_BUFLEN_PROFATTR];
	profstr_t	prof;
	union {
		nsc_data_t 	s_d;
		char		s_b[1024];
	} space;
	nsc_data_t	*sptr = (nsc_data_t *)NULL;
	profstr_t	*resptr = (profstr_t *)NULL;

	(void) memset(&prof, 0, sizeof (profstr_t));

#ifdef	PIC
	(void) memset(&space, 0, sizeof (space));

	if ((name == NULL) ||
	    (strlen(name) >= (sizeof (space) - sizeof (nsc_data_t)))) {
		errno = ERANGE;
		return ((profattr_t *)NULL);
	}
	ndata = sizeof (space);
	adata = strlen(name) + sizeof (nsc_call_t) + 1;
	space.s_d.nsc_call.nsc_callnumber = GETPROFNAM;
	(void) strcpy(space.s_d.nsc_call.nsc_u.name, name);
	sptr = &space.s_d;

	switch (_nsc_trydoorcall(&sptr, &ndata, &adata)) {
	case SUCCESS:	/* positive cache hit */
		break;
	case NOTFOUND:	/* negative cache hit */
		return ((profattr_t *)NULL);
	default:
		(void) memset(&prof, 0, sizeof (profattr_t));
		resptr = _getprofnam(name, &prof, buf,
		    NSS_BUFLEN_PROFATTR, &err);
		return (profstr2attr(resptr));
	}
	resptr = process_getprof(&prof, buf, NSS_BUFLEN_PROFATTR, sptr);

	/*
	 * check if doors reallocated the memory underneath us
	 * if they did munmap it or suffer a memory leak
	 */
	if (sptr != &space.s_d)
		(void) munmap((void *)sptr, ndata);
#else	/* !PIC */
	resptr = _getprofnam(name, &prof, buf, NSS_BUFLEN_PROFATTR, &err);
#endif	/* PIC */

	return (profstr2attr(resptr));

}


void
setprofattr()
{
	_setprofattr();
}


void
endprofattr()
{
	_endprofattr();
}


void
free_profattr(profattr_t *prof)
{
	if (prof) {
		free(prof->name);
		free(prof->res1);
		free(prof->res2);
		free(prof->desc);
		_kva_free(prof->attr);
		free(prof);
	}
}


static profattr_t *
profstr2attr(profstr_t *prof)
{
	profattr_t *newprof;

	if (prof == NULL)
		return ((profattr_t *)NULL);

	if ((newprof = (profattr_t *)malloc(sizeof (profattr_t))) == NULL)
		return ((profattr_t *)NULL);

	newprof->name = _do_unescape(prof->name);
	newprof->res1 = _do_unescape(prof->res1);
	newprof->res2 = _do_unescape(prof->res2);
	newprof->desc = _do_unescape(prof->desc);
	newprof->attr = _str2kva(prof->attr, KV_ASSIGN, KV_DELIMITER);
	return (newprof);
}


static profstr_t *
process_getprof(
	profstr_t *result,
	char *buffer,
	int buflen,
	nsc_data_t *sptr)
{
	char *fixed;
#ifdef	_LP64
	profstr_t prof64;

	fixed = (char *)(((uintptr_t)buffer + 7) & ~7);
#else
	fixed = (char *)(((uintptr_t)buffer + 3) & ~3);
#endif
	buflen -= fixed - buffer;
	buffer = fixed;

	if (sptr->nsc_ret.nsc_return_code != SUCCESS)
		return ((profstr_t *)NULL);

#ifdef	_LP64
	if (sptr->nsc_ret.nsc_bufferbytesused - (int)sizeof (profstr32_t)
	    > buflen)
#else
	if (sptr->nsc_ret.nsc_bufferbytesused - (int)sizeof (profstr_t)
	    > buflen)
#endif
	{
		errno = ERANGE;
		return ((profstr_t *)NULL);
	}

#ifdef	_LP64
	(void) memcpy(buffer, (sptr->nsc_ret.nsc_u.buff + sizeof (profstr32_t)),
	    (sptr->nsc_ret.nsc_bufferbytesused - sizeof (profstr32_t)));
	prof64.name = (char *)(sptr->nsc_ret.nsc_u.prof.name +
	    (uintptr_t)buffer);
	prof64.res1 = (char *)(sptr->nsc_ret.nsc_u.prof.res1 +
	    (uintptr_t)buffer);
	prof64.res2 = (char *)(sptr->nsc_ret.nsc_u.prof.res2 +
	    (uintptr_t)buffer);
	prof64.desc = (char *)(sptr->nsc_ret.nsc_u.prof.desc +
	    (uintptr_t)buffer);
	prof64.attr = (char *)(sptr->nsc_ret.nsc_u.prof.attr +
	    (uintptr_t)buffer);
	*result = prof64;
#else
	sptr->nsc_ret.nsc_u.prof.name += (uintptr_t)buffer;
	sptr->nsc_ret.nsc_u.prof.res1 += (uintptr_t)buffer;
	sptr->nsc_ret.nsc_u.prof.res2 += (uintptr_t)buffer;
	sptr->nsc_ret.nsc_u.prof.desc += (uintptr_t)buffer;
	sptr->nsc_ret.nsc_u.prof.attr += (uintptr_t)buffer;
	*result = sptr->nsc_ret.nsc_u.prof;
	(void) memcpy(buffer, (sptr->nsc_ret.nsc_u.buff + sizeof (profstr_t)),
	    (sptr->nsc_ret.nsc_bufferbytesused - sizeof (profstr_t)));
#endif
	return (result);
}


/*
 * Given a profile name, gets the list of profiles found from
 * the whole hierarchy, using the given profile as root
 */
void
getproflist(const char *profileName, char **profArray, int *profcnt)
{
	profattr_t	*profattr;
	char		*subprofiles, *lasts, *profname;
	int		i;

	/* Check if this is a duplicate */
	for (i = 0; i < *profcnt; i++) {
		if (strcmp(profileName, profArray[i]) == 0) {
			/* It's a duplicate, don't need to do anything */
			return;
		}
	}

	profArray[*profcnt] = strdup(profileName);
	*profcnt = *profcnt + 1;

	profattr = getprofnam(profileName);
	if (profattr == NULL) {
		return;
	}

	if (profattr->attr == NULL) {
		free_profattr(profattr);
		return;
	}

	subprofiles = kva_match(profattr->attr, PROFATTR_PROFS_KW);
	if (subprofiles == NULL) {
		free_profattr(profattr);
		return;
	}

	/* get execattr from each subprofiles */
	for (profname = (char *)strtok_r(subprofiles, ",", &lasts);
	    profname != NULL;
	    profname = (char *)strtok_r(NULL, ",", &lasts)) {
			getproflist(profname, profArray, profcnt);
	}
	free_profattr(profattr);
}

void
free_proflist(char **profArray, int profcnt)
{
	int i;
	for (i = 0; i < profcnt; i++) {
		free(profArray[i]);
	}
}


#ifdef DEBUG
void
print_profattr(profattr_t *prof)
{
	extern void print_kva(kva_t *);
	char *empty = "empty";

	if (prof == NULL) {
		printf("NULL\n");
		return;
	}

	printf("name=%s\n", prof->name ? prof->name : empty);
	printf("res1=%s\n", prof->res1 ? prof->res1 : empty);
	printf("res2=%s\n", prof->res2 ? prof->res2 : empty);
	printf("desc=%s\n", prof->desc ? prof->desc : empty);
	printf("attr=\n");
	print_kva(prof->attr);
	fflush(stdout);
}
#endif  /* DEBUG */
