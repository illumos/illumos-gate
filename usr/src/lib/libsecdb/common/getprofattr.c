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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

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
	char		buf[NSS_BUFLEN_PROFATTR];
	profstr_t	prof;
	profstr_t	*resptr = (profstr_t *)NULL;

	(void) memset(&prof, 0, sizeof (profstr_t));

	resptr = _getprofnam(name, &prof, buf, NSS_BUFLEN_PROFATTR, &err);

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


extern int _enum_common_p(const char *, int (*)(const char *, kva_t *, void *,
    void *), void *, void *, boolean_t, int *, char *[MAXPROFS]);

/*
 * Given a profile name, gets the list of profiles found from
 * the whole hierarchy, using the given profile as root
 */
void
getproflist(const char *profileName, char **profArray, int *profcnt)
{
	/* There can't be a "," in a profile name. */
	if (strchr(profileName, KV_SEPCHAR) != NULL)
		return;

	(void) _enum_common_p(profileName, NULL, NULL, NULL, B_FALSE,
	    profcnt, profArray);
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
