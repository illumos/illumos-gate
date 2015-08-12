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

#include "lint.h"
#include "mtlib.h"
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <euc.h>
#include <widec.h>
#include <wctype.h>
#include <limits.h>
#include <synch.h>
#include <thread.h>
#include <libintl.h>
#include "libc.h"

#include <locale.h>
#include <dlfcn.h>
#include "_loc_path.h"

static int	wdchkind_C(wchar_t);
static int	(*wdchknd)(wchar_t) = wdchkind_C;
static int	wdbindf_C(wchar_t, wchar_t, int);
static int	(*wdbdg)(wchar_t, wchar_t, int) = wdbindf_C;
static wchar_t	*wddelim_C(wchar_t, wchar_t, int);
static wchar_t	*(*wddlm)(wchar_t, wchar_t, int) = wddelim_C;
static wchar_t	(*mcfllr)(void) = NULL;
static int	(*mcwrp)(void) = NULL;
static void	*modhandle = NULL;
static int	initialized = 0;

static int
_wdinitialize(void)
{
#define	_DFLTLOCPATH_LEN	(sizeof (_DFLT_LOC_PATH) - 1)
#define	_WDMODPATH_LEN		(sizeof (_WDMOD_PATH) - 1)
	char	wdmodpath[PATH_MAX];
	char	*loc;
	size_t	loclen;
	locale_t	curloc;

	initialized = 1;

	if (modhandle)
		(void) dlclose(modhandle);

	curloc = uselocale(NULL);
	loc = current_locale(curloc, LC_CTYPE);
	loclen = strlen(loc);
	if (_DFLTLOCPATH_LEN + loclen + _WDMODPATH_LEN >= sizeof (wdmodpath)) {
		/* pathname too long */
		modhandle = NULL;
		goto C_fallback;
	}

	(void) strcpy(wdmodpath, _DFLT_LOC_PATH);
	(void) strcpy(wdmodpath + _DFLTLOCPATH_LEN, loc);
	(void) strcpy(wdmodpath + _DFLTLOCPATH_LEN + loclen, _WDMOD_PATH);

	if ((modhandle = dlopen(wdmodpath, RTLD_LAZY)) != NULL) {
		wdchknd = (int(*)(wchar_t))dlsym(modhandle, "_wdchkind_");
		if (wdchknd == NULL)
			wdchknd = wdchkind_C;
		wdbdg = (int(*)(wchar_t, wchar_t, int))dlsym(modhandle,
		    "_wdbindf_");
		if (wdbdg == NULL)
			wdbdg = wdbindf_C;
		wddlm = (wchar_t *(*)(wchar_t, wchar_t, int))
		    dlsym(modhandle, "_wddelim_");
		if (wddlm == NULL)
			wddlm = wddelim_C;
		mcfllr = (wchar_t(*)(void))dlsym(modhandle, "_mcfiller_");
		mcwrp = (int(*)(void))dlsym(modhandle, "_mcwrap_");
		return ((mcfllr && mcwrp) ? 0 : -1);
	}

C_fallback:
	wdchknd = wdchkind_C;
	wdbdg = wdbindf_C;
	wddlm = wddelim_C;
	mcfllr = NULL;
	mcwrp = NULL;
	return (-1);
}

/*
 * wdinit() initializes other word-analyzing routines according to the
 * current locale.  Programmers are supposed to call this routine every
 * time the locale for the LC_CTYPE category is changed.  It returns 0
 * when every initialization completes successfully, or -1 otherwise.
 */
/* XXX: wdinit() is not exported from libc.  Should it be? */
int
wdinit()
{
	int res;

	callout_lock_enter();
	res = _wdinitialize();
	callout_lock_exit();
	return (res);
}

/*
 * wdchkind() returns a non-negative integral value unique to the kind
 * of the character represented by given argument.
 */
int
wdchkind(wchar_t wc)
{
	int i;

	callout_lock_enter();
	if (!initialized)
		(void) _wdinitialize();
	i = (*wdchknd)(wc);
	callout_lock_exit();
	return (i);
}
static int
wdchkind_C(wchar_t wc)
{
	switch (wcsetno(wc)) {
	case 1:
		return (2);
	case 2:
		return (3);
	case 3:
		return (4);
	case 0:
		return (isascii(wc) &&
		    (isalpha(wc) || isdigit(wc) || wc == ' '));
	}
	return (0);
}

/*
 * wdbindf() returns an integral value (0 - 7) indicating binding
 *  strength of two characters represented by the first two arguments.
 * It returns -1 when either of the two character is not printable.
 */
/*ARGSUSED*/
int
wdbindf(wchar_t wc1, wchar_t wc2, int type)
{
	int i;

	callout_lock_enter();
	if (!initialized)
		(void) _wdinitialize();
	if (!iswprint(wc1) || !iswprint(wc2)) {
		callout_lock_exit();
		return (-1);
	}
	i = (*wdbdg)(wc1, wc2, type);
	callout_lock_exit();
	return (i);
}
/*ARGSUSED*/
static int
wdbindf_C(wchar_t wc1, wchar_t wc2, int type)
{
	if (csetlen(wc1) > 1 && csetlen(wc2) > 1)
		return (4);
	return (6);
}

/*
 * wddelim() returns a pointer to a null-terminated word delimiter
 * string in wchar_t type that is thought most appropriate to join
 * a text line ending with the first argument and a line beginning
 * with the second argument, with.  When either of the two character
 * is not printable it returns a pointer to a null wide character.
 */
/*ARGSUSED*/
wchar_t *
wddelim(wchar_t wc1, wchar_t wc2, int type)
{
	wchar_t *i;

	callout_lock_enter();
	if (!initialized)
		(void) _wdinitialize();
	if (!iswprint(wc1) || !iswprint(wc2)) {
		callout_lock_exit();
		return ((wchar_t *)L"");
	}
	i = (*wddlm)(wc1, wc2, type);
	callout_lock_exit();
	return (i);
}
/*ARGSUSED*/
static wchar_t *
wddelim_C(wchar_t wc1, wchar_t wc2, int type)
{
	return ((wchar_t *)L" ");
}

/*
 * mcfiller returns a printable ASCII character suggested for use in
 * filling space resulted by a multicolumn character at the right margin.
 */
wchar_t
mcfiller(void)
{
	wchar_t fillerchar;

	callout_lock_enter();
	if (!initialized)
		(void) _wdinitialize();
	if (mcfllr) {
		fillerchar = (*mcfllr)();
		if (!fillerchar)
			fillerchar = (wchar_t)'~';
		if (iswprint(fillerchar)) {
			callout_lock_exit();
			return (fillerchar);
		}
	}
	callout_lock_exit();
	return ((wchar_t)'~');
}

/*
 * mcwrap returns an integral value indicating if a multicolumn character
 * on the right margin should be wrapped around on a terminal screen.
 */
/* XXX: mcwrap() is not exported from libc.  Should it be? */
int
mcwrap(void)
{
	callout_lock_enter();
	if (!initialized)
		(void) _wdinitialize();
	if (mcwrp)
		if ((*mcwrp)() == 0) {
			callout_lock_exit();
			return (0);
		}
	callout_lock_exit();
	return (1);
}
