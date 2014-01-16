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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.13	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "string.h"
#include "errno.h"
#include "stdlib.h"
#include "regexpr.h"

#include "lp.h"
#include "filters.h"

static char		*keyword_list[] = {
	PARM_INPUT,
	PARM_OUTPUT,
	PARM_TERM,
	PARM_PRINTER,
	PARM_CPI,
	PARM_LPI,
	PARM_LENGTH,
	PARM_WIDTH,
	PARM_PAGES,
	PARM_CHARSET,
	PARM_FORM,
	PARM_COPIES,
	PARM_MODES,
	0
};

#if	defined(__STDC__)
static char *		q_strchr ( char * , char );
static char *		q_strdup ( char * );
#else
static char		*q_strchr(),
			*q_strdup();
#endif

/**
 ** s_to_filtertype() - CONVERT (char *) TO (FILTERTYPE)
 **/

FILTERTYPE
#if	defined(__STDC__)
s_to_filtertype (
	char *			str
)
#else
s_to_filtertype (str)
	char			*str;
#endif
{
	/*
	 * The default type, if none is given, is ``slow''.
	 */
	if (STREQU(str, FL_FAST))
		return (fl_fast);
	else
		return (fl_slow);
}

/**
 ** s_to_type() - CONVERT (char *) TO (TYPE) 
 **/

TYPE
#if	defined(__STDC__)
s_to_type (
	char *			str
)
#else
s_to_type (str)
	register char		*str;
#endif
{
	TYPE			ret;

	if ((ret.name = Strdup(str)))
		ret.info = isterminfo(str);
	return (ret);
}

/**
 ** s_to_template() - CONVERT (char *) TO (TEMPLATE)
 **/

TEMPLATE
#if	defined(__STDC__)
s_to_template (
	char *			str
)
#else
s_to_template (str)
	register char		*str;
#endif
{
	TEMPLATE		ret;

	register char		*p,
				c;
	

	if (!*(str += strspn(str, " "))) {
		lp_errno = LP_ETEMPLATE;
		ret.keyword = 0;
		goto Done;
	}

	if (!(p = strchr(str, ' '))) {
		lp_errno = LP_EPATTERN;
		ret.keyword = 0;
		goto Done;
	}

	c = *p;
	*p = 0;
	ret.keyword = Strdup(str);
	*p = c;

	if (!ret.keyword) {
		lp_errno = LP_ENOMEM;
		goto Done;
	}
	if (!searchlist(ret.keyword, keyword_list)) {
		lp_errno = LP_EKEYWORD;
		ret.keyword = 0;
		goto Done;
	}

	str = p + strspn(p, " ");
	if (!(p = q_strchr(str, '='))) {
		lp_errno = LP_ERESULT;
		ret.keyword = 0;
		goto Done;
	}
	while (p[-1] == ' ' && p > str)
		p--;

	c = *p;
	*p = 0;
	ret.pattern = q_strdup(str);
	*p = c;

	if (!ret.pattern) {
		lp_errno = LP_ENOMEM;
		ret.keyword = 0;
		goto Done;
	}

	if (!*ret.pattern) {
		lp_errno = LP_EPATTERN;
		ret.keyword = 0;
		goto Done;
	}

	if (!(ret.re = compile(ret.pattern, (char *)0, (char *)0))) {
		lp_errno = LP_EREGEX;
		ret.keyword = 0;
		goto Done;
	}
	ret.nbra = nbra;

	if (!*(str = p + strspn(p, " ="))) {
		lp_errno = LP_ERESULT;
		ret.keyword = 0;
		goto Done;
	}
	ret.result = q_strdup(str);
	if (!ret.result) {
		lp_errno = LP_ENOMEM;
		ret.keyword = 0;
	}

Done:	return (ret);		
}

/**
 ** sl_to_typel() - CONVERT (char **) LIST TO (TYPE *) LIST
 **/

TYPE *
#if	defined(__STDC__)
sl_to_typel (
	char **			src
)
#else
sl_to_typel (src)
	char			**src;
#endif
{
	register TYPE		*dst;

	register int		nitems,
				n;

	if (!src || !*src)
		return (0);

	for (nitems = 0; src[nitems]; nitems++)
		;

	if (!(dst = (TYPE *)Malloc((nitems + 1) * sizeof(TYPE)))) {
		errno = ENOMEM;
		return (0);
	}

	for (n = 0; n < nitems; n++)
		dst[n] = s_to_type(src[n]);
	dst[nitems].name = 0;

	return (dst);
}

/**
 ** sl_to_templatel() - DUPLICATE A (char **) LIST AS (TEMPLATE *) LIST
 **/

TEMPLATE *
#if	defined(__STDC__)
sl_to_templatel (
	char **			src
)
#else
sl_to_templatel (src)
	register char		**src;
#endif
{
	register TEMPLATE	*dst;

	register int		nitems,
				n;

	if (!src || !*src)
		return (0);

	for (nitems = 0; src[nitems]; nitems++)
		;

	if (!(dst = (TEMPLATE *)Malloc((nitems + 1) * sizeof(TEMPLATE)))){
		errno = ENOMEM;
		return (0);
	}

	for (n = 0; n < nitems; n++) {
		dst[n] = s_to_template(src[n]);
		if (dst[n].keyword == 0) {
			freetempl (dst);
			return (0);
		}
	}
	dst[nitems].keyword = 0;

	return (dst);
}

/**
 ** type_to_s() - CONVERT (TYPE) TO (char *)
 **/

char *
#if	defined(__STDC__)
type_to_s (
	TYPE			t
)
#else
type_to_s (t)
	TYPE			t;
#endif
{
	return (Strdup(t.name));
}

/**
 ** template_to_s() - CONVERT (TEMPLATE) TO (char *)
 **/

char *
#if	defined(__STDC__)
template_to_s (
	TEMPLATE		t
)
#else
template_to_s (t)
	TEMPLATE		t;
#endif
{
	register char		*ret,
				*p,
				*r;

	register size_t		len;


	len  = strlen(t.keyword) + 1;
	for (p = t.pattern; *p; p++) {
		if (*p == '=')
			len++;
		len++;
	}
	len += 3 + strlen(t.result);

	ret = Malloc(len + 1);
	if (!ret) {
		errno = ENOMEM;
		return (0);
	}

	r = ret;
	for (p = t.keyword; *p; )
		*r++ = *p++;
	*r++ = ' ';
	for (p = t.pattern; *p; ) {
		if (*p == '=')
			*r++ = '\\';
		*r++ = *p++;
	}
	*r++ = ' ';
	*r++ = '=';
	*r++ = ' ';
	for (p = t.result; *p; )
		*r++ = *p++;
	*r = 0;

	return (ret);
}

/**
 ** typel_to_sl() - DUPLICATE (TYPE *) LIST AS (char **) LIST
 **/

char **
#if	defined(__STDC__)
typel_to_sl (
	TYPE *			src
)
#else
typel_to_sl (src)
	TYPE			*src;
#endif
{
	register char		**dst;

	register size_t		nitems;

	register int		n;


	if (!src || !src->name)
		return (0);

	for (nitems = 0; src[nitems].name; nitems++)
		;

	if (!(dst = (char **)Malloc((nitems + 1) * sizeof(char *)))) {
		errno = ENOMEM;
		return (0);
	}

	for (n = 0; n < nitems; n++)
		dst[n] = type_to_s(src[n]);
	dst[nitems] = 0;

	return (dst);
}

/**
 ** templatel_to_sl() - DUPLICATE A (TEMPLATE *) LIST AS (char **) LIST
 **/

char **
#if	defined(__STDC__)
templatel_to_sl (
	TEMPLATE *		src
)
#else
templatel_to_sl (src)
	register TEMPLATE	*src;
#endif
{
	register char		**dst;

	register size_t		nitems;

	register int		n;


	if (!src || !src->keyword)
		return (0);

	for (nitems = 0; src[nitems].keyword; nitems++)
		;

	if (!(dst = (char **)Malloc((nitems + 1) * sizeof(char *)))) {
		errno = ENOMEM;
		return (0);
	}

	for (n = 0; n < nitems; n++)
		dst[n] = template_to_s(src[n]);
	dst[nitems] = 0;

	return (dst);
}

/**
 ** q_strpbrk() - strpbrk() WITH BACKSLASH QUOTING
 ** q_strdup() - strdup() WITH BACKSLASHES OMITTED
 **/

static char *
#if	defined(__STDC__)
q_strchr (
	char *			sp,
	char			c
)
#else
q_strchr (sp, c)
	register char		*sp,
				c;
#endif
{
	do {
		if (*sp == '\\' && sp[1])
			sp += 2;
		if (*sp == c)
			return (sp);
	} while (*sp++);
	return (0);
}

static char *
#if	defined(__STDC__)
q_strdup (
	char *			str
)
#else
q_strdup (str)
	char			*str;
#endif
{
	char			*ret;

	register char		*p,
				*q;

	register int		len	= 0;


	for (p = str; *p; p++) {
		if (*p == '\\' && p[1] == '=')
			p++;
		len++;
	}

	if (!(ret = q = Malloc(len + 1)))
		return (0);

	for (p = str; *p; p++) {
		if (*p == '\\' && p[1] == '=')
			p++;
		*q++ = *p;
	}
	*q = 0;

	return (ret);
}
