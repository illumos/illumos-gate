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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1985 AT&T
 *      All Rights Reserved
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.3 */

#include	<stdio.h>
#include	"wish.h"
#include	"moremacros.h"

/*
 * gets the next line that does not begin with '#' or '\n', and removes
 * the trailing '\n'.  Returns buf, or NULL if EOF is encountered.
 */
char *
get_skip(buf, size, fp)
char	*buf;
int	size;
FILE	*fp;
{
	register char	*p;

	while ((p = fgets(buf, size, fp)) && (buf[0] == '#' || buf[0] == '\n'))
		;
	if (p)
		p[strlen(p) - 1] = '\0';
	return p;
}

/*
 * frees *dst, if already set, and sets it to the strsaved value of the
 * next tab delimited field.  Return value is ptr to char after the tab
 * (which is overwritten by a '\0').  If there is no field or src is
 * NULL, *dst remains unchanged and NULL is returned
 */
char *
tab_parse(dst, src)
char	**dst;
char	*src;
{
	register char	*p;
	char	*strchr();

	if (src == NULL)
		return NULL;
	while (*src == '\t')
		src++;
	if (*src == '\0')
		return NULL;
	if (*dst)
		free(*dst);
	if (p = strchr(src, '\t'))
		*p++ = '\0';
	*dst = strsave(src);
	src = p;
	return src;
}

long
tab_long(src, base)
char	**src;
{
	char	*strchr();
	long	strtol();

	if (*src == NULL || **src == '\0') {
		*src = NULL;
		return 0L;
	}
	while (**src == '\t')
		(*src)++;
	return strtol(*src, src, base);
}
