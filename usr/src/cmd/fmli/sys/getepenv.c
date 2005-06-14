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
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.4 */

#include	<stdio.h>
#include	"wish.h"
#include	"moremacros.h"
#include 	"sizes.h"

/*
 * getepenv looks for name=value in environment and in $HOME/pref/.environ
 * If not present, return NULL.
 */
char *
getepenv(name)
char	*name;
{
	char	path[PATHSIZ];
	register char	*ptr;
	extern char	*Home;
	char	*anyenv();
	char	*getenv();

	if ((ptr = getAltenv(name)) || (ptr = getenv(name)))
		return strsave(ptr);
	strcpy(path, Home);
	strcat(path, "/pref/.environ");
	return anyenv(path, name);
}

/*
 * anyenv lloks in path for name=value and returns value
 * value is backslash processed and expanded before it is returned
 */
char *
anyenv(path, name)
char	*path;
char	*name;
{
	char	buf[BUFSIZ];
	char	fpbuf[BUFSIZ];
	register char	*ptr;
	register int	c;
	register FILE	*fp;
	char	*fgets();
	char	*expand();
	char	*unbackslash();

	if ((fp = fopen(path, "r")) == NULL)
		return NULL;
	setbuf(fp, fpbuf);
	/* for (each line of .environ file) */
	for (c = !EOF; c != EOF; ) {
		ptr = name;
		while (*ptr && (c = getc(fp)) == *ptr)
			ptr++;
		/* if ("name=" found) get rest of line */
		if (*ptr == '\0' && (c = getc(fp)) == '=' && fgets(buf, sizeof(buf), fp)) {
			if (buf[c = strlen(buf) - 1] == '\n')
				buf[c] = '\0';
			fclose(fp);
			return expand(unbackslash(buf));
		}
		/* skip rest of line */
		while (c != EOF && c != '\n')
			c = getc(fp);
	}
	fclose(fp);
	return NULL;
}
