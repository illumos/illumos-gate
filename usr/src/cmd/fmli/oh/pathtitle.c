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
#include	<string.h>
#include	"wish.h"
#include	"sizes.h"


/*
 * note:  This subroutine depends on the fact that its argument is
 * a legal UNIX path, i.e., slash separated strings.
 */
char *
path_to_title(str, pre, width)
char	*str;
char	*pre;
int	width;
{
    static char	title[MAX_WIDTH];
    register int len;
    extern char	*Home;
    char	*strchr();

    if (width <= 0)
	width = MAX_TITLE;
    if (pre == NULL)            /* face fun and games */
	pre = Home;		
    if (pre != NULL)
    {				/* clip off pre */
	len = strlen(pre);
	if (strncmp(str, pre, len) == 0 && str[len] == '/') 
	    str += len + 1;
    }
    if ((len = strlen(str)) >= width) {
	register char	*part;	/* a component of the path */
	register int	tcount;

	/* replace part(s) of it by "..." */
	part = str + width / 2;
	while (*part != '/' && part > str)
	    part--;
	tcount = ++part - str;
	strncpy(title, str, tcount);
	/*
	 * title now has all the  leading components of the path..
	 * ..that fit completely in half of the desired width
	 */
	strcpy(&title[tcount], "..."); /* show something is missing */
	/*
	 * if there are trailing components that fit in the second half..
	 * ..tack them on
	 */
	if (part = strchr(&str[len - width + tcount + 3], '/'))	/* abs */
	    strcat(title, part);
	else	   /* tack on as much of the last component as fits. abs */
	{
	    part = &str[len];
	    while (*(--part) != '/')
		;
	    if (part <= str + tcount) /* orig. cut removed last component */
	    {
		title[tcount-1] = NULL;	/* -1 to prevent double //  */
		strncat(title, part, width -tcount -3);
	    }
	    else
		strncat(title, part, width - tcount -6);
	    strcpy(&title[width-4], "...");
	}
    }
    else
	strcpy(title, str);
    return title;
}
