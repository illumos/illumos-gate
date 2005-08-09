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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

# include	<errno.h>
# include	<stdio.h>
# include	<stdlib.h>

# include	"lp.h"
# include	"users.h"

static long pri;

/*
  Input:  Path name of the user priority file.  It has the following
		format:
	1 line with a number representing the default priority level.
		This must be the first line of the file, and no extra
		white space is allowed between the priority value and
		the newline.
	1 line anywhere in the file with a number representing
		the default priority limit.  This number is followed
		by a ':', and no extra white space is allowed.
	any number of lines with a number followed by a ':', followed
		by a white space (blank, tab or newline) separated
		list of user names.  No white space is allowed
		between the priority value and the colon (:), but any
		amount is ok in the UID list.

  Note:  If the default priority level is missing, a value of 20 will
	be used.  If the default limit is missing, zero will be used.
	Also, the st_priority_file writes out the priority file in the
	same order as the fields occur in the user_priority structure,
	but the only order restriction is that the default level is
	the first this.  A priority level may occur more than once, and
	this function will group them together (but the defaults may
	only occur once, however the defaults may occur only once each.

  Output:  This function returns a pointer to a statically stored
	structure containing the priority information.

   Effect:  The user priority file is read and parsed.  Storage for
	the priorities are allocated and loaded.  In case of an error,
	it prints out an error message, and returns 0 (NULL).
*/

struct user_priority * ld_priority_file ( char * path )
{
    char				line[BUFSIZ],
					*p,
					*user,
					*next_user();
    static struct user_priority		pri_tbl;
    int					line_no	= 1,
    					opri;
    int fd;

    if ((fd = open_locked(path, "r", 0)) < 0) {
	if (errno == ENOENT) {
empty:
	    pri_tbl.deflt = LEVEL_DFLT;
	    pri_tbl.deflt_limit = LIMIT_DFLT;
	    memset ((char *)pri_tbl.users, 0, sizeof(pri_tbl.users));
	    return (&pri_tbl);
	}
	return(0);
    }

    /* initialize table to empty */
    pri_tbl.deflt = -1;
    pri_tbl.deflt_limit = -1;
    memset ((char *)pri_tbl.users, 0, sizeof(pri_tbl.users));

    /* this loop reads the line containing the default priority,
       if any, and the first priority limit.  p is left pointing
       to the colon (:) in the line with the first limit. */

    while (1)
    {
	if (!(p = fdgets(line, BUFSIZ, fd)))
	    goto empty;
	p = line;
	pri = strtol(line, &p, 10);
	if (p == line)
	    goto Error;
	if (pri < PRI_MIN || pri > PRI_MAX)
	    goto Error;
	if (line_no == 1 && *p == '\n' && !p[1])
	    pri_tbl.deflt = pri;
	else
	    if (*p == ':')
	    {
		p++;
		break;
	    }
	    else
		goto Error;
	line_no++;
    }

    do
    {
	/* search list for this priority */
	opri = pri;
	if (!(user = next_user(fd, line, &p)))
	{
	    if (pri_tbl.deflt_limit == -1)
	    {
		pri_tbl.deflt_limit = opri;
		if (pri == -1) break;
		if (!(user = next_user(fd, line, &p))) goto Error;
	    }
	    else
	    {
Error:
	        errno = EBADF;
		close(fd);
		return(0);
	    }
	}

	do
	{
	    add_user (&pri_tbl, user, pri);
	}
	while ((user = next_user(fd, line, &p)));
    }
    while (pri != -1);

    if (pri_tbl.deflt == -1)
	pri_tbl.deflt = LEVEL_DFLT;

    if (pri_tbl.deflt_limit == -1)
	pri_tbl.deflt_limit = LIMIT_DFLT;

    close(fd);
    return (&pri_tbl);
}

/*
Inputs:  A pointer to a limit structure, and a user.
Ouputs:  The limit structure is modified.
Effects: Adds <user> to the list of users, if it is not already
	 there.
*/

int add_user ( struct user_priority * ppri_tbl, char * user, int limit )
{
    if (limit < PRI_MIN || PRI_MAX < limit)
	return 1;
    addlist (&(ppri_tbl->users[limit - PRI_MIN]), user);
    return 0;
}

/*
Inputs:   The input file to read additional lines, a pointer to
	  a buffer containing the current line, and to read additional
	  lines into, and a pointer to the location pointer (a pointer
	  into buf).
Outputs:  The routine returns the next user-id read or 0 if all the
	  users for this priority are read.  The buffer, the location
	  pointer, and the variable pri are modified as a side effect.
Effects:  The input buffer is scanned starting at *pp for the next
	  user-id, if the end of the line is reached, the next line is
	  read from the file.  If it scans the next priority value, the
	  variable pri (static to this file), is set to that priority.
	  EOF is indicated by setting this variable to -1, and also
	  returning 0.
*/
char * next_user (int fd, char * buf, char ** pp )
{
    long	temp;
    char	*p;
    static	int beg_line = 0; /* assumes a partial line is in buf to start */

    do
    {
	while (**pp == ' ' || **pp == '\n' || **pp == '\t')
	    (*pp)++;
	p = *pp;
	if (*p)
	{
	    if (*p >= '0' && *p <= '9')
	    {
		temp = strtol(p, pp, 10);
		if (beg_line && **pp == ':')
		{
		    (*pp)++;
		    pri = temp;
		    beg_line = 0;
		    return (0);
		}
	    }

	    for (; **pp && **pp != ' ' && **pp != '\n' && **pp != '\t'; (*pp)++)
		;
	    if (**pp)
		*(*pp)++ = 0;
	    beg_line = 0;
	    return (p);
	}
	beg_line = 1;
    }
    while (*pp = fdgets(buf, BUFSIZ, fd));

    pri = -1;
    return (0);
}

/*
Inputs:  A pointer to a priority table and a user.
Outputs: Zero if user found, else 1, and priority table is modified.
Effects: All occurences of <user> in the priority table will be removed.
	 (There should only be one at most.)
*/
int del_user ( struct user_priority * ppri_tbl, char * user )
{
    int		limit;

    for (limit = PRI_MIN; limit <= PRI_MAX; limit++)
	if (searchlist(user, ppri_tbl->users[limit - PRI_MIN]))
	{
	    dellist (&(ppri_tbl->users[limit - PRI_MIN]), user);
	    return (0);
	}
    return (1);
}
