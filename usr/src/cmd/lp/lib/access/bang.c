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
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "string.h"
#include "unistd.h"
#include "stdlib.h"
#include "sys/utsname.h"

#include "lp.h"

/*
 * The rules:
 *
 *	Key:	A - some system
 *		X - some user
 *
 *	X	a user named X on the local system
 *	A!X	the user named X from the system A
 *	all!X	all users named X from any system
 *	all	all users from local system
 *	A!all	all users from the system A
 *	all!all	all users from any system
 */


/**
 ** bangequ() - LIKE STREQU, BUT HANDLES system!name CASES
 **/

int
bangequ (char *user1p, char *user2p)
{
	int	sysname1_all	= 0,
		username1_all	= 0;
	int	sysname2_all	= 0,
		username2_all	= 0;
	char	sysname1[BUFSIZ],
		sysname2[BUFSIZ];
	char	username1[BUFSIZ],
		username2[BUFSIZ],
		*sp;

	static	char *Nodenamep = (char *) 0;

	if (! user1p || ! user2p)
		return	1;

	if (! Nodenamep) {
		struct utsname	utsbuf;

		(void)	uname (&utsbuf);
		Nodenamep = Strdup (utsbuf.nodename);
	}

	/* pattern=all */
	if (STREQU (NAME_ALL, user2p) || STREQU(NAME_ALL, user1p))
		return	1;

	if ((sp = strrchr(user1p, '@')) != NULL) {	 /* user@host */
		*sp++ = '\0';
		(void) snprintf(sysname1, sizeof (sysname1), "%s", sp);
		(void) snprintf(username1, sizeof (username1), "%s", user1p);
		*--sp = '@';
	} else if ((sp = strchr(user1p, '!')) != NULL) { /* host!user */
		*sp++ = '\0';
		(void) snprintf(sysname1, sizeof (sysname1), "%s", user1p);
		(void) snprintf(username1, sizeof (username1), "%s", sp);
		*--sp = '!';
	} else {					 /* user */
		(void) snprintf(sysname1, sizeof (sysname1), "%s", Nodenamep);
		(void) snprintf(username1, sizeof (username1), "%s", user1p);
	}

	sysname1_all = STREQU (NAME_ALL, sysname1);
	username1_all = STREQU (NAME_ALL, username1);

	/* user2p is simple user name */
	if (strpbrk (user2p, "!@") == NULL)
		return	(username1_all && sysname1_all) ||
			 STREQU (username1, user2p);

	if ((sp = strrchr(user2p, '@')) != NULL) {	 /* user@host */
		*sp++ = '\0';
		(void) snprintf(sysname2, sizeof (sysname2), "%s", sp);
		(void) snprintf(username2, sizeof (username2), "%s", user2p);
		*--sp = '@';
	} else if ((sp = strchr(user2p, '!')) != NULL) { /* host!user */
		*sp++ = '\0';
		(void) snprintf(sysname2, sizeof (sysname2), "%s", user2p);
		(void) snprintf(username2, sizeof (username2), "%s", sp);
		*--sp = '!';
	} else {					 /* user */
		(void) snprintf(sysname2, sizeof (sysname2), "%s", Nodenamep);
		(void) snprintf(username2, sizeof (username2), "%s", user1p);
	}

	sysname2_all = STREQU (NAME_ALL, sysname2);
	username2_all = STREQU (NAME_ALL, username2);

	if ((sysname1_all && username1_all) ||
	    (sysname2_all && username2_all) ||
	    (sysname1_all && username2_all) ||
	    (sysname2_all && username1_all))
		return 1;

	if (sysname1_all || sysname2_all)
		return	STREQU (username1, username2);

	if (username1_all || username2_all)
		return STREQU (sysname1, sysname2);

	if (STREQU (sysname1, sysname2) && STREQU (username1, username2))
		return 1;

	return 0;
}

/**
 ** bang_searchlist() - SEARCH (char **) LIST FOR "system!user" ITEM
 **/
int
bang_searchlist(char *item, char **list)
{
	if (!list || !*list)
		return (0);

	/*
	 * This is a linear search--we believe that the lists
	 * will be short.
	 */
	while (*list) {
		if (bangequ(item, *list))
			return (1);
		list++;
	}
	return (0);
}

/**
 ** bang_dellist() - REMOVE "system!name" ITEM FROM (char **) LIST
 **/

int
bang_dellist(char ***plist, char *item)
{
	register char **	pl;
	register char **	ql;

	register int		n;

				/*
				 * "hole" is a pointer guaranteed not
				 * to point to anyplace malloc'd.
				 */
	char *			hole	= "";


	/*
	 * There are two ways this routine is different from the
	 * regular "dellist()" routine: First, the items are of the form
	 * ``system!name'', which means there is a two part matching
	 * for ``all'' cases (all systems and/or all names). Second,
	 * ALL matching items in the list are deleted.
	 *
	 * Now suppose the list contains just the word ``all'', and
	 * the item to be deleted is the name ``foo''. What will
	 * happen? The word ``all'' will be deleted, leaving the list
	 * empty (null)! This may sound odd at first, but keep in mind
	 * that this routine is paired with the regular "addlist()"
	 * routine; the item (``foo'') is ADDED to an opposite list
	 * (we are either deleting from a deny list and adding to an allow
	 * list or vice versa). So, to continue the example, if previously
	 * ``all'' were allowed, removing ``foo'' from the allow list
	 * does indeed empty that list, but then putting it in the deny
	 * list means only ``foo'' is denied, which is the effect we
	 * want.
	 */

	if (*plist) {

		for (pl = *plist; *pl; pl++)
			if (bangequ(item, *pl)) {
				Free (*pl);
				*pl = hole;
			}

		for (n = 0, ql = pl = *plist; *pl; pl++)
			if (*pl != hole) {
				*ql++ = *pl;
				n++;
			}

		if (n == 0) {
			Free ((char *)*plist);
			*plist = 0;
		} else {
			*plist = (char **)Realloc(
				(char *)*plist,
				(n + 1) * sizeof(char *)
			);
			if (!*plist)
				return (-1);
			(*plist)[n] = 0;
		}
	}

	return (0);
}
