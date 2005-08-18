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
/*
    NAME
	add_recip, madd_recip - add recipients to recipient list

    SYNOPSIS
	int add_recip(reciplist *plist, char *name, int checkdups)
	void madd_recip(reciplist *plist, char *name, int checkdups)

    DESCRIPTION
	add_recip() adds the name to the recipient linked list.
	If checkdups is set, it first checks to make certain that
	the name is not in the list.

	madd_recips() is given a list of names separated by white
	space. Each name is split off and passed to add_recips.
*/

#include "mail.h"

int
add_recip(reciplist *plist, char *name, int checkdups)
{
	char		*p;
	static char	pn[] = "add_recip";
	recip		*r = &plist->recip_list;

	if ((name == (char *)NULL) || (*name == '\0')) {
		Tout(pn, "translation to NULL name ignored\n");
		return(0);
	}

	p = name;
	while (*p && !isspace(*p)) {
		p++;
	}
	if (*p != '\0') {
	    Tout(pn, "'%s' not added due to imbedded spaces\n", name);
	    return(0);
	}

	if (checkdups == TRUE) {
	    while (r->next != (struct recip *)NULL) {
		r = r->next;
		if (strcmp(r->name, name) == 0) {
			Tout(pn, "duplicate recipient '%s' not added to list\n",
									name);
			return(0);
		}
	    }
	}

	if ((p = malloc (sizeof(struct recip))) == (char *)NULL) {
		errmsg(E_MEM,"first malloc failed in add_recip()");
		done(1);
	}
	plist->last_recip->next = (struct recip *)p;
	r = plist->last_recip = plist->last_recip->next;
	if ((r->name = malloc (strlen(name)+1)) == (char *)NULL) {
		errmsg(E_MEM,"second malloc failed in add_recip()");
		done(1);
	}
	strcpy (r->name, name);
	r->next = (struct recip *)NULL;
	Tout(pn, "'%s' added to recipient list\n", name);

	return(1);
}

void
madd_recip(reciplist *plist, char *namelist, int checkdups)
{
	char	*name;
	for (name = strtok(namelist, " \t"); name; name = strtok((char*)0, " \t"))
		add_recip(plist, name, checkdups);
}
