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
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2 */
/*LINTLIBRARY*/

/*
 * listdev.c
 *
 *  Contains:
 *	listdev()	List attributes defined for a device
 */

/*
 *  Header files needed:
 *	<sys/types.h>	System Data Types
 *	<string.h>	Standard string definitions
 *	<devmgmt.h>	Device management definitions
 *	"devtab.h"	Local device table definitions
 */

#include	<sys/types.h>
#include	<string.h>
#include	<devmgmt.h>
#include	"devtab.h"
#include	<stdlib.h>

/*
 *  Local Definitions:
 */


/*
 *  Local, Static data:
 */

/*
 * void sortlist(list)
 *	char  **list
 *
 *	This function sorts a list of character strings
 *	so that the list is ordered alphabetically.
 *
 *  Arguments:
 *	list	The list to be sorted
 *
 *  Returns:  void
 */

static	void
sortlist(char **list)		/* List to be sorted */
{
	char  **pp;		/* Pointer to item being sorted */
	char  **qq;
	char  **rr;
	char   *t;		/* Temp for swapping pointers */

	/* If the list isn't empty ... */
	if (*list) {

	    /* Find the last item in the list */
	    for (pp = list; *pp; pp++)
		;
	    --pp;

	/*
	 * Sort 'em by sorting larger and larger portions
	 * of the list (my CSC101 fails me, I forget what
	 * this sort is called!) [Where I come from, CS
	 * is Crop Science...]
	 */

	    while (pp != list) {
		qq = pp;
		rr = --pp;
		while (*qq && (strcmp(*rr, *qq) > 0)) {
		    t = *rr;
		    *rr++ = *qq;
		    *qq++ = t;
		}
	    }
	}
}

/*
 * char **listdev(device)
 *	char   *device;
 *
 *	Generate an alphabetized list of attribute names of the
 *	attributes defined for the device <device>.
 *
 *  Arguments:
 *	device		Device who's attributes are to be listed
 *
 *  Returns: char **
 *	List of attribute names of the attributes defined for this
 *	device.  (Never empty since all devices have the "alias"
 *	attribute defined.)
 */

char **
listdev(char *device)		/* Device to describe */
{
	/*  Automatic data  */

	struct devtabent	*devtabent;	/* Ptr to devtab entry */
	struct attrval		*attrval;	/* Ptr to attr val pair */
	char			**list;		/* Ptr to alloc'd list */
	char			**rtnval;	/* Value to return */
	char			**pp;		/* Ptr to current val in list */
	int			noerror;	/* FLAG, TRUE if :-) */
	int			n;		/* Temp counter */


	/*  If the device <device> is defined ...  */
	if (devtabent = _getdevrec(device)) {

	/*
	 *  Count the number of attributes defined for the device
	 *  being sure to count the (char *) NULL that terminates
	 *  the list
	 */

	    n = 1;
	    if (devtabent->alias) n++;		/*  Alias, if defined  */
	    if (devtabent->cdevice) n++;	/*  Char spcl, if defined  */
	    if (devtabent->bdevice) n++;	/*  Blk spcl, if defined  */
	    if (devtabent->pathname) n++;	/*  Pathname, if defined  */

	    /*  Other attributes, if any  */
	    if ((attrval = devtabent->attrlist) != NULL) {
		do
		    n++;
		while ((attrval = attrval->next) != NULL);
	    }
	    noerror = TRUE;
	    if (list = malloc(n*sizeof (char *))) {
		pp = list;
		if (devtabent->alias) {
		    if (*pp = malloc(strlen(DTAB_ALIAS)+1))
			(void) strcpy(*pp++, DTAB_ALIAS);
		    else noerror = FALSE;
		}
		if (noerror && devtabent->bdevice) {
		    if (*pp = malloc(strlen(DTAB_BDEVICE)+1))

			(void) strcpy(*pp++, DTAB_BDEVICE);
		    else noerror = FALSE;
		}
		if (noerror && devtabent->cdevice) {
		    if (*pp = malloc(strlen(DTAB_CDEVICE)+1))

			(void) strcpy(*pp++, DTAB_CDEVICE);
		    else noerror = FALSE;
		}
		if (noerror && devtabent->pathname) {
		    if (*pp = malloc(strlen(DTAB_PATHNAME)+1))

			(void) strcpy(*pp++, DTAB_PATHNAME);
		    else noerror = FALSE;
		}
		if (noerror && (attrval = devtabent->attrlist)) {
		    do {
			if (*pp = malloc(strlen(attrval->attr)+1))

			    (void) strcpy(*pp++, attrval->attr);
			else noerror = FALSE;
		    } while (noerror && (attrval = attrval->next));
		}
		if (noerror) {
		    *pp = NULL;
		    sortlist(list);
		    rtnval = list;
		} else {
		    for (pp = list; *pp; pp++) free(*pp);
		    free(list);
		    rtnval = NULL;
		}
	    } else rtnval = NULL;
	} else rtnval = NULL;

	_enddevtab();

	/* Fini */
	return (rtnval);
}
