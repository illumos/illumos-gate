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

#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1 */
/*LINTLIBRARY*/

/*
 *  listdgrp.c
 *
 *  Contents:
 *	listdgrp()	List devices that belong to a device group.
 */

/*
 * Header files referenced:
 *	<sys/types.h>	System Data Types
 *	<errno.h>	UNIX and C error definitions
 *	<string.h>	String handling definitions
 *	<devmgmt.h>	Device management definitions
 *	"devtab.h"	Local device table definitions
 */

#include	<sys/types.h>
#include	<errno.h>
#include	<string.h>
#include	<stdlib.h>
#include	<devmgmt.h>
#include	"devtab.h"

/*
 * Local definitions
 */


/*
 *  Structure definitions:
 */

/*
 * Local functions referenced
 */

/*
 * Global Data
 */

/*
 * Static Data
 */

/*
 * char **listdgrp(dgroup)
 *	char   *dgroup
 *
 *	List the members of a device group.
 *
 *  Arguments:
 *	char *dgroup	The device group needed
 *
 *  Returns:  char **
 *	A pointer to a list of pointers to char-strings containing
 *	the members of the device group.
 *
 *  Notes:
 *    -	malloc()ed space containing addresses
 */

char  **
listdgrp(char *dgroup)	/* The device group to list */
{
	/* Automatic data */
	struct dgrptabent	*dgrpent;	/* Device group description */
	struct member		*member;	/* Device group member */
	char			**listbuf;	/* Buffer allocated for addrs */
	char			**rtnval;	/* Value to return */
	char			**pp;		/* Running ptr through addrs */
	int			noerror;	/* Flag, TRUE if all's well */
	int			n;		/* Counter */


	/*
	 *  Initializations
	 */

	/*
	 *  Get the record for this device group
	 */

	if (dgrpent = _getdgrprec(dgroup)) {

	    /*  Count the number of members in the device group  */
	    n = 1;
	    for (member = dgrpent->membership; member; member = member->next)
		n++;

	    /*  Get space for the list to return  */
	    if (listbuf = malloc(n*sizeof (char **))) {

		/*
		 *  For each member in the device group, add that device
		 *  name to the list of devices we're building
		 */

		pp = listbuf;
		noerror = TRUE;
		for (member = dgrpent->membership; noerror && member;
		    member = member->next) {

		    if (*pp = malloc(strlen(member->name)+1))

			(void) strcpy(*pp++, member->name);
		    else noerror = FALSE;
		}


		/*
		 *  If there's no error, terminate the list we've built.
		 *  Otherwise, free the space allocated to the stuff we've built
		 */

		if (noerror) {
		    *pp = NULL;
		    rtnval = listbuf;
		} else {
		    /*  Some error occurred.  Clean up allocations  */
		    for (pp = listbuf; *pp; pp++) free(*pp);
		    free(listbuf);
		    rtnval = NULL;
		}

	    }  /* if (malloc()) */

	    /*  Free space alloced to the device group entry  */
	    _freedgrptabent(dgrpent);

	}  /* if (_getdgrprec()) */
	else rtnval = NULL;


	/*  Finished -- wasn't that simple?  */
	return (rtnval);
}
