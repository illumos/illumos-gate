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
 *  devattr.c
 *
 *  Contents:
 *	devattr()	Get the value of a attribute for a specific device
 */

/*
 *  Header files needed
 *	<sys/types.h>		System Data Types
 *	<stdio.h>		Standard I/O Definitions
 *	<errno.h>		Error-value definitions
 *	<string.h>		String function and constant definitions
 *	<devmgmt.h>		Device table definitions available to the world
 *	"devtab.h"		Local device table definitions
 */

#include	<sys/types.h>
#include	<stdio.h>
#include	<errno.h>
#include	<string.h>
#include	<stdlib.h>
#include	<devmgmt.h>
#include	"devtab.h"

/*
 *  Local constant definitions
 */


/*
 *  Local static data
 */

/*
 *  char *devattr(device, attr)
 *
 *	This function searches the device table, looking for the device
 *	specified by <device>.  If it finds a record corresponding to that
 *	device (see below for a definition of that correspondence), it
 *	extracts the value of the field <attr> from that record, if any.
 *	It returns a pointer to that value, or (char *) NULL if none.
 *
 *  Arguments:
 *	device		Pointer to the character-string that describes the
 *			device whose record is to be looked for
 *	attr		The device's attribute to be looked for
 *
 *  Returns:  char *
 *	A pointer to the character-string containing the value of the
 *	attribute <attr> for the device <device>, or (char *) NULL if none
 *	was found.  If the function returns (char *) NULL and the error was
 *	detected by this function, it sets "errno" to indicate the problem.
 *
 *  "errno" Values:
 *	EPERM		Permissions deny reading access of the device-table
 *			file
 *	ENOENT		The specified device-table file could not be found
 *	ENODEV		Device not found in the device table
 *	EINVAL		The device does not have that attribute defined
 *	ENOMEM		No memory available
 */

char *
devattr(
	char   *device,		/* The device ) we're to look for */
	char   *attribute)	/* The attribute to extract */
{
	/* Automatic data */
	struct devtabent	*record;	/* Retrieved record */
	struct attrval		*p;		/* attr/val records */
	char			*val;		/* Extracted value */
	char			*rtnval;	/* Value to return */
	int			found;		/* TRUE if attribute found */


	/* Get the record for the specified device */
	if (!(record = _getdevrec(device))) {
		_enddevtab();
		return (NULL);
	}

	/* Search the record for the specified attribute */
	found = FALSE;

	/* Did they ask for the device alias? */
	if (strcmp(attribute, DTAB_ALIAS) == 0) {
	    val = (record->alias != NULL) ? record->alias : "";
	    found = TRUE;
	}

	/* Did they ask for the character-special device? */
	else if (strcmp(attribute, DTAB_CDEVICE) == 0) {
	    val = (record->cdevice != NULL) ? record->cdevice : "";
	    found = TRUE;
	}

	/* Did they ask for the block-special device? */
	else if (strcmp(attribute, DTAB_BDEVICE) == 0) {
	    val = (record->bdevice != NULL) ? record->bdevice : "";
	    found = TRUE;
	}

	/* Did they ask for the pathname? */
	else if (strcmp(attribute, DTAB_PATHNAME) == 0) {
	    val = (record->pathname != NULL) ? record->pathname : "";
	    found = TRUE;
	}

	else {

	/*
	 * Didn't ask for one of the easy ones, search the attr/val
	 * structure
	 */

	    p = record->attrlist;
	    while (!found && (p)) {
		if (strcmp(p->attr, attribute) == 0) {
		    val = p->val;
		    found = TRUE;
		} else p = p->next;
	    }
	}

	/*
	 * If the attribute was found, copy it into malloc()ed space.
	 * If not, set errno appropriately; we'll return NULL
	 */

	if (found) {
	    if (rtnval = malloc(strlen(val)+1))
		(void) strcpy(rtnval, val);
	    else errno = ENOMEM;
	} else {
	    rtnval = NULL;
	    errno = EINVAL;
	}

	/* Free the space allocated to the struct devtabent structure */
	_freedevtabent(record);

	_enddevtab();

	/* Fini */
	return (rtnval);
}
