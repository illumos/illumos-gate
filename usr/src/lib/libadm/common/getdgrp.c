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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

/*
 *  getdgrp.c
 *
 * Contains the following global functions:
 *	getdgrp()	Get the device groups that meet certain criteria.
 */

/*
 *  Header Files Referenced
 *	<sys/types.h>		Data Types
 *	<stdio.h>		Standard I/O definitions
 *	<string.h>		Character-string definitions
 *	<devmgmt.h>		Definitions for accessing device table files
 *	"devtab.h"		Local definitions for device tables
 */

#include	<sys/types.h>
#include	<stdio.h>
#include	<string.h>
#include	<stdlib.h>
#include	<devmgmt.h>
#include	"devtab.h"

/*
 *  Local definitions
 *	struct dgrplist		Structure that makes up the internal device
 *				group list
 *				Members:
 *				    name	Name of the device group
 *				    next	Pointer to the next in the list
 */

struct dgrplist {
	char			*name;
	struct dgrplist		*next;
};


/*
 *  Local functions
 *	initdgrplist		Initialize the internal device group list
 *	addtodgrplist		Add a device group to the device group list
 *	isindevlist		Does the device group contain a device?
 *	isincallerslist		Is a device group in the caller's list?
 *	buildreturnlist		Build list of device groups to return
 *	freedgrplist		Free the internal device group list
 */

static	void	initdgrplist(void);
static	int	addtodgrplist(struct dgrptabent *);
static	int	isindevlist(struct dgrptabent *, char **);
static	int	isincallerslist(struct dgrptabent *, char **);
static	char	**buildreturnlist(void);
static	void	freedgrplist(void);


/*
 *  Local data
 *	dgrplistfirst	First (dummy) node in the device group list
 *	dgrplistcount	Number of items in the device group list
 */

static	struct dgrplist	dgrplistfirst;
static	int		dgrplistcount;

/*
 * char **getdgrp(dgroups, criteria, options)
 *	char  **dgroups
 *	char  **criteria
 *	int	options
 *
 *	This function compiles a list of device groups containing devices
 *	that meet certain criteria and returns a pointer to the first
 *	item in that list.
 *
 *  Arguments:
 *	dgroups		The list of device groups to choose from or the list
 *			of device groups to exclude from the list (depends on
 *			"options"
 *	criteria	The criteria that a device must meet
 *	options		Indicates 1) whether to "and" the criteria or to "or"
 *			the criteria, 2) indicates whether to limit the
 *			generated list to "dgroups" or to exclude those
 *			device-groups from the list, 3) to list all device
 *			groups even if they don't contain valid devices.
 *
 *  Returns:  char **
 *	A pointer to the first address in the list of addresses of generated
 *	device groups
 */

char **
getdgrp(
	char	**dgroups,	/* List of device groups */
	char	**criteria,	/* List of criteria to meet */
	int	options)	/* Options governing the search */
{
	/*  Automatic data  */
	char			**devlist;	/* Devices that meet criteria */
	char			**plist;	/* Device groups to return */
	struct dgrptabent	*dgrp;		/* Dgrp information struct */
	int			errorflag;	/* TRUE if error occurred */
	int listallflag; /* TRUE if DTAB_LISTALL && (!criteria || !*criteria) */


	/*
	 *  Open the device-group table if needed
	 */

	if (!oam_dgroup && !_opendgrptab("r"))
		return (NULL);


	/*
	 *  Get the list of devices that meet the criteria specified
	 *  This step can be skipped if DTAB_LISTALL is requested and
	 *  there is no criteria list.
	 */

	if (((options & DTAB_LISTALL) == 0) || (criteria && *criteria)) {
	    devlist = getdev(NULL, criteria, (options & DTAB_ANDCRITERIA));
	    listallflag = FALSE;
	} else {
	    devlist = NULL;
	    listallflag = TRUE;
	}


	/*
	 *  Initialize the device group list (contains the device groups
	 *  we're accumulating)
	 */

	errorflag = FALSE;
	initdgrplist();


	/*
	 *  If no device groups were specified by the caller, accumulate all
	 *  device groups
	 */

	_setdgrptab();
	if (!dgroups || !(*dgroups)) {
	    while (!errorflag && (dgrp = _getdgrptabent())) {
		if (!dgrp->comment && (listallflag ||
		    isindevlist(dgrp, devlist)))
		    errorflag = !addtodgrplist(dgrp);
		_freedgrptabent(dgrp);
	    }
	}

	else {

	/*
	 *  If the exclusion flag is not set, build a list of device
	 *  groups that is a subset of those specified by the caller
	 */

	    if ((options & DTAB_EXCLUDEFLAG) == 0) {
		while (!errorflag && (dgrp = _getdgrptabent())) {
		    if (!dgrp->comment && isincallerslist(dgrp, dgroups) &&
			(listallflag || isindevlist(dgrp, devlist))) {
			errorflag = !addtodgrplist(dgrp);
		    }
		    _freedgrptabent(dgrp);
		}
	    }

		/*
		 *  If the exclusion flag is set, build a list of device groups
		 *  that meet the criteria and are not in the list of device
		 *  groups specified by the caller.
		 */
	    else {
		while (!errorflag && (dgrp = _getdgrptabent())) {
		    if (!dgrp->comment && !isincallerslist(dgrp, dgroups) &&
			(listallflag || isindevlist(dgrp, devlist))) {
			errorflag = !addtodgrplist(dgrp);
		    }
		    _freedgrptabent(dgrp);
		}
	    }
	}
	plist = buildreturnlist();
	freedgrplist();
	_enddgrptab();
	return (plist);
}

/*
 *  int initdgrplist()
 *
 *	Initializes the internal device group linked list
 *
 *  Arguments:  None
 *
 *  Returns:  void
 */

static void
initdgrplist(void)
{
	/*  Automatic data  */

	/*
	 *  Initialize the structure.  Dummy node points to nothing, count to
	 * zero.
	 */
	dgrplistcount = 0;
	dgrplistfirst.name = "";
	dgrplistfirst.next = NULL;
}

/*
 *  int addtodgrplist(dgrp)
 *	struct dgrptabent *dgrp
 *
 *	Adds the device group described by the "dgrp" structure to the
 *	internal list of device-groups we're accumulating.
 *
 *  Arguments:
 *	dgrp	Describes the device-group we're adding
 *
 *  Returns: int
 *	TRUE if successful, FALSE otherwise
 */

static int
addtodgrplist(struct dgrptabent *dgrp)
{
	/*  Automatic data  */
	struct dgrplist *newnode;	/* Allocated node */
	struct dgrplist	*p;		/* Running dgrp list ptr */
	struct dgrplist	*q;		/* Another Running dgrp list ptr */
	char		*newstr;	/* Space for the dgroup name */
	int		errorflag;	/* TRUE if error */
	int		cmpval;		/* Value from strcmp() */

	/*  No errors seen yet  */
	errorflag = FALSE;

	/*  Find where we're supposed to insert this item in the list  */
	q = &dgrplistfirst;
	p = q->next;
	while (p && ((cmpval = strcmp(p->name, dgrp->name)) < 0)) {
	    q = p;
	    p = p->next;
	}

	/*  If the item isn't already in the list, insert it  */
	if ((p == NULL) || (cmpval != 0)) {

	    /* Allocate space for the structure */
	    newnode = malloc(sizeof (struct dgrplist));
	    if (newnode) {

		/* Allocate space for the device group name */
		if (newstr = malloc(strlen(dgrp->name)+1)) {

		    /* Link the new structure into the list */
		    newnode->name = strcpy(newstr, dgrp->name);
		    newnode->next = p;
		    q->next = newnode;
		    dgrplistcount++;
		} else {
		    /* No space for the string.  Clean up */
		    errorflag = TRUE;
		    free(newnode);
		}
	    } else errorflag = TRUE;
	}

	/* Return a value that indicates whether we've had an error */
	return (!errorflag);
}

/*
 *  int isindevlist(dgrp, devlist)
 *	struct dgrptabent *dgrp
 *	char		 **devlist
 *
 *	This function searches the device membership list of the device
 *	group <dgrp> for any of the devices listed in the list of devices
 *	<devlist>.  It returns TRUE if at least one device in <devlist> is
 *	found in <dgrp>, otherwise it returns false.
 *
 *  Arguments:
 *	dgrp		The device group to examine
 *	devlist		The list of devices to search for
 *
 *  Returns:  int
 *	TRUE if one of the devices in <devlist> is a member of the device
 *	group <dgrp>, FALSE otherwise
 */

static int
isindevlist(
	struct dgrptabent *dgrp,	/* Dgrp to search for */
	char		**devlist)	/* List of devices to search against */
{
	/*  Automatic data  */
	struct member *pmbr;	/* Next member of the dgrp list */
	char **pdev;		/* Next device in the dev list */
	char *mbralias;		/* The alias of a group member */
	int cmpval;		/* strcmp() result */
	int notfound;		/* TRUE if no mbr of dgrp is in dev list */
	int allocflag;		/* TRUE if the mbralias string is malloc()ed */


	/*
	 *  For each device in the device group, search the alphabetically
	 *  sorted list of devices for that device.
	 */

	notfound = TRUE;
	for (pmbr = dgrp->membership; notfound && pmbr; pmbr = pmbr->next) {

	/*
	 * Get the member's alias (we've got it if the member is not a
	 * pathname)
	 */
	    allocflag = (*pmbr->name == '/');
	    if (allocflag)
		mbralias = devattr(pmbr->name, DTAB_ALIAS);
	    else mbralias = pmbr->name;

	    /* If we've got a member alias, search the device list for it */
	    if (mbralias)
		for (pdev = devlist; notfound && *pdev; pdev++)

		if ((cmpval = strcmp(mbralias, *pdev)) == 0) notfound = FALSE;
		else if (cmpval < 0)
			break;	/* Optimization:  alpha sorted list */

		/*
		 * Free the space allocated to the member alias
		 * (if it was allocated above by devattr())
		 */
	    if (allocflag) free(mbralias);

	}


	/*
	 *  Return a value indicating that we the device group contains
	 *  a member that is in the list of devices
	 */

	return (!notfound);
}

/*
 * int isincallerslist(dgrp, dgroups)
 *	struct dgrptabent *dgrp
 *	char		 **dgroups
 *
 *	This function looks through the "dgroups" list for the device
 *	group described by "dgrp"
 *
 *  Arguments:
 *	dgrp		Device group to search for
 *	dgroups		The address of the first item in the list of device
 *			groups to search
 *
 *  Returns:  int
 *	TRUE if found, FALSE otherwise
 */

static int
isincallerslist(
	struct dgrptabent *dgrp,	/* Dgrp to search for */
	char		**dgroups)	/* Caller's list of dgroups */
{
	/*  Automatic data  */
	char		**pdgrp;
	int		notfound;

	/*
	 *  Search the list of device groups for the name of the device group
	 *  in the structure described by <dgrp>.
	 */

	/*  Initializations  */
	notfound = TRUE;

	/*  Search the device group list for name of this device group  */
	for (pdgrp = dgroups; notfound && *pdgrp; pdgrp++) {
	    if (strcmp(dgrp->name, *pdgrp) == 0) notfound = FALSE;
	}

	/*  Return TRUE if the device group is in the list, FALSE otherwise  */
	return (!notfound);
}

/*
 *  char **buildreturnlist()
 *
 *	This function builds the list of pointers to device groups
 *	to return to the caller from the linked list of device-groups
 *	we've been accumulating.
 *
 *  Arguments:  none
 *
 *  Returns: char **
 *	A pointer to the first element in the malloc()ed list of pointers
 *	to malloc()ed character strings containing device groups which have
 *	member devices which match the criteria
 */

static char **
buildreturnlist(void)
{
	char		**list;		/* List being built */
	char		**pp;		/* Temp ptr within list */
	struct dgrplist	*pdgrpent;	/* Ptr into list of dgrps to return */

	/*  Allocate space for the list of pointers to device groups */
	list = malloc((dgrplistcount+1)*sizeof (char *));

	/*
	 *  For each item in the device group list, put an entry in the
	 *  list of names we're building
	 */
	if ((pp = list) != NULL) {
	    for (pdgrpent = dgrplistfirst.next; pdgrpent;
		pdgrpent = pdgrpent->next) {

		*pp++ = pdgrpent->name;
	    }
	    /*  The list ends with a null pointer  */
	    *pp = NULL;
	}

	/*  Return a pointer to the allocated list  */
	return (list);
}

/*
 *  void freedgrplist()
 *
 *	This function frees the resources allocated to the internal
 *	linked list of device groups
 *
 *  Arguments:  none
 *
 *  Returns:  void
 */

static void
freedgrplist(void)
{
	struct dgrplist		*pdgrpent;	/* Dgrp to free */
	struct dgrplist		*nextnode;	/* Next one to free */

	for (pdgrpent = dgrplistfirst.next; pdgrpent; pdgrpent = nextnode) {
	    nextnode = pdgrpent->next;
	    free(pdgrpent);
	}
}
