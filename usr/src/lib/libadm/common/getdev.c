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

#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4 */
/*LINTLIBRARY*/

/*
 *  getdev.c
 *
 *  Contents:
 *	getdev()	List devices that match certain criteria.
 */

/*
 * Header files referenced:
 *	<sys/types.h>	System Data Types
 *	<errno.h>	Error handling
 *	<fcntl.h>	File controlling
 *	<ctype.h>	Character types
 *	<string.h>	String handling
 *	<devmgmt.h>	Global device-management def'ns
 *	"devtab.h"	Local device-management dev'ns
 */

#include	<sys/types.h>
#include	<errno.h>
#include	<fcntl.h>
#include	<ctype.h>
#include	<string.h>
#include	<devmgmt.h>
#include	"devtab.h"
#include	<stdlib.h>

/*
 * Local definitions
 *	NULL		Nil address
 *	TRUE		Boolean TRUE
 *	FALSE		Boolean FALSE
 */

#ifndef	NULL
#define	NULL			0
#endif

#ifndef	TRUE
#define	TRUE			('t')
#endif

#ifndef	FALSE
#define	FALSE			0
#endif


/*
 *  Comparison values.  These values are placed in the struct srch
 *  structure by buildsearchlist() and are used to compare values
 *  in matches().
 *	EQUAL		Attribute must equal this value
 *	NOTEQUAL	Attribute must not equal this value
 *	EXISTS		Attribute must exist
 *	NOEXISTS	Attribute must not exist
 *	IGNORE		Ignore this entry
 *	ENDLIST		This entry ends the list
 */

#define	EQUAL			1
#define	NOTEQUAL		2
#define	EXISTS			3
#define	NOEXISTS		4
#define	IGNORE			5
#define	ENDLIST			0


/*
 *  Structure definitions:
 * 	deviceent	Defines a device that matches criteria
 *	srch		Describes a criteria
 */

struct deviceent {
	struct deviceent	*next;	/* Pointer to next item in the list */
	char			*name;	/* Presentation name of the device */
};

struct srch {
	char   *name;			/* Name of field to compare */
	char   *cmp;			/* Value to compare against */
	int	fcn;			/* Type of comparison (see above) */
};


/*
 * Local functions referenced
 *	oktoaddtolist()		Determines if device can be added to the
 *				list by examining the devices list and
 *				the options governing the search
 *	initdevicelist()	Initializes the linked list of devices
 *				to be included in the list-to-return
 *	freedevicelist()	Frees the resources allocated to the linked
 *				list of devices
 *	addtodevicelist()	Adds an entry to the linked list of devices
 *	buildsearchlist()	Builds a list of struct srch structures from
 *				the criteria strings
 *	freesearchlist()	Frees the resources allocated to the list of
 *				struct srch structures
 *	buildreturnlist()	Builds the list of devices to return from the
 *				linked list of devices we've accumulated
 *	makealiaslist()		Builds a list of aliases from the list of
 *				devices presented by the caller
 *	freealiaslist()		Frees the resources allocated to the list of
 *				devices aliases
 *	getnextmatch()		Get the next device that matches the search
 *				criteria
 *	matchallcriteria()	See if the device attributes match all of the
 *				search criteria
 *	matchanycriteria()	See if the device attributes match any of the
 *				search criteria
 *	matches()		See if the criteria and attribute match
 */

static	char		*oktoaddtolist(char   *, char  **, char  **, int);
static	void		initdevicelist(void);
static	void		freedevicelist(void);
static	int		addtodevicelist(char *);
static	struct srch	*buildsearchlist(char **);
static	void 		freesearchlist(struct srch *);
static	char		**buildreturnlist(void);
static	char		**makealiaslist(char **);
static	void		freealiaslist(char **);
static	char		*getnextmatch(struct srch *, int);
static	int		matchallcriteria(struct devtabent *, struct srch *);
static	int		matchanycriteria(struct devtabent *, struct srch *);
static	int		matches(char *, char *, int);


/*
 * Global Data
 */

/*
 * Static Data
 *	devicelisthead	The first item (dummy) in the linked list of devices
 *			we're building
 *	devicelist	Structure describing the linked list of devices
 */

static	struct deviceent	devicelisthead;
static	struct {
	struct deviceent	*head;
	int			count;
} devicelist = {&devicelisthead, 0};

/*
 *  char **getdev(devices, criteria, options)
 *	char  **devices
 *	char  **criteria
 *	int	options
 *
 *	This function builds a list of devices that match criteria,
 *	governed by the device list.
 *
 *  Arguments:
 *	devices		The list of devices to select from or the list of
 *			devices to exclude, depending on the value of
 *			"options"
 *	criteria	The list of criteria governing the device selection
 *			Of the form <attr><op><val>
 *	options		Options controlling the device selection.  May require
 *			that a device meet all of the criteria (default is
 *			any one of the criteria), or may require that the
 *			devices in the list of devices be excluded from the
 *			generated list (default is to select only those
 * 			devices in the list)
 *
 *  Returns:  char **
 *	The address of the first item in the list of devices that meet
 *	the selection criteria
 */

char  **
getdev(
	char  **devices,		/* List of devices to constrain */
	char  **criteria,		/* List of selection criteria */
	int	options)		/* Options governing the search */
{
	/* Automatic data */
	char		**aliases;	/* List of constraining devices */
	char		**returnlist;	/* List of ptrs to aliases to return */
	struct srch	*searchlist;	/* Pointer to searching criteria */
	char		*entry;		/* Pointer to alias in record */
	int		errflag;	/* FLAG:  TRUE if error */


	/*
	 *  Initializations
	 */

	/*  Make sure the exclude/include list is all aliases */
	aliases = makealiaslist(devices);
	if (devices && !aliases)
		return (NULL);

	/*  Build the search list  */
	if (criteria) {
	    if (!(searchlist = buildsearchlist(criteria)))
		return (NULL);
	} else searchlist = NULL;

	/*  Initialize searching  */
	initdevicelist();
	_setdevtab();


	/*
	 *  Keep on going until we get no more matches
	 */

	errflag = FALSE;
	while (!errflag && (entry = getnextmatch(searchlist, options))) {
	    if (entry = oktoaddtolist(entry, devices, aliases, options)) {
		errflag = addtodevicelist(entry);
	    }
	}


	/*
	 *  Clean up:
	 *    -	Free the entry space we've allocated.
	 *    -	Close the device table.
	 *    - Build the list to return to the caller.
	 *    - Free the accumulate device space (but not the strings!)
	 *    - Free the alias list
	 *    - Return the built list to the caller.
	 */

	returnlist = buildreturnlist();
	freedevicelist();
	freealiaslist(aliases);
	_enddevtab();
	return (returnlist);
}

/*
 *  char *oktoaddtolist(devtabentry, devices, aliases, options)
 *	char   *devtabentry
 *	char  **devices
 *	char  **aliases
 *	int	options
 *
 *	This function determines the device "devtabentry" can be
 *	added to the list of devices we're accumulating.  If so,
 *	it returns the device name (not the alias).
 *
 *  Arguments:
 *	devtabentry	The device alias that may or may not belong in the
 *			list we're building.
 *	devices		The devices specified by the caller
 *	aliases		The aliases of the devices specified by the caller
 *			(1-1 correspondence with "devices")
 *	options		Options controlling the search
 */

static	char *
oktoaddtolist(
	char   *devtabentry,	/* Alias to check against list */
	char  **devices,	/* List of devices to check against */
	char  **aliases,	/* List of alias of those devices */
	int	options)	/* Options governing search */
{
	/* Automatic data */
	char   *rtnval;		/* Value to return */
	int	found;		/* Flag:  TRUE if found */

	/* If there's a constraint list, is this device in it? */
	if (devices && aliases) {

	    /* Set "found" to TRUE if the device is in the list */
	    found = FALSE;
	    while (!found && *aliases) {
		if (strcmp(devtabentry, *aliases) == 0) found = TRUE;
		else {
		    devices++;
		    aliases++;
		}
	    }

	    /* Set value to return */
	    if (found)
		rtnval = (options & DTAB_EXCLUDEFLAG) ?
		    NULL : *devices;
	    else
		rtnval = (options & DTAB_EXCLUDEFLAG) ?
		    devtabentry : NULL;

	} else rtnval = devtabentry;  /* No constraint list */

	return (rtnval);
}

/*
 *  void initdevicelist()
 *
 *	This function initializes the list of accumulated devices.
 *
 *  Arguments:  None
 *
 *  Returns:  Void.
 *
 *  Notes:
 */

static	void
initdevicelist(void)
{
	/* Make the list a null list */
	(devicelist.head)->next = NULL;
	devicelist.count = 0;
}

/*
 *  void freedevicelist()
 *
 *	This function frees the resources allocated to the linked list of
 *	devices we've been accumulating.
 *
 *  Arguments:  none
 *
 *  Returns:  void
 */

static	void
freedevicelist(void)
{
	/* Automatic data */
	struct deviceent	*pdevice;	/* Pointer to current entry */
	char			*freeblk;	/* Pointer space to free */

	/* List has a dummy head node */
	pdevice = (devicelist.head)->next;
	while (pdevice) {
	    freeblk = (char *) pdevice;
	    pdevice = pdevice->next;
	    free(freeblk);
	}
}

/*
 *  int addtodevicelist(deventry)
 *	char   *deventry
 *
 * 	This function adds the device <deventry> to the list of devices already
 *	accumulated.  It will not add the device if that device already exists
 *	in the list.  The function returns 0 if successful, -1 if not with
 *	"errno" set (by functions called) to indicate the error.
 *
 *  Arguments:
 *	deventry		char *
 *				The name of the device to add to the list of
 *				accumulated devices
 *
 *  Returns:
 *	0	If successful
 *	-1	If failed.  "errno" will be set to a value that indicates the
 *		error.
 *
 *  Notes:
 *    -	The memory allocation scheme has the potential to fragment the memory
 *	in the malloc heap.  We're allocating space for a local structure,
 *	which will be freed by getdev(), then allocating space for the device
 *	name, which will be freed (maybe) by the application using getdev().
 *	Not worrying about this at the moment.
 */

static	int
addtodevicelist(char *deventry)
{
	/* Automatic data */
	struct deviceent	*p;	/* Pointer to current device */
	struct deviceent	*q;	/* Pointer to next device */
	struct deviceent	*new;	/* Pointer to the alloc'd new node */
	char			*str;	/* Pointer to alloc'd space for name */
	int			rtncd;	/* Value to return to the caller */
	int			cmpcd;	/* strcmp() value, comparing names */
	int			done;	/* Loop control, TRUE if done */


	/* Initializations */
	rtncd = FALSE;


	/*
	 * Find the place in the found device list devicelist where this
	 * device is to reside
	 */

	p = devicelist.head;
	done = FALSE;
	while (!done) {
	    q = p->next;
	    if (!q) done = TRUE;
	    else if ((cmpcd = strcmp(deventry, q->name)) <= 0) done = TRUE;
	    else p = q;
	}

	/*
	 *  If the device is not already in the list, insert it in the list
	 */

	if (!q || (cmpcd != 0)) {

	    /* Alloc space for the new node */
	    if (new = malloc(sizeof (struct deviceent))) {

		/* Alloc space for the device character string */
		if (str = malloc(strlen(deventry)+1)) {

		/*
		 * Insert an entry in the found device list containing
		 * this device name
		 */
		    new->next = q;
		    p->next = new;
		    new->name = strcpy(str, deventry);
		    devicelist.count++;
		}

		/* Couldn't alloc space for the device name.  Error. */
		else rtncd = TRUE;
	    }

	    /* Couldn't alloc space for new node in the found list.  Error. */
	    else rtncd = TRUE;

	}

	/* Return an value indicating success or failure */
	return (rtncd);
}

/*
 *  struct srch *buildsearchlist(criteria)
 *	char  **criteria
 *
 *	This function builds a list of search criteria structures from the
 *	criteria strings in the list of criteria whose first argument is
 *	specified by "criteria".
 *
 *  Arguments:
 *	criteria	The address of the first item in a list of
 *			character-strings specifying search criteria
 *
 *  Returns: struct srch *
 *	The address of the structure in the list of structures describing the
 *	search criteria.
 *
 *  Notes:
 *    -	The only "regular expression" currently supported by the
 *	kywd:exp and kywd!:exp forms is exp=*.  This function assumes
 *	that kywd:exp means "if kywd exist" and that kywd!:exp means
 *	"if kywd doesn't exist".
 */

static 	struct srch *
buildsearchlist(char **criteria)	/* Criteria from caller */
{
	/*  Automatic data  */
	struct srch	*rtnbuf;	/* Value to return */
	struct srch	*psrch;		/* Running pointer */
	char		*str;		/* Ptr to malloc()ed string space */
	char		*p;		/* Temp pointer to char */
	int		noerror;	/* TRUE if all's well */
	int		n;		/* Temp counter */
	char		**pp;		/* Running ptr to (char *) */


	/*  Initializations  */
	rtnbuf = NULL;				/* Nothing to return yet */
	noerror = TRUE;				/* No errors (yet) */

	/* If we were given any criteria ... */
	if (criteria) {

	    /* Count the number of criteria in the list */
	    for (n = 1, pp = criteria; *pp++; n++)
		;

	    /* Allocate space for structures describing the criteria */
	    if (rtnbuf = malloc(n*sizeof (struct srch))) {

		/* Build structures describing the criteria */
		pp = criteria;
		psrch = rtnbuf;
		while (noerror && *pp) {

		    /* Keep list sane for cleanup if necessary */
		    psrch->fcn = ENDLIST;

		    /* Alloc space for strings referenced by the structure */
		    if (str = malloc(strlen(*pp)+1)) {

			/* Extract field name, function, and compare string */
			(void) strcpy(str, *pp);

			/* If criteria contains an equal sign ('=') ... */
			if (p = strchr(str+1, '=')) {
			    if (*(p-1) == '!') {
				*(p-1) = '\0';
				psrch->fcn = NOTEQUAL;
			    } else {
				*p = '\0';
				psrch->fcn = EQUAL;
			    }
			    psrch->cmp = p+1;
			    psrch->name = str;
			    psrch++;
			}

			/* If criteria contains a colon (':') ... */
			else if (p = strchr(str+1, ':')) {
			    if (*(p-1) == '!') {
				*(p-1) = '\0';
				psrch->fcn = NOEXISTS;
			    } else {
				*p = '\0';
				psrch->fcn = EXISTS;
			    }
			    psrch->cmp = p+1;
			    psrch->name = str;
			    psrch++;
			}
		    } else {
			/* Unable to malloc() string space.  Clean up */
			freesearchlist(rtnbuf);
			noerror = FALSE;
		    }
		    /* Next criteria */
		    pp++;
		}
		/* Terminate list */
		if (noerror) psrch->fcn = ENDLIST;
	    }
	}

	/* Return a pointer to allocated space (if any) */
	return (rtnbuf);
}

/*
 *  void freesearchlist(list)
 *	struct srch  *list
 *
 *	This function frees the resources allocated to the searchlist <list>.
 *
 *  Arguments:
 *	list		The list whose resources are to be released.
 *
 *  Returns:  void
 */

static	void
freesearchlist(struct srch *list)
{
	/* Automatic data */
	struct srch		*psrch;		/* Running ptr to structs */


	/* Free all of the string space allocated for the structure elememts */
	for (psrch = list; psrch->fcn != ENDLIST; psrch++) {
	    free(psrch->name);
	}

	/* Free the list space */
	free(list);
}

/*
 *  char **buildreturnlist()
 *
 *	This function builds a list of addresses of character-strings
 *	to be returned from the linked-list of devices we've been
 *	building.  It returns a pointer to the first item in that list.
 *
 *  Arguments:  none
 *
 *  Returns:  char **
 *	The address of the first item in the return list
 */

static	char **
buildreturnlist(void)
{
	/* Automatic data */
	char			**list;
	char			**q;
	struct deviceent	*p;


	/*
	 * Allocate space for the return list,
	 * with space for the terminating node
	 */

	if (list = malloc((devicelist.count+1)*sizeof (char *))) {

	/*
	 * Walk the list of accumulated devices, putting pointers to
	 * device names in the list to return
	 */

	    q = list;
	    for (p = devicelist.head->next; p; p = p->next) *q++ = p->name;

	    /* End the list with a null-pointer */
	    *q = NULL;
	}


	/* Return a pointer to the list we've built */
	return (list);
}

/*
 *  char **makealiaslist(devices)
 *	char  **devices		List of aliases
 *
 *	Builds a list of aliases of the devices in the "devices"
 *	list.  This list will be terminated by (char *) NULL and
 *	will have the same number of elements as "devices".  If
 *	a device couldn't be found, that alias will be "".  There
 *	will be a one-to-one correspondence of devices to aliases
 *	in the device list "devices" and the generated list.
 *
 *  Arguments:
 *	devices		The list of devices to derive aliases from
 *
 *  Returns:  char **
 *	The address of the list of addresses of aliases.  The list
 *	and aliases will be allocated using the malloc() function.
 */

static	char **
makealiaslist(char **devices)
{
	/*  Automatic data  */
	char		**pp;		/* Running ptr to (char *) */
	char		**qq;		/* Running ptr to (char *) */
	char		**aliases;	/* List being returned */
	char		*alias;		/* Alias of current device */
	int		olderrno;	/* Value of errno on entry */
	int		noerror;	/* Flag, TRUE if all's well */
	int		n;		/* Count of entries in "devices" */


	noerror = TRUE;
	olderrno = errno;
	if (devices) {

	    /* Get the number of entries in the constaint list */
	    for (n = 1, pp = devices; *pp; pp++) n++;

	    /* Get space for the alias list */
	    if (aliases = malloc(n*sizeof (char *))) {

		/* Build the alias list */
		qq = aliases;
		for (pp = devices; noerror && *pp; pp++) {

		    /* Get the device's alias and put it in the list */
		    if (alias = devattr(*pp, DTAB_ALIAS)) *qq++ = alias;
		    else {
			errno = olderrno;
			if (alias = malloc(strlen("")+1))
			    *qq++ = strcpy(alias, "");
			else {
			    /* No space for a null string?  Yeech... */
			    for (qq = aliases; *qq; qq++) free(*qq);
			    free(aliases);
			    aliases = NULL;
			    noerror = FALSE;
			}
		    }
		}
		if (noerror)
			*qq = NULL;

	    }

	} else
		aliases = NULL;  /* No constraint list */

	/* Return ptr to generated list or NULL if none or error */
	return (aliases);
}

/*
 *  void freealiaslist(aliaslist)
 *	char  **aliaslist;
 *
 *	Free the space allocated to the aliaslist.  It frees the space
 *	allocated to the character-strings referenced by the list then
 *	it frees the list.
 *
 *  Arguments:
 *	aliaslist	The address of the first item in the list of
 *			aliases that is to be freed
 *
 *  Returns:  void
 */

static	void
freealiaslist(char **aliaslist)		/* Ptr to new device list */
{
	/* Automatic Data */
	char   **pp;			/* Running pointer */

	/* If there's a list ... */
	if (aliaslist) {

	    /* For each entry in the old list, free the entry */
	    for (pp = aliaslist; *pp; pp++) free(*pp);

	    /* Free the list */
	    free(aliaslist);
	}
}

/*
 *  char *getnextmatch(criteria, options)
 *	struct srch	       *criteria
 *	int			options
 *
 *  	Gets the next device in the device table that matches the criteria.
 *	Returns the alias of that device.
 *
 *  Arguments:
 *	criteria	The linked list of criteria to use to match a device
 *	options		Options modifying the criteria (only one that's really
 *			important is the DTAB_ANDCRITERIA flag)
 *
 *  Returns:  char *
 *	A pointer to a malloc()ed string containing the alias of the next
 *	device that matches the criteria, or (char *) NULL if none.
 */

static	char   *
getnextmatch(struct srch *criteria, int options)
{
	/* Automatic data */
	struct devtabent	*devtabent;	/* Ptr to current record */
	char			*alias;		/* Alias of device found */
	int			notdone;	/* Flag, done yet? */
	int			noerror;	/* Flag, had an error yet? */


	/*
	 *  Initializations:
	 *    -	No alias yet
	 *    - Not finished yet
	 *    -	Make sure there are criteria we're to use
	 */

	alias = NULL;
	notdone = TRUE;
	noerror = TRUE;

	/*  If we're to "and" the criteria...  */
	if (options & DTAB_ANDCRITERIA) {

	/*
	 *  Search the device table until we've got a record that matches
	 *  all of the criteria or we run out of records
	 */

	    while (notdone && (devtabent = _getdevtabent())) {
		if (!devtabent->comment) {
		    if (!criteria || matchallcriteria(devtabent, criteria)) {
			if (alias = malloc(strlen(devtabent->alias)+1))
			    (void) strcpy(alias, devtabent->alias);
			else noerror = FALSE;
			notdone = FALSE;
		    }
		}
		_freedevtabent(devtabent);
	    }
	} else {

	/*
	 *  Search the device table until we've got a record that matches
	 *  any of the criteria or we run out of records
	 */

	    while (notdone && (devtabent = _getdevtabent())) {
		if (!devtabent->comment) {
		    if (!criteria || matchanycriteria(devtabent, criteria)) {
			if (alias = malloc(strlen(devtabent->alias)+1))
			    (void) strcpy(alias, devtabent->alias);
			else noerror = FALSE;
			notdone = FALSE;
		    }
		}
		_freedevtabent(devtabent);
	    }
	}


	/* Return pointer to extracted alias (or NULL if none) */
	if ((alias == NULL) && noerror) errno = ENOENT;
	return (alias);
}

/*
 * int matchallcriteria(devtabent, criteria)
 *
 *	This function examines the record contained in "devtabent" and
 *	determines if that record meets all of the criteria specified by
 *	"criteria".
 *
 * Arguments:
 *	struct devtabent *devtabent	The device table entry to examine.
 *	struct srch    *criteria	The criteria to match.
 *
 * Returns:	int
 *	Returns TRUE if the record matches criteria, FALSE otherwise.
 */

static	int
matchallcriteria(
	struct devtabent	*ent,		/* Entry to check */
	struct srch		*criteria)	/* Criteria governing match */
{
	/* Automatic data */
	struct srch    *p;		/* Pointer to current criteria */
	struct attrval *q;		/* Pointer to current attr/val pair */
	int		notfound;	/* TRUE if attr found in list */
	int		failed;		/* TRUE if record failed to match */


	/* Test only if there's criteria to test against */
	if (criteria && (criteria->fcn != ENDLIST)) {

	    failed = FALSE;
	    for (p = criteria; !failed && (p->fcn != ENDLIST); p++) {

		/*
		 * Don't compare against this criteria if it's function is
		 * "IGNORE"
		 */
		if (p->fcn != IGNORE) {
		    if (p->fcn != NOEXISTS) {

			/*  Alias?  */
			if (strcmp(p->name, DTAB_ALIAS) == 0)
			    failed = !matches(ent->alias, p->cmp, p->fcn);

			/*  Char special device?  */
			else if (strcmp(p->name, DTAB_CDEVICE) == 0)
			    failed = !matches(ent->cdevice, p->cmp, p->fcn);

			/*  Block special device?  */
			else if (strcmp(p->name, DTAB_BDEVICE) == 0)
			    failed = !matches(ent->bdevice, p->cmp, p->fcn);

			/*  Pathname?  */
			else if (strcmp(p->name, DTAB_PATHNAME) == 0)
			    failed = !matches(ent->pathname, p->cmp, p->fcn);

			/*  Check other attributes...  */
			else {
			    notfound = TRUE;
			    q = ent->attrlist;
			    while (notfound && q) {
				if (strcmp(p->name, q->attr) == 0) {
				    notfound = FALSE;
				    if (!matches(q->val, p->cmp, p->fcn))
					failed = TRUE;
				} else q = q->next;
			    }
			    if (notfound) failed = TRUE;
			}
		    } else {
			if (strcmp(p->name, DTAB_ALIAS) == 0) failed = TRUE;
			else if (strcmp(p->name, DTAB_CDEVICE) == 0)
				failed = FALSE;
			else if (strcmp(p->name, DTAB_BDEVICE) == 0)
				failed = FALSE;
			else if (strcmp(p->name, DTAB_PATHNAME) == 0)
				failed = FALSE;
			else {
			    q = ent->attrlist;
			    while (!failed && q) {
				if (strcmp(p->name, q->attr) == 0)
					failed = TRUE;
				else q = q->next;
			    }
			}
		    }

		}  /* Search function is not "IGNORE" */

	    }  /* for loop, checking each criteria */

	}  /* if (criteria) */

	else failed = FALSE;  /* No criteria specified, it's a match */


	/* Return a value indicating if the record matches all criteria */
	return (!failed);
}

/*
 * int matchanycriteria(devtabent, criteria)
 *
 *	This function examines the record contained in "devtabent" and
 *	determines if that record meets any of the criteria specified by
 *	"criteria".
 *
 * Arguments:
 *	struct devtabent *devtabent	The device table entry to examine.
 *	struct srch      *criteria	The criteria to match.
 *
 * Returns:	int
 *	Returns TRUE if the record matches criteria, FALSE otherwise.
 */

static	int
matchanycriteria(
	struct devtabent	*ent,		/* Entry to check */
	struct srch		*criteria)	/* Criteria governing match */
{
	/* Automatic data */
	struct srch    *p;		/* Pointer to current criteria */
	struct attrval *q;		/* Pointer to current attr/val pair */
	int		matched;	/* FLAG: TRUE if record matched */
	int		found;		/* FLAG: TRUE if attribute found */


	/* Test only if there's criteria to test against */
	if (criteria && (criteria->fcn != ENDLIST)) {

	    matched = FALSE;
	    for (p = criteria; !matched && (p->fcn != ENDLIST); p++) {

		/*
		 * Don't compare against this criteria if it's function is
		 * "IGNORE"
		 */
		if (p->fcn != IGNORE) {
		    if (p->fcn != NOEXISTS) {

			/*  Alias?  */
			if (strcmp(p->name, DTAB_ALIAS) == 0)
			    matched = matches(ent->alias, p->cmp, p->fcn);

			/*  Char special device?  */
			else if (strcmp(p->name, DTAB_CDEVICE) == 0)
			    matched = matches(ent->cdevice, p->cmp, p->fcn);

			/*  Block special device?  */
			else if (strcmp(p->name, DTAB_BDEVICE) == 0)
			    matched = matches(ent->bdevice, p->cmp, p->fcn);

			/*  Pathname?  */
			else if (strcmp(p->name, DTAB_PATHNAME) == 0)
			    matched = matches(ent->pathname, p->cmp, p->fcn);

			/*  Check other attributes...  */
			else {
			    q = ent->attrlist;
			    found = FALSE;
			    while (!found && q)
				if (strcmp(p->name, q->attr) == 0) {
				    matched = matches(q->val, p->cmp, p->fcn);
				    found = TRUE;
				} else q = q->next;
			}
		    } else {
			if (strcmp(p->name, DTAB_ALIAS) == 0) matched = FALSE;
			else if (strcmp(p->name, DTAB_CDEVICE) == 0)
				matched = FALSE;
			else if (strcmp(p->name, DTAB_BDEVICE) == 0)
				matched = FALSE;
			else if (strcmp(p->name, DTAB_PATHNAME) == 0)
				matched = FALSE;
			else {
			    q = ent->attrlist;
			    matched = TRUE;
			    while (matched && q) {
				if (strcmp(p->name, q->attr) == 0)
					matched = FALSE;
				else q = q->next;
			    }
			}
		    }
		}  /* Search function is not "IGNORE" */

	    }  /* for loop, checking each criteria */

	}  /* if (criteria) */

	else matched = TRUE;  /* No criteria specified, it's a match */


	/* Return a value indicating if the record matches all criteria */
	return (matched);
}

/*
 *  int matches(value, compare, function)
 *	char   *value
 *	char   *compare
 *	int	function
 *
 *	This function sees if the operation <function> is satisfied by
 *	comparing the value <value> with <compare>.  It returns TRUE
 *	if so, FALSE otherwise.
 *
 *  Arguments:
 *	value		Value to compare
 *	compare		Value to compare against
 *	function	Function to be satisfied
 *
 *  Returns:  int
 *	TRUE if the function is satisfied, FALSE otherwise
 */

static	int
matches(char *value, char *compare, int function)
{
	/*  Automatic data  */
	int	rtn;		/* Value to return */


	if (value == NULL)
		value = "";

	/* Do case depending on the function */
	switch (function) {

	/* attr=val */
	case EQUAL:
	    rtn = (strcmp(value, compare) == 0);
	    break;

	/* attr!=val */
	case NOTEQUAL:
	    rtn = (strcmp(value, compare) != 0);
	    break;

	/* attr:* */
	case EXISTS:
	    rtn = TRUE;
	    break;

	/* attr!:* */
	case NOEXISTS:
	    rtn = FALSE;
	    break;

	/* Shouldn't get here... */
	default:
	    rtn = FALSE;
	    break;
	}

	/* Return a value indicating if the match was made */
	return (rtn);
}
