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
 * Copyright (c) 1996-1997, by Sun Microsystems, Inc.
 * All Rights reserved.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2 */
/* LINTLIBRARY */

/*
 * putdgrp.c
 *
 * Global Definitions:
 *	_putdgrptabrec()	Write a device-group record to a stream
 *	_rmdgrptabrec()		Remove a device-group table record
 *	_rmdgrpmems()		Remove specific members from a device group
 *	_adddgrptabrec()	Add a device-group record to the table
 */

/*
 *  G L O B A L   R E F E R E N C E S
 *
 *	Header Files
 *	Externals Referenced
 */

/*
 * Header Files
 *	<sys/types.h>		UNIX System Data Types
 *	<stdio.h>		Standard I/O definitions
 *	<fcntl.h>		Definitions for file control
 *	<errno.h>		Error handling definitions
 *	<string.h>		String Handling Definitions
 *	<unistd.h>		Standard UNIX(r) Definitions
 *	<devmgmt.h>		Device Management Definitions
 *	"devtab.h"		Local Device Management Definitions
 */

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<stdio.h>
#include	<fcntl.h>
#include	<errno.h>
#include	<string.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<devmgmt.h>
#include	"devtab.h"

/*
 *  L O C A L   D E F I N I T I O N S
 *	TDGTABNM	Name of the temporary device-group table (in the
 *			directory of the existing table)
 *	TDGTABNMLN	Number of characters added to the directory
 *			name -- the length of the device-group table temp name
 */

#define	TDGTABNM	"%sdgroup.%6.6d"
#define	TDGTABNMLN	13


/*
 * Static functions
 *	lkdgrptab	Locks the device-group table
 *	unlkdgrptab	Unlocks the device-group table
 *	mkdgrptabent	Builds a device-group table entry from the alias and the
 *			list of attr=val pairs given
 *	opennewdgrptab	Opens a new device-group table (as a temp file)
 *	mknewdgrptab	Makes the temp device-group table the new dgrptab
 *	rmnewdgrptab	Remove the temporary device-group table and free space
 *			allocated to the filename of that file.
 */

static	int			lkdgrptab(char *o_mode, short lktype);
static	int			unlkdgrptab(void);
static	struct dgrptabent	*mkdgrptabent(char *dgroup, char **members);
static	FILE			*opennewdgrptab(char **pname);
static	int			mknewdgrptab(char *tempname);
static	int			rmnewdgrptab(char *tempname);

/*
 * FILE *opennewdgrptab(pname)
 *	char   **pname
 *
 *	Generates a temporary device-group table name from the existing
 *	device-group table name (in the same directory) and opens that
 *	file for writing.  It puts a pointer to the malloc()ed space
 *	containing the temp device-group table's name at the place
 *	referenced by <pname>.
 *
 *  Arguments:
 *	pname	Pointer to the char * to contain the address of the name
 *		of the temporary file
 *
 *  Returns:  FILE *
 *	A pointer to the opened stream or (FILE *) NULL if an error occurred.
 *	If an error occurred, "errno" will be set to reflect the problem.
 */

static FILE *
opennewdgrptab(char **pname)	 /* A(ptr to temp filename's path) */
{
	char   *oldname;		/* Ptr to the dgrptab name */
	char   *buf;			/* Ptr to the temp file's name */
	char   *dirname;		/* Directory containing dgrptab */
	char   *p;			/* Ptr to last '/' in dgrptab name */
	int    fd;			/* Opened file descriptor */
	FILE   *fp;			/* Opened file pointer */
	struct stat64	sbuf;		/* stat buf for old dgrptab file */


	/* Initializations */
	fp = NULL;

	/* Get the name of the device-group table */
	if (oldname = _dgrptabpath()) {
	/*
	 * It is possible for us to have sufficient permissions to create
	 * the new file without having sufficient permissions to write the
	 * original dgrptab file.  For consistency with the operations which
	 * modify the original file by writing it directly we require write
	 * permissions for the original file in order to make a new one.
	 */
	    if ((fd = open(oldname, O_WRONLY)) == -1)
		return (NULL);

	    if (fstat64(fd, &sbuf) == -1) {
		(void) close(fd);
		return (NULL);
	    }
	    (void) close(fd);

	    /* Get the directory that the device-group table lives in */
	    if (p = strrchr(oldname, '/')) {
		*(p+1) = '\0';
		dirname = oldname;
	    } else
		dirname = "./";

	    /* Get space for the temp dgrptab pathname */
	    if (buf = malloc(TDGTABNMLN+strlen(dirname)+1)) {

		/*
		 * Build the name of the temp dgrptab and open the
		 * file.  We must reset the owner, group and perms to those
		 * of the original dgrptab file.
		 */
		(void) sprintf(buf, TDGTABNM, dirname, getpid());
		if (fp = fopen(buf, "w")) {
			*pname = buf;
			(void) fchmod(fileno(fp), sbuf.st_mode & 0777);
			(void) fchown(fileno(fp), sbuf.st_uid, sbuf.st_gid);
		} else {
			free(buf);
		}
	    }

	    /* Free the space containing the dgrptab's name */
	    free(oldname);
	}

	/* Finished.  Return what we've got */
	return (fp);
}

/*
 *  int rmnewdgrptab(tempname)
 *	char   *tempname
 *
 *	Unlink the temp dgrptab and free the memory allocated to
 *	contain the name of that file
 *
 *  Arguments:
 *	tempname	Name of the temporary file
 *
 *  Returns: int
 *	TRUE if successful, FALSE otherwise
 */

static int
rmnewdgrptab(char *tempname)
{
	/* Automatic data */
	int	noerr;

	/* Unlink the temporary file */
	noerr = (unlink(tempname) == 0);
	free(tempname);

	/* Finished */
	return (noerr);
}

/*
 *  int mknewdgrptab(tempname)
 *	char   *tempname
 *
 *	Make the temporary device-group table the new system
 *	device-group table
 *
 *  Arguments:
 *	tempname	Name of the temporary file
 *
 *  Returns:  int
 *	TRUE if successful, FALSE otherwise
 *
 *  Notes:
 *	- Need to use rename() someday instead of link()/unlink()
 *	- This code is somewhat ineffecient in that asks for the name
 *	  of the device-group table more than once.  Done so that we don't
 *	  have to manage that space, but this may be somewhat lazy.
 */

static int
mknewdgrptab(char *tempname)		/* Ptr to name of temp dgrp tab */
{
	char   *dgrpname;		/* Ptr to the dgrptab's name */
	int	noerr;			/* FLAG, TRUE if all's well */

	/* Get the dgrptab's pathname */
	if (dgrpname = _dgrptabpath()) {

	    /* Unlink the existing file */
	    if (unlink(dgrpname) == 0) {

		/* Make the temp file the real device-group table */
		noerr = (link(tempname, dgrpname) == 0) ? TRUE : FALSE;

		/* Remove the temp file */
		if (noerr) noerr = rmnewdgrptab(tempname);

	    } else noerr = FALSE;	/* unlink() failed */

	    /* Free the dgrptab's name */
	    free(dgrpname);

	} else noerr = FALSE; 	/* dgrptabpath() failed */

	/* Finished.  Return success indicator */
	return (noerr);
}

/*
 * int lkdgrptab(o_mode, lktype)
 *	char   *o_mode
 *	short	lktype
 *
 *	Lock the device-group table for writing.  If it isn't available, it
 *	waits until it is.
 *
 *  Arguments:
 *	o_mode	The open() mode to use when opening the device-group table
 *	lktype	The type of lock to apply
 *
 *  Returns:  int
 *	TRUE if successful, FALSE with errno set otherwise
 */

static int
lkdgrptab(
	char   *o_mode,				/* Open mode */
	short	lktype)				/* Lock type */
{
	/* Automatic data */
	struct flock	lockinfo;		/* File locking structure */
	int		noerr;			/* FLAG, TRUE if no error */
	int		olderrno;		/* Former value of errno */


	/* Close the device-group table (if it's open) */
	_enddgrptab();

	/* Open the device-group table for read/append */
	noerr = TRUE;
	if (_opendgrptab(o_mode)) {

	/*
	 * Lock the device-group table (for writing).  If it's not
	 * available, wait until it is, then close and open the
	 * table (modify and delete change the table!) and try
	 * to lock it again
	 */

	    /* Build the locking structure */
	    lockinfo.l_type = lktype;
	    lockinfo.l_whence = 0;
	    lockinfo.l_start = 0L;
	    lockinfo.l_len = 0L;
	    olderrno = errno;

	    /* Keep on going until we lock the file or an error happens */
	    while ((fcntl(fileno(oam_dgroup), F_SETLK, &lockinfo) == -1) &&
		!noerr) {

		/*
		 * fcntl() failed.
		 * If errno=EACCES, it's because the file's locked by someone
		 * else.  Wait for the file to be unlocked, then close and
		 * reopen the file and try the lock again.
		 */

		if (errno == EACCES) {
		    if (fcntl(fileno(oam_dgroup), F_SETLKW, &lockinfo) == -1)
			noerr = FALSE;
		    else {
			_enddgrptab();
			if (!_opendgrptab(o_mode)) noerr = FALSE;
			else errno = olderrno;
		    }

		} else noerr = FALSE;  /* fcntl() failed hard */

	    }   /* End while (fcntl() && !noerr) */

	    /* Don't keep file open if an error happened */
	    if (!noerr) _enddgrptab();

	} else noerr = FALSE;	/* _opendgrptab() failed */

	/* Done */
	return (noerr);
}

/*
 * int unlkdgrptab()
 *
 *	Unlock the locked device-group table.
 *
 *  Arguments:  None
 *
 *  Returns:  int
 *	Whatever fcntl() returns...
 */

static int
unlkdgrptab(void)
{
	/* Automatic data */
	struct flock	lockinfo;		/* Locking structure */
	int		noerr;			/* FLAG, TRUE if all's well */

	/* Build the locking structure */
	lockinfo.l_type = F_UNLCK;		/* Lock type */
	lockinfo.l_whence = 0;			/* Count from top of file */
	lockinfo.l_start = 0L;			/* From beginning */
	lockinfo.l_len = 0L;			/* Length of locked data */

	/* Unlock it */
	noerr = (fcntl(fileno(oam_dgroup), F_SETLK, &lockinfo) != -1);
	_enddgrptab();

	/* Finished */
	return (noerr);
}

/*
 * struct dgrptabent *mkdgrptabent(dgroup, members)
 *	char   *dgroup
 *	char  **members
 *
 *	This function builds a struct dgrptabent structure describing the
 *	device-group <dgroup> so that it contains the members in the
 *	membership list <members>.
 *
 *  Arguments:
 *	dgroup		The device-group being added to the device-group table
 *	members		The members of the device-group
 *
 *  Returns:  struct dgrptabent *
 *	A completed struct dgrptabent structure containing the description
 *	of the device group.  The structure, and all of the data in the
 *	structure are each in space allocated using the malloc() function
 *	and should be freed using the free() function (or the _freedgrptabent()
 *	function.
 */

static struct dgrptabent *
mkdgrptabent(
	char   *dgroup,		/* Device-group being created (or modified) */
	char  **members)	/* Members to add to that entry */
{
	/* Automatic data */
	struct dgrptabent	*ent;	/* Ptr to struct we're making */
	struct member		*prev;	/* Ptr to prev attr/val struct */
	struct member		*member;	/* Ptr to current struct */
	char			**pp;	/* Ptr into list of ptrs */
	int			noerr;	/* TRUE if all's well */


	/* No problems (yet) */
	noerr = TRUE;

	/* Get space for the structure */
	if (ent = malloc(sizeof (struct dgrptabent))) {

	    /* Fill in default values */
	    ent->name = NULL; 				/* alias */
	    ent->entryno = 0;				/* Entry no. */
	    ent->comment = FALSE;			/* data rec */
	    ent->dataspace = NULL;			/* string */
	    ent->membership = NULL;			/* attr list */

	    /* Fill in the device-group name */
	    if (ent->name = malloc(strlen(dgroup)+1)) {
		(void) strcpy(ent->name, dgroup);

		/* Add membership to the structure */
		prev = NULL;
		if ((pp = members) != NULL)
		    while (*pp && noerr) {

		    if (member = malloc(sizeof (struct member))) {

			if (member->name = malloc(strlen(*pp)+1)) {
			    (void) strcpy(member->name, *pp);
			    if (prev) prev->next = member;
			    else ent->membership = member;
			    member->next = NULL;
			    prev = member;
			} else {
			    noerr = FALSE;
			    free(member);
			}
		    } else noerr = FALSE;
		    pp++;
		}   /* End membership processing loop */

	    } else noerr = FALSE;	/* malloc() failed */

		/*
		 * If there was a problem, clean up the mess we've made
		 */

	    if (!noerr) {

		_freedgrptabent(ent);
		ent = NULL;

	    }   /* if (noerr) */

	} else noerr = FALSE;   /* if (malloc(dgrptabent space)) */

	/* Finished */
	return (ent);
}

/*
 * int _putdgrptabrec(stream, rec)
 *	FILE		       *stream
 *	struct dgrptabent      *rec
 *
 *	Write a device-group table record containing the information in the
 *	struct dgrptab structure <rec> to the current position of the
 *	standard I/O stream <stream>.
 *
 *  Arguments:
 *	stream		The stream to write to
 *	rec		The structure containing the information to write
 *
 *  Returns:  int
 *	The number of characters written or EOF if there was some error.
 */

int
_putdgrptabrec(
	FILE			*stream,	/* Stream to write to */
	struct dgrptabent	*rec)		/* Record to write */
{
	/* Automatic Data */
	struct member		*mem;		/* Ptr to attr/val pair */
	char			*buf;		/* Allocated buffer */
	char			*p;		/* Temp char pointer */
	char			*q;		/* Temp char pointer */
	int			count;		/* Number of chars written */
	int			size;		/* Size of needed buffer */


	/* Comment or data record? */
	if (rec->comment) count = fputs(rec->dataspace, stream);
	else {

	/*
	 * Record is a data record
	 */

	    /* Figure out the amount of space the record needs */
	    size = (int)strlen(rec->name) + 1;	    /* "name:" */
	    if ((mem = rec->membership) != NULL)
		do {	    /* members */
		    /* "membername " or "membername\n" */
		    size += (int)strlen(mem->name) + 1;
		} while ((mem = mem->next) != NULL);	/* Next attr/val */
	    else
		size++;		/* Count trailing '\n' if empty grp */


	    /* Alloc space for the record */
	    if (buf = malloc((size_t) size+1)) {

		/* Initializations */
		p = buf;

		/* Write the device-group name */
		q = rec->name;
		while (*q) *p++ = *q++;
		*p++ = ':';

		/* Write the membership list */
		if ((mem = rec->membership) != NULL) do {
		    q = mem->name;
		    while (*q) *p++ = *q++;
		    if ((mem = mem->next) != NULL) *p++ = ',';
		} while (mem);

		/* Terminate the record */
		*p++ = '\n';
		*p = '\0';

		/* Write the record */
		count = fputs(buf, stream);
		free(buf);
	    } else
		count = EOF;  /* malloc() failed */
	}

	/* Finished */
	return (count);
}

/*
 *  int _adddgrptabrec(dgrp, members)
 *	char   *dgrp
 *	char  **members
 *
 *	If <dgrp> doesn't exist, this function adds a record to the
 *	device-group table for that device-group.  That record will
 *	have the name <dgrp> and will have a membership described in
 *	the list referenced by <members>.  The record is added to the
 *	end of the table.
 *
 *	If <dgrp> already exists in the table, the function adds the
 *	members in the <members> list to the group's membership.
 *
 *  Arguments:
 *	dgrp		The name of the device-group being added to the
 *			device-group table.
 *	members		A pointer to the first item of the list of members
 *			in the device-group being added to the table.
 *			(This value may be (char **) NULL).
 *
 *  Returns:  int
 *	TRUE if successful, FALSE with "errno" set otherwise.
 */

int
_adddgrptabrec(
	char   *dgrp,			/* Devgrp to add to the table */
	char  **members)		/* Members for that devgrp */
{
	/* Automatic data */
	struct dgrptabent	*ent;		/* Ptr to dev tab entry */
	struct dgrptabent	*new;		/* Ptr to new dev tab info */
	struct dgrptabent	*p;		/* Temp ptr to dev tab info */
	struct member		*pm, *qm, *rm;	/* Tmp ptrs to struct member */
	FILE			*fd;		/* File descr, temp file */
	char			*path;		/* Ptr to new devtab name */
	int			olderrno;	/* Errno on entry */
	int			noerr;		/* FLAG, TRUE if all's well */


	/* Make a structure describing the new information */
	if ((new = mkdgrptabent(dgrp, members)) == NULL)
	    return (FALSE);

	/*
	 * Lock the device-group table.  This only returns if the
	 * table is locked or some error occurred.  It waits until the
	 * table is available.
	 */
	if (!lkdgrptab("a+", F_WRLCK)) {
	    _freedgrptabent(new);
	    return (FALSE);
	}

	/*
	 * If the device-group is already in the table, add
	 * the specified members
	 */

	noerr = TRUE;
	olderrno = errno;
	if (ent = _getdgrprec(dgrp)) {

	    /* Any members to add?  If not, do nothing. */
	    if (new->membership) {

		/* Any existing members? */
		if ((pm = ent->membership) != NULL) {

		    /* Find the end of the existing membership list */
		    while (pm->next) pm = pm->next;

		    /* Append the new members to the membership list */
		    pm->next = new->membership;

		    /* Remove any duplicates */
		    for (pm = ent->membership; pm; pm = pm->next) {
			qm = pm;
			while ((rm = qm->next) != NULL) {
			    if (strcmp(pm->name, rm->name) == 0) {
				qm->next = rm->next;
				free(rm->name);
				free(rm);
			    } else qm = rm;
			}
		    }
		} else ent->membership = new->membership;

		/* No members in the new list any more */
		new->membership = NULL;

		/*
		 * Make a new device-group table, replacing the
		 * record for the specified device-group
		 */

		_setdgrptab();	/* Rewind existing table */

		/* Open a temp file */
		if (fd = opennewdgrptab(&path)) {

		    /* While there's more records and no error ... */
		    while (((p = _getdgrptabent()) != NULL) && noerr) {

			/*
			 * If this isn't the record we're replacing,
			 * write it to the temporary file.  Otherwise,
			 * write the updated record
			 */

			if (ent->entryno != p->entryno)
				noerr = _putdgrptabrec(fd, p) != EOF;
			else noerr = _putdgrptabrec(fd, ent) != EOF;
			_freedgrptabent(p);
		    }

		    /* Fix the files */
		    if (noerr) {
			(void) fclose(fd);
			noerr = mknewdgrptab(path);
		    } else {
			(void) fclose(fd);
			(void) rmnewdgrptab(path);
		    }
		}   /* if (opennewdgrptab()) */

	    }   /* If there's members to add */

	    /* Free the memory associated with the updated entry */
	    _freedgrptabent(ent);
	}

	/*
	 * Otherwise, add the device-group to the end of the table
	 */

	else if (errno == EINVAL) {
	    errno = olderrno;
	    if (fseek(oam_dgroup, 0, SEEK_END) == 0)
		noerr = (_putdgrptabrec(oam_dgroup, new) != EOF);
	} else noerr = FALSE;

	/* Finished */
	(void) unlkdgrptab();		/* Unlock the file */
	_freedgrptabent(new);		/* Free the new dgrptab info struct */
	return (noerr);			/* Return with success indicator */
}

/*
 * int _rmdgrptabrec(dgrp)
 *	char   *dgrp
 *
 *	This function removes the record in the device-group table
 *	for the specified device-group.
 *
 *  Arguments:
 *	dgrp	The device-group to be removed
 *
 *  Returns:  int
 *	Success indicator:  TRUE if successful, FALSE with errno set otherwise.
 */

int
_rmdgrptabrec(char *dgrp)		/* Device-group to remove */
{
	/* Automatic data */
	struct dgrptabent	*ent;	/* Entry to remove */
	struct dgrptabent	*p;	/* Entry being copied */
	FILE			*fd;	/* Temp file's file descriptor */
	char			*path;	/* Pathname of temp file */
	int			noerr;	/* FLAG, TRUE if all's well */

	noerr = TRUE;
	if (!lkdgrptab("r", F_WRLCK))
		return (FALSE);
	if (ent = _getdgrprec(dgrp)) {
	    _setdgrptab();
	    if (fd = opennewdgrptab(&path)) {
		while (((p = _getdgrptabent()) != NULL) && noerr) {
		    if (ent->entryno != p->entryno)
			noerr = _putdgrptabrec(fd, p) != EOF;
		    _freedgrptabent(p);
		}
		if (noerr) {
		    (void) fclose(fd);
		    noerr = mknewdgrptab(path);
		} else {
		    (void) fclose(fd);
		    (void) rmnewdgrptab(path);
		}
	    } else noerr = FALSE;
	    _freedgrptabent(ent);
	} else noerr = FALSE;
	(void) unlkdgrptab();
	return (noerr);
}

/*
 * int _rmdgrpmems(dgrp, mems, notfounds)
 *	char   *dgrp
 *	char  **mems
 *	char ***notfounds
 *
 *	Remove the specified members from the membership of the specified
 *	device-group.  Any members not found in that device-group are
 *	returned in the list referenced by <notfounds>.
 *
 *  Arguments:
 *	dgrp		The device-group from which members are to be removed
 *	mems		The address of the first element in the list of
 *			members to remove.  This list is terminated by
 *			(char *) NULL.
 *	notfounds	The place to put the address of the list of addresses
 *			referencing the requested members that were not
 *			members of the specified device-group
 *
 *  Returns: int
 *	TRUE if successful, FALSE with errno set otherwise.
 */

int
_rmdgrpmems(
	char   *dgrp,			/* Device-group to modify */
	char  **mems,			/* Members to remove */
	char ***notfounds)		/* Members req'd but not found */
{
	/* Automatic data */
	struct dgrptabent	*ent;	/* Entry to modify */
	struct dgrptabent	*p;	/* Entry being copied */
	struct member		*pm;	/* Ptr to member being examined */
	struct member		*prev;	/* Ptr to previous member */
	char			**nflst; /* Ptr to not-found list */
	char			**pnf;	/* Ptr into not-found list */
	char			**pp;	/* Ptr into members-to-rm list */
	FILE			*fd;	/* Temp file's file descriptor */
	char			*path;	/* Pathname of temp file */
	int			noerr;	/* TRUE if all's well */
	int			found;	/* TRUE if member is in membership */
	int			i;	/* Temp counter */

	noerr = TRUE;

	/* Lock the device-group table */
	if (!lkdgrptab("r", F_WRLCK))
		return (FALSE);

	/* Nothing is "not found" yet */
	*notfounds = NULL;

	/* Get the entry we're to modify */
	if (ent = _getdgrprec(dgrp)) {

	    /* Allocate space for the not-found list */
	    i = 1;
	    if (mems)
		for (pp = mems; *pp; pp++)
			i++;
	    if (nflst = malloc(i*sizeof (char *))) {
		pnf = nflst;
		*pnf = NULL;

		/* For each member to remove ... (if any) */
		if (mems)
		    for (pp = mems; *pp; pp++) {

		    found = FALSE;

		    /* Compare against each member in the membership list */
		    pm = ent->membership;
		    prev = NULL;
		    while (pm && !found) {

			if (strcmp(*pp, pm->name) == 0) {

			    /* Found.  Remove from linked list */
			    if (prev) prev->next = pm->next;
			    else ent->membership = pm->next;
			    if (pm->name) free(pm->name);
			    free(pm);
			    found = TRUE;

			} else {

			    /* Bump to the next member */
			    prev = pm;
			    pm = pm->next;

			}

		    }   /* For each member in the group */

		/*
		 * If the requested member-to-remove wasn't found,
		 * add it to the list of not-found members
		 */
		    if (!found) {
			if (*pnf = malloc(strlen(*pp)+1)) {
			    (void) strcpy(*pnf++, *pp);
			    *pnf = NULL;
			} else noerr = FALSE;
		    }

		}   /* for (each requested member to remove */

		_setdgrptab();		/* Rewind existing table */

		if (fd = opennewdgrptab(&path)) {
		    while (((p = _getdgrptabent()) != NULL) && noerr) {
			if (ent->entryno != p->entryno)
			    noerr = _putdgrptabrec(fd, p) != EOF;
			else noerr = _putdgrptabrec(fd, ent) != EOF;
			_freedgrptabent(p);
		    }
		    if (noerr) {
			(void) fclose(fd);
			noerr = mknewdgrptab(path);
		    } else {
			(void) fclose(fd);
			(void) rmnewdgrptab(path);
		    }
		} else noerr = FALSE;   /* if (opennewdgrptab()) */

		/*
		 * If there was no error but there was requested members
		 * that weren't found, set the not-found list and the error
		 * information.  Otherwise, free the not-found list
		 */

		if (noerr && (pnf != nflst)) {
		    *notfounds = nflst;
		    errno = ENODEV;
		    noerr = FALSE;
		} else {
		    for (pnf = nflst; *pnf; pnf++) free(*pnf);
		    free(nflst);
		    if (!noerr) *notfounds = NULL;
		}
	    } else noerr = FALSE;

	    /* Free the description of the modified device group */
	    _freedgrptabent(ent);

	} else noerr = FALSE;    /* _getdgrprec() failed */

	/* Unlock the original device-group table */
	(void) unlkdgrptab();
	return (noerr);
}
