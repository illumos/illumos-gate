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

/*LINTLIBRARY*/

/*
 * Globals defined:
 *
 *	devreserv()	Reserve a set of OA&M devices
 *	devfree()	Free a reserved device
 *	reservdev()	Get a list of reserved devices
 *	_openlkfile()	Opens the lock file
 *	_rsvtabpath()	Get the pathname of the lock table file
 *	_closelkfile()	Closes the lock file
 */

/*
 * Headers referenced:
 *	<sys/types.h>	System data types
 *	<errno.h>	Error definitions (including "errno")
 *	<string.h>	String handling definitions
 *	<fcntl.h>	File control definitions
 *	<unistd.h>	Unix standard value definitions
 *	<devmgmt.h>	Global Device Management definitions
 *	"devtab.h"	Local Device Management definitions
 */

#include	<sys/types.h>
#include	<errno.h>
#include	<string.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<devmgmt.h>
#include	"devtab.h"

/*
 * Local Definitions:
 */


/*
 * Local data types:
 *	struct devlks	Structure that defines locking information (key
 *			with alias name (may be '\0' terminated)
 */

struct devlks {
	int	lk_key;
	char	lk_alias[((DTAB_MXALIASLN+2)/2)*2];
};


/*
 * Local Functions:
 *	isanullstr()	Is a character string a null string ("")?
 *	getlkcnt()	Get the number of devices locked
 *	locklkfile()	Lock the OA&M Device locking file
 *	getlocks()	Get the device locks from the device-lock file
 *	islocked()	Determines if a device is locked
 *	putlocks()	Close the device locks w/ update
 *	freelkfile()	Close the device locks w/o updating
 *	compresslks()	Compresses the table containing lock info
 */

#define	isanullstr(s)	(s[0] == '\0')

static	int	locklkfile(short);	/* Lock the lock file */
static	int	getlkcnt(void);		/* Get the number of locked devices */
static	int	getlocks(void);		/* Get the lock information */
static	int	putlocks(char **, int); /* Update lock information */
static	int	freelkfile(void);	/* Free lock information (no update) */
static	char   *islocked(char *);	/* Determines if a device is locked */


/*
 * Static data
 */

static	struct flock	lkinfo = {0, 0, 0, 0, 0};
static	struct devlks  *locklist;
static	int		lockcount;
static	int		lkfilefd = -1;

/*
 * char *_rsvtabpath()
 *
 *	Determines the pathname of the device reservation table file
 *
 *	Uses the following sequential steps:
 *	     1)	If OAM_DEVLKFILE is defined and is not null, use that as
 *		the pathname to the file
 *	     2)	Otherwise, use the devault name found in DVLK_PATH (defined
 *		in the header file <devtab.h>
 *
 *  Arguments:  None
 *
 *  Returns:  char *
 *	A pointer to the filename in malloc()ed memory or (char *) NULL if
 *	it fails.  "errno" will indicate the error if it fails.
 */

char *
_rsvtabpath(void)
{
	/* Automatics */
	char		*lockname;	/* Name of the lockfile */
#ifdef	DEBUG
	char		*p;		/* Temporary pointer */
#endif

#ifdef	DEBUG
	p = getenv(OAM_DEVLKTAB);
	if ((p != NULL) && (*p != '\0')) {
	    if (lockname = malloc(strlen(p)+1))
		(void) strcpy(lockname, p);
	} else {
#endif
	    if (lockname = malloc(strlen(DVLK_PATH)+1))
		(void) strcpy(lockname, DVLK_PATH);

#ifdef	DEBUG
	}
#endif

	/* Fini -- return a pointer to the lockfile pathname */
	return (lockname);
}

/*
 *  int _openlkfile()
 *
 *	The _openlkfile() function opens a device-reservation table file
 *	for read/write access.
 *
 *  Arguments: None
 *
 *  Returns:  int
 *	TRUE if successful, FALSE otherwise.
 *
 *  Statics Used:
 *	lkfilefd	Lock file file descriptor
 */

int
_openlkfile(void)
{
	/*
	 *  Automatic data
	 */

	char   *lockname;		/* Name of the lock file */


	/* Close the lockfile -- it might be open */
	(void) _closelkfile();

	/* If we can get the name of the lock file ... */
	if (lockname = _rsvtabpath()) {

	    /* Open it */
	    lkfilefd = open(lockname, O_RDWR|O_CREAT, 0600);
	    free(lockname);

	}

	/*  Finis  */
	return ((lkfilefd != -1) ? TRUE : FALSE);
}

/*
 * int _closelkfile()
 *
 *	Function closes the device-reservation table file and sets the
 *	necessary external variables to indicate such.
 *
 *  Arguments:  None
 *
 *  Returns:  int
 *	Same as close()
 *
 *  Statics referenced:
 *	lkfilefd	The device reservation table file's file descriptor
 */

int
_closelkfile(void)
{
	/* Automatics */
	int	rtnval;		/* Value to return */

	/* Close the lock file if it's open */
	if (lkfilefd != -1) rtnval = close(lkfilefd);
	else rtnval = 0;

	/* Indicate that the lock-file is closed */
	lkfilefd = -1;

	/* Finis */
	return (rtnval);
}

/*
 *  int locklkfile(lkflag)
 *	short		lkflag
 *
 *	This function locks the device lock file.  If the request cannot
 *	be serviced, it keeps on trying until it manages to lock the file
 *	or it encounters an error.
 *
 *  Arguments:
 *	lkflag		Flag (from FCNTL(BA_OS)) indicating which type
 *			of lock is being requested.  Values that make
 *			sense:
 *				F_RDLCK:	Read lock.
 *				F_WRLCK:	Write lock.
 *
 *  Returns: int
 *	TRUE (non-zero) if the function managed to lock the file, FALSE
 *	otherwise ("errno" will indicate the problem).
 *
 *  Statics used:
 *	int lkfilefd		File descriptor of the open lock file
 *	struct flock lkinfo	Structure used by fcntl() to lock a file
 */

static	int
locklkfile(short lkflag)
{
	/* Automatic data */
	int		noerror;	/* TRUE if no error yet */
	int		locked;		/* TRUE if the file is locked */
	int		olderrno;	/* Value of errno on call */


	/* Set up the locking structure */
	lkinfo.l_type = lkflag;

	/* Try to lock the file.  If it's locked, wait and try again */
	noerror = TRUE;
	locked = FALSE;
	olderrno = errno;
	while (noerror && !locked) {
	    if (fcntl(lkfilefd, F_SETLK, &lkinfo) != -1) locked = TRUE;
	    else {
		if ((errno == EACCES) || (errno == EAGAIN)) {
		    errno = olderrno;
		    if (sleep(2)) noerror = FALSE;
		} else noerror = FALSE;
	    }
	}

	/* Return a success flag */
	return (locked);
}

/*
 *  int getlkcnt()
 *
 *	This function extracts the number of currently-locked devices
 *	from the lock file.
 *
 *  Arguments:  None
 *
 *  Returns:  int
 *	The number of devices locked or -1 if an error occurred.
 *
 *  Statics used:
 *	lkfilefd	File descriptor of the open lockfile
 *
 *  Assumptions:
 *    -	The file is positioned to the beginning-of-file
 */

static	int
getlkcnt(void)
{
	/* Automatics */
	int	cntread;		/* Number of bytes read */
	int	lkcnt;			/* Number of current locks */

	/* Get the lock count from the file */
	cntread = (int)read(lkfilefd, &lkcnt, sizeof (int));

	/* If there wasn't one, set to 0.  If error, set to -1 */
	if (cntread != (int)sizeof (int))
		lkcnt = (cntread < 0) ? -1 : 0;

	/* Return the lock count */
	return (lkcnt);
}

/*
 *  int readlocks()
 *
 *	The readlocks() function reads the reserved-device list from
 *	the reserved-device file (which has already been opened)
 *
 *  Arguments:  None
 *
 *  Returns:  int
 *	TRUE if all went well, FALSE otherwise.
 *
 *  Statics Used:
 *	lockcount	Sets this to the number of locks in the lock list
 *	locklist	Sets this to the malloc()ed space containing the
 *			list of reserved devices.
 *	lkfilefd	Reads data from this file
 */

static	int
readlocks(void)
{
	/* Automatics */
	struct devlks  *alloc;		/* Ptr to alloc'ed space */
	int		noerror;	/* TRUE if all is well */
	size_t		bufsiz;		/* # bytes needed for lock data */


	/* Initializations */
	noerror = TRUE;

	/* Get the number of devices currently locked */
	if ((lockcount = getlkcnt()) > 0) {

	    /* Allocate space for the locks */
	    bufsiz = lockcount * sizeof (struct devlks);
	    if (alloc = malloc(bufsiz)) {

		/* Read the locks into the malloc()ed buffer */
		if (read(lkfilefd, alloc, bufsiz) != (ssize_t)bufsiz)
		    noerror = FALSE;

		/* If the read failed, free malloc()ed buffer */
		if (!noerror) free(alloc);

	    } else noerror = FALSE;  /* malloc() failed */

	} else if (lockcount < 0) noerror = FALSE;

	/* Finished */
	if (noerror)
		locklist = (lockcount > 0) ? alloc : NULL;
	return (noerror);
}

/*
 *  int getlocks()
 *
 *	getlocks() extracts the list of locked devices from the file
 *	containing that information.  It returns the number of locked
 *	devices.  If there are any locked devices, it allocates a buffer
 *	for the locked file information, saves that buffer address in
 *	the allocated buffer.  Also, the device lock file is open and
 *	locked if the function is successful.
 *
 *  Arguments:  None
 *
 *  Returns:  int
 *	TRUE if successful, FALSE otherwise.  "errno" will reflect the
 *	error if the function returns FALSE.
 *
 *  Static data referenced:
 *	int lkfilefd			File descriptor of the lock file
 */

static	int
getlocks(void)
{
	/* Automatic data */
	int		noerror;	/* TRUE if all's well */


	/* Initializations */
	noerror = TRUE;

	/* Open the lock file */
	if (_openlkfile()) {

	    /* Lock the lock file */
	    if (locklkfile(F_WRLCK)) {

		/* Get the number of devices currently locked */
		if (!readlocks()) noerror = FALSE;

		/* If something happened, unlock the file */
		if (!noerror) (void) freelkfile();

	    } else noerror = FALSE;  /* Lock failed */

	    /* If something happened, close the lock file */
	    if (!noerror)
		(void) _closelkfile();

	} else noerror = FALSE;				/* Open failed */

	/* Done */
	return (noerror);
}

/*
 *  int writelks(tblcnt)
 *	int	tblcnt
 *
 *	writelks() writes the lock information to the lock file.  Lock
 *	information includes the number of locks (to be) in the table.
 *	Note that functions may still be appending new locks after this
 *	call...
 *
 *  Arguments:
 *	tblcnt	Number of locks in the lock table
 *
 *  Returns:
 *	TRUE if successful, FALSE otherwise with "errno" containing an
 *	indication of the error.
 *
 *  Statics Used:
 *	lockcount	Number of locks to exist
 *	locklist	Table of locks (may not include new ones)
 *	lkfilefd	File descriptor of the lock file
 *
 *  Notes:
 *    - The number of locks that are going to be in the lock file
 *	is in the static variable "lockcount".  <tblcnt> indicates
 *	the number of entries in the lock table.
 */

static	int
writelks(int tblcnt)
{
	/* Automatic data */
	int		noerr;		/* FLAG, TRUE if all's well */
	size_t		tblsz;		/* Size of the table to write */

	/* Initializations */
	noerr = TRUE;

	/* Rewind the OA&M Device Lock File */
	if (lseek(lkfilefd, 0L, 0) >= 0L) {

	    /* Write the number of locks that will (eventually) exist */
	    if (write(lkfilefd, &lockcount, sizeof (int)) == sizeof (int)) {

		/* Write the table as we currently know it */
		tblsz = tblcnt * sizeof (struct devlks);
		if (tblsz) {
		    if (write(lkfilefd, locklist, tblsz) != (ssize_t)tblsz)
			noerr = FALSE;  /* Write of locks failed */
		}
	    } else {
		noerr = FALSE;  /* write() of count failed */
	    }
	} else {
		noerr = FALSE;  /* Rewind failed */
	}

	/* Return an indicator of our success */
	return (noerr);
}

/*
 * int appendlk(key, alias)
 *	int	key
 *	char   *alias
 *
 *	Write device locking information to the device locking file.
 *
 *  Arguments:
 *	key	Key the device is being locked on
 *	alias	The device alias being locked
 *
 *  Returns:  int
 *	TRUE if we successfully appended a lock to the lock file,
 *	FALSE with "errno" set otherwise.
 *
 *  Static data used:
 *	lkfilefd	The open file descriptor for the open device
 *			locking file
 */

static	int
appendlk(
	int key,		/* Lock key */
	char *alias)		/* Alias to lock */
{
	/* Automatic data */
	struct devlks	lk;	/* Structure for writing a lock */

	/* Set up the data to write */
	lk.lk_key = key;
	(void) strcpy(lk.lk_alias, alias);

	/* Write the data, returning an indicator of our success */
	return (write(lkfilefd, &lk,
	    sizeof (struct devlks)) == sizeof (struct devlks));
}

/*
 *  int compresslks()
 *
 *	This function compresses the lock table, squeezing out the empty
 *	lock entries.
 *
 *  Arguments:  none
 *
 *  Returns:  int
 *	The number of non-empty entries in the table.  They will be the
 *	first 'n' entries in the table after compression.
 *
 *  Statics Used
 *	lockcount	Number of locks in the device lock list
 *	locklist	The device lock list
 */

static	int
compresslks(void)
{
	/* Automatics */
	struct devlks  *avail;		/* Pointer to empty slot */
	struct devlks  *p;		/* Running pointer to locks */
	int		nlocks;		/* Number of locks (up to date) */
	int		i;		/* Temporary counter */

	/* Initializations */
	p = locklist;
	nlocks = lockcount;
	avail = NULL;

	/* Loop through the lock list squeezing out unused slots */
	for (i = 0; i < lockcount; i++) {

	    /* If we've found an empty slot ... */
	    if (isanullstr(p->lk_alias)) {

		/*
		 * If we've an empty slot to move to, just decrement
		 * count of used slots.  Otherwise, make it the next
		 * available slot
		 */

		nlocks--;
		if (!avail) avail = p;
	    }

	    else if (avail) {

		/*
		 * If we found a slot in use and there's an
		 * available slot, move this one there
		 */

		(void) strcpy(avail->lk_alias, p->lk_alias);
		avail->lk_key = p->lk_key;
		avail++;
	    }

	    /* Next, please */
	    p++;
	}

	return (nlocks);
}

/*
 *  int freelkfile()
 *
 *	This function unlocks the OA&M device locking file.
 *
 *  Arguments:  None
 *
 *  Returns:  int
 *	TRUE if it successfully unlocked the file, FALSE otherwise
 *	with "errno" set to indicate the problem.
 *
 *  Statics Used:
 *	lkinfo		File-locking structure
 *	lkfilefd	File-descriptor of the open lock file
 */

static	int
freelkfile(void)
{
	/* Automatic data */
	int		noerr;		/* TRUE if all's well */

	/* Set the action to "unlock" */
	lkinfo.l_type = F_UNLCK;

	/* Unlock the file */
	noerr = (fcntl(lkfilefd, F_SETLK, &lkinfo) != -1);

	/* Return an indication of our success */
	return (noerr);
}

/*
 * int putlocks(newlist, key)
 *	char  **newlist
 *	int	key
 *
 *	This function updates the file containing OA&M device locks.
 *
 *  Arguments:
 *	newlist		The address of the list of addresses of device
 *			aliases to add to the list of locked devices
 *	key		The key on which to lock the devices
 *
 *  Returns:  int
 *	TRUE if all went well, FALSE otherwise with "errno" set to an
 *	error code that indicates the problem.
 *
 *  Statics Used:
 *	lockcount	Number of locks in the locked device structure
 *	locklist	Locked device structure
 */

static	int
putlocks(
	char **newlist,	/* New devices to lock */
	int key)	/* Key we're locking stuff on */
{
	/* Automatic data */
	struct devlks  *plk;		/* Ptr into the locks list */
	char		**pp;		/* Pointer into the device list */
	char		**qq;		/* Another ptr into the dev list */
	int		lkndx;		/* Index into locks list */
	int		noerr;		/* TRUE if all's well */
	int		lksintbl;	/* Number of locks in the table */


	/*
	 * Look through the existing lock list, looking for holes we can
	 * use for the newly locked devices
	 */

	plk = locklist;
	pp = newlist;
	lkndx = 0;
	while (*pp && (lkndx < lockcount)) {
	    if (isanullstr(plk->lk_alias)) {
		plk->lk_key = key;
		(void) strcpy(plk->lk_alias, *pp++);
	    }
	    lkndx++;
	    plk++;
	}

	/*
	 * Update the locks file (algorithm depends on whether we're adding
	 * new locks or not.  May be replacing old locks!)
	 */

	if (*pp) {

	/*
	 * Need to expand the locks file
	 *  - Remember the old lock count (in existing lock buffer)
	 *  - Count the number of new locks we need to add
	 *  - Write out the old locks structure
	 *  - Append locks for the newly added locks
	 */

	    lksintbl = lockcount;
	    for (qq = pp; *qq; qq++) lockcount++;
	    noerr = writelks(lksintbl);
	    while (noerr && *pp) noerr = appendlk(key, *pp++);
	} else {

	/*
	 * Don't need to expand the locks file.  Compress the locks
	 * then write out the locks information
	 */

	    lockcount = compresslks();
	    noerr = writelks(lockcount);
	}

	/* Done.  Return an indication of our success */
	return (noerr);
}

/*
 * char *islocked(device)
 *	char	       *device
 *
 *	This function checks a device to see if it is locked.  If it is
 *	not locked, it returns the device alias.
 *
 *	A device is not locked if the device's alias does not appear in
 *	the device locks table, or the key on which the device was locked
 *	is no longer active.
 *
 *  Argumetns:
 *	char *device		The device to be reserved.  This can be
 *				a pathname to the device or a device
 *				alias.
 *
 *  Returns:  char *
 *	Returns a pointer to the device alias if it's not locked, or
 *	(char *) NULL if it's locked or some error occurred.
 *
 *  Static data used:
 *	struct devlks *locklist		Pointer to the list of device locks
 *	int lockcount			The number of devices that are locked
 */

static	char *
islocked(char *device)
{
	/* Automatic data */
	char		*alias;		/* Alias of "device" */
	struct devlks	*plk;		/* Ptr to locking info */
	int		locked;		/* TRUE if device in locked list */
	int		i;		/* Temp counter */

	/* Get the device's alias */
	if (alias = devattr(device, DTAB_ALIAS)) {

	/*
	 * Look through the device locks to see if this device alias
	 * is locked
	 */

	    locked = FALSE;
	    plk = locklist;
	    for (i = 0; !locked && (i < lockcount); i++) {
		if (strncmp(alias, plk->lk_alias, DTAB_MXALIASLN) == 0)
		    locked = TRUE;
		else plk++;
	    }

	    if (locked) {
		    free(alias);
		    alias = NULL;
		    errno = EAGAIN;
	    }

	}  /* devattr() failed, no such device? */

	/* Return pointer to the device */
	return (alias);
}

/*
 *  int unreserv(key, device)
 *	int	key
 *	char   *device
 *
 *	This function removes a device reservation.
 *
 *  Arguments:
 *	int key	The key on which the device was allocated
 *	char *device	The device to be freed.
 *
 *  Returns:  int
 *	TRUE if successful, FALSE otherwise with "errno" set.
 *
 *  Explicit "errno" settings:
 *	(This follows the "signal()" model which gives one the ability
 *	to determine if a device is allocated without having the
 *	permission to free it.)
 *
 *	EINVAL	The device specified was not locked
 *	EPERM	The device specified was locked but not on the
 *		specified key
 *
 *  Static data used:
 *	locklist	List of locked devices
 *	lockcount	Number of entries in the locked-device list
 */

int
unreserv(int key, char *device)
{
	/* Automatics */
	char		*srchalias;	/* Device alias to search table with */
	char		*alias;		/* Device's alias (from devattr()) */
	struct devlks	*plk;		/* Pointer to a device lock */
	int		locked;		/* TRUE if device currently locked */
	int		noerr;		/* TRUE if all's well */
	int		olderrno;	/* Entry value of "errno" */
	int		i;		/* Counter of locks */


	/* Initializations */
	noerr = TRUE;

	/*
	 * Get the device alias.  If none can be found, try to free
	 * whatever it is that was given to us (the possibility exists
	 * that the device has been removed from the device table since
	 * it was reserved, so the device not being in the table shouldn't
	 * pose too much of a problem with us...)
	 */

	olderrno = errno;
	if (alias = devattr(device, DTAB_ALIAS)) srchalias = alias;
	else {
	    errno = olderrno;
	    srchalias = device;
	}

	/* Loop through the locked-device list looking for what we've got... */
	locked = FALSE;
	plk = locklist;
	for (i = 0; !locked && (i < lockcount); i++) {
	    if (strcmp(srchalias, plk->lk_alias) == 0)
		locked = TRUE;
	    else plk++;
	}

	/* Free the alias string (if any), we don't need it anymore */
	if (alias) free(alias);

	/* If the device is locked ... */
	if (locked) {

	/*
	 * If it's locked on the key we've been given, free it.
	 * Otherwise, don't free it and set errno to EPERM
	 */

	    if (plk->lk_key == key) {
		plk->lk_alias[0] = '\0';
	    } else {
		noerr = FALSE;
		errno = EPERM;
	    }
	} else {

	    /* The device isn't locked.  Set errno to EINVAL */
	    noerr = FALSE;
	    errno = EINVAL;
	}

	/* Finished.  Return an indication of our success */
	return (noerr);
}

/*
 *  char **devreserv(key, rsvlst)
 *	int		key
 *	char	      **rsvlist[]
 *
 *	The devreserv() function reserves devices known to the OA&M Device
 *	Management family of functions.  Once a device is reserved, it can't
 *	be reserved by another until it is freed or the process with the
 *	"key" is no longer active.  It returns a list aliases of the devices
 *	it allocated.
 *
 *	The function attempts to reserve a single device from each of the
 *	lists.  It scans each list sequentially until it was able to
 *	reserve a requested device.  If it successfully reserved a device
 *	from each of the lists, it updates the device-locked file and
 *	returns those aliases to the caller.  If it fails, it allocates
 *	nothing and returns (char **) NULL to the caller.  "errno"
 *	indicates the error.
 *
 *  Arguments:
 *	int key			The key on which this device is being reserved.
 *
 *	char **rsvlist[]	The address of the list of addresses of lists
 *				of pointers to the devices to allocate.
 *
 *  Returns:  char **
 *	A pointer to malloc()ed space containing pointers to the aliases
 *	of the reserved devices.  The aliases are in malloc()ed space also.
 *	The list is terminated by the value (char *) NULL.
 *
 *  Static Data Used:
 *	None directly, but functions called share hidden information
 *	that really isn't of concern to devreserv().
 */

char **
devreserv(
	int		key,		/* Key to reserve device on */
	char		**rsvlst[])	/* List of lists of devs to reserve */
{
	char		***ppp;		/* Ptr to current list in rsvlist */
	char		**pp;		/* Ptr to current item in list */
	char		**qq;		/* Ptr to item in rtnlist */
	char		**rr;		/* Ptr to item in aliases */
	char		**aliases;	/* List of aliases allocated */
	char		**rtnlist;	/* Ptr to buf to return */
	char		*alias;		/* Alias of dev to reserve */
	int		noerr;		/* TRUE if all's well */
	int		olderrno;	/* Old value of errno */
	int		gotone;		/* TRUE if unreserved dev found */
	int		foundone;	/* Found a valid device in the list */
	int		ndevs;		/* # of devs to reserve */

	noerr = TRUE;
	ppp = rsvlst;
	olderrno = errno;
	for (ndevs = 0; *ppp++; ndevs++)
		;
	if (rtnlist = malloc((ndevs+1)*sizeof (char **))) {
	    if (aliases = malloc((ndevs+1)*sizeof (char **))) {
		if (getlocks()) {
		    qq = rtnlist;
		    rr = aliases;

		    /* Go through the lists of devices we're to reserve */

		    for (ppp = rsvlst; noerr && *ppp; ppp++) {

			/* Try to reserve a device from each list */
			gotone = FALSE;
			foundone = FALSE;
			for (pp = *ppp; noerr && !gotone && *pp; pp++) {

			/*
			 * Check the next device in the list.  If islocked()
			 * returns that device's alias, it's ours to have
			 */

			    if (alias = islocked(*pp)) {
				gotone = TRUE;
				foundone = TRUE;
				if (*qq = malloc(strlen(*pp)+1)) {
				    (void) strcpy(*qq++, *pp);
				    *rr++ = alias;
				} else {
				    *rr = NULL;
				    noerr = FALSE;
				}
			    } else {
				if (errno == EAGAIN) {
				    foundone = TRUE;
				    errno = olderrno;
				} else if (errno == ENODEV) errno = olderrno;
				else {
				    noerr = FALSE;
				    *rr = NULL;
				}
			    }
			}

			/*
			 * If no device from the list could be reserved,
			 * we've failed
			 */

			if (noerr && !gotone) {
			    noerr = FALSE;
			    if (!foundone) errno = ENODEV;
			    else errno = EAGAIN;
			    *qq = NULL;
			    *rr = NULL;
			}

		    } /* End of loop through lists loop */

		/*
		 * If all went well, update lock file.
		 * Then, free locks
		 */

		    if (noerr) {
			*qq = NULL;
			*rr = NULL;
			if (!putlocks(aliases, key)) noerr = FALSE;
		    }

		    /* Free resources */
		    if (!freelkfile()) noerr = FALSE;
		    if (_closelkfile() != 0) noerr = FALSE;
		    for (qq = aliases; *qq; qq++) free(*qq);
		    if (!noerr)
			for (pp = rtnlist; *pp; pp++)
				free(*pp);

		} else noerr = FALSE; /* Error getting locks */

		free(aliases);

	    } else noerr = FALSE;  /* Malloc() for alias list failed */

	    if (!noerr) {
		free(rtnlist);
		rtnlist = NULL;
	    }

	} else noerr = FALSE;  /* malloc() failed */

	/* Return list or an indication of an error */
	return (noerr ? rtnlist : NULL);
}

/*
 *  int devfree(key, device)
 *	int	key
 *	char   *device
 *
 *	This function unreserves (frees) the given device.  It returns
 *	an indication of success with "errno" containing information about
 *	a failure.
 *
 *  Arguments:
 *	int	key	The key that the device is locked on
 *	char   *device	The device (alias, pathname to, etc.) to be freed.
 *
 *  Returns:  int
 *	0 if successful, -1 with "errno" set if fails.
 */

int
devfree(
	int	key,			/* Key device is locked on */
	char   *device)			/* Device to free */
{
	/* Automatics */
	int	noerr;

	/* Initializations */
	noerr = TRUE;

	/* Get the locks, locking the lock file */
	if (getlocks()) {

	    /* Attempt to unreserve the device */
	    if (unreserv(key, device)) {

		/*
		 * Successful.  Compress the lock structure and
		 * write the new locks
		 */

		lockcount = compresslks();
		if (!writelks(lockcount)) noerr = FALSE;

	    } else noerr = FALSE;  /* Couldn't unreserve the device */

	    /* Unlock and close the locks file */
	    if (!freelkfile()) noerr = FALSE;
	    if (_closelkfile() != 0) noerr = FALSE;

	} else noerr = FALSE;

	/* Return 0 if successful, something else otherwise */
	return (noerr? 0 : -1);
}

/*
 *  struct reservdev **reservdev()
 *
 *	This function returns the list of reserved devices
 *	along with the key on which those devices were locked.
 *
 *  Arguments:  None.
 *
 *  Returns:  struct reservdev **
 *	Pointer to the list of pointers to structures describing
 *	the reserved devices, or (struct reservdev **) NULL if an
 *	error occurred.  The list of pointers is terminated by
 *	(struct reservdev *) NULL.
 *
 *  Statics Used:
 *	locklist	List of reserved devices
 *	lockcount	Number of items in the reserved-devices list
 */

struct reservdev **
reservdev(void)
{
	/* Automatics */
	struct reservdev	**rtnlist;	/* Ptr to return list */
	struct devlks		*p;		/* Running ptr, locklist */
	struct reservdev	**q;		/* Running ptr, rtnlist */
	char			*r;		/* Temp ptr to char */
	size_t			bufsiz;		/* Size of buffer to alloc */
	int			noerr;		/* TRUE if all's well */
	int			i;		/* Lock counter */


	/* Initializations */
	noerr = TRUE;

	/* Open the lock file ... */
	if (_openlkfile()) {

	    /* Put a read-lock on the lock-file ... */
	    if (locklkfile(F_RDLCK)) {

		/* Read the locks ... */
		if (readlocks()) {

		    /* Alloc space for the return list */
		    bufsiz = (lockcount+1) * sizeof (struct reservdev *);
		    if (rtnlist = malloc(bufsiz)) {

			/* Build the return list from the lock list */
			p = locklist;
			q = rtnlist;
			for (i = 0; noerr && (i < lockcount); i++) {
			    if (*q = malloc(sizeof (struct reservdev))) {
				if (r = malloc(strlen(p->lk_alias)+1)) {
				    (*q)->devname = strcpy(r, p->lk_alias);
				    (*q)->key = p->lk_key;
				} else noerr = FALSE;  /* malloc() error */
			    } else noerr = FALSE;  /* malloc() error */
			    p++;
			    q++;
			}

			/*
			 * If no error, terminate the list.  Otherwise, free
			 * the space we've allocated
			 */

			if (noerr) *q = NULL;
			else {
			    for (q = rtnlist; *q; q++) {
				free((*q)->devname);
				free(*q);
			    }
			    free(rtnlist);
			}

		    } else noerr = FALSE;  /* Couldn't malloc() list space */

		} else noerr = FALSE;  /* Problem reading locks */

		/* Free the lock file */
		(void) freelkfile();

	    } else noerr = FALSE;  /* Error locking the lock file */

	    /* Close the lock file */
	    (void) _closelkfile();

	} else noerr = FALSE;  /* Error opening the lock file */

	/* Return ptr to list of locks or NULL if an error has occurred */
	return (noerr ? rtnlist : NULL);
}
