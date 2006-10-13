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
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<string.h>
#include	<strings.h>
#include	<volmgt.h>
#include	<errno.h>
#include	<sys/types.h>
#include	<sys/mkdev.h>
#include	<sys/ddi.h>
#include	<sys/stat.h>
#include	<sys/errno.h>
#include	<rpc/types.h>
#include	"volmgt.h"
#include	"volmgt_private.h"
#include	"volmgt_fsi_private.h"

/* just utnil volmgt.h is up to date */
#ifndef	VOL_RSV_MAXIDLEN
#define	VOL_RSV_MAXIDLEN	256
#endif


/* this routine used by both acquire and release */
static char	*fsi_xlate_name(char *);

/*
 * arc approved interface
 *	- can not be modified without approval from an arc
 *
 * committment level:
 *	uncommitted
 *
 * description:
 *	volmgt_acquire: try to acquire the volmgt advisory device reservation
 *	for a specific device.
 *
 * arguments:
 *	dev - a device name to attempt reserving.  This string can be:
 *		- a full path name to a device
 *		- a symbolic device name (e.g. floppy0)
 *
 *	id  - a reservation string that hopefully describes the application
 *		making this reservation.
 *
 *	pid - a pointer to a pid_t type.  If this argument is not NULL
 *		and the requested device is already reserved, the process
 *		id of the reservation owner will be returned in this
 *		location.
 *
 *	ovr - an override indicator.  If set to non-zero, the caller requests
 *		that this reservation be made unconditionally.
 *
 *	err - the address of a pointer to a string which is to receive the
 *		id argument used when the current device was reserved.  This
 *		is only used when the current reservation attempt fails due
 *		to an already existing reservation for this device.
 *
 * return value(s):
 *	A non-zero indicator if successful.
 *
 *	A zero indicator if unsuccessful.  If errno is EBUSY, then the err
 *	argument will be set to point to the string that the process currently
 *	holding the reservation supplied when reserving the device.  It is up
 *	to the caller to release the storage occupied by the string via
 *	free(3C) when no longer needed.
 *
 * preconditions:
 *	none
 */
int
volmgt_acquire(char *dev, char *id, int ovr, char **err, pid_t *pidp)
{
	char			*targ_name = NULL;
	struct stat		sb;
	dev_t			idev;
	vol_dbid_t		dbid = (vol_dbid_t)-1;
	vol_db_entry_t		dbe;
	vol_db_entry_t		*dbp;
	int			retval = 0;	/* default return => ERROR */
	int			reterr = 0;


#ifdef	DEBUG
	denter("volmgt_acquire(\"%s\", \"%s\", %s, %#p, %#p): entering\n",
	    dev ? dev : "<null ptr>", id ? id : "<null ptr>",
	    ovr ? "TRUE" : "FALSE", err, pidp);
#endif
	/*
	 * the supplied arguments must not be NULL
	 */
	if ((dev == NULL) || (id == NULL) || (err == NULL)) {
		errno = EINVAL;
		goto dun;
	}

	/*
	 * the id string must not be longer than the maximum allowable
	 * number of characters
	 */
	if (strlen(id) > VOL_RSV_MAXIDLEN) {
		errno = E2BIG;
		goto dun;
	}

	if ((targ_name = fsi_xlate_name(dev)) == NULL) {
		goto dun;
	}

	/*
	 * convert 'char *dev' to major/minor pair
	 */
	if (stat(targ_name, &sb) < 0) {
		goto dun;
	}
	idev = sb.st_rdev;

	/*
	 * open the database file
	 */
	if ((dbid = vol_db_open()) < 0) {
		goto dun;
	}

	if ((dbp = vol_db_find(dbid, idev)) == NULL) {
		/*
		 * the entry wasn't found, so reserve it
		 */
		dbe.dev_major = major(idev);
		dbe.dev_minor = minor(idev);
		dbe.pid = getpid();
		dbe.id_tag = id;
		if (vol_db_insert(dbid, &dbe) != 0) {
			retval = 1;		/* success! */
		}
	} else {
		if (ovr || (vol_db_proc_find(dbp->pid) == 0)) {
			/*
			 * the entry exists but either override was specified
			 * or the process holding the reservation is no longer
			 * active
			 *
			 * in either case we'll usurp the reservation
			 */
			if (vol_db_remove(dbid, idev) != 0) {
				/* reserve the device */
				dbe.dev_major = major(idev);
				dbe.dev_minor = minor(idev);
				dbe.pid = getpid();
				dbe.id_tag = id;
				if (vol_db_insert(dbid, &dbe) != 0) {
					retval = 1;
				}
			}

		} else {

			/*
			 * the entry exists and override was NOT specified
			 */

			/*
			 * optionally return the pid of the reservation
			 * owner
			 */
			if (pidp != NULL) {
				*pidp = dbp->pid;
			}

			*err = strdup(dbp->id_tag);
			reterr = EBUSY;
		}
		vol_db_free(dbp);	/* Release the entry */
	}


	/*
	 * if an error was encountered (currently only EBUSY supported)
	 * set errno to reflect it
	 */
	if (reterr != 0) {
		errno = reterr;
	}

dun:
	if ((int)dbid >= 0) {
		(void) vol_db_close(dbid);
	}
	if (targ_name != NULL) {
		free(targ_name);
	}
#ifdef	DEBUG
	dexit("volmgt_acquire: returning %s\n", retval ? "TRUE" : "FALSE");
#endif
	return (retval);
}


/*
 * arc approved interface
 *	- can not be modified without approval from an arc
 *
 * committment level:
 *	uncommitted
 *
 * description:
 *	volmgt_release: try to release the volmgt advisory device reservation
 *	for a specific device.
 *
 * arguments:
 *	dev - a device name to attempt reserving.  This string can be:
 *		- a full path name to a device
 *		- a symbolic device name (e.g. floppy0)
 *
 * return value(s):
 *	A non-zero indicator if successful
 *	A zero indicator if unsuccessful
 *
 * preconditions:
 *	none
 */
int
volmgt_release(char *dev)
{
	char			*targ_name = NULL;
	struct stat		sb;
	long			idev;
	vol_dbid_t		dbid;
	vol_db_entry_t		*dbp;
	int			retval = 0;	/* default return => FAILURE */
	int			reterr = 0;


#ifdef	DEBUG
	denter("volmgt_release(\"%s\"): entering\n", dev ? dev : "<null ptr>");
#endif
	/*
	 * first let's do some minimal validation of the supplied arguments
	 */

	/*
	 * the supplied argument must not be NULL
	 */
	if (dev == NULL) {
		errno = EINVAL;
		goto dun;
	}

	if ((targ_name = fsi_xlate_name(dev)) == NULL) {
		goto dun;
	}

	/*
	 * convert 'char *dev' to major/minor pair
	 */
	if (stat(targ_name, &sb) < 0) {
		goto dun;
	}
	idev = sb.st_rdev;

	/*
	 * open the database file
	 */
	if ((dbid = vol_db_open()) < 0) {
		goto dun;
	}

	if ((dbp = vol_db_find(dbid, idev)) == NULL) {
		/* the entry wasn't found so I can't clear reservation */
		errno = ENOENT;
		goto dun;
	}

	/* the entry was found so make sure I can clear it */
	if (dbp->pid == getpid()) {
		/*
		 * the reservation was made by me, clear it
		 */
		if (vol_db_remove(dbid, idev) != 0) {
			retval = 1;
		}
	} else {
		/*
		 * the entry wasn't made by me
		 */
		reterr = EBUSY;
	}
	vol_db_free(dbp);

	/*
	 * if an error was encountered (currently only EBUSY supported)
	 * set errno to reflect it
	 */
	if (reterr != 0) {
		errno = reterr;
	}
dun:
	if ((int)dbid >= 0) {
		(void) vol_db_close(dbid);
	}
	if (targ_name != NULL) {
		free(targ_name);
	}
#ifdef	DEBUG
	dexit("volmgt_release: returning %s\n", retval ? "TRUE" : "FALSE");
#endif
	return (retval);
}


/*
 * translate suplied vol name into a pathname
 *
 * if volmgt is running, this pathname will be in /vol (or its equiv)
 *
 * if volmgt is not running then this path may be anywhere
 *
 * in either case the pathname will *not* be verified as a blk/chr dev
 *
 * if the return value is non-null then it's been alloced
 *
 * NOTE: assume "vol" is not a NULL ptr
 */
static char *
fsi_xlate_name(char *vol)
{
	char	*res = NULL;			/* result to return */
	char	*vr;				/* volmgt root dir */
	bool_t	vm_running = volmgt_running();	/* volmgt running? */


#ifdef	DEBUG
	denter("fsi_xlate_name(\"%s\"): entering\n", vol);
#endif

	/* is it an absolute pathname ?? */
	if (*vol == '/') {

		if (vm_running) {
			/* pathname must be in the /vol namespace */
			vr = (char *)volmgt_root();
			if (strncmp(vol, vr, strlen(vr)) != 0) {
				/* not a cool pathname */
				errno = EINVAL;	/* XXX: is this correct */
				goto dun;
			}
		}

		res = strdup(vol);

	} else {

		/*
		 * if volmgt is running we can try to dereference it
		 * if volmgt isn't running then just give up
		 */

		if (!vm_running) {
			/* some unknown "name" */
			errno = ENOENT;
			goto dun;
		}

		res = volmgt_symdev(vol);

	}

dun:
#ifdef	DEBUG
	dexit("fsi_xlate_name: returning %s\n", res ? res : "<null ptr>");
#endif
	return (res);
}
