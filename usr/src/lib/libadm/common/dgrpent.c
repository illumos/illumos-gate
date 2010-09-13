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
 * Copyright (c) 1997,1998,2002 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1 */
/*LINTLIBRARY*/

/*
 * dgrpent.c
 *
 *  Contains functions that deal with the device-group table and are not for
 *  consumption by the general user population.
 *
 *  Functions defined:
 *	_opendgrptab()		Opens the device-group table for commands
 *	_setdgrptab()		Rewinds the open device table
 *	_enddgrptab()		Closes the open device table
 *	_getdgrptabent()	Gets the next entry in the device table
 *	_freedgrptabent()	Frees memory allocated to a device-table entry
 *	_getdgrprec()		Gets a specific record from the device table
 *	_dgrptabpath()		Gets the pathname of the device group file
 */

/*
 *  Header files
 *	<sys/types.h>	System data types
 *	<unistd.h>	Standard UNIX(r) definitions
 *	<stdio.h>	Standard I/O Definitions
 *	<string.h>	String handling definitions
 *	<ctype.h>	Character types and macros
 *	<errno.h>	Errorcode definitions
 *	<sys/stat.h>	File status information
 *	<devmgmt.h>	Global Device Management definitions
 *	"devtab.h"	Local device table definitions
 */

#include	<sys/types.h>
#include	<unistd.h>
#include	<stdio.h>
#include	<string.h>
#include	<ctype.h>
#include	<errno.h>
#include	<sys/stat.h>
#include	<devmgmt.h>
#include	"devtab.h"
#include	<stdlib.h>

/*
 *  Local definitions
 */


/*
 *  Static data definitions:
 *	leftoff		Addr of char to begin next parse using
 *			getfld(), getattrval(), getquoted()
 *	recbufsz	The size of the buffer used for reading records
 *	recbuf		Addr of malloc() buffer for reading records
 *	recnum		Record number of next record to read
 *	xtndcnt		Number of times the buffer has been extended
 */

static	char		*leftoff = NULL;
static	int		recbufsz = 0;
static	char		*recbuf = NULL;
static	int		recnum = 0;
static	int		xtndcnt = 0;

/*
 *  void _setdgrptab()
 *
 *	This function rewinds the open device table so that the next
 *	_getdgrptabent() returns the first record in the device table.
 *
 *  Arguments:  None
 *
 *  Returns:  Void
 */

void
_setdgrptab(void)
{
	/*  If the device table file is open, rewind the file  */
	if (oam_dgroup) {
	    rewind(oam_dgroup);
	    recnum = 0;
	}
}

/*
 *  void _enddgrptab()
 *
 *	This function closes the open device table.  It resets the
 *	open device table external variable to NULL.
 *
 *  Arguments:  None
 *
 *  Returns:  Void
 */

void
_enddgrptab(void)
{
	/*  If the device table file is open, close it  */
	if (oam_dgroup) {
	    (void) fclose(oam_dgroup);
	    recnum = 0;
	    oam_dgroup = NULL;
	}
}

/*
 *  char *getfld(ptr, delims)
 *	char   *ptr
 *	char   *delims
 *
 *  Notes:
 *    -	Can't use "strtok()" because of its use of static data.  The caller
 *	may be using strtok() and we'll really mess them up.
 *    - The function returns NULL if it didn't find any token -- '\0' can't
 *	be a delimiter using this algorithm.
 */

static char *
getfld(
	char   *ptr,		/* String to parse */
	char   *delims)		/* List of delimiters */
{
	char   *p, *q;

	/*
	 *  Figure out where to start.
	 *  If given a pointer, use that.
	 *  Otherwise, use where we left off.
	 */

	p = ptr ? ptr : leftoff;


	/*
	 *  If there's anything to parse, search the string for the first
	 *  occurrence of any of the delimiters.  If one is found, change it
	 *  to '\0' and remember the place to start for next time.  If not
	 *  found, forget the restart address and prepare to return NULL
	 */

	if (p) {
	    while (*p && isspace((unsigned char)*p)) p++;
	    if (*p) {
		q = p;
		while (*q && !strchr(delims, *q)) q++;
		if (*q) {
		    *q++ = '\0';
		    leftoff = q;
		} else leftoff = NULL;
	    } else leftoff = p = NULL;
	}

	/*  Finished  */
	return (p);
}

/*
 *  char *getnextrec()
 *
 *	This function gets the next record from the input stream "oam_dgroup"
 *	and puts it in the device-group table record buffer (whose address is
 *	in "recbuf").  If the buffer is not allocated or is too small to
 *	accommodate the record, the function allocates more space to the
 *	buffer.
 *
 *  Arguments:  None
 *
 *  Returns:  char *
 *	The address of the buffer containing the record.
 *
 *  Static Data Referenced:
 *	recbuf		Address of the buffer containing records read from the
 *			device table file
 *	recbufsz	Current size of the record buffer
 *	xtndcnt		Number of times the record buffer has been extended
 *	oam_dgroup	Device-group table stream, expected to be open for (at
 *			least) reading
 *
 *  Notes:
 *    - The string returned in the buffer <buf> ALWAYS end in a '\n' (newline)
 *	character followed by a '\0' (null).
 */

static char *
getnextrec(void)
{
	/* Automatic data */
	char		*recp;		/* Value to return */
	char		*p;		/* Temp pointer */
	int		done;		/* TRUE if we're finished */
	int		reclen;		/* Number of chars in record */


	/* If there's no buffer for records, try to get one */
	if (!recbuf) {
	    if (recbuf = malloc(DGRP_BUFSIZ)) {
		recbufsz = DGRP_BUFSIZ;
		xtndcnt = 0;
	    } else return (NULL);
	}


	/* Get the next record */
	recp = fgets(recbuf, recbufsz, oam_dgroup);
	done = FALSE;

	/* While we've something to return and we're not finished ... */
	while (recp && !done) {

	    /* If our return string isn't a null-string ... */
	    if ((reclen = (int)strlen(recp)) != 0) {

		/* If we have a complete record, we're finished */
		if (*(recp+reclen-1) == '\n') done = TRUE;
		else while (!done) {

		/*
		 * Need to complete the record.  A complete record is one
		 * which is terminated by a new-line character
		 */

		    /* If the buffer is full, expand it and continue reading */
		    if (reclen == recbufsz-1) {

			/* Have we reached our maximum extension count? */
			if (xtndcnt < XTND_MAXCNT) {

			    /* Expand the record buffer */
			    if (p = realloc(recbuf,
				(size_t)(recbufsz+DGRP_BUFINC))) {

				/* Update buffer information */
				xtndcnt++;
				recbuf = p;
				recbufsz += DGRP_BUFINC;

			    } else {

				/* Expansion failed */
				recp = NULL;
				done = TRUE;
			    }

			} else {

			    /* Maximum extend count exceeded.  Insane table */
			    recp = NULL;
			    done = TRUE;
			}

		    }

		    /* Complete the record */
		    if (!done) {

			/* Read stuff into the expanded space */
			if (fgets(recbuf+reclen, recbufsz-reclen, oam_dgroup)) {
			    reclen = (int)strlen(recbuf);
			    recp = recbuf;
			    if (*(recp+reclen-1) == '\n') done = TRUE;
			} else {
			    /* Read failed, corrupt record? */
			    recp = NULL;
			    done = TRUE;
			}
		    }

		}   /* End incomplete record handling */

	    } else {

		/* Read a null string?  (corrupt table) */
		recp = NULL;
		done = TRUE;
	    }

	}   /* while (recp && !done) */

	/* Return what we've got (if anything) */
	return (recp);
}

/*
 *  char *_dgrptabpath()
 *
 *	Get the pathname of the device-group table file
 *
 *  Arguments:  None
 *
 *  Returns:  char *
 *	Returns the pathname to the device group table of (char *) NULL if
 *	there was a problem getting the memory needed to contain the
 *	pathname.
 *
 *  Algorithm:
 *	1.  If OAM_DGRP is defined in the environment and is not
 *	    defined as "", it returns the value of that environment
 *	    variable.
 *	2.  Otherwise, use the devault pathname (as defined by the
 *	    environment variable DGRP_PATH in <devmgmt.h>.
 */


char *
_dgrptabpath(void)
{

	/* Automatic data */
#ifdef	DEBUG
	char		*path;		/* Ptr to path in environment */
#endif
	char		*rtnval;		/* Ptr to value to return */


	/*
	 * If compiled with -DDEBUG=1,
	 * look for the pathname in the environment
	 */

#ifdef	DEBUG
	if (((path = getenv(OAM_DGROUP)) != NULL) && (*path)) {
	    if (rtnval = malloc(strlen(path)+1))
		(void) strcpy(rtnval, path);
	} else {
#endif
	/*
	 * Use the default name.
	 */

	    if (rtnval = malloc(strlen(DGRP_PATH)+1))
		(void) strcpy(rtnval, DGRP_PATH);

#ifdef	DEBUG
	}
#endif

	/* Finished */
	return (rtnval);
}

/*
 *  int _opendgrptab(mode)
 *	char   *mode
 *
 *	The _opendgrptab() function opens a device-group table for a command.
 *
 *  Arguments:
 *	mode	The open mode to use to open the file.  (i.e. "r" for
 *		reading, "w" for writing.  See FOPEN(BA_OS) in SVID.)
 *
 *  Returns:  int
 *	TRUE if successful, FALSE otherwise
 */

int
_opendgrptab(char *mode)
{
	/* Automatic data */
	char   *dgrptabname;	/* Ptr to the device-group table name */
	int	rtnval;		/* Value to return */

	rtnval = TRUE;
	if (dgrptabname = _dgrptabpath()) {
	    if (oam_dgroup) (void) fclose(oam_dgroup);
	    if (oam_dgroup = fopen(dgrptabname, mode)) {
		xtndcnt = 0;
		recnum = 0;
	    } else rtnval = FALSE;  /* :-( */
	} else rtnval = FALSE;    /* :-( */
	return (rtnval);
}

/*
 *  struct dgrptabent *_getdgrptabent()
 *
 *  	This function returns the next entry in the device-group table.
 *	If no device-group table is open, it opens the standard device-group
 *      table and returns the first record in the table.
 *
 *  Arguments:  None.
 *
 *  Returns:  struct dgrptabent *
 *	Pointer to the next record in the device-group table, or
 *	(struct dgrptabent *) NULL if it was unable to open the file or there
 *	are no more records to read.  "errno" reflects the situation.  If
 *	errno is not changed and the function returns NULL, there are no more
 *	records to read.  If errno is set, it indicates the error.
 *
 *  Notes:
 *    - The caller should set "errno" to 0 before calling this function.
 */

struct dgrptabent *
_getdgrptabent(void)
{
	/*  Automatic data  */
	struct dgrptabent	*ent;		/* Dev table entry structure */
	struct member		*q, *r;		/* Tmps for member structs */
	char			*record;		/* Record just read */
	char			*p;		/* Tmp char ptr */
	int			done;		/* TRUE if built an entry */


	/*  Open the device-group table if it's not already open */
	if (!oam_dgroup)
	    if (!_opendgrptab("r"))
		return (NULL);


	/*  Get space for the structure we're returning  */
	if (!(ent = malloc(sizeof (struct dgrptabent)))) {
	    return (NULL);
	}

	done = FALSE;
	while (!done && (record = getnextrec())) {

	    /* Is this a comment record or a data record */
	    if (strchr("#\n", *record) ||
			isspace((unsigned char)*record)) {

		/*
		 *  Record is a comment record
		 */
		ent->comment = TRUE;
		ent->entryno = recnum++;

		/* Alloc space for the comment and save pointer in struct */
		if (ent->dataspace = malloc(strlen(record)+1)) {
		    (void) strcpy(ent->dataspace, record);
		} else {
		    free(ent);
		    ent = NULL;
		}
		done = TRUE;

	    } else {

		/*
		 *  Record is a data record
		 */
		ent->comment = FALSE;

		/* Extract the device-group name */
		if (p = getfld(record, ":")) {

		/* Record is a proper record */
		    done = TRUE;
		    ent->entryno = recnum++;

		    /* Copy device group name into malloc()ed space */
		    if (!(ent->name = malloc(strlen(p)+1))) {

			free(ent);
			return (NULL);
		    }
		    (void) strcpy(ent->name, p);

			/*
			 * Extract the membership from the membership list
			 */

		    /* Get the 1st member */
		    ent->dataspace = NULL;
		    while (((p = getfld(NULL, ",\n")) != NULL) && !(*p))
			;
		    if (p) {
			if (!(q = malloc(sizeof (struct member)))) {

			    free(ent->name);
			    free(ent);
			    return (NULL);
			}
			if (!(q->name = malloc(strlen(p)+1))) {
			    free(q);
			    free(ent->name);
			    free((char *)ent);
			    return (NULL);
			}
			(void) strcpy(q->name, p);
			ent->membership = q;
			q->next = NULL;

			/* Get the rest of the members */
			while (p = getfld(NULL, ",\n"))
			    if (*p) {
				if (!(r = malloc(sizeof (struct member)))) {
				    for (q = ent->membership; q; q = r) {
					free(q->name);
					r = q->next;
					free(q);
				    }
				    free(ent->name);
				    free(ent);
				    return (NULL);
				}
				if (!(r->name = malloc(strlen(p)+1))) {
				    free(r);
				    for (q = ent->membership; q; q = r) {
					free(q->name);
					r = q->next;
					free(q);
				    }
				    free(ent->name);
				    free(ent);
				    return (NULL);
				}

				q->next = r;
				(void) strcpy(r->name, p);
				r->next = NULL;
				q = r;
			    }

		    } else {
			/* No members */
			ent->membership = NULL;
		    }

		}   /* record contains a group name */

	    }   /* record is a data record */

	}   /* while (!done && there's more records) */


	/*  An entry read?  If not, free alloc'd space and return NULL */
	if (!done) {
	    free(ent);
	    ent = NULL;
	}

	/* Finis */
	return (ent);
}

/*
 *  void _freedgrptabent(dgrptabent)
 *	struct dgrptabent       *dgrptabent;
 *
 *	This function frees space allocated to a device table entry.
 *
 *  Arguments:
 *	struct dgrptabent *dgrptabent	The structure whose space is to be
 *					freed.
 *
 *  Returns:  void
 */

void
_freedgrptabent(struct dgrptabent *ent)	/* Structure to free */
{
	/*
	 * Automatic data
	 */

	struct member  *p;		/* Structure being freed */
	struct member  *q;		/* Next structure to free */

	/*
	 *  Free the space allocated to the membership structure.
	 */

	if (!ent->comment) {
	    if ((q = ent->membership) != NULL) do {
		p = q;
		q = p->next;
		if (p->name) free(p->name);
		free(p);
	    } while (q);

	    /* Free the device group name */
	    if (ent->name) free(ent->name);
	}

	/* Free the membership string */
	if (ent->dataspace) free(ent->dataspace);
}

/*
 *  struct dgrptabent *_getdgrprec(dgroup)
 *	char *dgroup
 *
 *	Thie _getdgrprec() function returns a pointer to a structure that
 *	contains the information in the device-group table entry that describes
 *	the device-group <dgroup>.
 *
 *  Arguments:
 *	char *dgroup	A character-string describing the device-group whose
 *			record is to be retrieved from the device-group table.
 *
 *  Returns:  struct dgrptabent *
 *	A pointer to a structure describing the device group.
 */

struct dgrptabent *
_getdgrprec(char *dgroup)		/* dgroup to search for */
{
	/*
	 *  Automatic data
	 */

	struct dgrptabent	*dgrprec;	/* Pointer to current record */
	int			found;		/* FLAG, TRUE if found */


	/*
	 *  Search the device-group table looking for the requested
	 *  device group
	 */

	_setdgrptab();
	errno = 0;
	found = FALSE;
	while (!found && (dgrprec = _getdgrptabent())) {
	    if (!dgrprec->comment && strcmp(dgroup, dgrprec->name) == 0)
		found = TRUE;
	    else _freedgrptabent(dgrprec);
	}

	/*  Set up return codes if we've failed  */
	if (!found) {
	    if (errno == 0) errno = EINVAL;
	    dgrprec = NULL;
	}

	/*  Finis  */
	return (dgrprec);
}
