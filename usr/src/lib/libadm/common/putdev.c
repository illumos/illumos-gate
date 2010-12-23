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
 * putdev.c
 *
 * Global Definitions:
 *	_adddevtabrec()		Add a record to the device table
 *	_putdevtabrec()		Write a record to the device table
 *	_moddevtabrec()		Modify a device-table record
 *	_rmdevtabrec()		Remove a device-table record
 *	_rmdevtabattrs()	Remove attributes from a device-table record
 *	oam_devtab		File descriptor of the open device table
 */

/*
 *  G L O B A L   R E F E R E N C E S
 *
 *	Header Files
 *	Externals Referenced
 */

/*
 * Header Files
 *	<sys/types.h>		UNIX(r) Data Types
 *	<sys/stat.h>
 *	<stdio.h>		Standard I/O definitions
 *	<fcntl.h>		Definitions for file control
 *	<errno.h>		Error handling definitions
 *	<string.h>		String Handling Definitions
 *	<devmgmt.h>		Device Management Definitions
 *	<unistd.h>		Get UNIX(r) Standard Definitions
 *	"devtab.h"		Local Device Management Definitions
 */

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<stdio.h>
#include	<fcntl.h>
#include	<errno.h>
#include	<string.h>
#include	<devmgmt.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	"devtab.h"

/*
 *  L O C A L   D E F I N I T I O N S
 *
 *	TDTABNM		Name of the temporary device table (in the
 *			directory of the existing table)
 *	TDTABNMLN	Number of characters added to the directory
 *			name -- the length of the device table temp name
 */

#define	TDTABNM		"%sdevtab.%6.6d"
#define	TDTABNMLN	13


/*
 * Static functions
 *	strcatesc	Copies a character-string from one place to another
 *			escaping the appropriate characters
 *	lkdevtab	Locks the device table
 *	unlkdevtab	Unlocks the device table
 *	mkdevtabent	Builds a device-table entry from the alias and the
 *			list of attr=val pairs given
 *	opennewdevtab	Opens a new device table (as a temp file)
 *	mknewdevtab	Makes the temp device table the new devtab
 *	rmnewdevtab	Remove the temporary device table and free space
 *			allocated to the filename of that file.
 */

static	char			*strcatesc(char *, char *);
static	int			lkdevtab(char *, short);
static	int			unlkdevtab(void);
static	struct devtabent	*mkdevtabent(char *, char **);
static	FILE			*opennewdevtab(char **);
static	int			mknewdevtab(char *);
static	int			rmnewdevtab(char *);

/*
 * char *strcatesc(p, q)
 *	char   *p
 *	char   *q
 *
 *	Write the character-string pointed to by "q" to the place
 *	pointed to by "p", escaping those characters in "q" found in the
 *	string "DTAB_ESCS" by preceding them with '\\'.  Return a pointer to
 *	the byte beyond the last character written to "p".
 *
 *  Arguments:
 *	p		The place to begin writing to
 *	q		The string to write
 *
 *  Returns:  char *
 *	The address of the byte beyond the last character written into "p"
 */

static char *
strcatesc(
	char   *p,		/* Place to write to */
	char   *q)		/* Thing to write */
{
	while (*q) {
	    if (strchr(DTAB_ESCS, *q)) *p++ = '\\';
	    *p++ = *q++;
	}
	return (p);
}

/*
 * FILE *opennewdevtab(pname)
 *	char   **pname
 *
 *	Generates a temporary device-table name from the existing
 *	device table name (in the same directory) and opens that
 *	file for writing.  It puts a pointer to the malloc()ed space
 *	containing the temp device table's name at the place referenced
 *	by <pname>.
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
opennewdevtab(char  **pname)		/* A(ptr to temp filename's path) */
{
	char   *oldname;		/* Ptr to the device-table's name */
	char   *buf;			/* Ptr to the temp file's name */
	char   *dirname;		/* Directory containing devtab */
	char   *p;			/* Ptr to last '/' in devtab name */
	int    fd;			/* Opened file descriptor */
	FILE   *fp;			/* Opened file pointer */
	struct stat64	sbuf;		/* stat buf for old devtab file */

	fp = NULL;
	if (oldname = _devtabpath()) {
	/*
	 * It is possible for us to have sufficient permissions to create
	 * the new file without having sufficient permissions to write the
	 * original devtab file.  For consistency with the operations which
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

	    if (p = strrchr(oldname, '/')) {
		*(p+1) = '\0';
		dirname = oldname;
	    } else dirname = "./";
	    if (buf = malloc(TDTABNMLN + strlen(dirname) + 1)) {

		/*
		 * Build the name of the temp device table and open the
		 * file.  We must reset the owner, group and perms to those
		 * of the original devtab file.
		 */
		(void) sprintf(buf, TDTABNM, dirname, getpid());
		if (fp = fopen(buf, "w")) {
			*pname = buf;
			(void) fchmod(fileno(fp), sbuf.st_mode & 0777);
			(void) fchown(fileno(fp), sbuf.st_uid, sbuf.st_gid);
		} else {
			free(buf);
		}
	    }

	/*
	 *
	 * Free the space containing the device table's name.
	 */
	    free(oldname);
	}

	/* Finished.  Return what we've got */
	return (fp);
}

/*
 *  int rmnewdevtab(tempname)
 *	char   *tempname
 *
 *	Unlink the temp device table and free the memory allocated to
 *	contain the name of that file
 *
 *  Arguments:
 *	tempname	Name of the temporary file
 *
 *  Returns: int
 *	TRUE if successful, FALSE otherwise
 */

static int
rmnewdevtab(char *tempname)	/* Filename of new device table */
{
	int	noerr;		/* Flag, TRUE if no error, FALSE otherwise */

	/* Unlink the file */
	noerr = (unlink(tempname) == 0);

	/* Free the space allocated to the filename */
	free(tempname);

	/* Return success indicator */
	return (noerr);
}

/*
 *  int mknewdevtab(tempname)
 *	char   *tempname
 *
 *	Make the temporary device-table the new system device table
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
 *	  of the device-table more than once.  Done so that we don't
 *	  have to manage that space, but this may be somewhat lazy.
 */

static int
mknewdevtab(char   *tempname)		/* Ptr to name of temp dev tab */
{
	char   *devtabname;		/* Ptr to the device table's name */
	int	noerr;			/* FLAG, TRUE if all's well */

	/* Get the device table's pathname */
	if (devtabname = _devtabpath()) {

	    /* Unlink the existing file */
	    if (unlink(devtabname) == 0) {

		/* Make the temp file the real device table */
		noerr = (link(tempname, devtabname) == 0) ? TRUE : FALSE;

		/* Remove the temp file (and resources) */
		if (noerr) (void) rmnewdevtab(tempname);

	    } else noerr = FALSE;	/* unlink() failed */

	    /* Free the device table's name */
	    free(devtabname);

	} else noerr = FALSE; 	/* devtabpath() failed */

	/* Finished.  Return success indicator */
	return (noerr);
}

/*
 * static int lkdevtab(o_mode, lktype)
 *	char   *o_mode
 *	short	lktype
 *
 *	Lock the device table for writing.  If it isn't available, it waits
 *	until it is.
 *
 *  Arguments:
 *	o_mode	The open() mode to use when opening the device table
 *	lktype	The type of lock to apply
 *
 *  Returns:  int
 *	TRUE if successful, FALSE with errno set otherwise
 */

static int
lkdevtab(
	char   *o_mode,				/* Open mode */
	short	lktype)				/* Lock type */
{
	/* Automatic data */
	struct flock	lockinfo;		/* File locking structure */
	int		noerr;			/* FLAG, TRUE if no error */
	int		olderrno;		/* Old value of "errno" */


	/* Close the device table (if it's open) */
	_enddevtab();

	/* Open the device table for read/append */
	noerr = TRUE;
	if (_opendevtab(o_mode)) {

	/*
	 * Lock the device table (for writing).  If it's not
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
	    while ((fcntl(fileno(oam_devtab), F_SETLK, &lockinfo) == -1) &&
		!noerr) {
		if (errno == EACCES) {
		    if (fcntl(fileno(oam_devtab), F_SETLKW, &lockinfo) == -1)
			noerr = FALSE;
		    else {
			/* Reopen the file (maybe it's moved?) */
			_enddevtab();
			if (!_opendevtab(o_mode)) noerr = FALSE;
			else errno = olderrno;
		    }
		} else noerr = FALSE;
	    }

	    if (!noerr) _enddevtab();  /* Don't keep open if in error */

	} else noerr = FALSE;

	/* Done */
	return (noerr);
}

/*
 * int unlkdevtab()
 *
 *	Unlock the locked device table.
 *
 *  Arguments:  None
 *
 *  Returns:  int
 *	Whatever fcntl() returns...
 */

static int
unlkdevtab(void)
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
	noerr = (fcntl(fileno(oam_devtab), F_SETLK, &lockinfo) != -1);
	_enddevtab();

	/* Finished */
	return (noerr);
}

/*
 * struct devtabent *mkdevtabent(alias, attrlist)
 *	char   *alias
 *	char  **attrlist
 *
 *	This function builds a struct devtabent structure describing the
 *	alias <alias> using the information in the attribute list <attrlist>.
 *	The <attrlist> contains data of the form attr=value where attr is
 *	the name of an attribute and value is the value of that attribute.
 *
 *  Arguments:
 *	alias		The alias being added to the device table
 *	attrlist	The attributes and values for that alias
 *
 *  Returns:  struct devtabent *
 *	A completed struct devtabent structure containing the description
 *	of the alias.  The structure, and all of the data in the structure
 *	are each in space allocated using the malloc() function and should
 *	be freed using the free() function (or the _freedevtabent() function).
 *
 *  Errors:
 *	EINVAL	If "alias" is used as an attribute in an attr=val pair
 *	EAGAIN	If an attribute is specified more than once
 */

static struct devtabent *
mkdevtabent(
	char   *alias,		/* Alias of entry */
	char  **attrlist)	/* Attributes of new entry */
{
	/* Automatic data */
	struct devtabent	*devtabent;	/* * to struct we're making */
	struct attrval		*prevattrval;	/* * to prev attr/val struct */
	struct attrval		*attrval;	/* * to current struct */
	char			**pp;		/* Ptr into list of ptrs */
	char			*peq;		/* Ptr to '=' in string */
	char			*val;		/* Ptr to space for value */
	char			*name;		/* Ptr to space for name */
	ssize_t			len;		/* Length of name */
	int			noerr;		/* TRUE if all's well */
	int			found;		/* TRUE the attr is found */


	/* No problems (yet) */
	noerr = TRUE;

	/* Get space for the structure */
	if (devtabent = malloc(sizeof (struct devtabent))) {

	    /* Fill in default values */
	    if (devtabent->alias = malloc(strlen(alias)+1)) {

		(void) strcpy(devtabent->alias, alias);		/* alias */
		devtabent->comment = FALSE;			/* data rec */
		devtabent->cdevice = NULL;			/* cdevice */
		devtabent->bdevice = NULL;			/* bdevice */
		devtabent->pathname = NULL;			/* pathname */
		devtabent->attrstr = NULL;			/* string */
		devtabent->attrlist = NULL;			/* attr list */

		/* Add attributes to the structure */
		prevattrval = NULL;
		if ((pp = attrlist) != NULL)
		    while (*pp && noerr) {

		    /* Valid attr=value pair? */
		    if (((peq = strchr(*pp, '=')) != NULL) &&
			((len = peq - *pp) > 0)) {

			/* Get space for the value */
			if (val = malloc(strlen(peq))) {
			    (void) strcpy(val, peq+1);		/* Copy it */

			    /* Get space for attribute name */
			    if (name = malloc((size_t)(len + 1))) {
				(void) strncpy(name, *pp, (size_t)len);
				*(name+len) = '\0';

				/* Specifying the alias?  If so, ERROR */
				if (strcmp(name, DTAB_ALIAS) == 0) {
				    noerr = FALSE;
				    free(name);
				    free(val);
				    errno = EINVAL;
				}

				/* Specifying the char device path? */
				else if (strcmp(name, DTAB_CDEVICE) == 0) {
				    if (!devtabent->cdevice) {
					if (val[0] != '/') {
						noerr = FALSE;
						free(name);
						free(val);
						errno = ENXIO;
					} else {
						devtabent->cdevice = val;
						free(name);
					}
				    } else {
					noerr = FALSE;
					free(name);
					free(val);
					errno = EAGAIN;
				    }
				}

				/* Specifying the block device path? */
				else if (strcmp(name, DTAB_BDEVICE) == 0) {
				    if (!devtabent->bdevice) {
					if (val[0] != '/') {
						noerr = FALSE;
						free(name);
						free(val);
						errno = ENXIO;
					} else {
						devtabent->bdevice = val;
						free(name);
					}
				    } else {
					noerr = FALSE;
					free(name);
					free(val);
					errno = EAGAIN;
				    }
				}

				/* Specifying the pathname (generic)? */
				else if (strcmp(name, DTAB_PATHNAME) == 0) {
				    if (!devtabent->pathname) {
					if (val[0] != '/') {
						noerr = FALSE;
						free(name);
						free(val);
						errno = ENXIO;
					} else {
						devtabent->pathname = val;
						free(name);
					}
				    } else {
					noerr = FALSE;
					free(name);
					free(val);
					errno = EAGAIN;
				    }
				}

				/* Some other attribute */
				else {
				    found = FALSE;
				    if ((attrval = devtabent->attrlist) != NULL)
					do {
					    if (strcmp(attrval->attr,
						name) == 0) {

						noerr = FALSE;
						free(name);
						free(val);
						errno = EAGAIN;
					    }
					} while (!found && noerr &&
					    (attrval = attrval->next));

				    if (!found && noerr) {

					/* Get space for attr/val structure */
					if (attrval =
					    malloc(sizeof (struct attrval))) {

					    /* Fill attr/val structure */
					    attrval->attr = name;
					    attrval->val = val;
					    attrval->next = NULL;

					/*
					 * Link into the list of attributes
					 */
					    if (prevattrval)
						prevattrval->next = attrval;
					    else devtabent->attrlist = attrval;
					    prevattrval = attrval;

					} else {
					    /* malloc() for attrval failed */
					    noerr = FALSE;
					    free(name);
					    free(val);
					}
				    }
				}   /* End else (some other attribute) */

			    } else { 	/* malloc() for attribute name failed */
				noerr = FALSE;
				free(val);
			    }

			} else noerr = FALSE;	/* Malloc() for "val" failed */

			/* If we saw an error, free structure, returning NULL */
			if (!noerr) {
			    _freedevtabent(devtabent);
			    devtabent = NULL;
			}

		    } 	/* Ignore invalid attr=val pair */

		    if (noerr) pp++;

		}   /* End attribute processing loop */

	    } else {	/* malloc() failed */
		free(devtabent);
		devtabent = NULL;
	    }
	}

	/* Finished */
	return (devtabent);
}

/*
 * int _putdevtabrec(stream, rec)
 *	FILE		       *stream
 *	struct devtabent       *rec
 *
 *	Write a device table record containing the information in the struct
 *	devtab structure <rec> to the current position of the standard I/O
 *	stream <stream>.
 *
 *  Arguments:
 *	stream		The stream to write to
 *	rec		The structure containing the information to write
 *
 *  Returns:  int
 *	The number of characters written or EOF if there was some error.
 */

int
_putdevtabrec(
	FILE			*stream,	/* Stream to which to write */
	struct devtabent	*rec)		/* Record to write */
{
	/* Automatic Data */
	struct attrval		*attrval;	/* Ptr to attr/val pair */
	char			*buf;		/* Allocated buffer */
	char			*p;		/* Temp char pointer */
	int			count;		/* Number of chars written */
	size_t			size = 0;	/* Size of needed buffer */


	/* Comment or data record? */
	if (rec->comment) {

	/*
	 * Record is a comment
	 */

	    /* Copy (escaping chars) record into temp buffer */
	    size = (strlen(rec->attrstr)*2)+1;		/* Max rec size */
	    if (buf = malloc(size+1)) {
		/* Alloc space */
		p = strcatesc(buf, rec->attrstr);	/* Copy "escaped" */
		*(p-2) = '\n';				/* Unescape last \n */
		*(p-1) = '\0';				/* Terminate string */

		/* Write the record */
		count = fputs(buf, stream);
		free(buf);

	    } else count = EOF;  /* malloc() failed */
	}

	else {

		/*
		 * Record is a data record
		 */

		/*
		 * Figure out maximum amount of space you're going to need.
		 * (Assume every escapable character is escaped to determine the
		 * maximum size needed)
		 */

	    if (rec->cdevice)
		size += (strlen(rec->cdevice)*2) + 1;	/* cdevice: */
	    if (rec->bdevice)
		size += (strlen(rec->bdevice)*2) + 1;	/* bdevice: */
	    if (rec->pathname)
		size += (strlen(rec->pathname)*2) + 1;	/* pathname: */
	    if ((attrval = rec->attrlist) != NULL) do {	/* Attributes */
		if (attrval->attr)
			size += (strlen(attrval->attr)*2);	    /* attr */
		if (attrval->val) {
			/* val & '="" ' or val & '=""\n' */
			size += (strlen(attrval->val)*2) +4;
		}
	    } while ((attrval = attrval->next) != NULL);    /* Next attr/val */
	    else size++;		/* Else make room for trailing '\n' */

	    /* Alloc space for "escaped" record */
	    if (buf = malloc(size+1)) {

		/* Initializations */
		p = buf;

		/* Write the alias ("alias" attribute) */
		p = strcatesc(p, rec->alias);
		*p++ = ':';

		/* Write the character device ("cdevice" attribute) */
		if (rec->cdevice) p = strcatesc(p, rec->cdevice);
		*p++ = ':';

		/* Write the block device ("bdevice" attribute) */
		if (rec->bdevice) p = strcatesc(p, rec->bdevice);
		*p++ = ':';

		/* Write the pathname ("pathname" attribute) */
		if (rec->pathname) p = strcatesc(p, rec->pathname);
		*p++ = ':';

		/* Write the rest of the attributes */
		if ((attrval = rec->attrlist) != NULL)
		    do {
			p = strcatesc(p, attrval->attr);
			*p++ = '=';
			*p++ = '"';
			p = strcatesc(p, attrval->val);
			*p++ = '"';
			if ((attrval = attrval->next) != NULL)
			    *p++ = ' ';
		    } while (attrval);

		/* Terminate the record */
		*p++ = '\n';
		*p = '\0';

		/* Write the record */
		count = fputs(buf, stream);
		free(buf);
	    } else count = EOF;  /* malloc() failed */
	}

	/* Finished */
	return (count);
}

/*
 *  int _adddevtabrec(alias, attrval)
 *	char   *alias
 *	char  **attrval
 *
 *	This function adds a record to the device table.  That record will
 *	have the alias <alias> and will have the attributes described in
 *	the list referenced by <attrval>.
 *
 *	It always adds the record to the end of the table.
 *
 *  Arguments:
 *	alias		The alias of the device whose description is being
 *			added to the device table.
 *	attrval		The pointer to the first item of a list of attributes
 *			defining the device whose description is being added.
 *			(This value may be (char **) NULL).
 *
 *  Returns:  int
 *	TRUE if successful, FALSE with errno set otherwise.
 */

int
_adddevtabrec(
	char   *alias,			/* Alias to add to the device table */
	char  **attrval)		/* Attributes for that device */
{
	/* Automatic data */
	struct devtabent	*devtabent;	/* Ptr to dev tab entry */
	int			olderrno;	/* Errno on entry */
	int			noerr;		/* FLAG, TRUE if all's well */

	/* Validate the device alias.  Error (EINVAL) if it's not valid */
	if (!_validalias(alias)) {
	    errno = EINVAL;
	    return (FALSE);
	}

	/*
	 * Lock the device table.  This only returns if the table is locked or
	 * some error occurred.  It waits until the table is available.
	 */
	if (!lkdevtab("a+", F_WRLCK))
		return (FALSE);

	/* Make sure that the alias isn't already in the table */
	noerr = TRUE;
	olderrno = errno;
	if (devtabent = _getdevrec(alias)) {

	    /* The alias is already in the table */
	    _freedevtabent(devtabent);		/* Free device table info */
	    errno = EEXIST;			/* Set errno, entry exists */
	    noerr = FALSE;			/* All's not well */
	} else if ((errno == ENOENT) || (errno == ENODEV)) {

	    /* The alias wasn't in the table or there wasn't a table. */

	    errno = olderrno;			/* Reset errno */

	    /* Build a struct devtabent that describes the new alias */
	    if (devtabent = mkdevtabent(alias, attrval)) {

		/* Position to the end of the existing table */
		if (fseek(oam_devtab, 0, SEEK_END) == 0)

		    /* Write the new entry */
		    noerr = (_putdevtabrec(oam_devtab, devtabent) != EOF);

		/* Free the info we just wrote */
		_freedevtabent(devtabent);

	    } else noerr = FALSE;	/* mkdevtabent() failed */
	} else noerr = FALSE;		/* Some odd error, _devtab */

	/* Unlock and close the device table */
	(void) unlkdevtab();

	/* Fini */
	return (noerr);
}

/*
 * int _moddevtabrec(device, attrval)
 *	char   *device
 *	char  **attrval
 *
 *	This function modifies the description for the specified device
 *	so that it has the attributes and values as specified in the
 *	given list.
 *
 *  Arguments:
 *	device		The name of the device whose description
 *			is being modified
 *	attrval		The first attr/val value in the list (attr=val) of
 *			the attributes that are to change
 *
 *  Returns:  int
 *	TRUE if all went well, FALSE with errno set otherwise
 */

int
_moddevtabrec(
	char   *device,			/* Device to modify */
	char  **attrval)		/* Attributes to add or change */
{
	/* Automatic data */
	FILE			*fd;	/* File ptr, new device table */
	struct devtabent	*ent;	/* Device's current description */
	struct devtabent	*chg;	/* Changes to make to description */
	struct attrval		*new;	/* New attribute/value desc */
	struct attrval		*old;	/* Old attribute/value desc */
	struct attrval		*newnew; /* Next "new" value to look at */
	struct attrval		*prevnew; /* Previous item in the 'new' list */
	char			*tname;	/* name of temp devtab file */
	int			noerr;	/* FLAG, TRUE if all's well */
	int			found;	/* FLAG, TRUE if attr found for dev */

	/* Lock the device table */
	if (!lkdevtab("r", F_WRLCK))
		return (FALSE);

	/* No problems (so far) */
	noerr = TRUE;

	/* Get the entry to modify */
	if (ent = _getdevrec(device)) {

	    /* Build a structure describing the changes */
	    if (chg = mkdevtabent(device, attrval)) {

		/* If the "cdevice" field is specified, change it */
		if (chg->cdevice) {
		    if (ent->cdevice) free(ent->cdevice);
		    ent->cdevice = chg->cdevice;
		    chg->cdevice = NULL;
		}

		/* If the "bdevice" field is specified, change it */
		if (chg->bdevice) {
		    if (ent->bdevice) free(ent->bdevice);
		    ent->bdevice = chg->bdevice;
		    chg->bdevice = NULL;
		}

		/* If the "pathname" field is specified, change it */
		if (chg->pathname) {
		    if (ent->pathname) free(ent->pathname);
		    ent->pathname = chg->pathname;
		    chg->pathname = NULL;
		}

		/* Change the other attributes (if any) */
		if (ent->attrlist) {
		    prevnew = NULL;
		    if ((new = chg->attrlist) != NULL) do {

			found = FALSE;
			for (old = ent->attrlist; !found && old;
			    old = old->next) {
			    if (strcmp(old->attr, new->attr) == 0) {
				found = TRUE;
				free(old->val);
				old->val = new->val;
				new->val = NULL;
			    }
			}   /* Loop through the existing attribute list */

			/*
			 * If the attribute wasn't found, add it to the list
			 * of attributes for the device.  If it was found, just
			 * bump to the next one and look for it
			 */

			if (!found) {

			/*
			 * Not found.  Move attr/val description to the
			 * device's list of attributes
			 */

			    if (prevnew) prevnew->next = new->next;
			    else chg->attrlist = new->next;
			    newnew = new->next;
			    new->next = ent->attrlist;
			    ent->attrlist = new;
			    new = newnew;
			} else {

			    /* Attribute changed, bump to the next one */
			    prevnew = new;
			    new = new->next;
			}
		    } while (new);  /* Loop for each attr to add or modify */

		} else {

		    /* Device had no attributes -- add entire list */
		    ent->attrlist = chg->attrlist;
		    chg->attrlist = NULL;
		}

		/* Free the structure containing the changes */
		_freedevtabent(chg);

	    } else noerr = FALSE;   /* Couldn't build changes struct */

	    /* If there hasn't been an error (so far), write the new record */
	    if (noerr) {

		/* Open the new device table */
		if (fd = opennewdevtab(&tname)) {

		/*
		 * For each entry in the existing table, write that entry
		 * to the new table.  If the entry is the one being
		 * modified, write the modified entry instead of the
		 * original entry.
		 */

		    _setdevtab();		/* Rewind existing table */
		    chg = ent;			/* Remember new record */
		    while (((ent = _getdevtabent()) != NULL) && noerr) {
			if (ent->entryno != chg->entryno)
			    noerr = _putdevtabrec(fd, ent) != EOF;
			else noerr = _putdevtabrec(fd, chg) != EOF;
			_freedevtabent(ent);
		    }

		/*
		 * If we successfully generated the new table, make it the
		 * new system device table.  Otherwise, just remove the
		 * temporary file we've created.
		 */

		    if (noerr) {
			(void) fclose(fd);
			noerr = mknewdevtab(tname);
		    } else {
			(void) fclose(fd);
			(void) rmnewdevtab(tname);
		    }

		    /* Free the changed device structure */
		    _freedevtabent(chg);

		}   /* if (_opennewdevtab()) */
		else noerr = FALSE;

	    } else _freedevtabent(ent);  /* if (noerr) */

	} else noerr = FALSE;	/* Device not found? */

	/* Finished.  Unlock the device table and quit */
	(void) unlkdevtab();
	return (noerr);
}

/*
 * int _rmdevtabrec(device)
 *	char   *device
 *
 *	This function removes the record in the device table for the specified
 *	device.
 *
 *  Arguments:
 *	device	The device (alias, cdevice, bdevice, pathname, or link to one)
 *		whose entry is to be removed
 *
 *  Returns:  int
 *	Success indicator:  TRUE if successful, FALSE with errno set otherwise.
 */

int
_rmdevtabrec(char *device)		/* Device to remove */
{
	struct devtabent	*rment;
	struct devtabent	*devtabent;
	char			*tempname;
	FILE			*fd;
	int			noerr;

	if (!lkdevtab("r", F_WRLCK))
		return (FALSE);
	noerr = TRUE;
	if (rment = _getdevrec(device)) {
	    if (fd = opennewdevtab(&tempname)) {
		_setdevtab();
		while (((devtabent = _getdevtabent()) != NULL) && noerr) {
		    if (devtabent->entryno != rment->entryno)
			noerr = _putdevtabrec(fd, devtabent) != EOF;
		    _freedevtabent(devtabent);
		}
		if (noerr) {
		    (void) fclose(fd);
		    noerr = mknewdevtab(tempname);
		} else {
		    (void) fclose(fd);
		    (void) rmnewdevtab(tempname);
		}
	    } else noerr = FALSE;
	    _freedevtabent(rment);
	} else noerr = FALSE;
	(void) unlkdevtab();
	return (noerr);
}

/*
 * int _rmdevtabattrs(device, attributes, notfounds)
 *	char   *device
 *	char  **attributes
 *	char ***notfounds
 *
 *	Remove the specified attributes from the specified device.  The
 *	device is specified by <device>, <attributes> is the address of
 *	the first char * in the list of char * pointing to the attributes
 *	to remove from the device, and <notfounds> is the address of a
 *	char ** to put the address of the first element in the malloc()ed
 *	list of (char *) pointing to requested attributes that were not
 *	defined for the device <device>.
 *
 *  Arguments:
 *	device		The device from which attributes are to be removed
 *	attributes	The address of the first element in the list of
 *			attributes to remove.  This list is terminated by
 *			(char *) NULL.
 *	notfounds	The place to put the address of the list of addresses
 *			referencing the requested attributes that are not
 *			defined for the specified device.
 *
 *  Returns: int
 *	TRUE if successful, FALSE with errno set otherwise.
 *
 *  Notes:
 *    -	"alias" may not be undefined
 *    - "cdevice", "bdevice", and "pathname" are made "null", not really
 *	undefined
 */

int
_rmdevtabattrs(
	char   *device,			/* Device to modify */
	char  **attributes,		/* Attributes to remove */
	char ***notfounds)		/* Attributes req'd but not found */
{
	/* Automatics */
	char			**pnxt;		/* Ptr to next attribute */
	char			**pp;		/* Ptr to current attr name */
	struct devtabent	*modent;	/* Entry being modified */
	struct devtabent	*devtabent;	/* Entry being copied */
	struct attrval		*attrval;	/* Ptr to attr/val desc */
	struct attrval		*prevattrval;	/* Ptr to prev attr/val */
	FILE			*fd;		/* File desc, temp file */
	char			*tempname;	/* Name of temp file */
	int			nattrs;		/* Number of attrs to remove */
	int			nobaderr;	/* TRUE if no fatal error */
	int			noerr;		/* TRUE if no non-fatal error */
	int			found;		/* TRUE if attribute found */
	int			nonotfounds;	/* TRUE if no attrs not fount */


	/* Initializations */
	nobaderr = TRUE;
	noerr = TRUE;

	/* Count attributes to remove -- make sure "alias" isn't specified */
	for (pp = attributes, nattrs = 0; *pp; pp++, nattrs++)
	    if (strcmp(*pp, DTAB_ALIAS) == 0) {
		*notfounds = NULL;
		errno = EINVAL;
		return (FALSE);
	    }

	/* Lock the device table */
	if (!lkdevtab("r", F_WRLCK))
		return (FALSE);

	/* Is there a record for the requested device? */
	if (modent = _getdevrec(device)) {

	    /* Record found.  Try to modify it */
	    nonotfounds = TRUE;

	    /* For each of the attributes in the attribute list ... */
	    for (pp = attributes; nobaderr && *pp; pp++) {

		/*
		 * Modify the device description, removing the requested
		 * attributes from the structure
		 */

		found = FALSE;				/* Not found yet */

		/* If it's the "cdevice" attribute, make it a null-string */
		if (strcmp(*pp, DTAB_CDEVICE) == 0) {
		    if (modent->cdevice) {
			free(modent->cdevice);
			modent->cdevice = NULL;
		    }
		    found = TRUE;
		}

		/* If it's the "bdevice" attribute, make it a null-string */
		else if (strcmp(*pp, DTAB_BDEVICE) == 0) {
		    if (modent->bdevice) {
			free(modent->bdevice);
			modent->bdevice = NULL;
		    }
		    found = TRUE;
		}

		/* If it's the "pathname" attribute, make it a null-string */
		else if (strcmp(*pp, DTAB_PATHNAME) == 0) {
		    if (modent->pathname) {
			free(modent->pathname);
			modent->pathname = NULL;
		    }
		    found = TRUE;
		}

		/* Must be one of the other "auxilliary" attributes */
		else {

		    /* Search the attribute list for the attribute */
		    prevattrval = NULL;
		    if ((attrval = modent->attrlist) != NULL) do {
			if (strcmp(*pp, attrval->attr) == 0) {

			    /* Found.  Remove from attribute list */
			    found = TRUE;
			    free(attrval->attr);
			    free(attrval->val);
			    if (prevattrval) {
				prevattrval->next = attrval->next;
				free(attrval);
				attrval = prevattrval->next;
			    } else {
				modent->attrlist = attrval->next;
				free(attrval);
				attrval = modent->attrlist;
			    }
			} else {
			    prevattrval = attrval;	/* Advance to next */
			    attrval = attrval->next;
			}
		    } while (!found && attrval);

		}   /* End attribute search loop */

		/*
		 * If the requested attribute wasn't defined for the device,
		 * put it in the list of attributes not found
		 */

		if (!found) {

			/*
			 * If there's no list (yet), alloc enough space for
			 * the list
			 */

		    if (nonotfounds)
			if (*notfounds = malloc(sizeof (char **)*(nattrs+1))) {

			    /* List allocated -- put in the first entry */
			    nonotfounds = FALSE;
			    pnxt = *notfounds;
			    if (*pnxt = malloc(strlen(*pp)+1)) {
				errno = EINVAL;
				noerr = FALSE;
				(void) strcpy(*pnxt++, *pp);
			    } else {
				/* malloc() failed, free list */
				free(*notfounds);
				*notfounds = NULL;
				nonotfounds = TRUE;
				nobaderr = FALSE;
			    }

			} else nobaderr = FALSE;  /* malloc() failed */

		    else {
			/* Already a list, add this attribute to it */
			if (*pnxt = malloc(strlen(*pp)+1))
			    (void) strcpy(*pnxt++, *pp);
			else {
			    /* Out of memory, clean up */
			    for (pnxt = *notfounds; *pnxt; pnxt++)
				free(*pnxt);
			    free(*notfounds);
			    *notfounds = NULL;
			    nonotfounds = TRUE;
			    nobaderr = FALSE;
			}
		    }

		}    /* end if (!found) */

		/* Terminate the not-found list */
		if (!nonotfounds) *pnxt = NULL;

	    }	/* end (for each attribute in attribute list) loop */


		/*
		 * If we haven't seen any problems so far,
		 * write the new device table
		 */

	    if (nobaderr) {

		/* Open the new device table */
		if (fd = opennewdevtab(&tempname)) {

		/*
		 * For each entry in the existing table, write that entry
		 * to the new table.  If the entry is the one being
		 * modified, write the modified entry instead of the
		 * original entry.
		 */

		    _setdevtab();		/* Rewind existing table */
		    while (((devtabent = _getdevtabent()) != NULL) &&
			nobaderr) {

			if (devtabent->entryno != modent->entryno)
			    nobaderr = _putdevtabrec(fd, devtabent) != EOF;
			else nobaderr = _putdevtabrec(fd, modent) != EOF;
			_freedevtabent(devtabent);
		    }

		/*
		 * If we successfully generated the new table, make it the
		 * new system device table.  Otherwise, just remove the
		 * temporary file we've created.
		 */

		    if (nobaderr) {
			(void) fclose(fd);
			nobaderr = mknewdevtab(tempname);
		    } else {
			(void) fclose(fd);
			(void) rmnewdevtab(tempname);
		    }

		}   /* if (_opennewdevtab()) */
		else nobaderr = FALSE;

		/*
		 * If there was some error, we need to clean up
		 * allocated resources
		 */
		if (!nobaderr && !nonotfounds) {
		    for (pnxt = *notfounds; *pnxt; pnxt++)
			free(*pnxt);
		    free(*notfounds);
		    *notfounds = NULL;
		    nonotfounds = TRUE;
		}

	    }	/* if (nobaderr) */

	    /* Free the resources alloc'ed for <device>'s entry */
	    _freedevtabent(modent);

	} else {
	    /* _getdevrec(device) failed */
	    nobaderr = FALSE;
	    *notfounds = NULL;
	}

	/* Unlock the device table */
	(void) unlkdevtab();

	/* We're finished */
	return (noerr && nobaderr);
}
