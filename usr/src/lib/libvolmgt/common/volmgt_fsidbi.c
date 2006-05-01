/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<unistd.h>
#include	<string.h>
#include	<strings.h>
#include	<malloc.h>
#include	<volmgt.h>
#include	<sys/stat.h>
#include	<errno.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<fcntl.h>
#include	<signal.h>
#include	<sys/types.h>
#include	<sys/mkdev.h>
#include	"volmgt_private.h"
#include	"volmgt_fsi_private.h"


/* just utnil volmgt.h is up to date */
#ifndef	VOL_RSV_MAXIDLEN
#define	VOL_RSV_MAXIDLEN	256
#endif


/*
 * volmgt_fsidbi -- volmgt FSI db interface routines
 *
 * routines supplied:
 *
 *	vol_dbid_t		vol_db_open(void)
 *	int			vol_db_close(vol_dbid_t)
 *	int			vol_db_insert(vol_dbid_t, vol_db_entry_t *)
 *	int			vol_db_remove(vol_dbid_t, dev_t)
 *	vol_db_entry_t		*vol_db_find(vol_dbid_t, dev_t)
 *	void			vol_db_free(vol_db_entry_t *)
 *	int			vol_db_proc_find(pid_t)
 */

/* name of our database file */
#define	VOL_DB_PATH	"/tmp/.volmgt_reserv_db"

/* mode for our database file */
#define	VOL_DB_MODE	(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)

/* for reading from and writing to the database */
#define	READ_FORMAT	"%d||%d||%d||%[^\n]"
#define	WRITE_FORMAT	"%d||%d||%d||%s\n"

/*
 * The next two defines indicate the number of fields we expect to find in a
 * database record. The first is the number of fields if no comment was
 * provided (which seems unlikely since volmgt_acquire() demands a comment of
 * some kind) and the other one is the number of fields to expect if a
 * comment is included.
 */
#define	NUM_FIELDS_WO_COMMENT 3
#define	NUM_FIELDS_W_COMMENT  4

/* maximum record size */
#define	VOL_MAX_RECSIZE	(VOL_RSV_MAXIDLEN + 20)



/*
 * internal list data
 */

#define	MAX_INTERNAL_DB_LIST_SIZE	64	/* should be big enough! */

static FILE	*db_list[MAX_INTERNAL_DB_LIST_SIZE];


/*
 * add the supplied file ptr to our list of file ptrs (if it'll fit)
 *
 * return it's index in the list (after type casting) if successful, else
 * return -1
 */
static vol_dbid_t
add_to_list(FILE *fp)
{
	int		i;
	vol_dbid_t	ret_val = (vol_dbid_t)-1;


#ifdef	DEBUG
	denter("add_to_list(%#x): entering\n", (char *)fp);
#endif


	for (i = 0; i < MAX_INTERNAL_DB_LIST_SIZE; i++) {
		if (db_list[i] == NULL) {
			db_list[i] = fp;
			ret_val = (vol_dbid_t)i;
#ifdef	DEBUG
			dprintf("add_to_list: adding at location %d\n", i);
#endif
			break;
		}
#ifdef	DEBUG
		dprintf("add_to_list: location %d already taken\n", i);
#endif
	}

#ifdef	DEBUG
	dexit("add_to_list: returning %d\n", (int)ret_val);
#endif
	return (ret_val);
}


/*
 * return the file ptr given the dbid
 */
static FILE *
db_to_fp(vol_dbid_t dbid)
{
	FILE	*ret_val = NULL;


#ifdef	DEBUG
	denter("db_to_fp(%d): entering\n", (int)dbid);
#endif
	if (((int)dbid >= 0) && ((int)dbid < MAX_INTERNAL_DB_LIST_SIZE)) {
		ret_val = db_list[dbid];
	}

#ifdef	DEBUG
	dexit("db_to_fp: returning %#p\n", (char *)ret_val);
#endif
	return (ret_val);
}


/*
 * remove the specified entry from the internal db
 */
static void
rem_from_list(vol_dbid_t dbid)
{
	if (((int)dbid >= 0) && ((int)dbid < MAX_INTERNAL_DB_LIST_SIZE)) {
		db_list[dbid] = NULL;
	}
}


/*
 * committment level:
 *	project private
 *
 * description:
 * 	vol_db_open: creates/opens volmgt Device Reservation Database.
 *	If the database file doesn't exist it is created and opened,
 *	otherwise it just is opened.  The file mode is updated to insure
 *	that it is readable and writeable by the world.  Then an advisory
 * 	write file lock is taken out on the entire file.  Any process
 *	attempting to gain access to the file via vol_db_open() will sleep
 *	attempting to set the file lock should another process currently have
 *	the lock set.  On success, a FILE pointer is returned to the caller.
 *
 * arguments:
 *	none
 *
 * return value(s):
 *	a small non-negative integer if successful, else -1
 *
 * preconditions:
 *	none
 */
vol_dbid_t
vol_db_open(void)
{
	const char	*dbpath = VOL_DB_PATH;
	FILE		 *fp = NULL;
	flock_t		flock;
	int		fd;
	int		status;
	vol_dbid_t	ret_val = (vol_dbid_t)-1;


#ifdef	DEBUG
	denter("vol_db_open(): entering\n");
#endif
	if ((status = access(dbpath, F_OK | R_OK | W_OK)) < 0) {
		/*
		 * file doesn't exist so create it, open for update, and
		 * make sure the file mode is read/write-able by the world
		 */
		if ((fp = fopen(dbpath, "w+F")) == NULL) {
#ifdef	DEBUG
			dprintf("can't open (w+) \"%s\" (%d)\n",
			    dbpath, errno);
#endif
			goto dun;
		}
	} else {
		/* does exist so open it for update */
		if ((fp = fopen(dbpath, "r+F")) == NULL) {
#ifdef	DEBUG
			dprintf("can't open (r+) \"%s\" (%d)\n",
			    dbpath, errno);
#endif
			goto dun;
		}
	}

	fd = fileno(fp);

	if (status < 0) {
		if (fchmod(fd, VOL_DB_MODE) < 0) {
			(void) fclose(fp);
			fp = NULL;
#ifdef	DEBUG
			dprintf("can't fchmod \"%s\" to %o (%d)\n",
			    dbpath, VOL_DB_MODE, errno);
#endif
			goto dun;
		}
	}

	/*
	 * set advisory lock on database file
	 */
	flock.l_type = F_WRLCK;
	flock.l_start = 0;
	flock.l_len = 0;
	flock.l_whence = SEEK_SET;

	if (fcntl(fd, F_SETLKW, &flock) < 0) {
		(void) fclose(fp);
		fp = NULL;
#ifdef	DEBUG
		dprintf("can't fcntl (lock) \"%s\" (%d)\n",
		    dbpath, errno);
#endif
		goto dun;
	}

	/* the file is open and locked -- try to keep track of it */
	ret_val = add_to_list(fp);

dun:
#ifdef	DEBUG
	dexit("vol_db_open: returning %d\n", ret_val);
#endif
	return (ret_val);
}


/*
 * committment level:
 *	project private
 *
 * description:
 *	vol_db_close: close the volmgt Device Reservation Database.  The
 *	database file is unconditionally closed.
 *
 * arguments:
 *	dbid - an identifier for the database to be closed
 *
 * return value(s):
 *	0 -> all went okay
 *	non-zero - an error
 *
 * preconditions:
 *	The volmgt database has already been opened by vol_db_open().
 */
int
vol_db_close(vol_dbid_t dbid)
{
	FILE	*fp;
	int	ret_val = -1;			/* default => failure */


#ifdef	DEBUG
	denter("volmgt_db_close(%d): entering\n", (int)dbid);
#endif
	if ((fp = db_to_fp(dbid)) != NULL) {
		if (fclose(fp) == 0) {
			rem_from_list(dbid);
			ret_val = 0;		/* success */
		}
	}

#ifdef	DEBUG
	dexit("volmgt_db_close: returning %d (%s)\n", ret_val,
	    ret_val == 0 ? "SUCCESS" : "FAILURE");
#endif
	return (ret_val);
}


/*
 * committment level:
 *	project private
 *
 * description:
 *	vol_db_insert:insert a record into the volmgt Device Reservation
 *	database.  The file is simply positioned to EOF and the requested
 *	entry written.
 *
 *	The semantics for use of this primitive depend on the caller having
 *	previously called vol_db_find() to determine whether the record already
 *	exists or not.  Multiple calls to vol_db_insert() for the same record
 *	will result in the existence of duplicate records.
 *
 * arguments:
 *	dbid - an identifier for the database to be accessed
 *	ep - pointer to a vol_db_entry structure describing the record to
 *		be inserted.
 *
 * return value(s):
 *	0/FALSE		failure
 *	1/TRUE		success
 *
 * preconditions:
 *	The volmgt database has already been opened by vol_db_open().
 */
int
vol_db_insert(vol_dbid_t dbid, vol_db_entry_t *ep)
{
	FILE	*fp;
	int	ret_val = 0;			/* default => failure */


#ifdef	DEBUG
	denter("volmgt_db_insert(%d, [(%d.%d), %d, ...]): entering\n", dbid,
	    ep->dev_major, ep->dev_minor, ep->pid);
#endif
	/* get the file ptr for the supplied dbid */
	if ((fp = db_to_fp(dbid)) == NULL) {
		goto dun;
	}

	/* just skip to EOF */
	if (fseek(fp, 0, SEEK_END) < 0) {
#ifdef	DEBUG
		dprintf("volmgt_db_insert: fseek failed (%d)\n", errno);
#endif
		goto dun;
	}

	/* append record to file */
	if (fprintf(fp, WRITE_FORMAT, ep->dev_major, ep->dev_minor,
	    ep->pid, ep->id_tag) < 0) {
#ifdef	DEBUG
		dprintf("volmgt_db_insert: fprintf failed (%d)\n", errno);
#endif
		goto dun;
	}

	ret_val = 1;				/* success */
dun:
#ifdef	DEBUG
	dexit("volmgt_db_insert: returning %s\n", ret_val ? "TRUE" : "FALSE");
#endif
	return (ret_val);
}


/*
 * committment level:
 *	project private
 *
 * description:
 *	vol_db_remove: remove a device entry from the volmgt Device
 *	Reservation Database.  The database file is scanned sequentially
 *	from file offset 0 looking for a match with the supplied dev argument.
 *	A match indicates that the device is currently reserved.  Note that the
 *	decision to allow a user to remove a database entry must be made by
 *	a higher level entity.  This function will blindly remove an entry
 *	if it exists and silently ignore the non-existence of a requested
 *	record.
 *
 *	This function is a little kludgier than the rest in this module.  To
 *	avoid having to deal with issues related to creation of a new file
 *	each time an entry is removed, the entire file contents are buffered
 *	into a malloc'ed memory block and then scanned from there.  Each non-
 *	matching entry scanned from the buffer is written back to the database
 *	file (which gets rewound following the file read).  If a matching
 *	entry(s) is found it is simply skipped over.  Once the file has been
 *	rewritten it is truncated by the length of the removed entry(s).  In
 *	other words, if multiple entries for the same record exist, they will
 *	all be removed.
 *
 * arguments:
 *	dbid - an identifier for the database to be accessed
 *	dev - the major/minor device pair uniquely identifying the record to
 *		be removed from the database.
 *
 * return value(s):
 *	An integer describing the success or failure of the operation.
 *
 * preconditions:
 *	The volmgt database has already been opened by vol_db_open().
 */
int
vol_db_remove(vol_dbid_t dbid, dev_t dev)
{
	FILE		*fp;
	int		count;		/* ttl record length in buf */
	int		nitems;		/* no. items scanned */
	char		*iobp = NULL;	/* ptr to malloc'ed I/O buf */
	char		*tiobp;		/* temp I/O buf ptr */
	struct stat	sb;		/* for stat(2) */
	major_t		fdev_major;	/* major dev read from database */
	minor_t		fdev_minor;	/* minor dev read from database */
	major_t		dev_major;	/* major dev (from passed dev_t) */
	minor_t		dev_minor;	/* minor_dev (from passed dev_t) */
	pid_t		fpid;		/* pid read from database */
	int		flen;		/* length of file read */
	int		dlen = 0;	/* datum length */
	char		buf[VOL_MAX_RECSIZE];	/* dest buf for scanning */
	int		ret_val = 0;	/* default -> failure */


#ifdef	DEBUG
	denter("volmgt_db_remove(%d): entering\n", dbid);
#endif
	/* get the file ptr for the supplied dbid */
	if ((fp = db_to_fp(dbid)) == NULL) {
		goto dun;
	}

	/*
	 * make sure database file is rewound since it is sequential
	 *
	 * this also insures that any buffered data is flushed prior to
	 * the next I/O operation
	 */
	rewind(fp);

	/*
	 * get a buffer big enough for reading the entire file
	 */
	if (fstat(fileno(fp), &sb) < 0) {
		goto dun;
	}

	if ((iobp = (char *)malloc((size_t)sb.st_size)) == NULL) {
		goto dun;
	}

	/*
	 * fill buffer with file contents
	 */
	if ((flen = fread(iobp, 1, (size_t)sb.st_size, fp)) != sb.st_size) {
		goto dun;
	}

	rewind(fp);
	tiobp = iobp;

	/*
	 * translate dev_t passed in to major and minro numbers
	 */
	dev_major = major(dev);
	dev_minor = minor(dev);

	/*
	 * while data remains in the buffer, scan records looking for the
	 * device we want to remove
	 *
	 * copy non-matching entries back to the database file
	 */
	while (flen > 0) {

		/* include newline */
		count = (int)(strchr(tiobp, '\n') - tiobp) + 1;

		nitems = sscanf(tiobp, READ_FORMAT, &fdev_major, &fdev_minor,
		    &fpid, buf);

		if (fdev_major == dev_major && fdev_minor == dev_minor) {
			dlen += count;
		} else {
			switch (nitems) {
			case NUM_FIELDS_WO_COMMENT:
				buf[0] = '\0';	/* string was NULL */
				break;
			case NUM_FIELDS_W_COMMENT:
				/* normal record -- do nothing */
				break;
			default:
				/*
				 * something is wrong, try to restore
				 * the file to its original state
				 */
				rewind(fp);
				if (fwrite(iobp, 1, (size_t)sb.st_size, fp) !=
				    sb.st_size) {
					goto dun;
				}
				break;
			}
			if (fprintf(fp, WRITE_FORMAT, fdev_major, fdev_minor,
			    fpid, buf) < 0) {
				goto dun;
			}
		}

		tiobp += count;
		flen -= count;
	}

	/*
	 * truncate file by the length of the record removed
	 */
	if (ftruncate(fileno(fp), sb.st_size - dlen) < 0) {
		/*
		 * something is wrong, try to restore
		 * the file to its original state
		 */
		rewind(fp);
		if (fwrite(iobp, 1, (size_t)sb.st_size, fp) != sb.st_size) {
			goto dun;
		}
	}

	/*
	 * done with the buffer, free it
	 */
	free(iobp);

	ret_val = 1;				/* success */
dun:
	if (iobp != NULL) {
		free(iobp);
	}
#ifdef	DEBUG
	dexit("volmgt_db_remove: returning %s\n", ret_val ? "TRUE" : "FALSE");
#endif
	return (ret_val);
}


/*
 * committment level:
 *	project private
 *
 * description:
 *	vol_db_find: locate a device entry in the volmgt Device Reservation
 *	Database.  The database file is scanned looking for an entry matching
 *	the supplied device argument.  If a match is found a pointer to a
 *	vol_db_entry_t is returned to the caller.  If no match is found
 *	a NULL pointer is returned.  The memory space for the structure whose
 *	address is returned is allocated by malloc and it is the caller's
 *	responsibility to insure that this space is freed.  This can be
 *	done using the vol_db_free() function.
 *
 * arguments:
 *	dbid - an identifier for the database to be accessed
 *	dev - the major/minor device pair uniquely identifying the record to
 *		be found.
 *
 * return value(s):
 *	A pointer to a vol_db_entry.  If the entry wasn't found a NULL
 *	pointer is returned.
 *
 * preconditions:
 *	The volmgt database has already been opened by vol_db_open().
 */
vol_db_entry_t *
vol_db_find(vol_dbid_t dbid, dev_t dev)
{
	FILE		*fp;
	major_t		fdev_major;	/* major device read from database */
	minor_t		fdev_minor;	/* minor device read from database */
	major_t		dev_major;	/* major device (from passed dev_t) */
	minor_t		dev_minor;	/* minor device (from passed dev_t) */
	pid_t		fpid;		/* process id read from database */
	int		nitems;		/* number of items scanned */
	vol_db_entry_t	*retval = NULL;
	vol_db_entry_t	*ep;
	char		buf[VOL_MAX_RECSIZE]; /* scann dest buf */


#ifdef	DEBUG
	denter("volmgt_db_find(%d, (%d)%d.%d): entering\n", dbid,
	    dev, major(dev), minor(dev));
#endif
	/* get the file ptr for the supplied dbid */
	if ((fp = db_to_fp(dbid)) == NULL) {
		goto dun;
	}

	/*
	 * make sure database file is rewound since it is sequential
	 *
	 * this also insures that any buffered data is flushed prior to
	 * the next I/O operation
	 */
	rewind(fp);

	/*
	 * convert dev_t to major and minor numbers
	 */
	dev_major = major(dev);
	dev_minor = minor(dev);

	/*
	 * scan each line looking for the requested device
	 */
	while ((nitems = fscanf(fp, READ_FORMAT, &fdev_major, &fdev_minor,
	    &fpid, buf)) > 0) {

		if (fdev_major == dev_major && fdev_minor == dev_minor) {
			/* the device entry was found, return it */

			if ((ep = (vol_db_entry_t *)
			    malloc(sizeof (vol_db_entry_t))) == NULL) {
				break;
			}

			ep->dev_major = fdev_major;
			ep->dev_minor = fdev_minor;
			ep->pid = fpid;
			if (nitems == NUM_FIELDS_WO_COMMENT) {
				buf[0] = '\0';	/* string was NULL */
			} else if (nitems != NUM_FIELDS_W_COMMENT) {
				break;		/* bad record */
			}
			ep->id_tag = strdup(buf);
			retval = ep;		/* success */
			break;
		}
	}
dun:
#ifdef	DEBUG
	dexit("volmgt_db_find: returning %#p\n", (char *)retval);
#endif
	return (retval);
}


/*
 * committment level:
 *	project private
 *
 * description:
 *	vol_db_free: free a vol_db_entry_t allocated by vol_db_find().
 *	This function is provided for symmetry with vol_db_find().  Since
 *	the find function allocates memory to contain the found database
 *	entry via malloc, this function can be called to release that memory
 *	block.
 *
 * arguments:
 *	entry - pointer to a vol_db_entry structure that was allocated by
 *		vol_db_find().
 *
 * return value(s):
 *	An integer describing the success or failure of the operation.  The
 *	operation always succeeds since free(3C) always returns void and
 *	doesn't set errno.
 *
 * preconditions:
 *	none
 */
void
vol_db_free(vol_db_entry_t *entry)
{
	/*
	 * check that a non-NULL pointer was supplied prior to dereferencing
	 */
	if (entry != NULL) {
		if (entry->id_tag != NULL) {
			free(entry->id_tag);
		}
		free(entry);
	}
}


/*
 * committment level:
 *	project private
 *
 * description:
 *	vol_db_proc_find: see if a process identified by *pid* is currently
 *	in the process table.  Send the zero signal to the process identified
 *	by *pid*.  If the process is found kill(2) will return a value of 0.
 *	This corresponds to a success condition for vol_db_proc_find().
 *
 *
 * arguments:
 *	pid - the process id of the process to locate.
 *
 * return value(s):
 *	An integer describing the success or failure of the operation.
 *
 * preconditions:
 *	none
 */
int
vol_db_proc_find(pid_t pid)
{
	return ((kill(pid, 0) != 0) ? 0 : 1);
}
