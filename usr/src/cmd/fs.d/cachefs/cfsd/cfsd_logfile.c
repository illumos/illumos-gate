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
 * Copyright 1994-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Methods of the cfsd_maptbl classes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <synch.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/cred.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dlog.h>
#include <mdbug/mdbug.h>
#include "cfsd.h"
#include "cfsd_logfile.h"

/*
 *			cfsd_logfile_create
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */
cfsd_logfile_object_t *
cfsd_logfile_create(void)
{
	cfsd_logfile_object_t *logfile_object_p;

	dbug_enter("cfsd_logfile_create");

	logfile_object_p = cfsd_calloc(sizeof (cfsd_logfile_object_t));
	logfile_object_p->i_fid = -1;
	logfile_object_p->i_map_entry.i_pa = NULL;
	logfile_object_p->i_map_entry.i_paoff = 0;
	logfile_object_p->i_map_entry.i_paend = 0;
	logfile_object_p->i_map_entry.i_palen = 0;
	logfile_object_p->i_map_offset.i_pa = NULL;
	logfile_object_p->i_map_offset.i_paoff = 0;
	logfile_object_p->i_map_offset.i_paend = 0;
	logfile_object_p->i_map_offset.i_palen = 0;
	logfile_object_p->i_cur_offset = 0;
	logfile_object_p->i_cur_entry = NULL;
	dbug_leave("cfsd_logfile_create");
	return (logfile_object_p);
}

/*
 *			cfsd_logfile_destroy
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */
void
cfsd_logfile_destroy(cfsd_logfile_object_t *logfile_object_p)
{
	dbug_enter("cfsd_logfile_destroy");
	logfile_sync(logfile_object_p);
	logfile_teardown(logfile_object_p);
	cfsd_free(logfile_object_p);
	dbug_leave("cfsd_logfile_destroy");
}

/*
 *			logfile_domap
 *
 * Description:
 *	Maps in the specified section of the file.
 * Arguments:
 *	off	The offset to map in.  Must be i_pagesize aligned.
 *	map	0 means use map_entry, 1 means use map_offset
 * Returns:
 *	Returns 0 for success or an errno value on failure.
 * Preconditions:
 */
int
logfile_domap(cfsd_logfile_object_t *logfile_object_p, off_t off, int map)
{
	int xx;
	int len;
	mmap_info_t *mmp;

	dbug_enter("logfile_domap");
	dbug_precond(logfile_object_p->i_fid >= 0);

	len = logfile_object_p->i_maplen;
	mmp = (map == 0) ?
		&logfile_object_p->i_map_entry :
		&logfile_object_p->i_map_offset;

	logfile_object_p->i_stat_mapmove++;

	/* destroy old mapping if it exists */
	if (mmp->i_pa) {
		/* determine how far we have to move the map */
		logfile_object_p->i_stat_mapdist += abs(mmp->i_paoff - off);

		/* remove the map */
		xx = munmap(mmp->i_pa, mmp->i_palen);
		if (xx == -1) {
			xx = errno;
			dbug_print(("error", "Could not unmap %s, %d, %p, %d",
			    logfile_object_p->i_name, xx, mmp->i_pa,
			    mmp->i_palen));
		}
		mmp->i_pa = NULL;
		mmp->i_palen = 0;
		mmp->i_paoff = 0;
		mmp->i_paend = 0;
	}

	/* do the mapping */
	mmp->i_pa = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED,
	    logfile_object_p->i_fid, off);
	if (mmp->i_pa == MAP_FAILED) {
		xx = errno;
		dbug_print(("error",
		    "Could not map %s, error %d, off %d, len %d",
		    logfile_object_p->i_name, xx, off, len));
		mmp->i_pa = NULL;
		dbug_leave("logfile_domap");
		return (xx);
	}

	mmp->i_palen = len;
	mmp->i_paoff = off;
	mmp->i_paend = off + len - 1;
	dbug_leave("logfile_domap");
	return (0);
}

/*
 *			logfile_getaddr
 *
 * Description:
 *	Returns an address of a particular offset in the file.
 *	The size of the item to map is i_maxmap
 *	This routine assumes that if we have to remap that i_maxmap
 *	will fit inside the default mapping size.
 * Arguments:
 *	start	offset in the file to map
 *	map	0 means use map_entry, 1 means use map_offset
 * Returns:
 *	Returns NULL for a failure with the mapping file.
 * Preconditions:
 */
caddr_t
logfile_getaddr(cfsd_logfile_object_t *logfile_object_p, off_t start, int map)
{
	mmap_info_t *mmp;
	caddr_t pa;
	off_t end;

	dbug_enter("logfile_getaddr");

	mmp = (map == 0) ?
	    &logfile_object_p->i_map_entry :
	    &logfile_object_p->i_map_offset;

	/* determine the end of the item */
	end = start + logfile_object_p->i_maxmap - 1;

	/* map the entry in if necessary */
	if ((start < mmp->i_paoff) || (mmp->i_paend < end)) {
		if (logfile_domap(logfile_object_p,
		    start & logfile_object_p->i_pagemask, map)) {
			dbug_leave("logfile_getaddr");
			return (NULL);
		}
		dbug_assert((mmp->i_paoff <= start) && (end <= mmp->i_paend));
	}

	/* make an address and return it */
	pa = mmp->i_pa + (start - mmp->i_paoff);
	dbug_leave("logfile_getaddr");
	return (pa);
}

/*
 *			logfile_setup
 *
 * Description:
 *	Sets up to use the specified file.
 *	Call this routine before using any of the other routines.
 * Arguments:
 *	filename	file to use
 *	maxmap		max amount needed after a map
 * Returns:
 *	Returns 0 for success or an errno value.
 * Preconditions:
 *	precond(filename)
 */
int
logfile_setup(cfsd_logfile_object_t *logfile_object_p,
	const char *filename, int maxmap)
{
	int xx;
	struct stat sinfo;
	long *versionp;

	dbug_enter("logfile_setup");
	dbug_precond(filename);

	/* clean up from a previous setup */
	logfile_teardown(logfile_object_p);

	strlcpy(logfile_object_p->i_name, filename,
	    sizeof (logfile_object_p->i_name));
	dbug_print(("info", "filename %s", logfile_object_p->i_name));
	logfile_object_p->i_maxmap = maxmap;

	/* get the page info */
	logfile_object_p->i_pagesize = PAGESIZE;
	logfile_object_p->i_pagemask = PAGEMASK;
	logfile_object_p->i_maplen = logfile_object_p->i_pagesize * 100;

	/* open the file */
	logfile_object_p->i_fid = open(logfile_object_p->i_name,
	    O_RDWR | O_NONBLOCK);
	if (logfile_object_p->i_fid == -1) {
		xx = errno;
		dbug_print(("error", "Could not open %s, %d",
		    logfile_object_p->i_name, xx));
		dbug_leave("logfile_setup");
		return (xx);
	}

	/* get the size and type of file */
	xx = fstat(logfile_object_p->i_fid, &sinfo);
	if (xx) {
		xx = errno;
		if (xx == ENOENT) {
			dbug_print(("info", "No log file to roll"));
		} else {
			dbug_print(("error", "Could not stat %s, %d",
			    logfile_object_p->i_name, xx));
		}
		dbug_leave("logfile_setup");
		return (xx);
	}
	logfile_object_p->i_size = sinfo.st_size;

	/* sanity check, better be a regular file */
	if (!S_ISREG(sinfo.st_mode)) {
		xx = ENOTSUP;
		dbug_print(("error", "%s Not a regular file.",
		    logfile_object_p->i_name));
		dbug_leave("logfile_setup");
		return (xx);
	}

	/* better not be too small */
	if (logfile_object_p->i_size < LOGFILE_ENTRY_START) {
		dbug_print(("error", "File %s is too small %d.",
		    logfile_object_p->i_name, logfile_object_p->i_size));
		dbug_leave("logfile_setup");
		return (EINVAL);
	}

	/* initialize statistic gathering */
	logfile_object_p->i_stat_mapmove = 0;
	logfile_object_p->i_stat_mapdist = 0;

	/* check the version number */
	versionp = (long *)logfile_getaddr(logfile_object_p, 0, 1);
	if (versionp == NULL) {
		dbug_leave("logfile_setup");
		return (EIO);
	}
	if (*versionp != CFS_DLOG_VERSION) {
		dbug_print(("error", "Log file version mismatch %d != %d",
		    *versionp, CFS_DLOG_VERSION));
		dbug_leave("logfile_setup");
		return (EINVAL);
	}

	/* return success */
	dbug_leave("logfile_setup");
	return (0);
}

/*
 *			logfile_teardown
 *
 * Description:
 *	Uninitializes the object.
 *	Call logfile_setup before using this object again.
 * Arguments:
 * Returns:
 * Preconditions:
 */
void
logfile_teardown(cfsd_logfile_object_t *logfile_object_p)
{
	int xx;

	dbug_enter("logfile_teardown");

	if (logfile_object_p->i_map_entry.i_pa) {
		xx = munmap(logfile_object_p->i_map_entry.i_pa,
		    logfile_object_p->i_map_entry.i_palen);
		if (xx == -1) {
			xx = errno;
			dbug_print(("error", "Could not unmap %s, %d, %p, %d",
			    logfile_object_p->i_name, xx,
			    logfile_object_p->i_map_entry.i_pa,
			    logfile_object_p->i_map_entry.i_palen));
		}
		logfile_object_p->i_map_entry.i_pa = NULL;
	}
	logfile_object_p->i_map_entry.i_paoff = 0;
	logfile_object_p->i_map_entry.i_paend = 0;
	logfile_object_p->i_map_entry.i_palen = 0;

	if (logfile_object_p->i_map_offset.i_pa) {
		xx = munmap(logfile_object_p->i_map_offset.i_pa,
		    logfile_object_p->i_map_offset.i_palen);
		if (xx == -1) {
			xx = errno;
			dbug_print(("error", "Could not unmap %s, %d, %p, %d",
			    logfile_object_p->i_name, xx,
			    logfile_object_p->i_map_offset.i_pa,
			    logfile_object_p->i_map_offset.i_palen));
		}
		logfile_object_p->i_map_offset.i_pa = NULL;
	}
	logfile_object_p->i_map_offset.i_paoff = 0;
	logfile_object_p->i_map_offset.i_paend = 0;
	logfile_object_p->i_map_offset.i_palen = 0;

	if (logfile_object_p->i_fid != -1) {
		if (close(logfile_object_p->i_fid))
			dbug_print(("error", "Could not close %s, %d",
			    logfile_object_p->i_name, errno));
		logfile_object_p->i_fid = -1;
	}
	logfile_object_p->i_cur_offset = 0;
	logfile_object_p->i_cur_entry = NULL;
	dbug_leave("logfile_teardown");
}

/*
 *			logfile_entry
 *
 * Description:
 *	Sets addrp to the address of the log entry at offset
 *	The mapping remains in effect until:
 *		a) this routine is called again
 *		b) logfile_teardown is called
 *		c) this object is destroyed
 * Arguments:
 *	offset	offset to start of entry
 *	entpp	place to store address
 * Returns:
 *	Returns 0 for success, 1 for EOF, -1 if a fatal error occurs.
 * Preconditions:
 *	precond(addrp)
 */
int
logfile_entry(cfsd_logfile_object_t *logfile_object_p,
	off_t offset,
	cfs_dlog_entry_t **entpp)
{
	cfs_dlog_entry_t *entp;

	dbug_enter("logfile_entry");
	dbug_precond(entpp);
	dbug_precond(offset >= sizeof (long));


	logfile_object_p->i_stat_nextcnt++;

	/* check for eof */
	if (offset >= logfile_object_p->i_size) {
		dbug_leave("logfile_entry");
		return (1);
	}
	dbug_assert((offset & 3) == 0);

	/* get the address of the entry */
	entp = (cfs_dlog_entry_t *)logfile_getaddr(logfile_object_p, offset, 0);
	if (entp == NULL) {
		dbug_leave("logfile_entry");
		return (-1);
	}
	/* sanity check, record should be alligned */
	if (entp->dl_len & 3) {
		dbug_print(("error",
		    "Record at offset %d length is not alligned %d",
		    offset, entp->dl_len));
		dbug_leave("logfile_entry");
		return (-1);
	}

	/* sanity check record should a reasonable size */
	if ((entp->dl_len < CFS_DLOG_ENTRY_MINSIZE) ||
	    (entp->dl_len > CFS_DLOG_ENTRY_MAXSIZE)) {
		dbug_print(("error",
		    "Record at offset %d has an invalid size %d", offset,
		    entp->dl_len));
		dbug_leave("logfile_entry");
		return (-1);
	}

	/* preserve offset and pointer */
	logfile_object_p->i_cur_offset = offset;
	logfile_object_p->i_cur_entry = entp;

	/* return success */
	*entpp = entp;
	dbug_leave("logfile_entry");
	return (0);
}

/*
 *			logfile_offset
 *
 * Description:
 *	Sets addrp to the address of the specified offset.
 *	The mapping remains in effect until:
 *		a) this routine is called again
 *		b) logfile_teardown is called
 *		c) this object is destroyed
 * Arguments:
 *	offset	offset into file, must be 0 <= offset < i_size
 *	addrp	returns mapped address
 * Returns:
 *	Returns 0 for success, -1 if a fatal error occurs.
 * Preconditions:
 *	precond(addrp)
 */
int
logfile_offset(cfsd_logfile_object_t *logfile_object_p,
	off_t offset,
	caddr_t *addrp)
{
	caddr_t pa;

	dbug_enter("logfile_offset");
	dbug_precond(addrp);
	dbug_precond((0 <= offset) && (offset < logfile_object_p->i_size));

	logfile_object_p->i_stat_offcnt++;

	/* get the address for the offset */
	pa = logfile_getaddr(logfile_object_p, offset, 1);
	if (pa == NULL) {
		dbug_leave("logfile_offset");
		return (-1);
	}
	/* return success */
	*addrp = pa;
	dbug_leave("logfile_offset");
	return (0);
}

/*
 *			logfile_sync
 *
 * Description:
 *	Performs an fsync on the log file.
 * Arguments:
 * Returns:
 *	Returns 0 for success or an errno value on failure.
 * Preconditions:
 */
int
logfile_sync(cfsd_logfile_object_t *logfile_object_p)
{
	int xx;

	dbug_enter("logfile_sync");

	if (logfile_object_p->i_fid == -1) {
		dbug_leave("logfile_sync");
		return (0);
	}
	xx = fsync(logfile_object_p->i_fid);
	if (xx) {
		xx = errno;
		dbug_print(("error", "fsync failed %d", xx));
	}
	dbug_leave("logfile_sync");
	return (xx);
}

/*
 *			logfile_dumpstats
 *
 * Description:
 *	Prints out various stats about the hashing.
 * Arguments:
 * Returns:
 * Preconditions:
 */
void
logfile_dumpstats(cfsd_logfile_object_t *logfile_object_p)
{
	int xx;
	double dd;

	dbug_enter("logfile_dumpstats");

	dbug_print(("dump", "Request - next %d",
	    logfile_object_p->i_stat_nextcnt));
	dbug_print(("dump", "Request - offset %d",
	    logfile_object_p->i_stat_offcnt));
	dbug_print(("dump", "Map Moves %d", logfile_object_p->i_stat_mapmove));
	dbug_print(("dump", "Mapping Size %d", logfile_object_p->i_maplen));
	dbug_print(("dump", "Item Size %d", logfile_object_p->i_maxmap));
	dbug_print(("dump", "File Size %d", logfile_object_p->i_size));
	if (logfile_object_p->i_stat_mapmove == 0) {
		dbug_leave("logfile_dumpstats");
		return;
	}

	dd = (double)logfile_object_p->i_stat_mapmove /
	    (logfile_object_p->i_stat_nextcnt +
	    logfile_object_p->i_stat_offcnt);
	dbug_print(("dump", "Mmap moves per Request %.2f", dd));

	xx = logfile_object_p->i_stat_mapdist /
	    logfile_object_p->i_stat_mapmove;
	dbug_print(("dump", "Average distance per mmap moves %d", xx));
	dbug_leave("logfile_dumpstats");
}
