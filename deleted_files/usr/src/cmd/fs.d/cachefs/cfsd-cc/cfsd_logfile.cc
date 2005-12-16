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
// -----------------------------------------------------------------
//
//			cfsd_logfile.cc
//
// Methods of the cfsd_maptbl classes.

#pragma ident	"%Z%%M%	%I%	%E% SMI"
// Copyright (c) 1994 by Sun Microsystems, Inc.

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <synch.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/cred.h>
#include <sys/attr.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <rw/cstring.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dlog.h>
#include <mdbug-cc/mdbug.h>
#include "cfsd_logfile.h"

//
//			cfsd_logfile::cfsd_logfile
//
// Description:
// Arguments:
// Returns:
// Preconditions:

cfsd_logfile::cfsd_logfile()
{
	dbug_enter("cfsd_logfile::cfsd_logfile");
	i_fid = -1;
	i_map_entry.i_pa = NULL;
	i_map_entry.i_paoff = 0;
	i_map_entry.i_paend = 0;
	i_map_entry.i_palen = 0;
	i_map_offset = i_map_entry;
	i_cur_offset = 0;
	i_cur_entry = NULL;
}

//
//			cfsd_logfile::~cfsd_logfile
//
// Description:
// Arguments:
// Returns:
// Preconditions:


cfsd_logfile::~cfsd_logfile()
{
	dbug_enter("cfsd_logfile::~cfsd_logfile");
	logfile_sync();
	logfile_teardown();
}

//
//			cfsd_logfile::i_domap
//
// Description:
//	Maps in the specified section of the file.
// Arguments:
//	off	The offset to map in.  Must be i_pagesize aligned.
//	map	0 means use map_entry, 1 means use map_offset
// Returns:
//	Returns 0 for success or an errno value on failure.
// Preconditions:

int
cfsd_logfile::i_domap(off_t off, int map)
{
	dbug_enter("cfsd_logfile::i_domap");
	dbug_precond(i_fid >= 0);

	int xx;
	int len = i_maplen;
	mmap_info *mmp = (map == 0) ? &i_map_entry : &i_map_offset;

	i_stat_mapmove++;

	// destroy old mapping if it exists
	if (mmp->i_pa) {
		// determine how far we have to move the map
		i_stat_mapdist += abs(mmp->i_paoff - off);

		// remove the map
		xx = munmap(mmp->i_pa, mmp->i_palen);
		if (xx == -1) {
			xx = errno;
			dbug_print("error", ("Could not unmap %s, %d, %p, %d",
			    i_name.data(), xx, mmp->i_pa, mmp->i_palen));
		}
		mmp->i_pa = NULL;
		mmp->i_palen = 0;
		mmp->i_paoff = 0;
		mmp->i_paend = 0;
	}

	// do the mapping
	mmp->i_pa = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED,
		    i_fid, off);
	if (mmp->i_pa == MAP_FAILED) {
		xx = errno;
		dbug_print("error",
		    ("Could not map %s, error %d, off %d, len %d",
		    i_name.data(), xx, off, len));
		mmp->i_pa = NULL;
		return (xx);
	}

	mmp->i_palen = len;
	mmp->i_paoff = off;
	mmp->i_paend = off + len - 1;
	return (0);
}

//
//			cfsd_logfile::i_getaddr
//
// Description:
//	Returns an address of a particular offset in the file.
//	The size of the item to map is i_maxmap
//	This routine assumes that if we have to remap that i_maxmap
//	will fit inside the default mapping size.
// Arguments:
//	start	offset in the file to map
//	map	0 means use map_entry, 1 means use map_offset
// Returns:
//	Returns NULL for a failure with the mapping file.
// Preconditions:

caddr_t
cfsd_logfile::i_getaddr(off_t start, int map)
{
	dbug_enter("cfsd_logfile::i_getaddr");

	mmap_info *mmp = (map == 0) ? &i_map_entry : &i_map_offset;

	// determine the end of the item
	off_t end = start + i_maxmap - 1;

	// map the entry in if necessary
	if ((start < mmp->i_paoff) || (mmp->i_paend < end)) {
		if (i_domap(start & i_pagemask, map))
			return (NULL);
		dbug_assert((mmp->i_paoff <= start) && (end <= mmp->i_paend));
	}

	// make an address and return it
	caddr_t pa = mmp->i_pa + (start - mmp->i_paoff);
	return (pa);
}

//
//			cfsd_logfile::logfile_setup
//
// Description:
//	Sets up to use the specified file.
//	Call this routine before using any of the other routines.
// Arguments:
//	filename	file to use
//	maxmap		max amount needed after a map
// Returns:
//	Returns 0 for success or an errno value.
// Preconditions:
//	precond(filename)

int
cfsd_logfile::logfile_setup(const char *filename, int maxmap)
{
	dbug_enter("cfsd_logfile::logfile_setup");
	dbug_precond(filename);

	int xx;

	// clean up from a previous setup
	logfile_teardown();

	i_name = filename;
	dbug_print("info", ("filename %s", i_name.data()));
	i_maxmap = maxmap;

	// get the page info
	i_pagesize = PAGESIZE;
	i_pagemask = PAGEMASK;
	i_maplen = i_pagesize * 100;

	// get the size and type of file
	struct stat sinfo;
	xx = stat(i_name.data(), &sinfo);
	if (xx) {
		xx = errno;
		if (xx == ENOENT) {
			dbug_print("info", ("No log file to roll"));
		} else {
			dbug_print("error", ("Could not stat %s, %d",
			    i_name.data(), xx));
		}
		return (xx);
	}
	i_size = sinfo.st_size;

	// sanity check, better be a regular file
	if (!S_ISREG(sinfo.st_mode)) {
		xx = ENOTSUP;
		dbug_print("error", ("%s Not a regular file.", i_name.data()));
		return (xx);
	}

	// better not be too small
	if (i_size < sizeof (long)) {
		dbug_print("error", ("File %s is too small %d.",
		    i_name.data(), i_size));
		return (0);
	}

	// open the file
	i_fid = open(i_name.data(), O_RDWR);
	if (i_fid == -1) {
		xx = errno;
		dbug_print("error", ("Could not open %s, %d", i_name.data(),
		    xx));
		return (xx);
	}

	// initialize statistic gathering
	i_stat_mapmove = 0;
	i_stat_mapdist = 0;

	// check the version number
	long *versionp;
	versionp = (long *)i_getaddr(0, 1);
	if (versionp == NULL)
		return (EIO);
	if (*versionp != CFS_DLOG_VERSION) {
		dbug_print("error", ("Log file version mismatch %d != %d",
		    *versionp, CFS_DLOG_VERSION));
		return (EINVAL);
	}

	// return success
	return (0);
}

//
//			cfsd_logfile::logfile_teardown
//
// Description:
//	Uninitializes the object.
//	Call logfile_setup before using this object again.
// Arguments:
// Returns:
// Preconditions:

void
cfsd_logfile::logfile_teardown()
{
	dbug_enter("cfsd_logfile::logfile_teardown");

	int xx;

	if (i_map_entry.i_pa) {
		xx = munmap(i_map_entry.i_pa, i_map_entry.i_palen);
		if (xx == -1) {
			xx = errno;
			dbug_print("error", ("Could not unmap %s, %d, %p, %d",
			    i_name.data(), xx,
			    i_map_entry.i_pa, i_map_entry.i_palen));
		}
		i_map_entry.i_pa = NULL;
	}
	i_map_entry.i_paoff = 0;
	i_map_entry.i_paend = 0;
	i_map_entry.i_palen = 0;

	if (i_map_offset.i_pa) {
		xx = munmap(i_map_offset.i_pa, i_map_offset.i_palen);
		if (xx == -1) {
			xx = errno;
			dbug_print("error", ("Could not unmap %s, %d, %p, %d",
			    i_name.data(), xx,
			    i_map_offset.i_pa, i_map_offset.i_palen));
		}
		i_map_offset.i_pa = NULL;
	}
	i_map_offset.i_paoff = 0;
	i_map_offset.i_paend = 0;
	i_map_offset.i_palen = 0;

	if (i_fid != -1) {
		close(i_fid);
		i_fid = -1;
	}
	i_cur_offset = 0;
	i_cur_entry = NULL;
}

//
//			cfsd_logfile::logfile_entry
//
// Description:
//	Sets addrp to the address of the log entry at offset
//	The mapping remains in effect until:
//		a) this routine is called again
//		b) logfile_teardown is called
//		c) this object is destroyed
// Arguments:
//	offset	offset to start of entry
//	entpp	place to store address
// Returns:
//	Returns 0 for success, 1 for EOF, -1 if a fatal error occurs.
// Preconditions:
//	precond(addrp)

int
cfsd_logfile::logfile_entry(off_t offset, cfs_dlog_entry_t **entpp)
{
	dbug_enter("cfsd_logfile::logfile_entrynext");
	dbug_precond(entpp);
	dbug_precond(offset >= sizeof (long));

	cfs_dlog_entry_t *entp;

	i_stat_nextcnt++;

	// check for eof
	if (offset >= i_size)
		return (1);
	dbug_assert((offset & 3) == 0);

	// get the address of the entry
	entp = (cfs_dlog_entry_t *)i_getaddr(offset, 0);
	if (entp == NULL)
		return (-1);

	// sanity check, record should be alligned
	if (entp->dl_len & 3) {
		dbug_print("error",
		    ("Record at offset %d length is not alligned %d",
		    offset, entp->dl_len));
		return (-1);
	}

	// sanity check record should a reasonable size
	if ((entp->dl_len < sizeof (int)) ||
	    (entp->dl_len > CFS_DLOG_ENTRY_MAXSIZE)) {
		dbug_print("error", ("Record at offset %d is too large %d",
		    offset, entp->dl_len));
		return (-1);
	}

	// preserve offset and pointer
	i_cur_offset = offset;
	i_cur_entry = entp;

	// return success
	*entpp = entp;
	return (0);
}

//
//			cfsd_logfile::logfile_offset
//
// Description:
//	Sets addrp to the address of the specified offset.
//	The mapping remains in effect until:
//		a) this routine is called again
//		b) logfile_teardown is called
//		c) this object is destroyed
// Arguments:
//	offset	offset into file, must be 0 <= offset < i_size
//	addrp	returns mapped address
// Returns:
//	Returns 0 for success, -1 if a fatal error occurs.
// Preconditions:
//	precond(addrp)

int
cfsd_logfile::logfile_offset(off_t offset, caddr_t *addrp)
{
	dbug_enter("cfsd_logfile::logfile_offset");
	dbug_precond(addrp);
	dbug_precond((0 <= offset) && (offset < i_size));

	caddr_t pa;

	i_stat_offcnt++;

	// get the address for the offset
	pa = i_getaddr(offset, 1);
	if (pa == NULL)
		return (-1);

	// return success
	*addrp = pa;
	return (0);
}

//
//			cfsd_logfile::logfile_sync
//
// Description:
//	Performs an fsync on the log file.
// Arguments:
// Returns:
//	Returns 0 for success or an errno value on failure.
// Preconditions:

int
cfsd_logfile::logfile_sync()
{
	dbug_enter("cfsd_logfile::logfile_sync");
	if (i_fid == -1)
		return (0);
	int xx = fsync(i_fid);
	if (xx) {
		xx = errno;
		dbug_print("error", ("fsync failed %d", xx));
	}
	return (xx);
}

//
//			cfsd_logfile::logfile_dumpstats
//
// Description:
//	Prints out various stats about the hashing.
// Arguments:
// Returns:
// Preconditions:

void
cfsd_logfile::logfile_dumpstats()
{
	dbug_enter("cfsd_logfile::logfile_dumpstats");

	dbug_print("dump", ("Request - next %d", i_stat_nextcnt));
	dbug_print("dump", ("Request - offset %d", i_stat_offcnt));
	dbug_print("dump", ("Map Moves %d", i_stat_mapmove));
	dbug_print("dump", ("Mapping Size %d", i_maplen));
	dbug_print("dump", ("Item Size %d", i_maxmap));
	dbug_print("dump", ("File Size %d", i_size));
	if (i_stat_mapmove == 0)
		return;

	int xx;
	double dd;

	dd = (double)i_stat_mapmove / (i_stat_nextcnt + i_stat_offcnt);
	dbug_print("dump", ("Mmap moves per Request %.2f", dd));

	xx = i_stat_mapdist / i_stat_mapmove;
	dbug_print("dump", ("Average distance per mmap moves %d", xx));
}
