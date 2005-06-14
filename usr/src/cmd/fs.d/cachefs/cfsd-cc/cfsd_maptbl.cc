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
//			cfsd_maptbl.cc
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
#include "cfsd_maptbl.h"

// a zeroed out cid
static cfs_cid_t nullcid;

//
//			cfsd_maptbl::cfsd_maptbl
//
// Description:
//	Constructor for the cfsd_maptbl class.
//	Just does some setup not much else.
// Arguments:
// Returns:
// Preconditions:

cfsd_maptbl::cfsd_maptbl()
{
	dbug_enter("cfsd_maptbl::cfsd_maptbl");
	i_fid = -1;
	i_pa = NULL;
	i_paoff = 0;
	i_paend = 0;
	i_palen = 0;
}

//
//			cfsd_maptbl::~cfsd_maptbl
//
// Description:
//	Destructor for the cfsd_maptbl class.
// Arguments:
// Returns:
// Preconditions:

cfsd_maptbl::~cfsd_maptbl()
{
	dbug_enter("cfsd_maptbl::~cfsd_maptbl");
	maptbl_teardown();
}

//
//			cfsd_maptbl::i_domap
//
// Description:
//	Maps in the specified section of the file.
// Arguments:
//	off	The offset to map in.  Must be i_pagesize aligned.
// Returns:
//	Returns 0 for success or an errno value on failure.
// Preconditions:

int
cfsd_maptbl::i_domap(off_t off)
{
	dbug_enter("cfsd_maptbl::i_domap");
	dbug_precond(i_fid >= 0);

	int xx;
	int len = i_maplen;

	i_stat_mapmove++;

	// destroy old mapping if it exists
	if (i_pa) {
		// determine how far we have to move the map
		i_stat_mapdist += abs(i_paoff - off);

		// remove the map
		xx = munmap(i_pa, i_palen);
		if (xx == -1) {
			xx = errno;
			dbug_print("error", ("Could not unmap %s, %d, %p, %d",
			    i_name.data(), xx, i_pa, i_palen));
		}
		i_pa = NULL;
		i_palen = 0;
		i_paoff = 0;
		i_paend = 0;
	}

	// do the mapping
	i_pa = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED,
		    i_fid, off);
	if (i_pa == MAP_FAILED) {
		xx = errno;
		dbug_print("error",
		    ("Could not map %s, error %d, off %d, len %d",
		    i_name.data(), xx, off, len));
		i_pa = NULL;
		return (xx);
	}

	i_palen = len;
	i_paoff = off;
	i_paend = off + len - 1;
	return (0);
}

//
//			cfsd_maptbl::i_getaddr
//
// Description:
//	Returns an address of a particular entry in the file.
// Arguments:
//	index
// Returns:
//	Returns NULL for a failure with the mapping file.
// Preconditions:

caddr_t
cfsd_maptbl::i_getaddr(int index)
{
	dbug_enter("cfsd_maptbl::i_getaddr");
	dbug_precond(index < i_entries);

	// find the boundaries of the entry
	off_t start = index * sizeof (cfs_dlog_mapping_space);
	off_t end = start + sizeof (cfs_dlog_mapping_space) - 1;

	// map the entry in if necessary
	if ((start < i_paoff) || (i_paend < end)) {
		if (i_domap(start & i_pagemask))
			return (NULL);
	}

	// make an address and return it
	caddr_t pa = i_pa + (start - i_paoff);
	return (pa);
}

//
//			cfsd_maptbl::i_cidhashaddr
//
// Description:
//	Finds the address of the specified cid by hashing to
//	the appropriate entry.  If the cid does not already
//	exist in the file, then the address of where it should
//	reside is returned.
// Arguments:
//	cid
//	addrp
// Returns:
//	Returns 0 for success, 1 if entry not found, -1 if an
//	error occurs in the mapping file.
// Preconditions:

int
cfsd_maptbl::i_cidhashaddr(cfs_cid_t cid, caddr_t *addrp)
{
	dbug_enter("cfsd_maptbl::i_cidhashaddr");
	dbug_precond(addrp);

	int xx;
	caddr_t pa;
	int index;
	ino_t fileno;

	i_stat_requests++;

	// get the index from the first hash function
	index = i_hash1(cid);

	i_stat_probes++;

	// get the address of the entry
	pa = i_getaddr(index);
	if (pa == NULL)
		return (-1);

	fileno = *(ino_t *)pa;

	// check for match
	if (fileno == cid.cid_fileno) {
		*addrp = pa;
		return (0);
	}

	// check for not found
	if (fileno == 0) {
		*addrp = pa;
		return (1);
	}

	// get the index from the second hash function
	index = i_hash2(cid, index);

	// do a linear search for a match or empty entry
	int start_index = index;
	do {
		i_stat_probes++;

		// get the address of the entry
		pa = i_getaddr(index);
		if (pa == NULL)
			return (-1);

		fileno = *(ino_t *)pa;

		// check for match
		if (fileno == cid.cid_fileno) {
			*addrp = pa;
			return (0);
		}

		// check for not found
		if (fileno == 0) {
			*addrp = pa;
			return (1);
		}

		// move to the next entry
		index++;
		index = index % i_entries;
	} while (start_index != index);

	// table full, this is bad
	dbug_print("error", ("Table is full"));
	return (-1);
}

//
//			cfsd_maptbl::i_hash1
//
// Description:
//	Hashes a cid into an index into the table.
// Arguments:
//	cid
// Returns:
//	Returns the index.
// Preconditions:

int
cfsd_maptbl::i_hash1(cfs_cid_t cid)
{
	unsigned int xx;
	unsigned int a, b;
#if 0
	xx = cid.cid_fileno % i_entries;
#else
	a = cid.cid_fileno >> 16;
	b = a ^ cid.cid_fileno;
	xx = b % i_entries;
#endif
	return (xx);
}

//
//			cfsd_maptbl::i_hash2
//
// Description:
//	Hashes a cid into an index into the table.
// Arguments:
//	cid
//	index
// Returns:
//	Returns the index.
// Preconditions:

int
cfsd_maptbl::i_hash2(cfs_cid_t cid, int index)
{
	unsigned int xx;
	unsigned int a, b, c, d;
#if 0
	a = cid.cid_fileno & 0x0ff;
	b = (cid.cid_fileno >> 8) & 0x0ff;
	b = cid.cid_fileno ^ a ^ b;
	xx = b % i_hash2mod;
#else
	a = cid.cid_fileno & 0x0ff;
	b = (cid.cid_fileno >> 8) & 0x0ff;
	c = (cid.cid_fileno >> 16) & 0x0ff;
	d = (cid.cid_fileno >> 24) & 0x0ff;
	xx = cid.cid_fileno ^ (a << 8) ^ b ^ c ^ d;
	xx = xx % i_hash2mod;
#endif
	xx = (index + xx) % i_entries;
	return (xx);
}

//
//			cfsd_maptbl::maptbl_setup
//
// Description:
//	Performs setup for the cfsd_maptbl class.
//	This routine must be called before other routines are used.
// Arguments:
//	filename
// Returns:
//	Returns 0 for success or an errno value.
// Preconditions:
//	precond(filename)

int
cfsd_maptbl::maptbl_setup(const char *filename)
{
	dbug_enter("cfsd_maptbl::maptbl_setup");
	dbug_precond(filename);

	int xx;

	// clean up from a previous setup
	maptbl_teardown();

	i_name = filename;
	dbug_print("info", ("filename %s", i_name.data()));

	// get the page info
	i_pagesize = PAGESIZE;
	i_pagemask = PAGEMASK;
	i_maplen = i_pagesize * 100;

	// get the size and type of file
	struct stat sinfo;
	xx = stat(i_name.data(), &sinfo);
	if (xx) {
		xx = errno;
		dbug_print("error", ("Could not stat %s, %d", i_name.data(),
		    xx));
		return (xx);
	}
	i_size = sinfo.st_size;

	// sanity check, better be a regular file
	if (!S_ISREG(sinfo.st_mode)) {
		xx = ENOTSUP;
		dbug_print("error", ("%s Not a regular file.", i_name.data()));
		return (xx);
	}

	// open the file
	i_fid = open(i_name.data(), O_RDWR);
	if (i_fid == -1) {
		xx = errno;
		dbug_print("error", ("Could not open %s, %d", i_name.data(),
		    xx));
		return (xx);
	}

	// determine number of entries
	i_entries = i_size / sizeof (cfs_dlog_mapping_space);

	// set up modulo value for second hash function
	i_hash2mod = (i_entries / 2) + 1;

	// initialize statistic gathering
	i_stat_requests = 0;
	i_stat_probes = 0;
	i_stat_mapmove = 0;
	i_stat_mapdist = 0;
	i_stat_filled = 0;

	// zero the file
	off_t offset;
	for (offset = 0; offset < i_size; offset += i_maplen) {
		// map in a section of the file
		xx = i_domap(offset);
		if (xx)
			return (xx);

		// zero this section of the file
		long *lp = (long *)i_pa;
		int cnt;
		off_t size = i_size - offset;
		if (size < i_palen) {
			cnt = size / sizeof (long);
		} else {
			cnt = i_palen / sizeof (long);
			dbug_assert((cnt * sizeof (long)) == i_palen);
		}
		for (xx = 0; xx < cnt; xx++)
			*lp++ = 0;
	}

	// return success
	return (0);
}

//
//			cfsd_maptbl::maptbl_teardown
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_maptbl::maptbl_teardown()
{
	dbug_enter("cfsd_maptbl::maptbl_teardown");

	int xx;
	if (i_pa) {
		xx = munmap(i_pa, i_palen);
		if (xx == -1) {
			xx = errno;
			dbug_print("error", ("Could not unmap %s, %d, %p, %d",
			    i_name.data(), xx, i_pa, i_palen));
		}
		i_pa = NULL;
	}
	i_paoff = 0;
	i_paend = 0;
	i_palen = 0;

	if (i_fid != -1) {
		close(i_fid);
		i_fid = -1;
	}
}

//
//			cfsd_maptbl::maptbl_get
//
// Description:
//	Gets the mapping info for the specified cid.
// Arguments:
//	cid
//	valuep
// Returns:
//	Returns 0 for success, 1 if entry not found, -1 if an
//	error occurs in the mapping file.
// Preconditions:
//	precond(valuep)

int
cfsd_maptbl::maptbl_get(cfs_cid_t cid, cfs_dlog_mapping_space *valuep)
{
	dbug_enter("cfsd_maptbl::maptbl_get");
	dbug_precond(valuep);

	if (i_entries == 0)
		return (1);

	int xx;
	caddr_t pa;
	xx = i_cidhashaddr(cid, &pa);
	if (xx == 0)
		*valuep = *(cfs_dlog_mapping_space *)pa;
	return (xx);
}

//
//			cfsd_maptbl::maptbl_set
//
// Description:
//	Sets the mapping info for the cid.
//	If insert is 1 then if the entry is not found it is put in the
//	table.
// Arguments:
//	valuep
//	insert
// Returns:
//	Returns 0 if mapping info placed in the table, 1 if entry
//	is not found an insert is 0, -1 if an error occurs in the
//	mapping file.
// Preconditions:
//	precond(valuep)

int
cfsd_maptbl::maptbl_set(cfs_dlog_mapping_space *valuep, int insert)
{
	dbug_enter("cfsd_maptbl::maptbl_set");
	dbug_precond(valuep);

	dbug_assert(i_entries > 0);

	int xx;
	caddr_t pa;
	xx = i_cidhashaddr(valuep->ms_cid, &pa);
	if ((xx == 0) || ((xx == 1) && insert)) {
		*(cfs_dlog_mapping_space *)pa = *valuep;
		if (xx == 1)
			i_stat_filled++;
		xx = 0;
	}
	return (xx);
}

//
//			cfsd_maptbl::maptbl_dumpstats
//
// Description:
//	Prints out various stats about the hashing.
// Arguments:
// Returns:
// Preconditions:

void
cfsd_maptbl::maptbl_dumpstats()
{
	dbug_enter("cfsd_maptbl::maptbl_dumpstats");

	dbug_print("dump", ("Total Entries %d", i_entries));
	dbug_print("dump", ("Filled Entries %d", i_stat_filled));
	dbug_print("dump", ("Requests %d", i_stat_requests));
	dbug_print("dump", ("Probes %d", i_stat_probes));
	dbug_print("dump", ("Map Moves %d", i_stat_mapmove));
	dbug_print("dump", ("Mapping Size %d", i_maplen));
	dbug_print("dump", ("File Size %d", i_size));
	if (i_stat_requests == 0)
		return;

	int xx;
	double dd;
	dd = (double)i_stat_probes / i_stat_requests;
	dbug_print("dump", ("Probes per Request %.2f", dd));

	dd = (double)i_stat_mapmove / i_stat_requests;
	dbug_print("dump", ("Mmap moves per Request %.2f", dd));

	xx = i_stat_mapdist / i_stat_mapmove;
	dbug_print("dump", ("Average distance per mmap moves %d", xx));

	xx = ((100.0 * i_stat_filled) / i_entries) + .5;
	dbug_print("dump", ("Table filled %d%%", xx));
}
