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
#include "cfsd_maptbl.h"

/*
 *			cfsd_maptbl_create
 *
 * Description:
 *	Constructor for the cfsd_maptbl class.
 *	Just does some setup not much else.
 * Arguments:
 * Returns:
 * Preconditions:
 */
cfsd_maptbl_object_t *
cfsd_maptbl_create(void)
{
	cfsd_maptbl_object_t *maptbl_object_p;

	dbug_enter("cfsd_maptbl_create");

	maptbl_object_p = cfsd_calloc(sizeof (cfsd_maptbl_object_t));

	maptbl_object_p->i_fid = -1;
	maptbl_object_p->i_pa = NULL;
	maptbl_object_p->i_paoff = 0;
	maptbl_object_p->i_paend = 0;
	maptbl_object_p->i_palen = 0;
	dbug_leave("cfsd_maptbl_create");
	return (maptbl_object_p);
}

/*
 *			cfsd_maptbl_destroy
 *
 * Description:
 *	Destructor for the cfsd_maptbl class.
 * Arguments:
 * Returns:
 * Preconditions:
 */
void
cfsd_maptbl_destroy(cfsd_maptbl_object_t *maptbl_object_p)
{
	dbug_enter("cfsd_maptbl_destroy");
	dbug_precond(maptbl_object_p);
	maptbl_teardown(maptbl_object_p);
	cfsd_free(maptbl_object_p);
	dbug_leave("cfsd_maptbl_destroy");
}

/*
 *			maptbl_domap
 *
 * Description:
 *	Maps in the specified section of the file.
 * Arguments:
 *	off	The offset to map in.  Must be i_pagesize aligned.
 * Returns:
 *	Returns 0 for success or an errno value on failure.
 * Preconditions:
 */
int
maptbl_domap(cfsd_maptbl_object_t *maptbl_object_p, off_t off)
{
	int xx;
	int len;

	dbug_enter("maptbl_domap");
	dbug_precond(maptbl_object_p);
	dbug_precond(maptbl_object_p->i_fid >= 0);

	len = maptbl_object_p->i_maplen;

	maptbl_object_p->i_stat_mapmove++;

	/* destroy old mapping if it exists */
	if (maptbl_object_p->i_pa) {
		/* determine how far we have to move the map */
		maptbl_object_p->i_stat_mapdist +=
		    abs(maptbl_object_p->i_paoff - off);

		/* remove the map */
		xx = munmap(maptbl_object_p->i_pa, maptbl_object_p->i_palen);
		if (xx == -1) {
			xx = errno;
			dbug_print(("error", "Could not unmap %s, %d, %p, %d",
			    maptbl_object_p->i_name, xx, maptbl_object_p->i_pa,
			    maptbl_object_p->i_palen));
		}
		maptbl_object_p->i_pa = NULL;
		maptbl_object_p->i_palen = 0;
		maptbl_object_p->i_paoff = 0;
		maptbl_object_p->i_paend = 0;
	}

	/* do the mapping */
	maptbl_object_p->i_pa =
	    mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED,
	    maptbl_object_p->i_fid, off);
	if (maptbl_object_p->i_pa == MAP_FAILED) {
		xx = errno;
		dbug_print(("error",
		    "Could not map %s, error %d, off %d, len %d",
		    maptbl_object_p->i_name, xx, off, len));
		maptbl_object_p->i_pa = NULL;
		dbug_leave("maptbl_domap");
		return (xx);
	}

	maptbl_object_p->i_palen = len;
	maptbl_object_p->i_paoff = off;
	maptbl_object_p->i_paend = off + len - 1;
	dbug_leave("maptbl_domap");
	return (0);
}

/*
 *			maptbl_getaddr
 *
 * Description:
 *	Returns an address of a particular entry in the file.
 * Arguments:
 *	index
 * Returns:
 *	Returns NULL for a failure with the mapping file.
 * Preconditions:
 */
caddr_t
maptbl_getaddr(cfsd_maptbl_object_t *maptbl_object_p, int index)
{
	off_t start;
	off_t end;
	caddr_t pa;

	dbug_enter("maptbl_getaddr");
	dbug_precond(maptbl_object_p);
	dbug_precond(index < maptbl_object_p->i_entries);

	/* find the boundaries of the entry */
	start = index * sizeof (struct cfs_dlog_mapping_space);
	end = start + sizeof (struct cfs_dlog_mapping_space) - 1;

	/* map the entry in if necessary */
	if ((start < maptbl_object_p->i_paoff) ||
		(maptbl_object_p->i_paend < end)) {
		if (maptbl_domap(maptbl_object_p,
		    start & maptbl_object_p->i_pagemask)) {
			dbug_leave("maptbl_getaddr");
			return (NULL);
		}
	}

	/* make an address and return it */
	pa = maptbl_object_p->i_pa + (start - maptbl_object_p->i_paoff);
	dbug_leave("maptbl_getaddr");
	return (pa);
}

/*
 *			maptbl_cidhashaddr
 *
 * Description:
 *	Finds the address of the specified cid by hashing to
 *	the appropriate entry.  If the cid does not already
 *	exist in the file, then the address of where it should
 *	reside is returned.
 * Arguments:
 *	cid
 *	addrp
 * Returns:
 *	Returns 0 for success, 1 if entry not found, -1 if an
 *	error occurs in the mapping file.
 * Preconditions:
 */
int
maptbl_cidhashaddr(cfsd_maptbl_object_t *maptbl_object_p,
	cfs_cid_t cid,
	caddr_t *addrp)
{
	ino64_t *pa;
	int index;
	ino64_t fileno;
	int start_index;

	dbug_enter("maptbl_cidhashaddr");
	dbug_precond(maptbl_object_p);
	dbug_precond(addrp);

	maptbl_object_p->i_stat_requests++;

	/* get the index from the first hash function */
	index = maptbl_hash1(maptbl_object_p, cid);

	maptbl_object_p->i_stat_probes++;

	/* get the address of the entry */
	pa = (ino64_t *)maptbl_getaddr(maptbl_object_p, index);
	if (pa == NULL) {
		dbug_leave("maptbl_cidhashaddr");
		return (-1);
	}
	fileno = *pa;

	/* check for match */
	if (fileno == cid.cid_fileno) {
		*addrp = (caddr_t)pa;
		dbug_leave("maptbl_cidhashaddr");
		return (0);
	}

	/* check for not found */
	if (fileno == 0) {
		*addrp = (caddr_t)pa;
		dbug_leave("maptbl_cidhashaddr");
		return (1);
	}

	/* get the index from the second hash function */
	index = maptbl_hash2(maptbl_object_p, cid, index);

	/* do a linear search for a match or empty entry */
	start_index = index;
	do {
		maptbl_object_p->i_stat_probes++;

		/* get the address of the entry */
		pa = (ino64_t *)maptbl_getaddr(maptbl_object_p, index);
		if (pa == NULL) {
			dbug_leave("maptbl_cidhashaddr");
			return (-1);
		}
		fileno = *pa;

		/* check for match */
		if (fileno == cid.cid_fileno) {
			*addrp = (caddr_t)pa;
			dbug_leave("maptbl_cidhashaddr");
			return (0);
		}

		/* check for not found */
		if (fileno == 0) {
			*addrp = (caddr_t)pa;
			dbug_leave("maptbl_cidhashaddr");
			return (1);
		}

		/* move to the next entry */
		index++;
		index = index % maptbl_object_p->i_entries;
	} while (start_index != index);

	/* table full, this is bad */
	dbug_print(("error", "Table is full"));
	dbug_leave("maptbl_cidhashaddr");
	return (-1);
}

/*
 *			maptbl_hash1
 *
 * Description:
 *	Hashes a cid into an index into the table.
 * Arguments:
 *	cid
 * Returns:
 *	Returns the index.
 * Preconditions:
 */
int
maptbl_hash1(cfsd_maptbl_object_t *maptbl_object_p, cfs_cid_t cid)
{
	unsigned int xx;
	unsigned int a, b;

	dbug_precond(maptbl_object_p);
#if 0
	xx = cid.cid_fileno % i_entries;
#else
	a = cid.cid_fileno >> 16;
	b = a ^ cid.cid_fileno;
	xx = b % maptbl_object_p->i_entries;
#endif
	return (xx);
}

/*
 *			maptbl_hash2
 *
 * Description:
 *	Hashes a cid into an index into the table.
 * Arguments:
 *	cid
 *	index
 * Returns:
 *	Returns the index.
 * Preconditions:
 */
int
maptbl_hash2(cfsd_maptbl_object_t *maptbl_object_p, cfs_cid_t cid, int index)
{
	unsigned int xx;
	unsigned int a, b, c, d;

	dbug_precond(maptbl_object_p);
#if 0
	a = cid.cid_fileno & 0x0ff;
	b = (cid.cid_fileno >> 8) & 0x0ff;
	b = cid.cid_fileno ^ a ^ b;
	xx = b % maptbl_object_p->i_hash2mod;
#else
	a = cid.cid_fileno & 0x0ff;
	b = (cid.cid_fileno >> 8) & 0x0ff;
	c = (cid.cid_fileno >> 16) & 0x0ff;
	d = (cid.cid_fileno >> 24) & 0x0ff;
	xx = cid.cid_fileno ^ (a << 8) ^ b ^ c ^ d;
	xx = xx % maptbl_object_p->i_hash2mod;
#endif
	xx = (index + xx) % maptbl_object_p->i_entries;
	return (xx);
}

/*
 *			maptbl_setup
 *
 * Description:
 *	Performs setup for the cfsd_maptbl class.
 *	This routine must be called before other routines are used.
 * Arguments:
 *	filename
 * Returns:
 *	Returns 0 for success or an errno value.
 * Preconditions:
 *	precond(filename)
 */
int
maptbl_setup(cfsd_maptbl_object_t *maptbl_object_p, const char *filename)
{
	int xx;
	struct stat sinfo;
	off_t offset;
	long *lp;
	size_t cnt;
	off_t size;

	dbug_enter("maptbl_setup");
	dbug_precond(maptbl_object_p);
	dbug_precond(filename);

	/* clean up from a previous setup */
	maptbl_teardown(maptbl_object_p);

	strlcpy(maptbl_object_p->i_name, filename,
	    sizeof (maptbl_object_p->i_name));
	dbug_print(("info", "filename %s", maptbl_object_p->i_name));

	/* get the page info */
	maptbl_object_p->i_pagesize = PAGESIZE;
	maptbl_object_p->i_pagemask = PAGEMASK;
	maptbl_object_p->i_maplen = maptbl_object_p->i_pagesize * 100;

	/* open the file */
	maptbl_object_p->i_fid = open(maptbl_object_p->i_name,
	    O_RDWR | O_NONBLOCK);
	if (maptbl_object_p->i_fid == -1) {
		xx = errno;
		dbug_print(("error",
		    "Could not open %s, %d", maptbl_object_p->i_name, xx));
		dbug_leave("maptbl_setup");
		return (xx);
	}

	/* get the size and type of file */
	xx = fstat(maptbl_object_p->i_fid, &sinfo);
	if (xx) {
		xx = errno;
		dbug_print(("error",
		    "Could not stat %s, %d", maptbl_object_p->i_name, xx));
		dbug_leave("maptbl_setup");
		return (xx);
	}
	maptbl_object_p->i_size = sinfo.st_size;

	/* sanity check, better be a regular file */
	if (!S_ISREG(sinfo.st_mode)) {
		xx = ENOTSUP;
		dbug_print(("error",
		    "%s Not a regular file.", maptbl_object_p->i_name));
		dbug_leave("maptbl_setup");
		return (xx);
	}

	/* determine number of entries */
	maptbl_object_p->i_entries =
	    maptbl_object_p->i_size / sizeof (struct cfs_dlog_mapping_space);

	/* set up modulo value for second hash function */
	maptbl_object_p->i_hash2mod = (maptbl_object_p->i_entries / 2) + 1;

	/* initialize statistic gathering */
	maptbl_object_p->i_stat_requests = 0;
	maptbl_object_p->i_stat_probes = 0;
	maptbl_object_p->i_stat_mapmove = 0;
	maptbl_object_p->i_stat_mapdist = 0;
	maptbl_object_p->i_stat_filled = 0;

	/* zero the file */
	for (offset = 0; offset < maptbl_object_p->i_size;
		offset += maptbl_object_p->i_maplen) {
		/* map in a section of the file */
		xx = maptbl_domap(maptbl_object_p, offset);
		if (xx) {
			dbug_leave("maptbl_setup");
			return (xx);
		}
		/* zero this section of the file */
		lp = (long *)maptbl_object_p->i_pa;
		size = maptbl_object_p->i_size - offset;
		if (size < maptbl_object_p->i_palen) {
			cnt = size / sizeof (long);
		} else {
			cnt = maptbl_object_p->i_palen / sizeof (long);
			dbug_assert((cnt * sizeof (long)) ==
			    maptbl_object_p->i_palen);
		}
		memset(lp, 0, cnt * sizeof (*lp));
	}

	/* return success */
	dbug_leave("maptbl_setup");
	return (0);
}

/*
 *			maptbl_teardown
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */
void
maptbl_teardown(cfsd_maptbl_object_t *maptbl_object_p)
{
	int xx;

	dbug_enter("maptbl_teardown");
	dbug_precond(maptbl_object_p);

	if (maptbl_object_p->i_pa) {
		xx = munmap(maptbl_object_p->i_pa, maptbl_object_p->i_palen);
		if (xx == -1) {
			xx = errno;
			dbug_print(("error", "Could not unmap %s, %d, %p, %d",
			    maptbl_object_p->i_name, xx, maptbl_object_p->i_pa,
			    maptbl_object_p->i_palen));
		}
		maptbl_object_p->i_pa = NULL;
	}
	maptbl_object_p->i_paoff = 0;
	maptbl_object_p->i_paend = 0;
	maptbl_object_p->i_palen = 0;

	if (maptbl_object_p->i_fid != -1) {
		if (close(maptbl_object_p->i_fid))
			dbug_print(("err", "cannot close maptbl fd, error %d",
			    errno));
		maptbl_object_p->i_fid = -1;
	}
	dbug_leave("maptbl_teardown");
}

/*
 *			maptbl_get
 *
 * Description:
 *	Gets the mapping info for the specified cid.
 * Arguments:
 *	cid
 *	valuep
 * Returns:
 *	Returns 0 for success, 1 if entry not found, -1 if an
 *	error occurs in the mapping file.
 * Preconditions:
 *	precond(valuep)
 */
int
maptbl_get(cfsd_maptbl_object_t *maptbl_object_p,
	cfs_cid_t cid,
	struct cfs_dlog_mapping_space *valuep)
{
	int xx;
	struct cfs_dlog_mapping_space *pa;

	dbug_enter("maptbl_get");
	dbug_precond(maptbl_object_p);
	dbug_precond(valuep);

	if (maptbl_object_p->i_entries == 0) {
		dbug_leave("maptbl_get");
		return (1);
	}
	xx = maptbl_cidhashaddr(maptbl_object_p, cid, (caddr_t *)&pa);
	if (xx == 0)
		*valuep = *pa;
	dbug_leave("maptbl_get");
	return (xx);
}

/*
 *			maptbl_set
 *
 * Description:
 *	Sets the mapping info for the cid.
 *	If insert is 1 then if the entry is not found it is put in the
 *	table.
 * Arguments:
 *	valuep
 *	insert
 * Returns:
 *	Returns 0 if mapping info placed in the table, 1 if entry
 *	is not found an insert is 0, -1 if an error occurs in the
 *	mapping file.
 * Preconditions:
 *	precond(valuep)
 */
int
maptbl_set(cfsd_maptbl_object_t *maptbl_object_p,
	struct cfs_dlog_mapping_space *valuep,
	int insert)
{
	int xx;
	struct cfs_dlog_mapping_space *pa;

	dbug_enter("maptbl_set");
	dbug_precond(maptbl_object_p);
	dbug_precond(valuep);

	dbug_assert(maptbl_object_p->i_entries > 0);

	xx = maptbl_cidhashaddr(maptbl_object_p, valuep->ms_cid,
	    (caddr_t *)&pa);
	if ((xx == 0) || ((xx == 1) && insert)) {
		*pa = *valuep;
		if (xx == 1)
			maptbl_object_p->i_stat_filled++;
		xx = 0;
	}
	dbug_leave("maptbl_set");
	return (xx);
}

/*
 *			maptbl_dumpstats
 *
 * Description:
 *	Prints out various stats about the hashing.
 * Arguments:
 * Returns:
 * Preconditions:
 */
void
maptbl_dumpstats(cfsd_maptbl_object_t *maptbl_object_p)
{
	int xx;
	double dd;

	dbug_enter("maptbl_dumpstats");
	dbug_precond(maptbl_object_p);

	dbug_print(("dump", "Total Entries %d", maptbl_object_p->i_entries));
	dbug_print(("dump", "Filled Entries %d",
	    maptbl_object_p->i_stat_filled));
	dbug_print(("dump", "Requests %d", maptbl_object_p->i_stat_requests));
	dbug_print(("dump", "Probes %d", maptbl_object_p->i_stat_probes));
	dbug_print(("dump", "Map Moves %d", maptbl_object_p->i_stat_mapmove));
	dbug_print(("dump", "Mapping Size %d", maptbl_object_p->i_maplen));
	dbug_print(("dump", "File Size %d", maptbl_object_p->i_size));
	if (maptbl_object_p->i_stat_requests == 0) {
		dbug_leave("maptbl_dumpstats");
		return;
	}
	dd = (double)maptbl_object_p->i_stat_probes /
	    maptbl_object_p->i_stat_requests;
	dbug_print(("dump", "Probes per Request %.2f", dd));

	dd = (double)maptbl_object_p->i_stat_mapmove /
	    maptbl_object_p->i_stat_requests;
	dbug_print(("dump", "Mmap moves per Request %.2f", dd));

	xx = maptbl_object_p->i_stat_mapdist / maptbl_object_p->i_stat_mapmove;
	dbug_print(("dump", "Average distance per mmap moves %d", xx));

	xx = ((100.0 * maptbl_object_p->i_stat_filled) /
	    maptbl_object_p->i_entries) + .5;
	dbug_print(("dump", "Table filled %d%%", xx));

	dbug_leave("maptbl_dumpstats");
}
