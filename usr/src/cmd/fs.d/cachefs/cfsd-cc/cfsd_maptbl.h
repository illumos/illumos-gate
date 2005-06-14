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
// ------------------------------------------------------------
//
//			cfsd_maptbl.h
//
// Include file for the maptbl class.
//

#pragma ident	"%Z%%M%	%I%	%E% SMI"
// Copyright (c) 1994 by Sun Microsystems, Inc.

#ifndef CFSD_MAPTBL
#define	CFSD_MAPTBL

class cfsd_maptbl {
private:
	RWCString	i_name;			// name of file
	int		i_fid;			// fid of file
	off_t		i_size;			// file size
	int		i_entries;		// number of entries
	int		i_hash2mod;		// second hash module value
	int		i_stat_filled;		// number of filled entries
	int		i_stat_requests;	// number of lookups done
	int		i_stat_probes;		// number of probes
	int		i_stat_mapmove;		// number of times map moved
	long		i_stat_mapdist;		// how far we move the map
	caddr_t		i_pa;			// address of mmap section
	size_t		i_palen;		// length of mmap section
	off_t		i_paoff;		// offset of mmap section
	off_t		i_paend;		// end offset of mmap section
	long		i_pagesize;		// size of a page
	u_long		i_pagemask;		// page alignment mask
	long		i_maplen;		// amount to map

	int i_domap(off_t off);
	caddr_t i_getaddr(int index);
	int i_cidhashaddr(cfs_cid_t cid, caddr_t *addrp);
	int i_hash1(cfs_cid_t cid);
	int i_hash2(cfs_cid_t cid, int index);

public:
	cfsd_maptbl();
	~cfsd_maptbl();

	// performs setup for the specified file
	int maptbl_setup(const char *filename);
	void maptbl_teardown();

	// gets/sets cid mapping
	int maptbl_get(cfs_cid_t cid, cfs_dlog_mapping_space *valuep);
	int maptbl_set(cfs_dlog_mapping_space *valuep, int insert);

	// returns number of entries in the table
	int maptbl_entries() { return i_entries; }

	// prints out various stats about the hashing
	void maptbl_dumpstats();
};

#endif /* CFSD_MAPTBL */
