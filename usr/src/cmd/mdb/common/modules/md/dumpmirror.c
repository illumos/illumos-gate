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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "mdinclude.h"

/*
 * Display an arbitrary bitmap by showing the set bits in the array.
 * Output will be <start>-<end> for ranges or <position> for singleton bits.
 */
static void
print_mm_bm(unsigned char *bm, uint_t size, char *bm_name)
{
	int	i;
	int	first_set = -1;
	int	need_comma = 0;

	mdb_printf("%s set bits: ", bm_name);
	for (i = 0; i < size; i++) {
		if (isset(bm, i)) {
			if (first_set == -1) {
				first_set = i;
			}
		} else {
			if (first_set != -1) {
				if (first_set != (i-1)) {
					mdb_printf("%s%u-%u",
					    (need_comma ? "," : ""),
					    first_set, (i-1));
				} else {
					mdb_printf("%s%u",
					    (need_comma ? "," : ""), first_set);
				}
				need_comma = 1;
				first_set = -1;
			}
		}
	}
	if (first_set != -1) {
		mdb_printf("%s%u-%u", (need_comma ? "," : ""), first_set,
		    size-1);
	}
	mdb_printf("\n");
}

/*
 * Print uchar_t sized count fields (typically un_pernode_dirty_map entries)
 */

static void
print_mm_cnt_c(unsigned char *bm, uint_t size, char *bm_name)
{
	int	i;
	int	need_comma = 0;

	mdb_printf("%s set counts: ", bm_name);
	for (i = 0; i < size; i++) {
		if (bm[i]) {
			mdb_printf("%s(%d,%3d)", (need_comma ? "," : ""), i,
			    (uint_t)bm[i]);
			need_comma = 1;
		}
	}
	mdb_printf("\n");
}

static void
print_mm_cnt_w(unsigned short *bm, uint_t size, char *bm_name)
{
	int	i;
	int	need_comma = 0;

	mdb_printf("%s set counts: ", bm_name);
	for (i = 0; i < size; i++) {
		if (bm[i]) {
			mdb_printf("%s(%d,%5d)", (need_comma ? "," : ""), i,
			    (uint_t)bm[i]);
			need_comma = 1;
		}
	}
	mdb_printf("\n");
}

/*
 * Print the associated bitmaps for the specified mm_unit_t
 * These are:
 *	un_pernode_dirty_bm
 *	un_goingclean_bm
 *	un_dirty_bm
 *	un_goingdirty_bm
 *	un_resync_bm
 *
 * Associated counts for unit:
 *	un_pernode_dirty_sum[] 	(uchar_t)
 *	un_outstanding_writes[]	(ushort_t)
 *
 */

/* ARGSUSED */
int
printmmbm(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mm_unit_t	mm, *mmp;
	unsigned char	*rr_dirty_bm, *rr_goingclean_bm, *rr_goingdirty_bm;
	unsigned char	*rr_resync_bm;
	uintptr_t	un_dbm, un_gcbm, un_gdbm, un_rrbm, un_pnds, un_ow;
	uint_t		num_rr, rr_bitmap_size;
	int		i;
	uintptr_t	un_pernode_bm;
	unsigned char	*rr_pernode_dirty, *rr_pnds;
	unsigned short	*rr_ow;
	/* just enough for un_pernode_dirty_bm[] plus three digits */
	char		pernode_str[25];

	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("No mm_unit_t address specified");
		return (DCMD_ERR);
	}

	if (mdb_vread(&mm, sizeof (mm_unit_t), addr) == -1) {
		mdb_warn("failed to read mm_unit_t at %p\n", addr);
		return (DCMD_ERR);
	}

	mmp = &mm;

	num_rr = mm.un_rrd_num;

	un_dbm = (uintptr_t)mmp->un_dirty_bm;
	un_gcbm = (uintptr_t)mmp->un_goingclean_bm;
	un_gdbm = (uintptr_t)mmp->un_goingdirty_bm;
	un_rrbm = (uintptr_t)mmp->un_resync_bm;
	un_pnds = (uintptr_t)mmp->un_pernode_dirty_sum;
	un_ow = (uintptr_t)mmp->un_outstanding_writes;

	rr_bitmap_size = howmany(num_rr, NBBY);
	rr_dirty_bm = (unsigned char *)mdb_alloc(rr_bitmap_size,
	    UM_SLEEP|UM_GC);
	rr_goingclean_bm = (unsigned char *)mdb_alloc(rr_bitmap_size,
	    UM_SLEEP|UM_GC);
	rr_goingdirty_bm = (unsigned char *)mdb_alloc(rr_bitmap_size,
	    UM_SLEEP|UM_GC);
	rr_resync_bm = (unsigned char *)mdb_alloc(rr_bitmap_size,
	    UM_SLEEP|UM_GC);
	rr_pnds = (unsigned char *)mdb_alloc(num_rr, UM_SLEEP|UM_GC);
	rr_ow = (unsigned short *)mdb_alloc(num_rr * sizeof (unsigned short),
	    UM_SLEEP|UM_GC);

	if (mdb_vread(rr_dirty_bm, rr_bitmap_size, un_dbm) == -1) {
		mdb_warn("failed to read un_dirty_bm at %p\n", un_dbm);
		return (DCMD_ERR);
	}
	if (mdb_vread(rr_goingclean_bm, rr_bitmap_size, un_gcbm) == -1) {
		mdb_warn("failed to read un_goingclean_bm at %p\n", un_gcbm);
		return (DCMD_ERR);
	}
	if (mdb_vread(rr_goingdirty_bm, rr_bitmap_size, un_gdbm) == -1) {
		mdb_warn("failed to read un_goingdirty_bm at %p\n", un_gdbm);
		return (DCMD_ERR);
	}
	if (mdb_vread(rr_resync_bm, rr_bitmap_size, un_rrbm) == -1) {
		mdb_warn("failed to read un_resync_bm at %p\n", un_rrbm);
		return (DCMD_ERR);
	}
	if (mdb_vread(rr_pnds, num_rr, un_pnds) == -1) {
		mdb_warn("failed to read un_pernode_dirty_sum at %p\n",
		    un_pnds);
		return (DCMD_ERR);
	}
	if (mdb_vread(rr_ow, num_rr * sizeof (unsigned short), un_ow) == -1) {
		mdb_warn("failed to read un_outstanding_writes at %p\n", un_ow);
		return (DCMD_ERR);
	}

	print_mm_bm(rr_dirty_bm, num_rr, "un_dirty_bm");
	print_mm_bm(rr_goingclean_bm, num_rr, "un_goingclean_bm");
	print_mm_bm(rr_goingdirty_bm, num_rr, "un_goingdirty_bm");
	print_mm_bm(rr_resync_bm, num_rr, "un_resync_bm");

	/*
	 * Load all the un_pernode_bm[] entries and iterate through the non-
	 * NULL entries
	 */
	rr_pernode_dirty = (unsigned char *)mdb_alloc(rr_bitmap_size,
	    UM_SLEEP|UM_GC);

	for (i = 0; i < 128; i++) {
		un_pernode_bm = (uintptr_t)mmp->un_pernode_dirty_bm[i];
		if (un_pernode_bm) {
			mdb_snprintf(pernode_str, sizeof (pernode_str),
			    "un_pernode_dirty_bm[%d]", i);
			if (mdb_vread(rr_pernode_dirty, rr_bitmap_size,
			    un_pernode_bm) == -1) {
				mdb_warn("failed to read %s at %p\n",
				    pernode_str, un_pernode_bm);
				return (DCMD_ERR);
			}
			print_mm_bm(rr_pernode_dirty, num_rr, pernode_str);
		}
	}
	print_mm_cnt_c(rr_pnds, num_rr, "un_pernode_dirty_sum");

	print_mm_cnt_w(rr_ow, num_rr, "un_outstanding_writes");

	return (DCMD_OK);
}
