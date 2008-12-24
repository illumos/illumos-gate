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

typedef struct	submirror_cb {
	minor_t		un_self_id;
	int		un_nsm;
	ushort_t	mm_un_nsm;
}submirror_cb_t;

void
print_setname(int setno)
{
	char		setname[1024];

	if (setno != 0) {
		if (mdb_readstr(setname, 1024,
		    (uintptr_t)set_dbs[setno].s_setname) == -1) {
			mdb_warn("failed to read setname at 0x%p\n",
			    set_dbs[setno].s_setname);
		}
		mdb_printf("%s/", setname);
	}
}

void
print_stripe(void *un_addr, void *mdcptr, uint_t verbose)
{
	ms_unit_t	ms;
	int		setno;
	minor_t		un_self_id;
	md_parent_t	un_parent;
	diskaddr_t	un_total_blocks;

	/* read in the device */
	un_self_id = ((mdc_unit_t *)mdcptr)->un_self_id;
	un_parent = ((mdc_unit_t *)mdcptr)->un_parent;
	un_total_blocks = ((mdc_unit_t *)mdcptr)->un_total_blocks;
	if (mdb_vread(&ms, sizeof (ms_unit_t),
	    (uintptr_t)un_addr) == -1) {
		mdb_warn("failed to read ms_unit_t at %p\n", un_addr);
		return;
	}

	setno = MD_MIN2SET(un_self_id);
	print_setname(setno);

	mdb_printf("d%u: ", MD_MIN2UNIT(un_self_id));
	if (un_parent == ((unit_t)-1)) {
		mdb_printf("Concat/Stripe");
	} else {
		mdb_printf("Subdevice of d%u", MD_MIN2UNIT(un_parent));
	}
	if (verbose) {
		mdb_printf("\t< %p::print ms_unit_t >\n", un_addr);
	} else {
		mdb_printf("\t< %p>\n", un_addr);
	}
	mdb_inc_indent(2);
	mdb_printf("Size: %llu blocks\n", un_total_blocks);
	mdb_printf("Rows: %u\n", ms.un_nrows);
	mdb_dec_indent(2);
}

/* ARGSUSED */
int
print_submirror(uintptr_t addr, void *arg, submirror_cb_t *data)
{
	uintptr_t	un_addr;
	mdc_unit_t	mdc_sm;

	if (mdb_vread(&un_addr, sizeof (void *), addr) == -1) {
		mdb_warn("failed to read submirror at %p\n", addr);
		return (WALK_ERR);
	}
	if (un_addr != NULL) {
		if (mdb_vread(&mdc_sm, sizeof (mdc_unit_t), un_addr) == -1) {
			mdb_warn("failed to read mdc_unit_t at %p", un_addr);
			return (WALK_ERR);
		}
		if (mdc_sm.un_parent == data->un_self_id) {
		/* this is one of the sub mirrors */
			mdb_printf("Submirror %u: d%u ",
			    data->un_nsm, MD_MIN2UNIT(mdc_sm.un_self_id));
			mdb_printf("Size: %llu\n", mdc_sm.un_total_blocks);
			data->un_nsm++;
			if (data->un_nsm == data->mm_un_nsm)
				return (WALK_DONE);
		}
	}
	return (WALK_NEXT);
}

/*
 * Construct an RLE count for the number of 'cleared' bits in the given 'bm'
 * Output the RLE count in form: [<set>.<cleared>.<set>.<cleared>...]
 * RLE is Run Length Encoding, a method for compactly describing a bitmap
 * as a series of numbers indicating the count of consecutive set or cleared
 * bits.
 *
 * Input:
 *	<bm>	bitmap to scan
 *	<size>	length of bitmap (in bits)
 *	<comp_bm>	RLE count array to be updated
 *	<opstr>	Descriptive text for bitmap RLE count display
 */
static void
print_comp_bm(unsigned char *bm, uint_t size, ushort_t *comp_bm, char *opstr)
{
	int	cnt_clean, tot_dirty, cur_idx;
	int	i, cur_clean, cur_dirty, printit, max_set_cnt, max_reset_cnt;

	cnt_clean = 1;
	printit = 0;
	cur_clean = 0;
	cur_dirty = 0;
	cur_idx = 0;
	tot_dirty = 0;
	max_set_cnt = max_reset_cnt = 0;
	for (i = 0; i < size; i++) {
		if (isset(bm, i)) {
			/* If we're counting clean bits, flush the count out */
			if (cnt_clean) {
				cnt_clean = 0;
				comp_bm[cur_idx] = cur_clean;
				printit = 1;
				if (cur_clean > max_reset_cnt) {
					max_reset_cnt = cur_clean;
				}
			}
			cur_clean = 0;
			cur_dirty++;
			tot_dirty++;
		} else {
			if (!cnt_clean) {
				cnt_clean = 1;
				comp_bm[cur_idx] = cur_dirty;
				printit = 1;
				if (cur_dirty > max_set_cnt) {
					max_set_cnt = cur_dirty;
				}
			}
			cur_dirty = 0;
			cur_clean++;
		}
		if (printit) {
			mdb_printf("%u.", comp_bm[cur_idx++]);
			printit = 0;
		}
	}

	mdb_printf("\nTotal %s bits = %lu\n", opstr, tot_dirty);
	mdb_printf("Total %s transactions = %lu\n", opstr, cur_idx);
	mdb_printf("Maximum %s set count = %lu, reset count = %lu\n", opstr,
	    max_set_cnt, max_reset_cnt);
}

void
print_mirror(void *un_addr, void *mdcptr, uint_t verbose)
{
	mm_unit_t	mm, *mmp;
	void		**ptr;
	int		setno = 0;
	minor_t		un_self_id;
	diskaddr_t	un_total_blocks;
	ushort_t	mm_un_nsm;
	submirror_cb_t	data;
	uint_t		num_rr, rr_blksize;
	ushort_t	*comp_rr;
	unsigned char	*rr_dirty_bm, *rr_goingclean_bm;
	uintptr_t	un_dbm, un_gcbm;

	/* read in the device */
	if (mdb_vread(&mm, sizeof (mm_unit_t),
	    (uintptr_t)un_addr) == -1) {
		mdb_warn("failed to read mm_unit_t at %p\n", un_addr);
		return;
	}

	mmp = &mm;

	un_self_id = ((mdc_unit_t *)mdcptr)->un_self_id;
	un_total_blocks = ((mdc_unit_t *)mdcptr)->un_total_blocks;
	mm_un_nsm = mm.un_nsm;
	setno = MD_MIN2SET(un_self_id);
	print_setname(setno);

	mdb_printf("d%u: Mirror", MD_MIN2UNIT(un_self_id));
	if (verbose) {
		mdb_printf("\t< %p::print mm_unit_t >\n", un_addr);
	} else {
		mdb_printf("\t< %p >\n", un_addr);
	}
	mdb_inc_indent(2);
	mdb_printf("Size: %llu blocks\n", un_total_blocks);

	/*
	 * Dump out the current un_dirty_bm together with its size
	 * Also, attempt to Run Length encode the bitmap to see if this
	 * is a viable option
	 */
	num_rr = mm.un_rrd_num;
	rr_blksize = mm.un_rrd_blksize;

	un_dbm = (uintptr_t)mmp->un_dirty_bm;
	un_gcbm = (uintptr_t)mmp->un_goingclean_bm;

	mdb_printf("RR size: %lu bits\n", num_rr);
	mdb_printf("RR block size: %lu blocks\n", rr_blksize);

	rr_dirty_bm = (unsigned char *)mdb_alloc(num_rr, UM_SLEEP|UM_GC);
	rr_goingclean_bm = (unsigned char *)mdb_alloc(num_rr, UM_SLEEP|UM_GC);
	comp_rr = (ushort_t *)mdb_alloc(num_rr * sizeof (ushort_t),
	    UM_SLEEP|UM_GC);

	if (mdb_vread(rr_dirty_bm, num_rr, un_dbm) == -1) {
		mdb_warn("failed to read un_dirty_bm at %p\n", un_dbm);
		return;
	}
	if (mdb_vread(rr_goingclean_bm, num_rr, un_gcbm) == -1) {
		mdb_warn("failed to read un_goingclean_bm at %p\n", un_gcbm);
		return;
	}

	print_comp_bm(rr_dirty_bm, num_rr, comp_rr, "dirty");

	print_comp_bm(rr_goingclean_bm, num_rr, comp_rr, "clean");

	/*
	 * find the sub mirrors, search through each metadevice looking
	 * at the un_parent.
	 */
	ptr = mdset[setno].s_un;

	data.un_self_id = un_self_id;
	data.un_nsm = 0;
	data.mm_un_nsm = mm_un_nsm;

	if (mdb_pwalk("md_units", (mdb_walk_cb_t)print_submirror, &data,
	    (uintptr_t)ptr) == -1) {
		mdb_warn("unable to walk units\n");
		return;
	}

	mdb_dec_indent(2);
}

void
print_raid(void *un_addr, void *mdcptr, uint_t verbose)
{
	mr_unit_t	mr;
	minor_t		un_self_id;
	diskaddr_t	un_total_blocks;
	mdc_unit_t	mdc_sc;
	void		**ptr;
	void		*addr;
	int		setno = 0;
	int		i;
	minor_t		sc_un_self_id;
	md_parent_t	sc_parent;
	diskaddr_t	sc_total_blocks;

	/* read in the device */
	if (mdb_vread(&mr, sizeof (mr_unit_t), (uintptr_t)un_addr) == -1) {
		mdb_warn("failed to read mr_unit_t at %p\n", un_addr);
		return;
	}
	un_self_id = ((mdc_unit_t *)mdcptr)->un_self_id;
	un_total_blocks = ((mdc_unit_t *)mdcptr)->un_total_blocks;
	setno = MD_MIN2SET(un_self_id);
	print_setname(setno);

	mdb_printf("d%u: Raid", MD_MIN2UNIT(un_self_id));
	if (verbose) {
		mdb_printf("\t< %p ::print mr_unit_t>\n", un_addr);
	} else {
		mdb_printf("\t< %p >\n", un_addr);
	}
	mdb_inc_indent(2);
	mdb_printf("Size: %llu\n", un_total_blocks);

	/*
	 * find the sub components if any, search through each metadevice
	 * looking at the un_parent.
	 */
	ptr = mdset[setno].s_un;
	for (i = 0; i < md_nunits; i++, ptr++) {
		if (mdb_vread(&addr, sizeof (void *), (uintptr_t)ptr) == -1) {
			mdb_warn("failed to read addr at %p\n", ptr);
			continue;
		}
		if (addr != NULL) {
			if (mdb_vread(&mdc_sc, sizeof (mdc_unit_t),
			    (uintptr_t)addr) == -1) {
				mdb_warn("failed to read mdc_unit_t at %p",
				    un_addr);
				continue;
			}
			sc_parent = mdc_sc.un_parent;
			sc_un_self_id = mdc_sc.un_self_id;
			sc_total_blocks = mdc_sc.un_total_blocks;
			if (sc_parent == un_self_id) {
				/* this is one of the sub components */
				mdb_printf("Subdevice %u ",
				    MD_MIN2UNIT(sc_un_self_id));
				mdb_printf("Size: %llu\n", sc_total_blocks);
			}
		}
	}
	mdb_dec_indent(2);
}

void
print_sp(void *un_addr, void *mdcptr, uint_t verbose)
{
	mp_unit_t	mp;
	minor_t		un_self_id;
	diskaddr_t	un_total_blocks;
	int		setno = 0;
	uintptr_t	extaddr;
	int		i;

	/* read in the device */
	if (mdb_vread(&mp, sizeof (mp_unit_t), (uintptr_t)un_addr) == -1) {
		mdb_warn("failed to read mp_unit_t at %p\n", un_addr);
		return;
	}
	un_self_id = ((mdc_unit_t *)mdcptr)->un_self_id;
	un_total_blocks = ((mdc_unit_t *)mdcptr)->un_total_blocks;
	setno = MD_MIN2SET(un_self_id);
	print_setname(setno);

	mdb_printf("d%u: Soft Partition", MD_MIN2UNIT(un_self_id));
	if (verbose) {
		mdb_printf("\t< %p ::print mp_unit_t >\n", un_addr);
	} else {
		mdb_printf("\t< %p >\n", un_addr);
	}
	mdb_inc_indent(2);
	mdb_printf("Size: %llu\n", un_total_blocks);
	mdb_inc_indent(2);
	mdb_printf("Extent\tStart Block\tBlock count\n");
	extaddr = (uintptr_t)un_addr + sizeof (mp_unit_t) - sizeof (mp_ext_t);
	for (i = 0; i < mp.un_numexts; i++) {
		mp_ext_t	mpext;

		if (mdb_vread(&mpext, sizeof (mp_ext_t), extaddr) == -1) {
			mdb_warn("failed to read mp_ext_t at %p\n", extaddr);
			return;
		}
		mdb_printf("   %d \t      %llu\t        %llu\n",
		    i, mpext.un_poff, mpext.un_len);
		extaddr += sizeof (mp_ext_t);
	}
	mdb_dec_indent(2);
	mdb_dec_indent(2);

}

void
print_trans(void *un_addr, void *mdcptr, uint_t verbose)
{
	mt_unit_t	mt;
	minor_t		un_self_id;
	int		setno = 0;

	/* read in the device */
	if (mdb_vread(&mt, sizeof (mt_unit_t), (uintptr_t)un_addr) == -1) {
		mdb_warn("failed to read mt_unit_t at %p\n", un_addr);
		return;
	}
	un_self_id = ((mdc_unit32_od_t *)mdcptr)->un_self_id;
	setno = MD_MIN2SET(un_self_id);
	print_setname(setno);

	mdb_printf("d%u: Trans", MD_MIN2UNIT(un_self_id));
	if (verbose) {
		mdb_printf("\t< %p ::print mt_unit_t>\n", un_addr);
	} else {
		mdb_printf("\t< %p >\n", un_addr);
	}

}

void
print_device(void *un_addr, void *mdcptr, uint_t verbose)
{
	u_longlong_t	un_type;

	un_type = ((mdc_unit_t *)mdcptr)->un_type;

	switch (un_type) {
	case MD_DEVICE:		/* stripe/concat */
		print_stripe(un_addr, mdcptr, verbose);
		break;
	case MD_METAMIRROR:
		print_mirror(un_addr, mdcptr, verbose);
		break;
	case MD_METATRANS:
		print_trans(un_addr, mdcptr, verbose);
		break;
	case MD_METARAID:
		print_raid(un_addr, mdcptr, verbose);
		break;
	case MD_METASP:
		print_sp(un_addr, mdcptr, verbose);
		break;
	case MD_UNDEFINED:
		mdb_warn("undefined metadevice at %p\n", un_addr);
		break;
	default:
		mdb_warn("invalid metadevice at %p\n", un_addr);
		break;
	}
}

/* ARGSUSED */
/*
 * usage:  ::metastat [-v]
 */
int
metastat(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdc_unit_t	mdc;
	uintptr_t	un_addr;
	uint_t		verbose = FALSE;

	snarf_sets();

	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL)
	    != argc) {
		return (DCMD_USAGE);
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("md_units", "metastat", argc,
		    argv) == -1) {
			mdb_warn("failed to walk units");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	if (!(flags & DCMD_LOOP)) {
		/* user passed set addr */
		if (mdb_pwalk_dcmd("md_units", "metastat", argc,
		    argv, addr) == -1) {
			mdb_warn("failed to walk units");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&un_addr, sizeof (void *), addr) == -1) {
		mdb_warn("failed to read un_addr at %p", addr);
		return (DCMD_ERR);
	}

	if (un_addr != NULL) {
		if (mdb_vread(&mdc, sizeof (mdc_unit_t), un_addr) == -1) {
			mdb_warn("failed to read mdc_unit_t at %p", un_addr);
			return (DCMD_ERR);
		}
		print_device((void *)un_addr, (void *)&mdc, verbose);
		mdb_dec_indent(2);
	}
	return (DCMD_OK);
}
