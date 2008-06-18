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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * md_convert.c
 *
 * As the size of a metadevice used to be stored in 32 bit signed variables,
 * there was a limit of 1 TB for the size (2^31 * 512 byte).
 * In order to be able to create larger metadevices, a 2nd set of structures
 * with wider variables for the size has been created.
 * There's one structure being shared by all types (mdc_unit_t) and one
 * for each type of metadevice (mm_unit_t, ms_unit_t, mr_unit_t, ...).
 * the wide structures are named like mdc_unit_t, mm_unit_t,..
 * The narrow structures are named like mdc_unit32_od_t, mm_unit32_od_t,...
 *
 * The wide structures are used for md's >= 1TB, the narrow structures
 * are used for md's < 1TB.
 * Once a metadevice grows from < 1TB to >= 1TB the record has to be
 * converted from a narrow one to a wide one.
 *
 * Incore (commands, libs and drivers) we only use the wide structures,
 * in order to keep it simple.
 * This means when we snarf a narrow struct, we have to convert it to a
 * wide incore instance before we can use the md.
 *
 *
 * This file contains conversion routines for the various metadevices.
 * All the conversion routines take as input two pointers to memory areas
 * and a direction. The directions specifies which memory area is the
 * source and which is the destination.
 */


#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/lvm/mdvar.h>
#ifdef _KERNEL
#include <sys/lvm/md_basic.h>
#else /* !_KERNEL */
#include <meta_basic.h>
#endif /* _KERNEL */
#include <sys/lvm/md_convert.h>


/*
 * SVM private devt expansion routine
 * INPUT:  dev  a 64 bit container holding either a 32 bit or a 64 bit device
 * OUTPUT: always an expanded 64 bit device, even if we are running in a
 *              32 bit Kernel.
 */
md_dev64_t
md_expldev(md_dev64_t dev)
{
	minor_t minor;
	major_t major = (major_t)(dev >> NBITSMINOR64) & MAXMAJ64;

	/* Here we were given a 64bit dev, return unchanged */
	if (major != (major_t)0)
		return (dev);
	/* otherwise we were given a 32 bit dev */
	major = (major_t)dev >> NBITSMINOR32 & MAXMAJ32;
	minor = (minor_t)dev & MAXMIN32;
	return (((md_dev64_t)major << NBITSMINOR64) | minor);
}

/*
 * SVM private devt compact routine
 * INPUT:  dev  a 64 bit container holding either a 32 bit or a 64 bit device
 * OUTPUT: always a compacted 32 bit device, even if we are running in a
 *              64 bit Kernel.
 */
dev32_t
md_cmpldev(md_dev64_t dev)
{
	minor_t minor;
	major_t major = (major_t)(dev >> NBITSMINOR64) & MAXMAJ64;

	/* Here we were given a 32bit dev, return unchanged */
	if (major == 0) {
		return ((dev32_t)dev);
	}
	/* otherwise we were given a 64 bit dev */
	minor = (minor_t)dev & MAXMIN32;
	return (((dev32_t)major << NBITSMINOR32) | minor);
}


/*
 * given a small stripe unit, compute the size of an appropriate
 * big stripe unit.
 * if first_comp_only is set just return the offset of the first component
 * in the new big unit.
 *
 * The function:
 * usr/src/lib/lvm/libmeta/common/meta_statconcise.c:get_stripe_req_size()
 * contains code derived from this function and thus if any changes are made to
 * this function get_stripe_req_size() should be evaluated to determine whether
 * or not code changes will also  be necessary there.
 *
 */
size_t
get_big_stripe_req_size(ms_unit32_od_t *un, int first_comp_only)
{
	struct ms_row32_od *mdr;
	uint_t row;
	uint_t ncomps = 0;
	size_t mdsize = 0;
	size_t first_comp = 0;


	/* Compute the offset of the first component */
	first_comp = sizeof (ms_unit_t) +
	    sizeof (struct ms_row) * (un->un_nrows - 1);
	first_comp = roundup(first_comp, sizeof (long long));
	if (first_comp_only == FIRST_COMP_OFFSET)
		return (first_comp);

	/*
	 * Requestor wants to have the total size, add the sizes of
	 * all components
	 */
	mdr = &un->un_row[0];
	for (row = 0; (row < un->un_nrows); row++)
		ncomps += mdr[row].un_ncomp;
	mdsize = first_comp + sizeof (ms_comp_t) * ncomps;
	return (mdsize);
}

/*
 * given a big stripe unit, compute the size of an appropriate
 * small stripe unit.
 * if first_comp_only is set just return the offset of the first component
 * in the new small unit.
 */
size_t
get_small_stripe_req_size(ms_unit_t *un, int first_comp_only)
{
	struct ms_row *mdr;
	uint_t row;
	uint_t ncomps = 0;
	size_t mdsize;
	size_t first_comp;

	/* Compute the size of the new small ms_unit */
	first_comp = sizeof (ms_unit32_od_t) +
	    sizeof (struct ms_row32_od) * (un->un_nrows - 1);
	first_comp = roundup(first_comp, sizeof (long long));
	if (first_comp_only == FIRST_COMP_OFFSET)
		return (first_comp);

	/*
	 * Requestor wants to have the total size, add the sizes of
	 * all components
	 */
	mdr = &un->un_row[0];
	for (row = 0; (row < un->un_nrows); row++)
		ncomps += mdr[row].un_ncomp;
	mdsize = first_comp + sizeof (ms_comp32_od_t) * ncomps;
	return (mdsize);
}


/*
 * stripe_convert(small, big, dir)
 *
 * Parameters:
 *	small is the address of a ms_unit32_od_t structure
 *	big   is the address of a ms_unit_t structure
 *	dir   is either BIG2SMALL or SMALL2BIG
 * Return value is void
 *
 * what it does:
 * 	if dir is BIG2SMALL, convert from big to small (updating old records)
 * 	if dir is SMALL2BIG, convert from small to big (snarfing old records)
 *
 * Caveat emptor: big and small must be well allocated memory areas.
 */

void
stripe_convert(caddr_t small, caddr_t big, int direction)
{
	/*LINTED*/
	ms_unit32_od_t *small_un = (ms_unit32_od_t *)small;
	/*LINTED*/
	ms_unit_t *big_un = (ms_unit_t *)big;

	struct ms_row32_od	*small_mdr;
	struct ms_row		*big_mdr;
	uint_t			row, comp, ncomps = 0;
	ms_comp_t		*big_mdcomp;
	ms_comp32_od_t		*small_mdcomp;

	if (direction == BIG_2_SMALL) {
		MDC_UNIT_BIG2SMALL(big_un, small_un);

		small_un->un_hsp_id = big_un->un_hsp_id;
		small_un->un_nrows  = big_un->un_nrows;
		small_un->c.un_size =
		    get_small_stripe_req_size(big_un, COMPLETE_STRUCTURE);
		small_un->un_ocomp  =
		    get_small_stripe_req_size(big_un, FIRST_COMP_OFFSET);

		/* walk through all rows */
		big_mdr   = &big_un->un_row[0];
		small_mdr = &small_un->un_row[0];

		for (row = 0; (row < big_un->un_nrows); row++) {
			ncomps += big_mdr[row].un_ncomp;
			MSROW_BIG2SMALL((&(big_mdr[row])), (&(small_mdr[row])));
		}

		/* Now copy the components */
		big_mdcomp = (ms_comp_t *)(void *)&((char *)big_un)
		    [big_un->un_ocomp];
		small_mdcomp = (ms_comp32_od_t *)(void *)&((char *)small_un)
		    [small_un->un_ocomp];
		for (comp = 0; (comp < ncomps); ++comp) {
			ms_comp_t	*big_mdcp   = &big_mdcomp[comp];
			ms_comp32_od_t	*small_mdcp = &small_mdcomp[comp];

			MSCOMP_BIG2SMALL(big_mdcp, small_mdcp);

		}
	}

	if (direction == SMALL_2_BIG) {
		MDC_UNIT_SMALL2BIG(small_un, big_un);

		big_un->un_hsp_id = small_un->un_hsp_id;
		big_un->un_nrows  = small_un->un_nrows;
		big_un->c.un_size =
		    get_big_stripe_req_size(small_un, COMPLETE_STRUCTURE);
		big_un->un_ocomp  =
		    get_big_stripe_req_size(small_un, FIRST_COMP_OFFSET);


		/* walk through all rows */
		small_mdr = &small_un->un_row[0];
		big_mdr   = &big_un->un_row[0];

		for (row = 0; (row < small_un->un_nrows); row++) {
			ncomps += small_mdr[row].un_ncomp;
			MSROW_SMALL2BIG((&(small_mdr[row])), (&(big_mdr[row])));
		}
		/* Now copy the components */
		big_mdcomp = (ms_comp_t *)(void *)&((char *)big_un)
		    [big_un->un_ocomp];
		small_mdcomp = (ms_comp32_od_t *)(void *)&((char *)small_un)
		    [small_un->un_ocomp];
		for (comp = 0; (comp < ncomps); ++comp) {
			ms_comp_t *big_mdcp = &big_mdcomp[comp];
			ms_comp32_od_t *small_mdcp = &small_mdcomp[comp];

			MSCOMP_SMALL2BIG(small_mdcp, big_mdcp);

		}
	}
}

/*
 * mirror_convert(small, big, dir)
 *
 * Parameters:
 *	small is the address of a mm_unit32_od_t structure
 *	big   is the address of a mm_unit_t structure
 *	dir   is either BIG2SMALL or SMALL2BIG
 * Return value is void
 *
 * what it does:
 * 	if dir is BIG2SMALL, convert from big to small (updating old records)
 * 	if dir is SMALL2BIG, convert from small to big (snarfing old records)
 *
 * Caveat emptor: big and small must be well allocated memory areas.
 */
void
mirror_convert(caddr_t small, caddr_t big, int direction)
{
	/*LINTED*/
	mm_unit32_od_t *small_un = (mm_unit32_od_t *)small;
	/*LINTED*/
	mm_unit_t *big_un = (mm_unit_t *)big;
	int i;


	if (direction == BIG_2_SMALL) {
		MDC_UNIT_BIG2SMALL(big_un, small_un);

		small_un->c.un_size =
		    roundup(sizeof (mm_unit32_od_t), sizeof (long long));
		small_un->un_last_read = big_un->un_last_read;
		small_un->un_changecnt = big_un->un_changecnt;
		small_un->un_nsm = big_un->un_nsm;
		for (i = 0; i < NMIRROR; i++) {
			MMSM_BIG2SMALL((&(big_un->un_sm[i])),
			    (&(small_un->un_sm[i])));
		}
		small_un->un_overlap_tree_flag = big_un->un_overlap_tree_flag;
		small_un->un_read_option = big_un->un_read_option;
		small_un->un_write_option = big_un->un_write_option;
		small_un->un_pass_num = big_un->un_pass_num;
		small_un->un_rrd_blksize = big_un->un_rrd_blksize;
		small_un->un_rrd_num = big_un->un_rrd_num;
		small_un->un_rr_dirty_recid = big_un->un_rr_dirty_recid;
		small_un->un_rs_copysize = big_un->un_rs_copysize;
		small_un->un_rs_dests = big_un->un_rs_dests;
		small_un->un_rs_resync_done =
		    (daddr32_t)big_un->un_rs_resync_done;
		small_un->un_rs_resync_2_do =
		    (daddr32_t)big_un->un_rs_resync_2_do;
		small_un->un_rs_dropped_lock = big_un->un_rs_dropped_lock;
		small_un->un_rs_type = big_un->un_rs_type;
	}

	if (direction == SMALL_2_BIG) {
		MDC_UNIT_SMALL2BIG(small_un, big_un);
		big_un->c.un_size =
		    roundup(sizeof (mm_unit_t), sizeof (long long));
		big_un->un_last_read = small_un->un_last_read;
		big_un->un_changecnt = small_un->un_changecnt;
		big_un->un_nsm = small_un->un_nsm;


		for (i = 0; i < NMIRROR; i++) {
			MMSM_SMALL2BIG((&(small_un->un_sm[i])),
			    (&(big_un->un_sm[i])));
		}


		/* Now back to the simple things again */
		big_un->un_overlap_tree_flag = small_un->un_overlap_tree_flag;
		big_un->un_read_option = small_un->un_read_option;
		big_un->un_write_option = small_un->un_write_option;
		big_un->un_pass_num = small_un->un_pass_num;
		big_un->un_rrd_blksize = small_un->un_rrd_blksize;
		big_un->un_rrd_num = small_un->un_rrd_num;
		big_un->un_rr_dirty_recid = small_un->un_rr_dirty_recid;
		big_un->un_rs_copysize = small_un->un_rs_copysize;
		big_un->un_rs_dests = small_un->un_rs_dests;
		big_un->un_rs_resync_done =
		    (diskaddr_t)small_un->un_rs_resync_done;
		big_un->un_rs_resync_2_do =
		    (diskaddr_t)small_un->un_rs_resync_2_do;
		big_un->un_rs_dropped_lock = small_un->un_rs_dropped_lock;
		big_un->un_rs_type = small_un->un_rs_type;
	}
}

/*
 * raid_convert(small, big, dir)
 *
 * Parameters:
 *	small is the address of a mr_unit32_od_t structure
 *	big   is the address of a mr_unit_t structure
 *	dir   is either BIG2SMALL or SMALL2BIG
 * Return value is void
 *
 * what it does:
 * 	if dir is BIG2SMALL, convert from big to small (updating old records)
 * 	if dir is SMALL2BIG, convert from small to big (snarfing old records)
 *
 * Caveat emptor: big and small must be well allocated memory areas.
 */
void
raid_convert(caddr_t small, caddr_t big, int direction)

{
	/*LINTED*/
	mr_unit32_od_t *small_un = (mr_unit32_od_t *)small;
	/*LINTED*/
	mr_unit_t *big_un = (mr_unit_t *)big;

	int i;
	uint_t	ncol;

	if (direction == BIG_2_SMALL) {
		MRUNIT_BIG2SMALL(big_un, small_un);

		ncol = small_un->un_totalcolumncnt;
		small_un->c.un_size = sizeof (mr_unit32_od_t);
		small_un->c.un_size += (ncol - 1) * sizeof (mr_column32_od_t);
		for (i = 0; i < ncol; i++) {
			MRCOL_BIG2SMALL((&(big_un->un_column[i])),
			    (&(small_un->un_column[i])));
		}
	}

	if (direction == SMALL_2_BIG) {
		MRUNIT_SMALL2BIG(small_un, big_un);

		ncol = big_un->un_totalcolumncnt;
		big_un->c.un_size = sizeof (mr_unit_t);
		big_un->c.un_size += (ncol - 1) * sizeof (mr_column_t);
		for (i = 0; i < ncol; i++) {
			MRCOL_SMALL2BIG((&(small_un->un_column[i])),
			    (&(big_un->un_column[i])));
		}
	}
}





/*
 * softpart_convert(small, big, dir)
 *
 * Parameters:
 *	small is the address of a mp_unit32_od_t structure
 *	big   is the address of a mp_unit_t structure
 *	dir   is either BIG2SMALL or SMALL2BIG
 * Return value is void
 *
 * what it does:
 * 	if dir is BIG2SMALL, convert from big to small (updating old records)
 * 	if dir is SMALL2BIG, convert from small to big (snarfing old records)
 *
 * Caveat emptor: big and small must be well allocated memory areas.
 */
void
softpart_convert(caddr_t small, caddr_t big, int direction)

{
	/*LINTED*/
	mp_unit32_od_t *small_un = (mp_unit32_od_t *)small;
	/*LINTED*/
	mp_unit_t *big_un = (mp_unit_t *)big;

	if (direction == BIG_2_SMALL) {
		MPUNIT_BIG2SMALL(big_un, small_un);
		/*
		 * Note that there isn't a mp_ext32_od_t, it's right to use
		 * mp_ext_t here, too.
		 */
		small_un->c.un_size = sizeof (mp_unit32_od_t) +
			(small_un->un_numexts - 1) * sizeof (mp_ext_t);
	}

	if (direction == SMALL_2_BIG) {
		MPUNIT_SMALL2BIG(small_un, big_un);
		big_un->c.un_size = sizeof (mp_unit_t) +
			(big_un->un_numexts - 1) * sizeof (mp_ext_t);
	}
}


/*
 * trans_master_convert(smallp, bigp, dir)
 *
 * Parameters:
 *	smallp is the address of a mt_unit32_od_t structure
 *	bigp   is the address of a mt_unit_t structure
 *	dir   is either BIG2SMALL or SMALL2BIG
 * Return value is void
 *
 * what it does:
 * 	if dir is BIG2SMALL, convert from big to small (updating old records)
 * 	if dir is SMALL2BIG, convert from small to big (snarfing old records)
 *
 * Caveat emptor: bigp and smallp must be well allocated memory areas.
 */
void
trans_master_convert(caddr_t smallp, caddr_t bigp, int direction)
{
	/*LINTED*/
	mt_unit32_od_t *small = (mt_unit32_od_t *)smallp;
	/*LINTED*/
	mt_unit_t *big = (mt_unit_t *)bigp;

	if (direction == SMALL_2_BIG) {
		MDC_UNIT_SMALL2BIG(small, big);
		big->c.un_size =
		    roundup(sizeof (mt_unit_t), sizeof (long long));
		big->un_flags		= small->un_flags;
		big->un_m_key		= small->un_m_key;
		big->un_m_dev		= md_expldev(small->un_m_dev);
		big->un_l_key		= small->un_l_key;
		big->un_l_dev		= md_expldev(small->un_l_dev);
		big->un_l_sblk		= small->un_l_sblk;
		big->un_l_pwsblk	= small->un_l_pwsblk;
		big->un_l_nblks		= small->un_l_nblks;
		big->un_l_tblks		= small->un_l_tblks;
		big->un_l_head		= small->un_l_head;
		big->un_l_tail		= small->un_l_tail;
		big->un_l_resv		= small->un_l_resv;
		big->un_l_maxresv	= small->un_l_maxresv;
		big->un_l_recid		= small->un_l_recid;
		big->un_l_error		= small->un_l_error;
		big->un_s_dev		= md_expldev(small->un_s_dev);
		big->un_debug		= small->un_debug;
		big->un_dev		= md_expldev(small->un_dev);
		big->un_logreset	= small->un_logreset;
		big->un_l_maxtransfer	= small->un_l_maxtransfer;
		big->un_timestamp.tv_sec = small->un_timestamp.tv_sec;
		big->un_timestamp.tv_usec = small->un_timestamp.tv_usec;
		big->un_l_timestamp.tv_sec = small->un_l_timestamp.tv_sec;
		big->un_l_timestamp.tv_usec = small->un_l_timestamp.tv_usec;
	}
	if (direction == BIG_2_SMALL) {
		MDC_UNIT_BIG2SMALL(big, small);
		small->c.un_size =
		    roundup(sizeof (mt_unit32_od_t), sizeof (long long));
		small->un_flags		= big->un_flags;
		small->un_m_key		= big->un_m_key;
		small->un_m_dev		= md_cmpldev(big->un_m_dev);
		small->un_l_key		= big->un_l_key;
		small->un_l_dev		= md_cmpldev(big->un_l_dev);
		small->un_l_sblk	= big->un_l_sblk;
		small->un_l_pwsblk	= big->un_l_pwsblk;
		small->un_l_nblks	= big->un_l_nblks;
		small->un_l_tblks	= big->un_l_tblks;
		small->un_l_head	= big->un_l_head;
		small->un_l_tail	= big->un_l_tail;
		small->un_l_resv	= big->un_l_resv;
		small->un_l_maxresv	= big->un_l_maxresv;
		small->un_l_maxtransfer	= big->un_l_maxtransfer;
		small->un_l_recid	= big->un_l_recid;
		small->un_l_error	= big->un_l_error;
		small->un_s_dev		= md_cmpldev(big->un_s_dev);
		small->un_debug		= big->un_debug;
		small->un_dev		= md_cmpldev(big->un_dev);
		small->un_logreset	= big->un_logreset;
		small->un_timestamp.tv_sec = big->un_timestamp.tv_sec;
		small->un_timestamp.tv_usec = big->un_timestamp.tv_usec;
		small->un_l_timestamp.tv_sec = big->un_l_timestamp.tv_sec;
		small->un_l_timestamp.tv_usec = big->un_l_timestamp.tv_usec;
	}

}


/*
 * trans_log_convert(smallp, bigp, dir)
 *
 * Parameters:
 *	smallp is the address of a ml_unit32_od_t structure
 *	bigp   is the address of a ml_unit_t structure
 *	dir   is either BIG2SMALL or SMALL2BIG
 * Return value is void
 *
 * what it does:
 * 	if dir is BIG2SMALL, convert from big to small (updating old records)
 * 	if dir is SMALL2BIG, convert from small to big (snarfing old records)
 *
 * Caveat emptor: bigp and smallp must be well allocated memory areas.
 */
void
trans_log_convert(caddr_t smallp, caddr_t bigp, int direction)
{
	/*LINTED*/
	ml_unit32_od_t *small = (ml_unit32_od_t *)smallp;
	/*LINTED*/
	ml_unit_t *big = (ml_unit_t *)bigp;

	if (direction == SMALL_2_BIG) {
		big->un_revision	= small->un_revision;
		big->un_recid		= small->un_recid;
		big->un_key		= small->un_key;
		big->un_dev		= md_expldev(small->un_dev);
		big->un_opencnt		= small->un_opencnt;
		big->un_transcnt	= small->un_transcnt;
		big->un_head_lof	= small->un_head_lof;
		big->un_head_ident	= small->un_head_ident;
		big->un_tail_lof	= small->un_tail_lof;
		big->un_tail_ident	= small->un_tail_ident;
		big->un_bol_lof		= small->un_bol_lof;
		big->un_eol_lof		= small->un_eol_lof;
		big->un_nblks		= small->un_nblks;
		big->un_tblks		= small->un_tblks;
		big->un_maxtransfer	= small->un_maxtransfer;
		big->un_status		= small->un_status;
		big->un_maxresv		= small->un_maxresv;
		big->un_pwsblk		= small->un_pwsblk;
		big->un_devbsize	= small->un_devbsize;
		big->un_resv		= small->un_resv;
		big->un_resv_wantin	= small->un_resv_wantin;
		big->un_error		= small->un_error;
		big->un_tid		= small->un_tid;
		big->un_head_tid	= small->un_head_tid;
		big->un_timestamp.tv_sec = small->un_timestamp.tv_sec;
		big->un_timestamp.tv_usec = small->un_timestamp.tv_usec;
	}
	if (direction == BIG_2_SMALL) {
		small->un_revision	= big->un_revision;
		small->un_recid		= big->un_recid;
		small->un_key		= big->un_key;
		small->un_dev		= md_cmpldev(big->un_dev);
		small->un_opencnt	= big->un_opencnt;
		small->un_transcnt	= big->un_transcnt;
		small->un_head_lof	= big->un_head_lof;
		small->un_head_ident	= big->un_head_ident;
		small->un_tail_lof	= big->un_tail_lof;
		small->un_tail_ident	= big->un_tail_ident;
		small->un_bol_lof	= big->un_bol_lof;
		small->un_eol_lof	= big->un_eol_lof;
		small->un_nblks		= big->un_nblks;
		small->un_tblks		= big->un_tblks;
		small->un_maxtransfer	= big->un_maxtransfer;
		small->un_status	= big->un_status;
		small->un_maxresv	= big->un_maxresv;
		small->un_pwsblk	= big->un_pwsblk;
		small->un_devbsize	= big->un_devbsize;
		small->un_resv		= big->un_resv;
		small->un_resv_wantin	= big->un_resv_wantin;
		small->un_error		= big->un_error;
		small->un_tid		= big->un_tid;
		small->un_head_tid	= big->un_head_tid;
		small->un_timestamp.tv_sec = big->un_timestamp.tv_sec;
		small->un_timestamp.tv_usec = big->un_timestamp.tv_usec;
	}
}

/*
 * hs_convert(small, big, dir)
 *
 * Parameters:
 *	small is the address of a hot_spare32_od_t structure
 *	big   is the address of a hot_spare_t structure
 *	dir   is either BIG2SMALL or SMALL2BIG
 * Return value is void
 *
 * what it does:
 * 	if dir is BIG2SMALL, convert from big to small (updating old records)
 * 	if dir is SMALL2BIG, convert from small to big (snarfing old records)
 *
 * Caveat emptor: big and small must be well allocated memory areas.
 */
void
hs_convert(caddr_t small, caddr_t big, int direction)

{
	/*LINTED*/
	hot_spare32_od_t *small_un = (hot_spare32_od_t *)small;
	/*LINTED*/
	hot_spare_t *big_un = (hot_spare_t *)big;

	if (direction == BIG_2_SMALL) {
		MHS_BIG2SMALL(big_un, small_un);
	}

	if (direction == SMALL_2_BIG) {
		MHS_SMALL2BIG(small_un, big_un);
	}
}
