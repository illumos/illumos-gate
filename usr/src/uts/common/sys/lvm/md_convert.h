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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS__MD_CONVERT_H
#define	_SYS__MD_CONVERT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/lvm/md_stripe.h>
#include <sys/lvm/md_mirror.h>
#include <sys/lvm/md_raid.h>
#include <sys/lvm/md_hotspares.h>
#include <sys/lvm/md_sp.h>
#include <sys/lvm/md_trans.h>

#ifdef	__cplusplus
extern "C" {
#endif

size_t get_big_stripe_req_size(ms_unit32_od_t *, int);
size_t get_small_stripe_req_size(ms_unit_t *, int);

void stripe_convert(caddr_t, caddr_t, int);
void mirror_convert(caddr_t, caddr_t, int);
void raid_convert(caddr_t, caddr_t, int);
void hs_convert(caddr_t, caddr_t, int);
void hsp_convert(caddr_t, caddr_t, int);
void softpart_convert(caddr_t, caddr_t, int);
void trans_master_convert(caddr_t, caddr_t, int);
void trans_log_convert(caddr_t, caddr_t, int);

extern void dump_mdc_unit(mdc_unit_t *);
extern void dump_mdc_unit32_od(mdc_unit32_od_t *);

extern void dump_mm_unit(mm_unit_t *);
extern void dump_mm_unit32_od(mm_unit32_od_t *);

extern void dump_ms_unit(ms_unit_t *);
extern void dump_ms_unit32_od(ms_unit32_od_t *);

extern void dump_mr_unit(mr_unit_t *);
extern void dump_mr_unit32_od(mr_unit32_od_t *);


/*
 * Nice debug printing macro:
 * eg: HBDBG(stripe_convert, 0x%llx, msp->c.un_revision);
 */
#define	HBDBG(r, f, v) printf(#r "," #v ":[" #f "]\n", v)

/* Compacting a timeval64 to a timeval32 */
#define	CMPLTV(dest, source)				\
	{						\
	(dest).tv_sec  = (int32_t)(source).tv_sec;	\
	(dest).tv_usec = (int32_t)(source).tv_usec;	\
	}

/* Expanding a timeval32 to a timeval64 */
#define	EXPLTV(dest, source)				\
	{						\
	(dest).tv_sec  = (long)(source).tv_sec;	\
	(dest).tv_usec = (long)(source).tv_usec;	\
	}

#define	COMPLETE_STRUCTURE 0
#define	FIRST_COMP_OFFSET 1

#define	SMALL_2_BIG 1
#define	BIG_2_SMALL 2

/* Used by different types */

/* mdc_unit -> mdc_unit32_od */
#define	MDC_UNIT_BIG2SMALL(big_un, small_un) \
	small_un->c.un_revision		= big_un->c.un_revision;\
	small_un->c.un_type		= big_un->c.un_type;\
	small_un->c.un_status		= big_un->c.un_status;\
	small_un->c.un_parent_res 	= big_un->c.un_parent_res;\
	small_un->c.un_child_res	= big_un->c.un_child_res;\
	small_un->c.un_self_id		= big_un->c.un_self_id;\
	small_un->c.un_record_id	= big_un->c.un_record_id;\
	small_un->c.un_flag		= big_un->c.un_flag;\
	small_un->c.un_total_blocks	= (daddr32_t)big_un->c.un_total_blocks;\
	small_un->c.un_actual_tb	= (daddr32_t)big_un->c.un_actual_tb;\
	small_un->c.un_nhead		= (ushort_t)big_un->c.un_nhead;\
	small_un->c.un_nsect		= (ushort_t)big_un->c.un_nsect;\
	small_un->c.un_rpm		= big_un->c.un_rpm;\
	small_un->c.un_wr_reinstruct	= big_un->c.un_wr_reinstruct;\
	small_un->c.un_rd_reinstruct	= big_un->c.un_rd_reinstruct;\
	small_un->c.un_vtoc_id		= big_un->c.un_vtoc_id;\
	small_un->c.un_capabilities	= big_un->c.un_capabilities;\
	small_un->c.un_parent		= big_un->c.un_parent;\
	small_un->c.un_user_flags	= big_un->c.un_user_flags;

#define	MDC_UNIT_SMALL2BIG(small_un, big_un) \
	big_un->c.un_revision	   = small_un->c.un_revision;\
	big_un->c.un_type	   = small_un->c.un_type;\
	big_un->c.un_status	   = small_un->c.un_status;\
	big_un->c.un_parent_res    = small_un->c.un_parent_res;\
	big_un->c.un_child_res	   = small_un->c.un_child_res;\
	big_un->c.un_self_id	   = small_un->c.un_self_id;\
	big_un->c.un_record_id	   = small_un->c.un_record_id;\
	big_un->c.un_flag	   = small_un->c.un_flag;\
	big_un->c.un_total_blocks  = (diskaddr_t)small_un->c.un_total_blocks;\
	big_un->c.un_actual_tb	   = (diskaddr_t)small_un->c.un_actual_tb;\
	big_un->c.un_nhead	   = (uint_t)small_un->c.un_nhead;\
	big_un->c.un_nsect	   = (uint_t)small_un->c.un_nsect;\
	big_un->c.un_rpm	   = small_un->c.un_rpm;\
	big_un->c.un_wr_reinstruct = small_un->c.un_wr_reinstruct;\
	big_un->c.un_rd_reinstruct = small_un->c.un_rd_reinstruct;\
	big_un->c.un_vtoc_id	   = small_un->c.un_vtoc_id;\
	big_un->c.un_capabilities  = small_un->c.un_capabilities;\
	big_un->c.un_parent	   = small_un->c.un_parent;\
	big_un->c.un_user_flags	   = small_un->c.un_user_flags;

/* md_m_shared -> md_m_shared32_od */
#define	MMSH_BIG2SMALL(big_mdms, small_mdms) \
	small_mdms->ms_flags		= big_mdms->ms_flags; \
	small_mdms->xms_mx[0]		= 0; \
	small_mdms->xms_mx[1]		= 0; \
	small_mdms->ms_state		= big_mdms->ms_state; \
	small_mdms->ms_lasterrcnt	= big_mdms->ms_lasterrcnt; \
	small_mdms->ms_orig_dev		= md_cmpldev(big_mdms->ms_orig_dev); \
	small_mdms->ms_orig_blk		= (daddr32_t)big_mdms->ms_orig_blk; \
	small_mdms->ms_hs_key		= big_mdms->ms_hs_key; \
	small_mdms->ms_hs_id		= big_mdms->ms_hs_id; \
	CMPLTV(small_mdms->ms_timestamp, big_mdms->ms_timestamp);

/* mdc_unit32_od -> mdc_unit */
/* md_m_shared32_od -> md_m_shared */
#define	MMSH_SMALL2BIG(small_mdms, big_mdms) \
	big_mdms->ms_flags		= small_mdms->ms_flags; \
	big_mdms->ms_state		= small_mdms->ms_state; \
	big_mdms->ms_lasterrcnt	= small_mdms->ms_lasterrcnt; \
	big_mdms->ms_orig_dev		= md_expldev(small_mdms->ms_orig_dev); \
	big_mdms->ms_orig_blk		= (diskaddr_t)small_mdms->ms_orig_blk; \
	big_mdms->ms_hs_key		= small_mdms->ms_hs_key; \
	big_mdms->ms_hs_id		= small_mdms->ms_hs_id; \
	CMPLTV(big_mdms->ms_timestamp, small_mdms->ms_timestamp);


/* Used by Stripes */

/* ms_comp -> ms_comp32_od */
#define	MSCOMP_BIG2SMALL(big_mdcp, small_mdcp) \
	small_mdcp->un_key		= big_mdcp->un_key; \
	small_mdcp->un_dev		= md_cmpldev(big_mdcp->un_dev); \
	small_mdcp->un_start_block	= (daddr32_t)big_mdcp->un_start_block; \
	MMSH_BIG2SMALL((&(big_mdcp->un_mirror)), (&(small_mdcp->un_mirror)));

/* ms_comp32_od -> ms_comp */
#define	MSCOMP_SMALL2BIG(small_mdcp, big_mdcp)				   \
	big_mdcp->un_key	 = small_mdcp->un_key;			   \
	big_mdcp->un_dev	 = md_expldev(small_mdcp->un_dev);	   \
	big_mdcp->un_start_block = (diskaddr_t)small_mdcp->un_start_block; \
	MMSH_SMALL2BIG((&(small_mdcp->un_mirror)), (&(big_mdcp->un_mirror)));


/* ms_row -> ms_row32_od */
#define	MSROW_BIG2SMALL(big_mdr, small_mdr)				\
	small_mdr->un_icomp	 = big_mdr->un_icomp;			\
	small_mdr->un_ncomp	 = big_mdr->un_ncomp;			\
	small_mdr->un_blocks	 = (daddr32_t)big_mdr->un_blocks;	\
	small_mdr->un_cum_blocks = (daddr32_t)big_mdr->un_cum_blocks;	\
	small_mdr->un_interlace	 = (daddr32_t)big_mdr->un_interlace;

/* ms_row -> ms_row32_od */
#define	MSROW_SMALL2BIG(small_mdr, big_mdr)				\
	big_mdr->un_icomp	= small_mdr->un_icomp;			\
	big_mdr->un_ncomp	= small_mdr->un_ncomp;			\
	big_mdr->un_blocks	= (diskaddr_t)small_mdr->un_blocks;	\
	big_mdr->un_cum_blocks	= (diskaddr_t)small_mdr->un_cum_blocks;	\
	big_mdr->un_interlace	= (diskaddr_t)small_mdr->un_interlace;



/* Used by Mirrors */

/* mm_submirror -> mm_submirror32_od */
#define	MMSM_BIG2SMALL(big_sm, small_sm)				\
	small_sm->sm_key	= big_sm->sm_key; \
	small_sm->sm_dev	= md_cmpldev(big_sm->sm_dev); \
	small_sm->sm_state	= big_sm->sm_state; \
	small_sm->sm_flags	= big_sm->sm_flags; \
	small_sm->sm_hsp_id	= big_sm->sm_hsp_id; \
	CMPLTV(small_sm->sm_timestamp, big_sm->sm_timestamp); \
	MMSH_BIG2SMALL((&(big_sm->sm_shared)), (&(small_sm->sm_shared)));

/* mm_submirror32_od -> mm_submirror */
#define	MMSM_SMALL2BIG(small_sm, big_sm) \
	big_sm->sm_key	  = small_sm->sm_key; \
	big_sm->sm_dev    = md_expldev(small_sm->sm_dev); \
	big_sm->sm_state  = small_sm->sm_state; \
	big_sm->sm_flags  = small_sm->sm_flags; \
	big_sm->sm_hsp_id = small_sm->sm_hsp_id; \
	CMPLTV(big_sm->sm_timestamp, small_sm->sm_timestamp); \
	MMSH_SMALL2BIG((&(small_sm->sm_shared)), (&(big_sm->sm_shared)));


/* Used by Raid */
/* mr_column -> mr_column32_od */
#define	MRCOL_BIG2SMALL(big_rcol, small_rcol)				\
	small_rcol->un_devstate		= big_rcol->un_devstate;	\
	small_rcol->un_devflags		= big_rcol->un_devflags;	\
	CMPLTV(small_rcol->un_devtimestamp, big_rcol->un_devtimestamp); \
	small_rcol->un_hs_id		= big_rcol->un_hs_id; 		\
	small_rcol->un_hs_pwstart	= (daddr32_t)big_rcol->un_hs_pwstart; \
	small_rcol->un_hs_devstart	= (daddr32_t)big_rcol->un_hs_devstart; \
	small_rcol->un_hs_key		= big_rcol->un_hs_key; 		\
	small_rcol->un_orig_dev		= md_cmpldev(big_rcol->un_orig_dev); \
	small_rcol->un_orig_key		= big_rcol->un_orig_key;	\
	small_rcol->un_orig_pwstart	= (daddr32_t)big_rcol->un_orig_pwstart;\
	small_rcol->un_orig_devstart  = (daddr32_t)big_rcol->un_orig_devstart;\
	small_rcol->un_dev		= md_cmpldev(big_rcol->un_dev);	\
	small_rcol->un_pwstart		= (daddr32_t)big_rcol->un_pwstart; \
	small_rcol->un_devstart		= (daddr32_t)big_rcol->un_devstart; \
	small_rcol->un_alt_dev		= md_cmpldev(big_rcol->un_alt_dev); \
	small_rcol->un_alt_pwstart	= (daddr32_t)big_rcol->un_alt_pwstart; \
	small_rcol->un_alt_devstart	= (daddr32_t)big_rcol->un_alt_devstart;

/* mr_column32_od -> mr_column */
#define	MRCOL_SMALL2BIG(small_rcol, big_rcol)				\
	big_rcol->un_devstate	   = small_rcol->un_devstate; 	\
	big_rcol->un_devflags	   = small_rcol->un_devflags; 	\
	CMPLTV(big_rcol->un_devtimestamp, small_rcol->un_devtimestamp); \
	big_rcol->un_hs_id	   = small_rcol->un_hs_id;		\
	big_rcol->un_hs_pwstart	   = (diskaddr_t)small_rcol->un_hs_pwstart; \
	big_rcol->un_hs_devstart   = (diskaddr_t)small_rcol->un_hs_devstart; \
	big_rcol->un_hs_key	   = small_rcol->un_hs_key;	\
	big_rcol->un_orig_dev	   = md_expldev(small_rcol->un_orig_dev); \
	big_rcol->un_orig_key	   = small_rcol->un_orig_key; 	\
	big_rcol->un_orig_pwstart  = (diskaddr_t)small_rcol->un_orig_pwstart; \
	big_rcol->un_orig_devstart = (diskaddr_t)small_rcol->un_orig_devstart;\
	big_rcol->un_dev	   = md_expldev(small_rcol->un_dev);	\
	big_rcol->un_pwstart	   = (diskaddr_t)small_rcol->un_pwstart; \
	big_rcol->un_devstart	   = (diskaddr_t)small_rcol->un_devstart; \
	big_rcol->un_alt_dev	   = md_expldev(small_rcol->un_alt_dev); \
	big_rcol->un_alt_pwstart   = (diskaddr_t)small_rcol->un_alt_pwstart; \
	big_rcol->un_alt_devstart  = (diskaddr_t)small_rcol->un_alt_devstart;

/* mr_unit -> mr_unit32_od */
#define	MRUNIT_BIG2SMALL(big_un, small_un)				\
	MDC_UNIT_BIG2SMALL(big_un, small_un);				\
	CMPLTV(small_un->un_timestamp, big_un->un_timestamp);		\
	small_un->un_magic		= big_un->un_magic;		\
	small_un->un_state		= big_un->un_state;		\
	small_un->un_origcolumncnt	= big_un->un_origcolumncnt;	\
	small_un->un_totalcolumncnt	= big_un->un_totalcolumncnt;	\
	small_un->un_rflags		= big_un->un_rflags;		\
	small_un->un_segsize		= big_un->un_segsize;		\
	small_un->un_segsincolumn	= (uint_t)big_un->un_segsincolumn;\
	small_un->un_maxio		= big_un->un_maxio;		\
	small_un->un_iosize		= big_un->un_iosize;		\
	small_un->un_linlck_flg		= big_un->un_linlck_flg;	\
	small_un->un_pwcnt		= big_un->un_pwcnt;		\
	small_un->un_pwsize		= big_un->un_pwsize;		\
	small_un->un_pwid		= big_un->un_pwid;		\
	small_un->un_percent_done	= big_un->un_percent_done;	\
	small_un->un_resync_copysize	= big_un->un_resync_copysize;	\
	small_un->un_hsp_id		= big_un->un_hsp_id;

/* mr_unit32_od -> mr_unit */
#define	MRUNIT_SMALL2BIG(small_un, big_un)				\
	MDC_UNIT_SMALL2BIG(small_un, big_un);				\
	CMPLTV(big_un->un_timestamp, small_un->un_timestamp);		\
	big_un->un_magic	   = small_un->un_magic;		\
	big_un->un_state	   = small_un->un_state;		\
	big_un->un_origcolumncnt   = small_un->un_origcolumncnt;	\
	big_un->un_totalcolumncnt  = small_un->un_totalcolumncnt;	\
	big_un->un_rflags	   = small_un->un_rflags;		\
	big_un->un_segsize	   = small_un->un_segsize;		\
	big_un->un_segsincolumn	   = (diskaddr_t)small_un->un_segsincolumn;\
	big_un->un_maxio	   = small_un->un_maxio;		\
	big_un->un_iosize	   = small_un->un_iosize;		\
	big_un->un_linlck_flg	   = small_un->un_linlck_flg;		\
	big_un->un_pwcnt	   = small_un->un_pwcnt;		\
	big_un->un_pwsize	   = small_un->un_pwsize;		\
	big_un->un_pwid		   = small_un->un_pwid;			\
	big_un->un_percent_done	   = small_un->un_percent_done;		\
	big_un->un_resync_copysize = small_un->un_resync_copysize;	\
	big_un->un_hsp_id	   = small_un->un_hsp_id;


/* Used by Softpartitions */
/* mp_unit -> mp_unit32_od */
#define	MPUNIT_BIG2SMALL(big_un, small_un) { 				\
	uint_t __i;							\
	MDC_UNIT_BIG2SMALL(big_un, small_un);				\
	small_un->un_key = big_un->un_key;				\
	small_un->un_dev = md_cmpldev(big_un->un_dev);			\
	small_un->un_start_blk = big_un->un_start_blk;			\
	small_un->un_status = big_un->un_status;			\
	small_un->un_numexts = big_un->un_numexts;			\
	small_un->un_length = big_un->un_length;			\
	for (__i = 0; __i < big_un->un_numexts; __i++) {		\
		small_un->un_ext[__i].un_voff = big_un->un_ext[__i].un_voff; \
		small_un->un_ext[__i].un_poff = big_un->un_ext[__i].un_poff; \
		small_un->un_ext[__i].un_len  = big_un->un_ext[__i].un_len; \
	} \
}

/* mp_unit32_od -> mp_unit */
#define	MPUNIT_SMALL2BIG(small_un, big_un) {				\
	uint_t __j;							\
	MDC_UNIT_BIG2SMALL(small_un, big_un);				\
	big_un->un_key = small_un->un_key;				\
	big_un->un_dev = md_expldev(small_un->un_dev);			\
	big_un->un_start_blk = small_un->un_start_blk;			\
	big_un->un_status = small_un->un_status;			\
	big_un->un_numexts = small_un->un_numexts;			\
	big_un->un_length = small_un->un_length;			\
	for (__j = 0; __j < small_un->un_numexts; __j++) {		\
		big_un->un_ext[__j].un_voff = small_un->un_ext[__j].un_voff; \
		big_un->un_ext[__j].un_poff = small_un->un_ext[__j].un_poff; \
		big_un->un_ext[__j].un_len  = small_un->un_ext[__j].un_len; \
	} \
}


/* Used by Hotspares */
/* hot_spare -> hot_spare32_od */
#define	MHS_BIG2SMALL(big, small)					\
	small->hs_revision = big->hs_revision;				\
	small->hs_record_id = big->hs_record_id;			\
	small->xx_hs_next = 0;						\
	small->hs_devnum = md_cmpldev(big->hs_devnum);			\
	small->hs_key = big->hs_key;					\
	small->hs_start_blk = (daddr32_t)big->hs_start_blk;		\
	small->hs_has_label = big->hs_has_label;			\
	small->hs_number_blks = (daddr32_t)big->hs_number_blks;		\
	small->hs_state = big->hs_state;				\
	small->hs_refcount = big->hs_refcount;				\
	small->hs_isopen = big->hs_isopen;				\
	CMPLTV(small->hs_timestamp, big->hs_timestamp);

/* hot_spare -> hot_spare32_od */
#define	MHS_SMALL2BIG(small, big)					\
	big->hs_revision = small->hs_revision;				\
	big->hs_record_id = small->hs_record_id;			\
	big->hs_devnum = md_expldev(small->hs_devnum);			\
	big->hs_key = small->hs_key;					\
	big->hs_start_blk = (diskaddr_t)small->hs_start_blk;		\
	big->hs_has_label = small->hs_has_label;			\
	big->hs_number_blks = (diskaddr_t)small->hs_number_blks;	\
	big->hs_state = small->hs_state;				\
	big->hs_refcount = small->hs_refcount;				\
	big->hs_isopen = small->hs_isopen;				\
	CMPLTV(big->hs_timestamp, small->hs_timestamp);

/* hot_spare_pool_ond -> hot_spare_pool_ond32 */
#define	MHSP_BIG2SMALL(big, small) {					\
	int __i;							\
	small->hsp_revision = big->hsp_revision;			\
	small->hsp_self_id = big->hsp_self_id;				\
	small->hsp_record_id = big->hsp_record_id;			\
	small->hsp_refcount = big->hsp_refcount;			\
	small->hsp_nhotspares = big->hsp_nhotspares;			\
	for (__i = 0; __i < big->hsp_nhotspares; __i++) 		\
		small->hsp_hotspares[__i] = big->hsp_hotspares[__i];	\
}

/* hot_spare_pool_ond32 -> hot_spare_pool_ond */
#define	MHSP_SMALL2BIG(small, big) {					\
	int __i;							\
	big->hsp_revision = small->hsp_revision;			\
	big->hsp_self_id = small->hsp_self_id;				\
	big->hsp_record_id = small->hsp_record_id;			\
	big->hsp_refcount = small->hsp_refcount;			\
	big->hsp_nhotspares = small->hsp_nhotspares;			\
	for (__i = 0; __i < small->hsp_nhotspares; __i++) 		\
		big->hsp_hotspares[__i] = small->hsp_hotspares[__i];	\
}

#ifdef	__cplusplus
}
#endif

#endif /* _SYS__MD_CONVERT_H */
