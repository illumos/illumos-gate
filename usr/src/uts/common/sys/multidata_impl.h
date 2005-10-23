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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MULTIDATA_IMPL_H
#define	_SYS_MULTIDATA_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Multidata: implementation-private data structure and declarations.
 */

/*
 * Structure used for insque/remque circular list operations.
 */
typedef struct ql_s {
	struct ql_s *ql_next;	/* pointer to next list element */
	struct ql_s *ql_prev;	/* pointer to previous list element */
} ql_t;

#define	QL_INIT(q) {				\
	((ql_t *)(q))->ql_next = (ql_t *)(q);	\
	((ql_t *)(q))->ql_prev = (ql_t *)(q);	\
}

typedef struct pdesc_slab_s pdesc_slab_t;

/*
 * Attribute hash bucket structure.
 */
typedef struct patbkt_s {
	kmutex_t pbkt_lock;	/* per-bucket lock */
	ql_t	pbkt_pattr_q;	/* list of attributes */
	uint_t	pbkt_tbl_sz;	/* table size (if this is first bucket) */
} patbkt_t;

/*
 * Attribute structure.
 */
#define	PATTR_MAGIC	0x50615472	/* "PaTr" */

struct pattr_s {
	pattr_t *pat_next;	/* pointer to next attribute in bucket */
	pattr_t *pat_prev;	/* pointer to previous attribute in bucket */

	uint_t pat_magic;	/* set to PATTR_MAGIC */

	kmutex_t *pat_lock;	/* pointer to per-bucket lock */
	multidata_t *pat_mmd;	/* back pointer to Multidata */
	uint_t	pat_buflen;	/* length of this structure + attribute */
	uint_t	pat_type;	/* type of encapsulated attribute */
	uint_t	pat_flags;	/* misc. flags */
};

/*
 * Values for pat_flags.
 */
#define	PATTR_REM_DEFER	0x1	/* entry is marked unusable but still exists */
#define	PATTR_PERSIST	0x2	/* entry can't be removed */

#define	Q2PATTR(p)	\
	((pattr_t *)((caddr_t)(p) - offsetof(pattr_t, pat_next)))

/*
 * Packet descriptor structure.
 */
#define	PDESC_MAGIC	0x506b5464	/* "PkTd" */

struct pdesc_s {
	pdesc_t	*pd_next;	/* pointer to next descriptor */
	pdesc_t	*pd_prev;	/* pointer to previous descriptor */

	uint_t pd_magic;	/* set to PDESC_MAGIC */

	pdesc_slab_t *pd_slab;	/* back pointer to descriptor slab */
	patbkt_t *pd_pattbl;	/* hash table of local attributes */

	pdescinfo_t pd_pdi;	/* embedded descriptor info structure */

#define	pd_flags	pd_pdi.flags
};

/*
 * Additional internal flags for pd_flags (see multidata.h for the rest).
 */
#define	PDESC_REM_DEFER	0x1000	/* entry is marked unusable but still exists */
#define	PDESC_HAS_REF	(PDESC_HBUF_REF | PDESC_PBUF_REF)

#define	Q2PD(p)		\
	((pdesc_t *)((caddr_t)(p) - offsetof(pdesc_t, pd_next)))

#define	PDI_COPY(pd_src, pd_dst) {				\
	(pd_dst)->flags = (pd_src)->flags & PDESC_HAS_REF;	\
	if ((pd_dst)->flags & PDESC_HBUF_REF) {			\
		(pd_dst)->hdr_base = (pd_src)->hdr_base;	\
		(pd_dst)->hdr_rptr = (pd_src)->hdr_rptr;	\
		(pd_dst)->hdr_wptr = (pd_src)->hdr_wptr;	\
		(pd_dst)->hdr_lim = (pd_src)->hdr_lim;		\
	} else {						\
		(pd_dst)->hdr_base = NULL;			\
		(pd_dst)->hdr_rptr = NULL;			\
		(pd_dst)->hdr_wptr = NULL;			\
		(pd_dst)->hdr_lim = NULL;			\
	}							\
								\
	if ((pd_dst)->flags & PDESC_PBUF_REF) {			\
		int i;						\
								\
		(pd_dst)->pld_cnt = (pd_src)->pld_cnt;		\
		for (i = 0; i < (pd_dst)->pld_cnt; i++) {	\
			(pd_dst)->pld_ary[i].pld_pbuf_idx =	\
			    (pd_src)->pld_ary[i].pld_pbuf_idx;	\
			(pd_dst)->pld_ary[i].pld_rptr =		\
			    (pd_src)->pld_ary[i].pld_rptr;	\
			(pd_dst)->pld_ary[i].pld_wptr =		\
			    (pd_src)->pld_ary[i].pld_wptr;	\
		}						\
	} else {						\
		(pd_dst)->pld_cnt = 0;				\
	}							\
}

/*
 * Packet descriptor slab structure.
 */
struct pdesc_slab_s {
	pdesc_slab_t *pds_next;	/* pointer to next descriptor slab */
	pdesc_slab_t *pds_prev;	/* pointer to previous descriptor slab */

	multidata_t *pds_mmd;	/* back pointer to Multidata */
	uint_t	pds_used;	/* always-increasing index to array */
	uint_t	pds_sz;		/* size of descriptor array */

	pdesc_t	pds_free_desc[1]; /* array of available descriptors */
};

#define	Q2PDSLAB(p)	\
	((pdesc_slab_t *)((caddr_t)(p) - offsetof(pdesc_slab_t, pds_next)))

#define	PDESC_SLAB_SIZE(npd)  \
	((size_t)(&((pdesc_slab_t *)0)->pds_free_desc[npd]))

/*
 * Multidata metadata structure.
 */
#define	MULTIDATA_MAGIC	0x4d645461	/* "MdTa" */

struct multidata_s {
	uint_t	mmd_magic;	/* set to MULTIDATA_MAGIC */

	dblk_t	*mmd_dp;	/* back pointer to wrapper dblk structure */
	mblk_t	*mmd_hbuf;	/* pointer to header buffer mblk */

	patbkt_t *mmd_pattbl;	/* hash table of global attributes */

	kmutex_t mmd_pd_slab_lock; /* lock to protect the following items */
	uint_t	mmd_pbuf_cnt;	/* number of data buffer */
	mblk_t	*mmd_pbuf[MULTIDATA_MAX_PBUFS];	/* data buffer mblk(s) */
	ql_t	mmd_pd_slab_q;	/* list of packet descriptor slabs */
	ql_t	mmd_pd_q;	/* list of packet descriptors */
	uint_t	mmd_slab_cnt;	/* number of packet descriptor slabs */
	uint_t	mmd_pd_cnt;	/* number of in-use packet desciptors */
	uint_t	mmd_hbuf_ref;	/* descriptors referring to header buffer */
	uint_t	mmd_pbuf_ref;	/* descriptors referring to payload buffer(s) */
};

#ifdef _KERNEL

extern void mmd_init(void);
extern mblk_t *mmd_copy(mblk_t *, int);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MULTIDATA_IMPL_H */
