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

#ifndef _SYS_MULTIDATA_H
#define	_SYS_MULTIDATA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Multidata interface declarations.
 * These interfaces are still evolving; do not use them in unbundled drivers.
 */

/*
 * Multidata packet attribute information.
 */
typedef struct pattrinfo_s {
	uint_t	type;		/* attribute type value */
	uint_t	len;		/* attribute length */
	void	*buf;		/* pointer to user data area */
} pattrinfo_t;

/*
 * Maximum number of payload areas for a single packet descriptor.
 */
#define	MULTIDATA_MAX_PBUFS	16

/*
 * Multidata buffer information.
 */
typedef struct mbufinfo_s {
	uchar_t	*hbuf_rptr;	/* start address of header buffer */
	uchar_t	*hbuf_wptr;	/* end address of header buffer */
	uint_t	pbuf_cnt;	/* number of payload buffer */
	struct pbuf_ary_s {
		uchar_t	*pbuf_rptr;	/* start address of payload buffer */
		uchar_t	*pbuf_wptr;	/* end address of payload buffer */
	} pbuf_ary[MULTIDATA_MAX_PBUFS];
} mbufinfo_t;

/*
 * Multidata packet descriptor information.
 */
struct pld_ary_s {
	int pld_pbuf_idx;	/* payload buffer index */
	uchar_t *pld_rptr;	/* start address of payload data */
	uchar_t *pld_wptr;	/* pointer to end of payload data */
};

#define	PDESCINFO_STRUCT(elems) 					\
{									\
	uint_t	flags;		/* misc. flags */			\
	uchar_t	*hdr_base;	/* start address of header area */	\
	uchar_t *hdr_rptr;	/* start address of header data */	\
	uchar_t *hdr_wptr;	/* end address of header data */	\
	uchar_t	*hdr_lim;	/* end address of header area */	\
	uint_t	pld_cnt;	/* number of payload area */		\
	struct pld_ary_s	pld_ary[(elems)];			\
}

typedef struct pdescinfo_s PDESCINFO_STRUCT(MULTIDATA_MAX_PBUFS) pdescinfo_t;

/*
 * Possible values for flags
 */
#define	PDESC_HBUF_REF	0x1	/* descriptor uses header buffer */
#define	PDESC_PBUF_REF	0x2	/* descriptor uses payload buffer(s) */

#define	PDESC_HDRSIZE(p) ((p)->hdr_lim - (p)->hdr_base)
#define	PDESC_HDRL(p)    ((p)->hdr_wptr - (p)->hdr_rptr)
#define	PDESC_HDRHEAD(p) ((p)->hdr_rptr - (p)->hdr_base)
#define	PDESC_HDRTAIL(p) ((p)->hdr_lim - (p)->hdr_wptr)

#define	PDESC_HDR_ADD(p, base, head, len, tail) {		\
	(p)->hdr_base = (base);					\
	(p)->hdr_rptr = (base) + (head);			\
	(p)->hdr_wptr = (p)->hdr_rptr + (len);			\
	(p)->hdr_lim = (p)->hdr_wptr + (tail);			\
}

#define	PDESC_PLD_INIT(p)  ((p)->pld_cnt = 0)

#define	PDESC_PLD_SPAN_SIZE(p, n)				\
	((p)->pld_ary[(n)].pld_wptr - (p)->pld_ary[(n)].pld_rptr)

#define	PDESC_PLDL(p, n) PDESC_PLD_SPAN_SIZE(p, n)

#define	PDESC_PLD_SPAN_TRIM(p, n, b) {				\
	((p)->pld_ary[(n)].pld_wptr -= (b));			\
	ASSERT((p)->pld_ary[(n)].pld_wptr >= (p)->pld_ary[(n)].pld_rptr); \
}

#define	PDESC_PLD_SPAN_CLEAR(p, n)				\
	PDESC_PLD_SPAN_TRIM(p, n, PDESC_PLD_SPAN_SIZE(p, n))

#define	PDESC_PLD_SPAN_ADD(p, pbuf_idx, rptr, len) {		\
	ASSERT((p)->pld_cnt < MULTIDATA_MAX_PBUFS);		\
	(p)->pld_ary[(p)->pld_cnt].pld_pbuf_idx = (pbuf_idx);	\
	(p)->pld_ary[(p)->pld_cnt].pld_rptr = (rptr);		\
	(p)->pld_ary[(p)->pld_cnt].pld_wptr = (rptr) + (len);	\
	(p)->pld_cnt++;						\
}

/*
 * These structures are opaque to multidata clients.
 */
struct pdesc_s;
typedef struct pdesc_s pdesc_t;

struct pattr_s;
typedef struct pattr_s pattr_t;

struct multidata_s;
typedef struct multidata_s multidata_t;

#ifdef _KERNEL

extern multidata_t *mmd_alloc(mblk_t *, mblk_t **, int);
extern int mmd_addpldbuf(multidata_t *, mblk_t *);
extern multidata_t *mmd_getmultidata(mblk_t *);
extern void mmd_getregions(multidata_t *, mbufinfo_t *);
extern uint_t mmd_getcnt(multidata_t *, uint_t *, uint_t *);
extern pdesc_t *mmd_addpdesc(multidata_t *, pdescinfo_t *, int *, int);
extern void mmd_rempdesc(pdesc_t *);
extern pdesc_t *mmd_getfirstpdesc(multidata_t *, pdescinfo_t *);
extern pdesc_t *mmd_getlastpdesc(multidata_t *, pdescinfo_t *);
extern pdesc_t *mmd_getnextpdesc(pdesc_t *, pdescinfo_t *);
extern pdesc_t *mmd_getprevpdesc(pdesc_t *, pdescinfo_t *);
extern pdesc_t *mmd_adjpdesc(pdesc_t *, pdescinfo_t *);
extern mblk_t *mmd_transform(pdesc_t *);
extern mblk_t *mmd_transform_link(pdesc_t *);
extern int mmd_dupbufs(multidata_t *, mblk_t **, mblk_t **);
extern int mmd_getpdescinfo(pdesc_t *, pdescinfo_t *);
extern pattr_t *mmd_addpattr(multidata_t *, pdesc_t *, pattrinfo_t *,
    boolean_t, int);
extern void mmd_rempattr(pattr_t *);
extern pattr_t *mmd_getpattr(multidata_t *, pdesc_t *, pattrinfo_t *);
extern void mmd_getsize(multidata_t *, uint_t *, uint_t *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MULTIDATA_H */
