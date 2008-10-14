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

#ifndef _RDC_BITMAP_H
#define	_RDC_BITMAP_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

extern int rdc_bitmap_mode;	/* property from rdc.conf */

/*
 * Possible values of rdc_bitmap_mode - integer flag.
 */
#define	RDC_BMP_AUTO	0x0	/* auto detect bitmap mode */
#define	RDC_BMP_ALWAYS	0x1	/* always write the bitmap */
#define	RDC_BMP_NEVER	0x2	/* never write the bitmap */

#endif	/* _KERNEL */

/*
 * Public bitmap interface
 * The bitmaps are maintained on 32 Kbyte segments
 */

#define	LOG_SHFT		15
#define	IND_BYTE(ind)		((ind) >> 3)
#define	IND_BIT(ind)		(1 << ((ind) & 0x7))

#define	FBA_LOG_SHFT		(LOG_SHFT - FBA_SHFT)
#define	FBA_TO_LOG_NUM(x)	((x) >> FBA_LOG_SHFT)
#define	LOG_TO_FBA_NUM(x)	((x) << FBA_LOG_SHFT)
#define	FBA_TO_LOG_LEN(x)	(FBA_TO_LOG_NUM((x)-1) + 1)

#define	BMAP_LOG_BYTES(fbas)	(IND_BYTE(FBA_TO_LOG_NUM((fbas)-1))+1)

#define	BITS_IN_BYTE		8

/*
 * Private macros for bitmap manipulation
 */

#define	BMAP_BIT_SET(bmap, ind) ((bmap)[IND_BYTE(ind)] |= IND_BIT(ind))
#define	BMAP_BIT_CLR(bmap, ind) ((bmap)[IND_BYTE(ind)] &= ~IND_BIT(ind))
#define	BMAP_BIT_ISSET(bmap, ind) \
				((bmap)[IND_BYTE(ind)] & IND_BIT(ind))

#define	BIT_TO_FBA(b)		(FBA_NUM(b) >> 3)

#define	BMAP_REF_SET(krdc, ind) (((krdc)->bm_refs->bmap_ref_set)(krdc, ind))
#define	BMAP_REF_CLR(krdc, ind) (((krdc)->bm_refs->bmap_ref_clr)(krdc, ind))
#define	BMAP_REF_ISSET(krdc, ind) (((krdc)->bm_refs->bmap_ref_isset)(krdc, ind))
#define	BMAP_REF_FORCE(krdc, ind, val) \
			(((krdc)->bm_refs->bmap_ref_force)(krdc, ind, val))
#define	BMAP_REF_MAXVAL(krdc) (((krdc)->bm_refs->bmap_ref_maxval)(krdc))
#define	BMAP_REF_SIZE(krdc)	((krdc)->bm_refs->bmap_ref_size)
#define	BMAP_REF_PREF_SIZE	(sizeof (unsigned int))

#ifndef _KERNEL

struct bm_ref_ops {
	void		(*bmap_ref_set)(void *, int);
	void		(*bmap_ref_clr)(void *, int);
	unsigned int	(*bmap_ref_isset)(void *, int);
	void		(*bmap_ref_force)(void *, int, unsigned int);
	unsigned int	(*bmap_ref_maxval)(void *);
	size_t		bmap_ref_size;
};

#else

struct bm_ref_ops {
	void		(*bmap_ref_set)(rdc_k_info_t *, int);
	void		(*bmap_ref_clr)(rdc_k_info_t *, int);
	unsigned int	(*bmap_ref_isset)(rdc_k_info_t *, int);
	void		(*bmap_ref_force)(rdc_k_info_t *, int, unsigned int);
	unsigned int	(*bmap_ref_maxval)(rdc_k_info_t *);
	size_t		bmap_ref_size;
};


/* convert fba to block number */
#define	_BNUM(x)		(FBA_TO_LOG_NUM(x))

/* force reference clear during sync */
#define	RDC_BIT_BUMP	0x0
#define	RDC_BIT_FORCE	0x1
#define	RDC_BIT_FLUSHER	0x2

/* check for overlap, taking account of blocking factor */
#define	RDC_OVERLAP(p1, l1, p2, l2)	\
		    ((_BNUM(((p1) + (l1) - 1)) >= _BNUM((p2))) && \
		    (_BNUM((p1)) <= _BNUM(((p2) + (l2) - 1))))

struct rdc_bitmap_ops {
	int	(*set_bitmap)(rdc_k_info_t *, const nsc_off_t, const nsc_size_t,
	    uint_t *);
	void	(*clr_bitmap)(rdc_k_info_t *, const nsc_off_t, const nsc_size_t,
	    const uint_t, const int);
	int	(*count_dirty)(rdc_k_info_t *);
	int	(*bit_isset)(rdc_k_info_t *, const int);
	int	(*fill_bitmap)(rdc_k_info_t *, const int);
	void	(*zero_bitmap)(rdc_k_info_t *);
	int	(*net_bmap)(const struct bmap6 *);
	int	(*net_b_data)(const struct net_bdata6 *);
	void	(*zero_bitref)(rdc_k_info_t *);
	void	(*set_bitmask)(const nsc_off_t, const nsc_size_t, uint_t *);
	void	(*check_bit)(rdc_k_info_t *, nsc_off_t, nsc_size_t);
};

extern struct rdc_bitmap_ops *rdc_bitmap_ops;

#define	RDC_SET_BITMAP(krdc, pos, len, bitmaskp) \
		(*rdc_bitmap_ops->set_bitmap)(krdc, pos, len, bitmaskp)
#define	RDC_CLR_BITMAP(krdc, pos, len, bitmask, flag) \
		(*rdc_bitmap_ops->clr_bitmap)(krdc, pos, len, bitmask, flag)
#define	RDC_COUNT_BITMAP(krdc) \
		(*rdc_bitmap_ops->count_dirty)(krdc)
#define	RDC_BIT_ISSET(krdc, bit) \
		(*rdc_bitmap_ops->bit_isset)(krdc, bit)
#define	RDC_FILL_BITMAP(krdc, write) \
		(*rdc_bitmap_ops->fill_bitmap)(krdc, write)
#define	RDC_ZERO_BITMAP(krdc) \
		(*rdc_bitmap_ops->zero_bitmap)(krdc)
#define	RDC_SEND_BITMAP(argp) \
		(*rdc_bitmap_ops->net_bmap)(argp)
#define	RDC_OR_BITMAP(argp) \
		(*rdc_bitmap_ops->net_b_data)(argp)
#define	RDC_ZERO_BITREF(krdc) \
		(*rdc_bitmap_ops->zero_bitref)(krdc)
#define	RDC_SET_BITMASK(off, len, maskp) \
		(*rdc_bitmap_ops->set_bitmask)(off, len, maskp)
#define	RDC_CHECK_BIT(krdc, pos, len) \
		(*rdc_bitmap_ops->check_bit)(krdc, pos, len)

/*
 * Functions
 */

extern void rdc_bitmap_init(void);
extern int rdc_move_bitmap(rdc_k_info_t *, char *);
extern int rdc_enable_bitmap(rdc_k_info_t *, int);
extern int rdc_resume_bitmap(rdc_k_info_t *);
extern int rdc_reset_bitmap(rdc_k_info_t *);
extern void rdc_free_bitmap(rdc_k_info_t *, int);
extern void rdc_close_bitmap(rdc_k_info_t *);
extern int rdc_write_bitmap(rdc_k_info_t *);
extern int rdc_write_bitmap_fill(rdc_k_info_t *);
extern void rdc_set_bitmap_many(rdc_k_info_t *, nsc_off_t, nsc_size_t);
extern void rdc_merge_bitmaps(rdc_k_info_t *, rdc_k_info_t *);

extern int rdc_read_state(rdc_k_info_t *, int *, int *);
extern int rdc_clear_state(rdc_k_info_t *);
extern void rdc_write_state(rdc_u_info_t *);
extern int rdc_ns_io(nsc_fd_t *, int, nsc_off_t, uchar_t *, nsc_size_t);
extern int rdc_read_refcount(rdc_k_info_t *);
extern int rdc_write_refcount(rdc_k_info_t *);
extern size_t rdc_refcntsize(rdc_k_info_t *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _RDC_BITMAP_H */
