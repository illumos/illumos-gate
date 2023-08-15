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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/asm_linkage.h>
#include "assym.h"

#include <sys/sun4asi.h>
#include <sys/machparam.h>
#include <vm/hat_sfmmu.h>

/*
 * This file contains a kmdb-support function which retrieves the TTE for a
 * given VA/context pair, and returns it to the caller if the TTE is valid.
 * The code here is essentially an assembly implementation of the unix-tte
 * word used to allow OBP to do the same thing.
 *
 * Depending on the invocation context, the translator may be invoked either
 * as a normal function (kdi_vatotte) or as a trap handler fragment
 * (kdi_trap_vatotte).
 */

/*
 * uint64_t
 * kdi_hme_hash_function(sfmmu_t *sfmmup, uintptr_t va, uint_t hmeshift)
 * {
 *	uintptr_t hash = (uintptr_t)sfmmup ^ (va >> hmeshift);
 *
 *	if (sfmmup == KHATID) {
 *		return (khme_hash_pa + (hash & KHMEHASH_SZ) *
 *		    sizeof (struct hmehash_bucket));
 *	} else {
 *		return (uhme_hash_pa + (hash & UHMEHASH_SZ) *
 *		    sizeof (struct hmehash_bucket));
 *	}
 * }
 */

/*
 * Parameters:	%g1: VA, %g2: sfmmup, %g4: hmeshift
 * Scratch:	%g4, %g5, %g6 available
 * Return:	Hash value in %g4
 */

#define	KDI_HME_HASH_FUNCTION \
	srlx	%g1, %g4, %g4;		/* va >> hmeshift */		\
	xor	%g4, %g2, %g4;		/* hash in g4 */		\
	set	KHATID, %g5;						\
	ldx	[%g5], %g5;						\
	cmp	%g2, %g5;						\
	be	%xcc, is_khat;						\
	nop;								\
									\
	/* sfmmup != KHATID */						\
	set	UHMEHASH_SZ, %g5;					\
	ld	[%g5], %g5;						\
	and	%g4, %g5, %g4;						\
	mulx	%g4, HMEBUCK_SIZE, %g4; /* g4 = off from hash_pa */	\
	set	uhme_hash_pa, %g5;					\
	ldx	[%g5], %g5;						\
	ba	hash_done;						\
	add	%g4, %g5, %g4;						\
									\
is_khat: /* sfmmup == KHATID */						\
	set	KHMEHASH_SZ, %g5;					\
	ld	[%g5], %g5;						\
	and	%g4, %g5, %g4;						\
	mulx	%g4, HMEBUCK_SIZE, %g4;	/* g4 = off from hash_pa */	\
	set	khme_hash_pa, %g5;					\
	ldx	[%g5], %g5;						\
	add	%g4, %g5, %g4;						\
									\
hash_done:

/*
 * uint64_t
 * kdi_hme_hash_tag(uint64_t rehash, uintptr_t va)
 * {
 *	uint_t hmeshift = HME_HASH_SHIFT(rehash);
 *	uint64_t bspage = HME_HASH_BSPAGE(va, hmeshift);
 *	return (rehash | (bspage << HTAG_BSPAGE_SHIFT));
 * }
 */

/*
 * Parameters:	%g1: VA, %g3: rehash
 * Scratch:	%g5, %g6 available
 * Return:	hmeblk tag in %g5
 */

#define	KDI_HME_HASH_TAG \
	cmp	%g3, TTE8K;					\
	be,a	%xcc, bspage;					\
	mov	HBLK_RANGE_SHIFT, %g5;				\
	mulx	%g3, 3, %g5;					\
	add	%g5, MMU_PAGESHIFT, %g5;			\
								\
bspage:	/* TTE_PAGE_SHIFT in %g5 */				\
	srlx	%g1, %g5, %g6;					\
	sub	%g5, MMU_PAGESHIFT, %g5;			\
	sllx	%g6, %g5, %g5;					\
								\
	/* BSPAGE in %g5 */					\
	sllx	%g5, HTAG_BSPAGE_SHIFT, %g5;			\
	sllx	%g3, HTAG_REHASH_SHIFT, %g6;			\
	or	%g6, SFMMU_INVALID_SHMERID, %g6;		\
	or	%g5, %g6, %g5

/*
 * uint64_t
 * kdi_hme_hash_table_search(sfmmu_t *sfmmup, uint64_t hmebpa, uint64_t hblktag)
 * {
 *	struct hme_blk *hblkp;
 *	uint64_t blkpap = hmebpa + HMEBP_HBLK;
 *	uint64_t blkpa;
 *
 *	while ((blkpa = lddphys(blkpap)) != HMEBLK_ENDPA) {
 *		if (lddphys(blkpa + HMEBLK_TAG) == hblktag) {
 *			if ((sfmmu_t *)lddphys(blkpa + HMEBLK_TAG + 8) ==
 *			    sfmmup)
 *				return (blkpa);
 *		}
 *
 *		blkpap = blkpa + HMEBLK_NEXTPA;
 *	}
 *
 *	return (NULL);
 * }
 */

/*
 * Parameters:	%g2: sfmmup, %g4: hmebp PA, %g5: hmeblk tag
 * Scratch:	%g4, %g5, %g6 available
 * Return:	hmeblk PA in %g4
 */

#define	KDI_HME_HASH_TABLE_SEARCH \
	add	%g4, HMEBUCK_NEXTPA, %g4; /* %g4 is hmebucket PA */	\
search_loop:								\
	ldxa	[%g4]ASI_MEM, %g4;					\
	cmp	%g4, HMEBLK_ENDPA;					\
	be,a,pn	%xcc, search_done;					\
	clr 	%g4;							\
									\
	add	%g4, HMEBLK_TAG, %g4;	/* %g4 is now hmeblk PA */	\
	ldxa	[%g4]ASI_MEM, %g6;					\
	sub	%g4, HMEBLK_TAG, %g4;					\
	cmp	%g5, %g6;						\
	bne,a	%xcc, search_loop;					\
	add	%g4, HMEBLK_NEXTPA, %g4;				\
									\
	/* Found a match.  Is it in the right address space? */		\
	add	%g4, (HMEBLK_TAG + 8), %g4;				\
	ldxa	[%g4]ASI_MEM, %g6;					\
	sub	%g4, (HMEBLK_TAG + 8), %g4;				\
	cmp	%g6, %g2;						\
	bne,a	%xcc, search_loop;					\
	add	%g4, HMEBLK_NEXTPA, %g4;				\
									\
search_done:

/*
 * uint64_t
 * kdi_hblk_to_ttep(uint64_t hmeblkpa, uintptr_t va)
 * {
 *	size_t ttesz = ldphys(hmeblkpa + HMEBLK_MISC) & HBLK_SZMASK;
 *	uint_t idx;
 *
 *	if (ttesz == TTE8K)
 *		idx = (va >> MMU_PAGESHIFT) & (NHMENTS - 1);
 *	else
 *		idx = 0;
 *
 *	return (hmeblkpa + (idx * sizeof (struct sf_hment)) +
 *	    HMEBLK_HME + SFHME_TTE);
 * }
 */

/*
 * Parameters:	%g1: VA, %g4: hmeblk PA
 * Scratch:	%g1, %g2, %g3, %g4, %g5, %g6 available
 * Return:	TTE PA in %g2
 */

#define	KDI_HBLK_TO_TTEP \
	add	%g4, HMEBLK_MISC, %g3;				\
	lda	[%g3]ASI_MEM, %g3;				\
	and	%g3, HBLK_SZMASK, %g3;	/* ttesz in %g3 */	\
								\
	cmp	%g3, TTE8K;					\
	bne,a	ttep_calc;					\
	clr	%g1;						\
	srlx	%g1, MMU_PAGESHIFT, %g1;			\
	and	%g1, NHMENTS - 1, %g1;				\
								\
ttep_calc:	/* idx in %g1 */				\
	mulx	%g1, SFHME_SIZE, %g2;				\
	add	%g2, %g4, %g2;					\
	add	%g2, (HMEBLK_HME1 + SFHME_TTE), %g2;

/*
 * uint64_t
 * kdi_vatotte(uintptr_t va, int cnum)
 * {
 *	sfmmu_t *sfmmup = ksfmmup;
 *	uint64_t hmebpa, hmetag, hmeblkpa;
 *	int i;
 *
 *	for (i = 1; i < DEFAULT_MAX_HASHCNT + 1; i++) {
 *		hmebpa = kdi_c_hme_hash_function(sfmmup, va, HME_HASH_SHIFT(i));
 *		hmetag = kdi_c_hme_hash_tag(i, va);
 *		hmeblkpa = kdi_c_hme_hash_table_search(sfmmup, hmebpa, hmetag);
 *
 *		if (hmeblkpa != NULL) {
 *			uint64_t tte = lddphys(kdi_c_hblk_to_ttep(hmeblkpa,
 *			    va));
 *
 *			if ((int64_t)tte < 0)
 *				return (tte);
 *			else
 *				return (0);
 *		}
 *	}
 *
 *	return (0);
 * }
 */

	/*
	 * Invocation in normal context as a VA-to-TTE translator
	 * for kernel context only. This routine returns 0 on
	 * success and -1 on error.
	 *
	 * %o0 = VA, input register
	 * %o1 = KCONTEXT
	 * %o2 = ttep, output register
	 */
	ENTRY_NP(kdi_vatotte)
	mov	%o0, %g1		/* VA in %g1 */
	mov	%o1, %g2		/* cnum in %g2 */

	set	kdi_trap_vatotte, %g3
	jmpl	%g3, %g7		/* => %g1: TTE or 0 */
	add	%g7, 8, %g7

	brz	%g1, 1f
	nop

	/* Got a valid TTE */
	stx	%g1, [%o2]
	retl
	clr	%o0

	/* Failed translation */
1:	retl
	mov	-1, %o0
	SET_SIZE(kdi_vatotte)

	/*
	 * %g1 = vaddr passed in, tte or 0 (error) when return
	 * %g2 = KCONTEXT
	 * %g7 = return address
	 */
	ENTRY_NP(kdi_trap_vatotte)

	cmp	%g2, KCONTEXT		/* make sure called in kernel ctx */
	bne,a,pn %icc, 6f
	  clr	%g1

	sethi   %hi(ksfmmup), %g2
        ldx     [%g2 + %lo(ksfmmup)], %g2

	mov	1, %g3			/* VA %g1, ksfmmup %g2, idx %g3 */
	mov	HBLK_RANGE_SHIFT, %g4
	ba	3f
	nop

1:	mulx	%g3, 3, %g4		/* 3: see TTE_BSZS_SHIFT */
	add	%g4, MMU_PAGESHIFT, %g4

3:	KDI_HME_HASH_FUNCTION		/* %g1, %g2, %g4 => hash in %g4 */
	KDI_HME_HASH_TAG		/* %g1, %g3 => tag in %g5 */
	KDI_HME_HASH_TABLE_SEARCH	/* %g2, %g4, %g5 => hmeblk PA in %g4 */

	brz	%g4, 5f
	nop

	KDI_HBLK_TO_TTEP		/* %g1, %g4 => TTE PA in %g2 */
	ldxa	[%g2]ASI_MEM, %g1
	brgez,a	%g1, 4f
	clr	%g1
4:	ba,a	6f

5:	add	%g3, 1, %g3
	set	mmu_hashcnt, %g4
	lduw	[%g4], %g4
	cmp	%g3, %g4
	ble	1b
	nop

	clr	%g1

6:	jmp	%g7
	nop
	SET_SIZE(kdi_trap_vatotte)

