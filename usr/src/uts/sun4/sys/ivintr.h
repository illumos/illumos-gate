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

#ifndef	_SYS_IVINTR_H
#define	_SYS_IVINTR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Software interrupt and other bit flags */
#define	IV_SOFTINT_PEND	0x1	/* Software interrupt is pending */
#define	IV_SOFTINT_MT	0x2	/* Multi target software interrupt */
#define	IV_CACHE_ALLOC	0x4	/* Allocated using kmem_cache_alloc() */

/*
 * Reserve some interrupt vector data structures for the hardware and software
 * interrupts.
 *
 * NOTE: Need two single target software interrupts per cpu for cyclics.
 *       Need one single target software interrupt per cpu for tick accounting.
 */
#define	MAX_RSVD_IV	((NCPU * 3) + 256) /* HW and Single target SW intrs */
#define	MAX_RSVD_IVX	32		/* Multi target software intrs */

#ifndef _ASM

typedef	uint_t (*intrfunc)(caddr_t, caddr_t);
typedef	uint_t (*softintrfunc)(caddr_t, caddr_t);
typedef	struct intr_vec intr_vec_t;
typedef	struct intr_vecx intr_vecx_t;

/* Software interrupt type */
typedef enum softint_type {
	SOFTINT_ST 	= (ushort_t)0,	/* Single target */
	SOFTINT_MT	= (ushort_t)1	/* Multi target */
} softint_type_t;

/*
 * Interrupt Vector Structure.
 *
 * Interrupt vector structure is allocated either from the reserved pool or
 * dynamically using kmem cache method. For the hardware interrupts, one per
 * vector with unique pil basis, i.e, interrupts sharing the same ino and the
 * same pil do share the same structure.
 *
 * Used by Hardware and Single target Software interrupts.
 */
struct intr_vec {
	ushort_t	iv_inum;	/* MDB: interrupt mondo number */
	ushort_t	iv_pil;		/* Interrupt priority level */
	ushort_t	iv_flags;	/* SW interrupt and other bit flags */
	uint8_t		iv_pad[10];	/* Align on cache line boundary */

	intrfunc	iv_handler;	/* ISR */
	caddr_t		iv_arg1;	/* ISR arg1 */
	caddr_t		iv_arg2;	/* ISR arg2 */
	caddr_t		iv_payload_buf;	/* Sun4v: mondo payload, epkt */

	intr_vec_t	*iv_vec_next;	/* Per vector list */
	intr_vec_t	*iv_pil_next;	/* Per PIL list */
};

/*
 * Extended version of Interrupt Vector Structure.
 *
 * Used by Multi target Software interrupts.
 */
struct intr_vecx {
	intr_vec_t	iv_vec;		/* CPU0 uses iv_pil_next */
	intr_vec_t	*iv_pil_xnext[NCPU -1]; /* For CPU1 through N-1 */
};

#define	IV_GET_PIL_NEXT(iv_p, cpu_id) \
	(((iv_p->iv_flags & IV_SOFTINT_MT) && (cpu_id != 0)) ? \
	((intr_vecx_t *)iv_p)->iv_pil_xnext[cpu_id - 1] : iv_p->iv_pil_next)
#define	IV_SET_PIL_NEXT(iv_p, cpu_id, next) \
	(((iv_p->iv_flags & IV_SOFTINT_MT) && (cpu_id != 0)) ? \
	(((intr_vecx_t *)iv_p)->iv_pil_xnext[cpu_id - 1] = next) : \
	(iv_p->iv_pil_next = next))

extern  uint64_t intr_vec_table[];

extern	void init_ivintr(void);
extern	void fini_ivintr(void);

extern	int add_ivintr(uint_t inum, uint_t pil, intrfunc intr_handler,
	caddr_t intr_arg1, caddr_t intr_arg2, caddr_t intr_payload);
extern	int rem_ivintr(uint_t inum, uint_t pil);

extern	uint64_t add_softintr(uint_t pil, softintrfunc intr_handler,
	caddr_t intr_arg1, softint_type_t type);
extern	int rem_softintr(uint64_t softint_id);
extern	int update_softint_arg2(uint64_t softint_id, caddr_t intr_arg2);
extern	int update_softint_pri(uint64_t softint_id, uint_t pil);

#endif	/* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IVINTR_H */
