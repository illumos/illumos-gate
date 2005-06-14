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

#ifndef	_SYS_IVINTR_H
#define	_SYS_IVINTR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef uint_t (*intrfunc)(caddr_t);
typedef uint_t (*softintrfunc)(caddr_t, caddr_t);

/*
 * Interrupt Vector Table Entry
 *
 *	The interrupt vector table is dynamically allocated during
 *	startup. An interrupt number is an index to the interrupt
 *	vector table representing unique interrupt source to the system.
 */
struct intr_vector {
	intrfunc	iv_handler;	/* interrupt handler */
	caddr_t		iv_arg;		/* interrupt argument */
	ushort_t	iv_pil;		/* interrupt request level */
	ushort_t	iv_pending;	/* pending softint flag */
	caddr_t		iv_payload_buf;	/* pointer to 64-byte mondo payload */
	caddr_t		iv_softint_arg2; /* softint argument #2 */
	void		*iv_pad[3];	/* makes structure power-of-2 size */
};

extern struct intr_vector intr_vector[];

extern uint_t nohandler(caddr_t);
extern void init_ivintr(void);
extern int add_ivintr(uint_t, uint_t, intrfunc, caddr_t, caddr_t);
extern void rem_ivintr(uint_t, struct intr_vector *);
#define	GET_IVINTR(inum)  (intr_vector[inum].iv_handler != nohandler)

extern uint_t add_softintr(uint_t, softintrfunc, caddr_t);
extern void rem_softintr(uint_t);
extern int update_softint_arg2(uint_t, caddr_t);
extern int update_softint_pri(uint_t, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IVINTR_H */
