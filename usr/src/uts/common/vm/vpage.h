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
 * Copyright (c) 2015, Joyent, Inc.  All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef	_VM_VPAGE_H
#define	_VM_VPAGE_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * VM - Information per virtual page.
 */
struct vpage {
	uchar_t nvp_prot;	/* see <sys/mman.h> prot flags */
	uchar_t nvp_advice;	/* pplock & <sys/mman.h> madvise flags */
};

/*
 * This was changed from a bitfield to flags/macros in order
 * to conserve space (uchar_t bitfields are not ANSI).  This could
 * have been condensed to a uchar_t, but at the expense of complexity.
 * We've stolen three bits from the top of nvp_advice: the first to store
 * pplock, the second to identify pages for which we have reserved
 * swap space, but have not necessarily allocated anon slots, and the third to
 * indicate that the page should be zeroed on fork.
 *
 * WARNING: VPP_SETADVICE(vpp, x) evaluates vpp twice, and VPP_PLOCK(vpp)
 * returns a positive integer when the lock is held, not necessarily (1).
 */
#define	VP_ADVICE_MASK	(0x07)
#define	VP_PPLOCK_MASK	(0x80)	/* physical page locked by me */
#define	VP_PPLOCK_SHIFT	(0x07)	/* offset of lock hiding inside nvp_advice */
#define	VP_SWAPRES_MASK	(0x40)	/* Swap space has been reserved, but we */
				/* might not have allocated an anon slot */
#define	VP_INHZERO_MASK	(0x20)	/* zero page on fork() */

#define	VPP_PROT(vpp)	((vpp)->nvp_prot)
#define	VPP_ADVICE(vpp)	((vpp)->nvp_advice & VP_ADVICE_MASK)
#define	VPP_ISPPLOCK(vpp) \
	((uchar_t)((vpp)->nvp_advice & VP_PPLOCK_MASK))
#define	VPP_ISSWAPRES(vpp) \
	((uchar_t)((vpp)->nvp_advice & VP_SWAPRES_MASK))
#define	VPP_ISINHZERO(vpp) \
	((uchar_t)((vpp)->nvp_advice & VP_INHZERO_MASK))

#define	VPP_SETPROT(vpp, x)	((vpp)->nvp_prot = (x))
#define	VPP_SETADVICE(vpp, x) \
	((vpp)->nvp_advice = ((vpp)->nvp_advice & ~VP_ADVICE_MASK) | \
		((x) & VP_ADVICE_MASK))
#define	VPP_SETPPLOCK(vpp)	((vpp)->nvp_advice |= VP_PPLOCK_MASK)
#define	VPP_CLRPPLOCK(vpp)	((vpp)->nvp_advice &= ~VP_PPLOCK_MASK)
#define	VPP_SETSWAPRES(vpp)	((vpp)->nvp_advice |= VP_SWAPRES_MASK)
#define	VPP_CLRSWAPRES(vpp)	((vpp)->nvp_advice &= ~VP_SWAPRES_MASK)
#define	VPP_SETINHZERO(vpp)	((vpp)->nvp_advice |= VP_INHZERO_MASK)
#define	VPP_CLRINHZERO(vpp)	((vpp)->nvp_advice &= ~VP_INHZERO_MASK)

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_VPAGE_H */
