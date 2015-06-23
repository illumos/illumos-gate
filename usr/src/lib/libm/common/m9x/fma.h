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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FMA_H
#define	_FMA_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __sparc

/*
 * Common definitions for fma routines (SPARC)
 */

/* fsr fields */

/* current exception bits */
#define	FSR_NXC		0x1
#define	FSR_DZC		0x2
#define	FSR_UFC		0x4
#define	FSR_OFC		0x8
#define	FSR_NVC		0x10
#define	FSR_CEXC	0x1f	/* mask for all cexc bits */

/* accrued exception bits */
#define	FSR_NXA		0x20
#define	FSR_DZA		0x40
#define	FSR_UFA		0x80
#define	FSR_OFA		0x100
#define	FSR_NVA		0x200

/* trap enable bits */
#define	FSR_NXM		0x00800000
#define	FSR_DZM		0x01000000
#define	FSR_UFM		0x02000000
#define	FSR_OFM		0x04000000
#define	FSR_NVM		0x08000000

/* rounding directions (right-adjusted) */
#define	FSR_RN		0
#define	FSR_RZ		1
#define	FSR_RP		2
#define	FSR_RM		3

/* inline templates */
extern void __fenv_getfsr32(unsigned int *);
extern void __fenv_setfsr32(const unsigned int *);

#endif /* __sparc */


#if defined(__x86)

/*
 * Common definitions for fma routines (x86)
 */

/* control and status word fields */

/* exception flags */
#define	FSW_NV		0x1
#define	FSW_DN		0x2
#define	FSW_DZ		0x4
#define	FSW_OF		0x8
#define	FSW_UF		0x10
#define	FSW_NX		0x20

/* exception masks */
#define	FCW_NVM		0x00010000
#define	FCW_DNM		0x00020000
#define	FCW_DZM		0x00040000
#define	FCW_OFM		0x00080000
#define	FCW_UFM		0x00100000
#define	FCW_NXM		0x00200000
#define FCW_ALLM	0x003f0000

/* rounding directions */
#define	FCW_RN		0x00000000
#define	FCW_RM		0x04000000
#define	FCW_RP		0x08000000
#define	FCW_RZ		0x0c000000

/* rounding precisions */
#define FCW_P24		0x00000000
#define FCW_P53		0x02000000
#define FCW_P64		0x03000000

/* inline templates */
extern void __fenv_getcwsw(unsigned int *);
extern void __fenv_setcwsw(const unsigned int *);

#endif /* __x86 */

#ifdef __cplusplus
}
#endif

#endif	/* _FMA_H */
