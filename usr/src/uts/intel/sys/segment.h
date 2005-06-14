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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef	_SYS_SEGMENT_H
#define	_SYS_SEGMENT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* access rights for data segments */
#define	UDATA_ACC1	0xF2 	/* present dpl=3 writable */
#define	DATA_ACC2	0xC	/* 4Kbyte gran. 4Gb limit avl=0 */
#define	DATA_ACC2_S	0x4	/* 1 byte gran., 32bit operands, avl=0 */
#define	UTEXT_ACC1	0xFA 	/* present dpl=3 readable */
#define	TEXT_ACC2	0xC	/* 4Kbyte gran., 32 bit operands avl=0 */
#define	TEXT_ACC2_S	0x4	/* 1 byte gran., 32 bit operands avl=0 */
#define	LDT_UACC1	0xE2	/* present dpl=3 type=ldt */
#define	LDT_ACC2	0x0	/* G=0 avl=0 */
#define	TGATE_UACC1	0xE5	/* present dpl=3 type=task gate		*/
#define	SEG_CONFORM	0X4	/* conforming bit in acc0007 */

#define	LDT_TYPE	0x2	/* type of segment is LDT */


/* access rights field for gates */

#define	GATE_UACC	0xE0		/* present and dpl = 3 */
#define	GATE_386CALL	0xC		/* 386 call gate */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SEGMENT_H */
