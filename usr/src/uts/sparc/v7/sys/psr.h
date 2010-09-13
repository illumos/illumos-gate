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
 * Copyright 1986,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_PSR_H
#define	_SYS_PSR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI" /* from SunOS psl.h 1.2 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definition of bits in the SPARC PSR (Processor Status Register)
 *  ________________________________________________________________________
 * | IMPL | VER	|	ICC	| resvd	| EC | EF | PIL	| S | PS | ET | CWP |
 * |	  |	| N | Z | V | C |	|    |	  |	|   |	 |    |	    |
 * |------|-----|---|---|---|---|-------|----|----|-----|---|----|----|-----|
 *  31  28 27 24  23  22  21  20 19   14  13   12  11  8   7   6    5  4   0
 *
 * Reserved bits are defined to be initialized to zero and must
 * be preserved if written, for compatabily with future revisions.
 */

#define	PSR_CWP		0x0000001F	/* current window pointer */
#define	PSR_ET		0x00000020	/* enable traps */
#define	PSR_PS		0x00000040	/* previous supervisor mode */
#define	PSR_S		0x00000080	/* supervisor mode */
#define	PSR_PIL		0x00000F00	/* processor interrupt level */
#define	PSR_EF		0x00001000	/* enable floating point unit */
#define	PSR_EC		0x00002000	/* enable coprocessor */
#define	PSR_RSV		0x000FC000	/* reserved */
#define	PSR_ICC		0x00F00000	/* integer condition codes */
#define	PSR_C		0x00100000	/* carry bit */
#define	PSR_V		0x00200000	/* overflow bit */
#define	PSR_Z		0x00400000	/* zero bit */
#define	PSR_N		0x00800000	/* negative bit */
#define	PSR_VER		0x0F000000	/* mask version */
#define	PSR_IMPL	0xF0000000	/* implementation */

#define	PSL_ALLCC	PSR_ICC		/* for portability */

#ifndef _ASM
typedef int	psw_t;
#endif

/*
 * Handy psr values.
 */
#define	PSL_USER	(PSR_S)		/* initial user psr */
#define	PSL_USERMASK	(PSR_ICC)	/* user variable psr bits */

#define	PSL_UBITS	(PSR_ICC|PSR_EF)	/* user modifiable fields */
						/* should set PSR_EC also */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PSR_H */
