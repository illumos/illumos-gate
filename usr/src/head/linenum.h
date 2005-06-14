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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _LINENUM_H
#define	_LINENUM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5	*/

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *  There is one line number entry for every
 *  "breakpointable" source line in a section.
 *  Line numbers are grouped on a per function
 *  basis; the first entry in a function grouping
 *  will have l_lnno = 0 and in place of physical
 *  address will be the symbol table index of
 *  the function name.
 */
struct lineno
{
	union
	{
		long	l_symndx;	/* sym. table index of function name */
					/* iff l_lnno == 0 */
		long	l_paddr;	/* (physical) address of line number */
	}		l_addr;
	unsigned short	l_lnno;		/* line number */
};

#define	LINENO	struct lineno
#define	LINESZ	6	/* sizeof(LINENO) */

#ifdef	__cplusplus
}
#endif

#endif	/* _LINENUM_H */
