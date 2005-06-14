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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_ELF_M32_H
#define	_SYS_ELF_M32_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/

#ifdef	__cplusplus
extern "C" {
#endif

#define	EF_M32_MAU		1	/* e_flags */

#define	R_M32_NONE		0	/* relocation type */
#define	R_M32_32		1
#define	R_M32_32_S		2
#define	R_M32_PC32_S		3
#define	R_M32_GOT32_S		4
#define	R_M32_PLT32_S		5
#define	R_M32_COPY		6
#define	R_M32_GLOB_DAT		7
#define	R_M32_JMP_SLOT		8
#define	R_M32_RELATIVE		9
#define	R_M32_RELATIVE_S	10
#define	R_M32_NUM		11	/* must be >last */

#define	ELF_M32_MAXPGSZ		0x2000	/* maximum page size */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ELF_M32_H */
