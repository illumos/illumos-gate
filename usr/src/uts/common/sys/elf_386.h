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
 *	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 *	  All Rights Reserved
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_ELF_386_H
#define	_SYS_ELF_386_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2	*/

#ifdef	__cplusplus
extern "C" {
#endif

#define	R_386_NONE		0	/* relocation type */
#define	R_386_32		1
#define	R_386_PC32		2
#define	R_386_GOT32		3
#define	R_386_PLT32		4
#define	R_386_COPY		5
#define	R_386_GLOB_DAT		6
#define	R_386_JMP_SLOT		7
#define	R_386_RELATIVE		8
#define	R_386_GOTOFF		9
#define	R_386_GOTPC		10
#define	R_386_32PLT		11
#define	R_386_TLS_GD_PLT	12
#define	R_386_TLS_LDM_PLT	13
#define	R_386_TLS_TPOFF		14
#define	R_386_TLS_IE		15
#define	R_386_TLS_GOTIE		16
#define	R_386_TLS_LE		17
#define	R_386_TLS_GD		18
#define	R_386_TLS_LDM		19
#define	R_386_16		20
#define	R_386_PC16		21
#define	R_386_8			22
#define	R_386_PC8		23
#define	R_386_UNKNOWN24		24
#define	R_386_UNKNOWN25		25
#define	R_386_UNKNOWN26		26
#define	R_386_UNKNOWN27		27
#define	R_386_UNKNOWN28		28
#define	R_386_UNKNOWN29		29
#define	R_386_UNKNOWN30		30
#define	R_386_UNKNOWN31		31
#define	R_386_TLS_LDO_32	32
#define	R_386_UNKNOWN33		33
#define	R_386_UNKNOWN34		34
#define	R_386_TLS_DTPMOD32	35
#define	R_386_TLS_DTPOFF32	36
#define	R_386_UNKNOWN37		37
#define	R_386_SIZE32		38
#define	R_386_NUM		39

#define	ELF_386_MAXPGSZ		0x10000	/* maximum page size */

#define	SHF_ORDERED	0x40000000
#define	SHF_EXCLUDE	0x80000000

#define	SHN_BEFORE	0xff00
#define	SHN_AFTER	0xff01

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ELF_386_H */
