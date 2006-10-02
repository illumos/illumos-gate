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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_ELF_AMD64_H
#define	_SYS_ELF_AMD64_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	R_AMD64_NONE		0	/* relocation types */
#define	R_AMD64_64		1
#define	R_AMD64_PC32		2
#define	R_AMD64_GOT32		3
#define	R_AMD64_PLT32		4
#define	R_AMD64_COPY		5
#define	R_AMD64_GLOB_DAT	6
#define	R_AMD64_JUMP_SLOT	7
#define	R_AMD64_RELATIVE	8
#define	R_AMD64_GOTPCREL	9
#define	R_AMD64_32		10
#define	R_AMD64_32S		11
#define	R_AMD64_16		12
#define	R_AMD64_PC16		13
#define	R_AMD64_8		14
#define	R_AMD64_PC8		15
#define	R_AMD64_DTPMOD64	16
#define	R_AMD64_DTPOFF64	17
#define	R_AMD64_TPOFF64		18
#define	R_AMD64_TLSGD		19
#define	R_AMD64_TLSLD		20
#define	R_AMD64_DTPOFF32	21
#define	R_AMD64_GOTTPOFF	22
#define	R_AMD64_TPOFF32		23
#define	R_AMD64_PC64		24
#define	R_AMD64_GOTOFF64	25
#define	R_AMD64_GOTPC32		26
#define	R_AMD64_GOT64		27	/* reserved for future expansion */
#define	R_AMD64_GOTPCREL64	28	/* reserved for future expansion */
#define	R_AMD64_GOTPC64		29	/* reserved for future expansion */
#define	R_AMD64_GOTPLT64	30	/* reserved for future expansion */
#define	R_AMD64_PLTOFF64	31	/* reserved for future expansion */
#define	R_AMD64_SIZE32		32
#define	R_AMD64_SIZE64		33
#define	R_AMD64_NUM		34


/*
 * The "System V Application Binary Interface, AMD64 Architecture Processor
 * Supplement", defines relocations in terms of R_X86_64_ rather than R_AMD64_.
 * Maintain both relocation naming conventions for compatibility.
 */
#define	R_X86_64_NONE		R_AMD64_NONE
#define	R_X86_64_64		R_AMD64_64
#define	R_X86_64_PC32		R_AMD64_PC32
#define	R_X86_64_GOT32		R_AMD64_GOT32
#define	R_X86_64_PLT32		R_AMD64_PLT32
#define	R_X86_64_COPY		R_AMD64_COPY
#define	R_X86_64_GLOB_DAT	R_AMD64_GLOB_DAT
#define	R_X86_64_JUMP_SLOT	R_AMD64_JUMP_SLOT
#define	R_X86_64_RELATIVE	R_AMD64_RELATIVE
#define	R_X86_64_GOTPCREL	R_AMD64_GOTPCREL
#define	R_X86_64_32		R_AMD64_32
#define	R_X86_64_32S		R_AMD64_32S
#define	R_X86_64_16		R_AMD64_16
#define	R_X86_64_PC16		R_AMD64_PC16
#define	R_X86_64_8		R_AMD64_8
#define	R_X86_64_PC8		R_AMD64_PC8
#define	R_X86_64_DTPMOD64	R_AMD64_DTPMOD64
#define	R_X86_64_DTPOFF64	R_AMD64_DTPOFF64
#define	R_X86_64_TPOFF64	R_AMD64_TPOFF64
#define	R_X86_64_TLSGD		R_AMD64_TLSGD
#define	R_X86_64_TLSLD		R_AMD64_TLSLD
#define	R_X86_64_DTPOFF32	R_AMD64_DTPOFF32
#define	R_X86_64_GOTTPOFF	R_AMD64_GOTTPOFF
#define	R_X86_64_TPOFF32	R_AMD64_TPOFF32
#define	R_X86_64_PC64		R_AMD64_PC64
#define	R_X86_64_GOTPC32	R_AMD64_GOTPC32
#define	R_X86_64_GOTOFF64	R_AMD64_GOTOFF64
#define	R_X86_64_GOT64		R_AMD64_GOT64
#define	R_X86_64_GOTPCREL64	R_AMD64_GOTPCREL64
#define	R_X86_64_GOTPC64	R_AMD64_GOTPC64
#define	R_X86_64_GOTPLT64	R_AMD64_GOTPLT64
#define	R_X86_64_PLTOFF64	R_AMD64_PLTOFF64
#define	R_X86_64_SIZE32		R_AMD64_SIZE32
#define	R_X86_64_SIZE64		R_AMD64_SIZE64
#define	R_X86_64_NUM		R_AMD64_NUM


#define	ELF_AMD64_MAXPGSZ	0x100000	/* maximum page size */

/*
 * processor specific section types
 */
#define	SHT_AMD64_UNWIND	0x70000001	/* unwind information */


/*
 * NOTE: PT_SUNW_UNWIND is defined in the OS specific range
 *	 to conform with the amd64 psABI.
 */

#define	SHF_AMD64_LARGE		0x10000000
#define	SHF_X86_64_LARGE	SHF_AMD64_LARGE
#define	SHF_ORDERED		0x40000000
#define	SHF_EXCLUDE		0x80000000

#define	SHN_BEFORE		0xff00
#define	SHN_AFTER		0xff01
#define	SHN_AMD64_LCOMMON	0xff02
#define	SHN_X86_64_LCOMMON	SHN_AMD64_LCOMMON


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ELF_AMD64_H */
