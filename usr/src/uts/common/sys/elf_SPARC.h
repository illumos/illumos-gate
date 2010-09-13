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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_ELF_SPARC_H
#define	_SYS_ELF_SPARC_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	EF_SPARC_32PLUS_MASK	0xffff00	/* bits indicating V8+ type */
#define	EF_SPARC_32PLUS		0x000100	/* generic V8+ features */
#define	EF_SPARC_EXT_MASK	0xffff00	/* bits for vendor extensions */
#define	EF_SPARC_SUN_US1	0x000200	/* Sun UltraSPARC1 extensions */
#define	EF_SPARC_HAL_R1		0x000400	/* HAL R1 extensions */
#define	EF_SPARC_SUN_US3	0x000800	/* Sun UltraSPARC3 extensions */

#define	EF_SPARCV9_MM		0x3		/* mask for memory model */
#define	EF_SPARCV9_TSO		0x0		/* total store ordering */
#define	EF_SPARCV9_PSO		0x1		/* partial store ordering */
#define	EF_SPARCV9_RMO		0x2		/* relaxed memory ordering */

#define	R_SPARC_NONE		0		/* relocation type */
#define	R_SPARC_8		1
#define	R_SPARC_16		2
#define	R_SPARC_32		3
#define	R_SPARC_DISP8		4
#define	R_SPARC_DISP16		5
#define	R_SPARC_DISP32		6
#define	R_SPARC_WDISP30		7
#define	R_SPARC_WDISP22		8
#define	R_SPARC_HI22		9
#define	R_SPARC_22		10
#define	R_SPARC_13		11
#define	R_SPARC_LO10		12
#define	R_SPARC_GOT10		13
#define	R_SPARC_GOT13		14
#define	R_SPARC_GOT22		15
#define	R_SPARC_PC10		16
#define	R_SPARC_PC22		17
#define	R_SPARC_WPLT30		18
#define	R_SPARC_COPY		19
#define	R_SPARC_GLOB_DAT	20
#define	R_SPARC_JMP_SLOT	21
#define	R_SPARC_RELATIVE	22
#define	R_SPARC_UA32		23
#define	R_SPARC_PLT32		24
#define	R_SPARC_HIPLT22		25
#define	R_SPARC_LOPLT10		26
#define	R_SPARC_PCPLT32		27
#define	R_SPARC_PCPLT22		28
#define	R_SPARC_PCPLT10		29
#define	R_SPARC_10		30
#define	R_SPARC_11		31
#define	R_SPARC_64		32
#define	R_SPARC_OLO10		33
#define	R_SPARC_HH22		34
#define	R_SPARC_HM10		35
#define	R_SPARC_LM22		36
#define	R_SPARC_PC_HH22		37
#define	R_SPARC_PC_HM10		38
#define	R_SPARC_PC_LM22		39
#define	R_SPARC_WDISP16		40
#define	R_SPARC_WDISP19		41
#define	R_SPARC_GLOB_JMP	42
#define	R_SPARC_7		43
#define	R_SPARC_5		44
#define	R_SPARC_6		45
#define	R_SPARC_DISP64		46
#define	R_SPARC_PLT64		47
#define	R_SPARC_HIX22		48
#define	R_SPARC_LOX10		49
#define	R_SPARC_H44		50
#define	R_SPARC_M44		51
#define	R_SPARC_L44		52
#define	R_SPARC_REGISTER	53
#define	R_SPARC_UA64		54
#define	R_SPARC_UA16		55
#define	R_SPARC_TLS_GD_HI22	56
#define	R_SPARC_TLS_GD_LO10	57
#define	R_SPARC_TLS_GD_ADD	58
#define	R_SPARC_TLS_GD_CALL	59
#define	R_SPARC_TLS_LDM_HI22	60
#define	R_SPARC_TLS_LDM_LO10	61
#define	R_SPARC_TLS_LDM_ADD	62
#define	R_SPARC_TLS_LDM_CALL	63
#define	R_SPARC_TLS_LDO_HIX22	64
#define	R_SPARC_TLS_LDO_LOX10	65
#define	R_SPARC_TLS_LDO_ADD	66
#define	R_SPARC_TLS_IE_HI22	67
#define	R_SPARC_TLS_IE_LO10	68
#define	R_SPARC_TLS_IE_LD	69
#define	R_SPARC_TLS_IE_LDX	70
#define	R_SPARC_TLS_IE_ADD	71
#define	R_SPARC_TLS_LE_HIX22	72
#define	R_SPARC_TLS_LE_LOX10	73
#define	R_SPARC_TLS_DTPMOD32	74
#define	R_SPARC_TLS_DTPMOD64	75
#define	R_SPARC_TLS_DTPOFF32	76
#define	R_SPARC_TLS_DTPOFF64	77
#define	R_SPARC_TLS_TPOFF32	78
#define	R_SPARC_TLS_TPOFF64	79
#define	R_SPARC_GOTDATA_HIX22	80
#define	R_SPARC_GOTDATA_LOX10	81
#define	R_SPARC_GOTDATA_OP_HIX22	82
#define	R_SPARC_GOTDATA_OP_LOX10	83
#define	R_SPARC_GOTDATA_OP	84
#define	R_SPARC_H34		85
#define	R_SPARC_SIZE32		86
#define	R_SPARC_SIZE64		87
#define	R_SPARC_NUM		88

/*
 * Relocation aliases
 */
#define	R_SPARC_L34	R_SPARC_L44	/* associated with R_SPARC_H34 */
					/*   same calc as R_SPARC_L44 */

#define	ELF_SPARC_MAXPGSZ	0x10000		/* maximum page size */
#define	ELF_SPARCV9_MAXPGSZ	0x100000

/*
 * Processor specific section types
 */
#define	SHT_SPARC_GOTDATA	0x70000000

#define	SHF_ORDERED		0x40000000
#define	SHF_EXCLUDE		0x80000000

#define	SHN_BEFORE		0xff00
#define	SHN_AFTER		0xff01

#define	STT_SPARC_REGISTER	13		/* register symbol type */

#define	DT_SPARC_REGISTER	0x70000001	/* identifies register */
						/*	symbols */


/*
 * Register symbol numbers - to be used in the st_value field
 * of register symbols.
 */
#define	STO_SPARC_REGISTER_G1	0x1		/* register %g1 */
#define	STO_SPARC_REGISTER_G2	0x2		/* register %g2 */
#define	STO_SPARC_REGISTER_G3	0x3		/* register %g3 */
#define	STO_SPARC_REGISTER_G4	0x4		/* register %g4 */
#define	STO_SPARC_REGISTER_G5	0x5		/* register %g5 */
#define	STO_SPARC_REGISTER_G6	0x6		/* register %g6 */
#define	STO_SPARC_REGISTER_G7	0x7		/* register %g7 */

/*
 * There are consumers of this file that want to include elf defines for
 * all architectures.  This is a problem for the defines below, because
 * while they are architecture specific they have common names.  Hence to
 * prevent attempts to redefine these variables we'll check if any of
 * the other elf architecture header files have been included.  If
 * they have then we'll just stick with the existing definitions.
 */
#if !defined(_SYS_ELF_MACH_COMMON)
#define	_SYS_ELF_MACH_COMMON

/*
 * Plt and Got information; the first few .got and .plt entries are reserved
 *	PLT[0]	jump to dynamic linker
 *	GOT[0]	address of _DYNAMIC
 */
#define	M_PLT_INSSIZE		4	/* single plt instruction size */
#define	M_PLT_XNumber		4	/* reserved no. of plt entries */
#define	M_GOT_XDYNAMIC		0	/* got index for _DYNAMIC */
#define	M_GOT_XNumber		1	/* reserved no. of got entries */

/*
 * ELF32 bit PLT constants
 */
#define	M32_WORD_ALIGN		4
#define	M32_PLT_ENTSIZE		12	/* plt entry size in bytes */
#define	M32_PLT_ALIGN		M_WORD_ALIGN /* alignment of .plt section */
#define	M32_GOT_ENTSIZE		4	/* got entry size in bytes */
#define	M32_GOT_MAXSMALL	2048	/* maximum no. of small gots */
#define	M32_PLT_RESERVSZ	(M_PLT_XNumber * \
				M32_PLT_ENTSIZE) /* first 4 plt's reserved */

/*
 * ELF64 bit PLT constants
 */
#define	M64_WORD_ALIGN		8
#define	M64_PLT_ENTSIZE		32	/* plt entry size in bytes */
#define	M64_PLT_ALIGN		256	/* alignment of .plt section */
#define	M64_GOT_ENTSIZE		8	/* got entry size in bytes */
#define	M64_GOT_MAXSMALL	1024	/* maximum no. of small gots */
#define	M64_PLT_RESERVSZ	(M_PLT_XNumber * \
				M64_PLT_ENTSIZE) /* first 4 plt's reserved */

#define	M64_PLT_NEARPLTS	0x8000	/* # of NEAR PLTS we can have */
#define	M64_PLT_FENTSIZE	24	/* size of far plt is 6 instructions */
					/*	x 4bytes */
#define	M64_PLT_PSIZE		8		/* size of PLTP pointer */
#define	M64_PLT_FBLKCNTS	160	/* # of plts in far PLT blocks */
#define	M64_PLT_FBLOCKSZ	(M64_PLT_FBLKCNTS *\
				M64_PLT_ENTSIZE) /* size of far PLT block */


/*
 * Make common alias for the 32/64 bit specific defines based on _ELF64
 */
#ifdef _ELF64
/* architecture common defines */
#define	M_WORD_ALIGN		M64_WORD_ALIGN
#define	M_PLT_ENTSIZE		M64_PLT_ENTSIZE
#define	M_PLT_ALIGN		M64_PLT_ALIGN
#define	M_PLT_RESERVSZ		M64_PLT_RESERVSZ
#define	M_GOT_ENTSIZE		M64_GOT_ENTSIZE
/* sparc specific defines */
#define	M_GOT_MAXSMALL		M64_GOT_MAXSMALL
#else /* !_ELF64 */
/* architecture common defines */
#define	M_WORD_ALIGN		M32_WORD_ALIGN
#define	M_PLT_ENTSIZE		M32_PLT_ENTSIZE
#define	M_PLT_ALIGN		M32_PLT_ALIGN
#define	M_PLT_RESERVSZ		M32_PLT_RESERVSZ
#define	M_GOT_ENTSIZE		M32_GOT_ENTSIZE
/* sparc specific defines */
#define	M_GOT_MAXSMALL		M32_GOT_MAXSMALL
#endif /* !_ELF64 */

#endif /* !_SYS_ELF_MACH_COMMON */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ELF_SPARC_H */
