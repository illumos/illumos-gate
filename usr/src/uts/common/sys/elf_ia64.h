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
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_ELF_IA64_H
#define	_SYS_ELF_IA64_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	EF_IA_64_MASKOS		0x0000000f	/* reserved for OS values */
#define	EF_IA_64_ABI64		0x00000010	/* object uses LP64 model */
#define	EF_IA_64_ARCH		0xff000000	/* arch. version ident */

/*
 * processor specific program headers
 */
#define	PT_IA_64_ARCHEXT	0x70000000
#define	PT_IA_64_UNWIND		0x70000001	/* stack unwind tables */

#define	PF_IA_64_NORECOV	0x80000000

#define	R_IA_64_NONE		0	/* relocation type */
#define	R_IA_64_IMM14		0x21
#define	R_IA_64_IMM22		0x22
#define	R_IA_64_IMM64		0x23
#define	R_IA_64_DIR32MSB	0x24
#define	R_IA_64_DIR32LSB	0x25
#define	R_IA_64_DIR64MSB	0x26
#define	R_IA_64_DIR64LSB	0x27
#define	R_IA_64_GPREL22		0x2a
#define	R_IA_64_GPREL64I	0x2b
#define	R_IA_64_GPREL64MSB	0x2e
#define	R_IA_64_GPREL64LSB	0x2f
#define	R_IA_64_LTOFF22		0x32
#define	R_IA_64_LTOFF64I	0x33
#define	R_IA_64_PLTOFF22	0x3a
#define	R_IA_64_PLTOFF64I	0x3b
#define	R_IA_64_PLTOFF64MSB	0x3e
#define	R_IA_64_PLTOFF64LSB	0x3f
#define	R_IA_64_FPTR64I		0x43
#define	R_IA_64_FPTR32MSB	0x44
#define	R_IA_64_FPTR32LSB	0x45
#define	R_IA_64_FPTR64MSB	0x46
#define	R_IA_64_FPTR64LSB	0x47
#define	R_IA_64_PCREL21B	0x49
#define	R_IA_64_PCREL21M	0x4a
#define	R_IA_64_PCREL21F	0x4b
#define	R_IA_64_PCREL32MSB	0x4c
#define	R_IA_64_PCREL32LSB	0x4d
#define	R_IA_64_PCREL64MSB	0x4e
#define	R_IA_64_PCREL64LSB	0x4f
#define	R_IA_64_LTOFF_FPTR22	0x52
#define	R_IA_64_LTOFF_FPTR64I	0x53
#define	R_IA_64_SEGREL32MSB	0x5c
#define	R_IA_64_SEGREL32LSB	0x5d
#define	R_IA_64_SEGREL64MSB	0x5e
#define	R_IA_64_SEGREL64LSB	0x5f
#define	R_IA_64_SECREL32MSB	0x64
#define	R_IA_64_SECREL32LSB	0x65
#define	R_IA_64_SECREL64MSB	0x66
#define	R_IA_64_SECREL64LSB	0x67
#define	R_IA_64_REL32MSB	0x6c
#define	R_IA_64_REL32LSB	0x6d
#define	R_IA_64_REL64MSB	0x6e
#define	R_IA_64_REL64LSB	0x6f
#define	R_IA_64_LTV32MSB	0x70
#define	R_IA_64_LTV32LSB	0x71
#define	R_IA_64_LTV64MSB	0x72
#define	R_IA_64_LTV64LSB	0x73
#define	R_IA_64_IPLTMSB		0x80
#define	R_IA_64_IPLTLSB		0x81
#define	R_IA_64_NUM		0x82

#define	ELF_IA_64_MAXPGSZ	0x100000	/* maximum page size */

#define	SHF_ORDERED	0x40000000
#define	SHF_EXCLUDE	0x80000000

#define	SHN_BEFORE	0xff00
#define	SHN_AFTER	0xff01

/*
 * processor specific sh_type's
 */
#define	SHT_IA_64_EXT		0x70000000
#define	SHT_IA_64_UNWIND	0x70000001

/*
 * processor specific sh_flags
 */
#define	SHF_IA_64_SHORT		0x10000000
#define	SHF_IA_64_NORECOV	0x20000000

/*
 * Processor specific DT entries
 */
#define	DT_IA_64_PLT_RESERVE	0x70000000



#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ELF_IA64_H */
