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
 */

#ifndef	_RELOC_DEFS_DOT_H
#define	_RELOC_DEFS_DOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/machelf.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definitions used by the relocation common code.
 */


/*
 * Structure used to build the reloc_table[]
 */
typedef struct {
	Xword	re_mask;	/* mask to apply to reloc (sparc only) */
	Word	re_flags;	/* relocation attributes */
	uchar_t	re_fsize;	/* field size (in bytes) */
	uchar_t	re_bshift;	/* number of bits to shift (sparc only) */
	uchar_t	re_sigbits;	/* number of significant bits */
} Rel_entry;

/*
 * Flags for reloc_entry->re_flags
 */
#define	FLG_RE_NOTREL		0x00000000
#define	FLG_RE_GOTADD		0x00000001	/* create a GOT entry */
#define	FLG_RE_GOTREL		0x00000002	/* GOT based */
#define	FLG_RE_GOTPC		0x00000004	/* GOT - P */
#define	FLG_RE_GOTOPINS		0x00000008	/* GOTOP instruction */
#define	FLG_RE_PCREL		0x00000010
#define	FLG_RE_PLTREL		0x00000020
#define	FLG_RE_VERIFY		0x00000040	/* verify value fits */
#define	FLG_RE_UNALIGN		0x00000080	/* offset is not aligned */
#define	FLG_RE_WDISP16		0x00000100	/* funky sparc DISP16 rel */
#define	FLG_RE_SIGN		0x00000200	/* value is signed */
#define	FLG_RE_ADDRELATIVE	0x00000400	/* RELATIVE relocation */
						/*	required for non- */
						/*	fixed objects */
#define	FLG_RE_EXTOFFSET	0x00000800	/* extra offset required */
#define	FLG_RE_REGISTER		0x00001000	/* relocation initializes */
						/*    a REGISTER by OLO10 */
#define	FLG_RE_SIZE		0x00002000	/* symbol size required */

#define	FLG_RE_NOTSUP		0x00010000	/* relocation not supported */

#define	FLG_RE_SEGREL		0x00040000	/* segment relative */
#define	FLG_RE_SECREL		0x00080000	/* section relative */

#define	FLG_RE_TLSGD		0x00200000	/* TLS GD relocation */
#define	FLG_RE_TLSLD		0x00400000	/* TLS LD relocation */
#define	FLG_RE_TLSIE		0x00800000	/* TLS IE relocation */
#define	FLG_RE_TLSLE		0x01000000	/* TLS LE relocation */
#define	FLG_RE_LOCLBND		0x02000000	/* relocation must bind */
						/*    locally */

/*
 * Relocation table and macros for testing relocation table flags.
 */

#define	RELTAB_IS_PLT(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_PLTREL) != 0)

#define	RELTAB_IS_GOT_RELATIVE(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_GOTADD) != 0)

#define	RELTAB_IS_GOT_PC(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_GOTPC) != 0)

#define	RELTAB_IS_GOTPCREL(X, _reltab) \
	((_reltab[(X)].re_flags & (FLG_RE_GOTPC | FLG_RE_GOTADD)) == \
	(FLG_RE_GOTPC | FLG_RE_GOTADD))

#define	RELTAB_IS_GOT_BASED(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_GOTREL) != 0)

#define	RELTAB_IS_GOT_OPINS(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_GOTOPINS) != 0)

#define	RELTAB_IS_GOT_REQUIRED(X, _reltab) \
	((_reltab[(X)].re_flags & (FLG_RE_GOTADD | FLG_RE_GOTREL | \
	FLG_RE_GOTPC | FLG_RE_GOTOPINS)) != 0)

#define	RELTAB_IS_PC_RELATIVE(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_PCREL) != 0)

#define	RELTAB_IS_ADD_RELATIVE(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_ADDRELATIVE) != 0)

#define	RELTAB_IS_REGISTER(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_REGISTER) != 0)

#define	RELTAB_IS_NOTSUP(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_NOTSUP) != 0)

#define	RELTAB_IS_SEG_RELATIVE(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_SEGREL) != 0)

#define	RELTAB_IS_EXTOFFSET(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_EXTOFFSET) != 0)

#define	RELTAB_IS_SEC_RELATIVE(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_SECREL) != 0)

#define	RELTAB_IS_TLS_INS(X, _reltab) \
	((_reltab[(X)].re_flags & \
	(FLG_RE_TLSGD | FLG_RE_TLSLD | FLG_RE_TLSIE | FLG_RE_TLSLE)) != 0)

#define	RELTAB_IS_TLS_GD(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_TLSGD) != 0)

#define	RELTAB_IS_TLS_LD(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_TLSLD) != 0)

#define	RELTAB_IS_TLS_IE(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_TLSIE) != 0)

#define	RELTAB_IS_TLS_LE(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_TLSLE) != 0)

#define	RELTAB_IS_LOCALBND(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_LOCLBND) != 0)

#define	RELTAB_IS_SIZE(X, _reltab) \
	((_reltab[(X)].re_flags & FLG_RE_SIZE) != 0)

#ifdef	__cplusplus
}
#endif

#endif /* _RELOC_DEFS_DOT_H */
