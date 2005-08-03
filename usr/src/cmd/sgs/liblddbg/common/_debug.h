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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DEBUG_DOT_H
#define	_DEBUG_DOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <debug.h>
#include <conv.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern	uint_t		_Dbg_mask;


/*
 * Debugging is enabled by various tokens (see debug.c) that result in an
 * internal bit mask (_Dbg_mask) being initialized.  Each debugging function is
 * appropriate for one or more of the classes specified by the bit mask.  Each
 * debugging function validates whether it is appropriate for the present
 * classes before printing anything.
 */
#define	DBG_NOTCLASS(c)	!(_Dbg_mask & DBG_MSK_CLASS & (c))
#define	DBG_NOTDETAIL()	!(_Dbg_mask & DBG_DETAIL)
#define	DBG_NOTLONG()	!(_Dbg_mask & DBG_LONG)

#define	DBG_GLOBAL	0xf0000000	/* see include/debug.h */
#define	DBG_LOCAL	0x0fffffff
#define	DBG_MSK_CLASS	0x00ffffff

#define	DBG_DETAIL	0x01000000
#define	DBG_LONG	0x02000000

#define	DBG_ARGS	0x00000001
#define	DBG_BASIC	0x00000002
#define	DBG_BINDINGS	0x00000004
#define	DBG_ENTRY	0x00000008
#define	DBG_FILES	0x00000010
#define	DBG_HELP	0x00000020
#define	DBG_LIBS	0x00000040
#define	DBG_MAP		0x00000080
#define	DBG_RELOC	0x00000100
#define	DBG_SECTIONS	0x00000200
#define	DBG_SEGMENTS	0x00000400
#define	DBG_SYMBOLS	0x00000800
#define	DBG_SUPPORT	0x00001000
#define	DBG_VERSIONS	0x00002000
#define	DBG_AUDITING	0x00004000
#define	DBG_GOT		0x00008000
#define	DBG_MOVE	0x00010000
#define	DBG_DEMANGLE	0x00020000
#define	DBG_TLS		0x00040000
#define	DBG_STRTAB	0x00080000
#define	DBG_STATISTICS	0x00100000
#define	DBG_UNUSED	0x00200000
#define	DBG_CAP		0x00400000
#define	DBG_INIT	0x00800000

typedef struct options {
	const char	*o_name;	/* command line argument name */
	uint_t		o_mask;		/* associated bit mask for this name */
} DBG_options, *DBG_opts;


/*
 * Internal debugging routines.
 */
#ifdef _ELF64
#define	_Dbg_seg_desc_entry	_Dbg_seg_desc_entry64
#endif
extern	const char	*_Dbg_sym_dem(const char *);
extern	void		_Dbg_elf_data_in(Os_desc *, Is_desc *);
extern	void		_Dbg_elf_data_out(Os_desc *);
extern	void		_Dbg_ent_entry(Half, Ent_desc * enp);
extern	void		_Dbg_seg_desc_entry(Half, int, Sg_desc *);

#ifdef	__cplusplus
}
#endif

#endif	/* _DEBUG_DOT_H */
