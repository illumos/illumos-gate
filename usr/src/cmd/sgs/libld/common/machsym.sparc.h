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

/*
 * Sparc register symbols
 */

#ifndef	_MACHSYM_DOT_SPARC_DOT_H
#define	_MACHSYM_DOT_SPARC_DOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#if	defined(_ELF64)

#define	ld_is_regsym_sparc	ld64_is_regsym_sparc
#define	ld_mach_sym_typecheck_sparc	ld64_mach_sym_typecheck_sparc
#define	ld_reg_check_sparc	ld64_reg_check_sparc
#define	ld_reg_enter_sparc	ld64_reg_enter_sparc
#define	ld_reg_find_sparc	ld64_reg_find_sparc

#else

#define	ld_is_regsym_sparc	ld32_is_regsym_sparc
#define	ld_mach_sym_typecheck_sparc	ld32_mach_sym_typecheck_sparc
#define	ld_reg_check_sparc	ld32_reg_check_sparc
#define	ld_reg_enter_sparc	ld32_reg_enter_sparc
#define	ld_reg_find_sparc	ld32_reg_find_sparc

#endif

extern const char	*ld_is_regsym_sparc(Ofl_desc *, Ifl_desc *, Sym *,
			    const char *, int, Word, const char *, Word *);
extern int		ld_mach_sym_typecheck_sparc(Sym_desc *, Sym *,
			    Ifl_desc *, Ofl_desc *);
extern int		ld_reg_check_sparc(Sym_desc *, Sym *, const char *,
			    Ifl_desc *, Ofl_desc *);
extern int		ld_reg_enter_sparc(Sym_desc *, Ofl_desc *);
extern Sym_desc *	ld_reg_find_sparc(Sym *, Ofl_desc *);


#ifdef	__cplusplus
}
#endif

#endif /* _MACHSYM_DOT_SPARC_DOT_H */
