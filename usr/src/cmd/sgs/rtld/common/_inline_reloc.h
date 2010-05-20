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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */
#ifndef	_INLINE_RELOC_H
#define	_INLINE_RELOC_H

#include	<sys/types.h>
#include	<rtld.h>
#include	<debug.h>

/*
 * Generic relative relocation function.
 */
inline static ulong_t
/* LINTED */
/* ARGSUSED4 */
_elf_reloc_relative(ulong_t rbgn, ulong_t base, Rt_map *lmp, APlist **textrel,
    int add)
{
	mmapobj_result_t	*mpp;
	ulong_t			roffset;

	roffset = ((M_RELOC *)rbgn)->r_offset;
	roffset += base;

	/*
	 * If this relocation is against an address that is not associated with
	 * a mapped segment, fall back to the generic relocation loop to
	 * collect the associated error.
	 */
	if ((mpp = find_segment((caddr_t)roffset, lmp)) == NULL)
		return (0);

	/*
	 * If this relocation is against a segment that does not provide write
	 * access, set the write permission for all non-writable mappings.
	 */
	if (((mpp->mr_prot & PROT_WRITE) == 0) && textrel &&
	    ((set_prot(lmp, mpp, 1) == 0) ||
	    (aplist_append(textrel, mpp, AL_CNT_TEXTREL) == NULL)))
		return (0);

	/*
	 * Perform a base address update.  This simple operation is required
	 * for updating .plt relocations in preparation for lazy binding.
	 */
#if	defined(__x86)
	if (add) {
		*((ulong_t *)roffset) += base;
		return (1);
	}
#endif
	/*
	 * Perform the actual relocation.  Note, for backward compatibility,
	 * SPARC relocations are added to the offset contents (there was a time
	 * when the offset was used to contain the addend, rather than using
	 * the addend itself).
	 */
#if	defined(__sparc)
	*((ulong_t *)roffset) += base + ((M_RELOC *)rbgn)->r_addend;
#elif	defined(__amd64)
	*((ulong_t *)roffset) = base + ((M_RELOC *)rbgn)->r_addend;
#else
	*((ulong_t *)roffset) += base;
#endif
	return (1);
}

/*
 * When a generic relocation loop realizes that it's dealing with relative
 * relocations, but no DT_RELCOUNT .dynamic tag is present, this tighter loop
 * is entered as an optimization.
 */
inline static ulong_t
/* LINTED */
elf_reloc_relative(ulong_t rbgn, ulong_t rend, ulong_t rsize, ulong_t base,
    Rt_map *lmp, APlist **textrel, int add)
{
	uchar_t	rtype;

	do {
		if (_elf_reloc_relative(rbgn, base, lmp, textrel, add) == 0)
			break;

		rbgn += rsize;
		if (rbgn >= rend)
			break;

		/*
		 * Make sure the next type is a relative relocation.
		 */
		rtype = ELF_R_TYPE(((M_RELOC *)rbgn)->r_info, M_MACH);

	} while (rtype == M_R_RELATIVE);

	return (rbgn);
}

/*
 * This is the tightest loop for RELATIVE relocations for those objects built
 * with the DT_RELACOUNT .dynamic entry.
 */
inline static ulong_t
/* LINTED */
elf_reloc_relative_count(ulong_t rbgn, ulong_t rcount, ulong_t rsize,
    ulong_t base, Rt_map *lmp, APlist **textrel, int add)
{
	for (; rcount; rcount--) {
		if (_elf_reloc_relative(rbgn, base, lmp, textrel, add) == 0)
			break;

		rbgn += rsize;
	}
	return (rbgn);
}

/*
 * Determine, from a symbols Syminfo information, whether a symbol reference
 * is deferred.  This routine is called from elf_reloc() as part of processing
 * an objects relocations.
 */
inline static int
/* LINTED */
is_sym_deferred(ulong_t rbgn, ulong_t base, Rt_map *lmp, APlist **textrel,
    Syminfo *sip, ulong_t sndx)
{
	Syminfo	*sipe;

	/*
	 * ldd(1) by default, sets LD_DEFERRED to force deferred dependency
	 * processing.  ldd -D disables LD_DEFERRED, which allows ld.so.1's
	 * default action of skipping deferred dependencies.
	 */
	if (rtld_flags & RT_FL_DEFERRED)
		return (0);

	/* LINTED */
	sipe = (Syminfo *)((char *)sip + (sndx * SYMINENT(lmp)));
	if (sipe->si_flags & SYMINFO_FLG_DEFERRED) {
		/*
		 * This .plt relocation should be skipped at this time, as
		 * deferred references are only processed when the associated
		 * function is explicitly called.
		 *
		 * On i386 and amd64 platforms the relocation offset needs
		 * adjusting to add this objects base address.  If the object
		 * has already been relocated without RTLD_NOW, then this
		 * update will have already been carried out.  However, if this
		 * is an initial RTLD_NOW relocation pass, this relocation
		 * offset needs updating now.
		 */
#if	defined(__x86)
		if ((FLAGS(lmp) & FLG_RT_RELOCED) == 0)
			(void) _elf_reloc_relative(rbgn, base, lmp, textrel, 1);
#endif
		return (1);
	}
	return (0);
}

#endif	/* _INLINE_RELOC_H */
