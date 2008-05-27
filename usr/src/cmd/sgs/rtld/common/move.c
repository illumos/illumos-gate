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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Object file dependent support for ELF objects.
 */
#include	"_synonyms.h"

#include	<stdio.h>
#include	<sys/procfs.h>
#include	<sys/mman.h>
#include	<dlfcn.h>
#include	<debug.h>
#include	<conv.h>
#include	"_rtld.h"
#include	"_audit.h"
#include	"_elf.h"
#include	"msg.h"

/*
 * For backward compatibility copy relocation processing, it can be necessary to
 * determine if a copy destination is also the recipient of a move record.  For
 * these instances, the move record addresses are retained for is_move_data().
 */
static	APlist	*alp = NULL;

/*
 * Move data
 */
int
move_data(Rt_map *lmp)
{
	Lm_list	*lml = LIST(lmp);
	Move	*mv = MOVETAB(lmp);
	Phdr	*pptr = SUNWBSS(lmp);
	ulong_t	num, mvnum = MOVESZ(lmp) / MOVEENT(lmp);
	int	moves;

	/*
	 * If these records are against the executable, and the executable was
	 * built prior to Solaris 8, keep track of the move record symbol.  See
	 * comment in analyze.c:lookup_sym_interpose() in regards Solaris 8
	 * objects and DT_FLAGS.
	 */
	moves = (lmp == lml->lm_head) && ((FLAGS2(lmp) & FL2_RT_DTFLAGS) == 0);

	DBG_CALL(Dbg_move_data(lmp));
	for (num = 0; num < mvnum; num++, mv++) {
		Addr	addr, taddr;
		Half 	rep, repno, stride;
		Sym	*sym;

		/*
		 * If the target address needs to be mapped in,
		 * map it first.
		 *	(You have to protect the code, thread safe)
		 */
		if (FLAGS(lmp) & FLG_RT_SUNWBSS) {
			long	zlen;
			Off	foff;
			caddr_t	zaddr, eaddr;

			foff = (Off) (pptr->p_vaddr + ADDR(lmp));
			zaddr = (caddr_t)M_PROUND(foff);
			eaddr = pptr->p_vaddr + ADDR(lmp) +
			    (caddr_t)pptr->p_memsz;
			zero((caddr_t)foff, (long)(zaddr - foff));
			zlen = eaddr - zaddr;
			if (zlen > 0) {
				if (dz_map(lml, zaddr, zlen,
				    (PROT_READ | PROT_WRITE),
				    (MAP_FIXED | MAP_PRIVATE)) == MAP_FAILED)
					return (0);
			}

			FLAGS(lmp) &= ~FLG_RT_SUNWBSS;
		}

		if ((sym = (Sym *)SYMTAB(lmp) + ELF_M_SYM(mv->m_info)) == 0)
			continue;

		stride = mv->m_stride + 1;
		addr = sym->st_value;
		if ((FLAGS(lmp) & FLG_RT_FIXED) == 0)
			addr += ADDR(lmp);
		taddr = addr + mv->m_poffset;

		DBG_CALL(Dbg_move_entry2(lml, mv, sym->st_name,
		    (const char *)(sym->st_name + STRTAB(lmp))));

		for (rep = 0, repno = 0; rep < mv->m_repeat; rep++) {
			DBG_CALL(Dbg_move_expand(lml, mv, taddr));

			switch (ELF_M_SIZE(mv->m_info)) {
			case 1:
				*((char *)taddr) = (char)mv->m_value;
				taddr += stride;
				repno++;
				break;
			case 2:
				/* LINTED */
				*((Half *)taddr) = (Half)mv->m_value;
				taddr += 2 * stride;
				repno++;
				break;
			case 4:
				/* LINTED */
				*((Word *)taddr) = (Word)mv->m_value;
				taddr += 4 * stride;
				repno++;
				break;
			case 8:
				/* LINTED */
				*((unsigned long long *)taddr) = mv->m_value;
				taddr += 8 * stride;
				repno++;
				break;
			default:
				eprintf(lml, ERR_NONE, MSG_INTL(MSG_MOVE_ERR1));
				break;
			}
		}

		/*
		 * If any move records have been applied to this symbol, retain
		 * the symbol address if required for backward compatibility
		 * copy relocation processing.
		 */
		if (moves && repno &&
		    (aplist_append(&alp, (void *)addr, AL_CNT_MOVES) == 0))
			return (0);
	}

	/*
	 * Binaries built in the early 1990's prior to Solaris 8, using the ild
	 * incremental linker are known to have zero filled move sections
	 * (presumably place holders for new, incoming move sections).  If no
	 * move records have been processed, remove the move identifier to
	 * optimize the amount of backward compatibility copy relocation
	 * processing that is needed.
	 */
	if (moves && (alp == NULL))
		FLAGS(lmp) &= ~FLG_RT_MOVE;

	return (1);
}

/*
 * Determine whether an address is the recipient of a move record.
 * Returns 1 if the address matches a move symbol, 0 otherwise.
 */
int
is_move_data(caddr_t addr)
{
	caddr_t	maddr;
	Aliste	idx;

	for (APLIST_TRAVERSE(alp, idx, maddr)) {
		if (addr == maddr)
			return (1);
	}
	return (0);
}
