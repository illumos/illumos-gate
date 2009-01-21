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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Object file dependent support for ELF objects.
 */

#include	<stdio.h>
#include	<sys/procfs.h>
#include	<sys/mman.h>
#include	<dlfcn.h>
#include	<debug.h>
#include	<conv.h>
#include	"_rtld.h"
#include	"_audit.h"
#include	"_elf.h"
#include	"_inline.h"
#include	"msg.h"

/*
 * For backward compatibility copy relocation processing, it can be necessary to
 * determine if a copy destination is also the recipient of a move record.  For
 * these instances, the move record addresses are retained for is_move_data().
 */
static	APlist	*alp = NULL;

/*
 * Warning message for bad move target.
 */
void
elf_move_bad(Lm_list *lml, Rt_map *lmp, Sym *sym, ulong_t num, Addr addr)
{
	const char	*name;
	int		trace;

	trace = (lml->lm_flags & LML_FLG_TRC_ENABLE) &&
	    (((rtld_flags & RT_FL_SILENCERR) == 0) ||
	    (lml->lm_flags & (LML_FLG_TRC_VERBOSE | LML_FLG_TRC_WARN)));

	if ((trace == 0) && (DBG_ENABLED == 0))
		return;

	if (ELF_ST_BIND(sym->st_info) != STB_LOCAL)
		name = (const char *)(STRTAB(lmp) + sym->st_name);
	else
		name = MSG_INTL(MSG_STR_UNKNOWN);

	if (trace)
		(void) printf(MSG_INTL(MSG_LDD_MOVE_ERR), EC_XWORD(num), name,
		    EC_ADDR(addr));
	else
		DBG_CALL(Dbg_move_bad(lml, num, name, addr));
}

/*
 * Move data.  Apply sparse initialization to data in zeroed bss.
 */
int
move_data(Rt_map *lmp, APlist **textrel)
{
	Lm_list		*lml = LIST(lmp);
	Move		*mv = MOVETAB(lmp);
	ulong_t		num, mvnum = MOVESZ(lmp) / MOVEENT(lmp);
	int		moves;

	/*
	 * If these records are against the executable, and the executable was
	 * built prior to Solaris 8, keep track of the move record symbol.  See
	 * comment in analyze.c:lookup_sym_interpose() in regards Solaris 8
	 * objects and DT_FLAGS.
	 */
	moves = (lmp == lml->lm_head) && ((FLAGS1(lmp) & FL1_RT_DTFLAGS) == 0);

	DBG_CALL(Dbg_move_data(lmp));
	for (num = 0; num < mvnum; num++, mv++) {
		mmapobj_result_t	*mpp;
		Addr			addr, taddr;
		Half 			rep, repno, stride;
		Sym			*sym;

		if ((sym = (Sym *)SYMTAB(lmp) + ELF_M_SYM(mv->m_info)) == 0)
			continue;

		stride = mv->m_stride + 1;
		addr = sym->st_value;

		/*
		 * Determine the move data target, and verify the address is
		 * writable.
		 */
		if ((FLAGS(lmp) & FLG_RT_FIXED) == 0)
			addr += ADDR(lmp);
		taddr = addr + mv->m_poffset;

		if ((mpp = find_segment((caddr_t)taddr, lmp)) == NULL) {
			elf_move_bad(lml, lmp, sym, num, taddr);
			continue;
		}
		if (((mpp->mr_prot & PROT_WRITE) == 0) &&
		    ((set_prot(lmp, mpp, 1) == 0) ||
		    (aplist_append(textrel, mpp, AL_CNT_TEXTREL) == NULL)))
			return (0);

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
		    (aplist_append(&alp, (void *)addr, AL_CNT_MOVES) == NULL))
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
