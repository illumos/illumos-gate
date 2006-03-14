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
 * Move data
 */
void
move_data(Rt_map *lmp)
{
	Lm_list	*lml = LIST(lmp);
	Move	*mv = MOVETAB(lmp);
	Phdr	*pptr = SUNWBSS(lmp);
	ulong_t	num, mvnum = MOVESZ(lmp) / MOVEENT(lmp);

	DBG_CALL(Dbg_move_data(lmp));
	for (num = 0; num < mvnum; num++, mv++) {
		Addr	taddr;
		Half 	rep, stride;
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
					return;
			}

			FLAGS(lmp) &= ~FLG_RT_SUNWBSS;
		}

		if ((sym = (Sym *)SYMTAB(lmp) + ELF_M_SYM(mv->m_info)) == 0)
			continue;

		stride = mv->m_stride + 1;
		taddr = sym->st_value;
		if (FLAGS(lmp) & FLG_RT_FIXED)
			taddr = taddr + mv->m_poffset;
		else
			taddr = taddr + mv->m_poffset + ADDR(lmp);

		DBG_CALL(Dbg_move_entry2(lml, mv, sym->st_name,
		    (const char *)(sym->st_name + STRTAB(lmp))));

		for (rep = 0; rep < mv->m_repeat; rep++) {
			DBG_CALL(Dbg_move_expand(lml, mv, taddr));

			switch (ELF_M_SIZE(mv->m_info)) {
			case 1:
				*((char *)taddr) = (char)mv->m_value;
				taddr += stride;
				break;
			case 2:
				/* LINTED */
				*((Half *)taddr) = (Half)mv->m_value;
				taddr += 2 * stride;
				break;
			case 4:
				/* LINTED */
				*((Word *)taddr) = (Word)mv->m_value;
				taddr += 4 * stride;
				break;
			case 8:
				/* LINTED */
				*((unsigned long long *)taddr) = mv->m_value;
				taddr += 8 * stride;
				break;
			default:
				eprintf(lml, ERR_NONE, MSG_INTL(MSG_MOVE_ERR1));
				break;
			}
		}
	}
}
