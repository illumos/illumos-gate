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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#include "libelf.h"
#include "decl.h"
#include "msg.h"


Elf_Scn *
elf_newscn(Elf * elf)
{
	Elf_Scn	*	tl;

	if (elf == 0)
		return (0);

	ELFWLOCK(elf)
	/*
	 * if no sections yet, the file either isn't cooked
	 * or it truly is empty.  Then allocate shdr[0]
	 */
	if ((elf->ed_hdscn == 0) && (_elf_cook(elf) != OK_YES)) {
		ELFUNLOCK(elf)
		return (0);
	}
	if (elf->ed_ehdr == 0) {
		_elf_seterr(ESEQ_EHDR, 0);
		ELFUNLOCK(elf)
		return (0);
	}

	if (elf->ed_class == ELFCLASS32) {
		Snode32	*s;

		if (elf->ed_hdscn == 0)	{
			if ((s = _elf32_snode()) == 0) {
				ELFUNLOCK(elf)
				return (0);
			}
			s->sb_scn.s_elf = elf;
			elf->ed_hdscn = elf->ed_tlscn = &s->sb_scn;
			s->sb_scn.s_uflags |= ELF_F_DIRTY;
		}
		if ((s = _elf32_snode()) == 0) {
			ELFUNLOCK(elf)
			return (0);
		}
		tl = elf->ed_tlscn;
		s->sb_scn.s_elf = elf;
		s->sb_scn.s_index = tl->s_index + 1;
		elf->ed_tlscn = tl->s_next = &s->sb_scn;
		((Elf32_Ehdr *)elf->ed_ehdr)->e_shnum
		    /* LINTED */
		    = (Elf32_Half)(tl->s_index + 2);
		s->sb_scn.s_uflags |= ELF_F_DIRTY;
		tl = &s->sb_scn;
		ELFUNLOCK(elf)
		return (tl);
	} else if (elf->ed_class == ELFCLASS64) {
		Snode64	*s;

		if (elf->ed_hdscn == 0)	{
			if ((s = _elf64_snode()) == 0) {
				ELFUNLOCK(elf)
				return (0);
			}
			s->sb_scn.s_elf = elf;
			elf->ed_hdscn = elf->ed_tlscn = &s->sb_scn;
			s->sb_scn.s_uflags |= ELF_F_DIRTY;
		}
		if ((s = _elf64_snode()) == 0) {
			ELFUNLOCK(elf)
			return (0);
		}
		tl = elf->ed_tlscn;
		s->sb_scn.s_elf = elf;
		s->sb_scn.s_index = tl->s_index + 1;
		elf->ed_tlscn = tl->s_next = &s->sb_scn;
		((Elf64_Ehdr *)elf->ed_ehdr)->e_shnum
		    /* LINTED */
		    = (Elf64_Half)(tl->s_index + 2);
		s->sb_scn.s_uflags |= ELF_F_DIRTY;
		tl = &s->sb_scn;
		ELFUNLOCK(elf)
		return (tl);
	} else {
		_elf_seterr(EREQ_CLASS, 0);
		ELFUNLOCK(elf)
		return (0);
	}
}
