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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "libelf.h"
#include "decl.h"
#include "msg.h"


unsigned
elf_flagdata(Elf_Data * data, Elf_Cmd cmd, unsigned flags)
{
	unsigned	rc = 0;
	Elf *		elf;
	Elf_Scn *	scn;
	Dnode *		d;

	if (data == 0)
		return (0);
	d = (Dnode *) data;
	scn = d->db_scn;
	elf = scn->s_elf;

	READLOCKS(elf, scn)

	if (cmd == ELF_C_SET) {
		rc = d->db_uflags |= flags;
	} else if (cmd == ELF_C_CLR) {
		rc = d->db_uflags &= ~flags;
	} else
		_elf_seterr(EREQ_FLAG, 0);
	READUNLOCKS(elf, scn)
	return (rc);
}


unsigned int
elf_flagehdr(Elf * elf, Elf_Cmd cmd, unsigned flags)
{
	int	rc;
	if (elf == 0)
		return (0);
	if (cmd == ELF_C_SET) {
		ELFWLOCK(elf)
		rc = elf->ed_ehflags |= flags;
		ELFUNLOCK(elf)
		return (rc);
	}
	if (cmd == ELF_C_CLR) {
		ELFWLOCK(elf)
		rc = elf->ed_ehflags &= ~flags;
		ELFUNLOCK(elf)
		return (rc);
	}
	_elf_seterr(EREQ_FLAG, 0);
	return (0);
}


unsigned
elf_flagelf(Elf * elf, Elf_Cmd cmd, unsigned flags)
{
	int	rc;
	if (elf == 0)
		return (0);
	if (cmd == ELF_C_SET) {
		ELFWLOCK(elf)
		rc = elf->ed_uflags |= flags;
		ELFUNLOCK(elf)
		return (rc);
	}
	if (cmd == ELF_C_CLR) {
		ELFWLOCK(elf)
		rc = elf->ed_uflags &= ~flags;
		ELFUNLOCK(elf)
		return (rc);
	}
	_elf_seterr(EREQ_FLAG, 0);
	return (0);
}


unsigned
elf_flagphdr(Elf * elf, Elf_Cmd cmd, unsigned flags)
{
	int	rc;
	if (elf == 0)
		return (0);
	if (cmd == ELF_C_SET) {
		ELFWLOCK(elf);
		rc = elf->ed_phflags |= flags;
		ELFUNLOCK(elf);
		return (rc);
	}
	if (cmd == ELF_C_CLR) {
		ELFWLOCK(elf);
		rc = elf->ed_phflags &= ~flags;
		ELFUNLOCK(elf);
		return (rc);
	}
	_elf_seterr(EREQ_FLAG, 0);
	return (0);
}


unsigned
elf_flagscn(Elf_Scn * scn, Elf_Cmd cmd, unsigned flags)
{
	unsigned	rc;
	Elf *		elf;

	if (scn == 0)
		return (0);

	elf = scn->s_elf;
	if (cmd == ELF_C_SET) {
		READLOCKS(elf, scn)
		rc = scn->s_uflags |= flags;
		READUNLOCKS(elf, scn)
		return (rc);
	}
	if (cmd == ELF_C_CLR) {
		READLOCKS(elf, scn)
		rc = scn->s_uflags &= ~flags;
		READUNLOCKS(elf, scn)
		return (rc);
	}
	_elf_seterr(EREQ_FLAG, 0);
	return (0);
}


unsigned
elf_flagshdr(Elf_Scn * scn, Elf_Cmd cmd, unsigned flags)
{
	unsigned	rc;
	Elf *		elf;
	if (scn == 0)
		return (0);

	elf = scn->s_elf;
	if (cmd == ELF_C_SET) {
		READLOCKS(elf, scn)
		rc = scn->s_shflags |= flags;
		READUNLOCKS(elf, scn)
		return (rc);
	}
	if (cmd == ELF_C_CLR) {
		READLOCKS(elf, scn)
		rc = scn->s_shflags &= ~flags;
		READUNLOCKS(elf, scn)
		return (rc);
	}
	_elf_seterr(EREQ_FLAG, 0);
	return (0);
}
