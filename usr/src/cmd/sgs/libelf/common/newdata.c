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


Elf_Data *
elf_newdata(Elf_Scn * s)
{
	Dnode *		d;
	Elf_Data *	rc;
	Elf *		elf;
	unsigned	work;

	if (s == 0)
		return (0);
	elf = s->s_elf;
	READLOCKS(elf, s)
	if (s->s_index == SHN_UNDEF) {
		_elf_seterr(EREQ_SCNNULL, 0);
		READUNLOCKS(elf, s)
		return (0);
	}

	if ((s->s_myflags & SF_READY) == 0) {
		UPGRADELOCKS(elf, s)
		/*
		 * re-confirm that another 'thread' hasn't come along
		 * and cooked this section while the locks were
		 * obtained.
		 */
		if ((s->s_myflags & SF_READY) == 0)
			(void) _elf_cookscn(s);
		DOWNGRADELOCKS(elf, s)
	}

	/*
	 * If this is the first new node, use the one allocated
	 * in the scn itself.  Update data buffer in both cases.
	 */
	ELFACCESSDATA(work, _elf_work)
	if (s->s_hdnode == 0) {
		s->s_dnode.db_uflags |= ELF_F_DIRTY;
		s->s_dnode.db_myflags |= DBF_READY;
		s->s_hdnode = &s->s_dnode;
		s->s_tlnode = &s->s_dnode;
		s->s_dnode.db_scn = s;
		s->s_dnode.db_data.d_version = work;
		rc = &s->s_dnode.db_data;
		READUNLOCKS(elf, s)
		return (rc);
	}
	if ((d = _elf_dnode()) == 0) {
		READUNLOCKS(elf, s)
		return (0);
	}
	d->db_data.d_version = work;
	d->db_scn = s;
	d->db_uflags |= ELF_F_DIRTY;
	d->db_myflags |= DBF_READY;
	s->s_tlnode->db_next = d;
	s->s_tlnode = d;
	rc = &d->db_data;
	READUNLOCKS(elf, s)
	return (rc);
}
