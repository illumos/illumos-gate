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

#include <stdlib.h>
#include <errno.h>
#include <libelf.h>
#include "decl.h"
#include "msg.h"


/*
 * Convert archive symbol table to memory format
 *	This takes a pointer to file's archive symbol table,
 *	alignment unconstrained.  Returns null terminated
 *	vector of Elf_Arsym structures.
 *
 *	Symbol table is the following:
 *		# offsets	4-byte word
 *		offset[0...]	4-byte word each
 *		strings		null-terminated, for offset[x]
 */


#define	get4(p)	((((((p[0]<<8)+p[1])<<8)+p[2])<<8)+p[3])


static Elf_Void	*arsym	_((Byte *, size_t, size_t *));


Elf_Void *
arsym(Byte *off, size_t sz, size_t *e)
{
	char		*endstr = (char *)off + sz;
	register char	*str;
	Byte		*endoff;
	Elf_Void	*oas;

	{
		register size_t	n;

		if (sz < 4 || (sz - 4) / 4 < (n = get4(off))) {
			_elf_seterr(EFMT_ARSYMSZ, 0);
			return (0);
		}
		off += 4;
		endoff = off + n * 4;

		/*
		 * string table must be present, null terminated
		 */

		if (((str = (char *)endoff) >= endstr) ||
		    (*(endstr - 1) != '\0')) {
			_elf_seterr(EFMT_ARSYM, 0);
			return (0);
		}

		/*
		 * overflow can occur here, but not likely
		 */

		*e = n + 1;
		n = sizeof (Elf_Arsym) * (n + 1);
		if ((oas = malloc(n)) == 0) {
			_elf_seterr(EMEM_ARSYM, errno);
			return (0);
		}
	}
	{
		register Elf_Arsym	*as = (Elf_Arsym *)oas;

		while (off < endoff) {
			if (str >= endstr) {
				_elf_seterr(EFMT_ARSYMSTR, 0);
				free(oas);
				return (0);
			}
			as->as_off = get4(off);
			as->as_name = str;
			as->as_hash = elf_hash(str);
			++as;
			off += 4;
			while (*str++ != '\0')
				/* LINTED */
				;
		}
		as->as_name = 0;
		as->as_off = 0;
		as->as_hash = ~(unsigned long)0L;
	}
	return (oas);
}


Elf_Arsym *
elf_getarsym(Elf *elf, size_t *ptr)
{
	Byte		*as;
	size_t		sz;
	Elf_Arsym	*rc;

	if (ptr != 0)
		*ptr = 0;
	if (elf == 0)
		return (0);
	ELFRLOCK(elf);
	if (elf->ed_kind != ELF_K_AR) {
		ELFUNLOCK(elf);
		_elf_seterr(EREQ_AR, 0);
		return (0);
	}
	if ((as = (Byte *)elf->ed_arsym) == 0) {
		ELFUNLOCK(elf);
		return (0);
	}
	if (elf->ed_myflags & EDF_ASALLOC) {
		if (ptr != 0)
			*ptr = elf->ed_arsymsz;
		ELFUNLOCK(elf);
		/* LINTED */
		return ((Elf_Arsym *)as);
	}
	/*
	 * We're gonna need a write lock.
	 */
	ELFUNLOCK(elf)
	ELFWLOCK(elf)
	sz = elf->ed_arsymsz;
	if (_elf_vm(elf, (size_t)(as - (Byte *)elf->ed_ident), sz) !=
	    OK_YES) {
		ELFUNLOCK(elf);
		return (0);
	}
	if ((elf->ed_arsym = arsym(as, sz, &elf->ed_arsymsz)) == 0) {
		ELFUNLOCK(elf);
		return (0);
	}
	elf->ed_myflags |= EDF_ASALLOC;
	if (ptr != 0)
		*ptr = elf->ed_arsymsz;
	rc = (Elf_Arsym *)elf->ed_arsym;
	ELFUNLOCK(elf);
	return (rc);
}
