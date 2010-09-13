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
#include <memory.h>
#include <errno.h>
#include "decl.h"
#include "msg.h"

/*
 * This module is compiled twice, the second time having
 * -D_ELF64 defined.  The following set of macros, along
 * with machelf.h, represent the differences between the
 * two compilations.  Be careful *not* to add any class-
 * dependent code (anything that has elf32 or elf64 in the
 * name) to this code without hiding it behind a switch-
 * able macro like these.
 */
#if	defined(_ELF64)

#define	ELFCLASS	ELFCLASS64
#define	elf_newphdr	elf64_newphdr
#define	elf_getehdr	elf64_getehdr
#define	_elf_msize	_elf64_msize
#define	elf_fsize	elf64_fsize

#else	/* else ELF32 */

#define	ELFCLASS	ELFCLASS32
#define	elf_newphdr	elf32_newphdr
#define	elf_getehdr	elf32_getehdr
#define	_elf_msize	_elf32_msize
#define	elf_fsize	elf32_fsize

#endif /* ELF64 */


Phdr *
elf_newphdr(Elf * elf, size_t count)
{
	Elf_Void *	ph;
	size_t		sz;
	Phdr *		rc;
	unsigned	work;

	if (elf == 0)
		return (0);
	ELFRLOCK(elf)
	if (elf->ed_class != ELFCLASS) {
		_elf_seterr(EREQ_CLASS, 0);
		ELFUNLOCK(elf)
		return (0);
	}
	ELFUNLOCK(elf)
	if (elf_getehdr(elf) == 0) {		/* this cooks if necessary */
		_elf_seterr(ESEQ_EHDR, 0);
		return (0);
	}

	/*
	 * Free the existing header if appropriate.  This could reuse
	 * existing space if big enough, but that's unlikely, benefit
	 * would be negligible, and code would be more complicated.
	 */

	ELFWLOCK(elf)
	if (elf->ed_myflags & EDF_PHALLOC) {
		elf->ed_myflags &= ~EDF_PHALLOC;
		rc = elf->ed_phdr;
		free(rc);
	}

	/*
	 * Delete the header if count is zero.
	 */

	ELFACCESSDATA(work, _elf_work)
	if ((sz = count * _elf_msize(ELF_T_PHDR, work)) == 0) {
		elf->ed_phflags &= ~ELF_F_DIRTY;
		elf->ed_phdr = 0;
		((Ehdr*)elf->ed_ehdr)->e_phnum = 0;
		((Ehdr*)elf->ed_ehdr)->e_phentsize = 0;
		elf->ed_phdrsz = 0;
		ELFUNLOCK(elf)
		return (0);
	}

	if ((ph = malloc(sz)) == 0) {
		_elf_seterr(EMEM_PHDR, errno);
		elf->ed_phflags &= ~ELF_F_DIRTY;
		elf->ed_phdr = 0;
		((Ehdr*)elf->ed_ehdr)->e_phnum = 0;
		((Ehdr*)elf->ed_ehdr)->e_phentsize = 0;
		elf->ed_phdrsz = 0;
		ELFUNLOCK(elf)
		return (0);
	}

	elf->ed_myflags |= EDF_PHALLOC;
	(void) memset(ph, 0, sz);
	elf->ed_phflags |= ELF_F_DIRTY;
	/* LINTED */
	((Ehdr*)elf->ed_ehdr)->e_phnum = (Half)count;
	((Ehdr*)elf->ed_ehdr)->e_phentsize
	    /* LINTED */
	    = (Half)elf_fsize(ELF_T_PHDR, 1, work);
	elf->ed_phdrsz = sz;
	elf->ed_phdr = rc = ph;

	ELFUNLOCK(elf)
	return (rc);
}
