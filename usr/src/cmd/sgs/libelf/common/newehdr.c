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

#define	ELFCLASS		ELFCLASS64
#define	_elf_ehdr_init		_elf64_ehdr_init
#define	elf_newehdr		elf64_newehdr
#define	getehdr			elf64_getehdr

#else	/* else ELF32 */

#define	ELFCLASS		ELFCLASS32
#define	_elf_ehdr_init		_elf32_ehdr_init
#define	elf_newehdr		elf32_newehdr
#define	getehdr			elf32_getehdr

#endif	/* ELF64 */


Ehdr *
elf_newehdr(Elf * elf)
{
	Ehdr	*eh;

	if (elf == 0)
		return (0);

	/*
	 * If reading file, return its hdr
	 */

	ELFWLOCK(elf)
	if (elf->ed_myflags & EDF_READ) {
		ELFUNLOCK(elf)
		if ((eh = (Ehdr *)getehdr(elf)) != 0) {
			ELFWLOCK(elf)
			elf->ed_ehflags |= ELF_F_DIRTY;
			ELFUNLOCK(elf)
		}
		return (eh);
	}

	/*
	 * Writing file
	 */

	if (elf->ed_class == ELFCLASSNONE)
		elf->ed_class = ELFCLASS;
	else if (elf->ed_class != ELFCLASS) {
		_elf_seterr(EREQ_CLASS, 0);
		ELFUNLOCK(elf)
		return (0);
	}
	ELFUNLOCK(elf);
	if ((eh = (Ehdr *)getehdr(elf)) != 0) {	/* this cooks if necessary */
		ELFWLOCK(elf)
		elf->ed_ehflags |= ELF_F_DIRTY;
		ELFUNLOCK(elf)
		return (eh);
	}
	ELFWLOCK(elf)

	if ((eh = (Ehdr *)malloc(sizeof (Ehdr))) == 0) {
		_elf_seterr(EMEM_EHDR, errno);
		ELFUNLOCK(elf)
		return (0);
	}
	*eh = _elf_ehdr_init;
	elf->ed_myflags |= EDF_EHALLOC;
	elf->ed_ehflags |= ELF_F_DIRTY;
	elf->ed_ehdr = eh;
	ELFUNLOCK(elf)
	return (eh);
}
