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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#include "libelf.h"
#include "decl.h"
#include "msg.h"

size_t
elf_rand(Elf * elf, size_t off)
{
	if (elf == 0)
		return (0);
	ELFWLOCK(elf)
	if (elf->ed_kind != ELF_K_AR) {
		_elf_seterr(EREQ_AR, 0);
		ELFUNLOCK(elf)
		return (0);
	}
	if ((off == 0) || (elf->ed_fsz < off)) {
		_elf_seterr(EREQ_RAND, 0);
		ELFUNLOCK(elf)
		return (0);
	}
	elf->ed_nextoff = off;
	ELFUNLOCK(elf)
	return (off);
}

/*
 * Private function used to obtain the current value of the next
 * offset field for an archive header. Returns 0 for error, and
 * the offset otherwise.
 */
size_t
_elf_getnextoff(Elf *elf)
{
	size_t	off;

	if (elf == NULL)
		return (0);
	ELFWLOCK(elf)
	if (elf->ed_kind != ELF_K_AR) {
		_elf_seterr(EREQ_AR, 0);
		ELFUNLOCK(elf)
		return (0);
	}
	off = elf->ed_nextoff;
	ELFUNLOCK(elf)
	return (off);

}
