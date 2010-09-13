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


char *
elf_rawfile(Elf *elf, size_t *ptr)
{
	register size_t	sz;
	char		*p = 0;

	if (elf == 0) {
		if (ptr != 0)
			*ptr = 0;
		return (0);
	}

	ELFWLOCK(elf)
	if ((sz = elf->ed_fsz) == 0) {
		if (ptr != 0)
			*ptr = 0;
		ELFUNLOCK(elf)
		return (0);
	}

	if (elf->ed_raw != 0)
		p = elf->ed_raw;
	else if (elf->ed_status == ES_COOKED) {
		if ((p = _elf_read(elf->ed_fd, elf->ed_baseoff, sz)) != 0) {
			elf->ed_raw = p;
			elf->ed_myflags |= EDF_RAWALLOC;
		} else
			sz = 0;
	} else {
		p = elf->ed_raw = elf->ed_ident;
		elf->ed_status = ES_FROZEN;
		if (_elf_vm(elf, (size_t)0, elf->ed_fsz) != OK_YES) {
			p = 0;
			sz = 0;
		}
	}
	if (ptr != 0)
		*ptr = sz;
	ELFUNLOCK(elf)
	return (p);
}
