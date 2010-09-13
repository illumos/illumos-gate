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


char *
elf_strptr(Elf * elf, size_t ndx, size_t off)
{
	Elf_Scn		*s;
	Elf_Data	*d;
	char		*rc;

	if (elf == 0)
		return (0);
	if ((s = elf_getscn(elf, ndx)) == 0) {
		_elf_seterr(EREQ_STRSCN, 0);
		return (0);
	}
	READLOCKS(elf, s)
	if (elf->ed_class == ELFCLASS32) {
		Elf32_Shdr* sh = (Elf32_Shdr*)s->s_shdr;

		if ((sh == 0) || (sh->sh_type != SHT_STRTAB)) {
			_elf_seterr(EREQ_STRSCN, 0);
			READUNLOCKS(elf, s)
			return (0);
		}
	} else if (elf->ed_class == ELFCLASS64) {
		Elf64_Shdr* sh = (Elf64_Shdr*)s->s_shdr;

		if ((sh == 0) || (sh->sh_type != SHT_STRTAB)) {
			_elf_seterr(EREQ_STRSCN, 0);
			READUNLOCKS(elf, s)
			return (0);
		}
	} else {
		_elf_seterr(EREQ_STRSCN, 0);
		READUNLOCKS(elf, s)
		return (0);
	}


	/*
	 * If the layout bit is set, use the offsets and
	 * sizes in the data buffers.  Otherwise, take
	 * data buffers in order.
	 */

	d = 0;
	if (elf->ed_uflags & ELF_F_LAYOUT) {
		while ((d = _elf_locked_getdata(s, d)) != 0) {
			if (d->d_buf == 0)
				continue;
			if ((off >= d->d_off) &&
			    (off < d->d_off + d->d_size)) {
				rc = (char *)d->d_buf + off - d->d_off;
				READUNLOCKS(elf, s)
				return (rc);
			}
		}
	} else {
		size_t	sz = 0, j;
		while ((d = _elf_locked_getdata(s, d)) != 0) {
			if (((j = d->d_align) > 1) && (sz % j != 0)) {
				j -= sz % j;
				sz += j;
				if (off < j)
					break;
				off -= j;
			}
			if (d->d_buf != 0) {
				if (off < d->d_size) {
					rc = (char *)d->d_buf + off;
					READUNLOCKS(elf, s)
					return (rc);
				}
			}
			sz += d->d_size;
			if (off < d->d_size)
				break;
			off -= d->d_size;
		}
	}
	_elf_seterr(EREQ_STROFF, 0);
	READUNLOCKS(elf, s)
	return (0);
}
