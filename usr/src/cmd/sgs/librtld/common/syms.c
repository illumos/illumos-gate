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
 *
 * Update the symbol table entries:
 *
 *  o	If addr is non-zero then every symbol entry is updated to indicate the
 *	new location to which the object will be mapped.
 *
 *  o	The address of the `_edata' and `_end' symbols, and their associated
 *	section, is updated to reflect any new heap addition.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<libelf.h>
#include	<string.h>
#include	"sgs.h"
#include	"machdep.h"
#include	"msg.h"
#include	"_librtld.h"

void
update_sym(Cache *cache, Cache *_cache, Addr edata, Half endx, Addr addr)
{
	char	*strs;
	Sym	*syms;
	Shdr	*shdr;
	Xword	symn, cnt;

	/*
	 * Set up to read the symbol table and its associated string table.
	 */
	shdr = _cache->c_shdr;
	syms = (Sym *)_cache->c_data->d_buf;
	symn = shdr->sh_size / shdr->sh_entsize;

	strs = (char *)cache[shdr->sh_link].c_data->d_buf;

	/*
	 * Loop through the symbol table looking for `_end' and `_edata'.
	 */
	for (cnt = 0; cnt < symn; cnt++, syms++) {
		char	*name = strs + syms->st_name;

		if (addr) {
			if (syms->st_value)
				syms->st_value += addr;
		}

		if ((name[0] != '_') || (name[1] != 'e'))
			continue;
		if (strcmp(name, MSG_ORIG(MSG_SYM_END)) &&
		    strcmp(name, MSG_ORIG(MSG_SYM_EDATA)))
			continue;

		syms->st_value = edata + addr;
		if (endx)
			syms->st_shndx = endx;
	}
}

int
syminfo(Cache *_cache, Alist **nodirect)
{
	Syminfo	*info;
	Shdr	*shdr;
	Word	num, ndx;

	shdr = _cache->c_shdr;
	info = (Syminfo *)_cache->c_data->d_buf;
	num = (Word)(shdr->sh_size / shdr->sh_entsize);

	/*
	 * Traverse the syminfo section recording the index of all nodirect
	 * symbols.
	 */
	for (ndx = 1, info++; ndx < num; ndx++, info++) {
		if ((info->si_flags & SYMINFO_FLG_NOEXTDIRECT) == 0)
			continue;

		if (alist_append(nodirect, &ndx, sizeof (Word), 20) == 0)
			return (1);
	}
	return (0);
}
