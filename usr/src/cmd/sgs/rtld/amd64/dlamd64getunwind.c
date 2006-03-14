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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Block comment which describes the contents of this file.
 */

#include <_synonyms.h>
#include <string.h>
#include <dlfcn.h>
#include <debug.h>
#include <_rtld.h>
#include <_elf.h>
#include <msg.h>

#include <stdio.h>

static Dl_amd64_unwindinfo *
getunwind_core(Rt_map *clmp, void *pc, Dl_amd64_unwindinfo *unwindinfo)
{
	/*
	 * Validate the version information.
	 */
	if (unwindinfo == NULL) {
		eprintf(LIST(clmp), ERR_FATAL, MSG_INTL(MSG_ARG_ILLVAL));
		return (0);
	}
	if ((unwindinfo->dlui_version < DLUI_VERS_1) ||
	    (unwindinfo->dlui_version > DLUI_VERS_CURRENT)) {
		eprintf(LIST(clmp), ERR_FATAL, MSG_INTL(MSG_UNW_BADVERS),
		    DLUI_VERS_CURRENT, unwindinfo->dlui_version);
		return (0);
	}

	/*
	 * Clean out the structure.
	 */
	unwindinfo->dlui_flags = 0;
	unwindinfo->dlui_objname = 0;
	unwindinfo->dlui_unwindstart = 0;
	unwindinfo->dlui_unwindend = 0;
	unwindinfo->dlui_segstart = 0;
	unwindinfo->dlui_segend = 0;

	if (clmp) {
		Mmap	*immap;

		unwindinfo->dlui_objname = PATHNAME(clmp);

		/*
		 * Scan through the mmaps of this object to get the specific
		 * segment found.
		 */
		for (immap = MMAPS(clmp); immap->m_vaddr; immap++) {
			if (((caddr_t)pc >= immap->m_vaddr) &&
			    ((caddr_t)pc < (immap->m_vaddr + immap->m_msize))) {
				break;
			}
		}
		unwindinfo->dlui_segstart = immap->m_vaddr;
		unwindinfo->dlui_segend = immap->m_vaddr + immap->m_msize;

		if (PTUNWIND(clmp) && (immap->m_vaddr)) {
			uintptr_t   base;

			if (FLAGS(clmp) & FLG_RT_FIXED)
				base = 0;
			else
				base = ADDR(clmp);

			unwindinfo->dlui_unwindstart =
			    (void *)(PTUNWIND(clmp)->p_vaddr + base);
			unwindinfo->dlui_unwindend =
			    (void *)(PTUNWIND(clmp)->p_vaddr +
			    PTUNWIND(clmp)->p_memsz + base);

		} else if (immap->m_vaddr)
			unwindinfo->dlui_flags |= DLUI_FLG_NOUNWIND;
		else
			unwindinfo->dlui_flags |=
			    DLUI_FLG_NOUNWIND | DLUI_FLG_NOOBJ;
	} else {
		/*
		 * No object found.
		 */
		unwindinfo->dlui_flags = DLUI_FLG_NOOBJ | DLUI_FLG_NOUNWIND;
	}
	return (unwindinfo);
}

#pragma weak dlamd64getunwind = _dlamd64getunwind

Dl_amd64_unwindinfo *
_dlamd64getunwind(void *pc, Dl_amd64_unwindinfo *unwindinfo)
{
	Rt_map	*clmp;
	int	entry = enter();

	clmp = _caller(caller(), CL_NONE);

	unwindinfo = getunwind_core(clmp, pc, unwindinfo);

	if (entry)
		leave(LIST(clmp));
	return (unwindinfo);
}
