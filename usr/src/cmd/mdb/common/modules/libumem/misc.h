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

#ifndef	_MDBMOD_MISC_H
#define	_MDBMOD_MISC_H

#include <mdb/mdb_modapi.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int umem_debug(uintptr_t, uint_t, int, const mdb_arg_t *);

extern int umem_set_standalone(void);
extern ssize_t umem_lookup_by_name(const char *, GElf_Sym *);
extern ssize_t umem_readvar(void *, const char *);

/*
 * Returns non-zero if sym matches libumem*`prefix*
 */
int is_umem_sym(const char *, const char *);

#define	dprintf(x) if (umem_debug_level) { \
	mdb_printf("umem debug: ");  \
	/*CSTYLED*/\
	mdb_printf x ;\
}

#define	dprintf_cont(x) if (umem_debug_level) { \
	/*CSTYLED*/\
	mdb_printf x ;\
}

extern int umem_debug_level;

#ifdef __cplusplus
}
#endif

#endif	/* _MDBMOD_MISC_H */
