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

#ifndef	_KGREP_H
#define	_KGREP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_modapi.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef int kgrep_cb_func(uintptr_t, uintptr_t, void *);

#define	KGREP_USAGE \
	":[-v] [-d dist|-m mask|-M invmask] [-a minad] [-A maxad] [-s sz]"

extern int kgrep(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void kgrep_help(void);

extern int kgrep_subr(kgrep_cb_func *, void *);
extern size_t kgrep_subr_pagesize(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _KGREP_H */
