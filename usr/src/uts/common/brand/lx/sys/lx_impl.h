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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef	_LX_IMPL_H
#define	_LX_IMPL_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef int64_t (*llfcn_t)();

typedef struct lx_sysent {
	int	sy_flags;
	char	*sy_name;
	llfcn_t	sy_callc;
	char	sy_narg;
} lx_sysent_t;

typedef void (lx_systrace_f)(ulong_t, ulong_t, ulong_t, ulong_t, ulong_t,
    ulong_t, ulong_t);


extern lx_sysent_t lx_sysent[];

extern lx_systrace_f *lx_systrace_entry_ptr;
extern lx_systrace_f *lx_systrace_return_ptr;

extern void lx_brand_systrace_enable(void);
extern void lx_brand_systrace_disable(void);

extern void lx_unsupported(char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LX_IMPL_H */
