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

#ifndef _LIST_H
#define	_LIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/va_list.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	 VFUNC_T	int (*)(void *, __va_list)	/* for casting */
#define	 COMP_T		int (*)(void *, void *)		/* for casting */

extern void **list_append(void **, void *);
extern void **list_append_unique(void **, void *, int (*)(void *, void*));
extern void **list_concatenate(void **, void **);
extern void * list_locate(void **, int (*)(void *, void *), void *);
extern int list_iterate(void **, int (*)(void *, __va_list), ...);

#ifdef __cplusplus
}
#endif

#endif /* _LIST_H */
