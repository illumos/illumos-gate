/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#ifndef _PRBK_H
#define	_PRBK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Declarations
 */

void prbk_buffer_list(void);
void prbk_buffer_alloc(int size);
void prbk_buffer_dealloc(void);
void *prbk_pidlist_add(void *, int);
void prbk_pfilter_add(void *);
void prbk_pfilter_drop(void *);
void prbk_set_pfilter_mode(boolean_t);
void prbk_show_pfilter_mode(void);
void prbk_set_tracing(boolean_t);
void prbk_show_tracing(void);
void prbk_warn_pfilter_empty(void);

#ifdef __cplusplus
}
#endif

#endif /* _PRBK_H */
