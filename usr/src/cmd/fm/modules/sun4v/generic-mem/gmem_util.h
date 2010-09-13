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

#ifndef _GMEM_UTIL_H
#define	_GMEM_UTIL_H


#include <sys/param.h>
#include <sys/param.h>
#include <fm/fmd_api.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gmem_list {
	struct gmem_list *l_prev;
	struct gmem_list *l_next;
} gmem_list_t;

#define	gmem_list_prev(elem)	((void *)(((gmem_list_t *)(elem))->l_prev))
#define	gmem_list_next(elem)	((void *)(((gmem_list_t *)(elem))->l_next))

extern void gmem_list_append(gmem_list_t *, void *);
extern void gmem_list_prepend(gmem_list_t *, void *);
extern void gmem_list_insert_before(gmem_list_t *, void *, void *);
extern void gmem_list_insert_after(gmem_list_t *, void *, void *);
extern void gmem_list_delete(gmem_list_t *, void *);

extern int gmem_set_errno(int);
extern void *gmem_buf_read(fmd_hdl_t *, fmd_case_t *, const char *, size_t);
extern void gmem_bufname(char *, size_t, const char *, ...);
extern void gmem_vbufname(char *, size_t, const char *, va_list);
#ifdef __cplusplus
}
#endif

#endif /* _GMEM_UTIL_H */
