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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SIZED_ARRAY_H
#define	_SIZED_ARRAY_H

/*
 * Like calloc, but with mechanisms to get the size of the allocated
 * area given only the pointer.
 */

#ifdef __cplusplus
extern "C" {
#endif

void *sized_array(size_t n, size_t sz);
void sized_array_free(void *p);
size_t sized_array_n(void *p);
size_t sized_array_sz(void *p);

#ifdef __cplusplus
}
#endif

#endif /* _SIZED_ARRAY_H */
