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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _RCAPD_MAPPING_H
#define	_RCAPD_MAPPING_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * List of mappings.
 */
typedef struct lmapping {
	uintptr_t	lm_addr;
	size_t		lm_size;
	struct lmapping	*lm_next;
} lmapping_t;

extern int  lmapping_contains(lmapping_t *, uintptr_t, size_t);
extern void lmapping_free(lmapping_t **);
extern int  lmapping_insert(lmapping_t **, uintptr_t, size_t);
extern int  lmapping_remove(lmapping_t **, uintptr_t, size_t);

#ifdef	__cplusplus
}
#endif

#endif /* _RCAPD_MAPPING_H */
