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

#ifndef _CLNT_H
#define	_CLNT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAXCOLOR	256	/* Max size of a static color string */
#define	MIN_CMW_LEN	8	/* minimum length of clipped CMW Label */
#define	MIN_SL_LEN	3	/* minimum length of clipped SL */
#define	MIN_IL_LEN	3	/* minimum length of clipped IL */
#define	MIN_CLR_LEN	3	/* minimum length of clipped Clearance */

#define	ALLOC_CHUNK	1024	/* size of chunk for sb*tos allocs */

extern int alloc_string(char **, size_t, char);
extern void set_label_view(uint_t *, uint_t);
#ifdef	__cplusplus
}
#endif

#endif	/* _CLNT_H */
