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

#ifndef _FILE_H
#define	_FILE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * header for the file command
 */

#ifdef __cplusplus
extern "C" {
#endif

extern int f_mkmtab(char *, int, int);
extern int f_ckmtab(char *, int, int);
extern void f_prtmtab(void);
extern intmax_t f_getmaxoffset(int);

#ifdef __cplusplus
}
#endif

#endif /* _FILE_H */
