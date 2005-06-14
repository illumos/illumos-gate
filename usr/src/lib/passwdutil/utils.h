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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _UTILS_H
#define	_UTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Prototypes for utility functions
 */

#ifdef	__cplusplus
extern "C" {
#endif

int dup_pw(struct passwd **, struct passwd *);
int dup_spw(struct spwd **, struct spwd *);
void free_pwd(struct passwd *);
void free_spwd(struct spwd *);

#ifdef	__cplusplus
}
#endif

#endif /* _UTILS_H */
