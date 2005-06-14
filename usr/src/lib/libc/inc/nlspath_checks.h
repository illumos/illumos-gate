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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _NLSPATH_CHECKS_H
#define	_NLSPATH_CHECKS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stat.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern int nls_safe_open(const char *, struct stat64 *, int *, int);
extern char *check_format(const char *, const char *, int);

#ifdef __cplusplus
}
#endif

#endif /* _NLSPATH_CHECKS_H */
