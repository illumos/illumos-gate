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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FMD_STRING_H
#define	_FMD_STRING_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <strings.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <fmd_alloc.h>

extern char *fmd_strdup(const char *, int);
extern void fmd_strfree(char *);

extern const char *fmd_strbasename(const char *);
extern char *fmd_strdirname(char *);

extern ulong_t fmd_strhash(const char *);
extern size_t fmd_stresc2chr(char *);
extern const char *fmd_strbadid(const char *, int);
extern int fmd_strmatch(const char *, const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_STRING_H */
