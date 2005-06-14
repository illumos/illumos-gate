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

#ifndef _INJ_STRING_H
#define	_INJ_STRING_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#include <inj_list.h>
#include <inj_hash.h>

#ifdef __cplusplus
extern "C" {
#endif

extern char *inj_strdup(const char *);
extern char *inj_strndup(const char *, size_t);
extern void inj_strfree(const char *);

extern int inj_strtoll(const char *, int, longlong_t *);
extern int inj_strtoull(const char *, int, u_longlong_t *);
extern int inj_strtime(hrtime_t *, const char *);

extern void inj_strhash_create(inj_hash_t *);
extern int inj_strhash_insert(inj_hash_t *, const char *, uintmax_t);
extern inj_var_t *inj_strhash_lookup(inj_hash_t *, const char *);
extern void inj_strhash_destroy(inj_hash_t *);

#ifdef __cplusplus
}
#endif

#endif /* _INJ_STRING_H */
