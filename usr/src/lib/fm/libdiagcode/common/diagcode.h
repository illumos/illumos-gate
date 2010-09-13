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

#ifndef	_FM_DIAGCODE_H
#define	_FM_DIAGCODE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following interfaces are private to Sun and should
 * not be used by applications developed outside of Sun.
 * They may change incompatibly or go away without notice.
 */

#define	FM_DC_VERSION   1	/* pass to fm_dc_opendict() */

typedef struct fm_dc_handle fm_dc_handle_t;

/* open a dictionary, return opaque handle */
fm_dc_handle_t *fm_dc_opendict(int version, const char *dirpath,
    const char *dictname);

/* close a dictionary */
void fm_dc_closedict(fm_dc_handle_t *dhp);

/* return maximum length (in bytes) of diagcodes for a given dictionary */
size_t fm_dc_codelen(fm_dc_handle_t *dhp);

/* return number of strings in key for a given dictionary, plus 1 for null */
int fm_dc_maxkey(fm_dc_handle_t *dhp);

/* given a key, construct a diagcode */
int fm_dc_key2code(fm_dc_handle_t *dhp,
    const char *key[], char *code, size_t maxcode);

/* given a diagcode, return the key (array of strings) */
int fm_dc_code2key(fm_dc_handle_t *dhp, const char *code,
    char *key[], int maxkey);

/* return the right-hand side of a names property from the dict header */
const char *fm_dc_getprop(fm_dc_handle_t *dhp, const char *name);

#ifdef	__cplusplus
}
#endif

#endif	/* _FM_DIAGCODE_H */
