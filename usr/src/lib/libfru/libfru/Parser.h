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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_PARSER_H
#define	_PARSER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	__cplusplus
}
#endif

#include "fru_tag.h"
#include "libfrureg.h"
#include "Ancestor.h"

struct PathDef
{
	fru_regdef_t *def;
	static const int lastIteration = -1;
	static const int addIteration = -2;
	int iterIndex; // index of the iteration. (or special)
			// -1 if '$' specified.
			// -2 if '+' specified.
	PathDef *next;

	~PathDef() { delete next; }
};

// returns the top PathData object.
// and a NULL terminated list of Ancestor objects.
// USER MUST delete the PathDef and Ancestor returned.
fru_errno_t fru_field_parser(const char *path, Ancestor **ancestors,
				int *absolute, PathDef **pathDef);

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _PARSER_H */
