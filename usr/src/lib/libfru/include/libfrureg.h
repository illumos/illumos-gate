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

#ifndef	_LIBFRUREG_H
#define	_LIBFRUREG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "libfru.h"
#include "fru_tag.h"

#define	REGDEF_VERSION 1
typedef struct {
	int version;
	const char *name;
	fru_tagtype_t tagType;
	int tagDense;
	int payloadLen;
	int dataLength;
	fru_datatype_t dataType;
	fru_displaytype_t dispType;
	fru_which_t purgeable;
	fru_which_t relocatable;
	int enumCount;
	fru_enum_t *enumTable;
	int iterationCount;
	fru_itertype_t iterationType;
	const char *exampleString;
} fru_regdef_t;

extern const fru_regdef_t *fru_reg_lookup_def_by_name(const char *elem_name);
extern const fru_regdef_t *fru_reg_lookup_def_by_tag(fru_tag_t tag);
extern char **fru_reg_list_entries(unsigned int *num);

#ifdef __cplusplus
}
#endif

#endif /* _LIBFRUREG_H */
