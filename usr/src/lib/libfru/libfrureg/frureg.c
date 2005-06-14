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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "libfrureg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define	FRU_REVNO 1
#include "frudefs.c"

const int max_data_element_count = sizeof (Element_Defs) /
				sizeof (fru_regdef_t);

const fru_regdef_t *
fru_reg_lookup_def_by_name(const char *elem_name)
{
	fru_regdef_t *ret_def = NULL;
	int i = 0;
	for (i = 0; i < max_data_element_count; i++) {
		ret_def = &(Element_Defs[i]);
		if (strcmp(ret_def->name, elem_name) == 0) {
			return (ret_def);
		}
	}
	return (NULL);
}

const fru_regdef_t *
fru_reg_lookup_def_by_tag(fru_tag_t tag)
{
	fru_regdef_t *ret_def = NULL;
	int i = 0;
	for (i = 0; i < max_data_element_count; i++) {
		ret_def = &(Element_Defs[i]);
		if (ret_def->tagType == get_tag_type(&tag) &&
			ret_def->tagDense == get_tag_dense(&tag) &&
			ret_def->payloadLen == get_payload_length(&tag)) {
			return (ret_def);
		}
	}
	return (NULL);
}

char **
fru_reg_list_entries(unsigned int *num)
{
	char **rc = NULL;
	int number = 0;
	fru_regdef_t *def = NULL;
	int i = 0;

	for (i = 0; i < max_data_element_count; i++) {
		def = &(Element_Defs[i]);
		rc = realloc(rc, sizeof (char *) * (number + 1));
		rc[number] = strdup(def->name);
		number++;
	}

	*num = number;
	return (rc);
}
