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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file provides a text translation service for NT status codes.
 */

#include <stdio.h>
#include <stdlib.h>

/*
 * Include the generated file with ntx_table[]
 * See smb_status_gen.awk
 */
#include "smb_status_tbl.h"
static const int ntx_rows = sizeof (ntx_table) / sizeof (ntx_table[0]);

/*
 * Comparison function for bsearch(3C).
 */
static int
xlate_compare(const void *vkey, const void *vrow)
{
	const smb_status_table_t *key = vkey;
	const smb_status_table_t *row = vrow;

	if (key->value == row->value)
		return (0);
	if (key->value < row->value)
		return (-1);
	return (1);
}

/*
 * Translate an ntstatus value to a meaningful text string. If there isn't
 * a corresponding text string in the table, the text representation of the
 * status value is returned. This uses a static buffer so there is a
 * possible concurrency issue if the caller hangs on to this pointer for a
 * while but it should be harmless and really remote since the value will
 * almost always be found in the table.
 */
const char *
xlate_nt_status(unsigned int ntstatus)
{
	static char unknown[16];
	smb_status_table_t key;
	const smb_status_table_t *tep;

	key.value = ntstatus;
	key.name = NULL;
	tep = bsearch(&key, ntx_table, ntx_rows,
	    sizeof (*tep), xlate_compare);

	if (tep != NULL)
		return (tep->name);

	(void) sprintf(unknown, "0x%08X", ntstatus);
	return ((const char *)unknown);
}
