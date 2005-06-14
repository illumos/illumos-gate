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
 *	db_entry.cc
 *
 *	Copyright (c) 1988-2001 by Sun Microsystems, Inc.
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/types.h>
#include <stdio.h>
#include <string.h>

#include "db_headers.h"
#include "db_table.h"  /* must come before db_entry */
#include "db_entry.h"
#include "nisdb_mt.h"

#define	PRINT_WIDTH 32

void
print_entry(entryp location, entry_object *e)
{
	printf("entry at location %d: \n", location);

	if (e == NULL) {
		printf("\tnull object\n");
		return;
	}

	int size = e->en_cols.en_cols_len, i, j, col_width;
	entry_col * entry = e->en_cols.en_cols_val;

	printf("\ttype: %s\n", e->en_type ? e->en_type : "none");
	printf("\tnumber of columns: %d\n", size);

	for (i = 0; i < size; i++) {
		printf("\t\t%d: flags=0x%x, length=%d, value=",
			i, entry[i].ec_flags, entry[i].ec_value.ec_value_len);
		col_width = ((entry[i].ec_value.ec_value_len > PRINT_WIDTH) ?
				PRINT_WIDTH : entry[i].ec_value.ec_value_len);
		for (j = 0; j < col_width; j++) {
			if (entry[i].ec_value.ec_value_val[j] < 32) {
				putchar('^');
				putchar(entry[i].ec_value.ec_value_val[j]+32);
			} else {
				putchar(entry[i].ec_value.ec_value_val[j]);
			}
		}

		putchar('\n');
	}
}

entry_object*
new_entry(entry_object *old)
{
	entry_object* newobj = new entry_object;
	if (newobj == NULL)
	    FATAL3("new_entry:: cannot allocate space", DB_MEMORY_LIMIT,
			NULL);

	if (copy_entry(old, newobj))
		return (newobj);
	else {
	    delete newobj;
	    return (NULL);
	}
}

bool_t
copy_entry(entry_object * old, entry_object *nb)
{
	int tlen, j, i;
	int num_cols = 0;
	entry_col *cols, *newcols = NULL;

	if (old == NULL) return FALSE;

	if (old->en_type == NULL)
		nb->en_type = NULL;
	else {
		nb->en_type = strdup(old->en_type);
		if (nb->en_type == NULL)
			FATAL3(
			    "copy_entry: cannot allocate space for entry type",
			    DB_MEMORY_LIMIT, FALSE);
	}

	num_cols = old->en_cols.en_cols_len;
	cols = old->en_cols.en_cols_val;
	if (num_cols == 0)
		nb->en_cols.en_cols_val = NULL;
	else {
		newcols = new entry_col[num_cols];
		if (newcols == NULL) {
			if (nb->en_type)
			delete nb->en_type;
			FATAL3("copy_entry: cannot allocate space for columns",
				DB_MEMORY_LIMIT, FALSE);
		}
		for (j = 0; j < num_cols; j++) {
			newcols[j].ec_flags = cols[j].ec_flags;
			tlen = newcols[j].ec_value.ec_value_len =
				cols[j].ec_value.ec_value_len;
			newcols[j].ec_value.ec_value_val = new char[ tlen ];
			if (newcols[j].ec_value.ec_value_val == NULL) {
				// cleanup space already allocated
				if (nb->en_type)
					delete nb->en_type;
				for (i = 0; i < j; i++)
					delete newcols[i].ec_value.ec_value_val;
				delete newcols;
				FATAL3(
			"copy_entry: cannot allocate space for column value",
			DB_MEMORY_LIMIT, FALSE);
			}
			memcpy(newcols[j].ec_value.ec_value_val,
				cols[j].ec_value.ec_value_val,
				tlen);
		}
	}
	nb->en_cols.en_cols_len = num_cols;
	nb->en_cols.en_cols_val = newcols;
	return (TRUE);
}

void
free_entry(entry_object * obj)
{
	int i;
	int num_cols;
	entry_col *cols;

	if (obj != NULL) {
		num_cols = obj->en_cols.en_cols_len;
		cols = obj->en_cols.en_cols_val;
		for (i = 0; i < num_cols; i++)
			if (cols[i].ec_value.ec_value_val != NULL)
				delete cols[i].ec_value.ec_value_val;
		if (cols)
			delete cols;
		if (obj->en_type)
			delete obj->en_type;
		delete obj;
	}
}

bool_t
sameEntry(entry_object *a, entry_object *b) {
	uint_t	i;

	if (a == 0)
		return (b == 0);
	if (b == 0)
		return (FALSE);

	if (a->en_type != 0 && b->en_type != 0) {
		if (strcmp(a->en_type, b->en_type) != 0)
			return (FALSE);
	} else if (a->en_type != b->en_type) {
		return (FALSE);
	}

	if (a->en_cols.en_cols_len != b->en_cols.en_cols_len)
		return (FALSE);

	for (i = 0; i < a->en_cols.en_cols_len; i++) {
		if (a->en_cols.en_cols_val[i].ec_flags !=
				b->en_cols.en_cols_val[i].ec_flags)
			return (FALSE);
		if (a->en_cols.en_cols_val[i].ec_value.ec_value_len !=
			b->en_cols.en_cols_val[i].ec_value.ec_value_len)
			return (FALSE);
		if (memcmp(a->en_cols.en_cols_val[i].ec_value.ec_value_val,
			b->en_cols.en_cols_val[i].ec_value.ec_value_val,
			a->en_cols.en_cols_val[i].ec_value.ec_value_len) != 0)
			return (FALSE);
	}

	return (TRUE);
}
