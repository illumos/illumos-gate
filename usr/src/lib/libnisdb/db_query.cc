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
 *	db_query.cc
 *
 *	Copyright (c) 1988-2000 by Sun Microsystems, Inc.
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "db_headers.h"
#include "db_query.h"
#include "nisdb_mt.h"
#include <string.h>

/* Returns db_query containing the index values as obtained from 'attrlist.' */
db_query::db_query(db_scheme * scheme, int size, nis_attr* attrlist)
{
	int i;
	num_components = size;
	components = new db_qcomp[size];

	if (components == NULL) {
		num_components = 0;
		FATAL(
		    "db_query::db_query: cannot allocate space for components",
		    DB_MEMORY_LIMIT);
	}

	for (i = 0; i < size; i++) {
		if (!scheme->find_index(attrlist[i].zattr_ndx,
					&(components[i].which_index))) {
			syslog(LOG_ERR, "db_query::db_query: bad index (%s)",
				attrlist[i].zattr_ndx);
			clear_components(i);
			return;
		}
		components[i].index_value = new
				item(attrlist[i].zattr_val.zattr_val_val,
					attrlist[i].zattr_val.zattr_val_len);
		if (components[i].index_value  == NULL) {
			clear_components(i);
			FATAL(
			"db_query::db_query:cannot allocate space for index",
			DB_MEMORY_LIMIT);
		}
	}
}

/*
 * Returns a newly db_query containing the index values as
 * obtained from the given object.  The object itself,
 * along with information on the scheme given, will determine
 * which values are extracted from the object and placed into the query.
 * Returns an empty query if 'obj' is not a valid entry.
 * Note that space is allocated for the query and the index values
 * (i.e. do not share pointers with strings in 'obj'.)
*/
db_query::db_query(db_scheme *scheme, entry_object_p obj)
{
	num_components = scheme->numkeys();	// scheme's view of key count
	db_key_desc *keyinfo = scheme->keyloc();

	int objsize = obj->en_cols.en_cols_len;	// total num columns in obj */
	struct entry_col * objcols = obj->en_cols.en_cols_val;

	/* components of query to be returned */
	components = new db_qcomp[num_components];

	int wherein_obj, i;
	if (components == NULL) {
		FATAL(
		    "db_query::db_query: cannot allocate space for components",
		    DB_MEMORY_LIMIT);
	}

	/* fill in each component of query */
	for (i = 0; i < num_components; i++) {
		components[i].which_index = i;		// index i
		wherein_obj = keyinfo[i].column_number; // column in entry obj
		if (wherein_obj >= objsize) {
			syslog(LOG_ERR,
"db_query::column %d cannot occur in object with %d columns (start counting at 0)\n",
				wherein_obj, objsize);
			clear_components(i);		// clean up
			return;
		}

		components[i].index_value = new
			item(objcols[wherein_obj].ec_value.ec_value_val,
				objcols[wherein_obj].ec_value.ec_value_len);
		if (components[i].index_value  == NULL) {
			clear_components(i);
			FATAL(
			"db_query::db_query:cannot allocate space for index",
			DB_MEMORY_LIMIT);
		}

		/* do something about null keys? */
	}
}

void
db_query::clear_components(int how_many)
{
	int i;
	if (components) {
		for (i = 0; i < how_many; i++)
			if (components[i].index_value)
				delete components[i].index_value;
		delete components;
		components = NULL;
	}
	num_components = 0;
}

/* destructor */
db_query::~db_query()
{
	clear_components(num_components);
}

/* Print all components of this query to stdout. */
void
db_query::print()
{
	int i;
	for (i = 0; i < num_components; i++) {
		printf("%d: ", components[i].which_index);
		components[i].index_value->print();
		putchar('\n');
	}
}
