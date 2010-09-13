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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ldap_scheme.h"
#include "ldap_util.h"
#include "ldap_nisdbquery.h"


/*
 * Input:  A db_query where the 'which_index' fields refer to the schema
 *         columns.
 * Output: A db_query where the 'which_index' fields refer to the table
 *         columns.
 */
db_query *
schemeQuery2Query(db_query *qin, db_scheme *s) {
	db_query	*q;
	int		i;
	char		*myself = "schemeQuery2Query";

	q = cloneQuery(qin, 0);
	if (q == 0 || s == 0)
		return (q);

	for (i = 0; i < q->components.components_len; i++) {
		int	index = q->components.components_val[i].which_index;
		if (index >= s->keys.keys_len) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: query index %d out-of-range (%d)",
				myself, index, s->keys.keys_len-1);
			freeQuery(q);
			return (0);
		}
		q->components.components_val[i].which_index =
			s->keys.keys_val[index].column_number - 1;
	}

	return (q);
}

static const char	*dirCol = "name";

/*
 * Input:  A db_query where the 'which_index' fields refer to the scheme
 *         columns, space for a nis_attr array with at least q->components->
 *	   components_len elements, a scheme, and a __nis_table_mapping_t
 *	   (for column names).
 * Output: A nis_attr structure with the searchable columns.
 */
nis_attr *
schemeQuery2nisAttr(db_query *q, nis_attr *space, db_scheme *s,
		__nis_table_mapping_t *t, int *numAttr) {
	nis_attr	*a;
	int		na, i, nc;
	char		**col;
	char		*myself = "schemeQuery2nisAttr";

	if (q == 0 || space == 0 || s == 0 || t == 0 || numAttr == 0)
		return (0);

	/*
	 * A table will have the column names stored in the mapping
	 * structure, while a directory only has a single column
	 * called "name". The latter isn't stored in the mapping,
	 * so we create a column name array for a directory.
	 */
	if (t->numColumns > 0) {
		col = t->column;
		nc = t->numColumns;
	} else {
		if (t->objType == NIS_DIRECTORY_OBJ) {
			col = (char **)&dirCol;
			nc = 1;
		} else {
			return (0);
		}
	}

	a = space;

	for (i = 0, na = 0; i < q->components.components_len; i++) {
		int	index;

		if (q->components.components_val[i].which_index >=
				s->keys.keys_len) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: query index %d out-of-range (%d)",
				myself,
				q->components.components_val[i].which_index,
				s->keys.keys_len-1);
			return (0);
		}

		index = s->keys.keys_val[i].column_number - 1;
		if (index >= nc) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: column index out-of-range (%d >= %d)",
				myself, index, nc);
			return (0);
		}

		a[na].zattr_ndx = col[index];
		a[na].zattr_val.zattr_val_val =	q->components.
			components_val[i].index_value->itemvalue.itemvalue_val;
		a[na].zattr_val.zattr_val_len = q->components.
			components_val[i].index_value->itemvalue.itemvalue_len;
		na++;
	}

	*numAttr = na;

	return (a);
}
