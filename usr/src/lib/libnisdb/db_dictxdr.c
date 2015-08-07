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
 *	db_dictxdr.c
 *
 * Copyright 2015 Gary Mills
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "db_dictionary_c.h"
#include "db_dictionary.h"
#include "db_vers_c.h"

extern vers db_update_version;

extern void make_zero(vers*);

/* Special xdr_db_dict_desc that understands optional version number at end. */
bool_t
xdr_db_dict_desc(XDR *xdrs, db_dict_desc *objp)
{

	if (!xdr_db_dict_version(xdrs, &objp->impl_vers))
		return (FALSE);
	if (!xdr_array(xdrs, (char **)&objp->tables.tables_val,
		(uint_t *)&objp->tables.tables_len, ~0,
		sizeof (db_table_desc_p), (xdrproc_t)xdr_db_table_desc_p))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->count))
		return (FALSE);

	if (xdrs->x_op == XDR_DECODE) {
		/* If no version was found, set version to 0. */
		if (!xdr_vers(xdrs, (void**) &db_update_version))
			make_zero(&db_update_version);
		return (TRUE);
	} else if (xdrs->x_op == XDR_ENCODE) {
		/* Always write out version */
		if (!xdr_vers(xdrs, (void**) &db_update_version))
			return (FALSE);
	} /* else XDR_FREE: do nothing */

	return (TRUE);
}
