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
 * Copyright 2015 Gary Mills
 */

/*
 * This is a non-recursive version of XDR routine used for db_index_entry
 * type.
 */

#include <sys/types.h>
#include <sys/syslog.h>
#include <stdio.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <memory.h>
#include "db_index_entry_c.h"
#include "db_table_c.h"
#include "xdr_nullptr.h"

bool_t
xdr_db_index_entry(xdrs, objp)
	register XDR *xdrs;
	db_index_entry *objp;
{
	bool_t	more_data;
	register db_index_entry *ep = objp;
	register db_index_entry *loc;
	register db_index_entry *freeptr = NULL;

	for (;;) {
		if (!xdr_u_long(xdrs, &ep->hashval))
			return (FALSE);
		if (!xdr_pointer(xdrs, (char **)&ep->key, sizeof (item),
			(xdrproc_t) xdr_item))
			return (FALSE);
		if (!xdr_entryp(xdrs, &ep->location))
			return (FALSE);
		if (!xdr_nullptr(xdrs, &ep->next_result))
			return (FALSE);

		/*
		 * The following code replaces the call to
		 * xdr_pointer(
		 *	xdrs,
		 *	(char **)&ep->next,
		 *	sizeof (db_index_entry),
		 *	(xdrproc_t) xdr_db_index_entry))
		 *
		 * It's a modified version of xdr_refer.c from the rpc library:
		 *	@(#)xdr_refer.c		1.8	92/07/20 SMI
		 */


		/*
		 * the following assignment to more_data is only useful when
		 * encoding and freeing.  When decoding, more_data will be
		 * filled by the xdr_bool() routine.
		 */
		more_data = (ep->next != NULL);
		if (! xdr_bool(xdrs, &more_data))
			return (FALSE);
		if (! more_data) {
			ep->next = NULL;
			break;
		}

		loc = ep->next;


		switch (xdrs->x_op) {
		case XDR_DECODE:
			if (loc == NULL) {
				ep->next = loc = (db_index_entry *)
					mem_alloc(sizeof (db_index_entry));
				if (loc == NULL) {
					syslog(LOG_ERR,
				"xdr_db_index_entry: mem_alloc failed");
					return (FALSE);
				}
				memset(loc, 0, sizeof (db_index_entry));
			}
			break;
		case XDR_FREE:
			if (freeptr != NULL) {
				mem_free(freeptr, sizeof (db_index_entry));
			} else
				ep->next = NULL;
			freeptr = loc;
			break;
		}

		if (loc == NULL)
			break;
		ep = loc;
	}	/* for loop */

	if ((freeptr != NULL) && (xdrs->x_op == XDR_FREE)) {
		mem_free(freeptr, sizeof (db_index_entry));
	}

	return (TRUE);
}


bool_t
xdr_db_index_entry_p(xdrs, objp)
	register XDR *xdrs;
	db_index_entry_p *objp;
{

	if (!xdr_pointer(xdrs, (char **)objp, sizeof (db_index_entry),
		(xdrproc_t) xdr_db_index_entry))
		return (FALSE);
	return (TRUE);
}



bool_t
xdr_db_free_entry(xdrs, objp)
	register XDR *xdrs;
	db_free_entry *objp;
{
	bool_t	more_data;
	register db_free_entry *ep = objp;
	register db_free_entry *loc;
	register db_free_entry *freeptr = NULL;

	for (;;) {
		if (!xdr_entryp(xdrs, &ep->where))
			return (FALSE);

		/*
		 * The following code replaces the call to
		 * xdr_pointer(
		 *	xdrs,
		 *	(char **)&ep->next,
		 *	sizeof (db_free_entry),
		 *	(xdrproc_t) xdr_db_free_entry))
		 *
		 * It's a modified version of xdr_refer.c from the rpc library:
		 *	@(#)xdr_refer.c		1.8	92/07/20 SMI
		 */


		/*
		 * the following assignment to more_data is only useful when
		 * encoding and freeing.  When decoding, more_data will be
		 * filled by the xdr_bool() routine.
		 */
		more_data = (ep->next != NULL);
		if (! xdr_bool(xdrs, &more_data))
			return (FALSE);
		if (! more_data) {
			ep->next = NULL;
			break;
		}

		loc = ep->next;


		switch (xdrs->x_op) {
		case XDR_DECODE:
			if (loc == NULL) {
				ep->next = loc = (db_free_entry *)
					mem_alloc(sizeof (db_free_entry));
				if (loc == NULL) {
					syslog(LOG_ERR,
				"db_free_entry: mem_alloc failed");
					return (FALSE);
				}
				memset(loc, 0, sizeof (db_free_entry));
			}
			break;
		case XDR_FREE:
			if (freeptr != NULL) {
				mem_free(freeptr, sizeof (db_free_entry));
			} else
				ep->next = NULL;
			freeptr = loc;
			break;
		}

		if (loc == NULL)
			break;
		ep = loc;
	}	/* for loop */

	if ((freeptr != NULL) && (xdrs->x_op == XDR_FREE)) {
		mem_free(freeptr, sizeof (db_free_entry));
	}
	return (TRUE);
}
