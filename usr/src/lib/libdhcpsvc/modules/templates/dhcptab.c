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

/*
 * This module contains the public API functions for managing the dhcptab
 * container.
 */

#include <dhcp_svc_public.h>

/*
 * Creates or opens the dhcptab container in ``location'' and initializes
 * ``handlep'' to point to the instance handle. When creating a new dhcptab, the
 * caller's identity is used for owner/permissions. Performs any initialization
 * needed by data store.
 */
int
open_dt(void **handlep, const char *location, uint_t flags)
{
	return (DSVC_UNSUPPORTED);
}

/*
 * Frees instance handle, cleans up per instance state.
 */
int
close_dt(void **handlep)
{
	return (DSVC_UNSUPPORTED);
}

/*
 * Remove dhcptab container in ``location'' from data store. If the underlying
 * data store is busy, this function will block.
 */
int
remove_dt(const char *location)
{
	return (DSVC_UNSUPPORTED);
}

/*
 * Searches the dhcptab container for instances that match the query
 * described by the combination of query and targetp.  If the partial
 * argument is true, then lookup operations that are unable to
 * complete entirely are allowed (and considered successful).  The
 * query argument consists of 2 fields, each 16 bits long.  The lower
 * 16 bits selects which fields {key, flags} of targetp are to be
 * considered in the query.  The upper 16 bits identifies whether a
 * particular field value must match (bit set) or not match (bit
 * clear).  Bits 2-15 in both 16 bit fields are currently unused, and
 * must be set to 0.  The count field specifies the maximum number of
 * matching records to return, or -1 if any number of records may be
 * returned.  The recordsp argument is set to point to the resulting
 * list of records; if recordsp is passed in as NULL then no records
 * are actually returned. Note that these records are dynamically
 * allocated, thus the caller is responsible for freeing them.  The
 * number of records found is returned in nrecordsp; a value of 0
 * means that no records matched the query.
 */
int
lookup_dt(void *handle, boolean_t partial, uint_t query, int count,
    const dt_rec_t *targetp, dt_rec_list_t **recordsp, uint_t *nrecordsp)
{
	return (DSVC_UNSUPPORTED);
}

/*
 * Add the record pointed to by ``addp'' to from the dhcptab container referred
 * to by the handle. The underlying public module will set ``addp's'' signature
 * as part of the data store operation.
 */
int
add_dt(void *handle, dt_rec_t *addp)
{
	return (DSVC_UNSUPPORTED);
}

/*
 * Atomically modify the record ``origp'' with the record ``newp'' in the
 * dhcptab container referred to by the handle.  ``newp's'' signature will
 * be set by the underlying public module.  If an update collision
 * occurs, either because ``origp's'' signature in the data store has changed
 * or ``newp'' would overwrite an existing record, DSVC_COLLISION is
 * returned and no update of the data store occurs.
 */
int
modify_dt(void *handle, const dt_rec_t *origp, dt_rec_t *newp)
{
	return (DSVC_UNSUPPORTED);
}

/*
 * Delete the record referred to by dtp from the dhcptab container
 * referred to by the handle. If ``dtp's'' signature is zero, the
 * caller is not interested in checking for collisions, and the record
 * should simply be deleted if it exists. If the signature is non-zero,
 * and the signature of the data store version of this record do not match,
 * an update collision occurs, no deletion of matching record in data store
 * is done, and DSVC_COLLISION is returned.
 */
int
delete_dt(void *handle, const dt_rec_t *dtp)
{
	return (DSVC_UNSUPPORTED);
}

/*
 * List the current number of dhcptab container objects located at
 * ``location'' in ``listppp''. Return number of list elements in ``count''.
 * If no objects exist, then ``count'' is set to 0 and DSVC_SUCCESS is returned.
 *
 * This function will block waiting for a result, if the underlying data store
 * is busy.
 */
int
list_dt(const char *location, char ***listppp, uint_t *count)
{
	return (DSVC_UNSUPPORTED);
}
