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
 * This module contains public API functions for managing dhcp network
 * containers.
 */

#include <dhcp_svc_public.h>

/*
 * Creates or opens the dhcp network container ``netp'' (host order) in
 * ``location'' and initializes ``handlep'' to point to the instance handle.
 * Performs any initialization needed by data store. New containers are
 * created with the identity of the caller.
 */
int
open_dn(void **handlep, const char *location, uint_t flags,
    const struct in_addr *netp, const struct in_addr *maskp)
{
	return (DSVC_UNSUPPORTED);
}

/*
 * Frees instance handle, cleans up per instance state.
 */
int
close_dn(void **handlep)
{
	return (DSVC_UNSUPPORTED);
}

/*
 * Remove DHCP network container ``netp'' (host order) in location.
 * This function will block if the underlying data service is busy or
 * otherwise unavailable.
 */
int
remove_dn(const char *location, const struct in_addr *netp)
{
	return (DSVC_UNSUPPORTED);
}

/*
 * Searches DHCP network container for instances that match the query
 * described by the combination of query and targetp.  If the partial
 * argument is true, then lookup operations that are unable to
 * complete entirely are allowed (and considered successful).  The
 * query argument consists of 2 fields, each 16 bits long.  The lower
 * 16 bits selects which fields {client_id, flags, client_ip,
 * server_ip, expiration, macro, or comment} of targetp are to be
 * considered in the query.  The upper 16 bits identifies whether a
 * particular field value must match (bit set) or not match (bit
 * clear).  Bits 7-15 in both 16 bit fields are currently unused, and
 * must be set to 0.  The count field specifies the maximum number of
 * matching records to return, or -1 if any number of records may be
 * returned.  The recordsp argument is set to point to the resulting
 * list of records; if recordsp is passed in as NULL then no records
 * are actually returned. Note that these records are dynamically
 * allocated, thus the caller is responsible for freeing them.  The
 * number of records found is returned in nrecordsp; a value of 0 means
 * that no records matched the query.
 */
int
lookup_dn(void *handle, boolean_t partial, uint_t query, int count,
    const dn_rec_t *targetp, dn_rec_list_t **recordsp, uint_t *nrecordsp)
{
	return (DSVC_UNSUPPORTED);
}

/*
 * Add the record pointed to by ``addp'' to from the dhcp network container
 * referred to by the handle.  The underlying public module will set ``addp's''
 * signature as part of the data store operation.
 */
int
add_dn(void *handle, dn_rec_t *addp)
{
	return (DSVC_UNSUPPORTED);
}

/*
 * Atomically modify the record ``origp'' with the record ``newp'' in the dhcp
 * network container referred to by the handle.  ``newp's'' signature will
 * be set by the underlying public module.  If an update collision
 * occurs, either because ``origp's'' signature in the data store has changed
 * or ``newp'' would overwrite an preexisting record, DSVC_COLLISION is
 * returned and no update of the data store occurs.
 */
int
modify_dn(void *handle, const dn_rec_t *origp, dn_rec_t *newp)
{
	return (DSVC_UNSUPPORTED);
}

/*
 * Delete the record pointed to by ``pnp'' from the dhcp network container
 * referred to by the handle. If ``pnp's'' signature is zero, the caller
 * is not interested in checking for collisions, and the record should simply
 * be deleted if it exists. If the signature is non-zero, and the signature of
 * the data store version of this record do not match, an update collision
 * occurs, no deletion of any record is done, and DSVC_COLLISION is returned.
 */
int
delete_dn(void *handle, const dn_rec_t *pnp)
{
	return (DSVC_UNSUPPORTED);
}

/*
 * List the current number of dhcp network container objects located at
 * ``location'' in ``listppp''. Return number of list elements in ``count''.
 * If no objects exist, then ``count'' is set to 0 and DSVC_SUCCESS is returned.
 *
 * This function will block if the underlying data service is busy or is
 * otherwise unvailable.
 */
int
list_dn(const char *location, char ***listppp, uint_t *count)
{
	return (DSVC_UNSUPPORTED);
}
