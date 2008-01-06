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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module provides the handles used in the various server-side
 * RPC functions. I don't think other systems care about the value in
 * the handle. It should be treated as an opaque data block. Handles
 * are issued when a service is opened and obsoleted when it is closed.
 * We should check incoming RPC requests to ensure that the handle
 * being used is associated with the particular service being accessed.
 */

#include <strings.h>
#include <unistd.h>
#include <assert.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/ntsid.h>

/*
 * Each time a handle is allocated it is added to the global handle
 * descriptor list because we need some way of identifying the
 * interface and domain to which the handle was assigned when it is
 * returned on a subsequent RPC.
 */
ms_handle_t mlsvc_handle;
ms_handle_desc_t *mlsvc_desc_list;

/*
 * mlsvc_get_handle
 *
 * This function returns a handle for use with the server-side RPC
 * functions. Every time it is called it will increment the handle
 * value and return a pointer to it. On NT, handle[0] always seems
 * to be zero and handle[1] increments. The rest seems to be some
 * sort of unique value so the local domain SID should do.
 *
 * The handle is added to the global handle descriptor list with the
 * designated ifspec and key tag.
 */
ms_handle_t *
mlsvc_get_handle(ms_ifspec_t ifspec, char *key, DWORD discrim)
{
	ms_handle_desc_t *desc;
	nt_sid_t *sid;

	if ((desc = malloc(sizeof (ms_handle_desc_t))) == NULL)
		assert(desc);

	sid = nt_domain_local_sid();
	if (mlsvc_handle.handle[1] == 0) {
		mlsvc_handle.handle[0] = 0;
		mlsvc_handle.handle[1] = 0;
		mlsvc_handle.handle[2] = sid->SubAuthority[1];
		mlsvc_handle.handle[3] = sid->SubAuthority[2];
		mlsvc_handle.handle[4] = sid->SubAuthority[3];
	}

	++mlsvc_handle.handle[1];

	bcopy(&mlsvc_handle, &desc->handle, sizeof (ms_handle_t));
	desc->ifspec = ifspec;
	desc->discrim = discrim;
	desc->next = mlsvc_desc_list;
	mlsvc_desc_list = desc;

	if (key)
		(void) strlcpy(desc->key, key, MLSVC_HANDLE_KEY_MAX);
	else
		desc->key[0] = '\0';

	return (&mlsvc_handle);
}


/*
 * mlsvc_put_handle
 *
 * Remove a handle from the global handle descriptor list and free the
 * memory it was using. If the list contained the descriptor, a value
 * of 0 is returned. Otherwise -1 is returned.
 */
int
mlsvc_put_handle(ms_handle_t *handle)
{
	ms_handle_desc_t *desc;
	ms_handle_desc_t **ppdesc = &mlsvc_desc_list;

	assert(handle);

	while (*ppdesc) {
		desc = *ppdesc;

		if (bcmp(&desc->handle, handle, sizeof (ms_handle_t)) == 0) {
			*ppdesc = desc->next;
			free(desc);
			return (0);
		}

		ppdesc = &(*ppdesc)->next;
	}

	return (-1);
}


/*
 * mlsvc_validate_handle
 *
 * Lookup a handle in the global handle descriptor list. If the handle
 * is in the list, a pointer to the descriptor is returned. Otherwise
 * a null pointer is returned.
 */
int
mlsvc_validate_handle(ms_handle_t *handle, char *key)
{
	ms_handle_desc_t *desc;

	assert(handle);
	assert(key);

	if ((desc = mlsvc_lookup_handle(handle)) == 0)
		return (NULL);

	if (strcmp(desc->key, key))
		return (NULL);

	return (1);
}


/*
 * mlsvc_lookup_handle
 *
 * Lookup a handle in the global handle descriptor list. If the handle
 * is in the list, a pointer to the descriptor is returned. Otherwise
 * a null pointer is returned.
 */
ms_handle_desc_t *
mlsvc_lookup_handle(ms_handle_t *handle)
{
	ms_handle_desc_t *desc = mlsvc_desc_list;

	assert(handle);

	while (desc) {
		if (bcmp(&desc->handle, handle, sizeof (ms_handle_t)) == 0)
			return (desc);

		desc = desc->next;
	}

	return (NULL);
}
