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
 * native LDAP related utility routines
 */

#include "idmapd.h"

/* ARGSUSED */
idmap_retcode
nldap_lookup(idmap_mapping *req, idmap_id_res *res, int w2u, int bywinname)
{
	/*
	 * TBD: native LDAP lookup either by unixname or pid or winname
	 */
	return (IDMAP_ERR_NOTSUPPORTED);
}

/* ARGSUSED */
idmap_retcode
nldap_lookup_batch(lookup_state_t *state, idmap_mapping_batch *batch,
		idmap_ids_res *result)
{
	/*
	 * TBD: Batch native LDAP lookups by uid/gid/winname
	 * In case of non-fatal errors set the retcode in each
	 * request to success so that we can process name-based
	 * mapping rules for those failed cases.
	 * This function loops through the batch again to verify
	 * the results and to map winnames obtained from
	 * native LDAP to SIDs using well-known SIDs table and
	 * name_cache.
	 */
	return (IDMAP_ERR_NOTSUPPORTED);
}
