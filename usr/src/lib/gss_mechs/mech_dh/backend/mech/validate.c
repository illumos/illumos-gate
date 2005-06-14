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
 *	validate.c
 *
 *	Copyright (c) 1997, by Sun Microsystems, Inc.
 *	All rights reserved.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "dh_gssapi.h"

/*
 * This module provides the interface to validating contexts, credentials,
 * and principals. The current implementation does nothing.
 */

/*
 * __dh_validate_context: Validate a context, i.e., check if the context is
 * in the database. If the context is non null then return success, else
 * return bad context.
 */

OM_uint32
__dh_validate_context(dh_gss_context_t ctx)
{
	if (ctx && ctx->state != BAD)
		return (DH_SUCCESS);
	return (DH_BAD_CONTEXT);
}

/*
 * __dh_install_context: Install the context in to the database of current
 * contexts.
 */
OM_uint32
__dh_install_context(dh_gss_context_t ctx)
{
	return (ctx ? DH_SUCCESS : DH_BAD_CONTEXT);
}

/*
 * __dh_remove_context: Deinstall the context from the database of current
 * contexts.
 */
OM_uint32
__dh_remove_context(dh_gss_context_t ctx)
{
	return (ctx ? DH_SUCCESS : DH_BAD_CONTEXT);
}

/*
 * __dh_validate_cred: Check the cred database if the supplied crediential
 * is present, valid.
 */

/*ARGSUSED*/
OM_uint32
__dh_validate_cred(dh_cred_id_t cred)
{
	return (DH_SUCCESS);
}

/*
 * __dh_install_cred: Installed the cred into the credential database
 */

/*ARGSUSED*/
OM_uint32
__dh_install_cred(dh_cred_id_t cred)
{
	return (DH_SUCCESS);
}

/*
 * __dh_remove_cred: Remove the supplied cred from the database.
 */

/*ARGSUSED*/
OM_uint32
__dh_remove_cred(dh_cred_id_t cred)
{
	return (DH_SUCCESS);
}

/*
 * Check if a principal is valid.
 *
 * XXX We could check for a valid netname.
 */

/*ARGSUSED*/
OM_uint32
__dh_validate_principal(dh_principal principal)
{
	return (DH_SUCCESS);
}
