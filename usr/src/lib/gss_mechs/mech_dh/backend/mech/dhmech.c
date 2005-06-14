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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "dh_gssapi.h"
#include <stdlib.h>

/*
 * gss_config structure for Diffie-Hellman family of mechanisms.
 * This structure is defined in mechglueP.h and defines the entry points
 * that libgss uses to call a backend.
 */
static struct gss_config dh_mechanism = {
	{0, 0},				/* OID for mech type. */
	0,
	__dh_gss_acquire_cred,
	__dh_gss_release_cred,
	__dh_gss_init_sec_context,
	__dh_gss_accept_sec_context,
/* EXPORT DELETE START */ /* CRYPT DELETE START */
	__dh_gss_unseal,
/* EXPORT DELETE END */ /* CRYPT DELETE END */
	__dh_gss_process_context_token,
	__dh_gss_delete_sec_context,
	__dh_gss_context_time,
	__dh_gss_display_status,
	NULL, /* Back ends don't implement this */
	__dh_gss_compare_name,
	__dh_gss_display_name,
	__dh_gss_import_name,
	__dh_gss_release_name,
	__dh_gss_inquire_cred,
	NULL, /* Back ends don't implement this */
/* EXPORT DELETE START */ /* CRYPT DELETE START */
	__dh_gss_seal,
/* EXPORT DELETE END */ /* CRYPT DELETE END */
	__dh_gss_export_sec_context,
	__dh_gss_import_sec_context,
	__dh_gss_inquire_cred_by_mech,
	__dh_gss_inquire_names_for_mech,
	__dh_gss_inquire_context,
	__dh_gss_internal_release_oid,
	__dh_gss_wrap_size_limit,
	__dh_pname_to_uid,
	NULL,  /* __gss_userok */
	__dh_gss_export_name,
/* EXPORT DELETE START */
/* CRYPT DELETE START */
/*
 * This block comment is Sun Proprietary: Need-To-Know.
 * What we are doing is leaving the seal and unseal entry points
 * in an obvious place before sign and unsign for the Domestic customer
 * of the Solaris Source Product. The Domestic customer of the Solaris Source
 * Product will have to deal with the problem of creating exportable libgss
 * binaries.
 * In the binary product that Sun builds, these entry points are elsewhere,
 * and bracketed with special comments so that the CRYPT_SRC and EXPORT_SRC
 * targets delete them.
 */
#if 0
/* CRYPT DELETE END */
	__dh_gss_seal,
	__dh_gss_unseal,
/* CRYPT DELETE START */
#endif /* 0 */
/* CRYPT DELETE END */
/* EXPORT DELETE END */
	__dh_gss_sign,
	__dh_gss_verify,
	NULL, /* gss_store_cred() -- DH lacks this for now */
};

/*
 * __dh_gss_initialize:
 * Each mechanism in the Diffie-Hellman family of mechanisms calls this
 * routine passing a pointer to a gss_config structure. This routine will
 * then check that the mech is not already initialized (If so just return
 * the mech). It will then assign the entry points that are common to the
 * mechanism family to the uninitialized mech. After which, it allocate space
 * for that mechanism's context. It will be up to the caller to fill in
 * its mechanism OID and fill in the corresponding fields in mechanism
 * specific context.
 */
gss_mechanism
__dh_gss_initialize(gss_mechanism mech)
{
	if (mech->context != NULL)
		return (mech);    /* already initialized */

	/* Copy the common entry points for this mechcanisms */
	*mech = dh_mechanism;

	/* Allocate space for this mechanism's context */
	mech->context = New(dh_context_desc, 1);
	if (mech->context == NULL)
		return (NULL);

	/* return the mech */
	return (mech);
}
