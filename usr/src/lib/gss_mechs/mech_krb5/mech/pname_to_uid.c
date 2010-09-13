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
 *  krb5 mechanism specific routine for pname_to_uid
 */

#include <gssapiP_krb5.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>

/*
 * This functions supplements the gsscred table.
 *
 * First, it provides the mapping for root principal
 * entries.  The uid mapping returned is that of 0.
 * The name must be of the form root/... or root@...
 * or host/... (no host@... mapped to 0 cuz host could
 * be the name of a normal user)
 * or in Kerberos terms, the first component must be root or host.
 *
 * Second, it provides the mapping for normal user principals
 * using the passwd tbl.  Thus, the gsscred table is not normally
 * needed for the krb5 mech (though libgss will use it if this
 * routine fails).
 *
 * GSS_S_COMPLETE is returned on success.
 * GSS_S_FAILURE is returned on failure.
 */
OM_uint32
krb5_pname_to_uid(minor,  pname, uidOut)
OM_uint32 *minor;
const gss_name_t pname;
uid_t *uidOut;
{
	krb5_context context;
	char lname[256];
	struct passwd	*pw;
	krb5_error_code stat;

	if (! kg_validate_name(pname))
	{
		*minor = (OM_uint32) G_VALIDATE_FAILED;
		return (GSS_S_CALL_BAD_STRUCTURE|GSS_S_BAD_NAME);
	}

	stat = krb5_init_context(&context);
	if (stat) {
		*minor = stat;
		return (GSS_S_FAILURE);
	}

	stat = krb5_aname_to_localname(context, (krb5_principal) pname,
				    sizeof (lname), lname);
	krb5_free_context(context);
	context = NULL;
	if (stat)
		return (GSS_S_FAILURE);

	/* get the uid from the passwd tbl */
	if (pw = getpwnam(lname))
	{
		*uidOut = pw->pw_uid;
		return (GSS_S_COMPLETE);
	}

	return (GSS_S_FAILURE);
} /* krb5_pname_to_uid */
