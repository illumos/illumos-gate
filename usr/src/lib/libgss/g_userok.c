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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <deflt.h>
#include <mechglueP.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>


static OM_uint32
compare_names(OM_uint32 *minor,
	    const gss_OID mech_type,
	    const gss_name_t name,
	    const char *user,
	    int *user_ok)
{

	OM_uint32 status, tmpMinor;
	gss_name_t imported_name;
	gss_name_t canon_name;
	gss_buffer_desc gss_user;
	int match = 0;

	*user_ok = 0;

	gss_user.value = (void *)user;
	if (!gss_user.value || !name || !mech_type)
		return (GSS_S_BAD_NAME);
	gss_user.length = strlen(gss_user.value);

	status = gss_import_name(minor,
				&gss_user,
				GSS_C_NT_USER_NAME,
				&imported_name);
	if (status != GSS_S_COMPLETE) {
		goto out;
	}

	status = gss_canonicalize_name(minor,
				    imported_name,
				    mech_type,
				    &canon_name);
	if (status != GSS_S_COMPLETE) {
		(void) gss_release_name(&tmpMinor, &imported_name);
		goto out;
	}

	status = gss_compare_name(minor,
				canon_name,
				name,
				&match);
	(void) gss_release_name(&tmpMinor, &canon_name);
	(void) gss_release_name(&tmpMinor, &imported_name);
	if (status == GSS_S_COMPLETE) {
		if (match)
			*user_ok = 1; /* remote user is a-ok */
	}

out:
	return (status);
}


OM_uint32
__gss_userok(OM_uint32 *minor,
	    const gss_name_t name,
	    const char *user,
	    int *user_ok)

{
	gss_mechanism mech;
	gss_union_name_t intName;
	gss_name_t mechName = NULL;
	OM_uint32 major;

	if (minor == NULL || user_ok == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (name == NULL || user == NULL)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	*user_ok = 0;
	*minor = GSS_S_COMPLETE;

	intName = (gss_union_name_t)name;

	mech = __gss_get_mechanism(intName->mech_type);
	if (mech == NULL)
		return (GSS_S_UNAVAILABLE);

	/* may need to import the name if this is not MN */
	if (intName->mech_type == NULL) {
		return (GSS_S_FAILURE);
	} else
		mechName = intName->mech_name;

	if (mech->__gss_userok)
		major = mech->__gss_userok(mech->context,  minor, mechName,
				user, user_ok);
	else
		major = compare_names(minor, intName->mech_type,
				    name, user, user_ok);

	return (major);
} /* gss_userok */
