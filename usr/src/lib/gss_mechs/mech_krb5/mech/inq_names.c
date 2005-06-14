/*
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/gssapi/krb5/inq_names.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * inq_names.c - Return set of nametypes supported by the KRB5 mechanism.
 */
#include <gssapiP_krb5.h>

/*ARGSUSED*/
OM_uint32
krb5_gss_inquire_names_for_mech(ctx, minor_status, mechanism, name_types)
    void	*ctx;
    OM_uint32	*minor_status;
    gss_OID	mechanism;
    gss_OID_set	*name_types;
{
    OM_uint32	major, minor;

   /* Solaris Kerberos:  for MT safety, we avoid the use of a default
    * context via kg_get_context() */
#if 0
    if (GSS_ERROR(kg_get_context(minor_status, &context)))
       return(GSS_S_FAILURE);
#endif

    mutex_lock(&krb5_mutex);

    /*
     * We only know how to handle our own mechanism.
     */
    if ((mechanism != GSS_C_NULL_OID) &&
	!g_OID_equal(gss_mech_krb5_v2, mechanism) &&
	!g_OID_equal(gss_mech_krb5, mechanism) &&
	!g_OID_equal(gss_mech_krb5_old, mechanism)) {
	*minor_status = 0;
	mutex_unlock(&krb5_mutex);
	return(GSS_S_BAD_MECH);
    }

    /* We're okay.  Create an empty OID set */
    major = gss_create_empty_oid_set(minor_status, name_types);
    if (major == GSS_S_COMPLETE) {
	/* Now add our members. */
	if (
	    /* The following are GSS specified nametypes */
	    ((major = gss_add_oid_set_member(minor_status,
					     (gss_OID) GSS_C_NT_USER_NAME,
					     name_types)
	      ) == GSS_S_COMPLETE) &&
	    ((major = gss_add_oid_set_member(minor_status,
					     (gss_OID) GSS_C_NT_MACHINE_UID_NAME,
					     name_types)
	      ) == GSS_S_COMPLETE) &&
	    ((major = gss_add_oid_set_member(minor_status,
					     (gss_OID) GSS_C_NT_STRING_UID_NAME,
					     name_types)
	      ) == GSS_S_COMPLETE) &&
	    ((major = gss_add_oid_set_member(minor_status,
					     (gss_OID) GSS_C_NT_HOSTBASED_SERVICE,
					     name_types)
	      ) == GSS_S_COMPLETE) &&
		/* The following are kerberos only nametypes */
	    ((major = gss_add_oid_set_member(minor_status,
					     (gss_OID) gss_nt_service_name_v2,
					     name_types)
	      ) == GSS_S_COMPLETE) &&
	    ((major = gss_add_oid_set_member(minor_status,
					     (gss_OID) gss_nt_exported_name,
					     name_types)
	      ) == GSS_S_COMPLETE) &&
	    ((major = gss_add_oid_set_member(minor_status,
					     (gss_OID) gss_nt_krb5_name,
					     name_types)
	      ) == GSS_S_COMPLETE)
	    ) {
	    major = gss_add_oid_set_member(minor_status,
					   (gss_OID) gss_nt_krb5_principal,
					   name_types);
	}

	/*
	 * If we choked, then release the set, but don't overwrite the minor
	 * status with the release call.
	 */
	if (major != GSS_S_COMPLETE)
	    (void) gss_release_oid_set(&minor,
				       name_types);
    }
    mutex_unlock(&krb5_mutex);
    return(major);
}
