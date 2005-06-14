/*
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 1997 by Massachusetts Institute of Technology
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

#include <gssapiP_krb5.h>

OM_uint32
krb5_gss_validate_cred(ct, minor_status, cred_handle)
     void *ct;
     OM_uint32 *minor_status;
     gss_cred_id_t cred_handle;
{
    OM_uint32 major_status; 

    mutex_lock(&krb5_mutex);
    major_status = krb5_gss_validate_cred_no_lock(ct, minor_status, 
						  cred_handle);
    mutex_unlock(&krb5_mutex);

    return(major_status);
}

/*
 * Check to see whether or not a GSSAPI krb5 credential is valid.  If
 * it is not, return an error.
 */

/*ARGSUSED*/
OM_uint32
krb5_gss_validate_cred_no_lock(ct, minor_status, cred_handle)
     void *ct;
     OM_uint32 *minor_status;
     gss_cred_id_t cred_handle;
{
    krb5_context context = ct;
    krb5_gss_cred_id_t cred;
    krb5_error_code code;
    krb5_principal princ;
    OM_uint32 major_status = GSS_S_FAILURE;
	
   /* Solaris Kerberos:  for MT safety, we avoid the use of a default
    * context via kg_get_context() */
#if 0
    if (GSS_ERROR(kg_get_context(minor_status, &context)))
	return (major_status);
#endif

    if (!kg_validate_cred_id(cred_handle)) {
	*minor_status = (OM_uint32) G_VALIDATE_FAILED;
	major_status = (GSS_S_CALL_BAD_STRUCTURE|GSS_S_DEFECTIVE_CREDENTIAL);
	return (major_status);
    }

    cred = (krb5_gss_cred_id_t) cred_handle;
	
    if (cred->ccache) {
	code = krb5_cc_get_principal(context, cred->ccache, &princ);
	if (code) {
	    *minor_status = code;
	    major_status = GSS_S_DEFECTIVE_CREDENTIAL;
	    return (major_status);
	}
	if (!krb5_principal_compare(context, princ, cred->princ)) {
	    *minor_status = KG_CCACHE_NOMATCH;
	    major_status = GSS_S_DEFECTIVE_CREDENTIAL;
	    return (major_status);
	}
	(void)krb5_free_principal(context, princ);
    }
    *minor_status = 0;
    major_status = GSS_S_COMPLETE;
    return (major_status);
}
