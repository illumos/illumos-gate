/*
 * Copyright 2000 by the Massachusetts Institute of Technology.
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
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "gssapiP_krb5.h"
#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

/*
 * $Id: add_cred.c 18396 2006-07-25 20:29:43Z lxs $
 */

/* V2 interface */
OM_uint32
krb5_gss_add_cred(minor_status, input_cred_handle,
		  desired_name, desired_mech, cred_usage,
		  initiator_time_req, acceptor_time_req,
		  output_cred_handle, actual_mechs, 
		  initiator_time_rec, acceptor_time_rec)
    OM_uint32		*minor_status;
    gss_cred_id_t	input_cred_handle;
    gss_name_t		desired_name;
    gss_OID		desired_mech;
    gss_cred_usage_t	cred_usage;
    OM_uint32		initiator_time_req;
    OM_uint32		acceptor_time_req;
    gss_cred_id_t	*output_cred_handle;
    gss_OID_set		*actual_mechs;
    OM_uint32		*initiator_time_rec;
    OM_uint32		*acceptor_time_rec;
{
    krb5_context	context;
    OM_uint32		major_status, lifetime;
    krb5_gss_cred_id_t	cred;
    krb5_error_code	code;

    /* this is pretty simple, since there's not really any difference
       between the underlying mechanisms.  The main hair is in copying
       a mechanism if requested. */

    /* check if the desired_mech is bogus */

    if (!g_OID_equal(desired_mech, gss_mech_krb5) &&
	!g_OID_equal(desired_mech, gss_mech_krb5_old)) {
	*minor_status = 0;
	return(GSS_S_BAD_MECH);
    }

    /* check if the desired_mech is bogus */

    if ((cred_usage != GSS_C_INITIATE) &&
	(cred_usage != GSS_C_ACCEPT) &&
	(cred_usage != GSS_C_BOTH)) {
	*minor_status = (OM_uint32) G_BAD_USAGE;
	return(GSS_S_FAILURE);
    }

    /* since the default credential includes all the mechanisms,
       return an error for that case. */

    /*SUPPRESS 29*/
    if (input_cred_handle == GSS_C_NO_CREDENTIAL) {
	*minor_status = 0;
	return(GSS_S_DUPLICATE_ELEMENT);
    }

    code = krb5_gss_init_context(&context);
    if (code) {
	*minor_status = code;
	return GSS_S_FAILURE;
    }

    major_status = krb5_gss_validate_cred_1(minor_status, input_cred_handle,
					    context);
    if (GSS_ERROR(major_status)) {
	krb5_free_context(context);
	return major_status;
    }

    cred = (krb5_gss_cred_id_t) input_cred_handle;
    k5_mutex_assert_locked(&cred->lock);

    /* check if the cred_usage is equal or "less" than the passed-in cred
       if copying */

    if (!((cred->usage == cred_usage) ||
	  ((cred->usage == GSS_C_BOTH) &&
	   (output_cred_handle != NULL)))) {
      *minor_status = (OM_uint32) G_BAD_USAGE;
      krb5_free_context(context);
      return(GSS_S_FAILURE);
    }

    /* check that desired_mech isn't already in the credential */

    if ((g_OID_equal(desired_mech, gss_mech_krb5_old) && cred->prerfc_mech) ||
	(g_OID_equal(desired_mech, gss_mech_krb5) && cred->rfc_mech)) {
	*minor_status = 0;
	krb5_free_context(context);
	return(GSS_S_DUPLICATE_ELEMENT);
    }

    if (GSS_ERROR(kg_sync_ccache_name(context, minor_status))) {
	krb5_free_context(context);
	return GSS_S_FAILURE;
    }

    /* verify the desired_name */

    /*SUPPRESS 29*/
    if ((desired_name != (gss_name_t) NULL) &&
	(! kg_validate_name(desired_name))) {
	*minor_status = (OM_uint32) G_VALIDATE_FAILED;
	krb5_free_context(context);
	return(GSS_S_CALL_BAD_STRUCTURE|GSS_S_BAD_NAME);
    }

    /* make sure the desired_name is the same as the existing one */

    if (desired_name &&
	!krb5_principal_compare(context, (krb5_principal) desired_name,
				cred->princ)) {
	*minor_status = 0;
	krb5_free_context(context);
	return(GSS_S_BAD_NAME);
    }

    /* copy the cred if necessary */

    if (output_cred_handle) {
	/* make a copy */
	krb5_gss_cred_id_t new_cred;
	char *kttype, ktboth[1024];
	const char *cctype, *ccname;
	char ccboth[1024];

	if ((new_cred =
	     (krb5_gss_cred_id_t) xmalloc(sizeof(krb5_gss_cred_id_rec)))
	    == NULL) {
	    *minor_status = ENOMEM;
	    krb5_free_context(context);
	    return(GSS_S_FAILURE);
	}
	memset(new_cred, 0, sizeof(krb5_gss_cred_id_rec));
	
	new_cred->usage = cred_usage;
	new_cred->prerfc_mech = cred->prerfc_mech;
	new_cred->rfc_mech = cred->rfc_mech;
	new_cred->tgt_expire = cred->tgt_expire;

	if (cred->princ)
	    code = krb5_copy_principal(context, cred->princ, &new_cred->princ);
	if (code) {
	    xfree(new_cred);

	    *minor_status = code;
	    krb5_free_context(context);
	    return(GSS_S_FAILURE);
	}
	    
	if (cred->keytab) {
	    kttype = krb5_kt_get_type(context, cred->keytab);
	    if ((strlen(kttype)+2) > sizeof(ktboth)) {
		if (new_cred->princ)
		    krb5_free_principal(context, new_cred->princ);
		xfree(new_cred);

		*minor_status = ENOMEM;
		krb5_free_context(context);
		return(GSS_S_FAILURE);
	    }

	    strncpy(ktboth, kttype, sizeof(ktboth) - 1);
	    ktboth[sizeof(ktboth) - 1] = '\0';
	    strncat(ktboth, ":", sizeof(ktboth) - 1 - strlen(ktboth));

	    code = krb5_kt_get_name(context, cred->keytab, 
				    ktboth+strlen(ktboth),
				    sizeof(ktboth)-strlen(ktboth));
	    if (code) {
		if(new_cred->princ)
		    krb5_free_principal(context, new_cred->princ);
		xfree(new_cred);

		*minor_status = code;
		krb5_free_context(context);
		return(GSS_S_FAILURE);
	    }

	    code = krb5_kt_resolve(context, ktboth, &new_cred->keytab);
	    if (code) {
		if (new_cred->princ)
		krb5_free_principal(context, new_cred->princ);
		xfree(new_cred);

		*minor_status = code;
		krb5_free_context(context);
		return(GSS_S_FAILURE);
	    }
	} else {
	    new_cred->keytab = NULL;
	}
		
	if (cred->rcache) {
	    /* Open the replay cache for this principal. */
	    if ((code = krb5_get_server_rcache(context,
					       krb5_princ_component(context, cred->princ, 0),
					       &new_cred->rcache))) {
		if (new_cred->keytab)
		    krb5_kt_close(context, new_cred->keytab);
		if (new_cred->princ)
		    krb5_free_principal(context, new_cred->princ);
		xfree(new_cred);

		krb5_free_context(context);
		*minor_status = code;
		return(GSS_S_FAILURE);
	    }
	} else {
	    new_cred->rcache = NULL;
	}

	if (cred->ccache) {
	    cctype = krb5_cc_get_type(context, cred->ccache);
	    ccname = krb5_cc_get_name(context, cred->ccache);

	    if ((strlen(cctype)+strlen(ccname)+2) > sizeof(ccboth)) {
		if (new_cred->rcache)
		    krb5_rc_close(context, new_cred->rcache);
		if (new_cred->keytab)
		    krb5_kt_close(context, new_cred->keytab);
		if (new_cred->princ)
		krb5_free_principal(context, new_cred->princ);
		xfree(new_cred);

		krb5_free_context(context);
		*minor_status = ENOMEM;
		return(GSS_S_FAILURE);
	    }

	    strncpy(ccboth, cctype, sizeof(ccboth) - 1);
	    ccboth[sizeof(ccboth) - 1] = '\0';
	    strncat(ccboth, ":", sizeof(ccboth) - 1 - strlen(ccboth));
	    strncat(ccboth, ccname, sizeof(ccboth) - 1 - strlen(ccboth));

	    code = krb5_cc_resolve(context, ccboth, &new_cred->ccache);
	    if (code) {
		if (new_cred->rcache)
		    krb5_rc_close(context, new_cred->rcache);
		if (new_cred->keytab)
		    krb5_kt_close(context, new_cred->keytab);
		if (new_cred->princ)
		    krb5_free_principal(context, new_cred->princ);
		xfree(new_cred);
		krb5_free_context(context);

		*minor_status = code;
		return(GSS_S_FAILURE);
	    }
	} else {
	    new_cred->ccache = NULL;
	}

	/* intern the credential handle */

	if (! kg_save_cred_id((gss_cred_id_t) new_cred)) {
	    if (new_cred->ccache)
		krb5_cc_close(context, new_cred->ccache);
	    if (new_cred->rcache)
		krb5_rc_close(context, new_cred->rcache);
	    if (new_cred->keytab)
		krb5_kt_close(context, new_cred->keytab);
	    if (new_cred->princ)
	    krb5_free_principal(context, new_cred->princ);
	    xfree(new_cred);
	    krb5_free_context(context);

	    *minor_status = (OM_uint32) G_VALIDATE_FAILED;
	    return(GSS_S_FAILURE);
	}

	/* modify new_cred */

	cred = new_cred;
    }
		
    /* set the flag for the new mechanism */

    if (g_OID_equal(desired_mech, gss_mech_krb5_old))
	cred->prerfc_mech = 1;
    else if (g_OID_equal(desired_mech, gss_mech_krb5))
	cred->rfc_mech = 1;

    /* set the outputs */

    if (GSS_ERROR(major_status = krb5_gss_inquire_cred(minor_status, 
						       (gss_cred_id_t)cred,
						       NULL, &lifetime,
						       NULL, actual_mechs))) {
	OM_uint32 dummy;
	
	if (output_cred_handle)
	    (void) krb5_gss_release_cred(&dummy, (gss_cred_id_t *) &cred);
	krb5_free_context(context);

	return(major_status);
    }

    if (initiator_time_rec)
	*initiator_time_rec = lifetime;
    if (acceptor_time_rec)
	*acceptor_time_rec = lifetime;

    if (output_cred_handle)
	*output_cred_handle = (gss_cred_id_t)cred;

    krb5_free_context(context);
    *minor_status = 0;
    return(GSS_S_COMPLETE);
}
