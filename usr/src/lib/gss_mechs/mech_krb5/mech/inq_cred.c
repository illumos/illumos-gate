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
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
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
#include "mglueP.h"

OM_uint32
krb5_gss_inquire_cred(minor_status, cred_handle, name, lifetime_ret,
		      cred_usage, mechanisms)
     OM_uint32 *minor_status;
     gss_cred_id_t cred_handle;
     gss_name_t *name;
     OM_uint32 *lifetime_ret;
     gss_cred_usage_t *cred_usage;
     gss_OID_set *mechanisms;
{
   krb5_context context;
   krb5_gss_cred_id_t cred;
   krb5_error_code code;
   krb5_timestamp now;
   krb5_deltat lifetime;
   krb5_principal ret_name;
   gss_OID_set mechs;
   OM_uint32 ret;

   ret = GSS_S_FAILURE;
   ret_name = NULL;

   code = krb5_gss_init_context(&context);
   if (code) {
       *minor_status = code;
       return GSS_S_FAILURE;
   }

   if (name) *name = NULL;
   if (mechanisms) *mechanisms = NULL;

   /* check for default credential */
   /*SUPPRESS 29*/
   if (cred_handle == GSS_C_NO_CREDENTIAL) {
      OM_uint32 major;

      if ((major = kg_get_defcred(minor_status, (gss_cred_id_t *)&cred)) &&
	  GSS_ERROR(major)) {
	 krb5_free_context(context);
	 return(major);
      }
   } else {
      OM_uint32 major;

      major = krb5_gss_validate_cred(minor_status, cred_handle);
      if (GSS_ERROR(major)) {
	  krb5_free_context(context);
	  return(major);
      }
      cred = (krb5_gss_cred_id_t) cred_handle;
   }

   if ((code = krb5_timeofday(context, &now))) {
      *minor_status = code;
      ret = GSS_S_FAILURE;
      goto fail;
   }

   code = k5_mutex_lock(&cred->lock);
   if (code != 0) {
       *minor_status = code;
       ret = GSS_S_FAILURE;
       goto fail;
   }
   if (cred->tgt_expire > 0) {
       if ((lifetime = cred->tgt_expire - now) < 0)
	   lifetime = 0;
   }
   else
       lifetime = GSS_C_INDEFINITE;

   if (name) {
      if (cred->princ &&
	  (code = krb5_copy_principal(context, cred->princ, &ret_name))) {
	 k5_mutex_unlock(&cred->lock);
	 *minor_status = code;
	 ret = GSS_S_FAILURE;
	 goto fail;
      }
   }

   if (mechanisms) {
       /* Solaris Kerberos */
       if (GSS_ERROR(ret = generic_gss_create_empty_oid_set(minor_status,
							    &mechs)) ||
	   (cred->prerfc_mech &&
	    GSS_ERROR(ret = generic_gss_add_oid_set_member(minor_status,
							  (const gss_OID) gss_mech_krb5_old,
							   &mechs))) ||
	   (cred->rfc_mech &&
	    GSS_ERROR(ret = generic_gss_add_oid_set_member(minor_status,
							  (const gss_OID) gss_mech_krb5,
							   &mechs)))) {
	   k5_mutex_unlock(&cred->lock);
	   if (ret_name)
	       krb5_free_principal(context, ret_name);
	   /* *minor_status set above */
	   goto fail;
       }
   }

   if (name) {
      if (ret_name != NULL && ! kg_save_name((gss_name_t) ret_name)) {
	 k5_mutex_unlock(&cred->lock);
	 if (cred_handle == GSS_C_NO_CREDENTIAL)
	     krb5_gss_release_cred(minor_status, (gss_cred_id_t *)&cred);

	 (void) gss_release_oid_set(minor_status, &mechs);
	 krb5_free_principal(context, ret_name);
	 *minor_status = (OM_uint32) G_VALIDATE_FAILED;
	 krb5_free_context(context);
	 return(GSS_S_FAILURE);
      }
      if (ret_name != NULL)
	  *name = (gss_name_t) ret_name;
      else
	  *name = GSS_C_NO_NAME;
   }

   if (lifetime_ret)
      *lifetime_ret = lifetime;

   if (cred_usage)
      *cred_usage = cred->usage;
   k5_mutex_unlock(&cred->lock);

   if (mechanisms)
      *mechanisms = mechs;

   if (cred_handle == GSS_C_NO_CREDENTIAL)
       krb5_gss_release_cred(minor_status, (gss_cred_id_t *)&cred);

   krb5_free_context(context);
   *minor_status = 0;
   return((lifetime == 0)?GSS_S_CREDENTIALS_EXPIRED:GSS_S_COMPLETE);
fail:
   if (cred_handle == GSS_C_NO_CREDENTIAL) {
       OM_uint32 tmp_min_stat;

       krb5_gss_release_cred(&tmp_min_stat, (gss_cred_id_t *)&cred);
   }
   krb5_free_context(context);
   return ret;
}

/* V2 interface */
OM_uint32
krb5_gss_inquire_cred_by_mech(minor_status, cred_handle,
			      mech_type, name, initiator_lifetime,
			      acceptor_lifetime, cred_usage)
    OM_uint32		*minor_status;
    gss_cred_id_t	cred_handle;
    gss_OID		mech_type;
    gss_name_t		*name;
    OM_uint32		*initiator_lifetime;
    OM_uint32		*acceptor_lifetime;
    gss_cred_usage_t *cred_usage;
{
    krb5_gss_cred_id_t	cred;
    OM_uint32		lifetime;
    OM_uint32		mstat;

    /*
     * We only know how to handle our own creds.
     */
    if ((mech_type != GSS_C_NULL_OID) &&
	!g_OID_equal(gss_mech_krb5_old, mech_type) &&
	!g_OID_equal(gss_mech_krb5, mech_type)) {
	*minor_status = 0;
	return(GSS_S_NO_CRED);
    }

    cred = (krb5_gss_cred_id_t) cred_handle;
    mstat = krb5_gss_inquire_cred(minor_status,
				  cred_handle,
				  name,
				  &lifetime,
				  cred_usage,
				  (gss_OID_set *) NULL);
    if (mstat == GSS_S_COMPLETE) {
	if (cred &&
	    ((cred->usage == GSS_C_INITIATE) ||
	     (cred->usage == GSS_C_BOTH)) &&
	    initiator_lifetime)
	    *initiator_lifetime = lifetime;
	if (cred &&
	    ((cred->usage == GSS_C_ACCEPT) ||
	     (cred->usage == GSS_C_BOTH)) &&
	    acceptor_lifetime)
	    *acceptor_lifetime = lifetime;
    }
    return(mstat);
}

