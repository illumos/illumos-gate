/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#include <gssapiP_krb5.h>
#include <k5-int.h>

#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

/*
 * $Id: acquire_cred.c,v 1.25.6.2 2000/05/22 20:41:32 meeroh Exp $
 */

/* get credentials corresponding to a key in the krb5 keytab.
   If the default name is requested, return the name in output_princ.
     If output_princ is non-NULL, the caller will use or free it, regardless
     of the return value.
   If successful, set the keytab-specific fields in cred
   */

static OM_uint32
acquire_accept_cred(context, minor_status, desired_name, output_princ, cred)
     krb5_context context;
     OM_uint32 *minor_status;
     gss_name_t desired_name;
     krb5_principal *output_princ;
     krb5_gss_cred_id_rec *cred;
{
   krb5_error_code code;
   krb5_principal princ;
   krb5_keytab kt;
   krb5_keytab_entry entry;

   *output_princ = NULL;
   cred->keytab = NULL;

   /* open the default keytab */

   if ((code = krb5_kt_default(context, &kt))) {
      *minor_status = code;
      /* NOTE: GSS_S_CRED_UNAVAIL is not RFC 2743 compliant */
      return(GSS_S_NO_CRED);
   }

   if (desired_name != GSS_C_NO_NAME) {
      princ = (krb5_principal) desired_name;
      if ((code = krb5_kt_get_entry(context, kt, princ, 0, 0, &entry))) {
	 (void) krb5_kt_close(context, kt);
	 if (code == KRB5_KT_NOTFOUND)
	    *minor_status = KG_KEYTAB_NOMATCH;
	 else
	    *minor_status = code;
      /* NOTE: GSS_S_CRED_UNAVAIL is not RFC 2743 compliant */
	 return(GSS_S_NO_CRED);
      }
      krb5_kt_free_entry(context, &entry);

      /* Open the replay cache for this principal. */
      if ((code = krb5_get_server_rcache(context,
					 krb5_princ_component(context, princ, 0),
					 &cred->rcache))) {
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }

   }

   /* hooray.  we made it */

   cred->keytab = kt;

   return(GSS_S_COMPLETE);
}

/* get credentials corresponding to the default credential cache.
   If the default name is requested, return the name in output_princ.
     If output_princ is non-NULL, the caller will use or free it, regardless
     of the return value.
   If successful, set the ccache-specific fields in cred.
   */

static OM_uint32
acquire_init_cred(context, minor_status, desired_name, output_princ, cred)
     krb5_context context;
     OM_uint32 *minor_status;
     gss_name_t desired_name;
     krb5_principal *output_princ;
     krb5_gss_cred_id_rec *cred;
{
   krb5_error_code code;
   krb5_ccache ccache;
   krb5_principal princ, tmp_princ;
   krb5_flags flags;
   krb5_cc_cursor cur;
   krb5_creds creds;
   int got_endtime;

   cred->ccache = NULL;

   /* SUNW14resync - do we need this? */
#if 0
   /* load the GSS ccache name into the kg_context */
   if (GSS_ERROR(kg_sync_ccache_name(context, minor_status)))
       return(GSS_S_FAILURE);
#endif

   /* open the default credential cache */

   code = krb5int_cc_default(context, &ccache);
   if (code) {
      *minor_status = code;
      return(GSS_S_NO_CRED);
   }

   /* turn off OPENCLOSE mode while extensive frobbing is going on */
   /*
    * SUNW14resync
    * Added calls to krb5_cc_set_flags(... KRB5_TC_OPENCLOSE)
    * on the error returns cuz the 1.4 krb5_cc_close does not always close
    * the file like it used to and caused STC test gss.27 to fail.
    */
   flags = 0;		/* turns off OPENCLOSE mode */
   if ((code = krb5_cc_set_flags(context, ccache, flags)) != 0) {
      (void)krb5_cc_close(context, ccache);
      *minor_status = code;
      return(GSS_S_NO_CRED);
   }

   /* get out the principal name and see if it matches */

   if ((code = krb5_cc_get_principal(context, ccache, &princ)) != 0) {
      (void)krb5_cc_set_flags(context, ccache, KRB5_TC_OPENCLOSE);
      (void)krb5_cc_close(context, ccache);
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   if (desired_name != (gss_name_t) NULL) {
      if (! krb5_principal_compare(context, princ, (krb5_principal) desired_name)) {
	 (void)krb5_free_principal(context, princ);
         (void)krb5_cc_set_flags(context, ccache, KRB5_TC_OPENCLOSE);
	 (void)krb5_cc_close(context, ccache);
	 *minor_status = KG_CCACHE_NOMATCH;
	 return(GSS_S_NO_CRED);
      }
      (void)krb5_free_principal(context, princ);
      princ = (krb5_principal) desired_name;
   } else {
      *output_princ = princ;
   }

   /* iterate over the ccache, find the tgt */

   if ((code = krb5_cc_start_seq_get(context, ccache, &cur)) != 0) {
      (void)krb5_cc_set_flags(context, ccache, KRB5_TC_OPENCLOSE);
      (void)krb5_cc_close(context, ccache);
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   /* this is hairy.  If there's a tgt for the principal's local realm
      in here, that's what we want for the expire time.  But if
      there's not, then we want to use the first key.  */

   got_endtime = 0;

   code = krb5_build_principal_ext(context, &tmp_princ,
				   krb5_princ_realm(context, princ)->length,
				   krb5_princ_realm(context, princ)->data,
				   6, "krbtgt",
				   krb5_princ_realm(context, princ)->length,
				   krb5_princ_realm(context, princ)->data,
				   0);
   if (code) {
      (void)krb5_cc_set_flags(context, ccache, KRB5_TC_OPENCLOSE);
      (void)krb5_cc_close(context, ccache);
      *minor_status = code;
      return(GSS_S_FAILURE);
   }
   while ((code = krb5_cc_next_cred(context, ccache, &cur, &creds)) == 0) {
      if (krb5_principal_compare(context, tmp_princ, creds.server)) {
	 cred->tgt_expire = creds.times.endtime;
	 got_endtime = 1;
	 *minor_status = 0;
	 code = 0;
	 krb5_free_cred_contents(context, &creds);
	 break;
      }
      if (got_endtime == 0) {
	 cred->tgt_expire = creds.times.endtime;
	 got_endtime = 1;
      }
      krb5_free_cred_contents(context, &creds);
   }
   krb5_free_principal(context, tmp_princ);

   if (code && code != KRB5_CC_END) {
      /* this means some error occurred reading the ccache */
      (void)krb5_cc_end_seq_get(context, ccache, &cur);
      (void)krb5_cc_set_flags(context, ccache, KRB5_TC_OPENCLOSE);
      (void)krb5_cc_close(context, ccache);
      *minor_status = code;
      return(GSS_S_FAILURE);
   } else if (! got_endtime) {
      /* this means the ccache was entirely empty */
      (void)krb5_cc_end_seq_get(context, ccache, &cur);
      (void)krb5_cc_set_flags(context, ccache, KRB5_TC_OPENCLOSE);
      (void)krb5_cc_close(context, ccache);
      *minor_status = KG_EMPTY_CCACHE;
      return(GSS_S_FAILURE);
   } else {
      /* this means that we found an endtime to use. */
      if ((code = krb5_cc_end_seq_get(context, ccache, &cur)) != 0) {
	 (void)krb5_cc_set_flags(context, ccache, KRB5_TC_OPENCLOSE);
	 (void)krb5_cc_close(context, ccache);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }
      flags = KRB5_TC_OPENCLOSE;	/* turns on OPENCLOSE mode */
      if ((code = krb5_cc_set_flags(context, ccache, flags)) != 0) {
	 (void)krb5_cc_close(context, ccache);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }
   }

   /* the credentials match and are valid */

   cred->ccache = ccache;
   /* minor_status is set while we are iterating over the ccache */
   return(GSS_S_COMPLETE);
}

OM_uint32
krb5_gss_acquire_cred(ctx, minor_status, desired_name, time_req,
		      desired_mechs, cred_usage, output_cred_handle,
		      actual_mechs, time_rec)
     void *ctx;
     OM_uint32 *minor_status;
     gss_name_t desired_name;
     OM_uint32 time_req;
     gss_OID_set desired_mechs;
     gss_cred_usage_t cred_usage;
     gss_cred_id_t *output_cred_handle;
     gss_OID_set *actual_mechs;
     OM_uint32 *time_rec;
{
    OM_uint32 ret;

    mutex_lock(&krb5_mutex);
    ret = krb5_gss_acquire_cred_no_lock(ctx, minor_status, desired_name,
	    time_req, desired_mechs, cred_usage, output_cred_handle,
	    actual_mechs, time_rec);
    mutex_unlock(&krb5_mutex);
    return(ret);
}

/*ARGSUSED*/
OM_uint32
krb5_gss_acquire_cred_no_lock(ctx, minor_status, desired_name, time_req,
		      desired_mechs, cred_usage, output_cred_handle,
		      actual_mechs, time_rec)
     void *ctx;
     OM_uint32 *minor_status;
     gss_name_t desired_name;
     OM_uint32 time_req;
     gss_OID_set desired_mechs;
     gss_cred_usage_t cred_usage;
     gss_cred_id_t *output_cred_handle;
     gss_OID_set *actual_mechs;
     OM_uint32 *time_rec;
{
   krb5_context context;
   size_t i;
   krb5_gss_cred_id_t cred;
   gss_OID_set ret_mechs = GSS_C_NULL_OID_SET;
   const gss_OID_set_desc * valid_mechs;
   int req_old, req_new;
   OM_uint32 ret;
   krb5_error_code code;

   /* Solaris Kerberos:  for MT safety, we avoid the use of a default
    * context via kg_get_context() */
#if 0
   if (GSS_ERROR(kg_get_context(minor_status, &context)))
      return(GSS_S_FAILURE);
#endif

   context = ctx;

   /* make sure all outputs are valid */

   *output_cred_handle = NULL;
   if (actual_mechs)
      *actual_mechs = NULL;
   if (time_rec)
      *time_rec = 0;

   /* validate the name */

   /*SUPPRESS 29*/
   if ((desired_name != (gss_name_t) NULL) &&
       (! kg_validate_name(desired_name))) {
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      return(GSS_S_CALL_BAD_STRUCTURE|GSS_S_BAD_NAME);
   }

   /* verify that the requested mechanism set is the default, or
      contains krb5 */

   if (desired_mechs == GSS_C_NULL_OID_SET) {
      valid_mechs = gss_mech_set_krb5_both;
      req_old = 1;
      req_new = 1;
   } else {
      req_old = 0;
      req_new = 0;

      for (i=0; i<desired_mechs->count; i++) {
	 if (g_OID_equal(gss_mech_krb5_old, &(desired_mechs->elements[i])))
	    req_old++;
	 if (g_OID_equal(gss_mech_krb5, &(desired_mechs->elements[i])))
	    req_new++;
      }

      if (!req_old && !req_new) {
	 *minor_status = 0;
	 return(GSS_S_BAD_MECH);
      }
   }

   /* create the gss cred structure */

   if ((cred =
	(krb5_gss_cred_id_t) xmalloc(sizeof(krb5_gss_cred_id_rec))) == NULL) {
      *minor_status = ENOMEM;
      return(GSS_S_FAILURE);
   }
   memset(cred, 0, sizeof(krb5_gss_cred_id_rec));

   cred->usage = cred_usage;
   cred->princ = NULL;
   cred->actual_mechs = valid_mechs;
   cred->prerfc_mech = req_old;
   cred->rfc_mech = req_new;

   cred->keytab = NULL;
   cred->ccache = NULL;

   if ((cred_usage != GSS_C_INITIATE) &&
       (cred_usage != GSS_C_ACCEPT) &&
       (cred_usage != GSS_C_BOTH)) {
      xfree(cred);
      *minor_status = (OM_uint32) G_BAD_USAGE;
      return(GSS_S_FAILURE);
   }

   /* if requested, acquire credentials for accepting */
   /* this will fill in cred->princ if the desired_name is not specified */

   if ((cred_usage == GSS_C_ACCEPT) ||
       (cred_usage == GSS_C_BOTH))
      if ((ret = acquire_accept_cred(context, minor_status, desired_name,
				     &(cred->princ), cred))
	  != GSS_S_COMPLETE) {
	 if (cred->princ)
	    krb5_free_principal(context, cred->princ);
	 xfree(cred);
	 /* minor_status set by acquire_accept_cred() */
	 return(ret);
      }

   /* if requested, acquire credentials for initiation */
   /* this will fill in cred->princ if it wasn't set above, and
      the desired_name is not specified */

   if ((cred_usage == GSS_C_INITIATE) ||
       (cred_usage == GSS_C_BOTH))
      if ((ret =
	   acquire_init_cred(context, minor_status,
			     cred->princ?(gss_name_t)cred->princ:desired_name,
			     &(cred->princ), cred))
	  != GSS_S_COMPLETE) {
	 if (cred->keytab)
	    (void) krb5_kt_close(context, cred->keytab);
	 if (cred->princ)
	    krb5_free_principal(context, cred->princ);
	 xfree(cred);
	 /* minor_status set by acquire_init_cred() */
	 return(ret);
      }

   /* Solaris Kerberos:
    * if the princ wasn't filled in already, fill it in now unless 
    * a cred with no associated princ is requested (will invoke default
    * behaviour when gss_accept_init_context() is called).
    */
   if (!cred->princ && (desired_name != GSS_C_NO_NAME))
      if ((code = krb5_copy_principal(context, (krb5_principal) desired_name,
				      &(cred->princ)))) {
	 if (cred->ccache)
	    (void)krb5_cc_close(context, cred->ccache);
	 if (cred->keytab)
	    (void)krb5_kt_close(context, cred->keytab);
	 xfree(cred);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }

   /*** at this point, the cred structure has been completely created */

   /* compute time_rec */

   if (cred_usage == GSS_C_ACCEPT) {
      if (time_rec)
	 *time_rec = GSS_C_INDEFINITE;
   } else {
      krb5_timestamp now;

      if ((code = krb5_timeofday(context, &now))) {
	 if (cred->ccache)
	    (void)krb5_cc_close(context, cred->ccache);
	 if (cred->keytab)
	    (void)krb5_kt_close(context, cred->keytab);
	 if (cred->princ)
	    krb5_free_principal(context, cred->princ);
	 xfree(cred);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }

      if (time_rec)
	 *time_rec = (cred->tgt_expire > now) ? (cred->tgt_expire - now) : 0;
   }

   /* create mechs */

   if (actual_mechs) {
       if (GSS_ERROR(ret = gss_create_empty_oid_set(minor_status,
							    &ret_mechs)) ||
	   (cred->prerfc_mech &&
	    GSS_ERROR(ret = gss_add_oid_set_member(minor_status,
							   (gss_OID) gss_mech_krb5_old,
							   &ret_mechs))) ||
	   (cred->rfc_mech &&
	    GSS_ERROR(ret = gss_add_oid_set_member(minor_status,
							   (gss_OID) gss_mech_krb5,
							   &ret_mechs)))) {
	   if (cred->ccache)
	       (void)krb5_cc_close(context, cred->ccache);
	   if (cred->keytab)
	       (void)krb5_kt_close(context, cred->keytab);
	   if (cred->princ)
	       krb5_free_principal(context, cred->princ);
	   xfree(cred);
	   /* (*minor_status) set above */
	   return(ret);
       }
   }

   /* intern the credential handle */

   if (! kg_save_cred_id((gss_cred_id_t) cred)) {
      (void) gss_release_oid_set(NULL, &ret_mechs);
      free(ret_mechs->elements);
      free(ret_mechs);
      if (cred->ccache)
	 (void)krb5_cc_close(context, cred->ccache);
      if (cred->keytab)
	 (void)krb5_kt_close(context, cred->keytab);
      if (cred->princ)
	 krb5_free_principal(context, cred->princ);
      xfree(cred);
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      return(GSS_S_FAILURE);
   }

   /* return success */

   *minor_status = 0;
   *output_cred_handle = (gss_cred_id_t) cred;
   if (actual_mechs)
      *actual_mechs = ret_mechs;
   return(GSS_S_COMPLETE);
}
