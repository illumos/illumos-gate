/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
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
 * $Id: import_name.c 18015 2006-05-17 05:26:12Z raeburn $
 */

#include "gssapiP_krb5.h"

#ifndef NO_PASSWORD
#include <pwd.h>
#include <stdio.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <locale.h>

/*
 * errors:
 * GSS_S_BAD_NAMETYPE	if the type is bogus
 * GSS_S_BAD_NAME	if the type is good but the name is bogus
 * GSS_S_FAILURE	if memory allocation fails
 */

OM_uint32
krb5_gss_import_name(minor_status, input_name_buffer,
		     input_name_type, output_name)
     OM_uint32 *minor_status;
     gss_buffer_t input_name_buffer;
     gss_OID input_name_type;
     gss_name_t *output_name;
{
   krb5_context context;
   krb5_principal princ;
   krb5_error_code code;
   char *stringrep, *tmp, *tmp2, *cp;
   OM_uint32	length;
#ifndef NO_PASSWORD
   struct passwd *pw;
#endif

   code = krb5_gss_init_context(&context);
   if (code) {
       *minor_status = code;
       return GSS_S_FAILURE;
   }

   /* set up default returns */

   *output_name = NULL;
   *minor_status = 0;

   /* Go find the appropriate string rep to pass into parse_name */

   if ((input_name_type != GSS_C_NULL_OID) &&
       (g_OID_equal(input_name_type, gss_nt_service_name) ||
	g_OID_equal(input_name_type, gss_nt_service_name_v2))) {
      char *service, *host;

      if ((tmp =
	   (char *) xmalloc(input_name_buffer->length + 1)) == NULL) {
	 *minor_status = ENOMEM;
	 krb5_free_context(context);
	 return(GSS_S_FAILURE);
      }

      memcpy(tmp, input_name_buffer->value, input_name_buffer->length);
      tmp[input_name_buffer->length] = 0;

      service = tmp;
      if ((host = strchr(tmp, '@'))) {
	 *host = '\0';
	 host++;
      }

      code = krb5_sname_to_principal(context, host, service, KRB5_NT_SRV_HST,
				     &princ);

      xfree(tmp);
   } else if ((input_name_type != GSS_C_NULL_OID) &&
	      (g_OID_equal(input_name_type, gss_nt_krb5_principal))) {
       krb5_principal input;

       if (input_name_buffer->length != sizeof(krb5_principal)) {
	   *minor_status = (OM_uint32) G_WRONG_SIZE;
	   /* Solaris Kerberos: spruce-up the err msg */
	   krb5_set_error_message(context, *minor_status,
				dgettext(TEXT_DOMAIN,
					"The size of the specified principal is wrong"));
	   save_error_info(*minor_status, context);
	   krb5_free_context(context);
	   return(GSS_S_BAD_NAME);
      }

      input = *((krb5_principal *) input_name_buffer->value);

      if ((code = krb5_copy_principal(context, input, &princ))) {
	 *minor_status = code;
	 save_error_info(*minor_status, context);
	 krb5_free_context(context);
	 return(GSS_S_FAILURE);
      }
   } else {
#ifndef NO_PASSWORD
      uid_t uid;
      struct passwd pwx;
      char pwbuf[BUFSIZ];
#endif

      stringrep = NULL;

      if ((tmp =
	   (char *) xmalloc(input_name_buffer->length + 1)) == NULL) {
	 *minor_status = ENOMEM;
	 krb5_free_context(context);
	 return(GSS_S_FAILURE);
      }
      tmp2 = 0;

      memcpy(tmp, input_name_buffer->value, input_name_buffer->length);
      tmp[input_name_buffer->length] = 0;

      if ((input_name_type == GSS_C_NULL_OID) ||
	  g_OID_equal(input_name_type, gss_nt_krb5_name) ||
	  g_OID_equal(input_name_type, gss_nt_user_name)) {
	 stringrep = (char *) tmp;
#ifndef NO_PASSWORD
      } else if (g_OID_equal(input_name_type, gss_nt_machine_uid_name)) {
	 uid = *(uid_t *) input_name_buffer->value;
      do_getpwuid:
	 if (k5_getpwuid_r(uid, &pwx, pwbuf, sizeof(pwbuf), &pw) == 0)
	     stringrep = pw->pw_name;
	 else
	    *minor_status = (OM_uint32) G_NOUSER;
      } else if (g_OID_equal(input_name_type, gss_nt_string_uid_name)) {
	 uid = atoi(tmp);
	 goto do_getpwuid;
#endif
      } else if (g_OID_equal(input_name_type, gss_nt_exported_name)) {
	 cp = tmp;
	 if (*cp++ != 0x04)
		 goto fail_name;
	 if (*cp++ != 0x01)
		 goto fail_name;
	 if (*cp++ != 0x00)
		 goto fail_name;
	 length = *cp++;
	 if (length != gss_mech_krb5->length+2)
		 goto fail_name;
	 if (*cp++ != 0x06)
		 goto fail_name;
	 length = *cp++;
	 if (length != gss_mech_krb5->length)
		 goto fail_name;
	 if (memcmp(cp, gss_mech_krb5->elements, length) != 0)
		 goto fail_name;
	 cp += length;
	 length = *cp++;
	 length = (length << 8) | *cp++;
	 length = (length << 8) | *cp++;
	 length = (length << 8) | *cp++;
	 tmp2 = malloc(length+1);
	 if (tmp2 == NULL) {
		 xfree(tmp);
		 *minor_status = ENOMEM;
		 krb5_free_context(context);
		 return GSS_S_FAILURE;
	 }
	 strncpy(tmp2, cp, length);
	 tmp2[length] = 0;

	 stringrep = tmp2;
     } else {
	 xfree(tmp);
	 krb5_free_context(context);
	 return(GSS_S_BAD_NAMETYPE);
      }

      /* at this point, stringrep is set, or if not, *minor_status is. */

      if (stringrep)
	 code = krb5_parse_name(context, (char *) stringrep, &princ);
      else {
      fail_name:
	  xfree(tmp);
	  if (tmp2)
		 xfree(tmp2);

	  /* Solaris Kerberos: spruce-up (not much, sigh) the err msg */
	  krb5_set_error_message(context, *minor_status,
				dgettext(TEXT_DOMAIN,
					"Failed to convert the specified principal to GSS-API internal format"));
	  save_error_info(*minor_status, context);

	  krb5_free_context(context);
	  return(GSS_S_BAD_NAME);
      }

      if (tmp2)
	      xfree(tmp2);
      xfree(tmp);
   }

   /* at this point, a krb5 function has been called to set princ.  code
      contains the return status */

   if (code) {
       /* Solaris Kerberos: spruce-up the err msg */
       *minor_status = (OM_uint32) code;
       /* krb5_sname_to_principal() sets specific err msg for bad hostname. */
       if (*minor_status != (OM_uint32)KRB5_ERR_BAD_HOSTNAME)
	    krb5_set_error_message(context, *minor_status,
				dgettext(TEXT_DOMAIN,
				  "Failed to convert the specified principal to GSS-API internal format: %s"),
				error_message(code));
       save_error_info(*minor_status, context);
       krb5_free_context(context);
       return(GSS_S_BAD_NAME);
   }

   /* save the name in the validation database */

   if (! kg_save_name((gss_name_t) princ)) {
      krb5_free_principal(context, princ);
      krb5_free_context(context);
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      return(GSS_S_FAILURE);
   }

   krb5_free_context(context);

   /* return it */

   *output_name = (gss_name_t) princ;
   return(GSS_S_COMPLETE);
}
