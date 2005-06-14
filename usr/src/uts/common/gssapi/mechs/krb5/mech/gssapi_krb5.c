/*
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* 
 * Solaris Kerberos:  This is identical to MIT Release 1.2.1 except for 
 * changes to the call kg_get_context to get the context in release and 
 * getcred.  In order to be MT safe, we keep a global variable kg_context
 * and do not keep a defcred for default credentials.
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

/*
 * $Id: gssapi_krb5.c,v 1.18 1999/03/26 03:51:42 tytso Exp $
 */

#include <gssapiP_krb5.h>
#include <k5-int.h>

/*
 * Kernel kgssd module debugging aid. The global variable "krb5_log" is a bit
 * mask which allows various types of log messages to be printed out.  
 *
 * The log levels are defined in:
 * usr/src/uts/common/gssapi/mechs/krb5/include/k5-int.h
 *
 * Note, KRB5_LOG_LVL can be assigned via the make invocation.  See KRB5_DEFS in
 * the various Makefiles.
 */

#ifdef KRB5_LOG_LVL
/* set the log level to that specified */
u_int krb5_log = KRB5_LOG_LVL;
#else
/* default log level */
u_int krb5_log = 0;
#endif /* KRB5_LOG_LVL */

/** exported constants defined in gssapi_krb5{,_nx}.h **/

/* these are bogus, but will compile */

/*
 * The OID of the draft krb5 mechanism, assigned by IETF, is:
 * 	iso(1) org(3) dod(5) internet(1) security(5)
 *	kerberosv5(2) = 1.3.5.1.5.2
 * The OID of the krb5_user_name type is:
 *      iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 *      generic(1) user_name(1) = 1.2.840.113554.1.2.1.1
 * The OID of the krb5_name type is:
 * 	iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 * 	krb5(2) krb5_name(1) = 1.2.840.113554.1.2.2.1
 * The OID of the krb5_principal type is:
 *      iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 *      krb5(2) krb5_principal(2) = 1.2.840.113554.1.2.2.2
 * The OID of the proposed standard krb5 mechanism is:
 * 	iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 * 	krb5(2) = 1.2.840.113554.1.2.2
 * The OID of the proposed standard krb5 v2 mechanism is:
 * 	iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 * 	krb5v2(3) = 1.2.840.113554.1.2.3
 *	
 */

/* gss_mech_krb5 = 1.2.840.113554.1.2.2 
 * gss_mech_krb5_old = 1.3.5.1.5.2
 * gss_mech_krb5_v2 = 1.2.840.113554.1.2.3
 * gss_nt_krb5_name = 1.2.840.113554.1.2.2.1
 * gss_nt_krb5_principal = 1.2.840.113554.1.2.2.2
 */

/*
 * Encoding rules: The first two values are encoded in one byte as 40
 * * value1 + value2.  Subsequent values are encoded base 128, most
 * significant digit first, with the high bit (\200) set on all octets
 * except the last in each value's encoding.
 */

/*  Global lock for krb5 mechanism  */
#ifdef  _KERNEL
kmutex_t	krb5_mutex;
#else
mutex_t		krb5_mutex;
#endif

/* krb5 mechanism oids */

const gss_OID_desc krb5_gss_oid_array[] = {
   /* this is the official, rfc-specified OID */
   {9, "\052\206\110\206\367\022\001\002\002"},
   /* this is the unofficial, wrong OID */
   {5, "\053\005\001\005\002"},   
   /* this is the v2 assigned OID */
   {9, "\052\206\110\206\367\022\001\002\003"},
   /* these two are name type OID's */
   {10, "\052\206\110\206\367\022\001\002\002\001"},
   /* XXX this value isn't defined in an RFC */
   {10, "\052\206\110\206\367\022\001\002\002\002"},
   /* 
    * Solaris Kerberos: the following element is the GSS_KRB5_NT_USER_NAME OID
    * (1.2.840.113554.1.2.1.1, see RFC 1964) which is used for backward
    * compatibility with earlier Solaris kerberos releases.
    */
   {10, "\052\206\110\206\367\022\001\002\001\001"},
   { 0, 0 }
};

const gss_OID_desc * const gss_mech_krb5 = krb5_gss_oid_array+0;
const gss_OID_desc * const gss_mech_krb5_old = krb5_gss_oid_array+1;
const gss_OID_desc * const gss_mech_krb5_v2 = krb5_gss_oid_array+2;

/* 
 * Solaris Kerberos: gss_nt_krb5_name points to the GSS_KRB5_NT_USER_NAME OID
 * for backwards compat with earlier Solaris Kerberos releases.  In MIT this
 * points to the GSS_KRB5_NT_PRINCIPAL_NAME OID (1.2.840.113554.1.2.2.1).
 */

const gss_OID_desc * const gss_nt_krb5_name = krb5_gss_oid_array+5;

/* 
 * XXX gss_nt_krb5_principal points to an OID value that is specific to MIT
 * which is not described in any RFC at this point.  Be cautious about using
 * this.
 */ 

const gss_OID_desc * const gss_nt_krb5_principal = krb5_gss_oid_array+4;

static const gss_OID_set_desc oidsets[] = {
   {1, (gss_OID) krb5_gss_oid_array+0},
   {1, (gss_OID) krb5_gss_oid_array+1},
   {2, (gss_OID) krb5_gss_oid_array+0},
   {1, (gss_OID) krb5_gss_oid_array+2},
   {3, (gss_OID) krb5_gss_oid_array+0},
};

const gss_OID_set_desc * const gss_mech_set_krb5 = oidsets+0;
const gss_OID_set_desc * const gss_mech_set_krb5_old = oidsets+1;
const gss_OID_set_desc * const gss_mech_set_krb5_both = oidsets+2;
const gss_OID_set_desc * const gss_mech_set_krb5_v2 = oidsets+3;
const gss_OID_set_desc * const gss_mech_set_krb5_v1v2 = oidsets+4;

void *kg_vdb = NULL;

/** default credential support */

/* default credentials */

/*
 * Solaris Kerberos:
 * We no longer store the defcred in a global variable since this will
 * prevent us from assuming different user ids by gss daemon.
 * This also makes gss_release_defcred a no-op. 
 */
#if 0
static gss_cred_id_t defcred = GSS_C_NO_CREDENTIAL;
#endif

krb5_context kg_context = NULL;

/* XXX what happens when the default credentials expire or are invalidated? */

#ifndef  _KERNEL

/* Note, the krb5_mutex lock must be held prior to calling this function */
OM_uint32
kg_get_defcred(minor_status, cred)
     OM_uint32 *minor_status;
     gss_cred_id_t *cred;
{
OM_uint32 major;
	
   KRB5_LOG0(KRB5_INFO, "kg_get_defcred() start\n");

   if (!kg_context && GSS_ERROR(kg_get_context(minor_status,&kg_context))){
	 KRB5_LOG(KRB5_ERR, "kg_get_defcred() end, error, kg_get_context() "
		 "minor_status=%d\n", *minor_status);
      return GSS_S_FAILURE;
   }

      major = krb5_gss_acquire_cred_no_lock(kg_context,minor_status, 
	(gss_name_t) NULL, GSS_C_INDEFINITE, GSS_C_NULL_OID_SET, GSS_C_INITIATE, 
	 cred, NULL, NULL);
      if (major && GSS_ERROR(major)) {
	 *cred = GSS_C_NO_CREDENTIAL;
	 KRB5_LOG(KRB5_ERR, "kg_get_defcred() end, error major=%d\n", major);
	 return(major);
      }

   *minor_status = 0;
   KRB5_LOG0(KRB5_INFO, "kg_get_defcred() end\n");
   return(GSS_S_COMPLETE);
}

OM_uint32
kg_release_defcred(minor_status)
     OM_uint32 *minor_status;
{
      *minor_status = 0;
      return(GSS_S_COMPLETE);
}

OM_uint32
kg_get_context(minor_status, context)
   OM_uint32 *minor_status;
   krb5_context *context;
{
   /*
    * Solaris Kerberos:  the following is a global variable declared 
    * above and initialized here below
    */
   /* static krb5_context kg_context = NULL; */
   krb5_error_code code;

   KRB5_LOG0(KRB5_INFO, "kg_get_context() start\n");

   if (!kg_context) {
	   if ((code = krb5_init_context(&kg_context)))
		   goto fail;
	   if ((code = krb5_ser_context_init(kg_context)))
		   goto fail;
	   if ((code = krb5_ser_auth_context_init(kg_context)))
		   goto fail;
	   if ((code = krb5_ser_ccache_init(kg_context)))
		   goto fail;
	   if ((code = krb5_ser_rcache_init(kg_context)))
		   goto fail;
	   if ((code = krb5_ser_keytab_init(kg_context)))
		   goto fail;
	   if ((code = krb5_ser_auth_context_init(kg_context)))
	       goto fail;
   }
   *context = kg_context;
   *minor_status = 0;
   KRB5_LOG0(KRB5_INFO, "kg_get_context() end\n");
   return GSS_S_COMPLETE;
   
fail:
   *minor_status = (OM_uint32) code;
   KRB5_LOG(KRB5_ERR, "kg_get_context() end, error code=%d\n", code);
   return GSS_S_FAILURE;
}
#endif
