/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * $Id: gssapi_krb5.c 18131 2006-06-14 22:27:54Z tlyu $
 */


/* For declaration of krb5_ser_context_init */
#include "k5-int.h"
#include "gssapiP_krb5.h"

/*
 * Solaris Kerberos
 * Kernel kgssd module debugging aid. The global variable "krb5_log" is a bit
 * mask which allows various types of log messages to be printed out.
 *
 * The log levels are defined in:
 * usr/src/uts/common/gssapi/mechs/krb5/include/k5-int.h
 *
 * Note, KRB5_LOG_LVL can be assigned via the make invocation.
 * See KRB5_DEFS in the various Makefiles.
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
 * The OID of the krb5_name type is:
 * 	iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 * 	krb5(2) krb5_name(1) = 1.2.840.113554.1.2.2.1
 * The OID of the krb5_principal type is:
 * 	iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 * 	krb5(2) krb5_principal(2) = 1.2.840.113554.1.2.2.2
 * The OID of the proposed standard krb5 mechanism is:
 * 	iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 * 	krb5(2) = 1.2.840.113554.1.2.2
 * The OID of the proposed standard krb5 v2 mechanism is:
 * 	iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 * 	krb5v2(3) = 1.2.840.113554.1.2.3
 *	
 */

/*
 * Encoding rules: The first two values are encoded in one byte as 40
 * * value1 + value2.  Subsequent values are encoded base 128, most
 * significant digit first, with the high bit (\200) set on all octets
 * except the last in each value's encoding.
 */

const gss_OID_desc krb5_gss_oid_array[] = {
   /* this is the official, rfc-specified OID */
   {GSS_MECH_KRB5_OID_LENGTH, GSS_MECH_KRB5_OID},
   /* this pre-RFC mech OID */
   {GSS_MECH_KRB5_OLD_OID_LENGTH, GSS_MECH_KRB5_OLD_OID},
   /* this is the unofficial, incorrect mech OID emitted by MS */
   {GSS_MECH_KRB5_WRONG_OID_LENGTH, GSS_MECH_KRB5_WRONG_OID},
   /* this is the v2 assigned OID */
   {9, "\052\206\110\206\367\022\001\002\003"},
   /* these two are name type OID's */

    /* 2.1.1. Kerberos Principal Name Form:  (rfc 1964)
     * This name form shall be represented by the Object Identifier {iso(1)
     * member-body(2) United States(840) mit(113554) infosys(1) gssapi(2)
     * krb5(2) krb5_name(1)}.  The recommended symbolic name for this type
     * is "GSS_KRB5_NT_PRINCIPAL_NAME". */
   {10, "\052\206\110\206\367\022\001\002\002\001"},

   /* gss_nt_krb5_principal.  Object identifier for a krb5_principal. Do not use. */
   {10, "\052\206\110\206\367\022\001\002\002\002"},
   { 0, 0 }
};

const gss_OID_desc * const gss_mech_krb5              = krb5_gss_oid_array+0;
const gss_OID_desc * const gss_mech_krb5_old          = krb5_gss_oid_array+1;
const gss_OID_desc * const gss_mech_krb5_wrong        = krb5_gss_oid_array+2;
const gss_OID_desc * const gss_nt_krb5_name           = krb5_gss_oid_array+4;
const gss_OID_desc * const gss_nt_krb5_principal      = krb5_gss_oid_array+5;
const gss_OID_desc * const GSS_KRB5_NT_PRINCIPAL_NAME = krb5_gss_oid_array+4;

static const gss_OID_set_desc oidsets[] = {
   {1, (gss_OID) krb5_gss_oid_array+0},
   {1, (gss_OID) krb5_gss_oid_array+1},
   {3, (gss_OID) krb5_gss_oid_array+0},
   {1, (gss_OID) krb5_gss_oid_array+2},
   {3, (gss_OID) krb5_gss_oid_array+0},
};

const gss_OID_set_desc * const gss_mech_set_krb5 = oidsets+0;
const gss_OID_set_desc * const gss_mech_set_krb5_old = oidsets+1;
const gss_OID_set_desc * const gss_mech_set_krb5_both = oidsets+2;

g_set kg_vdb = G_SET_INIT;

/** default credential support */

#ifndef  _KERNEL

/*
 * init_sec_context() will explicitly re-acquire default credentials,
 * so handling the expiration/invalidation condition here isn't needed.
 */
OM_uint32
kg_get_defcred(minor_status, cred)
     OM_uint32 *minor_status;
     gss_cred_id_t *cred;
{
    OM_uint32 major;
    
    if ((major = krb5_gss_acquire_cred(minor_status, 
				      (gss_name_t) NULL, GSS_C_INDEFINITE, 
				      GSS_C_NULL_OID_SET, GSS_C_INITIATE, 
				      cred, NULL, NULL)) && GSS_ERROR(major)) {
      return(major);
   }
   *minor_status = 0;
   return(GSS_S_COMPLETE);
}

OM_uint32
kg_sync_ccache_name (krb5_context context, OM_uint32 *minor_status)
{
    OM_uint32 err = 0;
    
    /* 
     * Sync up the context ccache name with the GSSAPI ccache name.
     * If kg_ccache_name is NULL -- normal unless someone has called 
     * gss_krb5_ccache_name() -- then the system default ccache will 
     * be picked up and used by resetting the context default ccache.
     * This is needed for platforms which support multiple ccaches.
     */
    
    if (!err) {
        /* if NULL, resets the context default ccache */
        err = krb5_cc_set_default_name(context,
				       (char *) k5_getspecific(K5_KEY_GSS_KRB5_CCACHE_NAME));
    }
    
    *minor_status = err;
    return (*minor_status == 0) ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

OM_uint32
kg_get_ccache_name (OM_uint32 *minor_status, const char **out_name)
{
    const char *name = NULL;
    OM_uint32 err = 0;
    char *kg_ccache_name;

    kg_ccache_name = k5_getspecific(K5_KEY_GSS_KRB5_CCACHE_NAME);
    
    if (kg_ccache_name != NULL) {
	name = strdup(kg_ccache_name);
	if (name == NULL)
	    err = errno;
    } else {
	krb5_context context = NULL;

	/* Reset the context default ccache (see text above), and then
	   retrieve it.  */
	err = krb5_gss_init_context(&context);
	if (!err)
	    err = krb5_cc_set_default_name (context, NULL);
	if (!err) {
	    name = krb5_cc_default_name(context);
	    if (name) {
		name = strdup(name);
		if (name == NULL)
		    err = errno;
	    }
	}
	if (context)
	    krb5_free_context(context);
    }

    if (!err) {
        if (out_name) {
            *out_name = name;
        }
    }
    
    *minor_status = err;
    return (*minor_status == 0) ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

OM_uint32
kg_set_ccache_name (OM_uint32 *minor_status, const char *name)
{
    char *new_name = NULL;
    char *swap = NULL;
    char *kg_ccache_name;
    krb5_error_code kerr;

    if (name) {
	new_name = malloc(strlen(name) + 1);
	if (new_name == NULL) {
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}
	strcpy(new_name, name);
    }

    kg_ccache_name = k5_getspecific(K5_KEY_GSS_KRB5_CCACHE_NAME);
    swap = kg_ccache_name;
    kg_ccache_name = new_name;
    new_name = swap;
    kerr = k5_setspecific(K5_KEY_GSS_KRB5_CCACHE_NAME, kg_ccache_name);
    if (kerr != 0) {
	/* Can't store, so free up the storage.  */
	free(kg_ccache_name);
	/* ??? free(new_name); */
	*minor_status = kerr;
	return GSS_S_FAILURE;
    }

    free (new_name);
    *minor_status = 0;
    return GSS_S_COMPLETE;
}
#endif
