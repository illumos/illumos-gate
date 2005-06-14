/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

#ifndef _GSSAPI_KRB5_H_
#define _GSSAPI_KRB5_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi_err_generic.h>

/* C++ friendlyness */
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if !defined(PROTOTYPE)
#define     PROTOTYPE(x) x
#endif

extern const gss_OID_desc * const gss_mech_krb5;
extern const gss_OID_desc * const gss_mech_krb5_old;
extern const gss_OID_desc * const gss_mech_krb5_v2;
extern const gss_OID_set_desc * const gss_mech_set_krb5;
extern const gss_OID_set_desc * const gss_mech_set_krb5_old;
extern const gss_OID_set_desc * const gss_mech_set_krb5_both;
extern const gss_OID_set_desc * const gss_mech_set_krb5_v2;
extern const gss_OID_set_desc * const gss_mech_set_krb5_v1v2;

extern const gss_OID_desc * const gss_nt_krb5_name;
extern const gss_OID_desc * const gss_nt_krb5_principal;

/* Added name type definitions - declared in gen_oids.c */
extern gss_OID gss_nt_user_name;
extern gss_OID gss_nt_machine_uid_name;
extern gss_OID gss_nt_string_uid_name;
extern gss_OID gss_nt_service_name;

extern const gss_OID_desc krb5_gss_oid_array[];

#define gss_krb5_nt_general_name	gss_nt_krb5_name
#define gss_krb5_nt_principal		gss_nt_krb5_principal
#define gss_krb5_nt_service_name	gss_nt_service_name
#define gss_krb5_nt_user_name		gss_nt_user_name
#define gss_krb5_nt_machine_uid_name	gss_nt_machine_uid_name
#define gss_krb5_nt_string_uid_name	gss_nt_string_uid_name

GSS_DLLIMP OM_uint32 KRB5_CALLCONV gss_krb5_get_tkt_flags
	PROTOTYPE((OM_uint32 *minor_status,
		   gss_ctx_id_t context_handle,
		   krb5_flags *ticket_flags));

GSS_DLLIMP OM_uint32 KRB5_CALLCONV gss_krb5_copy_ccache
	PROTOTYPE((void *ctx, OM_uint32 *minor_status,
		   gss_cred_id_t cred_handle,
		   krb5_ccache out_ccache));

GSS_DLLIMP OM_uint32 KRB5_CALLCONV gss_krb5_ccache_name
	PROTOTYPE((OM_uint32 *minor_status, const char *name,
		   const char **out_name));

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _GSSAPI_KRB5_H_ */
