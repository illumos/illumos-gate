/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMBSRV_SMB_KRB5_H
#define	_SMBSRV_SMB_KRB5_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <gssapi/gssapi.h>
#include <kerberosv5/krb5.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	SMBNS_KRB5_KEYTAB "/etc/krb5/krb5.keytab"

extern gss_OID gss_nt_user_name;
extern gss_OID gss_nt_machine_uid_name;
extern gss_OID gss_nt_string_uid_name;
extern gss_OID gss_nt_service_name;
extern gss_OID gss_nt_exported_name;
extern gss_OID gss_nt_service_name_v2;

int krb5_acquire_cred_kinit(char *, char *, gss_cred_id_t *,
    gss_OID *, int *, char *);
int krb5_establish_sec_ctx_kinit(char *, char *, gss_cred_id_t,
    gss_ctx_id_t *, gss_name_t, gss_OID, int, gss_buffer_desc *,
    gss_buffer_desc *, OM_uint32 *, OM_uint32 *, int *,
    int *, OM_uint32 *, char *);
int smb_krb5_ctx_init(krb5_context *ctx);
void smb_krb5_ctx_fini(krb5_context ctx);
int smb_krb5_get_principal(krb5_context ctx, char *princ_str,
    krb5_principal *princ);
int smb_krb5_setpwd(krb5_context ctx, krb5_principal princ, char *passwd);
int smb_krb5_remove_keytab_entries(krb5_context ctx, krb5_principal princ,
    char *fname);
int smb_krb5_update_keytab_entries(krb5_context ctx, krb5_principal princ,
    char *fname, krb5_kvno kvno, char *passwd, krb5_enctype *enctypes,
    int enctype_count);

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_SMB_KRB5_H */
