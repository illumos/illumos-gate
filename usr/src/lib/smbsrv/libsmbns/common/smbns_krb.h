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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMBSRV_SMB_KRB_H
#define	_SMBSRV_SMB_KRB_H

#include <kerberosv5/krb5.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	SMBNS_KRB5_KEYTAB	"/etc/krb5/krb5.keytab"
#define	SMBNS_KRB5_KEYTAB_TMP	"/etc/krb5/krb5.keytab.tmp.XXXXXX"

#define	SMB_PN_SPN_ATTR			0x0001 /* w/o REALM portion */
#define	SMB_PN_UPN_ATTR			0x0002 /* w/  REALM */
#define	SMB_PN_KEYTAB_ENTRY		0x0004 /* w/  REALM */
#define	SMB_PN_SALT			0x0008 /* w/  REALM */

#define	SMB_PN_SVC_HOST			"host"
#define	SMB_PN_SVC_CIFS			"cifs"
#define	SMB_PN_SVC_NFS			"nfs"
#define	SMB_PN_SVC_HTTP			"HTTP"
#define	SMB_PN_SVC_ROOT			"root"

/* Assign an identifier for each principal name format */
typedef enum smb_krb5_pn_id {
	SMB_KRB5_PN_ID_SALT,
	SMB_KRB5_PN_ID_HOST_FQHN,	/* fully qualified name */
	SMB_KRB5_PN_ID_HOST_SHORT,	/* short name */
	SMB_KRB5_PN_ID_CIFS_FQHN,
	SMB_KRB5_PN_ID_CIFS_SHORT,
	SMB_KRB5_PN_ID_MACHINE,		/* the machine account */
	SMB_KRB5_PN_ID_NFS_FQHN,
	SMB_KRB5_PN_ID_HTTP_FQHN,
	SMB_KRB5_PN_ID_ROOT_FQHN,
} smb_krb5_pn_id_t;

/*
 * A principal name can be constructed based on the following:
 *
 * p_id    - identifier for a principal name.
 * p_svc   - service with which the principal is associated.
 * p_flags - usage of the principal is identified - whether it can be used as a
 *           SPN attribute, UPN attribute, or/and keytab entry, etc.
 */
typedef struct smb_krb5_pn {
	smb_krb5_pn_id_t	p_id;
	char			*p_svc;
	uint32_t		p_flags;
} smb_krb5_pn_t;

/*
 * A set of principal names
 *
 * ps_cnt - the number of principal names in the array.
 * ps_set - An array of principal names terminated with a NULL pointer.
 */
typedef struct smb_krb5_pn_set {
	uint32_t	s_cnt;
	char		**s_pns;
} smb_krb5_pn_set_t;

int smb_kinit(char *, char *);
int smb_krb5_ctx_init(krb5_context *);
void smb_krb5_ctx_fini(krb5_context);
int smb_krb5_get_kprincs(krb5_context, char **, size_t, krb5_principal **);
void smb_krb5_free_kprincs(krb5_context, krb5_principal *, size_t);
int smb_krb5_setpwd(krb5_context, const char *, char *);

int smb_krb5_kt_populate(krb5_context, const char *, krb5_principal *,
    int, char *, krb5_kvno, char *, krb5_enctype *, int);
boolean_t smb_krb5_kt_find(smb_krb5_pn_id_t, const char *, char *);

uint32_t smb_krb5_get_pn_set(smb_krb5_pn_set_t *, uint32_t, char *);
void smb_krb5_free_pn_set(smb_krb5_pn_set_t *);
void smb_krb5_log_errmsg(krb5_context, const char *, krb5_error_code);

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_SMB_KRB_H */
