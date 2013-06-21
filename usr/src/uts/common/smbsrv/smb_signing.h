/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMB_SIGNING_H_
#define	_SMB_SIGNING_H_

#ifdef	_KERNEL
#include <sys/crypto/api.h>
#else
#include <security/cryptoki.h>
#include <security/pkcs11.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define	MD5_DIGEST_LENGTH	16	/* MD5 digest length in bytes */

#ifdef	_KERNEL
/* KCF variant */
typedef crypto_mechanism_t	smb_sign_mech_t;
typedef crypto_context_t	smb_sign_ctx_t;
#else	/* _KERNEL */
/* PKCS11 variant */
typedef CK_MECHANISM		smb_sign_mech_t;
typedef CK_SESSION_HANDLE	smb_sign_ctx_t;
#endif	/* _KERNEL */

/*
 * SMB1 signing routines used in smb_signing.c
 * Two implementations of these (kernel/user) in:
 *	uts/common/fs/smbsrv/smb_sign_kcf.c
 *	lib/smbsrv/libfksmbsrv/common/fksmb_sign_pkcs.c
 */

int smb_md5_getmech(smb_sign_mech_t *);
int smb_md5_init(smb_sign_ctx_t *, smb_sign_mech_t *);
int smb_md5_update(smb_sign_ctx_t, void *, size_t);
int smb_md5_final(smb_sign_ctx_t, uint8_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SMB_SIGNING_H_ */
