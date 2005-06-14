/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_KRB5DEFS_H
#define	_KRB5DEFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <libintl.h>
#include <locale.h>
#include <profile/prof_int.h>
#include <com_err.h>
#include <syslog.h>
#include <krb5.h>
#include <kcmd.h>

#define	RDIST_BUFSIZ (50 * 1024)

extern krb5_context bsd_context;
extern krb5_auth_context auth_context;
extern krb5_flags authopts;
extern char *krb_cache;
extern krb5_creds *cred;
extern krb5_error_code status;
extern char des_inbuf[2 * RDIST_BUFSIZ];  /* needs to be > largest read size */
extern char des_outbuf[2 * RDIST_BUFSIZ]; /* needs to be > largest write size */
extern krb5_data desinbuf, desoutbuf;
extern krb5_encrypt_block eblock;	/* eblock for encrypt/decrypt */
extern int encrypt_flag;	/* Flag set, when encryption is enabled */
extern int krb5auth_flag;	/* Flag set, when KERBEROS is enabled */
extern int debug_port;
extern enum kcmd_proto kcmd_proto;
extern int retval;
extern char *krb_realm;

static krb5_keyblock *session_key;

#ifdef	__cplusplus
}
#endif

#endif /* _KRB5DEFS_H */
