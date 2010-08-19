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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_KT_SOLARIS_H
#define	_KT_SOLARIS_H

#define	KRB5_KT_FLAG_AES_SUPPORT	1

krb5_error_code krb5_kt_add_ad_entries(krb5_context, char **, char *, krb5_kvno,
    uint_t, char *);

krb5_error_code krb5_kt_remove_by_realm(krb5_context, char *);

krb5_error_code krb5_kt_remove_by_svcprinc(krb5_context, char *);

krb5_error_code krb5_kt_ad_validate(krb5_context, char *, uint_t, boolean_t *);

#endif /* _KT_SOLARIS_H */
