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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _NPD_CLNT_H
#define	_NPD_CLNT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

nispasswd_status nispasswd_auth(char *, char *, char *, uchar_t *, char *,
    keylen_t, algtype_t, des_block *, CLIENT *, uint32_t *, uint32_t *, int *);

int nispasswd_pass(CLIENT *, uint32_t, uint32_t, des_block *, char *, char *,
    char *, int *, nispasswd_error **);

bool_t npd_makeclnthandle(char *, CLIENT **, char **, keylen_t *, algtype_t *,
    char **);

void __npd_free_errlist(nispasswd_error *);

#ifdef __cplusplus
}
#endif

#endif /* _NPD_CLNT_H */
