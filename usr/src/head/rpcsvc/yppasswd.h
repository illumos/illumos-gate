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
 * Copyright (c) 1985 by Sun Microsystems, Inc.
 *
 */


#ifndef _RPCSVC_YPPASSWD_H
#define	_RPCSVC_YPPASSWD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _PWD_H
#include <pwd.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#define	YPPASSWDPROG ((rpcprog_t)100009)
#define	YPPASSWDVERS ((rpcvers_t)1)
#define	YPPASSWDPROC_UPDATE ((rpcproc_t)1)

struct yppasswd {
	char *oldpass;		/* old (unencrypted) password */
	struct passwd newpw;	/* new pw structure */
};

int xdr_yppasswd();

#ifdef	__cplusplus
}
#endif

#endif	/* !_RPCSVC_YPPASSWD_H */
