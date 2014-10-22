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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <rpc/rpc.h>
#include <rpcsvc/yppasswd.h>

bool_t
xdr_passwd(XDR *xdrs, struct passwd *pw)
{
	if (!xdr_wrapstring(xdrs, &pw->pw_name)) {
		return (FALSE);
	}
	if (!xdr_wrapstring(xdrs, &pw->pw_passwd)) {
		return (FALSE);
	}
	if (!xdr_uid_t(xdrs, &pw->pw_uid)) {
		return (FALSE);
	}
	if (!xdr_gid_t(xdrs, (&pw->pw_gid))) {
		return (FALSE);
	}
	if (!xdr_wrapstring(xdrs, &pw->pw_gecos)) {
		return (FALSE);
	}
	if (!xdr_wrapstring(xdrs, &pw->pw_dir)) {
		return (FALSE);
	}
	if (!xdr_wrapstring(xdrs, &pw->pw_shell)) {
		return (FALSE);
	}
	return (TRUE);
}

bool_t
xdr_yppasswd(XDR *xdrs, struct yppasswd *yppw)
{
	if (!xdr_wrapstring(xdrs, &yppw->oldpass)) {
		return (FALSE);
	}
	if (!xdr_passwd(xdrs, &yppw->newpw)) {
		return (FALSE);
	}
	return (TRUE);
}
