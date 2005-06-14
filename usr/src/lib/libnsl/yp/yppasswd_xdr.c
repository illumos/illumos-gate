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
 *	Copyright (c) 1985 by Sun Microsystems, Inc.
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/rpc.h>
#include <rpcsvc/yppasswd.h>

bool_t
xdr_passwd(xdrsp, pw)
	XDR *xdrsp;
	struct passwd *pw;
{
	if (xdr_wrapstring(xdrsp, &pw->pw_name) == 0)
		return (FALSE);
	if (xdr_wrapstring(xdrsp, &pw->pw_passwd) == 0)
		return (FALSE);
	if (xdr_int(xdrsp, (int *)&pw->pw_uid) == 0)
		return (FALSE);
	if (xdr_int(xdrsp, (int *)&pw->pw_gid) == 0)
		return (FALSE);
	if (xdr_wrapstring(xdrsp, &pw->pw_gecos) == 0)
		return (FALSE);
	if (xdr_wrapstring(xdrsp, &pw->pw_dir) == 0)
		return (FALSE);
	if (xdr_wrapstring(xdrsp, &pw->pw_shell) == 0)
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_yppasswd(xdrsp, pp)
	XDR *xdrsp;
	struct yppasswd *pp;
{
	if (xdr_wrapstring(xdrsp, &pp->oldpass) == 0)
		return (FALSE);
	if (xdr_passwd(xdrsp, &pp->newpw) == 0)
		return (FALSE);
	return (TRUE);
}
