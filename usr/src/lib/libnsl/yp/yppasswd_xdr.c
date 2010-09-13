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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <rpc/rpc.h>
#include <rpcsvc/yppasswd.h>

bool_t
xdr_passwd(XDR *xdrsp, struct passwd *pw)
{
	if (!xdr_wrapstring(xdrsp, &pw->pw_name))
		return (FALSE);
	if (!xdr_wrapstring(xdrsp, &pw->pw_passwd))
		return (FALSE);
	if (!xdr_int(xdrsp, (int *)&pw->pw_uid))
		return (FALSE);
	if (!xdr_int(xdrsp, (int *)&pw->pw_gid))
		return (FALSE);
	if (!xdr_wrapstring(xdrsp, &pw->pw_gecos))
		return (FALSE);
	if (!xdr_wrapstring(xdrsp, &pw->pw_dir))
		return (FALSE);
	return (xdr_wrapstring(xdrsp, &pw->pw_shell));
}

bool_t
xdr_yppasswd(XDR *xdrsp, struct yppasswd *pp)
{
	if (!xdr_wrapstring(xdrsp, &pp->oldpass))
		return (FALSE);
	return (xdr_passwd(xdrsp, &pp->newpw));
}
