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
#pragma ident	"%Z%%M%	%I%	%E% SMI" 

/* 
 * Copyright (c) 1992 by Sun Microsystems, Inc.
 */


#include <rpc/types.h>
#include <rpc/auth.h>

#undef authunix_create
#undef authunix_create_default

AUTH *
authunix_create(machname, uid, gid, len, aup_gids)
	char *machname;
	uid_t uid;
	gid_t gid;
	register int len;
	gid_t *aup_gids;
{
	return(authsys_create(machname, uid, gid, len, aup_gids));
}



AUTH *
authunix_create_default()
{
	return(authsys_create_default());
}
