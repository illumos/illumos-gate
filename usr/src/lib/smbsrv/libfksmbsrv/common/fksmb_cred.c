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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/sid.h>
#include <sys/priv_names.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <smbsrv/smb_idmap.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_token.h>


/*
 * Kind of a hack here.  In this user-space test implementation,
 * we don't bother with real credential.  Everything here uses
 * the ordinary credentials of the process running this.
 */
cred_t *
smb_cred_create(smb_token_t *token)
{
	cred_t *cr;
	cr = (cred_t *)token;	/* hack */
	return (cr);
}

void
smb_user_setcred(smb_user_t *user, cred_t *cr, uint32_t privileges)
{
	user->u_cred = cr;
	user->u_privcred = NULL;
	user->u_privileges = privileges;
}
