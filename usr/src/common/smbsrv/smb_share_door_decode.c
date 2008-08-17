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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"@(#)smb_share_door_decode.c	1.4	08/08/05 SMI"

/*
 * Encode/decode functions used by both lmshare door server and client.
 */

#ifndef _KERNEL
#include <errno.h>
#include <string.h>
#include <strings.h>
#else
#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#endif

#include <smbsrv/smb_share.h>
#include <smbsrv/smb_common_door.h>
#include <smbsrv/alloc.h>
#include <smbsrv/smbinfo.h>

void
smb_dr_get_share(smb_dr_ctx_t *ctx, smb_share_t *si)
{
	if (ctx->status == 0) {
		if (smb_dr_get_int32(ctx)) {
			(void) memcpy(si, ctx->ptr, sizeof (smb_share_t));
			ctx->ptr += sizeof (smb_share_t);
		}
		else
			bzero(si, sizeof (smb_share_t));
	}
	else
		bzero(si, sizeof (smb_share_t));
}

void
smb_dr_put_share(smb_dr_ctx_t *ctx, smb_share_t *si)
{
	if (si) {
		smb_dr_put_int32(ctx, 1);
		if (ctx->ptr + sizeof (smb_share_t) <= ctx->end_ptr) {
			(void) memcpy(ctx->ptr, si, sizeof (smb_share_t));
			ctx->ptr += sizeof (smb_share_t);
		}
		else
			ctx->status = ENOSPC;
	}
	else
		smb_dr_put_int32(ctx, 0);
}
