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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#include <smbsrv/lmshare.h>
#include <smbsrv/smb_common_door.h>
#include <smbsrv/lmshare_door.h>
#include <smbsrv/alloc.h>
#include <smbsrv/smbinfo.h>

void
smb_dr_get_kconfig(smb_dr_ctx_t *ctx, smb_kmod_cfg_t *cfg)
{
	if (ctx->status == 0) {
		(void) memcpy(cfg, ctx->ptr, sizeof (smb_kmod_cfg_t));
		ctx->ptr += sizeof (smb_kmod_cfg_t);
	}
	else
		bzero(cfg, sizeof (smb_kmod_cfg_t));
}

void
smb_dr_put_kconfig(smb_dr_ctx_t *ctx, smb_kmod_cfg_t *cfg)
{
	if (ctx->ptr + sizeof (smb_kmod_cfg_t) <= ctx->end_ptr) {
		(void) memcpy(ctx->ptr, cfg, sizeof (smb_kmod_cfg_t));
		ctx->ptr += sizeof (smb_kmod_cfg_t);
	}
	else
		ctx->status = ENOSPC;
}

void
smb_dr_get_lmshare(smb_dr_ctx_t *ctx, lmshare_info_t *si)
{
	if (ctx->status == 0) {
		if (smb_dr_get_int32(ctx)) {
			(void) memcpy(si, ctx->ptr, sizeof (lmshare_info_t));
			ctx->ptr += sizeof (lmshare_info_t);
		}
		else
			bzero(si, sizeof (lmshare_info_t));
	}
	else
		bzero(si, sizeof (lmshare_info_t));
}

void
smb_dr_put_lmshare(smb_dr_ctx_t *ctx, lmshare_info_t *si)
{
	if (si) {
		smb_dr_put_int32(ctx, 1);
		if (ctx->ptr + sizeof (lmshare_info_t) <= ctx->end_ptr) {
			(void) memcpy(ctx->ptr, si, sizeof (lmshare_info_t));
			ctx->ptr += sizeof (lmshare_info_t);
		}
		else
			ctx->status = ENOSPC;
	}
	else
		smb_dr_put_int32(ctx, 0);
}

uint64_t
smb_dr_get_lmshr_iterator(smb_dr_ctx_t *ctx)
{
	uint64_t lmshr_iter;

	if (smb_dr_get_int32(ctx))
		lmshr_iter = smb_dr_get_uint64(ctx);
	else
		lmshr_iter = 0;

	return (lmshr_iter);
}

void
smb_dr_put_lmshr_iterator(smb_dr_ctx_t *ctx, uint64_t lmshr_iter)
{
	if (lmshr_iter) {
		smb_dr_put_int32(ctx, 1);
		smb_dr_put_uint64(ctx, lmshr_iter);
	}
	else
		smb_dr_put_int32(ctx, 0);
}

void
smb_dr_get_lmshr_list(smb_dr_ctx_t *ctx, lmshare_list_t *shrlist)
{
	if (ctx->status == 0) {
		if (smb_dr_get_int32(ctx)) {
			(void) memcpy(shrlist,
			    ctx->ptr, sizeof (lmshare_list_t));
			ctx->ptr += sizeof (lmshare_list_t);
		}
		else
			bzero(shrlist, sizeof (lmshare_list_t));
	}
	else
		bzero(shrlist, sizeof (lmshare_list_t));
}

void
smb_dr_put_lmshr_list(smb_dr_ctx_t *ctx, lmshare_list_t *shrlist)
{
	if (shrlist) {
		smb_dr_put_int32(ctx, 1);
		if (ctx->ptr + sizeof (lmshare_list_t) <= ctx->end_ptr) {
			(void) memcpy(ctx->ptr,
			    shrlist, sizeof (lmshare_list_t));
			ctx->ptr += sizeof (lmshare_list_t);
		}
		else
			ctx->status = ENOSPC;
	}
	else
		smb_dr_put_int32(ctx, 0);
}
