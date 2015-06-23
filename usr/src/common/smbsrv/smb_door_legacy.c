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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Legacy encode/decode routines for door clients and servers.
 */

#if !defined(_KERNEL) && !defined(_FAKE_KERNEL)
#include <errno.h>
#include <string.h>
#include <strings.h>
#else
#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#endif

#include <smbsrv/wintypes.h>
#include <smbsrv/smb_share.h>
#include <smbsrv/smb_door.h>
#include <smbsrv/alloc.h>
#include <smbsrv/smbinfo.h>

smb_dr_ctx_t *
smb_dr_decode_start(char *ptr, int size)
{
	smb_dr_ctx_t *ctx = MEM_MALLOC("CommonDoor", sizeof (smb_dr_ctx_t));
	if (ctx) {
		ctx->start_ptr = ctx->ptr = ptr;
		ctx->end_ptr = ptr + size;
		ctx->status = 0;
	}
	return (ctx);
}

int
smb_dr_decode_finish(smb_dr_ctx_t *ctx)
{
	int status = ctx->status;
	if (status == 0 && ctx->ptr != ctx->end_ptr)
		status = ENOTEMPTY;

	MEM_FREE("CommonDoor", ctx);
	return (status);
}

smb_dr_ctx_t *
smb_dr_encode_start(char *ptr, int size)
{
	smb_dr_ctx_t *ctx = MEM_MALLOC("CommonDoor",  sizeof (smb_dr_ctx_t));
	if (ctx) {
		ctx->start_ptr = ctx->ptr = ptr;
		ctx->end_ptr = ptr + size;
		ctx->status = 0;
	}
	return (ctx);
}

int
smb_dr_encode_finish(smb_dr_ctx_t *ctx, unsigned int *used)
{
	int status = ctx->status;
	if (status == 0) {
		if (ctx->ptr < ctx->end_ptr) {
			/*LINTED E_PTRDIFF_OVERFLOW*/
			*used = ctx->ptr - ctx->start_ptr;
		} else {
			status = ENOSPC;
		}
	}

	MEM_FREE("CommonDoor", ctx);
	return (status);
}

DWORD
smb_dr_get_dword(smb_dr_ctx_t *ctx)
{
	DWORD num = 0;
	if (ctx->status == 0) {
		if (ctx->ptr + sizeof (DWORD) <= ctx->end_ptr) {
			(void) memcpy(&num, ctx->ptr, sizeof (DWORD));
			ctx->ptr += sizeof (DWORD);
		} else {
			ctx->status = ENOSPC;
		}
	}
	return (num);
}

int32_t
smb_dr_get_int32(smb_dr_ctx_t *ctx)
{
	int32_t num = 0;
	if (ctx->status == 0) {
		if (ctx->ptr + sizeof (int32_t) <= ctx->end_ptr) {
			(void) memcpy(&num, ctx->ptr, sizeof (int32_t));
			ctx->ptr += sizeof (int32_t);
		} else {
			ctx->status = ENOSPC;
		}
	}
	return (num);
}

uint32_t
smb_dr_get_uint32(smb_dr_ctx_t *ctx)
{
	return ((uint32_t)smb_dr_get_int32(ctx));
}

char *
smb_dr_get_string(smb_dr_ctx_t *ctx)
{
	char *buf = NULL;
	int len = smb_dr_get_int32(ctx);

	if (ctx->status == 0) {
		if (len == -1)
			return (buf);

		if (ctx->ptr + len <= ctx->end_ptr) {
			buf = MEM_MALLOC("CommonDoor", len +1);
			if (buf) {
				if (len == 0) {
					(void) strcpy(buf, "");
				} else {
					(void) memcpy(buf, ctx->ptr, len);
					ctx->ptr += len;
					*(buf + len) = '\0';
				}
			} else {
#if !defined(_KERNEL) && !defined(_FAKE_KERNEL)
				ctx->status = errno;
#else
				ctx->status = ENOMEM;
#endif
			}
		} else {
			ctx->status = ENOSPC;
		}
	}
	return (buf);
}

void
smb_dr_put_dword(smb_dr_ctx_t *ctx, DWORD num)
{
	if (ctx->status == 0) {
		if (ctx->ptr + sizeof (DWORD) <= ctx->end_ptr) {
			(void) memcpy(ctx->ptr, &num, sizeof (DWORD));
			ctx->ptr += sizeof (DWORD);
		} else {
			ctx->status = ENOSPC;
		}
	}
}

void
smb_dr_put_int32(smb_dr_ctx_t *ctx, int32_t num)
{
	if (ctx->status == 0) {
		if (ctx->ptr + sizeof (int32_t) <= ctx->end_ptr) {
			(void) memcpy(ctx->ptr, &num, sizeof (int32_t));
			ctx->ptr += sizeof (int32_t);
		} else {
			ctx->status = ENOSPC;
		}
	}
}

void
smb_dr_put_uint32(smb_dr_ctx_t *ctx, uint32_t num)
{
	smb_dr_put_int32(ctx, (int32_t)num);
}

void
smb_dr_put_string(smb_dr_ctx_t *ctx, const char *buf)
{
	int len;

	if (!buf)
		len = -1;
	else
		len = strlen(buf);

	if (ctx->status == 0) {
		smb_dr_put_int32(ctx, len);
		if (len <= 0)
			return;

		if (ctx->ptr + len <= ctx->end_ptr) {
			(void) memcpy(ctx->ptr, buf, len);
			ctx->ptr += len;
		} else {
			ctx->status = ENOSPC;
		}
	}
}

void
smb_dr_free_string(char *buf)
{
	if (buf)
		MEM_FREE("CommonDoor", buf);
}

int64_t
smb_dr_get_int64(smb_dr_ctx_t *ctx)
{
	int64_t num = 0;
	if (ctx->status == 0) {
		if (ctx->ptr + sizeof (int64_t) <= ctx->end_ptr) {
			(void) memcpy(&num, ctx->ptr, sizeof (int64_t));
			ctx->ptr += sizeof (int64_t);
		} else {
			ctx->status = ENOSPC;
		}
	}
	return (num);
}

uint64_t
smb_dr_get_uint64(smb_dr_ctx_t *ctx)
{
	return ((uint64_t)smb_dr_get_int64(ctx));
}


void
smb_dr_put_int64(smb_dr_ctx_t *ctx, int64_t num)
{
	if (ctx->status == 0) {
		if (ctx->ptr + sizeof (int64_t) <= ctx->end_ptr) {
			(void) memcpy(ctx->ptr, &num, sizeof (int64_t));
			ctx->ptr += sizeof (int64_t);
		} else {
			ctx->status = ENOSPC;
		}
	}
}

void
smb_dr_put_uint64(smb_dr_ctx_t *ctx, uint64_t num)
{
	smb_dr_put_int64(ctx, (int64_t)num);
}

void
smb_dr_put_short(smb_dr_ctx_t *ctx, short num)
{
	if (ctx->status == 0) {
		if (ctx->ptr + sizeof (short) <= ctx->end_ptr) {
			(void) memcpy(ctx->ptr, &num, sizeof (short));
			ctx->ptr += sizeof (short);
		} else {
			ctx->status = ENOSPC;
		}
	}
}

short
smb_dr_get_short(smb_dr_ctx_t *ctx)
{
	short num = 0;
	if (ctx->status == 0) {
		if (ctx->ptr + sizeof (short) <= ctx->end_ptr) {
			(void) memcpy(&num, ctx->ptr, sizeof (short));
			ctx->ptr += sizeof (short);
		} else {
			ctx->status = ENOSPC;
		}
	}
	return (num);
}

void
smb_dr_put_ushort(smb_dr_ctx_t *ctx, unsigned short num)
{
	smb_dr_put_short(ctx, (short)num);
}

unsigned short
smb_dr_get_ushort(smb_dr_ctx_t *ctx)
{
	return ((unsigned short)smb_dr_get_short(ctx));
}

void
smb_dr_put_word(smb_dr_ctx_t *ctx, WORD num)
{
	smb_dr_put_ushort(ctx, num);
}

WORD
smb_dr_get_word(smb_dr_ctx_t *ctx)
{
	return (smb_dr_get_ushort(ctx));
}

void
smb_dr_put_BYTE(smb_dr_ctx_t *ctx, BYTE byte)
{
	if (ctx->status == 0) {
		if (ctx->ptr + sizeof (BYTE) <= ctx->end_ptr) {
			(void) memcpy(ctx->ptr, &byte, sizeof (BYTE));
			ctx->ptr += sizeof (BYTE);
		} else {
			ctx->status = ENOSPC;
		}
	}
}

BYTE
smb_dr_get_BYTE(smb_dr_ctx_t *ctx)
{
	BYTE byte = 0;
	if (ctx->status == 0) {
		if (ctx->ptr + sizeof (BYTE) <= ctx->end_ptr) {
			(void) memcpy(&byte, ctx->ptr, sizeof (BYTE));
			ctx->ptr += sizeof (BYTE);
		} else {
			ctx->status = ENOSPC;
		}
	}
	return (byte);
}

void
smb_dr_put_buf(smb_dr_ctx_t *ctx, unsigned char *start, int len)
{
	smb_dr_put_int32(ctx, len);
	if (ctx->status == 0) {
		if (ctx->ptr + len <= ctx->end_ptr) {
			(void) memcpy(ctx->ptr, start, len);
			ctx->ptr += len;
		} else {
			ctx->status = ENOSPC;
		}
	}
}

int
smb_dr_get_buf(smb_dr_ctx_t *ctx, unsigned char *buf, int bufsize)
{
	int len = -1;

	if (!buf)
		return (-1);

	len = smb_dr_get_int32(ctx);
	if (ctx->status == 0) {
		if (bufsize < len) {
			ctx->status = ENOSPC;
			return (-2);
		}

		if (ctx->ptr + len <= ctx->end_ptr) {
			(void) memcpy(buf, ctx->ptr, len);
			ctx->ptr += len;
		} else {
			ctx->status = ENOSPC;
			return (-3);
		}
	}

	return (len);
}

void
smb_dr_get_share(smb_dr_ctx_t *ctx, smb_share_t *si)
{
	if (ctx->status == 0) {
		if (smb_dr_get_int32(ctx)) {
			(void) memcpy(si, ctx->ptr, sizeof (smb_share_t));
			ctx->ptr += sizeof (smb_share_t);
		} else {
			bzero(si, sizeof (smb_share_t));
		}
	} else {
		bzero(si, sizeof (smb_share_t));
	}
}

void
smb_dr_put_share(smb_dr_ctx_t *ctx, smb_share_t *si)
{
	if (si) {
		smb_dr_put_int32(ctx, 1);
		if (ctx->ptr + sizeof (smb_share_t) <= ctx->end_ptr) {
			(void) memcpy(ctx->ptr, si, sizeof (smb_share_t));
			ctx->ptr += sizeof (smb_share_t);
		} else {
			ctx->status = ENOSPC;
		}
	} else {
		smb_dr_put_int32(ctx, 0);
	}
}
