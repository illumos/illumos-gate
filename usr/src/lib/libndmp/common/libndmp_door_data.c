/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Provides encode/decode routines for all door servers/clients.
 */

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <libndmp.h>

ndmp_door_ctx_t *
ndmp_door_decode_start(char *ptr, int size)
{
	ndmp_door_ctx_t *ctx = malloc(sizeof (ndmp_door_ctx_t));
	if (ctx) {
		ctx->start_ptr = ctx->ptr = ptr;
		ctx->end_ptr = ptr + size;
		ctx->status = 0;
	}
	return (ctx);
}

int
ndmp_door_decode_finish(ndmp_door_ctx_t *ctx)
{
	int status = ctx->status;
	if ((status == 0) && (ctx->ptr != ctx->end_ptr)) {
		status = ENOTEMPTY;
	}
	free(ctx);
	return (status);
}

ndmp_door_ctx_t *
ndmp_door_encode_start(char *ptr, int size)
{
	ndmp_door_ctx_t *ctx = malloc(sizeof (ndmp_door_ctx_t));
	if (ctx) {
		ctx->start_ptr = ctx->ptr = ptr;
		ctx->end_ptr = ptr + size;
		ctx->status = 0;
	}
	return (ctx);
}

int
ndmp_door_encode_finish(ndmp_door_ctx_t *ctx, unsigned int *used)
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
	free(ctx);
	return (status);
}

int32_t
ndmp_door_get_int32(ndmp_door_ctx_t *ctx)
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
ndmp_door_get_uint32(ndmp_door_ctx_t *ctx)
{
	return ((uint32_t)ndmp_door_get_int32(ctx));
}

char *
ndmp_door_get_string(ndmp_door_ctx_t *ctx)
{
	char *buf = NULL;
	int len = ndmp_door_get_int32(ctx);

	if (ctx->status == 0) {
		if (len == -1)
			return (buf);

		if (ctx->ptr + len <= ctx->end_ptr) {
			buf = malloc(len +1);
			if (buf) {
				if (len == 0) {
					(void) strcpy(buf, "");
				} else {
					(void) memcpy(buf, ctx->ptr, len);
					ctx->ptr += len;
					*(buf + len) = '\0';
				}
			} else {
				ctx->status = errno;
			}
		} else {
			ctx->status = ENOSPC;
		}
	}
	return (buf);
}

void
ndmp_door_put_int32(ndmp_door_ctx_t *ctx, int32_t num)
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
ndmp_door_put_uint32(ndmp_door_ctx_t *ctx, uint32_t num)
{
	ndmp_door_put_int32(ctx, (int32_t)num);
}

void
ndmp_door_put_string(ndmp_door_ctx_t *ctx, char *buf)
{
	int len;

	if (!buf)
		len = -1;
	else
		len = strlen(buf);

	if (ctx->status == 0) {
		ndmp_door_put_int32(ctx, len);
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
ndmp_door_free_string(char *buf)
{
	free(buf);
}

int64_t
ndmp_door_get_int64(ndmp_door_ctx_t *ctx)
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
ndmp_door_get_uint64(ndmp_door_ctx_t *ctx)
{
	return ((uint64_t)ndmp_door_get_int64(ctx));
}


void
ndmp_door_put_int64(ndmp_door_ctx_t *ctx, int64_t num)
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
ndmp_door_put_uint64(ndmp_door_ctx_t *ctx, uint64_t num)
{
	ndmp_door_put_int64(ctx, (int64_t)num);
}

void
ndmp_door_put_short(ndmp_door_ctx_t *ctx, short num)
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
ndmp_door_get_short(ndmp_door_ctx_t *ctx)
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
ndmp_door_put_ushort(ndmp_door_ctx_t *ctx, unsigned short num)
{
	ndmp_door_put_short(ctx, (short)num);
}

unsigned short
ndmp_door_get_ushort(ndmp_door_ctx_t *ctx)
{
	return ((unsigned short)ndmp_door_get_short(ctx));
}

void
ndmp_door_put_buf(ndmp_door_ctx_t *ctx, unsigned char *start, int len)
{
	ndmp_door_put_int32(ctx, len);
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
ndmp_door_get_buf(ndmp_door_ctx_t *ctx, unsigned char *buf, int bufsize)
{
	int len = -1;

	if (!buf)
		return (-1);

	len = ndmp_door_get_int32(ctx);
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
