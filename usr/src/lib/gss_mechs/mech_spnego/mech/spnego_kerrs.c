/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * lib/krb5/krb/kerrs.c
 *
 * Copyright 2006 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * error-message functions
 */
#include        <sys/param.h>
#include        <unistd.h>
#include        <assert.h>
#include        <stdio.h>
#include        <stdlib.h>
#include        <string.h>
#include        <k5-int.h>
#include        <krb5.h>
#include        <mglueP.h>
#include        "gssapiP_spnego.h"
#include        "gssapiP_generic.h"
#include        <gssapi_err_generic.h>

#ifdef DEBUG
static int error_message_debug = 0;
#ifndef ERROR_MESSAGE_DEBUG
#define ERROR_MESSAGE_DEBUG() (error_message_debug != 0)
#endif
#endif

void
spnego_set_error_message (spnego_gss_ctx_id_t ctx, spnego_error_code code,
			const char *fmt, ...)
{
    va_list args;
    if (ctx == NULL)
	return;
    va_start (args, fmt);
#ifdef DEBUG
    if (ERROR_MESSAGE_DEBUG())
	fprintf(stderr,
		"spnego_set_error_message(ctx=%p/err=%p, code=%ld, ...)\n",
		ctx, &ctx->err, (long) code);
#endif
    krb5int_vset_error (&ctx->err, code, fmt, args);
#ifdef DEBUG
    if (ERROR_MESSAGE_DEBUG())
	fprintf(stderr, "->%s\n", ctx->err.msg);
#endif
    va_end (args);
}

void
spnego_vset_error_message (spnego_gss_ctx_id_t ctx, spnego_error_code code,
			 const char *fmt, va_list args)
{
#ifdef DEBUG
    if (ERROR_MESSAGE_DEBUG())
	fprintf(stderr, "spnego_vset_error_message(ctx=%p, code=%ld, ...)\n",
		ctx, (long) code);
#endif
    if (ctx == NULL)
	return;
    krb5int_vset_error (&ctx->err, code, fmt, args);
#ifdef DEBUG
    if (ERROR_MESSAGE_DEBUG())
	fprintf(stderr, "->%s\n", ctx->err.msg);
#endif
}

const char *
spnego_get_error_message (spnego_gss_ctx_id_t ctx, spnego_error_code code)
{
#ifdef DEBUG
    if (ERROR_MESSAGE_DEBUG())
	fprintf(stderr, "spnego_get_error_message(%p, %ld)\n", ctx, (long) code);
#endif
    if (ctx == NULL)
	return error_message(code);
    return krb5int_get_error (&ctx->err, code);
}

void
spnego_free_error_message (spnego_gss_ctx_id_t ctx, const char *msg)
{
#ifdef DEBUG
    if (ERROR_MESSAGE_DEBUG())
	fprintf(stderr, "spnego_free_error_message(%p, %p)\n", ctx, msg);
#endif
    if (ctx == NULL)
	return;
    krb5int_free_error (&ctx->err, msg);
}

void
spnego_clear_error_message (spnego_gss_ctx_id_t ctx)
{
#ifdef DEBUG
    if (ERROR_MESSAGE_DEBUG())
	fprintf(stderr, "spnego_clear_error_message(%p)\n", ctx);
#endif
    if (ctx == NULL)
	return;
    krb5int_clear_error (&ctx->err);
}
