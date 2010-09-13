/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
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

/* X internationalization!! */

static inline int
compare_OM_uint32 (OM_uint32 a, OM_uint32 b)
{
    if (a < b)
        return -1;
    else if (a == b)
        return 0;
    else
        return 1;
}
static inline void
free_string (char *s)
{
    free(s);
}
#include "error_map.h"
#include <stdio.h>

#define get_error_message spnego_gss_get_error_message
char *get_error_message(OM_uint32 minor_code)
{
    gsserrmap *p = k5_getspecific(K5_KEY_GSS_SPNEGO_ERROR_MESSAGE);
    char *msg = NULL;

#ifdef DEBUG
    fprintf(stderr, "%s(%lu, p=%p)", __func__, (unsigned long) minor_code,
            (void *) p);
#endif
    if (p) {
        char **v = gsserrmap_find(p, minor_code);
        if (v) {
            msg = *v;
#ifdef DEBUG
            fprintf(stderr, " FOUND!");
#endif
        }
    }
    if (msg == 0)
        msg = (char *)error_message(minor_code);
#ifdef DEBUG
    fprintf(stderr, " -> %p/%s\n", (void *) msg, msg);
#endif

    return msg;
}

static int save_error_string_nocopy(OM_uint32 minor_code, char *msg)
{
    gsserrmap *p;
    int ret;

#ifdef DEBUG
    fprintf(stderr, "%s(%lu, %s)", __func__, (unsigned long) minor_code, msg);
#endif
    p = k5_getspecific(K5_KEY_GSS_SPNEGO_ERROR_MESSAGE);
    if (!p) {
        p = malloc(sizeof(*p));
        if (p == NULL) {
            ret = 1;
            goto fail;
        }
        if (gsserrmap_init(p) != 0) {
            free(p);
            p = NULL;
            ret = 1;
            goto fail;
        }
        if (k5_setspecific(K5_KEY_GSS_SPNEGO_ERROR_MESSAGE, p) != 0) {
            gsserrmap_destroy(p);
            free(p);
            p = NULL;
            ret = 1;
            goto fail;
        }
    }
    ret = gsserrmap_replace_or_insert(p, minor_code, msg);
    /* Solaris SPNEGO */
    if (ret) {
            gsserrmap_destroy(p);
            free(p);
            p = NULL;
    }

fail:
#ifdef DEBUG
    fprintf(stderr, " p=%p %s\n", (void *)p, ret ? "FAIL" : "SUCCESS");
#endif
    return ret;
}
void save_error_string(OM_uint32 minor_code, char *msg)
{
    char *s = strdup(msg);
    if (s) {
        if (save_error_string_nocopy(minor_code, s) != 0)
            free(s);
    }
}
void save_error_message(OM_uint32 minor_code, const char *format, ...)
{
    char *s;
    int n;
    va_list ap;

    va_start(ap, format);
    n = vasprintf(&s, format, ap);
    va_end(ap);
    if (n >= 0) {
        if (save_error_string_nocopy(minor_code, s) != 0)
            free(s);
    }
}
void spnego_gss_save_error_info(OM_uint32 minor_code, spnego_gss_ctx_id_t ctx)
{
    char *s;

#ifdef DEBUG
    fprintf(stderr, "%s(%lu, ctx=%p)\n", __func__,
            (unsigned long) minor_code, (void *)ctx);
#endif
    s = (char *)spnego_get_error_message(ctx,  minor_code);
#ifdef DEBUG
    fprintf(stderr, "%s(%lu, ctx=%p) saving: %s\n", __func__,
            (unsigned long) minor_code, (void *)ctx, s);
#endif
    save_error_string(minor_code, s);
    /* The get_error_message call above resets the error message in
       ctx.  Put it back, in case we make this call again *sigh*.  */
    spnego_set_error_message(ctx, minor_code, "%s", s);
    spnego_free_error_message(ctx, s);
}
void spnego_gss_delete_error_info(void *p)
{
    gsserrmap_destroy(p);
}

OM_uint32
spnego_gss_display_status2(minor_status, status_value, status_type,
                        mech_type, message_context, status_string)
    OM_uint32 *minor_status;
    OM_uint32 status_value;
    int status_type;
    gss_OID mech_type;
    OM_uint32 *message_context;
    gss_buffer_t status_string;
{
    status_string->length = 0;
    status_string->value = NULL;

    if ((mech_type != GSS_C_NULL_OID) &&
        !g_OID_equal(gss_mech_spnego, mech_type)) {
        *minor_status = 0;
        return(GSS_S_BAD_MECH);
    }

    if (status_type == GSS_C_GSS_CODE) {
        return(g_display_major_status(minor_status, status_value,
                                      message_context, status_string));
    } else if (status_type == GSS_C_MECH_CODE) {
	/*
	 * Solaris SPNEGO
	 * This init call appears to be not needed as
	 * gss_spnegoint_lib_init() is called on dl open.
	 */
#if 0
        (void) gss_spnegoint_initialize_library();
#endif

        if (*message_context) {
            *minor_status = (OM_uint32) G_BAD_MSG_CTX;
            return(GSS_S_FAILURE);
        }

        /* If this fails, there's not much we can do...  */
        if (g_make_string_buffer(spnego_gss_get_error_message(status_value),
                                 status_string) != 0) {
            *minor_status = ENOMEM;
	    return(GSS_S_FAILURE);
        } else
            *minor_status = 0;
        return(0);
    } else {
        *minor_status = 0;
        return(GSS_S_BAD_STATUS);
    }
}
