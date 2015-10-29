/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* -*- mode: c; indent-tabs-mode: nil -*- */
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
/*
 * Copyright (c) 2006-2008, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
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
 * Copyright (c) 2006-2008, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
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

#include "gssapiP_krb5.h"
#include "mechglueP.h" /* SUNW17PACresync */

OM_uint32
krb5_gss_inquire_context(minor_status, context_handle, initiator_name,
                         acceptor_name, lifetime_rec, mech_type, ret_flags,
                         locally_initiated, opened)
    OM_uint32 *minor_status;
    gss_ctx_id_t context_handle;
    gss_name_t *initiator_name;
    gss_name_t *acceptor_name;
    OM_uint32 *lifetime_rec;
    gss_OID *mech_type;
    OM_uint32 *ret_flags;
    int *locally_initiated;
    int *opened;
{
    krb5_context context;
    krb5_error_code code;
    krb5_gss_ctx_id_rec *ctx;
    krb5_principal initiator, acceptor;
    krb5_timestamp now;
    krb5_deltat lifetime;

    if (initiator_name)
        *initiator_name = (gss_name_t) NULL;
    if (acceptor_name)
        *acceptor_name = (gss_name_t) NULL;

    /* validate the context handle */
    if (! kg_validate_ctx_id(context_handle)) {
        *minor_status = (OM_uint32) G_VALIDATE_FAILED;
        return(GSS_S_NO_CONTEXT);
    }

    ctx = (krb5_gss_ctx_id_rec *) context_handle;

    if (! ctx->established) {
        *minor_status = KG_CTX_INCOMPLETE;
        return(GSS_S_NO_CONTEXT);
    }

    initiator = NULL;
    acceptor = NULL;
    context = ctx->k5_context;

    if ((code = krb5_timeofday(context, &now))) {
        *minor_status = code;
        save_error_info(*minor_status, context);
        return(GSS_S_FAILURE);
    }


    /* SUNW17PACresync - should be krb_times.endtime (revisit) */
    if ((lifetime = ctx->endtime - now) < 0)
        lifetime = 0;

    if (initiator_name) {
        if ((code = krb5_copy_principal(context,
                                        ctx->initiate?ctx->here:ctx->there,
                                        &initiator))) {
            *minor_status = code;
            save_error_info(*minor_status, context);
            return(GSS_S_FAILURE);
        }
        if (! kg_save_name((gss_name_t) initiator)) {
            krb5_free_principal(context, initiator);
            *minor_status = (OM_uint32) G_VALIDATE_FAILED;
            return(GSS_S_FAILURE);
        }
    }

    if (acceptor_name) {
        if ((code = krb5_copy_principal(context,
                                        ctx->initiate?ctx->there:ctx->here,
                                        &acceptor))) {
            if (initiator) krb5_free_principal(context, initiator);
            *minor_status = code;
            save_error_info(*minor_status, context);
            return(GSS_S_FAILURE);
        }
        if (! kg_save_name((gss_name_t) acceptor)) {
            krb5_free_principal(context, acceptor);
            if (initiator) {
                kg_delete_name((gss_name_t) initiator);
                krb5_free_principal(context, initiator);
            }
            *minor_status = (OM_uint32) G_VALIDATE_FAILED;
            return(GSS_S_FAILURE);
        }
    }

    if (initiator_name)
        *initiator_name = (gss_name_t) initiator;

    if (acceptor_name)
        *acceptor_name = (gss_name_t) acceptor;

    if (lifetime_rec)
        *lifetime_rec = lifetime;

    if (mech_type)
        *mech_type = (gss_OID) ctx->mech_used;

    if (ret_flags)
        *ret_flags = ctx->gss_flags;

    if (locally_initiated)
        *locally_initiated = ctx->initiate;

    if (opened)
        *opened = ctx->established;

    *minor_status = 0;

    return((lifetime == 0)?GSS_S_CONTEXT_EXPIRED:GSS_S_COMPLETE);
}

OM_uint32
gss_krb5int_inq_session_key(
    OM_uint32 *minor_status,
    const gss_ctx_id_t context_handle,
    const gss_OID desired_object,
    gss_buffer_set_t *data_set)
{
    krb5_gss_ctx_id_rec *ctx;
    krb5_keyblock *key;
    gss_buffer_desc keyvalue, keyinfo;
    OM_uint32 major_status, minor;
    unsigned char oid_buf[GSS_KRB5_SESSION_KEY_ENCTYPE_OID_LENGTH + 6];
    gss_OID_desc oid;

    ctx = (krb5_gss_ctx_id_rec *) context_handle;
    key = ctx->have_acceptor_subkey ? ctx->acceptor_subkey : ctx->subkey;

    keyvalue.value = key->contents;
    keyvalue.length = key->length;

    major_status = generic_gss_add_buffer_set_member(minor_status, &keyvalue, data_set);
    if (GSS_ERROR(major_status))
        goto cleanup;

    oid.elements = oid_buf;
    oid.length = sizeof(oid_buf);

    major_status = generic_gss_oid_compose(minor_status,
                                           GSS_KRB5_SESSION_KEY_ENCTYPE_OID,
                                           GSS_KRB5_SESSION_KEY_ENCTYPE_OID_LENGTH,
                                           key->enctype,
                                           &oid);
    if (GSS_ERROR(major_status))
        goto cleanup;

    keyinfo.value = oid.elements;
    keyinfo.length = oid.length;

    major_status = generic_gss_add_buffer_set_member(minor_status, &keyinfo, data_set);
    if (GSS_ERROR(major_status))
        goto cleanup;

    return GSS_S_COMPLETE;

cleanup:
    if (*data_set != GSS_C_NO_BUFFER_SET) {
        if ((*data_set)->count != 0)
            memset((*data_set)->elements[0].value, 0, (*data_set)->elements[0].length);
        gss_release_buffer_set(&minor, data_set);
    }

    return major_status;
}

OM_uint32
gss_krb5int_extract_authz_data_from_sec_context(
   OM_uint32 *minor_status,
   const gss_ctx_id_t context_handle,
   const gss_OID desired_object,
   gss_buffer_set_t *data_set)
{
    gss_buffer_desc ad_data;
    OM_uint32 major_status;
    krb5_error_code code;
    krb5_gss_ctx_id_rec *ctx;
    int ad_type = 0;
    int i, j;

    *data_set = GSS_C_NO_BUFFER_SET;

    ctx = (krb5_gss_ctx_id_rec *) context_handle;

    major_status = generic_gss_oid_decompose(minor_status,
                                             GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID,
                                             GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID_LENGTH,
                                             desired_object,
                                             &ad_type);
    if (major_status != GSS_S_COMPLETE || ad_type == 0) {
        *minor_status = ENOENT;
        return major_status; /* SUNW17PACresync */
    }

    if (ctx->authdata != NULL) {
        for (i = 0; ctx->authdata[i] != NULL; i++) {
            if (ctx->authdata[i]->ad_type == ad_type) {

                ad_data.length = ctx->authdata[i]->length;
                ad_data.value = ctx->authdata[i]->contents;

                major_status = generic_gss_add_buffer_set_member(minor_status,
                                                                 &ad_data, data_set);
                if (GSS_ERROR(major_status))
                    break;
            } else if (ctx->authdata[i]->ad_type == KRB5_AUTHDATA_IF_RELEVANT) {
                /*
                 * Solaris Kerberos (illumos)
                 * Unwrap the AD-IF-RELEVANT object and look inside.
                 */
                krb5_authdata **ad_if_relevant = NULL;
                code = krb5_decode_authdata_container(ctx->k5_context,
                                                      KRB5_AUTHDATA_IF_RELEVANT,
                                                      ctx->authdata[i],
                                                      &ad_if_relevant);
                if (code != 0)
                    continue;

                for (j = 0; ad_if_relevant[j] != NULL; j++) {
                    if (ad_if_relevant[j]->ad_type == ad_type) {
                        ad_data.length = ad_if_relevant[j]->length;
                        ad_data.value = ad_if_relevant[j]->contents;

                        major_status = generic_gss_add_buffer_set_member(minor_status,
                                                                         &ad_data, data_set);
                        if (GSS_ERROR(major_status)) {
                            krb5_free_authdata(ctx->k5_context, ad_if_relevant);
                            goto break2;
                        }
                    }
                }
                krb5_free_authdata(ctx->k5_context, ad_if_relevant);
                /* Solaris Kerberos (illumos) */
            }
        }
    }

break2:
    if (GSS_ERROR(major_status)) {
        OM_uint32 tmp;

        generic_gss_release_buffer_set(&tmp, data_set);
    }

    return major_status;
}

OM_uint32
gss_krb5int_extract_authtime_from_sec_context(OM_uint32 *minor_status,
                                              const gss_ctx_id_t context_handle,
                                              const gss_OID desired_oid,
                                              gss_buffer_set_t *data_set)
{
    krb5_gss_ctx_id_rec *ctx;
    gss_buffer_desc rep;

    ctx = (krb5_gss_ctx_id_rec *) context_handle;

    rep.value = &ctx->krb_times.authtime;
    rep.length = sizeof(ctx->krb_times.authtime);

    return generic_gss_add_buffer_set_member(minor_status, &rep, data_set);
}

