/*
 * COPYRIGHT (C) 2006,2007
 * THE REGENTS OF THE UNIVERSITY OF MICHIGAN
 * ALL RIGHTS RESERVED
 *
 * Permission is granted to use, copy, create derivative works
 * and redistribute this software and such derivative works
 * for any purpose, so long as the name of The University of
 * Michigan is not used in any advertising or publicity
 * pertaining to the use of distribution of this software
 * without specific, written prior authorization.  If the
 * above copyright notice or any other identification of the
 * University of Michigan is included in any copy of any
 * portion of this software, then the disclaimer below must
 * also be included.
 *
 * THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION
 * FROM THE UNIVERSITY OF MICHIGAN AS TO ITS FITNESS FOR ANY
 * PURPOSE, AND WITHOUT WARRANTY BY THE UNIVERSITY OF
 * MICHIGAN OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING
 * WITHOUT LIMITATION THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
 * REGENTS OF THE UNIVERSITY OF MICHIGAN SHALL NOT BE LIABLE
 * FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES, WITH RESPECT TO ANY CLAIM ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OF THE SOFTWARE, EVEN
 * IF IT HAS BEEN OR IS HEREAFTER ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGES.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <dlfcn.h>
#include <sys/stat.h>

#include "pkinit.h"

#ifdef LONGHORN_BETA_COMPAT
/*
 * It is anticipated that all the special checks currently
 * required when talking to a Longhorn server will go away
 * by the time it is officially released and all references
 * to the longhorn global can be removed and any code
 * #ifdef'd with LONGHORN_BETA_COMPAT can be removed.
 *
 * Current testing (20070620) is against a patched Beta 3
 * version of Longhorn.  Most, if not all, problems should
 * be fixed in SP1 of Longhorn.
 */
int longhorn = 0;	/* Talking to a Longhorn server? */
#endif

krb5_error_code pkinit_client_process
	(krb5_context context, void *plugin_context, void *request_context,
		krb5_get_init_creds_opt *gic_opt,
		preauth_get_client_data_proc get_data_proc,
		struct _krb5_preauth_client_rock *rock,
		krb5_kdc_req * request, krb5_data *encoded_request_body,
		krb5_data *encoded_previous_request, krb5_pa_data *in_padata,
		krb5_prompter_fct prompter, void *prompter_data,
		preauth_get_as_key_proc gak_fct, void *gak_data,
		krb5_data * salt, krb5_data * s2kparams,
		krb5_keyblock * as_key, krb5_pa_data *** out_padata);

krb5_error_code pkinit_client_tryagain
	(krb5_context context, void *plugin_context, void *request_context,
		krb5_get_init_creds_opt *gic_opt,
		preauth_get_client_data_proc get_data_proc,
		struct _krb5_preauth_client_rock *rock,
		krb5_kdc_req * request, krb5_data *encoded_request_body,
		krb5_data *encoded_previous_request,
		krb5_pa_data *in_padata, krb5_error *err_reply,
		krb5_prompter_fct prompter, void *prompter_data,
		preauth_get_as_key_proc gak_fct, void *gak_data,
		krb5_data * salt, krb5_data * s2kparams,
		krb5_keyblock * as_key, krb5_pa_data *** out_padata);

void pkinit_client_req_init
	(krb5_context contex, void *plugin_context, void **request_context);

void pkinit_client_req_fini
	(krb5_context context, void *plugin_context, void *request_context);

krb5_error_code pa_pkinit_gen_req
	(krb5_context context, pkinit_context plgctx,
		pkinit_req_context reqctx, krb5_kdc_req * request,
		krb5_pa_data * in_padata, krb5_pa_data *** out_padata,
		krb5_prompter_fct prompter, void *prompter_data,
		krb5_get_init_creds_opt *gic_opt);

krb5_error_code pkinit_as_req_create
	(krb5_context context, pkinit_context plgctx,
		pkinit_req_context reqctx, krb5_timestamp ctsec,
		krb5_int32 cusec, krb5_ui_4 nonce,
		const krb5_checksum * cksum, krb5_principal server,
		krb5_data ** as_req);

krb5_error_code pkinit_as_rep_parse
	(krb5_context context, pkinit_context plgctx,
		pkinit_req_context reqctx, krb5_preauthtype pa_type,
		krb5_kdc_req * request, const krb5_data * as_rep,
		krb5_keyblock * key_block, krb5_enctype etype, krb5_data *);

krb5_error_code pa_pkinit_parse_rep
	(krb5_context context, pkinit_context plgctx,
		pkinit_req_context reqcxt, krb5_kdc_req * request,
		krb5_pa_data * in_padata, krb5_enctype etype,
		krb5_keyblock * as_key, krb5_data *);

static int pkinit_client_plugin_init(krb5_context context, void **blob);
static void pkinit_client_plugin_fini(krb5_context context, void *blob);

/* ARGSUSED */
krb5_error_code
pa_pkinit_gen_req(krb5_context context,
		  pkinit_context plgctx,
		  pkinit_req_context reqctx,
		  krb5_kdc_req * request,
		  krb5_pa_data * in_padata,
		  krb5_pa_data *** out_padata,
		  krb5_prompter_fct prompter,
		  void *prompter_data,
		  krb5_get_init_creds_opt *gic_opt)
{

    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    krb5_data *out_data = NULL;
    krb5_timestamp ctsec = 0;
    krb5_int32 cusec = 0;
    krb5_ui_4 nonce = 0;
    krb5_checksum cksum;
    krb5_data *der_req = NULL;
    krb5_pa_data **return_pa_data = NULL;

    cksum.contents = NULL;
    reqctx->pa_type = in_padata->pa_type;

    pkiDebug("kdc_options = 0x%x  till = %d\n",
	     request->kdc_options, request->till);
    /* If we don't have a client, we're done */
    if (request->client == NULL) {
	pkiDebug("No request->client; aborting PKINIT\n");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    retval = pkinit_get_kdc_cert(context, plgctx->cryptoctx, reqctx->cryptoctx,
				 reqctx->idctx, request->server);
    if (retval) {
	pkiDebug("pkinit_get_kdc_cert returned %d\n", retval);
	goto cleanup;
    }

    /* checksum of the encoded KDC-REQ-BODY */
    retval = k5int_encode_krb5_kdc_req_body(request, &der_req);
    if (retval) {
	pkiDebug("encode_krb5_kdc_req_body returned %d\n", (int) retval);
	goto cleanup;
    }

    retval = krb5_c_make_checksum(context, CKSUMTYPE_NIST_SHA, NULL, 0,
				  der_req, &cksum);
    if (retval)
	goto cleanup;
#ifdef DEBUG_CKSUM
    pkiDebug("calculating checksum on buf size (%d)\n", der_req->length);
    print_buffer(der_req->data, der_req->length);
#endif

    retval = krb5_us_timeofday(context, &ctsec, &cusec);
    if (retval)
	goto cleanup;

    /* XXX PKINIT RFC says that nonce in PKAuthenticator doesn't have be the
     * same as in the AS_REQ. However, if we pick a different nonce, then we
     * need to remember that info when AS_REP is returned. I'm choosing to
     * reuse the AS_REQ nonce.
     */
    nonce = request->nonce;

    retval = pkinit_as_req_create(context, plgctx, reqctx, ctsec, cusec,
				  nonce, &cksum, request->server, &out_data);
    if (retval || !out_data->length) {
	pkiDebug("error %d on pkinit_as_req_create; aborting PKINIT\n",
		 (int) retval);
	goto cleanup;
    }
    retval = ENOMEM;
    /*
     * The most we'll return is two pa_data, normally just one.
     * We need to make room for the NULL terminator.
     */
    return_pa_data = (krb5_pa_data **) malloc(3 * sizeof(krb5_pa_data *));
    if (return_pa_data == NULL)
	goto cleanup;

    return_pa_data[1] = NULL;	/* in case of an early trip to cleanup */
    return_pa_data[2] = NULL;	/* Terminate the list */

    return_pa_data[0] = (krb5_pa_data *) malloc(sizeof(krb5_pa_data));
    if (return_pa_data[0] == NULL)
	goto cleanup;

    return_pa_data[1] = (krb5_pa_data *) malloc(sizeof(krb5_pa_data));
    if (return_pa_data[1] == NULL)
	goto cleanup;

    return_pa_data[0]->magic = KV5M_PA_DATA;

    if (in_padata->pa_type == KRB5_PADATA_PK_AS_REQ_OLD)
	return_pa_data[0]->pa_type = KRB5_PADATA_PK_AS_REP_OLD;
    else
	return_pa_data[0]->pa_type = in_padata->pa_type;
    return_pa_data[0]->length = out_data->length;
    return_pa_data[0]->contents = (krb5_octet *) out_data->data;

#ifdef LONGHORN_BETA_COMPAT
    /*
     * LH Beta 3 requires the extra pa-data, even for RFC requests,
     * in order to get the Checksum rather than a Nonce in the reply.
     * This can be removed when LH SP1 is released.
     */
    if ((return_pa_data[0]->pa_type == KRB5_PADATA_PK_AS_REP_OLD
	&& reqctx->opts->win2k_require_cksum) || (longhorn == 1)) {
#else
    if ((return_pa_data[0]->pa_type == KRB5_PADATA_PK_AS_REP_OLD
	&& reqctx->opts->win2k_require_cksum)) {
#endif
	return_pa_data[1]->pa_type = 132;
	return_pa_data[1]->length = 0;
	return_pa_data[1]->contents = NULL;
    } else {
	free(return_pa_data[1]);
	return_pa_data[1] = NULL;   /* Move the list terminator */
    }
    *out_padata = return_pa_data;
    retval = 0;

  cleanup:
    if (der_req != NULL)
	krb5_free_data(context, der_req);

    if (out_data != NULL)
	free(out_data);

    if (retval) {
	if (return_pa_data) {
	    if (return_pa_data[0] != NULL)
		free(return_pa_data[0]);
	    if (return_pa_data[1] != NULL)
		free(return_pa_data[1]);
	    free(return_pa_data);
	}
	if (out_data) {
	    free(out_data->data);
	    free(out_data);
	}
    }
    return retval;
}

krb5_error_code
pkinit_as_req_create(krb5_context context,
		     pkinit_context plgctx,
		     pkinit_req_context reqctx,
		     krb5_timestamp ctsec,
		     krb5_int32 cusec,
		     krb5_ui_4 nonce,
		     const krb5_checksum * cksum,
		     krb5_principal server,
		     krb5_data ** as_req)
{
    krb5_error_code retval = ENOMEM;
    krb5_subject_pk_info *info = NULL;
    krb5_data *coded_auth_pack = NULL;
    krb5_auth_pack *auth_pack = NULL;
    krb5_pa_pk_as_req *req = NULL;
    krb5_auth_pack_draft9 *auth_pack9 = NULL;
    krb5_pa_pk_as_req_draft9 *req9 = NULL;
    int protocol = reqctx->opts->dh_or_rsa;

    pkiDebug("pkinit_as_req_create pa_type = %d\n", reqctx->pa_type);

    /* Create the authpack */
    switch((int)reqctx->pa_type) {
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    protocol = RSA_PROTOCOL;
	    init_krb5_auth_pack_draft9(&auth_pack9);
	    if (auth_pack9 == NULL)
		goto cleanup;
	    auth_pack9->pkAuthenticator.ctime = ctsec;
	    auth_pack9->pkAuthenticator.cusec = cusec;
	    auth_pack9->pkAuthenticator.nonce = nonce;
	    auth_pack9->pkAuthenticator.kdcName = server;
	    auth_pack9->pkAuthenticator.kdcRealm.magic = 0;
	    auth_pack9->pkAuthenticator.kdcRealm.data =
					(unsigned char *)server->realm.data;
	    auth_pack9->pkAuthenticator.kdcRealm.length = server->realm.length;
	    free(cksum->contents);
	    break;
	case KRB5_PADATA_PK_AS_REQ:
	    init_krb5_subject_pk_info(&info);
	    if (info == NULL)
		goto cleanup;
	    init_krb5_auth_pack(&auth_pack);
	    if (auth_pack == NULL)
		goto cleanup;
	    auth_pack->pkAuthenticator.ctime = ctsec;
	    auth_pack->pkAuthenticator.cusec = cusec;
	    auth_pack->pkAuthenticator.nonce = nonce;
	    auth_pack->pkAuthenticator.paChecksum = *cksum;
	    auth_pack->clientDHNonce.length = 0;
	    auth_pack->clientPublicValue = info;

	    /* add List of CMS algorithms */
	    retval = create_krb5_supportedCMSTypes(context, plgctx->cryptoctx,
			reqctx->cryptoctx, reqctx->idctx,
			&auth_pack->supportedCMSTypes);
	    if (retval)
		goto cleanup;
	    break;
	default:
	    pkiDebug("as_req: unrecognized pa_type = %d\n",
		    (int)reqctx->pa_type);
	    retval = -1;
	    goto cleanup;
    }

    switch(protocol) {
	case DH_PROTOCOL:
	    pkiDebug("as_req: DH key transport algorithm\n");
	    retval = pkinit_copy_krb5_octet_data(&info->algorithm.algorithm, &dh_oid);
	    if (retval) {
		pkiDebug("failed to copy dh_oid\n");
		goto cleanup;
	    }

	    /* create client-side DH keys */
	    if ((retval = client_create_dh(context, plgctx->cryptoctx,
		    reqctx->cryptoctx, reqctx->idctx, reqctx->opts->dh_size,
		    &info->algorithm.parameters.data,
		    &info->algorithm.parameters.length,
		    &info->subjectPublicKey.data,
		    &info->subjectPublicKey.length)) != 0) {
		pkiDebug("failed to create dh parameters\n");
		goto cleanup;
	    }
	    break;
	case RSA_PROTOCOL:
	    pkiDebug("as_req: RSA key transport algorithm\n");
	    switch((int)reqctx->pa_type) {
		case KRB5_PADATA_PK_AS_REQ_OLD:
		    auth_pack9->clientPublicValue = NULL;
		    break;
		case KRB5_PADATA_PK_AS_REQ:
		    free_krb5_subject_pk_info(&info);
		    auth_pack->clientPublicValue = NULL;
		    break;
	    }
	    break;
	default:
	    pkiDebug("as_req: unknown key transport protocol %d\n",
		    protocol);
	    retval = -1;
	    goto cleanup;
    }

    /* Encode the authpack */
    switch((int)reqctx->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    retval = k5int_encode_krb5_auth_pack(auth_pack, &coded_auth_pack);
	    break;
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    retval = k5int_encode_krb5_auth_pack_draft9(auth_pack9,
							&coded_auth_pack);
	    break;
    }
    if (retval) {
	pkiDebug("failed to encode the AuthPack %d\n", retval);
	goto cleanup;
    }
#ifdef DEBUG_ASN1
    print_buffer_bin((unsigned char *)coded_auth_pack->data,
		     coded_auth_pack->length,
		     "/tmp/client_auth_pack");
#endif

    /* create PKCS7 object from authpack */
    switch((int)reqctx->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    init_krb5_pa_pk_as_req(&req);
	    if (req == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    retval = cms_signeddata_create(context, plgctx->cryptoctx,
		reqctx->cryptoctx, reqctx->idctx, CMS_SIGN_CLIENT, 1,
		(unsigned char *)coded_auth_pack->data, coded_auth_pack->length,
		&req->signedAuthPack.data, &req->signedAuthPack.length);
#ifdef DEBUG_ASN1
	    print_buffer_bin((unsigned char *)req->signedAuthPack.data,
			     req->signedAuthPack.length,
			     "/tmp/client_signed_data");
#endif
	    break;
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    init_krb5_pa_pk_as_req_draft9(&req9);
	    if (req9 == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    retval = cms_signeddata_create(context, plgctx->cryptoctx,
		reqctx->cryptoctx, reqctx->idctx, CMS_SIGN_DRAFT9, 1,
		(unsigned char *)coded_auth_pack->data, coded_auth_pack->length,
		&req9->signedAuthPack.data, &req9->signedAuthPack.length);
	    break;
#ifdef DEBUG_ASN1
	    print_buffer_bin((unsigned char *)req9->signedAuthPack.data,
			     req9->signedAuthPack.length,
			     "/tmp/client_signed_data_draft9");
#endif
    }
    krb5_free_data(context, coded_auth_pack);
    if (retval) {
	pkiDebug("failed to create pkcs7 signed data\n");
	goto cleanup;
    }

    /* create a list of trusted CAs */
    switch((int)reqctx->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    retval = create_krb5_trustedCertifiers(context, plgctx->cryptoctx,
		reqctx->cryptoctx, reqctx->idctx, &req->trustedCertifiers);
	    if (retval)
		goto cleanup;
	    retval = create_issuerAndSerial(context, plgctx->cryptoctx,
		reqctx->cryptoctx, reqctx->idctx, &req->kdcPkId.data,
		&req->kdcPkId.length);
	    if (retval)
		goto cleanup;

	    /* Encode the as-req */
	    retval = k5int_encode_krb5_pa_pk_as_req(req, as_req);
	    break;
	case KRB5_PADATA_PK_AS_REQ_OLD:
#if 0
	    /* W2K3 KDC doesn't like this */
	    retval = create_krb5_trustedCas(context, plgctx->cryptoctx,
		reqctx->cryptoctx, reqctx->idctx, 1, &req9->trustedCertifiers);
	    if (retval)
		goto cleanup;

#endif
	    retval = create_issuerAndSerial(context, plgctx->cryptoctx,
		reqctx->cryptoctx, reqctx->idctx, &req9->kdcCert.data,
		&req9->kdcCert.length);
	    if (retval)
		goto cleanup;
	    /* Encode the as-req */
	    retval = k5int_encode_krb5_pa_pk_as_req_draft9(req9, as_req);
	    break;
    }
#ifdef DEBUG_ASN1
    if (!retval)
	print_buffer_bin((unsigned char *)(*as_req)->data, (*as_req)->length,
			 "/tmp/client_as_req");
#endif

cleanup:
    switch((int)reqctx->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    free_krb5_auth_pack(&auth_pack);
	    free_krb5_pa_pk_as_req(&req);
	    break;
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    free_krb5_pa_pk_as_req_draft9(&req9);
	    free(auth_pack9);
	    break;
    }


    pkiDebug("pkinit_as_req_create retval=%d\n", (int) retval);

    return retval;
}

krb5_error_code
pa_pkinit_parse_rep(krb5_context context,
		    pkinit_context plgctx,
		    pkinit_req_context reqctx,
		    krb5_kdc_req * request,
		    krb5_pa_data * in_padata,
		    krb5_enctype etype,
		    krb5_keyblock * as_key,
		    krb5_data *encoded_request)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    krb5_data asRep = { 0, 0, NULL};

    /*
     * One way or the other - success or failure - no other PA systems can
     * work if the server sent us a PKINIT reply, since only we know how to
     * decrypt the key.
     */
    if ((in_padata == NULL) || (in_padata->length == 0)) {
	pkiDebug("pa_pkinit_parse_rep: no in_padata\n");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    asRep.data = (char *) in_padata->contents;
    asRep.length = in_padata->length;

    retval =
	pkinit_as_rep_parse(context, plgctx, reqctx, in_padata->pa_type,
			    request, &asRep, as_key, etype, encoded_request);
    if (retval) {
	pkiDebug("pkinit_as_rep_parse returned %d (%s)\n",
		 retval, error_message(retval));
	goto cleanup;
    }

    retval = 0;

cleanup:

    return retval;
}

static krb5_error_code
verify_kdc_san(krb5_context context,
	       pkinit_context plgctx,
	       pkinit_req_context reqctx,
	       krb5_principal kdcprinc,
	       int *valid_san,
	       int *need_eku_checking)
{
    krb5_error_code retval;
    char **certhosts = NULL, **cfghosts = NULL;
    krb5_principal *princs = NULL;
    unsigned char ***get_dns;
    int i, j;

    *valid_san = 0;
    *need_eku_checking = 1;

    retval = pkinit_libdefault_strings(context,
				       krb5_princ_realm(context, kdcprinc),
				       "pkinit_kdc_hostname",
				       &cfghosts);
    if (retval || cfghosts == NULL) {
	pkiDebug("%s: No pkinit_kdc_hostname values found in config file\n",
		 __FUNCTION__);
	get_dns = NULL;
    } else {
	pkiDebug("%s: pkinit_kdc_hostname values found in config file\n",
		 __FUNCTION__);
	get_dns = (unsigned char ***)&certhosts;
    }

    retval = crypto_retrieve_cert_sans(context, plgctx->cryptoctx,
				       reqctx->cryptoctx, reqctx->idctx,
				       &princs, NULL, get_dns);
    if (retval) {
	pkiDebug("%s: error from retrieve_certificate_sans()\n", __FUNCTION__);
	retval = KRB5KDC_ERR_KDC_NAME_MISMATCH;
	goto out;
    }
#if 0
    retval = call_san_checking_plugins(context, plgctx, reqctx, idctx,
				       princs, hosts, &plugin_decision,
				       need_eku_checking);
    pkiDebug("%s: call_san_checking_plugins() returned retval %d\n",
	     __FUNCTION__);
    if (retval) {
	retval = KRB5KDC_ERR_KDC_NAME_MISMATCH;
	goto out;
    }
    pkiDebug("%s: call_san_checking_plugins() returned decision %d and "
	     "need_eku_checking %d\n",
	     __FUNCTION__, plugin_decision, *need_eku_checking);
    if (plugin_decision != NO_DECISION) {
	retval = plugin_decision;
	goto out;
    }
#endif

    pkiDebug("%s: Checking pkinit sans\n", __FUNCTION__);
    for (i = 0; princs != NULL && princs[i] != NULL; i++) {
	if (krb5_principal_compare(context, princs[i], kdcprinc)) {
	    pkiDebug("%s: pkinit san match found\n", __FUNCTION__);
	    *valid_san = 1;
	    *need_eku_checking = 0;
	    retval = 0;
	    goto out;
	}
    }
    pkiDebug("%s: no pkinit san match found\n", __FUNCTION__);

    if (certhosts == NULL) {
	pkiDebug("%s: no certhosts (or we wouldn't accept them anyway)\n",
		 __FUNCTION__);
	retval = KRB5KDC_ERR_KDC_NAME_MISMATCH;
	goto out;
    }

    for (i = 0; certhosts[i] != NULL; i++) {
	for (j = 0; cfghosts != NULL && cfghosts[j] != NULL; j++) {
	    pkiDebug("%s: comparing cert name '%s' with config name '%s'\n",
		     __FUNCTION__, certhosts[i], cfghosts[j]);
	    if (strcmp(certhosts[i], cfghosts[j]) == 0) {
		pkiDebug("%s: we have a dnsName match\n", __FUNCTION__);
		*valid_san = 1;
		retval = 0;
		goto out;
	    }
	}
    }
    pkiDebug("%s: no dnsName san match found\n", __FUNCTION__);

    /* We found no match */
    retval = 0;

out:
    if (princs != NULL) {
	for (i = 0; princs[i] != NULL; i++)
	    krb5_free_principal(context, princs[i]);
	free(princs);
    }
    if (certhosts != NULL) {
	for (i = 0; certhosts[i] != NULL; i++)
	    free(certhosts[i]);
	free(certhosts);
    }
    if (cfghosts != NULL)
	profile_free_list(cfghosts);

    pkiDebug("%s: returning retval %d, valid_san %d, need_eku_checking %d\n",
	     __FUNCTION__, retval, *valid_san, *need_eku_checking);
    return retval;
}

static krb5_error_code
verify_kdc_eku(krb5_context context,
	       pkinit_context plgctx,
	       pkinit_req_context reqctx,
	       int *eku_accepted)
{
    krb5_error_code retval;

    *eku_accepted = 0;

    if (reqctx->opts->require_eku == 0) {
	pkiDebug("%s: configuration requests no EKU checking\n", __FUNCTION__);
	*eku_accepted = 1;
	retval = 0;
	goto out;
    }
    retval = crypto_check_cert_eku(context, plgctx->cryptoctx,
				   reqctx->cryptoctx, reqctx->idctx,
				   1, /* kdc cert */
				   reqctx->opts->accept_secondary_eku,
				   eku_accepted);
    if (retval) {
	pkiDebug("%s: Error from crypto_check_cert_eku %d (%s)\n",
		 __FUNCTION__, retval, error_message(retval));
	goto out;
    }

out:
    pkiDebug("%s: returning retval %d, eku_accepted %d\n",
	     __FUNCTION__, retval, *eku_accepted);
    return retval;
}

/*
 * Parse PA-PK-AS-REP message. Optionally evaluates the message's
 * certificate chain.
 * Optionally returns various components.
 */
krb5_error_code
pkinit_as_rep_parse(krb5_context context,
		    pkinit_context plgctx,
  		    pkinit_req_context reqctx,
		    krb5_preauthtype pa_type,
		    krb5_kdc_req *request,
		    const krb5_data *as_rep,
		    krb5_keyblock *key_block,
		    krb5_enctype etype,
		    krb5_data *encoded_request)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    krb5_pa_pk_as_rep *kdc_reply = NULL;
    krb5_kdc_dh_key_info *kdc_dh = NULL;
    krb5_reply_key_pack *key_pack = NULL;
    krb5_reply_key_pack_draft9 *key_pack9 = NULL;
    krb5_octet_data dh_data = { 0, 0, NULL };
    unsigned char *client_key = NULL, *kdc_hostname = NULL;
    unsigned int client_key_len = 0;
    krb5_checksum cksum = {0, 0, 0, NULL};
    krb5_data k5data;
    int valid_san = 0;
    int valid_eku = 0;
    int need_eku_checking = 1;

    assert((as_rep != NULL) && (key_block != NULL));

#ifdef DEBUG_ASN1
    print_buffer_bin((unsigned char *)as_rep->data, as_rep->length,
		     "/tmp/client_as_rep");
#endif

    if ((retval = k5int_decode_krb5_pa_pk_as_rep(as_rep, &kdc_reply))) {
	pkiDebug("decode_krb5_as_rep failed %d\n", retval);
	return retval;
    }

    switch(kdc_reply->choice) {
	case choice_pa_pk_as_rep_dhInfo:
	    pkiDebug("as_rep: DH key transport algorithm\n");
#ifdef DEBUG_ASN1
    print_buffer_bin(kdc_reply->u.dh_Info.dhSignedData.data,
	kdc_reply->u.dh_Info.dhSignedData.length, "/tmp/client_kdc_signeddata");
#endif
	    if ((retval = cms_signeddata_verify(context, plgctx->cryptoctx,
		    reqctx->cryptoctx, reqctx->idctx, CMS_SIGN_SERVER,
		    reqctx->opts->require_crl_checking,
		    kdc_reply->u.dh_Info.dhSignedData.data,
		    kdc_reply->u.dh_Info.dhSignedData.length,
		    &dh_data.data, &dh_data.length, NULL, NULL)) != 0) {
		pkiDebug("failed to verify pkcs7 signed data\n");
		goto cleanup;
	    }

	    break;
	case choice_pa_pk_as_rep_encKeyPack:
	    pkiDebug("as_rep: RSA key transport algorithm\n");
	    if ((retval = cms_envelopeddata_verify(context, plgctx->cryptoctx,
		    reqctx->cryptoctx, reqctx->idctx, pa_type,
		    reqctx->opts->require_crl_checking,
		    kdc_reply->u.encKeyPack.data,
		    kdc_reply->u.encKeyPack.length,
		    &dh_data.data, &dh_data.length)) != 0) {
		pkiDebug("failed to verify pkcs7 enveloped data\n");
		goto cleanup;
	    }
	    break;
	default:
	    pkiDebug("unknown as_rep type %d\n", kdc_reply->choice);
	    retval = -1;
	    goto cleanup;
    }

    retval = verify_kdc_san(context, plgctx, reqctx, request->server,
			    &valid_san, &need_eku_checking);
    if (retval)
	    goto cleanup;
    if (!valid_san) {
	pkiDebug("%s: did not find an acceptable SAN in KDC certificate\n",
		 __FUNCTION__);
	retval = KRB5KDC_ERR_KDC_NAME_MISMATCH;
	goto cleanup;
    }

    if (need_eku_checking) {
	retval = verify_kdc_eku(context, plgctx, reqctx,
				&valid_eku);
	if (retval)
	    goto cleanup;
	if (!valid_eku) {
	    pkiDebug("%s: did not find an acceptable EKU in KDC certificate\n",
		     __FUNCTION__);
	    retval = KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE;
	    goto cleanup;
	}
    } else
	pkiDebug("%s: skipping EKU check\n", __FUNCTION__);

    OCTETDATA_TO_KRB5DATA(&dh_data, &k5data);

    switch(kdc_reply->choice) {
	case choice_pa_pk_as_rep_dhInfo:
#ifdef DEBUG_ASN1
	    print_buffer_bin(dh_data.data, dh_data.length,
			     "/tmp/client_dh_key");
#endif
	    if ((retval = k5int_decode_krb5_kdc_dh_key_info(&k5data,
		    &kdc_dh)) != 0) {
		pkiDebug("failed to decode kdc_dh_key_info\n");
		goto cleanup;
	    }

	    /* client after KDC reply */
	    if ((retval = client_process_dh(context, plgctx->cryptoctx,
		    reqctx->cryptoctx, reqctx->idctx,
		    kdc_dh->subjectPublicKey.data,
		    kdc_dh->subjectPublicKey.length,
		    &client_key, &client_key_len)) != 0) {
		pkiDebug("failed to process dh params\n");
		goto cleanup;
	    }

	    retval = pkinit_octetstring2key(context, etype, client_key,
					  client_key_len, key_block);
	    if (retval) {
		pkiDebug("failed to create key pkinit_octetstring2key %s\n",
			 error_message(retval));
		goto cleanup;
	    }

	    break;
	case choice_pa_pk_as_rep_encKeyPack:
#ifdef DEBUG_ASN1
	    print_buffer_bin(dh_data.data, dh_data.length,
			     "/tmp/client_key_pack");
#endif
	    if ((retval = k5int_decode_krb5_reply_key_pack(&k5data,
		    &key_pack)) != 0) {
		pkiDebug("failed to decode reply_key_pack\n");
#ifdef LONGHORN_BETA_COMPAT
    /*
     * LH Beta 3 requires the extra pa-data, even for RFC requests,
     * in order to get the Checksum rather than a Nonce in the reply.
     * This can be removed when LH SP1 is released.
     */
		if (pa_type == KRB5_PADATA_PK_AS_REP && longhorn == 0)
#else
		if (pa_type == KRB5_PADATA_PK_AS_REP)
#endif
		    goto cleanup;
		else {
		    if ((retval =
			k5int_decode_krb5_reply_key_pack_draft9(&k5data,
							  &key_pack9)) != 0) {
			pkiDebug("failed to decode reply_key_pack_draft9\n");
			goto cleanup;
		    }
		    pkiDebug("decode reply_key_pack_draft9\n");
		    if (key_pack9->nonce != request->nonce) {
			pkiDebug("nonce in AS_REP=%d doesn't match AS_REQ=%d\n",				 key_pack9->nonce, request->nonce);
			retval = -1;
			goto cleanup;
		    }
		    krb5_copy_keyblock_contents(context, &key_pack9->replyKey,
						key_block);
		    break;
		}
	    }
	    /*
	     * This is hack but Windows sends back SHA1 checksum
	     * with checksum type of 14. There is currently no
	     * checksum type of 14 defined.
	     */
	    if (key_pack->asChecksum.checksum_type == 14)
		key_pack->asChecksum.checksum_type = CKSUMTYPE_NIST_SHA;
	    retval = krb5_c_make_checksum(context,
					  key_pack->asChecksum.checksum_type,
					  &key_pack->replyKey,
					  KRB5_KEYUSAGE_TGS_REQ_AUTH_CKSUM,
					  encoded_request, &cksum);
	    if (retval) {
		pkiDebug("failed to make a checksum\n");
		goto cleanup;
	    }

	    if ((cksum.length != key_pack->asChecksum.length) ||
		memcmp(cksum.contents, key_pack->asChecksum.contents,
			cksum.length)) {
		pkiDebug("failed to match the checksums\n");
#ifdef DEBUG_CKSUM
	    pkiDebug("calculating checksum on buf size (%d)\n",
		     encoded_request->length);
	    print_buffer(encoded_request->data, encoded_request->length);
	    pkiDebug("encrypting key (%d)\n", key_pack->replyKey.length);
	    print_buffer(key_pack->replyKey.contents,
			 key_pack->replyKey.length);
	    pkiDebug("received checksum type=%d size=%d ",
		     key_pack->asChecksum.checksum_type,
		     key_pack->asChecksum.length);
	    print_buffer(key_pack->asChecksum.contents,
			 key_pack->asChecksum.length);
	    pkiDebug("expected checksum type=%d size=%d ",
		     cksum.checksum_type, cksum.length);
	    print_buffer(cksum.contents, cksum.length);
#endif
		goto cleanup;
	    } else
		pkiDebug("checksums match\n");

	    krb5_copy_keyblock_contents(context, &key_pack->replyKey,
					key_block);

	    break;
	default:
	    pkiDebug("unknow as_rep type %d\n", kdc_reply->choice);
	    goto cleanup;
    }

    retval = 0;

cleanup:
    if (dh_data.data != NULL)
	free(dh_data.data);
    if (client_key != NULL)
	free(client_key);
    free_krb5_kdc_dh_key_info(&kdc_dh);
    free_krb5_pa_pk_as_rep(&kdc_reply);

    if (key_pack != NULL) {
	free_krb5_reply_key_pack(&key_pack);
	if (cksum.contents != NULL)
	    free(cksum.contents);
    }
    if (key_pack9 != NULL)
	free_krb5_reply_key_pack_draft9(&key_pack9);

    if (kdc_hostname != NULL)
	free(kdc_hostname);

    pkiDebug("pkinit_as_rep_parse returning %d (%s)\n",
	     retval, error_message(retval));
    return retval;
}

static void
pkinit_client_profile(krb5_context context,
		      pkinit_context plgctx,
		      pkinit_req_context reqctx,
		      krb5_kdc_req *request)
{
    char *eku_string = NULL;

    pkiDebug("pkinit_client_profile %p %p %p %p\n",
	     context, plgctx, reqctx, request);

    (void) pkinit_libdefault_boolean(context, &request->server->realm,
			      "pkinit_win2k",
			      reqctx->opts->win2k_target,
			      &reqctx->opts->win2k_target);
    (void) pkinit_libdefault_boolean(context, &request->server->realm,
			      "pkinit_win2k_require_binding",
			      reqctx->opts->win2k_require_cksum,
			      &reqctx->opts->win2k_require_cksum);
    (void) pkinit_libdefault_boolean(context, &request->server->realm,
			      "pkinit_require_crl_checking",
			      reqctx->opts->require_crl_checking,
			      &reqctx->opts->require_crl_checking);
    (void) pkinit_libdefault_integer(context, &request->server->realm,
			      "pkinit_dh_min_bits",
			      reqctx->opts->dh_size,
			      &reqctx->opts->dh_size);
    if (reqctx->opts->dh_size != 1024 && reqctx->opts->dh_size != 2048
        && reqctx->opts->dh_size != 4096) {
	pkiDebug("%s: invalid value (%d) for pkinit_dh_min_bits, "
		 "using default value (%d) instead\n", __FUNCTION__,
		 reqctx->opts->dh_size, PKINIT_DEFAULT_DH_MIN_BITS);
	reqctx->opts->dh_size = PKINIT_DEFAULT_DH_MIN_BITS;
    }
    (void) pkinit_libdefault_string(context, &request->server->realm,
			     "pkinit_eku_checking",
			     &eku_string);
    if (eku_string != NULL) {
	if (strcasecmp(eku_string, "kpKDC") == 0) {
	    reqctx->opts->require_eku = 1;
	    reqctx->opts->accept_secondary_eku = 0;
	} else if (strcasecmp(eku_string, "kpServerAuth") == 0) {
	    reqctx->opts->require_eku = 1;
	    reqctx->opts->accept_secondary_eku = 1;
	} else if (strcasecmp(eku_string, "none") == 0) {
	    reqctx->opts->require_eku = 0;
	    reqctx->opts->accept_secondary_eku = 0;
	} else {
	    pkiDebug("%s: Invalid value for pkinit_eku_checking: '%s'\n",
		     __FUNCTION__, eku_string);
	}
	free(eku_string);
    }
#ifdef LONGHORN_BETA_COMPAT
    /* Temporarily just set global flag from config file */
    (void) pkinit_libdefault_boolean(context, &request->server->realm,
			      "pkinit_longhorn",
			      0,
			      &longhorn);
#endif

    /* Only process anchors here if they were not specified on command line */
    if (reqctx->idopts->anchors == NULL)
	(void) pkinit_libdefault_strings(context, &request->server->realm,
				  "pkinit_anchors",
				  &reqctx->idopts->anchors);
    /* Solaris Kerberos */
    (void) pkinit_libdefault_strings(context, &request->server->realm,
			      "pkinit_pool",
			      &reqctx->idopts->intermediates);
    (void) pkinit_libdefault_strings(context, &request->server->realm,
			      "pkinit_revoke",
			      &reqctx->idopts->crls);
    (void) pkinit_libdefault_strings(context, &request->server->realm,
			      "pkinit_identities",
			      &reqctx->idopts->identity_alt);
}

/* ARGSUSED */
krb5_error_code
pkinit_client_process(krb5_context context,
		      void *plugin_context,
		      void *request_context,
		      krb5_get_init_creds_opt *gic_opt,
		      preauth_get_client_data_proc get_data_proc,
		      struct _krb5_preauth_client_rock *rock,
		      krb5_kdc_req *request,
		      krb5_data *encoded_request_body,
		      krb5_data *encoded_previous_request,
		      krb5_pa_data *in_padata,
		      krb5_prompter_fct prompter,
		      void *prompter_data,
		      preauth_get_as_key_proc gak_fct,
		      void *gak_data,
		      krb5_data *salt,
		      krb5_data *s2kparams,
		      krb5_keyblock *as_key,
		      krb5_pa_data ***out_padata)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    krb5_enctype enctype = -1;
    krb5_data *cdata = NULL;
    int processing_request = 0;
    pkinit_context plgctx = (pkinit_context)plugin_context;
    pkinit_req_context reqctx = (pkinit_req_context)request_context;

    pkiDebug("pkinit_client_process %p %p %p %p\n",
	     context, plgctx, reqctx, request);

    if (plgctx == NULL || reqctx == NULL)
	return EINVAL;

    switch ((int) in_padata->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    pkiDebug("processing KRB5_PADATA_PK_AS_REQ\n");
	    processing_request = 1;
	    break;

	case KRB5_PADATA_PK_AS_REP:
	    pkiDebug("processing KRB5_PADATA_PK_AS_REP\n");
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    if (in_padata->length == 0) {
		pkiDebug("processing KRB5_PADATA_PK_AS_REQ_OLD\n");
		in_padata->pa_type = KRB5_PADATA_PK_AS_REQ_OLD;
		processing_request = 1;
	    } else {
		pkiDebug("processing KRB5_PADATA_PK_AS_REP_OLD\n");
		in_padata->pa_type = KRB5_PADATA_PK_AS_REP_OLD;
	    }
	    break;
	default:
	    pkiDebug("unrecognized patype = %d for PKINIT\n",
		    in_padata->pa_type);
	    return EINVAL;
    }

    if (processing_request) {
	pkinit_client_profile(context, plgctx, reqctx, request);
	/* Solaris Kerberos */
	retval = pkinit_identity_set_prompter(reqctx->idctx, prompter, prompter_data);
	if (retval) {
	    pkiDebug("pkinit_identity_set_prompter returned %d (%s)\n",
		     retval, error_message(retval));
	    return retval;
	}

	retval = pkinit_identity_initialize(context, plgctx->cryptoctx,
					    reqctx->cryptoctx, reqctx->idopts,
					    reqctx->idctx, 1, request->client);
	if (retval) {
	    pkiDebug("pkinit_identity_initialize returned %d (%s)\n",
		     retval, error_message(retval));
	    return retval;
	}
	retval = pa_pkinit_gen_req(context, plgctx, reqctx, request,
				   in_padata, out_padata, prompter,
				   prompter_data, gic_opt);
    } else {
	/*
	 * Get the enctype of the reply.
	 */
	retval = (*get_data_proc)(context, rock,
				krb5plugin_preauth_client_get_etype, &cdata);
	if (retval) {
	    pkiDebug("get_data_proc returned %d (%s)\n",
		     retval, error_message(retval));
	    return retval;
	}
	enctype = *((krb5_enctype *)cdata->data);
	(*get_data_proc)(context, rock,
			 krb5plugin_preauth_client_free_etype, &cdata);
	retval = pa_pkinit_parse_rep(context, plgctx, reqctx, request,
				     in_padata, enctype, as_key,
				     encoded_previous_request);
    }

    pkiDebug("pkinit_client_process: returning %d (%s)\n",
	     retval, error_message(retval));
    return retval;
}

/* ARGSUSED */
krb5_error_code
pkinit_client_tryagain(krb5_context context,
		       void *plugin_context,
		       void *request_context,
		       krb5_get_init_creds_opt *gic_opt,
		       preauth_get_client_data_proc get_data_proc,
		       struct _krb5_preauth_client_rock *rock,
		       krb5_kdc_req *request,
		       krb5_data *encoded_request_body,
		       krb5_data *encoded_previous_request,
		       krb5_pa_data *in_padata,
		       krb5_error *err_reply,
		       krb5_prompter_fct prompter,
		       void *prompter_data,
		       preauth_get_as_key_proc gak_fct,
		       void *gak_data,
		       krb5_data *salt,
		       krb5_data *s2kparams,
		       krb5_keyblock *as_key,
		       krb5_pa_data ***out_padata)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    pkinit_context plgctx = (pkinit_context)plugin_context;
    pkinit_req_context reqctx = (pkinit_req_context)request_context;
    krb5_typed_data **typed_data = NULL;
    krb5_data scratch;
    krb5_external_principal_identifier **krb5_trusted_certifiers = NULL;
    krb5_algorithm_identifier **algId = NULL;
    int do_again = 0;

    pkiDebug("pkinit_client_tryagain %p %p %p %p\n",
	     context, plgctx, reqctx, request);

    if (reqctx->pa_type != in_padata->pa_type)
	return retval;

#ifdef DEBUG_ASN1
    print_buffer_bin((unsigned char *)err_reply->e_data.data,
		     err_reply->e_data.length, "/tmp/client_edata");
#endif
    retval = k5int_decode_krb5_typed_data(&err_reply->e_data, &typed_data);
    if (retval) {
	pkiDebug("decode_krb5_typed_data failed\n");
	goto cleanup;
    }
#ifdef DEBUG_ASN1
    print_buffer_bin(typed_data[0]->data, typed_data[0]->length,
		     "/tmp/client_typed_data");
#endif
    OCTETDATA_TO_KRB5DATA(typed_data[0], &scratch);

    switch(typed_data[0]->type) {
	case TD_TRUSTED_CERTIFIERS:
	case TD_INVALID_CERTIFICATES:
	    retval = k5int_decode_krb5_td_trusted_certifiers(&scratch,
		&krb5_trusted_certifiers);
	    if (retval) {
		pkiDebug("failed to decode sequence of trusted certifiers\n");
		goto cleanup;
	    }
	    retval = pkinit_process_td_trusted_certifiers(context,
		    plgctx->cryptoctx, reqctx->cryptoctx, reqctx->idctx,
		    krb5_trusted_certifiers, typed_data[0]->type);
	    if (!retval)
		do_again = 1;
	    break;
	case TD_DH_PARAMETERS:
	    retval = k5int_decode_krb5_td_dh_parameters(&scratch, &algId);
	    if (retval) {
		pkiDebug("failed to decode td_dh_parameters\n");
		goto cleanup;
	    }
	    retval = pkinit_process_td_dh_params(context, plgctx->cryptoctx,
		reqctx->cryptoctx, reqctx->idctx, algId,
		&reqctx->opts->dh_size);
	    if (!retval)
		do_again = 1;
	    break;
	default:
	    break;
    }

    if (do_again) {
	retval = pa_pkinit_gen_req(context, plgctx, reqctx, request, in_padata,
				   out_padata, prompter, prompter_data, gic_opt);
	if (retval)
	    goto cleanup;
    }

    retval = 0;
cleanup:
    if (krb5_trusted_certifiers != NULL)
	free_krb5_external_principal_identifier(&krb5_trusted_certifiers);

    if (typed_data != NULL)
	free_krb5_typed_data(&typed_data);

    if (algId != NULL)
	free_krb5_algorithm_identifiers(&algId);

    pkiDebug("pkinit_client_tryagain: returning %d (%s)\n",
	     retval, error_message(retval));
    return retval;
}

/* ARGSUSED */
static int
pkinit_client_get_flags(krb5_context kcontext, krb5_preauthtype patype)
{
    return PA_REAL;
}

static krb5_preauthtype supported_client_pa_types[] = {
    KRB5_PADATA_PK_AS_REP,
    KRB5_PADATA_PK_AS_REQ,
    KRB5_PADATA_PK_AS_REP_OLD,
    KRB5_PADATA_PK_AS_REQ_OLD,
    0
};

/* ARGSUSED */
void
pkinit_client_req_init(krb5_context context,
		       void *plugin_context,
		       void **request_context)
{
    krb5_error_code retval = ENOMEM;
    struct _pkinit_req_context *reqctx = NULL;
    struct _pkinit_context *plgctx = (struct _pkinit_context *)plugin_context;

    *request_context = NULL;

    reqctx = (struct _pkinit_req_context *) malloc(sizeof(*reqctx));
    if (reqctx == NULL)
	return;
    (void) memset(reqctx, 0, sizeof(*reqctx));

    reqctx->magic = PKINIT_REQ_CTX_MAGIC;
    reqctx->cryptoctx = NULL;
    reqctx->opts = NULL;
    reqctx->idctx = NULL;
    reqctx->idopts = NULL;

    retval = pkinit_init_req_opts(&reqctx->opts);
    if (retval)
	goto cleanup;

    reqctx->opts->require_eku = plgctx->opts->require_eku;
    reqctx->opts->accept_secondary_eku = plgctx->opts->accept_secondary_eku;
    reqctx->opts->dh_or_rsa = plgctx->opts->dh_or_rsa;
    reqctx->opts->allow_upn = plgctx->opts->allow_upn;
    reqctx->opts->require_crl_checking = plgctx->opts->require_crl_checking;

    retval = pkinit_init_req_crypto(&reqctx->cryptoctx);
    if (retval)
	goto cleanup;

    retval = pkinit_init_identity_crypto(&reqctx->idctx);
    if (retval)
	goto cleanup;

    retval = pkinit_dup_identity_opts(plgctx->idopts, &reqctx->idopts);
    if (retval)
	goto cleanup;

    *request_context = (void *) reqctx;
    pkiDebug("%s: returning reqctx at %p\n", __FUNCTION__, reqctx);

cleanup:
    if (retval) {
	if (reqctx->idctx != NULL)
	    pkinit_fini_identity_crypto(reqctx->idctx);
	if (reqctx->cryptoctx != NULL)
	    pkinit_fini_req_crypto(reqctx->cryptoctx);
	if (reqctx->opts != NULL)
	    pkinit_fini_req_opts(reqctx->opts);
	if (reqctx->idopts != NULL)
	    pkinit_fini_identity_opts(reqctx->idopts);
	free(reqctx);
    }

    return;
}

/* ARGSUSED */
void
pkinit_client_req_fini(krb5_context context,
		      void *plugin_context,
		      void *request_context)
{
    struct _pkinit_req_context *reqctx =
	(struct _pkinit_req_context *)request_context;

    pkiDebug("%s: received reqctx at %p\n", __FUNCTION__, reqctx);
    if (reqctx == NULL)
	return;
    if (reqctx->magic != PKINIT_REQ_CTX_MAGIC) {
	pkiDebug("%s: Bad magic value (%x) in req ctx\n",
		 __FUNCTION__, reqctx->magic);
	return;
    }
    if (reqctx->opts != NULL)
	pkinit_fini_req_opts(reqctx->opts);

    if (reqctx->cryptoctx != NULL)
	pkinit_fini_req_crypto(reqctx->cryptoctx);

    if (reqctx->idctx != NULL)
	pkinit_fini_identity_crypto(reqctx->idctx);

    if (reqctx->idopts != NULL)
	pkinit_fini_identity_opts(reqctx->idopts);

    free(reqctx);
    return;
}

/* ARGSUSED */
static void
pkinit_fini_client_profile(krb5_context context, pkinit_context plgctx)
{
    /* This should clean up anything allocated in pkinit_init_client_profile */
}

/* ARGSUSED */
static krb5_error_code
pkinit_init_client_profile(krb5_context context, pkinit_context plgctx)
{
    return 0;
}

static int
pkinit_client_plugin_init(krb5_context context, void **blob)
{
    krb5_error_code retval = ENOMEM;
    struct _pkinit_context *ctx = NULL;

    ctx = (struct _pkinit_context *)calloc(1, sizeof(*ctx));
    if (ctx == NULL)
	return ENOMEM;
    (void) memset(ctx, 0, sizeof(*ctx));
    ctx->magic = PKINIT_CTX_MAGIC;
    ctx->opts = NULL;
    ctx->cryptoctx = NULL;
    ctx->idopts = NULL;

    retval = pkinit_accessor_init();
    if (retval)
	goto errout;

    retval = pkinit_init_plg_opts(&ctx->opts);
    if (retval)
	goto errout;

    retval = pkinit_init_plg_crypto(&ctx->cryptoctx);
    if (retval)
	goto errout;

    retval = pkinit_init_identity_opts(&ctx->idopts);
    if (retval)
	goto errout;

    retval = pkinit_init_client_profile(context, ctx);
    if (retval)
	goto errout;

    *blob = ctx;

    pkiDebug("%s: returning plgctx at %p\n", __FUNCTION__, ctx);

errout:
    if (retval)
	pkinit_client_plugin_fini(context, ctx);

    return retval;
}

static void
pkinit_client_plugin_fini(krb5_context context, void *blob)
{
    struct _pkinit_context *ctx = (struct _pkinit_context *)blob;

    if (ctx == NULL || ctx->magic != PKINIT_CTX_MAGIC) {
	pkiDebug("pkinit_lib_fini: got bad plgctx (%p)!\n", ctx);
	return;
    }
    pkiDebug("%s: got plgctx at %p\n", __FUNCTION__, ctx);

    pkinit_fini_client_profile(context, ctx);
    pkinit_fini_identity_opts(ctx->idopts);
    pkinit_fini_plg_crypto(ctx->cryptoctx);
    pkinit_fini_plg_opts(ctx->opts);
    free(ctx);

}

/* ARGSUSED */
static krb5_error_code
add_string_to_array(krb5_context context, char ***array, const char *addition)
{
    char **out = NULL;

    if (*array == NULL) {
	out = malloc(2 * sizeof(char *));
	if (out == NULL)
	    return ENOMEM;
	out[1] = NULL;
	out[0] = strdup(addition);
	if (out[0] == NULL) {
	    free(out);
	    return ENOMEM;
	}
    } else {
	int i;
	char **a = *array;
	for (i = 0; a[i] != NULL; i++);
	out = malloc( (i + 2) * sizeof(char *));
	if (out == NULL)
	    return ENOMEM;
	for (i = 0; a[i] != NULL; i++) {
	    out[i] = a[i];
	}
	out[i++] = strdup(addition);
	if (out == NULL) {
	    free(out);
	    return ENOMEM;
	}
	out[i] = NULL;
	free(*array);
    }
    *array = out;

    return 0;
}
static krb5_error_code
handle_gic_opt(krb5_context context,
	       struct _pkinit_context *plgctx,
	       const char *attr,
	       const char *value)
{
    krb5_error_code retval;

    if (strcmp(attr, "X509_user_identity") == 0) {
	if (plgctx->idopts->identity != NULL) {
	    krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
		"X509_user_identity can not be given twice\n");
	    return KRB5_PREAUTH_FAILED;
	}
	plgctx->idopts->identity = strdup(value);
	if (plgctx->idopts->identity == NULL) {
	    krb5_set_error_message(context, ENOMEM,
		"Could not duplicate X509_user_identity value\n");
	    return ENOMEM;
	}
    } else if (strcmp(attr, "X509_anchors") == 0) {
	retval = add_string_to_array(context, &plgctx->idopts->anchors, value);
	if (retval)
	    return retval;
    } else if (strcmp(attr, "flag_RSA_PROTOCOL") == 0) {
	if (strcmp(value, "yes") == 0) {
	    pkiDebug("Setting flag to use RSA_PROTOCOL\n");
	    plgctx->opts->dh_or_rsa = RSA_PROTOCOL;
	}
    } else if (strcmp(attr, "PIN") == 0) {
	/* Solaris Kerberos: handle our PIN attr */
	plgctx->idopts->PIN = strdup(value);
	if (plgctx->idopts->PIN == NULL)
	    return ENOMEM;
    }
    return 0;
}

/* ARGSUSED */
static krb5_error_code
pkinit_client_gic_opt(krb5_context context,
		      void *plugin_context,
		      krb5_get_init_creds_opt *gic_opt,
		      const char *attr,
		      const char *value)
{
    krb5_error_code retval;
    struct _pkinit_context *plgctx = (struct _pkinit_context *)plugin_context;

    pkiDebug("(pkinit) received '%s' = '%s'\n", attr, value);
    retval = handle_gic_opt(context, plgctx, attr, value);
    if (retval)
	return retval;

    return 0;
}

struct krb5plugin_preauth_client_ftable_v1 preauthentication_client_1 = {
    "pkinit",			/* name */
    supported_client_pa_types,	/* pa_type_list */
    NULL,			/* enctype_list */
    pkinit_client_plugin_init,	/* (*init) */
    pkinit_client_plugin_fini,	/* (*fini) */
    pkinit_client_get_flags,	/* (*flags) */
    pkinit_client_req_init,     /* (*client_req_init) */
    pkinit_client_req_fini,     /* (*client_req_fini) */
    pkinit_client_process,	/* (*process) */
    pkinit_client_tryagain,	/* (*tryagain) */
    pkinit_client_gic_opt	/* (*gic_opt) */
};
