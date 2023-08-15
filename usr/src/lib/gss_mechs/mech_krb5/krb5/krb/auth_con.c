/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include "k5-int.h"
#include "auth_con.h"

static krb5_boolean chk_heimdal_seqnum(krb5_ui_4, krb5_ui_4);

/*ARGSUSED*/
static krb5_error_code
actx_copy_addr(krb5_context context, const krb5_address *inad, krb5_address **outad)
{
    krb5_address *tmpad;

    if (!(tmpad = (krb5_address *)malloc(sizeof(*tmpad))))
	return ENOMEM;
    *tmpad = *inad;
    if (!(tmpad->contents = (krb5_octet *)malloc(inad->length))) {
	krb5_xfree(tmpad);
	return ENOMEM;
    }
    /* Solaris Kerberos */
    (void) memcpy((char *)tmpad->contents, (char *)inad->contents, inad->length);
    *outad = tmpad;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_init(krb5_context context, krb5_auth_context *auth_context)
{
    *auth_context =
            (krb5_auth_context)MALLOC(sizeof(struct _krb5_auth_context));
    if (!*auth_context)
	    return ENOMEM;

    /* Solaris Kerberos */
    (void) memset(*auth_context, 0, sizeof(struct _krb5_auth_context));

    /* Default flags, do time not seq */
    (*auth_context)->auth_context_flags =
	    KRB5_AUTH_CONTEXT_DO_TIME |  KRB5_AUTH_CONN_INITIALIZED;

    (*auth_context)->req_cksumtype = context->default_ap_req_sumtype;
    (*auth_context)->safe_cksumtype = context->default_safe_sumtype;
    (*auth_context) -> checksum_func = NULL;
    (*auth_context)->checksum_func_data = NULL;
    (*auth_context)->magic = KV5M_AUTH_CONTEXT;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_free(krb5_context context, krb5_auth_context auth_context)
{
    if (auth_context->local_addr)
	krb5_free_address(context, auth_context->local_addr);
    if (auth_context->remote_addr)
	krb5_free_address(context, auth_context->remote_addr);
    if (auth_context->local_port)
	krb5_free_address(context, auth_context->local_port);
    if (auth_context->remote_port)
	krb5_free_address(context, auth_context->remote_port);
    if (auth_context->authentp)
	krb5_free_authenticator(context, auth_context->authentp);
    if (auth_context->keyblock)
	krb5_free_keyblock(context, auth_context->keyblock);
    if (auth_context->send_subkey)
	krb5_free_keyblock(context, auth_context->send_subkey);
    if (auth_context->recv_subkey)
	krb5_free_keyblock(context, auth_context->recv_subkey);
    /* Solaris Kerberos */
    if (auth_context->rcache)
	(void) krb5_rc_close(context, auth_context->rcache);
    if (auth_context->permitted_etypes)
	krb5_xfree(auth_context->permitted_etypes);
    free(auth_context);
    return 0;
}

krb5_error_code
krb5_auth_con_setaddrs(krb5_context context, krb5_auth_context auth_context, krb5_address *local_addr, krb5_address *remote_addr)
{
    krb5_error_code	retval;

    /* Free old addresses */
    if (auth_context->local_addr)
	(void) krb5_free_address(context, auth_context->local_addr);
    if (auth_context->remote_addr)
	(void) krb5_free_address(context, auth_context->remote_addr);

    retval = 0;
    if (local_addr)
	retval = actx_copy_addr(context,
				local_addr,
				&auth_context->local_addr);
    else
	auth_context->local_addr = NULL;

    if (!retval && remote_addr)
	retval = actx_copy_addr(context,
				remote_addr,
				&auth_context->remote_addr);
    else
	auth_context->remote_addr = NULL;

    return retval;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_getaddrs(krb5_context context, krb5_auth_context auth_context, krb5_address **local_addr, krb5_address **remote_addr)
{
    krb5_error_code	retval;

    retval = 0;
    if (local_addr && auth_context->local_addr) {
	retval = actx_copy_addr(context,
				auth_context->local_addr,
				local_addr);
    }
    if (!retval && (remote_addr) && auth_context->remote_addr) {
	retval = actx_copy_addr(context,
				auth_context->remote_addr,
				remote_addr);
    }
    return retval;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_setports(krb5_context context, krb5_auth_context auth_context, krb5_address *local_port, krb5_address *remote_port)
{
    krb5_error_code	retval;

    /* Free old addresses */
    if (auth_context->local_port)
	(void) krb5_free_address(context, auth_context->local_port);
    if (auth_context->remote_port)
	(void) krb5_free_address(context, auth_context->remote_port);

    retval = 0;
    if (local_port)
	retval = actx_copy_addr(context,
				local_port,
				&auth_context->local_port);
    else
	auth_context->local_port = NULL;

    if (!retval && remote_port)
	retval = actx_copy_addr(context,
				remote_port,
				&auth_context->remote_port);
    else
	auth_context->remote_port = NULL;

    return retval;
}


/*
 * This function overloads the keyblock field. It is only useful prior to
 * a krb5_rd_req_decode() call for user to user authentication where the
 * server has the key and needs to use it to decrypt the incoming request.
 * Once decrypted this key is no longer necessary and is then overwritten
 * with the session key sent by the client.
 */
krb5_error_code KRB5_CALLCONV
krb5_auth_con_setuseruserkey(krb5_context context, krb5_auth_context auth_context, krb5_keyblock *keyblock)
{
    if (auth_context->keyblock)
	krb5_free_keyblock(context, auth_context->keyblock);
    return(krb5_copy_keyblock(context, keyblock, &(auth_context->keyblock)));
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_getkey(krb5_context context, krb5_auth_context auth_context, krb5_keyblock **keyblock)
{
    if (auth_context->keyblock)
    	return krb5_copy_keyblock(context, auth_context->keyblock, keyblock);
    *keyblock = NULL;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_getlocalsubkey(krb5_context context, krb5_auth_context auth_context, krb5_keyblock **keyblock)
{
    return krb5_auth_con_getsendsubkey(context, auth_context, keyblock);
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_getremotesubkey(krb5_context context, krb5_auth_context auth_context, krb5_keyblock **keyblock)
{
    return krb5_auth_con_getrecvsubkey(context, auth_context, keyblock);
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_setsendsubkey(krb5_context ctx, krb5_auth_context ac, krb5_keyblock *keyblock)
{
    if (ac->send_subkey != NULL)
	krb5_free_keyblock(ctx, ac->send_subkey);
    ac->send_subkey = NULL;
    if (keyblock !=NULL)
	return krb5_copy_keyblock(ctx, keyblock, &ac->send_subkey);
    else
	return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_setrecvsubkey(krb5_context ctx, krb5_auth_context ac, krb5_keyblock *keyblock)
{
    if (ac->recv_subkey != NULL)
	krb5_free_keyblock(ctx, ac->recv_subkey);
    ac->recv_subkey = NULL;
    if (keyblock != NULL)
	return krb5_copy_keyblock(ctx, keyblock, &ac->recv_subkey);
    else
	return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_getsendsubkey(krb5_context ctx, krb5_auth_context ac, krb5_keyblock **keyblock)
{
    if (ac->send_subkey != NULL)
	return krb5_copy_keyblock(ctx, ac->send_subkey, keyblock);
    *keyblock = NULL;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_getrecvsubkey(krb5_context ctx, krb5_auth_context ac, krb5_keyblock **keyblock)
{
    if (ac->recv_subkey != NULL)
	return krb5_copy_keyblock(ctx, ac->recv_subkey, keyblock);
    *keyblock = NULL;
    return 0;
}

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_auth_con_set_req_cksumtype(krb5_context context, krb5_auth_context auth_context, krb5_cksumtype cksumtype)
{
    auth_context->req_cksumtype = cksumtype;
    return 0;
}

/*ARGSUSED*/
krb5_error_code
krb5_auth_con_set_safe_cksumtype(krb5_context context, krb5_auth_context auth_context, krb5_cksumtype cksumtype)
{
    auth_context->safe_cksumtype = cksumtype;
    return 0;
}

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_auth_con_getlocalseqnumber(krb5_context context, krb5_auth_context auth_context, krb5_int32 *seqnumber)
{
    *seqnumber = auth_context->local_seq_number;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_getauthenticator(krb5_context context, krb5_auth_context auth_context, krb5_authenticator **authenticator)
{
    return (krb5_copy_authenticator(context, auth_context->authentp,
				    authenticator));
}

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_auth_con_getremoteseqnumber(krb5_context context, krb5_auth_context auth_context, krb5_int32 *seqnumber)
{
    *seqnumber = auth_context->remote_seq_number;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_initivector(krb5_context context, krb5_auth_context auth_context)
{
    krb5_error_code ret;

    if (auth_context->keyblock) {
	size_t blocksize;

	if ((ret = krb5_c_block_size(context, auth_context->keyblock->enctype,
				    &blocksize)))
	    return(ret);
	if ((auth_context->i_vector = (krb5_pointer)malloc(blocksize))) {
	    memset(auth_context->i_vector, 0, blocksize);
	    return 0;
	}
	return ENOMEM;
    }
    return EINVAL; /* XXX need an error for no keyblock */
}

/*ARGSUSED*/
krb5_error_code
krb5_auth_con_setivector(krb5_context context, krb5_auth_context auth_context, krb5_pointer ivector)
{
    auth_context->i_vector = ivector;
    return 0;
}

/*ARGSUSED*/
krb5_error_code
krb5_auth_con_getivector(krb5_context context, krb5_auth_context auth_context, krb5_pointer *ivector)
{
    *ivector = auth_context->i_vector;
    return 0;
}

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_auth_con_setflags(krb5_context context, krb5_auth_context auth_context, krb5_int32 flags)
{
    auth_context->auth_context_flags = flags;
    return 0;
}

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_auth_con_getflags(krb5_context context, krb5_auth_context auth_context, krb5_int32 *flags)
{
    *flags = auth_context->auth_context_flags;
    return 0;
}

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_auth_con_setrcache(krb5_context context, krb5_auth_context auth_context, krb5_rcache rcache)
{
    auth_context->rcache = rcache;
    return 0;
}

/*ARGSUSED*/
krb5_error_code
krb5_auth_con_getrcache(krb5_context context, krb5_auth_context auth_context, krb5_rcache *rcache)
{
    *rcache = auth_context->rcache;
    return 0;
}

/*ARGSUSED*/
krb5_error_code
krb5_auth_con_setpermetypes(krb5_context context, krb5_auth_context auth_context, const krb5_enctype *permetypes)
{
    krb5_enctype	* newpe;
    int i;

    for (i=0; permetypes[i]; i++)
	;
    i++; /* include the zero */

    if ((newpe = (krb5_enctype *) malloc(i*sizeof(krb5_enctype)))
	== NULL)
	return(ENOMEM);

    if (auth_context->permitted_etypes)
	krb5_xfree(auth_context->permitted_etypes);

    auth_context->permitted_etypes = newpe;

    /* Solaris Kerberos */
    (void) memcpy(newpe, permetypes, i*sizeof(krb5_enctype));

    return 0;
}

/*ARGSUSED*/
krb5_error_code
krb5_auth_con_getpermetypes(krb5_context context, krb5_auth_context auth_context, krb5_enctype **permetypes)
{
    krb5_enctype	* newpe;
    int i;

    if (! auth_context->permitted_etypes) {
	*permetypes = NULL;
	return(0);
    }

    for (i=0; auth_context->permitted_etypes[i]; i++)
	;
    i++; /* include the zero */

    if ((newpe = (krb5_enctype *) malloc(i*sizeof(krb5_enctype)))
	== NULL)
	return(ENOMEM);

    *permetypes = newpe;

    memcpy(newpe, auth_context->permitted_etypes, i*sizeof(krb5_enctype));

    return(0);
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_set_checksum_func( krb5_context context,
				 krb5_auth_context  auth_context,
				 krb5_mk_req_checksum_func func,
				 void *data)
{
  auth_context->checksum_func = func;
  auth_context->checksum_func_data = data;
  return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_get_checksum_func( krb5_context context,
				 krb5_auth_context auth_context,
				 krb5_mk_req_checksum_func *func,
				 void **data)
{
  *func = auth_context->checksum_func;
  *data = auth_context->checksum_func_data;
  return 0;
}

/*
 * krb5int_auth_con_chkseqnum
 *
 * We use a somewhat complex heuristic for validating received
 * sequence numbers.  We must accommodate both our older
 * implementation, which sends negative sequence numbers, and the
 * broken Heimdal implementation (at least as of 0.5.2), which
 * violates X.690 BER for integer encodings.  The requirement of
 * handling negative sequence numbers removes one of easier means of
 * detecting a Heimdal implementation, so we resort to this mess
 * here.
 *
 * X.690 BER (and consequently DER, which are the required encoding
 * rules in RFC1510) encode all integer types as signed integers.
 * This means that the MSB being set on the first octet of the
 * contents of the encoding indicates a negative value.  Heimdal does
 * not prepend the required zero octet to unsigned integer encodings
 * which would otherwise have the MSB of the first octet of their
 * encodings set.
 *
 * Our ASN.1 library implements a special decoder for sequence
 * numbers, accepting both negative and positive 32-bit numbers but
 * mapping them both into the space of positive unsigned 32-bit
 * numbers in the obvious bit-pattern-preserving way.  This maintains
 * compatibility with our older implementations.  This also means that
 * encodings emitted by Heimdal are ambiguous.
 *
 * Heimdal counter value	received uint32 value
 *
 * 0x00000080			0xFFFFFF80
 * 0x000000FF			0xFFFFFFFF
 * 0x00008000			0xFFFF8000
 * 0x0000FFFF			0xFFFFFFFF
 * 0x00800000			0xFF800000
 * 0x00FFFFFF			0xFFFFFFFF
 * 0xFF800000			0xFF800000
 * 0xFFFFFFFF			0xFFFFFFFF
 *
 * We use two auth_context flags, SANE_SEQ and HEIMDAL_SEQ, which are
 * only set after we can unambiguously determine the sanity of the
 * sending implementation.  Once one of these flags is set, we accept
 * only the sequence numbers appropriate to the remote implementation
 * type.  We can make the determination in two different ways.  The
 * first is to note the receipt of a "negative" sequence number when a
 * "positive" one was expected.  The second is to note the receipt of
 * a sequence number that wraps through "zero" in a weird way.  The
 * latter corresponds to the receipt of an initial sequence number in
 * the ambiguous range.
 *
 * There are 2^7 + 2^15 + 2^23 + 2^23 = 16810112 total ambiguous
 * initial Heimdal counter values, but we receive them as one of 2^23
 * possible values.  There is a ~1/256 chance of a Heimdal
 * implementation sending an intial sequence number in the ambiguous
 * range.
 *
 * We have to do special treatment when receiving sequence numbers
 * between 0xFF800000..0xFFFFFFFF, or when wrapping through zero
 * weirdly (due to ambiguous initial sequence number).  If we are
 * expecting a value corresponding to an ambiguous Heimdal counter
 * value, and we receive an exact match, we can mark the remote end as
 * sane.
 */
krb5_boolean
krb5int_auth_con_chkseqnum(
    krb5_context ctx,
    krb5_auth_context ac,
    krb5_ui_4 in_seq)
{
    krb5_ui_4 exp_seq;

    exp_seq = ac->remote_seq_number;

    /*
     * If sender is known to be sane, accept _only_ exact matches.
     */
    if (ac->auth_context_flags & KRB5_AUTH_CONN_SANE_SEQ)
	return in_seq == exp_seq;

    /*
     * If sender is not known to be sane, first check the ambiguous
     * range of received values, 0xFF800000..0xFFFFFFFF.
     */
    if ((in_seq & 0xFF800000) == 0xFF800000) {
	/*
	 * If expected sequence number is in the range
	 * 0xFF800000..0xFFFFFFFF, then we can't make any
	 * determinations about the sanity of the sending
	 * implementation.
	 */
	if ((exp_seq & 0xFF800000) == 0xFF800000 && in_seq == exp_seq)
	    return 1;
	/*
	 * If sender is not known for certain to be a broken Heimdal
	 * implementation, check for exact match.
	 */
	if (!(ac->auth_context_flags & KRB5_AUTH_CONN_HEIMDAL_SEQ)
	    && in_seq == exp_seq)
	    return 1;
	/*
	 * Now apply hairy algorithm for matching sequence numbers
	 * sent by broken Heimdal implementations.  If it matches, we
	 * know for certain it's a broken Heimdal sender.
	 */
	if (chk_heimdal_seqnum(exp_seq, in_seq)) {
	    ac->auth_context_flags |= KRB5_AUTH_CONN_HEIMDAL_SEQ;
	    return 1;
	}
	return 0;
    }

    /*
     * Received value not in the ambiguous range?  If the _expected_
     * value is in the range of ambiguous Hemidal counter values, and
     * it matches the received value, sender is known to be sane.
     */
    if (in_seq == exp_seq) {
	if ((   exp_seq & 0xFFFFFF80) == 0x00000080
	    || (exp_seq & 0xFFFF8000) == 0x00008000
	    || (exp_seq & 0xFF800000) == 0x00800000)
	    ac->auth_context_flags |= KRB5_AUTH_CONN_SANE_SEQ;
	return 1;
    }

    /*
     * Magic wraparound for the case where the intial sequence number
     * is in the ambiguous range.  This means that the sender's
     * counter is at a different count than ours, so we correct ours,
     * and mark the sender as being a broken Heimdal implementation.
     */
    if (exp_seq == 0
	&& !(ac->auth_context_flags & KRB5_AUTH_CONN_HEIMDAL_SEQ)) {
	switch (in_seq) {
	case 0x100:
	case 0x10000:
	case 0x1000000:
	    ac->auth_context_flags |= KRB5_AUTH_CONN_HEIMDAL_SEQ;
	    exp_seq = in_seq;
	    return 1;
	default:
	    return 0;
	}
    }
    return 0;
}

static krb5_boolean
chk_heimdal_seqnum(krb5_ui_4 exp_seq, krb5_ui_4 in_seq)
{
    if (( exp_seq & 0xFF800000) == 0x00800000
	&& (in_seq & 0xFF800000) == 0xFF800000
	&& (in_seq & 0x00FFFFFF) == exp_seq)
	return 1;
    else if ((  exp_seq & 0xFFFF8000) == 0x00008000
	     && (in_seq & 0xFFFF8000) == 0xFFFF8000
	     && (in_seq & 0x0000FFFF) == exp_seq)
	return 1;
    else if ((  exp_seq & 0xFFFFFF80) == 0x00000080
	     && (in_seq & 0xFFFFFF80) == 0xFFFFFF80
	     && (in_seq & 0x000000FF) == exp_seq)
	return 1;
    else
	return 0;
}
