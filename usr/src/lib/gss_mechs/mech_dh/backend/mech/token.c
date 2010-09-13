/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *	token.c
 *
 *	Copyright (c) 1997, by Sun Microsystems, Inc.
 *	All rights reserved.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dh_gssapi.h"
#include "crypto.h"

extern int
get_der_length(unsigned char **, unsigned int, unsigned int *);

extern unsigned int
der_length_size(unsigned int);

extern int
put_der_length(unsigned int, unsigned char **, unsigned int);

#define	MSO_BIT (8*(sizeof (int) - 1))	/* Most significant octet bit */

static OM_uint32
__xdr_encode_token(XDR *, gss_buffer_t, dh_token_t, dh_key_set_t);

static OM_uint32
__xdr_decode_token(XDR *, gss_buffer_t,
		dh_token_t, dh_key_set_t, dh_signature_t);

/*
 * get_qop: For a Diffie-Hellman token_t, return the associate QOP
 */
static dh_qop_t
get_qop(dh_token_t t)
{
	dh_token_body_t body = &t->ver.dh_version_u.body;
	switch (body->type) {
	case DH_INIT_CNTX:
	case DH_ACCEPT_CNTX:
		return (DH_MECH_QOP);
	case DH_MIC:
		return (body->dh_token_body_desc_u.sign.qop);
	case DH_WRAP:
		return (body->dh_token_body_desc_u.seal.mic.qop);
	default:
		/* Should never get here */
		return (DH_MECH_QOP);
	}
}

/*
 * __make_ap_token: This routine generates a Diffie-Hellman serialized
 * token which has an ASN.1 application 0 header prepended. The unserialized
 * token supplied should be of type DH_INIT_CNTX.
 *
 * The ASN.1 applicationtion prefix is encoded as follows:
 *
 *	+------+
 *	| 0x60 |	1	TAG for APPLICATION 0
 *	+------+
 *	|      |
 *	~      ~     app_size	DER encoded length of oid_size + token_size
 *	|      |
 *      +------+
 *	| 0x06 |	1	TAG for OID
 *	+------+
 *	|      |  der_length_size
 *	~      ~  (mech->length) DER encoded length of mech->length
 *	|      |
 *	+------+
 *	|      |
 *	~      ~  mech->length	OID elements (mech->elements)
 *	|      |
 *	+------+
 *	| 0x00 |       0-3	XDR padding
 *	+------+
 *	|      |
 *	~      ~		Serialized DH token
 *	|      |
 *	+------+
 *	| 0x00 |       0-3	Left over XDR padding
 *	+------+
 *
 * We will define the token_size to be the sizeof the serialize token plus
 * 3 the maximum XDR paddinging that will be needed. Thus the XDR padding
 * plus the left over XDR padding will alway equal 3.
 */
OM_uint32
__make_ap_token(gss_buffer_t result, /* The serialized token */
		gss_OID mech, /* The mechanism this is for */
		dh_token_t token, /* The unserialized input token */
		dh_key_set_t keys /* The session keys to sign the token */)
{
	unsigned int size, hsize, token_size, app_size, oid_size, start;
	XDR xdrs;
	unsigned char *sv, *buf, *xdrmem;
	OM_uint32 stat;

	/* Allocate the signature for the input token */
	if ((stat = __alloc_sig(get_qop(token),
				&token->verifier))
	    != DH_SUCCESS)
		return (stat);

	/*
	 * We will first determine the size of the output token in
	 * a bottom up fashion.
	 */

	/* Fetch the size of a serialized DH token */
	token_size = xdr_sizeof((xdrproc_t)xdr_dh_token_desc, (void *)token);

	/*
	 * The token itself needs to be pasted on to the ASN.1
	 * application header on BYTES_PER_XDR_UNIT boundry. So we may
	 *  need upto BYTES_PER_XDR_UNIT - 1 extra bytes.
	 */
	token_size += BYTES_PER_XDR_UNIT -1;


	oid_size = mech->length;
	oid_size += der_length_size(mech->length);
	oid_size += 1;   /* tag x06 for Oid */
	/* bytes to store the length */
	app_size = der_length_size(oid_size + token_size);

	hsize = app_size + oid_size;
	hsize += 1;  /* tag 0x60  for application 0 */
	size = hsize + token_size;

	/* Allocate a buffer to serialize into */
	buf = New(unsigned char, size);
	if (buf == NULL) {
		__free_signature(&token->verifier);
		return (DH_NOMEM_FAILURE);
	}

	result->value = sv = buf;
	result->length = size;

	/* ASN.1 application 0 header */

	/* Encode the tag */
	*buf++ = 0x60;
	/* Encode the app length */
	put_der_length(oid_size + token_size, &buf, app_size);

	/* Encode the OID tag */
	*buf++ = 0x06;
	/* Encode the OID length */
	put_der_length(mech->length, &buf, oid_size);
	/* Encode the OID elemeents */
	memcpy(buf, mech->elements, mech->length);

	/* Encode the Diffie-Hellmam token */
	/*
	 * Token has to be on BYTES_PER_XDR_UNIT boundry. (RNDUP is
	 * from xdr.h)
	 */
	start = RNDUP(hsize);
	/* Buffer for xdrmem_create to use */
	xdrmem = &sv[start];

	xdrmem_create(&xdrs, (caddr_t)xdrmem, token_size, XDR_ENCODE);
	/* Paste the DH token on */
	if ((stat = __xdr_encode_token(&xdrs, NULL, token, keys))
	    != DH_SUCCESS) {
		__free_signature(&token->verifier);
		__dh_release_buffer(result);
	}

	/* We're done with the signature, the token has been serialized */
	__free_signature(&token->verifier);

	return (stat);
}

/*
 * __make_token: Given an unserialized DH token, serialize it puting the
 * serialized output in result. If this token has a type of DH_MIC, then
 * the optional message, msg, should be supplied. The mic caluclated will be
 * over the message as well as the serialized token.
 */
OM_uint32
__make_token(gss_buffer_t result, /* Serialized token goes here */
	    gss_buffer_t msg,	/* Optional message for DH_MIC tokens */
	    dh_token_t token,	/* The token to encode */
	    dh_key_set_t keys	/* The keys to encrypt the check sum with */)
{
	unsigned int token_size;
	XDR xdrs;
	unsigned char *buf;
	OM_uint32 stat;

	/* Allocate a signature for this token */
	if ((stat = __alloc_sig(get_qop(token),
				&token->verifier))
	    != DH_SUCCESS)
		return (stat);

	/* Get the output token size to know how much to allocate */
	token_size = xdr_sizeof((xdrproc_t)xdr_dh_token_desc, (void *)token);

	/* Allocate the buffer to hold the serialized token */
	buf = New(unsigned char, token_size);
	if (buf == NULL) {
		__free_signature(&token->verifier);
		return (DH_NOMEM_FAILURE);
	}

	/* Set the result */
	result->length = token_size;
	result->value = (void *)buf;

	/* Create the xdr stream using the allocated buffer */
	xdrmem_create(&xdrs, (char *)buf, token_size, XDR_ENCODE);

	/* Encode the token */
	if ((stat = __xdr_encode_token(&xdrs, msg, token, keys))
	    != DH_SUCCESS) {
		__free_signature(&token->verifier);
		__dh_release_buffer(result);
	}

	/* Release the signature */
	__free_signature(&token->verifier);
	return (stat);
}

/*
 * __get_ap_token: This routine deserializes a Diffie-Hellman serialized
 * token which has an ASN.1 application 0 header prepended. The resulting
 * unserialized token supplied should be of type DH_INIT_CNTX..
 *
 * The ASN.1 applicationtion prefix  and token is encoded as follows:
 *
 *	+------+
 *	| 0x60 |	1	TAG for APPLICATION 0
 *	+------+
 *	|      |
 *	~      ~     app_size	DER encoded length of oid_size + token_size
 *	|      |
 *      +------+
 *	| 0x06 |	1	TAG for OID
 *	+------+
 *	|      |  der_length_size
 *	~      ~  (mech->length) DER encoded length of mech->length
 *	|      |
 *	+------+
 *	|      |
 *	~      ~  mech->length	OID elements (mech->elements)
 *	|      |
 *	+------+
 *	| 0x00 |       0-3	XDR padding
 *	+------+
 *	|      |
 *	~      ~		Serialized DH token
 *	|      |
 *	+------+
 *	| 0x00 |       0-3	Left over XDR padding
 *	+------+
 *
 * We will define the token_size to be the sizeof the serialize token plus
 * 3 the maximum XDR paddinging that will be needed. Thus the XDR padding
 * plus the left over XDR padding will alway equal 3.
 */
OM_uint32
__get_ap_token(gss_buffer_t input, /* The token to deserialize */
	    gss_OID mech, /* This context's OID */
	    dh_token_t token, /* The resulting token */
	    dh_signature_t sig /* The signature found over the input token */)
{
	unsigned char *buf, *p;
	unsigned int oid_len, token_len, bytes, hsize;
	int len;
	OM_uint32 stat;
	XDR xdrs;

	/* Set p and buf to point to the beginning of the token */
	p = buf = (unsigned char *)input->value;

	/* Check that this is an ASN.1 APPLICATION 0 token */
	if (*p++ != 0x60)
		return (DH_DECODE_FAILURE);

	/* Determine the length for the DER encoding of the packet length */
	if ((len = get_der_length(&p, input->length - 1, &bytes)) < 0)
		return (DH_DECODE_FAILURE);

	/*
	 * See if the number of bytes specified by the
	 * encoded length is all there
	 */
	if (input->length - 1 - bytes != len)
		return (DH_DECODE_FAILURE);

	/*
	 * Running total of the APPLICATION 0 prefix so far. One for the
	 * tag (0x60) and the bytes necessary to encode the length of the
	 * packet.
	 */
	hsize = 1 + bytes;

	/* Check that we're now looking at an OID */
	if (*p++ != 0x06)
		return (DH_DECODE_FAILURE);

	/* Get OID length and the number of bytes that to encode it */
	oid_len = get_der_length(&p, len - 1, &bytes);

	/*
	 * Now add the byte for the OID tag, plus the bytes for the oid
	 * length, plus the oid length its self. That is, add the size
	 * of the encoding of the OID to the running total of the
	 * APPLICATION 0 header. The result is the total size of the header.
	 */
	hsize += 1 + bytes + oid_len;

	/*
	 * The DH token length is the application length minus the length
	 * of the OID encoding.
	 */
	token_len = len - 1 - bytes - oid_len;

	/* Sanity check the token length */
	if (input->length - hsize != token_len)
		return (DH_DECODE_FAILURE);

	/* Check that this token is for this OID */
	if (mech->length != oid_len)
		return (DH_DECODE_FAILURE);
	if (memcmp(mech->elements, p, oid_len) != 0)
		return (DH_DECODE_FAILURE);

	/* Round up the header size to XDR boundry */
	hsize = RNDUP(hsize);

	/* Get the start of XDR encoded token */
	p = &buf[hsize];

	/* Create and XDR stream to decode from */
	xdrmem_create(&xdrs, (caddr_t)p, token_len, XDR_DECODE);

	/*
	 * Clear the deserialized token (we'll have the xdr routines
	 * do the the allocations).
	 */
	memset(token, 0, sizeof (dh_token_desc));

	/* Zero out the signature */
	memset(sig, 0, sizeof (*sig));

	/*
	 * Decode the DH_INIT_CNTX token. Note that at this point we have no
	 * session keys established, so that keys is null. The unencrypted
	 * signature will be made available to the caller in sig. The
	 * caller can then attempt to decrypt the session keys in token
	 * and encrypt the returned sig  with those keys to check the
	 * integrity of the token.
	 */
	if ((stat = __xdr_decode_token(&xdrs, NULL, token, NULL, sig))
	    != DH_SUCCESS) {
		xdr_free(xdr_dh_token_desc, (char *)token);
		return (stat);
	}

	return (stat);
}

/*
 * __get_token: Deserialize a supplied Diffie-Hellman token. Note the
 * session keys should always be supplied to this routine. The message
 * should only be supplied if the token is of DH_MIC type.
 */
OM_uint32
__get_token(gss_buffer_t input, /* The token to deserialize */
	    gss_buffer_t msg, /* Optional message to generate verifier over */
	    dh_token_t token,    /* The decode token */
	    dh_key_set_t keys    /* The session keys */)
{
	XDR xdrs;
	dh_signature sig;
	OM_uint32 stat;

	/* Create a an XDR stream out of the input token */
	xdrmem_create(&xdrs, (caddr_t)input->value, input->length, XDR_DECODE);

	/* Clear the token_desc and signature. */
	memset(token, 0, sizeof (dh_token_desc));
	memset(&sig, 0, sizeof (sig));

	/* Decode the token */
	if ((stat = __xdr_decode_token(&xdrs, msg, token, keys, &sig))
	    != DH_SUCCESS)
		/* If we fail release the deserialized token */
		xdr_free(xdr_dh_token_desc, (char *)token);

	/* We always free the signature */
	__free_signature(&sig);

	return (stat);
}

/*
 * Warning these routines assumes that xdrs was created with xdrmem_create!
 */

/*
 * __xdr_encode_token: Given an allocated xdrs stream serialize the supplied
 * token_desc pointed to by objp, using keys to encrypt the signature. If
 * msg is non null then calculate the signature over msg as well as the
 * serialized token. Note this protocol is designed with the signature as
 * the last part of any token. In this way the signature that is calculated is
 * always done over the entire token. All fields in any token are thus
 * protected from tampering
 */
static OM_uint32
__xdr_encode_token(register XDR *xdrs, gss_buffer_t msg,
		dh_token_desc *objp, dh_key_set_t keys)
{
	OM_uint32 stat;

	/* Check that xdrs is valid */
	if (xdrs == 0 || xdrs->x_op != XDR_ENCODE)
		return (DH_BADARG_FAILURE);

	/* Encode the protocol versioned body */
	if (!xdr_dh_version(xdrs, &objp->ver))
		return (DH_ENCODE_FAILURE);

	/* Calculate the signature */
	stat = __mk_sig(get_qop(objp), xdrs->x_base,
			xdr_getpos(xdrs), msg, keys,
			&objp->verifier);

	if (stat != DH_SUCCESS)
		return (stat);

	/* Encode the signature */
	if (!xdr_dh_signature(xdrs, &objp->verifier))
		return (DH_ENCODE_FAILURE);

	return (DH_SUCCESS);
}

/*
 * __xdr_decode_token: Decode a token from an XDR stream into a token_desc
 * pointed to by objp. We will calculate a signature over the serialized
 * token and an optional message. The calculated signature will be
 * returned to the caller in sig. If the supplied keys are available this
 * routine will compare that the verifier in the deserialized token is
 * the same as the calculated signature over the input stream. This is
 * the usual case. However if the supplied serialized token is DH_INIT_CNTX,
 * the keys have not yet been established. So we just give the caller back
 * our raw signature (Non encrypted) and the deserialized token. Higher in
 * the food chain (currently __dh_gss_accept_sec_context), we will attempt
 * to decrypt the session keys and call __verify_sig with the decrypted
 * session keys the signature returned from this routine and the deserialized
 * token.
 *
 * Note it is assumed that sig does point to a valid uninitialized signature.
 */

static OM_uint32
__xdr_decode_token(register XDR *xdrs, gss_buffer_t msg,
		dh_token_desc *objp, dh_key_set_t keys, dh_signature_t sig)
{
	OM_uint32 stat;

	/* Check that we are decoding */
	if (xdrs == 0 || xdrs->x_op != XDR_DECODE)
		return (DH_BADARG_FAILURE);

	/* Decode the protocol versioned body */
	if (!xdr_dh_version(xdrs, &objp->ver))
		return (DH_DECODE_FAILURE);

	/* Allocate the signature for this tokens QOP */
	if ((stat = __alloc_sig(get_qop(objp), sig)) != DH_SUCCESS)
		return (stat);

	/*
	 * Call __mk_sig in crypto.c to calculate the signature based on
	 * the decoded QOP. __mk_sig will encrypt the signature with the
	 * supplied keys if they are available. If keys is null the signature
	 * will be just the unencrypted check sum.
	 */
	stat = __mk_sig(get_qop(objp), xdrs->x_base,
			xdr_getpos(xdrs), msg, keys, sig);
	if (stat != DH_SUCCESS)
		return (stat);

	/* Now decode the supplied signature */
	if (!xdr_dh_signature(xdrs, &objp->verifier))
		return (stat);

	/*
	 * If we have keys then we can check that the signatures
	 * are the same
	 */
	if (keys && !__cmpsig(sig, &objp->verifier))
		return (DH_VERIFIER_MISMATCH);

	return (DH_SUCCESS);
}
