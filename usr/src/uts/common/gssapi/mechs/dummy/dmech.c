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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 */

/*
 * A module that implements a dummy security mechanism.
 * It's mainly used to test GSS-API application. Multiple tokens
 * exchanged during security context establishment can be
 * specified through dummy_mech.conf located in /etc.
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <gssapiP_dummy.h>
#include <gssapi_err_generic.h>
#include <mechglueP.h>
#include <gssapi/kgssapi_defs.h>
#include <sys/debug.h>

#ifdef DUMMY_MECH_DEBUG
/*
 * Kernel kgssd module debugging aid. The global variable "dummy_mech_log"
 * is a bit mask which allows various types of debugging messages
 * to be printed out.
 *
 *       dummy_mech_log & 1  will cause actual failures to be printed.
 *       dummy_mech_log & 2  will cause informational messages to be
 *                       printed on the client side of kgssd.
 *       dummy_mech_log & 4  will cause informational messages to be
 *                       printed on the server side of kgssd.
 *       dummy_mech_log & 8  will cause informational messages to be
 *                       printed on both client and server side of kgssd.
 */

uint_t dummy_mech_log = 1;
#endif

/* Local defines */
#define	MAGIC_TOKEN_NUMBER 12345
/* private routines for dummy_mechanism */
static gss_buffer_desc make_dummy_token_msg(void *data, int datalen);

static int der_length_size(int);

static void der_write_length(unsigned char **, int);
static int der_read_length(unsigned char **, int *);
static int g_token_size(gss_OID mech, unsigned int body_size);
static void g_make_token_header(gss_OID mech, int body_size,
				unsigned char **buf, int tok_type);
static int g_verify_token_header(gss_OID mech, int *body_size,
				unsigned char **buf_in, int tok_type,
				int toksize);

/* private global variables */
static int dummy_token_nums;

/*
 * This OID:
 * { iso(1) org(3) internet(6) dod(1) private(4) enterprises(1) sun(42)
 * products(2) gssapi(26) mechtypes(1) dummy(2) }
 */

static struct gss_config dummy_mechanism =
	{{10, "\053\006\001\004\001\052\002\032\001\002"},
	NULL,	/* context */
	NULL,	/* next */
	TRUE,	/* uses_kmod */
	dummy_gss_unseal,
	dummy_gss_delete_sec_context,
	dummy_gss_seal,
	dummy_gss_import_sec_context,
	dummy_gss_sign,
	dummy_gss_verify
};

static gss_mechanism
gss_mech_initialize()
{
	dprintf("Entering gss_mech_initialize\n");

	if (dummy_token_nums == 0)
		dummy_token_nums = 1;

	dprintf("Leaving gss_mech_initialize\n");
	return (&dummy_mechanism);
}

/*
 * Clean up after a failed mod_install()
 */
static void
gss_mech_fini()
{
	/* Nothing to do */
}


/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops, "in-kernel dummy GSS mechanism"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

static int dummy_fini_code = EBUSY;

int
_init()
{
	int retval;
	gss_mechanism mech, tmp;

	mech = gss_mech_initialize();

	mutex_enter(&__kgss_mech_lock);
	tmp = __kgss_get_mechanism(&mech->mech_type);
	if (tmp != NULL) {
		DUMMY_MECH_LOG0(8,
			"dummy GSS mechanism: mechanism already in table.\n");
		if (tmp->uses_kmod == TRUE) {
			DUMMY_MECH_LOG0(8, "dummy GSS mechanism: mechanism "
				"table supports kernel operations!\n");
		}
		/*
		 * keep us loaded, but let us be unloadable. This
		 * will give the developer time to trouble shoot
		 */
		dummy_fini_code = 0;
	} else {
		__kgss_add_mechanism(mech);
		ASSERT(__kgss_get_mechanism(&mech->mech_type) == mech);
	}
	mutex_exit(&__kgss_mech_lock);

	if ((retval = mod_install(&modlinkage)) != 0)
		gss_mech_fini();	/* clean up */

	return (retval);
}

int
_fini()
{
	int ret = dummy_fini_code;

	if (ret == 0) {
		ret = (mod_remove(&modlinkage));
	}
	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*ARGSUSED*/
static OM_uint32
dummy_gss_sign(context, minor_status, context_handle,
		qop_req, message_buffer, message_token,
		gssd_ctx_verifier)
	void *context;
	OM_uint32 *minor_status;
	gss_ctx_id_t context_handle;
	int qop_req;
	gss_buffer_t message_buffer;
	gss_buffer_t message_token;
	OM_uint32 gssd_ctx_verifier;
{
	dummy_gss_ctx_id_rec	*ctx;
	char token_string[] = "dummy_gss_sign";

	dprintf("Entering gss_sign\n");

	if (context_handle == GSS_C_NO_CONTEXT)
		return (GSS_S_NO_CONTEXT);
	ctx = (dummy_gss_ctx_id_rec *) context_handle;
	ASSERT(ctx->established == 1);
	ASSERT(ctx->token_number == MAGIC_TOKEN_NUMBER);

	*message_token = make_dummy_token_msg(
				token_string, strlen(token_string));

	dprintf("Leaving gss_sign\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
static OM_uint32
	dummy_gss_verify(context, minor_status, context_handle,
		message_buffer, token_buffer, qop_state,
		gssd_ctx_verifier)
	void *context;
	OM_uint32 *minor_status;
	gss_ctx_id_t context_handle;
	gss_buffer_t message_buffer;
	gss_buffer_t token_buffer;
	int *qop_state;
	OM_uint32 gssd_ctx_verifier;
{
	unsigned char *ptr;
	int bodysize;
	int err;
	dummy_gss_ctx_id_rec	*ctx;

	dprintf("Entering gss_verify\n");

	if (context_handle == GSS_C_NO_CONTEXT)
		return (GSS_S_NO_CONTEXT);

	ctx = (dummy_gss_ctx_id_rec *) context_handle;
	ASSERT(ctx->established == 1);
	ASSERT(ctx->token_number == MAGIC_TOKEN_NUMBER);
	/* Check for defective input token. */

	ptr = (unsigned char *) token_buffer->value;
	if (err = g_verify_token_header((gss_OID)gss_mech_dummy, &bodysize,
					&ptr, 0,
					token_buffer->length)) {
		*minor_status = err;
		return (GSS_S_DEFECTIVE_TOKEN);
	}

	*qop_state = GSS_C_QOP_DEFAULT;

	dprintf("Leaving gss_verify\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
static OM_uint32
dummy_gss_seal(context, minor_status, context_handle, conf_req_flag,
		qop_req, input_message_buffer, conf_state,
		output_message_buffer, gssd_ctx_verifier)
	void *context;
	OM_uint32 *minor_status;
	gss_ctx_id_t context_handle;
	int conf_req_flag;
	int qop_req;
	gss_buffer_t input_message_buffer;
	int *conf_state;
	gss_buffer_t output_message_buffer;
	OM_uint32 gssd_ctx_verifier;
{
	gss_buffer_desc	output;
	dummy_gss_ctx_id_rec	*ctx;
	dprintf("Entering gss_seal\n");

	if (context_handle == GSS_C_NO_CONTEXT)
		return (GSS_S_NO_CONTEXT);
	ctx = (dummy_gss_ctx_id_rec *) context_handle;
	ASSERT(ctx->established == 1);
	ASSERT(ctx->token_number == MAGIC_TOKEN_NUMBER);
	/* Copy the input message to output message */
	output = make_dummy_token_msg(
		input_message_buffer->value, input_message_buffer->length);

	if (conf_state)
		*conf_state = 1;

	*output_message_buffer = output;

	dprintf("Leaving gss_seal\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
static OM_uint32
dummy_gss_unseal(context, minor_status, context_handle,
		input_message_buffer, output_message_buffer,
		conf_state, qop_state, gssd_ctx_verifier)
	void *context;
	OM_uint32 *minor_status;
	gss_ctx_id_t context_handle;
	gss_buffer_t input_message_buffer;
	gss_buffer_t output_message_buffer;
	int *conf_state;
	int *qop_state;
	OM_uint32 gssd_ctx_verifier;
{
	gss_buffer_desc output;
	dummy_gss_ctx_id_rec	*ctx;
	unsigned char *ptr;
	int bodysize;
	int err;

	dprintf("Entering gss_unseal\n");

	if (context_handle == GSS_C_NO_CONTEXT)
		return (GSS_S_NO_CONTEXT);

	ctx = (dummy_gss_ctx_id_rec *) context_handle;
	ASSERT(ctx->established == 1);
	ASSERT(ctx->token_number == MAGIC_TOKEN_NUMBER);

	ptr = (unsigned char *) input_message_buffer->value;
	if (err = g_verify_token_header((gss_OID)gss_mech_dummy, &bodysize,
					&ptr, 0,
					input_message_buffer->length)) {
		*minor_status = err;
		return (GSS_S_DEFECTIVE_TOKEN);
	}
	output.length = bodysize;
	output.value = (void *)MALLOC(output.length);
	(void) memcpy(output.value, ptr, output.length);

	*output_message_buffer = output;
	*qop_state = GSS_C_QOP_DEFAULT;

	if (conf_state)
		*conf_state = 1;

	dprintf("Leaving gss_unseal\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
	dummy_gss_import_sec_context(ct, minor_status, interprocess_token,
					context_handle)
void *ct;
OM_uint32 *minor_status;
gss_buffer_t interprocess_token;
gss_ctx_id_t *context_handle;
{
	unsigned char *ptr;
	int bodysize;
	int err;

	/* Assume that we got ctx from the interprocess token. */
	dummy_gss_ctx_id_t ctx;

	dprintf("Entering import_sec_context\n");
	ptr = (unsigned char *) interprocess_token->value;
	if (err = g_verify_token_header((gss_OID)gss_mech_dummy, &bodysize,
					&ptr, 0,
					interprocess_token->length)) {
		*minor_status = err;
		return (GSS_S_DEFECTIVE_TOKEN);
	}
	ctx = (dummy_gss_ctx_id_t)MALLOC(sizeof (dummy_gss_ctx_id_rec));
	ctx->token_number = MAGIC_TOKEN_NUMBER;
	ctx->established = 1;

	*context_handle = (gss_ctx_id_t)ctx;

	dprintf("Leaving import_sec_context\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
static OM_uint32
dummy_gss_delete_sec_context(ct, minor_status,
			context_handle, output_token,
			gssd_ctx_verifier)
void *ct;
OM_uint32 *minor_status;
gss_ctx_id_t *context_handle;
gss_buffer_t output_token;
OM_uint32 gssd_ctx_verifier;
{
	dummy_gss_ctx_id_t ctx;

	dprintf("Entering delete_sec_context\n");

	/* Make the length to 0, so the output token is not sent to peer */
	if (output_token) {
		output_token->length = 0;
		output_token->value = NULL;
	}

	if (*context_handle == GSS_C_NO_CONTEXT) {
		*minor_status = 0;
		return (GSS_S_COMPLETE);
	}

	ctx = (dummy_gss_ctx_id_rec *) *context_handle;
	ASSERT(ctx->established == 1);
	ASSERT(ctx->token_number == MAGIC_TOKEN_NUMBER);

	FREE(ctx, sizeof (dummy_gss_ctx_id_rec));
	*context_handle = GSS_C_NO_CONTEXT;

	dprintf("Leaving delete_sec_context\n");
	return (GSS_S_COMPLETE);
}

static int
der_length_size(int length)
{
	if (length < (1<<7))
		return (1);
	else if (length < (1<<8))
		return (2);
	else if (length < (1<<16))
		return (3);
	else if (length < (1<<24))
		return (4);
	else
		return (5);
}

static void
der_write_length(unsigned char ** buf, int length)
{
	if (length < (1<<7)) {
		*(*buf)++ = (unsigned char) length;
	} else {
		*(*buf)++ = (unsigned char) (der_length_size(length)+127);
		if (length >= (1<<24))
			*(*buf)++ = (unsigned char) (length>>24);
		if (length >= (1<<16))
			*(*buf)++ = (unsigned char) ((length>>16)&0xff);
		if (length >= (1<<8))
			*(*buf)++ = (unsigned char) ((length>>8)&0xff);
		*(*buf)++ = (unsigned char) (length&0xff);
	}
}

static int
der_read_length(buf, bufsize)
unsigned char **buf;
int *bufsize;
{
	unsigned char sf;
	int ret;

	if (*bufsize < 1)
		return (-1);
	sf = *(*buf)++;
	(*bufsize)--;
	if (sf & 0x80) {
		if ((sf &= 0x7f) > ((*bufsize)-1))
			return (-1);
		if (sf > DUMMY_SIZE_OF_INT)
			return (-1);
		ret = 0;
		for (; sf; sf--) {
			ret = (ret<<8) + (*(*buf)++);
			(*bufsize)--;
		}
	} else {
		ret = sf;
	}

	return (ret);
}

static int
g_token_size(mech, body_size)
	gss_OID mech;
	unsigned int body_size;
{
	/* set body_size to sequence contents size */
	body_size += 4 + (int)mech->length;	/* NEED overflow check */
	return (1 + der_length_size(body_size) + body_size);
}

static void
g_make_token_header(mech, body_size, buf, tok_type)
	gss_OID mech;
	int body_size;
	unsigned char **buf;
	int tok_type;
{
	*(*buf)++ = 0x60;
	der_write_length(buf, 4 + mech->length + body_size);
	*(*buf)++ = 0x06;
	*(*buf)++ = (unsigned char) mech->length;
	TWRITE_STR(*buf, mech->elements, ((int)mech->length));
	*(*buf)++ = (unsigned char) ((tok_type>>8)&0xff);
	*(*buf)++ = (unsigned char) (tok_type&0xff);
}

static int
g_verify_token_header(mech, body_size, buf_in, tok_type, toksize)
	gss_OID mech;
	int *body_size;
	unsigned char **buf_in;
	int tok_type;
	int toksize;
{
	unsigned char *buf = *buf_in;
	int seqsize;
	gss_OID_desc toid;
	int ret = 0;

	if ((toksize -= 1) < 0)
		return (G_BAD_TOK_HEADER);
	if (*buf++ != 0x60)
		return (G_BAD_TOK_HEADER);

	if ((seqsize = der_read_length(&buf, &toksize)) < 0)
		return (G_BAD_TOK_HEADER);

	if (seqsize != toksize)
		return (G_BAD_TOK_HEADER);

	if ((toksize -= 1) < 0)
		return (G_BAD_TOK_HEADER);
	if (*buf++ != 0x06)
		return (G_BAD_TOK_HEADER);

	if ((toksize -= 1) < 0)
		return (G_BAD_TOK_HEADER);
	toid.length = *buf++;

	if ((toksize -= toid.length) < 0)
		return (G_BAD_TOK_HEADER);
	toid.elements = buf;
	buf += toid.length;

	if (! g_OID_equal(&toid, mech))
		ret = G_WRONG_MECH;

	/*
	 * G_WRONG_MECH is not returned immediately because it's more important
	 * to return G_BAD_TOK_HEADER if the token header is in fact bad
	 */

	if ((toksize -= 2) < 0)
		return (G_BAD_TOK_HEADER);

	if ((*buf++ != ((tok_type>>8)&0xff)) ||
	    (*buf++ != (tok_type&0xff)))
		return (G_BAD_TOK_HEADER);

	if (!ret) {
		*buf_in = buf;
		*body_size = toksize;
	}

	return (ret);
}

static gss_buffer_desc
make_dummy_token_msg(void *data, int dataLen)
{
	gss_buffer_desc buffer;
	int tlen;
	unsigned char *t;
	unsigned char *ptr;

	if (data == NULL) {
		buffer.length = 0;
		buffer.value = NULL;
		return (buffer);
	}

	tlen = g_token_size((gss_OID)gss_mech_dummy, dataLen);
	t = (unsigned char *) MALLOC(tlen);
	ptr = t;

	g_make_token_header((gss_OID)gss_mech_dummy, dataLen, &ptr, 0);
	(void) memcpy(ptr, data, dataLen);

	buffer.length = tlen;
	buffer.value = (void *) t;
	return (buffer);
}
