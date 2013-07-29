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
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 *
 * A module for Kerberos V5  security mechanism.
 *
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <mechglueP.h>
#include <gssapiP_krb5.h>
#include <gssapi_err_generic.h>
#include <gssapi/kgssapi_defs.h>
#include <sys/debug.h>
#include <k5-int.h>

/* mechglue wrappers */

static OM_uint32 k5glue_delete_sec_context
	(void *, OM_uint32 *,	/* minor_status */
	gss_ctx_id_t *,	/* context_handle */
	gss_buffer_t,	/* output_token */
	OM_uint32);

static OM_uint32 k5glue_sign
	(void *, OM_uint32 *,	/* minor_status */
	gss_ctx_id_t,	/* context_handle */
	int,		/* qop_req */
	gss_buffer_t,	/* message_buffer */
	gss_buffer_t,	/* message_token */
	OM_uint32);

static OM_uint32 k5glue_verify
	(void *, OM_uint32 *,	/* minor_status */
	gss_ctx_id_t,	/* context_handle */
	gss_buffer_t,	/* message_buffer */
	gss_buffer_t,	/* token_buffer */
	int *,	/* qop_state */
	OM_uint32);

static OM_uint32 k5glue_seal
	(void *, OM_uint32 *,	/* minor_status */
	gss_ctx_id_t,		/* context_handle */
	int,			/* conf_req_flag */
	int,			/* qop_req */
	gss_buffer_t,		/* input_message_buffer */
	int *,			/* conf_state */
	gss_buffer_t,		/* output_message_buffer */
	OM_uint32);

static OM_uint32 k5glue_unseal
	(void *, OM_uint32 *,	/* minor_status */
	gss_ctx_id_t,		/* context_handle */
	gss_buffer_t,		/* input_message_buffer */
	gss_buffer_t,		/* output_message_buffer */
	int *,			/* conf_state */
	int *,			/* qop_state */
	OM_uint32);

static OM_uint32 k5glue_import_sec_context
	(void *, OM_uint32 *,		/* minor_status */
	gss_buffer_t,			/* interprocess_token */
	gss_ctx_id_t *);		/* context_handle */



static	struct	gss_config krb5_mechanism =
	{{9, "\052\206\110\206\367\022\001\002\002"},
	NULL,	/* context */
	NULL,	/* next */
	TRUE,	/* uses_kmod */
	k5glue_unseal,
	k5glue_delete_sec_context,
	k5glue_seal,
	k5glue_import_sec_context,
	k5glue_sign,
	k5glue_verify,
	};

static gss_mechanism
	gss_mech_initialize()
{
	return (&krb5_mechanism);
}


/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops, "Krb5 GSS mechanism"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};


static int krb5_fini_code = EBUSY;

int
_init()
{
	int retval;
	gss_mechanism mech, tmp;

	if ((retval = mod_install(&modlinkage)) != 0)
		return (retval);

	mech = gss_mech_initialize();

	mutex_enter(&__kgss_mech_lock);
	tmp = __kgss_get_mechanism(&mech->mech_type);
	if (tmp != NULL) {

		KRB5_LOG0(KRB5_INFO,
		    "KRB5 GSS mechanism: mechanism already in table.\n");

		if (tmp->uses_kmod == TRUE) {
			KRB5_LOG0(KRB5_INFO, "KRB5 GSS mechanism: mechanism "
			    "table supports kernel operations!\n");
		}
		/*
		 * keep us loaded, but let us be unloadable. This
		 * will give the developer time to trouble shoot
		 */
		krb5_fini_code = 0;
	} else {
		__kgss_add_mechanism(mech);
		ASSERT(__kgss_get_mechanism(&mech->mech_type) == mech);
	}
	mutex_exit(&__kgss_mech_lock);

	return (0);
}

int
_fini()
{
	int ret = krb5_fini_code;

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

/* ARGSUSED */
static OM_uint32
k5glue_delete_sec_context(ctx, minor_status, context_handle, output_token,
	gssd_ctx_verifier)
	void *ctx;
	OM_uint32 *minor_status;
	gss_ctx_id_t *context_handle;
	gss_buffer_t output_token;
	OM_uint32 gssd_ctx_verifier;
{
	return (krb5_gss_delete_sec_context(minor_status,
				    context_handle, output_token,
				    gssd_ctx_verifier));
}

/* V2 */
/* ARGSUSED */
static OM_uint32
k5glue_import_sec_context(ctx, minor_status, interprocess_token, context_handle)
	void *ctx;
	OM_uint32 *minor_status;
	gss_buffer_t	interprocess_token;
	gss_ctx_id_t	 *context_handle;
{
	return (krb5_gss_import_sec_context(minor_status,
			interprocess_token,
			context_handle));
}

/* V1 only */
/* ARGSUSED */
static OM_uint32
k5glue_seal(ctx, minor_status, context_handle, conf_req_flag, qop_req,
	    input_message_buffer, conf_state, output_message_buffer,
	    gssd_ctx_verifier)
	void *ctx;
	OM_uint32 *minor_status;
	gss_ctx_id_t context_handle;
	int conf_req_flag;
	int qop_req;
	gss_buffer_t input_message_buffer;
	int *conf_state;
	gss_buffer_t output_message_buffer;
	OM_uint32 gssd_ctx_verifier;
{
	return (krb5_gss_seal(minor_status, context_handle,
			conf_req_flag, qop_req, input_message_buffer,
			conf_state, output_message_buffer, gssd_ctx_verifier));
}

/* ARGSUSED */
static OM_uint32
k5glue_sign(ctx, minor_status, context_handle,
		qop_req, message_buffer,
		message_token, gssd_ctx_verifier)
	void *ctx;
	OM_uint32 *minor_status;
	gss_ctx_id_t context_handle;
	int qop_req;
	gss_buffer_t message_buffer;
	gss_buffer_t message_token;
	OM_uint32 gssd_ctx_verifier;
{
	return (krb5_gss_sign(minor_status, context_handle,
		qop_req, message_buffer, message_token, gssd_ctx_verifier));
}

/* ARGSUSED */
static OM_uint32
k5glue_unseal(ctx, minor_status, context_handle, input_message_buffer,
	    output_message_buffer, conf_state, qop_state, gssd_ctx_verifier)
	void *ctx;
	OM_uint32 *minor_status;
	gss_ctx_id_t context_handle;
	gss_buffer_t input_message_buffer;
	gss_buffer_t output_message_buffer;
	int *conf_state;
	int *qop_state;
	OM_uint32 gssd_ctx_verifier;
{
	return (krb5_gss_unseal(minor_status, context_handle,
				input_message_buffer, output_message_buffer,
				conf_state, qop_state, gssd_ctx_verifier));
}

/* V1 only */
/* ARGSUSED */
static OM_uint32
k5glue_verify(ctx, minor_status, context_handle, message_buffer,
	    token_buffer, qop_state, gssd_ctx_verifier)
	void *ctx;
	OM_uint32 *minor_status;
	gss_ctx_id_t context_handle;
	gss_buffer_t message_buffer;
	gss_buffer_t token_buffer;
	int *qop_state;
	OM_uint32 gssd_ctx_verifier;
{
	return (krb5_gss_verify(minor_status,
				context_handle,
				message_buffer,
				token_buffer,
				qop_state, gssd_ctx_verifier));
}
