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
 */
/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/crypto/spi.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/ioctladmin.h>
#include <sys/sysmacros.h>
#include <sys/strsun.h>
#include <sys/sha1.h>
#include <sys/random.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/sunddi.h>
#include <sys/varargs.h>
#include <sys/kmem.h>
#include <sys/kstat.h>

#include <des/des_impl.h>
#include <ecc/ecc_impl.h>

#define	CKD_NULL		0x00000001

extern struct mod_ops mod_cryptoops;

/*
 * Module linkage information for the kernel.
 */
static struct modlcrypto modlcrypto = {
	&mod_cryptoops,
	"EC Kernel SW Provider"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlcrypto,
	NULL
};

/*
 * CSPI information (entry points, provider info, etc.)
 */
typedef enum ecc_mech_type {
	EC_KEY_PAIR_GEN_MECH_INFO_TYPE,	/* SUN_CKM_EC_KEY_PAIR_GEN */
	ECDSA_MECH_INFO_TYPE,		/* SUN_CKM_ECDSA */
	ECDSA_SHA1_MECH_INFO_TYPE,	/* SUN_CKM_ECDSA_SHA1 */
	ECDH1_DERIVE_MECH_INFO_TYPE	/* SUN_CKM_ECDH1_DERIVE */
} ecc_mech_type_t;

/*
 * Context for ECDSA mechanism.
 */
typedef struct ecc_ctx {
	ecc_mech_type_t	mech_type;
	crypto_key_t *key;
	size_t keychunk_size;
	ECParams ecparams;
} ecc_ctx_t;

/*
 * Context for ECDSA_SHA1 mechanism.
 */
typedef struct digest_ecc_ctx {
	ecc_mech_type_t	mech_type;
	crypto_key_t *key;
	size_t keychunk_size;
	ECParams ecparams;
	union {
		SHA1_CTX sha1ctx;
	} dctx_u;
} digest_ecc_ctx_t;

#define	sha1_ctx	dctx_u.sha1ctx

/*
 * Mechanism info structure passed to KCF during registration.
 */
static crypto_mech_info_t ecc_mech_info_tab[] = {
	/* EC_KEY_PAIR_GEN */
	{SUN_CKM_EC_KEY_PAIR_GEN, EC_KEY_PAIR_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_GENERATE_KEY_PAIR, EC_MIN_KEY_LEN, EC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* ECDH */
	{SUN_CKM_ECDH1_DERIVE, ECDH1_DERIVE_MECH_INFO_TYPE, CRYPTO_FG_DERIVE,
	    EC_MIN_KEY_LEN, EC_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* ECDSA */
	{SUN_CKM_ECDSA, ECDSA_MECH_INFO_TYPE,
	    CRYPTO_FG_SIGN | CRYPTO_FG_VERIFY |
	    CRYPTO_FG_SIGN_ATOMIC | CRYPTO_FG_VERIFY_ATOMIC,
	    EC_MIN_KEY_LEN, EC_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* ECDSA_SHA1 */
	{SUN_CKM_ECDSA_SHA1, ECDSA_SHA1_MECH_INFO_TYPE,
	    CRYPTO_FG_SIGN | CRYPTO_FG_VERIFY |
	    CRYPTO_FG_SIGN_ATOMIC | CRYPTO_FG_VERIFY_ATOMIC,
	    EC_MIN_KEY_LEN, EC_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS}
};

static void ecc_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t ecc_control_ops = {
	ecc_provider_status
};

static int ecc_sign_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int ecc_sign(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int ecc_sign_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int ecc_sign_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int ecc_sign_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);

static crypto_sign_ops_t ecc_sign_ops = {
	ecc_sign_init,
	ecc_sign,
	ecc_sign_update,
	ecc_sign_final,
	ecc_sign_atomic,
	NULL,
	NULL,
	NULL
};

static int ecc_verify_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int ecc_verify(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int ecc_verify_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int ecc_verify_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int ecc_verify_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static crypto_verify_ops_t ecc_verify_ops = {
	ecc_verify_init,
	ecc_verify,
	ecc_verify_update,
	ecc_verify_final,
	ecc_verify_atomic,
	NULL,
	NULL,
	NULL
};

static int ecc_nostore_key_generate_pair(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_object_attribute_t *,
    uint_t, crypto_object_attribute_t *, uint_t, crypto_object_attribute_t *,
    uint_t, crypto_object_attribute_t *, uint_t, crypto_req_handle_t);
static int ecc_nostore_key_derive(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *,
    crypto_object_attribute_t *, uint_t, crypto_object_attribute_t *,
    uint_t, crypto_req_handle_t);

static crypto_nostore_key_ops_t ecc_nostore_key_ops = {
	NULL,
	ecc_nostore_key_generate_pair,
	ecc_nostore_key_derive
};

static crypto_ops_t ecc_crypto_ops = {
	&ecc_control_ops,
	NULL,
	NULL,
	NULL,
	&ecc_sign_ops,
	&ecc_verify_ops,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	&ecc_nostore_key_ops,
	NULL,
};

static crypto_provider_info_t ecc_prov_info = {
	CRYPTO_SPI_VERSION_4,
	"EC Software Provider",
	CRYPTO_SW_PROVIDER,
	{&modlinkage},
	NULL,
	&ecc_crypto_ops,
	sizeof (ecc_mech_info_tab)/sizeof (crypto_mech_info_t),
	ecc_mech_info_tab
};

static crypto_kcf_provider_handle_t ecc_prov_handle = 0;

static int ecc_sign_common(ecc_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int ecc_verify_common(ecc_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int find_attr(crypto_object_attribute_t *, uint_t, uint64_t);
static int get_template_attr_ulong(crypto_object_attribute_t *,
    uint_t, uint64_t, ulong_t *);
static void ecc_free_context(crypto_ctx_t *);
static void free_ecparams(ECParams *, boolean_t);
static void free_ecprivkey(ECPrivateKey *);

int
_init(void)
{
	int ret;

	if ((ret = mod_install(&modlinkage)) != 0)
		return (ret);

	/* Register with KCF.  If the registration fails, remove the module. */
	if (crypto_register_provider(&ecc_prov_info, &ecc_prov_handle)) {
		(void) mod_remove(&modlinkage);
		return (EACCES);
	}

	return (0);
}

int
_fini(void)
{
	/* Unregister from KCF if module is registered */
	if (ecc_prov_handle != 0) {
		if (crypto_unregister_provider(ecc_prov_handle))
			return (EBUSY);

		ecc_prov_handle = 0;
	}

	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static void
ecc_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

/*
 * Return the index of an attribute of specified type found in
 * the specified array of attributes. If the attribute cannot
 * found, return -1.
 */
static int
find_attr(crypto_object_attribute_t *attr, uint_t nattr, uint64_t attr_type)
{
	int i;

	for (i = 0; i < nattr; i++)
		if (attr[i].oa_value != NULL && attr[i].oa_type == attr_type)
			return (i);
	return (-1);
}

/*
 * Common function used by the get_template_attr_*() family of
 * functions. Returns the value of the specified attribute of specified
 * length. Returns CRYPTO_SUCCESS on success, CRYPTO_ATTRIBUTE_VALUE_INVALID
 * if the length of the attribute does not match the specified length,
 * or CRYPTO_ARGUMENTS_BAD if the attribute cannot be found.
 */
static int
get_template_attr_scalar_common(crypto_object_attribute_t *template,
    uint_t nattr, uint64_t attr_type, void *value, size_t value_len)
{
	size_t oa_value_len;
	size_t offset = 0;
	int attr_idx;

	if ((attr_idx = find_attr(template, nattr, attr_type)) == -1)
		return (CRYPTO_ARGUMENTS_BAD);

	oa_value_len = template[attr_idx].oa_value_len;
	if (oa_value_len != value_len) {
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}

do_copy:
	bcopy(template[attr_idx].oa_value, (uchar_t *)value + offset,
	    oa_value_len);

	return (CRYPTO_SUCCESS);
}

/*
 * Get the value of a ulong_t attribute from the specified template.
 */
static int
get_template_attr_ulong(crypto_object_attribute_t *template,
    uint_t nattr, uint64_t attr_type, ulong_t *attr_value)
{
	return (get_template_attr_scalar_common(template, nattr,
	    attr_type, attr_value, sizeof (ulong_t)));
}

/*
 * Called from init routines to do basic sanity checks. Init routines,
 * e.g. sign_init should fail rather than subsequent operations.
 */
static int
check_mech_and_key(ecc_mech_type_t mech_type, crypto_key_t *key, ulong_t class)
{
	int rv = CRYPTO_SUCCESS;
	uchar_t *foo;
	ssize_t point_len;
	ssize_t value_len;

	if (mech_type != ECDSA_SHA1_MECH_INFO_TYPE &&
	    mech_type != ECDSA_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	if (key->ck_format != CRYPTO_KEY_ATTR_LIST) {
		return (CRYPTO_KEY_TYPE_INCONSISTENT);
	}

	switch (class) {
	case CKO_PUBLIC_KEY:
		if ((rv = crypto_get_key_attr(key, CKA_EC_POINT, &foo,
		    &point_len)) != CRYPTO_SUCCESS) {
			return (CRYPTO_TEMPLATE_INCOMPLETE);
		}
		if (point_len < CRYPTO_BITS2BYTES(EC_MIN_KEY_LEN) * 2 + 1 ||
		    point_len > CRYPTO_BITS2BYTES(EC_MAX_KEY_LEN) * 2 + 1)
			return (CRYPTO_KEY_SIZE_RANGE);
		break;

	case CKO_PRIVATE_KEY:
		if ((rv = crypto_get_key_attr(key, CKA_VALUE, &foo,
		    &value_len)) != CRYPTO_SUCCESS) {
			return (CRYPTO_TEMPLATE_INCOMPLETE);
		}
		if (value_len < CRYPTO_BITS2BYTES(EC_MIN_KEY_LEN) ||
		    value_len > CRYPTO_BITS2BYTES(EC_MAX_KEY_LEN))
			return (CRYPTO_KEY_SIZE_RANGE);
		break;

	default:
		return (CRYPTO_TEMPLATE_INCONSISTENT);
	}

	return (rv);
}

/*
 * This function guarantees to return non-zero random numbers.
 * This is needed as the /dev/urandom kernel interface,
 * random_get_pseudo_bytes(), may return zeros.
 */
int
ecc_knzero_random_generator(uint8_t *ran_out, size_t ran_len)
{
	int rv;
	size_t ebc = 0; /* count of extra bytes in extrarand */
	size_t i = 0;
	uint8_t extrarand[32];
	size_t extrarand_len;

	if ((rv = random_get_pseudo_bytes(ran_out, ran_len)) != 0)
		return (rv);

	/*
	 * Walk through the returned random numbers pointed by ran_out,
	 * and look for any random number which is zero.
	 * If we find zero, call random_get_pseudo_bytes() to generate
	 * another 32 random numbers pool. Replace any zeros in ran_out[]
	 * from the random number in pool.
	 */
	while (i < ran_len) {
		if (ran_out[i] != 0) {
			i++;
			continue;
		}

		/*
		 * Note that it is 'while' so we are guaranteed a
		 * non-zero value on exit.
		 */
		if (ebc == 0) {
			/* refresh extrarand */
			extrarand_len = sizeof (extrarand);
			if ((rv = random_get_pseudo_bytes(extrarand,
			    extrarand_len)) != 0) {
				return (rv);
			}

			ebc = extrarand_len;
		}
		/* Replace zero with byte from extrarand. */
		-- ebc;

		/*
		 * The new random byte zero/non-zero will be checked in
		 * the next pass through the loop.
		 */
		ran_out[i] = extrarand[ebc];
	}

	return (CRYPTO_SUCCESS);
}

static void
ecc_free_context(crypto_ctx_t *ctx)
{
	ecc_ctx_t *ctxp = ctx->cc_provider_private;

	if (ctxp != NULL) {
		bzero(ctxp->key, ctxp->keychunk_size);
		kmem_free(ctxp->key, ctxp->keychunk_size);

		free_ecparams(&ctxp->ecparams, B_FALSE);

		if (ctxp->mech_type == ECDSA_MECH_INFO_TYPE)
			kmem_free(ctxp, sizeof (ecc_ctx_t));
		else
			kmem_free(ctxp, sizeof (digest_ecc_ctx_t));

		ctx->cc_provider_private = NULL;
	}
}

/* ARGSUSED */
static int
ecc_sign_verify_common_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int rv;
	int kmflag;
	ecc_ctx_t *ctxp;
	digest_ecc_ctx_t *dctxp;
	ecc_mech_type_t mech_type = mechanism->cm_type;
	uchar_t *params;
	ssize_t params_len;
	ECParams  *ecparams;
	SECKEYECParams params_item;

	if (crypto_get_key_attr(key, CKA_EC_PARAMS, (void *) &params,
	    &params_len)) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/* ASN1 check */
	if (params[0] != 0x06 ||
	    params[1] != params_len - 2) {
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}
	params_item.data = params;
	params_item.len = (uint_t)params_len;
	kmflag = crypto_kmflag(req);
	if (EC_DecodeParams(&params_item, &ecparams, kmflag) != SECSuccess) {
		/* bad curve OID */
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/*
	 * Allocate an ECC context.
	 */
	switch (mech_type) {
	case ECDSA_SHA1_MECH_INFO_TYPE:
		dctxp = kmem_zalloc(sizeof (digest_ecc_ctx_t), kmflag);
		ctxp = (ecc_ctx_t *)dctxp;
		break;
	default:
		ctxp = kmem_zalloc(sizeof (ecc_ctx_t), kmflag);
		break;
	}

	if (ctxp == NULL) {
		free_ecparams(ecparams, B_TRUE);
		return (CRYPTO_HOST_MEMORY);
	}

	if ((rv = crypto_copy_key_to_ctx(key, &ctxp->key, &ctxp->keychunk_size,
	    kmflag)) != CRYPTO_SUCCESS) {
		switch (mech_type) {
		case ECDSA_SHA1_MECH_INFO_TYPE:
			kmem_free(dctxp, sizeof (digest_ecc_ctx_t));
			break;
		default:
			kmem_free(ctxp, sizeof (ecc_ctx_t));
			break;
		}
		free_ecparams(ecparams, B_TRUE);
		return (rv);
	}
	ctxp->mech_type = mech_type;
	ctxp->ecparams = *ecparams;
	kmem_free(ecparams, sizeof (ECParams));

	switch (mech_type) {
	case ECDSA_SHA1_MECH_INFO_TYPE:
		SHA1Init(&(dctxp->sha1_ctx));
		break;
	}

	ctx->cc_provider_private = ctxp;

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
ecc_sign_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int rv;

	ecc_mech_type_t mech_type = mechanism->cm_type;

	if ((rv = check_mech_and_key(mech_type, key,
	    CKO_PRIVATE_KEY)) != CRYPTO_SUCCESS)
		return (rv);

	rv = ecc_sign_verify_common_init(ctx, mechanism, key,
	    ctx_template, req);

	return (rv);
}

/* ARGSUSED */
static int
ecc_verify_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int rv;

	ecc_mech_type_t mech_type = mechanism->cm_type;

	if ((rv = check_mech_and_key(mech_type, key,
	    CKO_PUBLIC_KEY)) != CRYPTO_SUCCESS)
		return (rv);

	rv = ecc_sign_verify_common_init(ctx, mechanism, key,
	    ctx_template, req);

	return (rv);
}

#define	SHA1_DIGEST_SIZE 20

#define	INIT_RAW_CRYPTO_DATA(data, base, len, cd_len)	\
	(data).cd_format = CRYPTO_DATA_RAW;		\
	(data).cd_offset = 0;				\
	(data).cd_raw.iov_base = (char *)base;		\
	(data).cd_raw.iov_len = len;			\
	(data).cd_length = cd_len;

static int
ecc_digest_svrfy_common(digest_ecc_ctx_t *ctxp, crypto_data_t *data,
    crypto_data_t *signature, uchar_t flag, crypto_req_handle_t req)
{
	int rv = CRYPTO_FAILED;
	uchar_t digest[SHA1_DIGEST_LENGTH];
	crypto_data_t der_cd;
	ecc_mech_type_t mech_type;

	ASSERT(flag & CRYPTO_DO_SIGN || flag & CRYPTO_DO_VERIFY);
	ASSERT(data != NULL || (flag & CRYPTO_DO_FINAL));

	mech_type = ctxp->mech_type;
	if (mech_type != ECDSA_SHA1_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	/* Don't digest if only returning length of signature. */
	if (signature->cd_length > 0) {
		if (mech_type == ECDSA_SHA1_MECH_INFO_TYPE) {
			rv = crypto_digest_data(data, &(ctxp->sha1_ctx),
			    digest, (void (*)())SHA1Update,
			    (void (*)())SHA1Final, flag | CRYPTO_DO_SHA1);
			if (rv != CRYPTO_SUCCESS)
				return (rv);
		}
	}

	INIT_RAW_CRYPTO_DATA(der_cd, digest, SHA1_DIGEST_SIZE,
	    SHA1_DIGEST_SIZE);

	if (flag & CRYPTO_DO_SIGN) {
		rv = ecc_sign_common((ecc_ctx_t *)ctxp, &der_cd, signature,
		    req);
	} else
		rv = ecc_verify_common((ecc_ctx_t *)ctxp, &der_cd, signature,
		    req);

	return (rv);
}

/*
 * This is a single-part signing routine. It does not
 * compute a hash before signing.
 */
static int
ecc_sign_common(ecc_ctx_t *ctx, crypto_data_t *data, crypto_data_t *signature,
    crypto_req_handle_t req)
{
	int rv = CRYPTO_FAILED;
	SECStatus ss;
	uchar_t *param;
	uchar_t *private;
	ssize_t param_len;
	ssize_t private_len;
	uchar_t tmp_data[EC_MAX_DIGEST_LEN];
	uchar_t signed_data[EC_MAX_SIG_LEN];
	ECPrivateKey ECkey;
	SECItem signature_item;
	SECItem digest_item;
	crypto_key_t *key = ctx->key;
	int kmflag;

	if ((rv = crypto_get_key_attr(key, CKA_EC_PARAMS, &param,
	    &param_len)) != CRYPTO_SUCCESS) {
		return (rv);
	}

	if (data->cd_length > sizeof (tmp_data))
		return (CRYPTO_DATA_LEN_RANGE);

	if ((rv = crypto_get_input_data(data, &digest_item.data, tmp_data))
	    != CRYPTO_SUCCESS) {
		return (rv);
	}
	digest_item.len = data->cd_length;

	/* structure assignment */
	ECkey.ecParams = ctx->ecparams;

	if ((rv = crypto_get_key_attr(key, CKA_VALUE, &private,
	    &private_len)) != CRYPTO_SUCCESS) {
		return (rv);
	}
	ECkey.privateValue.data = private;
	ECkey.privateValue.len = (uint_t)private_len;

	signature_item.data = signed_data;
	signature_item.len = sizeof (signed_data);

	kmflag = crypto_kmflag(req);
	if ((ss = ECDSA_SignDigest(&ECkey, &signature_item, &digest_item,
	    kmflag)) != SECSuccess) {
		if (ss == SECBufferTooSmall)
			return (CRYPTO_BUFFER_TOO_SMALL);

		return (CRYPTO_FAILED);
	}

	if (rv == CRYPTO_SUCCESS) {
		/* copy out the signature */
		if ((rv = crypto_put_output_data(signed_data,
		    signature, signature_item.len)) != CRYPTO_SUCCESS)
			return (rv);

		signature->cd_length = signature_item.len;
	}

	return (rv);
}

/* ARGSUSED */
static int
ecc_sign(crypto_ctx_t *ctx, crypto_data_t *data, crypto_data_t *signature,
    crypto_req_handle_t req)
{
	int rv;
	ecc_ctx_t *ctxp;

	ASSERT(ctx->cc_provider_private != NULL);
	ctxp = ctx->cc_provider_private;

	switch (ctxp->mech_type) {
	case ECDSA_SHA1_MECH_INFO_TYPE:
		rv = ecc_digest_svrfy_common((digest_ecc_ctx_t *)ctxp, data,
		    signature, CRYPTO_DO_SIGN | CRYPTO_DO_UPDATE |
		    CRYPTO_DO_FINAL, req);
		break;
	default:
		rv = ecc_sign_common(ctxp, data, signature, req);
		break;
	}

	if (rv != CRYPTO_BUFFER_TOO_SMALL)
		ecc_free_context(ctx);

	return (rv);
}

/* ARGSUSED */
static int
ecc_sign_update(crypto_ctx_t *ctx, crypto_data_t *data, crypto_req_handle_t req)
{
	int rv;
	digest_ecc_ctx_t *ctxp;
	ecc_mech_type_t mech_type;

	ASSERT(ctx->cc_provider_private != NULL);
	ctxp = ctx->cc_provider_private;
	mech_type = ctxp->mech_type;

	if (mech_type == ECDSA_MECH_INFO_TYPE) {
		ecc_free_context(ctx);
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (mech_type == ECDSA_SHA1_MECH_INFO_TYPE)
		rv = crypto_digest_data(data, &(ctxp->sha1_ctx), NULL,
		    (void (*)())SHA1Update, (void (*)())SHA1Final,
		    CRYPTO_DO_SHA1 | CRYPTO_DO_UPDATE);

	if (rv != CRYPTO_SUCCESS)
		ecc_free_context(ctx);

	return (rv);
}

/* ARGSUSED */
static int
ecc_sign_final(crypto_ctx_t *ctx, crypto_data_t *signature,
    crypto_req_handle_t req)
{
	int rv;
	digest_ecc_ctx_t *ctxp;

	ASSERT(ctx->cc_provider_private != NULL);
	ctxp = ctx->cc_provider_private;

	rv = ecc_digest_svrfy_common(ctxp, NULL, signature, CRYPTO_DO_SIGN |
	    CRYPTO_DO_FINAL, req);
	if (rv != CRYPTO_BUFFER_TOO_SMALL)
		ecc_free_context(ctx);

	return (rv);
}

/* ARGSUSED */
static int
ecc_sign_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *signature,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int rv;
	ecc_mech_type_t mech_type = mechanism->cm_type;
	uchar_t *params;
	ssize_t params_len;
	ECParams  *ecparams;
	SECKEYECParams params_item;
	int kmflag;

	if ((rv = check_mech_and_key(mech_type, key,
	    CKO_PRIVATE_KEY)) != CRYPTO_SUCCESS)
		return (rv);

	if (crypto_get_key_attr(key, CKA_EC_PARAMS, (void *) &params,
	    &params_len)) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/* ASN1 check */
	if (params[0] != 0x06 ||
	    params[1] != params_len - 2) {
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}
	params_item.data = params;
	params_item.len = (uint_t)params_len;
	kmflag = crypto_kmflag(req);
	if (EC_DecodeParams(&params_item, &ecparams, kmflag) != SECSuccess) {
		/* bad curve OID */
		return (CRYPTO_ARGUMENTS_BAD);
	}

	if (mechanism->cm_type == ECDSA_MECH_INFO_TYPE) {
		ecc_ctx_t ctx;

		ctx.mech_type = mech_type;
		/* structure assignment */
		ctx.ecparams = *ecparams;
		ctx.key = key;
		rv = ecc_sign_common(&ctx, data, signature, req);
	} else {
		digest_ecc_ctx_t dctx;

		dctx.mech_type = mech_type;
		/* structure assignment */
		dctx.ecparams = *ecparams;
		dctx.key = key;
		SHA1Init(&(dctx.sha1_ctx));

		rv = ecc_digest_svrfy_common(&dctx, data, signature,
		    CRYPTO_DO_SIGN | CRYPTO_DO_UPDATE | CRYPTO_DO_FINAL, req);
	}
	free_ecparams(ecparams, B_TRUE);

	return (rv);
}

static int
ecc_verify_common(ecc_ctx_t *ctx, crypto_data_t *data, crypto_data_t *signature,
    crypto_req_handle_t req)
{
	int rv = CRYPTO_FAILED;
	uchar_t *param;
	uchar_t *public;
	ssize_t param_len;
	ssize_t public_len;
	uchar_t tmp_data[EC_MAX_DIGEST_LEN];
	uchar_t signed_data[EC_MAX_SIG_LEN];
	ECPublicKey ECkey;
	SECItem signature_item;
	SECItem digest_item;
	crypto_key_t *key = ctx->key;
	int kmflag;

	if ((rv = crypto_get_key_attr(key, CKA_EC_PARAMS, &param,
	    &param_len)) != CRYPTO_SUCCESS) {
		return (rv);
	}

	if (signature->cd_length > sizeof (signed_data)) {
		return (CRYPTO_SIGNATURE_LEN_RANGE);
	}

	if ((rv = crypto_get_input_data(signature, &signature_item.data,
	    signed_data)) != CRYPTO_SUCCESS) {
		return (rv);
	}
	signature_item.len = signature->cd_length;

	if (data->cd_length > sizeof (tmp_data))
		return (CRYPTO_DATA_LEN_RANGE);

	if ((rv = crypto_get_input_data(data, &digest_item.data, tmp_data))
	    != CRYPTO_SUCCESS) {
		return (rv);
	}
	digest_item.len = data->cd_length;

	/* structure assignment */
	ECkey.ecParams = ctx->ecparams;

	if ((rv = crypto_get_key_attr(key, CKA_EC_POINT, &public,
	    &public_len)) != CRYPTO_SUCCESS) {
		return (rv);
	}
	ECkey.publicValue.data = public;
	ECkey.publicValue.len = (uint_t)public_len;

	kmflag = crypto_kmflag(req);
	if (ECDSA_VerifyDigest(&ECkey, &signature_item, &digest_item, kmflag)
	    != SECSuccess) {
		rv = CRYPTO_SIGNATURE_INVALID;
	} else {
		rv = CRYPTO_SUCCESS;
	}

	return (rv);
}

/* ARGSUSED */
static int
ecc_verify(crypto_ctx_t *ctx, crypto_data_t *data, crypto_data_t *signature,
    crypto_req_handle_t req)
{
	int rv;
	ecc_ctx_t *ctxp;

	ASSERT(ctx->cc_provider_private != NULL);
	ctxp = ctx->cc_provider_private;

	switch (ctxp->mech_type) {
	case ECDSA_SHA1_MECH_INFO_TYPE:
		rv = ecc_digest_svrfy_common((digest_ecc_ctx_t *)ctxp, data,
		    signature, CRYPTO_DO_VERIFY | CRYPTO_DO_UPDATE |
		    CRYPTO_DO_FINAL, req);
		break;
	default:
		rv = ecc_verify_common(ctxp, data, signature, req);
		break;
	}

	ecc_free_context(ctx);
	return (rv);
}

/* ARGSUSED */
static int
ecc_verify_update(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	int rv;
	digest_ecc_ctx_t *ctxp;

	ASSERT(ctx->cc_provider_private != NULL);
	ctxp = ctx->cc_provider_private;

	switch (ctxp->mech_type) {
	case ECDSA_SHA1_MECH_INFO_TYPE:
		rv = crypto_digest_data(data, &(ctxp->sha1_ctx), NULL,
		    (void (*)())SHA1Update, (void (*)())SHA1Final,
		    CRYPTO_DO_SHA1 | CRYPTO_DO_UPDATE);
		break;
	default:
		rv = CRYPTO_MECHANISM_INVALID;
	}

	if (rv != CRYPTO_SUCCESS)
		ecc_free_context(ctx);

	return (rv);
}

/* ARGSUSED */
static int
ecc_verify_final(crypto_ctx_t *ctx, crypto_data_t *signature,
    crypto_req_handle_t req)
{
	int rv;
	digest_ecc_ctx_t *ctxp;

	ASSERT(ctx->cc_provider_private != NULL);
	ctxp = ctx->cc_provider_private;

	rv = ecc_digest_svrfy_common(ctxp, NULL, signature,
	    CRYPTO_DO_VERIFY | CRYPTO_DO_FINAL, req);

	ecc_free_context(ctx);

	return (rv);
}


/* ARGSUSED */
static int
ecc_verify_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *signature,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int rv;
	ecc_mech_type_t mech_type = mechanism->cm_type;
	uchar_t *params;
	ssize_t params_len;
	ECParams  *ecparams;
	SECKEYECParams params_item;
	int kmflag;

	if ((rv = check_mech_and_key(mech_type, key,
	    CKO_PUBLIC_KEY)) != CRYPTO_SUCCESS)
		return (rv);

	if (crypto_get_key_attr(key, CKA_EC_PARAMS, (void *) &params,
	    &params_len)) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/* ASN1 check */
	if (params[0] != 0x06 ||
	    params[1] != params_len - 2) {
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}
	params_item.data = params;
	params_item.len = (uint_t)params_len;
	kmflag = crypto_kmflag(req);
	if (EC_DecodeParams(&params_item, &ecparams, kmflag) != SECSuccess) {
		/* bad curve OID */
		return (CRYPTO_ARGUMENTS_BAD);
	}

	if (mechanism->cm_type == ECDSA_MECH_INFO_TYPE) {
		ecc_ctx_t ctx;

		ctx.mech_type = mech_type;
		/* structure assignment */
		ctx.ecparams = *ecparams;
		ctx.key = key;
		rv = ecc_verify_common(&ctx, data, signature, req);
	} else {
		digest_ecc_ctx_t dctx;

		dctx.mech_type = mech_type;
		/* structure assignment */
		dctx.ecparams = *ecparams;
		dctx.key = key;
		SHA1Init(&(dctx.sha1_ctx));

		rv = ecc_digest_svrfy_common(&dctx, data, signature,
		    CRYPTO_DO_VERIFY | CRYPTO_DO_UPDATE | CRYPTO_DO_FINAL, req);
	}
	free_ecparams(ecparams, B_TRUE);
	return (rv);
}

/* ARGSUSED */
static int
ecc_nostore_key_generate_pair(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_object_attribute_t *pub_template, uint_t pub_attribute_count,
    crypto_object_attribute_t *pri_template, uint_t pri_attribute_count,
    crypto_object_attribute_t *pub_out_template, uint_t pub_out_attribute_count,
    crypto_object_attribute_t *pri_out_template, uint_t pri_out_attribute_count,
    crypto_req_handle_t req)
{
	int rv = CRYPTO_SUCCESS;
	ECPrivateKey *privKey;	/* contains both public and private values */
	ECParams *ecparams;
	SECKEYECParams params_item;
	ulong_t pub_key_type = ~0UL, pub_class = ~0UL;
	ulong_t pri_key_type = ~0UL, pri_class = ~0UL;
	int params_idx, value_idx, point_idx;
	uchar_t *params = NULL;
	unsigned params_len;
	uchar_t *value = NULL;
	uchar_t *point = NULL;
	int valuelen;
	int pointlen;
	int xylen;
	int kmflag;

	if (mechanism->cm_type != EC_KEY_PAIR_GEN_MECH_INFO_TYPE) {
		return (CRYPTO_MECHANISM_INVALID);
	}

	/* optional */
	(void) get_template_attr_ulong(pub_template,
	    pub_attribute_count, CKA_CLASS, &pub_class);

	/* optional */
	(void) get_template_attr_ulong(pri_template,
	    pri_attribute_count, CKA_CLASS, &pri_class);

	/* optional */
	(void) get_template_attr_ulong(pub_template,
	    pub_attribute_count, CKA_KEY_TYPE, &pub_key_type);

	/* optional */
	(void) get_template_attr_ulong(pri_template,
	    pri_attribute_count, CKA_KEY_TYPE, &pri_key_type);

	if (pub_class != ~0UL && pub_class != CKO_PUBLIC_KEY) {
		return (CRYPTO_TEMPLATE_INCONSISTENT);
	}
	pub_class = CKO_PUBLIC_KEY;

	if (pri_class != ~0UL && pri_class != CKO_PRIVATE_KEY) {
		return (CRYPTO_TEMPLATE_INCONSISTENT);
	}
	pri_class = CKO_PRIVATE_KEY;

	if (pub_key_type != ~0UL && pub_key_type != CKK_EC) {
		return (CRYPTO_TEMPLATE_INCONSISTENT);
	}
	pub_key_type = CKK_EC;

	if (pri_key_type != ~0UL && pri_key_type != CKK_EC) {
		return (CRYPTO_TEMPLATE_INCONSISTENT);
	}
	pri_key_type = CKK_EC;

	/* public output template must contain CKA_EC_POINT attribute */
	if ((point_idx = find_attr(pub_out_template, pub_out_attribute_count,
	    CKA_EC_POINT)) == -1) {
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	/* private output template must contain CKA_VALUE attribute */
	if ((value_idx = find_attr(pri_out_template, pri_out_attribute_count,
	    CKA_VALUE)) == -1) {
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	if ((params_idx = find_attr(pub_template, pub_attribute_count,
	    CKA_EC_PARAMS)) == -1) {
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	params = (uchar_t *)pub_template[params_idx].oa_value;
	params_len = pub_template[params_idx].oa_value_len;

	value = (uchar_t *)pri_out_template[value_idx].oa_value;
	valuelen = (int)pri_out_template[value_idx].oa_value_len;
	point = (uchar_t *)pub_out_template[point_idx].oa_value;
	pointlen = (int)pub_out_template[point_idx].oa_value_len;

	/* ASN1 check */
	if (params[0] != 0x06 ||
	    params[1] != params_len - 2) {
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}
	params_item.data = params;
	params_item.len = params_len;
	kmflag = crypto_kmflag(req);
	if (EC_DecodeParams(&params_item, &ecparams, kmflag) != SECSuccess) {
		/* bad curve OID */
		return (CRYPTO_ARGUMENTS_BAD);
	}

	if (EC_NewKey(ecparams, &privKey, kmflag) != SECSuccess) {
		free_ecparams(ecparams, B_TRUE);
		return (CRYPTO_FAILED);
	}

	xylen = privKey->publicValue.len;
	/* ASSERT that xylen - 1 is divisible by 2 */
	if (xylen > pointlen) {
		rv = CRYPTO_BUFFER_TOO_SMALL;
		goto out;
	}

	if (privKey->privateValue.len > valuelen) {
		rv = CRYPTO_BUFFER_TOO_SMALL;
		goto out;
	}
	bcopy(privKey->privateValue.data, value, privKey->privateValue.len);
	pri_out_template[value_idx].oa_value_len = privKey->privateValue.len;

	bcopy(privKey->publicValue.data, point, xylen);
	pub_out_template[point_idx].oa_value_len = xylen;

out:
	free_ecprivkey(privKey);
	free_ecparams(ecparams, B_TRUE);
	return (rv);
}

/* ARGSUSED */
static int
ecc_nostore_key_derive(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *base_key, crypto_object_attribute_t *in_attrs,
    uint_t in_attr_count, crypto_object_attribute_t *out_attrs,
    uint_t out_attr_count, crypto_req_handle_t req)
{
	int rv = CRYPTO_SUCCESS;
	int params_idx, value_idx = -1, out_value_idx = -1;
	ulong_t key_type;
	ulong_t key_len;
	crypto_object_attribute_t *attrs;
	ECParams *ecparams;
	SECKEYECParams params_item;
	CK_ECDH1_DERIVE_PARAMS *mech_param;
	SECItem public_value_item, private_value_item, secret_item;
	int kmflag;

	if (mechanism->cm_type != ECDH1_DERIVE_MECH_INFO_TYPE) {
		return (CRYPTO_MECHANISM_INVALID);
	}

	ASSERT(IS_P2ALIGNED(mechanism->cm_param, sizeof (uint64_t)));
	/* LINTED: pointer alignment */
	mech_param = (CK_ECDH1_DERIVE_PARAMS *)mechanism->cm_param;
	if (mech_param->kdf != CKD_NULL) {
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	if ((base_key->ck_format != CRYPTO_KEY_ATTR_LIST) ||
	    (base_key->ck_count == 0)) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	if ((rv = get_template_attr_ulong(in_attrs, in_attr_count,
	    CKA_KEY_TYPE, &key_type)) != CRYPTO_SUCCESS) {
		return (rv);
	}

	switch (key_type) {
	case CKK_DES:
		key_len = DES_KEYSIZE;
		break;
	case CKK_DES2:
		key_len = DES2_KEYSIZE;
		break;
	case CKK_DES3:
		key_len = DES3_KEYSIZE;
		break;
	case CKK_RC4:
	case CKK_AES:
	case CKK_GENERIC_SECRET:
		if ((rv = get_template_attr_ulong(in_attrs, in_attr_count,
		    CKA_VALUE_LEN, &key_len)) != CRYPTO_SUCCESS) {
			return (rv);
		}
		break;
	default:
		key_len = 0;
	}

	attrs = base_key->ck_attrs;
	if ((value_idx = find_attr(attrs, base_key->ck_count,
	    CKA_VALUE)) == -1) {
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	if ((params_idx = find_attr(attrs, base_key->ck_count,
	    CKA_EC_PARAMS)) == -1) {
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	private_value_item.data = (uchar_t *)attrs[value_idx].oa_value;
	private_value_item.len = attrs[value_idx].oa_value_len;

	params_item.len = attrs[params_idx].oa_value_len;
	params_item.data = (uchar_t *)attrs[params_idx].oa_value;

	/* ASN1 check */
	if (params_item.data[0] != 0x06 ||
	    params_item.data[1] != params_item.len - 2) {
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}
	kmflag = crypto_kmflag(req);
	if (EC_DecodeParams(&params_item, &ecparams, kmflag) != SECSuccess) {
		/* bad curve OID */
		return (CRYPTO_ARGUMENTS_BAD);
	}

	public_value_item.data = (uchar_t *)mech_param->pPublicData;
	public_value_item.len = mech_param->ulPublicDataLen;

	if ((out_value_idx = find_attr(out_attrs, out_attr_count,
	    CKA_VALUE)) == -1) {
		rv = CRYPTO_TEMPLATE_INCOMPLETE;
		goto out;
	}
	secret_item.data = NULL;
	secret_item.len = 0;

	if (ECDH_Derive(&public_value_item, ecparams, &private_value_item,
	    B_FALSE, &secret_item, kmflag) != SECSuccess) {
		free_ecparams(ecparams, B_TRUE);
		return (CRYPTO_FAILED);
	} else {
		rv = CRYPTO_SUCCESS;
	}

	if (key_len == 0)
		key_len = secret_item.len;

	if (key_len > secret_item.len) {
		rv = CRYPTO_ATTRIBUTE_VALUE_INVALID;
		goto out;
	}
	if (key_len > out_attrs[out_value_idx].oa_value_len) {
		rv = CRYPTO_BUFFER_TOO_SMALL;
		goto out;
	}
	bcopy(secret_item.data + secret_item.len - key_len,
	    (uchar_t *)out_attrs[out_value_idx].oa_value, key_len);
	out_attrs[out_value_idx].oa_value_len = key_len;
out:
	free_ecparams(ecparams, B_TRUE);
	SECITEM_FreeItem(&secret_item, B_FALSE);
	return (rv);
}

static void
free_ecparams(ECParams *params, boolean_t freeit)
{
	SECITEM_FreeItem(&params->fieldID.u.prime, B_FALSE);
	SECITEM_FreeItem(&params->curve.a, B_FALSE);
	SECITEM_FreeItem(&params->curve.b, B_FALSE);
	SECITEM_FreeItem(&params->curve.seed, B_FALSE);
	SECITEM_FreeItem(&params->base, B_FALSE);
	SECITEM_FreeItem(&params->order, B_FALSE);
	SECITEM_FreeItem(&params->DEREncoding, B_FALSE);
	SECITEM_FreeItem(&params->curveOID, B_FALSE);
	if (freeit)
		kmem_free(params, sizeof (ECParams));
}

static void
free_ecprivkey(ECPrivateKey *key)
{
	free_ecparams(&key->ecParams, B_FALSE);
	SECITEM_FreeItem(&key->publicValue, B_FALSE);
	bzero(key->privateValue.data, key->privateValue.len);
	SECITEM_FreeItem(&key->privateValue, B_FALSE);
	SECITEM_FreeItem(&key->version, B_FALSE);
	kmem_free(key, sizeof (ECPrivateKey));
}
