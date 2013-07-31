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
 *
 */
/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * des_crypt.c, DES encryption library routines
 */

#include <sys/errno.h>
#include <sys/modctl.h>

#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <sys/sysmacros.h>
#include <sys/strsun.h>
#include <sys/note.h>
#include <modes/modes.h>
#define	_DES_IMPL
#include <des/des_impl.h>

#include <sys/types.h>
#include <rpc/des_crypt.h>
#include <des/des.h>

#ifdef sun_hardware
#include <sys/ioctl.h>
#ifdef _KERNEL
#include <sys/conf.h>
static int g_desfd = -1;
#define	getdesfd()	(cdevsw[11].d_open(0, 0) ? -1 : 0)
#define	ioctl(a, b, c)	(cdevsw[11].d_ioctl(0, b, c, 0) ? -1 : 0)
#else
#define	getdesfd()	(open("/dev/des", 0, 0))
#endif	/* _KERNEL */
#endif	/* sun */

static int common_crypt(char *key, char *buf, size_t len,
    unsigned int mode, struct desparams *desp);

extern int _des_crypt(char *buf, size_t len, struct desparams *desp);

extern struct mod_ops mod_cryptoops;

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops,
	"des encryption",
};

static struct modlcrypto modlcrypto = {
	&mod_cryptoops,
	"DES Kernel SW Provider"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlmisc,
	&modlcrypto,
	NULL
};

#define	DES_MIN_KEY_LEN		DES_MINBYTES
#define	DES_MAX_KEY_LEN		DES_MAXBYTES
#define	DES3_MIN_KEY_LEN	DES3_MAXBYTES	/* no CKK_DES2 support */
#define	DES3_MAX_KEY_LEN	DES3_MAXBYTES

#ifndef DES_MIN_KEY_LEN
#define	DES_MIN_KEY_LEN		0
#endif

#ifndef DES_MAX_KEY_LEN
#define	DES_MAX_KEY_LEN		0
#endif

#ifndef DES3_MIN_KEY_LEN
#define	DES3_MIN_KEY_LEN	0
#endif

#ifndef DES3_MAX_KEY_LEN
#define	DES3_MAX_KEY_LEN	0
#endif


/*
 * Mechanism info structure passed to KCF during registration.
 */
static crypto_mech_info_t des_mech_info_tab[] = {
	/* DES_ECB */
	{SUN_CKM_DES_ECB, DES_ECB_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    DES_MIN_KEY_LEN, DES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* DES_CBC */
	{SUN_CKM_DES_CBC, DES_CBC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    DES_MIN_KEY_LEN, DES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* DES3_ECB */
	{SUN_CKM_DES3_ECB, DES3_ECB_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    DES3_MIN_KEY_LEN, DES3_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* DES3_CBC */
	{SUN_CKM_DES3_CBC, DES3_CBC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    DES3_MIN_KEY_LEN, DES3_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES}
};

/* operations are in-place if the output buffer is NULL */
#define	DES_ARG_INPLACE(input, output)				\
	if ((output) == NULL)					\
		(output) = (input);

static void des_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t des_control_ops = {
	des_provider_status
};

static int
des_common_init(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int des_common_init_ctx(des_ctx_t *, crypto_spi_ctx_template_t *,
    crypto_mechanism_t *, crypto_key_t *, des_strength_t, int);
static int des_encrypt_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int des_decrypt_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);

static int des_encrypt(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int des_encrypt_update(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int des_encrypt_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static int des_decrypt(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int des_decrypt_update(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int des_decrypt_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static crypto_cipher_ops_t des_cipher_ops = {
	des_common_init,
	des_encrypt,
	des_encrypt_update,
	des_encrypt_final,
	des_encrypt_atomic,
	des_common_init,
	des_decrypt,
	des_decrypt_update,
	des_decrypt_final,
	des_decrypt_atomic
};

static int des_create_ctx_template(crypto_provider_handle_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_spi_ctx_template_t *,
    size_t *, crypto_req_handle_t);
static int des_free_context(crypto_ctx_t *);

static crypto_ctx_ops_t des_ctx_ops = {
	des_create_ctx_template,
	des_free_context
};

static int des_key_check(crypto_provider_handle_t, crypto_mechanism_t *,
    crypto_key_t *);

static crypto_key_ops_t des_key_ops = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	des_key_check
};

static crypto_ops_t des_crypto_ops = {
	&des_control_ops,
	NULL,
	&des_cipher_ops,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	&des_key_ops,
	NULL,
	&des_ctx_ops,
	NULL,
	NULL,
	NULL
};

static crypto_provider_info_t des_prov_info = {
	CRYPTO_SPI_VERSION_4,
	"DES Software Provider",
	CRYPTO_SW_PROVIDER,
	{&modlinkage},
	NULL,
	&des_crypto_ops,
	sizeof (des_mech_info_tab)/sizeof (crypto_mech_info_t),
	des_mech_info_tab
};

static crypto_kcf_provider_handle_t des_prov_handle = NULL;

int
_init(void)
{
	int ret;

	if ((ret = mod_install(&modlinkage)) != 0)
		return (ret);

	/*
	 * Register with KCF. If the registration fails, kcf will log an
	 * error but do not uninstall the module, since the functionality
	 * provided by misc/des should still be available.
	 *
	 */
	(void) crypto_register_provider(&des_prov_info, &des_prov_handle);

	return (0);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Copy 8 bytes
 */
#define	COPY8(src, dst) { \
	char *a = (char *)dst; \
	char *b = (char *)src; \
	*a++ = *b++; *a++ = *b++; *a++ = *b++; *a++ = *b++; \
	*a++ = *b++; *a++ = *b++; *a++ = *b++; *a++ = *b++; \
}

/*
 * Copy multiple of 8 bytes
 */
#define	DESCOPY(src, dst, len) { \
	char *a = (char *)dst; \
	char *b = (char *)src; \
	int i; \
	for (i = (size_t)len; i > 0; i -= 8) { \
		*a++ = *b++; *a++ = *b++; *a++ = *b++; *a++ = *b++; \
		*a++ = *b++; *a++ = *b++; *a++ = *b++; *a++ = *b++; \
	} \
}

/*
 * CBC mode encryption
 */
/* ARGSUSED */
int
cbc_crypt(char *key, char *buf, size_t len, unsigned int mode, char *ivec)
{
	int err = 0;
	struct desparams dp;

	dp.des_mode = CBC;
	COPY8(ivec, dp.des_ivec);
	err = common_crypt(key, buf, len, mode, &dp);
	COPY8(dp.des_ivec, ivec);
	return (err);
}


/*
 * ECB mode encryption
 */
/* ARGSUSED */
int
ecb_crypt(char *key, char *buf, size_t len, unsigned int mode)
{
	int err = 0;
	struct desparams dp;

	dp.des_mode = ECB;
	err = common_crypt(key, buf, len, mode, &dp);
	return (err);
}



/*
 * Common code to cbc_crypt() & ecb_crypt()
 */
static int
common_crypt(char *key, char *buf, size_t len, unsigned int mode,
    struct desparams *desp)
{
	int desdev;

	if ((len % 8) != 0 || len > DES_MAXDATA)
		return (DESERR_BADPARAM);

	desp->des_dir =
	    ((mode & DES_DIRMASK) == DES_ENCRYPT) ? ENCRYPT : DECRYPT;

	desdev = mode & DES_DEVMASK;
	COPY8(key, desp->des_key);

#ifdef sun_hardware
	if (desdev == DES_HW) {
		int res;

		if (g_desfd < 0 &&
		    (g_desfd == -1 || (g_desfd = getdesfd()) < 0))
				goto software;	/* no hardware device */

		/*
		 * hardware
		 */
		desp->des_len = len;
		if (len <= DES_QUICKLEN) {
			DESCOPY(buf, desp->des_data, len);
			res = ioctl(g_desfd, DESIOCQUICK, (char *)desp);
			DESCOPY(desp->des_data, buf, len);
		} else {
			desp->des_buf = (uchar_t *)buf;
			res = ioctl(g_desfd, DESIOCBLOCK, (char *)desp);
		}
		return (res == 0 ? DESERR_NONE : DESERR_HWERROR);
	}
software:
#endif
	/*
	 * software
	 */
	if (!_des_crypt(buf, len, desp))
		return (DESERR_HWERROR);

	return (desdev == DES_SW ? DESERR_NONE : DESERR_NOHWDEVICE);
}

/*
 * Initialize key schedules for DES and DES3
 */
static int
init_keysched(crypto_key_t *key, void *newbie, des_strength_t strength)
{
	uint8_t corrected_key[DES3_KEYSIZE];

	/*
	 * Only keys by value are supported by this module.
	 */
	switch (key->ck_format) {
	case CRYPTO_KEY_RAW:
		if (strength == DES && key->ck_length != DES_MAXBITS)
			return (CRYPTO_KEY_SIZE_RANGE);
		if (strength == DES3 && key->ck_length != DES3_MAXBITS)
			return (CRYPTO_KEY_SIZE_RANGE);
		break;
	default:
		return (CRYPTO_KEY_TYPE_INCONSISTENT);
	}

	/*
	 * Fix parity bits.
	 * Initialize key schedule even if key is weak.
	 */
	if (key->ck_data == NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	des_parity_fix(key->ck_data, strength, corrected_key);
	des_init_keysched(corrected_key, strength, newbie);
	return (CRYPTO_SUCCESS);
}

/*
 * KCF software provider control entry points.
 */
/* ARGSUSED */
static void
des_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

/*
 * KCF software provider encrypt entry points.
 */
static int
des_common_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t template,
    crypto_req_handle_t req)
{

	des_strength_t strength;
	des_ctx_t *des_ctx = NULL;
	int rv;
	int kmflag;

	/*
	 * Only keys by value are supported by this module.
	 */
	if (key->ck_format != CRYPTO_KEY_RAW) {
		return (CRYPTO_KEY_TYPE_INCONSISTENT);
	}

	kmflag = crypto_kmflag(req);
	/* Check mechanism type and parameter length */
	switch (mechanism->cm_type) {
	case DES_ECB_MECH_INFO_TYPE:
		des_ctx = ecb_alloc_ctx(kmflag);
		/* FALLTHRU */
	case DES_CBC_MECH_INFO_TYPE:
		if (mechanism->cm_param != NULL &&
		    mechanism->cm_param_len != DES_BLOCK_LEN)
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		if (key->ck_length != DES_MAXBITS)
			return (CRYPTO_KEY_SIZE_RANGE);
		strength = DES;
		if (des_ctx == NULL)
			des_ctx = cbc_alloc_ctx(kmflag);
		break;
	case DES3_ECB_MECH_INFO_TYPE:
		des_ctx = ecb_alloc_ctx(kmflag);
		/* FALLTHRU */
	case DES3_CBC_MECH_INFO_TYPE:
		if (mechanism->cm_param != NULL &&
		    mechanism->cm_param_len != DES_BLOCK_LEN)
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		if (key->ck_length != DES3_MAXBITS)
			return (CRYPTO_KEY_SIZE_RANGE);
		strength = DES3;
		if (des_ctx == NULL)
			des_ctx = cbc_alloc_ctx(kmflag);
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	if ((rv = des_common_init_ctx(des_ctx, template, mechanism, key,
	    strength, kmflag)) != CRYPTO_SUCCESS) {
		crypto_free_mode_ctx(des_ctx);
		return (rv);
	}

	ctx->cc_provider_private = des_ctx;

	return (CRYPTO_SUCCESS);
}

static void
des_copy_block64(uint8_t *in, uint64_t *out)
{
	if (IS_P2ALIGNED(in, sizeof (uint64_t))) {
		/* LINTED: pointer alignment */
		out[0] = *(uint64_t *)&in[0];
	} else {
		uint64_t tmp64;

#ifdef _BIG_ENDIAN
		tmp64 = (((uint64_t)in[0] << 56) |
		    ((uint64_t)in[1] << 48) |
		    ((uint64_t)in[2] << 40) |
		    ((uint64_t)in[3] << 32) |
		    ((uint64_t)in[4] << 24) |
		    ((uint64_t)in[5] << 16) |
		    ((uint64_t)in[6] << 8) |
		    (uint64_t)in[7]);
#else
		tmp64 = (((uint64_t)in[7] << 56) |
		    ((uint64_t)in[6] << 48) |
		    ((uint64_t)in[5] << 40) |
		    ((uint64_t)in[4] << 32) |
		    ((uint64_t)in[3] << 24) |
		    ((uint64_t)in[2] << 16) |
		    ((uint64_t)in[1] << 8) |
		    (uint64_t)in[0]);
#endif /* _BIG_ENDIAN */

		out[0] = tmp64;
	}
}

/* ARGSUSED */
static int
des_encrypt(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_req_handle_t req)
{
	int ret;

	des_ctx_t *des_ctx;

	/*
	 * Plaintext must be a multiple of the block size.
	 * This test only works for non-padded mechanisms
	 * when blocksize is 2^N.
	 */
	if ((plaintext->cd_length & (DES_BLOCK_LEN - 1)) != 0)
		return (CRYPTO_DATA_LEN_RANGE);

	ASSERT(ctx->cc_provider_private != NULL);
	des_ctx = ctx->cc_provider_private;

	DES_ARG_INPLACE(plaintext, ciphertext);

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following case.
	 */
	if (ciphertext->cd_length < plaintext->cd_length) {
		ciphertext->cd_length = plaintext->cd_length;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/*
	 * Do an update on the specified input data.
	 */
	ret = des_encrypt_update(ctx, plaintext, ciphertext, req);
	ASSERT(des_ctx->dc_remainder_len == 0);
	(void) des_free_context(ctx);

	/* LINTED */
	return (ret);
}

/* ARGSUSED */
static int
des_decrypt(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_req_handle_t req)
{
	int ret;

	des_ctx_t *des_ctx;

	/*
	 * Ciphertext must be a multiple of the block size.
	 * This test only works for non-padded mechanisms
	 * when blocksize is 2^N.
	 */
	if ((ciphertext->cd_length & (DES_BLOCK_LEN - 1)) != 0)
		return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);

	ASSERT(ctx->cc_provider_private != NULL);
	des_ctx = ctx->cc_provider_private;

	DES_ARG_INPLACE(ciphertext, plaintext);

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following case.
	 */
	if (plaintext->cd_length < ciphertext->cd_length) {
		plaintext->cd_length = ciphertext->cd_length;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/*
	 * Do an update on the specified input data.
	 */
	ret = des_decrypt_update(ctx, ciphertext, plaintext, req);
	ASSERT(des_ctx->dc_remainder_len == 0);
	(void) des_free_context(ctx);

	/* LINTED */
	return (ret);
}

/* ARGSUSED */
static int
des_encrypt_update(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_req_handle_t req)
{
	off_t saved_offset;
	size_t saved_length, out_len;
	int ret = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);

	DES_ARG_INPLACE(plaintext, ciphertext);

	/* compute number of bytes that will hold the ciphertext */
	out_len = ((des_ctx_t *)ctx->cc_provider_private)->dc_remainder_len;
	out_len += plaintext->cd_length;
	out_len &= ~(DES_BLOCK_LEN - 1);

	/* return length needed to store the output */
	if (ciphertext->cd_length < out_len) {
		ciphertext->cd_length = out_len;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	saved_offset = ciphertext->cd_offset;
	saved_length = ciphertext->cd_length;

	/*
	 * Do the DES update on the specified input data.
	 */
	switch (plaintext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(ctx->cc_provider_private,
		    plaintext, ciphertext, des_encrypt_contiguous_blocks,
		    des_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(ctx->cc_provider_private,
		    plaintext, ciphertext, des_encrypt_contiguous_blocks,
		    des_copy_block64);
		break;
	case CRYPTO_DATA_MBLK:
		ret = crypto_update_mp(ctx->cc_provider_private,
		    plaintext, ciphertext, des_encrypt_contiguous_blocks,
		    des_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		if (plaintext != ciphertext)
			ciphertext->cd_length =
			    ciphertext->cd_offset - saved_offset;
	} else {
		ciphertext->cd_length = saved_length;
	}
	ciphertext->cd_offset = saved_offset;

	return (ret);
}

/* ARGSUSED */
static int
des_decrypt_update(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_req_handle_t req)
{
	off_t saved_offset;
	size_t saved_length, out_len;
	int ret = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);

	DES_ARG_INPLACE(ciphertext, plaintext);

	/* compute number of bytes that will hold the plaintext */
	out_len = ((des_ctx_t *)ctx->cc_provider_private)->dc_remainder_len;
	out_len += ciphertext->cd_length;
	out_len &= ~(DES_BLOCK_LEN - 1);

	/* return length needed to store the output */
	if (plaintext->cd_length < out_len) {
		plaintext->cd_length = out_len;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	saved_offset = plaintext->cd_offset;
	saved_length = plaintext->cd_length;

	/*
	 * Do the DES update on the specified input data.
	 */
	switch (ciphertext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(ctx->cc_provider_private,
		    ciphertext, plaintext, des_decrypt_contiguous_blocks,
		    des_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(ctx->cc_provider_private,
		    ciphertext, plaintext, des_decrypt_contiguous_blocks,
		    des_copy_block64);
		break;
	case CRYPTO_DATA_MBLK:
		ret = crypto_update_mp(ctx->cc_provider_private,
		    ciphertext, plaintext, des_decrypt_contiguous_blocks,
		    des_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		if (ciphertext != plaintext)
			plaintext->cd_length =
			    plaintext->cd_offset - saved_offset;
	} else {
		plaintext->cd_length = saved_length;
	}
	plaintext->cd_offset = saved_offset;

	return (ret);
}

/* ARGSUSED */
static int
des_encrypt_final(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_req_handle_t req)
{
	des_ctx_t *des_ctx;

	ASSERT(ctx->cc_provider_private != NULL);
	des_ctx = ctx->cc_provider_private;

	/*
	 * There must be no unprocessed plaintext.
	 * This happens if the length of the last data is
	 * not a multiple of the DES block length.
	 */
	if (des_ctx->dc_remainder_len > 0)
		return (CRYPTO_DATA_LEN_RANGE);

	(void) des_free_context(ctx);
	ciphertext->cd_length = 0;

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
des_decrypt_final(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_req_handle_t req)
{
	des_ctx_t *des_ctx;

	ASSERT(ctx->cc_provider_private != NULL);
	des_ctx = ctx->cc_provider_private;

	/*
	 * There must be no unprocessed ciphertext.
	 * This happens if the length of the last ciphertext is
	 * not a multiple of the DES block length.
	 */
	if (des_ctx->dc_remainder_len > 0)
		return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);

	(void) des_free_context(ctx);
	plaintext->cd_length = 0;

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
des_encrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *plaintext, crypto_data_t *ciphertext,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req)
{
	int ret;

	des_ctx_t des_ctx;		/* on the stack */
	des_strength_t strength;
	off_t saved_offset;
	size_t saved_length;

	DES_ARG_INPLACE(plaintext, ciphertext);

	/*
	 * Plaintext must be a multiple of the block size.
	 * This test only works for non-padded mechanisms
	 * when blocksize is 2^N.
	 */
	if ((plaintext->cd_length & (DES_BLOCK_LEN - 1)) != 0)
		return (CRYPTO_DATA_LEN_RANGE);

	/* return length needed to store the output */
	if (ciphertext->cd_length < plaintext->cd_length) {
		ciphertext->cd_length = plaintext->cd_length;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/* Check mechanism type and parameter length */
	switch (mechanism->cm_type) {
	case DES_ECB_MECH_INFO_TYPE:
	case DES_CBC_MECH_INFO_TYPE:
		if (mechanism->cm_param_len > 0 &&
		    mechanism->cm_param_len != DES_BLOCK_LEN)
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		if (key->ck_length != DES_MINBITS)
			return (CRYPTO_KEY_SIZE_RANGE);
		strength = DES;
		break;
	case DES3_ECB_MECH_INFO_TYPE:
	case DES3_CBC_MECH_INFO_TYPE:
		if (mechanism->cm_param_len > 0 &&
		    mechanism->cm_param_len != DES_BLOCK_LEN)
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		if (key->ck_length != DES3_MAXBITS)
			return (CRYPTO_KEY_SIZE_RANGE);
		strength = DES3;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	bzero(&des_ctx, sizeof (des_ctx_t));

	if ((ret = des_common_init_ctx(&des_ctx, template, mechanism, key,
	    strength, crypto_kmflag(req))) != CRYPTO_SUCCESS) {
		return (ret);
	}

	saved_offset = ciphertext->cd_offset;
	saved_length = ciphertext->cd_length;

	/*
	 * Do the update on the specified input data.
	 */
	switch (plaintext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(&des_ctx, plaintext, ciphertext,
		    des_encrypt_contiguous_blocks, des_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(&des_ctx, plaintext, ciphertext,
		    des_encrypt_contiguous_blocks, des_copy_block64);
		break;
	case CRYPTO_DATA_MBLK:
		ret = crypto_update_mp(&des_ctx, plaintext, ciphertext,
		    des_encrypt_contiguous_blocks, des_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (des_ctx.dc_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
		bzero(des_ctx.dc_keysched, des_ctx.dc_keysched_len);
		kmem_free(des_ctx.dc_keysched, des_ctx.dc_keysched_len);
	}

	if (ret == CRYPTO_SUCCESS) {
		ASSERT(des_ctx.dc_remainder_len == 0);
		if (plaintext != ciphertext)
			ciphertext->cd_length =
			    ciphertext->cd_offset - saved_offset;
	} else {
		ciphertext->cd_length = saved_length;
	}
	ciphertext->cd_offset = saved_offset;

	/* LINTED */
	return (ret);
}

/* ARGSUSED */
static int
des_decrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *ciphertext, crypto_data_t *plaintext,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req)
{
	int ret;

	des_ctx_t des_ctx;	/* on the stack */
	des_strength_t strength;
	off_t saved_offset;
	size_t saved_length;

	DES_ARG_INPLACE(ciphertext, plaintext);

	/*
	 * Ciphertext must be a multiple of the block size.
	 * This test only works for non-padded mechanisms
	 * when blocksize is 2^N.
	 */
	if ((ciphertext->cd_length & (DES_BLOCK_LEN - 1)) != 0)
		return (CRYPTO_DATA_LEN_RANGE);

	/* return length needed to store the output */
	if (plaintext->cd_length < ciphertext->cd_length) {
		plaintext->cd_length = ciphertext->cd_length;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/* Check mechanism type and parameter length */
	switch (mechanism->cm_type) {
	case DES_ECB_MECH_INFO_TYPE:
	case DES_CBC_MECH_INFO_TYPE:
		if (mechanism->cm_param_len > 0 &&
		    mechanism->cm_param_len != DES_BLOCK_LEN)
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		if (key->ck_length != DES_MINBITS)
			return (CRYPTO_KEY_SIZE_RANGE);
		strength = DES;
		break;
	case DES3_ECB_MECH_INFO_TYPE:
	case DES3_CBC_MECH_INFO_TYPE:
		if (mechanism->cm_param_len > 0 &&
		    mechanism->cm_param_len != DES_BLOCK_LEN)
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		if (key->ck_length != DES3_MAXBITS)
			return (CRYPTO_KEY_SIZE_RANGE);
		strength = DES3;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	bzero(&des_ctx, sizeof (des_ctx_t));

	if ((ret = des_common_init_ctx(&des_ctx, template, mechanism, key,
	    strength, crypto_kmflag(req))) != CRYPTO_SUCCESS) {
		return (ret);
	}

	saved_offset = plaintext->cd_offset;
	saved_length = plaintext->cd_length;

	/*
	 * Do the update on the specified input data.
	 */
	switch (ciphertext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(&des_ctx, ciphertext, plaintext,
		    des_decrypt_contiguous_blocks, des_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(&des_ctx, ciphertext, plaintext,
		    des_decrypt_contiguous_blocks, des_copy_block64);
		break;
	case CRYPTO_DATA_MBLK:
		ret = crypto_update_mp(&des_ctx, ciphertext, plaintext,
		    des_decrypt_contiguous_blocks, des_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (des_ctx.dc_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
		bzero(des_ctx.dc_keysched, des_ctx.dc_keysched_len);
		kmem_free(des_ctx.dc_keysched, des_ctx.dc_keysched_len);
	}

	if (ret == CRYPTO_SUCCESS) {
		ASSERT(des_ctx.dc_remainder_len == 0);
		if (ciphertext != plaintext)
			plaintext->cd_length =
			    plaintext->cd_offset - saved_offset;
	} else {
		plaintext->cd_length = saved_length;
	}
	plaintext->cd_offset = saved_offset;

	/* LINTED */
	return (ret);
}

/*
 * KCF software provider context template entry points.
 */
/* ARGSUSED */
static int
des_create_ctx_template(crypto_provider_handle_t provider,
    crypto_mechanism_t *mechanism, crypto_key_t *key,
    crypto_spi_ctx_template_t *tmpl, size_t *tmpl_size, crypto_req_handle_t req)
{

	des_strength_t strength;
	void *keysched;
	size_t size;
	int rv;

	switch (mechanism->cm_type) {
	case DES_ECB_MECH_INFO_TYPE:
		strength = DES;
		break;
	case DES_CBC_MECH_INFO_TYPE:
		strength = DES;
		break;
	case DES3_ECB_MECH_INFO_TYPE:
		strength = DES3;
		break;
	case DES3_CBC_MECH_INFO_TYPE:
		strength = DES3;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	if ((keysched = des_alloc_keysched(&size, strength,
	    crypto_kmflag(req))) == NULL) {
		return (CRYPTO_HOST_MEMORY);
	}

	/*
	 * Initialize key schedule.  Key length information is stored
	 * in the key.
	 */
	if ((rv = init_keysched(key, keysched, strength)) != CRYPTO_SUCCESS) {
		bzero(keysched, size);
		kmem_free(keysched, size);
		return (rv);
	}

	*tmpl = keysched;
	*tmpl_size = size;

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
des_free_context(crypto_ctx_t *ctx)
{
	des_ctx_t *des_ctx = ctx->cc_provider_private;

	if (des_ctx != NULL) {
		if (des_ctx->dc_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
			ASSERT(des_ctx->dc_keysched_len != 0);
			bzero(des_ctx->dc_keysched, des_ctx->dc_keysched_len);
			kmem_free(des_ctx->dc_keysched,
			    des_ctx->dc_keysched_len);
		}
		crypto_free_mode_ctx(des_ctx);
		ctx->cc_provider_private = NULL;
	}

	return (CRYPTO_SUCCESS);
}

/*
 * Pass it to des_keycheck() which will
 * fix it (parity bits), and check if the fixed key is weak.
 */
/* ARGSUSED */
static int
des_key_check(crypto_provider_handle_t pd, crypto_mechanism_t *mech,
    crypto_key_t *key)
{
	int expectedkeylen;
	des_strength_t strength;
	uint8_t keydata[DES3_MAX_KEY_LEN];

	if ((mech == NULL) || (key == NULL))
		return (CRYPTO_ARGUMENTS_BAD);

	switch (mech->cm_type) {
	case DES_ECB_MECH_INFO_TYPE:
	case DES_CBC_MECH_INFO_TYPE:
		expectedkeylen = DES_MINBITS;
		strength = DES;
		break;
	case DES3_ECB_MECH_INFO_TYPE:
	case DES3_CBC_MECH_INFO_TYPE:
		expectedkeylen = DES3_MAXBITS;
		strength = DES3;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (key->ck_format != CRYPTO_KEY_RAW)
		return (CRYPTO_KEY_TYPE_INCONSISTENT);

	if (key->ck_length != expectedkeylen)
		return (CRYPTO_KEY_SIZE_RANGE);

	bcopy(key->ck_data, keydata, CRYPTO_BITS2BYTES(expectedkeylen));

	if (des_keycheck(keydata, strength, key->ck_data) == B_FALSE)
		return (CRYPTO_WEAK_KEY);

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
des_common_init_ctx(des_ctx_t *des_ctx, crypto_spi_ctx_template_t *template,
    crypto_mechanism_t *mechanism, crypto_key_t *key, des_strength_t strength,
    int kmflag)
{
	int rv = CRYPTO_SUCCESS;

	void *keysched;
	size_t size;

	if (template == NULL) {
		if ((keysched = des_alloc_keysched(&size, strength,
		    kmflag)) == NULL)
			return (CRYPTO_HOST_MEMORY);
		/*
		 * Initialize key schedule.
		 * Key length is stored in the key.
		 */
		if ((rv = init_keysched(key, keysched,
		    strength)) != CRYPTO_SUCCESS)
			kmem_free(keysched, size);

		des_ctx->dc_flags |= PROVIDER_OWNS_KEY_SCHEDULE;
		des_ctx->dc_keysched_len = size;
	} else {
		keysched = template;
	}
	des_ctx->dc_keysched = keysched;

	if (strength == DES3) {
		des_ctx->dc_flags |= DES3_STRENGTH;
	}

	switch (mechanism->cm_type) {
	case DES_CBC_MECH_INFO_TYPE:
	case DES3_CBC_MECH_INFO_TYPE:
		rv = cbc_init_ctx((cbc_ctx_t *)des_ctx, mechanism->cm_param,
		    mechanism->cm_param_len, DES_BLOCK_LEN, des_copy_block64);
		break;
	case DES_ECB_MECH_INFO_TYPE:
	case DES3_ECB_MECH_INFO_TYPE:
		des_ctx->dc_flags |= ECB_MODE;
	}

	if (rv != CRYPTO_SUCCESS) {
		if (des_ctx->dc_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
			bzero(keysched, size);
			kmem_free(keysched, size);
		}
	}

	return (rv);
}
