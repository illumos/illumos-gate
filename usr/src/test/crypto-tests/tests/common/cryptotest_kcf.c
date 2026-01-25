/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2023 RackTop Systems, Inc.
 */

#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/debug.h>

#include "cryptotest.h"

boolean_t cryptotest_pkcs = B_FALSE;	/* true if PKCS */

struct crypto_op {
	char *in;
	char *out;
	char *key;
	char *param;

	size_t inlen;
	size_t outlen;
	size_t keylen;
	size_t paramlen;
	const size_t *updatelens;

	char *mechname;

	/* internal */
	crypto_mech_type_t mech;
	crypto_session_id_t hsession;
	crypto_func_group_t fg;
};

static int fd = -1;
static const char CRYPTO_DEVICE[] = "/dev/crypto";

int
kcf_do_ioctl(int opcode, uint_t *arg, char *opstr)
{
	int ret;

	while ((ret = ioctl(fd, opcode, arg)) < 0) {
		if (errno != EINTR)
			break;
	}

	if (ret < 0 || *arg != CRYPTO_SUCCESS) {
		char errbuf[BUFSZ] = {0};
		(void) fprintf(stderr,
		    "%s: Error: %s errno: %s (%d) rc: %d\n",
		    (opstr == NULL) ? "ioctl" : opstr,
		    cryptotest_errstr(*arg, errbuf, sizeof (errbuf)),
		    strerror(errno), errno, ret);
	}

	/*
	 * The callers all expect CRYPTO_xx errors.  We've displayed the
	 * errno value (see above), so just return a generic CRYPTO_xxx
	 * error to signal failure.
	 */
	if (ret < 0)
		return (CRYPTO_GENERAL_ERROR);

	return (*arg);
}

crypto_op_t *
cryptotest_init(cryptotest_t *arg, crypto_func_group_t fg)
{
	crypto_op_t *op = malloc(sizeof (*op));

	if (op == NULL) {
		(void) fprintf(stderr, "malloc failed: %s\n", strerror(errno));
		return (NULL);
	}

	while ((fd = open(CRYPTO_DEVICE, O_RDWR)) < 0) {
		if (errno != EINTR) {
			(void) fprintf(stderr, "open of %s failed: %s",
			    CRYPTO_DEVICE, strerror(errno));
			free(op);
			return (NULL);
		}
	}

	op->in = (char *)arg->in;
	op->out = (char *)arg->out;
	op->key = (char *)arg->key;
	op->param = (char *)arg->param;

	op->inlen = arg->inlen;
	op->outlen = arg->outlen;
	op->keylen = arg->keylen * 8; /* kcf uses keylen in bits */
	op->paramlen = arg->plen;
	op->updatelens = arg->updatelens;

	op->mechname = arg->mechname;

	op->hsession = CRYPTO_INVALID_SESSION;
	op->fg = fg;

	if (op->out == NULL)
		op->outlen = op->inlen;
	return (op);
}

int
cryptotest_close_session(crypto_session_id_t session)
{
	crypto_close_session_t cs;

	cs.cs_session = session;
	return (kcf_do_ioctl(CRYPTO_CLOSE_SESSION, (uint_t *)&cs, "session"));
}

void
cryptotest_close(crypto_op_t *op)
{
	if (op->hsession != CRYPTO_INVALID_SESSION)
		(void) cryptotest_close_session(op->hsession);
	free(op);
	if (fd >= 0)
		VERIFY0(close(fd));
	fd = -1;
}

int
get_mech_info(crypto_op_t *op)
{
	crypto_get_mechanism_number_t get_number;

	bzero(&get_number, sizeof (get_number));

	get_number.pn_mechanism_string = op->mechname;
	get_number.pn_mechanism_len = strlen(op->mechname) + 1;

	if (kcf_do_ioctl(CRYPTO_GET_MECHANISM_NUMBER,
	    (uint_t *)&get_number, "get_mech_info") != CRYPTO_SUCCESS) {
		(void) fprintf(stderr, "failed to resolve mechanism name %s\n",
		    op->mechname);
		return (CTEST_NAME_RESOLVE_FAILED);
	}
	op->mech = get_number.pn_internal_number;
	return (CRYPTO_SUCCESS);
}

int
get_hsession_by_mech(crypto_op_t *op)
{
	crypto_by_mech_t mech;
	int rv;

	mech.mech_keylen = op->keylen;
	mech.mech_type = op->mech;
	mech.mech_fg = op->fg;

	rv = kcf_do_ioctl(CRYPTO_GET_PROVIDER_BY_MECH, (uint_t *)&mech,
	    "get_hsession_by_mech");

	if (rv != 0 || mech.rv != CRYPTO_SUCCESS) {
		(void) fprintf(stderr,
		    "could not find provider for mechanism %llu\n",
		    mech.mech_type);
		return (CTEST_MECH_NO_PROVIDER);
	}

	op->hsession = mech.session_id;

	return (CRYPTO_SUCCESS);
}

/*
 * CRYPTO_MAC_* functions
 */
int
mac_init(crypto_op_t *op)
{
	crypto_mac_init_t init;

	bzero((void *)&init, sizeof (init));

	init.mi_session = op->hsession;

	init.mi_key.ck_data = op->key;
	init.mi_key.ck_format = CRYPTO_KEY_RAW; /* must be this */
	init.mi_key.ck_length = op->keylen;

	init.mi_mech.cm_type = op->mech;
	init.mi_mech.cm_param = op->param;
	init.mi_mech.cm_param_len = op->paramlen;

	return (kcf_do_ioctl(CRYPTO_MAC_INIT, (uint_t *)&init, "init"));
}

int
mac_single(crypto_op_t *op)
{
	crypto_mac_t mac;

	bzero(&mac, sizeof (mac));
	mac.cm_session = op->hsession;
	mac.cm_datalen = op->inlen;
	mac.cm_databuf = op->in;
	mac.cm_maclen = op->outlen;
	mac.cm_macbuf = op->out;

	return (kcf_do_ioctl(CRYPTO_MAC, (uint_t *)&mac, "single"));
}

int
mac_update(crypto_op_t *op, size_t offset, size_t len, size_t *dummy __unused)
{
	crypto_mac_update_t update;

	bzero((void *)&update, sizeof (update));

	update.mu_session = op->hsession;
	update.mu_databuf = op->in + offset;
	update.mu_datalen = len;

	return (kcf_do_ioctl(CRYPTO_MAC_UPDATE, (uint_t *)&update, "update"));
}

int
mac_final(crypto_op_t *op, size_t dummy __unused)
{
	crypto_mac_final_t final;

	bzero((void *)&final, sizeof (final));

	final.mf_session = op->hsession;
	final.mf_maclen = op->outlen;
	final.mf_macbuf = op->out;

	return (kcf_do_ioctl(CRYPTO_MAC_FINAL, (uint_t *)&final, "final"));
}


/*
 * CRYPTO_ENCRYPT_* functions
 */

int
encrypt_init(crypto_op_t *op)
{
	crypto_encrypt_init_t init;

	bzero((void *)&init, sizeof (init));

	init.ei_session = op->hsession;

	init.ei_key.ck_data = op->key;
	init.ei_key.ck_format = CRYPTO_KEY_RAW; /* must be this */
	init.ei_key.ck_length = op->keylen;

	init.ei_mech.cm_type = op->mech;
	init.ei_mech.cm_param = op->param;
	init.ei_mech.cm_param_len = op->paramlen;

	return (kcf_do_ioctl(CRYPTO_ENCRYPT_INIT, (uint_t *)&init, "init"));
}

int
encrypt_single(crypto_op_t *op)
{
	crypto_encrypt_t encrypt;

	bzero(&encrypt, sizeof (encrypt));
	encrypt.ce_session = op->hsession;
	encrypt.ce_datalen = op->inlen;
	encrypt.ce_databuf = op->in;
	encrypt.ce_encrlen = op->outlen;
	encrypt.ce_encrbuf = op->out;

	return (kcf_do_ioctl(CRYPTO_ENCRYPT, (uint_t *)&encrypt, "single"));
}

int
encrypt_update(crypto_op_t *op, size_t offset, size_t plainlen, size_t *encrlen)
{
	crypto_encrypt_update_t update;
	int ret;
	bzero((void *)&update, sizeof (update));

	update.eu_session = op->hsession;
	update.eu_databuf = op->in + offset;
	update.eu_datalen = plainlen;
	update.eu_encrlen = op->outlen - *encrlen;
	update.eu_encrbuf = op->out + *encrlen;

	ret = kcf_do_ioctl(CRYPTO_ENCRYPT_UPDATE, (uint_t *)&update, "update");
	*encrlen += update.eu_encrlen;
	return (ret);
}

int
encrypt_final(crypto_op_t *op, size_t encrlen)
{
	crypto_encrypt_final_t final;

	bzero((void *)&final, sizeof (final));

	final.ef_session = op->hsession;
	final.ef_encrlen = op->outlen - encrlen;
	final.ef_encrbuf = op->out + encrlen;

	return (kcf_do_ioctl(CRYPTO_ENCRYPT_FINAL, (uint_t *)&final, "final"));
}

/*
 * CRYPTO_DECRYPT_* functions
 */

int
decrypt_init(crypto_op_t *op)
{
	crypto_decrypt_init_t init;

	bzero((void *)&init, sizeof (init));

	init.di_session = op->hsession;

	init.di_key.ck_data = op->key;
	init.di_key.ck_format = CRYPTO_KEY_RAW; /* must be this */
	init.di_key.ck_length = op->keylen;

	init.di_mech.cm_type = op->mech;
	init.di_mech.cm_param = op->param;
	init.di_mech.cm_param_len = op->paramlen;

	return (kcf_do_ioctl(CRYPTO_DECRYPT_INIT, (uint_t *)&init, "init"));
}

int
decrypt_single(crypto_op_t *op)
{
	crypto_decrypt_t decrypt;

	bzero(&decrypt, sizeof (decrypt));
	decrypt.cd_session = op->hsession;
	decrypt.cd_datalen = op->outlen;
	decrypt.cd_databuf = op->out;
	decrypt.cd_encrlen = op->inlen;
	decrypt.cd_encrbuf = op->in;

	return (kcf_do_ioctl(CRYPTO_DECRYPT, (uint_t *)&decrypt, "single"));
}

int
decrypt_update(crypto_op_t *op, size_t offset, size_t len, size_t *encrlen)
{
	crypto_decrypt_update_t update;
	int ret;

	bzero((void *)&update, sizeof (update));

	update.du_session = op->hsession;
	update.du_databuf = op->out + *encrlen;
	update.du_datalen = op->outlen - *encrlen;
	update.du_encrlen = len;
	update.du_encrbuf = op->in + offset;

	ret = kcf_do_ioctl(CRYPTO_DECRYPT_UPDATE, (uint_t *)&update, "update");
	*encrlen += update.du_datalen;
	return (ret);
}

int
decrypt_final(crypto_op_t *op, size_t encrlen)
{
	crypto_decrypt_final_t final;

	bzero((void *)&final, sizeof (final));

	final.df_session = op->hsession;
	final.df_datalen = op->outlen - encrlen;
	final.df_databuf = op->out + encrlen;

	return (kcf_do_ioctl(CRYPTO_DECRYPT_FINAL, (uint_t *)&final, "final"));
}

int
digest_init(crypto_op_t *op)
{
	crypto_digest_init_t init;

	bzero(&init, sizeof (init));

	init.di_session = op->hsession;

	init.di_mech.cm_type = op->mech;
	init.di_mech.cm_param = op->param;
	init.di_mech.cm_param_len = op->paramlen;

	return (kcf_do_ioctl(CRYPTO_DIGEST_INIT, (uint_t *)&init, "init"));
}

int
digest_single(crypto_op_t *op)
{
	crypto_digest_t digest;

	bzero(&digest, sizeof (digest));

	digest.cd_session = op->hsession;

	digest.cd_datalen = op->inlen;
	digest.cd_databuf = op->in;
	digest.cd_digestlen = op->outlen;
	digest.cd_digestbuf = op->out;

	return (kcf_do_ioctl(CRYPTO_DIGEST, (uint_t *)&digest, "digest"));
}

int
digest_update(crypto_op_t *op, size_t offset, size_t len,
    size_t *dummy __unused)
{
	crypto_digest_update_t update;

	bzero(&update, sizeof (update));

	update.du_session = op->hsession;

	update.du_datalen = len;
	update.du_databuf = op->in + offset;

	return (kcf_do_ioctl(CRYPTO_DIGEST_UPDATE, (uint_t *)&update,
	    "update"));
}

int
digest_final(crypto_op_t *op, size_t dummy __unused)
{
	crypto_digest_final_t final;

	bzero(&final, sizeof (final));

	final.df_session = op->hsession;

	final.df_digestlen = op->outlen;
	final.df_digestbuf = op->out;

	return (kcf_do_ioctl(CRYPTO_DIGEST_FINAL, (uint_t *)&final, "final"));
}

void
ccm_init_params(void *buf, ulong_t ulDataLen, uchar_t *pNonce,
    ulong_t ulNonceLen, uchar_t *pAAD, ulong_t ulAADLen, ulong_t ulMACLen)
{
	CK_AES_CCM_PARAMS *pp = buf;

	pp->ulDataSize = ulDataLen;
	pp->nonce = pNonce;
	pp->ulNonceSize = ulNonceLen;
	pp->authData = pAAD;
	pp->ulAuthDataSize = ulAADLen;
	pp->ulMACSize = ulMACLen;
}

size_t
ccm_param_len(void)
{
	return (sizeof (CK_AES_CCM_PARAMS));
}

/*
 * KCF always takes CK_AES_GMAC_PARAMS, but the caller may pass
 * either just the IV or IV plus AAD.
 *
 * Some tests pass ulAADLen = 0 and non-NULL pAAD, so allow that,
 * but require ulAADLen=0 if pAAD=NULL.
 */
void
gmac_init_params(void *buf, uchar_t *pIv, uchar_t *pAAD, ulong_t ulAADLen)
{
	CK_AES_GMAC_PARAMS *pp = buf;

	if (pAAD == NULL) {
		VERIFY0(ulAADLen);
	}

	pp->pIv = pIv;
	pp->pAAD = pAAD;	/* may be NULL */
	pp->ulAADLen = ulAADLen;
}

size_t
gmac_param_len(void)
{
	return (sizeof (CK_AES_GMAC_PARAMS));
}

const char *
cryptotest_errstr(int e, char *buf, size_t buflen)
{
	const char *valstr = NULL;

	switch (e) {
	case CRYPTO_SUCCESS:
		valstr = "CRYPTO_SUCCESS";
		break;
	case CRYPTO_CANCEL:
		valstr = "CRYPTO_CANCEL";
		break;
	case CRYPTO_HOST_MEMORY:
		valstr = "CRYPTO_HOST_MEMORY";
		break;
	case CRYPTO_GENERAL_ERROR:
		valstr = "CRYPTO_GENERAL_ERROR";
		break;
	case CRYPTO_FAILED:
		valstr = "CRYPTO_FAILED";
		break;
	case CRYPTO_ARGUMENTS_BAD:
		valstr = "CRYPTO_ARGUMENTS_BAD";
		break;
	case CRYPTO_ATTRIBUTE_READ_ONLY:
		valstr = "CRYPTO_ATTRIBUTE_READ_ONLY";
		break;
	case CRYPTO_ATTRIBUTE_SENSITIVE:
		valstr = "CRYPTO_ATTRIBUTE_SENSITIVE";
		break;
	case CRYPTO_ATTRIBUTE_TYPE_INVALID:
		valstr = "CRYPTO_ATTRIBUTE_TYPE_INVALID";
		break;
	case CRYPTO_ATTRIBUTE_VALUE_INVALID:
		valstr = "CRYPTO_ATTRIBUTE_VALUE_INVALID";
		break;
	case CRYPTO_CANCELED:
		valstr = "CRYPTO_CANCELED";
		break;
	case CRYPTO_DATA_INVALID:
		valstr = "CRYPTO_DATA_INVALID";
		break;
	case CRYPTO_DATA_LEN_RANGE:
		valstr = "CRYPTO_DATA_LEN_RANGE";
		break;
	case CRYPTO_DEVICE_ERROR:
		valstr = "CRYPTO_DEVICE_ERROR";
		break;
	case CRYPTO_DEVICE_MEMORY:
		valstr = "CRYPTO_DEVICE_MEMORY";
		break;
	case CRYPTO_DEVICE_REMOVED:
		valstr = "CRYPTO_DEVICE_REMOVED";
		break;
	case CRYPTO_ENCRYPTED_DATA_INVALID:
		valstr = "CRYPTO_ENCRYPTED_DATA_INVALID";
		break;
	case CRYPTO_ENCRYPTED_DATA_LEN_RANGE:
		valstr = "CRYPTO_ENCRYPTED_DATA_LEN_RANGE";
		break;
	case CRYPTO_KEY_HANDLE_INVALID:
		valstr = "CRYPTO_KEY_HANDLE_INVALID";
		break;
	case CRYPTO_KEY_SIZE_RANGE:
		valstr = "CRYPTO_KEY_SIZE_RANGE";
		break;
	case CRYPTO_KEY_TYPE_INCONSISTENT:
		valstr = "CRYPTO_KEY_TYPE_INCONSISTENT";
		break;
	case CRYPTO_KEY_NOT_NEEDED:
		valstr = "CRYPTO_KEY_NOT_NEEDED";
		break;
	case CRYPTO_KEY_CHANGED:
		valstr = "CRYPTO_KEY_CHANGED";
		break;
	case CRYPTO_KEY_NEEDED:
		valstr = "CRYPTO_KEY_NEEDED";
		break;
	case CRYPTO_KEY_INDIGESTIBLE:
		valstr = "CRYPTO_KEY_INDIGESTIBLE";
		break;
	case CRYPTO_KEY_FUNCTION_NOT_PERMITTED:
		valstr = "CRYPTO_KEY_FUNCTION_NOT_PERMITTED";
		break;
	case CRYPTO_KEY_NOT_WRAPPABLE:
		valstr = "CRYPTO_KEY_NOT_WRAPPABLE";
		break;
	case CRYPTO_KEY_UNEXTRACTABLE:
		valstr = "CRYPTO_KEY_UNEXTRACTABLE";
		break;
	case CRYPTO_MECHANISM_INVALID:
		valstr = "CRYPTO_MECHANISM_INVALID";
		break;
	case CRYPTO_MECHANISM_PARAM_INVALID:
		valstr = "CRYPTO_MECHANISM_PARAM_INVALID";
		break;
	case CRYPTO_OBJECT_HANDLE_INVALID:
		valstr = "CRYPTO_OBJECT_HANDLE_INVALID";
		break;
	case CRYPTO_OPERATION_IS_ACTIVE:
		valstr = "CRYPTO_OPERATION_IS_ACTIVE";
		break;
	case CRYPTO_OPERATION_NOT_INITIALIZED:
		valstr = "CRYPTO_OPERATION_NOT_INITIALIZED";
		break;
	case CRYPTO_PIN_INCORRECT:
		valstr = "CRYPTO_PIN_INCORRECT";
		break;
	case CRYPTO_PIN_INVALID:
		valstr = "CRYPTO_PIN_INVALID";
		break;
	case CRYPTO_PIN_LEN_RANGE:
		valstr = "CRYPTO_PIN_LEN_RANGE";
		break;
	case CRYPTO_PIN_EXPIRED:
		valstr = "CRYPTO_PIN_EXPIRED";
		break;
	case CRYPTO_PIN_LOCKED:
		valstr = "CRYPTO_PIN_LOCKED";
		break;
	case CRYPTO_SESSION_CLOSED:
		valstr = "CRYPTO_SESSION_CLOSED";
		break;
	case CRYPTO_SESSION_COUNT:
		valstr = "CRYPTO_SESSION_COUNT";
		break;
	case CRYPTO_SESSION_HANDLE_INVALID:
		valstr = "CRYPTO_SESSION_HANDLE_INVALID";
		break;
	case CRYPTO_SESSION_READ_ONLY:
		valstr = "CRYPTO_SESSION_READ_ONLY";
		break;
	case CRYPTO_SESSION_EXISTS:
		valstr = "CRYPTO_SESSION_EXISTS";
		break;
	case CRYPTO_SESSION_READ_ONLY_EXISTS:
		valstr = "CRYPTO_SESSION_READ_ONLY_EXISTS";
		break;
	case CRYPTO_SESSION_READ_WRITE_SO_EXISTS:
		valstr = "CRYPTO_SESSION_READ_WRITE_SO_EXISTS";
		break;
	case CRYPTO_SIGNATURE_INVALID:
		valstr = "CRYPTO_SIGNATURE_INVALID";
		break;
	case CRYPTO_SIGNATURE_LEN_RANGE:
		valstr = "CRYPTO_SIGNATURE_LEN_RANGE";
		break;
	case CRYPTO_TEMPLATE_INCOMPLETE:
		valstr = "CRYPTO_TEMPLATE_INCOMPLETE";
		break;
	case CRYPTO_TEMPLATE_INCONSISTENT:
		valstr = "CRYPTO_TEMPLATE_INCONSISTENT";
		break;
	case CRYPTO_UNWRAPPING_KEY_HANDLE_INVALID:
		valstr = "CRYPTO_UNWRAPPING_KEY_HANDLE_INVALID";
		break;
	case CRYPTO_UNWRAPPING_KEY_SIZE_RANGE:
		valstr = "CRYPTO_UNWRAPPING_KEY_SIZE_RANGE";
		break;
	case CRYPTO_UNWRAPPING_KEY_TYPE_INCONSISTENT:
		valstr = "CRYPTO_UNWRAPPING_KEY_TYPE_INCONSISTENT";
		break;
	case CRYPTO_USER_ALREADY_LOGGED_IN:
		valstr = "CRYPTO_USER_ALREADY_LOGGED_IN";
		break;
	case CRYPTO_USER_NOT_LOGGED_IN:
		valstr = "CRYPTO_USER_NOT_LOGGED_IN";
		break;
	case CRYPTO_USER_PIN_NOT_INITIALIZED:
		valstr = "CRYPTO_USER_PIN_NOT_INITIALIZED";
		break;
	case CRYPTO_USER_TYPE_INVALID:
		valstr = "CRYPTO_USER_TYPE_INVALID";
		break;
	case CRYPTO_USER_ANOTHER_ALREADY_LOGGED_IN:
		valstr = "CRYPTO_USER_ANOTHER_ALREADY_LOGGED_IN";
		break;
	case CRYPTO_USER_TOO_MANY_TYPES:
		valstr = "CRYPTO_USER_TOO_MANY_TYPES";
		break;
	case CRYPTO_WRAPPED_KEY_INVALID:
		valstr = "CRYPTO_WRAPPED_KEY_INVALID";
		break;
	case CRYPTO_WRAPPED_KEY_LEN_RANGE:
		valstr = "CRYPTO_WRAPPED_KEY_LEN_RANGE";
		break;
	case CRYPTO_WRAPPING_KEY_HANDLE_INVALID:
		valstr = "CRYPTO_WRAPPING_KEY_HANDLE_INVALID";
		break;
	case CRYPTO_WRAPPING_KEY_SIZE_RANGE:
		valstr = "CRYPTO_WRAPPING_KEY_SIZE_RANGE";
		break;
	case CRYPTO_WRAPPING_KEY_TYPE_INCONSISTENT:
		valstr = "CRYPTO_WRAPPING_KEY_TYPE_INCONSISTENT";
		break;
	case CRYPTO_RANDOM_SEED_NOT_SUPPORTED:
		valstr = "CRYPTO_RANDOM_SEED_NOT_SUPPORTED";
		break;
	case CRYPTO_RANDOM_NO_RNG:
		valstr = "CRYPTO_RANDOM_NO_RNG";
		break;
	case CRYPTO_DOMAIN_PARAMS_INVALID:
		valstr = "CRYPTO_DOMAIN_PARAMS_INVALID";
		break;
	case CRYPTO_BUFFER_TOO_SMALL:
		valstr = "CRYPTO_BUFFER_TOO_SMALL";
		break;
	case CRYPTO_INFORMATION_SENSITIVE:
		valstr = "CRYPTO_INFORMATION_SENSITIVE";
		break;
	case CRYPTO_NOT_SUPPORTED:
		valstr = "CRYPTO_NOT_SUPPORTED";
		break;
	case CRYPTO_QUEUED:
		valstr = "CRYPTO_QUEUED";
		break;
	case CRYPTO_BUFFER_TOO_BIG:
		valstr = "CRYPTO_BUFFER_TOO_BIG";
		break;
	case CRYPTO_INVALID_CONTEXT:
		valstr = "CRYPTO_INVALID_CONTEXT";
		break;
	case CRYPTO_INVALID_MAC:
		valstr = "CRYPTO_INVALID_MAC";
		break;
	case CRYPTO_MECH_NOT_SUPPORTED:
		valstr = "CRYPTO_MECH_NOT_SUPPORTED";
		break;
	case CRYPTO_INCONSISTENT_ATTRIBUTE:
		valstr = "CRYPTO_INCONSISTENT_ATTRIBUTE";
		break;
	case CRYPTO_NO_PERMISSION:
		valstr = "CRYPTO_NO_PERMISSION";
		break;
	case CRYPTO_INVALID_PROVIDER_ID:
		valstr = "CRYPTO_INVALID_PROVIDER_ID";
		break;
	case CRYPTO_VERSION_MISMATCH:
		valstr = "CRYPTO_VERSION_MISMATCH";
		break;
	case CRYPTO_BUSY:
		valstr = "CRYPTO_BUSY";
		break;
	case CRYPTO_UNKNOWN_PROVIDER:
		valstr = "CRYPTO_UNKNOWN_PROVIDER";
		break;
	case CRYPTO_MODVERIFICATION_FAILED:
		valstr = "CRYPTO_MODVERIFICATION_FAILED";
		break;
	case CRYPTO_OLD_CTX_TEMPLATE:
		valstr = "CRYPTO_OLD_CTX_TEMPLATE";
		break;
	case CRYPTO_WEAK_KEY:
		valstr = "CRYPTO_WEAK_KEY";
		break;
	case CRYPTO_FIPS140_ERROR:
		valstr = "CRYPTO_FIPS140_ERROR";
		break;
	default:
		valstr = "Unknown KCF error";
		break;
	}

	(void) snprintf(buf, buflen, "%s (0x%08x)", valstr, e);
	return (buf);
}
