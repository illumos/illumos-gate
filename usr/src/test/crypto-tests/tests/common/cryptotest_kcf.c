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
 * Copyright 2018, Joyent, Inc.
 */

#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "cryptotest.h"

struct crypto_op {
	char *in;
	char *out;
	char *key;
	char *param;

	size_t inlen;
	size_t outlen;
	size_t keylen;
	size_t paramlen;
	size_t updatelen;

	char *mechname;

	/* internal */
	crypto_mech_type_t mech;
	crypto_session_id_t hsession;
	crypto_func_group_t fg;
};

static int fd;
static const char CRYPTO_DEVICE[] = "/dev/crypto";

int
kcf_do_ioctl(int opcode, uint_t *arg, char *opstr)
{
	int ret;

	while ((ret = ioctl(fd, opcode, arg)) < 0) {
		if (errno != EINTR)
			break;
	}

	if (ret < 0 || *arg != CRYPTO_SUCCESS)
		(void) fprintf(stderr, "%s: Error = %d %d 0x%02x\n",
		    (opstr == NULL) ? "ioctl" : opstr,
		    ret, errno, *arg);

	if (ret < 0)
		return (errno);

	return (*arg);
}

crypto_op_t *
cryptotest_init(cryptotest_t *arg, crypto_func_group_t fg)
{
	crypto_op_t *op = malloc(sizeof (*op));

	if (op == NULL)
		return (NULL);

	while ((fd = open(CRYPTO_DEVICE, O_RDWR)) < 0) {
		if (errno != EINTR)
			return (NULL);
	}

	op->in = (char *)arg->in;
	op->out = (char *)arg->out;
	op->key = (char *)arg->key;
	op->param = (char *)arg->param;

	op->inlen = arg->inlen;
	op->outlen = arg->outlen;
	op->keylen = arg->keylen * 8; /* kcf uses keylen in bits */
	op->paramlen = arg->plen;
	op->updatelen = arg->updatelen;

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

int
cryptotest_close(crypto_op_t *op)
{
	if (op->hsession != CRYPTO_INVALID_SESSION)
		(void) cryptotest_close_session(op->hsession);
	free(op);
	if (fd >= 0)
		return (close(fd));
	return (0);
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
	init.mi_mech.cm_param = NULL;
	init.mi_mech.cm_param_len = 0;

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
mac_update(crypto_op_t *op, int offset)
{
	crypto_mac_update_t update;

	bzero((void *)&update, sizeof (update));

	update.mu_session = op->hsession;
	update.mu_databuf = op->in + offset;
	update.mu_datalen = op->updatelen;

	return (kcf_do_ioctl(CRYPTO_MAC_UPDATE, (uint_t *)&update, "update"));
}

int
mac_final(crypto_op_t *op)
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
encrypt_update(crypto_op_t *op, int offset, size_t *encrlen)
{
	crypto_encrypt_update_t update;
	int ret;
	bzero((void *)&update, sizeof (update));

	update.eu_session = op->hsession;
	update.eu_databuf = op->in + offset;
	update.eu_datalen = op->updatelen;
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
decrypt_update(crypto_op_t *op, int offset, size_t *encrlen)
{
	crypto_decrypt_update_t update;
	int ret;

	bzero((void *)&update, sizeof (update));

	update.du_session = op->hsession;
	update.du_databuf = op->out + *encrlen;
	update.du_datalen = op->outlen - *encrlen;
	update.du_encrlen = op->updatelen;
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
	init.di_mech.cm_param = NULL;
	init.di_mech.cm_param_len = 0;

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
digest_update(crypto_op_t *op, int offset)
{
	crypto_digest_update_t update;

	bzero(&update, sizeof (update));

	update.du_session = op->hsession;

	update.du_datalen = op->updatelen;
	update.du_databuf = op->in + offset;

	return (kcf_do_ioctl(CRYPTO_DIGEST_UPDATE, (uint_t *)&update,
	    "update"));
}

int
digest_final(crypto_op_t *op)
{
	crypto_digest_final_t final;

	bzero(&final, sizeof (final));

	final.df_session = op->hsession;

	final.df_digestlen = op->outlen;
	final.df_digestbuf = op->out;

	return (kcf_do_ioctl(CRYPTO_DIGEST_FINAL, (uint_t *)&final, "final"));
}
