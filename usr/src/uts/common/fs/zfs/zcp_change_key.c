/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

#include <sys/ctype.h>
#include <sys/zcp.h>
#include <sys/zcp_change_key.h>

static uint8_t
hexval(char c)
{
	if (c >= '0' && c <= '9')
		return (c - '0');
	else if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	else if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);

	panic("invalid hex value");
}

static int
hex_to_raw(const char *key, uint8_t *buf, size_t buflen)
{
	uint8_t *p;
	size_t srclen = strlen(key);
	size_t i;

	if (buflen * 2 != srclen)
		return (SET_ERROR(EINVAL));

	for (i = 0, p = buf; i < srclen; i += 2, p++) {
		if (!isxdigit(key[i]) || !isxdigit(key[i + 1]))
			return (SET_ERROR(EINVAL));

		*p = hexval(key[i]) << 4 | hexval(key[i + 1]);
	}

	return (0);
}

int
zcp_synctask_change_key_create_params(const char *key, size_t keylen,
    zfs_keyformat_t keyformat, dsl_crypto_params_t **dcpp)
{
	nvlist_t *args = fnvlist_alloc();
	nvlist_t *hidden_args = fnvlist_alloc();
	uint8_t rawkey[WRAPPING_KEY_LEN];
	uint_t rawlen = 0;
	int err = 0;

	/*
	 * Currently, only raw and hex keys are supported in channel
	 * programs (there is no pbkdf2 support in the kernel to convert
	 * a passphrase).
	 */
	switch (keyformat) {
	case ZFS_KEYFORMAT_RAW:
		/*
		 * dsl_crypto_params_create_nvlist() also verifies the
		 * raw key is WRAPPING_KEY_LEN bytes, so this is
		 * _almost_ redundant -- however we still want to
		 * guarantee we won't overflow rawkey when copying
		 * the contents over.
		 */
		if (keylen != WRAPPING_KEY_LEN) {
			err = SET_ERROR(EINVAL);
			goto done;
		}

		bcopy(key, rawkey, keylen);
		rawlen = keylen;
		break;
	case ZFS_KEYFORMAT_HEX:
		/*
		 * hex_to_raw() will reject any input that doesn't exactly
		 * fit into rawkey
		 */
		err = hex_to_raw(key, rawkey, sizeof (rawkey));
		if (err != 0)
			goto done;
		rawlen = sizeof (rawkey);
		break;
	default:
		err = SET_ERROR(EINVAL);
		goto done;
	}

	fnvlist_add_uint64(args, zfs_prop_to_name(ZFS_PROP_KEYFORMAT),
	    (uint64_t)keyformat);
	fnvlist_add_uint8_array(hidden_args, "wkeydata", rawkey, rawlen);

	err = dsl_crypto_params_create_nvlist(DCP_CMD_NEW_KEY, args,
	    hidden_args, dcpp);

done:
	fnvlist_free(args);
	fnvlist_free(hidden_args);
	bzero(rawkey, sizeof (rawkey));

	return (err);
}

void
zcp_synctask_change_key_cleanup(void *arg)
{
	spa_keystore_change_key_args_t *skcka = arg;

	dsl_crypto_params_free(skcka->skcka_cp, B_TRUE);
}

int
zcp_synctask_change_key_check(void *arg, dmu_tx_t *tx)
{
	/*
	 * zcp_synctask_change_key_create_params() already validates that
	 * the new key is in an acceptable format and size for a channel
	 * program. Any future channel program specific checks would go here.
	 * For now, we just perform all the same checks done for
	 * 'zfs change-key' by calling spa_keystore_change_key_check().
	 */
	return (spa_keystore_change_key_check(arg, tx));
}

void
zcp_synctask_change_key_sync(void *arg, dmu_tx_t *tx)
{
	spa_keystore_change_key_sync(arg, tx);
}
