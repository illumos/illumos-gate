/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifdef	_KERNEL
/* Solaris Kerberos:
 * we don't provide these functions to the kernel
 */
#define	krb5int_des_string_to_key	NULL
#define	krb5_dk_string_to_key	NULL
#define	krb5int_arcfour_string_to_key	NULL
#endif	/* _KERNEL */

#include <k5-int.h>
#include <enc_provider.h>
#include <hash_provider.h>
#include <etypes.h>
#include <old.h>
#include <raw.h>

#include <dk.h>
#include <arcfour.h>

/* these will be linear searched.  if they ever get big, a binary
   search or hash table would be better, which means these would need
   to be sorted.  An array would be more efficient, but that assumes
   that the keytypes are all near each other.  I'd rather not make
   that assumption. */

struct krb5_keytypes krb5_enctypes_list[] = {
    { ENCTYPE_DES_CBC_CRC,
      "des-cbc-crc", "DES cbc mode with CRC-32",
      &krb5int_enc_des, &krb5int_hash_crc32,
      krb5_old_encrypt_length, krb5_old_encrypt, krb5_old_decrypt,
      CKSUMTYPE_RSA_MD5,
#ifndef _KERNEL
      krb5int_des_string_to_key,
#else
      SUN_CKM_DES_CBC,
      NULL,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
},
    { ENCTYPE_DES_CBC_MD5,
      "des-cbc-md5", "DES cbc mode with RSA-MD5",
      &krb5int_enc_des, &krb5int_hash_md5,
      krb5_old_encrypt_length, krb5_old_encrypt, krb5_old_decrypt,
      CKSUMTYPE_RSA_MD5,
#ifndef _KERNEL
      krb5int_des_string_to_key,
#else
      SUN_CKM_DES_CBC,
      SUN_CKM_MD5,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
},
    { ENCTYPE_DES_CBC_MD5,
      "des", "DES cbc mode with RSA-MD5", /* alias */
      &krb5int_enc_des, &krb5int_hash_md5,
      krb5_old_encrypt_length, krb5_old_encrypt, krb5_old_decrypt,
      CKSUMTYPE_RSA_MD5,
#ifndef _KERNEL
      krb5int_des_string_to_key,
#else
      SUN_CKM_DES_CBC,
      SUN_CKM_MD5,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* _KERNEL */
 },
    { ENCTYPE_DES_CBC_RAW,
      "des-cbc-raw", "DES cbc mode raw",
      &krb5int_enc_des, NULL,
      krb5_raw_encrypt_length, krb5_raw_encrypt, krb5_raw_decrypt,
      0,
#ifndef _KERNEL
      krb5int_des_string_to_key,
#else
      SUN_CKM_DES_CBC,
      NULL,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
},

    { ENCTYPE_DES3_CBC_RAW,
      "des3-cbc-raw", "Triple DES cbc mode raw",
      &krb5int_enc_des3, NULL,
      krb5_raw_encrypt_length, krb5_raw_encrypt, krb5_raw_decrypt,
      0,
#ifndef _KERNEL
      krb5int_dk_string_to_key,
#else
      SUN_CKM_DES3_CBC,
      NULL,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
},

    { ENCTYPE_DES3_CBC_SHA1,
      "des3-cbc-sha1", "Triple DES cbc mode with HMAC/sha1",
      &krb5int_enc_des3, &krb5int_hash_sha1,
      krb5_dk_encrypt_length, krb5_dk_encrypt, krb5_dk_decrypt,
      CKSUMTYPE_HMAC_SHA1_DES3,
#ifndef _KERNEL
      krb5int_dk_string_to_key,
#else
      SUN_CKM_DES3_CBC,
      SUN_CKM_SHA1_HMAC,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif
 },
    { ENCTYPE_DES3_CBC_SHA1,	/* alias */
      "des3-hmac-sha1", "Triple DES cbc mode with HMAC/sha1",
      &krb5int_enc_des3, &krb5int_hash_sha1,
      krb5_dk_encrypt_length, krb5_dk_encrypt, krb5_dk_decrypt,
      CKSUMTYPE_HMAC_SHA1_DES3,
#ifndef _KERNEL
      krb5int_dk_string_to_key,
#else
      SUN_CKM_DES3_CBC,
      SUN_CKM_SHA1_HMAC,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
},
    { ENCTYPE_DES3_CBC_SHA1,	/* alias */
      "des3-cbc-sha1-kd", "Triple DES cbc mode with HMAC/sha1",
      &krb5int_enc_des3, &krb5int_hash_sha1,
      krb5_dk_encrypt_length, krb5_dk_encrypt, krb5_dk_decrypt,
      CKSUMTYPE_HMAC_SHA1_DES3,
#ifndef _KERNEL
      krb5int_dk_string_to_key,
#else
      SUN_CKM_DES3_CBC,
      SUN_CKM_SHA1_HMAC,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
},
      /* The des3-cbc-hmac-sha1-kd is the official enctype associated with
       * 3DES/SHA1 in draft-ietf-krb-wg-crypto-00.txt
       */
    { ENCTYPE_DES3_CBC_SHA1,	/* alias */
      "des3-cbc-hmac-sha1-kd", "Triple DES cbc mode with HMAC/sha1",
      &krb5int_enc_des3, &krb5int_hash_sha1,
      krb5_dk_encrypt_length, krb5_dk_encrypt, krb5_dk_decrypt,
      CKSUMTYPE_HMAC_SHA1_DES3,
#ifndef _KERNEL
      krb5int_dk_string_to_key,
#else
      SUN_CKM_DES3_CBC,
      SUN_CKM_SHA1_HMAC,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
},

    { ENCTYPE_DES_HMAC_SHA1,
      "des-hmac-sha1", "DES with HMAC/sha1",
      &krb5int_enc_des, &krb5int_hash_sha1,
      krb5_dk_encrypt_length, krb5_dk_encrypt, krb5_dk_decrypt,
      0,
#ifndef _KERNEL
      krb5int_dk_string_to_key,
#else
      SUN_CKM_DES_CBC,
      SUN_CKM_SHA1_HMAC,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
},
    { ENCTYPE_ARCFOUR_HMAC,
      "arcfour-hmac","ArcFour with HMAC/md5", &krb5int_enc_arcfour,
      &krb5int_hash_md5,
krb5_arcfour_encrypt_length, krb5_arcfour_encrypt,
      krb5_arcfour_decrypt,
	CKSUMTYPE_HMAC_MD5_ARCFOUR,
#ifndef _KERNEL
	krb5int_arcfour_string_to_key,
#else
      SUN_CKM_RC4,
      SUN_CKM_MD5_HMAC,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
    },
    { ENCTYPE_ARCFOUR_HMAC,  /* alias */
      "rc4-hmac", "ArcFour with HMAC/md5", &krb5int_enc_arcfour,
      &krb5int_hash_md5,
      krb5_arcfour_encrypt_length, krb5_arcfour_encrypt,
      krb5_arcfour_decrypt,
	CKSUMTYPE_HMAC_MD5_ARCFOUR,
#ifndef _KERNEL
	krb5int_arcfour_string_to_key,
#else
      SUN_CKM_RC4,
      SUN_CKM_MD5_HMAC,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
    },
    { ENCTYPE_ARCFOUR_HMAC,  /* alias */
      "arcfour-hmac-md5", "ArcFour with HMAC/md5", &krb5int_enc_arcfour,
      &krb5int_hash_md5,
      krb5_arcfour_encrypt_length, krb5_arcfour_encrypt,
      krb5_arcfour_decrypt,
	CKSUMTYPE_HMAC_MD5_ARCFOUR,
#ifndef _KERNEL
	krb5int_arcfour_string_to_key,
#else
      SUN_CKM_RC4,
      SUN_CKM_MD5_HMAC,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
    },
    { ENCTYPE_ARCFOUR_HMAC_EXP,
	"arcfour-hmac-exp", "Exportable ArcFour with HMAC/md5",
	&krb5int_enc_arcfour,
	&krb5int_hash_md5, krb5_arcfour_encrypt_length, krb5_arcfour_encrypt,
	krb5_arcfour_decrypt,
	CKSUMTYPE_HMAC_MD5_ARCFOUR,
#ifndef _KERNEL
	krb5int_arcfour_string_to_key,
#else
      SUN_CKM_RC4,
      SUN_CKM_MD5_HMAC,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
    },
    { ENCTYPE_ARCFOUR_HMAC_EXP, /* alias */
      "rc4-hmac-exp", "Exportable ArcFour with HMAC/md5",
      &krb5int_enc_arcfour,
      &krb5int_hash_md5,
      krb5_arcfour_encrypt_length, krb5_arcfour_encrypt,
      krb5_arcfour_decrypt,
	CKSUMTYPE_HMAC_MD5_ARCFOUR,
#ifndef _KERNEL
	krb5int_arcfour_string_to_key,
#else
      SUN_CKM_RC4,
      SUN_CKM_MD5_HMAC,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
    },
    { ENCTYPE_ARCFOUR_HMAC_EXP, /* alias */
      "arcfour-hmac-md5-exp", "Exportable ArcFour with HMAC/md5",
      &krb5int_enc_arcfour,
      &krb5int_hash_md5,
      krb5_arcfour_encrypt_length, krb5_arcfour_encrypt,
      krb5_arcfour_decrypt,
	CKSUMTYPE_HMAC_MD5_ARCFOUR,
#ifndef _KERNEL
	krb5int_arcfour_string_to_key,
#else
      SUN_CKM_RC4,
      SUN_CKM_MD5_HMAC,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
    },

    /*
     * Note, all AES enctypes must use SUN_CKM_AES_CBC.  See aes_provider.c for
     * more info.
     */
    { ENCTYPE_AES128_CTS_HMAC_SHA1_96,
      "aes128-cts-hmac-sha1-96", "AES-128 CTS mode with 96-bit SHA-1 HMAC",
      &krb5int_enc_aes128, &krb5int_hash_sha1,
      krb5int_aes_encrypt_length, krb5int_aes_dk_encrypt, krb5int_aes_dk_decrypt,
      CKSUMTYPE_HMAC_SHA1_96_AES128,
#ifndef _KERNEL
      krb5int_aes_string_to_key,
#else
      SUN_CKM_AES_CBC,
      SUN_CKM_SHA1_HMAC,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
    },
    { ENCTYPE_AES128_CTS_HMAC_SHA1_96,
	"aes128-cts", "AES-128 CTS mode with 96-bit SHA-1 HMAC",
	&krb5int_enc_aes128, &krb5int_hash_sha1,
	krb5int_aes_encrypt_length, krb5int_aes_dk_encrypt, krb5int_aes_dk_decrypt,
	CKSUMTYPE_HMAC_SHA1_96_AES128,
#ifndef _KERNEL
	krb5int_aes_string_to_key,
#else
      SUN_CKM_AES_CBC,
      SUN_CKM_SHA1_HMAC,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
    },
    { ENCTYPE_AES256_CTS_HMAC_SHA1_96,
      "aes256-cts-hmac-sha1-96", "AES-256 CTS mode with 96-bit SHA-1 HMAC",
      &krb5int_enc_aes256, &krb5int_hash_sha1,
      krb5int_aes_encrypt_length, krb5int_aes_dk_encrypt, krb5int_aes_dk_decrypt,
      CKSUMTYPE_HMAC_SHA1_96_AES256,
#ifndef _KERNEL
      krb5int_aes_string_to_key,
#else
      SUN_CKM_AES_CBC,
      SUN_CKM_SHA1_HMAC,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
    },
    { ENCTYPE_AES256_CTS_HMAC_SHA1_96,
	"aes256-cts", "AES-256 CTS mode with 96-bit SHA-1 HMAC",
	&krb5int_enc_aes256, &krb5int_hash_sha1,
	krb5int_aes_encrypt_length, krb5int_aes_dk_encrypt, krb5int_aes_dk_decrypt,
	CKSUMTYPE_HMAC_SHA1_96_AES256,
#ifndef _KERNEL
	krb5int_aes_string_to_key,
#else
      SUN_CKM_AES_CBC,
      SUN_CKM_SHA1_HMAC,
      CRYPTO_MECH_INVALID,
      CRYPTO_MECH_INVALID
#endif /* !_KERNEL */
    },
};

const int krb5_enctypes_length =
sizeof(krb5_enctypes_list)/sizeof(struct krb5_keytypes);

#ifdef _KERNEL

/*
 * Routine to pre-fetch the mechanism types from KEF so
 * we dont keep doing this step later.
 */
void
setup_kef_keytypes()
{
	int i;
	struct krb5_keytypes *kt;

	for (i=0; i<krb5_enctypes_length; i++) {
		kt = (struct krb5_keytypes *)&krb5_enctypes_list[i];
		if (kt->kef_cipher_mt == CRYPTO_MECH_INVALID &&
		    kt->mt_e_name != NULL) {
			krb5_enctypes_list[i].kef_cipher_mt =
				crypto_mech2id(kt->mt_e_name);
		}

		if (kt->kef_hash_mt == CRYPTO_MECH_INVALID &&
		    kt->mt_h_name != NULL) {
			krb5_enctypes_list[i].kef_hash_mt =
				crypto_mech2id(kt->mt_h_name);
		}
		KRB5_LOG1(KRB5_INFO, "setup_kef_keytypes(): %s ==> %ld",
			kt->mt_e_name,
			(ulong_t) krb5_enctypes_list[i].kef_cipher_mt);
	}
}

/*ARGSUSED*/
crypto_mech_type_t
get_cipher_mech_type(krb5_context context, krb5_keyblock *key)
{
	int i;
	struct krb5_keytypes *kt;

	if (key == NULL)
		return (CRYPTO_MECH_INVALID);

	for (i=0; i<krb5_enctypes_length; i++) {
		kt = (struct krb5_keytypes *)&krb5_enctypes_list[i];
		if (kt->etype == key->enctype) {
			KRB5_LOG1(KRB5_INFO, "get_cipher_mech_type() "
				"found %s %ld",
				kt->mt_e_name,
				(ulong_t) kt->kef_cipher_mt);
			return (kt->kef_cipher_mt);
		}
	}
	return (CRYPTO_MECH_INVALID);
}

/*ARGSUSED*/
crypto_mech_type_t
get_hash_mech_type(krb5_context context, krb5_keyblock *key)
{
	int i;
	struct krb5_keytypes *kt;

	if (key == NULL)
		return (CRYPTO_MECH_INVALID);

	for (i=0; i<krb5_enctypes_length; i++) {
		kt = (struct krb5_keytypes *)&krb5_enctypes_list[i];
		if (kt->etype == key->enctype) {
			KRB5_LOG1(KRB5_INFO, "get_hash_mech_type() "
				"found %s %ld",
				kt->mt_h_name,
				(ulong_t) kt->kef_hash_mt);
			return (kt->kef_hash_mt);
		}
	}
	return (CRYPTO_MECH_INVALID);
}

#endif /* _KERNEL */
