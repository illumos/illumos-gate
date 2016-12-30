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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2016 Jason King.  All rights reserved.
 */

#include <cryptoutil.h>

/*
 * Get the key generation mechanism for the given mechanism.
 *
 * All mechanisms in PKCS #11 v2.20 are listed here.
 */
CK_RV
pkcs11_mech2keygen(CK_MECHANISM_TYPE mech_type, CK_MECHANISM_TYPE *gen_mech)
{
	switch (mech_type) {

	case CKM_RSA_PKCS_KEY_PAIR_GEN:
	case CKM_RSA_PKCS:
	case CKM_RSA_9796:
	case CKM_RSA_X_509:
	case CKM_MD2_RSA_PKCS:
	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS_PSS:
	case CKM_SHA384_RSA_PKCS_PSS:
	case CKM_SHA512_RSA_PKCS_PSS:
	case CKM_RIPEMD128_RSA_PKCS:
	case CKM_RIPEMD160_RSA_PKCS:
	case CKM_RSA_PKCS_OAEP:
	case CKM_RSA_PKCS_OAEP_TPM_1_1:
	case CKM_RSA_PKCS_TPM_1_1:
		*gen_mech = CKM_RSA_PKCS_KEY_PAIR_GEN;
		break;

	case CKM_RSA_X9_31_KEY_PAIR_GEN:
	case CKM_RSA_X9_31:
	case CKM_SHA1_RSA_X9_31:
		*gen_mech = CKM_RSA_X9_31_KEY_PAIR_GEN;
		break;

	case CKM_RSA_PKCS_PSS:
	case CKM_SHA1_RSA_PKCS_PSS:
		*gen_mech = CKM_RSA_PKCS_KEY_PAIR_GEN;
		break;

	case CKM_DH_PKCS_PARAMETER_GEN:
		*gen_mech = CKM_DH_PKCS_PARAMETER_GEN;
		break;

	case CKM_DSA_KEY_PAIR_GEN:
	case CKM_DSA:
	case CKM_DSA_SHA1:
	case CKM_DSA_SHA224:
	case CKM_DSA_SHA256:
	case CKM_DSA_SHA384:
	case CKM_DSA_SHA512:
		*gen_mech = CKM_DSA_KEY_PAIR_GEN;
		break;

	case CKM_DSA_PARAMETER_GEN:
		*gen_mech = CKM_DSA_PARAMETER_GEN;
		break;

	case CKM_DSA_PROBABLISTIC_PARAMETER_GEN:
		*gen_mech = CKM_DSA_PROBABLISTIC_PARAMETER_GEN;
		break;

	case CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN:
		*gen_mech = CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN;
		break;

	case CKM_FORTEZZA_TIMESTAMP:
		*gen_mech = CKM_DSA_KEY_PAIR_GEN;
		break;

	case CKM_DH_PKCS_KEY_PAIR_GEN:
	case CKM_DH_PKCS_DERIVE:
		*gen_mech = CKM_DH_PKCS_KEY_PAIR_GEN;
		break;

	case CKM_ECDSA:
	case CKM_ECDSA_SHA1:
	case CKM_ECDSA_SHA224:
	case CKM_ECDSA_SHA256:
	case CKM_ECDSA_SHA384:
	case CKM_ECDSA_SHA512:
	case CKM_EC_KEY_PAIR_GEN:
	case CKM_ECDH1_DERIVE:
	case CKM_ECDH1_COFACTOR_DERIVE:
	case CKM_ECMQV_DERIVE:
		*gen_mech = CKM_EC_KEY_PAIR_GEN;
		break;

	case CKM_X9_42_DH_KEY_PAIR_GEN:
	case CKM_X9_42_DH_DERIVE:
	case CKM_X9_42_DH_HYBRID_DERIVE:
	case CKM_X9_42_MQV_DERIVE:
		*gen_mech = CKM_X9_42_DH_KEY_PAIR_GEN;
		break;

	case CKM_X9_42_DH_PARAMETER_GEN:
		*gen_mech = CKM_X9_42_DH_PARAMETER_GEN;
		break;

	case CKM_KEA_KEY_PAIR_GEN:
	case CKM_KEA_KEY_DERIVE:
		*gen_mech = CKM_KEA_KEY_PAIR_GEN;
		break;

	case CKM_MD2:
	case CKM_MD2_HMAC:
	case CKM_MD2_HMAC_GENERAL:
	case CKM_MD5:
	case CKM_MD5_HMAC:
	case CKM_MD5_HMAC_GENERAL:
	case CKM_SHA_1:
	case CKM_SHA_1_HMAC:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA256:
	case CKM_SHA256_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA384:
	case CKM_SHA384_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA512:
	case CKM_SHA512_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
	case CKM_SHA512_224:
	case CKM_SHA512_224_HMAC:
	case CKM_SHA512_224_HMAC_GENERAL:
	case CKM_SHA512_224_KEY_DERIVATION:
	case CKM_SHA512_256:
	case CKM_SHA512_256_HMAC:
	case CKM_SHA512_256_HMAC_GENERAL:
	case CKM_SHA512_256_KEY_DERIVATION:
	case CKM_GENERIC_SECRET_KEY_GEN:
	case CKM_FASTHASH:
	case CKM_PKCS5_PBKD2:
	case CKM_PBA_SHA1_WITH_SHA1_HMAC:
	case CKM_CMS_SIG:
		*gen_mech = CKM_GENERIC_SECRET_KEY_GEN;
		break;

	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:
	case CKM_SSL3_PRE_MASTER_KEY_GEN:
	case CKM_SSL3_MASTER_KEY_DERIVE:
	case CKM_SSL3_KEY_AND_MAC_DERIVE:
	case CKM_SSL3_MASTER_KEY_DERIVE_DH:
		*gen_mech = CKM_SSL3_PRE_MASTER_KEY_GEN;
		break;

	case CKM_TLS_PRE_MASTER_KEY_GEN:
	case CKM_TLS_MASTER_KEY_DERIVE:
	case CKM_TLS_KEY_AND_MAC_DERIVE:
	case CKM_TLS_MASTER_KEY_DERIVE_DH:
	case CKM_TLS_PRF:
		*gen_mech = CKM_TLS_PRE_MASTER_KEY_GEN;
		break;

	case CKM_WTLS_PRE_MASTER_KEY_GEN:
	case CKM_WTLS_MASTER_KEY_DERIVE:
	case CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC:
	case CKM_WTLS_PRF:
	case CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE:
	case CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE:
		*gen_mech = CKM_WTLS_PRE_MASTER_KEY_GEN;
		break;

	case CKM_CONCATENATE_BASE_AND_KEY:
	case CKM_CONCATENATE_BASE_AND_DATA:
	case CKM_CONCATENATE_DATA_AND_BASE:
	case CKM_XOR_BASE_AND_DATA:
	case CKM_EXTRACT_KEY_FROM_KEY:
	case CKM_RIPEMD128:
	case CKM_RIPEMD128_HMAC:
	case CKM_RIPEMD128_HMAC_GENERAL:
	case CKM_RIPEMD160:
	case CKM_RIPEMD160_HMAC:
	case CKM_RIPEMD160_HMAC_GENERAL:
	case CKM_SHA1_KEY_DERIVATION:
	case CKM_SHA256_KEY_DERIVATION:
	case CKM_SHA384_KEY_DERIVATION:
	case CKM_SHA512_KEY_DERIVATION:
	case CKM_MD5_KEY_DERIVATION:
	case CKM_MD2_KEY_DERIVATION:
	/* not sure the following 2 should be CKK_DES or not */
	case CKM_KEY_WRAP_LYNKS: /* wrap/unwrap secret key w/ DES key */
	case CKM_KEY_WRAP_SET_OAEP:  /* wrap/unwarp DES key w/ RSA key */
		*gen_mech = CKM_GENERIC_SECRET_KEY_GEN;
		break;

	case CKM_RC2_KEY_GEN:
	case CKM_RC2_ECB:
	case CKM_RC2_CBC:
	case CKM_RC2_MAC:
	case CKM_RC2_MAC_GENERAL:
	case CKM_RC2_CBC_PAD:
	case CKM_PBE_SHA1_RC2_128_CBC:
	case CKM_PBE_SHA1_RC2_40_CBC:
		*gen_mech = CKM_RC2_KEY_GEN;
		break;

	case CKM_RC4_KEY_GEN:
	case CKM_RC4:
	case CKM_PBE_SHA1_RC4_128:
	case CKM_PBE_SHA1_RC4_40:
		*gen_mech = CKM_RC4_KEY_GEN;
		break;

	case CKM_DES_KEY_GEN:
	case CKM_DES_ECB:
	case CKM_DES_CBC:
	case CKM_DES_MAC:
	case CKM_DES_MAC_GENERAL:
	case CKM_DES_CBC_PAD:
	case CKM_PBE_MD2_DES_CBC:
	case CKM_PBE_MD5_DES_CBC:
	case CKM_DES_OFB64:
	case CKM_DES_OFB8:
	case CKM_DES_CFB64:
	case CKM_DES_CFB8:
	case CKM_DES_ECB_ENCRYPT_DATA:
	case CKM_DES_CBC_ENCRYPT_DATA:
		*gen_mech = CKM_DES_KEY_GEN;
		break;

	case CKM_DES2_KEY_GEN:
	case CKM_PBE_SHA1_DES2_EDE_CBC:
		*gen_mech = CKM_DES2_KEY_GEN;
		break;

	case CKM_DES3_KEY_GEN:
	case CKM_DES3_ECB:
	case CKM_DES3_CBC:
	case CKM_DES3_MAC:
	case CKM_DES3_MAC_GENERAL:
	case CKM_DES3_CBC_PAD:
	case CKM_PBE_SHA1_DES3_EDE_CBC:
	case CKM_DES3_ECB_ENCRYPT_DATA:
	case CKM_DES3_CBC_ENCRYPT_DATA:
	case CKM_DES3_CMAC:
	case CKM_DES3_CMAC_GENERAL:
		*gen_mech = CKM_DES3_KEY_GEN;
		break;

	case CKM_ACTI:
	case CKM_ACTI_KEY_GEN:
		*gen_mech = CKM_ACTI_KEY_GEN;
		break;

	case CKM_CAST_KEY_GEN:
	case CKM_CAST_ECB:
	case CKM_CAST_CBC:
	case CKM_CAST_MAC:
	case CKM_CAST_MAC_GENERAL:
	case CKM_CAST_CBC_PAD:
	case CKM_PBE_MD5_CAST_CBC:
		*gen_mech = CKM_CAST_KEY_GEN;
		break;

	case CKM_CAST3_KEY_GEN:
	case CKM_CAST3_ECB:
	case CKM_CAST3_CBC:
	case CKM_CAST3_MAC:
	case CKM_CAST3_MAC_GENERAL:
	case CKM_CAST3_CBC_PAD:
	case CKM_PBE_MD5_CAST3_CBC:
		*gen_mech = CKM_CAST3_KEY_GEN;
		break;

	/* CAST5 and CAST128 are the same alg */
	case CKM_CAST5_CBC:
	case CKM_CAST5_CBC_PAD:
	case CKM_CAST5_ECB:
	case CKM_CAST5_KEY_GEN:
	case CKM_CAST5_MAC:
	case CKM_CAST5_MAC_GENERAL:
	case CKM_PBE_MD5_CAST5_CBC:
	case CKM_PBE_SHA1_CAST5_CBC:
		*gen_mech = CKM_CAST5_KEY_GEN;
		break;

	case CKM_RC5_KEY_GEN:
	case CKM_RC5_ECB:
	case CKM_RC5_CBC:
	case CKM_RC5_MAC:
	case CKM_RC5_MAC_GENERAL:
	case CKM_RC5_CBC_PAD:
		*gen_mech = CKM_RC5_KEY_GEN;
		break;

	case CKM_IDEA_KEY_GEN:
	case CKM_IDEA_ECB:
	case CKM_IDEA_CBC:
	case CKM_IDEA_MAC:
	case CKM_IDEA_MAC_GENERAL:
	case CKM_IDEA_CBC_PAD:
		*gen_mech = CKM_IDEA_KEY_GEN;
		break;

	case CKM_SKIPJACK_KEY_GEN:
	case CKM_SKIPJACK_ECB64:
	case CKM_SKIPJACK_CBC64:
	case CKM_SKIPJACK_OFB64:
	case CKM_SKIPJACK_CFB64:
	case CKM_SKIPJACK_CFB32:
	case CKM_SKIPJACK_CFB16:
	case CKM_SKIPJACK_CFB8:
	case CKM_SKIPJACK_WRAP:
	case CKM_SKIPJACK_PRIVATE_WRAP:
	case CKM_SKIPJACK_RELAYX:
		*gen_mech = CKM_SKIPJACK_KEY_GEN;
		break;

	case CKM_BATON_KEY_GEN:
	case CKM_BATON_ECB128:
	case CKM_BATON_ECB96:
	case CKM_BATON_CBC128:
	case CKM_BATON_COUNTER:
	case CKM_BATON_SHUFFLE:
	case CKM_BATON_WRAP:
		*gen_mech = CKM_BATON_KEY_GEN;
		break;

	case CKM_JUNIPER_KEY_GEN:
	case CKM_JUNIPER_ECB128:
	case CKM_JUNIPER_CBC128:
	case CKM_JUNIPER_COUNTER:
	case CKM_JUNIPER_SHUFFLE:
	case CKM_JUNIPER_WRAP:
		*gen_mech = CKM_JUNIPER_KEY_GEN;
		break;

	case CKM_CDMF_KEY_GEN:
	case CKM_CDMF_ECB:
	case CKM_CDMF_CBC:
	case CKM_CDMF_MAC:
	case CKM_CDMF_MAC_GENERAL:
	case CKM_CDMF_CBC_PAD:
		*gen_mech = CKM_CDMF_KEY_GEN;
		break;

	case CKM_AES_KEY_GEN:
	case CKM_AES_ECB:
	case CKM_AES_CBC:
	case CKM_AES_MAC:
	case CKM_AES_MAC_GENERAL:
	case CKM_AES_CBC_PAD:
	case CKM_AES_ECB_ENCRYPT_DATA:
	case CKM_AES_CBC_ENCRYPT_DATA:
	case CKM_AES_CCM:
	case CKM_AES_CFB1:
	case CKM_AES_CFB128:
	case CKM_AES_CFB64:
	case CKM_AES_CFB8:
	case CKM_AES_CMAC:
	case CKM_AES_CMAC_GENERAL:
	case CKM_AES_CTR:
	case CKM_AES_CTS:
	case CKM_AES_GCM:
	case CKM_AES_GMAC:
	case CKM_AES_KEY_WRAP:
	case CKM_AES_KEY_WRAP_PAD:
	case CKM_AES_OFB:
	case CKM_AES_XCBC_MAC:
	case CKM_AES_XCBC_MAC_96:
		*gen_mech = CKM_AES_KEY_GEN;
		break;

	case CKM_BLOWFISH_KEY_GEN:
	case CKM_BLOWFISH_CBC:
	case CKM_BLOWFISH_CBC_PAD:
		*gen_mech = CKM_BLOWFISH_KEY_GEN;
		break;

	case CKM_TWOFISH_KEY_GEN:
	case CKM_TWOFISH_CBC:
		*gen_mech = CKM_TWOFISH_KEY_GEN;
		break;

	case CKM_CAMELLIA_CBC:
	case CKM_CAMELLIA_CBC_ENCRYPT_DATA:
	case CKM_CAMELLIA_CBC_PAD:
	case CKM_CAMELLIA_CTR:
	case CKM_CAMELLIA_ECB:
	case CKM_CAMELLIA_ECB_ENCRYPT_DATA:
	case CKM_CAMELLIA_KEY_GEN:
	case CKM_CAMELLIA_MAC:
	case CKM_CAMELLIA_MAC_GENERAL:
		*gen_mech = CKM_CAMELLIA_KEY_GEN;
		break;

	case CKM_ARIA_CBC:
	case CKM_ARIA_CBC_ENCRYPT_DATA:
	case CKM_ARIA_CBC_PAD:
	case CKM_ARIA_ECB:
	case CKM_ARIA_ECB_ENCRYPT_DATA:
	case CKM_ARIA_KEY_GEN:
	case CKM_ARIA_MAC:
	case CKM_ARIA_MAC_GENERAL:
		*gen_mech = CKM_ARIA_KEY_GEN;
		break;

	case CKM_GOST28147:
	case CKM_GOST28147_ECB:
	case CKM_GOST28147_KEY_GEN:
	case CKM_GOST28147_KEY_WRAP:
	case CKM_GOST28147_MAC:
		*gen_mech = CKM_GOST28147_KEY_GEN;
		break;

	case CKM_GOSTR3410:
	case CKM_GOSTR3410_DERIVE:
	case CKM_GOSTR3410_KEY_PAIR_GEN:
	case CKM_GOSTR3410_KEY_WRAP:
	case CKM_GOSTR3410_WITH_GOSTR3411:
		*gen_mech = CKM_GOSTR3410_KEY_PAIR_GEN;
		break;

	case CKM_HOTP:
	case CKM_HOTP_KEY_GEN:
		*gen_mech = CKM_HOTP_KEY_GEN;
		break;

	case CKM_SECURID:
	case CKM_SECURID_KEY_GEN:
		*gen_mech = CKM_SECURID_KEY_GEN;
		break;

	case CKM_SEED_CBC:
	case CKM_SEED_CBC_ENCRYPT_DATA:
	case CKM_SEED_CBC_PAD:
	case CKM_SEED_ECB:
	case CKM_SEED_ECB_ENCRYPT_DATA:
	case CKM_SEED_KEY_GEN:
	case CKM_SEED_MAC:
	case CKM_SEED_MAC_GENERAL:
		*gen_mech = CKM_SEED_KEY_GEN;
		break;

	default:
		return (CKR_MECHANISM_INVALID);
	}

	return (CKR_OK);
}
