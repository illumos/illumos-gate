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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_FIPS_TEST_VECTORS_H
#define	_FIPS_TEST_VECTORS_H

#ifdef __cplusplus
extern "C" {
#endif

#define	DES3_KEY_SZ		24
#define	DES_IV_LEN		8
#define	DES_BLOCK_SZ		8

#define	AES_BLOCK_SZ		16
#define	AES_MAX_KEY_SZ		32

#define	AES_CCM_TLEN		16
#define	AES_CCM_NONCE_SZ	7
#define	AES_CCM_AUTHDATA_SZ	30
#define	AES_CCM_DATA_SZ		32	/* Payload size */
#define	AES_CCM_CIPHER_SZ	(AES_CCM_DATA_SZ + AES_CCM_TLEN)

#define	AES_GCM_IV_LEN		12
#define	AES_GCM_AAD_LEN		16
#define	AES_GCM_DATA_SZ		16
#define	AES_GCM_CIPHER_SZ	((AES_GCM_DATA_SZ) + ((AES_GMAC_TAG_BITS) / 8))

#define	AES_GMAC_IV_LEN		12
#define	AES_GMAC_AAD_LEN	16
#define	AES_GMAC_TAG_BITS	128
#define	AES_GMAC_TAG_SZ		((AES_GMAC_TAG_BITS) / 8)
#define	AES_GMAC_CIPHER_SZ	(AES_GMAC_TAG_SZ)

#define	SHA1_HASH_SZ		20
#define	SHA256_HASH_SZ		32
#define	SHA384_HASH_SZ		48
#define	SHA512_HASH_SZ		64


extern uint8_t des3_known_key[DES3_KEY_SZ];
extern uint8_t des3_cbc_known_iv[DES_IV_LEN];
extern uint8_t des3_ecb_known_plaintext[DES_BLOCK_SZ];
extern uint8_t des3_cbc_known_plaintext[DES_BLOCK_SZ];
extern uint8_t des3_ecb_known_ciphertext[DES_BLOCK_SZ];
extern uint8_t des3_cbc_known_ciphertext[DES_BLOCK_SZ];

extern uint8_t aes_known_key[AES_MAX_KEY_SZ];
extern uint8_t aes_cbc_known_initialization_vector[AES_BLOCK_SZ];
extern uint8_t aes_known_plaintext[AES_BLOCK_SZ];
extern uint8_t aes_ecb128_known_ciphertext[AES_BLOCK_SZ];
extern uint8_t aes_cbc128_known_ciphertext[AES_BLOCK_SZ];
extern uint8_t aes_ecb192_known_ciphertext[AES_BLOCK_SZ];
extern uint8_t aes_cbc192_known_ciphertext[AES_BLOCK_SZ];
extern uint8_t aes_ecb256_known_ciphertext[AES_BLOCK_SZ];
extern uint8_t aes_cbc256_known_ciphertext[AES_BLOCK_SZ];

extern uint8_t aes_ctr128_known_key[16];
extern uint8_t aes_ctr192_known_key[24];
extern uint8_t aes_ctr256_known_key[32];
extern uint8_t aes_ctr_known_counter[AES_BLOCK_SZ];
extern uint8_t aes_ctr_known_plaintext[AES_BLOCK_SZ];
extern uint8_t aes_ctr128_known_ciphertext[AES_BLOCK_SZ];
extern uint8_t aes_ctr192_known_ciphertext[AES_BLOCK_SZ];
extern uint8_t aes_ctr256_known_ciphertext[AES_BLOCK_SZ];

extern uint8_t aes_ccm128_known_key[16];
extern uint8_t aes_ccm192_known_key[24];
extern uint8_t aes_ccm256_known_key[32];
extern uint8_t aes_ccm128_known_nonce[AES_CCM_NONCE_SZ];
extern uint8_t aes_ccm192_known_nonce[AES_CCM_NONCE_SZ];
extern uint8_t aes_ccm256_known_nonce[AES_CCM_NONCE_SZ];
extern uint8_t aes_ccm128_known_adata[AES_CCM_AUTHDATA_SZ];
extern uint8_t aes_ccm192_known_adata[AES_CCM_AUTHDATA_SZ];
extern uint8_t aes_ccm256_known_adata[AES_CCM_AUTHDATA_SZ];
extern uint8_t aes_ccm128_known_plaintext[AES_CCM_DATA_SZ];
extern uint8_t aes_ccm192_known_plaintext[AES_CCM_DATA_SZ];
extern uint8_t aes_ccm256_known_plaintext[AES_CCM_DATA_SZ];
extern uint8_t aes_ccm128_known_ciphertext[AES_CCM_CIPHER_SZ];
extern uint8_t aes_ccm192_known_ciphertext[AES_CCM_CIPHER_SZ];
extern uint8_t aes_ccm256_known_ciphertext[AES_CCM_CIPHER_SZ];

extern uint8_t aes_gcm128_known_key[16];
extern uint8_t aes_gcm192_known_key[24];
extern uint8_t aes_gcm256_known_key[32];
extern uint8_t aes_gcm128_known_iv[AES_GCM_IV_LEN];
extern uint8_t aes_gcm192_known_iv[AES_GCM_IV_LEN];
extern uint8_t aes_gcm256_known_iv[AES_GCM_IV_LEN];
extern uint8_t aes_gcm128_known_adata[AES_GCM_AAD_LEN];
extern uint8_t aes_gcm192_known_adata[AES_GCM_AAD_LEN];
extern uint8_t aes_gcm256_known_adata[AES_GCM_AAD_LEN];
extern uint8_t aes_gcm128_known_plaintext[AES_BLOCK_SZ];
extern uint8_t aes_gcm192_known_plaintext[AES_BLOCK_SZ];
extern uint8_t aes_gcm256_known_plaintext[AES_BLOCK_SZ];
extern uint8_t aes_gcm128_known_ciphertext[32];
extern uint8_t aes_gcm192_known_ciphertext[32];
extern uint8_t aes_gcm256_known_ciphertext[32];

extern uint8_t aes_gmac128_known_key[16];
extern uint8_t aes_gmac192_known_key[24];
extern uint8_t aes_gmac256_known_key[32];
extern uint8_t aes_gmac128_known_iv[AES_GMAC_IV_LEN];
extern uint8_t aes_gmac192_known_iv[AES_GMAC_IV_LEN];
extern uint8_t aes_gmac256_known_iv[AES_GMAC_IV_LEN];
extern uint8_t aes_gmac128_known_tag[AES_GMAC_TAG_SZ];
extern uint8_t aes_gmac192_known_tag[AES_GMAC_TAG_SZ];
extern uint8_t aes_gmac256_known_tag[AES_GMAC_TAG_SZ];
extern uint8_t aes_gmac128_known_adata[AES_GMAC_AAD_LEN];
extern uint8_t aes_gmac192_known_adata[AES_GMAC_AAD_LEN];
extern uint8_t aes_gmac256_known_adata[AES_GMAC_AAD_LEN];


extern uint8_t sha1_known_hash_message[64];
extern uint8_t sha1_known_digest[SHA1_HASH_SZ];
extern uint8_t HMAC_known_secret_key[8];
extern uint8_t known_SHA1_hmac[10];
extern uint8_t hmac_sha1_known_hash_message[128];
extern uint8_t sha1_hmac_known_secret_key_2[SHA1_HASH_SZ];
extern uint8_t sha1_hmac_known_hash_message_2[9];
extern uint8_t sha1_known_hmac_2[SHA1_HASH_SZ];

extern uint8_t sha256_known_hash_message[64];
extern uint8_t known_sha256_digest[SHA256_HASH_SZ];
extern uint8_t sha384_known_hash_message[64];
extern uint8_t known_sha384_digest[SHA384_HASH_SZ];
extern uint8_t sha512_known_hash_message[64];
extern uint8_t known_sha512_digest[SHA512_HASH_SZ];
extern uint8_t sha256_hmac_known_hash_message[64];
extern uint8_t sha256_hmac_known_secret_key[36];
extern uint8_t known_sha256_hmac[SHA256_HASH_SZ];
extern uint8_t sha256_hmac_known_hash_message_1[28];
extern uint8_t sha256_hmac_known_secret_key_1[4];
extern uint8_t sha256_known_hmac_1[SHA256_HASH_SZ];
extern uint8_t sha256_hmac_known_hash_message_2[50];
extern uint8_t sha256_hmac_known_secret_key_2[25];
extern uint8_t sha256_known_hmac_2[SHA256_HASH_SZ];
extern uint8_t sha384_hmac_known_secret_key[16];
extern uint8_t sha384_hmac_known_hash_message[128];
extern uint8_t known_sha384_hmac[SHA384_HASH_SZ];
extern uint8_t sha512_hmac_known_secret_key[20];
extern uint8_t sha512_hmac_known_hash_message[128];
extern uint8_t known_sha512_hmac[SHA512_HASH_SZ];


extern uint8_t rsa_modulus_1024[128];
extern uint8_t rsa_public_exponent_1024[3];
extern uint8_t rsa_private_exponent_1024[128];
extern uint8_t rsa_prime1_1024[64];
extern uint8_t rsa_prime2_1024[64];
extern uint8_t rsa_exponent1_1024[64];
extern uint8_t rsa_exponent2_1024[64];
extern uint8_t rsa_coefficient_1024[64];
extern uint8_t rsa_modulus_2048[256];
extern uint8_t rsa_public_exponent_2048[1];
extern uint8_t rsa_private_exponent_2048[256];
extern uint8_t rsa_prime1_2048[128];
extern uint8_t rsa_prime2_2048[128];
extern uint8_t rsa_exponent1_2048[128];
extern uint8_t rsa_exponent2_2048[128];
extern uint8_t rsa_coefficient_2048[128];
extern uint8_t rsa_known_plaintext_msg[128];
extern uint8_t rsa_x509_known_signature_1024[128];
extern uint8_t rsa_pkcs_known_signature_1024[128];
extern uint8_t rsa_x509_known_signature_2048[256];
extern uint8_t rsa_pkcs_known_signature_2048[256];

extern uint8_t dsa_base_1024[128];
extern uint8_t dsa_prime_1024[128];
extern uint8_t dsa_subprime_1024[20];
extern uint8_t dsa_privalue_1024[20];
extern uint8_t dsa_pubvalue_1024[128];
extern uint8_t dsa_known_data[20];

extern uint8_t ec_param_oid_secp192r1[10];
extern uint8_t ec_point_p192r1[49];
extern uint8_t ec_value_p192r1[24];
extern uint8_t ec_param_oid_secp224r1[7];
extern uint8_t ec_point_p224r1[57];
extern uint8_t ec_value_p224r1[28];
extern uint8_t ec_param_oid_secp256r1[10];
extern uint8_t ec_point_p256r1[65];
extern uint8_t ec_value_p256r1[32];
extern uint8_t ec_param_oid_secp384r1[7];
extern uint8_t ec_point_p384r1[97];
extern uint8_t ec_value_p384r1[48];
extern uint8_t ec_param_oid_secp521r1[7];
extern uint8_t ec_point_p521r1[133];
extern uint8_t ec_value_p521r1[66];
extern uint8_t ec_param_oid_sect163k1[7];
extern uint8_t ec_point_t163k1[43];
extern uint8_t ec_value_t163k1[21];
extern uint8_t ec_param_oid_sect233k1[7];
extern uint8_t ec_point_t233k1[61];
extern uint8_t ec_value_t233k1[30];
extern uint8_t ec_param_oid_sect283k1[7];
extern uint8_t ec_point_t283k1[73];
extern uint8_t ec_value_t283k1[36];
extern uint8_t ec_param_oid_sect409k1[7];
extern uint8_t ec_point_t409k1[105];
extern uint8_t ec_value_t409k1[52];
extern uint8_t ec_param_oid_sect571k1[7];
extern uint8_t ec_point_t571k1[145];
extern uint8_t ec_value_t571k1[72];
extern uint8_t ec_param_oid_sect163r2[7];
extern uint8_t ec_point_t163r2[43];
extern uint8_t ec_value_t163r2[21];
extern uint8_t ec_param_oid_sect233r1[7];
extern uint8_t ec_point_t233r1[61];
extern uint8_t ec_value_t233r1[30];
extern uint8_t ec_param_oid_sect283r1[7];
extern uint8_t ec_point_t283r1[73];
extern uint8_t ec_value_t283r1[36];
extern uint8_t ec_param_oid_sect409r1[7];
extern uint8_t ec_point_t409r1[105];
extern uint8_t ec_value_t409r1[52];
extern uint8_t ec_param_oid_sect571r1[7];
extern uint8_t ec_point_t571r1[145];
extern uint8_t ec_value_t571r1[72];

#ifdef	__cplusplus
}
#endif

#endif /* _FIPS_TEST_VECTORS_H */
