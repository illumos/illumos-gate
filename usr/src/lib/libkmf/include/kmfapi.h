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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018, Joyent, Inc.
 *
 * Constant definitions and function prototypes for the KMF library.
 * Commonly used data types are defined in "kmftypes.h".
 */

#ifndef _KMFAPI_H
#define	_KMFAPI_H

#include <kmftypes.h>
#include <security/cryptoki.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Setup operations.
 */
extern KMF_RETURN kmf_initialize(KMF_HANDLE_T *, char *, char *);
extern KMF_RETURN kmf_configure_keystore(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);
extern KMF_RETURN kmf_finalize(KMF_HANDLE_T);

/*
 * Key operations.
 */
extern KMF_RETURN kmf_create_keypair(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

extern KMF_RETURN kmf_delete_key_from_keystore(KMF_HANDLE_T, int,
	KMF_ATTRIBUTE *);

extern KMF_RETURN kmf_find_key(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

extern KMF_RETURN kmf_find_prikey_by_cert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

extern KMF_RETURN kmf_store_key(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

extern KMF_RETURN kmf_create_sym_key(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

extern KMF_RETURN kmf_get_sym_key_value(KMF_HANDLE_T, KMF_KEY_HANDLE *,
	KMF_RAW_SYM_KEY *);

/*
 * Certificate operations.
 */
extern KMF_RETURN kmf_find_cert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

extern KMF_RETURN kmf_encode_cert_record(KMF_X509_CERTIFICATE *, KMF_DATA *);

extern KMF_RETURN kmf_import_cert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

extern KMF_RETURN kmf_store_cert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

extern KMF_RETURN kmf_delete_cert_from_keystore(KMF_HANDLE_T, int,
	KMF_ATTRIBUTE *);

extern KMF_RETURN kmf_validate_cert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

extern KMF_RETURN kmf_create_cert_file(const KMF_DATA *, KMF_ENCODE_FORMAT,
	char *);

extern KMF_RETURN kmf_download_cert(KMF_HANDLE_T, char *, char *, int,
	unsigned int, char *, KMF_ENCODE_FORMAT *);

extern KMF_RETURN kmf_is_cert_data(KMF_DATA *, KMF_ENCODE_FORMAT *);
extern KMF_RETURN kmf_is_cert_file(KMF_HANDLE_T, char *, KMF_ENCODE_FORMAT *);

extern KMF_RETURN kmf_check_cert_date(KMF_HANDLE_T, const KMF_DATA *);

/*
 * Crypto operations with key or cert.
 */
extern KMF_RETURN kmf_encrypt(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);
extern KMF_RETURN kmf_decrypt(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);
extern KMF_RETURN kmf_sign_cert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);
extern KMF_RETURN kmf_sign_data(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);
extern KMF_RETURN kmf_verify_cert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);
extern KMF_RETURN kmf_verify_data(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

/*
 * CRL operations.
 */
extern KMF_RETURN kmf_import_crl(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);
extern KMF_RETURN kmf_delete_crl(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);
extern KMF_RETURN kmf_list_crl(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);
extern KMF_RETURN kmf_find_crl(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);
extern KMF_RETURN kmf_find_cert_in_crl(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);
extern KMF_RETURN kmf_verify_crl_file(KMF_HANDLE_T, char *, KMF_DATA *);
extern KMF_RETURN kmf_check_crl_date(KMF_HANDLE_T, char *);
extern KMF_RETURN kmf_download_crl(KMF_HANDLE_T, char *, char *,
	int, unsigned int, char *, KMF_ENCODE_FORMAT *);
extern KMF_RETURN kmf_is_crl_file(KMF_HANDLE_T, char *, KMF_ENCODE_FORMAT *);

/*
 * CSR operations.
 */
extern KMF_RETURN kmf_create_csr_file(KMF_DATA *, KMF_ENCODE_FORMAT, char *);
extern KMF_RETURN kmf_set_csr_pubkey(KMF_HANDLE_T,
	KMF_KEY_HANDLE *, KMF_CSR_DATA *);
extern KMF_RETURN kmf_set_csr_version(KMF_CSR_DATA *, uint32_t);
extern KMF_RETURN kmf_set_csr_subject(KMF_CSR_DATA *, KMF_X509_NAME *);
extern KMF_RETURN kmf_set_csr_extn(KMF_CSR_DATA *, KMF_X509_EXTENSION *);
extern KMF_RETURN kmf_set_csr_sig_alg(KMF_CSR_DATA *, KMF_ALGORITHM_INDEX);
extern KMF_RETURN kmf_set_csr_subject_altname(KMF_CSR_DATA *, char *,
	int, KMF_GENERALNAMECHOICES);
extern KMF_RETURN kmf_set_csr_ku(KMF_CSR_DATA *, int, uint16_t);
extern KMF_RETURN kmf_decode_csr(KMF_HANDLE_T, KMF_DATA *, KMF_CSR_DATA *);
extern KMF_RETURN kmf_verify_csr(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);
extern KMF_RETURN kmf_sign_csr(KMF_HANDLE_T, const KMF_CSR_DATA *,
	KMF_KEY_HANDLE *, KMF_DATA *);
extern KMF_RETURN kmf_add_csr_eku(KMF_CSR_DATA *, KMF_OID *, int);

/*
 * GetCert operations.
 */
extern KMF_RETURN kmf_get_cert_extn(const KMF_DATA *, KMF_OID *,
	KMF_X509_EXTENSION *);

extern KMF_RETURN kmf_get_cert_extns(const KMF_DATA *, KMF_FLAG_CERT_EXTN,
	KMF_X509_EXTENSION **, int *);

extern KMF_RETURN kmf_get_cert_ku(const KMF_DATA *, KMF_X509EXT_KEY_USAGE *);

extern KMF_RETURN kmf_get_cert_eku(const KMF_DATA *, KMF_X509EXT_EKU *);

extern KMF_RETURN kmf_get_cert_basic_constraint(const KMF_DATA *,
	KMF_BOOL *, KMF_X509EXT_BASICCONSTRAINTS *);

extern KMF_RETURN kmf_get_cert_policies(const KMF_DATA *,
	KMF_BOOL *, KMF_X509EXT_CERT_POLICIES *);

extern KMF_RETURN kmf_get_cert_auth_info_access(const KMF_DATA *,
	KMF_X509EXT_AUTHINFOACCESS *);

extern KMF_RETURN kmf_get_cert_crl_dist_pts(const KMF_DATA *,
	KMF_X509EXT_CRLDISTPOINTS *);

extern KMF_RETURN kmf_get_cert_version_str(KMF_HANDLE_T, const KMF_DATA *,
	char **);

extern KMF_RETURN kmf_get_cert_subject_str(KMF_HANDLE_T, const KMF_DATA *,
	char **);

extern KMF_RETURN kmf_get_cert_issuer_str(KMF_HANDLE_T,	const KMF_DATA *,
	char **);

extern KMF_RETURN kmf_get_cert_serial_str(KMF_HANDLE_T, const KMF_DATA *,
	char **);

extern KMF_RETURN kmf_get_cert_start_date_str(KMF_HANDLE_T, const KMF_DATA *,
	char **);

extern KMF_RETURN kmf_get_cert_end_date_str(KMF_HANDLE_T, const KMF_DATA *,
	char **);

extern KMF_RETURN kmf_get_cert_pubkey_alg_str(KMF_HANDLE_T, const KMF_DATA *,
	char **);

extern KMF_RETURN kmf_get_cert_sig_alg_str(KMF_HANDLE_T, const KMF_DATA *,
	char **);

extern KMF_RETURN kmf_get_cert_pubkey_str(KMF_HANDLE_T,	const KMF_DATA *,
	char **);

extern KMF_RETURN kmf_get_cert_email_str(KMF_HANDLE_T, const KMF_DATA *,
	char **);

extern KMF_RETURN kmf_get_cert_extn_str(KMF_HANDLE_T, const KMF_DATA *,
	KMF_PRINTABLE_ITEM, char **);

extern KMF_RETURN kmf_get_cert_id_data(const KMF_DATA *, KMF_DATA *);

extern KMF_RETURN kmf_get_cert_id_str(const KMF_DATA *, char **);

extern KMF_RETURN kmf_get_cert_validity(const KMF_DATA *, time_t *, time_t *);


/*
 * SetCert operations
 */
extern KMF_RETURN kmf_set_cert_pubkey(KMF_HANDLE_T, KMF_KEY_HANDLE *,
	KMF_X509_CERTIFICATE *);

extern KMF_RETURN kmf_set_cert_subject(KMF_X509_CERTIFICATE *,
	KMF_X509_NAME *);

extern KMF_RETURN kmf_set_cert_ku(KMF_X509_CERTIFICATE *, int, uint16_t);

extern KMF_RETURN kmf_set_cert_issuer(KMF_X509_CERTIFICATE *,
	KMF_X509_NAME *);

extern KMF_RETURN kmf_set_cert_sig_alg(KMF_X509_CERTIFICATE *,
	KMF_ALGORITHM_INDEX);

extern KMF_RETURN kmf_set_cert_validity(KMF_X509_CERTIFICATE *,
	time_t, uint32_t);

extern KMF_RETURN kmf_set_cert_serial(KMF_X509_CERTIFICATE *,
	KMF_BIGINT *);

extern KMF_RETURN kmf_set_cert_version(KMF_X509_CERTIFICATE *, uint32_t);

extern KMF_RETURN kmf_set_cert_issuer_altname(KMF_X509_CERTIFICATE *,
	int, KMF_GENERALNAMECHOICES, char *);

extern KMF_RETURN kmf_set_cert_subject_altname(KMF_X509_CERTIFICATE *,
	int, KMF_GENERALNAMECHOICES, char *);

extern KMF_RETURN kmf_add_cert_eku(KMF_X509_CERTIFICATE *, KMF_OID *, int);

extern KMF_RETURN kmf_set_cert_extn(KMF_X509_CERTIFICATE *,
	KMF_X509_EXTENSION *);

extern KMF_RETURN kmf_set_cert_basic_constraint(KMF_X509_CERTIFICATE *,
	KMF_BOOL, KMF_X509EXT_BASICCONSTRAINTS *);


/*
 *  PK12 operations
 */
extern KMF_RETURN kmf_export_pk12(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

extern KMF_RETURN kmf_build_pk12(KMF_HANDLE_T, int, KMF_X509_DER_CERT *,
	int, KMF_KEY_HANDLE *, KMF_CREDENTIAL *, char *);

extern KMF_RETURN kmf_import_objects(KMF_HANDLE_T, char *, KMF_CREDENTIAL *,
	KMF_X509_DER_CERT **, int *, KMF_RAW_KEY_DATA **, int *);

/*
 * OCSP operations
 */
extern KMF_RETURN kmf_get_ocsp_for_cert(KMF_HANDLE_T, KMF_DATA *, KMF_DATA *,
	KMF_DATA *);

extern KMF_RETURN kmf_create_ocsp_request(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

extern KMF_RETURN kmf_get_encoded_ocsp_response(KMF_HANDLE_T, char *,
	char *, int, char *, int, char *, unsigned int);

extern KMF_RETURN kmf_get_ocsp_status_for_cert(KMF_HANDLE_T, int,
	KMF_ATTRIBUTE *);

/*
 * Policy Operations
 */
extern KMF_RETURN kmf_set_policy(KMF_HANDLE_T, char *, char *);

/*
 * Error handling.
 */
extern KMF_RETURN kmf_get_plugin_error_str(KMF_HANDLE_T, char **);
extern KMF_RETURN kmf_get_kmf_error_str(KMF_RETURN, char **);

/*
 * Miscellaneous
 */
extern KMF_RETURN kmf_dn_parser(char *, KMF_X509_NAME *);
extern KMF_RETURN kmf_dn_to_string(KMF_X509_NAME *, char **);
extern KMF_RETURN kmf_read_input_file(KMF_HANDLE_T, char *, KMF_DATA *);
extern KMF_RETURN kmf_der_to_pem(KMF_OBJECT_TYPE, unsigned char *,
	int, unsigned char **, int *);
extern KMF_RETURN kmf_pem_to_der(unsigned char *, int, unsigned char **, int *);
extern char *kmf_oid_to_string(KMF_OID *);
extern KMF_RETURN kmf_string_to_oid(char *, KMF_OID *);
extern int kmf_compare_rdns(KMF_X509_NAME *, KMF_X509_NAME *);
extern KMF_RETURN kmf_get_data_format(KMF_DATA *, KMF_ENCODE_FORMAT *);
extern KMF_RETURN kmf_get_file_format(char *, KMF_ENCODE_FORMAT *);
extern uint32_t kmf_string_to_ku(char *);
extern char *kmf_ku_to_string(uint32_t);
extern KMF_RETURN kmf_hexstr_to_bytes(unsigned char *, unsigned char **,
	size_t *);

extern KMF_RETURN kmf_get_plugin_info(KMF_HANDLE_T, char *,
	KMF_KEYSTORE_TYPE *, char **);

extern KMF_OID *kmf_ekuname_to_oid(char *);
extern char *kmf_oid_to_ekuname(KMF_OID *);

#define	KMF_CompareRDNs kmf_compare_rdns

/*
 * Memory cleanup operations
 */
extern void kmf_free_dn(KMF_X509_NAME *);
extern void kmf_free_kmf_cert(KMF_HANDLE_T, KMF_X509_DER_CERT *);
extern void kmf_free_data(KMF_DATA *);
extern void kmf_free_algoid(KMF_X509_ALGORITHM_IDENTIFIER *);
extern void kmf_free_extn(KMF_X509_EXTENSION *);
extern void kmf_free_tbs_csr(KMF_TBS_CSR *);
extern void kmf_free_signed_csr(KMF_CSR_DATA *);
extern void kmf_free_tbs_cert(KMF_X509_TBS_CERT *);
extern void kmf_free_signed_cert(KMF_X509_CERTIFICATE *);
extern void kmf_free_str(char *);
extern void kmf_free_eku(KMF_X509EXT_EKU *);
extern void kmf_free_spki(KMF_X509_SPKI *);
extern void kmf_free_kmf_key(KMF_HANDLE_T, KMF_KEY_HANDLE *);
extern void kmf_free_bigint(KMF_BIGINT *);
extern void kmf_free_raw_key(KMF_RAW_KEY_DATA *);
extern void kmf_free_raw_sym_key(KMF_RAW_SYM_KEY *);
extern void kmf_free_crl_dist_pts(KMF_X509EXT_CRLDISTPOINTS *);

/* APIs for PKCS#11 token */
extern KMF_RETURN kmf_pk11_token_lookup(KMF_HANDLE_T, char *, CK_SLOT_ID *);
extern KMF_RETURN kmf_pk11_init_token(KMF_HANDLE_T,
	char *, char *, CK_UTF8CHAR_PTR, CK_ULONG);
extern KMF_RETURN kmf_set_token_pin(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);
extern CK_SESSION_HANDLE kmf_get_pk11_handle(KMF_HANDLE_T);

/*
 * Attribute management routines.
 */
int kmf_find_attr(KMF_ATTR_TYPE, KMF_ATTRIBUTE *, int);
void *kmf_get_attr_ptr(KMF_ATTR_TYPE, KMF_ATTRIBUTE *, int);
KMF_RETURN kmf_get_attr(KMF_ATTR_TYPE, KMF_ATTRIBUTE *, int, void *,
	uint32_t *);
KMF_RETURN kmf_get_string_attr(KMF_ATTR_TYPE, KMF_ATTRIBUTE *, int, char **);
KMF_RETURN kmf_set_attr(KMF_ATTRIBUTE *, int, KMF_ATTR_TYPE, void *, uint32_t);
void kmf_set_attr_at_index(KMF_ATTRIBUTE *, int, KMF_ATTR_TYPE,
	void *, uint32_t);

/*
 * Certificate to name mapping functions.
 */
KMF_RETURN kmf_cert_to_name_mapping_initialize(KMF_HANDLE_T, int,
	KMF_ATTRIBUTE *);
KMF_RETURN kmf_cert_to_name_mapping_finalize(KMF_HANDLE_T);
KMF_RETURN kmf_map_cert_to_name(KMF_HANDLE_T, KMF_DATA *, KMF_DATA *);
KMF_RETURN kmf_match_cert_to_name(KMF_HANDLE_T, KMF_DATA *, KMF_DATA *,
	KMF_DATA *);
KMF_RETURN kmf_get_mapper_error_str(KMF_HANDLE_T, char **);
/*
 * Helper functions for handling the mapper internal state. They are part of the
 * public interface, too.
 */
void kmf_set_mapper_lasterror(KMF_HANDLE_T, uint32_t);
uint32_t kmf_get_mapper_lasterror(KMF_HANDLE_T);
void kmf_set_mapper_options(KMF_HANDLE_T, void *);
void *kmf_get_mapper_options(KMF_HANDLE_T);

#ifdef __cplusplus
}
#endif
#endif /* _KMFAPI_H */
