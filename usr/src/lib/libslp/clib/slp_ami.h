/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SLP_AMI_H
#define	_SLP_AMI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

typedef struct ami_oid {
    unsigned short  count;
    unsigned long   *value;
} ami_oid;

typedef struct Any {
    unsigned long   length;
    unsigned char   *value;
} Any;

typedef struct ami_rdn_seq *ami_dname;

typedef struct ami_name {
    unsigned short choice;
#define	distinguishedName_chosen 1
	union {
		struct ami_rdn_seq *distinguishedName;
	} u;
} ami_name;

typedef struct ami_rdn_seq {
    struct ami_rdn_seq *next;
    struct ami_rdname *value;
} *ami_rdn_seq;

typedef struct ami_rdname {
    struct ami_rdname *next;
    struct ami_ava  *value;
} *ami_rdname;

typedef Any ami_attr_value;

typedef struct ami_ava {
    struct ami_oid *objid;
    ami_attr_value  *value;
} ami_ava;

typedef struct ami_attr_list {
    struct ami_attr_list *next;
    struct ami_attr *value;
} *ami_attr_list;

typedef struct ami_attr {
    struct ami_oid *type;
    struct ami_attr_value_set *values;
} ami_attr;

typedef struct ami_attr_value_set {
    struct ami_attr_value_set *next;
    ami_attr_value  *value;
} *ami_attr_value_set;

typedef struct CaseIgnoreString {
    unsigned short choice;
#define	CaseIgnoreString_t61String_chosen 1
#define	CaseIgnoreString_printableString_chosen 2
	union {
		char *CaseIgnoreString_t61String;
		char *CaseIgnoreString_printableString;
	} u;
} CaseIgnoreString;

typedef CaseIgnoreString ami_case_ignore_string;

typedef char *ami_printable_string;

typedef struct ami_cert_pair {
    struct ami_cert *forward;  /* NULL for not present */
    struct ami_cert *reverse;  /* NULL for not present */
} ami_cert_pair;

typedef struct ami_cert_serialnum {
    unsigned short  length;
    unsigned char   *value;
} ami_cert_serialnum;

typedef struct ami_cert_info {
    unsigned char bit_mask;
#define	version_present 0x80
#define	extensions_present 0x40
    int version; /* default assumed if omitted */
#define	version_v1 0
#define	version_v2 1
#define	version_v3 2
    ami_cert_serialnum serial;
    struct ami_algid *signature;
    struct ami_name *issuer;
    struct ami_validity *validity;
    struct ami_name *subject;
    struct ami_pubkey_info *pubKeyInfo;
    struct ami_uid  *issuerUID;  /* NULL for not present */
    struct ami_uid  *subjectUID;  /* NULL for not present */
    struct ami_cert_extn_list *extensions;  /* optional */
} ami_cert_info;

typedef struct ami_bitstring {
    unsigned int    length;  /* number of significant bits */
    unsigned char   *value;
} ami_bitstring;

typedef struct ami_cert {
    ami_cert_info   info;
    struct ami_algid *algorithm;
    ami_bitstring   signature;
} ami_cert;

typedef struct ami_uid {
    unsigned int    length;  /* number of significant bits */
    unsigned char   *value;
} ami_uid;

typedef struct ami_octetstring {
    unsigned int    length;
    unsigned char   *value;
} ami_octetstring;

typedef int ami_cert_version;
#define	CertificateVersion_v1 0
#define	CertificateVersion_v2 1
#define	CertificateVersion_v3 2

typedef char amiBoolean;

typedef struct {
    short year; /* YYYY format when used for GeneralizedTime */
			/* YY format when used for UTCTime */
    short month;
    short day;
    short hour;
    short minute;
    short second;
    short millisec;
    short mindiff;  /* UTC +/- minute differential */
    amiBoolean utc; /* TRUE means UTC time */
} GeneralizedTime;

typedef GeneralizedTime UTCTime;

typedef struct ami_validity {
    UTCTime *notBefore;
    UTCTime *notAfter;
} ami_validity;

typedef struct ami_pubkey_info {
    struct ami_algid *algorithm;
    ami_bitstring   pubKey;
} ami_pubkey_info;

typedef Any ami_alg_params;

typedef struct ami_algid {
    struct ami_oid *algorithm;
    ami_alg_params *parameters;  /* NULL for not present */
} ami_algid;


typedef struct ami_cert_extn {
    unsigned char bit_mask;
#define	critical_present 0x80
    struct ami_oid *extend;
    amiBoolean critical;
    ami_octetstring extnValue;
} ami_cert_extn;

typedef struct ami_cert_extn_list {
    struct ami_cert_extn_list *next;
    struct ami_cert_extn *value;
} *ami_cert_extn_list;

typedef struct ami_cert_list_contents {
    unsigned char bit_mask;
#define	nextUpdate_present 0x80
#define	CertListContents_revokedCertificates_present 0x40
    ami_algid signature;
    ami_name issuer;
    UTCTime thisUpdate;
    UTCTime nextUpdate;
	struct _seqof1 {
		struct _seqof1  *next;
		struct {
			ami_cert_serialnum userCertificate;
			UTCTime revocationDate;
		} value;
	} *CertListContents_revokedCertificates;
} ami_cert_list_contents;

typedef struct ami_cert_list {
    ami_cert_list_contents certListContents;
    ami_algid algId;
    ami_bitstring signature;
} ami_cert_list;

typedef struct ami_rc2_cbc_param {
    unsigned short choice;
#define	 iv_chosen 1
#define	sequence_chosen 2
	union {
		ami_octetstring iv;
		struct _seq1 {
			int version;
			ami_octetstring iv;
		} sequence;
	} u;
} ami_rc2_cbc_param;

typedef int INT;

typedef struct ami_keypkg_info {
    unsigned char bit_mask;
#define	keypkgAttrs_present 0x80
#define	tKeys_present 0x40
    char *version;
    char *keypkgId;
    struct ami_name *owner;
    struct ami_pubkey_info *pubKeyInfo;
    struct ami_encr_privkey_info *encrPrivKeyInfo;
    struct ami_attr_list *keypkgAttrs;  /* optional */
    int usage;
    struct ami_tkey_list *tKeys;  /* optional */
} ami_keypkg_info;

typedef struct ami_keypkg {
    ami_keypkg_info info;
    struct ami_algid *algorithm;
    ami_bitstring   signature;
} ami_keypkg;

typedef struct ami_tkey_list {
    struct ami_tkey_list *next;
    struct ami_tkey *value;
} *ami_tkey_list;

typedef struct ami_tkey {
    unsigned char bit_mask;
#define	TrustedKey_extensions_present 0x80
    struct ami_name *owner;
    struct ami_pubkey_info *pubKeyInfo;
    struct ami_name *issuer;  /* NULL for not present */
    struct ami_validity *validity;  /* NULL for not present */
    struct ami_cert_serialnum *serial;  /* NULL for not present */
    struct ami_cert_extn_list *TrustedKey_extensions;  /* optional */
} ami_tkey;

typedef struct ami_serv_key_info {
    Any keyAlgId;
    int uid;
    int flags;
    Any privKey;
    char *keypkgId;
    char *hostIP;
    Any keypkg;
} ami_serv_key_info;

typedef struct _octet1 {
    unsigned int    length;
    unsigned char   *value;
} _octet1;

typedef struct ami_digest_info {
    struct ami_algid *digestAlgorithm;
    _octet1 digest;
} ami_digest_info;

typedef struct ami_crl_set {
    struct ami_crl_set *next;
    struct ami_crl  *value;
} *ami_crl_set;

typedef struct ami_crl_entry {
    int userCertificate;
    UTCTime *revocationDate;
} ami_crl_entry;

typedef struct ami_crl_info {
    unsigned char bit_mask;
#define	CertificateRevocationListInfo_revokedCertificates_present 0x80
    struct ami_algid *signature;
    struct ami_name *issuer;
    UTCTime *lastUpdate;
    UTCTime  *nextUpdate;
	struct _seqof2 {
		struct _seqof2 *next;
		ami_crl_entry value;
	} *CertificateRevocationListInfo_revokedCertificates;
} ami_crl_info;

typedef struct ami_crl {
    ami_crl_info info;
    struct ami_algid *algorithm;
    ami_bitstring signature;
} ami_crl;

typedef struct ami_pbe_param {
	struct {
		unsigned short  length;
		unsigned char   value[8];
	} salt;
    int iterationCount;
} ami_pbe_param;

typedef struct ami_extcert_info {
    int version;
    struct ami_cert *certificate;
    struct ami_attr_list *attributes;
} ami_extcert_info;

typedef struct ami_extcert {
    struct ami_extcert_info *extendedCertificateInfo;
    struct ami_algid *signatureAlgorithm;
    ami_bitstring signature;
} ami_extcert;

typedef struct ami_extcerts_and_certs {
    struct ami_extcerts_and_certs *next;
    struct ami_extcert_or_cert *value;
} *ami_extcerts_and_certs;

typedef struct ami_extcert_or_cert {
    unsigned short choice;
#define	cert_chosen 1
#define	 extendedCert_chosen 2
	union {
		struct ami_cert *cert;
		struct ami_extcert *extendedCert;
	} u;
} ami_extcert_or_cert;

typedef Any Content;

typedef struct ami_content_info {
    struct ami_oid *contentType;
    Content *content;  /* NULL for not present */
} ami_content_info;

typedef struct ami_content_info_fm {
    struct ami_oid *contentType;
    Content *content;  /* NULL for not present */
} ami_content_info_fm;

typedef struct ami_enveloped_data {
    int version;
    struct ami_rcpt_info_list *recipientInfos;
    struct ami_encr_content_info *encryptedContentInfo;
} ami_enveloped_data;

typedef struct ami_encr_data {
    int version;
    struct ami_encr_content_info *encryptedContentInfo;
} ami_encr_data;

typedef struct ami_signed_data {
    unsigned char bit_mask;
#define	SignedData_certs_present 0x80
#define	SignedData_crls_present 0x40
    int version;
    struct ami_digest_alg_list *digestAlgorithms;
    struct ami_content_info *contentInfo;
    struct ami_extcerts_and_certs *SignedData_certs;  /* optional */
    struct ami_crl_set *SignedData_crls;  /* optional */
    struct ami_signer_info_list *signerInfos;
} ami_signed_data;

typedef struct ami_signed_data_fm {
    unsigned char bit_mask;
#define	SignedDataFm_certs_present 0x80
#define	SignedDataFm_crls_present 0x40
    int version;
    struct ami_digest_alg_list *digestAlgorithms;
    struct ami_content_info_fm *contentInfo;
    struct ami_extcerts_and_certs *SignedDataFm_certs;  /* optional */
    struct ami_crl_set *SignedDataFm_crls;  /* optional */
    struct ami_signer_info_list *signerInfos;
} ami_signed_data_fm;

typedef struct ami_rcpt_info_list {
    struct ami_rcpt_info_list *next;
    struct ami_rcpt_info *value;
} *ami_rcpt_info_list;

typedef struct ami_encr_content_info {
    struct ami_oid *contentType;
    struct ami_algid *contentEncryptionAlgorithm;
    struct ami_encr_content *encryptedContent;  /* NULL for not present */
} ami_encr_content_info;

typedef struct ami_pkcs_data {
    unsigned int length;
    unsigned char *value;
} ami_pkcs_data;

typedef struct ami_pkcs_data_fm {
    unsigned int length;
    unsigned char *value;
} ami_pkcs_data_fm;

typedef struct ami_encr_content {
    unsigned int length;
    unsigned char *value;
} ami_encr_content;

typedef struct ami_rcpt_info {
    int version;
    struct ami_issuer_and_serialnum *issuerAndSerialNumber;
    struct ami_algid *keyEncryptionAlgorithm;
    _octet1 encryptedKey;
} ami_rcpt_info;

typedef struct ami_signer_info {
    unsigned char bit_mask;
#define	authenticatedAttributes_present 0x80
#define	unauthenticatedAttributes_present 0x40
    int version;
    struct ami_issuer_and_serialnum *issuerAndSerialNumber;
    struct ami_algid *digestAlgorithm;
    struct ami_attr_list *authenticatedAttributes;  /* optional */
    struct ami_algid *digestEncryptionAlgorithm;
    _octet1 encryptedDigest;
    struct ami_attr_list *unauthenticatedAttributes;  /* optional */
} ami_signer_info;

typedef struct ami_signer_info_list {
    struct ami_signer_info_list *next;
    struct ami_signer_info *value;
} *ami_signer_info_list;

typedef struct ami_issuer_and_serialnum {
    struct ami_name *issuer;
    ami_cert_serialnum serial;
} ami_issuer_and_serialnum;

typedef struct ami_digest_alg_list {
    struct ami_digest_alg_list *next;
    struct ami_algid *value;
} *ami_digest_alg_list;

typedef struct ami_privkey_info {
    unsigned char   bit_mask;
#define	attributes_present 0x80
    int version;
    struct ami_algid *privateKeyAlgorithm;
    _octet1 privateKey;
    struct ami_attr_list *attributes;  /* optional */
} ami_privkey_info;

typedef struct ami_encr_privkey_info {
    struct ami_algid *encryptionAlgorithm;
    ami_octetstring encryptedData;
} ami_encr_privkey_info;

typedef struct ami_certreq_info {
    int version;
    struct ami_name *subject;
    struct ami_pubkey_info *pubKeyInfo;
    struct ami_attr_list *attributes;
} ami_certreq_info;

typedef struct ami_certreq {
    ami_certreq_info info;
    struct ami_algid *algorithm;
    ami_bitstring   signature;
} ami_certreq;

typedef struct ami_challenge_pwd {
    unsigned short  choice;
#define	ChallengePassword_printableString_chosen 1
#define	ChallengePassword_t61String_chosen 2
	union {
		char *ChallengePassword_printableString;
		char *ChallengePassword_t61String;
	} u;
} ami_challenge_pwd;

typedef char *ami_email_addr;

typedef struct ami_pubkey_and_challenge {
	struct ami_pubkey_info *spki;
	char *challenge;
} ami_pubkey_and_challenge;

typedef struct ami_signed_pubkey_and_challenge {
    ami_pubkey_and_challenge pubKeyAndChallenge;
    struct ami_algid *sigAlg;
    ami_bitstring   signature;
} ami_signed_pubkey_and_challenge;

extern ami_oid *AMI_MD2_OID;
extern ami_oid *AMI_MD4_OID;
extern ami_oid *AMI_MD5_OID;
extern ami_oid *AMI_SHA_1_OID;
extern ami_oid *AMI_RSA_ENCR_OID;
extern ami_oid *AMI_MD2WithRSAEncryption_OID;
extern ami_oid *AMI_MD5WithRSAEncryption_OID;
extern ami_oid *AMI_DSA_OID;
extern ami_oid *AMI_SHA1WithDSASignature_OID;
extern ami_oid *AMI_DES_ECB_OID;
extern ami_oid *AMI_DES_CBC_OID;
extern ami_oid *AMI_DES3_CBC_OID;
extern ami_oid *AMI_DES_MAC_OID;
extern ami_oid *AMI_RC2_CBC_OID;
extern ami_oid *AMI_RC4_OID;

/*
 * Misc. AlgIDs
 */
extern struct ami_algid *AMI_RSA_ENCR_AID;
extern struct ami_algid *AMI_MD2WithRSAEncryption_AID;
extern struct ami_algid *AMI_MD5WithRSAEncryption_AID;
extern struct ami_algid *AMI_DSA_AID;
extern struct ami_algid *AMI_SHA1WithDSASignature_AID;
extern struct ami_algid *AMI_DH_AID;
extern struct ami_algid *AMI_MD2_AID;
extern struct ami_algid *AMI_MD4_AID;
extern struct ami_algid *AMI_MD5_AID;
extern struct ami_algid *AMI_SHA1_AID;
extern struct ami_algid *AMI_RC4_AID;

/* Algorithm types */
typedef enum {
	AMI_OTHER_ALG = -1,
	AMI_SYM_ENC_ALG,
	AMI_ASYM_ENC_ALG,
	AMI_HASH_ALG,
	AMI_SIG_ALG,
	AMI_KEYED_INTEGRITY_ALG
} ami_alg_type;

/* Parameter types */
typedef enum {
	AMI_PARM_OTHER = -1,
	AMI_PARM_ABSENT,
	AMI_PARM_INTEGER,
	AMI_PARM_OCTETSTRING,
	AMI_PARM_NULL,
	AMI_PARM_RC2_CBC,
	AMI_PARM_PBE
} ami_parm_type;

/* Algorithm table */
#define	AMI_NO_EXPORT_KEYSIZE_LIMIT	0
typedef struct ami_alg_list {
	ami_oid	*oid;
	char		*name;
	ami_alg_type	algType;
	ami_parm_type	parmType;
	size_t		keysize_limit;
} ami_alg_list;

/*
 * AMI function return values
 */

#define	AMI_OK				0
#define	AMI_EBUFSIZE			1
#define	AMI_ENOMEM			2	/* ENOMEM MUST be 2 */
#define	AMI_BAD_FILE			3
#define	AMI_FILE_NOT_FOUND		4
#define	AMI_FILE_IO_ERR			5
#define	AMI_BAD_PASSWD			6
#define	AMI_UNKNOWN_USER		7
#define	AMI_ALGORITHM_UNKNOWN		8
#define	AMI_ASN1_ENCODE_ERR		9
#define	AMI_ASN1_DECODE_ERR		10
#define	AMI_BAD_KEY			11
#define	AMI_KEYGEN_ERR			12
#define	AMI_ENCRYPT_ERR			13
#define	AMI_DECRYPT_ERR			14
#define	AMI_SIGN_ERR			15
#define	AMI_VERIFY_ERR			16
#define	AMI_DIGEST_ERR			17
#define	AMI_OUTPUT_FORMAT_ERR		18
#define	AMI_SYSTEM_ERR			19	/* General Errors */
#define	AMI_ATTRIBUTE_UNKNOWN		20
#define	AMI_AMILOGIN_ERR		21
#define	AMI_AMILOGOUT_ERR		22
#define	AMI_NO_SUCH_ENTRY		23
#define	AMI_ENTRY_ALREADY_EXISTS	24
#define	AMI_AMISERV_DECRYPT_ERR		25
#define	AMI_AMISERV_SIGN_ERR		26
#define	AMI_USER_DID_NOT_AMILOGIN	27
#define	AMI_AMISERV_CONNECT		28
#define	AMI_KEYPKG_NOT_FOUND		29
#define	AMI_TIME_INVALID		30
#define	AMI_UNTRUSTED_PUBLIC_KEY	31
#define	AMI_EPARM			32	/* EPARM MUST be 32 */
#define	AMI_BINARY_TO_RFC1421_ERR	33
#define	AMI_RFC1421_TO_BINARY_ERR	34
#define	AMI_RANDOM_NUM_ERR		35
#define	AMI_XFN_ERR			36
#define	AMI_CERT_CHAIN_ERR		37
#define	AMI_RDN_MISSING_EQUAL		38
#define	AMI_AVA_TYPE_MISSING		39
#define	AMI_AVA_VALUE_MISSING		40
#define	AMI_CERT_NOT_FOUND		41
#define	AMI_DN_NOT_FOUND		42
#define	AMI_CRITICAL_EXTNS_ERR		43
#define	AMI_ASN1_INIT_ERROR		44
#define	AMI_WRAP_ERROR			45
#define	AMI_UNWRAP_ERROR		46
#define	AMI_UNSUPPORTED_KEY_TYPE	47
#define	AMI_DH_PART1_ERR		48
#define	AMI_DH_PART2_ERR		49
#define	AMI_DOUBLE_ENCRYPT		50
#define	AMI_AMISERV_KEYPKG_UPDATE	51
#define	AMI_AMISERV_STAT_ERR		52
#define	AMI_GLOBAL_ERR			53
#define	AMI_TRUSTED_KEY_EXPIRED		54
#define	AMI_OPEN_ERR		55
#define	AMI_TOTAL_ERRNUM		56
#define	AMI_CERT_ERR		57
#define	AMI_KEYPKG_ERR		58

/* flags for ami_encrypt, ami_decrypt, ami_sign, ami_verify, ami_digest */
#define	AMI_ADD_DATA	1
#define	AMI_END_DATA	2
#define	AMI_DIGESTED_DATA 3 /* for ami_verify for digested data */

/* AMI Handle and status */
typedef struct ami_handle ami_handle_t;

/* AMI return variable */
typedef int AMI_STATUS;

/*
 * Parameter
 */

typedef struct ami_rsa_keygen_param_t {
	uint_t modulusBits;
	uchar_t *publicExponent; /* const */
	size_t publicExponentLen;
} ami_rsa_keygen_param;

typedef struct ami_des_keygen_param_t {
	uchar_t *saltVal; /* const */
	size_t saltLen;
	char *passwd; /* const */
	int iterationCount;
} ami_des_keygen_param;

/*
 * PROTOTYPES should be set to one if and only if the compiler supports
 * function argument prototyping.
 * The following makes PROTOTYPES default to 1 if it has not already been
 * defined as 0 with C compiler flags.
 */
#ifndef	PROTOTYPES
#define	PROTOTYPES	1
#endif

/*
 * PROTO_LIST is defined depending on how PROTOTYPES is defined above.
 * If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
 * returns an empty list.
 */

#if PROTOTYPES
#define	PROTO_LIST(list) list
#else
#define	PROTO_LIST(list) ()
#endif

/*
 * AMI prototypes
 */

/* Init and Terminate a AMI session */
AMI_STATUS ami_init PROTO_LIST((
	ami_handle_t **,
	const char *,
	const char *,
	const uint_t,
	const uint_t,
	const char *));

AMI_STATUS ami_end PROTO_LIST((
	ami_handle_t *));

char *ami_strerror PROTO_LIST((
	ami_handle_t *,
	const AMI_STATUS));	/* errno */

/* Key generation */
AMI_STATUS ami_gen_des_key PROTO_LIST((
	const ami_handle_t *,	/* IN:	ami handle */
	uchar_t **,		/* OUT: DES session key */
	ami_alg_params **));	/* OUT: IV */

AMI_STATUS ami_gen_des3_key PROTO_LIST((
	const ami_handle_t *,	/* IN:	ami handle */
	uchar_t **,		/* OUT: triple DES session key */
	ami_alg_params **));	/* OUT: IV */

AMI_STATUS ami_gen_rc2_key PROTO_LIST((
	const ami_handle_t *,	/* IN:  AMI handle */
	const size_t,		/* IN:  key length */
	const uint_t,		/* IN:  effective key size in bits */
	uchar_t **,		/* OUT: RC2 session key */
	ami_alg_params **));	/* OUT: RC2 parameter */

AMI_STATUS ami_gen_rc4_key PROTO_LIST((
	const ami_handle_t *,	/* IN:	ami handle */
	const size_t,		/* IN:  key length in bytes */
	uchar_t **));		/* OUT: RC4 key */

AMI_STATUS ami_gen_rsa_keypair PROTO_LIST((
	const ami_handle_t *,		/* IN:	ami handle */
	const ami_rsa_keygen_param *,	/* IN:  keypair generation parameters */
	const uchar_t *,
	const size_t,
	uchar_t **,			/* OUT: public key */
	size_t *,			/* OUT: public key length */
	uchar_t **,			/* OUT: private key */
	size_t *));			/* OUT: private key length */

/* crypto */
AMI_STATUS ami_digest PROTO_LIST((
	ami_handle_t *,			/* IN:	ami handle */
	const uchar_t *,		/* IN:  input data  */
	const size_t,			/* IN:  length of data in bytes */
	const int,			/* IN:  more input data flag */
	const ami_algid *,		/* IN:  digest algorithm */
	uchar_t **,			/* OUT: digest */
	size_t *));			/* OUT: length of digest */
AMI_STATUS ami_sign PROTO_LIST((
	ami_handle_t *,			/* IN:	ami handle */
	const uchar_t *,		/* IN:  data to be signed */
	const size_t,			/* IN:  data length */
	const int,			/* IN:  more input data flag */
	const ami_algid *,		/* IN:  signature key algorithm */
	const uchar_t *,		/* IN:  signature key */
	const size_t,			/* IN:  signature key length */
	const ami_algid *,		/* IN:  signature algorithm */
	uchar_t **, 			/* OUT: signature */
	size_t *));			/* OUT: signature length */
AMI_STATUS ami_verify PROTO_LIST((
	ami_handle_t *,			/* IN: ami handle */
	const uchar_t *, 		/* IN: data to be verified */
	const size_t,			/* IN: data length */
	const int,			/* IN: more input data flag */
	const ami_algid *,		/* IN: verification key algorithm */
	const uchar_t *,		/* IN: verification key */
	const size_t,			/* IN: verification key length */
	const ami_algid *,		/* IN: verification algorithm */
	const uchar_t *, 		/* IN: signature */
	const size_t));			/* IN: signature length */
AMI_STATUS ami_encrypt PROTO_LIST((
	ami_handle_t *,			/* IN:	ami handle */
	const uchar_t *,		/* IN:  input data */
	const size_t,			/* IN:  input data length */
	const int,			/* IN:	more input data flag */
	const ami_algid *,		/* IN:  encryption key algorithm */
	const uchar_t *,		/* IN:  encryption key */
	const size_t,			/* IN:  encryption key length */
	const ami_algid *,		/* IN:  encryption algorithm */
	uchar_t **,			/* OUT: ciphertext */
	size_t *));			/* OUT: ciphertext length */
AMI_STATUS ami_decrypt PROTO_LIST((
	ami_handle_t *,			/* IN:	ami handle */
	const uchar_t *,		/* IN:  ciphertext */
	const size_t,			/* IN:  ciphertext length */
	const int,			/* IN:  more input data flag */
	const ami_algid *,		/* IN:  decryption key algorithm */
	const uchar_t *,		/* IN:  decryption key */
	const size_t,			/* IN:  decryption key length */
	const ami_algid *,		/* IN:  decryption algorithm */
	uchar_t **,			/* OUT: cleartext */
	size_t *));			/* OUT: cleartext length */
AMI_STATUS ami_wrap_key PROTO_LIST((
	const ami_handle_t *,		/* IN:  ami handle */
	const uchar_t *,		/* IN:	key to be wrapped  */
	const size_t,			/* IN:	length of key to be wrapped */
	const ami_algid *,		/* IN:	wrapping key algorithm */
	const uchar_t *,		/* IN:	wrapping key */
	const size_t,			/* IN:	wrapping key length */
	const ami_algid *,		/* IN:	wrapping algorithm */
	uchar_t **,			/* OUT: wrapped key */
	size_t *));			/* IN/OUT: wrapped key length */
AMI_STATUS ami_unwrap_key PROTO_LIST((
	const ami_handle_t *,		/* IN:  ami handle */
	const uchar_t *,		/* IN:  wrapped key */
	const size_t,			/* IN:  wrapped key length */
	const ami_algid *,		/* IN:  unwrapping key algorithm */
	const uchar_t *,		/* IN:  unwrapping key */
	const size_t,			/* IN:  unwrapping key length */
	const ami_algid *,		/* IN:  unwrapping algorithm */
	uchar_t **,			/* OUT: unwrapped key */
	size_t *));			/* OUT: unwrapped key length */

/* certificate verification */
AMI_STATUS ami_verify_cert PROTO_LIST((
	const ami_handle_t *,		/* IN: ami handle */
	const ami_cert *, 		/* IN: certificate to be verified */
	const ami_pubkey_info *,	/* IN: public verification key */
	const int));			/* IN: flags (unused) */
AMI_STATUS ami_verify_cert_chain PROTO_LIST((
	const ami_handle_t *,		/* IN: ami handle */
	const ami_cert *, 	/* IN: certificate chain to be verified */
	const int,			/* IN: length of cert chain */
	const struct ami_tkey_list *,	/* IN: trusted key list */
	const int,			/* IN: flags (unused) */
	ami_cert **));		/* OUT: first expired certificate */
AMI_STATUS ami_verify_cert_est_chain PROTO_LIST((
	const ami_handle_t *,		/* IN: ami handle */
	const ami_cert *, 		/* IN: certificate to be verified */
	const struct ami_tkey_list *,	/* IN: trusted key list */
	const char **,			/* IN: CA Name list */
	const int,			/* IN: flags (unused) */
	ami_cert **,			/* OUT: first expired certificate */
	ami_cert **,			/* OUT: certificate chain */
	int *));			/* OUT: length of cert chain */

/* certificate chain establishment */
AMI_STATUS ami_get_cert_chain PROTO_LIST((
	const ami_handle_t *,	/* IN: ami handle */
	const ami_cert *,	/* IN: user certificate */
	const char **,		/* IN: CA name list */
	int flags,		/* IN: flags (unused) */
	ami_cert **,		/* OUT: certificate chain */
	int *));		/* OUT: length of cert chain */

/* I/O */
AMI_STATUS ami_set_keypkg PROTO_LIST((
	const ami_handle_t *,	/* IN: ami handle */
	const char *,		/* IN: keypkg filename or repository index */
	const ami_keypkg *));	/* IN: keypkg to be stored */
AMI_STATUS ami_get_keypkg PROTO_LIST((
	const ami_handle_t *,	/* IN:	ami handle */
	const char *,		/* IN:  keypkg_filename or repository index */
	ami_keypkg **));		/* OUT: keypkg */
AMI_STATUS ami_set_cert PROTO_LIST((
	const ami_handle_t *,	/* IN: ami handle */
	const char *,		/* IN: cert filename or repository index */
	const ami_cert *));	/* IN: certificate */
AMI_STATUS ami_get_cert PROTO_LIST((
	const ami_handle_t *,	/* IN:	ami handle */
	const char *,		/* IN:  certificate filename, rep index, DN */
	ami_cert **,		/* OUT: set of certificates */
	int *));		/* OUT: certificate set length */

/* generate random bytes */
AMI_STATUS ami_random PROTO_LIST((
	const ushort_t,		/* IN:  requested number of random bytes */
	uchar_t **));		/* OUT: random byte buffer */


/* Free */
void ami_free_keypkg PROTO_LIST((ami_keypkg **));
void ami_free_cert PROTO_LIST((ami_cert **));
void ami_free_cert_list PROTO_LIST((ami_cert **, int));
void ami_free_dn PROTO_LIST((ami_name **));

/* DN */
AMI_STATUS ami_str2dn PROTO_LIST((
	const ami_handle_t *, char *, ami_name **));
AMI_STATUS ami_dn2str PROTO_LIST((
	const ami_handle_t *, ami_name *, char **));

/* Supported algorithms */
AMI_STATUS ami_get_alglist PROTO_LIST((ami_alg_list **));

#ifdef	__cplusplus
}
#endif

#endif	/* _SLP_AMI_H */
