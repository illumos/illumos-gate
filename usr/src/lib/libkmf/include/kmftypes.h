/*
 * Copyright (c) 1995-2000 Intel Corporation. All rights reserved.
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _KMFTYPES_H
#define	_KMFTYPES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdlib.h>
#include <strings.h>
#include <pthread.h>

#include <security/cryptoki.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t KMF_BOOL;

#define	KMF_FALSE (0)
#define	KMF_TRUE  (1)

/* KMF_HANDLE_T is a pointer to an incomplete C struct for type safety. */
typedef struct _kmf_handle *KMF_HANDLE_T;

/*
 * KMF_DATA
 * The KMF_DATA structure is used to associate a length, in bytes, with
 * an arbitrary block of contiguous memory.
 */
typedef struct kmf_data
{
    size_t	Length; /* in bytes */
    uchar_t	*Data;
} KMF_DATA;

typedef struct {
	uchar_t		*val;
	size_t		len;
} KMF_BIGINT;

/*
 * KMF_OID
 * The object identifier (OID) structure is used to hold a unique identifier for
 * the atomic data fields and the compound substructure that comprise the fields
 * of a certificate or CRL.
 */
typedef KMF_DATA KMF_OID;

typedef struct kmf_x509_private {
	int	keystore_type;
	int	flags;			/* see below */
	char	*label;
#define	KMF_FLAG_CERT_VALID	1	/* contains valid certificate */
#define	KMF_FLAG_CERT_SIGNED	2	/* this is a signed certificate */
} KMF_X509_PRIVATE;

/*
 * KMF_X509_DER_CERT
 * This structure associates packed DER certificate data.
 * Also, it contains the private information internal used
 * by KMF layer.
 */
typedef struct
{
	KMF_DATA		certificate;
	KMF_X509_PRIVATE	kmf_private;
} KMF_X509_DER_CERT;

typedef int KMF_KEYSTORE_TYPE;
#define	KMF_KEYSTORE_NSS	1
#define	KMF_KEYSTORE_OPENSSL	2
#define	KMF_KEYSTORE_PK11TOKEN	3

#define	VALID_DEFAULT_KEYSTORE_TYPE(t) ((t >= KMF_KEYSTORE_NSS) &&\
	(t <= KMF_KEYSTORE_PK11TOKEN))

typedef enum {
	KMF_FORMAT_UNDEF =	0,
	KMF_FORMAT_ASN1 =	1,	/* DER */
	KMF_FORMAT_PEM =	2,
	KMF_FORMAT_PKCS12 =	3,
	KMF_FORMAT_RAWKEY =	4,	/* For FindKey operation */
	KMF_FORMAT_PEM_KEYPAIR = 5
} KMF_ENCODE_FORMAT;

#define	KMF_FORMAT_NATIVE KMF_FORMAT_UNDEF

typedef enum {
	KMF_ALL_CERTS =		0,
	KMF_NONEXPIRED_CERTS =	1,
	KMF_EXPIRED_CERTS =	2
} KMF_CERT_VALIDITY;


typedef enum {
	KMF_ALL_EXTNS =		0,
	KMF_CRITICAL_EXTNS = 	1,
	KMF_NONCRITICAL_EXTNS =	2
} KMF_FLAG_CERT_EXTN;


typedef enum {
	KMF_KU_SIGN_CERT	= 0,
	KMF_KU_SIGN_DATA	= 1,
	KMF_KU_ENCRYPT_DATA	= 2
} KMF_KU_PURPOSE;

/*
 * Algorithms
 * This type defines a set of constants used to identify cryptographic
 * algorithms.
 */
typedef enum {
	KMF_ALGID_NONE	= 0,
	KMF_ALGID_CUSTOM,
	KMF_ALGID_SHA1,
	KMF_ALGID_RSA,
	KMF_ALGID_DSA,
	KMF_ALGID_MD5WithRSA,
	KMF_ALGID_MD2WithRSA,
	KMF_ALGID_SHA1WithRSA,
	KMF_ALGID_SHA1WithDSA
} KMF_ALGORITHM_INDEX;


/*
 * Generic credential structure used by other structures below
 * to convey authentication information to the underlying
 * mechanisms.
 */
typedef struct {
	char *cred;
	uint32_t credlen;
} KMF_CREDENTIAL;

typedef enum {
	KMF_KEYALG_NONE = 0,
	KMF_RSA = 1,
	KMF_DSA = 2,
	KMF_AES = 3,
	KMF_RC4 = 4,
	KMF_DES = 5,
	KMF_DES3 = 6,
	KMF_GENERIC_SECRET = 7
}KMF_KEY_ALG;

typedef enum {
	KMF_KEYCLASS_NONE = 0,
	KMF_ASYM_PUB = 1,	/* public key of an asymmetric keypair */
	KMF_ASYM_PRI = 2,	/* private key of an asymmetric keypair */
	KMF_SYMMETRIC = 3	/* symmetric key */
}KMF_KEY_CLASS;


typedef enum {
	KMF_CERT = 0,
	KMF_CSR = 1,
	KMF_CRL = 2
}KMF_OBJECT_TYPE;


typedef struct {
	KMF_BIGINT	mod;
	KMF_BIGINT	pubexp;
	KMF_BIGINT	priexp;
	KMF_BIGINT	prime1;
	KMF_BIGINT	prime2;
	KMF_BIGINT	exp1;
	KMF_BIGINT	exp2;
	KMF_BIGINT	coef;
} KMF_RAW_RSA_KEY;

typedef struct {
	KMF_BIGINT	prime;
	KMF_BIGINT	subprime;
	KMF_BIGINT	base;
	KMF_BIGINT	value;
	KMF_BIGINT	pubvalue;
} KMF_RAW_DSA_KEY;

typedef struct {
	KMF_BIGINT	keydata;
} KMF_RAW_SYM_KEY;

typedef struct {
	KMF_KEY_ALG	keytype;
	boolean_t	sensitive;
	boolean_t	not_extractable;
	union {
		KMF_RAW_RSA_KEY	rsa;
		KMF_RAW_DSA_KEY	dsa;
		KMF_RAW_SYM_KEY	sym;
	}rawdata;
	char *label;
	KMF_DATA id;
} KMF_RAW_KEY_DATA;

typedef struct {
	KMF_KEYSTORE_TYPE	kstype;
	KMF_KEY_ALG		keyalg;
	KMF_KEY_CLASS		keyclass;
	boolean_t		israw;
	char			*keylabel;
	void			*keyp;
} KMF_KEY_HANDLE;

typedef struct {
	KMF_KEYSTORE_TYPE	kstype;
	uint32_t		errcode;
} KMF_ERROR;

/*
 * Typenames to use with subjectAltName
 */
typedef enum {
	GENNAME_OTHERNAME	= 0x00,
	GENNAME_RFC822NAME,
	GENNAME_DNSNAME,
	GENNAME_X400ADDRESS,
	GENNAME_DIRECTORYNAME,
	GENNAME_EDIPARTYNAME,
	GENNAME_URI,
	GENNAME_IPADDRESS,
	GENNAME_REGISTEREDID
} KMF_GENERALNAMECHOICES;

/*
 * KMF_FIELD
 * This structure contains the OID/value pair for any item that can be
 * identified by an OID.
 */
typedef struct
{
	KMF_OID		FieldOid;
	KMF_DATA	FieldValue;
} KMF_FIELD;

typedef enum {
	KMF_OK			= 0x00,
	KMF_ERR_BAD_PARAMETER	= 0x01,
	KMF_ERR_BAD_KEY_FORMAT	= 0x02,
	KMF_ERR_BAD_ALGORITHM	= 0x03,
	KMF_ERR_MEMORY		= 0x04,
	KMF_ERR_ENCODING	= 0x05,
	KMF_ERR_PLUGIN_INIT	= 0x06,
	KMF_ERR_PLUGIN_NOTFOUND	= 0x07,
	KMF_ERR_INTERNAL	= 0x0b,
	KMF_ERR_BAD_CERT_FORMAT	= 0x0c,
	KMF_ERR_KEYGEN_FAILED	= 0x0d,
	KMF_ERR_UNINITIALIZED	= 0x10,
	KMF_ERR_ISSUER		= 0x11,
	KMF_ERR_NOT_REVOKED	= 0x12,
	KMF_ERR_CERT_NOT_FOUND	= 0x13,
	KMF_ERR_CRL_NOT_FOUND	= 0x14,
	KMF_ERR_RDN_PARSER	= 0x15,
	KMF_ERR_RDN_ATTR	= 0x16,
	KMF_ERR_SLOTNAME	= 0x17,
	KMF_ERR_EMPTY_CRL	= 0x18,
	KMF_ERR_BUFFER_SIZE	= 0x19,
	KMF_ERR_AUTH_FAILED	= 0x1a,
	KMF_ERR_TOKEN_SELECTED	= 0x1b,
	KMF_ERR_NO_TOKEN_SELECTED	= 0x1c,
	KMF_ERR_TOKEN_NOT_PRESENT	= 0x1d,
	KMF_ERR_EXTENSION_NOT_FOUND	= 0x1e,
	KMF_ERR_POLICY_ENGINE		= 0x1f,
	KMF_ERR_POLICY_DB_FORMAT	= 0x20,
	KMF_ERR_POLICY_NOT_FOUND	= 0x21,
	KMF_ERR_POLICY_DB_FILE		= 0x22,
	KMF_ERR_POLICY_NAME		= 0x23,
	KMF_ERR_OCSP_POLICY		= 0x24,
	KMF_ERR_TA_POLICY		= 0x25,
	KMF_ERR_KEY_NOT_FOUND		= 0x26,
	KMF_ERR_OPEN_FILE		= 0x27,
	KMF_ERR_OCSP_BAD_ISSUER		= 0x28,
	KMF_ERR_OCSP_BAD_CERT		= 0x29,
	KMF_ERR_OCSP_CREATE_REQUEST	= 0x2a,
	KMF_ERR_CONNECT_SERVER		= 0x2b,
	KMF_ERR_SEND_REQUEST		= 0x2c,
	KMF_ERR_OCSP_CERTID		= 0x2d,
	KMF_ERR_OCSP_MALFORMED_RESPONSE	= 0x2e,
	KMF_ERR_OCSP_RESPONSE_STATUS	= 0x2f,
	KMF_ERR_OCSP_NO_BASIC_RESPONSE	= 0x30,
	KMF_ERR_OCSP_BAD_SIGNER		= 0x31,

	KMF_ERR_OCSP_RESPONSE_SIGNATURE	= 0x32,
	KMF_ERR_OCSP_UNKNOWN_CERT	= 0x33,
	KMF_ERR_OCSP_STATUS_TIME_INVALID	= 0x34,
	KMF_ERR_BAD_HTTP_RESPONSE	= 0x35,
	KMF_ERR_RECV_RESPONSE		= 0x36,
	KMF_ERR_RECV_TIMEOUT		= 0x37,
	KMF_ERR_DUPLICATE_KEYFILE	= 0x38,
	KMF_ERR_AMBIGUOUS_PATHNAME	= 0x39,
	KMF_ERR_FUNCTION_NOT_FOUND	= 0x3a,
	KMF_ERR_PKCS12_FORMAT		= 0x3b,
	KMF_ERR_BAD_KEY_TYPE		= 0x3c,
	KMF_ERR_BAD_KEY_CLASS		= 0x3d,
	KMF_ERR_BAD_KEY_SIZE		= 0x3e,
	KMF_ERR_BAD_HEX_STRING		= 0x3f,
	KMF_ERR_KEYUSAGE		= 0x40,
	KMF_ERR_VALIDITY_PERIOD		= 0x41,
	KMF_ERR_OCSP_REVOKED		= 0x42,
	KMF_ERR_CERT_MULTIPLE_FOUND	= 0x43,
	KMF_ERR_WRITE_FILE		= 0x44,
	KMF_ERR_BAD_URI			= 0x45,
	KMF_ERR_BAD_CRLFILE		= 0x46,
	KMF_ERR_BAD_CERTFILE		= 0x47,
	KMF_ERR_GETKEYVALUE_FAILED	= 0x48,
	KMF_ERR_BAD_KEYHANDLE		= 0x49,
	KMF_ERR_BAD_OBJECT_TYPE		= 0x4a,
	KMF_ERR_OCSP_RESPONSE_LIFETIME	= 0x4b,
	KMF_ERR_UNKNOWN_CSR_ATTRIBUTE	= 0x4c,
	KMF_ERR_UNINITIALIZED_TOKEN	= 0x4d,
	KMF_ERR_INCOMPLETE_TBS_CERT	= 0x4e,
	KMF_ERR_MISSING_ERRCODE		= 0x4f,
	KMF_KEYSTORE_ALREADY_INITIALIZED = 0x50,
	KMF_ERR_SENSITIVE_KEY		= 0x51,
	KMF_ERR_UNEXTRACTABLE_KEY	= 0x52,
	KMF_ERR_KEY_MISMATCH		= 0x53,
	KMF_ERR_ATTR_NOT_FOUND		= 0x54,
	KMF_ERR_KMF_CONF		= 0x55
} KMF_RETURN;

/* Data structures for OCSP support */
typedef enum {
	OCSP_GOOD	= 0,
	OCSP_REVOKED	= 1,
	OCSP_UNKNOWN	= 2
} KMF_OCSP_CERT_STATUS;

typedef enum {
	OCSP_SUCCESS 		= 0,
	OCSP_MALFORMED_REQUEST	= 1,
	OCSP_INTERNAL_ERROR	= 2,
	OCSP_TRYLATER		= 3,
	OCSP_SIGREQUIRED	= 4,
	OCSP_UNAUTHORIZED	= 5
} KMF_OCSP_RESPONSE_STATUS;

typedef enum {
	OCSP_NOSTATUS		= -1,
	OCSP_UNSPECIFIED	= 0,
	OCSP_KEYCOMPROMISE	= 1,
	OCSP_CACOMPROMISE	= 2,
	OCSP_AFFILIATIONCHANGE	= 3,
	OCSP_SUPERCEDED		= 4,
	OCSP_CESSATIONOFOPERATION = 5,
	OCSP_CERTIFICATEHOLD	= 6,
	OCSP_REMOVEFROMCRL	= 7
} KMF_OCSP_REVOKED_STATUS;

typedef enum {
	KMF_ALGCLASS_NONE 	= 0,
	KMF_ALGCLASS_CUSTOM,
	KMF_ALGCLASS_SIGNATURE,
	KMF_ALGCLASS_SYMMETRIC,
	KMF_ALGCLASS_DIGEST,
	KMF_ALGCLASS_RANDOMGEN,
	KMF_ALGCLASS_UNIQUEGEN,
	KMF_ALGCLASS_MAC,
	KMF_ALGCLASS_ASYMMETRIC,
	KMF_ALGCLASS_KEYGEN,
	KMF_ALGCLASS_DERIVEKEY
} KMF_ALGCLASS;

typedef enum {
	KMF_CERT_ISSUER		= 1,
	KMF_CERT_SUBJECT,
	KMF_CERT_VERSION,
	KMF_CERT_SERIALNUM,
	KMF_CERT_NOTBEFORE,
	KMF_CERT_NOTAFTER,
	KMF_CERT_PUBKEY_ALG,
	KMF_CERT_SIGNATURE_ALG,
	KMF_CERT_EMAIL,
	KMF_CERT_PUBKEY_DATA,
	KMF_X509_EXT_PRIV_KEY_USAGE_PERIOD,
	KMF_X509_EXT_CERT_POLICIES,
	KMF_X509_EXT_SUBJ_ALTNAME,
	KMF_X509_EXT_ISSUER_ALTNAME,
	KMF_X509_EXT_BASIC_CONSTRAINTS,
	KMF_X509_EXT_NAME_CONSTRAINTS,
	KMF_X509_EXT_POLICY_CONSTRAINTS,
	KMF_X509_EXT_EXT_KEY_USAGE,
	KMF_X509_EXT_INHIBIT_ANY_POLICY,
	KMF_X509_EXT_AUTH_KEY_ID,
	KMF_X509_EXT_SUBJ_KEY_ID,
	KMF_X509_EXT_POLICY_MAPPINGS,
	KMF_X509_EXT_CRL_DIST_POINTS,
	KMF_X509_EXT_FRESHEST_CRL,
	KMF_X509_EXT_KEY_USAGE
} KMF_PRINTABLE_ITEM;

/*
 * KMF_X509_ALGORITHM_IDENTIFIER
 * This structure holds an object identifier naming a
 * cryptographic algorithm and an optional set of
 * parameters to be used as input to that algorithm.
 */
typedef struct
{
	KMF_OID algorithm;
	KMF_DATA parameters;
} KMF_X509_ALGORITHM_IDENTIFIER;

/*
 * KMF_X509_TYPE_VALUE_PAIR
 * This structure contain an type-value pair.
 */
typedef struct
{
	KMF_OID type;
	uint8_t valueType; /* The Tag to use when BER encoded */
	KMF_DATA value;
} KMF_X509_TYPE_VALUE_PAIR;


/*
 * KMF_X509_RDN
 * This structure contains a Relative Distinguished Name
 * composed of an ordered set of type-value pairs.
 */
typedef struct
{
	uint32_t			numberOfPairs;
	KMF_X509_TYPE_VALUE_PAIR	*AttributeTypeAndValue;
} KMF_X509_RDN;

/*
 * KMF_X509_NAME
 * This structure contains a set of Relative Distinguished Names.
 */
typedef struct
{
	uint32_t numberOfRDNs;
	KMF_X509_RDN	*RelativeDistinguishedName;
} KMF_X509_NAME;

/*
 * KMF_X509_SPKI
 * This structure contains the public key and the
 * description of the verification algorithm
 * appropriate for use with this key.
 */
typedef struct
{
	KMF_X509_ALGORITHM_IDENTIFIER algorithm;
	KMF_DATA subjectPublicKey;
} KMF_X509_SPKI;

/*
 * KMF_X509_TIME
 * Time is represented as a string according to the
 * definitions of GeneralizedTime and UTCTime
 * defined in RFC 2459.
 */
typedef struct
{
	uint8_t timeType;
	KMF_DATA time;
} KMF_X509_TIME;

/*
 * KMF_X509_VALIDITY
 */
typedef struct
{
	KMF_X509_TIME notBefore;
	KMF_X509_TIME notAfter;
} KMF_X509_VALIDITY;

/*
 *   KMF_X509EXT_BASICCONSTRAINTS
 */
typedef struct
{
	KMF_BOOL cA;
	KMF_BOOL pathLenConstraintPresent;
	uint32_t pathLenConstraint;
} KMF_X509EXT_BASICCONSTRAINTS;

/*
 * KMF_X509EXT_DATA_FORMAT
 * This list defines the valid formats for a certificate extension.
 */
typedef enum
{
	KMF_X509_DATAFORMAT_ENCODED = 0,
	KMF_X509_DATAFORMAT_PARSED,
	KMF_X509_DATAFORMAT_PAIR
} KMF_X509EXT_DATA_FORMAT;


/*
 * KMF_X509EXT_TAGandVALUE
 * This structure contains a BER/DER encoded
 * extension value and the type of that value.
 */
typedef struct
{
	uint8_t type;
	KMF_DATA value;
} KMF_X509EXT_TAGandVALUE;


/*
 * KMF_X509EXT_PAIR
 * This structure aggregates two extension representations:
 * a tag and value, and a parsed X509 extension representation.
 */
typedef struct
{
	KMF_X509EXT_TAGandVALUE tagAndValue;
	void *parsedValue;
} KMF_X509EXT_PAIR;

/*
 * KMF_X509_EXTENSION
 * This structure contains a complete certificate extension.
 */
typedef struct
{
	KMF_OID extnId;
	KMF_BOOL critical;
	KMF_X509EXT_DATA_FORMAT format;
	union
	{
		KMF_X509EXT_TAGandVALUE *tagAndValue;
		void *parsedValue;
		KMF_X509EXT_PAIR *valuePair;
	} value;
	KMF_DATA BERvalue;
} KMF_X509_EXTENSION;


/*
 * KMF_X509_EXTENSIONS
 * This structure contains the set of all certificate
 * extensions contained in a certificate.
 */
typedef struct
{
	uint32_t numberOfExtensions;
	KMF_X509_EXTENSION *extensions;
} KMF_X509_EXTENSIONS;

/*
 * KMF_X509_TBS_CERT
 * This structure contains a complete X.509 certificate.
 */
typedef struct
{
	KMF_DATA version;
	KMF_BIGINT serialNumber;
	KMF_X509_ALGORITHM_IDENTIFIER signature;
	KMF_X509_NAME issuer;
	KMF_X509_VALIDITY validity;
	KMF_X509_NAME subject;
	KMF_X509_SPKI subjectPublicKeyInfo;
	KMF_DATA issuerUniqueIdentifier;
	KMF_DATA subjectUniqueIdentifier;
	KMF_X509_EXTENSIONS extensions;
} KMF_X509_TBS_CERT;

/*
 * KMF_X509_SIGNATURE
 * This structure contains a cryptographic digital signature.
 */
typedef struct
{
	KMF_X509_ALGORITHM_IDENTIFIER algorithmIdentifier;
	KMF_DATA encrypted;
} KMF_X509_SIGNATURE;

/*
 * KMF_X509_CERTIFICATE
 * This structure associates a set of decoded certificate
 * values with the signature covering those values.
 */
typedef struct
{
	KMF_X509_TBS_CERT certificate;
	KMF_X509_SIGNATURE signature;
} KMF_X509_CERTIFICATE;

#define	CERT_ALG_OID(c) &c->certificate.signature.algorithm
#define	CERT_SIG_OID(c) &c->signature.algorithmIdentifier.algorithm

/*
 * KMF_TBS_CSR
 * This structure contains a complete PKCS#10 certificate request
 */
typedef struct
{
	KMF_DATA version;
	KMF_X509_NAME subject;
	KMF_X509_SPKI subjectPublicKeyInfo;
	KMF_X509_EXTENSIONS extensions;
} KMF_TBS_CSR;

/*
 * KMF_CSR_DATA
 * This structure contains a complete PKCS#10 certificate signed request
 */
typedef struct
{
	KMF_TBS_CSR csr;
	KMF_X509_SIGNATURE signature;
} KMF_CSR_DATA;

/*
 * KMF_X509EXT_POLICYQUALIFIERINFO
 */
typedef struct
{
	KMF_OID policyQualifierId;
	KMF_DATA value;
} KMF_X509EXT_POLICYQUALIFIERINFO;

/*
 * KMF_X509EXT_POLICYQUALIFIERS
 */
typedef struct
{
	uint32_t numberOfPolicyQualifiers;
	KMF_X509EXT_POLICYQUALIFIERINFO *policyQualifier;
} KMF_X509EXT_POLICYQUALIFIERS;

/*
 * KMF_X509EXT_POLICYINFO
 */
typedef struct
{
	KMF_OID policyIdentifier;
	KMF_X509EXT_POLICYQUALIFIERS policyQualifiers;
} KMF_X509EXT_POLICYINFO;

typedef struct
{
	uint32_t numberOfPolicyInfo;
	KMF_X509EXT_POLICYINFO *policyInfo;
} KMF_X509EXT_CERT_POLICIES;

typedef struct
{
	uchar_t critical;
	uint16_t KeyUsageBits;
} KMF_X509EXT_KEY_USAGE;

typedef struct
{
	uchar_t		critical;
	uint16_t	nEKUs;
	KMF_OID	*keyPurposeIdList;
} KMF_X509EXT_EKU;


/*
 * X509 AuthorityInfoAccess extension
 */
typedef struct
{
	KMF_OID AccessMethod;
	KMF_DATA AccessLocation;
} KMF_X509EXT_ACCESSDESC;

typedef struct
{
	uint32_t numberOfAccessDescription;
	KMF_X509EXT_ACCESSDESC *AccessDesc;
} KMF_X509EXT_AUTHINFOACCESS;


/*
 * X509 Crl Distribution Point extension
 */
typedef struct {
	KMF_GENERALNAMECHOICES	choice;
	KMF_DATA		name;
} KMF_GENERALNAME;

typedef struct {
	uint32_t	number;
	KMF_GENERALNAME *namelist;
} KMF_GENERALNAMES;

typedef enum  {
	DP_GENERAL_NAME = 1,
	DP_RELATIVE_NAME = 2
} KMF_CRL_DIST_POINT_TYPE;

typedef struct {
	KMF_CRL_DIST_POINT_TYPE type;
	union {
		KMF_GENERALNAMES full_name;
		KMF_DATA relative_name;
	} name;
	KMF_DATA reasons;
	KMF_GENERALNAMES crl_issuer;
} KMF_CRL_DIST_POINT;

typedef struct {
	uint32_t number;
	KMF_CRL_DIST_POINT *dplist;
} KMF_X509EXT_CRLDISTPOINTS;

typedef enum {
	KMF_DATA_ATTR,
	KMF_OID_ATTR,
	KMF_BIGINT_ATTR,
	KMF_X509_DER_CERT_ATTR,
	KMF_KEYSTORE_TYPE_ATTR,
	KMF_ENCODE_FORMAT_ATTR,
	KMF_CERT_VALIDITY_ATTR,
	KMF_KU_PURPOSE_ATTR,
	KMF_ALGORITHM_INDEX_ATTR,
	KMF_TOKEN_LABEL_ATTR,
	KMF_READONLY_ATTR,
	KMF_DIRPATH_ATTR,
	KMF_CERTPREFIX_ATTR,
	KMF_KEYPREFIX_ATTR,
	KMF_SECMODNAME_ATTR,
	KMF_CREDENTIAL_ATTR,
	KMF_TRUSTFLAG_ATTR,
	KMF_CRL_FILENAME_ATTR,
	KMF_CRL_CHECK_ATTR,
	KMF_CRL_DATA_ATTR,
	KMF_CRL_SUBJECT_ATTR,
	KMF_CRL_ISSUER_ATTR,
	KMF_CRL_NAMELIST_ATTR,
	KMF_CRL_COUNT_ATTR,
	KMF_CRL_OUTFILE_ATTR,
	KMF_CERT_LABEL_ATTR,
	KMF_SUBJECT_NAME_ATTR,
	KMF_ISSUER_NAME_ATTR,
	KMF_CERT_FILENAME_ATTR,
	KMF_KEY_FILENAME_ATTR,
	KMF_OUTPUT_FILENAME_ATTR,
	KMF_IDSTR_ATTR,
	KMF_CERT_DATA_ATTR,
	KMF_OCSP_RESPONSE_DATA_ATTR,
	KMF_OCSP_RESPONSE_STATUS_ATTR,
	KMF_OCSP_RESPONSE_REASON_ATTR,
	KMF_OCSP_RESPONSE_CERT_STATUS_ATTR,
	KMF_OCSP_REQUEST_FILENAME_ATTR,
	KMF_KEYALG_ATTR,
	KMF_KEYCLASS_ATTR,
	KMF_KEYLABEL_ATTR,
	KMF_KEYLENGTH_ATTR,
	KMF_RSAEXP_ATTR,
	KMF_TACERT_DATA_ATTR,
	KMF_SLOT_ID_ATTR,
	KMF_PK12CRED_ATTR,
	KMF_ISSUER_CERT_DATA_ATTR,
	KMF_USER_CERT_DATA_ATTR,
	KMF_SIGNER_CERT_DATA_ATTR,
	KMF_IGNORE_RESPONSE_SIGN_ATTR,
	KMF_RESPONSE_LIFETIME_ATTR,
	KMF_KEY_HANDLE_ATTR,
	KMF_PRIVKEY_HANDLE_ATTR,
	KMF_PUBKEY_HANDLE_ATTR,
	KMF_ERROR_ATTR,
	KMF_X509_NAME_ATTR,
	KMF_X509_SPKI_ATTR,
	KMF_X509_CERTIFICATE_ATTR,
	KMF_RAW_KEY_ATTR,
	KMF_CSR_DATA_ATTR,
	KMF_GENERALNAMECHOICES_ATTR,
	KMF_STOREKEY_BOOL_ATTR,
	KMF_SENSITIVE_BOOL_ATTR,
	KMF_NON_EXTRACTABLE_BOOL_ATTR,
	KMF_TOKEN_BOOL_ATTR,
	KMF_PRIVATE_BOOL_ATTR,
	KMF_NEWPIN_ATTR,
	KMF_IN_SIGN_ATTR,
	KMF_OUT_DATA_ATTR,
	KMF_COUNT_ATTR,
	KMF_DESTROY_BOOL_ATTR,
	KMF_TBS_CERT_DATA_ATTR,
	KMF_PLAINTEXT_DATA_ATTR,
	KMF_CIPHERTEXT_DATA_ATTR,
	KMF_VALIDATE_RESULT_ATTR,
	KMF_KEY_DATA_ATTR
} KMF_ATTR_TYPE;

typedef struct {
	KMF_ATTR_TYPE	type;
	void		*pValue;
	uint32_t	valueLen;
} KMF_ATTRIBUTE;

/*
 * Definitions for common X.509v3 certificate attribute OIDs
 */
#define	OID_ISO_MEMBER	42	/* Also in PKCS */
#define	OID_US	OID_ISO_MEMBER, 134, 72 /* Also in PKCS */
#define	OID_CA	OID_ISO_MEMBER, 124

#define	OID_ISO_IDENTIFIED_ORG 43
#define	OID_OSINET	OID_ISO_IDENTIFIED_ORG, 4
#define	OID_GOSIP	OID_ISO_IDENTIFIED_ORG, 5
#define	OID_DOD	OID_ISO_IDENTIFIED_ORG, 6
#define	OID_OIW	OID_ISO_IDENTIFIED_ORG, 14 /* Also in x9.57 */

#define	OID_ISO_CCITT_DIR_SERVICE 85
#define	OID_ISO_CCITT_COUNTRY	96
#define	OID_COUNTRY_US	OID_ISO_CCITT_COUNTRY, 134, 72
#define	OID_COUNTRY_CA	OID_ISO_CCITT_COUNTRY, 124
#define	OID_COUNTRY_US_ORG	OID_COUNTRY_US, 1
#define	OID_COUNTRY_US_MHS_MD	OID_COUNTRY_US, 2
#define	OID_COUNTRY_US_STATE	OID_COUNTRY_US, 3

/* From the PKCS Standards */
#define	OID_ISO_MEMBER_LENGTH 1
#define	OID_US_LENGTH	(OID_ISO_MEMBER_LENGTH + 2)

#define	OID_RSA	OID_US, 134, 247, 13
#define	OID_RSA_LENGTH	(OID_US_LENGTH + 3)

#define	OID_RSA_HASH	OID_RSA, 2
#define	OID_RSA_HASH_LENGTH   (OID_RSA_LENGTH + 1)

#define	OID_RSA_ENCRYPT	OID_RSA, 3
#define	OID_RSA_ENCRYPT_LENGTH (OID_RSA_LENGTH + 1)

#define	OID_PKCS	OID_RSA, 1
#define	OID_PKCS_LENGTH	(OID_RSA_LENGTH + 1)

#define	OID_PKCS_1	OID_PKCS, 1
#define	OID_PKCS_1_LENGTH	(OID_PKCS_LENGTH + 1)

#define	OID_PKCS_2	OID_PKCS, 2
#define	OID_PKCS_3	OID_PKCS, 3
#define	OID_PKCS_3_LENGTH	(OID_PKCS_LENGTH + 1)

#define	OID_PKCS_4	OID_PKCS, 4
#define	OID_PKCS_5	OID_PKCS, 5
#define	OID_PKCS_5_LENGTH	(OID_PKCS_LENGTH + 1)
#define	OID_PKCS_6	OID_PKCS, 6
#define	OID_PKCS_7	OID_PKCS, 7
#define	OID_PKCS_7_LENGTH	(OID_PKCS_LENGTH + 1)

#define	OID_PKCS_7_Data			OID_PKCS_7, 1
#define	OID_PKCS_7_SignedData		OID_PKCS_7, 2
#define	OID_PKCS_7_EnvelopedData	OID_PKCS_7, 3
#define	OID_PKCS_7_SignedAndEnvelopedData	OID_PKCS_7, 4
#define	OID_PKCS_7_DigestedData		OID_PKCS_7, 5
#define	OID_PKCS_7_EncryptedData	OID_PKCS_7, 6

#define	OID_PKCS_8	OID_PKCS, 8
#define	OID_PKCS_9	OID_PKCS, 9
#define	OID_PKCS_9_LENGTH	(OID_PKCS_LENGTH + 1)

#define	OID_PKCS_9_CONTENT_TYPE		OID_PKCS_9, 3
#define	OID_PKCS_9_MESSAGE_DIGEST	OID_PKCS_9, 4
#define	OID_PKCS_9_SIGNING_TIME		OID_PKCS_9, 5
#define	OID_PKCS_9_COUNTER_SIGNATURE	OID_PKCS_9, 6
#define	OID_PKCS_9_EXTENSION_REQUEST	OID_PKCS_9, 14

#define	OID_PKCS_10	OID_PKCS, 10

#define	OID_PKCS_12	OID_PKCS, 12
#define	OID_PKCS_12_LENGTH	(OID_PKCS_LENGTH + 1)

#define	PBEWithSHAAnd128BitRC4	OID_PKCS_12, 1, 1
#define	PBEWithSHAAnd40BitRC4	OID_PKCS_12, 1, 2
#define	PBEWithSHAAnd3KeyTripleDES_CBC	OID_PKCS_12, 1, 3
#define	PBEWithSHAAnd2KeyTripleDES_CBC	OID_PKCS_12, 1, 4
#define	PBEWithSHAAnd128BitRC2_CBC	OID_PKCS_12, 1, 5
#define	PBEWithSHAAnd40BitRC2_CBC	OID_PKCS_12, 1, 6

#define	OID_BAG_TYPES		OID_PKCS_12, 10, 1
#define	OID_KeyBag		OID_BAG_TYPES, 1
#define	OID_PKCS8ShroudedKeyBag	OID_BAG_TYPES, 2
#define	OID_CertBag		OID_BAG_TYPES, 3
#define	OID_CrlBag		OID_BAG_TYPES, 4
#define	OID_SecretBag		OID_BAG_TYPES, 5
#define	OID_SafeContentsBag	OID_BAG_TYPES, 6

#define	OID_ContentInfo		OID_PKCS_7, 0, 1

#define	OID_CERT_TYPES		OID_PKCS_9, 22
#define	OID_x509Certificate	OID_CERT_TYPES, 1
#define	OID_sdsiCertificate	OID_CERT_TYPES, 2

#define	OID_CRL_TYPES		OID_PKCS_9, 23
#define	OID_x509Crl		OID_CRL_TYPES, 1

#define	OID_DS	OID_ISO_CCITT_DIR_SERVICE /* Also in X.501 */
#define	OID_DS_LENGTH	1

#define	OID_ATTR_TYPE	OID_DS, 4	/* Also in X.501 */
#define	OID_ATTR_TYPE_LENGTH  (OID_DS_LENGTH + 1)

#define	OID_DSALG	OID_DS, 8	/* Also in X.501 */
#define	OID_DSALG_LENGTH	(OID_DS_LENGTH + 1)

#define	OID_EXTENSION	OID_DS, 29	/* Also in X.501 */
#define	OID_EXTENSION_LENGTH  (OID_DS_LENGTH + 1)

/*
 * From RFC 1274:
 * {itu-t(0) data(9) pss(2342) ucl(19200300) pilot(100) pilotAttributeType(1) }
 */
#define	OID_PILOT	0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x1
#define	OID_PILOT_LENGTH	9

#define	OID_USERID		OID_PILOT 1
#define	OID_USERID_LENGTH	(OID_PILOT_LENGTH + 1)

/*
 * From PKIX part1
 * { iso(1) identified-organization(3) dod(6) internet(1)
 *   security(5) mechanisms(5) pkix(7) }
 */
#define	OID_PKIX	43, 6, 1, 5, 5, 7
#define	OID_PKIX_LENGTH	6

/* private certificate extensions, { id-pkix 1 } */
#define	OID_PKIX_PE	OID_PKIX, 1
#define	OID_PKIX_PE_LENGTH   (OID_PKIX_LENGTH + 1)

/* policy qualifier types {id-pkix 2 } */
#define	OID_PKIX_QT	OID_PKIX, 2
#define	OID_PKIX_QT_LENGTH   (OID_PKIX_LENGTH + 1)

/* CPS qualifier, { id-qt 1 } */
#define	OID_PKIX_QT_CPS	OID_PKIX_QT, 1
#define	OID_PKIX_QT_CPS_LENGTH (OID_PKIX_QT_LENGTH + 1)
/* user notice qualifier, { id-qt 2 } */
#define	OID_PKIX_QT_UNOTICE  OID_PKIX_QT, 2
#define	OID_PKIX_QT_UNOTICE_LENGTH (OID_PKIX_QT_LENGTH + 1)

/* extended key purpose OIDs {id-pkix 3 } */
#define	OID_PKIX_KP	OID_PKIX, 3
#define	OID_PKIX_KP_LENGTH   (OID_PKIX_LENGTH + 1)

/* access descriptors {id-pkix 4 } */
#define	OID_PKIX_AD	OID_PKIX, 48
#define	OID_PKIX_AD_LENGTH   (OID_PKIX_LENGTH + 1)

/* access descriptors */
/* OCSP */
#define	OID_PKIX_AD_OCSP	OID_PKIX_AD, 1
#define	OID_PKIX_AD_OCSP_LENGTH (OID_PKIX_AD_LENGTH + 1)

/* cAIssuers */
#define	OID_PKIX_AD_CAISSUERS OID_PKIX_AD, 2
#define	OID_PKIX_AD_CAISSUERS_LENGTH (OID_PKIX_AD_LENGTH + 1)

/* end PKIX part1 */
#define	OID_APPL_TCP_PROTO   43, 6, 1, 2, 1, 27, 4
#define	OID_APPL_TCP_PROTO_LENGTH   8

#define	OID_DAP	OID_DS, 3, 1
#define	OID_DAP_LENGTH	(OID_DS_LENGTH + 2)

/* From x9.57 */
#define	OID_OIW_LENGTH	2

#define	OID_OIW_SECSIG	OID_OIW, 3
#define	OID_OIW_SECSIG_LENGTH (OID_OIW_LENGTH + 1)

#define	OID_OIW_ALGORITHM	OID_OIW_SECSIG, 2
#define	OID_OIW_ALGORITHM_LENGTH (OID_OIW_SECSIG_LENGTH + 1)

#define	OID_OIWDIR	OID_OIW, 7, 2
#define	OID_OIWDIR_LENGTH    (OID_OIW_LENGTH + 2)

#define	OID_OIWDIR_CRPT	OID_OIWDIR, 1

#define	OID_OIWDIR_HASH	OID_OIWDIR, 2
#define	OID_OIWDIR_HASH_LENGTH (OID_OIWDIR_LENGTH + 1)

#define	OID_OIWDIR_SIGN	OID_OIWDIR, 3
#define	OID_OIWDIR_SIGN_LENGTH (OID_OIWDIR_LENGTH + 1)

#define	OID_X9CM	OID_US, 206, 56
#define	OID_X9CM_MODULE	OID_X9CM, 1
#define	OID_X9CM_INSTRUCTION OID_X9CM, 2
#define	OID_X9CM_ATTR	OID_X9CM, 3
#define	OID_X9CM_X9ALGORITHM OID_X9CM, 4
#define	OID_X9CM_X9ALGORITHM_LENGTH ((OID_US_LENGTH) + 2 + 1)

#define	INTEL	96, 134, 72, 1, 134, 248, 77
#define	INTEL_LENGTH 7

#define	INTEL_SEC_FORMATS	INTEL_CDSASECURITY, 1
#define	INTEL_SEC_FORMATS_LENGTH	(INTEL_CDSASECURITY_LENGTH + 1)

#define	INTEL_SEC_ALGS	INTEL_CDSASECURITY, 2, 5
#define	INTEL_SEC_ALGS_LENGTH	(INTEL_CDSASECURITY_LENGTH + 2)

extern const KMF_OID
KMFOID_AliasedEntryName,
KMFOID_AuthorityRevocationList,
KMFOID_BusinessCategory,
KMFOID_CACertificate,
KMFOID_CertificateRevocationList,
KMFOID_ChallengePassword,
KMFOID_CollectiveFacsimileTelephoneNumber,
KMFOID_CollectiveInternationalISDNNumber,
KMFOID_CollectiveOrganizationName,
KMFOID_CollectiveOrganizationalUnitName,
KMFOID_CollectivePhysicalDeliveryOfficeName,
KMFOID_CollectivePostOfficeBox,
KMFOID_CollectivePostalAddress,
KMFOID_CollectivePostalCode,
KMFOID_CollectiveStateProvinceName,
KMFOID_CollectiveStreetAddress,
KMFOID_CollectiveTelephoneNumber,
KMFOID_CollectiveTelexNumber,
KMFOID_CollectiveTelexTerminalIdentifier,
KMFOID_CommonName,
KMFOID_ContentType,
KMFOID_CounterSignature,
KMFOID_CountryName,
KMFOID_CrossCertificatePair,
KMFOID_DNQualifier,
KMFOID_Description,
KMFOID_DestinationIndicator,
KMFOID_DistinguishedName,
KMFOID_EmailAddress,
KMFOID_EnhancedSearchGuide,
KMFOID_ExtendedCertificateAttributes,
KMFOID_ExtensionRequest,
KMFOID_FacsimileTelephoneNumber,
KMFOID_GenerationQualifier,
KMFOID_GivenName,
KMFOID_HouseIdentifier,
KMFOID_Initials,
KMFOID_InternationalISDNNumber,
KMFOID_KnowledgeInformation,
KMFOID_LocalityName,
KMFOID_Member,
KMFOID_MessageDigest,
KMFOID_Name,
KMFOID_ObjectClass,
KMFOID_OrganizationName,
KMFOID_OrganizationalUnitName,
KMFOID_Owner,
KMFOID_PhysicalDeliveryOfficeName,
KMFOID_PostOfficeBox,
KMFOID_PostalAddress,
KMFOID_PostalCode,
KMFOID_PreferredDeliveryMethod,
KMFOID_PresentationAddress,
KMFOID_ProtocolInformation,
KMFOID_RFC822mailbox,
KMFOID_RegisteredAddress,
KMFOID_RoleOccupant,
KMFOID_SearchGuide,
KMFOID_SeeAlso,
KMFOID_SerialNumber,
KMFOID_SigningTime,
KMFOID_StateProvinceName,
KMFOID_StreetAddress,
KMFOID_SupportedApplicationContext,
KMFOID_Surname,
KMFOID_TelephoneNumber,
KMFOID_TelexNumber,
KMFOID_TelexTerminalIdentifier,
KMFOID_Title,
KMFOID_UniqueIdentifier,
KMFOID_UniqueMember,
KMFOID_UnstructuredAddress,
KMFOID_UnstructuredName,
KMFOID_UserCertificate,
KMFOID_UserPassword,
KMFOID_X_121Address,
KMFOID_domainComponent,
KMFOID_userid;

extern const KMF_OID
KMFOID_AuthorityKeyID,
KMFOID_AuthorityInfoAccess,
KMFOID_VerisignCertificatePolicy,
KMFOID_KeyUsageRestriction,
KMFOID_SubjectDirectoryAttributes,
KMFOID_SubjectKeyIdentifier,
KMFOID_KeyUsage,
KMFOID_PrivateKeyUsagePeriod,
KMFOID_SubjectAltName,
KMFOID_IssuerAltName,
KMFOID_BasicConstraints,
KMFOID_CrlNumber,
KMFOID_CrlReason,
KMFOID_HoldInstructionCode,
KMFOID_InvalidityDate,
KMFOID_DeltaCrlIndicator,
KMFOID_IssuingDistributionPoints,
KMFOID_NameConstraints,
KMFOID_CrlDistributionPoints,
KMFOID_CertificatePolicies,
KMFOID_PolicyMappings,
KMFOID_PolicyConstraints,
KMFOID_AuthorityKeyIdentifier,
KMFOID_ExtendedKeyUsage,
KMFOID_PkixAdOcsp,
KMFOID_PkixAdCaIssuers,
KMFOID_PKIX_PQ_CPSuri,
KMFOID_PKIX_PQ_Unotice,
KMFOID_PKIX_KP_ServerAuth,
KMFOID_PKIX_KP_ClientAuth,
KMFOID_PKIX_KP_CodeSigning,
KMFOID_PKIX_KP_EmailProtection,
KMFOID_PKIX_KP_IPSecEndSystem,
KMFOID_PKIX_KP_IPSecTunnel,
KMFOID_PKIX_KP_IPSecUser,
KMFOID_PKIX_KP_TimeStamping,
KMFOID_PKIX_KP_OCSPSigning,
KMFOID_SHA1,
KMFOID_RSA,
KMFOID_DSA,
KMFOID_MD5WithRSA,
KMFOID_MD2WithRSA,
KMFOID_SHA1WithRSA,
KMFOID_SHA1WithDSA,
KMFOID_OIW_DSAWithSHA1,
KMFOID_X9CM_DSA,
KMFOID_X9CM_DSAWithSHA1;

/*
 * KMF Certificate validation codes.  These may be masked together.
 */
#define	KMF_CERT_VALIDATE_OK		0x00
#define	KMF_CERT_VALIDATE_ERR_TA	0x01
#define	KMF_CERT_VALIDATE_ERR_USER	0x02
#define	KMF_CERT_VALIDATE_ERR_SIGNATURE	0x04
#define	KMF_CERT_VALIDATE_ERR_KEYUSAGE	0x08
#define	KMF_CERT_VALIDATE_ERR_EXT_KEYUSAGE	0x10
#define	KMF_CERT_VALIDATE_ERR_TIME	0x20
#define	KMF_CERT_VALIDATE_ERR_CRL	0x40
#define	KMF_CERT_VALIDATE_ERR_OCSP	0x80
#define	KMF_CERT_VALIDATE_ERR_ISSUER	0x100

/*
 * KMF Key Usage bitmasks
 */
#define	KMF_digitalSignature	0x8000
#define	KMF_nonRepudiation	0x4000
#define	KMF_keyEncipherment	0x2000
#define	KMF_dataEncipherment	0x1000
#define	KMF_keyAgreement	0x0800
#define	KMF_keyCertSign		0x0400
#define	KMF_cRLSign		0x0200
#define	KMF_encipherOnly	0x0100
#define	KMF_decipherOnly	0x0080

#define	KMF_KUBITMASK 0xFF80

/*
 * KMF Extended KeyUsage OID definitions
 */
#define	KMF_EKU_SERVERAUTH			0x01
#define	KMF_EKU_CLIENTAUTH			0x02
#define	KMF_EKU_CODESIGNING			0x04
#define	KMF_EKU_EMAIL				0x08
#define	KMF_EKU_TIMESTAMP			0x10
#define	KMF_EKU_OCSPSIGNING			0x20


/*
 * Legacy support only - do not use these data structures - they can be
 * removed at any time.
 */

/* Keystore Configuration */
typedef struct {
	char    *configdir;
	char    *certPrefix;
	char    *keyPrefix;
	char    *secModName;
} KMF_NSS_CONFIG;

typedef struct {
	char		*label;
	boolean_t	readonly;
} KMF_PKCS11_CONFIG;

typedef struct {
	KMF_KEYSTORE_TYPE	kstype;
	union {
		KMF_NSS_CONFIG		nss_conf;
		KMF_PKCS11_CONFIG	pkcs11_conf;
	} ks_config_u;
} KMF_CONFIG_PARAMS;

#define	nssconfig	ks_config_u.nss_conf
#define	pkcs11config	ks_config_u.pkcs11_conf


typedef struct
{
	char    *trustflag;
	char	*slotlabel;	/* "internal" by default */
	int	issuerId;
	int	subjectId;
	char	*crlfile;	/* for ImportCRL */
	boolean_t crl_check;	/* for ImportCRL */

	/*
	 * The following 2 variables are for FindCertInCRL. The caller can
	 * either specify certLabel or provide the entire certificate in
	 * DER format as input.
	 */
	char	*certLabel;	/* for FindCertInCRL */
	KMF_DATA *certificate;  /* for FindCertInCRL */

	/*
	 * crl_subjName and crl_issuerName are used as the CRL deletion
	 * criteria.  One should be non-NULL and the other one should be NULL.
	 * If crl_subjName is not NULL, then delete CRL by the subject name.
	 * Othewise, delete by the issuer name.
	 */
	char 	*crl_subjName;
	char	*crl_issuerName;
} KMF_NSS_PARAMS;

typedef struct {
	char	*dirpath;
	char    *certfile;
	char	*crlfile;
	char    *keyfile;
	char	*outcrlfile;
	boolean_t crl_check;	/* CRL import check; default is true */
	KMF_ENCODE_FORMAT	format; /* output file format */
} KMF_OPENSSL_PARAMS;

typedef struct {
	boolean_t	private; /* for finding CKA_PRIVATE objects */
	boolean_t	sensitive;
	boolean_t	not_extractable;
	boolean_t	token; /* true == token object, false == session */
} KMF_PKCS11_PARAMS;

typedef struct {
	KMF_KEYSTORE_TYPE	kstype;
	char			*certLabel;
	char			*issuer;
	char			*subject;
	char			*idstr;
	KMF_BIGINT		*serial;
	KMF_CERT_VALIDITY	find_cert_validity;

	union {
		KMF_NSS_PARAMS		nss_opts;
		KMF_OPENSSL_PARAMS	openssl_opts;
		KMF_PKCS11_PARAMS	pkcs11_opts;
	} ks_opt_u;
} KMF_FINDCERT_PARAMS, KMF_DELETECERT_PARAMS;

typedef struct {
	KMF_KEYSTORE_TYPE	kstype;
	KMF_CREDENTIAL		cred;
	KMF_KEY_CLASS		keyclass;
	KMF_KEY_ALG		keytype;
	KMF_ENCODE_FORMAT	format; /* for key */
	char			*findLabel;
	char			*idstr;
	union {
		KMF_NSS_PARAMS		nss_opts;
		KMF_OPENSSL_PARAMS	openssl_opts;
		KMF_PKCS11_PARAMS	pkcs11_opts;
	} ks_opt_u;
} KMF_FINDKEY_PARAMS;

typedef struct {
	KMF_KEYSTORE_TYPE	kstype;
	KMF_KEY_ALG		keytype;
	uint32_t		keylength;
	char			*keylabel;
	KMF_CREDENTIAL		cred;
	KMF_BIGINT		rsa_exponent;
	union {
	    KMF_NSS_PARAMS	nss_opts;
	    KMF_OPENSSL_PARAMS	openssl_opts;
	}ks_opt_u;
} KMF_CREATEKEYPAIR_PARAMS;


typedef struct {
	KMF_KEYSTORE_TYPE	kstype;
	KMF_CREDENTIAL		cred;
	KMF_ENCODE_FORMAT	format; /* for key  */
	char			*certLabel;
	KMF_ALGORITHM_INDEX	algid;
	union {
	    KMF_NSS_PARAMS	nss_opts;
	    KMF_OPENSSL_PARAMS	openssl_opts;
	}ks_opt_u;
} KMF_CRYPTOWITHCERT_PARAMS;

typedef struct {
	char			*crl_name;
} KMF_CHECKCRLDATE_PARAMS;

#define	nssparms	ks_opt_u.nss_opts
#define	sslparms	ks_opt_u.openssl_opts
#define	pkcs11parms	ks_opt_u.pkcs11_opts

#ifdef __cplusplus
}
#endif
#endif /* _KMFTYPES_H */
