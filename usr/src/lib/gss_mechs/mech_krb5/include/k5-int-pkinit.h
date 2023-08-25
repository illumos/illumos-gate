
/*
 * COPYRIGHT (C) 2006
 * THE REGENTS OF THE UNIVERSITY OF MICHIGAN
 * ALL RIGHTS RESERVED
 *
 * Permission is granted to use, copy, create derivative works
 * and redistribute this software and such derivative works
 * for any purpose, so long as the name of The University of
 * Michigan is not used in any advertising or publicity
 * pertaining to the use of distribution of this software
 * without specific, written prior authorization.  If the
 * above copyright notice or any other identification of the
 * University of Michigan is included in any copy of any
 * portion of this software, then the disclaimer below must
 * also be included.
 *
 * THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION
 * FROM THE UNIVERSITY OF MICHIGAN AS TO ITS FITNESS FOR ANY
 * PURPOSE, AND WITHOUT WARRANTY BY THE UNIVERSITY OF
 * MICHIGAN OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING
 * WITHOUT LIMITATION THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
 * REGENTS OF THE UNIVERSITY OF MICHIGAN SHALL NOT BE LIABLE
 * FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES, WITH RESPECT TO ANY CLAIM ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OF THE SOFTWARE, EVEN
 * IF IT HAS BEEN OR IS HEREAFTER ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGES.
 */

#ifndef _KRB5_INT_PKINIT_H
#define _KRB5_INT_PKINIT_H

/*
 * pkinit structures
 */

/* PKAuthenticator */
typedef struct _krb5_pk_authenticator {
	krb5_int32	cusec;	/* (0..999999) */
	krb5_timestamp	ctime;
	krb5_int32	nonce;	/* (0..4294967295) */
	krb5_checksum	paChecksum;
} krb5_pk_authenticator;

/* PKAuthenticator draft9 */
typedef struct _krb5_pk_authenticator_draft9 {
	krb5_principal  kdcName;
	krb5_octet_data	kdcRealm;
	krb5_int32	cusec;	/* (0..999999) */
	krb5_timestamp	ctime;
	krb5_int32	nonce;	/* (0..4294967295) */
} krb5_pk_authenticator_draft9;

/* AlgorithmIdentifier */
typedef struct _krb5_algorithm_identifier {
	krb5_octet_data	algorithm;	/* OID */
	krb5_octet_data	parameters; /* Optional */
} krb5_algorithm_identifier;

/* SubjectPublicKeyInfo */
typedef struct _krb5_subject_pk_info {
	krb5_algorithm_identifier   algorithm;
	krb5_octet_data		    subjectPublicKey; /* BIT STRING */
} krb5_subject_pk_info;

/* AuthPack */
typedef struct _krb5_auth_pack {
	krb5_pk_authenticator	    pkAuthenticator;
	krb5_subject_pk_info	    *clientPublicValue; /* Optional */
	krb5_algorithm_identifier   **supportedCMSTypes; /* Optional */
	krb5_octet_data		    clientDHNonce; /* Optional */
} krb5_auth_pack;

/* AuthPack draft9 */
typedef struct _krb5_auth_pack_draft9 {
	krb5_pk_authenticator_draft9 pkAuthenticator;
	krb5_subject_pk_info	    *clientPublicValue; /* Optional */
} krb5_auth_pack_draft9;

/* ExternalPrincipalIdentifier */
typedef struct _krb5_external_principal_identifier {
	krb5_octet_data	subjectName; /* Optional */
	krb5_octet_data	issuerAndSerialNumber; /* Optional */
	krb5_octet_data	subjectKeyIdentifier; /* Optional */
} krb5_external_principal_identifier;

/* TrustedCas */
typedef struct _krb5_trusted_ca {
	enum {
		choice_trusted_cas_UNKNOWN = -1,
		choice_trusted_cas_principalName = 0,
		choice_trusted_cas_caName = 1,
		choice_trusted_cas_issuerAndSerial = 2
	} choice;
	union {
		krb5_principal	principalName;
		krb5_octet_data	caName;	/* fully-qualified X.500 "Name" as defined by X.509 (der-encoded) */
		krb5_octet_data	issuerAndSerial; /* Optional -- IssuerAndSerialNumber (der-encoded) */
	} u;
} krb5_trusted_ca;

/* typed data */
typedef struct _krb5_typed_data {
    krb5_magic magic;
    krb5_int32  type;
    unsigned int length;
    krb5_octet *data;
} krb5_typed_data;

/* PA-PK-AS-REQ (Draft 9 -- PA TYPE 14) */
typedef struct _krb5_pa_pk_as_req_draft9 {
	krb5_octet_data	signedAuthPack;
	krb5_trusted_ca **trustedCertifiers; /* Optional array */
	krb5_octet_data kdcCert; /* Optional */
	krb5_octet_data encryptionCert;
} krb5_pa_pk_as_req_draft9;

/* PA-PK-AS-REQ (rfc4556 -- PA TYPE 16) */
typedef struct _krb5_pa_pk_as_req {
	krb5_octet_data	signedAuthPack;
	krb5_external_principal_identifier **trustedCertifiers; /* Optional array */
	krb5_octet_data	kdcPkId; /* Optional */
} krb5_pa_pk_as_req;

/* DHRepInfo */
typedef struct _krb5_dh_rep_info {
	krb5_octet_data	dhSignedData;
	krb5_octet_data	serverDHNonce; /* Optional */
} krb5_dh_rep_info;

/* KDCDHKeyInfo */
typedef struct _krb5_kdc_dh_key_info {
	krb5_octet_data	subjectPublicKey; /* BIT STRING */
	krb5_int32	nonce;	/* (0..4294967295) */
	krb5_timestamp	dhKeyExpiration; /* Optional */
} krb5_kdc_dh_key_info;

/* KDCDHKeyInfo draft9*/
typedef struct _krb5_kdc_dh_key_info_draft9 {
	krb5_octet_data	subjectPublicKey; /* BIT STRING */
	krb5_int32	nonce;	/* (0..4294967295) */
} krb5_kdc_dh_key_info_draft9;

/* ReplyKeyPack */
typedef struct _krb5_reply_key_pack {
	krb5_keyblock	replyKey;
	krb5_checksum	asChecksum;
} krb5_reply_key_pack;

/* ReplyKeyPack */
typedef struct _krb5_reply_key_pack_draft9 {
	krb5_keyblock	replyKey;
	krb5_int32	nonce;
} krb5_reply_key_pack_draft9;

/* PA-PK-AS-REP (Draft 9 -- PA TYPE 15) */
typedef struct _krb5_pa_pk_as_rep_draft9 {
	enum {
		choice_pa_pk_as_rep_draft9_UNKNOWN = -1,
		choice_pa_pk_as_rep_draft9_dhSignedData = 0,
		choice_pa_pk_as_rep_draft9_encKeyPack = 1
	} choice;
	union {
		krb5_octet_data dhSignedData;
		krb5_octet_data encKeyPack;
	} u;
} krb5_pa_pk_as_rep_draft9;

/* PA-PK-AS-REP (rfc4556 -- PA TYPE 17) */
typedef struct _krb5_pa_pk_as_rep {
	enum {
		choice_pa_pk_as_rep_UNKNOWN = -1,
		choice_pa_pk_as_rep_dhInfo = 0,
		choice_pa_pk_as_rep_encKeyPack = 1
	} choice;
	union {
		krb5_dh_rep_info    dh_Info;
		krb5_octet_data	    encKeyPack;
	} u;
} krb5_pa_pk_as_rep;

/*
 * Begin "asn1.h"
 */

/*************************************************************************
 * Prototypes for pkinit asn.1 encode routines
 *************************************************************************/

krb5_error_code encode_krb5_pa_pk_as_req
	(const krb5_pa_pk_as_req *rep, krb5_data **code);

krb5_error_code encode_krb5_pa_pk_as_req_draft9
	(const krb5_pa_pk_as_req_draft9 *rep, krb5_data **code);

krb5_error_code encode_krb5_pa_pk_as_rep
	(const krb5_pa_pk_as_rep *rep, krb5_data **code);

krb5_error_code encode_krb5_pa_pk_as_rep_draft9
	(const krb5_pa_pk_as_rep_draft9 *rep, krb5_data **code);

krb5_error_code encode_krb5_auth_pack
	(const krb5_auth_pack *rep, krb5_data **code);

krb5_error_code encode_krb5_auth_pack_draft9
	(const krb5_auth_pack_draft9 *rep, krb5_data **code);

krb5_error_code encode_krb5_kdc_dh_key_info
	(const krb5_kdc_dh_key_info *rep, krb5_data **code);

krb5_error_code encode_krb5_reply_key_pack
	(const krb5_reply_key_pack *, krb5_data **code);

krb5_error_code encode_krb5_reply_key_pack_draft9
	(const krb5_reply_key_pack_draft9 *, krb5_data **code);

krb5_error_code encode_krb5_typed_data
	(const krb5_typed_data **, krb5_data **code);

krb5_error_code encode_krb5_td_trusted_certifiers
	(const krb5_external_principal_identifier **, krb5_data **code);

krb5_error_code encode_krb5_td_dh_parameters
	(const krb5_algorithm_identifier **, krb5_data **code);

/*************************************************************************
 * Prototypes for pkinit asn.1 decode routines
 *************************************************************************/

krb5_error_code decode_krb5_pa_pk_as_req
	(const krb5_data *, krb5_pa_pk_as_req **);

krb5_error_code decode_krb5_pa_pk_as_req_draft9
	(const krb5_data *, krb5_pa_pk_as_req_draft9 **);

krb5_error_code decode_krb5_pa_pk_as_rep
	(const krb5_data *, krb5_pa_pk_as_rep **);

krb5_error_code decode_krb5_pa_pk_as_rep_draft9
	(const krb5_data *, krb5_pa_pk_as_rep_draft9 **);

krb5_error_code decode_krb5_auth_pack
	(const krb5_data *, krb5_auth_pack **);

krb5_error_code decode_krb5_auth_pack_draft9
	(const krb5_data *, krb5_auth_pack_draft9 **);

krb5_error_code decode_krb5_kdc_dh_key_info
	(const krb5_data *, krb5_kdc_dh_key_info **);

krb5_error_code decode_krb5_principal_name
	(const krb5_data *, krb5_principal_data **);

krb5_error_code decode_krb5_reply_key_pack
	(const krb5_data *, krb5_reply_key_pack **);

krb5_error_code decode_krb5_reply_key_pack_draft9
	(const krb5_data *, krb5_reply_key_pack_draft9 **);

krb5_error_code decode_krb5_typed_data
	(const krb5_data *, krb5_typed_data ***);

krb5_error_code decode_krb5_td_trusted_certifiers
	(const krb5_data *, krb5_external_principal_identifier ***);

krb5_error_code decode_krb5_td_dh_parameters
	(const krb5_data *, krb5_algorithm_identifier ***);

#endif /* _KRB5_INT_PKINIT_H */
