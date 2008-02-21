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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef _KMFPOLICY_H
#define	_KMFPOLICY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <kmfapi.h>
#include <libxml/tree.h>
#include <libxml/parser.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	char		*name;
	char		*serial;
}KMF_RESP_CERT_POLICY;

typedef struct {
	char		*responderURI;
	char		*proxy;
	boolean_t 	uri_from_cert;
	char		*response_lifetime;
	boolean_t	ignore_response_sign;
}KMF_OCSP_BASIC_POLICY;

typedef struct {
	KMF_OCSP_BASIC_POLICY	basic;
	KMF_RESP_CERT_POLICY	resp_cert;
	boolean_t		has_resp_cert;
}KMF_OCSP_POLICY;

typedef struct {
	char *basefilename;
	char *directory;
	char *proxy;
	boolean_t get_crl_uri;
	boolean_t ignore_crl_sign;
	boolean_t ignore_crl_date;
}KMF_CRL_POLICY;

typedef struct {
	KMF_OCSP_POLICY	ocsp_info;
	KMF_CRL_POLICY	crl_info;
}KMF_VALIDATION_POLICY;

typedef struct {
	int		eku_count;
	KMF_OID		*ekulist;
}KMF_EKU_POLICY;


#define	KMF_REVOCATION_METHOD_CRL		0x1
#define	KMF_REVOCATION_METHOD_OCSP		0x2


typedef struct {
	char			*name;
	KMF_VALIDATION_POLICY	validation_info;
	KMF_EKU_POLICY		eku_set;
	uint32_t		ku_bits;
	boolean_t		ignore_date;
	boolean_t		ignore_unknown_ekus;
	boolean_t		ignore_trust_anchor;
	char			*validity_adjusttime;
	char			*ta_name;
	char			*ta_serial;
	uint32_t		revocation;
} KMF_POLICY_RECORD;


/*
 * Short cut for ocsp_info and etc.
 */
#define	VAL_OCSP			validation_info.ocsp_info

#define	VAL_OCSP_BASIC			VAL_OCSP.basic
#define	VAL_OCSP_RESPONDER_URI		VAL_OCSP_BASIC.responderURI
#define	VAL_OCSP_PROXY			VAL_OCSP_BASIC.proxy
#define	VAL_OCSP_URI_FROM_CERT		VAL_OCSP_BASIC.uri_from_cert
#define	VAL_OCSP_RESP_LIFETIME		VAL_OCSP_BASIC.response_lifetime
#define	VAL_OCSP_IGNORE_RESP_SIGN	VAL_OCSP_BASIC.ignore_response_sign

#define	VAL_OCSP_RESP_CERT		VAL_OCSP.resp_cert
#define	VAL_OCSP_RESP_CERT_NAME		VAL_OCSP_RESP_CERT.name
#define	VAL_OCSP_RESP_CERT_SERIAL	VAL_OCSP_RESP_CERT.serial

/*
 * Short cut for crl_info and etc.
 */
#define	VAL_CRL			validation_info.crl_info
#define	VAL_CRL_BASEFILENAME	validation_info.crl_info.basefilename
#define	VAL_CRL_DIRECTORY	validation_info.crl_info.directory
#define	VAL_CRL_GET_URI		validation_info.crl_info.get_crl_uri
#define	VAL_CRL_PROXY		validation_info.crl_info.proxy
#define	VAL_CRL_IGNORE_SIGN	validation_info.crl_info.ignore_crl_sign
#define	VAL_CRL_IGNORE_DATE	validation_info.crl_info.ignore_crl_date

/*
 * Policy related constant definitions.
 */
#define	KMF_POLICY_DTD		"/usr/share/lib/xml/dtd/kmfpolicy.dtd"
#define	KMF_DEFAULT_POLICY_FILE	"/etc/security/kmfpolicy.xml"

#define	KMF_DEFAULT_POLICY_NAME	"default"

#define	KMF_POLICY_ROOT	"kmf-policy-db"

#define	KULOWBIT	7
#define	KUHIGHBIT	15

#define	KMF_POLICY_ELEMENT		"kmf-policy"
#define	KMF_POLICY_NAME_ATTR		"name"
#define	KMF_OPTIONS_IGNORE_DATE_ATTR	"ignore-date"
#define	KMF_OPTIONS_IGNORE_UNKNOWN_EKUS	"ignore-unknown-eku"
#define	KMF_OPTIONS_IGNORE_TRUST_ANCHOR	"ignore-trust-anchor"
#define	KMF_OPTIONS_VALIDITY_ADJUSTTIME	"validity-adjusttime"
#define	KMF_POLICY_TA_NAME_ATTR		"ta-name"
#define	KMF_POLICY_TA_SERIAL_ATTR	"ta-serial"

#define	KMF_VALIDATION_METHODS_ELEMENT	"validation-methods"

#define	KMF_OCSP_ELEMENT		"ocsp"
#define	KMF_OCSP_BASIC_ELEMENT		"ocsp-basic"
#define	KMF_OCSP_RESPONDER_ATTR		"responder"
#define	KMF_OCSP_PROXY_ATTR		"proxy"
#define	KMF_OCSP_URI_ATTR		"uri-from-cert"
#define	KMF_OCSP_RESPONSE_LIFETIME_ATTR	"response-lifetime"
#define	KMF_OCSP_IGNORE_SIGN_ATTR	"ignore-response-sign"
#define	KMF_OCSP_RESPONDER_CERT_ELEMENT	"responder-cert"

#define	KMF_CERT_NAME_ATTR		"name"
#define	KMF_CERT_SERIAL_ATTR		"serial"

#define	KMF_CRL_ELEMENT			"crl"
#define	KMF_CRL_BASENAME_ATTR		"basefilename"
#define	KMF_CRL_DIRECTORY_ATTR		"directory"
#define	KMF_CRL_GET_URI_ATTR		"get-crl-uri"
#define	KMF_CRL_PROXY_ATTR		"proxy"
#define	KMF_CRL_IGNORE_SIGN_ATTR	"ignore-crl-sign"
#define	KMF_CRL_IGNORE_DATE_ATTR	"ignore-crl-date"

#define	KMF_KEY_USAGE_SET_ELEMENT	"key-usage-set"
#define	KMF_KEY_USAGE_ELEMENT		"key-usage"
#define	KMF_KEY_USAGE_USE_ATTR		"use"

#define	KMF_EKU_ELEMENT		"ext-key-usage"
#define	KMF_EKU_NAME_ELEMENT	"eku-name"
#define	KMF_EKU_NAME_ATTR	"name"
#define	KMF_EKU_OID_ELEMENT	"eku-oid"
#define	KMF_EKU_OID_ATTR	"oid"

#define	TMPFILE_TEMPLATE	"policyXXXXXX"

extern int parsePolicyElement(xmlNodePtr, KMF_POLICY_RECORD *);

extern KMF_RETURN kmf_get_policy(char *, char *, KMF_POLICY_RECORD *);
extern KMF_RETURN kmf_add_policy_to_db(KMF_POLICY_RECORD *, char *, boolean_t);
extern KMF_RETURN kmf_delete_policy_from_db(char *, char *);
extern KMF_RETURN kmf_verify_policy(KMF_POLICY_RECORD *);

extern void kmf_free_policy_record(KMF_POLICY_RECORD *);
extern void kmf_free_eku_policy(KMF_EKU_POLICY *);

#ifdef __cplusplus
}
#endif
#endif /* _KMFPOLICY_H */
