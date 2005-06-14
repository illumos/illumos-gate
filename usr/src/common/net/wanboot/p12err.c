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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <assert.h>
#include <openssl/err.h>
#include <p12err.h>

/*
 * OpenSSL provides a framework for pushing error codes onto a stack.
 * When an error occurs, the consumer may use the framework to
 * pop the errors off the stack and provide a trace of where the
 * errors occurred.
 *
 * Our PKCS12 code plugs into this framework by calling
 * ERR_load_SUNW_strings(). To push an error (which by the way, consists
 * of a function code and an error code) onto the stack our PKCS12 code
 * calls SUNWerr().
 *
 * Consumers of our PKCS12 code can then call the OpenSSL error routines
 * when an error occurs and retrieve the stack of errors.
 */

#ifndef OPENSSL_NO_ERR

/* Function codes and their matching strings */
static ERR_STRING_DATA SUNW_str_functs[] = {
	{ ERR_PACK(0, SUNW_F_USE_X509CERT, 0),	   "sunw_use_x509cert" },
	{ ERR_PACK(0, SUNW_F_USE_PKEY, 0),	   "sunw_use_pkey" },
	{ ERR_PACK(0, SUNW_F_USE_TASTORE, 0),	   "sunw_use_tastore" },
	{ ERR_PACK(0, SUNW_F_USE_CERTFILE, 0),	   "sunw_p12_use_certfile" },
	{ ERR_PACK(0, SUNW_F_USE_KEYFILE, 0),	   "sunw_p12_use_keyfile" },
	{ ERR_PACK(0, SUNW_F_USE_TRUSTFILE, 0),	   "sunw_p12_use_trustfile" },
	{ ERR_PACK(0, SUNW_F_READ_FILE, 0),	   "p12_read_file" },
	{ ERR_PACK(0, SUNW_F_DOPARSE, 0),	   "p12_doparse" },
	{ ERR_PACK(0, SUNW_F_PKCS12_PARSE, 0),	   "sunw_PKCS12_parse" },
	{ ERR_PACK(0, SUNW_F_PKCS12_CONTENTS, 0),  "sunw_PKCS12_contents" },
	{ ERR_PACK(0, SUNW_F_PARSE_ONE_BAG, 0),	   "parse_one_bag" },
	{ ERR_PACK(0, SUNW_F_PKCS12_CREATE, 0),	   "sunw_PKCS12_create" },
	{ ERR_PACK(0, SUNW_F_SPLIT_CERTS, 0),	   "sunw_split_certs" },
	{ ERR_PACK(0, SUNW_F_FIND_LOCALKEYID, 0),  "sunw_find_localkeyid" },
	{ ERR_PACK(0, SUNW_F_SET_LOCALKEYID, 0),   "sunw_set_localkeyid" },
	{ ERR_PACK(0, SUNW_F_GET_LOCALKEYID, 0),   "sunw_get_localkeyid" },
	{ ERR_PACK(0, SUNW_F_GET_PKEY_FNAME, 0),   "sunw_get_pkey_fname" },
	{ ERR_PACK(0, SUNW_F_APPEND_KEYS, 0),	   "sunw_append_keys" },
	{ ERR_PACK(0, SUNW_F_PEM_INFO, 0),	   "pem_info" },
	{ ERR_PACK(0, SUNW_F_ASC2BMPSTRING, 0),	   "asc2bmpstring" },
	{ ERR_PACK(0, SUNW_F_UTF82ASCSTR, 0),	   "utf82ascstr" },
	{ ERR_PACK(0, SUNW_F_FINDATTR, 0),	   "findattr" },
	{ ERR_PACK(0, SUNW_F_TYPE2ATTRIB, 0),	   "type2attrib" },
	{ ERR_PACK(0, SUNW_F_MOVE_CERTS, 0),	   "move_certs" },
	{ ERR_PACK(0, SUNW_F_FIND_FNAME, 0),	   "sunw_find_fname" },
	{ ERR_PACK(0, SUNW_F_PARSE_OUTER, 0),	   "parse_outer" },
	{ ERR_PACK(0, SUNW_F_CHECKFILE, 0),	   "checkfile" },
	{ 0, NULL }
};

/* Error codes and their matching strings */
static ERR_STRING_DATA SUNW_str_reasons[] = {
	{ SUNW_R_INVALID_ARG,		"invalid argument" },
	{ SUNW_R_MEMORY_FAILURE,	"memory failure" },
	{ SUNW_R_MAC_VERIFY_FAILURE,	"mac verify failure" },
	{ SUNW_R_MAC_CREATE_FAILURE,	"mac create failure" },
	{ SUNW_R_BAD_FILETYPE,		"bad file type" },
	{ SUNW_R_BAD_PKEY,		"bad or missing private key" },
	{ SUNW_R_BAD_PKEYTYPE,		"unsupported key type" },
	{ SUNW_R_PKEY_READ_ERR,		"unable to read private key" },
	{ SUNW_R_NO_TRUST_ANCHOR,	"no trust anchors found" },
	{ SUNW_R_READ_TRUST_ERR,	"unable to read trust anchor" },
	{ SUNW_R_ADD_TRUST_ERR,		"unable to add trust anchor" },
	{ SUNW_R_PKCS12_PARSE_ERR,	"PKCS12 parse error" },
	{ SUNW_R_PKCS12_CREATE_ERR,	"PKCS12 create error" },
	{ SUNW_R_BAD_CERTTYPE,		"unsupported certificate type" },
	{ SUNW_R_PARSE_CERT_ERR,	"error parsing PKCS12 certificate" },
	{ SUNW_R_PARSE_BAG_ERR,		"error parsing PKCS12 bag" },
	{ SUNW_R_MAKE_BAG_ERR,		"error making PKCS12 bag" },
	{ SUNW_R_BAD_LKID,		"bad localKeyID format" },
	{ SUNW_R_SET_LKID_ERR,		"error setting localKeyID" },
	{ SUNW_R_BAD_FNAME,		"bad friendlyName format" },
	{ SUNW_R_SET_FNAME_ERR,		"error setting friendlyName" },
	{ SUNW_R_BAD_TRUST,		"bad or missing trust anchor" },
	{ SUNW_R_BAD_BAGTYPE,		"unsupported bag type" },
	{ SUNW_R_CERT_ERR,		"certificate error" },
	{ SUNW_R_PKEY_ERR,		"private key error" },
	{ SUNW_R_READ_ERR,		"error reading file" },
	{ SUNW_R_ADD_ATTR_ERR,		"error adding attribute" },
	{ SUNW_R_STR_CONVERT_ERR,	"error converting string" },
	{ SUNW_R_PKCS12_EMPTY_ERR,	"empty PKCS12 structure" },
	{ SUNW_R_PASSWORD_ERR,		"bad password" },
	{ 0, NULL }
};

/*
 * The library name that our module will be known as. This name
 * may be retrieved via OpenSSLs error APIs.
 */
static ERR_STRING_DATA SUNW_lib_name[] = {
	{ 0,	SUNW_LIB_NAME },
	{ 0, NULL }
};
#endif

/*
 * The value of this variable (initialized by a call to
 * ERR_load_SUNW_strings()) is what identifies our errors
 * to OpenSSL as being ours.
 */
static int SUNW_lib_error_code = 0;

/*
 * Called by our PKCS12 code to read our function and error codes
 * into memory so that the OpenSSL framework can retrieve them.
 */
void
ERR_load_SUNW_strings(void)
{
	assert(SUNW_lib_error_code == 0);
#ifndef OPENSSL_NO_ERR
	/*
	 * Have OpenSSL provide us with a unique ID.
	 */
	SUNW_lib_error_code = ERR_get_next_error_library();

	ERR_load_strings(SUNW_lib_error_code, SUNW_str_functs);
	ERR_load_strings(SUNW_lib_error_code, SUNW_str_reasons);

	SUNW_lib_name->error = ERR_PACK(SUNW_lib_error_code, 0, 0);
	ERR_load_strings(0, SUNW_lib_name);
#endif
}

/*
 * The SUNWerr macro resolves to this routine. So when we need
 * to push an error, this routine does it for us. Notice that
 * the SUNWerr macro provides a filename and line #.
 */
void
ERR_SUNW_error(int function, int reason, char *file, int line)
{
	assert(SUNW_lib_error_code != 0);
#ifndef OPENSSL_NO_ERR
	ERR_PUT_error(SUNW_lib_error_code, function, reason, file, line);
#endif
}
