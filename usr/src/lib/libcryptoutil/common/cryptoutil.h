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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2014, OmniTI Computer Consulting, Inc. All rights reserved.
 */

#ifndef _CRYPTOUTIL_H
#define	_CRYPTOUTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <syslog.h>
#include <security/cryptoki.h>
#include <sys/param.h>

#define	LOG_STDERR	-1
#define	SUCCESS		0
#define	FAILURE		1
#define	MECH_ID_HEX_LEN	11	/* length of mechanism id in hex form */

#define	_PATH_PKCS11_CONF	"/etc/crypto/pkcs11.conf"
#define	_PATH_KCF_CONF		"/etc/crypto/kcf.conf"
#define	_PATH_KCFD_LOCK		"/var/run/kcfd.lock"

/* $ISA substitution for parsing pkcs11.conf data */
#define	PKCS11_ISA	"/$ISA/"
#if defined(_LP64)
#define	PKCS11_ISA_DIR	"/64/"
#else	/* !_LP64 */
#define	PKCS11_ISA_DIR	"/"
#endif

/* keywords and delimiters for parsing configuration files */
#define	SEP_COLON	":"
#define	SEP_SEMICOLON	";"
#define	SEP_EQUAL	"="
#define	SEP_COMMA	","
#define	METASLOT_KEYWORD	"metaslot"
#define	FIPS_KEYWORD	"fips-140"
#define	EF_DISABLED	"disabledlist="
#define	EF_ENABLED	"enabledlist="
#define	EF_NORANDOM	"NO_RANDOM"
#define	METASLOT_TOKEN	"metaslot_token="
#define	METASLOT_SLOT	"metaslot_slot="
#define	METASLOT_STATUS	"metaslot_status="
#define	EF_FIPS_STATUS	"fips_status="
#define	METASLOT_AUTO_KEY_MIGRATE	"metaslot_auto_key_migrate="
#define	ENABLED_KEYWORD		"enabled"
#define	DISABLED_KEYWORD	"disabled"
#define	SLOT_DESCRIPTION_SIZE	64
#define	TOKEN_LABEL_SIZE	32
#define	TOKEN_MANUFACTURER_SIZE	32
#define	TOKEN_SERIAL_SIZE	16
#define	CRYPTO_FIPS_MODE_DISABLED	0
#define	CRYPTO_FIPS_MODE_ENABLED	1

/*
 * Define the following softtoken values that are used by softtoken
 * library, cryptoadm and pktool command.
 */
#define	SOFT_SLOT_DESCRIPTION	\
			"Sun Crypto Softtoken            " \
			"                                "
#define	SOFT_TOKEN_LABEL	"Sun Software PKCS#11 softtoken  "
#define	SOFT_TOKEN_SERIAL	"                "
#define	SOFT_MANUFACTURER_ID	"Sun Microsystems, Inc.          "
#define	SOFT_DEFAULT_PIN	"changeme"

typedef char libname_t[MAXPATHLEN];
typedef char midstr_t[MECH_ID_HEX_LEN];

typedef struct umechlist {
	midstr_t		name;	/* mechanism name in hex form */
	struct umechlist	*next;
} umechlist_t;

typedef struct uentry {
	libname_t	name;
	boolean_t	flag_norandom; /* TRUE if random is disabled */
	boolean_t	flag_enabledlist; /* TRUE if an enabledlist */
	umechlist_t	*policylist; /* disabledlist or enabledlist */
	boolean_t	flag_metaslot_enabled; /* TRUE if metaslot's enabled */
	boolean_t	flag_metaslot_auto_key_migrate;
	CK_UTF8CHAR	metaslot_ks_slot[SLOT_DESCRIPTION_SIZE + 1];
	CK_UTF8CHAR	metaslot_ks_token[TOKEN_LABEL_SIZE + 1];
	int 		count;
	boolean_t	flag_fips_enabled;
} uentry_t;

typedef struct uentrylist {
	uentry_t	*puent;
	struct uentrylist	*next;
} uentrylist_t;

/* Return codes for pkcs11_parse_uri() */
#define	PK11_URI_OK		0
#define	PK11_URI_INVALID	1
#define	PK11_MALLOC_ERROR	2
#define	PK11_URI_VALUE_OVERFLOW	3
#define	PK11_NOT_PKCS11_URI	4

/*
 * There is no limit for the attribute length in the spec. 256 bytes should be
 * enough for the object name.
 */
#define	PK11_MAX_OBJECT_LEN		256
/*
 * CKA_ID is of type "byte array" which can be of arbitrary length. 256 bytes
 * should be sufficient though.
 */
#define	PK11_MAX_ID_LEN			256

/* Structure for the PKCS#11 URI. */
typedef struct pkcs11_uri_t {
	/* CKA_LABEL attribute to the C_FindObjectsInit function. */
	CK_UTF8CHAR_PTR	object;
	/*
	 * CKA_CLASS attribute to the C_FindObjectsInit function. The
	 * "objecttype" URI attribute can have a value one of "private",
	 * "public", "cert", "secretkey", and "data". The "objecttype" field can
	 * have a value of CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKO_CERTIFICATE,
	 * CKO_SECRET_KEY, and CKO_DATA. This attribute cannot be empty in the
	 * URI.
	 */
	CK_ULONG	objecttype;
	/* CKO_DATA is 0 so we need this flag. Not part of the URI itself. */
	boolean_t	objecttype_present;
	/*
	 * Token, manufufacturer, serial and model are of fixed size length in
	 * the specification. We allocate memory on the fly to distinguish
	 * between an attribute not present and an empty value. We check for
	 * overflows. We always terminate the string with '\0' even when that is
	 * not used in the PKCS#11's CK_TOKEN_INFO structure (fields are padded
	 * with spaces).
	 */
	/* Token label from CK_TOKEN_INFO. */
	CK_UTF8CHAR_PTR	token;
	/* ManufacturerID from CK_TOKEN_INFO. */
	CK_UTF8CHAR_PTR	manuf;
	/* SerialNumber from CK_TOKEN_INFO. */
	CK_CHAR_PTR	serial;
	/* Model from CK_TOKEN_INFO. */
	CK_UTF8CHAR_PTR	model;
	/* This is a byte array, we need a length parameter as well. */
	CK_BYTE_PTR	id;
	int		id_len;
	/*
	 * Location of the file with a token PIN. Application can overload this,
	 * eg. "/bin/askpass|" may mean to read the PIN from a command. However,
	 * the pkcs11_parse_uri() function does not interpret this field in any
	 * way.
	 */
	char		*pinfile;
} pkcs11_uri_t;

extern void cryptodebug(const char *fmt, ...);
extern void cryptoerror(int priority, const char *fmt, ...);
extern void cryptodebug_init(const char *prefix);
extern void cryptoerror_off();
extern void cryptoerror_on();

extern const char *pkcs11_mech2str(CK_MECHANISM_TYPE mech);
extern CK_RV pkcs11_str2mech(char *mech_str, CK_MECHANISM_TYPE_PTR mech);

extern int get_pkcs11conf_info(uentrylist_t **);
extern umechlist_t *create_umech(char *);
extern void free_umechlist(umechlist_t *);
extern void free_uentrylist(uentrylist_t *);
extern void free_uentry(uentry_t *);
extern uentry_t *getent_uef(char *);

extern void tohexstr(uchar_t *bytes, size_t blen, char *hexstr, size_t hexlen);
extern int hexstr_to_bytes(char *hexstr, size_t hexlen, uchar_t **bytes,
    size_t *blen);
extern CK_RV pkcs11_mech2keytype(CK_MECHANISM_TYPE mech_type,
    CK_KEY_TYPE *ktype);
extern CK_RV pkcs11_mech2keygen(CK_MECHANISM_TYPE mech_type,
    CK_MECHANISM_TYPE *gen_mech);
extern char *pkcs11_strerror(CK_RV rv);

extern int
get_metaslot_info(boolean_t  *status_enabled, boolean_t *migrate_enabled,
    char **objectstore_slot_info, char **objectstore_token_info);

extern char *get_fullpath(char *dir, char *filepath);
extern int str2lifetime(char *ltimestr, uint32_t *ltime);

extern char *pkcs11_default_token(void);
extern int pkcs11_get_pass(char *token_name, char **pdata, size_t *psize,
    size_t min_psize, boolean_t with_confirmation);

extern int pkcs11_seed_urandom(void *sbuf, size_t slen);
extern int pkcs11_get_random(void *dbuf, size_t dlen);
extern int pkcs11_get_urandom(void *dbuf, size_t dlen);
extern int pkcs11_get_nzero_urandom(void *dbuf, size_t dlen);
extern int pkcs11_read_data(char *filename, void **dbuf, size_t *dlen);

extern int open_nointr(const char *path, int oflag, ...);
extern ssize_t readn_nointr(int fd, void *dbuf, size_t dlen);
extern ssize_t writen_nointr(int fd, void *dbuf, size_t dlen);
extern int update_conf(char *conf_file, char *entry);

extern int pkcs11_parse_uri(const char *str, pkcs11_uri_t *uri);
extern void pkcs11_free_uri(pkcs11_uri_t *uri);

#ifdef __cplusplus
}
#endif

#endif /* _CRYPTOUTIL_H */
