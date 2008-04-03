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
 */

#ifndef _PKTOOL_COMMON_H
#define	_PKTOOL_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains data and functions shared between all the
 * modules that comprise this tool.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <cryptoutil.h>

/* I18N helpers. */
#include <libintl.h>
#include <locale.h>
#include <errno.h>
#include <kmfapi.h>

/* Defines used throughout */

/* Error codes */
#define	PK_ERR_NONE		0
#define	PK_ERR_USAGE		1
#define	PK_ERR_QUIT		2
#define	PK_ERR_PK11		3
#define	PK_ERR_SYSTEM		4
#define	PK_ERR_OPENSSL		5
#define	PK_ERR_NSS		6

/* Types of objects for searches. */
#define	PK_PRIVATE_OBJ		0x0001
#define	PK_PUBLIC_OBJ		0x0002
#define	PK_CERT_OBJ		0x0010
#define	PK_PRIKEY_OBJ		0x0020
#define	PK_PUBKEY_OBJ		0x0040
#define	PK_SYMKEY_OBJ		0x0080
#define	PK_CRL_OBJ		0x0100

#define	PK_KEY_OBJ		(PK_PRIKEY_OBJ | PK_PUBKEY_OBJ | PK_SYMKEY_OBJ)
#define	PK_ALL_OBJ		(PK_PRIVATE_OBJ | PK_PUBLIC_OBJ |\
				PK_CERT_OBJ| PK_CRL_OBJ | PK_KEY_OBJ)

#define	PK_DEFAULT_KEYTYPE	"rsa"
#define	PK_DEFAULT_KEYLENGTH	1024
#define	PK_DEFAULT_DIRECTORY	"."
#define	PK_DEFAULT_SERIALNUM	1
#define	PK_DEFAULT_PK11TOKEN	SOFT_TOKEN_LABEL

/* Constants for attribute templates. */
extern CK_BBOOL	pk_false;
extern CK_BBOOL	pk_true;

typedef struct {
	int	eku_count;
	int	*critlist;
	KMF_OID	*ekulist;
} EKU_LIST;

/* Common functions. */
extern CK_RV	init_pk11(void);
extern void	final_pk11(CK_SESSION_HANDLE sess);

extern CK_RV	login_token(CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR pin,
		    CK_ULONG pinlen, CK_SESSION_HANDLE_PTR sess);

extern CK_RV	quick_start(CK_SLOT_ID slot_id, CK_FLAGS sess_flags,
		    CK_UTF8CHAR_PTR pin, CK_ULONG pinlen,
		    CK_SESSION_HANDLE_PTR sess);

extern CK_RV	get_pin(char *prompt1, char *prompt2, CK_UTF8CHAR_PTR *pin,
		    CK_ULONG *pinlen);
extern boolean_t	yesno(char *prompt, char *invalid, boolean_t dflt);

extern CK_RV	get_token_slots(CK_SLOT_ID_PTR *slot_list,
		    CK_ULONG *slot_count);

extern int get_subname(char **);
extern int get_serial(char **);
extern int get_certlabel(char **);
extern int get_filename(char *, char **);

extern int	getopt_av(int argc, char * const argv[], const char *optstring);
extern char	*optarg_av;
extern int	optind_av;

int OT2Int(char *);
int PK2Int(char *);
KMF_KEYSTORE_TYPE KS2Int(char *);
int Str2KeyType(char *, KMF_KEY_ALG *, KMF_ALGORITHM_INDEX *);
int Str2SymKeyType(char *, KMF_KEY_ALG *);
int Str2Lifetime(char *, uint32_t *);
KMF_RETURN select_token(void *, char *, int);
KMF_RETURN configure_nss(void *, char *, char *);

KMF_ENCODE_FORMAT Str2Format(char *);
KMF_RETURN get_pk12_password(KMF_CREDENTIAL *);
KMF_RETURN hexstring2bytes(uchar_t *, uchar_t **, size_t *);
KMF_RETURN verify_altname(char *arg, KMF_GENERALNAMECHOICES *, int *);
KMF_RETURN verify_keyusage(char *arg, uint16_t *, int *);
KMF_RETURN verify_file(char *);
KMF_RETURN verify_ekunames(char *, EKU_LIST **);
KMF_RETURN token_auth_needed(KMF_HANDLE_T, char *, int *);

void free_eku_list(EKU_LIST *);

int yn_to_int(char *);

int get_token_password(KMF_KEYSTORE_TYPE, char *, KMF_CREDENTIAL *);
void display_error(void *, KMF_RETURN, char *);

#define	DEFAULT_NSS_TOKEN	"internal"
#define	DEFAULT_TOKEN_PROMPT	"Enter PIN for %s: "

#define	EMPTYSTRING(s) (s == NULL || !strlen((char *)s))

#ifdef __cplusplus
}
#endif

#endif /* _PKTOOL_COMMON_H */
