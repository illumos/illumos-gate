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

/*
 *	nis_dhext.h: NIS+ extended Diffie-Hellman interface.
 */

#ifndef _NIS_DHEXT_H
#define	_NIS_DHEXT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <rpc/rpc.h>
#include <rpc/key_prot.h>
#include <rpcsvc/nis.h>   /* to get nis_server */


#define	AUTH_DES_KEYLEN  192
#define	AUTH_DES_ALGTYPE 0
#define	AUTH_DES_AUTH_TYPE "DES"

#define	AUTH_DES_KEY(k, a) (((k) == AUTH_DES_KEYLEN) && \
			    ((a) == AUTH_DES_ALGTYPE))

#define	BITS2NIBBLES(b)	((b)/4)

#define	NIS_SVCNAME_NISD	"nisd"
#define	NIS_SVCNAME_NISPASSWD	"nispasswd"

typedef struct extdhkey {
	ushort_t	keylen;
	ushort_t	algtype;
	uchar_t		key[1];
} extdhkey_t;

char *__nis_dhext_extract_pkey(netobj *, keylen_t, algtype_t);
int __nis_dhext_extract_keyinfo(nis_server *, extdhkey_t **);


/*
 * NIS+ Security conf file
 */

#define	NIS_SEC_CF_PATHNAME		"/etc/rpcsec/nisplussec.conf"
#define	NIS_SEC_CF_MAX_FLDLEN		MAX_GSS_NAME


typedef struct {
		char			*mechname;
		char			*alias;
		keylen_t		keylen;
		algtype_t		algtype;
		char			*qop;
		rpc_gss_service_t	secserv;
} mechanism_t;

/* The string that indicates AUTH_DES compat in the nis sec conf file. */
#define	NIS_SEC_CF_DES_ALIAS		"des"

/*
 * The value a keylen or algtype mechanism_t element will be set
 * to if the conf file indicates "not applicable" for that field.
 * Except if the alias is equal to NIS_SEC_CF_DES_ALIAS,
 * then the keylen is set to 192 and the algtype to 0.
 */
#define	NIS_SEC_CF_NA_KA		-1

/* Is the NIS+ security conf file mech entry a real live GSS mech? */
#define	NIS_SEC_CF_GSS_MECH(mp)	((mp)->mechname != NULL)

#define	AUTH_DES_COMPAT_CHK(mp)	((mp)->alias && \
					(strncasecmp(NIS_SEC_CF_DES_ALIAS, \
					(mp)->alias,\
					sizeof (NIS_SEC_CF_DES_ALIAS) + 1) \
					== 0))

#define	VALID_GSS_MECH(m)	((m) != NULL)

/* valid keylen and algtype check */
#define	VALID_KEYALG(k, a)	((k) != NIS_SEC_CF_NA_KA && \
					(a) != NIS_SEC_CF_NA_KA)

#define	VALID_ALIAS(a)	((a) != NULL)

#define	VALID_MECH_ENTRY(mp) (VALID_GSS_MECH((mp)->mechname) && \
				VALID_KEYALG((mp)->keylen, (mp)->algtype) &&\
				VALID_ALIAS((mp)->alias))

/* Is the mech entry of the public key crypto variety? */
#define	MECH_PK_TECH(mp)  (((mp)->alias)[0] == 'd' && ((mp)->alias)[1] == 'h')

#define	MECH_MAXATNAME 32	/* Mechanism max size of auth_type name */
#define	MECH_MAXALIASNAME 32	/* Mechanism max size of mech alias name */

mechanism_t ** __nis_get_mechanisms(bool_t);
int __nis_translate_mechanism(const char *, int *, int *);
void __nis_release_mechanisms(mechanism_t **);
char *__nis_mechname2alias(const char *, char *, size_t);
char *__nis_authtype2mechalias(const char *, char *, size_t);
char *__nis_mechalias2authtype(const char *, char *, size_t);
char *__nis_keyalg2mechalias(keylen_t, algtype_t, char *, size_t);
char *__nis_keyalg2authtype(keylen_t, algtype_t, char *, size_t);


/*
 * NIS+ GSS Mech Dynamic Library Loading
 */

#define	MAXDHNAME	64

char *__nis_get_mechanism_library(keylen_t keylen, algtype_t algtype,
					char *buffer, size_t buflen);

void *__nis_get_mechanism_symbol(keylen_t keylen, algtype_t algtype,
					const char *);


/*
 * misc prototypes
 */

CLIENT *nis_make_rpchandle_gss_svc(nis_server *, int, rpcprog_t, rpcvers_t,
					uint_t, int, int, char *, char *);
CLIENT *nis_make_rpchandle_gss_svc_ruid(nis_server *, int, rpcprog_t, rpcvers_t,
					uint_t, int, int, char *, char *);
nis_server *__nis_host2nis_server_g(const char *, bool_t, bool_t, int *);
int __nis_gssprin2netname(rpc_gss_principal_t, char []);
void __nis_auth2princ_rpcgss(char *, struct svc_req *, bool_t, int);

void des_setparity_g(des_block *);
int passwd2des_g(const char *, const char *, int, des_block *, bool_t);
int getpublickey_g(const char [], keylen_t, algtype_t, char *, size_t);
int getsecretkey_g(const char *, keylen_t, algtype_t, char *, size_t,
			const char *);
int __getpublickey_cached_g(const char [], keylen_t, algtype_t, char *, size_t,
					int *);
void __getpublickey_flush_g(const char *, keylen_t, algtype_t);
int __gen_dhkeys_g(char *, char *, keylen_t, algtype_t, char *);
int __gen_common_dhkeys_g(char *, char *, keylen_t, algtype_t, des_block [],
	keynum_t);
int __cbc_triple_crypt(des_block [], char *, uint_t, uint_t, char *);
int key_get_conv_g(const char *, keylen_t, algtype_t, des_block [], keynum_t);
int key_secretkey_is_set_g(keylen_t, algtype_t);
int key_removesecret_g(void);
int key_setnet_g(const char *, const char *, keylen_t, const char *,
			keylen_t, algtype_t);
int xencrypt_g(char *, keylen_t, algtype_t, const char *, const char [],
		char **, bool_t);
int xdecrypt_g(char *, keylen_t, algtype_t, const char *, const char [],
		bool_t);

#ifdef __cplusplus
}
#endif

#endif /* !_NIS_DHEXT_H */
