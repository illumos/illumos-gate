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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBELFSIGN_H
#define	_LIBELFSIGN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * libelfsign Private Interfaces
 * This Header file should not be shipped as part of Solaris binary or
 * source products.
 */

#include <sys/crypto/elfsign.h>
#include <libelf.h>
#include <fcntl.h>
#include <md5.h>
#include <sha1.h>
#include <kmfapi.h>

/*
 * Certificate-related definitions
 */
#define	ELFSIGN_CRYPTO		"Solaris Cryptographic Framework"
#define	USAGELIMITED		"OU=UsageLimited"
#define	ESA			".esa"
#define	ESA_LEN			sizeof (".esa")

typedef enum ELFCert_VStatus_e {
	E_UNCHECKED,
	E_OK,
	E_IS_TA,
	E_FAILED
} ELFCert_VStatus_t;

typedef struct ELFCert_s {
	ELFCert_VStatus_t	c_verified;
	char			*c_subject;
	char			*c_issuer;
	KMF_X509_DER_CERT	c_cert;
	KMF_KEY_HANDLE		c_privatekey;
}	*ELFCert_t;

#define	CRYPTO_CERTS_DIR	"/etc/crypto/certs"
#define	ETC_CERTS_DIR		"/etc/certs"

/*
 * libelfsign actions
 */
enum ES_ACTION {
	ES_GET,
	ES_GET_CRYPTO,
	ES_UPDATE,
	ES_UPDATE_RSA_MD5_SHA1,
	ES_UPDATE_RSA_SHA1
};
#define	ES_ACTISUPDATE(a)	((a) >= ES_UPDATE)

/*
 * Context for elfsign operation
 */
struct ELFsign_s {
	Elf	*es_elf;
	char	*es_pathname;
	char	*es_certpath;
	int	es_fd;
	size_t	es_shstrndx;
	enum ES_ACTION	es_action;
	KMF_KEY_HANDLE		es_privatekey;
	filesig_vers_t	es_version;
	boolean_t	es_same_endian;
	boolean_t	es_has_phdr;
	char		es_ei_class;
	struct flock	es_flock;
	KMF_HANDLE_T	es_kmfhandle;
	void		*es_callbackctx;
	void		(*es_sigvercallback)(void *, void *, size_t, ELFCert_t);
	void		(*es_certCAcallback)(void *, ELFCert_t, char *);
	void		(*es_certvercallback)(void *, ELFCert_t, ELFCert_t);
};

#define	ES_FMT_RSA_MD5_SHA1	"rsa_md5_sha1"
#define	ES_FMT_RSA_SHA1		"rsa_sha1"

/*
 * ELF signature handling
 */
typedef struct ELFsign_s *ELFsign_t;
struct ELFsign_sig_info {
	char	*esi_format;
	char	*esi_signer;
	time_t	esi_time;
};

extern struct filesignatures *elfsign_insert_dso(ELFsign_t ess,
    struct filesignatures *fsp, const char *dn, int dn_len,
    const uchar_t *sig, int sig_len, const char *oid, int oid_len);
extern filesig_vers_t elfsign_extract_sig(ELFsign_t ess,
    struct filesignatures *fsp, uchar_t *sig, size_t *sig_len);
extern ELFsign_status_t elfsign_begin(const char *,
    enum ES_ACTION, ELFsign_t *);
extern void elfsign_end(ELFsign_t ess);
extern ELFsign_status_t elfsign_setcertpath(ELFsign_t ess, const char *path);
extern ELFsign_status_t elfsign_verify_signature(ELFsign_t ess,
    struct ELFsign_sig_info **esipp);
extern ELFsign_status_t elfsign_hash(ELFsign_t ess, uchar_t *hash,
    size_t *hash_len);
extern ELFsign_status_t elfsign_hash_mem_resident(ELFsign_t ess,
    uchar_t *hash, size_t *hash_len);
extern ELFsign_status_t elfsign_hash_esa(ELFsign_t ess,
    uchar_t *esa_buf, size_t esa_buf_len, uchar_t **hash, size_t *hash_len);
extern void elfsign_buffer_len(ELFsign_t ess, size_t *ip, uchar_t *cp,
    enum ES_ACTION action);

extern void elfsign_setcallbackctx(ELFsign_t ess, void *ctx);
extern void elfsign_setsigvercallback(ELFsign_t ess,
    void (*cb)(void *, void *, size_t, ELFCert_t));
extern ELFsign_status_t elfsign_signatures(ELFsign_t ess,
    struct filesignatures **fspp, size_t *fs_len, enum ES_ACTION action);

extern char const *elfsign_strerror(ELFsign_status_t);
extern boolean_t elfsign_sig_info(struct filesignatures *fssp,
    struct ELFsign_sig_info **esipp);
extern void elfsign_sig_info_free(struct ELFsign_sig_info *);

/*
 * ELF "Certificate Library"
 */

extern const char _PATH_ELFSIGN_CERTS[];

#define	ELFCERT_MAX_DN_LEN	255

extern boolean_t elfcertlib_init(ELFsign_t);
extern void elfcertlib_fini(ELFsign_t);
extern boolean_t elfcertlib_settoken(ELFsign_t, char *);
extern void elfcertlib_setcertCAcallback(ELFsign_t ess,
    void (*cb)(void *, ELFCert_t, char *));
extern void elfcertlib_setcertvercallback(ELFsign_t ess,
    void (*cb)(void *, ELFCert_t, ELFCert_t));

extern boolean_t elfcertlib_getcert(ELFsign_t ess, char *cert_pathname,
	char *signer_DN, ELFCert_t *certp, enum ES_ACTION action);
extern void elfcertlib_releasecert(ELFsign_t, ELFCert_t);
extern char *elfcertlib_getdn(ELFCert_t cert);
extern char *elfcertlib_getissuer(ELFCert_t cert);

extern boolean_t elfcertlib_loadprivatekey(ELFsign_t ess, ELFCert_t cert,
	const char *path);
extern boolean_t elfcertlib_loadtokenkey(ELFsign_t ess, ELFCert_t cert,
	const char *token_id, const char *pin);

extern boolean_t elfcertlib_sign(ELFsign_t ess, ELFCert_t cert,
	const uchar_t *data, size_t data_len, uchar_t *sig,
	size_t *sig_len);

extern boolean_t elfcertlib_verifycert(ELFsign_t ess, ELFCert_t cert);
extern boolean_t elfcertlib_verifysig(ELFsign_t ess, ELFCert_t cert,
	const uchar_t *sig, size_t sig_len,
	const uchar_t *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* _LIBELFSIGN_H */
