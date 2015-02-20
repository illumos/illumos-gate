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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file comprises the main driver for this tool.
 * Upon parsing the command verbs from user input, it
 * branches to the appropriate modules to perform the
 * requested task.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <malloc.h>
#include <libintl.h>
#include <libgen.h>
#include <errno.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include "common.h"

/*
 * The verbcmd construct allows genericizing information about a verb so
 * that it is easier to manipulate.  Makes parsing code easier to read,
 * fix, and extend with new verbs.
 */
typedef struct verbcmd_s {
	char	*verb;
	int	(*action)(int, char *[]);
	int	mode;
	char	*summary;
	char	*synopsis;
} verbcmd;

/* External declarations for supported verb actions. */
extern int	pk_setpin(int argc, char *argv[]);
extern int	pk_list(int argc, char *argv[]);
extern int	pk_delete(int argc, char *argv[]);
extern int	pk_import(int argc, char *argv[]);
extern int	pk_export(int argc, char *argv[]);
extern int	pk_tokens(int argc, char *argv[]);
extern int	pk_gencert(int argc, char *argv[]);
extern int	pk_gencsr(int argc, char *argv[]);
extern int	pk_download(int argc, char *argv[]);
extern int	pk_genkey(int argc, char *argv[]);
extern int	pk_signcsr(int argc, char *argv[]);
extern int	pk_inittoken(int argc, char *argv[]);
extern int	pk_genkeypair(int argc, char *argv[]);

/* Forward declarations for "built-in" verb actions. */
static int	pk_help(int argc, char *argv[]);

#define	TOKEN_IDX 0
#define	TOKEN_VERB "tokens"
#define	TOKEN_SUMM gettext("lists all visible PKCS#11 tokens")
#define	TOKEN_SYN  "tokens"

#define	SETPIN_IDX 1
#define	SETPIN_VERB "setpin"
#define	SETPIN_SUMM gettext("changes user authentication passphrase "\
	"for keystore access")
#define	SETPIN_SYN \
	"setpin [ keystore=pkcs11 ]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ usertype=so|user ]\n\t" \
\
	"setpin keystore=nss\n\t\t" \
	"[ token=token ]\n\t\t" \
	"[ dir=directory-path ]\n\t\t" \
	"[ prefix=DBprefix ]\n\t"

#define	LIST_IDX 2
#define	LIST_VERB "list"
#define	LIST_SUMM gettext("lists a summary of objects in the keystore")
#define	LIST_SYN \
	"list [ token=token[:manuf[:serial]]]\n\t\t" \
	"[ objtype=private|public|both ]\n\t\t" \
	"[ label=label ]\n\t" \
 \
	"list objtype=cert[:[public | private | both ]]\n\t\t" \
	"[ subject=subject-DN ]\n\t\t" \
	"[ keystore=pkcs11 ]\n\t\t" \
	"[ issuer=issuer-DN ]\n\t\t" \
	"[ serial=serial number ]\n\t\t" \
	"[ label=cert-label ]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ criteria=valid|expired|both ]\n\t" \
 \
	"list objtype=key[:[public | private | both ]]\n\t\t" \
	"[ keystore=pkcs11 ]\n\t\t" \
	"[ label=key-label ]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t" \
 \
	"list keystore=pkcs11 objtype=crl\n\t\t" \
	"infile=crl-fn\n\t" \
 \
	"list keystore=nss objtype=cert\n\t\t" \
	"[ subject=subject-DN ]\n\t\t" \
	"[ issuer=issuer-DN ]\n\t\t" \
	"[ serial=serial number ]\n\t\t" \
	"[ nickname=cert-nickname ]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ dir=directory-path ]\n\t\t" \
	"[ prefix=DBprefix ]\n\t\t" \
	"[ criteria=valid|expired|both ]\n\t" \
 \
	"list keystore=nss objtype=key\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ dir=directory-path ]\n\t\t" \
	"[ prefix=DBprefix ]\n\t\t" \
	"[ nickname=key-nickname ]\n\t" \
 \
	"list keystore=file objtype=cert\n\t\t" \
	"[ subject=subject-DN ]\n\t\t" \
	"[ issuer=issuer-DN ]\n\t\t" \
	"[ serial=serial number ]\n\t\t" \
	"[ infile=cert-fn ]\n\t\t" \
	"[ dir=directory-path ]\n\t\t" \
	"[ criteria=valid|expired|both ]\n\t" \
 \
	"list keystore=file objtype=key\n\t\t" \
	"[ infile=key-fn ]\n\t\t" \
	"[ dir=directory-path ]\n\t" \
 \
	"list keystore=file objtype=crl\n\t\t" \
	"infile=crl-fn\n\t"

#define	DELETE_IDX 3
#define	DELETE_VERB "delete"
#define	DELETE_SUMM gettext("deletes objects in the keystore")
#define	DELETE_SYN \
	"delete [ token=token[:manuf[:serial]]]\n\t\t" \
	"[ objtype=private|public|both ]\n\t\t" \
	"[ label=object-label ]\n\t" \
 \
	"delete keystore=nss objtype=cert\n\t\t" \
	"[ subject=subject-DN ]\n\t\t" \
	"[ issuer=issuer-DN ]\n\t\t" \
	"[ serial=serial number ]\n\t\t" \
	"[ label=cert-label ]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ dir=directory-path ]\n\t\t" \
	"[ prefix=DBprefix ]\n\t\t" \
	"[ criteria=valid|expired|both ]\n\t" \
 \
	"delete keystore=nss objtype=key\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ dir=directory-path ]\n\t\t" \
	"[ prefix=DBprefix ]\n\t\t" \
	"[ nickname=key-nickname ]\n\t\t" \
 \
	"delete keystore=nss objtype=crl\n\t\t" \
	"[ nickname=issuer-nickname ]\n\t\t" \
	"[ subject=subject-DN ]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ dir=directory-path ]\n\t\t" \
	"[ prefix=DBprefix ]\n\t" \
 \
	"delete keystore=pkcs11 " \
	"objtype=cert[:[public | private | both]]\n\t\t" \
	"[ subject=subject-DN ]\n\t\t" \
	"[ issuer=issuer-DN ]\n\t\t" \
	"[ serial=serial number ]\n\t\t" \
	"[ label=cert-label ]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ criteria=valid|expired|both ]\n\t" \
 \
	"delete keystore=pkcs11 " \
	"objtype=key[:[public | private | both]]\n\t\t" \
	"[ label=key-label ]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t" \
 \
	"delete keystore=pkcs11 objtype=crl\n\t\t" \
	"infile=crl-fn\n\t" \
 \
	"delete keystore=file objtype=cert\n\t\t" \
	"[ subject=subject-DN ]\n\t\t" \
	"[ issuer=issuer-DN ]\n\t\t" \
	"[ serial=serial number ]\n\t\t" \
	"[ infile=cert-fn ]\n\t\t" \
	"[ dir=directory-path ]\n\t\t" \
	"[ criteria=valid|expired|both ]\n\t" \
 \
	"delete keystore=file objtype=key\n\t\t" \
	"[ infile=key-fn ]\n\t\t" \
	"[ dir=directory-path ]\n\t" \
 \
	"delete keystore=file objtype=crl\n\t\t" \
	"infile=crl-fn\n\t"

#define	IMPORT_IDX 4
#define	IMPORT_VERB "import"
#define	IMPORT_SUMM gettext("imports objects from an external source")
#define	IMPORT_SYN \
	"import [token=token[:manuf[:serial]]]\n\t\t" \
	"infile=input-fn\n\t" \
 \
	"import keystore=nss objtype=cert\n\t\t" \
	"infile=input-fn\n\t\t" \
	"label=cert-label\n\t\t" \
	"[ trust=trust-value ]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ dir=directory-path ]\n\t\t" \
	"[ prefix=DBprefix ]\n\t" \
 \
	"import keystore=nss objtype=crl\n\t\t" \
	"infile=input-fn\n\t\t" \
	"[ verifycrl=y|n ]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ dir=directory-path ]\n\t\t" \
	"[ prefix=DBprefix ]\n\t" \
 \
	"import keystore=pkcs11\n\t\t" \
	"infile=input-fn\n\t\t" \
	"label=label\n\t\t" \
	"[ objtype=cert|key ]\n\t\t" \
	"[ keytype=aes|arcfour|des|3des|generic ]\n\t\t" \
	"[ sensitive=y|n ]\n\t\t" \
	"[ extractable=y|n ]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t" \
 \
	"import keystore=pkcs11 objtype=crl\n\t\t" \
	"infile=input-crl-fn\n\t\t" \
	"outcrl=output-crl-fn\n\t\t" \
	"outformat=pem|der\n\t" \
 \
	"import keystore=file\n\t\t" \
	"infile=input-fn\n\t\t" \
	"outkey=output-key-fn\n\t\t" \
	"outcert=output-cert-fn\n\t\t" \
	"[ outformat=pem|der|pkcs12 ]\n\t" \
 \
	"import keystore=file objtype=crl\n\t\t" \
	"infile=input-crl-fn\n\t\t" \
	"outcrl=output-crl-fn\n\t\t" \
	"outformat=pem|der\n\t"

#define	EXPORT_IDX 5
#define	EXPORT_VERB "export"
#define	EXPORT_SUMM gettext("exports objects from the keystore to a file")
#define	EXPORT_SYN \
	"export [token=token[:manuf[:serial]]]\n\t\t" \
	"outfile=output-fn\n\t" \
 \
	"export keystore=nss\n\t\t" \
	"outfile=output-fn\n\t\t" \
	"[ objtype=cert|key ]\n\t\t" \
	"[ subject=subject-DN ]\n\t\t" \
	"[ issuer=issuer-DN ]\n\t\t" \
	"[ serial=serial number ]\n\t\t" \
	"[ nickname=cert-nickname ]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ dir=directory-path ]\n\t\t" \
	"[ prefix=DBPrefix ]\n\t\t" \
	"[ outformat=pem|der|pkcs12 ]\n\t" \
 \
	"export keystore=pkcs11\n\t\t" \
	"outfile=output-fn\n\t\t" \
	"[ objtype=cert|key ]\n\t\t" \
	"[ label=label ]\n\t\t" \
	"[ subject=subject-DN ]\n\t\t" \
	"[ issuer=issuer-DN ]\n\t\t" \
	"[ serial=serial number ]\n\t\t" \
	"[ outformat=pem|der|pkcs12|raw ]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t" \
 \
	"export keystore=file\n\t\t" \
	"certfile=cert-input-fn\n\t\t" \
	"keyfile=key-input-fn\n\t\t" \
	"outfile=output-pkcs12-fn\n\t"

#define	GENCERT_IDX 6
#define	GENCERT_VERB "gencert"
#define	GENCERT_SUMM gettext("creates a self-signed X.509v3 certificate")
#define	GENCERT_SYN \
	"gencert listcurves\n\t" \
\
	"gencert keystore=nss\n\t\t" \
	"label=cert-nickname\n\t\t" \
	"serial=serial number hex string\n\t\t" \
	"[ -i ] | [subject=subject-DN]\n\t\t" \
	"[ altname=[critical:]SubjectAltName ]\n\t\t" \
	"[ keyusage=[critical:]usage,usage,...]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ dir=directory-path ]\n\t\t" \
	"[ prefix=DBprefix ]\n\t\t" \
	"[ keytype=rsa | ec [curve=ECC Curve Name] " \
	"[hash=md5 | sha1 | sha256 | sha384 | sha512]]\n\t\t" \
	"[ keytype=dsa [hash=sha1]]\n\t\t" \
	"[ keylen=key-size ]\n\t\t" \
	"[ trust=trust-value ]\n\t\t" \
	"[ eku=[critical:]EKU name,...]\n\t\t" \
	"[ lifetime=number-hour|number-day|number-year ]\n\t" \
 \
	"gencert [ keystore=pkcs11 ]\n\t\t" \
	"label=key/cert-label\n\t\t" \
	"serial=serial number hex string\n\t\t" \
	"[ -i ] | [subject=subject-DN]\n\t\t" \
	"[ altname=[critical:]SubjectAltName ]\n\t\t" \
	"[ keyusage=[critical:]usage,usage,...]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ keytype=rsa | ec [curve=ECC Curve Name] " \
	"[hash=md5 | sha1 | sha256 | sha384 | sha512]]\n\t\t" \
	"[ keytype=dsa [hash=sha1 | sha256 ]]\n\t\t" \
	"[ keylen=key-size ]\n\t\t" \
	"[ eku=[critical:]EKU name,...]\n\t\t" \
	"[ lifetime=number-hour|number-day|number-year ]\n\t" \
 \
	"gencert keystore=file\n\t\t" \
	"outcert=cert_filename\n\t\t" \
	"outkey=key_filename\n\t\t" \
	"serial=serial number hex string\n\t\t" \
	"[ -i ] | [subject=subject-DN]\n\t\t" \
	"[ altname=[critical:]SubjectAltName ]\n\t\t" \
	"[ keyusage=[critical:]usage,usage,...]\n\t\t" \
	"[ format=der|pem ]\n\t\t" \
	"[ keytype=rsa [hash=md5 | sha1 | sha256 | sha384 | sha512]]\n\t\t" \
	"[ keytype=dsa [hash=sha1 | sha256 ]]\n\t\t" \
	"[ keylen=key-size ]\n\t\t" \
	"[ eku=[critical:]EKU name,...]\n\t\t" \
	"[ lifetime=number-hour|number-day|number-year ]\n\t"

#define	GENCSR_IDX 7
#define	GENCSR_VERB "gencsr"
#define	GENCSR_SUMM gettext("creates a PKCS#10 certificate signing " \
	"request file")

#define	GENCSR_SYN \
	"gencsr listcurves\n\t" \
\
	"gencsr keystore=nss \n\t\t" \
	"nickname=cert-nickname\n\t\t" \
	"outcsr=csr-fn\n\t\t" \
	"[ -i ] | [subject=subject-DN]\n\t\t" \
	"[ altname=[critical:]SubjectAltName ]\n\t\t" \
	"[ keyusage=[critical:]usage,usage,...]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ dir=directory-path ]\n\t\t" \
	"[ prefix=DBprefix ]\n\t\t" \
	"[ keytype=rsa | ec [curve=ECC Curve Name] " \
	"[hash=md5 | sha1 | sha256 | sha384 | sha512]]\n\t\t" \
	"[ keytype=dsa [hash=sha1]]\n\t\t" \
	"[ keylen=key-size ]\n\t\t" \
	"[ eku=[critical:]EKU name,...]\n\t\t" \
	"[ format=pem|der ]\n\t" \
 \
	"gencsr [ keystore=pkcs11 ]\n\t\t" \
	"label=key-label\n\t\t" \
	"outcsr=csr-fn\n\t\t" \
	"[ -i ] | [subject=subject-DN]\n\t\t" \
	"[ altname=[critical:]SubjectAltName ]\n\t\t" \
	"[ keyusage=[critical:]usage,usage,...]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ keytype=rsa | ec [curve=ECC Curve Name] " \
	"[hash=md5 | sha1 | sha256 | sha384 | sha512]]\n\t\t" \
	"[ keytype=dsa [hash=sha1 | sha256 ]]\n\t\t" \
	"[ keylen=key-size ]\n\t\t" \
	"[ eku=[critical:]EKU name,...]\n\t\t" \
	"[ format=pem|der ]]\n\t" \
 \
	"gencsr keystore=file\n\t\t" \
	"outcsr=csr-fn\n\t\t" \
	"outkey=key-fn\n\t\t" \
	"[ -i ] | [subject=subject-DN]\n\t\t" \
	"[ altname=[critical:]SubjectAltName ]\n\t\t" \
	"[ keyusage=[critical:]usage,usage,...]\n\t\t" \
	"[ keytype=rsa [hash=md5 | sha1 | sha256 | sha384 | sha512]]\n\t\t" \
	"[ keytype=dsa [hash=sha1 | sha256 ]]\n\t\t" \
	"[ keylen=key-size ]\n\t\t" \
	"[ eku=[critical:]EKU name,...]\n\t\t" \
	"[ format=pem|der ]\n\t"

#define	DOWNLOAD_IDX 8
#define	DOWNLOAD_VERB "download"
#define	DOWNLOAD_SUMM gettext("downloads a CRL or certificate file " \
	"from an external source")
#define	DOWNLOAD_SYN \
	"download url=url_str\n\t\t" \
	"[ objtype=crl|cert ]\n\t\t" \
	"[ http_proxy=proxy_str ]\n\t\t" \
	"[ outfile = outfile ]\n\t"

#define	GENKEY_IDX 9
#define	GENKEY_VERB "genkey"
#define	GENKEY_SUMM gettext("creates a symmetric key in the keystore")
#define	GENKEY_SYN \
	"genkey [ keystore=pkcs11 ]\n\t\t" \
	"label=key-label\n\t\t" \
	"[ keytype=aes|arcfour|des|3des|generic ]\n\t\t" \
	"[ keylen=key-size (AES, ARCFOUR or GENERIC only)]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ sensitive=y|n ]\n\t\t" \
	"[ extractable=y|n ]\n\t\t" \
	"[ print=y|n ]\n\t" \
 \
	"genkey keystore=nss\n\t\t" \
	"label=key-label\n\t\t" \
	"[ keytype=aes|arcfour|des|3des|generic ]\n\t\t" \
	"[ keylen=key-size (AES, ARCFOUR or GENERIC only)]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ dir=directory-path ]\n\t\t" \
	"[ prefix=DBprefix ]\n\t" \
 \
	"genkey keystore=file\n\t\t" \
	"outkey=key-fn\n\t\t" \
	"[ keytype=aes|arcfour|des|3des|generic ]\n\t\t" \
	"[ keylen=key-size (AES, ARCFOUR or GENERIC only)]\n\t\t" \
	"[ print=y|n ]\n\t"

#define	SIGNCSR_IDX 10
#define	SIGNCSR_VERB "signcsr"
#define	SIGNCSR_SUMM gettext("Sign a PKCS#10 Certificate Signing Request")
#define	SIGNCSR_SYN \
	"signcsr keystore=pkcs11\n\t\t" \
	"signkey=label (label of signing key)\n\t\t" \
	"csr=CSR filename\n\t\t" \
	"serial=serial number hex string\n\t\t" \
	"outcert=filename for final certificate\n\t\t" \
	"issuer=issuer-DN\n\t\t" \
	"[ store=y|n ] (store the new cert on the token, default=n)\n\t\t" \
	"[ outlabel=certificate label ]\n\t\t" \
	"[ format=pem|der ] (output format)\n\t\t" \
	"[ subject=subject-DN ] (new subject name)\n\t\t" \
	"[ altname=subjectAltName ]\n\t\t" \
	"[ keyusage=[critical:]usage,...]\n\t\t" \
	"[ eku=[critical:]EKU Name,...]\n\t\t" \
	"[ lifetime=number-hour|number-day|number-year ]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t" \
 \
	"signcsr keystore=file\n\t\t" \
	"signkey=filename\n\t\t" \
	"csr=CSR filename\n\t\t" \
	"serial=serial number hex string\n\t\t" \
	"outcert=filename for final certificate\n\t\t" \
	"issuer=issuer-DN\n\t\t" \
	"[ format=pem|der ] (output format)\n\t\t" \
	"[ subject=subject-DN ] (new subject name)\n\t\t" \
	"[ altname=subjectAltName ]\n\t\t" \
	"[ keyusage=[critical:]usage,...]\n\t\t" \
	"[ lifetime=number-hour|number-day|number-year ]\n\t\t" \
	"[ eku=[critical:]EKU Name,...]\n\t" \
 \
	"signcsr keystore=nss\n\t\t" \
	"signkey=label (label of signing key)\n\t\t" \
	"csr=CSR filename\n\t\t" \
	"serial=serial number hex string\n\t\t" \
	"outcert=filename for final certificate\n\t\t" \
	"issuer=issuer-DN\n\t\t" \
	"[ store=y|n ] (store the new cert in NSS DB, default=n)\n\t\t" \
	"[ outlabel=certificate label ]\n\t\t" \
	"[ format=pem|der ] (output format)\n\t\t" \
	"[ subject=subject-DN ] (new subject name)\n\t\t" \
	"[ altname=subjectAltName ]\n\t\t" \
	"[ keyusage=[critical:]usage,...]\n\t\t" \
	"[ eku=[critical:]EKU Name,...]\n\t\t" \
	"[ lifetime=number-hour|number-day|number-year ]\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ dir=directory-path ]\n\t\t" \
	"[ prefix=DBprefix ]\n\t"

#define	INITTOKEN_IDX 11
#define	INITTOKEN_VERB "inittoken"
#define	INITTOKEN_SUMM gettext("Initialize a PKCS11 token")
#define	INITTOKEN_SYN \
	"inittoken \n\t\t" \
	"[ currlabel=token[:manuf[:serial]]]\n\t\t" \
	"[ newlabel=new token label ]\n\t"

#define	GENKEYPAIR_IDX 12
#define	GENKEYPAIR_VERB "genkeypair"
#define	GENKEYPAIR_SUMM gettext("creates an asymmetric keypair")
#define	GENKEYPAIR_SYN \
	"genkeypair listcurves\n\t" \
\
	"genkeypair keystore=nss\n\t\t" \
	"label=key-nickname\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ dir=directory-path ]\n\t\t" \
	"[ prefix=DBprefix ]\n\t\t" \
	"[ keytype=rsa | dsa | ec [curve=ECC Curve Name]]\n\t\t" \
	"[ keylen=key-size ]\n\t" \
 \
	"genkeypair [ keystore=pkcs11 ]\n\t\t" \
	"label=key-label\n\t\t" \
	"[ token=token[:manuf[:serial]]]\n\t\t" \
	"[ keytype=rsa | dsa | ec [curve=ECC Curve Name]]\n\t\t" \
	"[ keylen=key-size ]\n\t" \
 \
	"genkeypair keystore=file\n\t\t" \
	"outkey=key_filename\n\t\t" \
	"[ format=der|pem ]\n\t\t" \
	"[ keytype=rsa|dsa ]\n\t\t" \
	"[ keylen=key-size ]\n\t"

#define	HELP_IDX 13
#define	HELP_VERB "help"
#define	HELP_SUMM gettext("displays help message")
#define	HELP_SYN "help\t(help and usage)"

/* Command structure for verbs and their actions.  Do NOT i18n/l10n. */
static verbcmd	cmds[] = {
	{ NULL,	pk_tokens, 0, NULL, NULL },
	{ NULL,	pk_setpin, 0, NULL, NULL },
	{ NULL, pk_list, 0, NULL, NULL },
	{ NULL, pk_delete, 0, NULL, NULL },
	{ NULL,	pk_import, 0, NULL, NULL },
	{ NULL,	pk_export, 0, NULL, NULL },
	{ NULL,	pk_gencert, 0, NULL, NULL },
	{ NULL,	pk_gencsr, 0, NULL, NULL },
	{ NULL,	pk_download, 0, NULL, NULL },
	{ NULL,	pk_genkey, 0, NULL, NULL },
	{ NULL, pk_signcsr, 0, NULL, NULL },
	{ NULL, pk_inittoken, 0, NULL, NULL },
	{ NULL, pk_genkeypair, 0, NULL, NULL },
	{ NULL,	pk_help, 0, NULL, NULL }
};

static int	num_cmds = sizeof (cmds) / sizeof (verbcmd);

static char	*prog;
static void	usage(int);

static void
init_command_list()
{
	cmds[TOKEN_IDX].verb = TOKEN_VERB;
	cmds[TOKEN_IDX].summary = TOKEN_SUMM;
	cmds[TOKEN_IDX].synopsis = TOKEN_SYN;

	cmds[SETPIN_IDX].verb = SETPIN_VERB;
	cmds[SETPIN_IDX].summary = SETPIN_SUMM;
	cmds[SETPIN_IDX].synopsis = SETPIN_SYN;

	cmds[LIST_IDX].verb = LIST_VERB;
	cmds[LIST_IDX].summary = LIST_SUMM;
	cmds[LIST_IDX].synopsis = LIST_SYN;

	cmds[DELETE_IDX].verb = DELETE_VERB;
	cmds[DELETE_IDX].summary = DELETE_SUMM;
	cmds[DELETE_IDX].synopsis = DELETE_SYN;

	cmds[IMPORT_IDX].verb = IMPORT_VERB;
	cmds[IMPORT_IDX].summary = IMPORT_SUMM;
	cmds[IMPORT_IDX].synopsis = IMPORT_SYN;

	cmds[EXPORT_IDX].verb = EXPORT_VERB;
	cmds[EXPORT_IDX].summary = EXPORT_SUMM;
	cmds[EXPORT_IDX].synopsis = EXPORT_SYN;

	cmds[GENCERT_IDX].verb = GENCERT_VERB;
	cmds[GENCERT_IDX].summary = GENCERT_SUMM;
	cmds[GENCERT_IDX].synopsis = GENCERT_SYN;

	cmds[GENCSR_IDX].verb = GENCSR_VERB;
	cmds[GENCSR_IDX].summary = GENCSR_SUMM;
	cmds[GENCSR_IDX].synopsis = GENCSR_SYN;

	cmds[DOWNLOAD_IDX].verb = DOWNLOAD_VERB;
	cmds[DOWNLOAD_IDX].summary = DOWNLOAD_SUMM;
	cmds[DOWNLOAD_IDX].synopsis = DOWNLOAD_SYN;

	cmds[GENKEY_IDX].verb = GENKEY_VERB;
	cmds[GENKEY_IDX].summary = GENKEY_SUMM;
	cmds[GENKEY_IDX].synopsis = GENKEY_SYN;

	cmds[SIGNCSR_IDX].verb = SIGNCSR_VERB;
	cmds[SIGNCSR_IDX].summary = SIGNCSR_SUMM;
	cmds[SIGNCSR_IDX].synopsis = SIGNCSR_SYN;

	cmds[INITTOKEN_IDX].verb = INITTOKEN_VERB;
	cmds[INITTOKEN_IDX].summary = INITTOKEN_SUMM;
	cmds[INITTOKEN_IDX].synopsis = INITTOKEN_SYN;

	cmds[GENKEYPAIR_IDX].verb = GENKEYPAIR_VERB;
	cmds[GENKEYPAIR_IDX].summary = GENKEYPAIR_SUMM;
	cmds[GENKEYPAIR_IDX].synopsis = GENKEYPAIR_SYN;

	cmds[HELP_IDX].verb = HELP_VERB;
	cmds[HELP_IDX].summary = HELP_SUMM;
	cmds[HELP_IDX].synopsis = HELP_SYN;
}

/*
 * Usage information.  This function must be updated when new verbs or
 * options are added.
 */
static void
usage(int idx)
{
	int	i;

	/* Display this block only in command-line mode. */
	(void) fprintf(stdout, gettext("Usage:\n"));
	(void) fprintf(stdout, gettext("   %s -?\t(help and usage)\n"),
	    prog);
	(void) fprintf(stdout, gettext("   %s -f option_file\n"), prog);
	(void) fprintf(stdout, gettext("   %s subcommand [options...]\n"),
	    prog);
	(void) fprintf(stdout, gettext("where subcommands may be:\n"));

	/* Display only those verbs that match the current tool mode. */
	if (idx == -1) {
		for (i = 0; i < num_cmds; i++) {
			/* Do NOT i18n/l10n. */
			(void) fprintf(stdout, "   %-8s	- %s\n",
			    cmds[i].verb, cmds[i].summary);
		}
		(void) fprintf(stdout, "%s \'help\'.\n"
		    "Ex: pktool gencert help\n\n",
		    gettext("\nFurther details on the "
		    "subcommands can be found by adding"));
	} else {
		(void) fprintf(stdout, "\t%s\n", cmds[idx].synopsis);
	}
}

/*
 * Provide help, in the form of displaying the usage.
 */
static int
pk_help(int argc, char *argv[])
/* ARGSUSED */
{
	usage(-1);
	return (0);
}

/*
 * Process arguments from the argfile and create a new
 * argv/argc list to be processed later.
 */
static int
process_arg_file(char *argfile, char ***argv, int *argc)
{
	FILE *fp;
	char argline[2 * BUFSIZ]; /* 2048 bytes should be plenty */
	char *p;
	int nargs = 0;

	if ((fp = fopen(argfile, "rF")) == NULL) {
		(void) fprintf(stderr,
		    gettext("Cannot read argfile %s: %s\n"),
		    argfile, strerror(errno));
		return (errno);
	}

	while (fgets(argline, sizeof (argline), fp) != NULL) {
		int j;
		/* remove trailing whitespace */
		j = strlen(argline) - 1;
		while (j >= 0 && isspace(argline[j])) {
			argline[j] = 0;
			j--;
		}
		/* If it was a blank line, get the next one. */
		if (!strlen(argline))
			continue;

		(*argv) = realloc((*argv),
		    (nargs + 1) * sizeof (char *));
		if ((*argv) == NULL) {
			perror("memory error");
			(void) fclose(fp);
			return (errno);
		}
		p = (char *)strdup(argline);
		if (p == NULL) {
			perror("memory error");
			(void) fclose(fp);
			return (errno);
		}
		(*argv)[nargs] = p;
		nargs++;
	}
	*argc = nargs;
	(void) fclose(fp);
	return (0);
}

/*
 * MAIN() -- where all the action is
 */
int
main(int argc, char *argv[], char *envp[])
/* ARGSUSED2 */
{
	int	i, found = -1;
	int	rv;
	int	pk_argc = 0;
	char	**pk_argv = NULL;
	int	save_errno = 0;

	/* Set up for i18n/l10n. */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D. */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it isn't. */
#endif
	(void) textdomain(TEXT_DOMAIN);

	init_command_list();

	/* Get program base name and move pointer over 0th arg. */
	prog = basename(argv[0]);
	argv++, argc--;

	/* Set up for debug and error output. */
	if (argc == 0) {
		usage(-1);
		return (1);
	}

	/* Check for help options.  For CLIP-compliance. */
	if (strcmp(argv[0], "-?") == 0) {
		return (pk_help(argc, argv));
	} else if (strcmp(argv[0], "-f") == 0 && argc == 2) {
		rv = process_arg_file(argv[1], &pk_argv, &pk_argc);
		if (rv)
			return (rv);
	} else if (argc >= 1 && argv[0][0] == '-') {
		usage(-1);
		return (1);
	}

	/* Always turns off Metaslot so that we can see softtoken. */
	if (setenv("METASLOT_ENABLED", "false", 1) < 0) {
		save_errno = errno;
		cryptoerror(LOG_STDERR,
		    gettext("Disabling Metaslot failed (%s)."),
		    strerror(save_errno));
		return (1);
	}

	/* Begin parsing command line. */
	if (pk_argc == 0 && pk_argv == NULL) {
		pk_argc = argc;
		pk_argv = argv;
	}

	/* Check for valid verb (or an abbreviation of it). */
	found = -1;
	for (i = 0; i < num_cmds; i++) {
		if (strcmp(cmds[i].verb, pk_argv[0]) == 0) {
			if (found < 0) {
				found = i;
				break;
			}
		}
	}
	/* Stop here if no valid verb found. */
	if (found < 0) {
		cryptoerror(LOG_STDERR, gettext("Invalid verb: %s"),
		    pk_argv[0]);
		return (1);
	}

	/* Get to work! */
	rv = (*cmds[found].action)(pk_argc, pk_argv);
	switch (rv) {
	case PK_ERR_NONE:
		break;		/* Command succeeded, do nothing. */
	case PK_ERR_USAGE:
		usage(found);
		break;
	case PK_ERR_QUIT:
		exit(0);
		/* NOTREACHED */
	case PK_ERR_PK11:
	case PK_ERR_SYSTEM:
	case PK_ERR_OPENSSL:
	case PK_ERR_NSS:
	default:
		break;
	}
	return (rv);
}
