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

#ifndef _KSSLADM_H
#define	_KSSLADM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Common routines and variables used by kssladm files.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <kmfapi.h>

#define	SUCCESS		0
#define	FAILURE		1
#define	ERROR_USAGE	2

#define	MAX_CHAIN_LENGTH	12
#define	REPORT_KMF_ERROR(r, t, e) { \
	(void) KMF_GetKMFErrorString(r, &e); \
	(void) fprintf(stderr, t ": %s\n", \
		(e != NULL ? e : "<unknown error>")); \
	if (e) free(e); \
}

#define	MAX_ATTR_CNT	8

extern boolean_t verbose;

extern int do_create(int argc, char *argv[]);
extern int do_delete(int argc, char *argv[]);
extern void usage_create(boolean_t do_print);
extern void usage_delete(boolean_t do_print);

extern int PEM_get_rsa_key_certs(KMF_HANDLE_T, const char *,
    char *, KMF_RAW_KEY_DATA **, KMF_X509_DER_CERT **);

extern int PKCS12_get_rsa_key_certs(KMF_HANDLE_T, const char *,
    const char *, KMF_RAW_KEY_DATA **, KMF_X509_DER_CERT **);

extern int get_passphrase(const char *password_file, char *buf, int buf_size);
extern int kssl_send_command(char *buf, int cmd);
extern int parse_and_set_addr(char *arg1, char *arg2, struct sockaddr_in *addr);

#ifdef __cplusplus
}
#endif

#endif /* _KSSLADM_H */
