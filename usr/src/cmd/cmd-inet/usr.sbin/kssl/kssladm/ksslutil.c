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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <assert.h>
#include <strings.h>

#include <kmfapi.h>
#include "kssladm.h"

/*
 * Extract the Certificate and raw key data from a PKCS#12 file.
 * The password needed for decrypting the PKCS#12 PDU is stored
 * in plaintext in the given "password_file" parameter.
 */
int
PKCS12_get_rsa_key_certs(const char *filename, const char *password_file,
    KMF_RAW_KEY_DATA **rsa, KMF_DATA **certs)
{
	char password_buf[1024];
	KMF_HANDLE_T kmfh;
	KMF_RETURN rv = KMF_OK;
	KMF_CREDENTIAL pk12cred;
	KMF_DATA *tcerts;
	KMF_RAW_KEY_DATA *keys;
	int ncerts, nkeys;
	char *err = NULL;

	rv = kmf_initialize(&kmfh, NULL, NULL);
	if (rv != KMF_OK) {
		REPORT_KMF_ERROR(rv, "Error initializing KMF", err);
		return (0);
	}

	tcerts = NULL;
	keys = NULL;
	ncerts = 0;
	nkeys = 0;

	if (get_passphrase(password_file, password_buf,
	    sizeof (password_buf)) <= 0) {
		perror("Unable to read passphrase");
		goto done;
	}
	pk12cred.cred = password_buf;
	pk12cred.credlen = strlen(password_buf);

	rv = kmf_import_objects(kmfh, (char *)filename, &pk12cred, &tcerts,
	    &ncerts, &keys, &nkeys);
	if (rv != KMF_OK) {
		REPORT_KMF_ERROR(rv, "Error importing PKCS12 data", err);
	}

done:
	if (rv != KMF_OK) {
		int i;
		if (tcerts != NULL) {
			for (i = 0; i < ncerts; i++)
				kmf_free_data(&tcerts[i]);
			free(tcerts);
		}
		tcerts = NULL;
		ncerts = 0;
		if (keys != NULL) {
			for (i = 0; i < nkeys; i++)
				kmf_free_raw_key(&keys[i]);
			free(keys);
		}
		keys = NULL;
	}
	*certs = tcerts;
	*rsa = keys;

	(void) kmf_finalize(kmfh);

	return (ncerts);
}

/*
 * Parse a PEM file which should contain RSA private keys and
 * their associated X.509v3 certificates.  More than 1 may
 * be present in the file.
 */
int
PEM_get_rsa_key_certs(const char *filename, char *password_file,
    KMF_RAW_KEY_DATA **rsa, KMF_DATA **certs)
{
	KMF_HANDLE_T kmfh;
	KMF_RETURN rv = KMF_OK;
	KMF_CREDENTIAL creds;
	KMF_DATA *tcerts;
	KMF_RAW_KEY_DATA *keys;
	int ncerts, nkeys;
	char *err = NULL;
	char password_buf[1024];

	rv = kmf_initialize(&kmfh, NULL, NULL);
	if (rv != KMF_OK) {
		REPORT_KMF_ERROR(rv, "Error initializing KMF", err);
		return (0);
	}

	tcerts = NULL;
	keys = NULL;
	ncerts = 0;
	nkeys = 0;

	if (get_passphrase(password_file, password_buf,
	    sizeof (password_buf)) <= 0) {
		perror("Unable to read passphrase");
		goto done;
	}
	creds.cred = password_buf;
	creds.credlen = strlen(password_buf);

	rv = kmf_import_objects(kmfh, (char *)filename, &creds, &tcerts,
	    &ncerts, &keys, &nkeys);
	if (rv != KMF_OK) {
		REPORT_KMF_ERROR(rv, "Error importing key data", err);
	}

done:
	if (rv != KMF_OK) {
		int i;
		if (tcerts != NULL) {
			for (i = 0; i < ncerts; i++)
				kmf_free_data(&tcerts[i]);
			free(tcerts);
		}
		tcerts = NULL;
		ncerts = 0;
		if (keys != NULL) {
			for (i = 0; i < nkeys; i++)
				kmf_free_raw_key(&keys[i]);
			free(keys);
		}
		keys = NULL;
	}
	if (certs != NULL)
		*certs = tcerts;
	if (rsa != NULL)
		*rsa = keys;

	(void) kmf_finalize(kmfh);

	return (ncerts);
}
