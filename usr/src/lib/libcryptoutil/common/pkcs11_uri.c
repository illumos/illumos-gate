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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <strings.h>
#include <libgen.h>
#include <pthread.h>

#include <security/cryptoki.h>
#include <security/pkcs11.h>

#include <cryptoutil.h>

/* PKCS#11 URI prefix and attributes. */
#define	PK11_URI_PREFIX		"pkcs11:"
#define	PK11_TOKEN		"token"
#define	PK11_MANUF		"manufacturer"
#define	PK11_SERIAL		"serial"
#define	PK11_MODEL		"model"
#define	PK11_OBJECT		"object"
#define	PK11_OBJECTTYPE		"objecttype"
#define	PK11_ID			"id"
#define	PK11_PINFILE		"pinfile"

/*
 * Gets a hexadecimal string of the xx:xx:xx-like format and fills the output
 * buffer with bytes represeting each of the hexadecimal numbers. Returns 0 on
 * error (missing ':', not a hexadecimal character (eg. 'z'), output buffer
 * overflow, etc.), or the number of hexadecimal numbers processed.
 *
 * Returns:
 *	0
 *		on failure
 *	>0
 *		number of bytes returned via the output parameter
 */
static int
read_id(char *str, unsigned char *output, int out_len)
{
	int i, len, n;
	unsigned int x1, x2;

	len = strlen(str);
	(void) memset(output, 0, out_len);
	/* Counter of the processed bytes. */
	i = 0;
	/* Counter for the used output bytes. */
	n = 0;

	while (i < len) {
		/* We require at least one hexadecimal character. */
		if (sscanf(str + i, "%1x", &x1) != 1)
			return (0);
		++i;
		/* And we accept the 2nd one if it is there. */
		if (sscanf(str + i, "%1x", &x2) == 1) {
			x1 = x1 * 16 + x2;
			++i;
		}

		/* Output buffer overflow? */
		if ((n + 1) > out_len)
			return (0);
		output[n] = (unsigned char)x1;
		/* Still some bytes to process? */
		if (i < len) {
			/* ':' is the only acceptable delimiter. */
			if (str[i] != ':')
				return (0);
			/* Skip ':' */
			++i;
		}
		++n;
	}

	return (n);
}

/*
 * Process the PKCS#11 URI. The function expects an allocated URI structure. The
 * caller is later expected to call pkcs11_free_uri() when the parsed URI is no
 * longer needed.
 *
 * Returns:
 *      PK11_URI_OK
 *		success
 *      PK11_URI_INVALID
 *		invalid PKCS#11 URI (one that has the "pkcs11:" prefix but is
 *		otherwise incorrectly specified)
 *      PK11_MALLOC_ERROR
 *		malloc(3C) failed when allocating one of the internal buffers
 *      PK11_URI_VALUE_OVERFLOW
 *		some attributes in the URI are of the fixed length accroding to
 *		the spec. If any of those attributes overflows we report an
 *		error
 *      PK11_NOT_PKCS11_URI
 *		the URI supplied is not the PKCS#11 URI at all (does not have
 *		the "pkcs11:" prefix)
 */
int
pkcs11_parse_uri(const char *str, pkcs11_uri_t *uri)
{
	char *str2, *l1, *l2, *tok, *name;

	/* Initialize the structure. */
	(void) memset(uri, 0, sizeof (pkcs11_uri_t));
	/* Be really safe. */
	uri->objecttype_present = B_FALSE;

	/* Check that we have the correct PKCS#11 URI prefix. */
	if (strncmp(str, PK11_URI_PREFIX, strlen(PK11_URI_PREFIX)) != 0)
		return (PK11_NOT_PKCS11_URI);
	/* Dup the string and skip over the prefix then. */
	if ((str2 = strdup(str + strlen(PK11_URI_PREFIX))) == NULL)
		return (PK11_MALLOC_ERROR);

	/*
	 * Using strtok_r() would silently skip over multiple semicolons. We
	 * must check such situation before moving on. We must also avoid ';' as
	 * the first and the last character of the URI.
	 */
	if (strstr(str2, ";;") != NULL || str2[0] == ';' ||
	    (strlen(str2) > 0 && str2[strlen(str2) - 1] == ';'))
		goto bad_uri;

	/* Now parse the URI. */
	tok = strtok_r(str2, ";", &l1);
	for (; tok != NULL; tok = strtok_r(NULL, ";", &l1)) {
		/* "tok" is not empty so there will be something in "name". */
		name = strtok_r(tok, "=", &l2);
		/* Check whether there is '=' at all. */
		if (l2 == NULL)
			goto bad_uri;

		/*
		 * Fill out the URI structure. We do not accept duplicate
		 * attributes.
		 */
		if (strcmp(name, PK11_TOKEN) == 0) {
			/* Check for duplicity. */
			if (uri->token != NULL)
				goto bad_uri;
			if (strlen(l2) > 32)
				goto value_overflow;
			if ((uri->token = (unsigned char *)strdup(l2)) == NULL)
				goto malloc_failed;
		} else if (strcmp(name, PK11_MANUF) == 0) {
			/* Check for duplicity. */
			if (uri->manuf != NULL)
				goto bad_uri;
			if (strlen(l2) > 32)
				goto value_overflow;
			if ((uri->manuf = (unsigned char *)strdup(l2)) == NULL)
				goto malloc_failed;
		} else if (strcmp(name, PK11_SERIAL) == 0) {
			/* Check for duplicity. */
			if (uri->serial != NULL)
				goto bad_uri;
			if (strlen(l2) > 16)
				goto value_overflow;
			if ((uri->serial = (unsigned char *)strdup(l2)) == NULL)
				goto malloc_failed;
		} else if (strcmp(name, PK11_MODEL) == 0) {
			/* Check for duplicity. */
			if (uri->model != NULL)
				goto bad_uri;
			if (strlen(l2) > 16)
				goto value_overflow;
			if ((uri->model = (unsigned char *)strdup(l2)) == NULL)
				goto malloc_failed;
		} else if (strcmp(name, PK11_ID) == 0) {
			/* Check for duplicity. */
			if (uri->id_len != 0)
				goto bad_uri;
			/*
			 * We can have maximum of PK11_MAX_ID_LEN 2-byte
			 * numbers separated by ':'s, like
			 * 01:02:0A:FF:...
			 */
			if (strlen(l2) > PK11_MAX_ID_LEN * 2 +
			    PK11_MAX_ID_LEN - 1) {
				goto value_overflow;
			}
			if ((uri->id = malloc(PK11_MAX_ID_LEN)) == NULL)
				goto malloc_failed;
			uri->id_len = read_id(l2, uri->id,
			    PK11_MAX_ID_LEN);
			if (uri->id_len == 0)
				goto bad_uri;
		} else if (strcmp(name, PK11_OBJECT) == 0) {
			/* Check for duplicity. */
			if (uri->object != NULL)
				goto bad_uri;
			if (strlen(l2) > PK11_MAX_OBJECT_LEN)
				goto value_overflow;
			if ((uri->object = (unsigned char *)strdup(l2)) == NULL)
				goto malloc_failed;
		} else if (strcmp(name, PK11_OBJECTTYPE) == 0) {
			/*
			 * Check for duplicity. objecttype can not be empty, it
			 * would not make sense.
			 */
			if (uri->objecttype_present == CK_TRUE)
				goto bad_uri;
			if (strcmp(l2, "public") == 0)
				uri->objecttype = CKO_PUBLIC_KEY;
			else if (strcmp(l2, "private") == 0)
				uri->objecttype = CKO_PRIVATE_KEY;
			else if (strcmp(l2, "cert") == 0)
				uri->objecttype = CKO_CERTIFICATE;
			else if (strcmp(l2, "secretkey") == 0)
				uri->objecttype = CKO_SECRET_KEY;
			else if (strcmp(l2, "data") == 0)
				uri->objecttype = CKO_DATA;
			else
				goto bad_uri;
			uri->objecttype_present = CK_TRUE;
		} else if (strcmp(name, PK11_PINFILE) == 0)
			/* Check for duplicity. */
			if (uri->pinfile == NULL) {
				if (strlen(l2) > MAXPATHLEN)
					goto value_overflow;
				if ((uri->pinfile = strdup(l2)) == NULL)
					goto malloc_failed;
				/* Empty pinfile makes no sense. */
				if (uri->pinfile[0] == '\0')
					goto bad_uri;
			} else
				goto bad_uri;
		else
			/* Unknown attribute name. */
			goto bad_uri;
	}

	free(str2);
	return (PK11_URI_OK);
malloc_failed:
	free(str2);
	pkcs11_free_uri(uri);
	return (PK11_MALLOC_ERROR);
bad_uri:
	free(str2);
	pkcs11_free_uri(uri);
	return (PK11_URI_INVALID);
value_overflow:
	free(str2);
	pkcs11_free_uri(uri);
	return (PK11_URI_VALUE_OVERFLOW);
}

/*
 * Free the PKCS#11 URI structure attributes but do not free the structure
 * itself.
 */
void
pkcs11_free_uri(pkcs11_uri_t *uri)
{
	if (uri->object != NULL)
		free(uri->object);
	if (uri->token != NULL)
		free(uri->token);
	if (uri->manuf != NULL)
		free(uri->manuf);
	if (uri->serial != NULL)
		free(uri->serial);
	if (uri->model != NULL)
		free(uri->model);
	if (uri->id != NULL)
		free(uri->id);
	if (uri->pinfile != NULL)
		free(uri->pinfile);
}
