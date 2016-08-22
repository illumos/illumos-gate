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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

/*
 * Create sha1 hash for file.
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>
#include <locale.h>
#include "bootadm.h"

#define	BUFFERSIZE	(1024 * 64)
#define	RESULTLEN	(512)
static CK_BYTE buf[BUFFERSIZE];

/*
 * do_digest - Compute digest of a file. Borrowed from digest.
 *
 *  hSession - session
 *  pmech - ptr to mechanism to be used for digest
 *  fd  - file descriptor
 *  pdigest - buffer  where digest result is returned
 *  pdigestlen - length of digest buffer on input,
 *               length of result on output
 */
static CK_RV
do_digest(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pmech,
    int fd, CK_BYTE_PTR *pdigest, CK_ULONG_PTR pdigestlen)
{
	CK_RV rv;
	ssize_t nread;
	int err;

	if ((rv = C_DigestInit(hSession, pmech)) != CKR_OK) {
		return (rv);
	}

	while ((nread = read(fd, buf, sizeof (buf))) > 0) {
		/* Get the digest */
		rv = C_DigestUpdate(hSession, buf, (CK_ULONG)nread);
		if (rv != CKR_OK)
			return (rv);
	}

	/* There was a read error */
	if (nread == -1) {
		err = errno;
		bam_print(gettext("error reading file: %s\n"), strerror(err));
		return (CKR_GENERAL_ERROR);
	}

	rv = C_DigestFinal(hSession, *pdigest, pdigestlen);

	/* result too big to fit? Allocate a bigger buffer */
	if (rv == CKR_BUFFER_TOO_SMALL) {
		*pdigest = realloc(*pdigest, *pdigestlen);

		if (*pdigest == NULL) {
			err = errno;
			bam_print(gettext("realloc: %s\n"), strerror(err));
			return (CKR_HOST_MEMORY);
		}

		rv = C_DigestFinal(hSession, *pdigest, pdigestlen);
	}

	return (rv);
}

int
bootadm_digest(const char *filename, char **result)
{
	int fd;
	CK_RV rv;
	CK_ULONG slotcount;
	CK_SLOT_ID slotID;
	CK_SLOT_ID_PTR pSlotList = NULL;
	CK_MECHANISM_TYPE mech_type = CKM_SHA_1;
	CK_MECHANISM_INFO info;
	CK_MECHANISM mech;
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
	CK_BYTE_PTR resultbuf = NULL;
	CK_ULONG resultlen;
	char *resultstr = NULL;
	int resultstrlen;
	int i, exitcode;

	/* Initialize, and get list of slots */
	rv = C_Initialize(NULL);
	if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		bam_print(gettext(
		    "failed to initialize PKCS #11 framework: %s\n"),
		    pkcs11_strerror(rv));
		return (BAM_ERROR);
	}

	/* Get slot count */
	rv = C_GetSlotList(0, NULL, &slotcount);
	if (rv != CKR_OK || slotcount == 0) {
		bam_print(gettext(
		    "failed to find any cryptographic provider: %s\n"),
		    pkcs11_strerror(rv));
		exitcode = BAM_ERROR;
		goto cleanup;
	}

	/* Found at least one slot, allocate memory for slot list */
	pSlotList = malloc(slotcount * sizeof (CK_SLOT_ID));
	if (pSlotList == NULL) {
		bam_print(gettext("out of memory\n"));
		exitcode = BAM_ERROR;
		goto cleanup;
	}

	/* Get the list of slots */
	if ((rv = C_GetSlotList(0, pSlotList, &slotcount)) != CKR_OK) {
		bam_print(gettext(
		    "failed to find any cryptographic provider; "
		    "please check with your system administrator: %s\n"),
		    pkcs11_strerror(rv));
		exitcode = BAM_ERROR;
		goto cleanup;
	}

	/* Find a slot with matching mechanism */
	for (i = 0; i < slotcount; i++) {
		slotID = pSlotList[i];
		rv = C_GetMechanismInfo(slotID, mech_type, &info);
		if (rv != CKR_OK) {
			continue; /* to the next slot */
		} else {
			if (info.flags & CKF_DIGEST)
				break;
		}
	}

	/* Show error if no matching mechanism found */
	if (i == slotcount) {
		bam_print(gettext("no cryptographic provider was "
		    "found for sha1\n"));
		exitcode = BAM_ERROR;
		goto cleanup;
	}

	/* Mechanism is supported. Go ahead & open a session */
	rv = C_OpenSession(slotID, CKF_SERIAL_SESSION,
	    NULL, NULL, &hSession);

	if (rv != CKR_OK) {
		bam_print(gettext("can not open PKCS#11 session: %s\n"),
		    pkcs11_strerror(rv));
		exitcode = BAM_ERROR;
		goto cleanup;
	}

	/* Allocate a buffer to store result. */
	resultlen = RESULTLEN;
	if ((resultbuf = malloc(resultlen)) == NULL) {
		bam_print(gettext("out of memory\n"));
		exitcode = BAM_ERROR;
		goto cleanup;
	}

	mech.mechanism = mech_type;
	mech.pParameter = NULL;
	mech.ulParameterLen = 0;
	exitcode = BAM_SUCCESS;

	if ((fd = open(filename, O_RDONLY | O_NONBLOCK)) == -1) {
		bam_print(gettext("can not open input file %s\n"), filename);
		exitcode = BAM_ERROR;
		goto cleanup;
	}

	rv = do_digest(hSession, &mech, fd, &resultbuf, &resultlen);

	if (rv != CKR_OK) {
		bam_print(gettext("crypto operation failed for "
		    "file %s: %s\n"), filename, pkcs11_strerror(rv));
		exitcode = BAM_ERROR;
		goto cleanup;
	}

	/* Allocate a buffer to store result string */
	resultstrlen = 2 * resultlen + 1;
	if ((resultstr = malloc(resultstrlen)) == NULL) {
		bam_print(gettext("out of memory\n"));
		exitcode = BAM_ERROR;
		goto cleanup;
	}

	tohexstr(resultbuf, resultlen, resultstr, resultstrlen);

	(void) close(fd);
cleanup:
	if (exitcode == BAM_ERROR) {
		free(resultstr);
		resultstr = NULL;
	}

	free(resultbuf);
	free(pSlotList);

	if (hSession != CK_INVALID_HANDLE)
		(void) C_CloseSession(hSession);

	(void) C_Finalize(NULL);

	*result = resultstr;
	return (exitcode);
}
