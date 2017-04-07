/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 * Copyright 2017 OmniTI Computer Consulting, Inc. All rights reserved.
 */

/*
 * Create sha1 hash for file.
 *
 * NOTE:  This is hardwired for now, so use libmd's SHA1 for simplicity.
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <locale.h>
#include <sha1.h>
#include <cryptoutil.h>
#include "bootadm.h"

#define	BUFFERSIZE (64 * 1024)
static uint8_t buf[BUFFERSIZE];

int
bootadm_digest(const char *filename, char **result)
{
	int fd;
	char *resultstr = NULL;
	uint8_t *resultbuf;
	int resultstrlen, resultlen, exitcode;
	SHA1_CTX sha1_ctx;
	ssize_t nread;

	/* Allocate a buffer to store result. */
	resultlen = SHA1_DIGEST_LENGTH;
	if ((resultbuf = malloc(resultlen)) == NULL) {
		bam_print(gettext("out of memory\n"));
		exitcode = BAM_ERROR;
		goto cleanup;
	}

	if ((fd = open(filename, O_RDONLY | O_NONBLOCK)) == -1) {
		bam_print(gettext("can not open input file %s\n"), filename);
		exitcode = BAM_ERROR;
		goto cleanup;
	}

	SHA1Init(&sha1_ctx);
	while ((nread = read(fd, buf, sizeof (buf))) > 0)
		SHA1Update(&sha1_ctx, buf, nread);
	if (nread == -1) {
		bam_print(gettext("error reading file: %s\n"), strerror(errno));
		exitcode = BAM_ERROR;
		goto cleanup;
	}
	SHA1Final(resultbuf, &sha1_ctx);

	/* Allocate a buffer to store result string */
	resultstrlen = 2 * resultlen + 1;	/* Two hex chars per byte. */
	if ((resultstr = malloc(resultstrlen)) == NULL) {
		bam_print(gettext("out of memory\n"));
		exitcode = BAM_ERROR;
		goto cleanup;
	}

	tohexstr(resultbuf, resultlen, resultstr, resultstrlen);
	exitcode = BAM_SUCCESS;
	(void) close(fd);
cleanup:
	if (exitcode == BAM_ERROR) {
		free(resultstr);
		resultstr = NULL;
	}

	free(resultbuf);

	*result = resultstr;
	return (exitcode);
}
