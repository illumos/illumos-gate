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
 * Copyright 2020 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * Common utilities for libmlrpc tests.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

uchar_t *
read_buf_from_file(char *file, uint32_t *size)
{
	struct stat stats;
	uchar_t *buf;
	FILE *fp;
	size_t nread;
	int rc;

	errno = 0;
	rc = stat(file, &stats);

	if (rc < 0) {
		fprintf(stderr, "stat failed with rc %d:\n", rc);
		perror(file);
		return (NULL);
	}

	buf = malloc(stats.st_size);

	if (buf == NULL) {
		fprintf(stderr, "couldn't allocate buffer\n");
		return (NULL);
	}
	errno = 0;
	fp = fopen(file, "r");
	if (fp == NULL) {
		fprintf(stderr, "fopen failed to open file:\n");
		perror(file);
		free(buf);
		return (NULL);
	}

	errno = 0;
	nread = fread(buf, 1, stats.st_size, fp);
	if (nread == EOF && errno != 0) {
		fprintf(stderr, "fread failed:\n");
		perror(file);
		free(buf);
		return (NULL);
	}

	(void) fclose(fp);
	if (nread == EOF) {
		free(buf);
		buf = NULL;
	}
	*size = nread;
	return (buf);
}

/*
 * smb_token_log() outputs to syslog. The library defines syslog to be
 * smb_syslog, which it defines as NODIRECT to allow fksmbd to provide
 * its own version. We use that to redirect syslog to stderr, so that
 * we can print the token output to a useful location.
 */
void
smb_syslog(int pri, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}
