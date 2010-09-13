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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Utility functions used by the ipmgmtd daemon.
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include "ipmgmt_impl.h"

#define	IPMGMT_BUFSIZ	1024

void
ipmgmt_log(int pri, const char *fmt, ...)
{
	va_list alist;

	va_start(alist, fmt);
	vsyslog(pri, fmt, alist);
	va_end(alist);
}

/*
 * Copy a source file to a new destination. The source file will be
 * removed if rdonly is false (i.e., used when the source file resides
 * on a read-only file system).
 *
 * Returns 0 on success and errno on failure.
 */
int
ipmgmt_cpfile(const char *src, const char *dst, boolean_t rdonly)
{
	struct stat statbuf;
	FILE *sfp, *dfp;
	char buf[IPMGMT_BUFSIZ];
	int err = 0;

	errno = 0;
	/*
	 * Attempt to open the destination file first since we
	 * want to optimize for the case where it is read-only
	 * and will return EROFS.
	 */
	if ((dfp = fopen(dst, "w+")) == NULL)
		return (errno);

	/*
	 * Require that the source file exists.
	 */
	if (stat(src, &statbuf) != 0) {
		err = errno;
		(void) fclose(dfp);
		return (err);
	}
	if ((sfp = fopen(src, "r")) == NULL) {
		err = errno;
		(void) fclose(dfp);
		return (err);
	}

	/*
	 * Copy the file.
	 */
	while (fgets(buf, sizeof (buf), sfp) != NULL && errno == 0) {
		(void) fputs(buf, dfp);
		if (errno != 0)
			break;
	}
	if (errno != 0)
		err = errno;
	else if (fflush(dfp) == EOF)
		err = errno;

	(void) fclose(sfp);
	(void) fclose(dfp);

	/*
	 * If any error occurred, then remove the destination file.
	 */
	if (err != 0) {
		(void) unlink(dst);
		return (err);
	}

	/*
	 * Make sure the file attributes are correct.
	 */
	if (chmod(dst, IPADM_FILE_MODE) != 0 ||
	    chown(dst, UID_NETADM, GID_NETADM) != 0) {
		err = errno;
		(void) unlink(dst);
		return (err);
	}

	/*
	 * If the source file does not reside on a read-only file system
	 * then remove it.
	 */
	if (!rdonly)
		(void) unlink(src);

	return (0);
}
