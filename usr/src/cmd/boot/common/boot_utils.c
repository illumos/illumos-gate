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

#include <stdio.h>
#include <libintl.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include "bblk_einfo.h"
#include "boot_utils.h"

boolean_t boot_debug = B_FALSE;
boolean_t nowrite = B_FALSE;

void
boot_gdebug(const char *funcname, char *format, ...)
{
	va_list ap;

	if (boot_debug == B_FALSE)
		return;

	(void) fprintf(stdout, "%s(): ", funcname);

	va_start(ap, format);
	/* LINTED: E_SEC_PRINTF_VAR_FMT */
	(void) vfprintf(stdout, format, ap);
	va_end(ap);
}

/*
 * Common functions to write out and read in block-sized data to a file
 * descriptor.
 */
int
write_out(int fd, void *buffer, size_t size, off_t off)
{
	int		ret;
	char		*buf = buffer;

	if (size % SECTOR_SIZE != 0)
		BOOT_DEBUG("Expected block-sized data, got: %d\n", size);

	/* Dry run. */
	if (nowrite)
		return (BC_SUCCESS);

	for (;;) {
	again:
		ret = pwrite(fd, buf, size, off);
		if (ret == -1) {
			if (errno == EAGAIN)
				goto again;
			else
				return (BC_ERROR);
			}
		if (ret < size) {
			size -= ret;
			off += ret;
			buf += ret;
		} else {
			break;
		}
	}
	return (BC_SUCCESS);
}

int
read_in(int fd, void *buffer, size_t size, off_t off)
{
	int		ret;
	char		*buf = buffer;

	if (size % SECTOR_SIZE != 0)
		BOOT_DEBUG("Expected block-sized data, got: %d\n", size);

	for (;;) {
	again:
		ret = pread(fd, buf, size, off);
		if (ret == -1) {
			if (errno == EAGAIN)
				goto again;
			else
				return (BC_ERROR);
			}
		if (ret < size) {
			size -= ret;
			off += ret;
			buf += ret;
		} else {
			break;
		}
	}
	return (BC_SUCCESS);
}
