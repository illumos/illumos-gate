/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <meta.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <limits.h>
#include <svm.h>

/*
 * FUNCTION: valid_bootlist
 *
 * INPUT: file pointer, line buffer, line_length
 *
 * RETURN VALUES:
 *	0 - SUCCESS
 *	-1 - FAIL
 *
 */

int
valid_bootlist(FILE *fp, int line_len)
{
	char *bp = NULL;
	char *line;

	/*
	 * errno may not be cleared by callee routines and we
	 * we want to catch fgets failures hence errno is reset.
	 */
	errno = 0;
	if ((line = malloc(line_len)) == NULL)
		return (RET_ERROR);

	while (fgets(line, line_len, fp) != NULL) {
		bp = strstr(line, "mddb_bootlist");
		if (bp != NULL) {
			/* if not commented out then breakout */
			if (*line != '*' && *line != '#') {
				break;
			}
		}
	}

	free(line);
	if (bp == NULL || errno != 0)
		return (RET_ERROR);

	return (RET_SUCCESS);
}

/*
 * FUNCTION: svm_check
 *	Check the existance of DiskSuite or SVM
 *
 * INPUT: rootpath
 *
 * RETURN VALUES:
 *	0 - SUCCESS
 *	-1 - FAIL
 */

int
svm_check(char *path)
{
	FILE *fp;
	char tmppath[PATH_MAX];
	int rval;

	(void) strcat(strcpy(tmppath, path), MD_CONF);

	if ((fp = fopen(tmppath, "r")) == NULL) {
		rval = errno;
		goto free_exit;
	}

	rval = valid_bootlist(fp, MDDB_BOOTLIST_MAX_LEN);

	debug_printf("svm_check(): valid bootlist in %s. status %d\n",
		tmppath, rval);

	if (rval == RET_SUCCESS) {
		goto free_exit;
	}
	(void) fclose(fp);

	/* not found in md.conf  try etc/system */
	(void) strcat(strcpy(tmppath, path), SYSTEM_FILE);

	if ((fp = fopen(tmppath, "r")) == NULL) {
		rval = errno;
		goto free_exit;
	}

	rval = valid_bootlist(fp, MDDB_BOOTLIST_MAX_LEN);

	debug_printf("svm_check(): valid bootlist in %s. status %d\n",
		tmppath, rval);
free_exit:
	(void) fclose(fp);
	if (rval > 0)
		rval = RET_ERROR;
	return (rval);
}

/*
 * FUNCTION: svm_is_md
 *	Check if the the given device name has an md driver.
 * INPUT: special device name (/dev/dsk/c0t0d0s0 or /dev/md/dsk/d10)
 *
 * RETURN:
 *	1 - if it is a metadevice.
 *	0 - if it is not a metadevice.
 */

int
svm_is_md(char *device_name)
{
	char buf[30];
	struct stat sbuf;
	int rval = 0;

	(void) memset(buf, 0, 30);

	debug_printf("svm_is_md(): device %s\n", device_name);
	if (stat(device_name, &sbuf) != 0)
		return (RET_ERROR);

	if (get_drv_name(major(sbuf.st_rdev), "/", buf) == RET_ERROR) {
		debug_printf("svm_is_md(): device get_drv_name failed: %s\n",
				device_name);
		return (0);
	}
	if (strcmp(buf, MD_MODULE) == 0) {
		debug_printf("svm_is_md(): device %s succeed\n", device_name);
		rval = 1;
	}
	return (rval);
}
