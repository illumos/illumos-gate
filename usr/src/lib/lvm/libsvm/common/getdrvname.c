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
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <svm.h>

/*
 *	Macros to produce a quoted string containing the value of a
 *	preprocessor macro. For example, if SIZE is defined to be 256,
 *	VAL2STR(SIZE) is "256". This is used to construct format
 *	strings for scanf-family functions below.
 */
#define	QUOTE(x)	#x
#define	VAL2STR(x)	QUOTE(x)

/*
 * FUNCTION:
 *	Return the driver name for a major number
 *
 * INPUT: major number, mount point for name_to_major file, pointer
 * to a valid buffer.
 *
 * RETURN VALUES:
 *	0 - SUCCESS - buf contain the driver name.
 *	-1 - FAIL
 *
 */

int
get_drv_name(major_t major, char *mnt, char *buf)
{
	FILE *fp;
	char drv[FILENAME_MAX + 1];
	char entry[FILENAME_MAX + 1];
	char line[MAX_N2M_ALIAS_LINE];
	char fname[PATH_MAX];

	int status = RET_NOERROR;
	(void) snprintf(fname, sizeof (fname), "%s%s", mnt, NAME_TO_MAJOR);

	if ((fp = fopen(fname, "r")) == NULL) {
		return (RET_ERROR);
	}

	while ((fgets(line, sizeof (line), fp) != NULL) &&
						status == RET_NOERROR) {
		if (sscanf(line,
		    "%" VAL2STR(FILENAME_MAX) "s %" VAL2STR(FILENAME_MAX) "s",
		    drv, entry) != 2) {
			status = RET_ERROR;
		}
		if (atoi(entry) == major)
			break;

	}

	if (status == RET_NOERROR)
		(void) strcpy(buf, drv);
	(void) fclose(fp);
	return (status);
}
