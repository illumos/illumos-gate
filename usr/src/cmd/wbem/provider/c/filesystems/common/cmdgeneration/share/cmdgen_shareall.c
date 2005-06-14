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

#include "cmdgen_include.h"

#define	NFS_SHAREALL_CMD	"/usr/sbin/shareall"
#define	FSTYPE_FLAG		"-F"
#define	SPACE			" "

/*
 * Public methods
 */
char *
cmdgen_shareall(CCIMPropertyList *paramList, int *errp) {

	CCIMPropertyList	*tmpParamList;
	CCIMProperty		*fstype;
	CCIMProperty		*filename;
	char			*cmd = NULL;
	int			cmdLen;

	/*
	 * In parameters are as follows:
	 * 1. String fstype,
	 * 2. String filename
	 *
	 * They are expected to always be in this order in the property list.
	 */
	if (paramList == NULL) {
		*errp = EINVAL;
	} else {
		/*
		 * Check if a file system type and/or a filename was
		 * passed in.  These we will be used in forming the
		 * command.
		 */
		tmpParamList = paramList;
		fstype = tmpParamList->mDataObject;
		tmpParamList = tmpParamList->mNext;
		filename = tmpParamList->mDataObject;
		if (fstype != NULL && fstype->mValue != NULL &&
		    strlen(fstype->mValue) != 0) {
			cmdLen = strlen(NFS_SHAREALL_CMD) +
			    strlen(fstype->mValue) + 5;
				/*
				 * Added two bytes for spaces, two bytes
				 * for the "-F" filesystem type flag, and
				 * a byte for the string terminator.
				 */
			cmd = malloc((size_t)(cmdLen * sizeof (char)));
			if (cmd == NULL) {
				*errp = errno;
				return (NULL);
			}
			(void) snprintf(cmd, cmdLen, "%s %s %s",
			    NFS_SHAREALL_CMD, FSTYPE_FLAG,
			    fstype->mValue);
		}

		if (filename != NULL && filename->mValue != NULL &&
		    strlen(filename->mValue) != 0) {
			cmdLen = strlen(NFS_SHAREALL_CMD) +
			    strlen(filename->mValue) + 2;
				/*
				 * Added one byte for a space and one for
				 * the string terminator.
				 */
			cmd = malloc((size_t)(cmdLen * sizeof (char)));
			if (cmd == NULL) {
				*errp = errno;
				return (NULL);
			}
			(void) snprintf(cmd, cmdLen, "%s %s",
			    cmd, filename->mValue);
		} else {
			cmd = strdup(NFS_SHAREALL_CMD);
			if (cmd == NULL) {
				*errp = errno;
			}
		}
	}
	return (cmd);
} /* cmdgen_shareall */
