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

#define	NFS_UNSHAREALL_CMD	"/usr/sbin/unshareall"
#define	FSTYPE_FLAG		"-F"
#define	SPACE			" "

/*
 * Public methods
 */
char *
cmdgen_unshareall(CCIMPropertyList *paramList, int *errp) {
	CCIMPropertyList	*currentParam;
	CCIMProperty		*fstype;
	char			*cmd;
	int			cmdLen;

	if (paramList == NULL) {
		*errp = EINVAL;
		return (NULL);
	}

	/*
	 * In parameters are as follows:
	 * 1. String fstype
	 */
	/*
	 * If a filesystem type was passed in, add it to
	 * the command line.
	 */
	currentParam = paramList;
	fstype = currentParam->mDataObject;
	if (fstype != NULL && fstype->mValue != NULL &&
	    strlen(fstype->mValue) != 0) {
		/*
		 * Add two bytes for spaces, two bytes for
		 * the "-F" filesystem type flag, and a
		 * byte for the string terminator.
		 */
		cmdLen = strlen(NFS_UNSHAREALL_CMD) +
		    strlen(fstype->mValue) + 5;
		cmd = (char *)malloc((size_t)(cmdLen * sizeof (char)));
		if (cmd == NULL) {
			*errp = ENOMEM;
		}
		(void) snprintf(cmd, cmdLen, "%s %s %s", NFS_UNSHAREALL_CMD,
		    FSTYPE_FLAG, fstype->mValue);
	} else {
		cmd = strdup(NFS_UNSHAREALL_CMD);
		if (cmd == NULL) {
			*errp = ENOMEM;
		}
	}
	return (cmd);
} /* cmdgen_unshareall */
