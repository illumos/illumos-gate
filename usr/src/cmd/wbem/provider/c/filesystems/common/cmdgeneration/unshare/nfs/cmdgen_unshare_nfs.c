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
#include "nfs_keys.h"
#include "util.h"
#include <errno.h>



/*
 * Private data type declaration
 */
#define	NFS_UNSHARE_CMD	"unshare "

/*
 * Private method declarations
 */

/*
 * Public methods
 */
/*
 * generates the share command string
 * memory returned must be freed by the caller.
 */
/* ARGSUSED */
char *
cmdgen_unshare_nfs(CCIMInstance *inst, CCIMObjectPath *objPath, int *error)
{
	char *propValue;
	char *cmd;
	size_t len;

	if (objPath != NULL) {
		/*
		 * Create the unshare command using the properties
		 * passed in from inst.
		 */

		propValue = util_getKeyValue(objPath->mKeyProperties, string,
		    NAME, error);
		if (propValue == NULL) {
			*error = EINVAL;
			cim_logDebug("cmdgen_unshare_nfs",
			    "SHAREDNAME is NULL");
			return ((char *)NULL);
		}
		len = strlen(NFS_UNSHARE_CMD) + strlen(propValue) + 2;
		cmd = (char *)calloc(len, sizeof (char));
		(void) snprintf(cmd, len, "%s %s", NFS_UNSHARE_CMD, propValue);
	} else {
		cim_logDebug("cmdgen_unshare_nfs", "objPath is NULL");
		cmd = NULL;
	}
	return (cmd);
}
