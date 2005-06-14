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
 * Private variables and constants.
 */
#define	UMOUNT_CMD	"umount"
#define	SPACE		" "

/*
 * Private method declaration
 */

/*
 * Public methods
 */
/*
 * Method: cmdgen_umount
 *
 * Description: Forms the umount command with the given options.
 *
 * Parameters:
 *	- CCIMInstance *inst - Not used.
 *	- CCIMObjectPath *objPath - The object path containing the options to
 *	be used when forming the command.
 *	- int *errp - The error indicator.  Upon error, this will be set to a
 *	value != 0.
 *
 * Returns:
 *	- char * - The formed umount command.
 *	- NULL if an error occurred.
 */
/* ARGSUSED */
char *
cmdgen_umount(CCIMInstance *inst, CCIMObjectPath *objPath, int *errp) {
	int err;
	char *mount_point;
	char *cmd;
	CCIMObjectPath *depOP;

	if (objPath == NULL) {
		*errp = EINVAL;
		return (NULL);
	}

	/*
	 * Create the umount command with properties from the Solaris_NFSMount
	 * CCIMObjectPath passed in.
	 */
	/*
	 * We need to get the mount point from the Antecedent Key of the
	 * Solaris_NFSMount CCIMObjectPath.
	 */
	depOP = util_getKeyValue(objPath->mKeyProperties, reference, ANTECEDENT,
		&err);

	mount_point = util_getKeyValue(depOP->mKeyProperties, string, NAME,
		&err);

	cmd = (char *)calloc((size_t)(strlen(mount_point) + strlen(UMOUNT_CMD)
		+ 2), (size_t)sizeof (char));
	if (cmd == NULL) {
		*errp = ENOMEM;
		return (NULL);
	}

	(void) snprintf(cmd, (size_t)(strlen(mount_point) + strlen(UMOUNT_CMD)
	    + 2), "%s%s%s", UMOUNT_CMD, SPACE, mount_point);

	*errp = 0;
	return (cmd);
} /* cmdgen_umount */
