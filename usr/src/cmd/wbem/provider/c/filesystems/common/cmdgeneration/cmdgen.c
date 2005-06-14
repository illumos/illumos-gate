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

#include <errno.h>
#include "cmdgen.h"
#include "nfs_provider_names.h"
#include "util.h"
#include "cmdgen_include.h"

/*
 * Public methods
 */

/*
 * Method: cmdgen_generate_command
 *
 * Description: Routes the calls to the command generator to the appropriate
 * methods depending on the command type passed in.
 *
 * Parameters:
 *	- int cmd_type - The command type to execute.  This command type must
 *	be one of those defined in cmdgen.h.
 *	- CCIMInstance *inst - The instance used to form the command.
 *	- CCIMObjectPath *objPath - The object path used to form the command.
 *	- CCIMPropertyList *paramList - The parameter list used to form the
 *	command.
 *	- int *errp - The error pointer.
 *
 * Returns:
 *	- char * - the command formed from the input parameters.
 *	- NULL if an error occurred.
 */

char *
cmdgen_generate_command(int cmd_type, CCIMInstance *inst,
	CCIMObjectPath *objPath, CCIMPropertyList *paramList, int *errp) {

	char *cmd = NULL;
	int err;

	if (inst == NULL && objPath == NULL && paramList == NULL) {
		util_handleError(COMMAND_GEN, CIM_ERR_INVALID_PARAMETER,
			NULL, NULL, &err);
		*errp = EINVAL;
		return (NULL);
	}

	*errp = 0;
	switch (cmd_type) {
		case CMDGEN_MOUNTALL:
			cmd = cmdgen_mountall(paramList, errp);
			break;
		case CMDGEN_NFS_MOUNT:
			cmd = cmdgen_mount(CMDGEN_NFS, inst, objPath, errp);
			break;
		case CMDGEN_NFS_UMOUNT:
			cmd = cmdgen_umount(inst, objPath, errp);
			break;
		case CMDGEN_NFS_SHARE:
			cmd = cmdgen_share(CMDGEN_NFS, inst, objPath, errp);
			break;
		case CMDGEN_NFS_UNSHARE:
			cmd = cmdgen_unshare(CMDGEN_NFS, inst, objPath, errp);
			break;
		case CMDGEN_SHAREALL:
			cmd = cmdgen_shareall(paramList, errp);
			break;
		case CMDGEN_UNSHAREALL:
			cmd = cmdgen_unshareall(paramList, errp);
			break;
		case CMDGEN_UMOUNTALL:
			cmd = cmdgen_umountall(paramList, errp);
			break;
		default:
			*errp = EINVAL;

	}
	return (cmd);
} /* cmdgen_generate_command */
