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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "libproc.h"

/*
 * rename() system call -- executed by subject process.
 */
int
pr_rename(struct ps_prochandle *Pr, const char *old, const char *new)
{
	sysret_t rval;
	argdes_t argd[4];
	argdes_t *adp;
	int error;

	if (Pr == NULL)
		return (rename(old, new));

	adp = &argd[0];		/* old fd argument */
	adp->arg_value = AT_FDCWD;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* move to old argument */
	adp->arg_value = 0;
	adp->arg_object = (void *)old;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = strlen(old) + 1;

	adp++;			/* move to new fd argument */
	adp->arg_value = AT_FDCWD;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* move to new argument */
	adp->arg_value = 0;
	adp->arg_object = (void *)new;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = strlen(new) + 1;

	error = Psyscall(Pr, &rval, SYS_renameat, 4, &argd[0]);

	if (error) {
		errno = (error > 0) ? error : ENOSYS;
		return (-1);
	}
	return (rval.sys_rval1);
}

/*
 * link() system call -- executed by subject process.
 */
int
pr_link(struct ps_prochandle *Pr, const char *existing, const char *new)
{
	sysret_t rval;
	argdes_t argd[2];
	argdes_t *adp;
	int error;

	if (Pr == NULL)
		return (link(existing, new));

	adp = &argd[0];		/* existing argument */
	adp->arg_value = 0;
	adp->arg_object = (void *)existing;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = strlen(existing) + 1;

	adp++;			/* new argument */
	adp->arg_value = 0;
	adp->arg_object = (void *)new;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = strlen(new) + 1;

	error = Psyscall(Pr, &rval, SYS_link, 2, &argd[0]);

	if (error) {
		errno = (error > 0) ? error : ENOSYS;
		return (-1);
	}
	return (rval.sys_rval1);
}

/*
 * unlink() system call -- executed by subject process.
 */
int
pr_unlink(struct ps_prochandle *Pr, const char *path)
{
	sysret_t rval;
	argdes_t argd[3];
	argdes_t *adp;
	int error;

	if (Pr == NULL)
		return (unlink(path));

	adp = &argd[0];		/* directory fd argument */
	adp->arg_value = AT_FDCWD;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;			/* move to path argument */

	adp->arg_value = 0;
	adp->arg_object = (void *)path;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = strlen(path) + 1;
	adp++;			/* move to flags argument */

	adp->arg_value = 0;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, SYS_unlinkat, 3, &argd[0]);

	if (error) {
		errno = (error > 0) ? error : ENOSYS;
		return (-1);
	}
	return (rval.sys_rval1);
}
