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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	_LARGEFILE64_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <strings.h>
#include "libproc.h"
#include <sys/rctl_impl.h>

/*
 * getrctl() system call -- executed by subject process
 */
int
pr_getrctl(struct ps_prochandle *Pr, const char *rname,
	rctlblk_t *old_blk, rctlblk_t *new_blk, int rflag)
{
	sysret_t rval;
	argdes_t argd[6];
	argdes_t *adp;
	int error;

	if (Pr == NULL)		/* no subject process */
		return (getrctl(rname, old_blk, new_blk, rflag));

	adp = &argd[0];
	adp->arg_value = 0;	/* switch for getrctl in rctlsys */
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;
	adp->arg_value = 0;
	adp->arg_object = (void *)rname;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = strlen(rname) + 1;

	adp++;
	if (old_blk == NULL) {
		adp->arg_value = 0;
		adp->arg_object = NULL;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = 0;
	} else {
		adp->arg_value = 0;
		adp->arg_object = old_blk;
		adp->arg_type = AT_BYREF;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = rctlblk_size();
	}

	adp++;
	if (new_blk == NULL) {
		adp->arg_value = 0;
		adp->arg_object = NULL;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_OUTPUT;
		adp->arg_size = 0;
	} else {
		adp->arg_value = 0;
		adp->arg_object = new_blk;
		adp->arg_type = AT_BYREF;
		adp->arg_inout = AI_INOUT;
		adp->arg_size = rctlblk_size();
	}

	adp++;
	adp->arg_value = 0;		/* obufsz isn't used by getrctl() */
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;
	adp->arg_value = rflag;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, SYS_rctlsys, 6, &argd[0]);

	if (error) {
		errno = (error > 0) ? error : ENOSYS;
		return (-1);
	}
	return (rval.sys_rval1);
}

/*
 * setrctl() system call -- executed by subject process
 */
int
pr_setrctl(struct ps_prochandle *Pr, const char *rname,
	rctlblk_t *old_blk, rctlblk_t *new_blk, int rflag)
{
	sysret_t rval;
	argdes_t argd[6];
	argdes_t *adp;
	int error;

	if (Pr == NULL)		/* no subject process */
		return (setrctl(rname, old_blk, new_blk, rflag));

	adp = &argd[0];
	adp->arg_value = 1;	/* switch for setrctl in rctlsys */
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;
	adp->arg_value = 0;
	adp->arg_object = (void *)rname;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = strlen(rname) + 1;

	adp++;
	if (old_blk == NULL) {
		adp->arg_value = 0;
		adp->arg_object = NULL;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = 0;
	} else {
		adp->arg_value = 0;
		adp->arg_object = old_blk;
		adp->arg_type = AT_BYREF;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = rctlblk_size();
	}

	adp++;
	if (new_blk == NULL) {
		adp->arg_value = 0;
		adp->arg_object = NULL;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = 0;
	} else {
		adp->arg_value = 0;
		adp->arg_object = new_blk;
		adp->arg_type = AT_BYREF;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = rctlblk_size();
	}

	adp++;
	adp->arg_value = 0;		/* obufsz isn't used by setrctl() */
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;
	adp->arg_value = rflag;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, SYS_rctlsys, 6, &argd[0]);

	if (error) {
		errno = (error > 0) ? error : ENOSYS;
		return (-1);
	}
	return (rval.sys_rval1);
}

/*
 * setprojrctl() system call -- executed by subject process
 */
int
pr_setprojrctl(struct ps_prochandle *Pr, const char *rname,
	rctlblk_t *new_blk, size_t size, int rflag)
{
	sysret_t rval;
	argdes_t argd[6];
	argdes_t *adp;
	int error;

	if (Pr == NULL)		/* no subject process */
		return (setprojrctl(rname, new_blk, size, rflag));

	adp = &argd[0];
	adp->arg_value = 4;	/* switch for setprojrctls in rctlsys */
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;
	adp->arg_value = 0;
	adp->arg_object = (void *)rname;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = strlen(rname) + 1;

	adp++;
	adp->arg_value = 0;	/* old_blk is not used by setprojrctls() */
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;


	adp++;
	if (new_blk == NULL) {
		adp->arg_value = 0;
		adp->arg_object = NULL;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = 0;
	} else {
		adp->arg_value = 0;
		adp->arg_object = new_blk;
		adp->arg_type = AT_BYREF;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = rctlblk_size() * size;
	}

	adp++;
	adp->arg_value = size;		/* obufsz is used by setrctls() */
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;
	adp->arg_value = rflag;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, SYS_rctlsys, 6, &argd[0]);

	if (error) {
		errno = (error > 0) ? error : ENOSYS;
		return (-1);
	}
	return (rval.sys_rval1);
}
