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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/file.h>
#include <sys/fcntl.h>

int
flock(fd, operation)
int fd, operation;
{
	struct flock fl;
	int cmd = F_FLOCKW;

	fl.l_whence = 0;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_type = 0;
	if (operation & LOCK_UN)
		fl.l_type |= F_UNLCK;
	if (operation & LOCK_SH)
		fl.l_type |= F_RDLCK;
	if (operation & LOCK_EX)
		fl.l_type |= F_WRLCK;
	if (operation & LOCK_NB)
		cmd = F_FLOCK;
	return (bc_fcntl(fd, cmd, &fl));
}
