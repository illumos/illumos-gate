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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	String to binary label translations.
 */

#include <ctype.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>

#include <tsol/label.h>
#include <sys/tsol/label_macro.h>

#include <sys/syscall.h>
#include <sys/tsol/tsyscall.h>

#include <sys/types.h>

/*
 * getlabel(3TSOL) - get file label
 *
 * This is the library interface to the system call.
 */

int
getlabel(const char *path, bslabel_t *label)
{
	return (syscall(SYS_labelsys, TSOL_GETLABEL, path, label));
}

/*
 * fgetlabel(3TSOL) - get file label
 *
 * This is the library interface to the system call.
 */
int
fgetlabel(int fd, bslabel_t *label)
{
	return (syscall(SYS_labelsys, TSOL_FGETLABEL, fd, label));
}
