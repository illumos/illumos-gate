#ifndef _MKSH_DOSYS_H
#define _MKSH_DOSYS_H
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
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

#include <mksh/defs.h>
#include <vroot/vroot.h>

extern Boolean	await(register Boolean ignore_error, register Boolean silent_error, Name target, wchar_t *command, pid_t running_pid, void *xdrs, int job_msg_id);
extern int	doexec(register wchar_t *command, register Boolean ignore_error, char *stdout_file, char *stderr_file, pathpt vroot_path, int nice_prio);
extern int	doshell(wchar_t *command, register Boolean ignore_error, char *stdout_file, char *stderr_file, int nice_prio);
extern void	redirect_io(char *stdout_file, char *stderr_file);
extern void	sh_command2string(register String command, register String destination);

#endif
