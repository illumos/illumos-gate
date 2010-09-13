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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"lint.h"
#include	<sys/corectl.h>
#include	<sys/syscall.h>

int
core_set_options(int options)
{
	return (syscall(SYS_corectl, CC_SET_OPTIONS, options));
}

int
core_get_options(void)
{
	return (syscall(SYS_corectl, CC_GET_OPTIONS));
}

int
core_set_global_content(const core_content_t *content)
{
	return (syscall(SYS_corectl, CC_SET_GLOBAL_CONTENT, content));
}

int
core_get_global_content(core_content_t *content)
{
	return (syscall(SYS_corectl, CC_GET_GLOBAL_CONTENT, content));
}

int
core_set_global_path(const char *buf, size_t bufsize)
{
	return (syscall(SYS_corectl, CC_SET_GLOBAL_PATH, buf, bufsize));
}

int
core_get_global_path(char *buf, size_t bufsize)
{
	return (syscall(SYS_corectl, CC_GET_GLOBAL_PATH, buf, bufsize));
}

int
core_set_default_content(const core_content_t *content)
{
	return (syscall(SYS_corectl, CC_SET_DEFAULT_CONTENT, content));
}

int
core_get_default_content(core_content_t *content)
{
	return (syscall(SYS_corectl, CC_GET_DEFAULT_CONTENT, content));
}

int
core_set_default_path(const char *buf, size_t bufsize)
{
	return (syscall(SYS_corectl, CC_SET_DEFAULT_PATH, buf, bufsize));
}

int
core_get_default_path(char *buf, size_t bufsize)
{
	return (syscall(SYS_corectl, CC_GET_DEFAULT_PATH, buf, bufsize));
}

int
core_set_process_content(const core_content_t *content, pid_t pid)
{
	return (syscall(SYS_corectl, CC_SET_PROCESS_CONTENT, content, pid));
}

int
core_get_process_content(core_content_t *content, pid_t pid)
{
	return (syscall(SYS_corectl, CC_GET_PROCESS_CONTENT, content, pid));
}

int
core_set_process_path(const char *buf, size_t bufsize, pid_t pid)
{
	return (syscall(SYS_corectl, CC_SET_PROCESS_PATH, buf, bufsize, pid));
}

int
core_get_process_path(char *buf, size_t bufsize, pid_t pid)
{
	return (syscall(SYS_corectl, CC_GET_PROCESS_PATH, buf, bufsize, pid));
}
