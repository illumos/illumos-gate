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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MESSAGE_CONFD_H
#define	_MESSAGE_CONFD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


#define	OUT_OF_MEMORY_ERR	\
	gettext("Out of memory.")

#define	INIT_ROOT_DIR_ERR \
	gettext("Initialization error: could not allocate space for the local \
		root directory - %s\n")

#define	INIT_THR_CREATE_ERR \
	gettext("Initialization error:could not create signal thread - '%s' \
		\n")

#define	CANNOT_FORK_ERR	\
	gettext("cannot fork - %s\n")

#define	SETUID_ERR	\
	gettext("%s, line %d: " "cannot setuid to user '%s' - %s\n")

#define	CANNOT_EXEC_ERR	\
	gettext("cannot exec %s - %s\n")

#define	CHILD_EXIT_STATUS_ERR \
	gettext("process %d exited with status %d\n")

#define	CHILD_EXIT_CORE_ERR \
	gettext("process %d dumped core - %s\n")

#define	CHILD_EXIT_SIGNAL_ERR \
	gettext("process %d - %s\n")

#define	CHANNEL_OPEN_ERR \
	gettext("unable to open channel to syseventd\n")

#define	CHANNEL_BIND_ERR \
	gettext("unable to bind channel to syseventd\n")

#define	NO_NVLIST_ERR \
	gettext("missing nvlist\n")

#define	NVLIST_FORMAT_ERR \
	gettext("nvlist missing '%s'\n")

#define	NVLIST_FILE_LINE_FORMAT_ERR \
	gettext("%s, line %d: nvlist missing '%s'\n")


#ifdef	__cplusplus
}
#endif

#endif	/* _MESSAGE_CONFD_H */
