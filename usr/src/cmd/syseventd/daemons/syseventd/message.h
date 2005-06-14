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

#ifndef	_MESSAGE_H
#define	_MESSAGE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	SIGHUP_CAUGHT \
	gettext("SIGHUP caught - reloading modules\n")

#define	DAEMON_RESTARTED \
	gettext("Daemon restarted\n")

#define	UNKNOWN_SIGNAL_CAUGHT \
	gettext("Signal '%d' caught\n")

#define	FATAL_ERROR \
	gettext("Fatal:attempting to dump core\n")

#define	INIT_ROOT_DIR_ERR \
	gettext("Initialization error: could not allocate space for the local \
		root directory - %s\n")

#define	INIT_EV_BUF_ERR \
	gettext("Initialization error: could not allocate space for the event \
		buffer - %s\n")

#define	INIT_SIG_BLOCK_ERR \
	gettext("Initialization error: Unable to block signals before creating \
		event dispatch thread\n")

#define	INIT_THR_CREATE_ERR \
	gettext("Initialization error:could not create dispatch thread - '%s' \
		\n")

#define	INIT_SIG_UNBLOCK_ERR \
	gettext("Initialization error: Unable to unblock signals after \
		creating event dispatch thread\n")

#define	KERNEL_REPLAY_ERR \
	gettext("Kernel unable to post events: '%s'\n")

#define	LOAD_MOD_ALLOC_ERR \
	gettext("Unable to allocate load module data structure %s: %s")

#define	LOAD_MOD_OPEN_ERR \
	gettext("Unable to open module directory '%s': '%s'")

#define	LOAD_MOD_READ_ERR \
	gettext("Unable to read module directory '%s': '%s'")

#define	LOAD_MOD_DLOPEN_ERR \
	gettext("Unable to open module '%s': '%s'")

#define	LOAD_MOD_DLSYM_ERR \
	gettext("Unable to read symbols for module '%s': '%s'")

#define	LOAD_MOD_NO_INIT \
	gettext("Invalid module init routine for '%s': '%s'")

#define	LOAD_MOD_EINVAL \
	gettext("Invalid ops vector for module '%s'")

#define	LOAD_MOD_VERSION_MISMATCH \
	gettext("Invalid major number for module '%s': \
		syseventd version '%d' module version '%d'")

#define	INIT_OPEN_DOOR_ERR \
	gettext("Unable to open kernel event door: '%s'")

#define	INIT_CREATE_DOOR_ERR \
	gettext("Unable to create kernel event door: '%s'")

#define	INIT_FATTACH_ERR \
	gettext("Kernel door failed to attach: '%s'")

#define	INIT_DOOR_NAME_ERR \
	gettext("Unable to establish door name with kernel: '%s'")

#define	INIT_LOCK_OPEN_ERR \
	gettext("Unable to open daemon lock file '%s': '%s'")

#define	INIT_LOCK_ERR \
	gettext("Unable to obtain daemon lock file '%s': '%s'")

#define	INIT_PATH_ERR \
	gettext("Unable to open '%s': file path invalid")

#define	INIT_UNLOCK_ERR \
	gettext("Unable to release daemon lock file '%s': '%s'")

#define	INIT_LOCK_CLOSE_ERR \
	gettext("Unable to close daemon lock file '%s': '%s'")

#define	INIT_CLIENT_TBL_ERR \
	gettext("Unable to initialize event client table\n")

#define	GET_DATA_FAILED \
	gettext("Incomplete event buffer 0X%llx.%llx")

#define	WAIT_FAILED_ERR \
	gettext("waitpid() failed: %s\n")

#define	SEMA_WAIT_FAILED_ERR \
	gettext("sema_wait() failed: %s\n")

#ifdef	__cplusplus
}
#endif

#endif	/* _MESSAGE_H */
