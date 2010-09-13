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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MESSAGE_CONF_MOD_H
#define	_MESSAGE_CONF_MOD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


#define	OUT_OF_MEMORY_ERR	\
	gettext("Out of memory.")

#define	CANNOT_OPEN_ERR	\
	gettext("cannot open %s - %s\n")

#define	NO_USER_ERR	\
	gettext("%s, line %d: " "user '%s' not recognized\n")

#define	RESERVED_FIELD_ERR	\
	gettext("%s, line %d: " "reserved field '%s' must be '-'\n")

#define	SETREGID_ERR	\
	gettext("%s: setregid(%d) - %s\n")

#define	SETREUID_ERR	\
	gettext("%s: setreuid(%d)- %s\n")

#define	CANNOT_EXECUTE_ERR	\
	gettext("%s, line %d: no execute access to %s - %s\n")

#define	SYNTAX_ERR	\
	gettext("%s, line %d: syntax error\n")

#define	PATHCONF_ERR	\
	gettext("pathconf(%s, NAME_MAX) failed - %s\n")

#define	READDIR_ERR	\
	gettext("readdir(%s) failed - %s\n")

#define	CLOSEDIR_ERR	\
	gettext("closedir(%s) failed - %s\n")

#define	MACRO_UNDEF_ERR	\
	gettext("%s, line %d: macro '%s' undefined\n")

#define	MACRO_MULT_DEF_ERR	\
	gettext("%s, line %d: multiple definitions of macro '%s'\n")

#define	ATTR_VALUE_ERR	\
	gettext("%s, line %d: attribute type error for macro '%s'\n")

#define	ATTR_UNSUPPORTED_ERR	\
	gettext("%s, line %d: unsupported attribute type (0x%x) "	\
	"for macro '%s'\n")

#define	GET_ATTR_LIST_ERR	\
	gettext("%s, line %d: unable to get nvlist - %s\n")

#define	NVLIST_ALLOC_ERR	\
	gettext("%s, line %d: error allocating nvlist - %s\n")

#define	NVLIST_BUILD_ERR	\
	gettext("%s, line %d: error building nvlist - %s\n")

#define	SYSEVENT_ALLOC_ERR	\
	gettext("%s, line %d: error allocating event - %s\n")

#define	SYSEVENT_SEND_ERR	\
	gettext("%s, line %d: error sending event (%d) - "	\
		"syseventconfd not responding?\n")

#define	CHANNEL_OPEN_ERR \
	gettext("unable to open channel to syseventconfd\n")

#define	SYSEVENTCONFD_ERR	\
	gettext("syseventconfd not responding?\n")

#define	SYSEVENTCONFD_OK	\
	gettext("syseventconfd ok\n")

#define	SYSEVENTCONFD_TRAN_ERR	\
	gettext("syseventconfd transport error - %s\n")

#define	SYSEVENTCONFD_START_ERR		\
	gettext("error starting syseventconfd - %s\n")

#define	SYSEVENTCONFD_RESTART_ERR	\
	gettext("error restarting syseventconfd - %s\n")

#define	THR_CREATE_ERR	\
	gettext("thread create error at init - %s\n")

#define	THR_JOIN_ERR	\
	gettext("thread join error at fini - %s\n")

#define	N_EVENTS_DISCARDED_ERR	\
	gettext("discarding %d queued events\n")

#define	SERVICE_DISABLED_MSG	\
	gettext("sysevent_conf_mod service disabled - "	\
		"restart with 'pkill -HUP syseventd'\n")

#define	MSG_LOCK_CREATE_ERR	\
	gettext("%s: error creating lock %s - %s\n")

#define	MSG_LOCK_SET_ERR	\
	gettext("%s: error setting lock in %s - %s\n")

#define	MSG_LOCK_CLR_ERR	\
	gettext("%s: error clearing lock in %s - %s\n")

#define	MSG_LOCK_CLOSE_ERR	\
	gettext("%s: error closing lock %s - %s\n")


#ifdef	__cplusplus
}
#endif

#endif	/* _MESSAGE_CONF_MOD_H */
