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

#ifndef _LIBRCM_IMPL_H
#define	_LIBRCM_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <librcm.h>

/*
 * This file contains information private to librcm rcm_daemon.
 */
#define	RCM_DAEMON_START	"/usr/lib/rcm/rcm_daemon"
#define	RCM_SERVICE_DOOR	"/var/run/rcm_daemon_door"
#define	RCM_MODULE_SUFFIX	"_rcm.so"

/*
 * flag fields supported by individual librcm interfaces
 */
#define	RCM_ALLOC_HDL_MASK	(RCM_NOPID)
#define	RCM_GET_INFO_MASK	(RCM_INCLUDE_SUBTREE|RCM_INCLUDE_DEPENDENT|\
				RCM_DR_OPERATION|RCM_MOD_INFO|RCM_FILESYS)
#define	RCM_REGISTER_MASK	(RCM_FILESYS|RCM_REGISTER_DR|\
				RCM_REGISTER_EVENT|RCM_REGISTER_CAPACITY)
#define	RCM_REQUEST_MASK	(RCM_QUERY|RCM_SCOPE|RCM_FORCE|RCM_FILESYS|\
				RCM_QUERY_CANCEL|RCM_RETIRE_REQUEST)
#define	RCM_NOTIFY_MASK		(RCM_FILESYS|RCM_RETIRE_NOTIFY)

/* event data names */
#define	RCM_CMD			"rcm.cmd"
#define	RCM_RESULT		"rcm.result"
#define	RCM_RESULT_INFO		"rcm.result_info"
#define	RCM_RSRCNAMES		"rcm.rsrcnames"
#define	RCM_RSRCSTATE		"rcm.rsrcstate"
#define	RCM_CLIENT_ID		"rcm.client_id"
#define	RCM_CLIENT_INFO		"rcm.client_info"
#define	RCM_CLIENT_ERROR	"rcm.client_error"
#define	RCM_CLIENT_MODNAME	"rcm.client_modname"
#define	RCM_CLIENT_PROPERTIES	"rcm.client_properties"
#define	RCM_SEQ_NUM		"rcm.seq_num"
#define	RCM_REQUEST_FLAG	"rcm.request_flag"
#define	RCM_SUSPEND_INTERVAL	"rcm.suspend_interval"
#define	RCM_CHANGE_DATA		"rcm.change_data"
#define	RCM_EVENT_DATA		"rcm.event_data"

/*
 * action commands shared by librcm and rcm_daemon
 */
#define	CMD_KNOCK		0
#define	CMD_REGISTER		1
#define	CMD_UNREGISTER		2
#define	CMD_GETINFO		3
#define	CMD_SUSPEND		4
#define	CMD_RESUME		5
#define	CMD_OFFLINE		6
#define	CMD_ONLINE		7
#define	CMD_REMOVE		8
#define	CMD_EVENT		9
#define	CMD_REQUEST_CHANGE	10
#define	CMD_NOTIFY_CHANGE	11
#define	CMD_GETSTATE		12

/*
 * Ops vector for calling directly into daemon from RCM modules
 */
typedef struct {
	int	(*librcm_regis)();
	int	(*librcm_unregis)();
	int	(*librcm_getinfo)();
	int	(*librcm_suspend)();
	int	(*librcm_resume)();
	int	(*librcm_offline)();
	int	(*librcm_online)();
	int	(*librcm_remove)();
	int	(*librcm_request_change)();
	int	(*librcm_notify_change)();
	int	(*librcm_notify_event)();
	int	(*librcm_getstate)();
} librcm_ops_t;

/*
 * rcm handle struture
 */
struct rcm_handle {
	char		*modname;
	pid_t		pid;
	int		seq_num;
	librcm_ops_t	*lrcm_ops;
	struct module	*module;
};

struct rcm_info {
	nvlist_t *info;
	struct rcm_info	*next;
};

/*
 * module utility routines
 */
char *rcm_module_dir(uint_t);
void *rcm_module_open(char *);
void rcm_module_close(void *);

/*
 * rcm scripting utility routines
 */
char *rcm_script_dir(uint_t dirnum);
char *rcm_dir(uint_t dirnum, int *rcm_script);
char *rcm_get_script_dir(char *script_name);
int rcm_is_script(char *filename);


#ifdef	__cplusplus
}
#endif

#endif /* _LIBRCM_IMPL_H */
